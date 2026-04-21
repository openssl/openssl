/*
 * Copyright 1999-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/deprecated.h"
#include "internal/cryptlib.h"
#include <openssl/pkcs12.h>
#include "p12_local.h"
#include "crypto/x509.h" /* for ossl_x509_add_cert_new() */

/* Simplified PKCS#12 routines */

static int parse_pk12(PKCS12 *p12, const char *pass, int passlen,
    PKCS12_PARSE_CTX *ctx,
    OSSL_LIB_CTX *libctx, const char *propq);

static int parse_bags(const STACK_OF(PKCS12_SAFEBAG) *bags, const char *pass,
    int passlen, PKCS12_PARSE_CTX *ctx,
    OSSL_LIB_CTX *libctx, const char *propq);

static int parse_bag(PKCS12_SAFEBAG *bag, const char *pass, int passlen,
    PKCS12_PARSE_CTX *ctx,
    OSSL_LIB_CTX *libctx, const char *propq);

PKCS12_PARSE_CTX *PKCS12_PARSE_CTX_new(void)
{
    return OPENSSL_zalloc(sizeof(PKCS12_PARSE_CTX));
}

void PKCS12_PARSE_CTX_free(PKCS12_PARSE_CTX *ctx)
{
    OPENSSL_free(ctx);
}

void PKCS12_PARSE_CTX_set_pkey(PKCS12_PARSE_CTX *ctx, EVP_PKEY **pkey)
{
    ctx->pkey = pkey;
}

void PKCS12_PARSE_CTX_set_cert(PKCS12_PARSE_CTX *ctx, X509 **cert)
{
    ctx->cert = cert;
}

void PKCS12_PARSE_CTX_set_ca(PKCS12_PARSE_CTX *ctx, STACK_OF(X509) **ca)
{
    ctx->ca = ca;
}

void PKCS12_PARSE_CTX_set_skey(PKCS12_PARSE_CTX *ctx, EVP_SKEY **skey)
{
    ctx->skey = skey;
}

/*
 * Parse and decrypt a PKCS#12 structure returning user key, user cert,
 * other (CA) certs, and/or symmetric secret key according to ctx settings.
 */

int PKCS12_parse_ex(PKCS12 *p12, const char *pass,
    PKCS12_PARSE_CTX *ctx,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    X509 *x = NULL;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (ctx->pkey != NULL)
        *ctx->pkey = NULL;
    if (ctx->cert != NULL)
        *ctx->cert = NULL;
    if (ctx->skey != NULL)
        *ctx->skey = NULL;
    ctx->ocerts = NULL;

    /* Check for NULL PKCS12 structure */

    if (p12 == NULL) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_INVALID_NULL_PKCS12_POINTER);
        return 0;
    }

    /* Check the mac */
    if (PKCS12_mac_present(p12)) {
        /*
         * If password is zero length or NULL then try verifying both cases to
         * determine which password is correct. The reason for this is that under
         * PKCS#12 password based encryption no password and a zero length
         * password are two different things...
         */
        if (pass == NULL || *pass == '\0') {
            if (PKCS12_verify_mac(p12, NULL, 0))
                pass = NULL;
            else if (PKCS12_verify_mac(p12, "", 0))
                pass = "";
            else {
                ERR_raise(ERR_LIB_PKCS12, PKCS12_R_MAC_VERIFY_FAILURE);
                goto err;
            }
        } else if (!PKCS12_verify_mac(p12, pass, -1)) {
            ERR_raise(ERR_LIB_PKCS12, PKCS12_R_MAC_VERIFY_FAILURE);
            goto err;
        }
    } else if (pass == NULL || *pass == '\0') {
        pass = NULL;
    }

    /* If needed, allocate stack for other certificates */
    if ((ctx->cert != NULL || ctx->ca != NULL)
        && (ctx->ocerts = sk_X509_new_null()) == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_CRYPTO_LIB);
        goto err;
    }

    if (!parse_pk12(p12, pass, -1, ctx, libctx, propq)) {
        int err = ERR_peek_last_error();

        if (ERR_GET_LIB(err) != ERR_LIB_EVP
            && ERR_GET_REASON(err) != EVP_R_UNSUPPORTED_ALGORITHM)
            ERR_raise(ERR_LIB_PKCS12, PKCS12_R_PARSE_ERROR);
        goto err;
    }

    /* Split the certs in ocerts over *cert and *ca as far as requested */
    while ((x = sk_X509_shift(ctx->ocerts)) != NULL) {
        if (ctx->pkey != NULL && *ctx->pkey != NULL
            && ctx->cert != NULL && *ctx->cert == NULL) {
            int match;

            ERR_set_mark();
            match = X509_check_private_key(x, *ctx->pkey);
            ERR_pop_to_mark();
            if (match) {
                *ctx->cert = x;
                continue;
            }
        }

        if (ctx->ca != NULL) {
            if (!ossl_x509_add_cert_new(ctx->ca, x, X509_ADD_FLAG_DEFAULT))
                goto err;
            continue;
        }
        X509_free(x);
    }
    sk_X509_free(ctx->ocerts);
    ctx->ocerts = NULL;

    return 1;

err:

    if (ctx->pkey != NULL) {
        EVP_PKEY_free(*ctx->pkey);
        *ctx->pkey = NULL;
    }
    if (ctx->cert != NULL) {
        X509_free(*ctx->cert);
        *ctx->cert = NULL;
    }
    if (ctx->skey != NULL) {
        EVP_SKEY_free(*ctx->skey);
        *ctx->skey = NULL;
    }
    X509_free(x);
    OSSL_STACK_OF_X509_free(ctx->ocerts);
    ctx->ocerts = NULL;
    return 0;
}

int PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert,
    STACK_OF(X509) **ca)
{
    PKCS12_PARSE_CTX *ctx;
    int ret;

    ctx = PKCS12_PARSE_CTX_new();
    if (ctx == NULL)
        return 0;

    PKCS12_PARSE_CTX_set_pkey(ctx, pkey);
    PKCS12_PARSE_CTX_set_cert(ctx, cert);
    PKCS12_PARSE_CTX_set_ca(ctx, ca);

    ret = PKCS12_parse_ex(p12, pass, ctx, NULL, NULL);
    PKCS12_PARSE_CTX_free(ctx);
    return ret;
}

/* Parse the outer PKCS#12 structure */

static int parse_pk12(PKCS12 *p12, const char *pass, int passlen,
    PKCS12_PARSE_CTX *ctx,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    STACK_OF(PKCS7) *asafes;
    STACK_OF(PKCS12_SAFEBAG) *bags;
    int i, bagnid;
    PKCS7 *p7;

    if ((asafes = PKCS12_unpack_authsafes(p12)) == NULL)
        return 0;
    for (i = 0; i < sk_PKCS7_num(asafes); i++) {
        p7 = sk_PKCS7_value(asafes, i);
        bagnid = OBJ_obj2nid(p7->type);
        if (bagnid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(p7);
        } else if (bagnid == NID_pkcs7_encrypted) {
            bags = PKCS12_unpack_p7encdata(p7, pass, passlen);
        } else
            continue;
        if (!bags) {
            sk_PKCS7_pop_free(asafes, PKCS7_free);
            return 0;
        }
        /* Use provided libctx/propq if available, otherwise from p7 */
        if (!parse_bags(bags, pass, passlen, ctx,
                libctx != NULL ? libctx : p7->ctx.libctx,
                propq != NULL ? propq : p7->ctx.propq)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            sk_PKCS7_pop_free(asafes, PKCS7_free);
            return 0;
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }
    sk_PKCS7_pop_free(asafes, PKCS7_free);
    return 1;
}

static int parse_bags(const STACK_OF(PKCS12_SAFEBAG) *bags, const char *pass,
    int passlen, PKCS12_PARSE_CTX *ctx,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    int i;
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        if (!parse_bag(sk_PKCS12_SAFEBAG_value(bags, i),
                pass, passlen, ctx,
                libctx, propq))
            return 0;
    }
    return 1;
}

static int parse_bag(PKCS12_SAFEBAG *bag, const char *pass, int passlen,
    PKCS12_PARSE_CTX *ctx,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    PKCS8_PRIV_KEY_INFO *p8;
    X509 *x509;
    const ASN1_TYPE *attrib;
    ASN1_BMPSTRING *fname = NULL;
    ASN1_OCTET_STRING *lkid = NULL;

    if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName))) {
        if (attrib->type != V_ASN1_BMPSTRING)
            return 0;
        fname = attrib->value.bmpstring;
    }

    if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID))) {
        if (attrib->type != V_ASN1_OCTET_STRING)
            return 0;
        lkid = attrib->value.octet_string;
    }

    switch (PKCS12_SAFEBAG_get_nid(bag)) {
    case NID_keyBag:
        if (ctx->pkey == NULL || *ctx->pkey != NULL)
            return 1;
        *ctx->pkey = EVP_PKCS82PKEY_ex(PKCS12_SAFEBAG_get0_p8inf(bag),
            libctx, propq);
        if (*ctx->pkey == NULL)
            return 0;
        break;

    case NID_pkcs8ShroudedKeyBag:
        if (ctx->pkey == NULL || *ctx->pkey != NULL)
            return 1;
        if ((p8 = PKCS12_decrypt_skey_ex(bag, pass, passlen,
                 libctx, propq))
            == NULL)
            return 0;
        *ctx->pkey = EVP_PKCS82PKEY_ex(p8, libctx, propq);
        PKCS8_PRIV_KEY_INFO_free(p8);
        if (!(*ctx->pkey))
            return 0;
        break;

    case NID_certBag:
        if (ctx->ocerts == NULL
            || PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate)
            return 1;
        if ((x509 = PKCS12_SAFEBAG_get1_cert_ex(bag, libctx, propq)) == NULL)
            return 0;
        if (lkid && !X509_keyid_set1(x509, lkid->data, lkid->length)) {
            X509_free(x509);
            return 0;
        }
        if (fname) {
            int len, r;
            unsigned char *data;

            len = ASN1_STRING_to_UTF8(&data, fname);
            if (len >= 0) {
                r = X509_alias_set1(x509, data, len);
                OPENSSL_free(data);
                if (!r) {
                    X509_free(x509);
                    return 0;
                }
            }
        }

        if (!sk_X509_push(ctx->ocerts, x509)) {
            X509_free(x509);
            return 0;
        }

        break;

    case NID_secretBag:
        if (ctx->skey == NULL || *ctx->skey != NULL)
            return 1;
        if (PKCS12_SAFEBAG_get_bag_nid(bag) != NID_pkcs8ShroudedKeyBag)
            return 1;
        {
            PKCS8_PRIV_KEY_INFO *p8sb = PKCS12_decrypt_secretbag(bag, pass,
                passlen, libctx, propq);
            if (p8sb == NULL)
                return 0;
            *ctx->skey = PKCS8_PRIV_KEY_INFO_get1_skey(p8sb, libctx, propq);
            PKCS8_PRIV_KEY_INFO_free(p8sb);
            if (*ctx->skey == NULL) {
                ERR_raise(ERR_LIB_PKCS12, PKCS12_R_PARSE_ERROR);
                return 0;
            }
        }
        return 1;

    case NID_safeContentsBag:
        return parse_bags(PKCS12_SAFEBAG_get0_safes(bag), pass, passlen, ctx,
            libctx, propq);

    default:
        return 1;
    }
    return 1;
}
