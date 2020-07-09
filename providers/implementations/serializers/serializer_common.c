/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h> /* SIXTY_FOUR_BIT_LONG, ... */
#include <openssl/err.h>
#include <openssl/pem.h>         /* PEM_BUFSIZE */
#include <openssl/pkcs12.h>      /* PKCS8_encrypt() */
#include <openssl/types.h>
#include <openssl/x509.h>        /* i2d_X509_PUBKEY_bio() */
#include "crypto/bn.h"           /* bn_get_words() */
#include "crypto/ctype.h"
#include "crypto/ecx.h"
#include "prov/bio.h"            /* ossl_prov_bio_printf() */
#include "prov/implementations.h"
#include "prov/providercommonerr.h" /* PROV_R_READ_KEY */
#include "serializer_local.h"

static PKCS8_PRIV_KEY_INFO *
ossl_prov_p8info_from_obj(const void *obj, int obj_nid,
                          void *params,
                          int params_type,
                          int (*k2d)(const void *obj,
                                     unsigned char **pder))
{
    /* der, derlen store the key DER output and its length */
    unsigned char *der = NULL;
    int derlen;
    /* The final PKCS#8 info */
    PKCS8_PRIV_KEY_INFO *p8info = NULL;


    if ((p8info = PKCS8_PRIV_KEY_INFO_new()) == NULL
        || (derlen = k2d(obj, &der)) <= 0
        || !PKCS8_pkey_set0(p8info, OBJ_nid2obj(obj_nid), 0,
                            params_type, params, der, derlen)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        PKCS8_PRIV_KEY_INFO_free(p8info);
        OPENSSL_free(der);
        p8info = NULL;
    }

    return p8info;
}

static X509_SIG *ossl_prov_encp8_from_p8info(PKCS8_PRIV_KEY_INFO *p8info,
                                             struct pkcs8_encrypt_ctx_st *ctx)
{
    X509_SIG *p8 = NULL;
    char buf[PEM_BUFSIZE];
    const void *kstr = ctx->cipher_pass;
    size_t klen = ctx->cipher_pass_length;

    if (ctx->cipher == NULL)
        return NULL;

    if (kstr == NULL) {
        if (!ctx->cb(buf, sizeof(buf), &klen, NULL, ctx->cbarg)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_READ_KEY);
            return NULL;
        }
        kstr = buf;
    }
    /* NID == -1 means "standard" */
    p8 = PKCS8_encrypt(-1, ctx->cipher, kstr, klen, NULL, 0, 0, p8info);
    if (kstr == buf)
        OPENSSL_cleanse(buf, klen);
    return p8;
}

static X509_SIG *ossl_prov_encp8_from_obj(const void *obj, int obj_nid,
                                          void *params,
                                          int params_type,
                                          int (*k2d)(const void *obj,
                                                     unsigned char **pder),
                                          struct pkcs8_encrypt_ctx_st *ctx)
{
    PKCS8_PRIV_KEY_INFO *p8info =
        ossl_prov_p8info_from_obj(obj, obj_nid, params, params_type, k2d);
    X509_SIG *p8 = ossl_prov_encp8_from_p8info(p8info, ctx);

    PKCS8_PRIV_KEY_INFO_free(p8info);
    return p8;
}

static X509_PUBKEY *ossl_prov_pubkey_from_obj(const void *obj, int obj_nid,
                                              void *params,
                                              int params_type,
                                              int (*k2d)(const void *obj,
                                                         unsigned char **pder))
{
    /* der, derlen store the key DER output and its length */
    unsigned char *der = NULL;
    int derlen;
    /* The final X509_PUBKEY */
    X509_PUBKEY *xpk = NULL;


    if ((xpk = X509_PUBKEY_new()) == NULL
        || (derlen = k2d(obj, &der)) <= 0
        || !X509_PUBKEY_set0_param(xpk, OBJ_nid2obj(obj_nid),
                                   params_type, params, der, derlen)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        X509_PUBKEY_free(xpk);
        OPENSSL_free(der);
        xpk = NULL;
    }

    return xpk;
}

OSSL_FUNC_keymgmt_new_fn *ossl_prov_get_keymgmt_new(const OSSL_DISPATCH *fns)
{
    /* Pilfer the keymgmt dispatch table */
    for (; fns->function_id != 0; fns++)
        if (fns->function_id == OSSL_FUNC_KEYMGMT_NEW)
            return OSSL_FUNC_keymgmt_new(fns);

    return NULL;
}

OSSL_FUNC_keymgmt_free_fn *ossl_prov_get_keymgmt_free(const OSSL_DISPATCH *fns)
{
    /* Pilfer the keymgmt dispatch table */
    for (; fns->function_id != 0; fns++)
        if (fns->function_id == OSSL_FUNC_KEYMGMT_FREE)
            return OSSL_FUNC_keymgmt_free(fns);

    return NULL;
}

OSSL_FUNC_keymgmt_import_fn *ossl_prov_get_keymgmt_import(const OSSL_DISPATCH *fns)
{
    /* Pilfer the keymgmt dispatch table */
    for (; fns->function_id != 0; fns++)
        if (fns->function_id == OSSL_FUNC_KEYMGMT_IMPORT)
            return OSSL_FUNC_keymgmt_import(fns);

    return NULL;
}

OSSL_FUNC_keymgmt_export_fn *ossl_prov_get_keymgmt_export(const OSSL_DISPATCH *fns)
{
    /* Pilfer the keymgmt dispatch table */
    for (; fns->function_id != 0; fns++)
        if (fns->function_id == OSSL_FUNC_KEYMGMT_EXPORT)
            return OSSL_FUNC_keymgmt_export(fns);

    return NULL;
}

# ifdef SIXTY_FOUR_BIT_LONG
#  define BN_FMTu "%lu"
#  define BN_FMTx "%lx"
# endif

# ifdef SIXTY_FOUR_BIT
#  define BN_FMTu "%llu"
#  define BN_FMTx "%llx"
# endif

# ifdef THIRTY_TWO_BIT
#  define BN_FMTu "%u"
#  define BN_FMTx "%x"
# endif

int ossl_prov_print_labeled_bignum(BIO *out, const char *label,
                                   const BIGNUM *bn)
{
    int ret = 0, use_sep = 0;
    char *hex_str = NULL, *p;
    const char spaces[] = "    ";
    const char *post_label_spc = " ";

    const char *neg = "";
    int bytes;

    if (bn == NULL)
        return 0;
    if (label == NULL) {
        label = "";
        post_label_spc = "";
    }

    if (BN_is_zero(bn))
        return BIO_printf(out, "%s%s0\n", label, post_label_spc);

    if (BN_num_bytes(bn) <= BN_BYTES) {
        BN_ULONG *words = bn_get_words(bn);

        if (BN_is_negative(bn))
            neg = "-";

        return BIO_printf(out, "%s%s%s" BN_FMTu " (%s0x" BN_FMTx ")\n",
                          label, post_label_spc, neg, words[0], neg, words[0]);
    }

    hex_str = BN_bn2hex(bn);
    p = hex_str;
    if (*p == '-') {
        ++p;
        neg = " (Negative)";
    }
    if (BIO_printf(out, "%s%s\n", label, neg) <= 0)
        goto err;

    /* Keep track of how many bytes we have printed out so far */
    bytes = 0;

    if (BIO_printf(out, "%s", spaces) <= 0)
        goto err;

    /* Add a leading 00 if the top bit is set */
    if (*p >= '8') {
        if (BIO_printf(out, "%02x", 0) <= 0)
            goto err;
        ++bytes;
        use_sep = 1;
    }
    while (*p != '\0') {
        /* Do a newline after every 15 hex bytes + add the space indent */
        if ((bytes % 15) == 0 && bytes > 0) {
            if (BIO_printf(out, ":\n%s", spaces) <= 0)
                goto err;
            use_sep = 0; /* The first byte on the next line doesnt have a : */
        }
        if (BIO_printf(out, "%s%c%c", use_sep ? ":" : "",
                       ossl_tolower(p[0]), ossl_tolower(p[1])) <= 0)
            goto err;
        ++bytes;
        p += 2;
        use_sep = 1;
    }
    if (BIO_printf(out, "\n") <= 0)
        goto err;
    ret = 1;
err:
    OPENSSL_free(hex_str);
    return ret;
}

/* Number of octets per line */
#define LABELED_BUF_PRINT_WIDTH    15

int ossl_prov_print_labeled_buf(BIO *out, const char *label,
                                const unsigned char *buf, size_t buflen)
{
    size_t i;

    if (BIO_printf(out, "%s\n", label) <= 0)
        return 0;

    for (i = 0; i < buflen; i++) {
        if ((i % LABELED_BUF_PRINT_WIDTH) == 0) {
            if (i > 0 && BIO_printf(out, "\n") <= 0)
                return 0;
            if (BIO_printf(out, "    ") <= 0)
                return 0;
        }

        if (BIO_printf(out, "%02x%s", buf[i],
                                 (i == buflen - 1) ? "" : ":") <= 0)
            return 0;
    }
    if (BIO_printf(out, "\n") <= 0)
        return 0;

    return 1;
}

/* p2s = param to asn1, k2d = key to der */
int ossl_prov_write_priv_der_from_obj(BIO *out, const void *obj, int obj_nid,
                                      int (*p2s)(const void *obj, int nid,
                                                 void **str,
                                                 int *strtype),
                                      int (*k2d)(const void *obj,
                                                 unsigned char **pder),
                                      struct pkcs8_encrypt_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;

    if (p2s != NULL && !p2s(obj, obj_nid, &str, &strtype))
        return 0;

    if (ctx->cipher_intent) {
        X509_SIG *p8 =
            ossl_prov_encp8_from_obj(obj, obj_nid, str, strtype, k2d, ctx);

        if (p8 != NULL)
            ret = i2d_PKCS8_bio(out, p8);

        X509_SIG_free(p8);
    } else {
        PKCS8_PRIV_KEY_INFO *p8info =
            ossl_prov_p8info_from_obj(obj, obj_nid, str, strtype, k2d);

        if (p8info != NULL)
            ret = i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8info);

        PKCS8_PRIV_KEY_INFO_free(p8info);
    }

    return ret;
}

int ossl_prov_write_priv_pem_from_obj(BIO *out, const void *obj, int obj_nid,
                                      int (*p2s)(const void *obj, int nid,
                                                 void **str,
                                                 int *strtype),
                                      int (*k2d)(const void *obj,
                                                 unsigned char **pder),
                                      struct pkcs8_encrypt_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;

    if (p2s != NULL && !p2s(obj, obj_nid, &str, &strtype))
        return 0;

    if (ctx->cipher_intent) {
        X509_SIG *p8 = ossl_prov_encp8_from_obj(obj, obj_nid, str, strtype,
                                                k2d, ctx);

        if (p8 != NULL)
            ret = PEM_write_bio_PKCS8(out, p8);

        X509_SIG_free(p8);
    } else {
        PKCS8_PRIV_KEY_INFO *p8info =
            ossl_prov_p8info_from_obj(obj, obj_nid, str, strtype, k2d);

        if (p8info != NULL)
            ret = PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8info);

        PKCS8_PRIV_KEY_INFO_free(p8info);
    }

    return ret;
}

int ossl_prov_write_pub_der_from_obj(BIO *out, const void *obj, int obj_nid,
                                     int (*p2s)(const void *obj, int nid,
                                                void **str,
                                                int *strtype),
                                     int (*k2d)(const void *obj,
                                                unsigned char **pder))
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;
    X509_PUBKEY *xpk = NULL;

    if (p2s != NULL && !p2s(obj, obj_nid, &str, &strtype))
        return 0;

    xpk = ossl_prov_pubkey_from_obj(obj, obj_nid, str, strtype, k2d);

    if (xpk != NULL)
        ret = i2d_X509_PUBKEY_bio(out, xpk);

    /* Also frees |str| */
    X509_PUBKEY_free(xpk);
    return ret;
}

int ossl_prov_write_pub_pem_from_obj(BIO *out, const void *obj, int obj_nid,
                                     int (*p2s)(const void *obj, int nid,
                                                void **str,
                                                int *strtype),
                                     int (*k2d)(const void *obj,
                                                unsigned char **pder))
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;
    X509_PUBKEY *xpk = NULL;

    if (p2s != NULL && !p2s(obj, obj_nid, &str, &strtype))
        return 0;

    xpk = ossl_prov_pubkey_from_obj(obj, obj_nid, str, strtype, k2d);

    if (xpk != NULL)
        ret = PEM_write_bio_X509_PUBKEY(out, xpk);

    /* Also frees |str| */
    X509_PUBKEY_free(xpk);
    return ret;
}
