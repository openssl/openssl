/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* The PKCS7 APIs are deprecated for public use, but still ok for internal use. */
#include "internal/deprecated.h"

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include "p12_local.h"

/* Wraps |p7| in a new authsafe, taking ownership of |p7| on success. */
static PKCS12_AUTHSAFE *authsafe_new(PKCS7 *p7)
{
    PKCS12_AUTHSAFE *authsafe;

    if ((authsafe = OPENSSL_zalloc(sizeof(*authsafe))) == NULL)
        return NULL;
    authsafe->p7 = p7;
    return authsafe;
}

void PKCS12_AUTHSAFE_free(PKCS12_AUTHSAFE *authsafe)
{
    if (authsafe == NULL)
        return;
    PKCS7_free(authsafe->p7);
    OPENSSL_free(authsafe);
}

PKCS12_AUTHSAFE *PKCS12_AUTHSAFE_new_data(const STACK_OF(PKCS12_SAFEBAG) *bags)
{
    PKCS12_AUTHSAFE *authsafe;
    PKCS7 *p7;

    if (bags == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if ((p7 = PKCS12_pack_p7data((STACK_OF(PKCS12_SAFEBAG) *)bags)) == NULL)
        return NULL;
    if ((authsafe = authsafe_new(p7)) == NULL)
        PKCS7_free(p7);
    return authsafe;
}

PKCS12_AUTHSAFE *PKCS12_AUTHSAFE_new_encrypted(int pbe_nid,
    const char *pass, int passlen,
    const unsigned char *salt, int saltlen, int iter,
    const STACK_OF(PKCS12_SAFEBAG) *bags,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    PKCS12_AUTHSAFE *authsafe;
    PKCS7 *p7;

    if (bags == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    /* The salt is copied into the algorithm parameters, not modified. */
    p7 = PKCS12_pack_p7encdata_ex(pbe_nid, pass, passlen,
        (unsigned char *)salt, saltlen, iter,
        (STACK_OF(PKCS12_SAFEBAG) *)bags, libctx, propq);
    if (p7 == NULL)
        return NULL;
    if ((authsafe = authsafe_new(p7)) == NULL)
        PKCS7_free(p7);
    return authsafe;
}

int PKCS12_AUTHSAFE_get_type(const PKCS12_AUTHSAFE *authsafe)
{
    if (authsafe == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER);
        return NID_undef;
    }
    return OBJ_obj2nid(authsafe->p7->type);
}

const X509_ALGOR *PKCS12_AUTHSAFE_get0_alg(const PKCS12_AUTHSAFE *authsafe)
{
    if (authsafe == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if (!PKCS7_type_is_encrypted(authsafe->p7)
        || authsafe->p7->d.encrypted == NULL)
        return NULL;
    return authsafe->p7->d.encrypted->enc_data->algorithm;
}

STACK_OF(PKCS12_SAFEBAG) *PKCS12_AUTHSAFE_get1_bags(const PKCS12_AUTHSAFE *authsafe,
    const char *pass, int passlen,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    PKCS7 *p7;

    if (authsafe == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    p7 = authsafe->p7;

    switch (OBJ_obj2nid(p7->type)) {
    case NID_pkcs7_data:
        if (p7->d.data == NULL) {
            ERR_raise(ERR_LIB_PKCS12, PKCS12_R_DECODE_ERROR);
            return NULL;
        }
        return ASN1_item_unpack_ex(p7->d.data, ASN1_ITEM_rptr(PKCS12_SAFEBAGS),
            libctx, propq);
    case NID_pkcs7_encrypted:
        return ossl_pkcs12_unpack_p7encdata_ex(p7, pass, passlen,
            libctx, propq);
    default:
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_INVALID_TYPE);
        return NULL;
    }
}

STACK_OF(PKCS12_AUTHSAFE) *PKCS12_get1_authsafes(const PKCS12 *p12)
{
    STACK_OF(PKCS7) *p7s;
    STACK_OF(PKCS12_AUTHSAFE) *authsafes = NULL;
    PKCS12_AUTHSAFE *authsafe;
    PKCS7 *p7;

    if (p12 == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if ((p7s = ossl_pkcs12_unpack_authsafes_ex(p12, NULL, NULL)) == NULL)
        return NULL;
    if ((authsafes = sk_PKCS12_AUTHSAFE_new_reserve(NULL, sk_PKCS7_num(p7s))) == NULL)
        goto err;

    while ((p7 = sk_PKCS7_shift(p7s)) != NULL) {
        if ((authsafe = authsafe_new(p7)) == NULL) {
            PKCS7_free(p7);
            goto err;
        }
        /* Cannot fail: the stack has room reserved for every authsafe. */
        sk_PKCS12_AUTHSAFE_push(authsafes, authsafe);
    }
    sk_PKCS7_free(p7s);
    return authsafes;

err:
    sk_PKCS12_AUTHSAFE_pop_free(authsafes, PKCS12_AUTHSAFE_free);
    sk_PKCS7_pop_free(p7s, PKCS7_free);
    return NULL;
}

int PKCS12_set1_authsafes(PKCS12 *p12,
    const STACK_OF(PKCS12_AUTHSAFE) *authsafes)
{
    STACK_OF(PKCS7) *p7s;
    int i, ret;

    if (p12 == NULL || authsafes == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (!PKCS7_type_is_data(p12->authsafes)) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_CONTENT_TYPE_NOT_DATA);
        return 0;
    }
    if ((p7s = sk_PKCS7_new_reserve(NULL, sk_PKCS12_AUTHSAFE_num(authsafes))) == NULL)
        return 0;
    /*
     * The PKCS7 objects are borrowed from |authsafes| for the encoding.
     * Pushing cannot fail: the stack has room reserved for all of them.
     */
    for (i = 0; i < sk_PKCS12_AUTHSAFE_num(authsafes); i++)
        sk_PKCS7_push(p7s, sk_PKCS12_AUTHSAFE_value(authsafes, i)->p7);

    ret = PKCS12_pack_authsafes(p12, p7s);
    sk_PKCS7_free(p7s);
    return ret;
}

int PKCS12_add_authsafe(STACK_OF(PKCS12_AUTHSAFE) **pauthsafes,
    const STACK_OF(PKCS12_SAFEBAG) *bags,
    int safe_nid, int iter, const char *pass,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    PKCS12_AUTHSAFE *authsafe = NULL;
    PKCS7 *p7;
    int free_authsafes = 0;

    if (pauthsafes == NULL || bags == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if ((p7 = ossl_pkcs12_pack_safe(bags, safe_nid, iter, pass,
             libctx, propq))
        == NULL)
        return 0;
    if ((authsafe = authsafe_new(p7)) == NULL) {
        PKCS7_free(p7);
        return 0;
    }

    if (*pauthsafes == NULL) {
        if ((*pauthsafes = sk_PKCS12_AUTHSAFE_new_null()) == NULL)
            goto err;
        free_authsafes = 1;
    }
    if (!sk_PKCS12_AUTHSAFE_push(*pauthsafes, authsafe))
        goto err;
    return 1;

err:
    if (free_authsafes) {
        sk_PKCS12_AUTHSAFE_free(*pauthsafes);
        *pauthsafes = NULL;
    }
    PKCS12_AUTHSAFE_free(authsafe);
    return 0;
}

PKCS12 *PKCS12_add_authsafes(const STACK_OF(PKCS12_AUTHSAFE) *authsafes,
    int p7_nid, OSSL_LIB_CTX *libctx, const char *propq)
{
    PKCS12 *p12;

    if (authsafes == NULL) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if (p7_nid <= 0)
        p7_nid = NID_pkcs7_data;
    if ((p12 = PKCS12_init_ex(p7_nid, libctx, propq)) == NULL)
        return NULL;
    if (!PKCS12_set1_authsafes(p12, authsafes)) {
        PKCS12_free(p12);
        return NULL;
    }
    return p12;
}
