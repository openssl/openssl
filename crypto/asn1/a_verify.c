/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include <sys/types.h>

#include "internal/cryptlib.h"

#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"

#ifndef NO_ASN1_OLD

int ASN1_verify(i2d_of_void *i2d, X509_ALGOR *a, ASN1_BIT_STRING *signature,
                char *data, EVP_PKEY *pkey)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *type;
    unsigned char *p, *buf_in = NULL;
    int ret = -1, i, inl;

    if (ctx == NULL) {
        ASN1err(ASN1_F_ASN1_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    i = OBJ_obj2nid(a->algorithm);
    type = EVP_get_digestbyname(OBJ_nid2sn(i));
    if (type == NULL) {
        ASN1err(ASN1_F_ASN1_VERIFY, ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM);
        goto err;
    }

    if (signature->type == V_ASN1_BIT_STRING && signature->flags & 0x7) {
        ASN1err(ASN1_F_ASN1_VERIFY, ASN1_R_INVALID_BIT_STRING_BITS_LEFT);
        goto err;
    }

    inl = i2d(data, NULL);
    if (inl <= 0) {
        ASN1err(ASN1_F_ASN1_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    buf_in = OPENSSL_malloc((unsigned int)inl);
    if (buf_in == NULL) {
        ASN1err(ASN1_F_ASN1_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    p = buf_in;

    i2d(data, &p);
    ret = EVP_VerifyInit_ex(ctx, type, NULL)
        && EVP_VerifyUpdate(ctx, (unsigned char *)buf_in, inl);

    OPENSSL_clear_free(buf_in, (unsigned int)inl);

    if (!ret) {
        ASN1err(ASN1_F_ASN1_VERIFY, ERR_R_EVP_LIB);
        goto err;
    }
    ret = -1;

    if (EVP_VerifyFinal(ctx, (unsigned char *)signature->data,
                        (unsigned int)signature->length, pkey) <= 0) {
        ASN1err(ASN1_F_ASN1_VERIFY, ERR_R_EVP_LIB);
        ret = 0;
        goto err;
    }
    ret = 1;
 err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

#endif

int ASN1_item_verify(const ASN1_ITEM *it, X509_ALGOR *a,
                     ASN1_BIT_STRING *signature, void *asn, EVP_PKEY *pkey)
{
    int rv = -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);

    if (ctx == NULL || pctx == NULL) {
        ASN1err(0, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    EVP_MD_CTX_set_pkey_ctx(ctx, pctx);

    rv = ASN1_item_verify_ctx(it, a, signature, asn, ctx);

 err:
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(ctx);
    return rv;
}

int ASN1_item_verify_ctx(const ASN1_ITEM *it, X509_ALGOR *a,
                         ASN1_BIT_STRING *signature, void *asn,
                         EVP_MD_CTX *ctx)
{
    EVP_PKEY *pkey;
    unsigned char *buf_in = NULL;
    int ret = -1, inl = 0;
    int mdnid, pknid;
    size_t inll = 0;

    pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(ctx));

    if (pkey == NULL) {
        ASN1err(0, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    if (signature->type == V_ASN1_BIT_STRING && signature->flags & 0x7) {
        ASN1err(0, ASN1_R_INVALID_BIT_STRING_BITS_LEFT);
        return -1;
    }

    /* Convert signature OID into digest and public key OIDs */
    if (!OBJ_find_sigid_algs(OBJ_obj2nid(a->algorithm), &mdnid, &pknid)) {
        ASN1err(0, ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM);
        goto err;
    }

    if (mdnid == NID_undef) {
        if (pkey->ameth == NULL || pkey->ameth->item_verify == NULL) {
            ASN1err(0, ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM);
            goto err;
        }
        ret = pkey->ameth->item_verify(ctx, it, asn, a, signature, pkey);
        /*
         * Return values meaning:
         * <=0: error.
         *   1: method does everything.
         *   2: carry on as normal, method has called EVP_DigestVerifyInit()
         */
        if (ret <= 0)
            ASN1err(0, ERR_R_EVP_LIB);
        if (ret <= 1)
            goto err;
    } else {
        const EVP_MD *type = EVP_get_digestbynid(mdnid);

        if (type == NULL) {
            ASN1err(0, ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM);
            goto err;
        }

        /* Check public key OID matches public key type */
        if (EVP_PKEY_type(pknid) != pkey->ameth->pkey_id) {
            ASN1err(0, ASN1_R_WRONG_PUBLIC_KEY_TYPE);
            goto err;
        }

        if (!EVP_DigestVerifyInit(ctx, NULL, type, NULL, pkey)) {
            ASN1err(0, ERR_R_EVP_LIB);
            ret = 0;
            goto err;
        }
    }

    inl = ASN1_item_i2d(asn, &buf_in, it);
    if (inl <= 0) {
        ASN1err(0, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (buf_in == NULL) {
        ASN1err(0, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    inll = inl;

    ret = EVP_DigestVerify(ctx, signature->data, (size_t)signature->length,
                           buf_in, inl);
    if (ret <= 0) {
        ASN1err(0, ERR_R_EVP_LIB);
        goto err;
    }
    ret = 1;
 err:
    OPENSSL_clear_free(buf_in, inll);
    return ret;
}
