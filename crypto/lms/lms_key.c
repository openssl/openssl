/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "crypto/lms.h"
#include "internal/refcount.h"

LMS_KEY *ossl_lms_key_new(OSSL_LIB_CTX *libctx, const char *propq)
{
    LMS_KEY *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        return NULL;

    if (!CRYPTO_NEW_REF(&ret->references, 1))
        goto err;

    ret->libctx = libctx;
    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        if (ret->propq == NULL)
            goto err;
    }
    return ret;
err:
    if (ret != NULL) {
        OPENSSL_free(ret->propq);
        CRYPTO_FREE_REF(&ret->references);
    }
    OPENSSL_free(ret);
    return NULL;
}

void ossl_lms_key_free(LMS_KEY *key)
{
    int i;

    if (key == NULL)
        return;

    CRYPTO_DOWN_REF(&key->references, &i);
    REF_PRINT_COUNT("LMS_KEY", key);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (key->pub_allocated)
        OPENSSL_free(key->pub);
    OPENSSL_free(key->propq);
    CRYPTO_FREE_REF(&key->references);
    OPENSSL_free(key);
}

void ossl_lms_key_set0_libctx(LMS_KEY *key, OSSL_LIB_CTX *libctx)
{
    key->libctx = libctx;
}

int ossl_lms_key_up_ref(LMS_KEY *key)
{
    int i;

    if (CRYPTO_UP_REF(&key->references, &i) <= 0)
        return 0;

    REF_PRINT_COUNT("LMS_KEY", key);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

LMS_KEY *ossl_lms_key_dup(const LMS_KEY *src, int selection)
{
    LMS_KEY *ret;

    if (src == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ret = ossl_lms_key_new(src->libctx, src->propq);
    if (ret == NULL)
        return NULL;

    if (src->pub_allocated) {
        ret->pub = OPENSSL_memdup(src->pub, src->publen);
        if (ret->pub == NULL)
            goto err;
    } else {
        ret->pub = src->pub;
    }
    ret->L = src->L;
    ret->publen = src->publen;
    ret->pub_allocated = src->pub_allocated;
    ret->libctx = src->libctx;
    ret->I = ret->pub + (src->I - src->pub);
    ret->K = ret->pub + (src->K - src->pub);
    ret->lms_params = src->lms_params;
    ret->ots_params = src->ots_params;
    return ret;
 err:
    ossl_lms_key_free(ret);
    return NULL;
}

