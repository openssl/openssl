/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#include "internal/provider.h"
#include "crypto/evp.h"
#include "evp_local.h"

int EVP_SKEY_export(const EVP_SKEY *skey, int selection,
                    OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    if (skey == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (skey->skeymgmt == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    return evp_skeymgmt_export(skey->skeymgmt, skey->keydata, selection, export_cb, export_cbarg);
}

EVP_SKEY *evp_skey_alloc(void)
{
    EVP_SKEY *skey = OPENSSL_zalloc(sizeof(EVP_SKEY));

    if (!CRYPTO_NEW_REF(&skey->references, 1))
        goto err;

    skey->lock = CRYPTO_THREAD_lock_new();
    if (skey->lock == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_CRYPTO_LIB);
        goto err;
    }
    return skey;

 err:
    CRYPTO_FREE_REF(&skey->references);
    CRYPTO_THREAD_lock_free(skey->lock);
    OPENSSL_free(skey);
    return NULL;
}

EVP_SKEY *EVP_SKEY_import(OSSL_LIB_CTX *libctx, const char *skeymgmtname, const char *propquery,
                          int selection, const OSSL_PARAM *params)
{
    EVP_SKEYMGMT *skeymgmt = NULL;
    EVP_SKEY *skey = evp_skey_alloc();

    if (skey == NULL)
        return NULL;

    skeymgmt = EVP_SKEYMGMT_fetch(libctx, skeymgmtname, propquery);
    if (skeymgmt == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_FETCH_FAILED);
        goto err;
    }
    skey->skeymgmt = skeymgmt;

    skey->keydata = evp_skeymgmt_import(skey->skeymgmt, selection, params);
    if (skey->keydata == NULL)
        goto err;

    return skey;

 err:
    EVP_SKEYMGMT_free(skeymgmt);
    EVP_SKEY_free(skey);
    return NULL;
}

EVP_SKEY *EVP_SKEY_generate(OSSL_LIB_CTX *libctx, const char *skeymgmtname,
                            const char *propquery, const OSSL_PARAM *params)
{
    EVP_SKEYMGMT *skeymgmt = NULL;
    EVP_SKEY *skey = evp_skey_alloc();

    if (skey == NULL)
        return NULL;

    skeymgmt = EVP_SKEYMGMT_fetch(libctx, skeymgmtname, propquery);
    if (skeymgmt == NULL) {
        /*
         * if the specific key_type is unkown, attempt to use the generic
         * key management
         */
        skeymgmt = EVP_SKEYMGMT_fetch(libctx, OSSL_SKEY_TYPE_GENERIC, propquery);
        if (skeymgmt == NULL) {
            ERR_raise(ERR_LIB_EVP, ERR_R_FETCH_FAILED);
            goto err;
        }
    }
    skey->skeymgmt = skeymgmt;

    skey->keydata = evp_skeymgmt_generate(skey->skeymgmt, params);
    if (skey->keydata == NULL)
        goto err;

    return skey;

 err:
    EVP_SKEYMGMT_free(skeymgmt);
    EVP_SKEY_free(skey);
    return NULL;
}

struct raw_key_details_st {
    const void **key;
    size_t *len;
};

static int get_secret_key(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p = NULL;
    struct raw_key_details_st *raw_key = arg;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES)) != NULL)
        return OSSL_PARAM_get_octet_string_ptr(p, raw_key->key, raw_key->len);

    return 0;
}

int EVP_SKEY_get_raw_key(const EVP_SKEY *skey, const unsigned char **key,
                         size_t *len)
{
    struct raw_key_details_st raw_key;

    if (skey == NULL || key == NULL || len == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    raw_key.key = (const void **)key;
    raw_key.len = len;

    return evp_skeymgmt_export(skey->skeymgmt, skey->keydata,
                               OSSL_SKEYMGMT_SELECT_SECRET_KEY,
                               get_secret_key, &raw_key);
}

EVP_SKEY *EVP_SKEY_import_raw_key(OSSL_LIB_CTX *libctx, const char *skeymgmtname,
                                  unsigned char *key, size_t keylen,
                                  const char *propquery)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES,
                                                  (void *)key, keylen);
    params[1] = OSSL_PARAM_construct_end();

    return EVP_SKEY_import(libctx, skeymgmtname, propquery,
                           OSSL_SKEYMGMT_SELECT_SECRET_KEY, params);
}

int EVP_SKEY_up_ref(EVP_SKEY *skey)
{
    int i;

    if (CRYPTO_UP_REF(&skey->references, &i) <= 0)
        return 0;

    REF_PRINT_COUNT("EVP_SKEY", i, skey);
    REF_ASSERT_ISNT(i < 2);
    return i > 1 ? 1 : 0;
}

void EVP_SKEY_free(EVP_SKEY *skey)
{
    int i;

    if (skey == NULL)
        return;

    CRYPTO_DOWN_REF(&skey->references, &i);
    REF_PRINT_COUNT("EVP_SKEY", i, skey);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);
    if (skey->keydata && skey->skeymgmt)
        evp_skeymgmt_freedata(skey->skeymgmt, skey->keydata);

    EVP_SKEYMGMT_free(skey->skeymgmt);

    CRYPTO_THREAD_lock_free(skey->lock);
    CRYPTO_FREE_REF(&skey->references);
    OPENSSL_free(skey);
}

const char *EVP_SKEY_get0_key_id(const EVP_SKEY *skey)
{
    if (skey == NULL)
        return NULL;

    if (skey->skeymgmt->get_key_id)
        return skey->skeymgmt->get_key_id(skey->keydata);

    return NULL;
}

const char *EVP_SKEY_get0_skeymgmt_name(const EVP_SKEY *skey)
{
    if (skey == NULL)
        return NULL;

    return skey->skeymgmt->type_name;

}

const char *EVP_SKEY_get0_provider_name(const EVP_SKEY *skey)
{
    if (skey == NULL)
        return NULL;

    return ossl_provider_name(skey->skeymgmt->prov);
}
