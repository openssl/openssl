/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#include "internal/provider.h"
#include "crypto/evp.h"
#include "evp_local.h"

int EVP_SKEY_import(EVP_SKEY *skey, const OSSL_PARAM *params)
{
    void *keydata = NULL;

    if (skey == NULL || skey->keymgmt == NULL || skey->keydata != NULL)
        return -1;

    if ((keydata = evp_keymgmt_newdata(skey->keymgmt)) == NULL
        || !evp_keymgmt_import(skey->keymgmt, keydata, OSSL_KEYMGMT_SELECT_ALL, params)) {
        evp_keymgmt_freedata(skey->keymgmt, keydata);
        keydata = NULL;
    }

    if (keydata == NULL)
        return 0;

    skey->keydata = keydata;

    return 1;
}

int EVP_SKEY_export(const EVP_SKEY *skey, int selection,
                    OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    if (skey == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (skey->keymgmt == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return evp_keymgmt_export(skey->keymgmt, skey->keydata, selection, export_cb, export_cbarg);
}

static EVP_SKEY *evp_skey_int(void)
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

EVP_SKEY *EVP_SKEY_new(OSSL_LIB_CTX *libctx, const char *keymgmtname, const char *propquery)
{
    EVP_KEYMGMT *keymgmt = NULL;
    EVP_SKEY *skey = evp_skey_int();

    if (skey == NULL)
        return NULL;

    keymgmt = EVP_KEYMGMT_fetch(libctx, keymgmtname, propquery);
    if (keymgmt == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_FETCH_FAILED);
        goto err;
    }
    skey->keymgmt = keymgmt;

    return skey;

 err:
    EVP_KEYMGMT_free(keymgmt);
    EVP_SKEY_free(skey);
    return NULL;
}

EVP_SKEY *EVP_SKEY_new_raw_key(const unsigned char *key, size_t keylen)
{
    EVP_SKEY *skey = evp_skey_int();

    if (skey == NULL)
        return NULL;

    skey->keybytes = OPENSSL_malloc(keylen);
    if (skey->keybytes == NULL)
        goto err;

    memcpy(skey->keybytes, key, keylen);
    skey->keybyteslen = keylen;

    return skey;

 err:
    EVP_SKEY_free(skey);
    return NULL;
}

int EVP_SKEY_get_raw_key(const EVP_SKEY *skey, unsigned char *key, size_t *len)
{
    if (skey == NULL)
        return 0;

    if (skey->keymgmt != NULL) {
        struct raw_key_details_st raw_key;

        raw_key.key = key == NULL ? NULL : &key;
        raw_key.len = len;
        raw_key.selection = OSSL_KEYMGMT_SELECT_SECRET_KEY;

        return evp_keymgmt_export(skey->keymgmt, skey->keydata, OSSL_KEYMGMT_SELECT_SECRET_KEY,
                                  ossl_get_raw_key_details, &raw_key);
    }

    if (key == NULL && len != NULL) {
        *len = skey->keybyteslen;
        return 1;
    } else if (key != NULL && len != NULL && *len >= skey->keybyteslen) {
        memcpy(key, skey->keybytes, skey->keybyteslen);
        *len = skey->keybyteslen;
        return 1;
    }

    return 0;
}

int EVP_SKEY_up_ref(EVP_SKEY *skey)
{
    int i;

    if (CRYPTO_UP_REF(&skey->references, &i) <= 0)
        return 0;

    REF_PRINT_COUNT("EVP_SKEY", skey);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

void EVP_SKEY_free(EVP_SKEY *skey)
{
    int i;

    if (skey == NULL)
        return;

    CRYPTO_DOWN_REF(&skey->references, &i);
    REF_PRINT_COUNT("EVP_SKEY", skey);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);
    if (skey->keydata && skey->keymgmt)
        evp_keymgmt_freedata(skey->keymgmt, skey->keydata);

    EVP_KEYMGMT_free(skey->keymgmt);

    if (skey->keybytes != NULL)
        OPENSSL_clear_free(skey->keybytes, skey->keybyteslen);

    CRYPTO_THREAD_lock_free(skey->lock);
    CRYPTO_FREE_REF(&skey->references);
    OPENSSL_free(skey);
}
