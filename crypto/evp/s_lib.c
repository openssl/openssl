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

EVP_SKEY *evp_skey_int(void)
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
    EVP_SKEY *skey = evp_skey_int();

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

    skey->keydata = evp_skeymgmt_import(skey->skeymgmt, selection, params);
    if (skey->keydata == NULL)
        goto err;

    return skey;

 err:
    EVP_SKEYMGMT_free(skeymgmt);
    EVP_SKEY_free(skey);
    return NULL;
}

struct raw_key_details_st {
    unsigned char **key;
    size_t *len;
    int selection;
};

static int get_secret_key(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p = NULL;
    struct raw_key_details_st *raw_key = arg;

    if (raw_key->selection == OSSL_SKEYMGMT_SELECT_SECRET_KEY) {
        if ((p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES)) != NULL)
            return OSSL_PARAM_get_octet_string(p, (void **)raw_key->key,
                                               raw_key->key == NULL ? 0 : *raw_key->len,
                                               raw_key->len);
    }

    return 0;
}

int EVP_SKEY_get_raw_key(const EVP_SKEY *skey, unsigned char *key, size_t *len)
{
    struct raw_key_details_st raw_key;

    if (skey == NULL)
        return 0;

    raw_key.key = key == NULL ? NULL : &key;
    raw_key.len = len;
    raw_key.selection = OSSL_SKEYMGMT_SELECT_SECRET_KEY;

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
                                                  key, keylen);
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
    return ((i > 1) ? 1 : 0);
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

int EVP_SKEY_is_a(const EVP_SKEY *skey, const char *name)
{
    if (skey == NULL)
        return 0;

    if (skey->skeymgmt == NULL)
        return 0;

    return EVP_SKEYMGMT_is_a(skey->skeymgmt, name);
}

struct transfer_cb_ctx {
    int selection;
    EVP_SKEYMGMT *skeymgmt;
    void *keydata;
};

static int transfer_cb(const OSSL_PARAM params[], void *arg)
{
    struct transfer_cb_ctx *ctx = arg;

    ctx->keydata = evp_skeymgmt_import(ctx->skeymgmt, ctx->selection, params);
    return 1;
}

EVP_SKEY *EVP_SKEY_to_provider(EVP_SKEY *skey, OSSL_LIB_CTX *libctx,
                               OSSL_PROVIDER *prov, const char *propquery)
{
    struct transfer_cb_ctx ctx = { 0 };
    EVP_SKEYMGMT *skeymgmt = NULL;
    EVP_SKEY *ret = NULL;

    if (prov) {
        skeymgmt = evp_skeymgmt_fetch_from_prov(prov,
                                                skey->skeymgmt->type_name,
                                                propquery);

    } else {
        /* If no provider, get the default skeymgmt */
        skeymgmt = EVP_SKEYMGMT_fetch(libctx, skey->skeymgmt->type_name,
                                      propquery);
    }

    /* Short-circuit if destination provider is the same as origin */
    if (skey->skeymgmt->name_id == skeymgmt->name_id
        && skey->skeymgmt->prov == skeymgmt->prov) {
        if (!EVP_SKEY_up_ref(skey))
            goto err;
        EVP_SKEYMGMT_free(skeymgmt);
        return skey;
    }

    ctx.selection = OSSL_SKEYMGMT_SELECT_ALL;
    ctx.skeymgmt = skeymgmt;

    if (!EVP_SKEY_export(skey, ctx.selection, transfer_cb, &ctx))
        goto err;

    if (ctx.keydata == NULL)
        goto err;

    ret = evp_skey_int();
    if (ret == NULL)
        goto err;

    ret->keydata = ctx.keydata;
    ret->skeymgmt = skeymgmt;

    return ret;

 err:
    EVP_SKEYMGMT_free(skeymgmt);
    EVP_SKEY_free(ret);
    return NULL;
}
