/*
 * Copyright 2018-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018-2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include "crypto/evp.h"
#include "internal/numbers.h"
#include "internal/provider.h"
#include "evp_local.h"
#include "internal/param_build_set.h"

EVP_KDF_CTX *EVP_KDF_CTX_new(EVP_KDF *kdf)
{
    EVP_KDF_CTX *ctx = NULL;

    if (kdf == NULL)
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(EVP_KDF_CTX));
    if (ctx == NULL
        || (ctx->algctx = kdf->newctx(ossl_provider_ctx(kdf->prov))) == NULL
        || !EVP_KDF_up_ref(kdf)) {
        ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
        if (ctx != NULL)
            kdf->freectx(ctx->algctx);
        OPENSSL_free(ctx);
        ctx = NULL;
    } else {
        ctx->meth = kdf;
    }
    return ctx;
}

void EVP_KDF_CTX_free(EVP_KDF_CTX *ctx)
{
    if (ctx == NULL)
        return;
    ctx->meth->freectx(ctx->algctx);
    ctx->algctx = NULL;
    EVP_KDF_free(ctx->meth);
    OPENSSL_free(ctx);
}

EVP_KDF_CTX *EVP_KDF_CTX_dup(const EVP_KDF_CTX *src)
{
    EVP_KDF_CTX *dst;

    if (src == NULL || src->algctx == NULL || src->meth->dupctx == NULL)
        return NULL;

    dst = OPENSSL_malloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    memcpy(dst, src, sizeof(*dst));
    if (!EVP_KDF_up_ref(dst->meth)) {
        ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
        OPENSSL_free(dst);
        return NULL;
    }

    dst->algctx = src->meth->dupctx(src->algctx);
    if (dst->algctx == NULL) {
        EVP_KDF_CTX_free(dst);
        return NULL;
    }
    return dst;
}

int evp_kdf_get_number(const EVP_KDF *kdf)
{
    return kdf->name_id;
}

const char *EVP_KDF_get0_name(const EVP_KDF *kdf)
{
    return kdf->type_name;
}

const char *EVP_KDF_get0_description(const EVP_KDF *kdf)
{
    return kdf->description;
}

int EVP_KDF_is_a(const EVP_KDF *kdf, const char *name)
{
    return kdf != NULL && evp_is_a(kdf->prov, kdf->name_id, NULL, name);
}

const OSSL_PROVIDER *EVP_KDF_get0_provider(const EVP_KDF *kdf)
{
    return kdf->prov;
}

const EVP_KDF *EVP_KDF_CTX_kdf(EVP_KDF_CTX *ctx)
{
    return ctx->meth;
}

void EVP_KDF_CTX_reset(EVP_KDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->meth->reset != NULL)
        ctx->meth->reset(ctx->algctx);
}

size_t EVP_KDF_CTX_get_kdf_size(EVP_KDF_CTX *ctx)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    size_t s = 0;

    if (ctx == NULL)
        return 0;

    *params = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &s);
    if (ctx->meth->get_ctx_params != NULL
        && ctx->meth->get_ctx_params(ctx->algctx, params))
            return s;
    if (ctx->meth->get_params != NULL
        && ctx->meth->get_params(params))
            return s;
    return 0;
}

int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen,
                   const OSSL_PARAM params[])
{
    if (ctx == NULL)
        return 0;

    return ctx->meth->derive(ctx->algctx, key, keylen, params);
}

struct convert_key {
    const char *name;
    OSSL_PARAM *param;
};

static int convert_key_cb(const OSSL_PARAM params[], void *arg)
{
    struct convert_key *ckey = arg;
    const OSSL_PARAM *raw_bytes;
    unsigned char *data;
    size_t len;

    raw_bytes = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES);
    if (raw_bytes == NULL)
        return 0;

    if (!OSSL_PARAM_get_octet_string_ptr(raw_bytes, (const void **)&data, &len))
        return 0;

    *ckey->param = OSSL_PARAM_construct_octet_string(ckey->name, data, len);
    return 1;
}

int EVP_KDF_CTX_set_SKEY(EVP_KDF_CTX *ctx, EVP_SKEY *key, const char *paramname)
{
    struct convert_key ckey;

    if (ctx == NULL)
        return 0;

    ckey.name = (paramname != NULL) ? paramname : OSSL_KDF_PARAM_KEY;

    if (ctx->meth->set_skey != NULL) {
        EVP_SKEY *tmp_key = NULL;
        int ret;

        /* Transfer key to meth provider if different from key's */
        if (ctx->meth->prov != key->skeymgmt->prov) {
            /* FIXME: no libctx, no propquery */
            tmp_key = EVP_SKEY_to_provider(key, NULL, ctx->meth->prov, NULL);
            if (tmp_key == NULL)
                return 0;
        } else {
            tmp_key = key;
        }
        ret = ctx->meth->set_skey(ctx->algctx, key->keydata, ckey.name);
        if (tmp_key != key)
            EVP_SKEY_free(tmp_key);

        return ret;
    } else {
        /*
         * Provider does not support opaque keys, try to export and
         * set params.
         */
        OSSL_PARAM params[2] = {
            OSSL_PARAM_END,
            OSSL_PARAM_END,
        };
        ckey.param = &params[0];

        if (!ctx->meth->set_ctx_params)
            return 0;

        if (EVP_SKEY_export(key, OSSL_SKEYMGMT_SELECT_SECRET_KEY,
                            convert_key_cb, &ckey))
            return ctx->meth->set_ctx_params(ctx->algctx, params);

        return 0;
    }
}

EVP_SKEY *EVP_KDF_derive_SKEY(EVP_KDF_CTX *ctx, const char *key_type,
                              size_t keylen, const OSSL_PARAM params[])
{
    EVP_SKEYMGMT *skeymgmt = NULL;
    EVP_SKEY *ret = NULL;

    if (ctx == NULL || key_type == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    /*
     * FIXME: we have libctx but don't have the propquery here,
     * mostly needed for the fallbacks.
     *
     * We may want to pass it either explicitly or though params.
     */

    skeymgmt = evp_skeymgmt_fetch_from_prov(ctx->meth->prov,
                                            key_type, NULL);
    if (skeymgmt == NULL) {
        /*
         * The provider does not support skeymgmt, let's try to fallback
         * to a provider that supports it
         */
        skeymgmt = EVP_SKEYMGMT_fetch(ossl_provider_libctx(ctx->meth->prov),
                                      key_type, NULL);
    }

    if (skeymgmt == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_FETCH_FAILED);
        return NULL;
    }

    /* Fallback to raw derive + import if possible */
    if (skeymgmt->prov != ctx->meth->prov ||
        ctx->meth->derive_skey == NULL) {
        unsigned char *key = NULL;

        EVP_SKEYMGMT_free(skeymgmt);

        if (ctx->meth->derive == NULL) {
            ERR_raise(ERR_R_EVP_LIB, ERR_R_UNSUPPORTED);
            return NULL;
        }

        key = OPENSSL_zalloc(keylen);
        if (!key) {
            EVP_SKEY_free(ret);
            return NULL;
        }

        if (!ctx->meth->derive(ctx->algctx, key, keylen, params)) {
            EVP_SKEY_free(ret);
            OPENSSL_free(key);
            return NULL;
        }

        /* FIXME no propquery */
        ret = EVP_SKEY_import_raw_key(ossl_provider_libctx(skeymgmt->prov),
                                      key_type, key, keylen, NULL);
        OPENSSL_clear_free(key, keylen);
        return ret;
    }

    ret = evp_skey_int();
    if (ret == NULL) {
        EVP_SKEYMGMT_free(skeymgmt);
        return NULL;
    }

    ret->skeymgmt = skeymgmt;

    ret->keydata = ctx->meth->derive_skey(ctx->algctx, keylen, params);
    if (ret->keydata == NULL) {
        EVP_SKEY_free(ret);
        return NULL;
    }

    return ret;
}

/*
 * The {get,set}_params functions return 1 if there is no corresponding
 * function in the implementation.  This is the same as if there was one,
 * but it didn't recognise any of the given params, i.e. nothing in the
 * bag of parameters was useful.
 */
int EVP_KDF_get_params(EVP_KDF *kdf, OSSL_PARAM params[])
{
    if (kdf->get_params != NULL)
        return kdf->get_params(params);
    return 1;
}

int EVP_KDF_CTX_get_params(EVP_KDF_CTX *ctx, OSSL_PARAM params[])
{
    if (ctx->meth->get_ctx_params != NULL)
        return ctx->meth->get_ctx_params(ctx->algctx, params);
    return 1;
}

int EVP_KDF_CTX_set_params(EVP_KDF_CTX *ctx, const OSSL_PARAM params[])
{
    if (ctx->meth->set_ctx_params != NULL)
        return ctx->meth->set_ctx_params(ctx->algctx, params);
    return 1;
}

int EVP_KDF_names_do_all(const EVP_KDF *kdf,
                         void (*fn)(const char *name, void *data),
                         void *data)
{
    if (kdf->prov != NULL)
        return evp_names_do_all(kdf->prov, kdf->name_id, fn, data);

    return 1;
}
