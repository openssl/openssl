/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/kdf.h>
#include "internal/provider.h"
#include "internal/core.h"
#include "internal/cryptlib.h"
#include "internal/hashtable.h"
#include "internal/property.h"
#include "crypto/evp.h"
#include "evp_local.h"

HT_START_KEY_DEFN(kdfkey)
HT_DEF_KEY_FIELD_CHAR_ARRAY(name, 64)
HT_DEF_KEY_FIELD_CHAR_ARRAY(propq, 128)
HT_END_KEY_DEFN(KDFKEY)

/* implemented in context.c */
DECLARE_HT_VALUE_TYPE_FNS(EVP_KDF, algcache)

static int evp_kdf_up_ref(void *vkdf)
{
    EVP_KDF *kdf = (EVP_KDF *)vkdf;
    int ref = 0;

    CRYPTO_UP_REF(&kdf->refcnt, &ref);
    return 1;
}

static void evp_kdf_free(void *vkdf)
{
    EVP_KDF *kdf = (EVP_KDF *)vkdf;
    int ref = 0;

    if (kdf == NULL)
        return;

    CRYPTO_DOWN_REF(&kdf->refcnt, &ref);
    if (ref > 0)
        return;
    OPENSSL_free(kdf->type_name);
    ossl_provider_free(kdf->prov);
    CRYPTO_FREE_REF(&kdf->refcnt);
    OPENSSL_free(kdf);
}

static void *evp_kdf_new(void)
{
    EVP_KDF *kdf = NULL;

    if ((kdf = OPENSSL_zalloc(sizeof(*kdf))) == NULL
        || !CRYPTO_NEW_REF(&kdf->refcnt, 1)) {
        OPENSSL_free(kdf);
        return NULL;
    }
    return kdf;
}

static void *evp_kdf_from_algorithm(int name_id,
                                    const OSSL_ALGORITHM *algodef,
                                    OSSL_PROVIDER *prov)
{
    const OSSL_DISPATCH *fns = algodef->implementation;
    EVP_KDF *kdf = NULL;
    int fnkdfcnt = 0, fnctxcnt = 0;

    if ((kdf = evp_kdf_new()) == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
        return NULL;
    }
    kdf->name_id = name_id;
    if ((kdf->type_name = ossl_algorithm_get1_first_name(algodef)) == NULL) {
        evp_kdf_free(kdf);
        return NULL;
    }
    kdf->description = algodef->algorithm_description;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_KDF_NEWCTX:
            if (kdf->newctx != NULL)
                break;
            kdf->newctx = OSSL_FUNC_kdf_newctx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_KDF_DUPCTX:
            if (kdf->dupctx != NULL)
                break;
            kdf->dupctx = OSSL_FUNC_kdf_dupctx(fns);
            break;
        case OSSL_FUNC_KDF_FREECTX:
            if (kdf->freectx != NULL)
                break;
            kdf->freectx = OSSL_FUNC_kdf_freectx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_KDF_RESET:
            if (kdf->reset != NULL)
                break;
            kdf->reset = OSSL_FUNC_kdf_reset(fns);
            break;
        case OSSL_FUNC_KDF_DERIVE:
            if (kdf->derive != NULL)
                break;
            kdf->derive = OSSL_FUNC_kdf_derive(fns);
            fnkdfcnt++;
            break;
        case OSSL_FUNC_KDF_GETTABLE_PARAMS:
            if (kdf->gettable_params != NULL)
                break;
            kdf->gettable_params =
                OSSL_FUNC_kdf_gettable_params(fns);
            break;
        case OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS:
            if (kdf->gettable_ctx_params != NULL)
                break;
            kdf->gettable_ctx_params =
                OSSL_FUNC_kdf_gettable_ctx_params(fns);
            break;
        case OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS:
            if (kdf->settable_ctx_params != NULL)
                break;
            kdf->settable_ctx_params =
                OSSL_FUNC_kdf_settable_ctx_params(fns);
            break;
        case OSSL_FUNC_KDF_GET_PARAMS:
            if (kdf->get_params != NULL)
                break;
            kdf->get_params = OSSL_FUNC_kdf_get_params(fns);
            break;
        case OSSL_FUNC_KDF_GET_CTX_PARAMS:
            if (kdf->get_ctx_params != NULL)
                break;
            kdf->get_ctx_params = OSSL_FUNC_kdf_get_ctx_params(fns);
            break;
        case OSSL_FUNC_KDF_SET_CTX_PARAMS:
            if (kdf->set_ctx_params != NULL)
                break;
            kdf->set_ctx_params = OSSL_FUNC_kdf_set_ctx_params(fns);
            break;
        }
    }
    if (fnkdfcnt != 1 || fnctxcnt != 2) {
        /*
         * In order to be a consistent set of functions we must have at least
         * a derive function, and a complete set of context management
         * functions.
         */
        evp_kdf_free(kdf);
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        return NULL;
    }
    kdf->prov = prov;
    if (prov != NULL)
        ossl_provider_up_ref(prov);

    return kdf;
}

EVP_KDF *EVP_KDF_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
                       const char *properties)
{
    EVP_KDF *kdf = NULL;
#ifndef FIPS_MODULE
    KDFKEY key;
    HT_VALUE *v = NULL;
    HT *algcache;
    char *mpropq = ossl_get_merged_property_string(libctx, properties);

    HT_INIT_KEY(&key);
    HT_SET_KEY_STRING(&key, name, algorithm);
    HT_SET_KEY_STRING(&key, propq, mpropq);

    OPENSSL_free(mpropq);

    algcache = ossl_lib_ctx_get_algcache(libctx);
    ossl_ht_read_lock(algcache);
    kdf = ossl_ht_algcache_EVP_KDF_get(algcache, TO_HT_KEY(&key), &v);
    if (kdf != NULL)
        EVP_KDF_up_ref(kdf);
    ossl_ht_read_unlock(algcache);

    if (kdf != NULL)
        return kdf;
#endif

    kdf = evp_generic_fetch(libctx, OSSL_OP_KDF, algorithm, properties,
                            evp_kdf_from_algorithm, evp_kdf_up_ref,
                            evp_kdf_free);
#ifndef FIPS_MODULE
    if (kdf != NULL) {
        ossl_ht_write_lock(algcache);
        if (ossl_ht_algcache_EVP_KDF_insert(algcache, TO_HT_KEY(&key), kdf,
                                            NULL))
            EVP_KDF_up_ref(kdf);
        ossl_ht_write_unlock(algcache);
    }
#endif
    return kdf;
}

int EVP_KDF_up_ref(EVP_KDF *kdf)
{
    return evp_kdf_up_ref(kdf);
}

void EVP_KDF_free(EVP_KDF *kdf)
{
    evp_kdf_free(kdf);
}

const OSSL_PARAM *EVP_KDF_gettable_params(const EVP_KDF *kdf)
{
    if (kdf->gettable_params == NULL)
        return NULL;
    return kdf->gettable_params(ossl_provider_ctx(EVP_KDF_get0_provider(kdf)));
}

const OSSL_PARAM *EVP_KDF_gettable_ctx_params(const EVP_KDF *kdf)
{
    void *alg;

    if (kdf->gettable_ctx_params == NULL)
        return NULL;
    alg = ossl_provider_ctx(EVP_KDF_get0_provider(kdf));
    return kdf->gettable_ctx_params(NULL, alg);
}

const OSSL_PARAM *EVP_KDF_settable_ctx_params(const EVP_KDF *kdf)
{
    void *alg;

    if (kdf->settable_ctx_params == NULL)
        return NULL;
    alg = ossl_provider_ctx(EVP_KDF_get0_provider(kdf));
    return kdf->settable_ctx_params(NULL, alg);
}

const OSSL_PARAM *EVP_KDF_CTX_gettable_params(EVP_KDF_CTX *ctx)
{
    void *alg;

    if (ctx->meth->gettable_ctx_params == NULL)
        return NULL;
    alg = ossl_provider_ctx(EVP_KDF_get0_provider(ctx->meth));
    return ctx->meth->gettable_ctx_params(ctx->algctx, alg);
}

const OSSL_PARAM *EVP_KDF_CTX_settable_params(EVP_KDF_CTX *ctx)
{
    void *alg;

    if (ctx->meth->settable_ctx_params == NULL)
        return NULL;
    alg = ossl_provider_ctx(EVP_KDF_get0_provider(ctx->meth));
    return ctx->meth->settable_ctx_params(ctx->algctx, alg);
}

void EVP_KDF_do_all_provided(OSSL_LIB_CTX *libctx,
                             void (*fn)(EVP_KDF *kdf, void *arg),
                             void *arg)
{
    evp_generic_do_all(libctx, OSSL_OP_KDF,
                       (void (*)(void *, void *))fn, arg,
                       evp_kdf_from_algorithm, evp_kdf_up_ref, evp_kdf_free);
}
