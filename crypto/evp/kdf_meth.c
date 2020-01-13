/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/evp.h>
#include <opentls/err.h>
#include <opentls/core.h>
#include <opentls/core_numbers.h>
#include <opentls/kdf.h>
#include "crypto/evp.h"
#include "internal/provider.h"
#include "evp_local.h"

static int evp_kdf_up_ref(void *vkdf)
{
    EVP_KDF *kdf = (EVP_KDF *)vkdf;
    int ref = 0;

    CRYPTO_UP_REF(&kdf->refcnt, &ref, kdf->lock);
    return 1;
}

static void evp_kdf_free(void *vkdf){
    EVP_KDF *kdf = (EVP_KDF *)vkdf;
    int ref = 0;

    if (kdf != NULL) {
        CRYPTO_DOWN_REF(&kdf->refcnt, &ref, kdf->lock);
        if (ref <= 0) {
            otls_provider_free(kdf->prov);
            CRYPTO_THREAD_lock_free(kdf->lock);
            OPENtls_free(kdf);
        }
    }
}

static void *evp_kdf_new(void)
{
    EVP_KDF *kdf = NULL;

    if ((kdf = OPENtls_zalloc(sizeof(*kdf))) == NULL
        || (kdf->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        OPENtls_free(kdf);
        return NULL;
    }
    kdf->refcnt = 1;
    return kdf;
}

static void *evp_kdf_from_dispatch(int name_id,
                                   const Otls_DISPATCH *fns,
                                   Otls_PROVIDER *prov)
{
    EVP_KDF *kdf = NULL;
    int fnkdfcnt = 0, fnctxcnt = 0;

    if ((kdf = evp_kdf_new()) == NULL) {
        EVPerr(0, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    kdf->name_id = name_id;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case Otls_FUNC_KDF_NEWCTX:
            if (kdf->newctx != NULL)
                break;
            kdf->newctx = Otls_get_OP_kdf_newctx(fns);
            fnctxcnt++;
            break;
        case Otls_FUNC_KDF_DUPCTX:
            if (kdf->dupctx != NULL)
                break;
            kdf->dupctx = Otls_get_OP_kdf_dupctx(fns);
            break;
        case Otls_FUNC_KDF_FREECTX:
            if (kdf->freectx != NULL)
                break;
            kdf->freectx = Otls_get_OP_kdf_freectx(fns);
            fnctxcnt++;
            break;
        case Otls_FUNC_KDF_RESET:
            if (kdf->reset != NULL)
                break;
            kdf->reset = Otls_get_OP_kdf_reset(fns);
            break;
        case Otls_FUNC_KDF_DERIVE:
            if (kdf->derive != NULL)
                break;
            kdf->derive = Otls_get_OP_kdf_derive(fns);
            fnkdfcnt++;
            break;
        case Otls_FUNC_KDF_GETTABLE_PARAMS:
            if (kdf->gettable_params != NULL)
                break;
            kdf->gettable_params =
                Otls_get_OP_kdf_gettable_params(fns);
            break;
        case Otls_FUNC_KDF_GETTABLE_CTX_PARAMS:
            if (kdf->gettable_ctx_params != NULL)
                break;
            kdf->gettable_ctx_params =
                Otls_get_OP_kdf_gettable_ctx_params(fns);
            break;
        case Otls_FUNC_KDF_SETTABLE_CTX_PARAMS:
            if (kdf->settable_ctx_params != NULL)
                break;
            kdf->settable_ctx_params =
                Otls_get_OP_kdf_settable_ctx_params(fns);
            break;
        case Otls_FUNC_KDF_GET_PARAMS:
            if (kdf->get_params != NULL)
                break;
            kdf->get_params = Otls_get_OP_kdf_get_params(fns);
            break;
        case Otls_FUNC_KDF_GET_CTX_PARAMS:
            if (kdf->get_ctx_params != NULL)
                break;
            kdf->get_ctx_params = Otls_get_OP_kdf_get_ctx_params(fns);
            break;
        case Otls_FUNC_KDF_SET_CTX_PARAMS:
            if (kdf->set_ctx_params != NULL)
                break;
            kdf->set_ctx_params = Otls_get_OP_kdf_set_ctx_params(fns);
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
        otls_provider_up_ref(prov);

    return kdf;
}

EVP_KDF *EVP_KDF_fetch(OPENtls_CTX *libctx, const char *algorithm,
                       const char *properties)
{
    return evp_generic_fetch(libctx, Otls_OP_KDF, algorithm, properties,
                             evp_kdf_from_dispatch, evp_kdf_up_ref,
                             evp_kdf_free);
}

int EVP_KDF_up_ref(EVP_KDF *kdf)
{
    return evp_kdf_up_ref(kdf);
}

void EVP_KDF_free(EVP_KDF *kdf)
{
    evp_kdf_free(kdf);
}

const Otls_PARAM *EVP_KDF_gettable_params(const EVP_KDF *kdf)
{
    if (kdf->gettable_params == NULL)
        return NULL;
    return kdf->gettable_params();
}

const Otls_PARAM *EVP_KDF_gettable_ctx_params(const EVP_KDF *kdf)
{
    if (kdf->gettable_ctx_params == NULL)
        return NULL;
    return kdf->gettable_ctx_params();
}

const Otls_PARAM *EVP_KDF_settable_ctx_params(const EVP_KDF *kdf)
{
    if (kdf->settable_ctx_params == NULL)
        return NULL;
    return kdf->settable_ctx_params();
}

void EVP_KDF_do_all_provided(OPENtls_CTX *libctx,
                             void (*fn)(EVP_KDF *kdf, void *arg),
                             void *arg)
{
    evp_generic_do_all(libctx, Otls_OP_KDF,
                       (void (*)(void *, void *))fn, arg,
                       evp_kdf_from_dispatch, evp_kdf_free);
}
