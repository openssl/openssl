/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "internal/cryptlib.h"
#include "internal/numbers.h"
#include "internal/provider.h"
#include "evp_local.h"

static int evp_rand_up_ref(void *vrand)
{
    EVP_RAND *rand = (EVP_RAND *)vrand;
    int ref = 0;

    if (rand != NULL)
        return CRYPTO_UP_REF(&rand->refcnt, &ref, rand->refcnt_lock);
    return 1;
}

static void evp_rand_free(void *vrand){
    EVP_RAND *rand = (EVP_RAND *)vrand;
    int ref = 0;

    if (rand != NULL) {
        CRYPTO_DOWN_REF(&rand->refcnt, &ref, rand->refcnt_lock);
        if (ref <= 0) {
            ossl_provider_free(rand->prov);
            CRYPTO_THREAD_lock_free(rand->refcnt_lock);
            OPENSSL_free(rand);
        }
    }
}

static void *evp_rand_new(void)
{
    EVP_RAND *rand = OPENSSL_zalloc(sizeof(*rand));

    if (rand == NULL
            || (rand->refcnt_lock = CRYPTO_THREAD_lock_new()) == NULL) {
        OPENSSL_free(rand);
        return NULL;
    }
    rand->refcnt = 1;
    return rand;
}

/* Enable locking of the underlying DRBG/RAND if available */
int EVP_RAND_enable_locking(EVP_RAND_CTX *rand)
{
    if (rand->meth->enable_locking != NULL)
        return rand->meth->enable_locking(rand->data);
    EVPerr(0, EVP_R_LOCKING_NOT_SUPPORTED);
    return 0;
}

/* Lock the underlying DRBG/RAND if available */
static int evp_rand_lock(EVP_RAND_CTX *rand)
{
    if (rand->meth->lock != NULL)
        return rand->meth->lock(rand->data);
    return 1;
}

/* Unlock the underlying DRBG/RAND if available */
static void evp_rand_unlock(EVP_RAND_CTX *rand)
{
    if (rand->meth->unlock != NULL)
        rand->meth->unlock(rand->data);
}

static void *evp_rand_from_dispatch(int name_id,
                                    const OSSL_DISPATCH *fns,
                                    OSSL_PROVIDER *prov)
{
    EVP_RAND *rand = NULL;
    int fnrandcnt = 0, fnctxcnt = 0, fnlockcnt = 0;
#ifdef FIPS_MODULE
    int fnzeroizecnt = 0;
#endif

    if ((rand = evp_rand_new()) == NULL) {
        EVPerr(0, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    rand->name_id = name_id;
    rand->dispatch = fns;
    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_RAND_NEWCTX:
            if (rand->newctx != NULL)
                break;
            rand->newctx = OSSL_FUNC_rand_newctx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_RAND_FREECTX:
            if (rand->freectx != NULL)
                break;
            rand->freectx = OSSL_FUNC_rand_freectx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_RAND_INSTANTIATE:
            if (rand->instantiate != NULL)
                break;
            rand->instantiate = OSSL_FUNC_rand_instantiate(fns);
            fnrandcnt++;
            break;
        case OSSL_FUNC_RAND_UNINSTANTIATE:
             if (rand->uninstantiate != NULL)
                break;
            rand->uninstantiate = OSSL_FUNC_rand_uninstantiate(fns);
            fnrandcnt++;
            break;
        case OSSL_FUNC_RAND_GENERATE:
            if (rand->generate != NULL)
                break;
            rand->generate = OSSL_FUNC_rand_generate(fns);
            fnrandcnt++;
            break;
        case OSSL_FUNC_RAND_RESEED:
            if (rand->reseed != NULL)
                break;
            rand->reseed = OSSL_FUNC_rand_reseed(fns);
            break;
        case OSSL_FUNC_RAND_NONCE:
            if (rand->nonce != NULL)
                break;
            rand->nonce = OSSL_FUNC_rand_nonce(fns);
            break;
        case OSSL_FUNC_RAND_SET_CALLBACKS:
            if (rand->set_callbacks != NULL)
                break;
            rand->set_callbacks = OSSL_FUNC_rand_set_callbacks(fns);
            break;
        case OSSL_FUNC_RAND_ENABLE_LOCKING:
            if (rand->enable_locking != NULL)
                break;
            rand->enable_locking = OSSL_FUNC_rand_enable_locking(fns);
            fnlockcnt++;
            break;
        case OSSL_FUNC_RAND_LOCK:
            if (rand->lock != NULL)
                break;
            rand->lock = OSSL_FUNC_rand_lock(fns);
            fnlockcnt++;
            break;
        case OSSL_FUNC_RAND_UNLOCK:
            if (rand->unlock != NULL)
                break;
            rand->unlock = OSSL_FUNC_rand_unlock(fns);
            fnlockcnt++;
            break;
        case OSSL_FUNC_RAND_GETTABLE_PARAMS:
            if (rand->gettable_params != NULL)
                break;
            rand->gettable_params =
                OSSL_FUNC_rand_gettable_params(fns);
            break;
        case OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS:
            if (rand->gettable_ctx_params != NULL)
                break;
            rand->gettable_ctx_params =
                OSSL_FUNC_rand_gettable_ctx_params(fns);
            break;
        case OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS:
            if (rand->settable_ctx_params != NULL)
                break;
            rand->settable_ctx_params =
                OSSL_FUNC_rand_settable_ctx_params(fns);
            break;
        case OSSL_FUNC_RAND_GET_PARAMS:
            if (rand->get_params != NULL)
                break;
            rand->get_params = OSSL_FUNC_rand_get_params(fns);
            break;
        case OSSL_FUNC_RAND_GET_CTX_PARAMS:
            if (rand->get_ctx_params != NULL)
                break;
            rand->get_ctx_params = OSSL_FUNC_rand_get_ctx_params(fns);
            break;
        case OSSL_FUNC_RAND_SET_CTX_PARAMS:
            if (rand->set_ctx_params != NULL)
                break;
            rand->set_ctx_params = OSSL_FUNC_rand_set_ctx_params(fns);
            break;
        case OSSL_FUNC_RAND_VERIFY_ZEROIZATION:
            if (rand->verify_zeroization != NULL)
                break;
            rand->verify_zeroization = OSSL_FUNC_rand_verify_zeroization(fns);
#ifdef FIPS_MODULE
            fnzeroizecnt++;
#endif
            break;
        }
    }
    /*
     * In order to be a consistent set of functions we must have at least
     * a complete set of "rand" functions and a complete set of context
     * management functions.  In FIPS mode, we also require the zeroization
     * verification function.
     *
     * In addition, if locking can be enabled, we need a complete set of
     * locking functions.
     */
    if (fnrandcnt != 3
            || fnctxcnt != 2
            || (fnlockcnt != 0 && fnlockcnt != 3)
#ifdef FIPS_MODULE
            || fnzeroizecnt != 1
#endif
       ) {
        evp_rand_free(rand);
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        return NULL;
    }

    if (prov != NULL && !ossl_provider_up_ref(prov)) {
        evp_rand_free(rand);
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
    rand->prov = prov;

    return rand;
}

EVP_RAND *EVP_RAND_fetch(OPENSSL_CTX *libctx, const char *algorithm,
                         const char *properties)
{
    return evp_generic_fetch(libctx, OSSL_OP_RAND, algorithm, properties,
                             evp_rand_from_dispatch, evp_rand_up_ref,
                             evp_rand_free);
}

int EVP_RAND_up_ref(EVP_RAND *rand)
{
    return evp_rand_up_ref(rand);
}

void EVP_RAND_free(EVP_RAND *rand)
{
    evp_rand_free(rand);
}

int EVP_RAND_number(const EVP_RAND *rand)
{
    return rand->name_id;
}

const char *EVP_RAND_name(const EVP_RAND *rand)
{
    return evp_first_name(rand->prov, rand->name_id);
}

int EVP_RAND_is_a(const EVP_RAND *rand, const char *name)
{
    return evp_is_a(rand->prov, rand->name_id, NULL, name);
}

const OSSL_PROVIDER *EVP_RAND_provider(const EVP_RAND *rand)
{
    return rand->prov;
}

int EVP_RAND_get_params(EVP_RAND *rand, OSSL_PARAM params[])
{
    if (rand->get_params != NULL)
        return rand->get_params(params);
    return 1;
}

EVP_RAND_CTX *EVP_RAND_CTX_new(EVP_RAND *rand, EVP_RAND_CTX *parent)
{
    EVP_RAND_CTX *ctx;
    void *parent_ctx = NULL;
    const OSSL_DISPATCH *parent_dispatch = NULL;

    if (rand == NULL) {
        EVPerr(0, EVP_R_INVALID_NULL_ALGORITHM);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        EVPerr(0, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (parent != NULL) {
        if (!EVP_RAND_enable_locking(parent)) {
            EVPerr(0, EVP_R_UNABLE_TO_ENABLE_PARENT_LOCKING);
            OPENSSL_free(ctx);
            return NULL;
        }
        parent_ctx = parent->data;
        parent_dispatch = parent->meth->dispatch;
    }
    if ((ctx->data = rand->newctx(ossl_provider_ctx(rand->prov), parent_ctx,
                                  parent_dispatch)) == NULL
            || !EVP_RAND_up_ref(rand)) {
        EVPerr(0, ERR_R_MALLOC_FAILURE);
        rand->freectx(ctx->data);
        OPENSSL_free(ctx);
        return NULL;
    }
    ctx->meth = rand;
    return ctx;
}

void EVP_RAND_CTX_free(EVP_RAND_CTX *ctx)
{
    if (ctx != NULL) {
        ctx->meth->freectx(ctx->data);
        ctx->data = NULL;
        EVP_RAND_free(ctx->meth);
        OPENSSL_free(ctx);
    }
}

EVP_RAND *EVP_RAND_CTX_rand(EVP_RAND_CTX *ctx)
{
    return ctx->meth;
}

int EVP_RAND_get_ctx_params(EVP_RAND_CTX *ctx, OSSL_PARAM params[])
{
    int res = 1;

    if (ctx->meth->get_ctx_params != NULL) {
        if (!evp_rand_lock(ctx))
            return 0;
        res = ctx->meth->get_ctx_params(ctx->data, params);
        evp_rand_unlock(ctx);
    }
    return res;
}

int EVP_RAND_set_ctx_params(EVP_RAND_CTX *ctx, const OSSL_PARAM params[])
{
    int res = 1;

    if (ctx->meth->set_ctx_params != NULL) {
        if (!evp_rand_lock(ctx))
            return 0;
        res = ctx->meth->set_ctx_params(ctx->data, params);
        evp_rand_unlock(ctx);
        /* Clear out the cache state because the values can change on a set */
        ctx->strength = 0;
        ctx->max_request = 0;
    }
    return res;
}

const OSSL_PARAM *EVP_RAND_gettable_params(const EVP_RAND *rand)
{
    return rand->gettable_params == NULL ? NULL : rand->gettable_params();
}

const OSSL_PARAM *EVP_RAND_gettable_ctx_params(const EVP_RAND *rand)
{
    return rand->gettable_ctx_params == NULL ? NULL
                                             : rand->gettable_ctx_params();
}

const OSSL_PARAM *EVP_RAND_settable_ctx_params(const EVP_RAND *rand)
{
    return rand->settable_ctx_params == NULL ? NULL
                                             :rand->settable_ctx_params();
}

void EVP_RAND_do_all_provided(OPENSSL_CTX *libctx,
                              void (*fn)(EVP_RAND *rand, void *arg),
                              void *arg)
{
    evp_generic_do_all(libctx, OSSL_OP_RAND,
                       (void (*)(void *, void *))fn, arg,
                       evp_rand_from_dispatch, evp_rand_free);
}

void EVP_RAND_names_do_all(const EVP_RAND *rand,
                           void (*fn)(const char *name, void *data),
                           void *data)
{
    if (rand->prov != NULL)
        evp_names_do_all(rand->prov, rand->name_id, fn, data);
}

int EVP_RAND_instantiate(EVP_RAND_CTX *ctx, unsigned int strength,
                         int prediction_resistance,
                         const unsigned char *pstr, size_t pstr_len)
{
    int res;

    if (!evp_rand_lock(ctx))
        return 0;
    res = ctx->meth->instantiate(ctx->data, strength, prediction_resistance,
                                 pstr, pstr_len);
    evp_rand_unlock(ctx);
    return res;
}

int EVP_RAND_uninstantiate(EVP_RAND_CTX *ctx)
{
    int res;

    if (!evp_rand_lock(ctx))
        return 0;
    res = ctx->meth->uninstantiate(ctx->data);
    evp_rand_unlock(ctx);
    return res;
}

int EVP_RAND_generate(EVP_RAND_CTX *ctx, unsigned char *out, size_t outlen,
                      unsigned int strength, int prediction_resistance,
                      const unsigned char *addin, size_t addin_len)
{
    size_t chunk;
    OSSL_PARAM params[2];
    int res = 0;

    if (!evp_rand_lock(ctx))
        return 0;
    if (ctx->max_request == 0) {
        params[0] = OSSL_PARAM_construct_size_t(OSSL_DRBG_PARAM_MAX_REQUEST,
                                                &chunk);
        params[1] = OSSL_PARAM_construct_end();
        if (!EVP_RAND_get_ctx_params(ctx, params) || chunk == 0) {
            EVPerr(0, EVP_R_UNABLE_TO_GET_MAXIMUM_REQUEST_SIZE);
            goto err;
        }
        ctx->max_request = chunk;
    }
    for (; outlen > 0; outlen -= chunk, out += chunk) {
        chunk = outlen > ctx->max_request ? ctx->max_request : outlen;
        if (!ctx->meth->generate(ctx->data, out, chunk, strength,
                                 prediction_resistance, addin, addin_len)) {
            EVPerr(0, EVP_R_GENERATE_ERROR);
            goto err;
        }
        /*
         * Prediction resistance is only relevant the first time around,
         * subsequently, the DRBG has already been properly reseeded.
         */
        prediction_resistance = 0;
    }
    res = 1;
err:
    evp_rand_unlock(ctx);
    return res;
}

int EVP_RAND_reseed(EVP_RAND_CTX *ctx, int prediction_resistance,
                    const unsigned char *ent, size_t ent_len,
                    const unsigned char *addin, size_t addin_len)
{
    int res = 1;

    if (!evp_rand_lock(ctx))
        return 0;
    if (ctx->meth->reseed != NULL)
        res = ctx->meth->reseed(ctx->data, prediction_resistance,
                                ent, ent_len, addin, addin_len);
    evp_rand_unlock(ctx);
    return res;
}

int EVP_RAND_nonce(EVP_RAND_CTX *ctx, unsigned char *out, size_t outlen)
{
    int res = 1;
    unsigned int str = EVP_RAND_strength(ctx);

    if (!evp_rand_lock(ctx))
        return 0;
    if (ctx->meth->nonce == NULL
            || !ctx->meth->nonce(ctx->data, out, str, outlen, outlen))
        res = ctx->meth->generate(ctx->data, out, outlen, str, 0, NULL, 0);
    evp_rand_unlock(ctx);
    return res;
}

unsigned int EVP_RAND_strength(EVP_RAND_CTX *ctx)
{
    OSSL_PARAM params[2];
    unsigned int t;
    int res;

    if (ctx->strength == 0) {
        params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &t);
        params[1] = OSSL_PARAM_construct_end();
        if (!evp_rand_lock(ctx))
            return 0;
        res = EVP_RAND_get_ctx_params(ctx, params);
        evp_rand_unlock(ctx);
        if (!res)
            return 0;
        ctx->strength = t;
    }
    return ctx->strength;
}

int EVP_RAND_state(EVP_RAND_CTX *ctx)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    int status, res;

    params[0] = OSSL_PARAM_construct_int(OSSL_RAND_PARAM_STATE,
                                         &status);
    if (!evp_rand_lock(ctx))
        return 0;
    res = EVP_RAND_get_ctx_params(ctx, params);
    evp_rand_unlock(ctx);
    if (!res)
        status = EVP_RAND_STATE_ERROR;
    return status;
}

int EVP_RAND_set_callbacks(EVP_RAND_CTX *ctx,
                           OSSL_INOUT_CALLBACK *get_entropy,
                           OSSL_CALLBACK *cleanup_entropy,
                           OSSL_INOUT_CALLBACK *get_nonce,
                           OSSL_CALLBACK *cleanup_nonce, void *arg)
{
    if (ctx->meth->set_callbacks == NULL) {
        EVPerr(0, EVP_R_UNABLE_TO_SET_CALLBACKS);
        return 0;
    }
    ctx->meth->set_callbacks(ctx->data, get_entropy, cleanup_entropy,
                             get_nonce, cleanup_nonce, arg);
    return 1;
}

int EVP_RAND_verify_zeroization(EVP_RAND_CTX *ctx)
{
    int res = 0;

    if (ctx->meth->verify_zeroization != NULL) {
        if (!evp_rand_lock(ctx))
            return 0;
        res = ctx->meth->verify_zeroization(ctx->data);
        evp_rand_unlock(ctx);
    }
    return res;
}
