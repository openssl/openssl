/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "internal/numbers.h"
#include "internal/provider.h"
#include "evp_local.h"

/* NIST SP 800-90A DRBG recommends the use of a personalization string. */
static const char ossl_pers_string[] = DRBG_DEFAULT_PERS_STRING;


static int rand_add_lock(EVP_RAND_CTX *ctx)
{
    if (ctx->lock == NULL)
        ctx->lock = CRYPTO_THREAD_lock_new();
    return ctx->lock != NULL;
}

static int evp_rand_ctx_up_ref(EVP_RAND_CTX *ctx)
{
    int ref = 0;

    if (ctx->lock == NULL && !rand_add_lock(ctx)) {
        ERR_raise(ERR_LIB_EVP, RAND_R_FAILED_TO_CREATE_LOCK);
        return 0;
    }
    CRYPTO_UP_REF(&ctx->refcnt, &ref, ctx->lock);
    return 1;
}

static int evp_rand_ctx_down_ref(EVP_RAND_CTX *ctx)
{
    int ref = 0;

    if (ctx->lock == NULL)
        return 1;
    CRYPTO_DOWN_REF(&ctx->refcnt, &ref, ctx->lock);
    return ref;
}

EVP_RAND_CTX *EVP_RAND_CTX_new(EVP_RAND *rand, int secure, int df,
                               EVP_RAND_CTX *parent)
{
    EVP_RAND_CTX *ctx;

    if (rand == NULL)
        return NULL;
    if (parent != NULL && !evp_rand_ctx_up_ref(parent))
        return NULL;
    ctx = OPENSSL_zalloc(sizeof(EVP_RAND_CTX));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ctx->data = rand->newctx(ossl_provider_ctx(rand->prov), secure, df);
    if (ctx->data == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!EVP_RAND_up_ref(rand)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_REFERENCE_COUNT_FAILURE);
        goto err;
    }
    ctx->parent = parent;
    ctx->meth = rand;
    ctx->refcnt = 1;
    return ctx;
err:
    EVP_RAND_CTX_free(parent);
    if (ctx != NULL) {
        if (ctx->data != NULL)
            rand->freectx(ctx->data);
        OPENSSL_free(ctx);
    }
    return NULL;
}

void EVP_RAND_CTX_free(EVP_RAND_CTX *ctx)
{
    EVP_RAND_CTX *parent = NULL;

    if (ctx != NULL) {
        if (ctx->lock != NULL) {
            if (evp_rand_ctx_down_ref(ctx) > 0)
                return;
            CRYPTO_THREAD_lock_free(ctx->lock);
            parent = ctx->parent;
        }
        ctx->meth->freectx(ctx->data);
        ctx->data = NULL;
        EVP_RAND_free(ctx->meth);
        OPENSSL_free(ctx);
        /* Decrement the reference count of our parent and repeat if needed */
        if (parent != NULL)
            EVP_RAND_CTX_free(parent);
    }
}

const char *EVP_RAND_name(const EVP_RAND *rand)
{
    return evp_first_name(rand->prov, rand->name_id);
}

const OSSL_PROVIDER *EVP_RAND_provider(const EVP_RAND *rand)
{
    return rand->prov;
}

const EVP_RAND *EVP_RAND_CTX_rand(EVP_RAND_CTX *ctx)
{
    return ctx->meth;
}

EVP_RAND_CTX *evp_rand_ctx_parent(EVP_RAND_CTX *ctx)
{
    return ctx != NULL ? ctx->parent : NULL;
}

static int evp_rand_ctx_lock(EVP_RAND_CTX *ctx)
{
    return ctx->lock == NULL || CRYPTO_THREAD_write_lock(ctx->lock);
}

static void evp_rand_ctx_unlock(EVP_RAND_CTX *ctx)
{
    if (ctx->lock != NULL)
        CRYPTO_THREAD_unlock(ctx->lock);
}

int EVP_RAND_CTX_enable_locking(EVP_RAND_CTX *ctx)
{
    if (ctx->lock == NULL) {
        if (ctx->parent != NULL && ctx->parent->lock == NULL) {
            ERR_raise(ERR_LIB_EVP, RAND_R_PARENT_LOCKING_NOT_ENABLED);
            return 0;
        }
        if ((ctx->lock = CRYPTO_THREAD_lock_new()) != NULL) {
            ERR_raise(ERR_LIB_EVP, RAND_R_FAILED_TO_CREATE_LOCK);
            return 0;
        }
    }
    return 1;
}

static unsigned int evp_rand_ctx_get_uint(EVP_RAND_CTX *ctx, const char *name)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    unsigned int s = 0;

    if (ctx == NULL)
        return 0;

    *params = OSSL_PARAM_construct_uint(name, &s);
    if (!evp_rand_ctx_lock(ctx))
        return 0;
    if (ctx->meth->get_ctx_params != NULL
            && !ctx->meth->get_ctx_params(ctx->data, params)
            && ctx->meth->get_params != NULL
            && !ctx->meth->get_params(params))
        s = 0;
    evp_rand_ctx_unlock(ctx);
    return s;
}

unsigned int EVP_RAND_CTX_strength(EVP_RAND_CTX *ctx)
{
    return evp_rand_ctx_get_uint(ctx, OSSL_RAND_PARAM_STRENGTH);
}

DRBG_STATUS evp_rand_ctx_status(EVP_RAND_CTX *ctx)
{
    return ctx->state;
}

size_t evp_rand_ctx_max_request_length(EVP_RAND_CTX *ctx)
{
    return ctx->max_request;
}

size_t evp_rand_ctx_max_adin_length(EVP_RAND_CTX *ctx)
{
    return ctx->max_adinlen;
}

static size_t get_entropy(EVP_RAND_CTX *ctx, unsigned char **entropy,
                          size_t min_entropy, size_t min_entropylen,
                          size_t max_entropylen,
                          int prediction_resistance)
{
    unsigned char *buf;
    EVP_RAND_CTX *parent = ctx->parent;

    *entropy = NULL;
    if (min_entropy > max_entropylen) {
        ERR_raise(ERR_LIB_EVP, EVP_R_TOO_MUCH_ENTROPY_REQUESTED);
        return 0;
    }
    if (ctx->strength > parent->strength) {
        /*
         * We currently don't support the algorithm from NIST SP 800-90C
         * 10.1.2 to use a weaker DRBG as source
         */
        ERR_raise(ERR_LIB_EVP, RAND_R_PARENT_STRENGTH_TOO_WEAK);
        return 0;
    }
    if (min_entropy < min_entropylen)
        min_entropy = min_entropylen;

    buf = OPENSSL_secure_malloc(min_entropy);
    if (buf == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!EVP_RAND_CTX_generate(parent, buf, min_entropy, NULL, 0,
                               prediction_resistance)) {
        OPENSSL_secure_clear_free(entropy, min_entropy);
        ERR_raise(ERR_LIB_EVP, RAND_R_GENERATE_ERROR);
        return 0;
    }
    *entropy = buf;
    return min_entropy;
}

static int evp_rand_ctx_do_reseed(EVP_RAND_CTX *ctx,
                                  const void *adin, size_t adin_len,
                                  int prediction_resistance)
{
    unsigned char *entropy = NULL;
    size_t entropylen = 0;

    if (ctx->meth->reseed == NULL)
        return 1;
    if (ctx->state == DRBG_ERROR) {
        ERR_raise(ERR_LIB_EVP, RAND_R_IN_ERROR_STATE);
        return 0;
    }
    if (ctx->state == DRBG_UNINITIALISED) {
        ERR_raise(ERR_LIB_EVP, RAND_R_NOT_INSTANTIATED);
        return 0;
    }

    if (ctx->meth->reseed == NULL)
        return 1;
    if (ctx->parent == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_CANNOT_RESEED_WITHOUT_PARENT_SET);
        return 0;
    }

    ctx->state = DRBG_ERROR;
    if (adin == NULL) {
        adin_len = 0;
    } else if (adin_len > ctx->max_adinlen) {
        ERR_raise(ERR_LIB_EVP, RAND_R_ADDITIONAL_INPUT_TOO_LONG);
        return 0;
    }

    ctx->reseed_next_counter = tsan_load(&ctx->reseed_prop_counter);
    if (ctx->reseed_next_counter) {
        ctx->reseed_next_counter++;
        if(!ctx->reseed_next_counter)
            ctx->reseed_next_counter = 1;
    }

    entropylen = get_entropy(ctx, &entropy, ctx->strength,
                             ctx->min_entropylen, ctx->max_entropylen,
                             prediction_resistance);
    if (entropylen < ctx->min_entropylen
            || entropylen > ctx->max_entropylen) {
        ERR_raise(ERR_LIB_EVP, RAND_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (!ctx->meth->reseed(ctx->data, entropy, entropylen, adin, adin_len)) {
        ERR_raise(ERR_LIB_EVP, RAND_R_RESEED_ERROR);
        goto end;
    }

    ctx->state = DRBG_READY;
    ctx->reseed_gen_counter = 1;
    ctx->fork_id = openssl_get_fork_id();
    ctx->reseed_time = time(NULL);
    tsan_store(&ctx->reseed_prop_counter, ctx->reseed_next_counter);
    if (ctx->parent != NULL)
        ctx->reseed_next_counter = tsan_load(&ctx->parent->reseed_prop_counter);
 end:
    OPENSSL_secure_clear_free(entropy, entropylen);
    return ctx->state == DRBG_READY;
}

int EVP_RAND_CTX_reseed(EVP_RAND_CTX *ctx, const void *adin, size_t adin_len,
                        int prediction_resistance)
{
    int res = 0;

    if (ctx == NULL || !evp_rand_ctx_lock(ctx))
        return 1;
    res = evp_rand_ctx_do_reseed(ctx, adin, adin_len, prediction_resistance);
    evp_rand_ctx_unlock(ctx);
    return res;
}

int evp_rand_ctx_need_reseed(EVP_RAND_CTX *ctx)
{
    unsigned int parent_counter;

    if (ctx == NULL || ctx->meth->reseed == NULL)
        return 0;

    if (ctx->reseed_interval > 0
            && ctx->reseed_gen_counter > ctx->reseed_interval)
        return 1;
    if (ctx->fork_id != openssl_get_fork_id())
        return 1;
    if (ctx->reseed_time_interval > 0) {
        time_t now = time(NULL);

        if (now < ctx->reseed_time
                || now - ctx->reseed_time >= ctx->reseed_time_interval)
            return 1;
    }
    if (ctx->parent != NULL) {
        unsigned int reseed_counter = tsan_load(&ctx->reseed_prop_counter);

        if (reseed_counter > 0) {
            parent_counter = tsan_load(&ctx->parent->reseed_prop_counter);
            if (parent_counter > 0 && parent_counter != reseed_counter)
                return 1;
        }
    }
    return 0;
}

/*
 * Calculates the minimum length of a full entropy buffer
 * which is necessary to seed (i.e. instantiate) the DRBG
 * successfully.
 */
size_t evp_rand_seedlen(EVP_RAND_CTX *ctx)
{
    /*
     * If no os entropy source is available then RAND_seed(buffer, bufsize)
     * is expected to succeed if and only if the buffer length satisfies
     * the following requirements, which follow from the calculations
     * in RAND_DRBG_instantiate().
     */
    size_t min_entropy = ctx->strength;
    size_t min_entropylen = ctx->min_entropylen;

    /*
     * Extra entropy for the random nonce in the absence of a
     * get_nonce callback, see comment in RAND_DRBG_instantiate().
     */
    if (ctx->min_noncelen > 0 && ctx->meth->get_nonce == NULL) {
        min_entropy += ctx->strength / 2;
        min_entropylen += ctx->min_noncelen;
    }

    /*
     * Convert entropy requirement from bits to bytes
     * (dividing by 8 without rounding upwards, because
     * all entropy requirements are divisible by 8).
     */
    min_entropy >>= 3;

    /* Return a value that satisfies both requirements */
    return min_entropy > min_entropylen ? min_entropy : min_entropylen;
}

/*
 * Generate |outlen| bytes into the buffer at |out|.  Reseed if we need
 * to or if |prediction_resistance| is set.  Additional input can be
 * sent in |adin| and |adinlen|.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 *
 */
int EVP_RAND_CTX_generate(EVP_RAND_CTX *ctx, void *out, size_t outlen,
                          const void *adin, size_t adin_len,
                          int prediction_resistance)
{
    int res = 0;

    if (outlen == 0)
        return 1;
    if (ctx == NULL || out == NULL || !evp_rand_ctx_lock(ctx))
        return 0;

    if (ctx->state != DRBG_READY) {
        /* try to recover from previous errors */
        /*evp_rand_restart(ctx, NULL, 0, 0);*/
        if (ctx->state == DRBG_ERROR) {
            ERR_raise(ERR_LIB_EVP, RAND_R_IN_ERROR_STATE);
            goto end;
        }
        if (ctx->state == DRBG_UNINITIALISED) {
            ERR_raise(ERR_LIB_EVP, RAND_R_NOT_INSTANTIATED);
            goto end;
        }
    }

    if (outlen > ctx->max_request) {
        ERR_raise(ERR_LIB_EVP, RAND_R_REQUEST_TOO_LARGE_FOR_DRBG);
        goto end;
    }
    if (adin_len > ctx->max_adinlen) {
        ERR_raise(ERR_LIB_EVP, RAND_R_ADDITIONAL_INPUT_TOO_LONG);
        goto end;
    }

    if (prediction_resistance || evp_rand_ctx_need_reseed(ctx)) {
        /* MORE here, reseed parent first */
        if (prediction_resistance
                && ctx->parent != NULL
                && !EVP_RAND_CTX_reseed(ctx->parent, adin, adin_len, 1))
            goto end;
        if (!ctx->meth->reseed(ctx->data, NULL, 0, adin, adin_len))
            goto end;
        adin = NULL;
        adin_len = 0;
    }

    if (!ctx->meth->generate(ctx->data, out, outlen, adin, adin_len)) {
        ctx->state = DRBG_ERROR;
        ERR_raise(ERR_LIB_EVP, RAND_R_GENERATE_ERROR);
        goto end;
    }

    ctx->reseed_gen_counter++;
    res = 1;

end:
    evp_rand_ctx_unlock(ctx);
    return res;
}

static int evp_rand_ctx_get_params(EVP_RAND_CTX *ctx)
{
    OSSL_PARAM params[10], *p = params;

    ctx->strength = 0;
    ctx->max_request = ctx->min_entropylen = ctx->max_entropylen = 0;
    ctx->min_noncelen = ctx->max_noncelen = ctx->max_perslen = 0;
    ctx->max_adinlen = ctx->seedlen = 0;
    if (ctx->meth->get_ctx_params != NULL)
        return 0;

    *p++ = OSSL_PARAM_construct_int(OSSL_RAND_PARAM_STRENGTH, &ctx->strength);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_REQUEST,
                                       &ctx->max_request);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MIN_ENTROPYLEN,
                                       &ctx->min_entropylen);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_ENTROPYLEN,
                                       &ctx->max_entropylen);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MIN_NONCELEN,
                                       &ctx->min_noncelen);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_NONCELEN,
                                       &ctx->max_noncelen);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_PERSLEN,
                                       &ctx->max_perslen);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_ADINLEN,
                                       &ctx->max_adinlen);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_SEEDLEN,
                                       &ctx->seedlen);
    *p++ = OSSL_PARAM_construct_end();
    return ctx->meth->get_ctx_params(ctx->data, params);
}

int EVP_RAND_CTX_instantiate(EVP_RAND_CTX *ctx,
                             const unsigned char *pers, size_t perslen)
{
    unsigned char *nonce = NULL, *entropy = NULL;
    size_t noncelen = 0, entropylen = 0;
    size_t min_entropy, min_entropylen, max_entropylen;
    int seperate_nonce = 1;
    DRBG_STATUS state;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_NULL_CONTEXT);
        return 0;
    }
    if (!evp_rand_ctx_lock(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNABLE_TO_LOCK_CONTEXT);
        return 0;
    }

    if (!evp_rand_ctx_get_params(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_UNABLE_TO_GET_PARAMS);
        goto end;
    }
    if (ctx->meth->instantiate == NULL) {
        ctx->state = DRBG_READY;
        goto end;
    }
    min_entropy = ctx->strength;
    min_entropylen = ctx->min_entropylen;
    max_entropylen = ctx->max_entropylen;

    if (pers == NULL) {
        pers = (const unsigned char *)ossl_pers_string;
        perslen = sizeof(ossl_pers_string) - 1;
        if (perslen > ctx->max_perslen)
            perslen = ctx->max_perslen;
    } else if (perslen > ctx->max_perslen) {
        ERR_raise(ERR_LIB_EVP, RAND_R_PERSONALISATION_STRING_TOO_LONG);
        goto end;
    }

    if (ctx->meth == NULL) {
        ERR_raise(ERR_LIB_EVP, RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED);
        goto end;
    }

    if (ctx->state != DRBG_UNINITIALISED) {
        if (ctx->state == DRBG_ERROR)
            ERR_raise(ERR_LIB_EVP, RAND_R_IN_ERROR_STATE);
        else
            ERR_raise(ERR_LIB_EVP, RAND_R_ALREADY_INSTANTIATED);
        goto end;
    }

    ctx->state = DRBG_ERROR;

    ctx->reseed_next_counter = tsan_load(&ctx->reseed_prop_counter);
    if (ctx->reseed_next_counter) {
        ctx->reseed_next_counter++;
        if (!ctx->reseed_next_counter)
            ctx->reseed_next_counter = 1;
    }

    /*
     * NIST SP800-90Ar1 section 9.1 says you can combine getting the entropy
     * and nonce in 1 call by increasing the entropy with 50% and increasing
     * the minimum length to accommodate the length of the nonce.
     * We do this in case a nonce is required.
     */
    seperate_nonce = ctx->min_noncelen > 0 && ctx->meth->get_nonce != NULL;
    noncelen = ctx->strength / 2;
    if (!seperate_nonce) {
        min_entropy += noncelen;
        min_entropylen += ctx->min_noncelen;
        max_entropylen += ctx->max_noncelen;
    }
    if (ctx->parent != NULL) {
        entropylen = get_entropy(ctx, &entropy, min_entropy,
                                 min_entropylen, max_entropylen, 0);
        if (entropylen == 0) {
            ERR_raise(ERR_LIB_EVP, RAND_R_ERROR_RETRIEVING_ENTROPY);
            goto end;
        }
        if (seperate_nonce) {
            nonce = OPENSSL_malloc(ctx->min_noncelen);
            if (nonce == NULL) {
                ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                goto end;
            }
            noncelen = ctx->meth->get_nonce(ctx, nonce, ctx->min_noncelen);
            if (noncelen == 0) {
                ERR_raise(ERR_LIB_EVP, RAND_R_ERROR_RETRIEVING_NONCE);
                goto end;
            }
        } else if (entropylen > noncelen) {
            entropylen -= noncelen;
            noncelen = noncelen;
            nonce = entropy + entropylen;
        } else {
            ERR_raise(ERR_LIB_EVP, RAND_R_ERROR_EXTRACTING_NONCE);
            goto end;
        }
    }

    if (!ctx->meth->instantiate(ctx->data, entropy, entropylen,
                                nonce, noncelen, pers, perslen)) {
        ERR_raise(ERR_LIB_EVP, RAND_R_ERROR_INSTANTIATING_DRBG);
        goto end;
    }

    ctx->state = DRBG_READY;
    ctx->reseed_gen_counter = 1;
    ctx->reseed_time = time(NULL);
    tsan_store(&ctx->reseed_prop_counter, ctx->reseed_next_counter);

 end:
    OPENSSL_secure_clear_free(entropy, entropylen);
    if (seperate_nonce)
        OPENSSL_secure_clear_free(nonce, noncelen);
    state = ctx->state;
    evp_rand_ctx_unlock(ctx);

    return state == DRBG_READY;
}

int EVP_RAND_CTX_uninstantiate(EVP_RAND_CTX *ctx)
{
    int res = 1;

    if (ctx == NULL || !evp_rand_ctx_lock(ctx))
        return 0;
    if (ctx->meth->uninstantiate != NULL)
        res = ctx->meth->uninstantiate(ctx->data);
    evp_rand_ctx_unlock(ctx);
    return res;
}

int EVP_RAND_CTX_seed(EVP_RAND_CTX *ctx,
                      const unsigned char *ent, size_t ent_len,
                      double randomness)
{
    int res = 0;

    if (ctx == NULL || randomness < 0.0)
        return 0;
    if (ent == NULL && (ent_len > 0 || randomness > 0.))
        return 0;
    if (!evp_rand_ctx_lock(ctx))
        return 0;
    if (ctx->meth->reseed == NULL) {
        evp_rand_ctx_unlock(ctx->data);
        return 1;
    }
    ctx->state = DRBG_ERROR;
    if (ctx->seedlen == 0)
        goto fin;
#ifdef FIPS_MODE
    /*
     * NIST SP-800-90A mandates that entropy *shall not* be provided
     * by the consuming application. By setting the randomness to zero,
     * we ensure that the buffer contents will be added to the internal
     * state of the DRBG only as additional data.
     *
     * (NIST SP-800-90Ar1, Sections 9.1 and 9.2)
     */
    randomness = 0.0;
#endif

    if (ent_len < ctx->seedlen || randomness < (double)ctx->seedlen) {
        if (ctx->max_adinlen < ent_len) {
            ERR_raise(ERR_LIB_EVP, RAND_R_ADDITIONAL_INPUT_TOO_LONG);
            goto fin;
        }
#if defined(OPENSSL_RAND_SEED_NONE)
        /*
         * If no os entropy source is available, a reseeding will fail
         * inevitably. So we use a trick to mix the buffer contents into
         * the DRBG state without forcing a reseeding: we generate a
         * dummy random byte, using the buffer content as additional data.
         * Note: This won't work with RAND_DRBG_FLAG_CTR_NO_DF.
         */
        unsigned char dummy[1];

        res = ctx->meth->generate(ctx->data, dummy, sizeof(dummy),
                                  ent, ent_len, 0);
#else
        /*
         * If an OS entropy source is available then we declare the buffer
         * content as additional data and trigger a regular reseeding.
         */
        res = ctx->meth->reseed(ctx->data, NULL, 0, ent, ent_len);
#endif
        goto fin;
    }

    if (randomness > 0.) {
        if (ctx->max_entropylen < ent_len) {
            ERR_raise(ERR_LIB_EVP, RAND_R_ENTROPY_INPUT_TOO_LONG);
            goto fin;
        }
        if (randomness > (double)(8 * ent_len)) {
            ERR_raise(ERR_LIB_EVP, RAND_R_ENTROPY_OUT_OF_RANGE);
            goto fin;
        }
    }
    if (randomness > (double)ctx->seedlen) {
        /*
         * The purpose of this check is to bound |randomness| by a
         * relatively small value in order to prevent an integer
         * overflow when multiplying by 8. Note that randomness is
         * measured in bytes, not bits, so this value corresponds to
         * eight times the security strength.
         */
        randomness = (double)ctx->seedlen;
    }
    if (randomness > 0.)
        res = ctx->meth->reseed(ctx->data, ent, ent_len, NULL, 0);
    else
        res = ctx->meth->reseed(ctx->data, NULL, 0, ent, ent_len);

fin:
    if (res)
        ctx->state = DRBG_READY;
    evp_rand_ctx_unlock(ctx);
    return res;
}

/*
 * The {get,set}_params functions return 1 if there is no corresponding
 * function in the implementation.  This is the same as if there was one,
 * but it didn't recognise any of the given params, i.e. nothing in the
 * bag of parameters was useful.
 */
int EVP_RAND_get_params(EVP_RAND *rand, OSSL_PARAM params[])
{
    if (rand->get_params != NULL)
        return rand->get_params(params);
    return 1;
}

int EVP_RAND_CTX_get_params(EVP_RAND_CTX *ctx, OSSL_PARAM params[])
{
    if (ctx->meth->get_ctx_params != NULL)
        return ctx->meth->get_ctx_params(ctx->data, params);
    return 1;
}

int EVP_RAND_CTX_set_params(EVP_RAND_CTX *ctx, const OSSL_PARAM params[])
{
    if (ctx->meth->set_ctx_params != NULL)
        return ctx->meth->set_ctx_params(ctx->data, params);
    return 1;
}

static int evp_rand_up_ref(void *vrand)
{
    EVP_RAND *rand = (EVP_RAND *)vrand;
    int ref = 0;

    CRYPTO_UP_REF(&rand->refcnt, &ref, rand->lock);
    return 1;
}

static void evp_rand_free(void *vrand){
    EVP_RAND *rand = (EVP_RAND *)vrand;
    int ref = 0;

    if (rand != NULL) {
        CRYPTO_DOWN_REF(&rand->refcnt, &ref, rand->lock);
        if (ref <= 0) {
            ossl_provider_free(rand->prov);
            CRYPTO_THREAD_lock_free(rand->lock);
            OPENSSL_free(rand);
        }
    }
}

static void *evp_rand_new(void)
{
    EVP_RAND *rand = NULL;

    if ((rand = OPENSSL_zalloc(sizeof(*rand))) == NULL
        || (rand->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        OPENSSL_free(rand);
        return NULL;
    }
    rand->refcnt = 1;
    return rand;
}

static void *evp_rand_from_dispatch(int name_id,
                                    const OSSL_DISPATCH *fns,
                                    OSSL_PROVIDER *prov)
{
    EVP_RAND *rand = NULL;
    int fnrandcnt = 0, fnctxcnt = 0;

    if ((rand = evp_rand_new()) == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    rand->name_id = name_id;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_RAND_NEWCTX:
            if (rand->newctx != NULL)
                break;
            rand->newctx = OSSL_get_OP_rand_newctx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_RAND_FREECTX:
            if (rand->freectx != NULL)
                break;
            rand->freectx = OSSL_get_OP_rand_freectx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_RAND_INSTANTIATE:
            if (rand->instantiate != NULL)
                break;
            rand->instantiate = OSSL_get_OP_rand_instantiate(fns);
            break;
        case OSSL_FUNC_RAND_UNINSTANTIATE:
            if (rand->uninstantiate != NULL)
                break;
            rand->uninstantiate = OSSL_get_OP_rand_uninstantiate(fns);
            break;
        case OSSL_FUNC_RAND_RESEED:
            if (rand->reseed != NULL)
                break;
            rand->reseed = OSSL_get_OP_rand_reseed(fns);
            break;
        case OSSL_FUNC_RAND_GENERATE:
            if (rand->generate != NULL)
                break;
            rand->generate = OSSL_get_OP_rand_generate(fns);
            fnrandcnt++;
            break;
        case OSSL_FUNC_RAND_GETTABLE_PARAMS:
            if (rand->gettable_params != NULL)
                break;
            rand->gettable_params =
                OSSL_get_OP_rand_gettable_params(fns);
            break;
        case OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS:
            if (rand->gettable_ctx_params != NULL)
                break;
            rand->gettable_ctx_params =
                OSSL_get_OP_rand_gettable_ctx_params(fns);
            break;
        case OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS:
            if (rand->settable_ctx_params != NULL)
                break;
            rand->settable_ctx_params =
                OSSL_get_OP_rand_settable_ctx_params(fns);
            break;
        case OSSL_FUNC_RAND_GET_PARAMS:
            if (rand->get_params != NULL)
                break;
            rand->get_params = OSSL_get_OP_rand_get_params(fns);
            break;
        case OSSL_FUNC_RAND_GET_CTX_PARAMS:
            if (rand->get_ctx_params != NULL)
                break;
            rand->get_ctx_params = OSSL_get_OP_rand_get_ctx_params(fns);
            break;
        case OSSL_FUNC_RAND_SET_CTX_PARAMS:
            if (rand->set_ctx_params != NULL)
                break;
            rand->set_ctx_params = OSSL_get_OP_rand_set_ctx_params(fns);
            break;
        }
    }
    if (fnrandcnt != 1 || fnctxcnt != 2) {
        /*
         * In order to be a consistent set of functions we must have at least
         * a get bytes function, and a complete set of context management
         * functions.
         */
        evp_rand_free(rand);
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        return NULL;
    }
    rand->prov = prov;
    if (prov != NULL)
        ossl_provider_up_ref(prov);

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

const OSSL_PARAM *EVP_RAND_gettable_params(const EVP_RAND *rand)
{
    if (rand->gettable_params == NULL)
        return NULL;
    return rand->gettable_params();
}

const OSSL_PARAM *EVP_RAND_gettable_ctx_params(const EVP_RAND *rand)
{
    if (rand->gettable_ctx_params == NULL)
        return NULL;
    return rand->gettable_ctx_params();
}

const OSSL_PARAM *EVP_RAND_settable_ctx_params(const EVP_RAND *rand)
{
    if (rand->settable_ctx_params == NULL)
        return NULL;
    return rand->settable_ctx_params();
}

void EVP_RAND_do_all_ex(OPENSSL_CTX *libctx,
                       void (*fn)(EVP_RAND *rand, void *arg),
                       void *arg)
{
    evp_generic_do_all(libctx, OSSL_OP_RAND,
                       (void (*)(void *, void *))fn, arg,
                       evp_rand_from_dispatch, evp_rand_free);
}
