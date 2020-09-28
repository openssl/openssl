/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/e_os2.h>
#include <openssl/params.h>
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/provider_util.h"
#include "prov/implementations.h"
#include "drbg_local.h"

static OSSL_FUNC_rand_newctx_fn test_rng_new_wrapper;
static OSSL_FUNC_rand_freectx_fn test_rng_free;
static OSSL_FUNC_rand_instantiate_fn test_rng_instantiate_wrapper;
static OSSL_FUNC_rand_uninstantiate_fn test_rng_uninstantiate_wrapper;
static OSSL_FUNC_rand_generate_fn test_rng_generate_wrapper;
static OSSL_FUNC_rand_reseed_fn test_rng_reseed_wrapper;
static OSSL_FUNC_rand_nonce_fn test_rng_nonce;
static OSSL_FUNC_rand_settable_ctx_params_fn test_rng_settable_ctx_params;
static OSSL_FUNC_rand_set_ctx_params_fn test_rng_set_ctx_params;
static OSSL_FUNC_rand_gettable_ctx_params_fn test_rng_gettable_ctx_params;
static OSSL_FUNC_rand_get_ctx_params_fn test_rng_get_ctx_params;
static OSSL_FUNC_rand_verify_zeroization_fn test_rng_verify_zeroization;

typedef struct {
    unsigned char *entropy, *nonce;
    size_t entropy_len, entropy_pos, nonce_len;
    unsigned int strength;
} PROV_TEST_RNG;

static int test_rng_new(PROV_DRBG *ctx)
{
    PROV_TEST_RNG *t;

    t = OPENSSL_zalloc(sizeof(*t));
    if (t == NULL)
        return 0;
    ctx->data = t;
    ctx->seedlen = INT_MAX;
    ctx->max_entropylen = INT_MAX;
    ctx->max_noncelen = INT_MAX;
    ctx->max_perslen = INT_MAX;
    ctx->max_adinlen = INT_MAX;
    ctx->max_request = INT_MAX;
    return 1;
}

static void test_rng_free(void *vdrbg)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;
    PROV_TEST_RNG *t = (PROV_TEST_RNG *)drbg->data;

    OPENSSL_free(t->entropy);
    OPENSSL_free(t->nonce);
    OPENSSL_free(drbg->data);
    prov_rand_drbg_free(drbg);
}

static int test_rng_instantiate(PROV_DRBG *drbg,
                                const unsigned char *ent, size_t ent_len,
                                const unsigned char *nonce, size_t nonce_len,
                                const unsigned char *pstr, size_t pstr_len)
{
    PROV_TEST_RNG *t = (PROV_TEST_RNG *)drbg->data;

    if (ent != NULL && (ent_len < drbg->min_entropylen
                        || ent_len >= drbg->max_entropylen))
        return 0;
    if (nonce != NULL && (nonce_len < drbg->min_noncelen
                        || nonce_len >= drbg->max_noncelen))
        return 0;
    if (pstr != NULL && pstr_len >= drbg->max_perslen)
        return 0;

    t->entropy_pos = 0;
    return 1;
}

static int test_rng_instantiate_wrapper(void *vdrbg, unsigned int strength,
                                        int prediction_resistance,
                                        const unsigned char *pstr,
                                        size_t pstr_len)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;

    if (pstr != NULL && pstr_len >= drbg->max_perslen)
        return 0;

    return ossl_prov_drbg_instantiate(drbg, strength, prediction_resistance,
                                      pstr, pstr_len);
}

static int test_rng_uninstantiate(PROV_DRBG *drbg)
{
    PROV_TEST_RNG *t = (PROV_TEST_RNG *)drbg->data;

    t->entropy_pos = 0;
    return ossl_prov_drbg_uninstantiate(drbg);
}

static int test_rng_uninstantiate_wrapper(void *vdrbg)
{
    return test_rng_uninstantiate((PROV_DRBG *)vdrbg);
}

static int test_rng_generate(PROV_DRBG *drbg,
                             unsigned char *out, size_t outlen,
                             const unsigned char *adin, size_t adin_len)
{
    PROV_TEST_RNG *t = (PROV_TEST_RNG *)drbg->data;
    size_t i;

    if (t->entropy == NULL || (adin != NULL && adin_len >= drbg->max_adinlen))
        return 0;

    for (i = 0; i < outlen; i++) {
        out[i] = t->entropy[t->entropy_pos++];
        if (t->entropy_pos >= t->entropy_len)
            break;
    }
    return 1;
}

static int test_rng_generate_wrapper
    (void *vdrbg, unsigned char *out, size_t outlen,
      unsigned int strength, int prediction_resistance,
      const unsigned char *adin, size_t adin_len)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;

    if (strength > drbg->strength)
        return 0;
    return test_rng_generate(drbg, out, outlen, adin, adin_len);
}

static int test_rng_reseed(PROV_DRBG *drbg,
                            const unsigned char *ent, size_t ent_len,
                            const unsigned char *adin, size_t adin_len)
{
    if (ent != NULL && (ent_len < drbg->min_entropylen
                        || ent_len >= drbg->max_entropylen))
        return 0;
    if (adin != NULL && adin_len >= drbg->max_adinlen)
        return 0;

    return 1;
}

static int test_rng_reseed_wrapper(void *vdrbg, int prediction_resistance,
                                   const unsigned char *ent, size_t ent_len,
                                   const unsigned char *adin, size_t adin_len)
{
    return test_rng_reseed((PROV_DRBG *)vdrbg, ent, ent_len, adin, adin_len);
}

static size_t test_rng_nonce(void *vdrbg, unsigned char *out,
                             unsigned int strength, size_t min_noncelen,
                             size_t max_noncelen)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;
    PROV_TEST_RNG *t = (PROV_TEST_RNG *)drbg->data;

    if (t->nonce == NULL
            || strength > drbg->strength
            || min_noncelen > t->nonce_len
            || max_noncelen < t->nonce_len)
        return 0;

    if (out != NULL)
        memcpy(out, t->nonce, t->nonce_len);
    return t->nonce_len;
}

static int test_rng_get_ctx_params(void *vdrbg, OSSL_PARAM params[])
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;

    return drbg_get_ctx_params(drbg, params);
}

static const OSSL_PARAM *test_rng_gettable_ctx_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_DRBG_GETTABLE_CTX_COMMON,
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

static int set_size_t(const OSSL_PARAM *params, const char *name,
                            size_t *val)
{
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, name);

    return p == NULL || OSSL_PARAM_get_size_t(p, val);
}

static int test_rng_set_ctx_params(void *vdrbg, const OSSL_PARAM params[])
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;
    PROV_TEST_RNG *t = (PROV_TEST_RNG *)drbg->data;
    const OSSL_PARAM *p;
    void *ptr = NULL;
    size_t size = 0;
    unsigned int uint;

    p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &drbg->strength))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_TEST_ENTROPY);
    if (p != NULL) {
        if (!OSSL_PARAM_get_octet_string(p, &ptr, 0, &size))
            return 0;
        OPENSSL_free(t->entropy);
        t->entropy = ptr;
        t->entropy_len = size;
        t->entropy_pos = 0;
        ptr = NULL;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_TEST_NONCE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_octet_string(p, &ptr, 0, &size))
            return 0;
        OPENSSL_free(t->nonce);
        t->nonce = ptr;
        t->nonce_len = size;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_COUNTER);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &uint))
            return 0;
        tsan_store(&drbg->reseed_counter, uint);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RESEED_TIME);
    if (p != NULL && !OSSL_PARAM_get_time_t(p, &drbg->reseed_time))
        return 0;

    if (!set_size_t(params, OSSL_DRBG_PARAM_MAX_REQUEST, &drbg->max_request)
            || !set_size_t(params, OSSL_DRBG_PARAM_MIN_ENTROPYLEN,
                           &drbg->min_entropylen)
            || !set_size_t(params, OSSL_DRBG_PARAM_MAX_ENTROPYLEN,
                           &drbg->max_entropylen)
            || !set_size_t(params, OSSL_DRBG_PARAM_MIN_NONCELEN,
                           &drbg->min_noncelen)
            || !set_size_t(params, OSSL_DRBG_PARAM_MAX_NONCELEN,
                           &drbg->max_noncelen)
            || !set_size_t(params, OSSL_DRBG_PARAM_MAX_PERSLEN,
                           &drbg->max_perslen)
            || !set_size_t(params, OSSL_DRBG_PARAM_MAX_ADINLEN,
                           &drbg->max_adinlen))
        return 0;
    return drbg_set_ctx_params(drbg, params);
}

static const OSSL_PARAM *test_rng_settable_ctx_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_RAND_PARAM_TEST_NONCE, NULL, 0),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MIN_ENTROPYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_ENTROPYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MIN_NONCELEN, NULL),
        OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_NONCELEN, NULL),
        OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_PERSLEN, NULL),
        OSSL_PARAM_size_t(OSSL_DRBG_PARAM_MAX_ADINLEN, NULL),
        OSSL_PARAM_uint(OSSL_DRBG_PARAM_RESEED_COUNTER, NULL),
        OSSL_PARAM_time_t(OSSL_DRBG_PARAM_RESEED_TIME, NULL),
        OSSL_PARAM_DRBG_SETTABLE_CTX_COMMON,
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int test_rng_verify_zeroization(void *vdrbg)
{
    return 1;
}

static void *test_rng_new_wrapper(void *provctx, void *parent,
                                   const OSSL_DISPATCH *parent_dispatch)
{
    return prov_rand_drbg_new(provctx, parent, parent_dispatch,
                              &test_rng_new, &test_rng_instantiate,
                              &test_rng_uninstantiate, &test_rng_reseed,
                              &test_rng_generate);
}

const OSSL_DISPATCH ossl_test_rng_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void(*)(void))test_rng_new_wrapper },
    { OSSL_FUNC_RAND_FREECTX, (void(*)(void))test_rng_free },
    { OSSL_FUNC_RAND_INSTANTIATE,
      (void(*)(void))test_rng_instantiate_wrapper },
    { OSSL_FUNC_RAND_UNINSTANTIATE,
      (void(*)(void))test_rng_uninstantiate_wrapper },
    { OSSL_FUNC_RAND_GENERATE, (void(*)(void))test_rng_generate_wrapper },
    { OSSL_FUNC_RAND_RESEED, (void(*)(void))test_rng_reseed_wrapper },
    { OSSL_FUNC_RAND_NONCE, (void(*)(void))test_rng_nonce },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void(*)(void))drbg_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void(*)(void))drbg_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void(*)(void))drbg_unlock },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
      (void(*)(void))test_rng_settable_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void(*)(void))test_rng_set_ctx_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
      (void(*)(void))test_rng_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))test_rng_get_ctx_params },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
      (void(*)(void))test_rng_verify_zeroization },
    { 0, NULL }
};
