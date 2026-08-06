/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/rand.h>
#include <openssl/core_dispatch.h>
#include <openssl/e_os2.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/randerr.h>
#include <openssl/proverr.h>
#include <openssl/self_test.h>
#include "internal/common.h"
#include "internal/cryptlib.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "crypto/rand.h"
#include "crypto/rand_pool.h"

#ifndef OPENSSL_NO_CPURNG
#include "providers/implementations/rands/seed_src_cpurng.inc"

static OSSL_FUNC_rand_newctx_fn cpurng_new;
static OSSL_FUNC_rand_freectx_fn cpurng_free;
static OSSL_FUNC_rand_instantiate_fn cpurng_instantiate;
static OSSL_FUNC_rand_uninstantiate_fn cpurng_uninstantiate;
static OSSL_FUNC_rand_generate_fn cpurng_generate;
static OSSL_FUNC_rand_reseed_fn cpurng_reseed;
static OSSL_FUNC_rand_gettable_ctx_params_fn cpurng_gettable_ctx_params;
static OSSL_FUNC_rand_get_ctx_params_fn cpurng_get_ctx_params;
static OSSL_FUNC_rand_verify_zeroization_fn cpurng_verify_zeroization;
static OSSL_FUNC_rand_enable_locking_fn cpurng_enable_locking;
static OSSL_FUNC_rand_lock_fn cpurng_lock;
static OSSL_FUNC_rand_unlock_fn cpurng_unlock;
static OSSL_FUNC_rand_get_seed_fn cpurng_get_seed;
static OSSL_FUNC_rand_clear_seed_fn cpurng_clear_seed;

#if defined(__i386) || defined(__i386__) || defined(_M_IX86) || defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
#if defined(OPENSSL_RAND_SEED_RDCPU)
#define CPURNG_AVAILABLE 1
#endif
#endif

#if defined(CPURNG_AVAILABLE)
uint64_t OPENSSL_ia32_cpuver_info(void);
size_t OPENSSL_ia32_rdseed_bytes(unsigned char *buf, size_t len);
#else
#if defined(OPENSSL_RAND_SEED_NONE) || !defined(OPENSSL_RAND_SEED_GETRANDOM)
#error Fallback seeding type unacceptable
#endif
#endif

#if defined(CPURNG_AVAILABLE)
/*
 * We return an array of uint8_t in a unit64_t
 *
 * [ 00, Family, Model, Stepping ]
 */
static void cpurng_ver_parse(uint8_t *family, uint8_t *model, uint8_t *stepping)
{
    uint64_t cpurng_ver;

    cpurng_ver = OPENSSL_ia32_cpuver_info();
    /* First 4 bits are stepping */
    *stepping = cpurng_ver & 0xf;

    cpurng_ver >>= 4;

    /* Next are First 4 bits of model ID */
    *model = cpurng_ver & 0xf;

    cpurng_ver >>= 4;

    /* First 4 bit of FamilyID */
    *family = cpurng_ver & 0xf;

    if (*family == 0x06 || *family == 0x0f) {
        /* We ignore the type and the next 2 reserved bits */
        cpurng_ver >>= 8;

        /* Extend Model ID */
        *model += cpurng_ver & 0x0f;

        cpurng_ver >>= 4;
    }

    if (*family == 0x0f) {
        *family += cpurng_ver & 0xff;
    }
}

struct cpurng_models {
    uint8_t family;
    uint8_t model;
    uint8_t stepping;
    uint8_t entropy_factor;
};

/* CPU Models from:
 * https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/entropy/E164_PublicUse.pdf
 * https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/entropy/E293_PublicUse.pdf
 * https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/entropy/E27_PublicUse.pdf
 * https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/entropy/E183_PublicUse.pdf
 */
const struct cpurng_models validated_models[] = {
    /* E164 */
    /* Intel Sky Lake-18 FCBGA2518 */
    /* Intel Sky Lake/Cascade Lake - 10/18/28 FCLGA3647 */
    { 0x06, 0x55, 0x04, 1 },
    { 0x06, 0x55, 0x07, 1 },
    /* Intel Broadwell DE */
    /*Intel  Cooper Lake */
    { 0x06, 0x56, 0x02, 1 },
    { 0x06, 0x56, 0x03, 1 },
    { 0x06, 0x56, 0x04, 1 },
    { 0x06, 0x56, 0x05, 1 },

    /* E293 */
    /* Ice Lake D */
    { 0x06, 0x6c, 0xff, 1 },
    /* Ice Lake */
    { 0x06, 0x7d, 0xff, 1 },
    /* Sapphire Rapids */
    { 0x06, 0x8f, 0xff, 1 },
    /* Emeral Rapids */
    { 0x06, 0xcf, 0xff, 1 },

#if 0 /* It is unclear if AMD CPUs can produce full entropy so this is currently disabled */
    /* E27 */
    /* EPYC 7xx2 */
    { 0x17, 0x31, 0x00 },
    /* EPYC 7xx3 */
    { 0x19, 0x01, 0x01 },
    /* EPYC 9xx4/8xx4 */
    { 0x19, 0x17, 0x01 },
    /* EPYC 3xxx */
    { 0x17, 0x01, 0x02 },
    /* Ryzen V1xxxx */
    { 0x17, 0x18, 0x01 },
    /* Ryzen V3xxxx */
    { 0x19, 0x44, 0x00 },
    /* Ryzen V2xxxx */
    { 0x17, 0x60, 0x01 },
    /* Ryzen V5xxxE */
    { 0x19, 0x21, 0x00 },

    /* E183 */
    /* ??? no CPUIDs in the public use document */
    { 0xff, 0xff, 0xff, 0 },
#endif
};

static int cpurng_validated(void)
{
    uint8_t family, model, stepping;

    /* No RDSEED support */
    if ((OPENSSL_ia32cap_P[2] & (1 << 18)) == 0)
        return -1;
#ifdef OPENSSL_CPURNG_RELAXED
    else
        return 1;
#endif

    cpurng_ver_parse(&family, &model, &stepping);

    for (int i = 0; validated_models[i].family != 0xff; i++) {
        /* Stepping is not always easy to find, but looks like for Intel all
         * steppings within a given family are covered by the certificates
         * so far, so when stepping is set to 0xff (an impossible value) we
         * skip the check */
        if (family != validated_models[i].family)
            continue;
        if (model != validated_models[i].model)
            continue;
        if (stepping == 0xff || stepping == validated_models[i].stepping)
            return validated_models[i].entropy_factor;
    }

#if defined(FIPS_MODULE) && defined(OPENSSL_CPURNG_VALIDATED)
    return -1;
#else
    return 0;
#endif
}

/*
 * Acquire entropy from cpu
 *
 * Returns the total entropy count, if it exceeds the requested
 * entropy count. Otherwise, returns an entropy count of 0.
 */
static size_t cpurng_acquire_cpu_entropy(RAND_POOL *pool, int entropy_factor)
{
    size_t bytes_needed;
    unsigned char *buffer;

    bytes_needed = ossl_rand_pool_bytes_needed(pool, entropy_factor);
    if (bytes_needed > 0) {
        buffer = ossl_rand_pool_add_begin(pool, bytes_needed);

        if (buffer != NULL) {
            if (OPENSSL_ia32_rdseed_bytes(buffer, bytes_needed) == bytes_needed) {
                ossl_rand_pool_add_end(pool, bytes_needed, 8 * bytes_needed);
            } else {
                ossl_rand_pool_add_end(pool, 0, 0);
            }
        }
    }

    return ossl_rand_pool_entropy_available(pool);
}

#else
/* Architecture currently unsupported */
static int cpurng_validated(void)
{
#ifdef OPENSSL_CPURNG_VALIDATED
#error This architecture has no validated HW RNG
#else
    return 0;
#endif
}
#endif

typedef struct {
    void *provctx;
    int entropy_factor;
    int state;
} PROV_CPURNG;

/* We always seed an additional pool here that we then mix in.
 * If the RDSEED can credit entropy, then RDSEED is the
 * primary and we simply add OS retrieved entropy for good measure without
 * crediting it actual entropy.
 * If RDSEED is not available or can't be used for crediting entropy, we
 * use the OS entropy as primary and mix in RDSEED when available
 */
static size_t cpurng_acquire_entropy(PROV_CPURNG *s, RAND_POOL *pool)
{
    RAND_POOL *os_pool = NULL;
    size_t entropy_available = 0;
    size_t os_entropy = 0;

#if defined(CPURNG_AVAILABLE)
    if (s->entropy_factor > 0) {
        entropy_available = cpurng_acquire_cpu_entropy(pool, s->entropy_factor);
#if !defined(OPENSSL_CPURNG_RELAXED)
        if (entropy_available == 0)
            return 0;
#endif
#if !defined(OPENSSL_CPURNG_CONSERVATIVE)
        if (entropy_available > 0)
            return entropy_available;
#endif
    }
#endif

    if (entropy_available) {
        /* pool for mix-in */
        size_t entropy = ossl_rand_pool_entropy(pool);
        size_t len = ossl_rand_pool_length(pool);
        os_pool = ossl_rand_pool_new(entropy, 1, len, len);
    } else {
        os_pool = pool;
    }

    /* OS provided entropy */
    os_entropy = ossl_pool_acquire_entropy(os_pool);
    if (os_entropy == 0) {
        entropy_available = 0;
        goto done;
    }

    if (entropy_available) {
        if (!ossl_rand_pool_adin_mix_in(pool,
                ossl_rand_pool_buffer(os_pool),
                ossl_rand_pool_length(os_pool))) {
            entropy_available = 0;
            goto done;
        }
    } else {
        entropy_available = os_entropy;
    }

#if defined(CPURNG_AVAILABLE) && defined(OPENSSL_CPURNG_CONSERVATIVE)
    if (s->entropy_factor == 0) {
        size_t entropy = ossl_rand_pool_entropy(pool);
        size_t len = ossl_rand_pool_length(pool);
        /* OS Entropy is credited, mix in RDSEED bytes */
        RAND_POOL *addtl = ossl_rand_pool_new(entropy, 1, len, len);
        size_t cpurng_entropy = cpurng_acquire_cpu_entropy(addtl, 1);
        if (cpurng_entropy == 0)
            goto done;
        if (!ossl_rand_pool_adin_mix_in(pool,
                ossl_rand_pool_buffer(addtl),
                ossl_rand_pool_length(addtl))) {
            entropy_available = 0;
            goto done;
        }
    }
#endif

done:
    if (os_pool != pool)
        ossl_rand_pool_free(os_pool);
    return entropy_available;
}

static void *cpurng_new(void *provctx, void *parent,
    const OSSL_DISPATCH *parent_dispatch)
{
    PROV_CPURNG *s;

    if (parent != NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT);
        return NULL;
    }

    s = OPENSSL_zalloc(sizeof(*s));
    if (s == NULL)
        return NULL;

    s->provctx = provctx;
    s->state = EVP_RAND_STATE_UNINITIALISED;
    return s;
}

static void cpurng_free(void *vseed)
{
    OPENSSL_free(vseed);
}

static int cpurng_instantiate(void *vseed, unsigned int strength,
    int prediction_resistance,
    const unsigned char *pstr,
    size_t pstr_len,
    ossl_unused const OSSL_PARAM params[])
{
    PROV_CPURNG *s = (PROV_CPURNG *)vseed;

    s->entropy_factor = cpurng_validated();
#if defined(OPENSSL_CPURNG_VALIDATED)
    if (s->entropy_factor <= 0) {
        s->state = EVP_RAND_STATE_ERROR;
        return 0;
    }
#endif

    s->state = EVP_RAND_STATE_READY;
    return 1;
}

static int cpurng_uninstantiate(void *vseed)
{
    PROV_CPURNG *s = (PROV_CPURNG *)vseed;

    s->state = EVP_RAND_STATE_UNINITIALISED;
    return 1;
}

static int cpurng_generate(void *vseed, unsigned char *out, size_t outlen,
    unsigned int strength,
    ossl_unused int prediction_resistance,
    ossl_unused const unsigned char *adin,
    ossl_unused size_t adin_len)
{
    PROV_CPURNG *s = (PROV_CPURNG *)vseed;
    size_t entropy_available;
    RAND_POOL *pool;

    if (s->state != EVP_RAND_STATE_READY) {
        ERR_raise(ERR_LIB_PROV,
            s->state == EVP_RAND_STATE_ERROR ? PROV_R_IN_ERROR_STATE
                                             : PROV_R_NOT_INSTANTIATED);
        return 0;
    }

    pool = ossl_rand_pool_new(strength, 1, outlen, outlen);
    if (pool == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_RAND_LIB);
        return 0;
    }

    /* Get entropy from cpu. */
    entropy_available = cpurng_acquire_entropy(s, pool);
    if (entropy_available > 0) {
        if (!ossl_rand_pool_adin_mix_in(pool, adin, adin_len)) {
            ossl_rand_pool_free(pool);
            return 0;
        }
        memcpy(out, ossl_rand_pool_buffer(pool), ossl_rand_pool_length(pool));
    }

    ossl_rand_pool_free(pool);
    return entropy_available > 0;
}

static int cpurng_reseed(void *vseed,
    ossl_unused int prediction_resistance,
    ossl_unused const unsigned char *ent,
    ossl_unused size_t ent_len,
    ossl_unused const unsigned char *adin,
    ossl_unused size_t adin_len)
{
    PROV_CPURNG *s = (PROV_CPURNG *)vseed;

    if (s->state != EVP_RAND_STATE_READY) {
        ERR_raise(ERR_LIB_PROV,
            s->state == EVP_RAND_STATE_ERROR ? PROV_R_IN_ERROR_STATE
                                             : PROV_R_NOT_INSTANTIATED);
        return 0;
    }
    return 1;
}

static int cpurng_get_ctx_params(void *vseed, OSSL_PARAM params[])
{
    PROV_CPURNG *s = (PROV_CPURNG *)vseed;
    struct cpurng_get_ctx_params_st p;

    if (s == NULL || !cpurng_get_ctx_params_decoder(params, &p))
        return 0;

    if (p.state != NULL && !OSSL_PARAM_set_int(p.state, s->state))
        return 0;

    if (p.str != NULL && !OSSL_PARAM_set_uint(p.str, 1024))
        return 0;

    if (p.maxreq != NULL && !OSSL_PARAM_set_size_t(p.maxreq, 128))
        return 0;
    return 1;
}

static const OSSL_PARAM *cpurng_gettable_ctx_params(ossl_unused void *vseed,
    ossl_unused void *provctx)
{
    return cpurng_get_ctx_params_list;
}

static int cpurng_verify_zeroization(ossl_unused void *vseed)
{
    return 1;
}

static size_t cpurng_get_seed(void *vseed, unsigned char **pout,
    int entropy, size_t min_len,
    size_t max_len,
    int prediction_resistance,
    const unsigned char *adin,
    size_t adin_len)
{
    size_t ret = 0;
    size_t entropy_available = 0;
    RAND_POOL *pool;
    PROV_CPURNG *s = (PROV_CPURNG *)vseed;

    pool = ossl_rand_pool_new(entropy, 1, min_len, max_len);
    if (pool == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_RAND_LIB);
        return 0;
    }

    /* Get entropy from cpu. */
    entropy_available = cpurng_acquire_entropy(s, pool);

    if (entropy_available > 0
        && ossl_rand_pool_adin_mix_in(pool, adin, adin_len)) {
        ret = ossl_rand_pool_length(pool);
        *pout = ossl_rand_pool_detach(pool);
    } else {
        ERR_raise(ERR_LIB_PROV, PROV_R_ENTROPY_SOURCE_STRENGTH_TOO_WEAK);
    }
    ossl_rand_pool_free(pool);
    return ret;
}

static void cpurng_clear_seed(ossl_unused void *vdrbg,
    unsigned char *out, size_t outlen)
{
    OPENSSL_secure_clear_free(out, outlen);
}

static int cpurng_enable_locking(ossl_unused void *vseed)
{
    return 1;
}

int cpurng_lock(ossl_unused void *vctx)
{
    return 1;
}

void cpurng_unlock(ossl_unused void *vctx)
{
}

const OSSL_DISPATCH ossl_cpurng_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))cpurng_new },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))cpurng_free },
    { OSSL_FUNC_RAND_INSTANTIATE,
        (void (*)(void))cpurng_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE,
        (void (*)(void))cpurng_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))cpurng_generate },
    { OSSL_FUNC_RAND_RESEED, (void (*)(void))cpurng_reseed },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))cpurng_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void (*)(void))cpurng_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void (*)(void))cpurng_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        (void (*)(void))cpurng_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))cpurng_get_ctx_params },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
        (void (*)(void))cpurng_verify_zeroization },
    { OSSL_FUNC_RAND_GET_SEED, (void (*)(void))cpurng_get_seed },
    { OSSL_FUNC_RAND_CLEAR_SEED, (void (*)(void))cpurng_clear_seed },
    OSSL_DISPATCH_END
};
#else
NON_EMPTY_TRANSLATION_UNIT
#endif
