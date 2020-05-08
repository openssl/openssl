/*
 * Copyright 2011-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "crypto/rand.h"
#include "drbg_local.h"
#include "internal/thread_once.h"
#include "crypto/cryptlib.h"
#include "seeding/seeding.h"
#include "crypto/rand_pool.h"

/*
 * Support framework for NIST SP 800-90A DRBG
 *
 * See manual page PROV_DRBG(7) for a general overview.
 *
 * The OpenSSL model is to have new and free functions, and that new
 * does all initialization.  That is not the NIST model, which has
 * instantiation and un-instantiate, and re-use within a new/free
 * lifecycle.  (No doubt this comes from the desire to support hardware
 * DRBG, where allocation of resources on something like an HSM is
 * a much bigger deal than just re-setting an allocated resource.)
 */

#ifdef FIPS_MODULE
# define get_entropy        prov_crngt_get_entropy
# define cleanup_entropy    prov_crngt_cleanup_entropy
#else
# define get_entropy        prov_drbg_get_entropy
# define cleanup_entropy    prov_drbg_cleanup_entropy
#endif

/* NIST SP 800-90A DRBG recommends the use of a personalization string. */
static const char ossl_pers_string[] = DRBG_DEFAULT_PERS_STRING;

static unsigned int master_reseed_interval = MASTER_RESEED_INTERVAL;
static unsigned int slave_reseed_interval  = SLAVE_RESEED_INTERVAL;

static time_t master_reseed_time_interval = MASTER_RESEED_TIME_INTERVAL;
static time_t slave_reseed_time_interval  = SLAVE_RESEED_TIME_INTERVAL;

static const OSSL_DISPATCH *find_call(const OSSL_DISPATCH *dispatch,
                                      int function);

int drbg_lock(void *vctx)
{
    PROV_DRBG *drbg = vctx;

    if (drbg == NULL || drbg->lock == NULL)
        return 1;
    return CRYPTO_THREAD_write_lock(drbg->lock);
}

void drbg_unlock(void *vctx)
{
    PROV_DRBG *drbg = vctx;

    if (drbg != NULL && drbg->lock != NULL)
        CRYPTO_THREAD_unlock(drbg->lock);
}

static int drbg_lock_parent(PROV_DRBG *drbg)
{
    void *parent = drbg->parent;
    const OSSL_DISPATCH *pfunc;

    if (parent != NULL) {
        pfunc = find_call(drbg->parent_dispatch, OSSL_FUNC_RAND_LOCK);
        if (pfunc != NULL && !OSSL_get_OP_rand_lock(pfunc)(parent)) {
            ERR_raise(ERR_LIB_PROV, RAND_R_PARENT_LOCKING_NOT_ENABLED);
            return 0;
        }
    }
    return 1;
}

static void drbg_unlock_parent(PROV_DRBG *drbg)
{
    void *parent = drbg->parent;
    const OSSL_DISPATCH *pfunc;

    if (parent != NULL) {
        pfunc = find_call(drbg->parent_dispatch, OSSL_FUNC_RAND_UNLOCK);
        if (pfunc != NULL)
            OSSL_get_OP_rand_unlock(pfunc)(parent);
    }
}

static int get_parent_strength(PROV_DRBG *drbg, int *str)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    const OSSL_DISPATCH *pfunc;
    void *parent = drbg->parent;

    pfunc = find_call(drbg->parent_dispatch, OSSL_FUNC_RAND_GET_CTX_PARAMS);
    if (pfunc == NULL) {
        ERR_raise(ERR_LIB_PROV, RAND_R_UNABLE_TO_GET_PARENT_STRENGTH);
        return 0;
    }
    *params = OSSL_PARAM_construct_int(OSSL_RAND_PARAM_STRENGTH, str);
    if (!drbg_lock_parent(drbg)) {
        ERR_raise(ERR_LIB_PROV, RAND_R_UNABLE_TO_LOCK_PARENT);
        return 0;
    }
    if (!OSSL_get_OP_rand_get_ctx_params(pfunc)(parent, params)) {
        drbg_unlock_parent(drbg);
        ERR_raise(ERR_LIB_PROV, RAND_R_UNABLE_TO_GET_PARENT_STRENGTH);
        return 0;
    }
    drbg_unlock_parent(drbg);
    return 1;
}

static unsigned int get_parent_reseed_count(PROV_DRBG *drbg)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    const OSSL_DISPATCH *pfunc;
    void *parent = drbg->parent;
    unsigned int r;

    pfunc = find_call(drbg->parent_dispatch, OSSL_FUNC_RAND_GET_CTX_PARAMS);
    if (pfunc == NULL) {
        ERR_raise(ERR_LIB_PROV,
                  RAND_R_UNABLE_TO_GET_PARENT_RESEED_PROP_COUNTER);
        goto err;
    }
    *params = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_RESEED_PROP_CTR, &r);
    if (!drbg_lock_parent(drbg)) {
        ERR_raise(ERR_LIB_PROV, RAND_R_UNABLE_TO_LOCK_PARENT);
        goto err;
    }
    if (!OSSL_get_OP_rand_get_ctx_params(pfunc)(parent, params)) {
        drbg_unlock_parent(drbg);
        ERR_raise(ERR_LIB_PROV, RAND_R_UNABLE_TO_GET_RESEED_PROP_CTR);
        goto err;
    }
    drbg_unlock_parent(drbg);
    return r;

 err:
    r = tsan_load(&drbg->reseed_prop_counter) - 2;
    if (r == 0)
        r = UINT_MAX;
    return r;
}

#ifndef FIPS_MODULE
/*
 * Implements the get_entropy() callback (see RAND_DRBG_set_callbacks())
 *
 * If the DRBG has a parent, then the required amount of entropy input
 * is fetched using the parent's RAND_DRBG_generate().
 *
 * Otherwise, the entropy is polled from the system entropy sources
 * using rand_pool_acquire_entropy().
 *
 * If a random pool has been added to the DRBG using RAND_add(), then
 * its entropy will be used up first.
 */
static size_t prov_drbg_get_entropy(PROV_DRBG *drbg, unsigned char **pout,
                                    int entropy, size_t min_len, size_t max_len,
                                    int prediction_resistance)
{
    size_t ret = 0;
    size_t entropy_available = 0;
    RAND_POOL *pool;
    int p_str;
    const OSSL_DISPATCH *pfunc;

    if (drbg->parent != NULL) {
        if (!get_parent_strength(drbg, &p_str))
            return 0;
        if (drbg->strength > p_str) {
            /*
             * We currently don't support the algorithm from NIST SP 800-90C
             * 10.1.2 to use a weaker DRBG as source
             */
            RANDerr(0, RAND_R_PARENT_STRENGTH_TOO_WEAK);
            return 0;
        }
    }

    if (drbg->seed_pool != NULL) {
        pool = drbg->seed_pool;
        pool->entropy_requested = entropy;
    } else {
        pool = rand_pool_new(entropy, drbg->secure, min_len, max_len);
        if (pool == NULL)
            return 0;
    }

    if (drbg->parent != NULL) {
        size_t bytes_needed = rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
        unsigned char *buffer = rand_pool_add_begin(pool, bytes_needed);

        if (buffer != NULL) {
            size_t bytes = 0;

            /*
             * Get random data from parent. Include our address as additional input,
             * in order to provide some additional distinction between different
             * DRBG child instances.
             * Our lock is already held, but we need to lock our parent before
             * generating bits from it. (Note: taking the lock will be a no-op
             * if locking if drbg->parent->lock == NULL.)
             */
            pfunc = find_call(drbg->parent_dispatch, OSSL_FUNC_RAND_GENERATE);
            if (pfunc == NULL)
                return 0;
            drbg_lock_parent(drbg);
            if (OSSL_get_OP_rand_generate(pfunc)(drbg->parent, buffer, bytes_needed,
                                                 drbg->strength,
                                                 prediction_resistance,
                                                 (unsigned char *)&drbg,
                                                 sizeof(drbg)) != 0)
                bytes = bytes_needed;
            drbg->reseed_next_counter = get_parent_reseed_count(drbg);
            drbg_unlock_parent(drbg);

            rand_pool_add_end(pool, bytes, 8 * bytes);
            entropy_available = rand_pool_entropy_available(pool);
        }
    } else {
        /* Get entropy by polling system entropy sources. */
        entropy_available = rand_pool_acquire_entropy(pool);
    }

    if (entropy_available > 0) {
        ret   = rand_pool_length(pool);
        *pout = rand_pool_detach(pool);
    }

    if (drbg->seed_pool == NULL)
        rand_pool_free(pool);
    return ret;
}

/*
 * Implements the cleanup_entropy() callback (see RAND_DRBG_set_callbacks())
 *
 */
static void prov_drbg_cleanup_entropy(PROV_DRBG *drbg,
                                      unsigned char *out, size_t outlen)
{
    if (drbg->seed_pool == NULL) {
        if (drbg->secure)
            OPENSSL_secure_clear_free(out, outlen);
        else
            OPENSSL_clear_free(out, outlen);
    }
}
#endif

#ifndef PROV_RAND_GET_RANDOM_NONCE
typedef struct prov_drbg_nonce_global_st {
    CRYPTO_RWLOCK *rand_nonce_lock;
    int rand_nonce_count;
} PROV_DRBG_NONCE_GLOBAL;

/*
 * drbg_ossl_ctx_new() calls drgb_setup() which calls rand_drbg_get_nonce()
 * which needs to get the rand_nonce_lock out of the OPENSSL_CTX...but since
 * drbg_ossl_ctx_new() hasn't finished running yet we need the rand_nonce_lock
 * to be in a different global data object. Otherwise we will go into an
 * infinite recursion loop.
 */
static void *prov_drbg_nonce_ossl_ctx_new(OPENSSL_CTX *libctx)
{
    PROV_DRBG_NONCE_GLOBAL *dngbl = OPENSSL_zalloc(sizeof(*dngbl));

    if (dngbl == NULL)
        return NULL;

    dngbl->rand_nonce_lock = CRYPTO_THREAD_lock_new();
    if (dngbl->rand_nonce_lock == NULL) {
        OPENSSL_free(dngbl);
        return NULL;
    }

    return dngbl;
}

static void prov_drbg_nonce_ossl_ctx_free(void *vdngbl)
{
    PROV_DRBG_NONCE_GLOBAL *dngbl = vdngbl;

    if (dngbl == NULL)
        return;

    CRYPTO_THREAD_lock_free(dngbl->rand_nonce_lock);

    OPENSSL_free(dngbl);
}

static const OPENSSL_CTX_METHOD drbg_nonce_ossl_ctx_method = {
    prov_drbg_nonce_ossl_ctx_new,
    prov_drbg_nonce_ossl_ctx_free,
};

/* Get a nonce from the operating system */
static size_t prov_drbg_get_nonce(PROV_DRBG *drbg,
                                  unsigned char **pout,
                                  int entropy, size_t min_len, size_t max_len)
{
    size_t ret = 0;
    RAND_POOL *pool;
    PROV_DRBG_NONCE_GLOBAL *dngbl
        = openssl_ctx_get_data(drbg->libctx, OPENSSL_CTX_DRBG_NONCE_INDEX,
                               &drbg_nonce_ossl_ctx_method);
    struct {
        void *instance;
        int count;
    } data;
    

    if (dngbl == NULL)
        return 0;

    memset(&data, 0, sizeof(data));
    pool = rand_pool_new(0, 0, min_len, max_len);
    if (pool == NULL)
        return 0;

    if (rand_pool_add_nonce_data(pool) == 0)
        goto err;

    data.instance = drbg;
    CRYPTO_atomic_add(&dngbl->rand_nonce_count, 1, &data.count,
                      dngbl->rand_nonce_lock);

    if (rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0) == 0)
        goto err;

    ret   = rand_pool_length(pool);
    *pout = rand_pool_detach(pool);

 err:
    rand_pool_free(pool);

    return ret;
}
#endif

/*
 * Implements the cleanup_nonce() callback (see PROV_DRBG_set_callbacks())
 *
 */
static void prov_drbg_cleanup_nonce(PROV_DRBG *drbg,
                                    unsigned char *out, size_t outlen)
{
    OPENSSL_clear_free(out, outlen);
}

/*
 * Instantiate |drbg|, after it has been initialized.  Use |pers| and
 * |perslen| as prediction-resistance input.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int PROV_DRBG_instantiate(PROV_DRBG *drbg, int strength,
                          int prediction_resistance,
                          const unsigned char *pers, size_t perslen,
                          int (*ifnc)(PROV_DRBG *drbg,
                                      const unsigned char *ent, size_t ent_len,
                                      const unsigned char *nonce,
                                      size_t nonce_len,
                                      const unsigned char *pstr,
                                      size_t pstr_len))
{
    unsigned char *nonce = NULL, *entropy = NULL;
    size_t noncelen = 0, entropylen = 0;
    size_t min_entropy, min_entropylen, max_entropylen;
    const OSSL_DISPATCH *pnonce;

    if (strength > drbg->strength) {
        PROVerr(0, RAND_R_INSUFFICIENT_DRBG_STRENGTH);
        goto end;
    }
    min_entropy = drbg->strength;
    min_entropylen = drbg->min_entropylen;
    max_entropylen = drbg->max_entropylen;

    if (pers == NULL) {
        pers = (const unsigned char *)ossl_pers_string;
        perslen = sizeof(ossl_pers_string);
    }
    if (perslen > drbg->max_perslen) {
        PROVerr(0, RAND_R_PERSONALISATION_STRING_TOO_LONG);
        goto end;
    }

    if (drbg->state != DRBG_UNINITIALISED) {
        if (drbg->state == DRBG_ERROR)
            PROVerr(0, RAND_R_IN_ERROR_STATE);
        else
            PROVerr(0, RAND_R_ALREADY_INSTANTIATED);
        goto end;
    }

    drbg->state = DRBG_ERROR;

    if (drbg->min_noncelen > 0) {
#ifndef PROV_RAND_GET_RANDOM_NONCE
        if (drbg->parent != NULL)
#endif
        {
            pnonce = find_call(drbg->parent_dispatch, OSSL_FUNC_RAND_NONCE);
            if (pnonce == NULL) {
                /*
                 * NIST SP800-90Ar1 section 9.1 says you can combine getting
                 * the entropy and nonce in 1 call by increasing the entropy
                 * with 50% and increasing the minimum length to accommodate
                 * the length of the nonce. We do this in case a nonce is
                 * required and there is no parental nonce capability.
                 */
                min_entropy += drbg->strength / 2;
                min_entropylen += drbg->min_noncelen;
                max_entropylen += drbg->max_noncelen;
            } else {
                drbg_lock_parent(drbg);
                noncelen = OSSL_get_OP_rand_nonce(pnonce)(drbg->parent, &nonce,
                                                          drbg->strength / 2,
                                                          drbg->min_noncelen,
                                                          drbg->max_noncelen);
                drbg_unlock_parent(drbg);
                if (noncelen < drbg->min_noncelen
                        || noncelen > drbg->max_noncelen) {
                    PROVerr(0, RAND_R_ERROR_RETRIEVING_NONCE);
                    goto end;
                }
            }
        }
#ifndef PROV_RAND_GET_RANDOM_NONCE
        else { /* parent == NULL */
            noncelen = prov_drbg_get_nonce(drbg, &nonce, drbg->strength / 2,
                                           drbg->min_noncelen, 
                                           drbg->max_noncelen);
            if (noncelen < drbg->min_noncelen
                    || noncelen > drbg->max_noncelen) {
                PROVerr(0, RAND_R_ERROR_RETRIEVING_NONCE);
                goto end;
            }
        }
#endif
    }

    drbg->reseed_next_counter = tsan_load(&drbg->reseed_prop_counter);
    if (drbg->reseed_next_counter) {
        drbg->reseed_next_counter++;
        if(!drbg->reseed_next_counter)
            drbg->reseed_next_counter = 1;
    }

    entropylen = get_entropy(drbg, &entropy, min_entropy,
                             min_entropylen, max_entropylen,
                             prediction_resistance);
    if (entropylen < min_entropylen
            || entropylen > max_entropylen) {
        PROVerr(0, RAND_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (!ifnc(drbg, entropy, entropylen, nonce, noncelen, pers, perslen)) {
        PROVerr(0, RAND_R_ERROR_INSTANTIATING_DRBG);
        goto end;
    }

    drbg->state = DRBG_READY;
    drbg->reseed_gen_counter = 1;
    drbg->reseed_time = time(NULL);
    tsan_store(&drbg->reseed_prop_counter, drbg->reseed_next_counter);

 end:
    if (entropy != NULL)
        cleanup_entropy(drbg, entropy, entropylen);
    if (nonce != NULL)
        prov_drbg_cleanup_nonce(drbg, nonce, noncelen);
    if (drbg->state == DRBG_READY)
        return 1;
    return 0;
}

/*
 * Reseed |drbg|, mixing in the specified data
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int PROV_DRBG_reseed(PROV_DRBG *drbg, int prediction_resistance,
                     const unsigned char *ent, size_t ent_len,
                     const unsigned char *adin, size_t adinlen,
                     int (*reseed)(PROV_DRBG *drbg,
                                   const unsigned char *ent, size_t ent_len,
                                   const unsigned char *adin, size_t adin_len))
{
    unsigned char *entropy = NULL;
    size_t entropylen = 0;

    if (drbg->state == DRBG_ERROR) {
        PROVerr(0, RAND_R_IN_ERROR_STATE);
        return 0;
    }
    if (drbg->state == DRBG_UNINITIALISED) {
        PROVerr(0, RAND_R_NOT_INSTANTIATED);
        return 0;
    }

    if (adin == NULL) {
        adinlen = 0;
    } else if (adinlen > drbg->max_adinlen) {
        PROVerr(0, RAND_R_ADDITIONAL_INPUT_TOO_LONG);
        return 0;
    }

    drbg->state = DRBG_ERROR;

    drbg->reseed_next_counter = tsan_load(&drbg->reseed_prop_counter);
    if (drbg->reseed_next_counter) {
        drbg->reseed_next_counter++;
        if(!drbg->reseed_next_counter)
            drbg->reseed_next_counter = 1;
    }

    entropylen = get_entropy(drbg, &entropy, drbg->strength,
                             drbg->min_entropylen, drbg->max_entropylen,
                             prediction_resistance);
    if (entropylen < drbg->min_entropylen
            || entropylen > drbg->max_entropylen) {
        PROVerr(0, RAND_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (!reseed(drbg, entropy, entropylen, adin, adinlen))
        goto end;

    drbg->state = DRBG_READY;
    drbg->reseed_gen_counter = 1;
    drbg->reseed_time = time(NULL);
    tsan_store(&drbg->reseed_prop_counter, drbg->reseed_next_counter);

 end:
    if (entropy != NULL)
        OPENSSL_cleanse(entropy, entropylen);
    if (drbg->state == DRBG_READY)
        return 1;
    return 0;
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
int PROV_DRBG_generate(PROV_DRBG *drbg, unsigned char *out, size_t outlen,
                       int strength, int prediction_resistance,
                       const unsigned char *adin, size_t adinlen,
                       int (*generate)(PROV_DRBG *, unsigned char *out,
                                       size_t outlen, const unsigned char *adin,
                                       size_t adin_len),
                       int (*reseed)(PROV_DRBG *drbg, const unsigned char *ent,
                                     size_t ent_len, const unsigned char *adin,
                                     size_t adin_len))
{
    int fork_id;
    int reseed_required = 0;

    if (drbg->state != DRBG_READY) {
        if (drbg->state == DRBG_ERROR) {
            PROVerr(0, RAND_R_IN_ERROR_STATE);
            return 0;
        }
        if (drbg->state == DRBG_UNINITIALISED) {
            PROVerr(0, RAND_R_NOT_INSTANTIATED);
            return 0;
        }
    }

    if (outlen > drbg->max_request) {
        PROVerr(0, RAND_R_REQUEST_TOO_LARGE_FOR_DRBG);
        return 0;
    }
    if (adinlen > drbg->max_adinlen) {
        PROVerr(0, RAND_R_ADDITIONAL_INPUT_TOO_LONG);
        return 0;
    }

    fork_id = openssl_get_fork_id();

    if (drbg->fork_id != fork_id) {
        drbg->fork_id = fork_id;
        reseed_required = 1;
    }

    if (drbg->reseed_interval > 0) {
        if (drbg->reseed_gen_counter > drbg->reseed_interval)
            reseed_required = 1;
    }
    if (drbg->reseed_time_interval > 0) {
        time_t now = time(NULL);
        if (now < drbg->reseed_time
            || now - drbg->reseed_time >= drbg->reseed_time_interval)
            reseed_required = 1;
    }
    if (drbg->parent != NULL) {
        unsigned int reseed_counter = 0;

        if (reseed_counter > 0
            && get_parent_reseed_count(drbg) !=
               tsan_load(&drbg->reseed_prop_counter))
            reseed_required = 1;
    }

    if (reseed_required || prediction_resistance) {
        if (!PROV_DRBG_reseed(drbg, prediction_resistance, NULL, 0,
                              adin, adinlen, reseed)) {
            PROVerr(0, RAND_R_RESEED_ERROR);
            return 0;
        }
        adin = NULL;
        adinlen = 0;
    }

    if (!generate(drbg, out, outlen, adin, adinlen)) {
        drbg->state = DRBG_ERROR;
        PROVerr(0, RAND_R_GENERATE_ERROR);
        return 0;
    }

    drbg->reseed_gen_counter++;

    return 1;
}

#if 0
/*
 * Calculates the minimum length of a full entropy buffer
 * which is necessary to seed (i.e. instantiate) the DRBG
 * successfully.
 */
size_t prov_drbg_seedlen(PROV_DRBG *drbg)
{
    /*
     * If no os entropy source is available then PROV_seed(buffer, bufsize)
     * is expected to succeed if and only if the buffer length satisfies
     * the following requirements, which follow from the calculations
     * in PROV_DRBG_instantiate().
     */
    size_t min_entropy = drbg->strength;
    size_t min_entropylen = drbg->min_entropylen;

    /*
     * Extra entropy for the random nonce in the absence of a
     * get_nonce callback, see comment in PROV_DRBG_instantiate().
     */
    if (drbg->min_noncelen > 0) {
#ifndef PROV_RAND_GET_RANDOM_NONCE
        if (drbg->parent != NULL)
#endif
            if (find_call(drbg->parent_dispatch,
                          OSSL_FUNC_RAND_NONCE) == NULL) {
                min_entropy += drbg->strength / 2;
                min_entropylen += drbg->min_noncelen;
            }
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
#endif

/* Provider support from here down */
static const OSSL_DISPATCH *find_call(const OSSL_DISPATCH *dispatch,
                                      int function)
{
    if (dispatch != NULL)
        while (dispatch->function_id != 0)
            if (dispatch->function_id == function)
                return dispatch;
    return NULL;
}

int drbg_enable_locking(void *vctx)
{
    PROV_DRBG *drbg = vctx;
    const OSSL_DISPATCH *pfunc;

    if (drbg == NULL)
        return 1;
    if (drbg->lock == NULL) {
        if (drbg->state != DRBG_UNINITIALISED) {
            ERR_raise(ERR_LIB_PROV, RAND_R_DRBG_ALREADY_INITIALIZED);
            return 0;
        }

        pfunc = find_call(drbg->parent_dispatch, OSSL_FUNC_RAND_ENABLE_LOCKING);
        if (pfunc != NULL)
            if (!OSSL_get_OP_rand_enable_locking(pfunc)(drbg->parent)) {
                ERR_raise(ERR_LIB_PROV, RAND_R_PARENT_LOCKING_NOT_ENABLED);
                return 0;
            }
        drbg->lock = CRYPTO_THREAD_lock_new();
        if (drbg->lock == NULL) {
            ERR_raise(ERR_LIB_PROV, RAND_R_FAILED_TO_CREATE_LOCK);
            return 0;
        }
    }
    return 1;
}

/*
 * Allocate memory and initialize a new DRBG. The DRBG is allocated on
 * the secure heap if |secure| is nonzero and the secure heap is enabled.
 * The |parent|, if not NULL, will be used as random source for reseeding.
 * This also requires the parent's provider context and the parent's lock.
 *
 * Returns a pointer to the new DRBG instance on success, NULL on failure.
 */
PROV_DRBG *prov_rand_drbg_new(void *provctx, int secure, void *parent,
                              const OSSL_DISPATCH *parent_dispatch,
                              int (*dnew)(PROV_DRBG *ctx, int secure))
{
    PROV_DRBG *drbg = OPENSSL_zalloc(sizeof(*drbg));
    int p_str;

    if (drbg == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    drbg->libctx = provctx;
    drbg->secure = secure;
    drbg->parent = parent;
    drbg->parent_dispatch = parent_dispatch;

    /* Set some default maximums up */
    drbg->max_entropylen = DRBG_MAX_LENGTH;
    drbg->max_noncelen = DRBG_MAX_LENGTH;
    drbg->max_perslen = DRBG_MAX_LENGTH;
    drbg->max_adinlen = DRBG_MAX_LENGTH;
    drbg->reseed_gen_counter = 1;

    /* TODO(3.0) clean this up */
    if (parent == NULL) {
        drbg->reseed_interval = master_reseed_interval;
        drbg->reseed_time_interval = master_reseed_time_interval;
    } else {
        /*
         * Do not provide nonce callbacks, the child DRBGs will
         * obtain their nonce using random bits from the parent.
         */
        drbg->reseed_interval = slave_reseed_interval;
        drbg->reseed_time_interval = slave_reseed_time_interval;
    }

    if (!dnew(drbg, secure))
        goto err;

    if (parent != NULL) {
        if (!get_parent_strength(drbg, &p_str))
            goto err;
        if (drbg->strength > p_str) {
            /*
             * We currently don't support the algorithm from NIST SP 800-90C
             * 10.1.2 to use a weaker DRBG as source
             */
            ERR_raise(ERR_LIB_PROV, RAND_R_PARENT_STRENGTH_TOO_WEAK);
            goto err;
        }
    }
    return drbg;

 err:
    prov_rand_drbg_free(drbg);
    return NULL;
}

void prov_rand_drbg_free(PROV_DRBG *drbg)
{
    if (drbg == NULL)
        return;

    rand_pool_free(drbg->adin_pool);
    CRYPTO_THREAD_lock_free(drbg->lock);
#ifndef FIPS_MODULE
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RAND_DRBG, drbg, &drbg->ex_data);
#endif
}

int drbg_get_ctx_params(PROV_DRBG *drbg, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, drbg->state))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_int(p, drbg->strength))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_request))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MIN_ENTROPYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->min_entropylen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_ENTROPYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_entropylen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MIN_NONCELEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->min_noncelen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_NONCELEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_noncelen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_PERSLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_perslen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_ADINLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->max_adinlen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_RESEED_CTR);
    if (p != NULL && !OSSL_PARAM_set_uint(p, drbg->reseed_gen_counter))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_RESEED_REQUESTS);
    if (p != NULL && !OSSL_PARAM_set_uint(p, drbg->reseed_interval))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_RESEED_TIME_INTERVAL);
    if (p != NULL && !OSSL_PARAM_set_time_t(p, drbg->reseed_time_interval))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_RESEED_PROP_CTR);
    if (p != NULL
            && !OSSL_PARAM_set_uint(p, tsan_load(&drbg->reseed_prop_counter)))
        return 0;
    return 1;
}

int drbg_set_ctx_params(PROV_DRBG *drbg, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_RESEED_REQUESTS);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &drbg->reseed_interval))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_RESEED_TIME_INTERVAL);
    if (p != NULL && !OSSL_PARAM_get_time_t(p, &drbg->reseed_time_interval))
        return 0;
    return 1;
}
