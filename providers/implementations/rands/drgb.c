/*
 * Copyright 2011-2019 The OpenSSL Project Authors. All Rights Reserved.
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
#include <openssl/core_names.h>
#include "drbg_local.h"
#include "internal/thread_once.h"
#include "crypto/rand.h"
#include "crypto/cryptlib.h"

/*
 * Support framework for NIST SP 800-90A DRBG
 *
 * See manual page PROV_RAND(7) for a general overview.
 *
 * The OpenSSL model is to have new and free functions, and that new
 * does all initialization.  That is not the NIST model, which has
 * instantiation and un-instantiate, and re-use within a new/free
 * lifecycle.  (No doubt this comes from the desire to support hardware
 * DRBG, where allocation of resources on something like an HSM is
 * a much bigger deal than just re-setting an allocated resource.)
 */

#if 0

typedef struct drbg_nonce_global_st {
    CRYPTO_RWLOCK *rand_nonce_lock;
    int rand_nonce_count;
} DRBG_NONCE_GLOBAL;

/* NIST SP 800-90A DRBG recommends the use of a personalization string. */
static const char ossl_pers_string[] = DRBG_DEFAULT_PERS_STRING;

static unsigned int master_reseed_interval = MASTER_RESEED_INTERVAL;
static unsigned int slave_reseed_interval  = SLAVE_RESEED_INTERVAL;

static time_t master_reseed_time_interval = MASTER_RESEED_TIME_INTERVAL;
static time_t slave_reseed_time_interval  = SLAVE_RESEED_TIME_INTERVAL;
#endif

#if 0
/* A logical OR of all used DRBG flag bits (currently there is only one) */
static const unsigned int rand_drbg_used_flags =
    PROV_RAND_FLAG_CTR_NO_DF | PROV_RAND_FLAG_HMAC | PROV_RAND_TYPE_FLAGS;

static PROV_RAND *drbg_setup(OPENSSL_CTX *ctx, PROV_RAND *parent, int drbg_type);
#endif

/*
 * Allocate memory and initialize a new DRBG. The DRBG is allocated on
 * the secure heap if |secure| is nonzero and the secure heap is enabled.
 * The |parent|, if not NULL, will be used as random source for reseeding.
 * This also requires the parent's provider context and the parent's lock.
 *
 * Returns a pointer to the new DRBG instance on success, NULL on failure.
 */
PROV_RAND *prov_rand_drbg_new(void *provctx, int secure, int df,
                              int (*dnew)(PROV_RAND *ctx, int df))
{
    PROV_RAND *drbg = OPENSSL_zalloc(sizeof(*drbg));

    if (drbg == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    drbg->libctx = provctx;
    drbg->secure = secure;

    /* Set some default maximums up */
    drbg->max_entropylen = DRBG_MAX_LENGTH;
    drbg->max_noncelen = DRBG_MAX_LENGTH;
    drbg->max_perslen = DRBG_MAX_LENGTH;
    drbg->max_adinlen = DRBG_MAX_LENGTH;

#if 0
    if (parent == NULL) {
#ifdef FIPS_MODE
        drbg->get_entropy = rand_crngt_get_entropy;
        drbg->cleanup_entropy = rand_crngt_cleanup_entropy;
#else
        drbg->get_entropy = rand_drbg_get_entropy;
        drbg->cleanup_entropy = rand_drbg_cleanup_entropy;
#endif
#ifndef PROV_RAND_GET_RANDOM_NONCE
        drbg->get_nonce = rand_drbg_get_nonce;
        drbg->cleanup_nonce = rand_drbg_cleanup_nonce;
#endif

        drbg->reseed_interval = master_reseed_interval;
        drbg->reseed_time_interval = master_reseed_time_interval;
    } else {
        drbg->get_entropy = rand_drbg_get_entropy;
        drbg->cleanup_entropy = rand_drbg_cleanup_entropy;
        /*
         * Do not provide nonce callbacks, the child DRBGs will
         * obtain their nonce using random bits from the parent.
         */

        drbg->reseed_interval = slave_reseed_interval;
        drbg->reseed_time_interval = slave_reseed_time_interval;
    }
#endif

    if (!dnew(drbg, df))
        goto err;

#if 0
    if (parent != NULL) {
        rand_drbg_lock(parent_lock);
        *p = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &p_str);
        *p = OSSL_PARAM_construct_end();
        if (!drbg->parent->get_ctx_params(drbg->parent, params)) {
            rand_drbg_unlock(parent_lock);
            ERR_raise(ERR_LIB_PROV, RAND_R_UNABLE_TO_GET_PARENT_STRENGTH);
            goto err;
        }
        rand_drbg_unlock(parent_lock);
        if (drbg->strength > p_str) {
            /*
             * We currently don't support the algorithm from NIST SP 800-90C
             * 10.1.2 to use a weaker DRBG as source
             */
            ERR_raise(ERR_LIB_PROV, RAND_R_PARENT_STRENGTH_TOO_WEAK);
            goto err;
        }
    }
#endif

    return drbg;

 err:
    prov_rand_free(drbg);
    return NULL;
}

/*
 * Uninstantiate |drbg| and free all memory.
 */
void prov_rand_free(PROV_RAND *drbg)
{
    if (drbg == NULL)
        return;

#if 0
    if (drbg->meth != NULL)
        drbg->meth->uninstantiate(drbg);
    rand_pool_free(drbg->adin_pool);
    CRYPTO_THREAD_lock_free(drbg->lock);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_PROV_RAND, drbg, &drbg->ex_data);
#endif

    OPENSSL_free(drbg);
}

#if 0
/*
 * Uninstantiate |drbg|. Must be instantiated before it can be used.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int PROV_RAND_uninstantiate(PROV_RAND *drbg)
{
    int index = -1, type, flags;
    if (drbg->meth == NULL) {
        drbg->state = DRBG_ERROR;
        ERR_raise(ERR_LIB_PROV, RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED);
        return 0;
    }

    /* Clear the entire drbg->ctr struct, then reset some important
     * members of the drbg->ctr struct (e.g. keysize, df_ks) to their
     * initial values.
     */
    drbg->meth->uninstantiate(drbg);

    /* The reset uses the default values for type and flags */
    if (drbg->flags & PROV_RAND_FLAG_MASTER)
        index = PROV_RAND_TYPE_MASTER;
    else if (drbg->flags & PROV_RAND_FLAG_PRIVATE)
        index = PROV_RAND_TYPE_PRIVATE;
    else if (drbg->flags & PROV_RAND_FLAG_PUBLIC)
        index = PROV_RAND_TYPE_PUBLIC;

    if (index != -1) {
        flags = rand_drbg_flags[index];
        type = rand_drbg_type[index];
    } else {
        flags = drbg->flags;
        type = drbg->type;
    }
    return PROV_RAND_set(drbg, type, flags);
}

/*
 * Restart |drbg|, using the specified entropy or additional input
 *
 * Tries its best to get the drbg instantiated by all means,
 * regardless of its current state.
 *
 * Optionally, a |buffer| of |len| random bytes can be passed,
 * which is assumed to contain at least |entropy| bits of entropy.
 *
 * If |entropy| > 0, the buffer content is used as entropy input.
 *
 * If |entropy| == 0, the buffer content is used as additional input
 *
 * Returns 1 on success, 0 on failure.
 *
 * This function is used internally only.
 */
int rand_drbg_restart(PROV_RAND *drbg,
                      const unsigned char *buffer, size_t len, size_t entropy)
{
    int reseeded = 0;
    const unsigned char *adin = NULL;
    size_t adinlen = 0;

    if (drbg->seed_pool != NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        drbg->state = DRBG_ERROR;
        rand_pool_free(drbg->seed_pool);
        drbg->seed_pool = NULL;
        return 0;
    }

    if (buffer != NULL) {
        if (entropy > 0) {
            if (drbg->max_entropylen < len) {
                ERR_raise(ERR_LIB_PROV, RAND_R_ENTROPY_INPUT_TOO_LONG);
                drbg->state = DRBG_ERROR;
                return 0;
            }

            if (entropy > 8 * len) {
                ERR_raise(ERR_LIB_PROV, RAND_R_ENTROPY_OUT_OF_RANGE);
                drbg->state = DRBG_ERROR;
                return 0;
            }

            /* will be picked up by the rand_drbg_get_entropy() callback */
            drbg->seed_pool = rand_pool_attach(buffer, len, entropy);
            if (drbg->seed_pool == NULL)
                return 0;
        } else {
            if (drbg->max_adinlen < len) {
                ERR_raise(ERR_LIB_PROV, RAND_R_ADDITIONAL_INPUT_TOO_LONG);
                drbg->state = DRBG_ERROR;
                return 0;
            }
            adin = buffer;
            adinlen = len;
        }
    }

    /* repair error state */
    if (drbg->state == DRBG_ERROR)
        PROV_RAND_uninstantiate(drbg);

    /* repair uninitialized state */
    if (drbg->state == DRBG_UNINITIALISED) {
        /* reinstantiate drbg */
        prov_rand_instantiate(drbg,
                              (const unsigned char *) ossl_pers_string,
                              sizeof(ossl_pers_string) - 1);
        /* already reseeded. prevent second reseeding below */
        reseeded = (drbg->state == DRBG_READY);
    }

    /* refresh current state if entropy or additional input has been provided */
    if (drbg->state == DRBG_READY) {
        if (adin != NULL) {
            /*
             * mix in additional input without reseeding
             *
             * Similar to prov_rand_reseed(), but the provided additional
             * data |adin| is mixed into the current state without pulling
             * entropy from the trusted entropy source using get_entropy().
             * This is not a reseeding in the strict sense of NIST SP 800-90A.
             */
            drbg->meth->reseed(drbg, adin, adinlen, NULL, 0);
        } else if (reseeded == 0) {
            /* do a full reseeding if it has not been done yet above */
            prov_rand_reseed(drbg, NULL, 0, 0, );
        }
    }

    rand_pool_free(drbg->seed_pool);
    drbg->seed_pool = NULL;

    return drbg->state == DRBG_READY;
}

/*
 * Generates |outlen| random bytes and stores them in |out|. It will
 * using the given |drbg| to generate the bytes.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success 0 on failure.
 */
int PROV_RAND_bytes(PROV_RAND *drbg, unsigned char *out, size_t outlen)
{
    unsigned char *additional = NULL;
    size_t additional_len;
    size_t chunk;
    size_t ret = 0;

    if (drbg->adin_pool == NULL) {
        if (drbg->type == 0)
            goto err;
        drbg->adin_pool = rand_pool_new(0, 0, 0, drbg->max_adinlen);
        if (drbg->adin_pool == NULL)
            goto err;
    }

    additional_len = rand_drbg_get_additional_data(drbg->adin_pool,
                                                   &additional);

    for ( ; outlen > 0; outlen -= chunk, out += chunk) {
        chunk = outlen;
        if (chunk > drbg->max_request)
            chunk = drbg->max_request;
        ret = PROV_RAND_generate(drbg, out, chunk, 0, additional, additional_len);
        if (!ret)
            goto err;
    }
    ret = 1;

 err:
    if (additional != NULL)
        rand_drbg_cleanup_additional_data(drbg->adin_pool, additional);

    return ret;
}

/*
 * Set the PROV_RAND callbacks for obtaining entropy and nonce.
 *
 * Setting the callbacks is allowed only if the drbg has not been
 * initialized yet. Otherwise, the operation will fail.
 *
 * Returns 1 on success, 0 on failure.
 */
int PROV_RAND_set_callbacks(PROV_RAND *drbg,
                            PROV_RAND_get_entropy_fn get_entropy,
                            PROV_RAND_cleanup_entropy_fn cleanup_entropy,
                            PROV_RAND_get_nonce_fn get_nonce,
                            PROV_RAND_cleanup_nonce_fn cleanup_nonce)
{
    if (drbg->state != DRBG_UNINITIALISED
            || drbg->parent != NULL)
        return 0;
    drbg->get_entropy = get_entropy;
    drbg->cleanup_entropy = cleanup_entropy;
    drbg->get_nonce = get_nonce;
    drbg->cleanup_nonce = cleanup_nonce;
    return 1;
}

/*
 * Set the reseed interval.
 *
 * The drbg will reseed automatically whenever the number of generate
 * requests exceeds the given reseed interval. If the reseed interval
 * is 0, then this feature is disabled.
 *
 * Returns 1 on success, 0 on failure.
 */
int PROV_RAND_set_reseed_interval(PROV_RAND *drbg, unsigned int interval)
{
    if (interval > MAX_RESEED_INTERVAL)
        return 0;
    drbg->reseed_interval = interval;
    return 1;
}

/*
 * Set the reseed time interval.
 *
 * The drbg will reseed automatically whenever the time elapsed since
 * the last reseeding exceeds the given reseed time interval. For safety,
 * a reseeding will also occur if the clock has been reset to a smaller
 * value.
 *
 * Returns 1 on success, 0 on failure.
 */
int PROV_RAND_set_reseed_time_interval(PROV_RAND *drbg, time_t interval)
{
    if (interval > MAX_RESEED_TIME_INTERVAL)
        return 0;
    drbg->reseed_time_interval = interval;
    return 1;
}

/*
 * Set the default values for reseed (time) intervals of new DRBG instances
 *
 * The default values can be set independently for master DRBG instances
 * (without a parent) and slave DRBG instances (with parent).
 *
 * Returns 1 on success, 0 on failure.
 */

int PROV_RAND_set_reseed_defaults(
                                  unsigned int _master_reseed_interval,
                                  unsigned int _slave_reseed_interval,
                                  time_t _master_reseed_time_interval,
                                  time_t _slave_reseed_time_interval
                                  )
{
    if (_master_reseed_interval > MAX_RESEED_INTERVAL
        || _slave_reseed_interval > MAX_RESEED_INTERVAL)
        return 0;

    if (_master_reseed_time_interval > MAX_RESEED_TIME_INTERVAL
        || _slave_reseed_time_interval > MAX_RESEED_TIME_INTERVAL)
        return 0;

    master_reseed_interval = _master_reseed_interval;
    slave_reseed_interval = _slave_reseed_interval;

    master_reseed_time_interval = _master_reseed_time_interval;
    slave_reseed_time_interval = _slave_reseed_time_interval;

    return 1;
}

/*
 * Locks the given drbg lock. Locking a drbg which does not have locking
 * enabled is considered a successful no-op.
 *
 * Returns 1 on success, 0 on failure.
 */
int rand_drbg_lock(CRYPTO_RWLOCK *lock)
{
    if (lock != NULL)
        return CRYPTO_THREAD_write_lock(lock);

    return 1;
}

/*
 * Unlocks the given drbg lock. Unlocking a drbg which does not have locking
 * enabled is considered a successful no-op.
 *
 * Returns 1 on success, 0 on failure.
 */
int rand_drbg_unlock(CRYPTO_RWLOCK *lock)
{
    if (lock != NULL)
        return CRYPTO_THREAD_unlock(lock);

    return 1;
}

/*
 * Enables locking for the given drbg
 *
 * Locking can only be enabled if the random generator
 * is in the uninitialized state.
 *
 * Returns 1 on success, 0 on failure.
 */
int rand_drbg_enable_locking(PROV_RAND *drbg)
{
    if (drbg->state != DRBG_UNINITIALISED) {
        ERR_raise(ERR_LIB_PROV, RAND_R_DRBG_ALREADY_INITIALIZED);
        return 0;
    }

    if (drbg->lock == NULL) {
        if (drbg->parent_lock == NULL) {
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
 * Get and set the EXDATA
 */
int PROV_RAND_set_ex_data(PROV_RAND *drbg, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&drbg->ex_data, idx, arg);
}

void *PROV_RAND_get_ex_data(const PROV_RAND *drbg, int idx)
{
    return CRYPTO_get_ex_data(&drbg->ex_data, idx);
}


/*
 * The following functions provide a RAND_METHOD that works on the
 * global DRBG.  They lock.
 */

/*
 * Allocates a new global DRBG on the secure heap (if enabled) and
 * initializes it with default settings.
 *
 * Returns a pointer to the new DRBG instance on success, NULL on failure.
 */
static PROV_RAND *drbg_setup(OPENSSL_CTX *ctx, PROV_RAND *parent, int drbg_type)
{
    PROV_RAND *drbg;

    drbg = PROV_RAND_secure_new_ex(ctx, rand_drbg_type[drbg_type],
                                   rand_drbg_flags[drbg_type], parent);
    if (drbg == NULL)
        return NULL;

    /* Only the master DRBG needs to have a lock */
    if (parent == NULL && rand_drbg_enable_locking(drbg) == 0)
        goto err;

    /* enable seed propagation */
    tsan_store(&drbg->reseed_prop_counter, 1);

    /*
     * Ignore instantiation error to support just-in-time instantiation.
     *
     * The state of the drbg will be checked in PROV_RAND_generate() and
     * an automatic recovery is attempted.
     */
    (void)prov_rand_instantiate(drbg,
                                (const unsigned char *) ossl_pers_string,
                                sizeof(ossl_pers_string) - 1);
    return drbg;

err:
    prov_rand_free(drbg);
    return NULL;
}

static void drbg_delete_thread_state(void *arg)
{
    OPENSSL_CTX *ctx = arg;
    DRBG_GLOBAL *dgbl = drbg_get_global(ctx);
    PROV_RAND *drbg;

    if (dgbl == NULL)
        return;
    drbg = CRYPTO_THREAD_get_local(&dgbl->public_drbg);
    CRYPTO_THREAD_set_local(&dgbl->public_drbg, NULL);
    PROV_RAND_free(drbg);

    drbg = CRYPTO_THREAD_get_local(&dgbl->private_drbg);
    CRYPTO_THREAD_set_local(&dgbl->private_drbg, NULL);
    PROV_RAND_free(drbg);
}

/* Implements the default OpenSSL RAND_bytes() method */
static int drbg_bytes(unsigned char *out, int count)
{
    int ret;
    PROV_RAND *drbg = PROV_RAND_get0_public();

    if (drbg == NULL)
        return 0;

    ret = PROV_RAND_bytes(drbg, out, count);

    return ret;
}

/*
 * Calculates the minimum length of a full entropy buffer
 * which is necessary to seed (i.e. instantiate) the DRBG
 * successfully.
 */
size_t rand_drbg_seedlen(PROV_RAND *drbg)
{
    /*
     * If no os entropy source is available then RAND_seed(buffer, bufsize)
     * is expected to succeed if and only if the buffer length satisfies
     * the following requirements, which follow from the calculations
     * in prov_rand_instantiate().
     */
    size_t min_entropy = drbg->strength;
    size_t min_entropylen = drbg->min_entropylen;

    /*
     * Extra entropy for the random nonce in the absence of a
     * get_nonce callback, see comment in prov_rand_instantiate().
     */
    if (drbg->min_noncelen > 0 && drbg->get_nonce == NULL) {
        min_entropy += drbg->strength / 2;
        min_entropylen += drbg->min_noncelen;
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

/* Implements the default OpenSSL RAND_add() method */
static int drbg_add(const void *buf, int num, double randomness)
{
    int ret = 0;
    PROV_RAND *drbg = PROV_RAND_get0_master();
    size_t buflen;
    size_t seedlen;

    if (drbg == NULL)
        return 0;

    if (num < 0 || randomness < 0.0)
        return 0;

    rand_drbg_lock(drbg->lock);
    seedlen = rand_drbg_seedlen(drbg);

    buflen = (size_t)num;

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
    if (buflen < seedlen || randomness < (double) seedlen) {
#if defined(OPENSSL_RAND_SEED_NONE)
        /*
         * If no os entropy source is available, a reseeding will fail
         * inevitably. So we use a trick to mix the buffer contents into
         * the DRBG state without forcing a reseeding: we generate a
         * dummy random byte, using the buffer content as additional data.
         * Note: This won't work with PROV_RAND_FLAG_CTR_NO_DF.
         */
        unsigned char dummy[1];

        ret = PROV_RAND_generate(drbg, dummy, sizeof(dummy), 0, buf, buflen);
        rand_drbg_unlock(drbg->lock);
        return ret;
#else
        /*
         * If an os entropy source is available then we declare the buffer content
         * as additional data by setting randomness to zero and trigger a regular
         * reseeding.
         */
        randomness = 0.0;
#endif
    }

    if (randomness > (double)seedlen) {
        /*
         * The purpose of this check is to bound |randomness| by a
         * relatively small value in order to prevent an integer
         * overflow when multiplying by 8 in the rand_drbg_restart()
         * call below. Note that randomness is measured in bytes,
         * not bits, so this value corresponds to eight times the
         * security strength.
         */
        randomness = (double)seedlen;
    }

    ret = rand_drbg_restart(drbg, buf, buflen, (size_t)(8 * randomness));
    rand_drbg_unlock(drbg->lock);

    return ret;
}

/* Implements the default OpenSSL RAND_seed() method */
static int drbg_seed(const void *buf, int num)
{
    return drbg_add(buf, num, num);
}

/* Implements the default OpenSSL RAND_status() method */
static int drbg_status(void)
{
    int ret;
    PROV_RAND *drbg = PROV_RAND_get0_master();

    if (drbg == NULL)
        return 0;

    rand_drbg_lock(drbg->lock);
    ret = drbg->state == DRBG_READY ? 1 : 0;
    rand_drbg_unlock(drbg->lock);
    return ret;
}
#endif

int drbg_set_ctx_params(PROV_RAND *drbg, const OSSL_PARAM params[])
{
#if 0
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_RESEED_REQUESTS);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &drbg->reseed_interval))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_RESEED_TIME_INTERVAL);
    if (p != NULL && !OSSL_PARAM_get_uint64(p, &drbg->reseed_time_interval))
        return 0;
#endif
    return 1;
}

int drbg_get_ctx_params(PROV_RAND *drbg, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

#if 0
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, drbg->state))
        return 0;
#endif

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_int(p, drbg->strength))
        return 0;
#if 0
    p = OSSL_PARAM_local(params, OSSL_RAND_PARAM_RESEED_CTR);
    if (p != NULL
        && !OSSL_PARAM_set_uint(p, tsan_load(drbg->reseed_prop_counter)))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_RESEED_REQUESTS);
    if (p != NULL && !OSSL_PARAM_set_uint(p, drbg->reseed_interval))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_RESEED_TIME_INTERVAL);
    if (p != NULL && !OSSL_PARAM_set_uint64(p, drbg->reseed_time_interval))
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

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_SEEDLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, drbg->seedlen))
        return 0;
#endif
    return 1;
}
