/*
 * Copyright 2011-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "rand_lcl.h"
#include "internal/thread_once.h"
#include "internal/rand_int.h"

/*
 * Support framework for NIST SP 800-90A DRBG, AES-CTR mode.
 * The RAND_DRBG is OpenSSL's pointer to an instance of the DRBG.
 *
 * The OpenSSL model is to have new and free functions, and that new
 * does all initialization.  That is not the NIST model, which has
 * instantiation and un-instantiate, and re-use within a new/free
 * lifecycle.  (No doubt this comes from the desire to support hardware
 * DRBG, where allocation of resources on something like an HSM is
 * a much bigger deal than just re-setting an allocated resource.)
 */

/*
 * THE THREE SHARED DRBGs
 *
 * There are three shared DRBGs (master, public and private), which are
 * accessed concurrently by all threads.
 *
 * THE MASTER DRBG
 *
 * Not used directly by the application, only for reseeding the two other
 * DRBGs. It reseeds itself by pulling either randomness from os entropy
 * sources or by consuming randomnes which was added by RAND_add()
 */
static RAND_DRBG *drbg_master;
/*
 * THE PUBLIC DRBG
 *
 * Used by default for generating random bytes using RAND_bytes().
 */
static RAND_DRBG *drbg_public;
/*
 * THE PRIVATE DRBG
 *
 * Used by default for generating private keys using RAND_priv_bytes()
 */
static RAND_DRBG *drbg_private;
/*+
 * DRBG HIERARCHY
 *
 * In addition there are DRBGs, which are not shared, but used only by a
 * single thread at every time, for example the DRBGs which are owned by
 * an SSL context. All DRBGs are organized in a hierarchical fashion
 * with the <master> DRBG as root.
 *
 * This gives the following overall picture:
 *
 *                  <os entropy sources>
 *                         |
 *    RAND_add() ==>    <master>          \
 *                       /   \            | shared DRBGs (with locking)
 *                 <public>  <private>    /
 *                     |
 *                   <ssl>  owned by an SSL context
 *
 * AUTOMATIC RESEEDING
 *
 * Before satisfying a generate request, a DRBG reseeds itself automatically,
 * if one of the following two conditions holds:
 *
 * - the number of generate requests since the last reseeding exceeds a
 *   certain threshold, the so called |reseed_interval|. This behaviour
 *   can be disabled by setting the |reseed_interval| to 0.
 *
 * - the time elapsed since the last reseeding exceeds a certain time
 *   interval, the so called |reseed_time_interval|. This behaviour
 *   can be disabled by setting the |reseed_time_interval| to 0.
 *
 * MANUAL RESEEDING
 *
 * For the three shared DRBGs (and only for these) there is another way to
 * reseed them manually by calling RAND_seed() (or RAND_add() with a positive
 * |randomness| argument). This will immediately reseed the <master> DRBG.
 * The <public> and <private> DRBG will detect this on their next generate
 * call and reseed, pulling randomness from <master>.
 */


/* NIST SP 800-90A DRBG recommends the use of a personalization string. */
static const char ossl_pers_string[] = "OpenSSL NIST SP 800-90A DRBG";

static CRYPTO_ONCE rand_drbg_init = CRYPTO_ONCE_STATIC_INIT;

static RAND_DRBG *drbg_setup(RAND_DRBG *parent);
static void drbg_cleanup(RAND_DRBG *drbg);

/*
 * Set/initialize |drbg| to be of type |nid|, with optional |flags|.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_set(RAND_DRBG *drbg, int nid, unsigned int flags)
{
    int ret = 1;

    drbg->state = DRBG_UNINITIALISED;
    drbg->flags = flags;
    drbg->nid = nid;

    switch (nid) {
    default:
        RANDerr(RAND_F_RAND_DRBG_SET, RAND_R_UNSUPPORTED_DRBG_TYPE);
        return 0;
    case 0:
        /* Uninitialized; that's okay. */
        return 1;
    case NID_aes_128_ctr:
    case NID_aes_192_ctr:
    case NID_aes_256_ctr:
        ret = drbg_ctr_init(drbg);
        break;
    }

    if (ret == 0)
        RANDerr(RAND_F_RAND_DRBG_SET, RAND_R_ERROR_INITIALISING_DRBG);
    return ret;
}

/*
 * Allocate memory and initialize a new DRBG.  The |parent|, if not
 * NULL, will be used to auto-seed this RAND_DRBG as needed.
 *
 * Returns a pointer to the new DRBG instance on success, NULL on failure.
 */
RAND_DRBG *RAND_DRBG_new(int type, unsigned int flags, RAND_DRBG *parent)
{
    RAND_DRBG *drbg = OPENSSL_zalloc(sizeof(*drbg));

    if (drbg == NULL) {
        RANDerr(RAND_F_RAND_DRBG_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    drbg->fork_count = rand_fork_count;
    drbg->parent = parent;
    if (RAND_DRBG_set(drbg, type, flags) == 0)
        goto err;

    if (!RAND_DRBG_set_callbacks(drbg, rand_drbg_get_entropy,
                                 rand_drbg_cleanup_entropy,
                                 NULL, NULL))
        goto err;

    return drbg;

err:
    OPENSSL_free(drbg);
    return NULL;
}

/*
 * Uninstantiate |drbg| and free all memory.
 */
void RAND_DRBG_free(RAND_DRBG *drbg)
{
    if (drbg == NULL)
        return;

    if (drbg->meth != NULL)
        drbg->meth->uninstantiate(drbg);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DRBG, drbg, &drbg->ex_data);
    OPENSSL_clear_free(drbg, sizeof(*drbg));
}

/*
 * Instantiate |drbg|, after it has been initialized.  Use |pers| and
 * |perslen| as prediction-resistance input.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_instantiate(RAND_DRBG *drbg,
                          const unsigned char *pers, size_t perslen)
{
    unsigned char *nonce = NULL, *entropy = NULL;
    size_t noncelen = 0, entropylen = 0;

    if (perslen > drbg->max_perslen) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE,
                RAND_R_PERSONALISATION_STRING_TOO_LONG);
        goto end;
    }

    if (drbg->meth == NULL)
    {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE,
                RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED);
        goto end;
    }

    if (drbg->state != DRBG_UNINITIALISED) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE,
                drbg->state == DRBG_ERROR ? RAND_R_IN_ERROR_STATE
                                          : RAND_R_ALREADY_INSTANTIATED);
        goto end;
    }

    drbg->state = DRBG_ERROR;
    if (drbg->get_entropy != NULL)
        entropylen = drbg->get_entropy(drbg, &entropy, drbg->strength,
                                   drbg->min_entropylen, drbg->max_entropylen);
    if (entropylen < drbg->min_entropylen
        || entropylen > drbg->max_entropylen) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, RAND_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (drbg->max_noncelen > 0 && drbg->get_nonce != NULL) {
        noncelen = drbg->get_nonce(drbg, &nonce, drbg->strength / 2,
                                   drbg->min_noncelen, drbg->max_noncelen);
        if (noncelen < drbg->min_noncelen || noncelen > drbg->max_noncelen) {
            RANDerr(RAND_F_RAND_DRBG_INSTANTIATE,
                    RAND_R_ERROR_RETRIEVING_NONCE);
            goto end;
        }
    }

    if (!drbg->meth->instantiate(drbg, entropy, entropylen,
                         nonce, noncelen, pers, perslen)) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, RAND_R_ERROR_INSTANTIATING_DRBG);
        goto end;
    }

    drbg->state = DRBG_READY;
    drbg->generate_counter = 0;
    drbg->reseed_time = time(NULL);
    if (drbg->reseed_counter > 0) {
        if (drbg->parent == NULL)
            drbg->reseed_counter++;
        else
            drbg->reseed_counter = drbg->parent->reseed_counter;
    }

end:
    if (entropy != NULL && drbg->cleanup_entropy != NULL)
        drbg->cleanup_entropy(drbg, entropy, entropylen);
    if (nonce != NULL && drbg->cleanup_nonce!= NULL )
        drbg->cleanup_nonce(drbg, nonce, noncelen);
    if (drbg->pool != NULL) {
        if (drbg->state == DRBG_READY) {
            RANDerr(RAND_F_RAND_DRBG_INSTANTIATE,
                    RAND_R_ERROR_ENTROPY_POOL_WAS_IGNORED);
            drbg->state = DRBG_ERROR;
        }
        RAND_POOL_free(drbg->pool);
        drbg->pool = NULL;
    }
    if (drbg->state == DRBG_READY)
        return 1;
    return 0;
}

/*
 * Uninstantiate |drbg|. Must be instantiated before it can be used.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_uninstantiate(RAND_DRBG *drbg)
{
    if (drbg->meth == NULL)
    {
        RANDerr(RAND_F_RAND_DRBG_UNINSTANTIATE,
                RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED);
        return 0;
    }

    /* Clear the entire drbg->ctr struct, then reset some important
     * members of the drbg->ctr struct (e.g. keysize, df_ks) to their
     * initial values.
     */
    drbg->meth->uninstantiate(drbg);
    return RAND_DRBG_set(drbg, drbg->nid, drbg->flags);
}

/*
 * Reseed |drbg|, mixing in the specified data
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_reseed(RAND_DRBG *drbg,
                     const unsigned char *adin, size_t adinlen)
{
    unsigned char *entropy = NULL;
    size_t entropylen = 0;

    if (drbg->state == DRBG_ERROR) {
        RANDerr(RAND_F_RAND_DRBG_RESEED, RAND_R_IN_ERROR_STATE);
        return 0;
    }
    if (drbg->state == DRBG_UNINITIALISED) {
        RANDerr(RAND_F_RAND_DRBG_RESEED, RAND_R_NOT_INSTANTIATED);
        return 0;
    }

    if (adin == NULL)
        adinlen = 0;
    else if (adinlen > drbg->max_adinlen) {
        RANDerr(RAND_F_RAND_DRBG_RESEED, RAND_R_ADDITIONAL_INPUT_TOO_LONG);
        return 0;
    }

    drbg->state = DRBG_ERROR;
    if (drbg->get_entropy != NULL)
        entropylen = drbg->get_entropy(drbg, &entropy, drbg->strength,
                                   drbg->min_entropylen, drbg->max_entropylen);
    if (entropylen < drbg->min_entropylen
        || entropylen > drbg->max_entropylen) {
        RANDerr(RAND_F_RAND_DRBG_RESEED, RAND_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (!drbg->meth->reseed(drbg, entropy, entropylen, adin, adinlen))
        goto end;

    drbg->state = DRBG_READY;
    drbg->generate_counter = 0;
    drbg->reseed_time = time(NULL);
    if (drbg->reseed_counter > 0) {
        if (drbg->parent == NULL)
            drbg->reseed_counter++;
        else
            drbg->reseed_counter = drbg->parent->reseed_counter;
    }

end:
    if (entropy != NULL && drbg->cleanup_entropy != NULL)
        drbg->cleanup_entropy(drbg, entropy, entropylen);
    if (drbg->state == DRBG_READY)
        return 1;
    return 0;
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
int rand_drbg_restart(RAND_DRBG *drbg,
                      const unsigned char *buffer, size_t len, size_t entropy)
{
    int reseeded = 0;
    const unsigned char *adin = NULL;
    size_t adinlen = 0;

    if (drbg->pool != NULL) {
        RANDerr(RAND_F_RAND_DRBG_RESTART, ERR_R_INTERNAL_ERROR);
        RAND_POOL_free(drbg->pool);
        drbg->pool = NULL;
    }

    if (buffer != NULL) {
        if (entropy > 0) {
            if (drbg->max_entropylen < len) {
                RANDerr(RAND_F_RAND_DRBG_RESTART,
                    RAND_R_ENTROPY_INPUT_TOO_LONG);
                return 0;
            }

            if (entropy > 8 * len) {
                RANDerr(RAND_F_RAND_DRBG_RESTART, RAND_R_ENTROPY_OUT_OF_RANGE);
                return 0;
            }

            /* will be picked up by the rand_drbg_get_entropy() callback */
            drbg->pool = RAND_POOL_new(entropy, len, len);
            if (drbg->pool == NULL)
                return 0;

            RAND_POOL_add(drbg->pool, buffer, len, entropy);
        } else {
            if (drbg->max_adinlen < len) {
                RANDerr(RAND_F_RAND_DRBG_RESTART,
                        RAND_R_ADDITIONAL_INPUT_TOO_LONG);
                return 0;
            }
            adin = buffer;
            adinlen = len;
        }
    }

    /* repair error state */
    if (drbg->state == DRBG_ERROR)
        RAND_DRBG_uninstantiate(drbg);

    /* repair uninitialized state */
    if (drbg->state == DRBG_UNINITIALISED) {
        /* reinstantiate drbg */
        RAND_DRBG_instantiate(drbg,
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
             * Similar to RAND_DRBG_reseed(), but the provided additional
             * data |adin| is mixed into the current state without pulling
             * entropy from the trusted entropy source using get_entropy().
             * This is not a reseeding in the strict sense of NIST SP 800-90A.
             */
            drbg->meth->reseed(drbg, adin, adinlen, NULL, 0);
        } else if (reseeded == 0) {
            /* do a full reseeding if it has not been done yet above */
            RAND_DRBG_reseed(drbg, NULL, 0);
        }
    }

    /* check whether a given entropy pool was cleared properly during reseed */
    if (drbg->pool != NULL) {
        drbg->state = DRBG_ERROR;
        RANDerr(RAND_F_RAND_DRBG_RESTART, ERR_R_INTERNAL_ERROR);
        RAND_POOL_free(drbg->pool);
        drbg->pool = NULL;
        return 0;
    }

    return drbg->state == DRBG_READY;
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
int RAND_DRBG_generate(RAND_DRBG *drbg, unsigned char *out, size_t outlen,
                       int prediction_resistance,
                       const unsigned char *adin, size_t adinlen)
{
    int reseed_required = 0;

    if (drbg->state != DRBG_READY) {
        /* try to recover from previous errors */
        rand_drbg_restart(drbg, NULL, 0, 0);

        if (drbg->state == DRBG_ERROR) {
            RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_IN_ERROR_STATE);
            return 0;
        }
        if (drbg->state == DRBG_UNINITIALISED) {
            RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_NOT_INSTANTIATED);
            return 0;
        }
    }

    if (outlen > drbg->max_request) {
        RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_REQUEST_TOO_LARGE_FOR_DRBG);
        return 0;
    }
    if (adinlen > drbg->max_adinlen) {
        RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_ADDITIONAL_INPUT_TOO_LONG);
        return 0;
    }

    if (drbg->fork_count != rand_fork_count) {
        drbg->fork_count = rand_fork_count;
        reseed_required = 1;
    }

    if (drbg->reseed_interval > 0) {
        if (drbg->generate_counter >= drbg->reseed_interval)
            reseed_required = 1;
    }
    if (drbg->reseed_time_interval > 0) {
        time_t now = time(NULL);
        if (now < drbg->reseed_time
            || now - drbg->reseed_time >= drbg->reseed_time_interval)
            reseed_required = 1;
    }
    if (drbg->reseed_counter > 0 && drbg->parent != NULL) {
        if (drbg->reseed_counter != drbg->parent->reseed_counter)
            reseed_required = 1;
    }

    if (reseed_required || prediction_resistance) {
        if (!RAND_DRBG_reseed(drbg, adin, adinlen)) {
            RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_RESEED_ERROR);
            return 0;
        }
        adin = NULL;
        adinlen = 0;
    }

    if (!drbg->meth->generate(drbg, out, outlen, adin, adinlen)) {
        drbg->state = DRBG_ERROR;
        RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_GENERATE_ERROR);
        return 0;
    }

    drbg->generate_counter++;

    return 1;
}

/*
 * Generates |outlen| random bytes and stores them in |out|. It will
 * using the given |drbg| to generate the bytes.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success 0 on failure.
 */
int RAND_DRBG_bytes(RAND_DRBG *drbg, unsigned char *out, size_t outlen)
{
    unsigned char *additional = NULL;
    size_t additional_len;
    size_t ret;

    additional_len = rand_drbg_get_additional_data(&additional, drbg->max_adinlen);
    ret = RAND_DRBG_generate(drbg, out, outlen, 0, additional, additional_len);
    if (additional_len != 0)
        OPENSSL_secure_clear_free(additional, additional_len);

    return ret;
}

/*
 * Set the RAND_DRBG callbacks for obtaining entropy and nonce.
 *
 * In the following, the signature and the semantics of the
 * get_entropy() and cleanup_entropy() callbacks are explained.
 *
 * GET_ENTROPY
 *
 *     size_t get_entropy(RAND_DRBG *ctx,
 *                        unsigned char **pout,
 *                        int entropy,
 *                        size_t min_len, size_t max_len);
 *
 * This is a request to allocate and fill a buffer of size
 * |min_len| <= size <= |max_len| (in bytes) which contains
 * at least |entropy| bits of randomness. The buffer's address is
 * to be returned in |*pout| and the number of collected
 * randomness bytes (which may be less than the allocated size
 * of the buffer) as return value.
 *
 * If the callback fails to acquire at least |entropy| bits of
 * randomness, it shall return a buffer length of 0.
 *
 * CLEANUP_ENTROPY
 *
 *     void cleanup_entropy(RAND_DRBG *ctx,
 *                          unsigned char *out, size_t outlen);
 *
 * A request to clear and free the buffer allocated by get_entropy().
 * The values |out| and |outlen| are expected to be the random buffer's
 * address and length, as returned by the get_entropy() callback.
 *
 * GET_NONCE, CLEANUP_NONCE
 *
 * Signature and semantics of the get_nonce() and cleanup_nonce()
 * callbacks are analogous to get_entropy() and cleanup_entropy().
 * Currently, the nonce is used only for the known answer tests.
 */
int RAND_DRBG_set_callbacks(RAND_DRBG *drbg,
                            RAND_DRBG_get_entropy_fn get_entropy,
                            RAND_DRBG_cleanup_entropy_fn cleanup_entropy,
                            RAND_DRBG_get_nonce_fn get_nonce,
                            RAND_DRBG_cleanup_nonce_fn cleanup_nonce)
{
    if (drbg->state != DRBG_UNINITIALISED)
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
int RAND_DRBG_set_reseed_interval(RAND_DRBG *drbg, unsigned int interval)
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
int RAND_DRBG_set_reseed_time_interval(RAND_DRBG *drbg, time_t interval)
{
    if (interval > MAX_RESEED_TIME_INTERVAL)
        return 0;
    drbg->reseed_time_interval = interval;
    return 1;
}

/*
 * Get and set the EXDATA
 */
int RAND_DRBG_set_ex_data(RAND_DRBG *drbg, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&drbg->ex_data, idx, arg);
}

void *RAND_DRBG_get_ex_data(const RAND_DRBG *drbg, int idx)
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
static RAND_DRBG *drbg_setup(RAND_DRBG *parent)
{
    RAND_DRBG *drbg;

    drbg = OPENSSL_secure_zalloc(sizeof(RAND_DRBG));
    if (drbg == NULL)
        return NULL;

    drbg->lock = CRYPTO_THREAD_lock_new();
    if (drbg->lock == NULL) {
        RANDerr(RAND_F_DRBG_SETUP, RAND_R_FAILED_TO_CREATE_LOCK);
        goto err;
    }

    if (RAND_DRBG_set(drbg,
                      RAND_DRBG_NID, RAND_DRBG_FLAG_CTR_USE_DF) != 1)
        goto err;
    if (RAND_DRBG_set_callbacks(drbg, rand_drbg_get_entropy,
                                rand_drbg_cleanup_entropy, NULL, NULL) != 1)
        goto err;

    if (parent == NULL) {
        drbg->reseed_interval = MASTER_RESEED_INTERVAL;
        drbg->reseed_time_interval = MASTER_RESEED_TIME_INTERVAL;
    } else {
        drbg->parent = parent;
        drbg->reseed_interval = SLAVE_RESEED_INTERVAL;
        drbg->reseed_time_interval = SLAVE_RESEED_TIME_INTERVAL;
    }

    /* enable seed propagation */
    drbg->reseed_counter = 1;

    /*
     * Ignore instantiation error so support just-in-time instantiation.
     *
     * The state of the drbg will be checked in RAND_DRBG_generate() and
     * an automatic recovery is attempted.
     */
    RAND_DRBG_instantiate(drbg,
                          (const unsigned char *) ossl_pers_string,
                          sizeof(ossl_pers_string) - 1);
    return drbg;

err:
    drbg_cleanup(drbg);
    return NULL;
}

/*
 * Initialize the global DRBGs on first use.
 * Returns 1 on success, 0 on failure.
 */
DEFINE_RUN_ONCE_STATIC(do_rand_drbg_init)
{
    /*
     * ensure that libcrypto is initialized, otherwise the
     * DRBG locks are not cleaned up properly
     */
    if (!OPENSSL_init_crypto(0, NULL))
        return 0;

    drbg_master = drbg_setup(NULL);
    drbg_public = drbg_setup(drbg_master);
    drbg_private = drbg_setup(drbg_master);

    if (drbg_master == NULL || drbg_public == NULL || drbg_private == NULL)
        return 0;

    return 1;
}

/* Cleans up the given global DRBG  */
static void drbg_cleanup(RAND_DRBG *drbg)
{
    if (drbg != NULL) {
        RAND_DRBG_uninstantiate(drbg);
        CRYPTO_THREAD_lock_free(drbg->lock);
        OPENSSL_secure_clear_free(drbg, sizeof(RAND_DRBG));
    }
}

/* Clean up the global DRBGs before exit */
void rand_drbg_cleanup_int(void)
{
    drbg_cleanup(drbg_private);
    drbg_cleanup(drbg_public);
    drbg_cleanup(drbg_master);

    drbg_private = drbg_public = drbg_master = NULL;
}

/* Implements the default OpenSSL RAND_bytes() method */
static int drbg_bytes(unsigned char *out, int count)
{
    int ret = 0;
    size_t chunk;
    RAND_DRBG *drbg = RAND_DRBG_get0_public();

    if (drbg == NULL)
        return 0;

    CRYPTO_THREAD_write_lock(drbg->lock);
    for ( ; count > 0; count -= chunk, out += chunk) {
        chunk = count;
        if (chunk > drbg->max_request)
            chunk = drbg->max_request;
        ret = RAND_DRBG_generate(drbg, out, chunk, 0, NULL, 0);
        if (!ret)
            goto err;
    }
    ret = 1;

err:
    CRYPTO_THREAD_unlock(drbg->lock);
    return ret;
}

/* Implements the default OpenSSL RAND_add() method */
static int drbg_add(const void *buf, int num, double randomness)
{
    int ret = 0;
    RAND_DRBG *drbg = RAND_DRBG_get0_master();

    if (drbg == NULL)
        return 0;

    if (num < 0 || randomness < 0.0)
        return 0;

    if (randomness > (double)drbg->max_entropylen) {
        /*
         * The purpose of this check is to bound |randomness| by a
         * relatively small value in order to prevent an integer
         * overflow when multiplying by 8 in the rand_drbg_restart()
         * call below.
         */
        return 0;
    }

    CRYPTO_THREAD_write_lock(drbg->lock);
    ret = rand_drbg_restart(drbg, buf,
                            (size_t)(unsigned int)num,
                            (size_t)(8*randomness));
    CRYPTO_THREAD_unlock(drbg->lock);

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
    RAND_DRBG *drbg = RAND_DRBG_get0_master();

    if (drbg == NULL)
        return 0;

    CRYPTO_THREAD_write_lock(drbg->lock);
    ret = drbg->state == DRBG_READY ? 1 : 0;
    CRYPTO_THREAD_unlock(drbg->lock);
    return ret;
}

/*
 * Get the master DRBG.
 * Returns pointer to the DRBG on success, NULL on failure.
 *
 */
RAND_DRBG *RAND_DRBG_get0_master(void)
{
    if (!RUN_ONCE(&rand_drbg_init, do_rand_drbg_init))
        return NULL;

    return drbg_master;
}

/*
 * Get the public DRBG.
 * Returns pointer to the DRBG on success, NULL on failure.
 */
RAND_DRBG *RAND_DRBG_get0_public(void)
{
    if (!RUN_ONCE(&rand_drbg_init, do_rand_drbg_init))
        return NULL;

    return drbg_public;
}

/*
 * Get the private DRBG.
 * Returns pointer to the DRBG on success, NULL on failure.
 */
RAND_DRBG *RAND_DRBG_get0_private(void)
{
    if (!RUN_ONCE(&rand_drbg_init, do_rand_drbg_init))
        return NULL;

    return drbg_private;
}

RAND_METHOD rand_meth = {
    drbg_seed,
    drbg_bytes,
    NULL,
    drbg_add,
    drbg_bytes,
    drbg_status
};

RAND_METHOD *RAND_OpenSSL(void)
{
    return &rand_meth;
}
