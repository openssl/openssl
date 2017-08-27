/*
 * Copyright 2011-2017 The OpenSSL Project Authors. All Rights Reserved.
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

static CRYPTO_ONCE rand_init_drbg = CRYPTO_ONCE_STATIC_INIT;

/*
 * Set/initialize |drbg| to be of type |nid|, with optional |flags|.
 * Return -2 if the type is not supported, 1 on success and -1 on
 * failure.
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
        return -2;
    case 0:
        /* Uninitialized; that's okay. */
        return 1;
    case NID_aes_128_ctr:
    case NID_aes_192_ctr:
    case NID_aes_256_ctr:
        ret = ctr_init(drbg);
        break;
    }

    if (ret < 0)
        RANDerr(RAND_F_RAND_DRBG_SET, RAND_R_ERROR_INITIALISING_DRBG);
    return ret;
}

/*
 * Allocate memory and initialize a new DRBG.  The |parent|, if not
 * NULL, will be used to auto-seed this RAND_DRBG as needed.
 */
RAND_DRBG *RAND_DRBG_new(int type, unsigned int flags, RAND_DRBG *parent)
{
    RAND_DRBG *drbg = OPENSSL_zalloc(sizeof(*drbg));

    if (drbg == NULL) {
        RANDerr(RAND_F_RAND_DRBG_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    drbg->size = RANDOMNESS_NEEDED;
    drbg->fork_count = rand_fork_count;
    drbg->parent = parent;
    if (RAND_DRBG_set(drbg, type, flags) < 0)
        goto err;

    if (parent != NULL) {
        if (!RAND_DRBG_set_callbacks(drbg, drbg_entropy_from_parent,
                                     drbg_release_entropy,
                                     NULL, NULL))
            goto err;
    }

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
    /* The global DRBG is free'd by rand_cleanup_drbg_int() */
    if (drbg == NULL || drbg == &rand_drbg)
        return;

    ctr_uninstantiate(drbg);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DRBG, drbg, &drbg->ex_data);
    OPENSSL_clear_free(drbg, sizeof(*drbg));
}

/*
 * Instantiate |drbg|, after it has been initialized.  Use |pers| and
 * |perslen| as prediction-resistance input.
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
    if (entropylen < drbg->min_entropylen || entropylen > drbg->max_entropylen) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, RAND_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (drbg->max_noncelen > 0 && drbg->get_nonce != NULL) {
        noncelen = drbg->get_nonce(drbg, &nonce, drbg->strength / 2,
                                   drbg->min_noncelen, drbg->max_noncelen);
        if (noncelen < drbg->min_noncelen || noncelen > drbg->max_noncelen) {
            RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, RAND_R_ERROR_RETRIEVING_NONCE);
            goto end;
        }
    }

    if (!ctr_instantiate(drbg, entropy, entropylen,
                         nonce, noncelen, pers, perslen)) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, RAND_R_ERROR_INSTANTIATING_DRBG);
        goto end;
    }

    drbg->state = DRBG_READY;
    drbg->reseed_counter = 1;

end:
    if (entropy != NULL && drbg->cleanup_entropy != NULL)
        drbg->cleanup_entropy(drbg, entropy, entropylen);
    if (nonce != NULL && drbg->cleanup_nonce!= NULL )
        drbg->cleanup_nonce(drbg, nonce, noncelen);
    if (drbg->state == DRBG_READY)
        return 1;
    return 0;
}

/*
 * Uninstantiate |drbg|. Must be instantiated before it can be used.
 */
int RAND_DRBG_uninstantiate(RAND_DRBG *drbg)
{
    int ret = ctr_uninstantiate(drbg);

    OPENSSL_cleanse(&drbg->ctr, sizeof(drbg->ctr));
    drbg->state = DRBG_UNINITIALISED;
    return ret;
}

/*
 * Mix in the specified data to reseed |drbg|.
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
    if (entropylen < drbg->min_entropylen || entropylen > drbg->max_entropylen) {
        RANDerr(RAND_F_RAND_DRBG_RESEED, RAND_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (!ctr_reseed(drbg, entropy, entropylen, adin, adinlen))
        goto end;
    drbg->state = DRBG_READY;
    drbg->reseed_counter = 1;

end:
    if (entropy != NULL && drbg->cleanup_entropy != NULL)
        drbg->cleanup_entropy(drbg, entropy, entropylen);
    if (drbg->state == DRBG_READY)
        return 1;
    return 0;
}

/*
 * Generate |outlen| bytes into the buffer at |out|.  Reseed if we need
 * to or if |prediction_resistance| is set.  Additional input can be
 * sent in |adin| and |adinlen|.
 */
int RAND_DRBG_generate(RAND_DRBG *drbg, unsigned char *out, size_t outlen,
                       int prediction_resistance,
                       const unsigned char *adin, size_t adinlen)
{
    if (drbg->state == DRBG_ERROR) {
        RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_IN_ERROR_STATE);
        return 0;
    }
    if (drbg->state == DRBG_UNINITIALISED) {
        RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_NOT_INSTANTIATED);
        return 0;
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
        drbg->state = DRBG_RESEED;
    }

    if (drbg->reseed_counter >= drbg->reseed_interval)
        drbg->state = DRBG_RESEED;

    if (drbg->state == DRBG_RESEED || prediction_resistance) {
        if (!RAND_DRBG_reseed(drbg, adin, adinlen)) {
            RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_RESEED_ERROR);
            return 0;
        }
        adin = NULL;
        adinlen = 0;
    }

    if (!ctr_generate(drbg, out, outlen, adin, adinlen)) {
        drbg->state = DRBG_ERROR;
        RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_GENERATE_ERROR);
        return 0;
    }

    if (drbg->reseed_counter >= drbg->reseed_interval)
        drbg->state = DRBG_RESEED;
    else
        drbg->reseed_counter++;
    return 1;
}

/*
 * Set the callbacks for entropy and nonce.  We currently don't use
 * the nonce; that's mainly for the KATs
 */
int RAND_DRBG_set_callbacks(RAND_DRBG *drbg,
                            RAND_DRBG_get_entropy_fn cb_get_entropy,
                            RAND_DRBG_cleanup_entropy_fn cb_cleanup_entropy,
                            RAND_DRBG_get_nonce_fn cb_get_nonce,
                            RAND_DRBG_cleanup_nonce_fn cb_cleanup_nonce)
{
    if (drbg->state != DRBG_UNINITIALISED)
        return 0;
    drbg->get_entropy = cb_get_entropy;
    drbg->cleanup_entropy = cb_cleanup_entropy;
    drbg->get_nonce = cb_get_nonce;
    drbg->cleanup_nonce = cb_cleanup_nonce;
    return 1;
}

/*
 * Set the reseed interval.
 */
int RAND_DRBG_set_reseed_interval(RAND_DRBG *drbg, int interval)
{
    if (interval < 0 || interval > MAX_RESEED)
        return 0;
    drbg->reseed_interval = interval;
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
 * Creates a global DRBG with default settings.
 * Returns 1 on success, 0 on failure
 */
static int setup_drbg(RAND_DRBG *drbg)
{
    int ret = 1;

    drbg->lock = CRYPTO_THREAD_lock_new();
    ret &= drbg->lock != NULL;
    drbg->size = RANDOMNESS_NEEDED;
    drbg->secure = CRYPTO_secure_malloc_initialized();
    /* If you change these parameters, see RANDOMNESS_NEEDED */
    ret &= RAND_DRBG_set(drbg,
                         NID_aes_128_ctr, RAND_DRBG_FLAG_CTR_USE_DF) == 1;
    ret &= RAND_DRBG_set_callbacks(drbg, drbg_entropy_from_system,
                                   drbg_release_entropy, NULL, NULL) == 1;
    ret &= RAND_DRBG_instantiate(drbg, NULL, 0) == 1;
    return ret;
}

/*
 * Initialize the global DRBGs on first use.
 * Returns 1 on success, 0 on failure.
 */
DEFINE_RUN_ONCE_STATIC(do_rand_init_drbg)
{
    int ret = 1;

    ret &= setup_drbg(&rand_drbg);
    ret &= setup_drbg(&priv_drbg);

    return ret;
}

/* Clean up a DRBG and free it */
static void free_drbg(RAND_DRBG *drbg)
{
    CRYPTO_THREAD_lock_free(drbg->lock);
    RAND_DRBG_uninstantiate(drbg);
}

/* Clean up the global DRBGs before exit */
void rand_cleanup_drbg_int(void)
{
    free_drbg(&rand_drbg);
    free_drbg(&priv_drbg);
}

static int drbg_bytes(unsigned char *out, int count)
{
    int ret = 0;
    size_t chunk;
    RAND_DRBG *drbg = RAND_DRBG_get0_global();

    if (drbg == NULL)
        return 0;

    CRYPTO_THREAD_write_lock(drbg->lock);
    if (drbg->state == DRBG_UNINITIALISED)
        goto err;

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

static int drbg_add(const void *buf, int num, double randomness)
{
    unsigned char *in = (unsigned char *)buf;
    unsigned char *out, *end;

    CRYPTO_THREAD_write_lock(rand_bytes.lock);
    out = &rand_bytes.buff[rand_bytes.curr];
    end = &rand_bytes.buff[rand_bytes.size];

    /* Copy whatever fits into the end of the buffer. */
    for ( ; --num >= 0 && out < end; rand_bytes.curr++)
        *out++ = *in++;

    /* XOR any the leftover. */
    while (num > 0) {
        for (out = rand_bytes.buff; --num >= 0 && out < end; )
            *out++ ^= *in++;
    }

    CRYPTO_THREAD_unlock(rand_bytes.lock);
    return 1;
}

static int drbg_seed(const void *buf, int num)
{
    return drbg_add(buf, num, num);
}

static int drbg_status(void)
{
    int ret;
    RAND_DRBG *drbg = RAND_DRBG_get0_global();

    if (drbg == NULL)
        return 0;

    CRYPTO_THREAD_write_lock(drbg->lock);
    ret = drbg->state == DRBG_READY ? 1 : 0;
    CRYPTO_THREAD_unlock(drbg->lock);
    return ret;
}

/*
 * Get the global public DRBG.
 * Returns pointer to the DRBG on success, NULL on failure.
 */
RAND_DRBG *RAND_DRBG_get0_global(void)
{
    if (!RUN_ONCE(&rand_init_drbg, do_rand_init_drbg))
        return NULL;

    return &rand_drbg;
}

/*
 * Get the global private DRBG.
 * Returns pointer to the DRBG on success, NULL on failure.
 */
RAND_DRBG *RAND_DRBG_get0_priv_global(void)
{
    if (!RUN_ONCE(&rand_init_drbg, do_rand_init_drbg))
        return NULL;

    return &priv_drbg;
}

RAND_DRBG rand_drbg; /* The default global DRBG. */
RAND_DRBG priv_drbg; /* The global private-key DRBG. */

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
