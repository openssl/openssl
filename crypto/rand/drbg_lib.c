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

/*
 * Support framework for NIST SP 800-90A DRBG, AES-CTR mode.
 */

/*
 * Get entropy from the existing callback.
 */
static size_t get_entropy(RAND_DRBG *drbg, unsigned char **pout,
                          int entropy, size_t min_len, size_t max_len)
{
    if (drbg->get_entropy != NULL)
        return drbg->get_entropy(drbg, pout, entropy, min_len, max_len);
    /* TODO: Get from parent if it exists. */
    return 0;
}

/*
 * Cleanup entropy.
 */
static void cleanup_entropy(RAND_DRBG *drbg, unsigned char *out, size_t olen)
{
    if (drbg->cleanup_entropy != NULL)
        drbg->cleanup_entropy(drbg, out, olen);
}

/*
 * The OpenSSL model is to have new and free functions, and that new
 * does all initialization.  That is not the NIST model, which has
 * instantiation and un-instantiate, and re-use within a new/free
 * lifecycle.  (No doubt this comes from the desire to support hardware
 * DRBG, where allocation of resources on something like an HSM is
 * a much bigger deal than just re-setting an allocated resource.)
 *
 * The RAND_DRBG is OpenSSL's pointer to an instance of a DRBG.
 */

/*
 * Set/initialize |drbg| to be of type |nid|, with optional |flags|.
 * Return -2 if the type is not supported, 1 on success and -1 on
 * failure.
 */
int RAND_DRBG_set(RAND_DRBG *drbg, int nid, unsigned int flags)
{
    int ret = 1;

    drbg->status = DRBG_STATUS_UNINITIALISED;
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
        return NULL;
    }

    drbg->parent = parent;
    if (RAND_DRBG_set(drbg, type, flags) < 0) {
        OPENSSL_free(drbg);
        return NULL;
    }
    return drbg;
}

/*
 * Uninstantiate |drbg| and free all memory.
 */
void RAND_DRBG_free(RAND_DRBG *drbg)
{
    if (drbg == NULL)
        return;

    ctr_uninstantiate(drbg);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DRBG, drbg, &drbg->ex_data);

    /* Don't free up default DRBG */
    if (drbg == RAND_DRBG_get_default()) {
        OPENSSL_cleanse(drbg, sizeof(*drbg));
        drbg->nid = 0;
        drbg->status = DRBG_STATUS_UNINITIALISED;
    } else {
        OPENSSL_cleanse(&drbg->ctr, sizeof(drbg->ctr));
        OPENSSL_free(drbg);
    }
}

/*
 * Instantiate |drbg|, after it has been initialized.  Use |pers| and
 * |perslen| as prediction-resistance input.
 */
int RAND_DRBG_instantiate(RAND_DRBG *drbg,
                          const unsigned char *pers, size_t perslen)
{
    size_t entlen = 0, noncelen = 0;
    unsigned char *nonce = NULL, *entropy = NULL;
    int r = 0;

    if (perslen > drbg->max_pers) {
        r = RAND_R_PERSONALISATION_STRING_TOO_LONG;
        goto end;
    }
    if (drbg->status != DRBG_STATUS_UNINITIALISED) {
        r = drbg->status == DRBG_STATUS_ERROR ? RAND_R_IN_ERROR_STATE
                                              : RAND_R_ALREADY_INSTANTIATED;
        goto end;
    }

    drbg->status = DRBG_STATUS_ERROR;
    entlen = get_entropy(drbg, &entropy, drbg->strength,
                         drbg->min_entropy, drbg->max_entropy);
    if (entlen < drbg->min_entropy || entlen > drbg->max_entropy) {
        r = RAND_R_ERROR_RETRIEVING_ENTROPY;
        goto end;
    }

    if (drbg->max_nonce > 0 && drbg->get_nonce != NULL) {
        noncelen = drbg->get_nonce(drbg, &nonce,
                                   drbg->strength / 2,
                                   drbg->min_nonce, drbg->max_nonce);

        if (noncelen < drbg->min_nonce || noncelen > drbg->max_nonce) {
            r = RAND_R_ERROR_RETRIEVING_NONCE;
            goto end;
        }
    }

    if (!ctr_instantiate(drbg, entropy, entlen,
                         nonce, noncelen, pers, perslen)) {
        r = RAND_R_ERROR_INSTANTIATING_DRBG;
        goto end;
    }

    drbg->status = DRBG_STATUS_READY;
    drbg->reseed_counter = 1;

end:
    if (entropy != NULL && drbg->cleanup_entropy != NULL)
        drbg->cleanup_entropy(drbg, entropy, entlen);
    if (nonce != NULL && drbg->cleanup_nonce!= NULL )
        drbg->cleanup_nonce(drbg, nonce, noncelen);
    if (drbg->status == DRBG_STATUS_READY)
        return 1;

    if (r)
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, r);
    return 0;
}

/*
 * Uninstantiate |drbg|. Must be instantiated before it can be used.
 */
int RAND_DRBG_uninstantiate(RAND_DRBG *drbg)
{
    int ret = ctr_uninstantiate(drbg);

    OPENSSL_cleanse(&drbg->ctr, sizeof(drbg->ctr));
    drbg->status = DRBG_STATUS_UNINITIALISED;
    return ret;
}

/*
 * Mix in the specified data to reseed |drbg|.
 */
int RAND_DRBG_reseed(RAND_DRBG *drbg,
                     const unsigned char *adin, size_t adinlen)
{
    unsigned char *entropy = NULL;
    size_t entlen = 0;
    int r = 0;

    if (drbg->status != DRBG_STATUS_READY
            && drbg->status != DRBG_STATUS_RESEED) {
        if (drbg->status == DRBG_STATUS_ERROR)
            r = RAND_R_IN_ERROR_STATE;
        else if (drbg->status == DRBG_STATUS_UNINITIALISED)
            r = RAND_R_NOT_INSTANTIATED;
        goto end;
    }

    if (adin == NULL)
        adinlen = 0;
    else if (adinlen > drbg->max_adin) {
        r = RAND_R_ADDITIONAL_INPUT_TOO_LONG;
        goto end;
    }

    drbg->status = DRBG_STATUS_ERROR;
    entlen = get_entropy(drbg, &entropy, drbg->strength,
                         drbg->min_entropy, drbg->max_entropy);

    if (entlen < drbg->min_entropy || entlen > drbg->max_entropy) {
        r = RAND_R_ERROR_RETRIEVING_ENTROPY;
        goto end;
    }

    if (!ctr_reseed(drbg, entropy, entlen, adin, adinlen))
        goto end;
    drbg->status = DRBG_STATUS_READY;
    drbg->reseed_counter = 1;

end:
    if (entropy != NULL && drbg->cleanup_entropy != NULL)
        cleanup_entropy(drbg, entropy, entlen);
    if (drbg->status == DRBG_STATUS_READY)
        return 1;
    if (r)
        RANDerr(RAND_F_RAND_DRBG_RESEED, r);

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
    int r = 0;

    if (drbg->status != DRBG_STATUS_READY
            && drbg->status != DRBG_STATUS_RESEED) {
        if (drbg->status == DRBG_STATUS_ERROR)
            r = RAND_R_IN_ERROR_STATE;
        else if(drbg->status == DRBG_STATUS_UNINITIALISED)
            r = RAND_R_NOT_INSTANTIATED;
        goto end;
    }

    if (outlen > drbg->max_request) {
        r = RAND_R_REQUEST_TOO_LARGE_FOR_DRBG;
        return 0;
    }
    if (adinlen > drbg->max_adin) {
        r = RAND_R_ADDITIONAL_INPUT_TOO_LONG;
        goto end;
    }

    if (drbg->reseed_counter >= drbg->reseed_interval)
        drbg->status = DRBG_STATUS_RESEED;

    if (drbg->status == DRBG_STATUS_RESEED || prediction_resistance) {
        if (!RAND_DRBG_reseed(drbg, adin, adinlen)) {
            r = RAND_R_RESEED_ERROR;
            goto end;
        }
        adin = NULL;
        adinlen = 0;
    }

    if (!ctr_generate(drbg, out, outlen, adin, adinlen)) {
        r = RAND_R_GENERATE_ERROR;
        drbg->status = DRBG_STATUS_ERROR;
        goto end;
    }
    if (drbg->reseed_counter >= drbg->reseed_interval)
        drbg->status = DRBG_STATUS_RESEED;
    else
        drbg->reseed_counter++;
    return 1;

end:
    RANDerr(RAND_F_RAND_DRBG_GENERATE, r);
    return 0;
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
    if (drbg->status != DRBG_STATUS_UNINITIALISED)
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
