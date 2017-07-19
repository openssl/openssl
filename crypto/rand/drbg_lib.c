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
 * Get entropy from the existing callback.  This is mainly used for KATs.
 */
static size_t get_entropy(DRBG_CTX *dctx, unsigned char **pout,
                          int entropy, size_t min_len, size_t max_len)
{
    if (dctx->get_entropy != NULL)
        return dctx->get_entropy(dctx, pout, entropy, min_len, max_len);
    /* TODO: Get from parent if it exists. */
    return 0;
}

/*
 * Cleanup entropy.
 */
static void cleanup_entropy(DRBG_CTX *dctx, unsigned char *out, size_t olen)
{
    if (dctx->cleanup_entropy != NULL)
        dctx->cleanup_entropy(dctx, out, olen);
}

/*
 * The OpenSSL model is to have new and free functions, and that new
 * does all initialization.  That is not the NIST model, which has
 * instantiation and un-instantiate, and re-use within a new/free
 * lifecycle.  (No doubt this comes from the desire to support hardware
 * DRBG, where allocation of resources on something like an HSM is
 * a much bigger deal than just re-setting an allocated resource.)
 *
 * The DRBG_CTX is OpenSSL's opaque pointer to an instance of the
 * DRBG.
 */

/*
 * Set/initialize |dctx| to be of type |nid|, with optional |flags|.
 * Return -2 if the type is not supported, 1 on success and -1 on
 * failure.
 */
int RAND_DRBG_set(DRBG_CTX *dctx, int nid, unsigned int flags)
{
    int ret = 1;

    dctx->status = DRBG_STATUS_UNINITIALISED;
    dctx->flags = flags;
    dctx->nid = nid;

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
        ret = ctr_init(dctx);
        break;
    }

    if (ret < 0)
        RANDerr(RAND_F_RAND_DRBG_SET, RAND_R_ERROR_INITIALISING_DRBG);
    return ret;
}

/*
 * Allocate memory and initialize a new DRBG.  The |parent|, if not
 * NULL, will be used to auto-seed this DRBG_CTX as needed.
 */
DRBG_CTX *RAND_DRBG_new(int type, unsigned int flags, DRBG_CTX *parent)
{
    DRBG_CTX *dctx = OPENSSL_zalloc(sizeof(*dctx));

    if (dctx == NULL) {
        RANDerr(RAND_F_RAND_DRBG_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    dctx->parent = parent;
    if (RAND_DRBG_set(dctx, type, flags) < 0) {
        OPENSSL_free(dctx);
        return NULL;
    }
    return dctx;
}

/*
 * Uninstantiate |dctx| and free all memory.
 */
void RAND_DRBG_free(DRBG_CTX *dctx)
{
    if (dctx == NULL)
        return;

    ctr_uninstantiate(dctx);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DRBG, dctx, &dctx->ex_data);

    /* Don't free up default DRBG */
    if (dctx == RAND_DRBG_get_default()) {
        memset(dctx, 0, sizeof(DRBG_CTX));
        dctx->nid = 0;
        dctx->status = DRBG_STATUS_UNINITIALISED;
    } else {
        OPENSSL_cleanse(&dctx->ctr, sizeof(dctx->ctr));
        OPENSSL_free(dctx);
    }
}

/*
 * Instantiate |dctx|, after it has been initialized.  Use |pers| and
 * |perslen| as prediction-resistance input.
 */
int RAND_DRBG_instantiate(DRBG_CTX *dctx,
                          const unsigned char *pers, size_t perslen)
{
    size_t entlen = 0, noncelen = 0;
    unsigned char *nonce = NULL, *entropy = NULL;
    int r = 0;

    if (perslen > dctx->max_pers) {
        r = RAND_R_PERSONALISATION_STRING_TOO_LONG;
        goto end;
    }
    if (dctx->status != DRBG_STATUS_UNINITIALISED) {
        r = dctx->status == DRBG_STATUS_ERROR ? RAND_R_IN_ERROR_STATE
                                              : RAND_R_ALREADY_INSTANTIATED;
        goto end;
    }

    dctx->status = DRBG_STATUS_ERROR;
    entlen = get_entropy(dctx, &entropy, dctx->strength,
                         dctx->min_entropy, dctx->max_entropy);
    if (entlen < dctx->min_entropy || entlen > dctx->max_entropy) {
        r = RAND_R_ERROR_RETRIEVING_ENTROPY;
        goto end;
    }

    if (dctx->max_nonce > 0 && dctx->get_nonce != NULL) {
        noncelen = dctx->get_nonce(dctx, &nonce,
                                   dctx->strength / 2,
                                   dctx->min_nonce, dctx->max_nonce);

        if (noncelen < dctx->min_nonce || noncelen > dctx->max_nonce) {
            r = RAND_R_ERROR_RETRIEVING_NONCE;
            goto end;
        }
    }

    if (!ctr_instantiate(dctx, entropy, entlen,
                         nonce, noncelen, pers, perslen)) {
        r = RAND_R_ERROR_INSTANTIATING_DRBG;
        goto end;
    }

    dctx->status = DRBG_STATUS_READY;
    dctx->reseed_counter = 1;

end:
    if (entropy != NULL && dctx->cleanup_entropy != NULL)
        dctx->cleanup_entropy(dctx, entropy, entlen);
    if (nonce != NULL && dctx->cleanup_nonce!= NULL )
        dctx->cleanup_nonce(dctx, nonce, noncelen);
    if (dctx->status == DRBG_STATUS_READY)
        return 1;

    if (r)
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, r);
    return 0;
}

/*
 * Uninstantiate |dctx|. Must be instantiated before it can be used.
 */
int RAND_DRBG_uninstantiate(DRBG_CTX *dctx)
{
    int ret = ctr_uninstantiate(dctx);

    OPENSSL_cleanse(&dctx->ctr, sizeof(dctx->ctr));
    dctx->status = DRBG_STATUS_UNINITIALISED;
    return ret;
}

/*
 * Mix in the specified data to reseed |dctx|.
 */
int RAND_DRBG_reseed(DRBG_CTX *dctx,
                     const unsigned char *adin, size_t adinlen)
{
    unsigned char *entropy = NULL;
    size_t entlen = 0;
    int r = 0;

    if (dctx->status != DRBG_STATUS_READY
            && dctx->status != DRBG_STATUS_RESEED) {
        if (dctx->status == DRBG_STATUS_ERROR)
            r = RAND_R_IN_ERROR_STATE;
        else if (dctx->status == DRBG_STATUS_UNINITIALISED)
            r = RAND_R_NOT_INSTANTIATED;
        goto end;
    }

    if (adin == NULL)
        adinlen = 0;
    else if (adinlen > dctx->max_adin) {
        r = RAND_R_ADDITIONAL_INPUT_TOO_LONG;
        goto end;
    }

    dctx->status = DRBG_STATUS_ERROR;
    entlen = get_entropy(dctx, &entropy, dctx->strength,
                         dctx->min_entropy, dctx->max_entropy);

    if (entlen < dctx->min_entropy || entlen > dctx->max_entropy) {
        r = RAND_R_ERROR_RETRIEVING_ENTROPY;
        goto end;
    }

    if (!ctr_reseed(dctx, entropy, entlen, adin, adinlen))
        goto end;
    dctx->status = DRBG_STATUS_READY;
    dctx->reseed_counter = 1;

end:
    if (entropy != NULL && dctx->cleanup_entropy != NULL)
        cleanup_entropy(dctx, entropy, entlen);
    if (dctx->status == DRBG_STATUS_READY)
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
int RAND_DRBG_generate(DRBG_CTX *dctx, unsigned char *out, size_t outlen,
                       int prediction_resistance,
                       const unsigned char *adin, size_t adinlen)
{
    int r = 0;

    if (dctx->status != DRBG_STATUS_READY
            && dctx->status != DRBG_STATUS_RESEED) {
        if (dctx->status == DRBG_STATUS_ERROR)
            r = RAND_R_IN_ERROR_STATE;
        else if(dctx->status == DRBG_STATUS_UNINITIALISED)
            r = RAND_R_NOT_INSTANTIATED;
        goto end;
    }

    if (outlen > dctx->max_request) {
        r = RAND_R_REQUEST_TOO_LARGE_FOR_DRBG;
        return 0;
    }
    if (adinlen > dctx->max_adin) {
        r = RAND_R_ADDITIONAL_INPUT_TOO_LONG;
        goto end;
    }

    if (dctx->reseed_counter >= dctx->reseed_interval)
        dctx->status = DRBG_STATUS_RESEED;

    if (dctx->status == DRBG_STATUS_RESEED || prediction_resistance) {
        if (!RAND_DRBG_reseed(dctx, adin, adinlen)) {
            r = RAND_R_RESEED_ERROR;
            goto end;
        }
        adin = NULL;
        adinlen = 0;
    }

    if (!ctr_generate(dctx, out, outlen, adin, adinlen)) {
        r = RAND_R_GENERATE_ERROR;
        dctx->status = DRBG_STATUS_ERROR;
        goto end;
    }
    if (dctx->reseed_counter >= dctx->reseed_interval)
        dctx->status = DRBG_STATUS_RESEED;
    else
        dctx->reseed_counter++;
    return 1;

end:
    RANDerr(RAND_F_RAND_DRBG_GENERATE, r);
    return 0;
}

/*
 * Set the callbacks for entropy and nonce.  Used mainly for the KATs
 */
int RAND_DRBG_set_callbacks(DRBG_CTX *dctx,
    size_t (*cb_get_entropy)(DRBG_CTX *ctx, unsigned char **pout,
                             int entropy, size_t min_len, size_t max_len),
    void (*cb_cleanup_entropy)(DRBG_CTX *ctx, unsigned char *out, size_t olen),
    size_t (*cb_get_nonce)(DRBG_CTX *ctx, unsigned char **pout,
                           int entropy, size_t min_len, size_t max_len),
    void (*cb_cleanup_nonce)(DRBG_CTX *ctx, unsigned char *out, size_t olen))
{
    if (dctx->status != DRBG_STATUS_UNINITIALISED)
        return 0;
    dctx->get_entropy = cb_get_entropy;
    dctx->cleanup_entropy = cb_cleanup_entropy;
    dctx->get_nonce = cb_get_nonce;
    dctx->cleanup_nonce = cb_cleanup_nonce;
    return 1;
}

/*
 * Set the reseed interval. Used mainly for the KATs.
 */
int RAND_DRBG_set_reseed_interval(DRBG_CTX *dctx, int interval)
{
    if (interval < 0 || interval > MAX_RESEED)
        return 0;
    dctx->reseed_interval = interval;
    return 1;
}

/*
 * Get and set the EXDATA
 */
int RAND_DRBG_set_ex_data(DRBG_CTX *dctx, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&dctx->ex_data, idx, arg);
}

void *RAND_DRBG_get_ex_data(const DRBG_CTX *dctx, int idx)
{
    return CRYPTO_get_ex_data(&dctx->ex_data, idx);
}
