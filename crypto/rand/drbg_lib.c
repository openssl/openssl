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
#include "rand_drbg_lcl.h"

/*
 * Support framework for SP800-90 DRBGs
 */


int RAND_DRBG_set(DRBG_CTX *dctx, int type, unsigned int flags)
{
    int ret = 1;

    dctx->status = DRBG_STATUS_UNINITIALISED;
    dctx->xflags = flags;
    dctx->type = type;
    dctx->iflags = 0;
    dctx->entropy_blocklen = 0;
    dctx->health_check_cnt = 0;
    dctx->health_check_interval = DRBG_HEALTH_INTERVAL;

    switch (type) {
    default:
        ret = -2;
        break;
    case 0:
        break;
    case NID_sha224:
    case NID_sha256:
    case NID_sha384:
    case NID_sha512:
        ret = drbg_hash_init(dctx);
        break;
    case NID_aes_128_ctr:
    case NID_aes_192_ctr:
    case NID_aes_256_ctr:
        ret = drbg_ctr_init(dctx);
        break;
    case NID_hmacWithSHA1:
    case NID_hmacWithSHA224:
    case NID_hmacWithSHA256:
    case NID_hmacWithSHA512:
        ret = drbg_hmac_init(dctx);
        break;
    }
    if (ret == -2)
        RANDerr(RAND_F_RAND_DRBG_SET, RAND_R_UNSUPPORTED_DRBG_TYPE);
    else if (ret < 0)
        RANDerr(RAND_F_RAND_DRBG_SET, RAND_R_ERROR_INITIALISING_DRBG);

    return ret;
}

DRBG_CTX *RAND_DRBG_new(int type, unsigned int flags)
{
    DRBG_CTX *dctx = OPENSSL_zalloc(sizeof(*dctx));

    if (dctx == NULL) {
        RANDerr(RAND_F_RAND_DRBG_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (RAND_DRBG_set(dctx, type, flags) < 0) {
        OPENSSL_free(dctx);
        return NULL;
    }
    return dctx;
}

void RAND_DRBG_free(DRBG_CTX *dctx)
{
    if (dctx == NULL)
        return;
    if (dctx->uninstantiate)
        dctx->uninstantiate(dctx);

    /* Don't free up default DRBG */
    if (dctx == RAND_DRBG_get_default()) {
        memset(dctx, 0, sizeof(DRBG_CTX));
        dctx->type = 0;
        dctx->status = DRBG_STATUS_UNINITIALISED;
    } else {
        OPENSSL_cleanse(&dctx->d, sizeof(dctx->d));
        OPENSSL_free(dctx);
    }
}

static size_t drbg_get_entropy(DRBG_CTX *dctx, unsigned char **pout,
                               int entropy, size_t min_len, size_t max_len)
{
    unsigned char *tout, *p;
    size_t bl = dctx->entropy_blocklen, ret;

    if (dctx->get_entropy == NULL)
        return 0;
    if (bl == 0)
        return dctx->get_entropy(dctx, pout, entropy, min_len, max_len);

    ret = dctx->get_entropy(dctx, &tout, entropy + bl,
                            min_len + bl, max_len + bl);
    *pout = tout + bl;
    if (ret < min_len + bl || (ret % bl) != 0)
        return 0;

    /* Compare consecutive blocks for continuous PRNG test */
    for (p = tout; p < tout + ret - bl; p += bl) {
        if (memcmp(p, p + bl, bl) == 0) {
            RANDerr(RAND_F_DRBG_GET_ENTROPY, RAND_R_ENTROPY_SOURCE_STUCK);
            return 0;
        }
    }
    ret -= bl;
    return ret > max_len ? max_len : ret;
}

static void cleanup_entropy(DRBG_CTX *dctx, unsigned char *out, size_t olen)
{
    size_t bl = dctx->entropy_blocklen;

    /* Call cleanup with original arguments */
    dctx->cleanup_entropy(dctx, out - bl, olen + bl);
}


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
    if (dctx->instantiate == NULL) {
        r = RAND_R_DRBG_NOT_INITIALISED;
        goto end;
    }
    if (dctx->status != DRBG_STATUS_UNINITIALISED) {
        if (dctx->status == DRBG_STATUS_ERROR)
            r = RAND_R_IN_ERROR_STATE;
        else
            r = RAND_R_ALREADY_INSTANTIATED;
        goto end;
    }

    dctx->status = DRBG_STATUS_ERROR;
    entlen = drbg_get_entropy(dctx, &entropy, dctx->strength,
                              dctx->min_entropy, dctx->max_entropy);
    if (entlen < dctx->min_entropy || entlen > dctx->max_entropy) {
        r = RAND_R_ERROR_RETRIEVING_ENTROPY;
        goto end;
    }

    if (dctx->max_nonce > 0 && dctx->get_nonce) {
        noncelen = dctx->get_nonce(dctx, &nonce,
                                   dctx->strength / 2,
                                   dctx->min_nonce, dctx->max_nonce);

        if (noncelen < dctx->min_nonce || noncelen > dctx->max_nonce) {
            r = RAND_R_ERROR_RETRIEVING_NONCE;
            goto end;
        }
    }

    if (!dctx->instantiate(dctx, entropy, entlen,
                           nonce, noncelen, pers, perslen)) {
        r = RAND_R_ERROR_INSTANTIATING_DRBG;
        goto end;
    }

    dctx->status = DRBG_STATUS_READY;
    if (!(dctx->iflags & DRBG_CUSTOM_RESEED))
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

static int drbg_reseed(DRBG_CTX *dctx,
                       const unsigned char *adin, size_t adinlen,
                       int hcheck)
{
    unsigned char *entropy = NULL;
    size_t entlen = 0;
    int r = 0;

    if (dctx->status != DRBG_STATUS_READY
            && dctx->status != DRBG_STATUS_RESEED) {
        if (dctx->status == DRBG_STATUS_ERROR)
            r = RAND_R_IN_ERROR_STATE;
        else if(dctx->status == DRBG_STATUS_UNINITIALISED)
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
    entlen = drbg_get_entropy(dctx, &entropy, dctx->strength,
                              dctx->min_entropy, dctx->max_entropy);

    if (entlen < dctx->min_entropy || entlen > dctx->max_entropy) {
        r = RAND_R_ERROR_RETRIEVING_ENTROPY;
        goto end;
    }

    if (!dctx->reseed(dctx, entropy, entlen, adin, adinlen))
        goto end;
    dctx->status = DRBG_STATUS_READY;
    if (!(dctx->iflags & DRBG_CUSTOM_RESEED))
        dctx->reseed_counter = 1;

end:
    if (entropy != NULL && dctx->cleanup_entropy != NULL)
        cleanup_entropy(dctx, entropy, entlen);
    if (dctx->status == DRBG_STATUS_READY)
        return 1;
    if (r)
        RANDerr(RAND_F_DRBG_RESEED, r);

    return 0;
}

int RAND_DRBG_reseed(DRBG_CTX *dctx,
                     const unsigned char *adin, size_t adinlen)
{
    return drbg_reseed(dctx, adin, adinlen, 1);
}

static int drbg_check(DRBG_CTX *dctx)
{
    dctx->health_check_cnt++;
    if (dctx->health_check_cnt >= dctx->health_check_interval) {
#if 0
        if (!RAND_DRBG_health_check(dctx)) {
            RANDerr(RAND_F_DRBG_CHECK, RAND_R_SELFTEST_FAILURE);
            return 0;
        }
#endif
    }
    return 1;
}

int RAND_DRBG_generate(DRBG_CTX *dctx, unsigned char *out, size_t outlen,
                       int prediction_resistance,
                       const unsigned char *adin, size_t adinlen)
{
    int r = 0;

    if (!drbg_check(dctx))
        return 0;

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

    if (dctx->iflags & DRBG_CUSTOM_RESEED)
        dctx->generate(dctx, NULL, outlen, NULL, 0);
    else if (dctx->reseed_counter >= dctx->reseed_interval)
        dctx->status = DRBG_STATUS_RESEED;

    if (dctx->status == DRBG_STATUS_RESEED || prediction_resistance) {
        /* If prediction resistance request don't do health check */
        int hcheck = prediction_resistance ? 0 : 1;

        if (!drbg_reseed(dctx, adin, adinlen, hcheck)) {
            r = RAND_R_RESEED_ERROR;
            goto end;
        }
        adin = NULL;
        adinlen = 0;
    }

    if (!dctx->generate(dctx, out, outlen, adin, adinlen)) {
        r = RAND_R_GENERATE_ERROR;
        dctx->status = DRBG_STATUS_ERROR;
        goto end;
    }
    if (!(dctx->iflags & DRBG_CUSTOM_RESEED)) {
        if (dctx->reseed_counter >= dctx->reseed_interval)
            dctx->status = DRBG_STATUS_RESEED;
        else
            dctx->reseed_counter++;
    }
    return 1;

end:
    RANDerr(RAND_F_RAND_DRBG_GENERATE, r);
    return 0;
}

int RAND_DRBG_uninstantiate(DRBG_CTX *dctx)
{
    int ret;

    if (!dctx->uninstantiate)
        ret = 1;
    else
        ret = dctx->uninstantiate(dctx);

    /*
     * Although we'd like to cleanse here we can't, because we have to
     * test the uninstantiate really zeroes the data.
     */
    memset(&dctx->d, 0, sizeof(dctx->d));
    dctx->status = DRBG_STATUS_UNINITIALISED;
    return ret;
}

int RAND_DRBG_set_callbacks(DRBG_CTX *dctx,
    size_t (*get_entropy)(DRBG_CTX *ctx, unsigned char **pout,
                          int entropy, size_t min_len, size_t max_len),
    void (*cleanup_entropy)(DRBG_CTX *ctx, unsigned char *out, size_t olen),
    size_t entropy_blocklen,
    size_t (*get_nonce)(DRBG_CTX *ctx, unsigned char **pout,
                        int entropy, size_t min_len, size_t max_len),
    void (*cleanup_nonce)(DRBG_CTX *ctx, unsigned char *out, size_t olen))
{
    if (dctx->status != DRBG_STATUS_UNINITIALISED)
        return 0;
    dctx->entropy_blocklen = entropy_blocklen;
    dctx->get_entropy = get_entropy;
    dctx->cleanup_entropy = cleanup_entropy;
    dctx->get_nonce = get_nonce;
    dctx->cleanup_nonce = cleanup_nonce;
    return 1;
}

int RAND_DRBG_set_rand_callbacks(DRBG_CTX *dctx,
    size_t (*get_adin)(DRBG_CTX *ctx, unsigned char **pout),
    void (*cleanup_adin)(DRBG_CTX *ctx, unsigned char *out, size_t olen),
    int (*rand_seed_cb)(DRBG_CTX *ctx, const void *buf, int num),
    int (*rand_add_cb)(DRBG_CTX *ctx,
                       const void *buf, int num, double entropy))
{
    if (dctx->status != DRBG_STATUS_UNINITIALISED)
        return 0;
    dctx->get_adin = get_adin;
    dctx->cleanup_adin = cleanup_adin;
    dctx->rand_seed_cb = rand_seed_cb;
    dctx->rand_add_cb = rand_add_cb;
    return 1;
}

void *RAND_DRBG_get_app_data(const DRBG_CTX *dctx)
{
    return dctx->app_data;
}

void RAND_DRBG_set_app_data(DRBG_CTX *dctx, void *app_data)
{
    dctx->app_data = app_data;
}

size_t RAND_DRBG_get_blocklength(const DRBG_CTX *dctx)
{
    return dctx->blocklength;
}

int RAND_DRBG_get_strength(const DRBG_CTX *dctx)
{
    return dctx->strength;
}

void RAND_DRBG_set_check_interval(DRBG_CTX *dctx, int interval)
{
    dctx->health_check_interval = interval;
}

void RAND_DRBG_set_reseed_interval(DRBG_CTX *dctx, int interval)
{
    dctx->reseed_interval = interval;
}
