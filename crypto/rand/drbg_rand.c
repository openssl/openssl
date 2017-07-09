/*
 * Copyright 2011-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define OPENSSL_FIPSAPI

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rand.h>
#include "rand_drbg_lcl.h"

/* Mapping of SP800-90 DRBGs to OpenSSL RAND_METHOD */

/* Since we only have one global PRNG used at any time in OpenSSL use a global
 * variable to store context.
 */

static DRBG_CTX ossl_dctx;

DRBG_CTX *RAND_DRBG_get_default(void)
{
    return &ossl_dctx;
}

static int fips_drbg_bytes(unsigned char *out, int count)
{
    DRBG_CTX *dctx = &ossl_dctx;
    int rv = 0;
    unsigned char *adin = NULL;
    size_t adinlen = 0;
    CRYPTO_w_lock(CRYPTO_LOCK_RAND);
    do {
        size_t rcnt;
        if (count > (int)dctx->max_request)
            rcnt = dctx->max_request;
        else
            rcnt = count;
        if (dctx->get_adin) {
            adinlen = dctx->get_adin(dctx, &adin);
            if (adinlen && !adin) {
                RANDerr(RAND_F_RAND_DRBG_BYTES,
                        RAND_R_ERROR_RETRIEVING_ADDITIONAL_INPUT);
                goto err;
            }
        }
        rv = RAND_DRBG_generate(dctx, out, rcnt, 0, adin, adinlen);
        if (adin) {
            if (dctx->cleanup_adin)
                dctx->cleanup_adin(dctx, adin, adinlen);
            adin = NULL;
        }
        if (!rv)
            goto err;
        out += rcnt;
        count -= rcnt;
    }
    while (count);
    rv = 1;
 err:
    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
    return rv;
}

static int fips_drbg_pseudo(unsigned char *out, int count)
{
    if (fips_drbg_bytes(out, count) <= 0)
        return -1;
    return 1;
}

static int fips_drbg_status(void)
{
    DRBG_CTX *dctx = &ossl_dctx;
    int rv;
    CRYPTO_r_lock(CRYPTO_LOCK_RAND);
    rv = dctx->status == DRBG_STATUS_READY ? 1 : 0;
    CRYPTO_r_unlock(CRYPTO_LOCK_RAND);
    return rv;
}

static void fips_drbg_cleanup(void)
{
    DRBG_CTX *dctx = &ossl_dctx;
    CRYPTO_w_lock(CRYPTO_LOCK_RAND);
    RAND_DRBG_uninstantiate(dctx);
    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
}

static int fips_drbg_seed(const void *seed, int seedlen)
{
    DRBG_CTX *dctx = &ossl_dctx;
    if (dctx->rand_seed_cb)
        return dctx->rand_seed_cb(dctx, seed, seedlen);
    return 1;
}

static int fips_drbg_add(const void *seed, int seedlen, double add_entropy)
{
    DRBG_CTX *dctx = &ossl_dctx;
    if (dctx->rand_add_cb)
        return dctx->rand_add_cb(dctx, seed, seedlen, add_entropy);
    return 1;
}

static const RAND_METHOD rand_drbg_meth = {
    fips_drbg_seed,
    fips_drbg_bytes,
    fips_drbg_cleanup,
    fips_drbg_add,
    fips_drbg_pseudo,
    fips_drbg_status
};

const RAND_METHOD *RAND_DRBG_method(void)
{
    return &rand_drbg_meth;
}
