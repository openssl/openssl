/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include "ml_dsa_local.h"
#include "ml_dsa_key.h"
#include "ml_dsa_matrix.h"

#define SHAKE128_BLOCKSIZE 168
#define SHAKE256_BLOCKSIZE 136

typedef int (COEFF_FROM_NIBBLE_FUNC)(uint32_t nibble, uint32_t *out);

static COEFF_FROM_NIBBLE_FUNC coeff_from_nibble_4;
static COEFF_FROM_NIBBLE_FUNC coeff_from_nibble_2;

// FIPS 204, Algorithm 14 (`CoeffFromThreeBytes`)
static ossl_inline int coeff_from_three_bytes(const uint8_t *s, uint32_t *out)
{
    *out = (uint32_t)s[0] | ((uint32_t)s[1] << 8) | (((uint32_t)s[2] & 0x7f) << 16);
    return *out < ML_DSA_Q;
}

static ossl_inline int coeff_from_nibble_4(uint32_t nibble, uint32_t *out)
{
    if (value_barrier_32(nibble < 9)) {
        *out = mod_sub(4, nibble);
        return 1;
    }
    return 0;
}

static ossl_inline int coeff_from_nibble_2(uint32_t nibble, uint32_t *out)
{
    *out = mod_sub(2, nibble % 5);
    return 1;
}

/*
 *  FIPS 204, Algorithm 30 (`RejNTTPoly`).
 *
 * Rejection sample a Keccak stream to get uniformly distributed elements. This
 * is used for matrix expansion and only operates on public inputs.
 */
static int rej_ntt_poly(EVP_MD_CTX *ctx,
                        const uint8_t *seed, size_t seed_len, POLY *out)
{
    int j = 0;
    uint8_t blocks[SHAKE128_BLOCKSIZE], *b, *end = blocks + sizeof(blocks);

    if (EVP_DigestInit_ex2(ctx, NULL, NULL) != 1
            || EVP_DigestUpdate(ctx, seed, seed_len) != 1)
        return 0;

    while (1) {
        /*
         * Instead of just squeezing 3 bytes at a time, we grab a whole block
         * Note that 168 is divisible by 3.
         */
        if (!EVP_DigestSqueeze(ctx, blocks, sizeof(blocks)))
            return 0;
        for (b = blocks; b < end; b += 3) {
            if (coeff_from_three_bytes(b, &(out->coeff[j]))) {
                if (++j >= ML_DSA_NUM_POLY_COEFFICIENTS)
                    return 1;   /* finished */
            }
        }
    }
}

/* FIPS 204, Algorithm 31 (`RejBoundedPoly`) */

static int rej_bounded_poly(EVP_MD_CTX *h_ctx, COEFF_FROM_NIBBLE_FUNC *coef_from_nibble,
                            const uint8_t *seed, size_t seed_len, POLY *out)
{
    int j = 0;
    uint32_t z0, z1;
    uint8_t blocks[SHAKE256_BLOCKSIZE], *b, *end = blocks + sizeof(blocks);

    if (EVP_DigestInit_ex2(h_ctx, NULL, NULL) != 1
            || EVP_DigestUpdate(h_ctx, seed, seed_len) != 1)
        return 0;


    while (1) {
        /* Instead of just squeezing 1 byte at a time, we grab a whole block */
        if (!EVP_DigestSqueeze(h_ctx, blocks, sizeof(blocks)))
            return 0;
        for (b = blocks; b < end; b++) {
            z0 = *b & 0x0F; /* lower nibble of byte */
            z1 = *b >> 4;   /* high nibble of byte */

            if (coef_from_nibble(z0, &out->coeff[j])
                    && ++j >= ML_DSA_NUM_POLY_COEFFICIENTS)
                return 1;
            if (coef_from_nibble(z1, &out->coeff[j])
                    && ++j >= ML_DSA_NUM_POLY_COEFFICIENTS)
                return 1;
        }
    }
}

/* FIPS 204, Algorithm 32 (`ExpandA`) */
int ossl_ml_dsa_sample_expandA(EVP_MD_CTX *g_ctx, const uint8_t *rho,
                               MATRIX *out)
{
    int ret = 0;
    size_t i, j;
    uint8_t derived_seed[ML_DSA_RHO_BYTES + 2];
    //assert(k <= 0x100, "K must fit in 8 bits");
    //assert(l <= 0x100, "L must fit in 8 bits");

    memcpy(derived_seed, rho, ML_DSA_RHO_BYTES);

    for (i = 0; i < out->k; i++) {
        for (j = 0; j < out->l; j++) {
            derived_seed[ML_DSA_RHO_BYTES + 1] = (uint8_t)i;
            derived_seed[ML_DSA_RHO_BYTES] = (uint8_t)j;
            if (!rej_ntt_poly(g_ctx, derived_seed, sizeof(derived_seed),
                              &out->m_poly[i][j]))
                goto err;
        }
    }
    ret = 1;
err:
    return ret;
}

/* FIPS 204, Algorithm 33 (`ExpandS`) */
int ossl_ml_dsa_sample_expandS(EVP_MD_CTX *h_ctx, int eta, const uint8_t *seed,
                               VECTOR *s1, VECTOR *s2)
{
    int ret = 0;
    size_t i;
    size_t l = s1->num_poly;
    size_t k = s2->num_poly;
    uint8_t derived_seed[ML_DSA_SIGMA_BYTES + 2];
    COEFF_FROM_NIBBLE_FUNC *coef_from_nibble_fn;

    coef_from_nibble_fn = (eta == 4) ? coeff_from_nibble_4 : coeff_from_nibble_2;

    memcpy(derived_seed, seed, ML_DSA_SIGMA_BYTES);
    derived_seed[ML_DSA_SIGMA_BYTES] = 0;
    derived_seed[ML_DSA_SIGMA_BYTES + 1] = 0;

    for (i = 0; i < l; i++) {
        if (!rej_bounded_poly(h_ctx, coef_from_nibble_fn,
                              derived_seed, sizeof(derived_seed), &s1->poly[i]))
            goto err;
        ++derived_seed[ML_DSA_SIGMA_BYTES];
    }
    for (i = 0; i < k; i++) {
        if (!rej_bounded_poly(h_ctx, coef_from_nibble_fn,
                              derived_seed, sizeof(derived_seed), &s2->poly[i]))
            goto err;
        ++derived_seed[ML_DSA_SIGMA_BYTES];
    }
    ret = 1;
err:
    return ret;
}
