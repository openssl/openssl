/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "ml_dsa_local.h"
#include "ml_dsa_vector.h"
#include "ml_dsa_matrix.h"

#define SHAKE128_BLOCKSIZE 168
#define SHAKE256_BLOCKSIZE 136

typedef int (COEFF_FROM_NIBBLE_FUNC)(uint32_t nibble, uint32_t *out);

static COEFF_FROM_NIBBLE_FUNC coeff_from_nibble_4;
static COEFF_FROM_NIBBLE_FUNC coeff_from_nibble_2;

/**
 * @brief Combine 3 bytes to form an coefficient.
 * See FIPS 204, Algorithm 14, CoeffFromThreeBytes()
 *
 * This is not constant time as it is used to generate the matrix A which is public.
 *
 * @param s A byte array of 3 uniformly distributed bytes.
 * @param out The returned coefficient in the range 0..q-1.
 * @returns 1 if the value is less than q or 0 otherwise.
 *          This is used for rejection sampling.
 */
static ossl_inline int coeff_from_three_bytes(const uint8_t *s, uint32_t *out)
{
    /* Zero out the top bit of the 3rd byte to get a value in the range 0..2^23-1) */
    *out = (uint32_t)s[0] | ((uint32_t)s[1] << 8) | (((uint32_t)s[2] & 0x7f) << 16);
    return *out < ML_DSA_Q;
}

/**
 * @brief Generate a value in the range (q-4..0..4)
 * See FIPS 204, Algorithm 15, CoeffFromHalfByte() where eta = 4
 * Note the FIPS 204 code uses the range -4..4 (whereas this code adds q to the
 * negative numbers).
 *
 * @param nibble A value in the range 0..15
 * @param out The returned value if the range (q-4)..0..4 if nibble is < 9
 * @returns 1 nibble was in range, or 0 if the nibble was rejected.
 */
static ossl_inline int coeff_from_nibble_4(uint32_t nibble, uint32_t *out)
{
    /*
     * This is not constant time but will not leak any important info since
     * the value is either chosen or thrown away.
     */
    if (value_barrier_32(nibble < 9)) {
        *out = mod_sub(4, nibble);
        return 1;
    }
    return 0;
}

/**
 * @brief Generate a value in the range (q-2..0..2)
 * See FIPS 204, Algorithm 15, CoeffFromHalfByte() where eta = 2
 * Note the FIPS 204 code uses the range -2..2 (whereas this code adds q to the
 * negative numbers).
 *
 * @param nibble A value in the range 0..15
 * @param out The returned value if the range (q-2)..0..2 if nibble is < 15
 * @returns 1 nibble was in range, or 0 if the nibble was rejected.
 */
static ossl_inline int coeff_from_nibble_2(uint32_t nibble, uint32_t *out)
{
    if (value_barrier_32(nibble < 15)) {
        *out = mod_sub(2, nibble % 5);
        return 1;
    }
    return 0;
}

/**
 * @brief Use a seed value to generate a polynomial with coefficients in the
 * range of 0..q-1 using rejection sampling.
 * SHAKE128 is used to absorb the seed, and then sequences of 3 sample bytes are
 * squeezed to try to produce coefficients.
 * The SHAKE128 stream is used to get uniformly distributed elements.
 * This algorithm is used for matrix expansion and only operates on public inputs.
 *
 * See FIPS 204, Algorithm 30, RejNTTPoly()
 *
 * @param g_ctx A pre-fetched SHAKE128 context used for sampling the seed.
 * @param seed The seed to use for sampling.
 * @param seed_len The size of |seed|
 * @param out The returned polynomial with coefficients in the range of
 *            0..q-1. This range is required for NTT.
 * @returns 1 if the polynomial was successfully generated, or 0 if any of the
 *            digest operations failed.
 */
static int rej_ntt_poly(EVP_MD_CTX *g_ctx,
                        const uint8_t *seed, size_t seed_len, POLY *out)
{
    int j = 0;
    uint8_t blocks[SHAKE128_BLOCKSIZE], *b, *end = blocks + sizeof(blocks);

    if (EVP_DigestInit_ex2(g_ctx, NULL, NULL) != 1
            || EVP_DigestUpdate(g_ctx, seed, seed_len) != 1)
        return 0;

    while (1) {
        /*
         * Instead of just squeezing 3 bytes at a time, we grab a whole block
         * Note that the shake128 blocksize of 168 is divisible by 3.
         */
        if (!EVP_DigestSqueeze(g_ctx, blocks, sizeof(blocks)))
            return 0;
        for (b = blocks; b < end; b += 3) {
            if (coeff_from_three_bytes(b, &(out->coeff[j]))) {
                if (++j >= ML_DSA_NUM_POLY_COEFFICIENTS)
                    return 1;   /* finished */
            }
        }
    }
}

/**
 * @brief Use a seed value to generate a polynomial with coefficients in the
 * range of ((q-eta)..0..eta) using rejection sampling. eta is either 2 or 4.
 * SHAKE256 is used to absorb the seed, and then samples are squeezed.
 * See FIPS 204, Algorithm 31, RejBoundedPoly()
 *
 * @param h_ctx A pre-fetched SHAKE256 context used for sampling the seed.
 * @param coef_from_nibble A function that is dependent on eta, which takes a
 *                         nibble and tries to see if it is in the correct range.
 * @param seed The seed to use for sampling.
 * @param seed_len The size of |seed|
 * @param out The returned polynomial with coefficients in the range of
 *            ((q-eta)..0..eta)
 * @returns 1 if the polynomial was successfully generated, or 0 if any of the
 *            digest operations failed.
 */
static int rej_bounded_poly(EVP_MD_CTX *h_ctx,
                            COEFF_FROM_NIBBLE_FUNC *coef_from_nibble,
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

/**
 * @brief Generate a k * l matrix that has uniformly distributed polynomial
 *        elements using rejection sampling.
 * See FIPS 204, Algorithm 32, ExpandA()
 *
 * @param g_ctx A pre-fetched SHAKE128 context used for rejection sampling
 *              seed values generated from the seed rho.
 * @param rho A 32 byte seed to generated the matrix from.
 * @param out The generated k * l matrix of polynomials with coefficients
 *            in the range of 0..q-1.
 * @returns 1 if the matrix was generated, or 0 on error.
 */
int ossl_ml_dsa_sample_expandA(EVP_MD_CTX *g_ctx, const uint8_t *rho,
                               MATRIX *out)
{
    int ret = 0;
    size_t i, j;
    uint8_t derived_seed[ML_DSA_RHO_BYTES + 2];

    /* The seed used for each matrix element is rho + column_index + row_index */
    memcpy(derived_seed, rho, ML_DSA_RHO_BYTES);

    for (i = 0; i < out->k; i++) {
        for (j = 0; j < out->l; j++) {
            derived_seed[ML_DSA_RHO_BYTES + 1] = (uint8_t)i;
            derived_seed[ML_DSA_RHO_BYTES] = (uint8_t)j;
            /* Generate the polynomial for each matrix element using a unique seed */
            if (!rej_ntt_poly(g_ctx, derived_seed, sizeof(derived_seed),
                              &out->m_poly[i][j]))
                goto err;
        }
    }
    ret = 1;
err:
    return ret;
}

/**
 * @brief Generates 2 vectors using rejection sampling whose polynomial
 * coefficients are in the interval [q-eta..0..eta]
 *
 * See FIPS 204, Algorithm 33, ExpandS().
 * Note that in FIPS 204 the range -eta..eta is used.
 *
 * @param h_ctx A pre-fetched SHAKE256 context used for sampling the seed.
 * @param eta Is either 2 or 4, and determines the range of the coefficients for
 *            s1 and s2.
 * @param seed A 64 byte seed to use for sampling.
 * @param s1 A 1 * l column vector containing polynomials with coefficients in
 *           the range (q-eta)..0..eta
 * @param s2 A 1 * k column vector containing polynomials with coefficients in
 *           the range (q-eta)..0..eta
 * @returns 1 if s1 and s2 were successfully generated, or 0 otherwise.
 */
int ossl_ml_dsa_sample_expandS(EVP_MD_CTX *h_ctx, int eta, const uint8_t *seed,
                               VECTOR *s1, VECTOR *s2)
{
    int ret = 0;
    size_t i;
    size_t l = s1->num_poly;
    size_t k = s2->num_poly;
    uint8_t derived_seed[ML_DSA_PRIV_SEED_BYTES + 2];
    COEFF_FROM_NIBBLE_FUNC *coef_from_nibble_fn;

    coef_from_nibble_fn = (eta == 4) ? coeff_from_nibble_4 : coeff_from_nibble_2;

    /*
     * Each polynomial generated uses a unique seed that consists of
     * seed + counter (where the counter is 2 bytes starting at 0)
     */
    memcpy(derived_seed, seed, ML_DSA_PRIV_SEED_BYTES);
    derived_seed[ML_DSA_PRIV_SEED_BYTES] = 0;
    derived_seed[ML_DSA_PRIV_SEED_BYTES + 1] = 0;

    for (i = 0; i < l; i++) {
        if (!rej_bounded_poly(h_ctx, coef_from_nibble_fn,
                              derived_seed, sizeof(derived_seed), &s1->poly[i]))
            goto err;
        ++derived_seed[ML_DSA_PRIV_SEED_BYTES];
    }
    for (i = 0; i < k; i++) {
        if (!rej_bounded_poly(h_ctx, coef_from_nibble_fn,
                              derived_seed, sizeof(derived_seed), &s2->poly[i]))
            goto err;
        ++derived_seed[ML_DSA_PRIV_SEED_BYTES];
    }
    ret = 1;
err:
    return ret;
}
