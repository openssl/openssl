/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/crypto.h>

#define ML_DSA_NUM_POLY_COEFFICIENTS 256

/* Polynomial object with 256 coefficients. The coefficients are unsigned 32 bits */
struct poly_st {
    uint32_t coeff[ML_DSA_NUM_POLY_COEFFICIENTS];
};

/**
 * @brief Polynomial addition.
 *
 * @param lhs A polynomial with coefficients in the range (0..q-1)
 * @param rhs A polynomial with coefficients in the range (0..q-1) to add
 *            to the 'lhs'.
 * @param out The returned addition result with the coefficients all in the
 *            range 0..q-1
 */
static ossl_inline ossl_unused void
poly_add(const POLY *lhs, const POLY *rhs, POLY *out)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        out->coeff[i] = reduce_once(lhs->coeff[i] + rhs->coeff[i]);
}

/**
 * @brief Polynomial subtraction.
 *
 * @param lhs A polynomial with coefficients in the range (0..q-1)
 * @param rhs A polynomial with coefficients in the range (0..q-1) to subtract
 *            from the 'lhs'.
 * @param out The returned subtraction result with the coefficients all in the
 *            range 0..q-1
 */
static ossl_inline ossl_unused void
poly_sub(const POLY *lhs, const POLY *rhs, POLY *out)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        out->coeff[i] = mod_sub(lhs->coeff[i], rhs->coeff[i]);
}

/* @returns 1 if the polynomials are equal, or 0 otherwise */
static ossl_inline ossl_unused int
poly_equal(const POLY *a, const POLY *b)
{
    return CRYPTO_memcmp(a, b, sizeof(*a)) == 0;
}

/**
 * @brief Decompose the coefficients of a polynomial into (r1, r0) such that
 * coeff[i] == t1[i] * 2^13 + t0[i] mod q
 * See FIPS 204, Algorithm 35, Power2Round()
 *
 * @param t A polynomial containing coefficients in the range 0..q-1
 * @param t1 The returned polynomial containing coefficients that represent
 *           the top 10 MSB of each coefficient in t (i.e each ranging from 0..1023)
 * @param t0 The remainder coefficients of t in the range (0..4096 or q-4095..q-1)
 *           Each t0 coefficient has an effective range of 8192 (i.e. 13 bits).
 */
static ossl_inline ossl_unused void
poly_power2_round(const POLY *t, POLY *t1, POLY *t0)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        ossl_ml_dsa_key_compress_power2_round(t->coeff[i],
                                              &t1->coeff[i], &t0->coeff[i]);
}
