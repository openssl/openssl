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

/* Polynomial object with 256 coefficients */
struct poly_st {
    uint32_t coeff[ML_DSA_NUM_POLY_COEFFICIENTS];
};

static ossl_inline ossl_unused void
poly_add(const POLY *lhs, const POLY *rhs, POLY *out)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        out->coeff[i] = reduce_once(lhs->coeff[i] + rhs->coeff[i]);
}

static ossl_inline ossl_unused void
poly_sub(const POLY *lhs, const POLY *rhs, POLY *out)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        out->coeff[i] = mod_sub(lhs->coeff[i], rhs->coeff[i]);
}

static ossl_inline ossl_unused int
poly_equal(const POLY *a, const POLY *b)
{
    return CRYPTO_memcmp(a, b, sizeof(*a)) == 0;
}

static ossl_inline ossl_unused void
poly_power2_round(const POLY *s, POLY *s1, POLY *s0)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        ossl_ml_dsa_key_compress_power2_round(s->coeff[i], &s1->coeff[i], &s0->coeff[i]);
}
