/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ml_dsa_poly.h"

struct vector_st {
    POLY *poly;
    size_t num_poly;
};

/* @brief Set the number of polynomial elements that will be present in the vector */
static ossl_inline ossl_unused
void vector_init(VECTOR *v, POLY *polys, size_t num_polys)
{
    v->poly = polys;
    v->num_poly = num_polys;
}

/* @brief zeroize a vectors polynomial coefficients */
static ossl_inline ossl_unused
void vector_zero(VECTOR *va)
{
    memset(va->poly, 0, va->num_poly * sizeof(va->poly[0]));
}

/* @brief add 2 vectors */
static ossl_inline ossl_unused void
vector_add(const VECTOR *lhs, const VECTOR *rhs, VECTOR *out)
{
    size_t i;

    for (i = 0; i < lhs->num_poly; i++)
        poly_add(&lhs->poly[i], &rhs->poly[i], &out->poly[i]);
}

/* @brief subtract 2 vectors */
static ossl_inline ossl_unused void
vector_sub(const VECTOR *lhs, const VECTOR *rhs, VECTOR *out)
{
    size_t i;

    for (i = 0; i < lhs->num_poly; i++)
        poly_sub(&lhs->poly[i], &rhs->poly[i], &out->poly[i]);
}

/* @brief multiply a vector by a polynomial */
static ossl_inline ossl_unused void
vector_ntt_mult_poly(const VECTOR *lhs, const POLY *rhs, VECTOR *out)
{
    size_t i;

    for (i = 0; i < lhs->num_poly; i++)
        ossl_ml_dsa_poly_ntt_mult(&lhs->poly[i], rhs, &out->poly[i]);
}

/* @brief copy a vector */
static ossl_inline ossl_unused void
vector_copy(VECTOR *dst, const VECTOR *src)
{
    dst->num_poly = src->num_poly;
    memcpy(dst->poly, src->poly, src->num_poly * sizeof(src->poly[0]));
}

/* @brief return 1 if 2 vectors are equal, or 0 otherwise */
static ossl_inline ossl_unused int
vector_equal(const VECTOR *a, const VECTOR *b)
{
    size_t i;

    if (a->num_poly != b->num_poly)
        return 0;
    for (i = 0; i < a->num_poly; ++i) {
        if (!poly_equal(a->poly + i, b->poly + i))
            return 0;
    }
    return 1;
}

/* @brief convert a vector in place into NTT form */
static ossl_inline ossl_unused void
vector_ntt(VECTOR *va)
{
    size_t i;

    for (i = 0; i < va->num_poly; i++)
        ossl_ml_dsa_poly_ntt(&va->poly[i]);
}

/* @brief convert a vector in place into inverse NTT form */
static ossl_inline ossl_unused void
vector_ntt_inverse(VECTOR *va)
{
    size_t i;

    for (i = 0; i < va->num_poly; i++)
        ossl_ml_dsa_poly_ntt_inverse(&va->poly[i]);
}

/*
 * @brief Decompose all polynomial coefficients of a vector into (t1, t0) such
 * that coeff[i] == t1[i] * 2^13 + t0[i] mod q.
 * See FIPS 204, Algorithm 35, Power2Round()
 */
static ossl_inline ossl_unused void
vector_power2_round(const VECTOR *t, VECTOR *t1, VECTOR *t0)
{
    size_t i;

    for (i = 0; i < t->num_poly; i++)
        poly_power2_round(&t->poly[i], &t1->poly[i], &t0->poly[i]);
}
