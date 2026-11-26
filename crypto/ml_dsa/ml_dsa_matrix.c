/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "ml_dsa_local.h"
#include "ml_dsa_vector.h"
#include "ml_dsa_matrix.h"

/* Scalar (fallback) implementation */
static void matrix_mult_vector_scalar(const MATRIX *a, const VECTOR *s,
    VECTOR *t)
{
    size_t i, j;
    POLY *poly = a->m_poly;
    POLY product;

    vector_zero(t);

    for (i = 0; i < a->k; i++) {
        for (j = 0; j < a->l; j++) {
            ossl_ml_dsa_poly_ntt_mult(poly++, &s->poly[j], &product);
            poly_add(&product, &t->poly[i], &t->poly[i]);
        }
    }

    OPENSSL_cleanse(&product, sizeof(product));
}

/*
 * Scalar fallback for the fused matrix-multiply + INTT operation.
 * Calls the scalar matrix-vector multiply followed by a per-polynomial INTT.
 */
static void matrix_mult_vector_intt_scalar(const MATRIX *a, const VECTOR *s,
    VECTOR *out)
{
    size_t i;

    matrix_mult_vector_scalar(a, s, out);
    for (i = 0; i < out->num_poly; i++)
        ossl_ml_dsa_poly_ntt_inverse(out->poly + i);
}

/*
 * Function pointers for the matrix-vector implementations.
 * Both default to the scalar paths; upgraded to vec128 on s390x at first use
 * if the VX facility is present (see ml_dsa_matrix_init below).
 */
typedef void (*matrix_mult_vector_fn)(const MATRIX *, const VECTOR *,
    VECTOR *);
static matrix_mult_vector_fn matrix_mult_impl = matrix_mult_vector_scalar;
static matrix_mult_vector_fn matrix_mult_intt_impl = matrix_mult_vector_intt_scalar;

static CRYPTO_ONCE matrix_once = CRYPTO_ONCE_STATIC_INIT;

static void ml_dsa_matrix_init(void)
{
#if defined(OPENSSL_ML_DSA_S390X)
    if (S390X_VX_CAPABLE) {
        matrix_mult_impl = ossl_ml_dsa_matrix_mult_vector_vec128;
        matrix_mult_intt_impl = ossl_ml_dsa_matrix_mult_vector_intt_vec128;
    }
#endif
}

/*
 * Matrix multiply of a k*l matrix of polynomials by a 1 * l vector of
 * polynomials to produce a 1 * k vector of polynomial results.
 * i.e. t = a * s
 *
 * @param a A k * l matrix of polynomials in NTT form
 * @param s A 1 * l vector of polynomials in NTT form
 * @param t 1 * k vector of polynomial results in NTT form
 */
void ossl_ml_dsa_matrix_mult_vector(const MATRIX *a, const VECTOR *s,
    VECTOR *t)
{
    (void)CRYPTO_THREAD_run_once(&matrix_once, ml_dsa_matrix_init);
    matrix_mult_impl(a, s, t);
}

/*
 * Combined matrix-vector multiply + inverse NTT.
 * Computes out[i] = INTT(sum_j A[i,j] (*) s[j]) for each row i.
 * The vec128 path fuses the two operations to reduce data passes.
 */
void ossl_ml_dsa_matrix_mult_vector_intt(const MATRIX *a, const VECTOR *s,
    VECTOR *out)
{
    (void)CRYPTO_THREAD_run_once(&matrix_once, ml_dsa_matrix_init);
    matrix_mult_intt_impl(a, s, out);
}
