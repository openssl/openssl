/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* A 'k' by 'l' Matrix object ('k' rows and 'l' columns) containing polynomial entries */
struct matrix_st {
    POLY m_poly[ML_DSA_K_MAX][ML_DSA_L_MAX];
    size_t k, l;
};

static ossl_inline ossl_unused void
matrix_init(MATRIX *m, size_t k, size_t l)
{
    m->k = k;
    m->l = l;
}

void ossl_ml_dsa_matrix_mult_vector(const MATRIX *matrix_kl, const VECTOR *vl,
                                    VECTOR *vk);
