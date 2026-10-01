/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_ML_KEM_LOCAL_H
#define OSSL_CRYPTO_ML_KEM_LOCAL_H
#pragma once

#include "crypto/ml_kem.h"

#if defined(VX_COMPILER_SUPPORT_VEC128)
/* s390x vectorised entry points (ml_kem_vec128.c) */
void ossl_ml_kem_scalar_ntt_vec128(scalar *s);
void ossl_ml_kem_scalar_inverse_ntt_vec128(scalar *s);
void ossl_ml_kem_scalar_inverse_ntt_demontgomerize_vec128(scalar *s);
void ossl_ml_kem_scalar_mult_add_vec128(scalar *out,
    const scalar *lhs,
    const scalar *rhs);
void ossl_ml_kem_inner_product_montgomery_vec128(scalar *out,
    const scalar *lhs,
    const scalar *rhs,
    int rank);
void ossl_ml_kem_matrix_mult_intt_vec128(scalar *out,
    const scalar *m,
    const scalar *a,
    int rank);
#endif /* VX_COMPILER_SUPPORT_VEC128 */

#endif /* OSSL_CRYPTO_ML_KEM_LOCAL_H */
