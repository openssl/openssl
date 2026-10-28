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

void ossl_ml_kem_scalar_ntt_generic(scalar *s);
void ossl_ml_kem_scalar_inverse_ntt_generic(scalar *s);
void ossl_ml_kem_scalar_mult_generic(scalar *out, const scalar *lhs,
    const scalar *rhs);
void ossl_ml_kem_scalar_mult_add_generic(scalar *out, const scalar *lhs,
    const scalar *rhs);

/*
 * Gate for the AVX-512 ML-KEM kernels in ml_kem_avx512.c.  Same compiler
 * rule as VAES512_ELIGIBLE: x86_64, asm enabled, GCC >= 8, Clang >= 7, or
 * MSVC >= 1927.  ARM64EC is excluded because it is x64 emulation on Windows
 * ARM and has no AVX-512.  Callers use this macro so the declarations stay
 * with the definitions.  MSVC compiles the intrinsics from <immintrin.h>
 * with no target pragma and no /arch:AVX512; runtime selection is still
 * AVX512F+BW via OPENSSL_ia32cap_P.
 */
#if (defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)) \
    && !defined(OPENSSL_NO_ASM)                                                        \
    && !defined(_M_ARM64EC)                                                            \
    && ((defined(__GNUC__) && !defined(__clang__) && (__GNUC__ >= 8))                  \
        || (defined(__clang__) && (__clang_major__ >= 7))                              \
        || (defined(_MSC_VER) && (_MSC_VER >= 1927)))
#define ML_KEM_AVX512_ELIGIBLE 1
#else
#define ML_KEM_AVX512_ELIGIBLE 0
#endif

#if ML_KEM_AVX512_ELIGIBLE
int ossl_ml_kem_ntt_avx512_capable(void);
void ossl_ml_kem_scalar_ntt_avx512(uint16_t *c);
void ossl_ml_kem_scalar_inverse_ntt_avx512(uint16_t *c);
void ossl_ml_kem_scalar_mult_avx512(uint16_t *out, const uint16_t *lhs,
    const uint16_t *rhs);
void ossl_ml_kem_scalar_mult_add_avx512(uint16_t *out, const uint16_t *lhs,
    const uint16_t *rhs);
void ossl_ml_kem_basemul_acc_avx512(uint16_t *out, const uint16_t *lhs,
    const uint16_t *rhs, int rank);
void ossl_ml_kem_basemul_acc_intt_avx512(uint16_t *out, const uint16_t *lhs,
    const uint16_t *rhs, int rank);
void ossl_ml_kem_basemul_acc_transpose_add_avx512(uint16_t *out,
    const uint16_t *lhs, const uint16_t *rhs, int rank);
void ossl_ml_kem_avx512_dispatch_counts(unsigned int *ntt,
    unsigned int *inverse_ntt,
    unsigned int *inverse_ntt_demontgomerize,
    unsigned int *mult,
    unsigned int *mult_add,
    unsigned int *acc,
    unsigned int *transpose_add);
#endif

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
