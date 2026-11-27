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

/**
 * @brief Portable forward NTT (FIPS 203, Algorithm 9), in place.
 * @param s the polynomial to transform; coefficients in [0, q) on entry and
 *        on return
 */
void ossl_ml_kem_scalar_ntt_generic(scalar *s);

/**
 * @brief Portable inverse NTT (FIPS 203, Algorithm 10), in place, including
 * the final multiplication by (n/2)^-1.
 * @param s the NTT-domain polynomial to transform; coefficients in [0, q) on
 *        entry and on return
 */
void ossl_ml_kem_scalar_inverse_ntt_generic(scalar *s);

/**
 * @brief Portable NTT-domain base multiplication, out = lhs * rhs.
 * @param out the product
 * @param lhs the first NTT-domain factor
 * @param rhs the second NTT-domain factor
 */
void ossl_ml_kem_scalar_mult_generic(scalar *out, const scalar *lhs,
    const scalar *rhs);

/**
 * @brief Portable NTT-domain base multiply-accumulate, out += lhs * rhs.
 * @param out the accumulator
 * @param lhs the first NTT-domain factor
 * @param rhs the second NTT-domain factor
 */
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
/**
 * @brief Report whether the CPU supports the AVX-512 ML-KEM kernels.
 * @returns 1 if AVX512F and AVX512BW are both available, 0 otherwise
 */
int ossl_ml_kem_ntt_avx512_capable(void);

/**
 * @brief AVX-512 forward NTT, in place; bit-exact with
 * ossl_ml_kem_scalar_ntt_generic().
 * @param c the 256 coefficients to transform, in [0, q) on entry and on return
 */
void ossl_ml_kem_scalar_ntt_avx512(uint16_t *c);

/**
 * @brief AVX-512 inverse NTT, in place, including the final multiplication
 * by (n/2)^-1; bit-exact with ossl_ml_kem_scalar_inverse_ntt_generic().
 * @param c the 256 NTT-domain coefficients to transform, in [0, q) on entry
 *        and on return
 */
void ossl_ml_kem_scalar_inverse_ntt_avx512(uint16_t *c);

/**
 * @brief AVX-512 NTT-domain base multiplication, out = lhs * rhs, with a
 * canonical [0, q) result.
 * @param out the 256 output coefficients
 * @param lhs the first NTT-domain factor, coefficients in [0, q)
 * @param rhs the second NTT-domain factor, coefficients in [0, q)
 */
void ossl_ml_kem_scalar_mult_avx512(uint16_t *out, const uint16_t *lhs,
    const uint16_t *rhs);

/**
 * @brief AVX-512 NTT-domain base multiply-accumulate, out += lhs * rhs, with
 * a canonical [0, q) result.
 * @param out the 256-coefficient accumulator, in [0, q) on entry
 * @param lhs the first NTT-domain factor, coefficients in [0, q)
 * @param rhs the second NTT-domain factor, coefficients in [0, q)
 */
void ossl_ml_kem_scalar_mult_add_avx512(uint16_t *out, const uint16_t *lhs,
    const uint16_t *rhs);

/**
 * @brief AVX-512 NTT-domain inner product, out = sum_k lhs[k] * rhs[k], with
 * a single reduction to [0, q) at the end.
 * @param out the 256 output coefficients
 * @param lhs rank consecutive NTT-domain polynomials
 * @param rhs rank consecutive NTT-domain polynomials
 * @param rank the number of polynomials in each vector (2, 3 or 4)
 */
void ossl_ml_kem_basemul_acc_avx512(uint16_t *out, const uint16_t *lhs,
    const uint16_t *rhs, int rank);

/**
 * @brief AVX-512 inner product followed by the inverse NTT, out =
 * INTT(sum_k lhs[k] * rhs[k]), kept in registers and stored once in standard
 * form in [0, q).
 * @param out the 256 output coefficients
 * @param lhs one matrix row: rank consecutive NTT-domain polynomials
 * @param rhs rank consecutive NTT-domain polynomials
 * @param rank the number of polynomials in each vector (2, 3 or 4)
 */
void ossl_ml_kem_basemul_acc_intt_avx512(uint16_t *out, const uint16_t *lhs,
    const uint16_t *rhs, int rank);

/**
 * @brief AVX-512 transposed-matrix inner product added to out, out +=
 * sum_k lhs[k * rank] * rhs[k], with a canonical [0, q) result.
 * @param out the 256-coefficient accumulator, in [0, q) on entry
 * @param lhs the first polynomial of one matrix column; successive terms are
 *        rank polynomials apart
 * @param rhs rank consecutive NTT-domain polynomials
 * @param rank the matrix dimension (2, 3 or 4)
 */
void ossl_ml_kem_basemul_acc_transpose_add_avx512(uint16_t *out,
    const uint16_t *lhs, const uint16_t *rhs, int rank);

/**
 * @brief Test hook: read how many times each AVX-512 dispatch wrapper in
 * ml_kem.c has been called.  The counters are not synchronised.
 * @param ntt receives the forward NTT count, or NULL to skip
 * @param inverse_ntt receives the inverse NTT count, or NULL to skip
 * @param inverse_ntt_demontgomerize receives the count for the inverse NTT
 *        used after an inner product, or NULL to skip
 * @param mult receives the base multiplication count, or NULL to skip
 * @param mult_add receives the multiply-accumulate count, or NULL to skip
 * @param acc receives the inner product count, including rows of the
 *        fused matrix multiply, or NULL to skip
 * @param transpose_add receives the transposed-matrix row count, or NULL to
 *        skip
 */
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
