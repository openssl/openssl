/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef MPC_H
#define MPC_H

#include "macros.h"
#include "mzd_additional.h"

// Share count for proofs
#define SC_PROOF 3
// Share count for verification
#define SC_VERIFY 2

typedef union {
#if defined(WITH_CUSTOM_INSTANCES)
  mzd_local_t* s[SC_PROOF];
#endif
  uint64_t t[SC_PROOF];
} view_t;

typedef view_t rvec_t;

#define MPC_LOOP_CONST(function, result, first, second, sc)                                        \
  do {                                                                                             \
    for (unsigned int e = 0; e < (sc); ++e) {                                                      \
      function((result)[e], (first)[e], (second));                                                 \
    }                                                                                              \
  } while (0)

#define MPC_LOOP_SHARED(function, result, first, second, sc)                                       \
  do {                                                                                             \
    for (unsigned int o = 0; o < (sc); ++o) {                                                      \
      function((result)[o], (first)[o], (second)[o]);                                              \
    }                                                                                              \
  } while (0)

#define MPC_LOOP_CONST_C(function, result, first, second, sc, c)                                   \
  do {                                                                                             \
    if (!(c)) {                                                                                    \
      function((result)[0], (first)[0], (second));                                                 \
    } else if ((c) == (sc)) {                                                                      \
      function((result)[(sc)-1], first[(sc)-1], (second));                                         \
    }                                                                                              \
  } while (0)

void oqs_sig_picnic_mpc_shift_right(mzd_local_t* const* res, mzd_local_t* const* val, unsigned count,
                     unsigned sc) ATTR_NONNULL;

void oqs_sig_picnic_mpc_shift_left(mzd_local_t* const* res, mzd_local_t* const* val, unsigned count,
                    unsigned sc) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_const(mzd_local_t* const* res, mzd_local_t* const* first, mzd_local_t const* second,
                   unsigned sc) ATTR_NONNULL;

void oqs_sig_picnic_mpc_xor(mzd_local_t* const* res, mzd_local_t* const* first, mzd_local_t* const* second,
             unsigned sc) ATTR_NONNULL;

void oqs_sig_picnic_mpc_clear(mzd_local_t* const* res, unsigned sc) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and(mzd_local_t* const* res, mzd_local_t* const* first, mzd_local_t* const* second,
             mzd_local_t* const* r, view_t* view, unsigned viewshift,
             mzd_local_t* const* buffer) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_verify(mzd_local_t* const* res, mzd_local_t* const* first, mzd_local_t* const* second,
                    mzd_local_t* const* r, view_t* view, mzd_local_t const* mask,
                    unsigned viewshift, mzd_local_t* const* buffer) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_uint64(uint64_t* res, uint64_t const* first, uint64_t const* second, uint64_t const* r,
                    view_t* view, unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_verify_uint64(uint64_t* res, uint64_t const* first, uint64_t const* second,
                           uint64_t const* r, view_t* view, uint64_t const mask,
                           unsigned viewshift) ATTR_NONNULL;

#ifdef WITH_OPT
#include "simd.h"
#if defined(WITH_SSE2) || defined(WITH_AVX) || defined(WITH_SSE4_1)

void oqs_sig_picnic_mpc_and_sse(__m128i* res, __m128i const* first, __m128i const* second, __m128i const* r,
                 view_t* view, unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_verify_sse(__m128i* res, __m128i const* first, __m128i const* second, __m128i const* r,
                        view_t* view, __m128i const mask, unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_256_sse(__m128i res[SC_PROOF][2], __m128i const first[SC_PROOF][2],
                     __m128i const second[SC_PROOF][2], __m128i const r[SC_PROOF][2], view_t* view,
                     unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_verify_256_sse(__m128i res[SC_VERIFY][2], __m128i const first[SC_VERIFY][2],
                            __m128i const second[SC_VERIFY][2], __m128i const r[SC_VERIFY][2],
                            view_t* view, __m128i const* mask, unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_384_sse(__m128i res[SC_PROOF][3], __m128i const first[SC_PROOF][3],
                     __m128i const second[SC_PROOF][3], __m128i const r[SC_PROOF][3], view_t* view,
                     unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_verify_384_sse(__m128i res[SC_VERIFY][3], __m128i const first[SC_VERIFY][3],
                            __m128i const second[SC_VERIFY][3], __m128i const r[SC_VERIFY][3],
                            view_t* view, __m128i const* mask, unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_512_sse(__m128i res[SC_PROOF][4], __m128i const first[SC_PROOF][4],
                     __m128i const second[SC_PROOF][4], __m128i const r[SC_PROOF][4], view_t* view,
                     unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_verify_512_sse(__m128i res[SC_VERIFY][4], __m128i const first[SC_VERIFY][4],
                            __m128i const second[SC_VERIFY][4], __m128i const r[SC_VERIFY][4],
                            view_t* view, __m128i const* mask, unsigned viewshift) ATTR_NONNULL;

#endif

#if defined(WITH_AVX2)
void oqs_sig_picnic_mpc_and_avx(__m256i* res, __m256i const* first, __m256i const* second, __m256i const* r,
                 view_t* view, unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_verify_avx(__m256i* res, __m256i const* first, __m256i const* second, __m256i const* r,
                        view_t* view, __m256i const mask, unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_512_avx(__m256i res[SC_VERIFY][2], __m256i const first[SC_VERIFY][2],
                     __m256i const second[SC_VERIFY][2], __m256i const r[SC_VERIFY][2],
                     view_t* view, unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_verify_512_avx(__m256i res[SC_VERIFY][2], __m256i const first[SC_VERIFY][2],
                            __m256i const second[SC_VERIFY][2], __m256i const r[SC_VERIFY][2],
                            view_t* view, __m256i const* mask, unsigned viewshift) ATTR_NONNULL;
#endif

#ifdef WITH_NEON
void oqs_sig_picnic_mpc_and_neon(uint32x4_t* res, uint32x4_t const* first, uint32x4_t const* second,
                  uint32x4_t const* r, view_t* view, unsigned viewshift);

void oqs_sig_picnic_mpc_and_verify_neon(uint32x4_t* res, uint32x4_t const* first, uint32x4_t const* second,
                         uint32x4_t const* r, view_t* view, uint32x4_t const mask,
                         unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_256_neon(uint32x4_t res[SC_PROOF][2], uint32x4_t const first[SC_PROOF][2],
                      uint32x4_t const second[SC_PROOF][2], uint32x4_t const r[SC_PROOF][2],
                      view_t* view, unsigned viewshift);

void oqs_sig_picnic_mpc_and_verify_256_neon(uint32x4_t res[SC_VERIFY][2], uint32x4_t const first[SC_VERIFY][2],
                             uint32x4_t const second[SC_VERIFY][2],
                             uint32x4_t const r[SC_VERIFY][2], view_t* view, uint32x4_t const* mask,
                             unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_384_neon(uint32x4_t res[SC_PROOF][3], uint32x4_t const first[SC_PROOF][3],
                      uint32x4_t const second[SC_PROOF][3], uint32x4_t const r[SC_PROOF][3],
                      view_t* view, unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_verify_384_neon(uint32x4_t res[SC_VERIFY][3], uint32x4_t const first[SC_VERIFY][3],
                             uint32x4_t const second[SC_VERIFY][3],
                             uint32x4_t const r[SC_VERIFY][3], view_t* view, uint32x4_t const* mask,
                             unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_512_neon(uint32x4_t res[SC_PROOF][4], uint32x4_t const first[SC_PROOF][4],
                      uint32x4_t const second[SC_PROOF][4], uint32x4_t const r[SC_PROOF][4],
                      view_t* view, unsigned viewshift) ATTR_NONNULL;

void oqs_sig_picnic_mpc_and_verify_512_neon(uint32x4_t res[SC_VERIFY][4], uint32x4_t const first[SC_VERIFY][4],
                             uint32x4_t const second[SC_VERIFY][4],
                             uint32x4_t const r[SC_VERIFY][4], view_t* view, uint32x4_t const* mask,
                             unsigned viewshift) ATTR_NONNULL;

#endif
#endif

void oqs_sig_picnic_mpc_copy(mzd_local_t** out, mzd_local_t* const* in, unsigned sc) ATTR_NONNULL_ARG(2);

#endif
