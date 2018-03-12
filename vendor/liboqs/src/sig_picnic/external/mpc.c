/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "mpc.h"

#if !defined(_MSC_VER)
#include <stdalign.h>
#endif
#ifdef WITH_OPT
#include "simd.h"
#endif

#include <string.h>

void oqs_sig_picnic_mpc_clear(mzd_local_t* const* res, unsigned sc) {
  for (unsigned int i = 0; i < sc; i++) {
    oqs_sig_picnic_mzd_local_clear(res[i]);
  }
}

void oqs_sig_picnic_mpc_shift_right(mzd_local_t* const* res, mzd_local_t* const* val, unsigned count,
                     unsigned sc) {
  MPC_LOOP_CONST(oqs_sig_picnic_mzd_shift_right, res, val, count, sc);
}

void oqs_sig_picnic_mpc_shift_left(mzd_local_t* const* res, mzd_local_t* const* val, unsigned count, unsigned sc) {
  MPC_LOOP_CONST(oqs_sig_picnic_mzd_shift_left, res, val, count, sc);
}

void oqs_sig_picnic_mpc_and_const(mzd_local_t* const* result, mzd_local_t* const* first, mzd_local_t const* second,
                   unsigned sc) {
  MPC_LOOP_CONST(oqs_sig_picnic_mzd_xor, result, first, second, sc);
}

void oqs_sig_picnic_mpc_xor(mzd_local_t* const* result, mzd_local_t* const* first, mzd_local_t* const* second,
             unsigned sc) {
  MPC_LOOP_SHARED(oqs_sig_picnic_mzd_xor, result, first, second, sc);
}

void oqs_sig_picnic_mpc_and_uint64(uint64_t* res, uint64_t const* first, uint64_t const* second, uint64_t const* r,
                    view_t* view, unsigned viewshift) {
  for (unsigned m = 0; m < SC_PROOF; ++m) {
    const unsigned j = (m + 1) % SC_PROOF;
    uint64_t tmp1    = second[m] ^ second[j];
    uint64_t tmp2    = first[j] & second[m];
    tmp1             = tmp1 & first[m];
    tmp1             = tmp1 ^ tmp2;
    tmp2             = r[m] ^ r[j];
    res[m] = tmp1 = tmp1 ^ tmp2;
    tmp1          = tmp1 >> viewshift;
    view->t[m]    = view->t[m] ^ tmp1;
  }
}

#ifdef WITH_OPT
#define mpc_and_def(type, and, xor, shift_right)                                                   \
  for (unsigned m = 0; m < SC_PROOF; ++m) {                                                        \
    const unsigned j = (m + 1) % SC_PROOF;                                                         \
    type* sm         = (type*)ASSUME_ALIGNED(FIRST_ROW(view->s[m]), alignof(type));                \
    type tmp1        = (xor)(second[m], second[j]);                                                \
    type tmp2        = (and)(first[j], second[m]);                                                 \
    tmp1             = (and)(tmp1, first[m]);                                                      \
    tmp1             = (xor)(tmp1, tmp2);                                                          \
    tmp2             = (xor)(r[m], r[j]);                                                          \
    res[m] = tmp1 = (xor)(tmp1, tmp2);                                                             \
    tmp1          = (shift_right)(tmp1, viewshift);                                                \
    *sm           = (xor)(tmp1, *sm);                                                              \
  }

#define mpc_and_def_multiple(type, and, xor, shift_right, size)                                    \
  for (unsigned m = 0; m < SC_PROOF; ++m) {                                                        \
    const unsigned j = (m + 1) % SC_PROOF;                                                         \
    type* sm         = (type*)ASSUME_ALIGNED(FIRST_ROW(view->s[m]), alignof(type));                \
    type tmp1[size], tmp2[size];                                                                   \
    (xor)(tmp1, second[m], second[j]);                                                             \
    (and)(tmp2, first[j], second[m]);                                                              \
    (and)(tmp1, tmp1, first[m]);                                                                   \
    (xor)(tmp1, tmp1, tmp2);                                                                       \
    (xor)(tmp2, r[m], r[j]);                                                                       \
    (xor)(tmp1, tmp1, tmp2);                                                                       \
    memcpy(res[m], tmp1, size * sizeof(type));                                                     \
    (shift_right)(tmp1, tmp1, viewshift);                                                          \
    (xor)(sm, tmp1, sm);                                                                           \
  }

#ifdef WITH_SSE2
#ifdef WITH_CUSTOM_INSTANCES
ATTR_TARGET("sse2")
void oqs_sig_picnic_mpc_and_sse(__m128i* res, __m128i const* first, __m128i const* second, __m128i const* r,
                 view_t* view, unsigned viewshift) {
  mpc_and_def(__m128i, _mm_and_si128, _mm_xor_si128, mm128_shift_right);
}

ATTR_TARGET("sse2")
void oqs_sig_picnic_mpc_and_256_sse(__m128i res[SC_PROOF][2], __m128i const first[SC_PROOF][2],
                     __m128i const second[SC_PROOF][2], __m128i const r[SC_PROOF][2], view_t* view,
                     unsigned viewshift) {
  mpc_and_def_multiple(__m128i, mm256_and_sse, mm256_xor_sse, mm256_shift_right_sse, 2);
}

ATTR_TARGET("sse2")
void oqs_sig_picnic_mpc_and_384_sse(__m128i res[SC_PROOF][3], __m128i const first[SC_PROOF][3],
                     __m128i const second[SC_PROOF][3], __m128i const r[SC_PROOF][3], view_t* view,
                     unsigned viewshift) {
  mpc_and_def_multiple(__m128i, mm384_and_sse, mm384_xor_sse, mm384_shift_right_sse, 3);
}

ATTR_TARGET("sse2")
void oqs_sig_picnic_mpc_and_512_sse(__m128i res[SC_PROOF][4], __m128i const first[SC_PROOF][4],
                     __m128i const second[SC_PROOF][4], __m128i const r[SC_PROOF][4], view_t* view,
                     unsigned viewshift) {
  mpc_and_def_multiple(__m128i, mm512_and_sse, mm512_xor_sse, mm512_shift_right_sse, 4);
}
#endif
#endif

#ifdef WITH_AVX2
#ifdef WITH_CUSTOM_INSTANCES
ATTR_TARGET("avx2")
void oqs_sig_picnic_mpc_and_avx(__m256i* res, __m256i const* first, __m256i const* second, __m256i const* r,
                 view_t* view, unsigned viewshift) {
  mpc_and_def(__m256i, _mm256_and_si256, _mm256_xor_si256, mm256_shift_right);
}

ATTR_TARGET("avx2")
void oqs_sig_picnic_mpc_and_512_avx(__m256i res[SC_VERIFY][2], __m256i const first[SC_VERIFY][2],
                     __m256i const second[SC_VERIFY][2], __m256i const r[SC_VERIFY][2],
                     view_t* view, unsigned viewshift) {
  mpc_and_def_multiple(__m256i, mm512_and_avx, mm512_xor_avx, mm512_shift_right_avx, 2);
}
#endif
#endif

#ifdef WITH_NEON
#ifdef WITH_CUSTOM_INSTANCES
void oqs_sig_picnic_mpc_and_neon(uint32x4_t* res, uint32x4_t const* first, uint32x4_t const* second,
                  uint32x4_t const* r, view_t* view, unsigned viewshift) {
  mpc_and_def(uint32x4_t, vandq_u32, veorq_u32, mm128_shift_right);
}

void oqs_sig_picnic_mpc_and_256_neon(uint32x4_t res[SC_PROOF][2], uint32x4_t const first[SC_PROOF][2],
                      uint32x4_t const second[SC_PROOF][2], uint32x4_t const r[SC_PROOF][2],
                      view_t* view, unsigned viewshift) {
  mpc_and_def_multiple(uint32x4_t, mm256_and, mm256_xor, mm256_shift_right, 2);
}

void oqs_sig_picnic_mpc_and_384_neon(uint32x4_t res[SC_PROOF][3], uint32x4_t const first[SC_PROOF][3],
                      uint32x4_t const second[SC_PROOF][3], uint32x4_t const r[SC_PROOF][3],
                      view_t* view, unsigned viewshift) {
  mpc_and_def_multiple(uint32x4_t, mm384_and, mm384_xor, mm384_shift_right, 3);
}

void oqs_sig_picnic_mpc_and_512_neon(uint32x4_t res[SC_PROOF][4], uint32x4_t const first[SC_PROOF][4],
                      uint32x4_t const second[SC_PROOF][4], uint32x4_t const r[SC_PROOF][4],
                      view_t* view, unsigned viewshift) {
  mpc_and_def_multiple(uint32x4_t, mm512_and, mm512_xor, mm512_shift_right, 4);
}
#endif
#endif
#endif

#if defined(WITH_CUSTOM_INSTANCES)
void oqs_sig_picnic_mpc_and(mzd_local_t* const* res, mzd_local_t* const* first, mzd_local_t* const* second,
             mzd_local_t* const* r, view_t* view, unsigned viewshift, mzd_local_t* const* buffer) {
  mzd_local_t* b = buffer[0];

  for (unsigned m = 0; m < SC_PROOF; ++m) {
    const unsigned j = (m + 1) % SC_PROOF;

    // f[m] & s[m]
    mzd_and(res[m], first[m], second[m]);

    // f[m + 1] & s[m]
    mzd_and(b, first[j], second[m]);
    mzd_xor(res[m], res[m], b);

    // f[m] & s[m + 1]
    mzd_and(b, first[m], second[j]);
    mzd_xor(res[m], res[m], b);

    // ... ^ r[m] ^ r[m + 1]
    mzd_xor(res[m], res[m], r[m]);
    mzd_xor(res[m], res[m], r[j]);
  }

  mpc_shift_right(buffer, res, viewshift, SC_PROOF);
  mpc_xor(view->s, view->s, buffer, SC_PROOF);
}
#endif

void oqs_sig_picnic_mpc_and_verify_uint64(uint64_t* res, uint64_t const* first, uint64_t const* second,
                           uint64_t const* r, view_t* view, uint64_t const mask,
                           unsigned viewshift) {
  for (unsigned m = 0; m < (SC_VERIFY - 1); ++m) {
    const unsigned j = (m + 1);
    uint64_t tmp1    = second[m] ^ second[j];
    uint64_t tmp2    = first[j] & second[m];
    tmp1             = tmp1 & first[m];
    tmp1             = tmp1 ^ tmp2;
    tmp2             = r[m] ^ r[j];
    res[m] = tmp1 = tmp1 ^ tmp2;
    tmp1          = tmp1 >> viewshift;
    view->t[m]    = view->t[m] ^ tmp1;
  }
  uint64_t s1        = (view->t[SC_VERIFY - 1]);
  uint64_t rsc       = s1 << viewshift;
  res[SC_VERIFY - 1] = rsc & mask;
}

#ifdef WITH_OPT
#define mpc_and_verify_def(type, and, xor, shift_right, shift_left)                                \
  for (unsigned m = 0; m < (SC_VERIFY - 1); ++m) {                                                 \
    const unsigned j = (m + 1);                                                                    \
    type* sm         = (type*)ASSUME_ALIGNED(FIRST_ROW(view->s[m]), alignof(type));                \
    type tmp1        = (xor)(second[m], second[j]);                                                \
    type tmp2        = (and)(first[j], second[m]);                                                 \
    tmp1             = (and)(tmp1, first[m]);                                                      \
    tmp1             = (xor)(tmp1, tmp2);                                                          \
    tmp2             = (xor)(r[m], r[j]);                                                          \
    res[m] = tmp1 = (xor)(tmp1, tmp2);                                                             \
    tmp1          = (shift_right)(tmp1, viewshift);                                                \
    *sm           = (xor)(tmp1, *sm);                                                              \
  }                                                                                                \
  type const* s1 =                                                                                 \
      (type const*)ASSUME_ALIGNED(CONST_FIRST_ROW(view->s[SC_VERIFY - 1]), alignof(type));         \
  type rsc           = (shift_left)(*s1, viewshift);                                               \
  res[SC_VERIFY - 1] = (and)(rsc, mask);

#define mpc_and_verify_def_multiple(type, and, xor, shift_right, shift_left, size)                 \
  for (unsigned m = 0; m < (SC_VERIFY - 1); ++m) {                                                 \
    const unsigned j = (m + 1);                                                                    \
    type* sm         = (type*)ASSUME_ALIGNED(FIRST_ROW(view->s[m]), alignof(type));                \
    type tmp1[size], tmp2[size];                                                                   \
    (xor)(tmp1, second[m], second[j]);                                                             \
    (and)(tmp2, first[j], second[m]);                                                              \
    (and)(tmp1, tmp1, first[m]);                                                                   \
    (xor)(tmp1, tmp1, tmp2);                                                                       \
    (xor)(tmp2, r[m], r[j]);                                                                       \
    (xor)(tmp1, tmp1, tmp2);                                                                       \
    memcpy(res[m], tmp1, size * sizeof(type));                                                     \
    (shift_right)(tmp1, tmp1, viewshift);                                                          \
    (xor)(sm, tmp1, sm);                                                                           \
    uint64_t* tmp = (uint64_t*)&(view->t[m]);                                                      \
    *tmp ^= ((uint64_t*)&tmp1)[sizeof(type) / sizeof(uint64_t) - 1];                               \
  }                                                                                                \
  type const* s1 =                                                                                 \
      (type const*)ASSUME_ALIGNED(CONST_FIRST_ROW(view->s[SC_VERIFY - 1]), alignof(type));         \
  type rsc[size];                                                                                  \
  (shift_left)(rsc, s1, viewshift);                                                                \
  (and)(res[SC_VERIFY - 1], rsc, mask);

#ifdef WITH_SSE2
#ifdef WITH_CUSTOM_INSTANCES
ATTR_TARGET("sse2")
void oqs_sig_picnic_mpc_and_verify_sse(__m128i* res, __m128i const* first, __m128i const* second, __m128i const* r,
                        view_t* view, __m128i const mask, unsigned viewshift) {
  mpc_and_verify_def(__m128i, _mm_and_si128, _mm_xor_si128, mm128_shift_right, mm128_shift_left);
}

ATTR_TARGET("sse2")
void oqs_sig_picnic_mpc_and_verify_256_sse(__m128i res[SC_VERIFY][2], __m128i const first[SC_VERIFY][2],
                            __m128i const second[SC_VERIFY][2], __m128i const r[SC_VERIFY][2],
                            view_t* view, __m128i const* mask, unsigned viewshift) {
  mpc_and_verify_def_multiple(__m128i, mm256_and_sse, mm256_xor_sse, mm256_shift_right_sse,
                              mm256_shift_left_sse, 2);
}

ATTR_TARGET("sse2")
void oqs_sig_picnic_mpc_and_verify_384_sse(__m128i res[SC_VERIFY][3], __m128i const first[SC_VERIFY][3],
                            __m128i const second[SC_VERIFY][3], __m128i const r[SC_VERIFY][3],
                            view_t* view, __m128i const* mask, unsigned viewshift) {
  mpc_and_verify_def_multiple(__m128i, mm384_and_sse, mm384_xor_sse, mm384_shift_right_sse,
                              mm384_shift_left_sse, 3);
}

ATTR_TARGET("sse2")
void oqs_sig_picnic_mpc_and_verify_512_sse(__m128i res[SC_VERIFY][4], __m128i const first[SC_VERIFY][4],
                            __m128i const second[SC_VERIFY][4], __m128i const r[SC_VERIFY][4],
                            view_t* view, __m128i const* mask, unsigned viewshift) {
  mpc_and_verify_def_multiple(__m128i, mm512_and_sse, mm512_xor_sse, mm512_shift_right_sse,
                              mm512_shift_left_sse, 4);
}
#endif
#endif

#ifdef WITH_AVX2
#ifdef WITH_CUSTOM_INSTANCES
ATTR_TARGET("avx2")
void oqs_sig_picnic_mpc_and_verify_avx(__m256i* res, __m256i const* first, __m256i const* second, __m256i const* r,
                        view_t* view, __m256i const mask, unsigned viewshift) {
  mpc_and_verify_def(__m256i, _mm256_and_si256, _mm256_xor_si256, mm256_shift_right,
                     mm256_shift_left);
}

ATTR_TARGET("avx2")
void oqs_sig_picnic_mpc_and_verify_512_avx(__m256i res[SC_VERIFY][2], __m256i const first[SC_VERIFY][2],
                            __m256i const second[SC_VERIFY][2], __m256i const r[SC_VERIFY][2],
                            view_t* view, __m256i const* mask, unsigned viewshift) {
  mpc_and_verify_def_multiple(__m256i, mm512_and_avx, mm512_xor_avx, mm512_shift_right_avx,
                              mm512_shift_left_avx, 2);
}
#endif
#endif

#ifdef WITH_NEON
#ifdef WITH_CUSTOM_INSTANCES
void oqs_sig_picnic_mpc_and_verify_neon(uint32x4_t* res, uint32x4_t const* first, uint32x4_t const* second,
                         uint32x4_t const* r, view_t* view, uint32x4_t const mask,
                         unsigned viewshift) {
  mpc_and_verify_def(uint32x4_t, vandq_u32, veorq_u32, mm128_shift_right, mm128_shift_left);
}

void oqs_sig_picnic_mpc_and_verify_256_neon(uint32x4_t res[SC_VERIFY][2], uint32x4_t const first[SC_VERIFY][2],
                             uint32x4_t const second[SC_VERIFY][2],
                             uint32x4_t const r[SC_VERIFY][2], view_t* view, uint32x4_t const* mask,
                             unsigned viewshift) {
  mpc_and_verify_def_multiple(uint32x4_t, mm256_and, mm256_xor, mm256_shift_right, mm256_shift_left,
                              2);
}

void oqs_sig_picnic_mpc_and_verify_384_neon(uint32x4_t res[SC_VERIFY][3], uint32x4_t const first[SC_VERIFY][3],
                             uint32x4_t const second[SC_VERIFY][3],
                             uint32x4_t const r[SC_VERIFY][3], view_t* view, uint32x4_t const* mask,
                             unsigned viewshift) {
  mpc_and_verify_def_multiple(uint32x4_t, mm384_and, mm384_xor, mm384_shift_right, mm384_shift_left,
                              3);
}

void oqs_sig_picnic_mpc_and_verify_512_neon(uint32x4_t res[SC_VERIFY][4], uint32x4_t const first[SC_VERIFY][4],
                             uint32x4_t const second[SC_VERIFY][4],
                             uint32x4_t const r[SC_VERIFY][4], view_t* view, uint32x4_t const* mask,
                             unsigned viewshift) {
  mpc_and_verify_def_multiple(uint32x4_t, mm512_and, mm512_xor, mm512_shift_right, mm512_shift_left,
                              4);
}
#endif
#endif
#endif

#if defined(WITH_CUSTOM_INSTANCES)
void oqs_sig_picnic_mpc_and_verify(mzd_local_t* const* res, mzd_local_t* const* first, mzd_local_t* const* second,
                    mzd_local_t* const* r, view_t* view, mzd_local_t const* mask,
                    unsigned viewshift, mzd_local_t* const* buffer) {
  mzd_local_t* b = buffer[0];

  for (unsigned m = 0; m < (SC_VERIFY - 1); ++m) {
    const unsigned j = m + 1;

    mzd_and(res[m], first[m], second[m]);

    mzd_and(b, first[j], second[m]);
    mzd_xor(res[m], res[m], b);

    mzd_and(b, first[m], second[j]);
    mzd_xor(res[m], res[m], b);

    mzd_xor(res[m], res[m], r[m]);
    mzd_xor(res[m], res[m], r[j]);
  }

  for (unsigned m = 0; m < (SC_VERIFY - 1); ++m) {
    mzd_shift_right(b, res[m], viewshift);
    mzd_xor(view->s[m], view->s[m], b);
  }

  mzd_shift_left(res[SC_VERIFY - 1], view->s[SC_VERIFY - 1], viewshift);
  mzd_and(res[SC_VERIFY - 1], res[SC_VERIFY - 1], mask);
}
#endif

void oqs_sig_picnic_mpc_copy(mzd_local_t** out, mzd_local_t* const* in, unsigned sc) {
  for (unsigned i = 0; i < sc; ++i) {
    oqs_sig_picnic_mzd_local_copy(out[i], in[i]);
  }
}
