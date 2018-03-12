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

#include "lowmc_pars.h"
#include "mpc.h"
#include "mpc_lowmc.h"
#include "mzd_additional.h"

#if !defined(_MSC_VER)
#include <stdalign.h>
#endif
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef WITH_OPT
#include "simd.h"
#endif

typedef struct {
  mzd_local_t* x0m[SC_PROOF]; // a
  mzd_local_t* x1m[SC_PROOF]; // b
  mzd_local_t* x2m[SC_PROOF]; // c
  mzd_local_t* r0m[SC_PROOF];
  mzd_local_t* r1m[SC_PROOF];
  mzd_local_t* r2m[SC_PROOF];
  mzd_local_t* x0s[SC_PROOF];
  mzd_local_t* r0s[SC_PROOF];
  mzd_local_t* x1s[SC_PROOF];
  mzd_local_t* r1s[SC_PROOF];
  mzd_local_t* v[SC_PROOF];

  mzd_local_t** storage;
} sbox_vars_t;

static sbox_vars_t* sbox_vars_init(sbox_vars_t* vars, uint32_t n, unsigned sc);
static void sbox_vars_clear(sbox_vars_t* vars);

#define bitsliced_step_1(sc)                                                                       \
  mpc_and_const(out, in, mask->mask, sc);                                                          \
                                                                                                   \
  mpc_and_const(vars->x0m, in, mask->x0, sc);                                                      \
  mpc_and_const(vars->x1m, in, mask->x1, sc);                                                      \
  mpc_and_const(vars->x2m, in, mask->x2, sc);                                                      \
  mpc_and_const(vars->r0m, rvec, mask->x0, sc);                                                    \
  mpc_and_const(vars->r1m, rvec, mask->x1, sc);                                                    \
  mpc_and_const(vars->r2m, rvec, mask->x2, sc);                                                    \
                                                                                                   \
  mpc_shift_left(vars->x0s, vars->x0m, 2, sc);                                                     \
  mpc_shift_left(vars->r0s, vars->r0m, 2, sc);                                                     \
                                                                                                   \
  mpc_shift_left(vars->x1s, vars->x1m, 1, sc);                                                     \
  mpc_shift_left(vars->r1s, vars->r1m, 1, sc)

#define bitsliced_step_2(sc)                                                                       \
  /* (b & c) ^ a */                                                                                \
  mpc_xor(vars->r2m, vars->r2m, vars->x0s, sc);                                                    \
  /* a ^ b */                                                                                      \
  mpc_xor(vars->x0s, vars->x0s, vars->x1s, sc);                                                    \
  /* (c & a) ^ a ^ b */                                                                            \
  mpc_xor(vars->r1m, vars->r1m, vars->x0s, sc);                                                    \
  /* (a & b) ^ a ^ b ^ c */                                                                        \
  mpc_xor(vars->r0m, vars->r0m, vars->x0s, sc);                                                    \
  mpc_xor(vars->r0m, vars->r0m, vars->x2m, sc);                                                    \
                                                                                                   \
  mpc_shift_right(vars->x0s, vars->r2m, 2, sc);                                                    \
  mpc_shift_right(vars->x1s, vars->r1m, 1, sc);                                                    \
                                                                                                   \
  mpc_xor(out, out, vars->r0m, sc);                                                                \
  mpc_xor(out, out, vars->x0s, sc);                                                                \
  mpc_xor(out, out, vars->x1s, sc)

#ifdef WITH_CUSTOM_INSTANCES
static void _mpc_sbox_layer_bitsliced(mzd_local_t** out, mzd_local_t* const* in, view_t* view,
                                      mzd_local_t* const* rvec, mask_t const* mask,
                                      sbox_vars_t const* vars) {
  bitsliced_step_1(SC_PROOF);

  oqs_sig_picnic_mpc_clear(view->s, SC_PROOF);
  // a & b
  oqs_sig_picnic_mpc_and(vars->r0m, vars->x0s, vars->x1s, vars->r2m, view, 0, vars->v);
  // b & c
  oqs_sig_picnic_mpc_and(vars->r2m, vars->x1s, vars->x2m, vars->r1s, view, 1, vars->v);
  // c & a
  oqs_sig_picnic_mpc_and(vars->r1m, vars->x0s, vars->x2m, vars->r0s, view, 2, vars->v);

  bitsliced_step_2(SC_PROOF);
}

static void _mpc_sbox_layer_bitsliced_verify(mzd_local_t** out, mzd_local_t* const* in,
                                             view_t* view, mzd_local_t* const* rvec,
                                             mask_t const* mask, sbox_vars_t const* vars) {
  bitsliced_step_1(SC_VERIFY);

  oqs_sig_picnic_mzd_local_clear(view->s[0]);
  // a & b
  oqs_sig_picnic_mpc_and_verify(vars->r0m, vars->x0s, vars->x1s, vars->r2m, view, mask->x2, 0, vars->v);
  // b & c
  oqs_sig_picnic_mpc_and_verify(vars->r2m, vars->x1s, vars->x2m, vars->r1s, view, mask->x2, 1, vars->v);
  // c & a
  oqs_sig_picnic_mpc_and_verify(vars->r1m, vars->x0s, vars->x2m, vars->r0s, view, mask->x2, 2, vars->v);

  bitsliced_step_2(SC_VERIFY);
}
#endif

#define bitsliced_step_1_uint64(sc)                                                                \
  uint64_t r0m[sc];                                                                                \
  uint64_t r0s[sc];                                                                                \
  uint64_t r1m[sc];                                                                                \
  uint64_t r1s[sc];                                                                                \
  uint64_t r2m[sc];                                                                                \
  uint64_t x0s[sc];                                                                                \
  uint64_t x1s[sc];                                                                                \
  uint64_t x2m[sc];                                                                                \
  const uint64_t mx2 = mask->x2i;                                                                  \
  do {                                                                                             \
    const uint64_t mx0 = mask->x0i;                                                                \
    const uint64_t mx1 = mask->x1i;                                                                \
                                                                                                   \
    for (unsigned int m = 0; m < (sc); ++m) {                                                      \
      const uint64_t inm   = in[m];                                                                \
      const uint64_t rvecm = rvec[m];                                                              \
                                                                                                   \
      x0s[m] = (inm & mx0) << 2;                                                                   \
      x1s[m] = (inm & mx1) << 1;                                                                   \
      x2m[m] = inm & mx2;                                                                          \
                                                                                                   \
      r0m[m] = rvecm & mx0;                                                                        \
      r1m[m] = rvecm & mx1;                                                                        \
      r2m[m] = rvecm & mx2;                                                                        \
                                                                                                   \
      r0s[m] = r0m[m] << 2;                                                                        \
      r1s[m] = r1m[m] << 1;                                                                        \
    }                                                                                              \
  } while (0)

#define bitsliced_step_2_uint64(sc)                                                                \
  do {                                                                                             \
    const uint64_t maskm = mask->maski;                                                            \
    for (unsigned int m = 0; m < sc; ++m) {                                                        \
      const uint64_t inm = in[m];                                                                  \
      uint64_t* outm     = &out[m];                                                                \
                                                                                                   \
      const uint64_t tmp1 = r2m[m] ^ x0s[m];                                                       \
      const uint64_t tmp2 = x0s[m] ^ x1s[m];                                                       \
      const uint64_t tmp3 = tmp2 ^ r1m[m];                                                         \
      const uint64_t tmp4 = tmp2 ^ r0m[m] ^ x2m[m];                                                \
                                                                                                   \
      const uint64_t mout = maskm & inm;                                                           \
      *outm               = mout ^ (tmp4) ^ (tmp1 >> 2) ^ (tmp3 >> 1);                             \
    }                                                                                              \
  } while (0)

static void _mpc_sbox_layer_bitsliced_uint64(uint64_t* out, uint64_t const* in, view_t* view,
                                             uint64_t const* rvec, mask_t const* mask) {
  bitsliced_step_1_uint64(SC_PROOF);

  memset(view->t, 0, sizeof(uint64_t) * SC_PROOF);
  oqs_sig_picnic_mpc_and_uint64(r0m, x0s, x1s, r2m, view, 0);
  oqs_sig_picnic_mpc_and_uint64(r2m, x1s, x2m, r1s, view, 1);
  oqs_sig_picnic_mpc_and_uint64(r1m, x0s, x2m, r0s, view, 2);

  bitsliced_step_2_uint64(SC_PROOF);
}

static void _mpc_sbox_layer_bitsliced_verify_uint64(uint64_t* out, uint64_t const* in, view_t* view,
                                                    uint64_t const* rvec, mask_t const* mask) {
  bitsliced_step_1_uint64(SC_VERIFY);

  view->t[0] = 0;
  oqs_sig_picnic_mpc_and_verify_uint64(r0m, x0s, x1s, r2m, view, mx2, 0);
  oqs_sig_picnic_mpc_and_verify_uint64(r2m, x1s, x2m, r1s, view, mx2, 1);
  oqs_sig_picnic_mpc_and_verify_uint64(r1m, x0s, x2m, r0s, view, mx2, 2);

  bitsliced_step_2_uint64(SC_VERIFY);
}

#ifdef WITH_OPT
#define bitsliced_mm_step_1(sc, type, and, shift_left)                                             \
  type r0m[sc] ATTR_ALIGNED(alignof(type));                                                        \
  type r0s[sc] ATTR_ALIGNED(alignof(type));                                                        \
  type r1m[sc] ATTR_ALIGNED(alignof(type));                                                        \
  type r1s[sc] ATTR_ALIGNED(alignof(type));                                                        \
  type r2m[sc] ATTR_ALIGNED(alignof(type));                                                        \
  type x0s[sc] ATTR_ALIGNED(alignof(type));                                                        \
  type x1s[sc] ATTR_ALIGNED(alignof(type));                                                        \
  type x2m[sc] ATTR_ALIGNED(alignof(type));                                                        \
  const type mx2 ATTR_ALIGNED(alignof(type)) =                                                     \
      *((const type*)ASSUME_ALIGNED(CONST_FIRST_ROW(mask->x2), alignof(type)));                    \
  do {                                                                                             \
    const type mx0 ATTR_ALIGNED(alignof(type)) =                                                   \
        *((const type*)ASSUME_ALIGNED(CONST_FIRST_ROW(mask->x0), alignof(type)));                  \
    const type mx1 ATTR_ALIGNED(alignof(type)) =                                                   \
        *((const type*)ASSUME_ALIGNED(CONST_FIRST_ROW(mask->x1), alignof(type)));                  \
                                                                                                   \
    for (unsigned int m = 0; m < (sc); ++m) {                                                      \
      const type inm ATTR_ALIGNED(alignof(type)) =                                                 \
          *((const type*)ASSUME_ALIGNED(CONST_FIRST_ROW(in[m]), alignof(type)));                   \
      const type rvecm ATTR_ALIGNED(alignof(type)) =                                               \
          *((const type*)ASSUME_ALIGNED(CONST_FIRST_ROW(rvec[m]), alignof(type)));                 \
                                                                                                   \
      type tmp1 = (and)(inm, mx0);                                                                 \
      type tmp2 = (and)(inm, mx1);                                                                 \
      x2m[m]    = (and)(inm, mx2);                                                                 \
                                                                                                   \
      x0s[m] = (shift_left)(tmp1, 2);                                                              \
      x1s[m] = (shift_left)(tmp2, 1);                                                              \
                                                                                                   \
      r0m[m] = tmp1 = (and)(rvecm, mx0);                                                           \
      r1m[m] = tmp2 = (and)(rvecm, mx1);                                                           \
      r2m[m]        = (and)(rvecm, mx2);                                                           \
                                                                                                   \
      r0s[m] = (shift_left)(tmp1, 2);                                                              \
      r1s[m] = (shift_left)(tmp2, 1);                                                              \
    }                                                                                              \
  } while (0)

#define bitsliced_mm_step_2(sc, type, and, xor, shift_right)                                       \
  do {                                                                                             \
    const type maskm ATTR_ALIGNED(alignof(type)) =                                                 \
        *((const type*)ASSUME_ALIGNED(CONST_FIRST_ROW(mask->mask), alignof(type)));                \
    for (unsigned int m = 0; m < sc; ++m) {                                                        \
      const type inm ATTR_ALIGNED(alignof(type)) =                                                 \
          *((const type*)ASSUME_ALIGNED(CONST_FIRST_ROW(in[m]), alignof(type)));                   \
      type* outm = (type*)ASSUME_ALIGNED(CONST_FIRST_ROW(out[m]), alignof(type));                  \
                                                                                                   \
      type tmp1 = (xor)(r2m[m], x0s[m]);                                                           \
      type tmp2 = (xor)(x0s[m], x1s[m]);                                                           \
      type tmp3 = (xor)(tmp2, r1m[m]);                                                             \
                                                                                                   \
      type mout = (and)(maskm, inm);                                                               \
                                                                                                   \
      type tmp4 = (xor)(tmp2, r0m[m]);                                                             \
      tmp4      = (xor)(tmp4, x2m[m]);                                                             \
      mout      = (xor)(mout, tmp4);                                                               \
                                                                                                   \
      tmp2 = (shift_right)(tmp1, 2);                                                               \
      mout = (xor)(mout, tmp2);                                                                    \
                                                                                                   \
      tmp1  = (shift_right)(tmp3, 1);                                                              \
      *outm = (xor)(mout, tmp1);                                                                   \
    }                                                                                              \
  } while (0)

#define bitsliced_mm_step_1_multiple_of_128(sc, type, and, shift_left, size)                       \
  type r0m[sc][size] ATTR_ALIGNED(alignof(type));                                                  \
  type r0s[sc][size] ATTR_ALIGNED(alignof(type));                                                  \
  type r1m[sc][size] ATTR_ALIGNED(alignof(type));                                                  \
  type r1s[sc][size] ATTR_ALIGNED(alignof(type));                                                  \
  type r2m[sc][size] ATTR_ALIGNED(alignof(type));                                                  \
  type x0s[sc][size] ATTR_ALIGNED(alignof(type));                                                  \
  type x1s[sc][size] ATTR_ALIGNED(alignof(type));                                                  \
  type x2m[sc][size] ATTR_ALIGNED(alignof(type));                                                  \
  const type* mx2 ATTR_ALIGNED(alignof(type)) =                                                    \
      ((const type*)ASSUME_ALIGNED(CONST_FIRST_ROW(mask->x2), alignof(type)));                     \
  do {                                                                                             \
    const type* mx0 ATTR_ALIGNED(alignof(type)) =                                                  \
        ((const type*)ASSUME_ALIGNED(CONST_FIRST_ROW(mask->x0), alignof(type)));                   \
    const type* mx1 ATTR_ALIGNED(alignof(type)) =                                                  \
        ((const type*)ASSUME_ALIGNED(CONST_FIRST_ROW(mask->x1), alignof(type)));                   \
                                                                                                   \
    for (unsigned int m = 0; m < (sc); ++m) {                                                      \
      const type* inm ATTR_ALIGNED(alignof(type)) =                                                \
          ((const type*)ASSUME_ALIGNED(CONST_FIRST_ROW(in[m]), alignof(type)));                    \
      const type* rvecm ATTR_ALIGNED(alignof(type)) =                                              \
          ((const type*)ASSUME_ALIGNED(CONST_FIRST_ROW(rvec[m]), alignof(type)));                  \
                                                                                                   \
      type tmp1[size] ATTR_ALIGNED(alignof(type));                                                 \
      type tmp2[size] ATTR_ALIGNED(alignof(type));                                                 \
      (and)(tmp1, inm, mx0);                                                                       \
      (and)(tmp2, inm, mx1);                                                                       \
      (and)(x2m[m], inm, mx2);                                                                     \
                                                                                                   \
      (shift_left)(x0s[m], tmp1, 2);                                                               \
      (shift_left)(x1s[m], tmp2, 1);                                                               \
                                                                                                   \
      (and)(tmp1, rvecm, mx0);                                                                     \
      memcpy(r0m[m], tmp1, size * sizeof(type));                                                   \
                                                                                                   \
      (and)(tmp2, rvecm, mx1);                                                                     \
      memcpy(r1m[m], tmp2, size * sizeof(type));                                                   \
                                                                                                   \
      (and)(r2m[m], rvecm, mx2);                                                                   \
                                                                                                   \
      (shift_left)(r0s[m], tmp1, 2);                                                               \
      (shift_left)(r1s[m], tmp2, 1);                                                               \
    }                                                                                              \
  } while (0)

#define bitsliced_mm_step_2_multiple_of_128(sc, type, and, xor, shift_right, size)                 \
  do {                                                                                             \
    const type* maskm ATTR_ALIGNED(alignof(type)) =                                                \
        ((const type*)ASSUME_ALIGNED(CONST_FIRST_ROW(mask->mask), alignof(type)));                 \
    for (unsigned int m = 0; m < sc; ++m) {                                                        \
      const type* inm ATTR_ALIGNED(alignof(type)) =                                                \
          ((const type*)ASSUME_ALIGNED(CONST_FIRST_ROW(in[m]), alignof(type)));                    \
      type* outm = (type*)ASSUME_ALIGNED(CONST_FIRST_ROW(out[m]), alignof(type));                  \
                                                                                                   \
      type tmp1[size], tmp2[size], tmp3[size];                                                     \
      (xor)(tmp1, r2m[m], x0s[m]);                                                                 \
      (xor)(tmp2, x0s[m], x1s[m]);                                                                 \
      (xor)(tmp3, tmp2, r1m[m]);                                                                   \
                                                                                                   \
      type mout[size];                                                                             \
      (and)(mout, maskm, inm);                                                                     \
                                                                                                   \
      type tmp4[size];                                                                             \
      (xor)(tmp4, tmp2, r0m[m]);                                                                   \
      (xor)(tmp4, tmp4, x2m[m]);                                                                   \
      (xor)(mout, mout, tmp4);                                                                     \
                                                                                                   \
      (shift_right)(tmp2, tmp1, 2);                                                                \
      (xor)(mout, mout, tmp2);                                                                     \
      (shift_right)(tmp1, tmp3, 1);                                                                \
      (xor)(outm, mout, tmp1);                                                                     \
    }                                                                                              \
  } while (0)

#ifdef WITH_SSE2
#ifdef WITH_CUSTOM_INSTANCES
ATTR_TARGET("sse2")
static void _mpc_sbox_layer_bitsliced_128_sse(mzd_local_t** out, mzd_local_t* const* in,
                                              view_t* view, mzd_local_t** rvec,
                                              mask_t const* mask) {
  bitsliced_mm_step_1(SC_PROOF, __m128i, _mm_and_si128, mm128_shift_left);

  oqs_sig_picnic_mpc_clear(view->s, SC_PROOF);
  oqs_sig_picnic_mpc_and_sse(r0m, x0s, x1s, r2m, view, 0);
  oqs_sig_picnic_mpc_and_sse(r2m, x1s, x2m, r1s, view, 1);
  oqs_sig_picnic_mpc_and_sse(r1m, x0s, x2m, r0s, view, 2);

  bitsliced_mm_step_2(SC_PROOF, __m128i, _mm_and_si128, _mm_xor_si128, mm128_shift_right);
}

ATTR_TARGET("sse2")
static void _mpc_sbox_layer_bitsliced_verify_128_sse(mzd_local_t** out, mzd_local_t* const* in,
                                                     view_t* view, mzd_local_t** rvec,
                                                     mask_t const* mask) {
  bitsliced_mm_step_1(SC_VERIFY, __m128i, _mm_and_si128, mm128_shift_left);

  oqs_sig_picnic_mzd_local_clear(view->s[0]);
  oqs_sig_picnic_mpc_and_verify_sse(r0m, x0s, x1s, r2m, view, mx2, 0);
  oqs_sig_picnic_mpc_and_verify_sse(r2m, x1s, x2m, r1s, view, mx2, 1);
  oqs_sig_picnic_mpc_and_verify_sse(r1m, x0s, x2m, r0s, view, mx2, 2);

  bitsliced_mm_step_2(SC_VERIFY, __m128i, _mm_and_si128, _mm_xor_si128, mm128_shift_right);
}
//----------------------------------------------------------------------------------------------------------------------
ATTR_TARGET("sse2")
static void _mpc_sbox_layer_bitsliced_256_sse(mzd_local_t** out, mzd_local_t* const* in,
                                              view_t* view, mzd_local_t** rvec,
                                              mask_t const* mask) {
  bitsliced_mm_step_1_multiple_of_128(SC_PROOF, __m128i, mm256_and_sse, mm256_shift_left_sse, 2);

  oqs_sig_picnic_mpc_clear(view->s, SC_PROOF);
  oqs_sig_picnic_mpc_and_256_sse(r0m, x0s, x1s, r2m, view, 0);
  oqs_sig_picnic_mpc_and_256_sse(r2m, x1s, x2m, r1s, view, 1);
  oqs_sig_picnic_mpc_and_256_sse(r1m, x0s, x2m, r0s, view, 2);

  bitsliced_mm_step_2_multiple_of_128(SC_PROOF, __m128i, mm256_and_sse, mm256_xor_sse,
                                      mm256_shift_right_sse, 2);
}

ATTR_TARGET("sse2")
static void _mpc_sbox_layer_bitsliced_verify_256_sse(mzd_local_t** out, mzd_local_t* const* in,
                                                     view_t* view, mzd_local_t** rvec,
                                                     mask_t const* mask) {
  bitsliced_mm_step_1_multiple_of_128(SC_VERIFY, __m128i, mm256_and_sse, mm256_shift_left_sse, 2);

  oqs_sig_picnic_mzd_local_clear(view->s[0]);
  oqs_sig_picnic_mpc_and_verify_256_sse(r0m, x0s, x1s, r2m, view, mx2, 0);
  oqs_sig_picnic_mpc_and_verify_256_sse(r2m, x1s, x2m, r1s, view, mx2, 1);
  oqs_sig_picnic_mpc_and_verify_256_sse(r1m, x0s, x2m, r0s, view, mx2, 2);

  bitsliced_mm_step_2_multiple_of_128(SC_VERIFY, __m128i, mm256_and_sse, mm256_xor_sse,
                                      mm256_shift_right_sse, 2);
}
//----------------------------------------------------------------------------------------------------------------------
ATTR_TARGET("sse2")
static void _mpc_sbox_layer_bitsliced_384_sse(mzd_local_t** out, mzd_local_t* const* in,
                                              view_t* view, mzd_local_t** rvec,
                                              mask_t const* mask) {
  bitsliced_mm_step_1_multiple_of_128(SC_PROOF, __m128i, mm384_and_sse, mm384_shift_left_sse, 3);

  oqs_sig_picnic_mpc_clear(view->s, SC_PROOF);
  oqs_sig_picnic_mpc_and_384_sse(r0m, x0s, x1s, r2m, view, 0);
  oqs_sig_picnic_mpc_and_384_sse(r2m, x1s, x2m, r1s, view, 1);
  oqs_sig_picnic_mpc_and_384_sse(r1m, x0s, x2m, r0s, view, 2);

  bitsliced_mm_step_2_multiple_of_128(SC_PROOF, __m128i, mm384_and_sse, mm384_xor_sse,
                                      mm384_shift_right_sse, 3);
}

ATTR_TARGET("sse2")
static void _mpc_sbox_layer_bitsliced_verify_384_sse(mzd_local_t** out, mzd_local_t* const* in,
                                                     view_t* view, mzd_local_t** rvec,
                                                     mask_t const* mask) {
  bitsliced_mm_step_1_multiple_of_128(SC_VERIFY, __m128i, mm384_and_sse, mm384_shift_left_sse, 3);

  oqs_sig_picnic_mzd_local_clear(view->s[0]);
  oqs_sig_picnic_mpc_and_verify_384_sse(r0m, x0s, x1s, r2m, view, mx2, 0);
  oqs_sig_picnic_mpc_and_verify_384_sse(r2m, x1s, x2m, r1s, view, mx2, 1);
  oqs_sig_picnic_mpc_and_verify_384_sse(r1m, x0s, x2m, r0s, view, mx2, 2);

  bitsliced_mm_step_2_multiple_of_128(SC_VERIFY, __m128i, mm384_and_sse, mm384_xor_sse,
                                      mm384_shift_right_sse, 3);
}
//----------------------------------------------------------------------------------------------------------------------
ATTR_TARGET("sse2")
static void _mpc_sbox_layer_bitsliced_512_sse(mzd_local_t** out, mzd_local_t* const* in,
                                              view_t* view, mzd_local_t** rvec,
                                              mask_t const* mask) {
  bitsliced_mm_step_1_multiple_of_128(SC_PROOF, __m128i, mm512_and_sse, mm512_shift_left_sse, 4);

  oqs_sig_picnic_mpc_clear(view->s, SC_PROOF);
  oqs_sig_picnic_mpc_and_512_sse(r0m, x0s, x1s, r2m, view, 0);
  oqs_sig_picnic_mpc_and_512_sse(r2m, x1s, x2m, r1s, view, 1);
  oqs_sig_picnic_mpc_and_512_sse(r1m, x0s, x2m, r0s, view, 2);

  bitsliced_mm_step_2_multiple_of_128(SC_PROOF, __m128i, mm512_and_sse, mm512_xor_sse,
                                      mm512_shift_right_sse, 4);
}

ATTR_TARGET("sse2")
static void _mpc_sbox_layer_bitsliced_verify_512_sse(mzd_local_t** out, mzd_local_t* const* in,
                                                     view_t* view, mzd_local_t** rvec,
                                                     mask_t const* mask) {
  bitsliced_mm_step_1_multiple_of_128(SC_VERIFY, __m128i, mm512_and_sse, mm512_shift_left_sse, 4);

  oqs_sig_picnic_mzd_local_clear(view->s[0]);
  oqs_sig_picnic_mpc_and_verify_512_sse(r0m, x0s, x1s, r2m, view, mx2, 0);
  oqs_sig_picnic_mpc_and_verify_512_sse(r2m, x1s, x2m, r1s, view, mx2, 1);
  oqs_sig_picnic_mpc_and_verify_512_sse(r1m, x0s, x2m, r0s, view, mx2, 2);

  bitsliced_mm_step_2_multiple_of_128(SC_VERIFY, __m128i, mm512_and_sse, mm512_xor_sse,
                                      mm512_shift_right_sse, 4);
}
#endif
#endif
//----------------------------------------------------------------------------------------------------------------------
#ifdef WITH_AVX2
#ifdef WITH_CUSTOM_INSTANCES
ATTR_TARGET("avx2")
static void _mpc_sbox_layer_bitsliced_256_avx(mzd_local_t** out, mzd_local_t* const* in,
                                              view_t* view, mzd_local_t** rvec,
                                              mask_t const* mask) {
  bitsliced_mm_step_1(SC_PROOF, __m256i, _mm256_and_si256, mm256_shift_left);

  oqs_sig_picnic_mpc_clear(view->s, SC_PROOF);
  oqs_sig_picnic_mpc_and_avx(r0m, x0s, x1s, r2m, view, 0);
  oqs_sig_picnic_mpc_and_avx(r2m, x1s, x2m, r1s, view, 1);
  oqs_sig_picnic_mpc_and_avx(r1m, x0s, x2m, r0s, view, 2);

  bitsliced_mm_step_2(SC_PROOF, __m256i, _mm256_and_si256, _mm256_xor_si256, mm256_shift_right);
}

ATTR_TARGET("avx2")
static void _mpc_sbox_layer_bitsliced_verify_256_avx(mzd_local_t** out, mzd_local_t** in,
                                                     view_t* view, mzd_local_t* const* rvec,
                                                     mask_t const* mask) {
  bitsliced_mm_step_1(SC_VERIFY, __m256i, _mm256_and_si256, mm256_shift_left);

  oqs_sig_picnic_mzd_local_clear(view->s[0]);
  oqs_sig_picnic_mpc_and_verify_avx(r0m, x0s, x1s, r2m, view, mx2, 0);
  oqs_sig_picnic_mpc_and_verify_avx(r2m, x1s, x2m, r1s, view, mx2, 1);
  oqs_sig_picnic_mpc_and_verify_avx(r1m, x0s, x2m, r0s, view, mx2, 2);

  bitsliced_mm_step_2(SC_VERIFY, __m256i, _mm256_and_si256, _mm256_xor_si256, mm256_shift_right);
}
//----------------------------------------------------------------------------------------------------------------------
ATTR_TARGET("avx2")
static void _mpc_sbox_layer_bitsliced_512_avx(mzd_local_t** out, mzd_local_t* const* in,
                                              view_t* view, mzd_local_t** rvec,
                                              mask_t const* mask) {
  bitsliced_mm_step_1_multiple_of_128(SC_PROOF, __m256i, mm512_and_avx, mm512_shift_left_avx, 2);

  oqs_sig_picnic_mpc_clear(view->s, SC_PROOF);
  oqs_sig_picnic_mpc_and_512_avx(r0m, x0s, x1s, r2m, view, 0);
  oqs_sig_picnic_mpc_and_512_avx(r2m, x1s, x2m, r1s, view, 1);
  oqs_sig_picnic_mpc_and_512_avx(r1m, x0s, x2m, r0s, view, 2);

  bitsliced_mm_step_2_multiple_of_128(SC_PROOF, __m256i, mm512_and_avx, mm512_xor_avx,
                                      mm512_shift_right_avx, 2);
}

ATTR_TARGET("avx2")
static void _mpc_sbox_layer_bitsliced_verify_512_avx(mzd_local_t** out, mzd_local_t** in,
                                                     view_t* view, mzd_local_t* const* rvec,
                                                     mask_t const* mask) {
  bitsliced_mm_step_1_multiple_of_128(SC_VERIFY, __m256i, mm512_and_avx, mm512_shift_left_avx, 2);

  oqs_sig_picnic_mzd_local_clear(view->s[0]);
  oqs_sig_picnic_mpc_and_verify_512_avx(r0m, x0s, x1s, r2m, view, mx2, 0);
  oqs_sig_picnic_mpc_and_verify_512_avx(r2m, x1s, x2m, r1s, view, mx2, 1);
  oqs_sig_picnic_mpc_and_verify_512_avx(r1m, x0s, x2m, r0s, view, mx2, 2);

  bitsliced_mm_step_2_multiple_of_128(SC_VERIFY, __m256i, mm512_and_avx, mm512_xor_avx,
                                      mm512_shift_right_avx, 2);
}
#endif
#endif
//----------------------------------------------------------------------------------------------------------------------
#ifdef WITH_NEON
#ifdef WITH_CUSTOM_INSTANCES
static void _mpc_sbox_layer_bitsliced_128_neon(mzd_local_t** out, mzd_local_t* const* in,
                                               view_t* view, mzd_local_t** rvec,
                                               mask_t const* mask) {
  bitsliced_mm_step_1(SC_PROOF, uint32x4_t, vandq_u32, mm128_shift_left);

  oqs_sig_picnic_mpc_clear(view->s, SC_PROOF);
  oqs_sig_picnic_mpc_and_neon(r0m, x0s, x1s, r2m, view, 0);
  oqs_sig_picnic_mpc_and_neon(r2m, x1s, x2m, r1s, view, 1);
  oqs_sig_picnic_mpc_and_neon(r1m, x0s, x2m, r0s, view, 2);

  bitsliced_mm_step_2(SC_PROOF, uint32x4_t, vandq_u32, veorq_u32, mm128_shift_right);
}

static void _mpc_sbox_layer_bitsliced_verify_128_neon(mzd_local_t** out, mzd_local_t* const* in,
                                                      view_t* view, mzd_local_t** rvec,
                                                      mask_t const* mask) {
  bitsliced_mm_step_1(SC_VERIFY, uint32x4_t, vandq_u32, mm128_shift_left);

  oqs_sig_picnic_mzd_local_clear(view->s[0]);
  oqs_sig_picnic_mpc_and_verify_neon(r0m, x0s, x1s, r2m, view, mx2, 0);
  oqs_sig_picnic_mpc_and_verify_neon(r2m, x1s, x2m, r1s, view, mx2, 1);
  oqs_sig_picnic_mpc_and_verify_neon(r1m, x0s, x2m, r0s, view, mx2, 2);

  bitsliced_mm_step_2(SC_VERIFY, uint32x4_t, vandq_u32, veorq_u32, mm128_shift_right);
}
//----------------------------------------------------------------------------------------------------------------------
static void _mpc_sbox_layer_bitsliced_256_neon(mzd_local_t** out, mzd_local_t* const* in,
                                               view_t* view, mzd_local_t** rvec,
                                               mask_t const* mask) {
  bitsliced_mm_step_1_multiple_of_128(SC_PROOF, uint32x4_t, mm256_and, mm256_shift_left, 2);

  oqs_sig_picnic_mpc_clear(view->s, SC_PROOF);
  oqs_sig_picnic_mpc_and_256_neon(r0m, x0s, x1s, r2m, view, 0);
  oqs_sig_picnic_mpc_and_256_neon(r2m, x1s, x2m, r1s, view, 1);
  oqs_sig_picnic_mpc_and_256_neon(r1m, x0s, x2m, r0s, view, 2);

  bitsliced_mm_step_2_multiple_of_128(SC_PROOF, uint32x4_t, mm256_and, mm256_xor, mm256_shift_right,
                                      2);
}

static void _mpc_sbox_layer_bitsliced_verify_256_neon(mzd_local_t** out, mzd_local_t* const* in,
                                                      view_t* view, mzd_local_t** rvec,
                                                      mask_t const* mask) {
  bitsliced_mm_step_1_multiple_of_128(SC_VERIFY, uint32x4_t, mm256_and, mm256_shift_left, 2);

  oqs_sig_picnic_mzd_local_clear(view->s[0]);
  oqs_sig_picnic_mpc_and_verify_256_neon(r0m, x0s, x1s, r2m, view, mx2, 0);
  oqs_sig_picnic_mpc_and_verify_256_neon(r2m, x1s, x2m, r1s, view, mx2, 1);
  oqs_sig_picnic_mpc_and_verify_256_neon(r1m, x0s, x2m, r0s, view, mx2, 2);

  bitsliced_mm_step_2_multiple_of_128(SC_VERIFY, uint32x4_t, mm256_and, mm256_xor,
                                      mm256_shift_right, 2);
}
//----------------------------------------------------------------------------------------------------------------------
static void _mpc_sbox_layer_bitsliced_384_neon(mzd_local_t** out, mzd_local_t* const* in,
                                               view_t* view, mzd_local_t** rvec,
                                               mask_t const* mask) {
  bitsliced_mm_step_1_multiple_of_128(SC_PROOF, uint32x4_t, mm384_and, mm384_shift_left, 3);

  oqs_sig_picnic_mpc_clear(view->s, SC_PROOF);
  oqs_sig_picnic_mpc_and_384_neon(r0m, x0s, x1s, r2m, view, 0);
  oqs_sig_picnic_mpc_and_384_neon(r2m, x1s, x2m, r1s, view, 1);
  oqs_sig_picnic_mpc_and_384_neon(r1m, x0s, x2m, r0s, view, 2);

  bitsliced_mm_step_2_multiple_of_128(SC_PROOF, uint32x4_t, mm384_and, mm384_xor, mm384_shift_right,
                                      3);
}

static void _mpc_sbox_layer_bitsliced_verify_384_neon(mzd_local_t** out, mzd_local_t* const* in,
                                                      view_t* view, mzd_local_t** rvec,
                                                      mask_t const* mask) {
  bitsliced_mm_step_1_multiple_of_128(SC_VERIFY, uint32x4_t, mm384_and, mm384_shift_left, 3);

  oqs_sig_picnic_mzd_local_clear(view->s[0]);
  oqs_sig_picnic_mpc_and_verify_384_neon(r0m, x0s, x1s, r2m, view, mx2, 0);
  oqs_sig_picnic_mpc_and_verify_384_neon(r2m, x1s, x2m, r1s, view, mx2, 1);
  oqs_sig_picnic_mpc_and_verify_384_neon(r1m, x0s, x2m, r0s, view, mx2, 2);

  bitsliced_mm_step_2_multiple_of_128(SC_VERIFY, uint32x4_t, mm384_and, mm384_xor,
                                      mm384_shift_right, 3);
}

//----------------------------------------------------------------------------------------------------------------------
static void _mpc_sbox_layer_bitsliced_512_neon(mzd_local_t** out, mzd_local_t* const* in,
                                               view_t* view, mzd_local_t** rvec,
                                               mask_t const* mask) {
  bitsliced_mm_step_1_multiple_of_128(SC_PROOF, uint32x4_t, mm512_and, mm512_shift_left, 4);

  oqs_sig_picnic_mpc_clear(view->s, SC_PROOF);
  oqs_sig_picnic_mpc_and_512_neon(r0m, x0s, x1s, r2m, view, 0);
  oqs_sig_picnic_mpc_and_512_neon(r2m, x1s, x2m, r1s, view, 1);
  oqs_sig_picnic_mpc_and_512_neon(r1m, x0s, x2m, r0s, view, 2);

  bitsliced_mm_step_2_multiple_of_128(SC_PROOF, uint32x4_t, mm512_and, mm512_xor, mm512_shift_right,
                                      4);
}

static void _mpc_sbox_layer_bitsliced_verify_512_neon(mzd_local_t** out, mzd_local_t* const* in,
                                                      view_t* view, mzd_local_t** rvec,
                                                      mask_t const* mask) {
  bitsliced_mm_step_1_multiple_of_128(SC_VERIFY, uint32x4_t, mm512_and, mm512_shift_left, 4);

  oqs_sig_picnic_mzd_local_clear(view->s[0]);
  oqs_sig_picnic_mpc_and_verify_512_neon(r0m, x0s, x1s, r2m, view, mx2, 0);
  oqs_sig_picnic_mpc_and_verify_512_neon(r2m, x1s, x2m, r1s, view, mx2, 1);
  oqs_sig_picnic_mpc_and_verify_512_neon(r1m, x0s, x2m, r0s, view, mx2, 2);

  bitsliced_mm_step_2_multiple_of_128(SC_VERIFY, uint32x4_t, mm512_and, mm512_xor,
                                      mm512_shift_right, 4);
}
#endif
#endif
#endif

#define MPC_LOOP MPC_LOOP_CONST
#define MPC_LOOP_TWO_MATRICES MPC_LOOP_SHARED
#define MPC_IF_ELSE MPC_LOOP_CONST_C

#define noscr(const_mat_mul_func, add_func, const_addmat_mul_func, shares)                         \
  MPC_LOOP(const_addmat_mul_func, x, lowmc_key, round->k_lookup, shares);

#define scr(const_mat_mul_func, add_func, const_addmat_mul_func, shares)                           \
  MPC_LOOP(const_mat_mul_func, y, lowmc_key, round->k_matrix, shares);                             \
  MPC_LOOP_TWO_MATRICES(add_func, x, x, y, shares);

#define SBOX(X, sbox, sbox_selector, y, x, views, r, lowmcmask, vars, n, shares)                   \
  SBOX_##sbox_selector(X, sbox, y, x, views, r, lowmcmask, vars, n, shares)

#define SBOX_mzd(X, sbox, y, x, views, r, lowmcmask, vars, n, shares)                              \
  SBOX_mzd_##X(sbox, y, x, views, r, lowmcmask, vars, n)

#define SBOX_mzd_5(sbox, y1, x, views, r, lowmcmask, vars, n) sbox(y1, x, views, r, lowmcmask);
#define SBOX_mzd_6(sbox, y1, x, views, r, lowmcmask, vars, n)                                      \
  sbox(y1, x, views, r, lowmcmask, vars);

#define SBOX_uint64(X, sbox, y, x, views, r, lowmcmask, vars, n, shares)                           \
  SBOX_uint64_##shares(sbox, y, x, views, r, lowmcmask, vars, n)

#define SBOX_uint64_3(sbox, y1, x, views, r, lowmcmask, vars, n)                                   \
  uint64_t in[SC_PROOF];                                                                           \
  uint64_t out[SC_PROOF];                                                                          \
  for (int count = 0; count < SC_PROOF; count++) {                                                 \
    in[count]  = CONST_FIRST_ROW(x[count])[n / 64 - 1];                                            \
    out[count] = CONST_FIRST_ROW(y1[count])[n / 64 - 1];                                           \
  }                                                                                                \
  _mpc_sbox_layer_bitsliced_uint64(out, in, views, r, lowmcmask);                                  \
  for (int count = 0; count < SC_PROOF; count++) {                                                 \
    memcpy(FIRST_ROW(y1[count]), CONST_FIRST_ROW(x[count]), (n / 64 - 1) * sizeof(word));          \
    FIRST_ROW(y1[count])[n / 64 - 1] = out[count];                                                 \
  }

#define SBOX_uint64_2(sbox, y1, x, views, r, lowmcmask, vars, n)                                   \
  uint64_t in[SC_VERIFY];                                                                          \
  uint64_t out[SC_VERIFY];                                                                         \
  for (int count = 0; count < SC_VERIFY; count++) {                                                \
    in[count]  = CONST_FIRST_ROW(x[count])[n / 64 - 1];                                            \
    out[count] = CONST_FIRST_ROW(y1[count])[n / 64 - 1];                                           \
  }                                                                                                \
  _mpc_sbox_layer_bitsliced_verify_uint64(out, in, views, r, lowmcmask);                           \
  for (int count = 0; count < SC_VERIFY; count++) {                                                \
    memcpy(FIRST_ROW(y1[count]), CONST_FIRST_ROW(x[count]), (n / 64 - 1) * sizeof(word));          \
    FIRST_ROW(y1[count])[n / 64 - 1] = out[count];                                                 \
  }

#define R(selector, shares) R_##selector##_##shares

#define R_mzd_2 mzd_local_t** r = rvec[i].s
#define R_mzd_3 mzd_local_t** r = rvec[i].s

#ifdef _MSC_VER
#define R_uint64_2                                                                                 \
  uint64_t r[SC_VERIFY];                                                                           \
  r[0] = rvec[i].t[0];                                                                             \
  r[1] = rvec[i].t[1]
#define R_uint64_3                                                                                 \
  uint64_t r[SC_PROOF];                                                                            \
  r[0] = rvec[i].t[0];                                                                             \
  r[1] = rvec[i].t[1];                                                                             \
  r[2] = rvec[i].t[2]
#else
#define R_uint64_2 uint64_t r[SC_VERIFY] = {rvec[i].t[0], rvec[i].t[1]}
#define R_uint64_3 uint64_t r[SC_PROOF]  = {rvec[i].t[0], rvec[i].t[1], rvec[i].t[2]}
#endif

#define loop_optimize(sbox_args, sbox, sbox_selector, no_scr, no_scr_active, const_mat_mul_func,   \
                      add_func, mul_more_cols, const_addmat_mul_func, ch, shares)                  \
  mzd_local_t* nl_part[shares];                                                                    \
  oqs_sig_picnic_mzd_local_init_multiple_ex(nl_part, shares, 1, lowmc->r * 32, false);             \
  MPC_LOOP(mul_more_cols, nl_part, lowmc_key, lowmc->precomputed_non_linear_part_##no_scr,         \
           shares);                                                                                \
  word mask = 0x00000000FFFFFFFF;                                                                  \
  for (unsigned i = 0; i < lowmc->r; ++i, ++views, ++round) {                                      \
    R(sbox_selector, shares);                                                                      \
    SBOX(sbox_args, sbox, sbox_selector, y, x, views, r, &lowmc->mask, &vars, lowmc->n, shares);   \
    const unsigned int shift = ((mask & 0xFFFFFFFF) ? 34 : 2);                                     \
    for (unsigned int k = 0; k < shares; k++) {                                                    \
      FIRST_ROW(y[k])[y[k]->width - 1] ^= (CONST_FIRST_ROW(nl_part[k])[i >> 1] & mask) << shift;   \
    }                                                                                              \
    mask = ~mask;                                                                                  \
    MPC_LOOP(const_mat_mul_func, x, y, round->l_##no_scr, shares);                                 \
    MPC_IF_ELSE(add_func, x, x, round->constant, shares, ch);                                      \
  }                                                                                                \
  oqs_sig_picnic_mzd_local_free_multiple(nl_part);

#define loop(sbox_args, sbox, sbox_selector, no_scr, no_scr_active, const_mat_mul_func, add_func,  \
             mul_more_cols, const_addmat_mul_func, ch, shares)                                     \
  for (unsigned i = 0; i < lowmc->r; ++i, ++views, ++round) {                                      \
    R(sbox_selector, shares);                                                                      \
    SBOX(sbox_args, sbox, sbox_selector, y, x, views, r, &lowmc->mask, &vars, lowmc->n, shares);   \
    oqs_sig_picnic_mpc_clear(x, shares);                                                                          \
    MPC_LOOP(const_mat_mul_func, x, y, round->l_##no_scr, shares);                                 \
    MPC_IF_ELSE(add_func, x, x, round->constant, shares, ch);                                      \
    no_scr_active(const_mat_mul_func, add_func, const_addmat_mul_func, shares);                    \
  }

#define VARS_5(shares)
#define VARS_6(shares)                                                                             \
  sbox_vars_t vars;                                                                                \
  sbox_vars_init(&vars, lowmc->n, shares)

#define VARS_FREE_5
#define VARS_FREE_6 sbox_vars_clear(&vars)

#define _mpc_lowmc_call_bitsliced(ch, sbox_args, sbox, sbox_selector, no_scr, no_scr_active,       \
                                  optimize, const_mat_mul_func, add_func, mul_more_cols,           \
                                  const_addmat_mul_func)                                           \
  oqs_sig_picnic_mpc_copy(in_out_shares->s, lowmc_key, SC_PROOF);                                                 \
  ++in_out_shares;                                                                                 \
  VARS_##sbox_args(SC_PROOF);                                                                      \
  mzd_local_t** x = in_out_shares->s;                                                              \
  mzd_local_t* y[SC_PROOF];                                                                        \
  oqs_sig_picnic_mzd_local_init_multiple_ex(y, SC_PROOF, 1, lowmc->n, false);                      \
                                                                                                   \
  MPC_LOOP(const_mat_mul_func, x, lowmc_key, lowmc->k0_##no_scr, SC_PROOF);                        \
  MPC_IF_ELSE(add_func, x, x, p, SC_PROOF, ch);                                                    \
                                                                                                   \
  lowmc_round_t const* round = lowmc->rounds;                                                      \
                                                                                                   \
  loop##optimize(sbox_args, sbox, sbox_selector, no_scr, no_scr_active, const_mat_mul_func,        \
                 add_func, mul_more_cols, const_addmat_mul_func, ch, SC_PROOF)                     \
      VARS_FREE_##sbox_args;                                                                       \
  oqs_sig_picnic_mzd_local_free_multiple(y);

#define init_key mzd_local_t* const* lowmc_key = &in_out_shares->s[0];

#define _mpc_lowmc_call_bitsliced_verify_m(ch, sbox_args, sbox, sbox_selector, no_scr,             \
                                           no_scr_active, optimize, const_mat_mul_func, add_func,  \
                                           mul_more_cols, const_addmat_mul_func)                   \
  init_key;                                                                                        \
                                                                                                   \
  ++in_out_shares;                                                                                 \
  VARS_##sbox_args(SC_VERIFY);                                                                     \
  mzd_local_t* x[2 * SC_VERIFY];                                                                   \
  mzd_local_t** y = &x[SC_VERIFY];                                                                 \
  oqs_sig_picnic_mzd_local_init_multiple_ex(x, 2 * SC_VERIFY, 1, lowmc->n, false);                 \
                                                                                                   \
  MPC_LOOP(const_mat_mul_func, x, lowmc_key, lowmc->k0_##no_scr, SC_VERIFY);                       \
  MPC_IF_ELSE(add_func, x, x, p, SC_VERIFY, ch);                                                   \
                                                                                                   \
  lowmc_round_t const* round = lowmc->rounds;                                                      \
                                                                                                   \
  loop##optimize(sbox_args, sbox, sbox_selector, no_scr, no_scr_active, const_mat_mul_func,        \
                 add_func, mul_more_cols, const_addmat_mul_func, ch, SC_VERIFY);                   \
  oqs_sig_picnic_mpc_copy(in_out_shares->s, x, SC_VERIFY);                                                        \
  oqs_sig_picnic_mzd_local_free_multiple(x);                                                       \
  VARS_FREE_##sbox_args;

static void mpc_lowmc_call(lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key, mzd_local_t const* p,
                           view_t* views, in_out_shares_t* in_out_shares, rvec_t* rvec) {
#ifdef REDUCED_LINEAR_LAYER
#ifdef MUL_M4RI
#ifdef WITH_CUSTOM_INSTANCES
  if (lowmc->m != 10) {
    _mpc_lowmc_call_bitsliced(0, 6, _mpc_sbox_layer_bitsliced, mzd, lookup, noscr, _optimize,
                              oqs_sig_picnic_mzd_mul_vl_general, oqs_sig_picnic_mzd_xor_general, oqs_sig_picnic_mzd_mul_vl_general,
                              mzd_addmul_vl_general);
  } else
#endif
  {
    _mpc_lowmc_call_bitsliced(0, 6, , uint64, lookup, noscr, _optimize, oqs_sig_picnic_mzd_mul_vl_general,
                              oqs_sig_picnic_mzd_xor_general, oqs_sig_picnic_mzd_mul_vl_general, mzd_addmul_vl_general);
  }
#else
#ifdef WITH_CUSTOM_INSTANCES
  if (lowmc->m != 10) {
    _mpc_lowmc_call_bitsliced(0, 6, _mpc_sbox_layer_bitsliced, mzd, matrix, scr, _optimize,
                              oqs_sig_picnic_mzd_mul_v_general, oqs_sig_picnic_mzd_xor_general, oqs_sig_picnic_mzd_mul_v_general,
                              oqs_sig_picnic_mzd_addmul_v_general);
  } else
#endif
  {
    _mpc_lowmc_call_bitsliced(0, 6, , uint64, matrix, scr, _optimize, oqs_sig_picnic_mzd_mul_v_general,
                              oqs_sig_picnic_mzd_xor_general, oqs_sig_picnic_mzd_mul_v_general, oqs_sig_picnic_mzd_addmul_v_general);
  }
#endif
#else
#ifdef MUL_M4RI
#ifdef WITH_CUSTOM_INSTANCES
  if (lowmc->m != 10) {
    _mpc_lowmc_call_bitsliced(0, 6, _mpc_sbox_layer_bitsliced, mzd, lookup, noscr, ,
                              oqs_sig_picnic_mzd_mul_vl_general, oqs_sig_picnic_mzd_xor_general, , mzd_addmul_vl_general);
  } else
#endif
  {
    _mpc_lowmc_call_bitsliced(0, 6, , uint64, lookup, noscr, , oqs_sig_picnic_mzd_mul_vl_general, oqs_sig_picnic_mzd_xor_general,
                              , mzd_addmul_vl_general);
  }
#else
#ifdef WITH_CUSTOM_INSTANCES
  if (lowmc->m != 10) {
    _mpc_lowmc_call_bitsliced(0, 6, _mpc_sbox_layer_bitsliced, mzd, matrix, scr, ,
                              oqs_sig_picnic_mzd_mul_v_general, oqs_sig_picnic_mzd_xor_general, , oqs_sig_picnic_mzd_addmul_v_general);
  } else
#endif
  {
    _mpc_lowmc_call_bitsliced(0, 6, , uint64, matrix, scr, , oqs_sig_picnic_mzd_mul_v_general, oqs_sig_picnic_mzd_xor_general, ,
                              oqs_sig_picnic_mzd_addmul_v_general);
  }
#endif
#endif
}

static void mpc_lowmc_call_verify(lowmc_t const* lowmc, mzd_local_t const* p, view_t* views,
                                  in_out_shares_t* in_out_shares, rvec_t* rvec, unsigned int ch) {
#ifdef REDUCED_LINEAR_LAYER
#ifdef MUL_M4RI
#ifdef WITH_CUSTOM_INSTANCES
  if (lowmc->m != 10) {
    _mpc_lowmc_call_bitsliced_verify_m(ch, 6, _mpc_sbox_layer_bitsliced_verify, mzd, lookup, noscr,
                                       _optimize, oqs_sig_picnic_mzd_mul_vl_general, oqs_sig_picnic_mzd_xor_general,
                                       oqs_sig_picnic_mzd_mul_vl_general, mzd_addmul_vl_general);
  } else
#endif
  {
    _mpc_lowmc_call_bitsliced_verify_m(ch, 6, , uint64, lookup, noscr, _optimize,
                                       oqs_sig_picnic_mzd_mul_vl_general, oqs_sig_picnic_mzd_xor_general, oqs_sig_picnic_mzd_mul_vl_general,
                                       mzd_addmul_vl_general);
  }
#else
#ifdef WITH_CUSTOM_INSTANCES
  if (lowmc->m != 10) {
    _mpc_lowmc_call_bitsliced_verify_m(ch, 6, _mpc_sbox_layer_bitsliced_verify, mzd, matrix, scr,
                                       _optimize, oqs_sig_picnic_mzd_mul_v_general, oqs_sig_picnic_mzd_xor_general,
                                       oqs_sig_picnic_mzd_mul_v_general, oqs_sig_picnic_mzd_addmul_v_general);
  } else
#endif
  {
    _mpc_lowmc_call_bitsliced_verify_m(ch, 6, , uint64, matrix, scr, _optimize, oqs_sig_picnic_mzd_mul_v_general,
                                       oqs_sig_picnic_mzd_xor_general, oqs_sig_picnic_mzd_mul_v_general, oqs_sig_picnic_mzd_addmul_v_general);
  }
#endif
#else
#ifdef MUL_M4RI
#ifdef WITH_CUSTOM_INSTANCES
  if (lowmc->m != 10) {
    _mpc_lowmc_call_bitsliced_verify_m(ch, 6, _mpc_sbox_layer_bitsliced_verify, mzd, lookup, noscr,
                                       , oqs_sig_picnic_mzd_mul_vl_general, oqs_sig_picnic_mzd_xor_general, ,
                                       mzd_addmul_vl_general);
  } else
#endif
  {
    _mpc_lowmc_call_bitsliced_verify_m(ch, 6, , uint64, lookup, noscr, , oqs_sig_picnic_mzd_mul_vl_general,
                                       oqs_sig_picnic_mzd_xor_general, , mzd_addmul_vl_general);
  }
#else
#ifdef WITH_CUSTOM_INSTANCES
  if (lowmc->m != 10) {
    _mpc_lowmc_call_bitsliced_verify_m(ch, 6, _mpc_sbox_layer_bitsliced_verify, mzd, matrix, scr, ,
                                       oqs_sig_picnic_mzd_mul_v_general, oqs_sig_picnic_mzd_xor_general, , oqs_sig_picnic_mzd_addmul_v_general);
  } else
#endif
  {
    _mpc_lowmc_call_bitsliced_verify_m(ch, 6, , uint64, matrix, scr, , oqs_sig_picnic_mzd_mul_v_general,
									   oqs_sig_picnic_mzd_xor_general, , oqs_sig_picnic_mzd_addmul_v_general);
  }
#endif
#endif
}

#ifdef REDUCED_LINEAR_LAYER
#ifdef MUL_M4RI
#define mpc_lowmc_call_def_gen(N_SIGN, N_VERIFY, SBOX_SIGN, SBOX_VERIFY, MUL, MUL_L, XOR, XOR_L,   \
                               MUL_MC, MUL_MC_L, ADDMUL, ADDMUL_L)                                 \
  static inline void N_SIGN(lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key,                      \
                            mzd_local_t const* p, view_t* views, in_out_shares_t* in_out_shares,   \
                            rvec_t* rvec) {                                                        \
    _mpc_lowmc_call_bitsliced(0, 5, SBOX_SIGN, mzd, lookup, noscr, _optimize, MUL_L, XOR_L,        \
                              MUL_MC_L, ADDMUL_L);                                                 \
  }                                                                                                \
  static inline void N_VERIFY(lowmc_t const* lowmc, mzd_local_t const* p, view_t* views,           \
                              in_out_shares_t* in_out_shares, rvec_t* rvec, unsigned int ch) {     \
    _mpc_lowmc_call_bitsliced_verify_m(ch, 5, SBOX_VERIFY, mzd, lookup, noscr, _optimize, MUL_L,   \
                                       XOR_L, MUL_MC_L, ADDMUL_L);                                 \
  }

#define mpc_lowmc_call_def_10(N_SIGN, N_VERIFY, SBOX_SIGN, SBOX_VERIFY, MUL, MUL_L, XOR, XOR_L,    \
                              MUL_MC, MUL_MC_L, ADDMUL, ADDMUL_L)                                  \
  static inline void N_SIGN##_10(lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key,                 \
                                 mzd_local_t const* p, view_t* views,                              \
                                 in_out_shares_t* in_out_shares, rvec_t* rvec) {                   \
    _mpc_lowmc_call_bitsliced(0, 5, , uint64, lookup, noscr, _optimize, MUL_L, XOR_L, MUL_MC_L,    \
                              ADDMUL_L);                                                           \
  }                                                                                                \
  static inline void N_VERIFY##_10(lowmc_t const* lowmc, mzd_local_t const* p, view_t* views,      \
                                   in_out_shares_t* in_out_shares, rvec_t* rvec,                   \
                                   unsigned int ch) {                                              \
    _mpc_lowmc_call_bitsliced_verify_m(ch, 5, , uint64, lookup, noscr, _optimize, MUL_L, XOR_L,    \
                                       MUL_MC_L, ADDMUL_L);                                        \
  }
#else
#define mpc_lowmc_call_def_gen(N_SIGN, N_VERIFY, SBOX_SIGN, SBOX_VERIFY, MUL, MUL_L, XOR, XOR_L,   \
                               MUL_MC, MUL_MC_L, ADDMUL, ADDMUL_L)                                 \
  static inline void N_SIGN(lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key,                      \
                            mzd_local_t const* p, view_t* views, in_out_shares_t* in_out_shares,   \
                            rvec_t* rvec) {                                                        \
    _mpc_lowmc_call_bitsliced(0, 5, SBOX_SIGN, mzd, matrix, scr, _optimize, MUL, XOR, MUL_MC,      \
                              ADDMUL);                                                             \
  }                                                                                                \
  static inline void N_VERIFY(lowmc_t const* lowmc, mzd_local_t const* p, view_t* views,           \
                              in_out_shares_t* in_out_shares, rvec_t* rvec, unsigned int ch) {     \
    _mpc_lowmc_call_bitsliced_verify_m(ch, 5, SBOX_VERIFY, mzd, matrix, scr, _optimize, MUL, XOR,  \
                                       MUL_MC, ADDMUL);                                            \
  }

#define mpc_lowmc_call_def_10(N_SIGN, N_VERIFY, SBOX_SIGN, SBOX_VERIFY, MUL, MUL_L, XOR, XOR_L,    \
                              MUL_MC, MUL_MC_L, ADDMUL, ADDMUL_L)                                  \
  static inline void N_SIGN##_10(lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key,                 \
                                 mzd_local_t const* p, view_t* views,                              \
                                 in_out_shares_t* in_out_shares, rvec_t* rvec) {                   \
    _mpc_lowmc_call_bitsliced(0, 5, , uint64, matrix, scr, _optimize, MUL, XOR, MUL_MC, ADDMUL);   \
  }                                                                                                \
  static inline void N_VERIFY##_10(lowmc_t const* lowmc, mzd_local_t const* p, view_t* views,      \
                                   in_out_shares_t* in_out_shares, rvec_t* rvec,                   \
                                   unsigned int ch) {                                              \
    _mpc_lowmc_call_bitsliced_verify_m(ch, 5, , uint64, matrix, scr, _optimize, MUL, XOR, MUL_MC,  \
                                       ADDMUL);                                                    \
  }
#endif
#else
#ifdef MUL_M4RI
#define mpc_lowmc_call_def_gen(N_SIGN, N_VERIFY, SBOX_SIGN, SBOX_VERIFY, MUL, MUL_L, XOR, XOR_L,   \
                               MUL_MC, MUL_MC_L, ADDMUL, ADDMUL_L)                                 \
  static inline void N_SIGN(lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key,                      \
                            mzd_local_t const* p, view_t* views, in_out_shares_t* in_out_shares,   \
                            rvec_t* rvec) {                                                        \
    _mpc_lowmc_call_bitsliced(0, 5, SBOX_SIGN, mzd, lookup, noscr, , MUL_L, XOR_L, MUL_MC_L,       \
                              ADDMUL_L);                                                           \
  }                                                                                                \
  static inline void N_VERIFY(lowmc_t const* lowmc, mzd_local_t const* p, view_t* views,           \
                              in_out_shares_t* in_out_shares, rvec_t* rvec, unsigned int ch) {     \
    _mpc_lowmc_call_bitsliced_verify_m(ch, 5, SBOX_VERIFY, mzd, lookup, noscr, , MUL_L, XOR_L,     \
                                       MUL_MC_L, ADDMUL_L);                                        \
  }

#define mpc_lowmc_call_def_10(N_SIGN, N_VERIFY, SBOX_SIGN, SBOX_VERIFY, MUL, MUL_L, XOR, XOR_L,    \
                              MUL_MC, MUL_MC_L, ADDMUL, ADDMUL_L)                                  \
  static inline void N_SIGN##_10(lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key,                 \
                                 mzd_local_t const* p, view_t* views,                              \
                                 in_out_shares_t* in_out_shares, rvec_t* rvec) {                   \
    _mpc_lowmc_call_bitsliced(0, 5, , uint64, lookup, noscr, , MUL_L, XOR_L, MUL_MC_L, ADDMUL_L);  \
  }                                                                                                \
  static inline void N_VERIFY##_10(lowmc_t const* lowmc, mzd_local_t const* p, view_t* views,      \
                                   in_out_shares_t* in_out_shares, rvec_t* rvec,                   \
                                   unsigned int ch) {                                              \
    _mpc_lowmc_call_bitsliced_verify_m(ch, 5, , uint64, lookup, noscr, , MUL_L, XOR_L, MUL_MC_L,   \
                                       ADDMUL_L);                                                  \
  }
#else
#define mpc_lowmc_call_def_gen(N_SIGN, N_VERIFY, SBOX_SIGN, SBOX_VERIFY, MUL, MUL_L, XOR, XOR_L,   \
                               MUL_MC, MUL_MC_L, ADDMUL, ADDMUL_L)                                 \
  static inline void N_SIGN(lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key,                      \
                            mzd_local_t const* p, view_t* views, in_out_shares_t* in_out_shares,   \
                            rvec_t* rvec) {                                                        \
    _mpc_lowmc_call_bitsliced(0, 5, SBOX_SIGN, mzd, matrix, scr, , MUL, XOR, MUL_MC, ADDMUL);      \
  }                                                                                                \
  static inline void N_VERIFY(lowmc_t const* lowmc, mzd_local_t const* p, view_t* views,           \
                              in_out_shares_t* in_out_shares, rvec_t* rvec, unsigned int ch) {     \
    _mpc_lowmc_call_bitsliced_verify_m(ch, 5, SBOX_VERIFY, mzd, matrix, scr, , MUL, XOR, MUL_MC,   \
                                       ADDMUL);                                                    \
  }
#define mpc_lowmc_call_def_10(N_SIGN, N_VERIFY, SBOX_SIGN, SBOX_VERIFY, MUL, MUL_L, XOR, XOR_L,    \
                              MUL_MC, MUL_MC_L, ADDMUL, ADDMUL_L)                                  \
  static inline void N_SIGN##_10(lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key,                 \
                                 mzd_local_t const* p, view_t* views,                              \
                                 in_out_shares_t* in_out_shares, rvec_t* rvec) {                   \
    _mpc_lowmc_call_bitsliced(0, 5, , uint64, matrix, scr, , MUL, XOR, MUL_MC, ADDMUL);            \
  }                                                                                                \
  static inline void N_VERIFY##_10(lowmc_t const* lowmc, mzd_local_t const* p, view_t* views,      \
                                   in_out_shares_t* in_out_shares, rvec_t* rvec,                   \
                                   unsigned int ch) {                                              \
    _mpc_lowmc_call_bitsliced_verify_m(ch, 5, , uint64, matrix, scr, , MUL, XOR, MUL_MC, ADDMUL);  \
  }
#endif
#endif

#ifdef WITH_CUSTOM_INSTANCES
#define mpc_lowmc_call_def(N_SIGN, N_VERIFY, SBOX_SIGN, SBOX_VERIFY, MUL, MUL_L, XOR, XOR_L,       \
                           MUL_MC, MUL_MC_L, ADDMUL, ADDMUL_L)                                     \
  mpc_lowmc_call_def_gen(N_SIGN, N_VERIFY, SBOX_SIGN, SBOX_VERIFY, MUL, MUL_L, XOR, XOR_L, MUL_MC, \
                         MUL_MC_L, ADDMUL, ADDMUL_L)                                               \
  mpc_lowmc_call_def_10(N_SIGN, N_VERIFY, SBOX_SIGN, SBOX_VERIFY, MUL, MUL_L, XOR, XOR_L, MUL_MC,  \
                        MUL_MC_L, ADDMUL, ADDMUL_L)
#else
#define mpc_lowmc_call_def(N_SIGN, N_VERIFY, SBOX_SIGN, SBOX_VERIFY, MUL, MUL_L, XOR, XOR_L,       \
                           MUL_MC, MUL_MC_L, ADDMUL, ADDMUL_L)                                     \
  mpc_lowmc_call_def_10(N_SIGN, N_VERIFY, SBOX_SIGN, SBOX_VERIFY, MUL, MUL_L, XOR, XOR_L, MUL_MC,  \
                        MUL_MC_L, ADDMUL, ADDMUL_L)
#endif

#ifdef WITH_OPT
#ifdef WITH_SSE2
mpc_lowmc_call_def(mpc_lowmc_call_128_sse, mpc_lowmc_call_verify_128_sse,
                   _mpc_sbox_layer_bitsliced_128_sse, _mpc_sbox_layer_bitsliced_verify_128_sse,
                   oqs_sig_picnic_mzd_mul_v_sse, oqs_sig_picnic_mzd_mul_vl_sse_128, oqs_sig_picnic_mzd_xor_sse, oqs_sig_picnic_mzd_xor_sse, oqs_sig_picnic_mzd_mul_v_sse,
                   oqs_sig_picnic_mzd_mul_vl_sse, oqs_sig_picnic_mzd_addmul_v_sse, oqs_sig_picnic_mzd_addmul_vl_sse_128)
mpc_lowmc_call_def(mpc_lowmc_call_256_sse, mpc_lowmc_call_verify_256_sse,
                   _mpc_sbox_layer_bitsliced_256_sse, _mpc_sbox_layer_bitsliced_verify_256_sse,
                   oqs_sig_picnic_mzd_mul_v_sse, oqs_sig_picnic_mzd_mul_vl_sse, oqs_sig_picnic_mzd_xor_sse, oqs_sig_picnic_mzd_xor_sse, oqs_sig_picnic_mzd_mul_v_sse,
                   oqs_sig_picnic_mzd_mul_vl_sse, oqs_sig_picnic_mzd_addmul_v_sse, oqs_sig_picnic_mzd_addmul_vl_sse)
#ifdef WITH_CUSTOM_INSTANCES
mpc_lowmc_call_def(mpc_lowmc_call_384_sse, mpc_lowmc_call_verify_384_sse,
                   _mpc_sbox_layer_bitsliced_384_sse, _mpc_sbox_layer_bitsliced_verify_384_sse,
                   oqs_sig_picnic_mzd_mul_v_sse, oqs_sig_picnic_mzd_mul_vl_sse, oqs_sig_picnic_mzd_xor_sse, oqs_sig_picnic_mzd_xor_sse, oqs_sig_picnic_mzd_mul_v_sse,
                   oqs_sig_picnic_mzd_mul_vl_sse, oqs_sig_picnic_mzd_addmul_v_sse, oqs_sig_picnic_mzd_addmul_vl_sse)
mpc_lowmc_call_def(mpc_lowmc_call_512_sse, mpc_lowmc_call_verify_512_sse,
                   _mpc_sbox_layer_bitsliced_512_sse, _mpc_sbox_layer_bitsliced_verify_512_sse,
                   oqs_sig_picnic_mzd_mul_v_sse, oqs_sig_picnic_mzd_mul_vl_sse, oqs_sig_picnic_mzd_xor_sse, oqs_sig_picnic_mzd_xor_sse, oqs_sig_picnic_mzd_mul_v_sse,
                   oqs_sig_picnic_mzd_mul_vl_sse, oqs_sig_picnic_mzd_addmul_v_sse, oqs_sig_picnic_mzd_addmul_vl_sse)
#endif
#endif
#ifdef WITH_AVX2
mpc_lowmc_call_def(mpc_lowmc_call_256_avx, mpc_lowmc_call_verify_256_avx,
                   _mpc_sbox_layer_bitsliced_256_avx, _mpc_sbox_layer_bitsliced_verify_256_avx,
                   oqs_sig_picnic_mzd_mul_v_avx, oqs_sig_picnic_mzd_mul_vl_avx_256, oqs_sig_picnic_mzd_xor_avx, oqs_sig_picnic_mzd_xor_avx, oqs_sig_picnic_mzd_mul_v_avx,
                   oqs_sig_picnic_mzd_mul_vl_avx, oqs_sig_picnic_mzd_addmul_v_avx, oqs_sig_picnic_mzd_addmul_vl_avx_256)
#ifdef WITH_CUSTOM_INSTANCES
mpc_lowmc_call_def(mpc_lowmc_call_384_avx, mpc_lowmc_call_verify_384_avx,
                   _mpc_sbox_layer_bitsliced_512_avx, _mpc_sbox_layer_bitsliced_verify_512_avx,
                   oqs_sig_picnic_mzd_mul_v_avx, oqs_sig_picnic_mzd_mul_vl_avx, oqs_sig_picnic_mzd_xor_avx, oqs_sig_picnic_mzd_xor_avx, oqs_sig_picnic_mzd_mul_v_avx,
                   oqs_sig_picnic_mzd_mul_vl_avx, oqs_sig_picnic_mzd_addmul_v_avx, oqs_sig_picnic_mzd_addmul_vl_avx)
mpc_lowmc_call_def(mpc_lowmc_call_512_avx, mpc_lowmc_call_verify_512_avx,
                   _mpc_sbox_layer_bitsliced_512_avx, _mpc_sbox_layer_bitsliced_verify_512_avx,
                   oqs_sig_picnic_mzd_mul_v_avx, oqs_sig_picnic_mzd_mul_vl_avx, oqs_sig_picnic_mzd_xor_avx, oqs_sig_picnic_mzd_xor_avx, oqs_sig_picnic_mzd_mul_v_avx,
                   oqs_sig_picnic_mzd_mul_vl_avx, oqs_sig_picnic_mzd_addmul_v_avx, oqs_sig_picnic_mzd_addmul_vl_avx)
#endif
#endif
#ifdef WITH_NEON
mpc_lowmc_call_def(mpc_lowmc_call_128_neon, mpc_lowmc_call_verify_128_neon,
                   _mpc_sbox_layer_bitsliced_128_neon, _mpc_sbox_layer_bitsliced_verify_128_neon,
                   oqs_sig_picnic_mzd_mul_v_neon, oqs_sig_picnic_mzd_mul_vl_neon_128, oqs_sig_picnic_mzd_xor_neon, oqs_sig_picnic_mzd_xor_neon, oqs_sig_picnic_mzd_mul_v_neon,
                   oqs_sig_picnic_mzd_mul_vl_neon_multiple_of_128, oqs_sig_picnic_mzd_addmul_v_neon, oqs_sig_picnic_mzd_addmul_vl_neon_128)
mpc_lowmc_call_def(mpc_lowmc_call_256_neon, mpc_lowmc_call_verify_256_neon,
                   _mpc_sbox_layer_bitsliced_256_neon, _mpc_sbox_layer_bitsliced_verify_256_neon,
                   oqs_sig_picnic_mzd_mul_v_neon, oqs_sig_picnic_mzd_mul_vl_neon_multiple_of_128, oqs_sig_picnic_mzd_xor_neon, oqs_sig_picnic_mzd_xor_neon,
                   oqs_sig_picnic_mzd_mul_v_neon, oqs_sig_picnic_mzd_mul_vl_neon_multiple_of_128, oqs_sig_picnic_mzd_addmul_v_neon,
                   oqs_sig_picnic_mzd_addmul_vl_neon)
#ifdef WITH_CUSTOM_INSTANCES
mpc_lowmc_call_def(mpc_lowmc_call_384_neon, mpc_lowmc_call_verify_384_neon,
                   _mpc_sbox_layer_bitsliced_384_neon, _mpc_sbox_layer_bitsliced_verify_384_neon,
                   oqs_sig_picnic_mzd_mul_v_neon, oqs_sig_picnic_mzd_mul_vl_neon_multiple_of_128, oqs_sig_picnic_mzd_xor_neon, oqs_sig_picnic_mzd_xor_neon,
                   oqs_sig_picnic_mzd_mul_v_neon, oqs_sig_picnic_mzd_mul_vl_neon_multiple_of_128, oqs_sig_picnic_mzd_addmul_v_neon,
                   oqs_sig_picnic_mzd_addmul_vl_neon)
mpc_lowmc_call_def(mpc_lowmc_call_512_neon, mpc_lowmc_call_verify_512_neon,
                   _mpc_sbox_layer_bitsliced_512_neon, _mpc_sbox_layer_bitsliced_verify_512_neon,
                   oqs_sig_picnic_mzd_mul_v_neon, oqs_sig_picnic_mzd_mul_vl_neon_multiple_of_128, oqs_sig_picnic_mzd_xor_neon, oqs_sig_picnic_mzd_xor_neon,
                   oqs_sig_picnic_mzd_mul_v_neon, oqs_sig_picnic_mzd_mul_vl_neon_multiple_of_128, oqs_sig_picnic_mzd_addmul_v_neon,
                   oqs_sig_picnic_mzd_addmul_vl_neon)
#endif
#endif
#endif

static void sbox_vars_clear(sbox_vars_t* vars) {
  if (vars->storage) {
    oqs_sig_picnic_mzd_local_free_multiple(vars->storage);
    free(vars->storage);
    memset(vars, 0, sizeof(*vars));
  }
}

static sbox_vars_t* sbox_vars_init(sbox_vars_t* vars, uint32_t n, unsigned sc) {
  vars->storage = calloc(11 * sc, sizeof(mzd_local_t*));
  oqs_sig_picnic_mzd_local_init_multiple_ex(vars->storage, 11 * sc, 1, n, false);

  for (unsigned int i = 0; i < sc; ++i) {
    vars->x0m[i] = vars->storage[11 * i + 0];
    vars->x1m[i] = vars->storage[11 * i + 1];
    vars->x2m[i] = vars->storage[11 * i + 2];
    vars->r0m[i] = vars->storage[11 * i + 3];
    vars->r1m[i] = vars->storage[11 * i + 4];
    vars->r2m[i] = vars->storage[11 * i + 5];
    vars->x0s[i] = vars->storage[11 * i + 6];
    vars->x1s[i] = vars->storage[11 * i + 7];
    vars->r0s[i] = vars->storage[11 * i + 8];
    vars->r1s[i] = vars->storage[11 * i + 9];
    vars->v[i]   = vars->storage[11 * i + 10];
  }

  return vars;
}

#ifdef WITH_CUSTOM_INSTANCES
#define general_or_10(l, f) (l)->m == 10 ? f##_10 : (f)
#else
#define general_or_10(l, f) f##_10
#endif

lowmc_implementation_f oqs_sig_picnic_get_lowmc_implementation(const lowmc_t* lowmc) {
#ifdef WITH_OPT
#ifdef WITH_SSE2
  if (CPU_SUPPORTS_SSE2 && lowmc->n <= 128) {
    return general_or_10(lowmc, mpc_lowmc_call_128_sse);
  }
#endif
#ifdef WITH_AVX2
  if (CPU_SUPPORTS_AVX2 && lowmc->n >= 129 && lowmc->n <= 256) {
    return general_or_10(lowmc, mpc_lowmc_call_256_avx);
  }
#ifdef WITH_CUSTOM_INSTANCES
  if (CPU_SUPPORTS_AVX2 && lowmc->n == 384) {
    return general_or_10(lowmc, mpc_lowmc_call_384_avx);
  } else if (CPU_SUPPORTS_AVX2 && lowmc->n == 512) {
    return general_or_10(lowmc, mpc_lowmc_call_512_avx);
  }
#endif
#endif
#ifdef WITH_SSE2
  if (CPU_SUPPORTS_SSE2 && lowmc->n <= 256) {
    return general_or_10(lowmc, mpc_lowmc_call_256_sse);
  }
#ifdef WITH_CUSTOM_INSTANCES
  if (CPU_SUPPORTS_SSE2 && lowmc->n == 384) {
    return general_or_10(lowmc, mpc_lowmc_call_384_sse);
  } else if (CPU_SUPPORTS_SSE2 && lowmc->n == 512) {
    return general_or_10(lowmc, mpc_lowmc_call_512_sse);
  }
#endif
#endif
#ifdef WITH_NEON
  if (CPU_SUPPORTS_NEON && lowmc->n == 128) {
    return general_or_10(lowmc, mpc_lowmc_call_128_neon);
  } else if (CPU_SUPPORTS_NEON && lowmc->n <= 256) {
    return general_or_10(lowmc, mpc_lowmc_call_256_neon);
  }
#ifdef WITH_CUSTOM_INSTANCES
  if (CPU_SUPPORTS_NEON && lowmc->n == 384) {
    return general_or_10(lowmc, mpc_lowmc_call_384_neon);
  } else if (CPU_SUPPORTS_NEON && lowmc->n == 512) {
    return general_or_10(lowmc, mpc_lowmc_call_512_neon);
  }
#endif
#endif
#endif

#ifndef WITH_CUSTOM_INSTANCES
  if (lowmc->m != 10) {
    return NULL;
  }
#endif

  (void)lowmc;
  return mpc_lowmc_call;
}

lowmc_verify_implementation_f oqs_sig_picnic_get_lowmc_verify_implementation(const lowmc_t* lowmc) {
#ifdef WITH_OPT
#ifdef WITH_SSE2
  if (CPU_SUPPORTS_SSE2 && lowmc->n <= 128) {
    return general_or_10(lowmc, mpc_lowmc_call_verify_128_sse);
  }
#endif
#ifdef WITH_AVX2
  if (CPU_SUPPORTS_AVX2 && lowmc->n >= 129 && lowmc->n <= 256) {
    return general_or_10(lowmc, mpc_lowmc_call_verify_256_avx);
  }
#ifdef WITH_CUSTOM_INSTANCES
  if (CPU_SUPPORTS_AVX2 && lowmc->n == 384) {
    return general_or_10(lowmc, mpc_lowmc_call_verify_384_avx);
  } else if (CPU_SUPPORTS_AVX2 && lowmc->n == 512) {
    return general_or_10(lowmc, mpc_lowmc_call_verify_512_avx);
  }
#endif
#endif
#ifdef WITH_SSE2
  if (CPU_SUPPORTS_SSE2 && lowmc->n <= 256) {
    return general_or_10(lowmc, mpc_lowmc_call_verify_256_sse);
  }
#ifdef WITH_CUSTOM_INSTANCES
  if (CPU_SUPPORTS_SSE2 && lowmc->n == 384) {
    return general_or_10(lowmc, mpc_lowmc_call_verify_384_sse);
  } else if (CPU_SUPPORTS_SSE2 && lowmc->n == 512) {
    return general_or_10(lowmc, mpc_lowmc_call_verify_512_sse);
  }
#endif
#endif
#ifdef WITH_NEON
  if (CPU_SUPPORTS_NEON && lowmc->n == 128) {
    return general_or_10(lowmc, mpc_lowmc_call_verify_128_neon);
  } else if (CPU_SUPPORTS_NEON && lowmc->n <= 256) {
    return general_or_10(lowmc, mpc_lowmc_call_verify_256_neon);
  }
#ifdef WITH_CUSTOM_INSTANCES
  if (CPU_SUPPORTS_NEON && lowmc->n == 384) {
    return general_or_10(lowmc, mpc_lowmc_call_verify_384_neon);
  } else if (CPU_SUPPORTS_NEON && lowmc->n == 512) {
    return general_or_10(lowmc, mpc_lowmc_call_verify_512_neon);
  }
#endif
#endif
#endif

#ifndef WITH_CUSTOM_INSTANCES
  if (lowmc->m != 10) {
    return NULL;
  }
#endif

  (void)lowmc;
  return mpc_lowmc_call_verify;
}
