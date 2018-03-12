/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef SIMD_H
#define SIMD_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "macros.h"

#if defined(_MSC_VER)
#include <immintrin.h>
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#include <x86intrin.h>
#elif defined(__GNUC__) && defined(__ARM_NEON)
#include <arm_neon.h>
#endif

#if defined(__GNUC__) && !(defined(__APPLE__) && (__clang_major__ <= 8)) &&                        \
    !defined(__MINGW32__) && !defined(__MINGW64__)
#define BUILTIN_CPU_SUPPORTED
#endif

#ifdef WITH_SSE2
/* backwards compatibility macros for GCC 4.8 and 4.9
 *
 * bs{l,r}i was introduced in GCC 5 and in clang as macros sometime in 2015.
 * */
#if (!defined(__clang__) && defined(__GNUC__) && __GNUC__ < 5) ||                                  \
    (defined(__clang__) && !defined(_mm_bslli_si128)) || defined(_MSC_VER)
#define _mm_bslli_si128(a, imm) _mm_slli_si128((a), (imm))
#define _mm_bsrli_si128(a, imm) _mm_srli_si128((a), (imm))
#endif
#endif

#include "cpu.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#if defined(BUILTIN_CPU_SUPPORTED)
#define CPU_SUPPORTS_AVX2 __builtin_cpu_supports("avx2")
#define CPU_SUPPORTS_SSE4_1 __builtin_cpu_supports("sse4.1")
#else
#define CPU_SUPPORTS_AVX2 cpu_supports(CPU_CAP_AVX2)
#define CPU_SUPPORTS_SSE4_1 cpu_supports(CPU_CAP_SSE4_1)
#endif
#endif

#if defined(__x86_64__) || defined(_M_X64)
// X86-64 CPUs always support SSE2
#define CPU_SUPPORTS_SSE2 1
#elif defined(__i386__) || defined(_M_IX86)
#if defined(BUILTIN_CPU_SUPPORTED)
#define CPU_SUPPORTS_SSE2 __builtin_cpu_supports("sse2")
#else
#define CPU_SUPPORTS_SSE2 cpu_supports(CPU_CAP_SSE2)
#endif
#else
#define CPU_SUPPORTS_SSE2 0
#endif

#if defined(__aarch64__)
#define CPU_SUPPORTS_NEON 1
#elif defined(__arm__)
#define CPU_SUPPRTS_NEON cpu_supports(CPU_CAP_NEON)
#else
#define CPU_SUPPORTS_NEON 0
#endif

#if defined(_MSC_VER)
#define restrict __restrict
#endif

#define apply_region(name, type, xor, attributes)                                                  \
  static inline void attributes name(type* restrict dst, type const* restrict src,                 \
                                     unsigned int count) {                                         \
    for (unsigned int i = count; i; --i, ++dst, ++src) {                                           \
      *dst = (xor)(*dst, *src);                                                                    \
    }                                                                                              \
  }

#define apply_mask_region(name, type, xor, and, attributes)                                        \
  static inline void attributes name(type* restrict dst, type const* restrict src,                 \
                                     type const mask, unsigned int count) {                        \
    for (unsigned int i = count; i; --i, ++dst, ++src) {                                           \
      *dst = (xor)(*dst, (and)(mask, *src));                                                       \
    }                                                                                              \
  }

#define apply_array(name, type, xor, count, attributes)                                            \
  static inline void attributes name(type dst[count], type const lhs[count],                       \
                                     type const rhs[count]) {                                      \
    for (unsigned int i = 0; i < count; ++i) {                                                     \
      dst[i] = (xor)(lhs[i], rhs[i]);                                                              \
    }                                                                                              \
  }

#ifdef WITH_AVX2
/**
 * \brief Perform a left shift on a 256 bit value.
 */
static inline __m256i FN_ATTRIBUTES_AVX2 mm256_shift_left(__m256i data, unsigned int count) {
  if (!count) {
    return data;
  }

  __m256i carry  = _mm256_srli_epi64(data, 64 - count);
  __m256i rotate = _mm256_permute4x64_epi64(carry, _MM_SHUFFLE(2, 1, 0, 3));
  carry          = _mm256_blend_epi32(_mm256_setzero_si256(), rotate, _MM_SHUFFLE(3, 3, 3, 0));
  data           = _mm256_slli_epi64(data, count);
  return _mm256_or_si256(data, carry);
}

/**
 * \brief Perform a right shift on a 256 bit value.
 */
static inline __m256i FN_ATTRIBUTES_AVX2 mm256_shift_right(__m256i data, unsigned int count) {
  if (!count) {
    return data;
  }

  __m256i carry  = _mm256_slli_epi64(data, 64 - count);
  __m256i rotate = _mm256_permute4x64_epi64(carry, _MM_SHUFFLE(0, 3, 2, 1));
  carry          = _mm256_blend_epi32(_mm256_setzero_si256(), rotate, _MM_SHUFFLE(0, 3, 3, 3));
  data           = _mm256_srli_epi64(data, count);
  return _mm256_or_si256(data, carry);
}

#ifdef WITH_CUSTOM_INSTANCES
static inline void FN_ATTRIBUTES_AVX2_NP mm512_shift_left_avx(__m256i res[2], __m256i const data[2],
                                                              unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    return;
  }

  __m256i total_carry = _mm256_bsrli_epi128(data[0], 8);
  total_carry         = _mm256_srli_epi64(total_carry, 64 - count);
  total_carry         = _mm256_permute2x128_si256(total_carry, _mm256_setzero_si256(), 0x21);

  res[0] = mm256_shift_left(data[0], count);
  res[1] = mm256_shift_left(data[1], count);
  res[1] = _mm256_or_si256(res[1], total_carry);
}

static inline void FN_ATTRIBUTES_AVX2_NP mm512_shift_right_avx(__m256i res[2],
                                                               __m256i const data[2],
                                                               unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    return;
  }

  __m256i total_carry = _mm256_bslli_epi128(data[1], 8);
  total_carry         = _mm256_slli_epi64(total_carry, 64 - count);
  total_carry         = _mm256_permute2x128_si256(total_carry, _mm256_setzero_si256(), 0x02);
  res[0]              = mm256_shift_right(data[0], count);
  res[1]              = mm256_shift_right(data[1], count);
  res[0]              = _mm256_or_si256(res[0], total_carry);
}
#endif

apply_region(mm256_xor_region, __m256i, _mm256_xor_si256, FN_ATTRIBUTES_AVX2_NP);
apply_mask_region(mm256_xor_mask_region, __m256i, _mm256_xor_si256, _mm256_and_si256,
                  FN_ATTRIBUTES_AVX2_NP);
#ifdef WITH_CUSTOM_INSTANCES
apply_array(mm512_xor_avx, __m256i, _mm256_xor_si256, 2, FN_ATTRIBUTES_AVX2_NP);
apply_array(mm512_and_avx, __m256i, _mm256_and_si256, 2, FN_ATTRIBUTES_AVX2_NP);
#endif
#endif

#ifdef WITH_SSE2
/**
 * \brief Perform a left shift on a 128 bit value.
 */
static inline __m128i FN_ATTRIBUTES_SSE2 mm128_shift_left(__m128i data, unsigned int count) {
  if (!count) {
    return data;
  }

  __m128i carry = _mm_bslli_si128(data, 8);
  /* if (count >= 64) {
    return _mm_slli_epi64(carry, count - 64);
  } */
  carry = _mm_srli_epi64(carry, 64 - count);
  data  = _mm_slli_epi64(data, count);
  return _mm_or_si128(data, carry);
}

/**
 * \brief Perform a right shift on a 128 bit value.
 */
static inline __m128i FN_ATTRIBUTES_SSE2 mm128_shift_right(__m128i data, unsigned int count) {
  if (!count) {
    return data;
  }

  __m128i carry = _mm_bsrli_si128(data, 8);
  /* if (count >= 64) {
    return _mm_srli_epi64(carry, count - 64);
  } */
  carry = _mm_slli_epi64(carry, 64 - count);
  data  = _mm_srli_epi64(data, count);
  return _mm_or_si128(data, carry);
}

static inline void FN_ATTRIBUTES_SSE2_NP mm256_shift_right_sse(__m128i res[2],
                                                               __m128i const data[2],
                                                               unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    return;
  }

  __m128i total_carry = _mm_bslli_si128(data[1], 8);
  total_carry         = _mm_slli_epi64(total_carry, 64 - count);
  for (int i = 0; i < 2; ++i) {
    __m128i carry = _mm_bsrli_si128(data[i], 8);
    carry         = _mm_slli_epi64(carry, 64 - count);
    res[i]        = _mm_srli_epi64(data[i], count);
    res[i]        = _mm_or_si128(res[i], carry);
  }
  res[0] = _mm_or_si128(res[0], total_carry);
}

static inline void FN_ATTRIBUTES_SSE2_NP mm256_shift_left_sse(__m128i res[2], __m128i const data[2],
                                                              unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    return;
  }

  __m128i total_carry = _mm_bsrli_si128(data[0], 8);
  total_carry         = _mm_srli_epi64(total_carry, 64 - count);

  for (int i = 0; i < 2; ++i) {
    __m128i carry = _mm_bslli_si128(data[i], 8);

    carry  = _mm_srli_epi64(carry, 64 - count);
    res[i] = _mm_slli_epi64(data[i], count);
    res[i] = _mm_or_si128(res[i], carry);
  }
  res[1] = _mm_or_si128(res[1], total_carry);
}

static inline void FN_ATTRIBUTES_SSE2_NP mm384_shift_right_sse(__m128i res[3],
                                                               __m128i const data[3],
                                                               unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    res[2] = data[2];
    return;
  }
  __m128i total_carry = _mm_bslli_si128(data[2], 8);
  total_carry         = _mm_slli_epi64(total_carry, 64 - count);

  mm256_shift_right_sse(&(res[0]), &(data[0]), count);
  res[2] = mm128_shift_right(data[2], count);

  res[1] = _mm_or_si128(res[1], total_carry);
}

static inline void FN_ATTRIBUTES_SSE2_NP mm384_shift_left_sse(__m128i res[3], __m128i const data[3],
                                                              unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    res[2] = data[2];
    return;
  }

  __m128i total_carry = _mm_bsrli_si128(data[1], 8);
  total_carry         = _mm_srli_epi64(total_carry, 64 - count);

  mm256_shift_left_sse(&(res[0]), &(data[0]), count);
  res[2] = mm128_shift_left(data[2], count);

  res[2] = _mm_or_si128(res[2], total_carry);
}

static inline void FN_ATTRIBUTES_SSE2_NP mm512_shift_right_sse(__m128i res[4],
                                                               __m128i const data[4],
                                                               unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    res[2] = data[2];
    res[3] = data[3];
    return;
  }
  __m128i total_carry = _mm_bslli_si128(data[2], 8);
  total_carry         = _mm_slli_epi64(total_carry, 64 - count);

  mm256_shift_right_sse(&(res[0]), &(data[0]), count);
  mm256_shift_right_sse(&(res[2]), &(data[2]), count);
  res[1] = _mm_or_si128(res[1], total_carry);
}

static inline void FN_ATTRIBUTES_SSE2_NP mm512_shift_left_sse(__m128i res[4], __m128i const data[4],
                                                              unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    res[2] = data[2];
    res[3] = data[3];
    return;
  }

  __m128i total_carry = _mm_bsrli_si128(data[1], 8);
  total_carry         = _mm_srli_epi64(total_carry, 64 - count);

  mm256_shift_left_sse(&(res[0]), &(data[0]), count);
  mm256_shift_left_sse(&(res[2]), &(data[2]), count);
  res[2] = _mm_or_si128(res[2], total_carry);
}

apply_region(mm128_xor_region, __m128i, _mm_xor_si128, FN_ATTRIBUTES_SSE2_NP)
apply_mask_region(mm128_xor_mask_region, __m128i, _mm_xor_si128, _mm_and_si128,
                  FN_ATTRIBUTES_SSE2_NP)
apply_array(mm256_xor_sse, __m128i, _mm_xor_si128, 2, FN_ATTRIBUTES_SSE2_NP)
apply_array(mm256_and_sse, __m128i, _mm_and_si128, 2, FN_ATTRIBUTES_SSE2_NP)
#ifdef WITH_CUSTOM_INSTANCES
apply_array(mm384_xor_sse, __m128i, _mm_xor_si128, 3, FN_ATTRIBUTES_SSE2_NP)
apply_array(mm384_and_sse, __m128i, _mm_and_si128, 3, FN_ATTRIBUTES_SSE2_NP)
apply_array(mm512_xor_sse, __m128i, _mm_xor_si128, 4, FN_ATTRIBUTES_SSE2_NP)
apply_array(mm512_and_sse, __m128i, _mm_and_si128, 4, FN_ATTRIBUTES_SSE2_NP)
#endif
#endif

#ifdef WITH_NEON
/**
 * \brief Perform a right shift on a 128 bit value.
 */
static inline uint32x4_t mm128_shift_right(uint32x4_t data, const unsigned int count) {
  if (!count) {
    return data;
  }

  uint32x4_t carry = vmovq_n_u32(0);
  carry            = vextq_u32(data, carry, 1);
  carry            = vshlq_n_u32(carry, 32 - count);
  data             = vshrq_n_u32(data, count);
  data             = vorrq_u32(data, carry);
  return data;
}

static inline uint32x4_t mm128_shift_left(uint32x4_t data, unsigned int count) {
  if (!count) {
    return data;
  }

  uint32x4_t carry = vmovq_n_u32(0);
  carry            = vextq_u32(carry, data, 3);
  carry            = vshrq_n_u32(carry, 32 - count);
  data             = vshlq_n_u32(data, count);
  data             = vorrq_u32(data, carry);
  return data;
}

static inline void mm256_shift_right(uint32x4_t res[2], uint32x4_t const data[2],
                                     const unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    return;
  }

  uint32x4_t total_carry = vmovq_n_u32(0);
  total_carry            = vextq_u32(total_carry, data[1], 1);

  total_carry = vshlq_n_u32(total_carry, 32 - count);

  for (int i = 0; i < 2; i++) {
    uint32x4_t carry = vmovq_n_u32(0);
    carry            = vextq_u32((uint32x4_t)data[i], carry, 1);
    carry            = vshlq_n_u32(carry, 32 - count);
    res[i]           = vshrq_n_u32(data[i], count);
    res[i]           = vorrq_u32(res[i], carry);
  }

  res[0] = vorrq_u32(res[0], total_carry);
}

static inline void mm256_shift_left(uint32x4_t res[2], uint32x4_t const data[2],
                                    unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    return;
  }

  uint32x4_t total_carry = vmovq_n_u32(0);
  total_carry            = vextq_u32((uint32x4_t)data[0], total_carry, 3);
  total_carry            = vshrq_n_u32(total_carry, 32 - count);

  for (int i = 0; i < 2; i++) {
    uint32x4_t carry = vmovq_n_u32(0);
    carry            = vextq_u32(carry, data[i], 3);
    carry            = vshrq_n_u32(carry, 32 - count);
    res[i]           = vshlq_n_u32(data[i], count);
    res[i]           = vorrq_u32(res[i], carry);
  }
  res[1] = vorrq_u32(res[1], total_carry);
}

#ifdef WITH_CUSTOM_INSTANCES
static inline void mm384_shift_left(uint32x4_t res[3], uint32x4_t const data[3],
                                    unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    res[2] = data[2];
    return;
  }

  uint32x4_t total_carry = vmovq_n_u32(0);
  total_carry            = vextq_u32((uint32x4_t)data[1], total_carry, 3);
  total_carry            = vshrq_n_u32(total_carry, 32 - count);

  mm256_shift_left(&(res[0]), &(data[0]), count);
  res[2] = mm128_shift_left(data[2], count);
  res[2] = vorrq_u32(res[2], total_carry);
}

static inline void mm384_shift_right(uint32x4_t res[3], uint32x4_t const data[3],
                                     const unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    res[2] = data[2];
    return;
  }
  uint32x4_t total_carry = vmovq_n_u32(0);
  total_carry            = vextq_u32(total_carry, data[2], 1);
  total_carry            = vshlq_n_u32(total_carry, 32 - count);

  mm256_shift_right(&(res[0]), &(data[0]), count);
  res[2] = mm128_shift_right(data[2], count);

  res[1] = vorrq_u32(res[1], total_carry);
}

static inline void mm512_shift_left(uint32x4_t res[4], uint32x4_t const data[4],
                                    unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    res[2] = data[2];
    res[3] = data[3];
    return;
  }

  uint32x4_t total_carry = vmovq_n_u32(0);
  total_carry            = vextq_u32((uint32x4_t)data[1], total_carry, 3);
  total_carry            = vshrq_n_u32(total_carry, 32 - count);

  mm256_shift_left(&(res[0]), &(data[0]), count);
  mm256_shift_left(&(res[2]), &(data[2]), count);
  res[2] = vorrq_u32(res[2], total_carry);
}

static inline void mm512_shift_right(uint32x4_t res[4], uint32x4_t const data[4],
                                     const unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    res[2] = data[2];
    res[3] = data[3];
    return;
  }

  uint32x4_t total_carry = vmovq_n_u32(0);
  total_carry            = vextq_u32(total_carry, data[2], 1);
  total_carry            = vshlq_n_u32(total_carry, 32 - count);

  mm256_shift_right(&(res[0]), &(data[0]), count);
  mm256_shift_right(&(res[2]), &(data[2]), count);

  res[1] = vorrq_u32(res[1], total_carry);
}
#endif

apply_region(mm128_xor_region, uint32x4_t, veorq_u32, );
apply_mask_region(mm128_xor_mask_region, uint32x4_t, veorq_u32, vandq_u32, );
apply_array(mm256_xor, uint32x4_t, veorq_u32, 2, );
apply_array(mm256_and, uint32x4_t, vandq_u32, 2, );
#ifdef WITH_CUSTOM_INSTANCES
apply_array(mm384_xor, uint32x4_t, veorq_u32, 3, );
apply_array(mm384_and, uint32x4_t, vandq_u32, 3, );
apply_array(mm512_xor, uint32x4_t, veorq_u32, 4, );
apply_array(mm512_and, uint32x4_t, vandq_u32, 4, );
#endif
#endif

#if defined(_MSC_VER)
#undef restrict
#endif

#undef apply_region
#undef apply_mask_region
#undef apply_array
#undef BUILTIN_CPU_SUPPORTED

#endif
