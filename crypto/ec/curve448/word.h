/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2014 Cryptography Research, Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#ifndef __WORD_H__
# define __WORD_H__

# include <string.h>

# include <assert.h>
# include <openssl/e_os2.h>
# include "arch_intrinsics.h"

# include "curve448utils.h"
# include <stdlib.h>

# if defined(__ARM_NEON__)
#  include <arm_neon.h>
# elif defined(__SSE2__)
#  if !defined(__GNUC__) || defined(__clang__) || __GNUC__ >= 5 \
      || (__GNUC__==4 && __GNUC_MINOR__ >= 4)
#   include <immintrin.h>
#  else
#   include <emmintrin.h>
#  endif
# endif

# if (ARCH_WORD_BITS == 64)
typedef uint64_t word_t, mask_t;
typedef __uint128_t dword_t;
typedef int32_t hsword_t;
typedef int64_t sword_t;
typedef __int128_t dsword_t;
# elif (ARCH_WORD_BITS == 32)
typedef uint32_t word_t, mask_t;
typedef uint64_t dword_t;
typedef int16_t hsword_t;
typedef int32_t sword_t;
typedef int64_t dsword_t;
# else
#  error "For now, we only support 32- and 64-bit architectures."
# endif

/*
 * Scalar limbs are keyed off of the API word size instead of the arch word
 * size.
 */
# if C448_WORD_BITS == 64
#  define SC_LIMB(x) (x)
# elif C448_WORD_BITS == 32
#  define SC_LIMB(x) ((uint32_t)x),(x>>32)
# else
#  error "For now we only support 32- and 64-bit architectures."
# endif

# ifdef __ARM_NEON__
typedef uint32x4_t vecmask_t;
# elif defined(__clang__)
typedef uint64_t uint64x2_t __attribute__ ((ext_vector_type(2)));
typedef int64_t int64x2_t __attribute__ ((ext_vector_type(2)));
typedef uint64_t uint64x4_t __attribute__ ((ext_vector_type(4)));
typedef int64_t int64x4_t __attribute__ ((ext_vector_type(4)));
typedef uint32_t uint32x4_t __attribute__ ((ext_vector_type(4)));
typedef int32_t int32x4_t __attribute__ ((ext_vector_type(4)));
typedef uint32_t uint32x2_t __attribute__ ((ext_vector_type(2)));
typedef int32_t int32x2_t __attribute__ ((ext_vector_type(2)));
typedef uint32_t uint32x8_t __attribute__ ((ext_vector_type(8)));
typedef int32_t int32x8_t __attribute__ ((ext_vector_type(8)));
typedef word_t vecmask_t __attribute__ ((ext_vector_type(4)));
# elif defined(__GNUC__) \
       && (__GNUC__ >= 4 || (__GNUC__== 3 && __GNUC_MINOR__ >= 1))
typedef uint64_t uint64x2_t __attribute__ ((vector_size(16)));
typedef int64_t int64x2_t __attribute__ ((vector_size(16)));
typedef uint64_t uint64x4_t __attribute__ ((vector_size(32)));
typedef int64_t int64x4_t __attribute__ ((vector_size(32)));
typedef uint32_t uint32x4_t __attribute__ ((vector_size(16)));
typedef int32_t int32x4_t __attribute__ ((vector_size(16)));
typedef uint32_t uint32x2_t __attribute__ ((vector_size(8)));
typedef int32_t int32x2_t __attribute__ ((vector_size(8)));
typedef uint32_t uint32x8_t __attribute__ ((vector_size(32)));
typedef int32_t int32x8_t __attribute__ ((vector_size(32)));
typedef word_t vecmask_t __attribute__ ((vector_size(32)));
# endif

# if defined(__AVX2__)
#  define VECTOR_ALIGNED __attribute__((aligned(32)))
typedef uint32x8_t big_register_t;
typedef uint64x4_t uint64xn_t;
typedef uint32x8_t uint32xn_t;

static ossl_inline big_register_t br_set_to_mask(mask_t x)
{
    uint32_t y = (uint32_t)x;
    big_register_t ret = { y, y, y, y, y, y, y, y };
    return ret;
}
# elif defined(__SSE2__)
#  define VECTOR_ALIGNED __attribute__((aligned(16)))
typedef uint32x4_t big_register_t;
typedef uint64x2_t uint64xn_t;
typedef uint32x4_t uint32xn_t;

static ossl_inline big_register_t br_set_to_mask(mask_t x)
{
    uint32_t y = x;
    big_register_t ret = { y, y, y, y };
    return ret;
}
# elif defined(__ARM_NEON__)
#  define VECTOR_ALIGNED __attribute__((aligned(16)))
typedef uint32x4_t big_register_t;
typedef uint64x2_t uint64xn_t;
typedef uint32x4_t uint32xn_t;

static ossl_inline big_register_t br_set_to_mask(mask_t x)
{
    return vdupq_n_u32(x);
}
# elif !defined(_MSC_VER) \
       && (defined(_WIN64) || defined(__amd64__) || defined(__X86_64__) \
           || defined(__aarch64__))
#  define VECTOR_ALIGNED __attribute__((aligned(8)))
typedef uint64_t big_register_t, uint64xn_t;

typedef uint32_t uint32xn_t;
static ossl_inline big_register_t br_set_to_mask(mask_t x)
{
    return (big_register_t) x;
}
# else
#  ifdef __GNUC__
#   define VECTOR_ALIGNED __attribute__((aligned(4)))
#  else
/*
 * This shouldn't be a problem because a big_register_t isn't actually a vector
 * type anyway in this case.
 */
#   define VECTOR_ALIGNED
#  endif
typedef uint64_t uint64xn_t;
typedef uint32_t uint32xn_t;
typedef uint32_t big_register_t;

static ossl_inline big_register_t br_set_to_mask(mask_t x)
{
    return (big_register_t) x;
}
# endif

# if defined(__AVX2__)
static ossl_inline big_register_t br_is_zero(big_register_t x)
{
    return (big_register_t) (x == br_set_to_mask(0));
}
# elif defined(__SSE2__)
static ossl_inline big_register_t br_is_zero(big_register_t x)
{
    return (big_register_t) _mm_cmpeq_epi32((__m128i) x, _mm_setzero_si128());
}
# elif defined(__ARM_NEON__)
static ossl_inline big_register_t br_is_zero(big_register_t x)
{
    return vceqq_u32(x, x ^ x);
}
# else
#  define br_is_zero word_is_zero
# endif

/* PERF: vectorize vs unroll */
# ifdef __clang__
#  if 100*__clang_major__ + __clang_minor__ > 305
#   define UNROLL _Pragma("clang loop unroll(full)")
#  endif
# endif

# ifndef UNROLL
#  define UNROLL
# endif

/*
 * The plan on booleans: The external interface uses c448_bool_t, but this
 * might be a different size than our particular arch's word_t (and thus
 * mask_t).  Also, the caller isn't guaranteed to pass it as nonzero.  So
 * bool_to_mask converts word sizes and checks nonzero. On the flip side,
 * mask_t is always -1 or 0, but it might be a different size than
 * c448_bool_t. On the third hand, we have success vs boolean types, but
 * that's handled in common.h: it converts between c448_bool_t and
 * c448_error_t.
 */
static ossl_inline c448_bool_t mask_to_bool(mask_t m)
{
    return (c448_sword_t)(sword_t)m;
}

static ossl_inline mask_t bool_to_mask(c448_bool_t m)
{
    /* On most arches this will be optimized to a simple cast. */
    mask_t ret = 0;
    unsigned int i;
    unsigned int limit = sizeof(c448_bool_t) / sizeof(mask_t);

    if (limit < 1)
        limit = 1;
    for (i = 0; i < limit; i++)
        ret |= ~word_is_zero(m >> (i * 8 * sizeof(word_t)));

    return ret;
}

static ossl_inline void ignore_result(c448_bool_t boo)
{
    (void)boo;
}

#endif                          /* __WORD_H__ */
