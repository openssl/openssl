/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef PICNIC_MACROS_H
#define PICNIC_MACROS_H

/* compatibility with clang and other compilers*/
#ifndef __has_attribute
#define __has_attribute(a) 0
#endif

#ifndef __has_builtin
#define __has_builtin(b) 0
#endif

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define GNUC_CHECK(maj, min)                                                                       \
  (((__GNUC__ << 20) + (__GNUC_MINOR__ << 10)) >= (((maj) << 20) + ((min) << 10)))
#else
#define GNUC_CHECK(maj, min) 0
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#if GNUC_CHECK(3, 3) || __has_attribute(nonnull)
#define ATTR_NONNULL __attribute__((nonnull))
#define ATTR_NONNULL_ARG(i) __attribute__((nonnull(i)))
#else
#define ATTR_NONNULL
#define ATTR_NONNULL_ARG(i)
#endif

#if GNUC_CHECK(2, 7) || __has_attribute(destructor)
#define ATTR_DTOR __attribute__((destructor))
#else
#define ATTR_DTOR
#endif

#if GNUC_CHECK(4, 9) || __has_attribute(assume_aligned)
#define ATTR_ASSUME_ALIGNED(i) __attribute__((assume_aligned(i)))
#else
#define ATTR_ASSUME_ALIGNED(i)
#endif

#if GNUC_CHECK(4, 9) || __has_attribute(aligned)
#define ATTR_ALIGNED(i) __attribute__((aligned(i)))
#else
#define ATTR_ALIGNED(i)
#endif

#if GNUC_CHECK(4, 9) || __has_builtin(assume_aligned)
#define ASSUME_ALIGNED(p, a) __builtin_assume_aligned((p), (a))
#else
#define ASSUME_ALIGNED(p, a) (p)
#endif

#if GNUC_CHECK(4, 0) || __has_attribute(always_inline)
#define ATTR_ALWAYS_INLINE __attribute__((always_inline))
#elif defined(_MSC_VER)
#define ATTR_ALWAYS_INLINE __forceinline
#else
#define ATTR_ALWAYS_INLINE
#endif

#if defined(__GNUC__) || __has_attribute(pure)
#define ATTR_PURE __attribute__((pure))
#else
#define ATTR_PURE
#endif

#if defined(__GNUC__) || __has_attribute(target)
#define ATTR_TARGET(x) __attribute__((target((x))))
#else
#define ATTR_TARGET(x)
#endif

#define FN_ATTRIBUTES_AVX2_NP ATTR_ALWAYS_INLINE ATTR_TARGET("avx2")
#define FN_ATTRIBUTES_SSE2_NP ATTR_ALWAYS_INLINE ATTR_TARGET("sse2")

#define FN_ATTRIBUTES_AVX2 FN_ATTRIBUTES_AVX2_NP ATTR_PURE
#define FN_ATTRIBUTES_SSE2 FN_ATTRIBUTES_SSE2_NP ATTR_PURE

#endif
