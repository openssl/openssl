/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#ifndef __WORD_H__
#define __WORD_H__

/* for posix_memalign */
#define _XOPEN_SOURCE 600
#define __STDC_WANT_LIB_EXT1__ 1 /* for memset_s */
#include <string.h>
#if defined(__sun) && defined(__SVR4)
extern int posix_memalign(void **, size_t, size_t);
#endif

#include <assert.h>
#include <stdint.h>
#include "arch_intrinsics.h"

#include "curve448utils.h"

#ifndef _BSD_SOURCE
#define _BSD_SOURCE 1
#endif

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include "portable_endian.h"

#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>

#if defined(__ARM_NEON__)
#include <arm_neon.h>
#elif defined(__SSE2__)
    #if !defined(__GNUC__) || __clang__ || __GNUC__ >= 5 || (__GNUC__==4 && __GNUC_MINOR__ >= 4)
        #include <immintrin.h>
    #else
        #include <emmintrin.h>
    #endif
#endif

#if (ARCH_WORD_BITS == 64)
    typedef uint64_t word_t, mask_t;
    typedef __uint128_t dword_t;
    typedef int32_t hsword_t;
    typedef int64_t sword_t;
    typedef __int128_t dsword_t;
#elif (ARCH_WORD_BITS == 32)
    typedef uint32_t word_t, mask_t;
    typedef uint64_t dword_t;
    typedef int16_t hsword_t;
    typedef int32_t sword_t;
    typedef int64_t dsword_t;
#else
    #error "For now, libdecaf only supports 32- and 64-bit architectures."
#endif
    
/* Scalar limbs are keyed off of the API word size instead of the arch word size. */
#if DECAF_WORD_BITS == 64
    #define SC_LIMB(x) (x##ull)
#elif DECAF_WORD_BITS == 32
    #define SC_LIMB(x) ((uint32_t)x##ull),(x##ull>>32)
#else
    #error "For now, libdecaf only supports 32- and 64-bit architectures."
#endif

#ifdef __ARM_NEON__
    typedef uint32x4_t vecmask_t;
#elif __clang__
    typedef uint64_t uint64x2_t __attribute__((ext_vector_type(2)));
    typedef int64_t  int64x2_t __attribute__((ext_vector_type(2)));
    typedef uint64_t uint64x4_t __attribute__((ext_vector_type(4)));
    typedef int64_t  int64x4_t __attribute__((ext_vector_type(4)));
    typedef uint32_t uint32x4_t __attribute__((ext_vector_type(4)));
    typedef int32_t  int32x4_t __attribute__((ext_vector_type(4)));
    typedef uint32_t uint32x2_t __attribute__((ext_vector_type(2)));
    typedef int32_t  int32x2_t __attribute__((ext_vector_type(2)));
    typedef uint32_t uint32x8_t __attribute__((ext_vector_type(8)));
    typedef int32_t  int32x8_t __attribute__((ext_vector_type(8)));
    typedef word_t vecmask_t __attribute__((ext_vector_type(4)));
#else /* GCC, hopefully? */
    typedef uint64_t uint64x2_t __attribute__((vector_size(16)));
    typedef int64_t  int64x2_t __attribute__((vector_size(16)));
    typedef uint64_t uint64x4_t __attribute__((vector_size(32)));
    typedef int64_t  int64x4_t __attribute__((vector_size(32)));
    typedef uint32_t uint32x4_t __attribute__((vector_size(16)));
    typedef int32_t  int32x4_t __attribute__((vector_size(16)));
    typedef uint32_t uint32x2_t __attribute__((vector_size(8)));
    typedef int32_t  int32x2_t __attribute__((vector_size(8)));
    typedef uint32_t uint32x8_t __attribute__((vector_size(32)));
    typedef int32_t  int32x8_t __attribute__((vector_size(32)));
    typedef word_t vecmask_t __attribute__((vector_size(32)));
#endif

#if __AVX2__
    #define VECTOR_ALIGNED __attribute__((aligned(32)))
    typedef uint32x8_t big_register_t;
    typedef uint64x4_t uint64xn_t;
    typedef uint32x8_t uint32xn_t;

    static DECAF_INLINE big_register_t
    br_set_to_mask(mask_t x) {
        uint32_t y = (uint32_t)x;
        big_register_t ret = {y,y,y,y,y,y,y,y};
        return ret;
    }
#elif __SSE2__
    #define VECTOR_ALIGNED __attribute__((aligned(16)))
    typedef uint32x4_t big_register_t;
    typedef uint64x2_t uint64xn_t;
    typedef uint32x4_t uint32xn_t;

    static DECAF_INLINE big_register_t
    br_set_to_mask(mask_t x) {
        uint32_t y = x;
        big_register_t ret = {y,y,y,y};
        return ret;
    }
#elif __ARM_NEON__
    #define VECTOR_ALIGNED __attribute__((aligned(16)))
    typedef uint32x4_t big_register_t;
    typedef uint64x2_t uint64xn_t;
    typedef uint32x4_t uint32xn_t;
    
    static DECAF_INLINE big_register_t
    br_set_to_mask(mask_t x) {
        return vdupq_n_u32(x);
    }
#elif _WIN64 || __amd64__ || __X86_64__ || __aarch64__
    #define VECTOR_ALIGNED __attribute__((aligned(8)))
    typedef uint64_t big_register_t, uint64xn_t;

    typedef uint32_t uint32xn_t;
    static DECAF_INLINE big_register_t
    br_set_to_mask(mask_t x) {
        return (big_register_t)x;
    }
#else
    #define VECTOR_ALIGNED __attribute__((aligned(4)))
    typedef uint64_t uint64xn_t;
    typedef uint32_t uint32xn_t;
    typedef uint32_t big_register_t;

    static DECAF_INLINE big_register_t
    br_set_to_mask(mask_t x) {
        return (big_register_t)x;
    }
#endif

typedef struct {
    uint64xn_t unaligned;
} __attribute__((packed)) unaligned_uint64xn_t;

typedef struct {
    uint32xn_t unaligned;
} __attribute__((packed)) unaligned_uint32xn_t;

#if __AVX2__
    static DECAF_INLINE big_register_t
    br_is_zero(big_register_t x) {
        return (big_register_t)(x == br_set_to_mask(0));
    }
#elif __SSE2__
    static DECAF_INLINE big_register_t
    br_is_zero(big_register_t x) {
        return (big_register_t)_mm_cmpeq_epi32((__m128i)x, _mm_setzero_si128());
        //return (big_register_t)(x == br_set_to_mask(0));
    }
#elif __ARM_NEON__
    static DECAF_INLINE big_register_t
    br_is_zero(big_register_t x) {
        return vceqq_u32(x,x^x);
    }
#else
    #define br_is_zero word_is_zero
#endif

/**
 * Really call memset, in a way that prevents the compiler from optimizing it out.
 * @param p The object to zeroize.
 * @param c The char to set it to (probably zero).
 * @param s The size of the object.
 */
#if defined(__DARWIN_C_LEVEL) || defined(__STDC_LIB_EXT1__)
#define HAS_MEMSET_S
#endif

#if !defined(__STDC_WANT_LIB_EXT1__) || __STDC_WANT_LIB_EXT1__ != 1
#define NEED_MEMSET_S_EXTERN
#endif

#ifdef HAS_MEMSET_S
    #ifdef NEED_MEMSET_S_EXTERN
        extern int memset_s(void *, size_t, int, size_t);
    #endif
    static DECAF_INLINE void
    really_memset(void *p, char c, size_t s) {
        memset_s(p, s, c, s);
    }
#else
    /* PERF: use words? */
    static DECAF_INLINE void
    really_memset(void *p, char c, size_t s) {
        volatile char *pv = (volatile char *)p;
        size_t i;
        for (i=0; i<s; i++) pv[i] = c;
    }
#endif

/**
 * Allocate memory which is sufficiently aligned to be used for the
 * largest vector on the system (for now that's a big_register_t).
 *
 * Man malloc says that it does this, but at least for AVX2 on MacOS X,
 * it's lying.
 *
 * @param size The size of the region to allocate.
 * @return A suitable pointer, which can be free'd with free(),
 * or NULL if no memory can be allocated.
 */
static DECAF_INLINE void *
malloc_vector(size_t size) {
    void *out = NULL;
    
    int ret = posix_memalign(&out, sizeof(big_register_t), size);
    
    if (ret) {
        return NULL;
    } else {
        return out;
    }
}

/* PERF: vectorize vs unroll */
#ifdef __clang__
#if 100*__clang_major__ + __clang_minor__ > 305
#define UNROLL _Pragma("clang loop unroll(full)")
#endif
#endif

#ifndef UNROLL
#define UNROLL
#endif

/* The plan on booleans:
 *
 * The external interface uses decaf_bool_t, but this might be a different
 * size than our particular arch's word_t (and thus mask_t).  Also, the caller
 * isn't guaranteed to pass it as nonzero.  So bool_to_mask converts word sizes
 * and checks nonzero.
 *
 * On the flip side, mask_t is always -1 or 0, but it might be a different size
 * than decaf_bool_t.
 *
 * On the third hand, we have success vs boolean types, but that's handled in
 * common.h: it converts between decaf_bool_t and decaf_error_t.
 */
static DECAF_INLINE decaf_bool_t mask_to_bool (mask_t m) {
    return (decaf_sword_t)(sword_t)m;
}

static DECAF_INLINE mask_t bool_to_mask (decaf_bool_t m) {
    /* On most arches this will be optimized to a simple cast. */
    mask_t ret = 0;
    unsigned int limit = sizeof(decaf_bool_t)/sizeof(mask_t);
    if (limit < 1) limit = 1;
    for (unsigned int i=0; i<limit; i++) {
        ret |= ~ word_is_zero(m >> (i*8*sizeof(word_t)));
    }
    return ret;
}

static DECAF_INLINE void ignore_result ( decaf_bool_t boo ) {
    (void)boo;
}

#endif /* __WORD_H__ */
