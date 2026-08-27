/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_FN_LOCAL_H
#define OSSL_CRYPTO_FN_LOCAL_H

#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <openssl/opensslconf.h>
#include <openssl/e_os2.h>
#include "internal/common.h"
#include "internal/safe_math.h"
#include "crypto/fn.h"
#include "crypto/fn_intern.h"

#if OSSL_FN_BYTES == 4
/* 32-bit systems */
#define OSSL_FN_ULONG_C(n) UINT32_C(n)
#define OSSL_FN_MASK UINT32_MAX
#elif OSSL_FN_BYTES == 8
#define OSSL_FN_ULONG_C(n) UINT64_C(n)
#define OSSL_FN_MASK UINT64_MAX
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif

#define OSSL_FN_BITS (OSSL_FN_BYTES * 8)
#define OSSL_FN_HIGH_BIT_MASK (OSSL_FN_ULONG_C(1) << (OSSL_FN_BITS - 1))
#define OSSL_FN_LOW_HALF_MASK ((OSSL_FN_ULONG_C(1) << (OSSL_FN_BITS / 2)) - 1)
#define OSSL_FN_HIGH_HALF_MASK (OSSL_FN_LOW_HALF_MASK << (OSSL_FN_BITS / 2))

/* maximum precomputation table size for *variable* sliding windows */
#define TABLE_SIZE 32

/*
 * Sliding-window size selection: a function of the exponent bit count (a
 * public magnitude), capped at 6, so TABLE_SIZE == 1 << 5 always suffices.
 */
#define OSSL_FN_WINDOW_BITS_FOR_EXPONENT_SIZE(b) \
    ((b) > 671 ? 6 : (b) > 239 ? 5               \
            : (b) > 79         ? 4               \
            : (b) > 23         ? 3               \
                               : 1)

/*
 * Safe-accumulate arena size helpers, shared across OSSL_FN operation
 * modules.  ossl_fn_ctx_add_size() returns 0 on overflow; ossl_fn_ctx_max_size()
 * returns the larger of its two operands (often used to pick among
 * sequential frame budgets).
 */
static ossl_inline size_t ossl_fn_ctx_add_size(size_t a, size_t b)
{
    if (ossl_unlikely(a > OSSL_SAFE_MATH_MAXU(size_t) - b))
        return 0;
    return a + b;
}

static ossl_inline size_t ossl_fn_ctx_max_size(size_t a, size_t b)
{
    return a > b ? a : b;
}

struct ossl_fn_st {
    /* Flag: alloced with OSSL_FN_new() or  OSSL_FN_secure_new() */
    unsigned int is_dynamically_allocated : 1;
    /* Flag: alloced with OSSL_FN_secure_new() */
    unsigned int is_securely_allocated : 1;

    /*
     * The d array, with its size in number of OSSL_FN_ULONG.
     * This stores the number itself.
     *
     * Note: |dsize| is an int, because it turns out that some lower level
     * (possibly assembler) functions expect that type (especially, that
     * type size).
     * This deviates from the design in doc/designs/fixed-size-large-numbers.md
     */
    int dsize;
    OSSL_FN_ULONG d[];
};

static ossl_inline size_t ossl_fn_totalsize(size_t limbs)
{
    /*
     * TODO(FIXNUM): Since the number of limbs is currently represented
     * as an 'int' in OSSL_FN, we must ensure that the desired size isn't
     * larger than can be represented.
     */
    if (ossl_unlikely(limbs >= INT_MAX))
        return 0;

    /*
     *    sizeof(OSSL_FN) + limbs * sizeof(OSSL_FN_ULONG) > SIZE_MAX
     * => limbs * sizeof(OSSL_FN_ULONG) > SIZE_MAX - sizeof(OSSL_FN)
     * => limbs > (SIZE_MAX - sizeof(OSSL_FN)) / sizeof(OSSL_FN_ULONG)
     */
    if (ossl_unlikely(limbs > (SIZE_MAX - sizeof(OSSL_FN)) / sizeof(OSSL_FN_ULONG)))
        return 0;
    return sizeof(OSSL_FN) + limbs * sizeof(OSSL_FN_ULONG);
}

static ossl_inline size_t ossl_fn_bytes_to_limbs(size_t size)
{
    return (size + sizeof(OSSL_FN_ULONG) - 1) / sizeof(OSSL_FN_ULONG);
}

static ossl_inline size_t ossl_fn_bits_to_bytes(size_t size)
{
    return (size + 7) / 8;
}

/*
 * Internal functions to support BIGNUM's bn_expand_internal, BN_copy, and
 * similar.
 * The caller must ensure that src and dest are not NULL.
 * With ossl_fn_copy_internal, bn_words may be given -1 to signify that the
 * number of BN_ULONG should be found in src.
 */
static ossl_inline OSSL_FN *ossl_fn_copy_internal_limbs(OSSL_FN *dest,
    const OSSL_FN_ULONG *src,
    int limbs)
{
    if (ossl_unlikely(dest->dsize < limbs))
        return NULL;
    memcpy(dest->d, src, limbs * sizeof(dest->d[0]));
    memset(dest->d + limbs, 0, (dest->dsize - limbs) * sizeof(dest->d[0]));
    return dest;
}

static ossl_inline OSSL_FN *ossl_fn_copy_internal(OSSL_FN *dest,
    const OSSL_FN *src,
    int bn_words)
{
    int words = bn_words < 0 ? src->dsize : bn_words;

    if (ossl_fn_copy_internal_limbs(dest, src->d, words) == NULL)
        return NULL;
    return dest;
}

/* OSSL_FN_CTX internals */

struct ossl_fn_ctx_st {
    /*
     * Pointer to the last OSSL_FN_CTX_start() location (a simple pointer into
     * the memory area).  See the struct ossl_fn_ctx_frame_st definition below
     * for details.
     */
    struct ossl_fn_ctx_frame_st *last_frame;

    /*
     * Flags
     */
    unsigned int is_securely_allocated : 1;

    /*
     * Current and peak usage tracking, by allocation components.
     * The |n_*| fields hold the currently active counts; the |peak_n_*|
     * fields hold the maximum each count has ever reached simultaneously.
     * This allows callers to determine suitable arena parameters for a
     * given workload without precise up-front prediction.
     */
    size_t n_frames;
    size_t n_numbers;
    size_t n_limbs;
    size_t peak_n_frames;
    size_t peak_n_numbers;
    size_t peak_n_limbs;

    /*
     * The arena itself.
     */
    size_t msize; /* Size of the arena, in bytes */
    unsigned char memory[];
};

struct ossl_fn_ctx_frame_st {
    /*
     * Pointer back to the whole arena where the frame is located,
     * for |last_frame| bookkeeping.
     */
    struct ossl_fn_ctx_st *arena;
    /*
     * Pointer to the previous frame in the arena, allowing OSSL_FN_CTX_end()
     * to do its job.
     */
    struct ossl_fn_ctx_frame_st *previous_frame;
    /*
     * Tracking for peak usage instrumentation.  These count the OSSL_FN
     * instances and total limbs allocated within this frame.
     */
    size_t n_numbers;
    size_t n_limbs;
    /*
     * Every time OSSL_FN_CTX_get() is called, the current value of
     * |free_memory| is returned, and it's updated by incrementing it
     * by the number of bytes given by OSSL_FN_CTX_get().
     * The available number of bytes is limited by what's left in the arena.
     */
    unsigned char *free_memory; /* Pointer to the free area of the frame */
    size_t msize; /* Size of the frame, in bytes */
    unsigned char memory[];
};

/* end OSSL_FN_CTX internals */

/* OSSL_FN_MONT_ CTX internals (used for Montgomery multiplication) */
struct ossl_fn_mont_ctx_st {
    const OSSL_FN *N; /* The modulus */
    const OSSL_FN *RR; /* used to convert to Montgomery form,
                          possibly zero-padded */
    OSSL_FN_ULONG n0[2]; /* least significant word(s) of Ni */
    int ri; /* number of bits in R */
    unsigned int is_securely_allocated : 1; /* Flag: alloced securely */
    OSSL_FN_ULONG memory[];
};
#endif
