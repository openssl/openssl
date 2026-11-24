/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_FXN_LOCAL_H
#define OSSL_CRYPTO_FXN_LOCAL_H

#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <openssl/opensslconf.h>
#include <openssl/e_os2.h>
#include "internal/common.h"
#include "crypto/fxn.h"
#include "crypto/fxn_intern.h"

#if OSSL_FXN_BYTES == 4
/* 32-bit systems */
#define OSSL_FXN_ULONG_C(n) UINT32_C(n)
#define OSSL_FXN_MASK UINT32_MAX
#elif OSSL_FXN_BYTES == 8
#define OSSL_FXN_ULONG_C(n) UINT64_C(n)
#define OSSL_FXN_MASK UINT64_MAX
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif

#define OSSL_FXN_HIGH_BIT_MASK (OSSL_FXN_ULONG_C(1) << (OSSL_FXN_BITS - 1))
#define OSSL_FXN_LOW_HALF_MASK ((OSSL_FXN_ULONG_C(1) << (OSSL_FXN_BITS / 2)) - 1)
#define OSSL_FXN_HIGH_HALF_MASK (OSSL_FXN_LOW_HALF_MASK << (OSSL_FXN_BITS / 2))

static ossl_inline size_t ossl_fxn_totalsize(size_t limbs)
{
    /*
     * TODO(FIXNUM): Since the number of limbs is currently represented
     * as an 'int' in OSSL_FXN, we must ensure that the desired size isn't
     * larger than can be represented.
     */
    if (ossl_unlikely(limbs >= INT_MAX))
        return 0;

    /*
     *    sizeof(OSSL_FXN) + limbs * sizeof(OSSL_FXN_ULONG) > SIZE_MAX
     * => limbs * sizeof(OSSL_FXN_ULONG) > SIZE_MAX - sizeof(OSSL_FXN)
     * => limbs > (SIZE_MAX - sizeof(OSSL_FXN)) / sizeof(OSSL_FXN_ULONG)
     */
    if (ossl_unlikely(limbs > (SIZE_MAX - sizeof(OSSL_FXN)) / sizeof(OSSL_FXN_ULONG)))
        return 0;
    return sizeof(OSSL_FXN) + limbs * sizeof(OSSL_FXN_ULONG);
}

static ossl_inline size_t ossl_fxn_bytes_to_limbs(size_t size)
{
    return (size + sizeof(OSSL_FXN_ULONG) - 1) / sizeof(OSSL_FXN_ULONG);
}

static ossl_inline size_t ossl_fxn_bits_to_bytes(size_t size)
{
    return (size + 7) / 8;
}

/*
 * Internal functions to support BIGNUM's bn_expand_internal, BN_copy, and
 * similar.
 * The caller must ensure that src and dest are not NULL.
 * With ossl_fxn_copy_internal, bn_words may be given -1 to signify that the
 * number of BN_ULONG should be found in src.
 */
static ossl_inline OSSL_FXN *ossl_fxn_copy_internal_limbs(OSSL_FXN *dest,
    const OSSL_FXN_ULONG *src,
    int limbs)
{
    if (ossl_unlikely(dest->dsize < limbs))
        return NULL;
    memcpy(dest->d, src, limbs * sizeof(dest->d[0]));
    memset(dest->d + limbs, 0, (dest->dsize - limbs) * sizeof(dest->d[0]));
    return dest;
}

static ossl_inline OSSL_FXN *ossl_fxn_copy_internal(OSSL_FXN *dest,
    const OSSL_FXN *src,
    int bn_words)
{
    int words = bn_words < 0 ? src->dsize : bn_words;

    if (ossl_fxn_copy_internal_limbs(dest, src->d, words) == NULL)
        return NULL;
    return dest;
}

/* OSSL_FXN_CTX internals */

struct ossl_fxn_ctx_st {
    /*
     * Pointer to the last OSSL_FXN_CTX_start() location (a simple pointer into
     * the memory area).  See the struct ossl_fxn_ctx_frame_st definition below
     * for details.
     */
    struct ossl_fxn_ctx_frame_st *last_frame;

    /*
     * Flags
     */
    unsigned int is_securely_allocated : 1;

    /*
     * Library context this arena was created with, carried so that operations
     * needing randomness (e.g. the EC ladder's coordinate blinding) can draw
     * from the caller's context rather than the global default.
     */
    OSSL_LIB_CTX *libctx;

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

struct ossl_fxn_ctx_frame_st {
    /*
     * Pointer back to the whole arena where the frame is located,
     * for |last_frame| bookkeeping.
     */
    struct ossl_fxn_ctx_st *arena;
    /*
     * Pointer to the previous frame in the arena, allowing OSSL_FXN_CTX_end()
     * to do its job.
     */
    struct ossl_fxn_ctx_frame_st *previous_frame;
    /*
     * Tracking for peak usage instrumentation.  These count the OSSL_FXN
     * instances and total limbs allocated within this frame.
     */
    size_t n_numbers;
    size_t n_limbs;
    /*
     * Every time OSSL_FXN_CTX_get() is called, the current value of
     * |free_memory| is returned, and it's updated by incrementing it
     * by the number of bytes given by OSSL_FXN_CTX_get().
     * The available number of bytes is limited by what's left in the arena.
     */
    unsigned char *free_memory; /* Pointer to the free area of the frame */
    size_t msize; /* Size of the frame, in bytes */
    unsigned char memory[];
};

/* end OSSL_FXN_CTX internals */

/* OSSL_FXN_MONT_ CTX internals (used for Montgomery multiplication) */
struct ossl_fxn_mont_ctx_st {
    const OSSL_FXN *N; /* The modulus */
    const OSSL_FXN *RR; /* used to convert to Montgomery form,
                          possibly zero-padded */
    OSSL_FXN_ULONG n0[2]; /* least significant word(s) of Ni */
    int ri; /* number of bits in R */
    unsigned int is_securely_allocated : 1; /* Flag: alloced securely */
    OSSL_FXN_ULONG memory[];
};
#endif
