/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <openssl/crypto.h>
#include "crypto/fn.h"
#include "fn_local.h"

/*
 * An OSSL_FN_CTX is a large pre-allocated chunk of memory that can be used
 * to quickly allocate OSSL_FN instances.  The organization of memory is as
 * a fairly typical arena, where OSSL_FN instances are "stacked" one after
 * the other.
 *
 * However, there is also the concept of frames, which are arenas within an
 * arena.  This allows easily passing an OSSL_FN_CTX to a function, and for
 * that function to allocate such a frame for itself, and easily deallocate
 * it when it's done.
 */

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
     * The arena itself.
     */
    size_t msize;                /* Size of the arena, in bytes */
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
     * Every time OSSL_FN_CTX_get() is called, the current value of
     * |free_memory| is returned, and it's updated by incrementing it
     * by the number of bytes given by OSSL_FN_CTX_get().
     * The available number of bytes is limited by what's left in the arena.
     */
    unsigned char *free_memory;  /* Pointer to the free area of the frame */
    size_t msize;                /* Size of the frame, in bytes */
    unsigned char memory[];
};

static size_t calculate_arena_size(size_t max_n_frames, size_t max_n_numbers, size_t max_n_limbs)
{
    return max_n_frames * sizeof(struct ossl_fn_ctx_frame_st)
        + max_n_numbers * sizeof(OSSL_FN)
        + max_n_limbs * OSSL_FN_BYTES;
}

OSSL_FN_CTX *OSSL_FN_CTX_new(OSSL_LIB_CTX *libctx, size_t max_n_frames,
                             size_t max_n_numbers, size_t max_n_limbs)
{
    size_t arena_size = calculate_arena_size(max_n_frames, max_n_numbers, max_n_limbs);
    OSSL_FN_CTX *ctx = OPENSSL_zalloc(sizeof(OSSL_FN_CTX) + arena_size);

    if (ctx != NULL)
        ctx->msize = arena_size;

    return ctx;
}

OSSL_FN_CTX *OSSL_FN_CTX_secure_new(OSSL_LIB_CTX *libctx, size_t max_n_frames,
                                    size_t max_n_numbers, size_t max_n_limbs)
{
    size_t arena_size = calculate_arena_size(max_n_frames, max_n_numbers, max_n_limbs);
    OSSL_FN_CTX *ctx = OPENSSL_secure_zalloc(sizeof(OSSL_FN_CTX) + arena_size);

    if (ctx != NULL) {
        ctx->msize = arena_size;
        ctx->is_securely_allocated = 1;
    }

    return ctx;
}

void OSSL_FN_CTX_free(OSSL_FN_CTX *ctx)
{
    if (ctx == NULL)
        return;

    assert(ctx->last_frame == NULL);

    if (ctx->is_securely_allocated)
        OPENSSL_secure_free(ctx);
    else
        OPENSSL_free(ctx);
}

int OSSL_FN_CTX_start(OSSL_FN_CTX *ctx)
{
    if (!ossl_assert(ctx != NULL))
        return 0;

    struct ossl_fn_ctx_frame_st *last_frame = ctx->last_frame;
    size_t used = (last_frame == NULL) ? 0 : last_frame->free_memory - ctx->memory;

    if (ctx->msize - used < sizeof(struct ossl_fn_ctx_frame_st))
        return 0;

    if (ctx->last_frame == NULL)
        ctx->last_frame = (struct ossl_fn_ctx_frame_st *)ctx->memory;
    else
        ctx->last_frame = (struct ossl_fn_ctx_frame_st *)last_frame->free_memory;

    struct ossl_fn_ctx_frame_st *frame = ctx->last_frame;
    frame->arena = ctx;
    frame->previous_frame = last_frame;
    frame->free_memory = frame->memory;
    frame->msize = ctx->msize - used - sizeof(*frame);

    return 1;
}

int OSSL_FN_CTX_end(OSSL_FN_CTX *ctx)
{
    if (!ossl_assert(ctx != NULL))
        return 0;

    struct ossl_fn_ctx_frame_st *last_frame = ctx->last_frame;

    ctx->last_frame = last_frame->previous_frame;

    return 1;
}

OSSL_FN *OSSL_FN_CTX_get_limbs(OSSL_FN_CTX *ctx, size_t limbs)
{
    if (!ossl_assert(ctx != NULL))
        return NULL;

    struct ossl_fn_ctx_frame_st *frame = ctx->last_frame;

    if (!ossl_assert(frame != NULL))
        return NULL;

    size_t totalsize = ossl_fn_totalsize(limbs);
    size_t used = frame->free_memory - frame->memory;
    if (totalsize == 0 || frame->msize - used < totalsize)
       return NULL;

    OSSL_FN *fn = (OSSL_FN *)frame->free_memory;
    frame->free_memory += totalsize;

    memset(fn, 0, totalsize);
    fn->dsize = (int)limbs;
    fn->is_securely_allocated = ctx->is_securely_allocated;
    fn->is_dynamically_allocated = 1;

    return fn;
}

OSSL_FN *OSSL_FN_CTX_get_bytes(OSSL_FN_CTX *ctx, size_t bytes)
{
    return OSSL_FN_CTX_get_limbs(ctx, ossl_fn_bytes_to_limbs(bytes));
}

OSSL_FN *OSSL_FN_CTX_get_bits(OSSL_FN_CTX *ctx, size_t bits)
{
    return OSSL_FN_CTX_get_bytes(ctx, ossl_fn_bits_to_bytes(bits));
}
