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
#include "internal/safe_math.h"
#include "crypto/fn.h"
#include "fn_local.h"

OSSL_SAFE_MATH_ADDU(size_t, size_t, OSSL_SAFE_MATH_MAXU(size_t))
OSSL_SAFE_MATH_MULU(size_t, size_t, OSSL_SAFE_MATH_MAXU(size_t))

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

size_t OSSL_FN_CTX_size(size_t max_n_frames, size_t max_n_numbers,
    size_t max_n_limbs)
{
    int err = 0;
    size_t frames, numbers, limbs, total;

    frames = safe_mul_size_t(max_n_frames,
        sizeof(struct ossl_fn_ctx_frame_st), &err);
    numbers = safe_mul_size_t(max_n_numbers, sizeof(OSSL_FN), &err);
    limbs = safe_mul_size_t(max_n_limbs, OSSL_FN_BYTES, &err);
    total = safe_add_size_t(frames, numbers, &err);
    total = safe_add_size_t(total, limbs, &err);

    return err == 0 ? total : 0;
}

OSSL_FN_CTX *OSSL_FN_CTX_new(OSSL_LIB_CTX *libctx, size_t max_n_frames,
    size_t max_n_numbers, size_t max_n_limbs)
{
    return OSSL_FN_CTX_new_size(libctx,
        OSSL_FN_CTX_size(max_n_frames, max_n_numbers, max_n_limbs));
}

OSSL_FN_CTX *OSSL_FN_CTX_new_size(OSSL_LIB_CTX *libctx, size_t size)
{
    size_t total_size;
    OSSL_FN_CTX *ctx;

    int err = 0;

    total_size = safe_add_size_t(sizeof(*ctx), size, &err);
    if (err != 0)
        return NULL;

    ctx = OPENSSL_zalloc(total_size);

    if (ctx != NULL)
        ctx->msize = size;

    return ctx;
}

OSSL_FN_CTX *OSSL_FN_CTX_secure_new(OSSL_LIB_CTX *libctx, size_t max_n_frames,
    size_t max_n_numbers, size_t max_n_limbs)
{
    return OSSL_FN_CTX_secure_new_size(libctx,
        OSSL_FN_CTX_size(max_n_frames, max_n_numbers, max_n_limbs));
}

OSSL_FN_CTX *OSSL_FN_CTX_secure_new_size(OSSL_LIB_CTX *libctx, size_t size)
{
    size_t total_size;
    OSSL_FN_CTX *ctx;

    int err = 0;

    total_size = safe_add_size_t(sizeof(*ctx), size, &err);
    if (err != 0)
        return NULL;

    ctx = OPENSSL_secure_zalloc(total_size);

    if (ctx != NULL) {
        ctx->msize = size;
        ctx->is_securely_allocated = 1;
    }

    return ctx;
}

void OSSL_FN_CTX_peak_usage(const OSSL_FN_CTX *ctx, size_t *peak_n_frames,
    size_t *peak_n_numbers, size_t *peak_n_limbs)
{
    if (ctx == NULL) {
        if (peak_n_frames != NULL)
            *peak_n_frames = 0;
        if (peak_n_numbers != NULL)
            *peak_n_numbers = 0;
        if (peak_n_limbs != NULL)
            *peak_n_limbs = 0;
        return;
    }
    if (peak_n_frames != NULL)
        *peak_n_frames = ctx->peak_n_frames;
    if (peak_n_numbers != NULL)
        *peak_n_numbers = ctx->peak_n_numbers;
    if (peak_n_limbs != NULL)
        *peak_n_limbs = ctx->peak_n_limbs;
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

const void *OSSL_FN_CTX_start(OSSL_FN_CTX *ctx)
{
    if (!ossl_assert(ctx != NULL))
        return NULL;

    struct ossl_fn_ctx_frame_st *last_frame = ctx->last_frame;
    size_t used = (last_frame == NULL) ? 0 : last_frame->free_memory - ctx->memory;

    if (ctx->msize - used < sizeof(struct ossl_fn_ctx_frame_st))
        return NULL;

    if (ctx->last_frame == NULL)
        ctx->last_frame = (struct ossl_fn_ctx_frame_st *)ctx->memory;
    else
        ctx->last_frame = (struct ossl_fn_ctx_frame_st *)last_frame->free_memory;

    struct ossl_fn_ctx_frame_st *frame = ctx->last_frame;
    frame->arena = ctx;
    frame->previous_frame = last_frame;
    frame->free_memory = frame->memory;
    frame->msize = ctx->msize - used - sizeof(*frame);
    frame->n_numbers = 0;
    frame->n_limbs = 0;

    ctx->n_frames++;
    if (ctx->n_frames > ctx->peak_n_frames)
        ctx->peak_n_frames = ctx->n_frames;

    return ctx->last_frame;
}

int OSSL_FN_CTX_end(OSSL_FN_CTX *ctx, const void *token)
{
    if (!ossl_assert(ctx != NULL) || !ossl_assert(ctx->last_frame != NULL))
        return 0;

    struct ossl_fn_ctx_frame_st *last_frame = ctx->last_frame;

    if (last_frame != token)
        return 0;

    ctx->n_numbers -= last_frame->n_numbers;
    ctx->n_limbs -= last_frame->n_limbs;
    ctx->n_frames--;
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
    frame->n_numbers++;
    frame->n_limbs += limbs;

    ctx->n_numbers++;
    ctx->n_limbs += limbs;
    if (ctx->n_numbers > ctx->peak_n_numbers)
        ctx->peak_n_numbers = ctx->n_numbers;
    if (ctx->n_limbs > ctx->peak_n_limbs)
        ctx->peak_n_limbs = ctx->n_limbs;

    memset(fn, 0, totalsize);
    fn->dsize = (int)limbs;
    fn->is_securely_allocated = ctx->is_securely_allocated;

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
