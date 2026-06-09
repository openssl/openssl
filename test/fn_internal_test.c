/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file Internal tests of OSSL_FN
 *
 * This tests OSSL_FN internals only, i.e. anything that requires including
 * ../crypto/fn/fn_local.h, such as introspection.
 */

#include "crypto/fn.h"
#include "crypto/fn_intern.h"
#include "fn_local.h"
#include "testutil.h"

static int test_struct(void)
{
    TEST_note("OSSL_FN struct is %zu bytes\n", sizeof(OSSL_FN));
    TEST_note("OSSL_FN 'd' array starts at offset %zu\n", offsetof(OSSL_FN, d));

    /*
     * Note: The working theory for the moment is that the 'd' array *must*
     * align with the end of the OSSL_FN struct.
     * If it turns out that this isn't the case, we can choose to run
     * TEST_size_t_eq() for display purposes, but ignore its result and
     * return 1.
     */
    return TEST_size_t_eq(sizeof(OSSL_FN), offsetof(OSSL_FN, d));
}

static int test_alloc(void)
{
    int ret = 1;
    OSSL_FN *f = NULL;
    const OSSL_FN_ULONG *u = NULL;

    /*
     * OSSL_FN_new_bits() calls OSSL_FN_new_bytes(), which calls
     * OSSL_FN_new_limbs(), so we're exercising all three in one go.
     *
     * The curious size formula is there to check that the number of bits that
     * is passed in gets properly rounded up to the number of limbs they fit
     * into.
     * This formula aims for two limbs (each of which is at least 32 bits),
     * shaving off 17 bits for demonstration purposes.
     */
    if (!TEST_ptr(f = OSSL_FN_new_bits(sizeof(OSSL_FN_ULONG) * 16 - 17))
        || !TEST_true(ossl_fn_is_dynamically_allocated(f))
        || !TEST_false(ossl_fn_is_securely_allocated(f))
        || !TEST_size_t_eq(ossl_fn_get_dsize(f), 2)
        || !TEST_ptr(u = ossl_fn_get_words(f))
        || !TEST_size_t_eq(u[0], 0)
        || !TEST_size_t_eq(u[1], 0))
        ret = 0;
    OSSL_FN_free(f);

    return ret;
}

static int test_secure_alloc(void)
{
    int ret = 1;
    OSSL_FN *f = NULL;
    const OSSL_FN_ULONG *u = NULL;

    /*
     * OSSL_FN_secure_new_bits() calls OSSL_FN_secure_new_bytes(), which calls
     * OSSL_FN_secure_new_limbs(), so we're exercising all three in one go.
     *
     * The curious size formula is there to check that the number of bits that
     * is passed in gets properly rounded up to the number of limbs they fit
     * into.
     * This formula aims for two limbs (each of which is at least 32 bits),
     * shaving off 17 bits for demonstration purposes.
     */
    if (!TEST_ptr(f = OSSL_FN_secure_new_bits(sizeof(OSSL_FN_ULONG) * 16 - 17))
        || !TEST_true(ossl_fn_is_dynamically_allocated(f))
        || !TEST_true(ossl_fn_is_securely_allocated(f))
        || !TEST_size_t_eq(ossl_fn_get_dsize(f), 2)
        || !TEST_ptr(u = ossl_fn_get_words(f))
        || !TEST_size_t_eq(u[0], 0)
        || !TEST_size_t_eq(u[1], 0))
        ret = 0;
    OSSL_FN_free(f);

    return ret;
}

static int test_ctx(void)
{
    int ret = 1;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *f = NULL;
    const void *token = NULL;

    /*
     * Make a CTX that is likely to contain two 2048-bit or one 4096-bit OSSL_FN
     * and one frame (let's overestimate its size to 128 bytes).
     * Note that OSSL_FN_CTX_new() takes a maximum number of limbs in the last
     * parameter, so we must ensure that we get that number right.
     */
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 1, 2, 4096 / OSSL_FN_BITS))) {
        ret = 0;
        /* It's pointless to try more tests after this failure */
        goto end;
    }

    /* Check that we can get 1 2048-bit OSSL_FN instance, and check its metadata */
    if (!TEST_ptr(token = OSSL_FN_CTX_start(ctx))) {
        ret = 0;
        /* It's pointless to try more tests after this failure */
        goto end;
    }
    if (!TEST_ptr(f = OSSL_FN_CTX_get_bits(ctx, 2048))
        || !TEST_false(ossl_fn_is_dynamically_allocated(f))
        || !TEST_false(ossl_fn_is_securely_allocated(f)))
        ret = 0;
    if (!TEST_true(OSSL_FN_CTX_end(ctx, token))) {
        ret = 0;
        /* It's pointless to try more tests after this failure */
        goto end;
    }

    /* Check that we can get 2 2048-bit OSSL_FN instances, but not 3 */
    if (!TEST_ptr(token = OSSL_FN_CTX_start(ctx))) {
        ret = 0;
        /* It's pointless to try more tests after this failure */
        goto end;
    }
    if (!TEST_ptr(f = OSSL_FN_CTX_get_bits(ctx, 2048))
        || !TEST_ptr(f = OSSL_FN_CTX_get_bits(ctx, 2048))
        || !TEST_ptr_null(f = OSSL_FN_CTX_get_bits(ctx, 2048)))
        ret = 0;
    if (!TEST_true(OSSL_FN_CTX_end(ctx, token))) {
        ret = 0;
        /* It's pointless to try more tests after this failure */
        goto end;
    }

    /* Check that we can get 1 4096-bit OSSL_FN instance, but not 2 */
    if (!TEST_ptr(token = OSSL_FN_CTX_start(ctx))) {
        ret = 0;
        /* It's pointless to try more tests after this failure */
        goto end;
    }
    if (!TEST_ptr(f = OSSL_FN_CTX_get_bits(ctx, 4096))
        || !TEST_ptr_null(f = OSSL_FN_CTX_get_bits(ctx, 2048)))
        ret = 0;
    if (!TEST_true(OSSL_FN_CTX_end(ctx, token))) {
        ret = 0;
        /* It's pointless to try more tests after this failure */
        goto end;
    }

end:
    OSSL_FN_CTX_free(ctx);

    return ret;
}

static int test_secure_ctx(void)
{
    int ret = 1;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *f = NULL;
    const void *token = NULL;

    /*
     * Make a CTX that is likely to contain two 2048-bit OSSL_FN and one frame
     * (let's overestimate its size to 128 bytes).
     * Note that OSSL_FN_CTX_new() takes a maximum number of limbs in the last
     * parameter, so we must ensure that we get that number right.
     */
    if (!TEST_ptr(ctx = OSSL_FN_CTX_secure_new(NULL, 1, 2, 2048 / OSSL_FN_BITS))) {
        ret = 0;
        /* It's pointless to try more tests after this failure */
        goto end;
    }

    /* Check that we can get 1 2048-bit OSSL_FN instance, and check its metadata */
    if (!TEST_ptr(token = OSSL_FN_CTX_start(ctx))) {
        ret = 0;
        /* It's pointless to try more tests after this failure */
        goto end;
    }
    if (!TEST_ptr(f = OSSL_FN_CTX_get_bits(ctx, 2048))
        || !TEST_false(ossl_fn_is_dynamically_allocated(f))
        || !TEST_true(ossl_fn_is_securely_allocated(f)))
        ret = 0;
    if (!TEST_true(OSSL_FN_CTX_end(ctx, token))) {
        ret = 0;
        /* It's pointless to try more tests after this failure */
        goto end;
    }

end:
    OSSL_FN_CTX_free(ctx);

    return ret;
}

static int test_ctx_peak_used(void)
{
    int ret = 1;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *f = NULL;
    const void *token1 = NULL;
    const void *token2 = NULL;
    size_t frames, numbers, limbs;
    size_t limbs_2048 = 2048 / 8 / OSSL_FN_BYTES;
    size_t limbs_4096 = 4096 / 8 / OSSL_FN_BYTES;

    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 2, 4, 256))) {
        ret = 0;
        goto end;
    }

    /*
     * Fresh context.
     */
    OSSL_FN_CTX_peak_usage(ctx, &frames, &numbers, &limbs);
    if (!TEST_size_t_eq(frames, 0)
        || !TEST_size_t_eq(numbers, 0)
        || !TEST_size_t_eq(limbs, 0))
        ret = 0;

    /*
     * NULL context: all out parameters set to 0.
     */
    OSSL_FN_CTX_peak_usage(NULL, &frames, &numbers, &limbs);
    if (!TEST_size_t_eq(frames, 0)
        || !TEST_size_t_eq(numbers, 0)
        || !TEST_size_t_eq(limbs, 0))
        ret = 0;

    /*
     * NULL out parameters are tolerated.
     */
    OSSL_FN_CTX_peak_usage(ctx, NULL, NULL, NULL);

    /*
     * Start frame 1.
     */
    if (!TEST_ptr(token1 = OSSL_FN_CTX_start(ctx))) {
        ret = 0;
        goto end;
    }
    OSSL_FN_CTX_peak_usage(ctx, &frames, &numbers, &limbs);
    if (!TEST_size_t_eq(frames, 1)
        || !TEST_size_t_eq(numbers, 0)
        || !TEST_size_t_eq(limbs, 0))
        ret = 0;

    /*
     * Allocate one number in frame 1.
     */
    if (!TEST_ptr(f = OSSL_FN_CTX_get_bits(ctx, 2048)))
        ret = 0;
    OSSL_FN_CTX_peak_usage(ctx, &frames, &numbers, &limbs);
    if (!TEST_size_t_eq(frames, 1)
        || !TEST_size_t_eq(numbers, 1)
        || !TEST_size_t_eq(limbs, limbs_2048))
        ret = 0;

    /*
     * Start frame 2 (nested inside frame 1).
     */
    if (!TEST_ptr(token2 = OSSL_FN_CTX_start(ctx))) {
        ret = 0;
        goto end;
    }
    OSSL_FN_CTX_peak_usage(ctx, &frames, &numbers, &limbs);
    if (!TEST_size_t_eq(frames, 2)
        || !TEST_size_t_eq(numbers, 1)
        || !TEST_size_t_eq(limbs, limbs_2048))
        ret = 0;

    /*
     * Allocate one number in frame 2.
     */
    if (!TEST_ptr(f = OSSL_FN_CTX_get_bits(ctx, 4096)))
        ret = 0;
    OSSL_FN_CTX_peak_usage(ctx, &frames, &numbers, &limbs);
    if (!TEST_size_t_eq(frames, 2)
        || !TEST_size_t_eq(numbers, 2)
        || !TEST_size_t_eq(limbs, limbs_2048 + limbs_4096))
        ret = 0;

    /*
     * Allocate a second number in frame 2.
     */
    if (!TEST_ptr(f = OSSL_FN_CTX_get_bits(ctx, 2048)))
        ret = 0;
    OSSL_FN_CTX_peak_usage(ctx, &frames, &numbers, &limbs);
    if (!TEST_size_t_eq(frames, 2)
        || !TEST_size_t_eq(numbers, 3)
        || !TEST_size_t_eq(limbs, limbs_2048 + limbs_4096 + limbs_2048))
        ret = 0;

    if (!TEST_true(OSSL_FN_CTX_end(ctx, token2))) {
        ret = 0;
        goto end;
    }

    /*
     * After ending frame 2: peaks must not decrease.
     */
    OSSL_FN_CTX_peak_usage(ctx, &frames, &numbers, &limbs);
    if (!TEST_size_t_eq(frames, 2)
        || !TEST_size_t_eq(numbers, 3)
        || !TEST_size_t_eq(limbs, limbs_2048 + limbs_4096 + limbs_2048))
        ret = 0;

    if (!TEST_true(OSSL_FN_CTX_end(ctx, token1))) {
        ret = 0;
        goto end;
    }

    /*
     * After ending frame 1: peaks still preserved.
     */
    OSSL_FN_CTX_peak_usage(ctx, &frames, &numbers, &limbs);
    if (!TEST_size_t_eq(frames, 2)
        || !TEST_size_t_eq(numbers, 3)
        || !TEST_size_t_eq(limbs, limbs_2048 + limbs_4096 + limbs_2048))
        ret = 0;

end:
    OSSL_FN_CTX_free(ctx);

    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_struct);
    ADD_TEST(test_alloc);
    ADD_TEST(test_secure_alloc);
    ADD_TEST(test_ctx);
    ADD_TEST(test_secure_ctx);
    ADD_TEST(test_ctx_peak_used);

    return 1;
}
