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

static int test_ctx_size(void)
{
    int ret = 1;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *f = NULL;
    const void *token = NULL;
    size_t size = OSSL_FN_CTX_size(1, 2, 4096 / OSSL_FN_BITS);

    if (!TEST_size_t_ne(size, 0)
        || !TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL, size))) {
        ret = 0;
        goto end;
    }

    if (!TEST_ptr(token = OSSL_FN_CTX_start(ctx))) {
        ret = 0;
        goto end;
    }

    if (!TEST_ptr(f = OSSL_FN_CTX_get_bits(ctx, 2048))
        || !TEST_false(ossl_fn_is_dynamically_allocated(f))
        || !TEST_false(ossl_fn_is_securely_allocated(f))
        || !TEST_ptr(f = OSSL_FN_CTX_get_bits(ctx, 2048))
        || !TEST_ptr_null(f = OSSL_FN_CTX_get_bits(ctx, 2048)))
        ret = 0;

    if (!TEST_true(OSSL_FN_CTX_end(ctx, token)))
        ret = 0;

end:
    OSSL_FN_CTX_free(ctx);

    /*
     * Force each term of OSSL_FN_CTX_size() to overflow in turn,
     * keeping the others at a minimal valid context (1 frame, 1
     * number, 1 limb) so only the overflowing term is unrealistic.
     */
    if (!TEST_size_t_eq(OSSL_FN_CTX_size(SIZE_MAX, 1, 1), 0))
        ret = 0;
    if (!TEST_size_t_eq(OSSL_FN_CTX_size(1, SIZE_MAX, 1), 0))
        ret = 0;
    if (!TEST_size_t_eq(OSSL_FN_CTX_size(1, 1, SIZE_MAX), 0))
        ret = 0;
    /* A context must have at least one frame. */
    if (!TEST_size_t_eq(OSSL_FN_CTX_size(0, 1, 1), 0))
        ret = 0;
    /*
     * Numbers and limbs must both be present or both absent: a context
     * with one budget but not the other can never allocate a usable
     * number, since OSSL_FN_CTX_get_limbs() allocates the OSSL_FN header
     * and its limbs together.
     */
    if (!TEST_size_t_eq(OSSL_FN_CTX_size(1, 0, 1), 0))
        ret = 0;
    if (!TEST_size_t_eq(OSSL_FN_CTX_size(1, 1, 0), 0))
        ret = 0;
    if (!TEST_ptr_null(OSSL_FN_CTX_new_size(NULL, SIZE_MAX)))
        ret = 0;
    /* A size of 0 is the error return of OSSL_FN_CTX_size(). */
    if (!TEST_ptr_null(OSSL_FN_CTX_new_size(NULL, 0)))
        ret = 0;

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

static int test_secure_ctx_size(void)
{
    int ret = 1;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *f = NULL;
    const void *token = NULL;
    size_t size = OSSL_FN_CTX_size(1, 1, 2048 / OSSL_FN_BITS);

    if (!TEST_size_t_ne(size, 0)
        || !TEST_ptr(ctx = OSSL_FN_CTX_secure_new_size(NULL, size))) {
        ret = 0;
        goto end;
    }

    if (!TEST_ptr(token = OSSL_FN_CTX_start(ctx))) {
        ret = 0;
        goto end;
    }

    if (!TEST_ptr(f = OSSL_FN_CTX_get_bits(ctx, 2048))
        || !TEST_false(ossl_fn_is_dynamically_allocated(f))
        || !TEST_true(ossl_fn_is_securely_allocated(f))
        || !TEST_ptr_null(f = OSSL_FN_CTX_get_bits(ctx, 2048)))
        ret = 0;

    if (!TEST_true(OSSL_FN_CTX_end(ctx, token)))
        ret = 0;

end:
    OSSL_FN_CTX_free(ctx);

    if (!TEST_ptr_null(OSSL_FN_CTX_secure_new_size(NULL, SIZE_MAX)))
        ret = 0;
    /* A size of 0 is the error return of OSSL_FN_CTX_size(). */
    if (!TEST_ptr_null(OSSL_FN_CTX_secure_new_size(NULL, 0)))
        ret = 0;

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

/*
 * Test that OSSL_FN_CTX_free() cleanses the whole context allocation
 * before freeing it.  Custom memory hooks record the pointer and size of
 * each allocation, and check that the buffer handed back to free() has
 * been zeroed.
 */
static struct recorded_alloc_st {
    void *ptr;
    size_t size;
} recorded_allocs[8];
static size_t recorded_allocs_n = 0;
static int recorded_allocs_nonzero = 0;

static void record_alloc(void *ptr, size_t size)
{
    if (recorded_allocs_n < OSSL_NELEM(recorded_allocs)) {
        recorded_allocs[recorded_allocs_n].ptr = ptr;
        recorded_allocs[recorded_allocs_n].size = size;
        recorded_allocs_n++;
    }
}

static void check_free(void *ptr)
{
    for (size_t i = 0; i < recorded_allocs_n; i++) {
        if (recorded_allocs[i].ptr == ptr) {
            const unsigned char *p = recorded_allocs[i].ptr;

            for (size_t j = 0; j < recorded_allocs[i].size; j++)
                if (p[j] != 0)
                    recorded_allocs_nonzero = 1;
            recorded_allocs[i].ptr = NULL; /* only check each alloc once */
        }
    }
}

static void *hook_malloc(size_t num, const char *file, int line)
{
    void *ptr = malloc(num);

    if (ptr != NULL)
        record_alloc(ptr, num);
    return ptr;
}

static void *hook_realloc(void *addr, size_t num, const char *file, int line)
{
    void *ptr = realloc(addr, num);

    if (ptr != NULL && ptr != addr)
        record_alloc(ptr, num);
    return ptr;
}

static void hook_free(void *ptr, const char *file, int line)
{
    if (ptr != NULL)
        check_free(ptr);
    free(ptr);
}

static int test_ctx_free_clear_common(int secure)
{
    int ret = 0;
    OSSL_FN_CTX *ctx = NULL;
    size_t size = OSSL_FN_CTX_size(2, 4, 16);
    const void *token = NULL;

    if (!TEST_size_t_ne(size, 0))
        return 0;

    recorded_allocs_n = 0;
    recorded_allocs_nonzero = 0;
    memset(recorded_allocs, 0, sizeof(recorded_allocs));
    if (!CRYPTO_set_mem_functions(hook_malloc, hook_realloc, hook_free))
        return 0;

    if (secure)
        ctx = OSSL_FN_CTX_secure_new_size(NULL, size);
    else
        ctx = OSSL_FN_CTX_new_size(NULL, size);

    /* Allocate a number in the arena and fill it with a non-zero pattern */
    if (TEST_ptr(ctx)
        && TEST_ptr(token = OSSL_FN_CTX_start(ctx))) {
        OSSL_FN *fn = OSSL_FN_CTX_get_limbs(ctx, 4);

        if (TEST_ptr(fn)) {
            OSSL_FN_ULONG *u = (OSSL_FN_ULONG *)ossl_fn_get_words(fn);

            memset(u, 0xff, 4 * OSSL_FN_BYTES);
        }
        (void)OSSL_FN_CTX_end(ctx, token);
    }
    OSSL_FN_CTX_free(ctx);

    if (!CRYPTO_set_mem_functions(NULL, NULL, NULL))
        goto end;

    if (!TEST_int_eq(recorded_allocs_nonzero, 0))
        goto end;

    ret = 1;
end:
    return ret;
}

static int test_ctx_free_clear(void)
{
    int ret = 0;

    if (!TEST_true(CRYPTO_secure_malloc_init(4096, 32)))
        return 0;

    if (!test_ctx_free_clear_common(0)
        || !test_ctx_free_clear_common(1))
        goto end;

    ret = 1;
end:
    CRYPTO_secure_malloc_done();
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_struct);
    ADD_TEST(test_alloc);
    ADD_TEST(test_secure_alloc);
    ADD_TEST(test_ctx);
    ADD_TEST(test_ctx_size);
    ADD_TEST(test_secure_ctx);
    ADD_TEST(test_secure_ctx_size);
    ADD_TEST(test_ctx_peak_used);
    ADD_TEST(test_ctx_free_clear);

    return 1;
}
