/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../testutil.h"
#include "tu_local.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/crypto.h>

static int mfail_fail_after = -1;
static int mfail_alloc_count = 0;
static int mfail_triggered = 0;
static int mfail_counting = 0;
static int mfail_do_skip_all = 0;
static int mfail_do_skip_slow = 0;
static int mfail_single_point = -1;
static int mfail_start_point = 0;
static int mfail_installed = 0;

static int should_fail(void)
{
    if (mfail_fail_after < 0 || !mfail_counting || mfail_triggered)
        return 0;
    if (mfail_alloc_count++ == mfail_fail_after) {
        mfail_triggered = 1;
        return 1;
    }
    return 0;
}

static void *mfail_malloc(size_t num, const char *file, int line)
{
    if (num == 0)
        return NULL;
    if (should_fail())
        return NULL;
    return malloc(num);
}

static void *mfail_realloc(void *addr, size_t num, const char *file, int line)
{
    if (addr == NULL)
        return mfail_malloc(num, file, line);
    if (num == 0) {
        free(addr);
        return NULL;
    }
    if (should_fail())
        return NULL;
    return realloc(addr, num);
}

static void mfail_free(void *addr, const char *file, int line)
{
    free(addr);
}

static int env_is_true(const char *name)
{
    const char *val = getenv(name);

    return val != NULL && *val != '\0' && strcmp(val, "0") != 0;
}

void mfail_install(void)
{
    if (env_is_true("OPENSSL_TEST_MFAIL_DISABLE"))
        return;
    if (!CRYPTO_set_mem_functions(mfail_malloc, mfail_realloc, mfail_free))
        return;
    mfail_installed = 1;
}

void mfail_start(void)
{
    mfail_alloc_count = 0;
    mfail_counting = 1;
}

void mfail_end(void)
{
    mfail_counting = 0;
}

static void mfail_arm(int fail_after)
{
    mfail_fail_after = fail_after;
    mfail_alloc_count = 0;
    mfail_triggered = 0;
    mfail_counting = 0;
}

static void mfail_disarm(void)
{
    mfail_fail_after = -1;
    mfail_alloc_count = 0;
    mfail_triggered = 0;
    mfail_counting = 0;
}

static double elapsed_secs(clock_t start)
{
    return (double)(clock() - start) / CLOCKS_PER_SEC;
}

void mfail_init(void)
{
    const char *env;

    mfail_do_skip_all = env_is_true("OPENSSL_TEST_MFAIL_SKIP_ALL");
    mfail_do_skip_slow = env_is_true("OPENSSL_TEST_MFAIL_SKIP_SLOW");

    env = getenv("OPENSSL_TEST_MFAIL_POINT");
    if (env != NULL && *env != '\0')
        mfail_single_point = atoi(env);

    env = getenv("OPENSSL_TEST_MFAIL_START");
    if (env != NULL && *env != '\0')
        mfail_start_point = atoi(env);
}

int mfail_should_skip(int slow)
{
    if (!mfail_installed)
        return 1;
    return mfail_do_skip_all || (slow && mfail_do_skip_slow);
}

int mfail_run_test(const char *test_case_name, int (*test_fn)(void))
{
    int alloc_point, ret = 1;
    clock_t start;

    start = clock();

    if (mfail_single_point >= 0) {
        int rv, triggered;

        ERR_clear_error();
        mfail_arm(mfail_single_point);
        rv = test_fn();
        triggered = mfail_triggered;
        mfail_disarm();

        if (!triggered) {
            TEST_info("mfail test '%s': point %d is beyond the last "
                      "allocation point, test %s",
                test_case_name, mfail_single_point,
                rv == 1 ? "succeeded" : "failed");
        } else if (!TEST_int_eq(rv, 0)) {
            TEST_error("mfail test '%s': allocation failure at point %d "
                       "not handled",
                test_case_name, mfail_single_point);
            ret = 0;
        }
    } else {
        for (alloc_point = mfail_start_point;; alloc_point++) {
            int rv, triggered;

            ERR_clear_error();
            mfail_arm(alloc_point);
            rv = test_fn();
            triggered = mfail_triggered;
            mfail_disarm();

            if (!triggered) {
                if (!TEST_int_eq(rv, 1)) {
                    TEST_error("mfail test '%s': no injection but test failed",
                        test_case_name);
                    ret = 0;
                }
                break;
            }

            if (!TEST_int_eq(rv, 0)) {
                TEST_error("mfail test '%s': allocation failure at point %d "
                           "not handled",
                    test_case_name, alloc_point);
                ret = 0;
            }
        }
        TEST_info("mfail test '%s': points %d..%d, %d iterations, %.6f seconds",
            test_case_name, mfail_start_point, alloc_point,
            alloc_point - mfail_start_point + 1, elapsed_secs(start));
    }

    return ret;
}
