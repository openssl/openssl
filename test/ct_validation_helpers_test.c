/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Tests for the constant-time validation helpers in constant_time.h:
 * - CONSTTIME_SECRET
 * - CONSTTIME_DECLASSIFY
 * - constant_time_declassify_u32()
 *
 * Most of the modes below check whether Valgrind flags code that is
 * deliberately NOT constant-time. The accompanying recipe asserts that the
 * harness flags it. Each such mode is a separate process because Valgrind's
 * verdict is delivered as a process exit code via Valgrind's --error-exitcode.
 *
 * The "identity" mode is different: It ensures constant_time_declassify_u32()
 * still exists and functions correctly when used OUTSIDE enable-ct-validation.
 * Thus this mode uses the ordinary test framework pass/fail signal
 * and does not require Valgrind.
 */

#include <string.h>

#include <openssl/crypto.h>

#include "internal/constant_time.h"
#include "internal/nelem.h"
#include "testutil.h"

#define SECRET_LEN 32

/*
 * Volatile sink for results computed by tests below.
 *
 * Must be volatile so that the compiler cannot delete the offending code as
 * dead, which would silently cause tests to check nothing and pass falsely.
 */
static volatile unsigned int sink;

static const unsigned char lut[16] = {
    3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3 /* arbitrary values */
};

static void fill_secret(unsigned char *secret)
{
    size_t i;

    for (i = 0; i < SECRET_LEN; i++)
        secret[i] = (unsigned char)(i * 7 + 1);
}

/*
 * "branch" mode: Ensure Valgrind flags a branch (a loop iteration count) on a
 * secret marked with CONSTTIME_SECRET.
 *
 * Valgrind should report:
 * "Conditional jump or move depends on uninitialised value(s)".
 */
static int test_secret_dependent_branch(void)
{
    unsigned char secret[SECRET_LEN];
    unsigned int i, n;

    fill_secret(secret);
    CONSTTIME_SECRET(secret, sizeof(secret));

    n = secret[0] & 0x0f;
    for (i = 0; i < n; i++)
        sink = i;

    CONSTTIME_DECLASSIFY(secret, sizeof(secret));
    return 1;
}

/*
 * "index" mode: Ensure Valgrind flags a lookup table index derived from a
 * secret marked with CONSTTIME_SECRET.
 *
 * Valgrind should report:
 * "Use of uninitialised value".
 */
static int test_secret_dependent_index(void)
{
    unsigned char secret[SECRET_LEN];

    fill_secret(secret);
    CONSTTIME_SECRET(secret, sizeof(secret));

    sink = lut[secret[0] & 0x0f];

    CONSTTIME_DECLASSIFY(secret, sizeof(secret));
    return 1;
}

/*
 * "control" mode: Ensure Valgrind does NOT flag a branch on a secret that has
 * been declassified by CONSTTIME_DECLASSIFY.
 */
static int test_constant_time_control(void)
{
    unsigned char secret[SECRET_LEN];
    unsigned int acc = 0;
    size_t i;

    fill_secret(secret);
    CONSTTIME_SECRET(secret, sizeof(secret));

    for (i = 0; i < sizeof(secret); i++)
        acc |= secret[i];

    CONSTTIME_DECLASSIFY(&acc, sizeof(acc));
    CONSTTIME_DECLASSIFY(secret, sizeof(secret));

    if (acc == 0)
        sink = 1;
    else
        sink = 2;

    return TEST_uint_eq(sink, 2);
}

/*
 * "mask" mode: Ensure Valgrind does NOT flag a branch on the result of
 * constant_time_declassify_u32().
 *
 * Uses the same calling pattern as constant_time_declassify_u32's current
 * unique caller:
 * - A constant_time_ge()/constant_time_lt() mask (0 or all-ones) computed from
 *   secret data is declassified and immediately branched on. The boolean
 *   outcome of a rejection-sampling check is safe to leak even though the data
 *   behind it is not.
 */
static int test_declassify_mask(void)
{
    unsigned char secret[SECRET_LEN];
    unsigned int mask;

    fill_secret(secret);
    CONSTTIME_SECRET(secret, sizeof(secret));

    mask = constant_time_ge(secret[0], 0x80);

    if (constant_time_declassify_u32(mask))
        sink = 1;
    else
        sink = 2;

    CONSTTIME_DECLASSIFY(secret, sizeof(secret));
    return 1;
}

/*
 * "identity" mode: Ensure constant_time_declassify_u32() returns its input
 * unmodified, independent of whether Valgrind or enable-ct-validation are
 * enabled.
 */
static int test_declassify_u32_identity(void)
{
    static const uint32_t values[] = { 0, 1, 0xdeadbeef, 0xffffffff };
    size_t i;
    int ret = 1;

    for (i = 0; i < OSSL_NELEM(values); i++)
        ret &= TEST_uint_eq(constant_time_declassify_u32(values[i]), values[i]);
    return ret;
}

OPT_TEST_DECLARE_USAGE("branch|index|control|mask|identity\n")

int setup_tests(void)
{
    const char *mode;

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(mode = test_get_argument(0)))
        return 0;

    if (strcmp(mode, "branch") == 0)
        ADD_TEST(test_secret_dependent_branch);
    else if (strcmp(mode, "index") == 0)
        ADD_TEST(test_secret_dependent_index);
    else if (strcmp(mode, "control") == 0)
        ADD_TEST(test_constant_time_control);
    else if (strcmp(mode, "mask") == 0)
        ADD_TEST(test_declassify_mask);
    else if (strcmp(mode, "identity") == 0)
        ADD_TEST(test_declassify_u32_identity);
    else {
        TEST_error("Unknown mode '%s'\n", mode);
        return 0;
    }

    return 1;
}
