/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <errno.h>
#include <limits.h>

#include <openssl/crypto.h>
#include <internal/cryptlib.h>
#include <internal/nelem.h>
#include "testutil.h"

struct strtoul_test_entry {
    char *input; /* the input string */
    int base; /* the base we are converting in */
    unsigned long expect_val; /* the expected value we should get */
    int expect_err; /* the expected error we expect to receive */
    size_t expect_endptr_offset; /* the expected endptr offset, +1 for NULL */
};

static struct strtoul_test_entry strtoul_tests[] = {
    /* pass on conv "0" to 0 */
    {
        "0", 0, 0, 1, 1 },
    /* pass on conv "12345" to 12345 */
    {
        "12345", 0, 12345, 1, 5 },
    /* pass on conv "0x12345" to 0x12345, base 16 */
    {
        "0x12345", 0, 0x12345, 1, 7 },
    /* pass on base 10 translation, endptr points to 'x' */
    {
        "0x12345", 10, 0, 1, 1 },
#if ULONG_MAX == 4294967295
    /* pass on ULONG_MAX translation */
    {
        "4294967295", 0, ULONG_MAX, 1, 10 },
#else
    { "18446744073709551615", 0, ULONG_MAX, 1, 20 },
#endif

    /* fail on negative input */
    {
        "-1", 0, 0, 0, 0 },
    /* fail on non-numerical input */
    {
        "abcd", 0, 0, 0, 0 },
    /* pass on decimal input */
    {
        "1.0", 0, 1, 1, 1 },
    /* Fail on decimal input without leading number */
    {
        ".1", 0, 0, 0, 0 }
};

static int test_strtoul(int idx)
{
    unsigned long val;
    char *endptr = NULL;
    int err;
    struct strtoul_test_entry *test = &strtoul_tests[idx];

    /*
     * For each test, convert the string to an unsigned long
     */
    err = OPENSSL_strtoul(test->input, &endptr, test->base, &val);

    /*
     * Check to ensure the error returned is expected
     */
    if (!TEST_int_eq(err, test->expect_err))
        return 0;
    /*
     * Confirm that the endptr points to where we expect
     */
    if (!TEST_ptr_eq(endptr, &test->input[test->expect_endptr_offset]))
        return 0;
    /*
     * And check that we received the proper translated value
     * Note, we only check the value if the conversion passed
     */
    if (test->expect_err == 1) {
        if (!TEST_ulong_eq(val, test->expect_val))
            return 0;
    }
    return 1;
}

struct strtol_test_entry {
    char *input; /* the input string */
    int base; /* the base we are converting in */
    long expect_val; /* the expected value we should get */
    int expect_err; /* the expected error we expect to receive */
    size_t expect_endptr_offset; /* expected endptr offset (index into input) */
};

static struct strtol_test_entry strtol_tests[] = {
    /* pass on conv "0" to 0 */
    {
        "0", 0, 0, 1, 1 },
    /* pass on conv "12345" to 12345 */
    {
        "12345", 0, 12345, 1, 5 },
    /* pass on conv "0x12345" to 0x12345, base 16 */
    {
        "0x12345", 0, 0x12345, 1, 7 },
    /* pass on base 10 translation, endptr points to 'x' */
    {
        "0x12345", 10, 0, 1, 1 },
    /* pass on conv " 123" to 123 (leading whitespace) */
    {
        " 123", 0, 123, 1, 4 },
    /* pass on conv "-1" to -1 (signed negative) */
    {
        "-1", 0, -1, 1, 2 },
    /* pass on conv "-12345" to -12345 */
    {
        "-12345", 0, -12345, 1, 6 },
    /* pass on conv " -1" to -1 (whitespace + negative) */
    {
        " -1", 0, -1, 1, 3 },
#if LONG_MAX == 2147483647
    /* pass on LONG_MAX translation */
    {
        "2147483647", 0, LONG_MAX, 1, 10 },
    /* pass on LONG_MIN translation */
    {
        "-2147483648", 0, LONG_MIN, 1, 11 },
#else
    /* pass on LONG_MAX translation */
    {
        "9223372036854775807", 0, LONG_MAX, 1, 19 },
    /* pass on LONG_MIN translation */
    {
        "-9223372036854775808", 0, LONG_MIN, 1, 20 },
#endif
    /* fail on non-numerical input */
    {
        "abcd", 0, 0, 0, 0 },
    /* pass on decimal input */
    {
        "1.0", 0, 1, 1, 1 },
    /* Fail on decimal input without leading number */
    {
        ".1", 0, 0, 0, 0 }
};

static int test_strtol(int idx)
{
    long val;
    char *endptr = NULL;
    int err;
    struct strtol_test_entry *test = &strtol_tests[idx];

    err = ossl_strtol(test->input, &endptr, test->base, &val);

    if (!TEST_int_eq(err, test->expect_err))
        return 0;
    if (!TEST_ptr_eq(endptr, &test->input[test->expect_endptr_offset]))
        return 0;
    if (test->expect_err == 1) {
        if (!TEST_long_eq(val, test->expect_val))
            return 0;
    }
    return 1;
}

/* Overflow/underflow must fail and leave errno set to ERANGE */
static int test_strtol_overflow(void)
{
    long l;
    int ret, saved_errno;

    ret = ossl_strtol("99999999999999999999999", NULL, 0, &l);
    saved_errno = errno;
    if (!TEST_int_eq(ret, 0) || !TEST_int_eq(saved_errno, ERANGE))
        return 0;

    ret = ossl_strtol("-99999999999999999999999", NULL, 0, &l);
    saved_errno = errno;
    if (!TEST_int_eq(ret, 0) || !TEST_int_eq(saved_errno, ERANGE))
        return 0;

    return 1;
}

/*
 * A NULL endptr requires the whole string to be consumed.  Pre-setting errno
 * also verifies the internal errno = 0 reset.
 */
static int test_strtol_null_endptr(void)
{
    long l;
    int ret;

    /* full consumption succeeds */
    ret = ossl_strtol("123", NULL, 0, &l);
    if (!TEST_int_eq(ret, 1) || !TEST_long_eq(l, 123))
        return 0;

    /* leading whitespace + negative, full consumption succeeds */
    ret = ossl_strtol("  -456", NULL, 0, &l);
    if (!TEST_int_eq(ret, 1) || !TEST_long_eq(l, -456))
        return 0;

    /* trailing garbage with NULL endptr must fail */
    ret = ossl_strtol("123abc", NULL, 0, &l);
    if (!TEST_int_eq(ret, 0))
        return 0;

    /* pre-set errno; the internal reset must let a clean parse succeed */
    errno = ERANGE;
    ret = ossl_strtol("789", NULL, 0, &l);
    if (!TEST_int_eq(ret, 1) || !TEST_long_eq(l, 789) || !TEST_int_eq(errno, 0))
        return 0;

    return 1;
}

/* NULL result / NULL str short-circuit to failure */
static int test_strtol_null_args(void)
{
    long l;
    int i;

    /* ossl_strtol: result == NULL */
    if (!TEST_int_eq(ossl_strtol("123", NULL, 0, NULL), 0))
        return 0;
    /* ossl_strtol: str == NULL */
    if (!TEST_int_eq(ossl_strtol(NULL, NULL, 0, &l), 0))
        return 0;
    /* ossl_strtoint: result == NULL (short-circuits before ossl_strtol) */
    if (!TEST_int_eq(ossl_strtoint("123", NULL, 0, NULL), 0))
        return 0;
    /* ossl_strtoint: str == NULL (rejected by ossl_strtol) */
    if (!TEST_int_eq(ossl_strtoint(NULL, NULL, 0, &i), 0))
        return 0;
    return 1;
}

static struct strtol_test_entry strtoint_tests[] = {
    /* pass on conv "0" to 0 */
    {
        "0", 0, 0, 1, 1 },
    /* pass on conv "123" to 123 */
    {
        "123", 0, 123, 1, 3 },
    /* pass on conv "-456" to -456 (signed, within int range) */
    {
        "-456", 0, -456, 1, 4 },
#if INT_MAX == 2147483647
    /* pass on INT_MAX translation */
    {
        "2147483647", 0, INT_MAX, 1, 10 },
    /* pass on INT_MIN translation */
    {
        "-2147483648", 0, INT_MIN, 1, 11 },
#endif
    /* fail on non-numerical input */
    {
        "abcd", 0, 0, 0, 0 },
    /* pass on decimal input */
    {
        "1.0", 0, 1, 1, 1 },
    /* Fail on decimal input without leading number */
    {
        ".1", 0, 0, 0, 0 }
};

/*
 * Driver named test_strtoint_arr so it does not clash with the test_strtoint()
 * symbol under test.
 */
static int test_strtoint_arr(int idx)
{
    int val;
    char *endptr = NULL;
    int err;
    struct strtol_test_entry *test = &strtoint_tests[idx];

    err = ossl_strtoint(test->input, &endptr, test->base, &val);

    if (!TEST_int_eq(err, test->expect_err))
        return 0;
    if (!TEST_ptr_eq(endptr, &test->input[test->expect_endptr_offset]))
        return 0;
    if (test->expect_err == 1) {
        if (!TEST_int_eq(val, (int)test->expect_val))
            return 0;
    }
    return 1;
}

/* Values outside [INT_MIN, INT_MAX] and long overflow all fail */
static int test_strtoint_overflow(void)
{
    int i;

    /* INT_MAX + 1 (narrowing failure, or long overflow on ILP32) */
    if (!TEST_int_eq(ossl_strtoint("2147483648", NULL, 10, &i), 0))
        return 0;
    /* INT_MIN - 1 (narrowing failure, or long underflow on ILP32) */
    if (!TEST_int_eq(ossl_strtoint("-2147483649", NULL, 10, &i), 0))
        return 0;
    /* long overflow: ossl_strtol fails */
    if (!TEST_int_eq(ossl_strtoint("99999999999999999999999", NULL, 10, &i), 0))
        return 0;
    return 1;
}

struct strtoint_util_entry {
    char *input; /* the input string */
    int expect_val; /* the expected value we should get */
    int expect_err; /* the expected error we expect to receive */
};

static struct strtoint_util_entry util_strtoint_tests[] = {
    /* pass on conv "0" to 0 */
    {
        "0", 0, 1 },
    /* pass on conv "123" to 123 */
    {
        "123", 123, 1 },
    /* pass on conv " 45" to 45 (leading whitespace) */
    {
        " 45", 45, 1 },
#if INT_MAX == 2147483647
    /* pass on INT_MAX translation */
    {
        "2147483647", INT_MAX, 1 },
#endif
    /* fail on negative input */
    {
        "-1", 0, 0 },
    /* fail on value > INT_MAX */
    {
        "2147483648", 0, 0 },
    /* fail on unsigned overflow */
    {
        "99999999999999999999999", 0, 0 },
    /* fail on non-numerical input */
    {
        "abcd", 0, 0 },
    /* fail on trailing garbage (NULL-endptr full-consumption rule) */
    {
        "12abc", 0, 0 },
    /* fail on empty input */
    {
        "", 0, 0 }
};

static int test_util_strtoint(int idx)
{
    int val;
    int err;
    struct strtoint_util_entry *test = &util_strtoint_tests[idx];

    err = test_strtoint(test->input, &val);

    if (!TEST_int_eq(err, test->expect_err))
        return 0;
    if (test->expect_err == 1) {
        if (!TEST_int_eq(val, test->expect_val))
            return 0;
    }
    return 1;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_strtoul, OSSL_NELEM(strtoul_tests));
    ADD_ALL_TESTS(test_strtol, OSSL_NELEM(strtol_tests));
    ADD_ALL_TESTS(test_strtoint_arr, OSSL_NELEM(strtoint_tests));
    ADD_ALL_TESTS(test_util_strtoint, OSSL_NELEM(util_strtoint_tests));
    ADD_TEST(test_strtol_overflow);
    ADD_TEST(test_strtol_null_endptr);
    ADD_TEST(test_strtol_null_args);
    ADD_TEST(test_strtoint_overflow);
    return 1;
}
