/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>

#include "testutil.h"

static int callback_count;

static int list_cb(const char *elem, int len, void *arg)
{
    (void)elem;
    (void)len;
    (void)arg;

    callback_count++;
    return 1;
}

static int count_and_stop_cb(const char *elem, int len, void *arg)
{
    (void)list_cb(elem, len, arg);
    return 0;
}

static const char *expected[] = { "one", "two" };

static int check_list_cb(const char *elem, int len, void *arg)
{
    int *idx = arg;
    size_t expected_len;

    if (!TEST_int_lt(*idx, (int)OSSL_NELEM(expected)))
        return 0;

    expected_len = strlen(expected[*idx]);
    if (!TEST_ptr(elem)
        || !TEST_int_eq(len, (int)expected_len)
        || !TEST_mem_eq(elem, expected_len, expected[*idx], expected_len))
        return 0;

    (*idx)++;
    return 1;
}

static int test_invalid_separator(int sep)
{
    unsigned long err;
    int ret = 0;

    ERR_clear_error();
    callback_count = 0;
    if (!TEST_false(CONF_parse_list("entry", sep, 0, count_and_stop_cb, NULL))
        || !TEST_int_eq(callback_count, 0))
        goto end;

    err = ERR_get_error();
    if (!TEST_int_eq(ERR_GET_LIB(err), ERR_LIB_CONF)
        || !TEST_int_eq(ERR_GET_REASON(err), ERR_R_PASSED_INVALID_ARGUMENT)
        || !TEST_ulong_eq(ERR_get_error(), 0))
        goto end;

    ret = 1;
end:
    ERR_clear_error();
    return ret;
}

static int test_valid_separator(void)
{
    int idx = 0;

    ERR_clear_error();

    return TEST_true(CONF_parse_list("one,two", ',', 0, check_list_cb, &idx))
        && TEST_int_eq(idx, (int)OSSL_NELEM(expected))
        && TEST_ulong_eq(ERR_get_error(), 0);
}

static int test_nul_separator(void)
{
    int ret = test_invalid_separator('\0');

#if UCHAR_MAX < INT_MAX
    ret &= test_invalid_separator(UCHAR_MAX + 1);
    ret &= test_invalid_separator(-(UCHAR_MAX + 1));
#endif
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_valid_separator);
    ADD_TEST(test_nul_separator);
    return 1;
}
