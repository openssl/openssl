/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdarg.h>
#include <string.h>
#include <openssl/crypto.h>
#include "testutil.h"

/* Helper: call OPENSSL_vasprintf via a wrapper to exercise the va_list path. */
static int vasprintf_wrapper(char **str, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = OPENSSL_vasprintf(str, format, args);
    va_end(args);
    return ret;
}

/* Format short enough to fit in the initial buffer (64 bytes). */
static int test_asprintf_short(void)
{
    char *result = NULL;
    int n;
    int ok;

    n = OPENSSL_asprintf(&result, "answer=%d", 42);
    ok = TEST_int_eq(n, (int)strlen("answer=42"))
        && TEST_ptr(result)
        && TEST_str_eq(result, "answer=42");
    OPENSSL_free(result);
    return ok;
}

/* Format that exceeds the initial 64-byte buffer to exercise the grow path. */
static int test_asprintf_grows(void)
{
    static const char lumberjack[] = "I'm a lumberjack, and I'm okay\n"
                                     "I sleep all night and I work all day";
    char *result = NULL;
    int n;
    int ok;

    n = OPENSSL_asprintf(&result, "%s", lumberjack);
    ok = TEST_int_eq(n, (int)(sizeof(lumberjack) - 1))
        && TEST_ptr(result)
        && TEST_str_eq(result, lumberjack);
    OPENSSL_free(result);
    return ok;
}

/* OPENSSL_vasprintf exercised through a small wrapper. */
static int test_vasprintf(void)
{
    char *result = NULL;
    int n;
    int ok;

    n = vasprintf_wrapper(&result, "x=%d y=%s", 7, "hello");
    ok = TEST_int_eq(n, (int)strlen("x=7 y=hello"))
        && TEST_ptr(result)
        && TEST_str_eq(result, "x=7 y=hello");
    OPENSSL_free(result);
    return ok;
}

/* Empty format string yields an empty buffer (but not NULL). */
static int test_asprintf_empty(void)
{
    char *result = NULL;
    int n;
    int ok;

    n = OPENSSL_asprintf(&result, "%s", "");
    ok = TEST_int_eq(n, 0)
        && TEST_ptr(result)
        && TEST_int_eq(result[0], '\0');
    OPENSSL_free(result);
    return ok;
}

int setup_tests(void)
{
    ADD_TEST(test_asprintf_short);
    ADD_TEST(test_asprintf_grows);
    ADD_TEST(test_vasprintf);
    ADD_TEST(test_asprintf_empty);
    return 1;
}
