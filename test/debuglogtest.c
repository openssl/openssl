/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>

#include "testutil.h"

static const char* file1 = "file1";
static int line1 = 1;
static int result1 = 1;

static void logging_callback1(const char* file, int line, int severity, const char* buf)
{
    if (!TEST_str_eq(file, file1) ||
        !TEST_int_eq(line, line1) ||
        !TEST_int_eq(severity, DBG_VERBOSE) ||
        !TEST_str_eq(buf, "this is my log with 1 parameter")) {
        
        result1 = 0;
    }
}

/* Tests that log callback is called and passes the correct parameters */
static int debug_log_print1(void)
{
    CRYPTO_set_logging_callback(logging_callback1);

    debug_log(file1, line1, DBG_VERBOSE, "this is %s log with %d parameter", "my", 1);

    return result1;
}

/* Tests get/set */
static int debug_log_print2(void)
{
    CRYPTO_set_logging_callback(logging_callback1);

    if ( TEST_ptr_eq((void*)CRYPTO_get_logging_callback(), (void*)logging_callback1)) {
        return 1;
    }

    return 0;
}

static int result2 = 1;
static void logging_callback2(const char* file, int line, int severity, const char* buf)
{
    result2 = 0;
}

/* Tests no callback set */
static int debug_log_print3(void)
{
    result2 = 1;
    CRYPTO_set_logging_callback(logging_callback2);
    debug_log(NULL, 0, 0, "");

    if ( !TEST_int_eq(result2, 0)) {
        return 0;
    }

    result2 = 1;
    CRYPTO_set_logging_callback(NULL);
    debug_log(NULL, 0, 0, "");

    if ( !TEST_int_eq(result2, 1)) {
        return 0;
    }

    return 1;
}

/* Tests bad input */
static int debug_log_print4(void)
{
    result2 = 1;
    CRYPTO_set_logging_callback(logging_callback2);
    debug_log(NULL, 0, 0, NULL);

    if ( !TEST_int_eq(result2, 1)) {
        return 0;
    }

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(debug_log_print1);
    ADD_TEST(debug_log_print2);
    ADD_TEST(debug_log_print3);
    ADD_TEST(debug_log_print4);
    return 1;
}
