/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include "internal/err.h"
#include "testutil.h"

/* Text longer than the room ossl_err_add_error_fmt() allocates up front. */
#define LONG_TEXT                                                   \
    "0123456789012345678901234567890123456789012345678901234567890" \
    "123456789012345678901234567890123456789"

static const char *appended(void)
{
    const char *data = NULL;

    ERR_peek_last_error_data(&data, NULL);
    return data;
}

/* An error carrying no data takes the formatted text as its data. */
static int test_add_to_error_without_data(void)
{
    int ok;

    ERR_clear_error();
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
    ossl_err_add_error_fmt("host=%s", "example.com");
    ok = TEST_str_eq(appended(), "host=example.com");
    ERR_clear_error();
    return ok;
}

/* An error already carrying data has the text appended to it. */
static int test_add_to_error_with_data(void)
{
    int ok;

    ERR_clear_error();
    ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR, "code=%d", 404);
    ossl_err_add_error_fmt(", reason=%s", "gone");
    ok = TEST_str_eq(appended(), "code=404, reason=gone");
    ERR_clear_error();
    return ok;
}

/* Repeated calls accumulate rather than replace. */
static int test_appends_accumulate(void)
{
    int ok;

    ERR_clear_error();
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
    ossl_err_add_error_fmt("one");
    ossl_err_add_error_fmt(" %s", "two");
    ossl_err_add_error_fmt(" %d", 3);
    ok = TEST_str_eq(appended(), "one two 3");
    ERR_clear_error();
    return ok;
}

/* Conversions other than %s are formatted as printf(3) would. */
static int test_conversions(void)
{
    int ok;

    ERR_clear_error();
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
    ossl_err_add_error_fmt("%s=%d/%lu/%02x", "v", -7, 8UL, 255);
    ok = TEST_str_eq(appended(), "v=-7/8/ff");
    ERR_clear_error();
    return ok;
}

/* Text too long for the initial allocation is not truncated. */
static int test_text_longer_than_initial_room(void)
{
    int ok;

    ERR_clear_error();
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
    ossl_err_add_error_fmt("%s", LONG_TEXT);
    ok = TEST_str_eq(appended(), LONG_TEXT)
        && TEST_size_t_eq(strlen(appended()), strlen(LONG_TEXT));
    ERR_clear_error();
    return ok;
}

/* Repeated growth of one error's data. */
static int test_repeated_growth(void)
{
    char expected[1024];
    size_t pos = 0;
    int i, ok;

    ERR_clear_error();
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
    for (i = 0; i < 50; i++) {
        ossl_err_add_error_fmt("%d,", i);
        pos += (size_t)snprintf(expected + pos, sizeof(expected) - pos,
            "%d,", i);
    }
    ok = TEST_str_eq(appended(), expected);
    ERR_clear_error();
    return ok;
}

/* Appending nothing leaves the existing data alone. */
static int test_empty_append(void)
{
    int ok;

    ERR_clear_error();
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
    ossl_err_add_error_fmt("kept");
    ossl_err_add_error_fmt("%s", "");
    ok = TEST_str_eq(appended(), "kept");
    ERR_clear_error();
    return ok;
}

/* Appending with nothing on the queue neither crashes nor raises. */
static int test_add_with_empty_queue(void)
{
    int ok;

    ERR_clear_error();
    ossl_err_add_error_fmt("ignored=%d", 1);
    ok = TEST_ulong_eq(ERR_peek_error(), 0);
    ERR_clear_error();
    return ok;
}

int setup_tests(void)
{
    ADD_TEST(test_add_to_error_without_data);
    ADD_TEST(test_add_to_error_with_data);
    ADD_TEST(test_appends_accumulate);
    ADD_TEST(test_conversions);
    ADD_TEST(test_text_longer_than_initial_room);
    ADD_TEST(test_repeated_growth);
    ADD_TEST(test_empty_append);
    ADD_TEST(test_add_with_empty_queue);
    return 1;
}
