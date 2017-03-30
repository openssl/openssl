/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Copyright (c) 2017 Oracle and/or its affiliates.  All rights reserved.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "e_os.h"
#include "test_main.h"
#include "testutil.h"

#define C(l, b, t)                                      \
    if ((t) != b) {                                     \
        fprintf(stderr, "FATAL : %s != %d\n", #t, b);   \
        goto l;                                         \
    }

static int test_int(void)
{
    C(err, 1, TEST_int_eq(1, 1));
    C(err, 0, TEST_int_eq(1, -1));
    C(err, 1, TEST_int_ne(1, 2));
    C(err, 0, TEST_int_ne(3, 3));
    C(err, 1, TEST_int_lt(4, 9));
    C(err, 0, TEST_int_lt(9, 4));
    C(err, 1, TEST_int_le(4, 9));
    C(err, 1, TEST_int_le(5, 5));
    C(err, 0, TEST_int_le(9, 4));
    C(err, 1, TEST_int_gt(8, 5));
    C(err, 0, TEST_int_gt(5, 8));
    C(err, 1, TEST_int_ge(8, 5));
    C(err, 1, TEST_int_ge(6, 6));
    C(err, 0, TEST_int_ge(5, 8));
    return 1;

err:
    return 0;
}

static int test_uint(void)
{
    C(err, 1, TEST_uint_eq(3u, 3u));
    C(err, 0, TEST_uint_eq(3u, 5u));
    C(err, 1, TEST_uint_ne(4u, 2u));
    C(err, 0, TEST_uint_ne(6u, 6u));
    C(err, 1, TEST_uint_lt(5u, 9u));
    C(err, 0, TEST_uint_lt(9u, 5u));
    C(err, 1, TEST_uint_le(5u, 9u));
    C(err, 1, TEST_uint_le(7u, 7u));
    C(err, 0, TEST_uint_le(9u, 5u));
    C(err, 1, TEST_uint_gt(11u, 1u));
    C(err, 0, TEST_uint_gt(1u, 11u));
    C(err, 1, TEST_uint_ge(11u, 1u));
    C(err, 1, TEST_uint_ge(6u, 6u));
    C(err, 0, TEST_uint_ge(1u, 11u));
    return 1;

err:
    return 0;
}

static int test_char(void)
{
    C(err, 1, TEST_char_eq('a', 'a'));
    C(err, 0, TEST_char_eq('a', 'A'));
    C(err, 1, TEST_char_ne('a', 'c'));
    C(err, 0, TEST_char_ne('e', 'e'));
    C(err, 1, TEST_char_lt('i', 'x'));
    C(err, 0, TEST_char_lt('x', 'i'));
    C(err, 1, TEST_char_le('i', 'x'));
    C(err, 1, TEST_char_le('n', 'n'));
    C(err, 0, TEST_char_le('x', 'i'));
    C(err, 1, TEST_char_gt('w', 'n'));
    C(err, 0, TEST_char_gt('n', 'w'));
    C(err, 1, TEST_char_ge('w', 'n'));
    C(err, 1, TEST_char_ge('p', 'p'));
    C(err, 0, TEST_char_ge('n', 'w'));
    return 1;

err:
    return 0;
}

static int test_uchar(void)
{
    C(err, 1, TEST_uchar_eq(49, 49));
    C(err, 0, TEST_uchar_eq(49, 60));
    C(err, 1, TEST_uchar_ne(50, 2));
    C(err, 0, TEST_uchar_ne(66, 66));
    C(err, 1, TEST_uchar_lt(60, 80));
    C(err, 0, TEST_uchar_lt(80, 60));
    C(err, 1, TEST_uchar_le(60, 80));
    C(err, 1, TEST_uchar_le(78, 78));
    C(err, 0, TEST_uchar_le(80, 60));
    C(err, 1, TEST_uchar_gt(88, 37));
    C(err, 0, TEST_uchar_gt(37, 88));
    C(err, 1, TEST_uchar_ge(88, 37));
    C(err, 1, TEST_uchar_ge(66, 66));
    C(err, 0, TEST_uchar_ge(37, 88));
    return 1;

err:
    return 0;
}

static int test_long(void)
{
    C(err, 1, TEST_long_eq(123l, 123l));
    C(err, 0, TEST_long_eq(123l, -123l));
    C(err, 1, TEST_long_ne(123l, 500l));
    C(err, 0, TEST_long_ne(1000l, 1000l));
    C(err, 1, TEST_long_lt(-8923l, 102934563l));
    C(err, 0, TEST_long_lt(102934563l, -8923l));
    C(err, 1, TEST_long_le(-8923l, 102934563l));
    C(err, 1, TEST_long_le(12345l, 12345l));
    C(err, 0, TEST_long_le(102934563l, -8923l));
    C(err, 1, TEST_long_gt(84325677l, 12345l));
    C(err, 0, TEST_long_gt(12345l, 84325677l));
    C(err, 1, TEST_long_ge(84325677l, 12345l));
    C(err, 1, TEST_long_ge(465869l, 465869l));
    C(err, 0, TEST_long_ge(12345l, 84325677l));
    return 1;

err:
    return 0;
}

static int test_ulong(void)
{
    C(err, 1, TEST_ulong_eq(919ul, 919ul));
    C(err, 0, TEST_ulong_eq(919ul, 10234ul));
    C(err, 1, TEST_ulong_ne(8190ul, 66ul));
    C(err, 0, TEST_ulong_ne(10555ul, 10555ul));
    C(err, 1, TEST_ulong_lt(10234ul, 1000000ul));
    C(err, 0, TEST_ulong_lt(1000000ul, 10234ul));
    C(err, 1, TEST_ulong_le(10234ul, 1000000ul));
    C(err, 1, TEST_ulong_le(100000ul, 100000ul));
    C(err, 0, TEST_ulong_le(1000000ul, 10234ul));
    C(err, 1, TEST_ulong_gt(100000000ul, 22ul));
    C(err, 0, TEST_ulong_gt(22ul, 100000000ul));
    C(err, 1, TEST_ulong_ge(100000000ul, 22ul));
    C(err, 1, TEST_ulong_ge(10555ul, 10555ul));
    C(err, 0, TEST_ulong_ge(22ul, 100000000ul));
    return 1;

err:
    return 0;
}

static int test_size_t(void)
{
    C(err, 1, TEST_int_eq((size_t)10, (size_t)10));
    C(err, 0, TEST_int_eq((size_t)10, (size_t)12));
    C(err, 1, TEST_int_ne((size_t)10, (size_t)12));
    C(err, 0, TEST_int_ne((size_t)24, (size_t)24));
    C(err, 1, TEST_int_lt((size_t)30, (size_t)88));
    C(err, 0, TEST_int_lt((size_t)88, (size_t)30));
    C(err, 1, TEST_int_le((size_t)30, (size_t)88));
    C(err, 1, TEST_int_le((size_t)33, (size_t)33));
    C(err, 0, TEST_int_le((size_t)88, (size_t)30));
    C(err, 1, TEST_int_gt((size_t)52, (size_t)33));
    C(err, 0, TEST_int_gt((size_t)33, (size_t)52));
    C(err, 1, TEST_int_ge((size_t)52, (size_t)33));
    C(err, 1, TEST_int_ge((size_t)38, (size_t)38));
    C(err, 0, TEST_int_ge((size_t)33, (size_t)52));
    return 1;

err:
    return 0;
}

static int test_pointer(void)
{
    int x = 0;
    char y = 1;

    C(err, 1, TEST_ptr(&y));
    C(err, 0, TEST_ptr(NULL));
    C(err, 0, TEST_ptr_null(&y));
    C(err, 1, TEST_ptr_null(NULL));
    C(err, 1, TEST_ptr_eq(NULL, NULL));
    C(err, 0, TEST_ptr_eq(NULL, &y));
    C(err, 0, TEST_ptr_eq(&y, NULL));
    C(err, 0, TEST_ptr_eq(&y, &x));
    C(err, 1, TEST_ptr_eq(&x, &x));
    C(err, 0, TEST_ptr_ne(NULL, NULL));
    C(err, 1, TEST_ptr_ne(NULL, &y));
    C(err, 1, TEST_ptr_ne(&y, NULL));
    C(err, 1, TEST_ptr_ne(&y, &x));
    C(err, 0, TEST_ptr_ne(&x, &x));
    return 1;

err:
    return 0;
}

static int test_bool(void)
{
    C(err, 0, TEST_true(0));
    C(err, 1, TEST_true(1));
    C(err, 1, TEST_false(0));
    C(err, 0, TEST_false(1));
    return 1;

err:
    return 0;
}

static int test_string(void)
{
    static char buf[] = "abc";
    C(err, 1, TEST_str_eq(NULL, NULL));
    C(err, 1, TEST_str_eq("abc", buf));
    C(err, 0, TEST_str_eq("abc", NULL));
    C(err, 0, TEST_str_eq(NULL, buf));
    C(err, 0, TEST_str_ne(NULL, NULL));
    C(err, 0, TEST_str_ne("abc", buf));
    C(err, 1, TEST_str_ne("abc", NULL));
    C(err, 1, TEST_str_ne(NULL, buf));
    return 1;

err:
    return 0;
}

static int test_memory(void)
{
    static char buf[] = "xyz";
    C(err, 1, TEST_mem_eq(NULL, 0, NULL, 0));
    C(err, 1, TEST_mem_eq(NULL, 1, NULL, 2));
    C(err, 0, TEST_mem_eq(NULL, 0, "xyz", 3));
    C(err, 0, TEST_mem_eq(NULL, 0, "", 0));
    C(err, 0, TEST_mem_eq("xyz", 3, NULL, 0));
    C(err, 0, TEST_mem_eq("xyz", 3, buf, sizeof(buf)));
    C(err, 1, TEST_mem_eq("xyz", 4, buf, sizeof(buf)));
    return 1;

err:
    return 0;
}

static int test_messages(void)
{
    TEST_info("This is an %s message.", "info");
    TEST_error("This is an %s message.", "error");
    return 1;
}

void register_tests(void)
{
    ADD_TEST(test_int);
    ADD_TEST(test_uint);
    ADD_TEST(test_char);
    ADD_TEST(test_uchar);
    ADD_TEST(test_long);
    ADD_TEST(test_ulong);
    ADD_TEST(test_size_t);
    ADD_TEST(test_pointer);
    ADD_TEST(test_bool);
    ADD_TEST(test_string);
    ADD_TEST(test_memory);
    ADD_TEST(test_messages);
}
