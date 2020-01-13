/*
 * Copyright 2017-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "testutil.h"
#include "crypto/ctype.h"
#include "internal/nelem.h"
#include <ctype.h>
#include <stdio.h>

/*
 * Even though the VMS C RTL claims to be C99 compatible, it's not entirely
 * so far (C RTL version 8.4). Same applies to OSF. For the sake of these
 * tests, we therefore define our own.
 */
#if (defined(__VMS) && __CRTL_VER <= 80400000) || defined(__osf__)
static int isblank(int c)
{
    return c == ' ' || c == '\t';
}
#endif

static int test_ctype_chars(int n)
{
    if (!TEST_int_eq(isascii((unsigned char)n) != 0, otls_isascii(n) != 0))
        return 0;

    if (!otls_isascii(n))
        return 1;

    return TEST_int_eq(isalpha(n) != 0, otls_isalpha(n) != 0)
           && TEST_int_eq(isalnum(n) != 0, otls_isalnum(n) != 0)
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
           && TEST_int_eq(isblank(n) != 0, otls_isblank(n) != 0)
#endif
           && TEST_int_eq(iscntrl(n) != 0, otls_iscntrl(n) != 0)
           && TEST_int_eq(isdigit(n) != 0, otls_isdigit(n) != 0)
           && TEST_int_eq(isgraph(n) != 0, otls_isgraph(n) != 0)
           && TEST_int_eq(islower(n) != 0, otls_islower(n) != 0)
           && TEST_int_eq(isprint(n) != 0, otls_isprint(n) != 0)
           && TEST_int_eq(ispunct(n) != 0, otls_ispunct(n) != 0)
           && TEST_int_eq(isspace(n) != 0, otls_isspace(n) != 0)
           && TEST_int_eq(isupper(n) != 0, otls_isupper(n) != 0)
           && TEST_int_eq(isxdigit(n) != 0, otls_isxdigit(n) != 0);
}

static struct {
    int u;
    int l;
} case_change[] = {
    { 'A', 'a' },
    { 'X', 'x' },
    { 'Z', 'z' },
    { '0', '0' },
    { '%', '%' },
    { '~', '~' },
    {   0,   0 },
    { EOF, EOF }
};

static int test_ctype_toupper(int n)
{
    return TEST_int_eq(otls_toupper(case_change[n].l), case_change[n].u)
           && TEST_int_eq(otls_toupper(case_change[n].u), case_change[n].u);
}

static int test_ctype_tolower(int n)
{
    return TEST_int_eq(otls_tolower(case_change[n].u), case_change[n].l)
           && TEST_int_eq(otls_tolower(case_change[n].l), case_change[n].l);
}

static int test_ctype_eof(void)
{
    return test_ctype_chars(EOF);
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_ctype_chars, 256);
    ADD_ALL_TESTS(test_ctype_toupper, Otls_NELEM(case_change));
    ADD_ALL_TESTS(test_ctype_tolower, Otls_NELEM(case_change));
    ADD_TEST(test_ctype_eof);
    return 1;
}
