/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <limits.h>

#include <openssl/crypto.h>
#include <internal/nelem.h>

#include "internal/sparse_array.h"
#include "testutil.h"

/* The macros below generate unused functions which error out one of the clang
 * builds.  We disable this check here.
 */
#ifdef __clang__
#pragma clang diagnostic ignored "-Wunused-function"
#endif

DEFINE_SPARSE_ARRAY_OF(char);

static int test_sparse_array(void)
{
    static const struct {
        size_t n;
        char *v;
    } cases[] = {
        { 22, "a" }, { 0, "z" }, { 1, "b" }, { 290, "c" },
        { INT_MAX, "m" }, { 6666666, "d" }, { (size_t)-1, "H" },
        { 99, "e" }
    };
    SPARSE_ARRAY_OF(char) *sa;
    size_t i, j;
    int res = 0;

    if (!TEST_ptr(sa = ossl_sa_char_new())
            || !TEST_ptr_null(ossl_sa_char_get(sa, 3))
            || !TEST_ptr_null(ossl_sa_char_get(sa, 0))
            || !TEST_ptr_null(ossl_sa_char_get(sa, UINT_MAX)))
        goto err;

    for (i = 0; i < OSSL_NELEM(cases); i++) {
        if (!TEST_true(ossl_sa_char_set(sa, cases[i].n, cases[i].v))) {
            TEST_note("iteration %zu", i + 1);
            goto err;
        }
        for (j = 0; j <= i; j++)
            if (!TEST_str_eq(ossl_sa_char_get(sa, cases[j].n), cases[j].v)) {
                TEST_note("iteration %zu / %zu", i + 1, j + 1);
                goto err;
            }
    }

    res = 1;
err:
    ossl_sa_char_free(sa);
    return res;
}

static int test_sparse_array_num(void)
{
    static const struct {
        size_t num;
        size_t n;
        char *v;
    } cases[] = {
        { 1, 22, "a" }, { 2, 1021, "b" }, { 3, 3, "c" }, { 2, 22, NULL },
        { 2, 3, "d" }, { 3, 22, "e" }, { 3, 666, NULL }, { 4, 666, "f" },
        { 3, 3, NULL }, { 2, 22, NULL }, { 1, 666, NULL }, { 2, 64000, "g" },
        { 1, 1021, NULL }, { 0, 64000, NULL }, { 1, 23, "h" }, { 0, 23, NULL }
    };
    SPARSE_ARRAY_OF(char) *sa = NULL;
    size_t i;
    int res = 0;

    if (!TEST_size_t_eq(ossl_sa_char_num(NULL), 0)
            || !TEST_ptr(sa = ossl_sa_char_new())
            || !TEST_size_t_eq(ossl_sa_char_num(sa), 0))
        goto err;
    for (i = 0; i < OSSL_NELEM(cases); i++)
        if (!TEST_true(ossl_sa_char_set(sa, cases[i].n, cases[i].v))
                || !TEST_size_t_eq(ossl_sa_char_num(sa), cases[i].num))
            goto err;
    res = 1;
err:
    ossl_sa_char_free(sa);
    return res;
}

int setup_tests(void)
{
    ADD_TEST(test_sparse_array);
    ADD_TEST(test_sparse_array_num);
    return 1;
}
