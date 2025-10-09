/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file Internal tests of OSSL_FN
 *
 * This tests OSSL_FN internals only, i.e. anything that requires including
 * ../crypto/fn/fn_local.h, such as introspection.
 */

#include "crypto/fn.h"
#include "fn_local.h"
#include "testutil.h"

static int test_alloc(void)
{
    int ret = 1;
    OSSL_FN *f = NULL;

    /*
     * Note that our uses of TEST_int_ and TEST_size_t_ functions don't
     * always correspond exactly to the types of the arguments.  However,
     * the normal type coersion done in C allows this to be done without
     * friction.
     */
    if (!TEST_ptr(f = OSSL_FN_new(sizeof(OSSL_FN_ULONG) * 2 - 2))
        || !TEST_uint_eq(f->is_dynamically_allocated, 1)
        || !TEST_uint_eq(f->is_securely_allocated, 0)
        || !TEST_uint_eq(f->is_acquired, 0)
        || !TEST_uint_eq(f->is_negative, 0)
        || !TEST_size_t_eq(f->dsize, 2)
        || !TEST_size_t_eq(f->d[0], 0)
        || !TEST_size_t_eq(f->d[1], 0))
        ret = 0;
    if (f != NULL)
        OSSL_FN_free(f);

    return ret;
}
static int test_secure_alloc(void)
{
    int ret = 1;
    OSSL_FN *f = NULL;

    /*
     * Note that our uses of TEST_int_ and TEST_size_t_ functions don't
     * always correspond exactly to the types of the arguments.  However,
     * the normal type coersion done in C allows this to be done without
     * friction.
     */
    if (!TEST_ptr(f = OSSL_FN_secure_new(sizeof(OSSL_FN_ULONG) * 2 - 2))
        || !TEST_uint_eq(f->is_dynamically_allocated, 1)
        || !TEST_uint_eq(f->is_securely_allocated, 1)
        || !TEST_uint_eq(f->is_acquired, 0)
        || !TEST_uint_eq(f->is_negative, 0)
        || !TEST_size_t_eq(f->dsize, 2)
        || !TEST_size_t_eq(f->d[0], 0)
        || !TEST_size_t_eq(f->d[1], 0))
        ret = 0;
    if (f != NULL)
        OSSL_FN_free(f);

    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_alloc);
    ADD_TEST(test_secure_alloc);

    return 1;
}

void cleanup_tests(void)
{
}
