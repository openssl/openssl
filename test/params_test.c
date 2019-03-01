/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "testutil.h"
#include "internal/nelem.h"
#include <openssl/params.h>

#define IVAL    22
#define U64VAL  0xDEADBEEF
#define DOUBLE  3.14159

static int test_params(void)
{
    size_t sz = 0;
    int i = 0;
    uint64_t u64 = U64VAL, alt64 = 0;
    double d1 = DOUBLE, d2 = 0;
    const OSSL_PARAM params[] = {
        OSSL_PARAM_uint64("u64param", &u64),
        OSSL_PARAM_int("intparam", &i),
        OSSL_PARAM_size_t("UNUSEDparam", &sz),
        OSSL_PARAM_double("doubleparam", &d1),
        { NULL }
    };
    int r = 0;

    /* Setting a param should change the value in the related variable. */
    if (!TEST_true(OSSL_PARAM_set_int(params, "intparam", IVAL))
            || !TEST_int_eq(i, IVAL)
            || !TEST_true(OSSL_PARAM_set_double(params, "doubleparam", DOUBLE))
            || !TEST_true(d1 == DOUBLE))
        goto err;

    /* Getting a parameter should return the value that was in the variable. */
    if (!TEST_true(OSSL_PARAM_get_uint64(params, "u64param", &alt64))
            || !TEST_true(alt64 == u64)
            || (!TEST_true(OSSL_PARAM_get_double(params, "doubleparam", &d2)))
            || !TEST_true(d1 == d2))
        goto err;

    /* Type mismatches. */
    if (!TEST_false(OSSL_PARAM_get_uint64(params, "intparam", &alt64))
            || !TEST_false(OSSL_PARAM_get_int(params, "u64param", &i)))
        goto err;

    r = 1;
err:
    return r;
}

int setup_tests(void)
{
    /*ADD_ALL_TESTS(test_property_parse, OSSL_NELEM(parser_tests));*/
    ADD_TEST(test_params);
    return 1;
}
