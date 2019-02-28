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

static int test_params(void)
{
    size_t sz;
    int i;
    uint64_t u64 = U64VAL, alt64;
    const OSSL_PARAM params[] = {
        OSSL_PARAM_uint64("uv", &u64),
        OSSL_PARAM_int("a", &i),
        OSSL_PARAM_size_t("b", &sz),
        { NULL }
    };
    int r = 0;

    /* Set and get. */
    if (!TEST_true(OSSL_PARAM_set_int(params, "a", IVAL))
            || !TEST_int_eq(i, IVAL))
        goto err;

    /* Auto-set. */
    if (!TEST_true(OSSL_PARAM_get_uint64(params, "uv", &alt64))
            || !TEST_true(alt64 == u64))
        goto err;

    /* Type mismatches. */
    if (!TEST_false(OSSL_PARAM_get_uint64(params, "a", &alt64))
            || !TEST_false(OSSL_PARAM_get_int(params, "uv", &i)))
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
