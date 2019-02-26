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

static int test_params(void)
{
    int8_t i8;
    size_t sz;
    double dbl;
    const OSSL_PARAM params[] = {
        OSSL_PARAM_int8("a", &i8),
        OSSL_PARAM_size_t("b", &sz),
        OSSL_PARAM_double("c", &dbl)
    };
    int r = 0;

    if (!TEST_true(OSSL_PARAM_set_int(params, "a", 22))
        || !TEST_int_eq((int)i8, 22)
        || !TEST_true(OSSL_PARAM_get_size_t(params, "a", &sz))
        || !TEST_size_t_eq(sz, 22))
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
