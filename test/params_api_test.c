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

#define BNSTRING \
        "D78AF684E71DB0C39CFF4E64FB9DB567132CB9C50CC98009FEB820B26F2DED9B"

static int test_params(void)
{
    static size_t sz;
    static int i;
    static uint64_t u64 = U64VAL;
    static double d1 = DOUBLE;
    static char buffer[200];
    uint64_t alt64 = 0;
    double d2 = 0;
    BIGNUM *b1 = NULL, *b2 = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_uint64("u64param", &u64),
        OSSL_PARAM_int("intparam", &i),
        OSSL_PARAM_size_t("--unused--", &sz),
        OSSL_PARAM_double("doubleparam", &d1),
        OSSL_PARAM_bignum("bignumparam", buffer, sizeof(buffer)),
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
            || !TEST_true(OSSL_PARAM_get_double(params, "doubleparam", &d2))
            || !TEST_true(d1 == d2))
        goto err;

    /* Type mismatches. */
    if (!TEST_false(OSSL_PARAM_get_uint64(params, "intparam", &alt64))
            || !TEST_false(OSSL_PARAM_get_int(params, "u64param", &i)))
        goto err;
    ERR_clear_error();

    /* Some BIGNUM tests. */
    b1 = BN_new();
    BN_zero(b1);
    if (!TEST_true(OSSL_PARAM_set_bignum(params, "bignumparam", b1))
            || !TEST_true(OSSL_PARAM_get_bignum(params, "bignumparam", &b2))
            || !TEST_int_eq(BN_cmp(b1, b2), 0))
        goto err;

    if (!TEST_true(BN_hex2bn(&b1, BNSTRING))
            || !TEST_true(OSSL_PARAM_set_bignum(params, "bignumparam", b1))
            || !TEST_true(OSSL_PARAM_get_bignum(params, "bignumparam", &b2))
            || !TEST_int_eq(BN_cmp(b1, b2), 0))
        goto err;

    r = 1;
err:
    BN_free(b1);
    BN_free(b2);
    return r;
}

int setup_tests(void)
{
    /*ADD_ALL_TESTS(test_property_parse, OSSL_NELEM(parser_tests));*/
    ADD_TEST(test_params);
    return 1;
}
