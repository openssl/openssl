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

static char foo[] = "abcdefg";

static int called_function(int dummy, OSSL_PARAM *plist, const char *hello)
{
    int r = 0;
    int i;
    uint64_t u64;
    void *ptr;
    BIGNUM *bn;

    if (!TEST_true(OSSL_PARAM_get_int(plist, "int", &i))
            || !TEST_int_eq(i, IVAL)
            || !TEST_true(OSSL_PARAM_get_uint64(plist, "u64", &u64))
            || !TEST_true(u64 == U64VAL)
            || !TEST_true(OSSL_PARAM_get_pointer(plist, "ptr", &ptr))
            || !TEST_ptr_eq(ptr, foo)
            || !TEST_true(OSSL_PARAM_get_bignum(plist, "bignum", &bn))
            || !TEST_true(BN_is_zero(bn))
            || !TEST_true(OSSL_PARAM_return_double(plist, "double", DOUBLE)))
        goto end;

    r = 1;
end:
    return r;
}

static int test_params(void)
{
    int r = 0;
    void *ptr;
    BIGNUM *b1 = NULL, *b2 = NULL;
    int i;
    uint64_t u64;
    double d1;
    char buff[200];
    OSSL_PARAM plist[] = {
        OSSL_PARAM_uint64("u64"),
        OSSL_PARAM_int("int"),
        OSSL_PARAM_size_t("--unused--"),
        OSSL_PARAM_pointer("ptr"),
        OSSL_PARAM_bignum("bignum"),
        OSSL_PARAM_double("double"),
        OSSL_PARAM_bignum("prime"),
        { NULL }
    };

    /* Set some input parameters. */
    ptr = foo;
    u64 = 42;
    b1 = BN_new();
    BN_zero(b1);
    if (!TEST_true(OSSL_PARAM_set_int(plist, "int", &i))
            || !TEST_true(OSSL_PARAM_set_uint64(&plist[0], NULL, &u64))
            || !TEST_true(OSSL_PARAM_set_pointer(plist, "ptr", &ptr))
            || !TEST_true(OSSL_PARAM_set_bignum(plist, "bignum", &b1)))
        goto err;

    /* Values can be changed up until plist is used. */
    i = IVAL;
    u64 = U64VAL;

    /* Return parameters. */
    if (!TEST_true(OSSL_PARAM_reserve_double(plist, "double", &d1))
            || !TEST_true(OSSL_PARAM_reserve_bignum(plist, "prime",
                                                    buff, sizeof(buff))))
        goto err;

    if (!called_function(0, plist, "hello world"))
        goto err;

    /* Compare results. */
    if (!TEST_true(d1 == DOUBLE))
        goto err;

    r = 1;

err:
    BN_free(b1);
    BN_free(b2);
    return r;

#if 0
            || !TEST_int_eq(i, IVAL)
            || !TEST_true(OSSL_PARAM_set_double(plist, "doubleparam", DOUBLE))
            || !TEST_true(d1 == DOUBLE))
        goto err;

    /* Getting a parameter should return the value that was in the variable. */
    if (!TEST_true(OSSL_PARAM_get_uint64(plist, "u64param", &alt64))
            || !TEST_true(alt64 == u64)
            || !TEST_true(OSSL_PARAM_get_double(plist, "doubleparam", &d2))
            || !TEST_true(d1 == d2))
        goto err;

    /* Type mismatches. */
    if (!TEST_false(OSSL_PARAM_get_uint64(plist, "intparam", &alt64))
            || !TEST_false(OSSL_PARAM_get_int(plist, "u64param", &i))
            || !TEST_false(OSSL_PARAM_get_pointer(plist, "intparam", &altptr)))
        goto err;

    /* Pointers. */
    if (!TEST_true(OSSL_PARAM_get_pointer(plist, "ptr", &altptr))
            || !TEST_ptr_eq(ptr, altptr))
        goto err;

    ERR_clear_error();

    /* Some BIGNUM tests. */
    if (!TEST_true(OSSL_PARAM_set_bignum(params, "bignumparam", b1))
            || !TEST_ptr((b2 = OSSL_PARAM_get_bignum(params, "bignumparam")))
            || !TEST_BN_eq(b1, b2))
        goto err;
    BN_free(b2);

    if (!TEST_true(BN_hex2bn(&b1, BNSTRING))
            || !TEST_true(OSSL_PARAM_set_bignum(params, "bignumparam", b1))
            || !TEST_ptr(b2 = OSSL_PARAM_get_bignum(params, "bignumparam"))
            || !TEST_BN_eq(b1, b2))
        goto err;
#endif
}

int setup_tests(void)
{
    /*ADD_ALL_TESTS(test_property_parse, OSSL_NELEM(parser_tests));*/
    ADD_TEST(test_params);
    return 1;
}
