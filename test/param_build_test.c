/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/params.h>
#include "internal/param_build.h"
#include "internal/nelem.h"
#include "testutil.h"

static int template_public_test(void)
{
    OSSL_PARAM_BLD bld;
    OSSL_PARAM *params = NULL, *p;
    BIGNUM *bn = NULL, *bn_res = NULL;
    int i;
    long int l;
    int32_t i32;
    int64_t i64;
    double d;
    char *utf = NULL;
    const char *cutf;
    int res = 0;

    ossl_param_bld_init(&bld);
    if (!TEST_true(ossl_param_bld_push_int(&bld, "i", -6))
        || !TEST_true(ossl_param_bld_push_long(&bld, "l", 42))
        || !TEST_true(ossl_param_bld_push_int32(&bld, "i32", 1532))
        || !TEST_true(ossl_param_bld_push_int64(&bld, "i64", -9999999))
        || !TEST_true(ossl_param_bld_push_double(&bld, "d", 1.61803398875))
        || !TEST_ptr(bn = BN_new())
        || !TEST_true(BN_set_word(bn, 1729))
        || !TEST_true(ossl_param_bld_push_BN(&bld, "bignumber", bn))
        || !TEST_true(ossl_param_bld_push_utf8_string(&bld, "utf8_s", "foo",
                                                      sizeof("foo")))
        || !TEST_true(ossl_param_bld_push_utf8_ptr(&bld, "utf8_p", "bar-boom",
                                                   0))
        || !TEST_ptr(params = ossl_param_bld_to_param(&bld))
        /* Check int */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "i"))
        || !TEST_true(OSSL_PARAM_get_int(p, &i))
        || !TEST_str_eq(p->key, "i")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_INTEGER)
        || !TEST_size_t_eq(p->data_size, sizeof(int))
        || !TEST_int_eq(i, -6)
        /* Check int32 */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "i32"))
        || !TEST_true(OSSL_PARAM_get_int32(p, &i32))
        || !TEST_str_eq(p->key, "i32")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_INTEGER)
        || !TEST_size_t_eq(p->data_size, sizeof(int32_t))
        || !TEST_int_eq((int)i32, 1532)
        /* Check int64 */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "i64"))
        || !TEST_str_eq(p->key, "i64")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_INTEGER)
        || !TEST_size_t_eq(p->data_size, sizeof(int64_t))
        || !TEST_true(OSSL_PARAM_get_int64(p, &i64))
        || !TEST_long_eq((long)i64, -9999999)
        /* Check long */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "l"))
        || !TEST_str_eq(p->key, "l")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_INTEGER)
        || !TEST_size_t_eq(p->data_size, sizeof(long int))
        || !TEST_true(OSSL_PARAM_get_long(p, &l))
        || !TEST_long_eq(l, 42)
        /* Check double */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "d"))
        || !TEST_true(OSSL_PARAM_get_double(p, &d))
        || !TEST_str_eq(p->key, "d")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_REAL)
        || !TEST_size_t_eq(p->data_size, sizeof(double))
        || !TEST_double_eq(d, 1.61803398875)
        /* Check UTF8 string */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "utf8_s"))
        || !TEST_str_eq(p->data, "foo")
        || !TEST_true(OSSL_PARAM_get_utf8_string(p, &utf, 0))
        || !TEST_str_eq(utf, "foo")
        /* Check UTF8 pointer */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "utf8_p"))
        || !TEST_true(OSSL_PARAM_get_utf8_ptr(p, &cutf))
        || !TEST_str_eq(cutf, "bar-boom")
        /* Check BN */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "bignumber"))
        || !TEST_str_eq(p->key, "bignumber")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_UNSIGNED_INTEGER)
        || !TEST_true(OSSL_PARAM_get_BN(p, &bn_res))
        || !TEST_int_eq(BN_cmp(bn_res, bn), 0))
        goto err;
    res = 1;
err:
    ossl_param_bld_free(params);
    OPENSSL_free(utf);
    BN_free(bn);
    BN_free(bn_res);
    return res;
}

static int template_private_test(void)
{
    static int data1[] = { 2, 3, 5, 7, 11, 15, 17 };
    static unsigned char data2[] = { 2, 4, 6, 8, 10 };
    OSSL_PARAM_BLD bld;
    OSSL_PARAM *params = NULL, *p;
    unsigned int i;
    unsigned long int l;
    uint32_t i32;
    uint64_t i64;
    size_t st;
    BIGNUM *bn = NULL, *bn_res = NULL;
    int res = 0;

    ossl_param_bld_init(&bld);
    if (!TEST_true(ossl_param_bld_push_uint(&bld, "i", 6))
        || !TEST_true(ossl_param_bld_push_ulong(&bld, "l", 42))
        || !TEST_true(ossl_param_bld_push_uint32(&bld, "i32", 1532))
        || !TEST_true(ossl_param_bld_push_uint64(&bld, "i64", 9999999))
        || !TEST_true(ossl_param_bld_push_size_t(&bld, "st", 65537))
        || !TEST_ptr(bn = BN_secure_new())
        || !TEST_true(BN_set_word(bn, 1729))
        || !TEST_true(ossl_param_bld_push_BN(&bld, "bignumber", bn))
        || !TEST_true(ossl_param_bld_push_octet_string(&bld, "oct_s", data1,
                                                       sizeof(data1)))
        || !TEST_true(ossl_param_bld_push_octet_ptr(&bld, "oct_p", data2,
                                                    sizeof(data2)))
        || !TEST_ptr(params = ossl_param_bld_to_param(&bld))
        /* Check unsigned int */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "i"))
        || !TEST_true(OSSL_PARAM_get_uint(p, &i))
        || !TEST_str_eq(p->key, "i")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_UNSIGNED_INTEGER)
        || !TEST_size_t_eq(p->data_size, sizeof(int))
        || !TEST_uint_eq(i, 6)
        /* Check unsigned int32 */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "i32"))
        || !TEST_true(OSSL_PARAM_get_uint32(p, &i32))
        || !TEST_str_eq(p->key, "i32")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_UNSIGNED_INTEGER)
        || !TEST_size_t_eq(p->data_size, sizeof(int32_t))
        || !TEST_uint_eq((unsigned int)i32, 1532)
        /* Check unsigned int64 */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "i64"))
        || !TEST_str_eq(p->key, "i64")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_UNSIGNED_INTEGER)
        || !TEST_size_t_eq(p->data_size, sizeof(int64_t))
        || !TEST_true(OSSL_PARAM_get_uint64(p, &i64))
        || !TEST_ulong_eq((unsigned long)i64, 9999999)
        /* Check unsigned long int */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "l"))
        || !TEST_str_eq(p->key, "l")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_UNSIGNED_INTEGER)
        || !TEST_size_t_eq(p->data_size, sizeof(unsigned long int))
        || !TEST_true(OSSL_PARAM_get_ulong(p, &l))
        || !TEST_ulong_eq(l, 42)
        /* Check size_t */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "st"))
        || !TEST_str_eq(p->key, "st")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_UNSIGNED_INTEGER)
        || !TEST_size_t_eq(p->data_size, sizeof(size_t))
        || !TEST_true(OSSL_PARAM_get_size_t(p, &st))
        || !TEST_size_t_eq(st, 65537)
        /* Check octet string */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "oct_s"))
        || !TEST_str_eq(p->key, "oct_s")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_OCTET_STRING)
        || !TEST_mem_eq(p->data, p->data_size, data1, sizeof(data1))
        /* Check octet pointer */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "oct_p"))
        || !TEST_str_eq(p->key, "oct_p")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_OCTET_PTR)
        || !TEST_mem_eq(*(void **)p->data, p->data_size, data2, sizeof(data2))
        /* Check BN */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "bignumber"))
        || !TEST_str_eq(p->key, "bignumber")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_UNSIGNED_INTEGER)
        || !TEST_true(OSSL_PARAM_get_BN(p, &bn_res))
        || !TEST_int_eq(BN_cmp(bn_res, bn), 0))
        goto err;
    res = 1;
err:
    ossl_param_bld_free(params);
    BN_free(bn);
    BN_free(bn_res);
    return res;
}

static int template_static_params_test(int n)
{
    unsigned char data[1000], secure[500];
    OSSL_PARAM_BLD bld;
    OSSL_PARAM params[20], *p;
    BIGNUM *bn = NULL, *bn_r = NULL;
    unsigned int i;
    char *utf = NULL;
    int res = 0;

    ossl_param_bld_init(&bld);
    if (!TEST_true(ossl_param_bld_push_uint(&bld, "i", 6))
        || !TEST_ptr(bn = (n & 1) == 0 ? BN_new() : BN_secure_new())
        || !TEST_true(BN_set_word(bn, 1337))
        || !TEST_true(ossl_param_bld_push_BN(&bld, "bn", bn))
        || !TEST_true(ossl_param_bld_push_utf8_string(&bld, "utf8_s", "bar",
                                                      0))
        || !TEST_ptr(ossl_param_bld_to_param_ex(&bld, params,
                                                OSSL_NELEM(params),
                                                data, sizeof(data),
                                                secure, sizeof(secure)))
        /* Check unsigned int */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "i"))
        || !TEST_true(OSSL_PARAM_get_uint(p, &i))
        || !TEST_str_eq(p->key, "i")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_UNSIGNED_INTEGER)
        || !TEST_size_t_eq(p->data_size, sizeof(int))
        || !TEST_uint_eq(i, 6)
        /* Check BIGNUM */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "bn"))
        || !TEST_true(OSSL_PARAM_get_BN(p, &bn_r))
        || !TEST_str_eq(p->key, "bn")
        || !TEST_uint_eq(p->data_type, OSSL_PARAM_UNSIGNED_INTEGER)
        || !TEST_size_t_le(p->data_size, sizeof(BN_ULONG))
        || !TEST_uint_eq((unsigned int)BN_get_word(bn_r), 1337)
        /* Check UTF8 string */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "utf8_s"))
        || !TEST_str_eq(p->data, "bar")
        || !TEST_true(OSSL_PARAM_get_utf8_string(p, &utf, 0))
        || !TEST_str_eq(utf, "bar"))
        goto err;
    res = 1;
err:
    OPENSSL_free(utf);
    BN_free(bn);
    BN_free(bn_r);
    return res;
}

static int template_static_fail_test(int n)
{
    unsigned char data[10000], secure[500];
    OSSL_PARAM_BLD bld;
    OSSL_PARAM prms[20];
    BIGNUM *bn = NULL;
    int res = 0;

    ossl_param_bld_init(&bld);
    if (!TEST_true(ossl_param_bld_push_uint(&bld, "i", 6))
        || !TEST_ptr(bn = (n & 1) == 0 ? BN_new() : BN_secure_new())
        || !TEST_true(BN_hex2bn(&bn, "ABCDEF78901234567890ABCDEF0987987654321"))
        || !TEST_true(ossl_param_bld_push_BN(&bld, "bn", bn))
        || !TEST_true(ossl_param_bld_push_utf8_string(&bld, "utf8_s", "abc",
                                                      1000))
        /* No OSSL_PARAMS */
        || !TEST_ptr_null(ossl_param_bld_to_param_ex(&bld, NULL, 0, data,
                                                     sizeof(data), secure,
                                                     sizeof(secure)))
        /* Short OSSL_PARAMS */
        || !TEST_ptr_null(ossl_param_bld_to_param_ex(&bld, prms, 2,
                                                     data, sizeof(data),
                                                     secure, sizeof(secure)))
        /* No normal data */
        || !TEST_ptr_null(ossl_param_bld_to_param_ex(&bld, prms,
                                                     OSSL_NELEM(prms),
                                                     NULL, 0, secure,
                                                     sizeof(secure)))
        /* Not enough normal data */
        || !TEST_ptr_null(ossl_param_bld_to_param_ex(&bld, prms,
                                                     OSSL_NELEM(prms),
                                                     data, 50, secure,
                                                     sizeof(secure))))
            goto err;
        if ((n & 1) == 1) {
            /* No secure data */
            if (!TEST_ptr_null(ossl_param_bld_to_param_ex(&bld, prms,
                                                          OSSL_NELEM(prms),
                                                          data, sizeof(data),
                                                          NULL, 0))
            /* Not enough secure data */
            || !TEST_ptr_null(ossl_param_bld_to_param_ex(&bld, prms,
                                                         OSSL_NELEM(prms),
                                                         data, sizeof(data),
                                                         secure, 4)))
                goto err;
        }
    res = 1;
err:
    BN_free(bn);
    return res;
}

int setup_tests(void)
{
    ADD_TEST(template_public_test);
    ADD_TEST(template_private_test);
    ADD_ALL_TESTS(template_static_params_test, 2);
    ADD_ALL_TESTS(template_static_fail_test, 2);
    return 1;
}
