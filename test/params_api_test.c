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
#include "testutil.h"
#include "internal/nelem.h"
#include <openssl/params.h>
#include <openssl/bn.h>

/* The maximum size of the static buffers used to test most things */
#define MAX_LEN 20

static void swap_copy(unsigned char *out, const void *in, size_t len)
{
    size_t j;

    for (j = 0; j < len; j++)
        out[j] = ((unsigned char *)in)[len - j - 1];
}

static void copy_to_le(unsigned char *out, const void *in, size_t len)
{
#ifdef B_ENDIAN
    swap_copy(out, in, len);
#else
    memcpy(out, in, len);
#endif
}

static void copy_be_to_native(unsigned char *out, const void *in, size_t len)
{
#ifdef B_ENDIAN
    memcpy(out, in, len);
#else
    swap_copy(out, in, len);
#endif
}

static const struct {
    size_t len;
    unsigned char value[MAX_LEN];
} raw_values[] = {
    { 4, { 0x38, 0x27, 0xbf, 0x3b } },
    { 4, { 0x9f, 0x26, 0x48, 0x22 } },
    { 8, { 0x59, 0xb2, 0x1a, 0xe9, 0x2a, 0xd8, 0x46, 0x40 } },
    { 8, { 0xb4, 0xae, 0xbd, 0xb4, 0xdd, 0x04, 0xb1, 0x4c } },
    { 16, { 0x61, 0xe8, 0x7e, 0x31, 0xe9, 0x33, 0x83, 0x3d,
            0x87, 0x99, 0xc7, 0xd8, 0x5d, 0xa9, 0x8b, 0x42 } },
    { 16, { 0xee, 0x6e, 0x8b, 0xc3, 0xec, 0xcf, 0x37, 0xcc,
            0x89, 0x67, 0xf2, 0x68, 0x33, 0xa0, 0x14, 0xb0 } },
};

static int test_param_type_extra(const OSSL_PARAM *param, unsigned char *cmp,
                                 size_t width)
{
    int32_t i32;
    double d;
    int64_t i64;
    size_t s, sz;
    unsigned char buf[MAX_LEN];
    const int bit32 = param->buffer_size == sizeof(int32_t);
    const int sizet = bit32 && sizeof(size_t) > sizeof(int32_t);

    if ((bit32 && !TEST_true(OSSL_PARAM_get_int32(param, &i32)))
        || !TEST_true(OSSL_PARAM_get_int64(param, &i64))
        || (sizet && !TEST_true(OSSL_PARAM_get_size_t(param, &s)))
        || !TEST_true(OSSL_PARAM_get_double(param, &d)))
        return 0;

    /* Check signed types */
    if (bit32) {
        copy_to_le(buf, &i32, sizeof(i32));
        sz = sizeof(i32) < width ? sizeof(i32) : width;
        if (!TEST_mem_eq(buf, sz, cmp, sz))
            return 0;
    }
    copy_to_le(buf, &i64, sizeof(i64));
        sz = sizeof(i64) < width ? sizeof(i64) : width;
    if (!TEST_mem_eq(buf, sz, cmp, sz))
        return 0;
    if (sizet) {
        copy_to_le(buf, &s, sizeof(s));
        sz = sizeof(s) < width ? sizeof(s) : width;
        if (!TEST_mem_eq(buf, sz, cmp, sz))
            return 0;
    }

    /* Check reals, remembering that they can lose accuracy */
    if (param->buffer_size <= 6) {
        i64 = (int64_t)d;
        copy_to_le(buf, &i64, sizeof(i64));
        if (!TEST_mem_eq(buf, param->buffer_size, cmp, param->buffer_size))
            return 0;
    }

    /* Check a widening write if possible */
    if (sizeof(size_t) > width)
        if (!TEST_true(OSSL_PARAM_set_int32(param, 12345))
            || !TEST_true(OSSL_PARAM_get_size_t(param, &s))
            || !TEST_size_t_eq(s, 12345))
            return 0;
    return 1;
}

/*
 * This macro defines a basic test case that sets a param of a specified
 * integral type, attempts to read the value back and then calls the above
 * function to verify that the params can be read as other types.
 *
 * Since this macro doesn't know the exact sizes of everything, all the real
 * work is done via byte buffers which are converted to machine order or little
 * endian for comparisons.  Narrower values are best compared using little
 * endian because their values and positions don't change.
 */
#define TEST_INT(name, type) \
    static int test_param_##name(int n) \
    { \
        type in, out; \
        unsigned char buf[MAX_LEN], le[MAX_LEN], cmp[sizeof(type)]; \
        const size_t len = raw_values[n].len >= sizeof(type) \
                           ? sizeof(type) : raw_values[n].len; \
        OSSL_PARAM param = OSSL_PARAM_##name("a", NULL); \
        \
        memset(buf, 0, sizeof(buf)); \
        memset(le, 0, sizeof(le)); \
        copy_be_to_native(buf, raw_values[n].value, len); \
        swap_copy(le, raw_values[n].value, len); \
        memcpy(&in, buf, sizeof(in)); \
        param.buffer = &out; \
        if (!TEST_true(OSSL_PARAM_set_##name(&param, in))) \
            return 0; \
        copy_to_le(cmp, &out, sizeof(out)); \
        if (!TEST_mem_eq(cmp, len, le, len)) \
            return 0; \
        in = 0; \
        param.buffer = buf; \
        if (!TEST_true(OSSL_PARAM_get_##name(&param, &in))) \
            return 0; \
        copy_to_le(cmp, &in, sizeof(in)); \
        if (!TEST_mem_eq(cmp, sizeof(in), le, sizeof(in))) \
            return 0; \
        param.buffer = &out; \
        return test_param_type_extra(&param, le, sizeof(type)); \
    }

/*
 * The negative test needs to come from outside the macro to avoid
 * unsigned comparisons that are always true.
 */
TEST_INT(int, int)
TEST_INT(long, long int)
TEST_INT(uint, unsigned int)
TEST_INT(ulong, unsigned long int)
TEST_INT(int32, int32_t)
TEST_INT(uint32, uint32_t)
TEST_INT(int64, int64_t)
TEST_INT(uint64, uint64_t)
TEST_INT(size_t, size_t)

static int test_param_bignum(int n)
{
    unsigned char buf[MAX_LEN], bnbuf[MAX_LEN], le[MAX_LEN];
    const size_t len = raw_values[n].len;
    size_t bnsize;
    BIGNUM *b = NULL, *c = NULL;
    OSSL_PARAM param = OSSL_PARAM_DEFN("bn", OSSL_PARAM_UNSIGNED_INTEGER,
                                       NULL, sizeof(bnbuf), NULL);
    int ret = 0;

    param.buffer = bnbuf;
    param.return_size = &bnsize;

    copy_be_to_native(buf, raw_values[n].value, len);
    swap_copy(le, raw_values[n].value, len);
    if (!TEST_ptr(b = BN_bin2bn(raw_values[n].value, (int)len, NULL)))
        goto err;

    if (!TEST_true(OSSL_PARAM_set_BN(&param, b))
        || !TEST_mem_eq(bnbuf, len, buf, len)
        || !TEST_true(OSSL_PARAM_get_BN(&param, &c))
        || !TEST_BN_eq(b, c))
        goto err;

    ret = 1;
err:
    BN_free(b);
    BN_free(c);
    return ret;
}

static int test_param_real(void)
{
    double p;
    OSSL_PARAM param = OSSL_PARAM_double("r", NULL);

    param.buffer = &p;
    return TEST_true(OSSL_PARAM_set_double(&param, 3.14159))
           && TEST_double_eq(p, 3.14159);
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_param_int, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_long, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uint, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_ulong, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_int32, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uint32, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_size_t, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_int64, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uint64, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_bignum, OSSL_NELEM(raw_values));
    ADD_TEST(test_param_real);
    return 1;
}
