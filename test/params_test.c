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
    { 0, { 0 } },
    { 1, { 0x5c } },
    { 2, { 0xf6, 0xfa } },
    { 3, { 0xfe, 0x04, 0x4d } },
    { 4, { 0x38, 0x27, 0xbf, 0x3b } },
    { 5, { 0xd5, 0xf8, 0xa9, 0x45, 0x2b } },
    { 6, { 0x23, 0x56, 0xf9, 0xb6, 0x9e, 0x36 } },
    { 7, { 0x84, 0x38, 0x90, 0xd4, 0x60, 0x6b, 0x53} },
    { 8, { 0x59, 0xb2, 0x1a, 0xe9, 0x2a, 0xd8, 0x46, 0x40 } },
    { 10, { 0x14, 0x02, 0x15, 0x57, 0xd8, 0x4c, 0x0b, 0x73, 0xc7, 0x0e } }
};

static int test_param_type_extra(const OSSL_PARAM *param, uintmax_t v)
{
    uint8_t u8;
    int32_t i32;
    int i;
    double d;
    float f;
    unsigned char buf[MAX_LEN], cmp[sizeof(v)];

    copy_to_le(cmp, &v, sizeof(v));

    if (!TEST_true(OSSL_PARAM_get_int(param, "a", &i))
        || !TEST_true(OSSL_PARAM_get_uint8(param, "a", &u8))
        || !TEST_true(OSSL_PARAM_get_int32(param, "a", &i32))
        || !TEST_true(OSSL_PARAM_get_double(param, "a", &d))
        || !TEST_true(OSSL_PARAM_get_float(param, "a", &f)))
        return 0;

    copy_to_le(buf, &i, sizeof(i));
    if (!TEST_mem_eq(buf, sizeof(i), cmp, sizeof(i)))
        return 0;
    copy_to_le(buf, &u8, sizeof(u8));
    if (!TEST_mem_eq(&u8, sizeof(u8), cmp, sizeof(u8)))
        return 0;
    copy_to_le(buf, &i32, sizeof(i32));
    if (!TEST_mem_eq(&i32, sizeof(i32), cmp, sizeof(i32)))
        return 0;

    /* reals lose accuracy */
    if (param->buffer_size <= 6 && !TEST_size_t_eq((size_t)d, v))
        return 0;
    if (param->buffer_size <= 3 && !TEST_size_t_eq((size_t)f, v))
        return 0;
    return 1;
}

#define TEST_INT(name, type) \
    static int test_param_##name(int n) \
    { \
        type in, out; \
        unsigned char buf[MAX_LEN], le[MAX_LEN], cmp[sizeof(type)]; \
        const size_t len = raw_values[n].len > sizeof(type) \
                           ? sizeof(type) : raw_values[n].len; \
        OSSL_PARAM param = OSSL_PARAM_##name("a", &out); \
        \
        memset(buf, 0, sizeof(buf)); \
        memset(le, 0, sizeof(le)); \
        copy_be_to_native(buf, raw_values[n].value, len); \
        swap_copy(le, raw_values[n].value, len); \
        memcpy(&in, buf, sizeof(in)); \
        if (!TEST_true(OSSL_PARAM_set_##name(&param, "a", in))) \
            return 0; \
        copy_to_le(cmp, &out, sizeof(out)); \
        if (!TEST_mem_eq(cmp, sizeof(out), le, sizeof(out))) \
            return 0; \
        param.buffer = buf; \
        in = 0; \
        if (!TEST_true(OSSL_PARAM_get_##name(&param, "a", &in))) \
            return 0; \
        if (!TEST_mem_eq(&in, sizeof(type), &out, sizeof(type))) \
            return 0; \
        return test_param_type_extra(&param, (uintmax_t)in); \
    }

TEST_INT(int, int)
TEST_INT(long, long int)
TEST_INT(int8, int8_t)
TEST_INT(int16, int16_t)
TEST_INT(int32, int32_t)
TEST_INT(int64, int64_t)
TEST_INT(intmax, intmax_t)

TEST_INT(uint, unsigned int)
TEST_INT(ulong, unsigned long int)
TEST_INT(uint8, uint8_t)
TEST_INT(uint16, uint16_t)
TEST_INT(uint32, uint32_t)
TEST_INT(uint64, uint64_t)
TEST_INT(uintmax, uintmax_t)
TEST_INT(size_t, size_t)

int setup_tests(void)
{
    ADD_ALL_TESTS(test_param_int, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_long, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_int8, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_int16, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_int32, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_int64, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_intmax, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uint, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_ulong, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uint8, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uint16, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uint32, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uint64, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uintmax, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_size_t, OSSL_NELEM(raw_values));
    return 1;
}
