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

static int test_param_type_extra(const OSSL_PARAM *param,
                                 const unsigned char *cmp)
{
    uint8_t u8;
    int32_t i32;
    int i;
    double d;
    float f;
    uintmax_t um;
    int64_t i64;
    size_t s;
    unsigned char buf[MAX_LEN];

    if (!TEST_true(OSSL_PARAM_get_int(param, "a", &i))
        || !TEST_true(OSSL_PARAM_get_uint8(param, "a", &u8))
        || !TEST_true(OSSL_PARAM_get_int32(param, "a", &i32))
        || !TEST_true(OSSL_PARAM_get_int64(param, "a", &i64))
        || !TEST_true(OSSL_PARAM_get_size_t(param, "a", &s))
        || !TEST_true(OSSL_PARAM_get_uintmax(param, "a", &um))
        || !TEST_true(OSSL_PARAM_get_double(param, "a", &d))
        || !TEST_true(OSSL_PARAM_get_float(param, "a", &f)))
        return 0;

    copy_to_le(buf, &i, sizeof(i));
    if (!TEST_mem_eq(buf, sizeof(i), cmp, sizeof(i)))
        return 0;
    copy_to_le(buf, &u8, sizeof(u8));
    if (!TEST_mem_eq(buf, sizeof(u8), cmp, sizeof(u8)))
        return 0;
    copy_to_le(buf, &i32, sizeof(i32));
    if (!TEST_mem_eq(buf, sizeof(i32), cmp, sizeof(i32)))
        return 0;
#ifndef OPENSSL_SYS_WINDOWS
    copy_to_le(buf, &i64, sizeof(i64));
    if (!TEST_mem_eq(buf, sizeof(i64), cmp, sizeof(i64)))
        return 0;
#endif
    copy_to_le(buf, &s, sizeof(s));
    if (!TEST_mem_eq(buf, sizeof(s), cmp, sizeof(s)))
        return 0;
    copy_to_le(buf, &um, sizeof(um));
    if (!TEST_mem_eq(buf, sizeof(um), cmp, sizeof(um)))
        return 0;

    /* reals lose accuracy */
    if (param->buffer_size <= 6) {
        i64 = (int64_t)d;
        copy_to_le(buf, &i64, sizeof(i64));
        if (!TEST_mem_eq(buf, param->buffer_size, cmp, param->buffer_size))
            return 0;
    }
    if (param->buffer_size <= 3) {
        i32 = (int32_t)f;
        copy_to_le(buf, &i32, sizeof(i32));
        if (!TEST_mem_eq(buf, param->buffer_size, cmp, param->buffer_size))
            return 0;
    }
     return 1;
}

#define TEST_INT(name, type, neg) \
    static int test_param_##name(int n) \
    { \
        type in, out; \
        unsigned char buf[MAX_LEN], le[MAX_LEN], cmp[sizeof(type)]; \
        const size_t len = raw_values[n].len > sizeof(type) \
                           ? sizeof(type) : raw_values[n].len; \
        OSSL_PARAM param = OSSL_PARAM_##name("a", NULL); \
        size_t i; \
        \
        memset(buf, 0, sizeof(buf)); \
        memset(le, 0, sizeof(le)); \
        copy_be_to_native(buf, raw_values[n].value, len); \
        swap_copy(le, raw_values[n].value, len); \
        memcpy(&in, buf, sizeof(in)); \
        param.buffer = &out; \
        if (!TEST_true(OSSL_PARAM_set_##name(&param, "a", in))) \
            return 0; \
        copy_to_le(cmp, &out, sizeof(out)); \
        if (!TEST_mem_eq(cmp, sizeof(out), le, sizeof(out))) \
            return 0; \
        in = 0; \
        param.buffer = buf; \
        if (!TEST_true(OSSL_PARAM_get_##name(&param, "a", &in))) \
            return 0; \
        copy_to_le(cmp, &in, sizeof(in)); \
        if (!TEST_mem_eq(cmp, sizeof(in), le, sizeof(in))) \
            return 0; \
        if (neg) \
            for (i = sizeof(type); i < MAX_LEN; i++) \
                le[i] = 0xff; \
        return test_param_type_extra(&param, le); \
    }

/*
 * The negative test needs to come from outside the macro to avoid
 * unsigned comparisons that are always true.
 */
TEST_INT(int, int, in < 0)
TEST_INT(long, long int, in < 0)
TEST_INT(int8, int8_t, in < 0)
TEST_INT(int16, int16_t, in < 0)
TEST_INT(int32, int32_t, in < 0)
TEST_INT(intmax, intmax_t, in < 0)

TEST_INT(uint, unsigned int, 0)
TEST_INT(ulong, unsigned long int, 0)
TEST_INT(uint8, uint8_t, 0)
TEST_INT(uint16, uint16_t, 0)
TEST_INT(uint32, uint32_t, 0)
TEST_INT(uintmax, uintmax_t, 0)
TEST_INT(size_t, size_t, 0)

#ifndef OPENSSL_SYS_WINDOWS
TEST_INT(int64, int64_t, in < 0)
TEST_INT(uint64, uint64_t, 0)
#endif

int setup_tests(void)
{
    ADD_ALL_TESTS(test_param_int, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_long, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_int8, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_int16, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_int32, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_intmax, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uint, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_ulong, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uint8, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uint16, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uint32, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uintmax, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_size_t, OSSL_NELEM(raw_values));
#ifndef OPENSSL_SYS_WINDOWS
    ADD_ALL_TESTS(test_param_int64, OSSL_NELEM(raw_values));
    ADD_ALL_TESTS(test_param_uint64, OSSL_NELEM(raw_values));
#endif
    return 1;
}
