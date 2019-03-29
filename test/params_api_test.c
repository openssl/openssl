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
#include "ossl_test_endian.h"
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
    DECLARE_IS_ENDIAN;

    if (IS_LITTLE_ENDIAN)
        memcpy(out, in, len);
    else
        swap_copy(out, in, len);
}

static void copy_be_to_native(unsigned char *out, const void *in, size_t len)
{
    DECLARE_IS_ENDIAN;

    if (IS_LITTLE_ENDIAN)
        swap_copy(out, in, len);
    else
        memcpy(out, in, len);
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
    int64_t i64;
    size_t s, sz;
    unsigned char buf[MAX_LEN];
    const int bit32 = param->data_size == sizeof(int32_t);
    const int sizet = bit32 && sizeof(size_t) > sizeof(int32_t);
    const int signd = param->data_type == OSSL_PARAM_INTEGER;

    if (signd) {
        if ((bit32 && !TEST_true(OSSL_PARAM_get_int32(param, &i32)))
            || !TEST_true(OSSL_PARAM_get_int64(param, &i64)))
            return 0;
    } else {
        if ((bit32
             && !TEST_true(OSSL_PARAM_get_uint32(param, (uint32_t *)&i32)))
            || !TEST_true(OSSL_PARAM_get_uint64(param, (uint64_t *)&i64))
            || (sizet && !TEST_true(OSSL_PARAM_get_size_t(param, &s))))
            return 0;
    }

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
    if (sizet && !signd) {
        copy_to_le(buf, &s, sizeof(s));
        sz = sizeof(s) < width ? sizeof(s) : width;
        if (!TEST_mem_eq(buf, sz, cmp, sz))
            return 0;
    }

    /* Check a widening write if possible */
    if (sizeof(size_t) > width) {
        if (signd) {
            if (!TEST_true(OSSL_PARAM_set_int32(param, 12345))
                || !TEST_true(OSSL_PARAM_get_int64(param, &i64))
                || !TEST_size_t_eq((size_t)i64, 12345))
                return 0;
        } else {
            if (!TEST_true(OSSL_PARAM_set_uint32(param, 12345))
                || !TEST_true(OSSL_PARAM_get_uint64(param, (uint64_t *)&i64))
                || !TEST_size_t_eq((size_t)i64, 12345))
                return 0;
        }
    }
    return 1;
}

/*
 * The test cases for each of the bastic integral types are similar.
 * For each type, a param of that type is set and an attempt to read it
 * get is made.  Finally, the above function is called to verify that
 * the params can be read as other types.
 *
 * All the real work is done via byte buffers which are converted to machine
 * byte order and to little endian for comparisons.  Narrower values are best
 * compared using little endian because their values and positions don't
 * change.
 */

static int test_param_int(int n)
{
    int in, out;
    unsigned char buf[MAX_LEN], le[MAX_LEN], cmp[sizeof(int)];
    const size_t len = raw_values[n].len >= sizeof(int) ?
                       sizeof(int) : raw_values[n].len;
    OSSL_PARAM param = OSSL_PARAM_int("a", NULL);

    memset(buf, 0, sizeof(buf));
    memset(le, 0, sizeof(le));
    copy_be_to_native(buf, raw_values[n].value, len);
    swap_copy(le, raw_values[n].value, len);
    memcpy(&in, buf, sizeof(in));
    param.data = &out;
    if (!TEST_true(OSSL_PARAM_set_int(&param, in)))
        return 0;
    copy_to_le(cmp, &out, sizeof(out));
    if (!TEST_mem_eq(cmp, len, le, len))
        return 0;
    in = 0;
    param.data = buf;
    if (!TEST_true(OSSL_PARAM_get_int(&param, &in)))
        return 0;
    copy_to_le(cmp, &in, sizeof(in));
    if (!TEST_mem_eq(cmp, sizeof(in), le, sizeof(in)))
        return 0;
    param.data = &out;
    return test_param_type_extra(&param, le, sizeof(int));
}

static int test_param_long(int n)
{
    long int in, out;
    unsigned char buf[MAX_LEN], le[MAX_LEN], cmp[sizeof(long int)];
    const size_t len = raw_values[n].len >= sizeof(long int)
                       ? sizeof(long int) : raw_values[n].len;
    OSSL_PARAM param = OSSL_PARAM_long("a", NULL);

    memset(buf, 0, sizeof(buf));
    memset(le, 0, sizeof(le));
    copy_be_to_native(buf, raw_values[n].value, len);
    swap_copy(le, raw_values[n].value, len);
    memcpy(&in, buf, sizeof(in));
    param.data = &out;
    if (!TEST_true(OSSL_PARAM_set_long(&param, in)))
        return 0;
    copy_to_le(cmp, &out, sizeof(out));
    if (!TEST_mem_eq(cmp, len, le, len))
        return 0;
    in = 0;
    param.data = buf;
    if (!TEST_true(OSSL_PARAM_get_long(&param, &in)))
        return 0;
    copy_to_le(cmp, &in, sizeof(in));
    if (!TEST_mem_eq(cmp, sizeof(in), le, sizeof(in)))
        return 0;
    param.data = &out;
    return test_param_type_extra(&param, le, sizeof(long int));
}

static int test_param_uint(int n)
{
    unsigned int in, out;
    unsigned char buf[MAX_LEN], le[MAX_LEN], cmp[sizeof(unsigned int)];
    const size_t len = raw_values[n].len >= sizeof(unsigned int) ? sizeof(unsigned int) : raw_values[n].len;
    OSSL_PARAM param = OSSL_PARAM_uint("a", NULL);
    memset(buf, 0, sizeof(buf));
    memset(le, 0, sizeof(le));
    copy_be_to_native(buf, raw_values[n].value, len);
    swap_copy(le, raw_values[n].value, len);
    memcpy(&in, buf, sizeof(in));
    param.data = &out;
    if (!TEST_true(OSSL_PARAM_set_uint(&param, in)))
        return 0;
    copy_to_le(cmp, &out, sizeof(out));
    if (!TEST_mem_eq(cmp, len, le, len))
        return 0;
    in = 0;
    param.data = buf;
    if (!TEST_true(OSSL_PARAM_get_uint(&param, &in)))
        return 0;
    copy_to_le(cmp, &in, sizeof(in));
    if (!TEST_mem_eq(cmp, sizeof(in), le, sizeof(in)))
        return 0;
    param.data = &out;
    return test_param_type_extra(&param, le, sizeof(unsigned int));
}

static int test_param_ulong(int n)
{
    unsigned long int in, out;
    unsigned char buf[MAX_LEN], le[MAX_LEN], cmp[sizeof(unsigned long int)];
    const size_t len = raw_values[n].len >= sizeof(unsigned long int)
                       ? sizeof(unsigned long int) : raw_values[n].len;
    OSSL_PARAM param = OSSL_PARAM_ulong("a", NULL);
    memset(buf, 0, sizeof(buf));
    memset(le, 0, sizeof(le));
    copy_be_to_native(buf, raw_values[n].value, len);
    swap_copy(le, raw_values[n].value, len);
    memcpy(&in, buf, sizeof(in));
    param.data = &out;
    if (!TEST_true(OSSL_PARAM_set_ulong(&param, in)))
        return 0;
    copy_to_le(cmp, &out, sizeof(out));
    if (!TEST_mem_eq(cmp, len, le, len))
        return 0;
    in = 0;
    param.data = buf;
    if (!TEST_true(OSSL_PARAM_get_ulong(&param, &in)))
        return 0;
    copy_to_le(cmp, &in, sizeof(in));
    if (!TEST_mem_eq(cmp, sizeof(in), le, sizeof(in)))
        return 0;
    param.data = &out;
    return test_param_type_extra(&param, le, sizeof(unsigned long int));
}

static int test_param_int32(int n)
{
    int32_t in, out;
    unsigned char buf[MAX_LEN], le[MAX_LEN], cmp[sizeof(int32_t)];
    const size_t len = raw_values[n].len >= sizeof(int32_t)
                       ? sizeof(int32_t) : raw_values[n].len;
    OSSL_PARAM param = OSSL_PARAM_int32("a", NULL);
    memset(buf, 0, sizeof(buf));
    memset(le, 0, sizeof(le));
    copy_be_to_native(buf, raw_values[n].value, len);
    swap_copy(le, raw_values[n].value, len);
    memcpy(&in, buf, sizeof(in));
    param.data = &out;
    if (!TEST_true(OSSL_PARAM_set_int32(&param, in)))
        return 0;
    copy_to_le(cmp, &out, sizeof(out));
    if (!TEST_mem_eq(cmp, len, le, len))
        return 0;
    in = 0;
    param.data = buf;
    if (!TEST_true(OSSL_PARAM_get_int32(&param, &in)))
        return 0;
    copy_to_le(cmp, &in, sizeof(in));
    if (!TEST_mem_eq(cmp, sizeof(in), le, sizeof(in)))
        return 0;
    param.data = &out;
    return test_param_type_extra(&param, le, sizeof(int32_t));
}

static int test_param_uint32(int n)
{
    uint32_t in, out;
    unsigned char buf[MAX_LEN], le[MAX_LEN], cmp[sizeof(uint32_t)];
    const size_t len = raw_values[n].len >= sizeof(uint32_t)
                       ? sizeof(uint32_t) : raw_values[n].len;
    OSSL_PARAM param = OSSL_PARAM_uint32("a", NULL);
    memset(buf, 0, sizeof(buf));
    memset(le, 0, sizeof(le));
    copy_be_to_native(buf, raw_values[n].value, len);
    swap_copy(le, raw_values[n].value, len);
    memcpy(&in, buf, sizeof(in));
    param.data = &out;
    if (!TEST_true(OSSL_PARAM_set_uint32(&param, in)))
        return 0;
    copy_to_le(cmp, &out, sizeof(out));
    if (!TEST_mem_eq(cmp, len, le, len))
        return 0;
    in = 0;
    param.data = buf;
    if (!TEST_true(OSSL_PARAM_get_uint32(&param, &in)))
        return 0;
    copy_to_le(cmp, &in, sizeof(in));
    if (!TEST_mem_eq(cmp, sizeof(in), le, sizeof(in)))
        return 0;
    param.data = &out;
    return test_param_type_extra(&param, le, sizeof(uint32_t));
}

static int test_param_int64(int n)
{
    int64_t in, out;
    unsigned char buf[MAX_LEN], le[MAX_LEN], cmp[sizeof(int64_t)];
    const size_t len = raw_values[n].len >= sizeof(int64_t)
                       ? sizeof(int64_t) : raw_values[n].len;
    OSSL_PARAM param = OSSL_PARAM_int64("a", NULL);
    memset(buf, 0, sizeof(buf));
    memset(le, 0, sizeof(le));
    copy_be_to_native(buf, raw_values[n].value, len);
    swap_copy(le, raw_values[n].value, len);
    memcpy(&in, buf, sizeof(in));
    param.data = &out;
    if (!TEST_true(OSSL_PARAM_set_int64(&param, in)))
        return 0;
    copy_to_le(cmp, &out, sizeof(out));
    if (!TEST_mem_eq(cmp, len, le, len))
        return 0;
    in = 0;
    param.data = buf;
    if (!TEST_true(OSSL_PARAM_get_int64(&param, &in)))
        return 0;
    copy_to_le(cmp, &in, sizeof(in));
    if (!TEST_mem_eq(cmp, sizeof(in), le, sizeof(in)))
        return 0;
    param.data = &out;
    return test_param_type_extra(&param, le, sizeof(int64_t));
}

static int test_param_uint64(int n)
{
    uint64_t in, out;
    unsigned char buf[MAX_LEN], le[MAX_LEN], cmp[sizeof(uint64_t)];
    const size_t len = raw_values[n].len >= sizeof(uint64_t)
                       ? sizeof(uint64_t) : raw_values[n].len;
    OSSL_PARAM param = OSSL_PARAM_uint64("a", NULL);
    memset(buf, 0, sizeof(buf));
    memset(le, 0, sizeof(le));
    copy_be_to_native(buf, raw_values[n].value, len);
    swap_copy(le, raw_values[n].value, len);
    memcpy(&in, buf, sizeof(in));
    param.data = &out;
    if (!TEST_true(OSSL_PARAM_set_uint64(&param, in)))
        return 0;
    copy_to_le(cmp, &out, sizeof(out));
    if (!TEST_mem_eq(cmp, len, le, len))
        return 0;
    in = 0;
    param.data = buf;
    if (!TEST_true(OSSL_PARAM_get_uint64(&param, &in)))
        return 0;
    copy_to_le(cmp, &in, sizeof(in));
    if (!TEST_mem_eq(cmp, sizeof(in), le, sizeof(in)))
        return 0;
    param.data = &out;
    return test_param_type_extra(&param, le, sizeof(uint64_t));
}

static int test_param_size_t(int n)
{
    size_t in, out;
    unsigned char buf[MAX_LEN], le[MAX_LEN], cmp[sizeof(size_t)];
    const size_t len = raw_values[n].len >= sizeof(size_t)
                       ? sizeof(size_t) : raw_values[n].len;
    OSSL_PARAM param = OSSL_PARAM_size_t("a", NULL);
    memset(buf, 0, sizeof(buf));
    memset(le, 0, sizeof(le));
    copy_be_to_native(buf, raw_values[n].value, len);
    swap_copy(le, raw_values[n].value, len);
    memcpy(&in, buf, sizeof(in));
    param.data = &out;
    if (!TEST_true(OSSL_PARAM_set_size_t(&param, in)))
        return 0;
    copy_to_le(cmp, &out, sizeof(out));
    if (!TEST_mem_eq(cmp, len, le, len))
        return 0;
    in = 0;
    param.data = buf;
    if (!TEST_true(OSSL_PARAM_get_size_t(&param, &in)))
        return 0;
    copy_to_le(cmp, &in, sizeof(in));
    if (!TEST_mem_eq(cmp, sizeof(in), le, sizeof(in)))
        return 0;
    param.data = &out;
    return test_param_type_extra(&param, le, sizeof(size_t));
}

static int test_param_bignum(int n)
{
    unsigned char buf[MAX_LEN], bnbuf[MAX_LEN], le[MAX_LEN];
    const size_t len = raw_values[n].len;
    size_t bnsize;
    BIGNUM *b = NULL, *c = NULL;
    OSSL_PARAM param = OSSL_PARAM_DEFN("bn", OSSL_PARAM_UNSIGNED_INTEGER,
                                       NULL, 0, NULL);
    int ret = 0;

    param.data = bnbuf;
    param.data_size = len;
    param.return_size = &bnsize;

    copy_be_to_native(buf, raw_values[n].value, len);
    swap_copy(le, raw_values[n].value, len);
    if (!TEST_ptr(b = BN_bin2bn(raw_values[n].value, (int)len, NULL)))
        goto err;

    if (!TEST_true(OSSL_PARAM_set_BN(&param, b))
        || !TEST_mem_eq(bnbuf, bnsize, buf, bnsize))
        goto err;
    param.data_size = *param.return_size;
    if (!TEST_true(OSSL_PARAM_get_BN(&param, &c))
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

    param.data = &p;
    return TEST_true(OSSL_PARAM_set_double(&param, 3.14159))
           && TEST_double_eq(p, 3.14159);
}

/*
 * The tests are a bit special in that they are trying to do both sides
 * of the param passing.  This means that the OSSL_PARAM structure needs to
 * be updated so that a get call matches size with the corresponding set call.
 * This is not a problem in normal usage because the owner of the OSSL_PARAM
 * "knows" the size of what it wants to put in and gets the size back via the
 * return_size pointer when it needs to get data out.  That is, the owner
 * does not need to call these APIs since it has direct access.
 *
 * The result is that the tests need the locate call to return a non-const
 * pointer at times.  Hence the cast here.
 */
static OSSL_PARAM *locate(OSSL_PARAM *p, const char *name)
{
    return (OSSL_PARAM *)OSSL_PARAM_locate(p, name);
}

static int test_param_construct(void)
{
    static const char *int_names[] = {
        "int", "long", "int32", "int64"
    };
    static const char *uint_names[] = {
        "uint", "ulong", "uint32", "uint64", "size_t"
    };
    static const unsigned char bn_val[16] = {
        0xac, 0x75, 0x22, 0x7d, 0x81, 0x06, 0x7a, 0x23,
        0xa6, 0xed, 0x87, 0xc7, 0xab, 0xf4, 0x73, 0x22
    };
    OSSL_PARAM params[20];
    char buf[100], buf2[100], *bufp, *bufp2;
    unsigned char ubuf[100];
    void *vp, *vpn = NULL, *vp2;
    OSSL_PARAM *p;
    const OSSL_PARAM *cp;
    static const OSSL_PARAM pend = OSSL_PARAM_END;
    int i, n = 0, ret = 0;
    unsigned int u;
    long int l;
    unsigned long int ul;
    int32_t i32;
    uint32_t u32;
    int64_t i64;
    uint64_t u64;
    size_t j, k, s, sz;
    double d, d2;
    BIGNUM *bn = NULL, *bn2 = NULL;

    params[n++] = OSSL_PARAM_construct_int("int", &i, &sz);
    params[n++] = OSSL_PARAM_construct_uint("uint", &u, &sz);
    params[n++] = OSSL_PARAM_construct_long("long", &l, &sz);
    params[n++] = OSSL_PARAM_construct_ulong("ulong", &ul, &sz);
    params[n++] = OSSL_PARAM_construct_int32("int32", &i32, &sz);
    params[n++] = OSSL_PARAM_construct_int64("int64", &i64, &sz);
    params[n++] = OSSL_PARAM_construct_uint32("uint32", &u32, &sz);
    params[n++] = OSSL_PARAM_construct_uint64("uint64", &u64, &sz);
    params[n++] = OSSL_PARAM_construct_size_t("size_t", &s, &sz);
    params[n++] = OSSL_PARAM_construct_double("double", &d, &sz);
    params[n++] = OSSL_PARAM_construct_BN("bignum", ubuf, sizeof(ubuf), &sz);
    params[n++] = OSSL_PARAM_construct_utf8_string("utf8str", buf, sizeof(buf),
                                                   &sz);
    params[n++] = OSSL_PARAM_construct_octet_string("octstr", buf, sizeof(buf),
                                                    &sz);
    params[n++] = OSSL_PARAM_construct_utf8_ptr("utf8ptr", &bufp, &sz);
    params[n++] = OSSL_PARAM_construct_octet_ptr("octptr", &vp, &sz);
    params[n] = pend;

    /* Search failure */
    if (!TEST_ptr_null(OSSL_PARAM_locate(params, "fnord")))
        goto err;

    /* All signed integral types */
    for (j = 0; j < OSSL_NELEM(int_names); j++) {
        if (!TEST_ptr(cp = OSSL_PARAM_locate(params, int_names[j]))
            || !TEST_true(OSSL_PARAM_set_int32(cp, (int32_t)(3 + j)))
            || !TEST_true(OSSL_PARAM_get_int64(cp, &i64))
            || !TEST_size_t_eq(cp->data_size, sz)
            || !TEST_size_t_eq((size_t)i64, 3 + j)) {
            TEST_note("iteration %zu var %s", j + 1, int_names[j]);
            goto err;
        }
    }
    /* All unsigned integral types */
    for (j = 0; j < OSSL_NELEM(uint_names); j++) {
        if (!TEST_ptr(cp = OSSL_PARAM_locate(params, uint_names[j]))
            || !TEST_true(OSSL_PARAM_set_uint32(cp, (uint32_t)(3 + j)))
            || !TEST_true(OSSL_PARAM_get_uint64(cp, &u64))
            || !TEST_size_t_eq(cp->data_size, sz)
            || !TEST_size_t_eq((size_t)u64, 3 + j)) {
            TEST_note("iteration %zu var %s", j + 1, uint_names[j]);
            goto err;
        }
    }
    /* Real */
    if (!TEST_ptr(cp = OSSL_PARAM_locate(params, "double"))
        || !TEST_true(OSSL_PARAM_set_double(cp, 3.14))
        || !TEST_true(OSSL_PARAM_get_double(cp, &d2))
        || !TEST_size_t_eq(sz, sizeof(double))
        || !TEST_double_eq(d, d2))
        goto err;
    /* UTF8 string */
    bufp = NULL;
    if (!TEST_ptr(cp = OSSL_PARAM_locate(params, "utf8str"))
        || !TEST_true(OSSL_PARAM_set_utf8_string(cp, "abcdef"))
        || !TEST_size_t_eq(sz, sizeof("abcdef"))
        || !TEST_true(OSSL_PARAM_get_utf8_string(cp, &bufp, 0))
        || !TEST_str_eq(bufp, "abcdef"))
        goto err;
    OPENSSL_free(bufp);
    bufp = buf2;
    if (!TEST_true(OSSL_PARAM_get_utf8_string(cp, &bufp, sizeof(buf2)))
        || !TEST_str_eq(buf2, "abcdef"))
        goto err;
    /* UTF8 pointer */
    bufp = buf;
    sz = 0;
    if (!TEST_ptr(cp = OSSL_PARAM_locate(params, "utf8ptr"))
        || !TEST_true(OSSL_PARAM_set_utf8_ptr(cp, "tuvwxyz"))
        || !TEST_size_t_eq(sz, sizeof("tuvwxyz"))
        || !TEST_str_eq(bufp, "tuvwxyz")
        || !TEST_true(OSSL_PARAM_get_utf8_ptr(cp, (const char **)&bufp2))
        || !TEST_ptr_eq(bufp2, bufp))
        goto err;
    /* OCTET string */
    if (!TEST_ptr(p = locate(params, "octstr"))
        || !TEST_true(OSSL_PARAM_set_octet_string(p, "abcdefghi",
                                                  sizeof("abcdefghi")))
        || !TEST_size_t_eq(sz, sizeof("abcdefghi")))
        goto err;
    /* Match the return size to avoid trailing garbage bytes */
    p->data_size = *p->return_size;
    if (!TEST_true(OSSL_PARAM_get_octet_string(p, &vpn, 0, &s))
        || !TEST_size_t_eq(s, sizeof("abcdefghi"))
        || !TEST_mem_eq(vpn, sizeof("abcdefghi"),
                        "abcdefghi", sizeof("abcdefghi")))
        goto err;
    vp = buf2;
    if (!TEST_true(OSSL_PARAM_get_octet_string(p, &vp, sizeof(buf2), &s))
        || !TEST_size_t_eq(s, sizeof("abcdefghi"))
        || !TEST_mem_eq(vp, sizeof("abcdefghi"),
                        "abcdefghi", sizeof("abcdefghi")))
        goto err;
    /* OCTET pointer */
    vp = &l;
    sz = 0;
    if (!TEST_ptr(p = locate(params, "octptr"))
        || !TEST_true(OSSL_PARAM_set_octet_ptr(p, &ul, sizeof(ul)))
        || !TEST_size_t_eq(sz, sizeof(ul))
        || !TEST_ptr_eq(vp, &ul))
        goto err;
    /* Match the return size to avoid trailing garbage bytes */
    p->data_size = *p->return_size;
    if (!TEST_true(OSSL_PARAM_get_octet_ptr(p, (const void **)&vp2, &k))
        || !TEST_size_t_eq(k, sizeof(ul))
        || !TEST_ptr_eq(vp2, vp))
        goto err;
    /* BIGNUM */
    if (!TEST_ptr(p = locate(params, "bignum"))
        || !TEST_ptr(bn = BN_lebin2bn(bn_val, (int)sizeof(bn_val), NULL))
        || !TEST_true(OSSL_PARAM_set_BN(p, bn))
        || !TEST_size_t_eq(sz, sizeof(bn_val)))
        goto err;
    /* Match the return size to avoid trailing garbage bytes */
    p->data_size = *p->return_size;
    if(!TEST_true(OSSL_PARAM_get_BN(p, &bn2))
        || !TEST_BN_eq(bn, bn2))
        goto err;
    ret = 1;
err:
    OPENSSL_free(vpn);
    BN_free(bn);
    BN_free(bn2);
    return ret;
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
    ADD_TEST(test_param_construct);
    return 1;
}
