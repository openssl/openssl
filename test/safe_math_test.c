/*
 * Copyright 2021-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>

#include "internal/nelem.h"
#include "internal/safe_math.h"
#include "testutil.h"

/* Create the safe math instances we're interested in */
OSSL_SAFE_MATH_SIGNED(int, int)
OSSL_SAFE_MATH_UNSIGNED(uint, unsigned int)
OSSL_SAFE_MATH_UNSIGNED(size_t, size_t)
OSSL_SAFE_MATH_SIGNED(int64_t, int64_t)
OSSL_SAFE_MATH_UNSIGNED(uint64_t, uint64_t)

static const struct {
    int a, b;
    int sum_err, sub_err, mul_err, div_err, mod_err, div_round_up_err;
    int neg_a_err, neg_b_err, abs_a_err, abs_b_err;
} test_ints[] = {
    /*  +  -  *  /  %  /r -a -b |a||b|  */
    { 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { -1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, -3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { -1, -3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { -3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 2, -3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { -2, -3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { INT_MAX, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { INT_MAX, 2, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
    { INT_MAX, 4, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
    { INT_MAX - 3, 4, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
    { INT_MIN, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0 },
    { 1, INT_MIN, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1 },
    { INT_MIN, 2, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0 },
    { 2, INT_MIN, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1 },
    { INT_MIN, -1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0 },
    { INT_MAX, INT_MIN, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1 },
    { INT_MIN, INT_MAX, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0 },
    { 3, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0 },
};

static int test_int_ops(int n)
{
    int err, r, s;
    const int a = test_ints[n].a, b = test_ints[n].b;

    err = 0;
    r = safe_add_int(a, b, &err);
    if (!TEST_int_eq(err, test_ints[n].sum_err)
        || (!err && !TEST_int_eq(r, a + b)))
        goto err;

    err = 0;
    r = safe_sub_int(a, b, &err);
    if (!TEST_int_eq(err, test_ints[n].sub_err)
        || (!err && !TEST_int_eq(r, a - b)))
        goto err;

    err = 0;
    r = safe_mul_int(a, b, &err);
    if (!TEST_int_eq(err, test_ints[n].mul_err)
        || (!err && !TEST_int_eq(r, a * b)))
        goto err;

    err = 0;
    r = safe_div_int(a, b, &err);
    if (!TEST_int_eq(err, test_ints[n].div_err)
        || (!err && !TEST_int_eq(r, a / b)))
        goto err;

    err = 0;
    r = safe_mod_int(a, b, &err);
    if (!TEST_int_eq(err, test_ints[n].mod_err)
        || (!err && !TEST_int_eq(r, a % b)))
        goto err;

    err = 0;
    r = safe_div_round_up_int(a, b, &err);
    if (!TEST_int_eq(err, test_ints[n].div_round_up_err))
        goto err;
    s = safe_mod_int(a, b, &err);
    s = safe_add_int(safe_div_int(a, b, &err), s != 0, &err);
    if (!err && !TEST_int_eq(r, s))
        goto err;

    err = 0;
    r = safe_neg_int(a, &err);
    if (!TEST_int_eq(err, test_ints[n].neg_a_err)
        || (!err && !TEST_int_eq(r, -a)))
        goto err;

    err = 0;
    r = safe_neg_int(b, &err);
    if (!TEST_int_eq(err, test_ints[n].neg_b_err)
        || (!err && !TEST_int_eq(r, -b)))
        goto err;

    err = 0;
    r = safe_abs_int(a, &err);
    if (!TEST_int_eq(err, test_ints[n].abs_a_err)
        || (!err && !TEST_int_eq(r, a < 0 ? -a : a)))
        goto err;

    err = 0;
    r = safe_abs_int(b, &err);
    if (!TEST_int_eq(err, test_ints[n].abs_b_err)
        || (!err && !TEST_int_eq(r, b < 0 ? -b : b)))
        goto err;
    return 1;
err:
    TEST_info("a = %d  b = %d  r = %d  err = %d", a, b, r, err);
    return 0;
}

static const struct {
    unsigned int a, b;
    int sum_err, sub_err, mul_err, div_err, mod_err, div_round_up_err;
} test_uints[] = {
    /*  +  -  *  /  %  /r   */
    { 3, 1, 0, 0, 0, 0, 0, 0 },
    { 1, 3, 0, 1, 0, 0, 0, 0 },
    { UINT_MAX, 1, 1, 0, 0, 0, 0, 0 },
    { UINT_MAX, 2, 1, 0, 1, 0, 0, 0 },
    { UINT_MAX, 16, 1, 0, 1, 0, 0, 0 },
    { UINT_MAX - 13, 16, 1, 0, 1, 0, 0, 0 },
    { 1, UINT_MAX, 1, 1, 0, 0, 0, 0 },
    { 2, UINT_MAX, 1, 1, 1, 0, 0, 0 },
    { UINT_MAX, 0, 0, 0, 0, 1, 1, 1 },
};

static int test_uint_ops(int n)
{
    int err;
    unsigned int r;
    const unsigned int a = test_uints[n].a, b = test_uints[n].b;

    err = 0;
    r = safe_add_uint(a, b, &err);
    if (!TEST_int_eq(err, test_uints[n].sum_err)
        || (!err && !TEST_uint_eq(r, a + b)))
        goto err;

    err = 0;
    r = safe_sub_uint(a, b, &err);
    if (!TEST_int_eq(err, test_uints[n].sub_err)
        || (!err && !TEST_uint_eq(r, a - b)))
        goto err;

    err = 0;
    r = safe_mul_uint(a, b, &err);
    if (!TEST_int_eq(err, test_uints[n].mul_err)
        || (!err && !TEST_uint_eq(r, a * b)))
        goto err;

    err = 0;
    r = safe_div_uint(a, b, &err);
    if (!TEST_int_eq(err, test_uints[n].div_err)
        || (!err && !TEST_uint_eq(r, a / b)))
        goto err;

    err = 0;
    r = safe_mod_uint(a, b, &err);
    if (!TEST_int_eq(err, test_uints[n].mod_err)
        || (!err && !TEST_uint_eq(r, a % b)))
        goto err;

    err = 0;
    r = safe_div_round_up_uint(a, b, &err);
    if (!TEST_int_eq(err, test_uints[n].div_round_up_err)
        || (!err && !TEST_uint_eq(r, a / b + (a % b != 0))))
        goto err;

    err = 0;
    r = safe_neg_uint(a, &err);
    if (!TEST_int_eq(err, a != 0) || (!err && !TEST_uint_eq(r, 0)))
        goto err;

    err = 0;
    r = safe_neg_uint(b, &err);
    if (!TEST_int_eq(err, b != 0) || (!err && !TEST_uint_eq(r, 0)))
        goto err;

    err = 0;
    r = safe_abs_uint(a, &err);
    if (!TEST_int_eq(err, 0) || !TEST_uint_eq(r, a))
        goto err;

    err = 0;
    r = safe_abs_uint(b, &err);
    if (!TEST_int_eq(err, 0) || !TEST_uint_eq(r, b))
        goto err;
    return 1;
err:
    TEST_info("a = %u  b = %u  r = %u  err = %d", a, b, r, err);
    return 0;
}

static const struct {
    size_t a, b;
    int sum_err, sub_err, mul_err, div_err, mod_err, div_round_up_err;
} test_size_ts[] = {
    { 3, 1, 0, 0, 0, 0, 0, 0 },
    { 1, 3, 0, 1, 0, 0, 0, 0 },
    { 36, 8, 0, 0, 0, 0, 0, 0 },
    { SIZE_MAX, 1, 1, 0, 0, 0, 0, 0 },
    { SIZE_MAX, 2, 1, 0, 1, 0, 0, 0 },
    { SIZE_MAX, 8, 1, 0, 1, 0, 0, 0 },
    { SIZE_MAX - 3, 8, 1, 0, 1, 0, 0, 0 },
    { 1, SIZE_MAX, 1, 1, 0, 0, 0, 0 },
    { 2, SIZE_MAX, 1, 1, 1, 0, 0, 0 },
    { 11, 0, 0, 0, 0, 1, 1, 1 },
};

static int test_size_t_ops(int n)
{
    int err;
    size_t r;
    const size_t a = test_size_ts[n].a, b = test_size_ts[n].b;

    err = 0;
    r = safe_add_size_t(a, b, &err);
    if (!TEST_int_eq(err, test_size_ts[n].sum_err)
        || (!err && !TEST_size_t_eq(r, a + b)))
        goto err;

    err = 0;
    r = safe_sub_size_t(a, b, &err);
    if (!TEST_int_eq(err, test_size_ts[n].sub_err)
        || (!err && !TEST_size_t_eq(r, a - b)))
        goto err;

    err = 0;
    r = safe_mul_size_t(a, b, &err);
    if (!TEST_int_eq(err, test_size_ts[n].mul_err)
        || (!err && !TEST_size_t_eq(r, a * b)))
        goto err;

    err = 0;
    r = safe_div_size_t(a, b, &err);
    if (!TEST_int_eq(err, test_size_ts[n].div_err)
        || (!err && !TEST_size_t_eq(r, a / b)))
        goto err;

    err = 0;
    r = safe_mod_size_t(a, b, &err);
    if (!TEST_int_eq(err, test_size_ts[n].mod_err)
        || (!err && !TEST_size_t_eq(r, a % b)))
        goto err;

    err = 0;
    r = safe_div_round_up_size_t(a, b, &err);
    if (!TEST_int_eq(err, test_size_ts[n].div_round_up_err)
        || (!err && !TEST_size_t_eq(r, a / b + (a % b != 0))))
        goto err;

    err = 0;
    r = safe_neg_size_t(a, &err);
    if (!TEST_int_eq(err, a != 0) || (!err && !TEST_size_t_eq(r, 0)))
        goto err;

    err = 0;
    r = safe_neg_size_t(b, &err);
    if (!TEST_int_eq(err, b != 0) || (!err && !TEST_size_t_eq(r, 0)))
        goto err;

    err = 0;
    r = safe_abs_size_t(a, &err);
    if (!TEST_int_eq(err, 0) || !TEST_size_t_eq(r, a))
        goto err;

    err = 0;
    r = safe_abs_size_t(b, &err);
    if (!TEST_int_eq(err, 0) || !TEST_size_t_eq(r, b))
        goto err;
    return 1;
err:
    TEST_info("a = %zu  b = %zu  r = %zu  err = %d", a, b, r, err);
    return 0;
}

static const struct {
    int a, b, c;
    int err;
    int result;
} test_muldiv_ints[] = {
    { 3, 1, 2, 0, 1 },
    { 1, 3, 2, 0, 1 },
    { -3, 1, 2, 0, -1 },
    { 1, 3, -2, 0, -1 },
    { INT_MAX, INT_MAX, INT_MAX, 0, INT_MAX },
    { INT_MIN, INT_MIN, INT_MAX, 1, 0 },
    { INT_MIN, INT_MIN, INT_MIN, 0, INT_MIN },
    { INT_MAX, 2, 4, 0, INT_MAX / 2 },
    { 8, INT_MAX, 4, 1, 0 },
    { INT_MIN, 2, 4, 0, INT_MIN / 2 },
    { 8, INT_MIN, 4, 1, 0 },
    { INT_MIN, -1, INT_MIN, 0, -1 },
    { INT_MIN, -1, 2, 0, -(INT_MIN / 2) },
    { INT_MIN, -1, -1, 0, INT_MIN },
    { INT_MIN, 1, -1, 1, 0 },
    { INT_MIN, 2, 2, 0, INT_MIN },
    { INT_MIN, 2, -2, 1, 0 },
    { INT_MAX - 1, INT_MAX - 1, INT_MAX, 0, INT_MAX - 2 },
    { -(INT_MAX - 1), INT_MAX - 1, INT_MAX, 0, -(INT_MAX - 2) },
    { INT_MAX - 1, INT_MAX - 1, -INT_MAX, 0, -(INT_MAX - 2) },
    { -(INT_MAX - 1), INT_MAX - 1, -INT_MAX, 0, INT_MAX - 2 },
    { -(INT_MAX - 1), -(INT_MAX - 1), INT_MAX, 0, INT_MAX - 2 },
    { -(INT_MAX - 1), -(INT_MAX - 1), -INT_MAX, 0, -(INT_MAX - 2) },
    { INT_MAX, INT_MAX / 2 + 1, INT_MAX / 2 + 1, 0, INT_MAX },
    { INT_MIN, INT_MAX, INT_MIN, 0, INT_MAX },
    { INT_MAX, INT_MAX, INT_MIN, 0, -(INT_MAX - 1) },
    { INT_MAX, INT_MAX, 1, 1, 0 },
    { -INT_MAX, INT_MAX, 1, 1, 0 },
    { 0, INT_MIN, -1, 0, 0 },
    { INT_MAX, 0, INT_MIN, 0, 0 },
    { 3, 4, 0, 1, 0 },
    { 0, 4, 0, 1, 0 },
    { 3, 0, 0, 1, 0 },
    { 0, 0, 0, 1, 0 },
    /* Minimum products and overflowing intermediate products. */
    { INT_MIN / 2, 2, 4, 0, INT_MIN / 4 },
    { -2, INT_MAX / 2 + 1, 3, 0, INT_MIN / 3 },
    { INT_MIN / 2, 2, INT_MIN, 0, 1 },
    { INT_MIN / 2, 2, -1, 1, 0 },
    { INT_MIN / 2, -4, -2, 0, INT_MIN },
};

static int test_int_muldiv(int n)
{
    const int a = test_muldiv_ints[n].a;
    const int b = test_muldiv_ints[n].b;
    const int c = test_muldiv_ints[n].c;
    int initial, swap, err;
    int r;

    for (initial = 0; initial <= 2; initial += 2) {
        for (swap = 0; swap < 2; swap++) {
            err = initial;
            r = safe_muldiv_int(swap ? b : a, swap ? a : b, c, &err);
            if (!TEST_int_eq(err, initial | test_muldiv_ints[n].err)
                || (!test_muldiv_ints[n].err
                    && !TEST_int_eq(r, test_muldiv_ints[n].result))
                || (c == 0 && !TEST_int_eq(r, a == 0 || b == 0 ? 0 : INT_MAX))) {
                TEST_info("case %d: initial error = %d, swap = %d", n, initial, swap);
                return 0;
            }
        }
    }
    return 1;
}

static const struct {
    unsigned int a, b, c;
    int err;
    unsigned int result;
} test_muldiv_uints[] = {
    { 3, 1, 2, 0, 1 },
    { 1, 3, 2, 0, 1 },
    { UINT_MAX, UINT_MAX, UINT_MAX, 0, UINT_MAX },
    { UINT_MAX, 2, 4, 0, UINT_MAX / 2 },
    { 8, UINT_MAX, 4, 1, 0 },
    { UINT_MAX - 1, UINT_MAX - 1, UINT_MAX, 0, UINT_MAX - 2 },
    { UINT_MAX, UINT_MAX / 2 + 1, UINT_MAX / 2 + 1, 0, UINT_MAX },
    { UINT_MAX, UINT_MAX, 1, 1, 0 },
    { UINT_MAX, UINT_MAX, UINT_MAX - 1, 1, 0 },
    { 0, UINT_MAX, 1, 0, 0 },
    { UINT_MAX, 0, UINT_MAX, 0, 0 },
    { 3, 4, 0, 1, 0 },
    { 0, 4, 0, 1, 0 },
    { 3, 0, 0, 1, 0 },
    { 0, 0, 0, 1, 0 },
};

static int test_uint_muldiv(int n)
{
    const unsigned int a = test_muldiv_uints[n].a;
    const unsigned int b = test_muldiv_uints[n].b;
    const unsigned int c = test_muldiv_uints[n].c;
    int initial, swap, err;
    unsigned int r;

    for (initial = 0; initial <= 2; initial += 2) {
        for (swap = 0; swap < 2; swap++) {
            err = initial;
            r = safe_muldiv_uint(swap ? b : a, swap ? a : b, c, &err);
            if (!TEST_int_eq(err, initial | test_muldiv_uints[n].err)
                || (!test_muldiv_uints[n].err
                    && !TEST_uint_eq(r, test_muldiv_uints[n].result))
                || (c == 0 && !TEST_uint_eq(r, a == 0 || b == 0 ? 0 : UINT_MAX))) {
                TEST_info("case %d: initial error = %d, swap = %d", n, initial, swap);
                return 0;
            }
        }
    }
    return 1;
}

static const struct {
    int64_t a, b, c;
    int err;
    int64_t result;
} test_muldiv_int64_ts[] = {
    { 3, 1, 2, 0, 1 },
    { 1, 3, 2, 0, 1 },
    { -3, 1, 2, 0, -1 },
    { 1, 3, -2, 0, -1 },
    { INT64_MAX, INT64_MAX, INT64_MAX, 0, INT64_MAX },
    { INT64_MIN, INT64_MIN, INT64_MAX, 1, 0 },
    { INT64_MIN, INT64_MIN, INT64_MIN, 0, INT64_MIN },
    { INT64_MAX, 2, 4, 0, INT64_MAX / 2 },
    { 8, INT64_MAX, 4, 1, 0 },
    { INT64_MIN, 2, 4, 0, INT64_MIN / 2 },
    { 8, INT64_MIN, 4, 1, 0 },
    { INT64_MIN, -1, INT64_MIN, 0, -1 },
    { INT64_MIN, -1, 2, 0, -(INT64_MIN / 2) },
    { INT64_MIN, -1, -1, 0, INT64_MIN },
    { INT64_MIN, 1, -1, 1, 0 },
    { INT64_MIN, 2, 2, 0, INT64_MIN },
    { INT64_MIN, 2, -2, 1, 0 },
    { INT64_MAX - 1, INT64_MAX - 1, INT64_MAX, 0, INT64_MAX - 2 },
    { -(INT64_MAX - 1), INT64_MAX - 1, INT64_MAX, 0, -(INT64_MAX - 2) },
    { INT64_MAX - 1, INT64_MAX - 1, -INT64_MAX, 0, -(INT64_MAX - 2) },
    { -(INT64_MAX - 1), INT64_MAX - 1, -INT64_MAX, 0, INT64_MAX - 2 },
    { -(INT64_MAX - 1), -(INT64_MAX - 1), INT64_MAX, 0, INT64_MAX - 2 },
    { -(INT64_MAX - 1), -(INT64_MAX - 1), -INT64_MAX, 0, -(INT64_MAX - 2) },
    { INT64_MAX, INT64_MAX / 2 + 1, INT64_MAX / 2 + 1, 0, INT64_MAX },
    { INT64_MIN, INT64_MAX, INT64_MIN, 0, INT64_MAX },
    { INT64_MAX, INT64_MAX, INT64_MIN, 0, -(INT64_MAX - 1) },
    { INT64_MAX, INT64_MAX, 1, 1, 0 },
    { -INT64_MAX, INT64_MAX, 1, 1, 0 },
    { 0, INT64_MIN, -1, 0, 0 },
    { INT64_MAX, 0, INT64_MIN, 0, 0 },
    { 3, 4, 0, 1, 0 },
    { 0, 4, 0, 1, 0 },
    { 3, 0, 0, 1, 0 },
    { 0, 0, 0, 1, 0 },
    /* Minimum products and overflowing intermediate products. */
    { INT64_MIN / 2, 2, 4, 0, INT64_MIN / 4 },
    { -2, INT64_MAX / 2 + 1, 3, 0, INT64_MIN / 3 },
    { INT64_MIN / 2, 2, INT64_MIN, 0, 1 },
    { INT64_MIN / 2, 2, -1, 1, 0 },
    { INT64_MIN / 2, -4, -2, 0, INT64_MIN },
};

static int test_int64_t_muldiv(int n)
{
    const int64_t a = test_muldiv_int64_ts[n].a;
    const int64_t b = test_muldiv_int64_ts[n].b;
    const int64_t c = test_muldiv_int64_ts[n].c;
    int initial, swap, err;
    int64_t r;

    for (initial = 0; initial <= 2; initial += 2) {
        for (swap = 0; swap < 2; swap++) {
            err = initial;
            r = safe_muldiv_int64_t(swap ? b : a, swap ? a : b, c, &err);
            if (!TEST_int_eq(err, initial | test_muldiv_int64_ts[n].err)
                || (!test_muldiv_int64_ts[n].err
                    && !TEST_int64_t_eq(r, test_muldiv_int64_ts[n].result))
                || (c == 0 && !TEST_int64_t_eq(r, a == 0 || b == 0 ? 0 : INT64_MAX))) {
                TEST_info("case %d: initial error = %d, swap = %d", n, initial, swap);
                return 0;
            }
        }
    }
    return 1;
}

static const struct {
    uint64_t a, b, c;
    int err;
    uint64_t result;
} test_muldiv_uint64_ts[] = {
    { 3, 1, 2, 0, 1 },
    { 1, 3, 2, 0, 1 },
    { UINT64_MAX, UINT64_MAX, UINT64_MAX, 0, UINT64_MAX },
    { UINT64_MAX, 2, 4, 0, UINT64_MAX / 2 },
    { 8, UINT64_MAX, 4, 1, 0 },
    { UINT64_MAX - 1, UINT64_MAX - 1, UINT64_MAX, 0, UINT64_MAX - 2 },
    { UINT64_MAX, UINT64_MAX / 2 + 1, UINT64_MAX / 2 + 1, 0, UINT64_MAX },
    { UINT64_MAX, UINT64_MAX, 1, 1, 0 },
    { UINT64_MAX, UINT64_MAX, UINT64_MAX - 1, 1, 0 },
    { 0, UINT64_MAX, 1, 0, 0 },
    { UINT64_MAX, 0, UINT64_MAX, 0, 0 },
    { 3, 4, 0, 1, 0 },
    { 0, 4, 0, 1, 0 },
    { 3, 0, 0, 1, 0 },
    { 0, 0, 0, 1, 0 },
};

static int test_uint64_t_muldiv(int n)
{
    const uint64_t a = test_muldiv_uint64_ts[n].a;
    const uint64_t b = test_muldiv_uint64_ts[n].b;
    const uint64_t c = test_muldiv_uint64_ts[n].c;
    int initial, swap, err;
    uint64_t r;

    for (initial = 0; initial <= 2; initial += 2) {
        for (swap = 0; swap < 2; swap++) {
            err = initial;
            r = safe_muldiv_uint64_t(swap ? b : a, swap ? a : b, c, &err);
            if (!TEST_int_eq(err, initial | test_muldiv_uint64_ts[n].err)
                || (!test_muldiv_uint64_ts[n].err
                    && !TEST_uint64_t_eq(r, test_muldiv_uint64_ts[n].result))
                || (c == 0 && !TEST_uint64_t_eq(r, a == 0 || b == 0 ? 0 : UINT64_MAX))) {
                TEST_info("case %d: initial error = %d, swap = %d", n, initial, swap);
                return 0;
            }
        }
    }
    return 1;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_int_ops, OSSL_NELEM(test_ints));
    ADD_ALL_TESTS(test_uint_ops, OSSL_NELEM(test_uints));
    ADD_ALL_TESTS(test_size_t_ops, OSSL_NELEM(test_size_ts));
    ADD_ALL_TESTS(test_int_muldiv, OSSL_NELEM(test_muldiv_ints));
    ADD_ALL_TESTS(test_uint_muldiv, OSSL_NELEM(test_muldiv_uints));
    ADD_ALL_TESTS(test_int64_t_muldiv, OSSL_NELEM(test_muldiv_int64_ts));
    ADD_ALL_TESTS(test_uint64_t_muldiv, OSSL_NELEM(test_muldiv_uint64_ts));
    return 1;
}
