/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file API tests of OSSL_FN
 *
 * This tests the OSSL_FN "public" API, i.e. anything that only requires
 * including crypto/fn.h.  including crypto/fn_intern.h is included too,
 * for introspection.
 */

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "crypto/fn.h"
#include "crypto/fn_intern.h"
#include "crypto/fnerr.h"
#include "testutil.h"

/*
 * Helper to pollute a number before writing to it.
 * This is a destructive function, use with care!
 */
static int pollute(OSSL_FN *f, size_t start, size_t end)
{
    /* Constness deliberately violated here */
    OSSL_FN_ULONG *u = (OSSL_FN_ULONG *)ossl_fn_get_words(f);
    size_t l = ossl_fn_get_dsize(f);

    if (end > l)
        end = l;
    if (start > end)
        start = end;

    unsigned char tmp_char;
    (void)RAND_bytes(&tmp_char, 1);
    memset(u + start, tmp_char, sizeof(OSSL_FN_ULONG) * (end - start));
    return 1;
}

static int check_limbs_value(const OSSL_FN *f, size_t start, size_t end,
    OSSL_FN_ULONG value)
{
    const OSSL_FN_ULONG *u = ossl_fn_get_words(f);
    size_t l = ossl_fn_get_dsize(f);

    if (end > l)
        end = l;
    if (start > end)
        start = end;

    for (size_t i = start; i < end; i++)
        if (!TEST_size_t_eq(u[i], value)) {
            TEST_note("start = %zu, end = %zu, i = %zu\n", start, end, i);
            return 0;
        }
    return 1;
}

/* A set of numbers on OSSL_FN_ULONG array form */
/* $num0 = 0x8000000000000001 */
static const OSSL_FN_ULONG num0[] = { OSSL_FN_ULONG64_C(0x80000000, 0x00000001) };
/* $num1 = 0x0000000180000000 */
static const OSSL_FN_ULONG num1[] = { OSSL_FN_ULONG64_C(0x00000001, 0x80000000) };
/* $num2 = 0x0123456789abcdef */
static const OSSL_FN_ULONG num2[] = { OSSL_FN_ULONG64_C(0x01234567, 0x89abcdef) };
/* $num3 = 0x76543210fedcba98 */
static const OSSL_FN_ULONG num3[] = { OSSL_FN_ULONG64_C(0xfedcba98, 0x76543210) };

/* Numbers for edge cases */
/* $num4 = 0x0000000000000000 */
static const OSSL_FN_ULONG num4[] = { OSSL_FN_ULONG64_C(0x00000000, 0x00000000) };
/* $num5 = 0xffffffffffffffff */
static const OSSL_FN_ULONG num5[] = { OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff) };
/* $num6 = 0x10000000000000000000000000000000 */
static const OSSL_FN_ULONG num6[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x10000000, 0x00000000),
};
/* [32-bit] $num7 = 0xffffffff00000000000000000000000000000000 */
/* [64-bit] $num7 = 0xffffffffffffffff00000000000000000000000000000000 */
static const OSSL_FN_ULONG num7[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
#if OSSL_FN_BYTES == 4
    OSSL_FN_ULONG_C(0xffffffff)
#elif OSSL_FN_BYTES == 8
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff)
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif
};
static const OSSL_FN_ULONG num8[] = {
    OSSL_FN_ULONG64_C(0x01234567, 0x89abcdef),
    OSSL_FN_ULONG_C(0x00000001),
};

/*
 * For each test function using predefined numbers, set up an
 * arrays of test cases to simply run through, and call common
 * test function for the operation being tested.
 *
 * All sizes are in number of limbs, the LIMBSOF() macro is there to help
 */
#define LIMBSOF(num) ((sizeof(num) + OSSL_FN_BYTES - 1) / OSSL_FN_BYTES)
#define OSSL_FN_BITS (OSSL_FN_BYTES * 8)
struct test_case_st {
    /* Two operands and expected full result (possibly two numbers) */
    const OSSL_FN_ULONG *op1;
    size_t op1_size;
    const OSSL_FN_ULONG *op2;
    size_t op2_size;
    const OSSL_FN_ULONG *ex1;
    size_t ex1_size;
    const OSSL_FN_ULONG *ex2;
    size_t ex2_size;

    /* Setup sizes for creating OSSL_FNs */
    size_t op1_live_size;
    size_t op2_live_size;
    size_t res1_live_size;
    size_t res2_live_size;

    /* Number of limbs to compare the result's OSSL_FN_ULONG array against ex1 and ex2 */
    size_t check1_size;
    size_t check2_size;

    /* When the result is larger than check1_size or check2_size, the expected extended value */
    OSSL_FN_ULONG extended_limb_value1;
    OSSL_FN_ULONG extended_limb_value2;
#define EXTENDED_LIMB_ZERO ((OSSL_FN_ULONG)0)
#define EXTENDED_LIMB_MINUS_ONE ((OSSL_FN_ULONG)-1)
};

struct mod_op_test_st {
    const OSSL_FN_ULONG *a;
    size_t a_size;
    const OSSL_FN_ULONG *b;
    size_t b_size;
    const OSSL_FN_ULONG *m;
    size_t m_size;
    int n;
};

/* $num0 + $num0 == 0x10000000000000002 */
static const OSSL_FN_ULONG ex_add_num0_num0[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000002),
    OSSL_FN_ULONG_C(0x1),
};
/* $num0 + $num1 == 0x8000000180000001 */
static const OSSL_FN_ULONG ex_add_num0_num1[] = {
    OSSL_FN_ULONG64_C(0x80000001, 0x80000001),
};
/* $num0 + $num2 == 0x8123456789abcdf0 */
static const OSSL_FN_ULONG ex_add_num0_num2[] = {
    OSSL_FN_ULONG64_C(0x81234567, 0x89abcdf0),
};
/* $num0 + $num3 == 0x17edcba9876543211 */
static const OSSL_FN_ULONG ex_add_num0_num3[] = {
    OSSL_FN_ULONG64_C(0x7edcba98, 0x76543211),
    OSSL_FN_ULONG_C(0x1),
};
static const OSSL_FN_ULONG ex_add_num1_num1[] = {
    OSSL_FN_ULONG64_C(0x00000003, 0x00000000),
};
static const OSSL_FN_ULONG ex_add_num1_num2[] = {
    OSSL_FN_ULONG64_C(0x01234569, 0x09abcdef),
};
static const OSSL_FN_ULONG ex_add_num1_num3[] = {
    OSSL_FN_ULONG64_C(0xfedcba99, 0xf6543210),
};
static const OSSL_FN_ULONG ex_add_num2_num2[] = {
    OSSL_FN_ULONG64_C(0x02468acf, 0x13579bde),
};
static const OSSL_FN_ULONG ex_add_num2_num3[] = {
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff),
};
static const OSSL_FN_ULONG ex_add_num3_num3[] = {
    OSSL_FN_ULONG64_C(0xfdb97530, 0xeca86420),
    OSSL_FN_ULONG_C(0x1),
};
static const OSSL_FN_ULONG ex_add_num0_num7[] = {
    OSSL_FN_ULONG64_C(0x80000000, 0x00000001),
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
#if OSSL_FN_BYTES == 4
    OSSL_FN_ULONG_C(0xffffffff)
#elif OSSL_FN_BYTES == 8
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff)
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif
};

static int test_add_common(struct test_case_st test_case)
{
    const OSSL_FN_ULONG *n1 = test_case.op1;
    size_t n1_limbs = test_case.op1_size;
    const OSSL_FN_ULONG *n2 = test_case.op2;
    size_t n2_limbs = test_case.op2_size;
    const OSSL_FN_ULONG *ex = test_case.ex1;
    size_t n1_new_limbs = test_case.op1_live_size;
    size_t n2_new_limbs = test_case.op2_live_size;
    size_t res_limbs = test_case.res1_live_size;
    size_t check_limbs = test_case.check1_size;
    OSSL_FN_ULONG extended_value = test_case.extended_limb_value1;
    int ret = 1;
    OSSL_FN *fn1 = NULL, *fn2 = NULL, *res = NULL;
    const OSSL_FN_ULONG *u = NULL;

    /* To test that OSSL_FN_add() does a complete job, 'res' is pre-polluted */

    if (!TEST_ptr(fn1 = OSSL_FN_new_limbs(n1_new_limbs))
        || !TEST_ptr(fn2 = OSSL_FN_new_limbs(n2_new_limbs))
        || !TEST_true(ossl_fn_set_words(fn1, n1, n1_limbs))
        || !TEST_true(ossl_fn_set_words(fn2, n2, n2_limbs))
        || !TEST_ptr(res = OSSL_FN_new_limbs(res_limbs))
        || !TEST_true(pollute(res, 0, res_limbs))) {
        ret = 0;
        /* There's no way to continue tests in this case */
        goto end;
    }

    if (!TEST_true(OSSL_FN_add(res, fn1, fn2))
        || !TEST_ptr(u = ossl_fn_get_words(res))
        || !TEST_mem_eq(u, check_limbs * OSSL_FN_BYTES,
            ex, check_limbs * OSSL_FN_BYTES)
        || !TEST_true(check_limbs_value(res, check_limbs, res_limbs,
            extended_value)))
        ret = 0;

end:
    OSSL_FN_free(fn1);
    OSSL_FN_free(fn2);
    OSSL_FN_free(res);

    return ret;
}

#define ADD_CASE(i, op1, op2, ex)                      \
    {                                                  \
        /* op1 */ op1,                                 \
        /* op1_size */ LIMBSOF(op1),                   \
        /* op2 */ op2,                                 \
        /* op2_size */ LIMBSOF(op2),                   \
        /* ex1 */ ex,                                  \
        /* ex1_size */ LIMBSOF(ex),                    \
        /* ex2 */ NULL,                                \
        /* ex2_size */ 0,                              \
        /* op1_live_size */ LIMBSOF(op1) + 1,          \
        /* op2_live_size */ LIMBSOF(op2) + 2,          \
        /* res1_live_size */ LIMBSOF(ex) + 3,          \
        /* res2_live_size */ 0,                        \
        /* check1_size */ LIMBSOF(ex),                 \
        /* check2_size */ 0,                           \
        /* extended_limb_value1 */ EXTENDED_LIMB_ZERO, \
        /* extended_limb_value2 */ 0,                  \
    }

static struct test_case_st test_add_cases[] = {
    ADD_CASE(1, num0, num0, ex_add_num0_num0),
    ADD_CASE(2, num0, num1, ex_add_num0_num1),
    ADD_CASE(3, num0, num2, ex_add_num0_num2),
    ADD_CASE(4, num0, num3, ex_add_num0_num3),
    ADD_CASE(5, num1, num0, ex_add_num0_num1), /* Commutativity check */
    ADD_CASE(6, num1, num1, ex_add_num1_num1),
    ADD_CASE(7, num1, num2, ex_add_num1_num2),
    ADD_CASE(8, num1, num3, ex_add_num1_num3),
    ADD_CASE(9, num2, num0, ex_add_num0_num2), /* Commutativity check */
    ADD_CASE(10, num2, num1, ex_add_num1_num2), /* Commutativity check */
    ADD_CASE(11, num2, num2, ex_add_num2_num2),
    ADD_CASE(12, num2, num3, ex_add_num2_num3),
    ADD_CASE(13, num3, num0, ex_add_num0_num3), /* Commutativity check */
    ADD_CASE(14, num3, num1, ex_add_num1_num3), /* Commutativity check */
    ADD_CASE(15, num3, num2, ex_add_num2_num3), /* Commutativity check */
    ADD_CASE(16, num3, num3, ex_add_num3_num3),
    ADD_CASE(17, num0, num7, ex_add_num0_num7),
};

static int test_add(int i)
{
    return test_add_common(test_add_cases[i]);
}

#define ADD_TRUNCATED_CASE(i, op1, op2, ex)            \
    {                                                  \
        /* op1 */ op1,                                 \
        /* op1_size */ LIMBSOF(op1),                   \
        /* op2 */ op2,                                 \
        /* op2_size */ LIMBSOF(op2),                   \
        /* ex1 */ ex,                                  \
        /* ex1_size */ LIMBSOF(ex),                    \
        /* ex2 */ NULL,                                \
        /* ex2_size */ 0,                              \
        /* op1_live_size */ LIMBSOF(op1) + 1,          \
        /* op2_live_size */ LIMBSOF(op2) + 2,          \
        /* res1_live_size */ LIMBSOF(ex) - 1,          \
        /* res2_live_size */ 0,                        \
        /* check1_size */ LIMBSOF(ex) - 1,             \
        /* check2_size */ 0,                           \
        /* extended_limb_value1 */ EXTENDED_LIMB_ZERO, \
        /* extended_limb_value2 */ 0,                  \
    }

static struct test_case_st test_add_truncated_cases[] = {
    ADD_TRUNCATED_CASE(1, num0, num0, ex_add_num0_num0),
    ADD_TRUNCATED_CASE(2, num0, num1, ex_add_num0_num1),
    ADD_TRUNCATED_CASE(3, num0, num2, ex_add_num0_num2),
    ADD_TRUNCATED_CASE(4, num0, num3, ex_add_num0_num3),
    ADD_TRUNCATED_CASE(5, num1, num0, ex_add_num0_num1), /* Commutativity check */
    ADD_TRUNCATED_CASE(6, num1, num1, ex_add_num1_num1),
    ADD_TRUNCATED_CASE(7, num1, num2, ex_add_num1_num2),
    ADD_TRUNCATED_CASE(8, num1, num3, ex_add_num1_num3),
    ADD_TRUNCATED_CASE(9, num2, num0, ex_add_num0_num2), /* Commutativity check */
    ADD_TRUNCATED_CASE(10, num2, num1, ex_add_num1_num2), /* Commutativity check */
    ADD_TRUNCATED_CASE(11, num2, num2, ex_add_num2_num2),
    ADD_TRUNCATED_CASE(12, num2, num3, ex_add_num2_num3),
    ADD_TRUNCATED_CASE(13, num3, num0, ex_add_num0_num3), /* Commutativity check */
    ADD_TRUNCATED_CASE(14, num3, num1, ex_add_num1_num3), /* Commutativity check */
    ADD_TRUNCATED_CASE(15, num3, num2, ex_add_num2_num3), /* Commutativity check */
    ADD_TRUNCATED_CASE(16, num3, num3, ex_add_num3_num3),
    ADD_TRUNCATED_CASE(17, num0, num7, ex_add_num0_num7),
};

static int test_add_truncated(int i)
{
    return test_add_common(test_add_truncated_cases[i]);
}

static const OSSL_FN_ULONG ex_sub_num0_num0[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
static const OSSL_FN_ULONG ex_sub_num0_num1[] = {
    OSSL_FN_ULONG64_C(0x7ffffffe, 0x80000001),
};
static const OSSL_FN_ULONG ex_sub_num0_num2[] = {
    OSSL_FN_ULONG64_C(0x7edcba98, 0x76543212),
};
static const OSSL_FN_ULONG ex_sub_num0_num3[] = {
    OSSL_FN_ULONG64_C(0x81234567, 0x89abcdf1),
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff)
};
static const OSSL_FN_ULONG ex_sub_num1_num0[] = {
    OSSL_FN_ULONG64_C(0x80000001, 0x7fffffff),
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff),
};
static const OSSL_FN_ULONG ex_sub_num1_num1[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
static const OSSL_FN_ULONG ex_sub_num1_num2[] = {
    OSSL_FN_ULONG64_C(0xfedcba99, 0xf6543211),
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff),
};
static const OSSL_FN_ULONG ex_sub_num1_num3[] = {
    OSSL_FN_ULONG64_C(0x01234569, 0x09abcdf0),
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff),
};
static const OSSL_FN_ULONG ex_sub_num2_num0[] = {
    OSSL_FN_ULONG64_C(0x81234567, 0x89abcdee),
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff),
};
static const OSSL_FN_ULONG ex_sub_num2_num1[] = {
    OSSL_FN_ULONG64_C(0x01234566, 0x09abcdef),
};
static const OSSL_FN_ULONG ex_sub_num2_num2[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
static const OSSL_FN_ULONG ex_sub_num2_num3[] = {
    OSSL_FN_ULONG64_C(0x02468acf, 0x13579bdf),
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff),
};
static const OSSL_FN_ULONG ex_sub_num3_num0[] = {
    OSSL_FN_ULONG64_C(0x7edcba98, 0x7654320f),
};
static const OSSL_FN_ULONG ex_sub_num3_num1[] = {
    OSSL_FN_ULONG64_C(0xfedcba96, 0xf6543210),
};
static const OSSL_FN_ULONG ex_sub_num3_num2[] = {
    OSSL_FN_ULONG64_C(0xfdb97530, 0xeca86421),
};
static const OSSL_FN_ULONG ex_sub_num3_num3[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
static const OSSL_FN_ULONG ex_sub_num0_num7[] = {
    OSSL_FN_ULONG64_C(0x80000000, 0x00000001),
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG_C(0x1),
};
static const OSSL_FN_ULONG ex_sub_num7_num0[] = {
    OSSL_FN_ULONG64_C(0x7fffffff, 0xffffffff),
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff),
#if OSSL_FN_BYTES == 4
    OSSL_FN_ULONG_C(0xfffffffe)
#elif OSSL_FN_BYTES == 8
    OSSL_FN_ULONG64_C(0xffffffff, 0xfffffffe)
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif
};

/* $num2 << 1 == 0x02468acf13579bde */
static const OSSL_FN_ULONG ex_lshift1_num2[] = {
    OSSL_FN_ULONG64_C(0x02468acf, 0x13579bde),
};
/* $num0 << 1 == 0x10000000000000002 */
static const OSSL_FN_ULONG ex_lshift1_num0[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000002),
    OSSL_FN_ULONG_C(0x1),
};
/* $num2 << 4 == 0x123456789abcdef0 */
static const OSSL_FN_ULONG ex_lshift_num2_4[] = {
    OSSL_FN_ULONG64_C(0x12345678, 0x9abcdef0),
};
#if OSSL_FN_BYTES == 4
/* $num2 << 32 == 0x0123456789abcdef00000000 */
static const OSSL_FN_ULONG ex_lshift_num2_limb[] = {
    OSSL_FN_ULONG_C(0x00000000),
    OSSL_FN_ULONG_C(0x89abcdef),
    OSSL_FN_ULONG_C(0x01234567),
};
#elif OSSL_FN_BYTES == 8
/* $num2 << 64 == 0x0123456789abcdef0000000000000000 */
static const OSSL_FN_ULONG ex_lshift_num2_limb[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x01234567, 0x89abcdef),
};
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif
#if OSSL_FN_BYTES == 4
/* $num2 << 35 == 0x091a2b3c4d5e6f7800000000 */
static const OSSL_FN_ULONG ex_lshift_num2_limb_3[] = {
    OSSL_FN_ULONG_C(0x00000000),
    OSSL_FN_ULONG_C(0x4d5e6f78),
    OSSL_FN_ULONG_C(0x091a2b3c),
};
#elif OSSL_FN_BYTES == 8
/* $num2 << 67 == 0x091a2b3c4d5e6f780000000000000000 */
static const OSSL_FN_ULONG ex_lshift_num2_limb_3[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x091a2b3c, 0x4d5e6f78),
};
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif

/* $num2 >> 1 == 0x0091a2b3c4d5e6f7 */
static const OSSL_FN_ULONG ex_rshift1_num2[] = {
    OSSL_FN_ULONG64_C(0x0091a2b3, 0xc4d5e6f7),
};
/* $num8 >> 1 == 0x000000008091a2b3c4d5e6f7 */
static const OSSL_FN_ULONG ex_rshift1_num8[] = {
    OSSL_FN_ULONG64_C(0x8091a2b3, 0xc4d5e6f7),
};
/* $num2 >> 4 == 0x00123456789abcde */
static const OSSL_FN_ULONG ex_rshift_num2_4[] = {
    OSSL_FN_ULONG64_C(0x00123456, 0x789abcde),
};
#if OSSL_FN_BYTES == 4
/* $num8 >> 32 == 0x0000000101234567 */
static const OSSL_FN_ULONG ex_rshift_num8_limb[] = {
    OSSL_FN_ULONG_C(0x01234567),
    OSSL_FN_ULONG_C(0x00000001),
};
#elif OSSL_FN_BYTES == 8
/* $num8 >> 64 == 0x0000000000000001 */
static const OSSL_FN_ULONG ex_rshift_num8_limb[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000001),
};
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif
#if OSSL_FN_BYTES == 4
/* $num8 >> 35 == 0x00000000202468ac */
static const OSSL_FN_ULONG ex_rshift_num8_limb_3[] = {
    OSSL_FN_ULONG_C(0x202468ac),
};
#elif OSSL_FN_BYTES == 8
/* $num8 >> 67 == 0x0000000000000000 */
static const OSSL_FN_ULONG ex_rshift_num8_limb_3[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif
#if OSSL_FN_BYTES == 4
/* $num2 >> 32 == 0x01234567 */
static const OSSL_FN_ULONG ex_rshift_num2_limb[] = {
    OSSL_FN_ULONG_C(0x01234567),
    OSSL_FN_ULONG_C(0x00000000),
};
#elif OSSL_FN_BYTES == 8
/* $num2 >> 64 == 0x0000000000000000 */
static const OSSL_FN_ULONG ex_rshift_num2_limb[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif
/* Expected all-zero result for shifts beyond the operand's width. */
static const OSSL_FN_ULONG ex_rshift_zero[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};

static int test_sub_common(struct test_case_st test_case)
{
    const OSSL_FN_ULONG *n1 = test_case.op1;
    size_t n1_limbs = test_case.op1_size;
    const OSSL_FN_ULONG *n2 = test_case.op2;
    size_t n2_limbs = test_case.op2_size;
    const OSSL_FN_ULONG *ex = test_case.ex1;
    size_t n1_new_limbs = test_case.op1_live_size;
    size_t n2_new_limbs = test_case.op2_live_size;
    size_t res_limbs = test_case.res1_live_size;
    size_t check_limbs = test_case.check1_size;
    OSSL_FN_ULONG extended_value = test_case.extended_limb_value1;
    int ret = 1;
    OSSL_FN *fn1 = NULL, *fn2 = NULL, *res = NULL;
    const OSSL_FN_ULONG *u = NULL;

    /* To test that OSSL_FN_sub() does a complete job, 'res' is pre-polluted */

    if (!TEST_ptr(fn1 = OSSL_FN_new_limbs(n1_new_limbs))
        || !TEST_ptr(fn2 = OSSL_FN_new_limbs(n2_new_limbs))
        || !TEST_true(ossl_fn_set_words(fn1, n1, n1_limbs))
        || !TEST_true(ossl_fn_set_words(fn2, n2, n2_limbs))
        || !TEST_ptr(res = OSSL_FN_new_limbs(res_limbs))
        || !TEST_true(pollute(res, 0, res_limbs))) {
        ret = 0;
        /* There's no way to continue tests in this case */
        goto end;
    }

    if (!TEST_true(OSSL_FN_sub(res, fn1, fn2))
        || !TEST_ptr(u = ossl_fn_get_words(res))
        || !TEST_mem_eq(u, check_limbs * OSSL_FN_BYTES,
            ex, check_limbs * OSSL_FN_BYTES)
        || !TEST_true(check_limbs_value(res, check_limbs, res_limbs,
            extended_value)))
        ret = 0;

end:
    OSSL_FN_free(fn1);
    OSSL_FN_free(fn2);
    OSSL_FN_free(res);

    return ret;
}

#define SUB_CASE(i, op1, op2, ex, ext)        \
    {                                         \
        /* op1 */ op1,                        \
        /* op1_size */ LIMBSOF(op1),          \
        /* op2 */ op2,                        \
        /* op2_size */ LIMBSOF(op2),          \
        /* ex1 */ ex,                         \
        /* ex1_size */ LIMBSOF(ex),           \
        /* ex2 */ NULL,                       \
        /* ex2_size */ 0,                     \
        /* op1_live_size */ LIMBSOF(op1) + 1, \
        /* op2_live_size */ LIMBSOF(op2) + 2, \
        /* res1_live_size */ LIMBSOF(ex) + 3, \
        /* res2_live_size */ 0,               \
        /* check1_size */ LIMBSOF(ex),        \
        /* check2_size */ 0,                  \
        /* extended_limb_value1 */ (ext),     \
        /* extended_limb_value2 */ 0,         \
    }

static struct test_case_st test_sub_cases[] = {
    SUB_CASE(1, num0, num0, ex_sub_num0_num0, EXTENDED_LIMB_ZERO),
    SUB_CASE(2, num0, num1, ex_sub_num0_num1, EXTENDED_LIMB_ZERO),
    SUB_CASE(3, num0, num2, ex_sub_num0_num2, EXTENDED_LIMB_ZERO),
    SUB_CASE(4, num0, num3, ex_sub_num0_num3, EXTENDED_LIMB_MINUS_ONE),
    SUB_CASE(5, num1, num0, ex_sub_num1_num0, EXTENDED_LIMB_MINUS_ONE),
    SUB_CASE(6, num1, num1, ex_sub_num1_num1, EXTENDED_LIMB_ZERO),
    SUB_CASE(7, num1, num2, ex_sub_num1_num2, EXTENDED_LIMB_MINUS_ONE),
    SUB_CASE(8, num1, num3, ex_sub_num1_num3, EXTENDED_LIMB_MINUS_ONE),
    SUB_CASE(9, num2, num0, ex_sub_num2_num0, EXTENDED_LIMB_MINUS_ONE),
    SUB_CASE(10, num2, num1, ex_sub_num2_num1, EXTENDED_LIMB_ZERO),
    SUB_CASE(11, num2, num2, ex_sub_num2_num2, EXTENDED_LIMB_ZERO),
    SUB_CASE(12, num2, num3, ex_sub_num2_num3, EXTENDED_LIMB_MINUS_ONE),
    SUB_CASE(13, num3, num0, ex_sub_num3_num0, EXTENDED_LIMB_ZERO),
    SUB_CASE(14, num3, num1, ex_sub_num3_num1, EXTENDED_LIMB_ZERO),
    SUB_CASE(15, num3, num2, ex_sub_num3_num2, EXTENDED_LIMB_ZERO),
    SUB_CASE(16, num3, num3, ex_sub_num3_num3, EXTENDED_LIMB_ZERO),
    SUB_CASE(17, num0, num7, ex_sub_num0_num7, EXTENDED_LIMB_MINUS_ONE),
    SUB_CASE(18, num7, num0, ex_sub_num7_num0, EXTENDED_LIMB_ZERO),
};

static int test_sub(int i)
{
    return test_sub_common(test_sub_cases[i]);
}

#define SUB_TRUNCATED_CASE(i, op1, op2, ex)            \
    {                                                  \
        /* op1 */ op1,                                 \
        /* op1_size */ LIMBSOF(op1),                   \
        /* op2 */ op2,                                 \
        /* op2_size */ LIMBSOF(op2),                   \
        /* ex1 */ ex,                                  \
        /* ex1_size */ LIMBSOF(ex),                    \
        /* ex2 */ NULL,                                \
        /* ex2_size */ 0,                              \
        /* op1_live_size */ LIMBSOF(op1) + 1,          \
        /* op2_live_size */ LIMBSOF(op2) + 2,          \
        /* res1_live_size */ LIMBSOF(ex) - 1,          \
        /* res2_live_size */ 0,                        \
        /* check1_size */ LIMBSOF(ex) - 1,             \
        /* check2_size */ 0,                           \
        /* extended_limb_value1 */ EXTENDED_LIMB_ZERO, \
        /* extended_limb_value2 */ 0,                  \
    }

static struct test_case_st test_sub_truncated_cases[] = {
    SUB_TRUNCATED_CASE(1, num0, num0, ex_sub_num0_num0),
    SUB_TRUNCATED_CASE(2, num0, num1, ex_sub_num0_num1),
    SUB_TRUNCATED_CASE(3, num0, num2, ex_sub_num0_num2),
    SUB_TRUNCATED_CASE(4, num0, num3, ex_sub_num0_num3),
    SUB_TRUNCATED_CASE(5, num1, num0, ex_sub_num1_num0),
    SUB_TRUNCATED_CASE(6, num1, num1, ex_sub_num1_num1),
    SUB_TRUNCATED_CASE(7, num1, num2, ex_sub_num1_num2),
    SUB_TRUNCATED_CASE(8, num1, num3, ex_sub_num1_num3),
    SUB_TRUNCATED_CASE(9, num2, num0, ex_sub_num2_num0),
    SUB_TRUNCATED_CASE(10, num2, num1, ex_sub_num2_num1),
    SUB_TRUNCATED_CASE(11, num2, num2, ex_sub_num2_num2),
    SUB_TRUNCATED_CASE(12, num2, num3, ex_sub_num2_num3),
    SUB_TRUNCATED_CASE(13, num3, num0, ex_sub_num3_num0),
    SUB_TRUNCATED_CASE(14, num3, num1, ex_sub_num3_num1),
    SUB_TRUNCATED_CASE(15, num3, num2, ex_sub_num3_num2),
    SUB_TRUNCATED_CASE(16, num3, num3, ex_sub_num3_num3),
    SUB_TRUNCATED_CASE(17, num0, num7, ex_sub_num0_num7),
    SUB_TRUNCATED_CASE(18, num7, num0, ex_sub_num7_num0),
};

static int test_sub_truncated(int i)
{
    return test_sub_common(test_sub_truncated_cases[i]);
}

static int test_num_bits(void)
{
    int ret = 0;
    OSSL_FN *zero = NULL, *fn1 = NULL, *fn2 = NULL, *wide = NULL;

    if (!TEST_ptr(zero = OSSL_FN_new_limbs(2))
        || !TEST_ptr(fn1 = OSSL_FN_new_limbs(2))
        || !TEST_ptr(fn2 = OSSL_FN_new_limbs(2))
        || !TEST_ptr(wide = OSSL_FN_new_limbs(4))
        || !TEST_true(ossl_fn_set_words(fn1, num1, LIMBSOF(num1)))
        || !TEST_true(ossl_fn_set_words(fn2, num2, LIMBSOF(num2)))
        || !TEST_true(ossl_fn_set_words(wide, num8, LIMBSOF(num8))))
        goto err;

    if (!TEST_size_t_eq(OSSL_FN_num_bits(zero), 0)
        || !TEST_size_t_eq(OSSL_FN_num_bits(fn1), 33)
        || !TEST_size_t_eq(OSSL_FN_num_bits(fn2), 57)
        || !TEST_size_t_eq(OSSL_FN_num_bits(wide), 65))
        goto err;

    ret = 1;
err:
    OSSL_FN_free(zero);
    OSSL_FN_free(fn1);
    OSSL_FN_free(fn2);
    OSSL_FN_free(wide);
    return ret;
}

static int test_cmp(void)
{
    int ret = 0;
    OSSL_FN *zero = NULL, *fn1 = NULL, *fn1_wide = NULL, *fn2 = NULL;
    OSSL_FN *fn2_wide = NULL;

    if (!TEST_ptr(zero = OSSL_FN_new_limbs(2))
        || !TEST_ptr(fn1 = OSSL_FN_new_limbs(2))
        || !TEST_ptr(fn1_wide = OSSL_FN_new_limbs(4))
        || !TEST_ptr(fn2 = OSSL_FN_new_limbs(2))
        || !TEST_ptr(fn2_wide = OSSL_FN_new_limbs(4))
        || !TEST_true(ossl_fn_set_words(fn1, num1, LIMBSOF(num1)))
        || !TEST_true(ossl_fn_set_words(fn1_wide, num1, LIMBSOF(num1)))
        || !TEST_true(ossl_fn_set_words(fn2, num2, LIMBSOF(num2)))
        || !TEST_true(ossl_fn_set_words(fn2_wide, num2, LIMBSOF(num2))))
        goto err;

    if (!TEST_int_eq(OSSL_FN_cmp(zero, zero), 0)
        || !TEST_int_eq(OSSL_FN_cmp(fn2, fn2_wide), 0)
        || !TEST_int_eq(OSSL_FN_cmp(fn2_wide, fn2), 0)
        || !TEST_int_eq(OSSL_FN_cmp(fn2, fn1), 1)
        || !TEST_int_eq(OSSL_FN_cmp(fn1, fn2), -1)
        || !TEST_int_eq(OSSL_FN_cmp(fn2_wide, fn1), 1)
        || !TEST_int_eq(OSSL_FN_cmp(fn1, fn2_wide), -1)
        || !TEST_int_eq(OSSL_FN_cmp(fn2, fn1_wide), 1)
        || !TEST_int_eq(OSSL_FN_cmp(fn1_wide, fn2), -1)
        || !TEST_int_eq(OSSL_FN_cmp(zero, fn1), -1)
        || !TEST_int_eq(OSSL_FN_cmp(fn1, zero), 1))
        goto err;

    ret = 1;
err:
    OSSL_FN_free(zero);
    OSSL_FN_free(fn1);
    OSSL_FN_free(fn1_wide);
    OSSL_FN_free(fn2);
    OSSL_FN_free(fn2_wide);
    return ret;
}

/*-
 * Focused tests for the OSSL_FN introspection predicates: is_word, is_zero,
 * is_one, is_odd.  Covers plain values, fixed-top zero-padding (a value
 * whose high limbs are zero limbs by dsize rather than by trimming), and the
 * dsize == 0 (zero-limb) degenerate case.
 */
static int test_introspection(void)
{
    int ret = 0;
    OSSL_FN *z = NULL; /* dsize 2, value 0 */
    OSSL_FN *z_wide = NULL; /* dsize 4, value 0 (fixed-top zero padding) */
    OSSL_FN *z_empty = NULL; /* dsize 0, value 0 */
    OSSL_FN *one = NULL; /* dsize 2, value 1 */
    OSSL_FN *one_wide = NULL; /* dsize 4, value 1 (fixed-top zero padding) */
    OSSL_FN *w5 = NULL; /* dsize 2, value 5 */
    OSSL_FN *w5_wide = NULL; /* dsize 4, value 5 (fixed-top zero padding) */
    OSSL_FN *even = NULL; /* dsize 2, value 0x...76543210 (even) */
    OSSL_FN *odd = NULL; /* dsize 2, value 0x...01234567 (odd) */
    OSSL_FN *two_limbs = NULL; /* dsize 2, value 0x...76543210 fedcba98 (nonzero high limb) */
    OSSL_FN_ULONG one_word = OSSL_FN_ULONG_C(1);
    OSSL_FN_ULONG five_word = OSSL_FN_ULONG_C(5);
    OSSL_FN_ULONG even_word = OSSL_FN_ULONG_C(0x76543210);
    OSSL_FN_ULONG odd_word = OSSL_FN_ULONG_C(0x01234567);
    const OSSL_FN_ULONG two_limbs_words[] = {
        OSSL_FN_ULONG_C(0x76543210),
        OSSL_FN_ULONG_C(0xfedcba98)
    };

    if (!TEST_ptr(z = OSSL_FN_new_limbs(2))
        || !TEST_ptr(z_wide = OSSL_FN_new_limbs(4))
        || !TEST_ptr(z_empty = OSSL_FN_new_limbs(0))
        || !TEST_ptr(one = OSSL_FN_new_limbs(2))
        || !TEST_ptr(one_wide = OSSL_FN_new_limbs(4))
        || !TEST_ptr(w5 = OSSL_FN_new_limbs(2))
        || !TEST_ptr(w5_wide = OSSL_FN_new_limbs(4))
        || !TEST_ptr(even = OSSL_FN_new_limbs(2))
        || !TEST_ptr(odd = OSSL_FN_new_limbs(2))
        || !TEST_ptr(two_limbs = OSSL_FN_new_limbs(2)))
        goto err;

    /* All fresh allocations are zero-initialised, so z, z_wide, z_empty are 0. */
    if (!TEST_true(ossl_fn_set_words(one, &one_word, 1))
        || !TEST_true(ossl_fn_set_words(one_wide, &one_word, 1))
        || !TEST_true(ossl_fn_set_words(w5, &five_word, 1))
        || !TEST_true(ossl_fn_set_words(w5_wide, &five_word, 1))
        || !TEST_true(ossl_fn_set_words(even, &even_word, 1))
        || !TEST_true(ossl_fn_set_words(odd, &odd_word, 1))
        || !TEST_true(ossl_fn_set_words(two_limbs, two_limbs_words,
            LIMBSOF(two_limbs_words))))
        goto err;

    /* OSSL_FN_is_zero */
    if (!TEST_int_eq(OSSL_FN_is_zero(z), 1)
        || !TEST_int_eq(OSSL_FN_is_zero(z_wide), 1) /* fixed-top zero padding */
        || !TEST_int_eq(OSSL_FN_is_zero(z_empty), 1) /* dsize == 0 */
        || !TEST_int_eq(OSSL_FN_is_zero(one), 0)
        || !TEST_int_eq(OSSL_FN_is_zero(w5_wide), 0))
        goto err;

    /* OSSL_FN_is_one */
    if (!TEST_int_eq(OSSL_FN_is_one(one), 1)
        || !TEST_int_eq(OSSL_FN_is_one(one_wide), 1) /* fixed-top zero padding */
        || !TEST_int_eq(OSSL_FN_is_one(z), 0)
        || !TEST_int_eq(OSSL_FN_is_one(w5), 0)
        || !TEST_int_eq(OSSL_FN_is_one(z_empty), 0))
        goto err;

    /* OSSL_FN_is_word -- value equality against a single-limb word */
    if (!TEST_int_eq(OSSL_FN_is_word(z, 0), 1)
        || !TEST_int_eq(OSSL_FN_is_word(z_wide, 0), 1) /* fixed-top zero padding */
        || !TEST_int_eq(OSSL_FN_is_word(z_empty, 0), 1)
        || !TEST_int_eq(OSSL_FN_is_word(z, 1), 0)
        || !TEST_int_eq(OSSL_FN_is_word(one, 1), 1)
        || !TEST_int_eq(OSSL_FN_is_word(one_wide, 1), 1) /* fixed-top zero padding */
        || !TEST_int_eq(OSSL_FN_is_word(one, 0), 0)
        || !TEST_int_eq(OSSL_FN_is_word(w5, 5), 1)
        || !TEST_int_eq(OSSL_FN_is_word(w5_wide, 5), 1) /* fixed-top zero padding */
        || !TEST_int_eq(OSSL_FN_is_word(w5, 1), 0)
        /* A value whose high limb is nonzero is not equal to a single word. */
        || !TEST_int_eq(OSSL_FN_is_word(two_limbs, even_word), 0)
        || !TEST_int_eq(OSSL_FN_is_word(two_limbs, 0), 0))
        goto err;

    /* OSSL_FN_is_odd */
    if (!TEST_int_eq(OSSL_FN_is_odd(one), 1)
        || !TEST_int_eq(OSSL_FN_is_odd(odd), 1)
        || !TEST_int_eq(OSSL_FN_is_odd(w5), 1)
        || !TEST_int_eq(OSSL_FN_is_odd(z), 0)
        || !TEST_int_eq(OSSL_FN_is_odd(z_wide), 0)
        || !TEST_int_eq(OSSL_FN_is_odd(z_empty), 0)
        || !TEST_int_eq(OSSL_FN_is_odd(even), 0))
        goto err;

    ret = 1;
err:
    OSSL_FN_free(z);
    OSSL_FN_free(z_wide);
    OSSL_FN_free(z_empty);
    OSSL_FN_free(one);
    OSSL_FN_free(one_wide);
    OSSL_FN_free(w5);
    OSSL_FN_free(w5_wide);
    OSSL_FN_free(even);
    OSSL_FN_free(odd);
    OSSL_FN_free(two_limbs);
    return ret;
}

/*-
 * Focused tests for OSSL_FN_add_word() / OSSL_FN_sub_word().  Each case is
 * cross-checked against OSSL_FN_add() / OSSL_FN_sub() with a single-limb
 * operand, an independent oracle that exercises the exact fixed-size
 * truncation / 2's-complement semantics the word variants must match.
 *
 * OSSL_FN_add_word()/OSSL_FN_sub_word() take the word by value; the earlier
 * pointer-typed declaration had no implementation and no callers, and is
 * corrected together with the implementation landing here.
 */
struct word_op_case_st {
    const OSSL_FN_ULONG *a_words;
    size_t a_limbs; /* significant limbs of a */
    size_t a_dsize; /* allocated dsize (>= a_limbs; exercises padding) */
    OSSL_FN_ULONG w;
};

static const OSSL_FN_ULONG w_zero[] = { OSSL_FN_ULONG_C(0) };
static const OSSL_FN_ULONG w_5[] = { OSSL_FN_ULONG_C(5) };
static const OSSL_FN_ULONG w_01234567[] = { OSSL_FN_ULONG_C(0x01234567) };
static const OSSL_FN_ULONG w_FFFFFFFF[] = { OSSL_FN_ULONG_C(0xffffffff) };
static const OSSL_FN_ULONG w_FFFFFFFE[] = { OSSL_FN_ULONG_C(0xfffffffe) };
static const OSSL_FN_ULONG w_7FFFFFFF[] = { OSSL_FN_ULONG_C(0x7fffffff) };
static const OSSL_FN_ULONG w_0_1[] = { OSSL_FN_ULONG_C(0), OSSL_FN_ULONG_C(1) };
static const OSSL_FN_ULONG w_0_0[] = { OSSL_FN_ULONG_C(0), OSSL_FN_ULONG_C(0) };
static const OSSL_FN_ULONG w_FF_FF[] = { OSSL_FN_ULONG_C(0xffffffff),
    OSSL_FN_ULONG_C(0xffffffff) };
static const OSSL_FN_ULONG w_FE_FF[] = { OSSL_FN_ULONG_C(0xfffffffe),
    OSSL_FN_ULONG_C(0xffffffff) };
static const OSSL_FN_ULONG w_67_89[] = { OSSL_FN_ULONG_C(0x01234567),
    OSSL_FN_ULONG_C(0x89abcdef) };

static const struct word_op_case_st add_word_cases[] = {
    { w_zero, 1, 2, OSSL_FN_ULONG_C(5) }, /* a == 0 */
    { w_01234567, 1, 2, OSSL_FN_ULONG_C(1) }, /* no carry */
    { w_FFFFFFFF, 1, 2, OSSL_FN_ULONG_C(1) }, /* carry into next limb */
    { w_FF_FF, 2, 2, OSSL_FN_ULONG_C(1) }, /* carry out truncated */
    { w_FE_FF, 2, 2, OSSL_FN_ULONG_C(2) }, /* carry propagates one limb */
    { w_67_89, 2, 2, OSSL_FN_ULONG_C(0) }, /* w == 0 noop */
    { w_FFFFFFFF, 1, 1, OSSL_FN_ULONG_C(1) }, /* dsize 1, carry truncated */
    { w_7FFFFFFF, 1, 1, OSSL_FN_ULONG_C(0x7fffffff) }, /* no carry, near boundary */
};

static const struct word_op_case_st sub_word_cases[] = {
    { w_zero, 1, 2, OSSL_FN_ULONG_C(5) }, /* borrow out -> 2's complement */
    { w_01234567, 1, 2, OSSL_FN_ULONG_C(1) }, /* no borrow */
    { w_0_1, 2, 2, OSSL_FN_ULONG_C(1) }, /* borrow repaid at limb 1 */
    { w_0_0, 2, 2, OSSL_FN_ULONG_C(1) }, /* borrow out truncated */
    { w_67_89, 2, 2, OSSL_FN_ULONG_C(0) }, /* w == 0 noop */
    { w_zero, 1, 1, OSSL_FN_ULONG_C(1) }, /* dsize 1, borrow truncated */
    { w_5, 1, 1, OSSL_FN_ULONG_C(5) }, /* exact, no borrow */
    { w_FFFFFFFE, 1, 2, OSSL_FN_ULONG_C(0xffffffff) }, /* borrow through to limb 1 */
};

/*
 * Cross-check OSSL_FN_<op>_word(a, w) against OSSL_FN_<op>(r, a_ref, b) where
 * b is a single-limb operand holding w.  The two-limb/general operation and
 * the word variant must agree on the full dsize, including truncation and
 * 2's-complement wrap behaviour.
 */
static int test_word_op_common(int i,
    const struct word_op_case_st *cases, size_t ncases,
    int (*word_op)(OSSL_FN *, OSSL_FN_ULONG),
    int (*ref_op)(OSSL_FN *, const OSSL_FN *,
        const OSSL_FN *))
{
    const struct word_op_case_st *tc = &cases[i];
    OSSL_FN *a = NULL, *a_ref = NULL, *b = NULL, *res = NULL;
    const OSSL_FN_ULONG *u = NULL, *r = NULL;
    int ret = 0;

    if (!TEST_ptr(a = OSSL_FN_new_limbs(tc->a_dsize))
        || !TEST_ptr(a_ref = OSSL_FN_new_limbs(tc->a_dsize))
        || !TEST_ptr(b = OSSL_FN_new_limbs(1))
        || !TEST_ptr(res = OSSL_FN_new_limbs(tc->a_dsize))
        || !TEST_true(ossl_fn_set_words(a, tc->a_words, tc->a_limbs))
        || !TEST_true(ossl_fn_set_words(a_ref, tc->a_words, tc->a_limbs))
        || !TEST_true(ossl_fn_set_words(b, &tc->w, 1))
        || !TEST_true(pollute(res, 0, tc->a_dsize)))
        goto err;

    if (!TEST_true(word_op(a, tc->w))
        || !TEST_true(ref_op(res, a_ref, b)))
        goto err;

    u = ossl_fn_get_words(a);
    r = ossl_fn_get_words(res);
    if (!TEST_mem_eq(u, tc->a_dsize * OSSL_FN_BYTES,
            r, tc->a_dsize * OSSL_FN_BYTES))
        goto err;

    ret = 1;
err:
    OSSL_FN_free(a);
    OSSL_FN_free(a_ref);
    OSSL_FN_free(b);
    OSSL_FN_free(res);
    return ret;
}

static int test_add_word(int i)
{
    return test_word_op_common(i, add_word_cases, OSSL_NELEM(add_word_cases),
        OSSL_FN_add_word, OSSL_FN_add);
}

static int test_sub_word(int i)
{
    return test_word_op_common(i, sub_word_cases, OSSL_NELEM(sub_word_cases),
        OSSL_FN_sub_word, OSSL_FN_sub);
}

/*-
 * Focused tests for the assignment helpers: OSSL_FN_set_word(), OSSL_FN_one(),
 * OSSL_FN_zero().  set_word is cross-checked against the internal
 * ossl_fn_set_words() (an independent setter) and pollutes the destination
 * first so that zeroing of high limbs is verified rather than assumed.
 */
struct set_word_case_st {
    size_t dsize; /* allocated dsize */
    OSSL_FN_ULONG w;
    int expect_err; /* 1 if the call should fail (dsize == 0) */
};

static const struct set_word_case_st set_word_cases[] = {
    { 1, OSSL_FN_ULONG_C(5), 0 }, /* minimal dsize */
    { 1, OSSL_FN_ULONG_C(0), 0 }, /* zero, minimal dsize */
    { 4, OSSL_FN_ULONG_C(0x01234567), 0 }, /* high limbs must be zeroed */
    { 4, OSSL_FN_ULONG_C(0), 0 }, /* zero, high limbs zeroed */
    { 2, OSSL_FN_ULONG_C(0xffffffff), 0 }, /* all-ones word */
    { 0, OSSL_FN_ULONG_C(5), 1 }, /* dsize 0 -> error */
};

static int test_set_word(int i)
{
    const struct set_word_case_st *tc = &set_word_cases[i];
    OSSL_FN *a = NULL, *ref = NULL;
    const OSSL_FN_ULONG *u = NULL, *r = NULL;
    int ret = 0;

    if (!TEST_ptr(a = OSSL_FN_new_limbs(tc->dsize))
        || !TEST_ptr(ref = OSSL_FN_new_limbs(tc->dsize)))
        goto err;

    /* Pollute both so that zeroing of untouched limbs is detectable. */
    if (tc->dsize > 0) {
        if (!TEST_true(pollute(a, 0, tc->dsize))
            || !TEST_true(pollute(ref, 0, tc->dsize)))
            goto err;
    }

    if (tc->expect_err) {
        if (!TEST_false(OSSL_FN_set_word(a, tc->w)))
            goto err;
        /* ossl_fn_set_words() with 1 limb also fails on dsize 0. */
        if (!TEST_false(ossl_fn_set_words(ref, &tc->w, 1)))
            goto err;
        ret = 1;
        goto err;
    }

    if (!TEST_true(OSSL_FN_set_word(a, tc->w))
        || !TEST_true(ossl_fn_set_words(ref, &tc->w, 1)))
        goto err;

    u = ossl_fn_get_words(a);
    r = ossl_fn_get_words(ref);
    if (!TEST_mem_eq(u, tc->dsize * OSSL_FN_BYTES,
            r, tc->dsize * OSSL_FN_BYTES))
        goto err;
    /* High limbs beyond limb 1 must be zero. */
    if (tc->dsize > 1
        && !TEST_true(check_limbs_value(a, 1, tc->dsize, 0)))
        goto err;

    ret = 1;
err:
    OSSL_FN_free(a);
    OSSL_FN_free(ref);
    return ret;
}

static int test_one(void)
{
    int ret = 0;
    OSSL_FN *a = NULL;
    const OSSL_FN_ULONG *u = NULL;
    size_t dsize = 4;

    if (!TEST_ptr(a = OSSL_FN_new_limbs(dsize))
        || !TEST_true(pollute(a, 0, dsize))
        || !TEST_true(OSSL_FN_one(a)))
        goto err;

    u = ossl_fn_get_words(a);
    if (!TEST_int_eq((int)u[0], 1)
        || !TEST_true(check_limbs_value(a, 1, dsize, 0)))
        goto err;

    ret = 1;
err:
    OSSL_FN_free(a);
    return ret;
}

static int test_zero(void)
{
    int ret = 0;
    OSSL_FN *a = NULL;
    size_t dsize = 4;

    if (!TEST_ptr(a = OSSL_FN_new_limbs(dsize))
        || !TEST_true(pollute(a, 0, dsize))
        || !TEST_true(OSSL_FN_zero(a)))
        goto err;

    /* OSSL_FN_is_zero() (added in the introspection commit) reads the result. */
    if (!TEST_int_eq(OSSL_FN_is_zero(a), 1)
        || !TEST_true(check_limbs_value(a, 0, dsize, 0)))
        goto err;

    ret = 1;
err:
    OSSL_FN_free(a);
    return ret;
}

static int test_lshift_common(int i, int use_lshift1)
{
    const OSSL_FN_ULONG *a_words = NULL;
    const OSSL_FN_ULONG *ex_words = NULL;
    OSSL_FN *a = NULL, *r = NULL;
    size_t a_limbs = 0, a_live_limbs = 0, r_limbs = 0, check_limbs = 0;
    int shift = 0, ret = 0;
    const OSSL_FN_ULONG *u = NULL;

    switch (i) {
    case 0:
        a_words = num2;
        a_limbs = LIMBSOF(num2);
        a_live_limbs = LIMBSOF(num2);
        r_limbs = LIMBSOF(ex_lshift1_num2) + 2;
        ex_words = ex_lshift1_num2;
        check_limbs = LIMBSOF(ex_lshift1_num2);
        shift = 1;
        break;
    case 1:
        a_words = num0;
        a_limbs = LIMBSOF(num0);
        a_live_limbs = LIMBSOF(num0);
        r_limbs = LIMBSOF(ex_lshift1_num0) + 2;
        ex_words = ex_lshift1_num0;
        check_limbs = LIMBSOF(ex_lshift1_num0);
        shift = 1;
        break;
    case 2:
        a_words = num2;
        a_limbs = LIMBSOF(num2);
        a_live_limbs = LIMBSOF(num2);
        r_limbs = LIMBSOF(ex_lshift_num2_4) + 2;
        ex_words = ex_lshift_num2_4;
        check_limbs = LIMBSOF(ex_lshift_num2_4);
        shift = 4;
        break;
    case 3:
        a_words = num2;
        a_limbs = LIMBSOF(num2);
        a_live_limbs = LIMBSOF(num2) + 2;
        r_limbs = LIMBSOF(ex_lshift_num2_limb) + 2;
        ex_words = ex_lshift_num2_limb;
        check_limbs = LIMBSOF(ex_lshift_num2_limb);
        shift = OSSL_FN_BYTES * 8;
        break;
    case 4:
        a_words = num2;
        a_limbs = LIMBSOF(num2);
        a_live_limbs = LIMBSOF(num2);
        r_limbs = LIMBSOF(ex_lshift1_num2) - 1;
        ex_words = ex_lshift1_num2;
        check_limbs = r_limbs;
        shift = 1;
        break;
    case 5:
        a_words = num2;
        a_limbs = LIMBSOF(num2);
        a_live_limbs = LIMBSOF(num2);
        r_limbs = LIMBSOF(ex_lshift_num2_limb_3) + 2;
        ex_words = ex_lshift_num2_limb_3;
        check_limbs = LIMBSOF(ex_lshift_num2_limb_3);
        shift = OSSL_FN_BYTES * 8 + 3;
        break;
    default:
        return 0;
    }

    if (!TEST_ptr(a = OSSL_FN_new_limbs(a_live_limbs))
        || !TEST_ptr(r = OSSL_FN_new_limbs(r_limbs))
        || !TEST_true(ossl_fn_set_words(a, a_words, a_limbs))
        || !TEST_true(pollute(r, 0, r_limbs)))
        goto err;

    if (use_lshift1) {
        if (!TEST_int_eq(shift, 1)
            || !TEST_true(OSSL_FN_lshift1(r, a)))
            goto err;
    } else {
        if (!TEST_true(OSSL_FN_lshift(r, a, shift)))
            goto err;
    }

    if (!TEST_ptr(u = ossl_fn_get_words(r))
        || !TEST_mem_eq(u, check_limbs * OSSL_FN_BYTES,
            ex_words, check_limbs * OSSL_FN_BYTES)
        || !TEST_true(check_limbs_value(r, check_limbs, r_limbs,
            EXTENDED_LIMB_ZERO)))
        goto err;

    ret = 1;
err:
    OSSL_FN_free(a);
    OSSL_FN_free(r);
    return ret;
}

static int test_lshift1(int i)
{
    return test_lshift_common(i, 1);
}

static int test_lshift(int i)
{
    return test_lshift_common(i, 0);
}

static int test_rshift_common(int i, int use_rshift1, int alias)
{
    const OSSL_FN_ULONG *a_words = NULL;
    const OSSL_FN_ULONG *ex_words = NULL;
    OSSL_FN *a = NULL, *r = NULL;
    size_t a_limbs = 0, a_live_limbs = 0, r_limbs = 0, check_limbs = 0;
    int shift = 0, ret = 0;
    const OSSL_FN_ULONG *u = NULL;

    switch (i) {
    case 0:
        a_words = num2;
        a_limbs = LIMBSOF(num2);
        a_live_limbs = LIMBSOF(num2);
        r_limbs = LIMBSOF(ex_rshift1_num2) + 2;
        ex_words = ex_rshift1_num2;
        check_limbs = LIMBSOF(ex_rshift1_num2);
        shift = 1;
        break;
    case 1:
        a_words = num8;
        a_limbs = LIMBSOF(num8);
        a_live_limbs = LIMBSOF(num8);
        r_limbs = LIMBSOF(ex_rshift1_num8) + 2;
        ex_words = ex_rshift1_num8;
        check_limbs = LIMBSOF(ex_rshift1_num8);
        shift = 1;
        break;
    case 2:
        a_words = num2;
        a_limbs = LIMBSOF(num2);
        a_live_limbs = LIMBSOF(num2);
        r_limbs = LIMBSOF(ex_rshift_num2_4) + 2;
        ex_words = ex_rshift_num2_4;
        check_limbs = LIMBSOF(ex_rshift_num2_4);
        shift = 4;
        break;
    case 3:
        a_words = num8;
        a_limbs = LIMBSOF(num8);
        a_live_limbs = LIMBSOF(num8);
        r_limbs = LIMBSOF(ex_rshift_num8_limb) + 2;
        ex_words = ex_rshift_num8_limb;
        check_limbs = LIMBSOF(ex_rshift_num8_limb);
        shift = OSSL_FN_BYTES * 8;
        break;
    case 4:
        a_words = num8;
        a_limbs = LIMBSOF(num8);
        a_live_limbs = LIMBSOF(num8);
        r_limbs = LIMBSOF(ex_rshift_num8_limb_3) + 2;
        ex_words = ex_rshift_num8_limb_3;
        check_limbs = LIMBSOF(ex_rshift_num8_limb_3);
        shift = OSSL_FN_BYTES * 8 + 3;
        break;
    case 5:
        a_words = num2;
        a_limbs = LIMBSOF(num2);
        a_live_limbs = LIMBSOF(num2);
        r_limbs = LIMBSOF(ex_rshift_num2_limb) + 2;
        ex_words = ex_rshift_num2_limb;
        check_limbs = LIMBSOF(ex_rshift_num2_limb);
        shift = OSSL_FN_BYTES * 8;
        break;
    case 6:
        a_words = num8;
        a_limbs = LIMBSOF(num8);
        a_live_limbs = LIMBSOF(num8);
        r_limbs = LIMBSOF(num8) - 1;
        ex_words = num8;
        check_limbs = r_limbs;
        shift = 0;
        break;
    case 7:
        /* Shifting by more than the operand's width must yield zero. */
        a_words = num2;
        a_limbs = LIMBSOF(num2);
        a_live_limbs = LIMBSOF(num2);
        r_limbs = LIMBSOF(num2) + 2;
        ex_words = ex_rshift_zero;
        check_limbs = LIMBSOF(num2);
        shift = OSSL_FN_BYTES * 8 * (LIMBSOF(num2) + 1);
        break;
    case 8:
        /* Exact-fit destination (no padding) with a non-zero shift. */
        a_words = num2;
        a_limbs = LIMBSOF(num2);
        a_live_limbs = LIMBSOF(num2);
        r_limbs = LIMBSOF(ex_rshift_num2_4);
        ex_words = ex_rshift_num2_4;
        check_limbs = LIMBSOF(ex_rshift_num2_4);
        shift = 4;
        break;
    default:
        return 0;
    }

    if (!TEST_ptr(a = OSSL_FN_new_limbs(a_live_limbs))
        || !TEST_true(ossl_fn_set_words(a, a_words, a_limbs)))
        goto err;

    if (alias) {
        r = a;
    } else if (!TEST_ptr(r = OSSL_FN_new_limbs(r_limbs))
        || !TEST_true(pollute(r, 0, r_limbs))) {
        goto err;
    }

    if (use_rshift1) {
        if (!TEST_int_eq(shift, 1)
            || !TEST_true(OSSL_FN_rshift1(r, a)))
            goto err;
    } else {
        if (!TEST_true(OSSL_FN_rshift(r, a, shift)))
            goto err;
    }

    if (!TEST_ptr(u = ossl_fn_get_words(r))
        || !TEST_mem_eq(u, check_limbs * OSSL_FN_BYTES,
            ex_words, check_limbs * OSSL_FN_BYTES)
        || !TEST_true(check_limbs_value(r, check_limbs, r_limbs,
            EXTENDED_LIMB_ZERO)))
        goto err;

    ret = 1;
err:
    if (!alias)
        OSSL_FN_free(r);
    OSSL_FN_free(a);
    return ret;
}

static int test_rshift1(int i)
{
    return test_rshift_common(i, 1, 0);
}

static int test_rshift(int i)
{
    return test_rshift_common(i, 0, 0);
}

/*
 * In-place (r == a) coverage: rshift1 (case 0), rshift by 1 (case 1),
 * by 4 (case 2), and by a full limb width (case 3).  The low-to-high
 * walk makes in-place safe for any shift, so this exercises the
 * multi-limb carry path under aliasing beyond shift-by-1.
 */
static int test_rshift_alias(int i)
{
    return test_rshift_common(i, i == 0, 1);
}

static int test_rshift_invalid_shift(void)
{
    OSSL_FN *a = NULL, *r = NULL;
    int ret = 0;

    if (!TEST_ptr(a = OSSL_FN_new_limbs(LIMBSOF(num2)))
        || !TEST_ptr(r = OSSL_FN_new_limbs(LIMBSOF(num2)))
        || !TEST_true(ossl_fn_set_words(a, num2, LIMBSOF(num2))))
        goto err;

    if (!TEST_false(OSSL_FN_rshift(r, a, -1)))
        goto err;

    ERR_clear_error();
    ret = 1;
err:
    OSSL_FN_free(a);
    OSSL_FN_free(r);
    return ret;
}

/* A set of expected results, also in OSSL_FN_ULONG array form */
static const OSSL_FN_ULONG ex_mul_num0_num0[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000001),
    OSSL_FN_ULONG64_C(0x40000000, 0x00000001),
};
static const OSSL_FN_ULONG ex_mul_num0_num1[] = {
    OSSL_FN_ULONG64_C(0x00000001, 0x80000000),
    OSSL_FN_ULONG64_C(0x00000000, 0xC0000000),
};
static const OSSL_FN_ULONG ex_mul_num0_num2[] = {
    OSSL_FN_ULONG64_C(0x81234567, 0x89ABCDEF),
    OSSL_FN_ULONG64_C(0x0091A2B3, 0xC4D5E6F7),
};
static const OSSL_FN_ULONG ex_mul_num0_num3[] = {
    OSSL_FN_ULONG64_C(0xFEDCBA98, 0x76543210),
    OSSL_FN_ULONG64_C(0x7F6E5D4C, 0x3B2A1908),
};
static const OSSL_FN_ULONG ex_mul_num1_num1[] = {
    OSSL_FN_ULONG64_C(0x40000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x00000000, 0x00000002),
};
static const OSSL_FN_ULONG ex_mul_num1_num2[] = {
    OSSL_FN_ULONG64_C(0x4E81B4E6, 0x80000000),
    OSSL_FN_ULONG64_C(0x00000000, 0x01B4E81B),
};
static const OSSL_FN_ULONG ex_mul_num1_num3[] = {
    OSSL_FN_ULONG64_C(0xB17E4B18, 0x00000000),
    OSSL_FN_ULONG64_C(0x00000001, 0x7E4B17E4),
};
static const OSSL_FN_ULONG ex_mul_num2_num2[] = {
    OSSL_FN_ULONG64_C(0xDCA5E208, 0x90F2A521),
    OSSL_FN_ULONG64_C(0x00014B66, 0xDC33F6AC),
};
static const OSSL_FN_ULONG ex_mul_num2_num3[] = {
    OSSL_FN_ULONG64_C(0x2236D88F, 0xE5618CF0),
    OSSL_FN_ULONG64_C(0x0121FA00, 0xAD77D742),
};
static const OSSL_FN_ULONG ex_mul_num3_num3[] = {
    OSSL_FN_ULONG64_C(0xDEEC6CD7, 0xA44A4100),
    OSSL_FN_ULONG64_C(0xFDBAC097, 0xC8DC5ACC),
};
/* Expected results for edge cases */
static const OSSL_FN_ULONG ex_mul_num4_num4[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
static const OSSL_FN_ULONG ex_mul_num5_num5[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000001),
    OSSL_FN_ULONG64_C(0xFFFFFFFF, 0xFFFFFFFE),
};
/* $num6 * $num6 == 0x0100000000000000000000000000000000000000000000000000000000000000 */
static const OSSL_FN_ULONG ex_mul_num6_num6[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x01000000, 0x00000000),
};

static int test_mul_feature_r_is_operand(int i)
{
    int ret = 1;
    const OSSL_FN_ULONG *a_data = num0;
    size_t a_limbs = sizeof(num0) / OSSL_FN_BYTES;
    const OSSL_FN_ULONG *b_data = num1;
    size_t b_limbs = sizeof(num1) / OSSL_FN_BYTES;
    OSSL_FN *a = NULL, *b = NULL, *res = NULL;

    OSSL_FN_CTX *ctx = NULL;
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 1, 1, a_limbs + b_limbs))
        || !TEST_ptr(a = OSSL_FN_new_limbs(a_limbs))
        || !TEST_ptr(b = OSSL_FN_new_limbs(b_limbs))
        || !TEST_true(ossl_fn_set_words(a, a_data, a_limbs))
        || !TEST_true(ossl_fn_set_words(b, b_data, b_limbs))) {
        ret = 0;
        /* There's no way to continue tests in this case */
        goto end;
    }

    const OSSL_FN *op1 = NULL, *op2 = NULL;
    const OSSL_FN_ULONG *u = NULL;
    const OSSL_FN_ULONG *ex_data = NULL;
    size_t ex_limbs = 0;

    switch (i) {
    case 0:
        /* a * b, result in separate OSSL_FN */
        if (!TEST_ptr(res = OSSL_FN_new_limbs(a_limbs + b_limbs))) {
            ret = 0;
            goto end;
        }
        op1 = a;
        op2 = b;
        ex_data = ex_mul_num0_num1;
        ex_limbs = ossl_fn_get_dsize(res);
        break;
    case 1:
        /* a * b, result in a */
        res = a;
        op1 = a;
        op2 = b;
        ex_data = ex_mul_num0_num1;
        ex_limbs = ossl_fn_get_dsize(res);
        break;
    case 2:
        /* a * b, result in b */
        res = b;
        op1 = a;
        op2 = b;
        ex_data = ex_mul_num0_num1;
        ex_limbs = ossl_fn_get_dsize(res);
        break;
    case 3:
        /* a * a, result in a */
        res = a;
        op1 = a;
        op2 = a;
        ex_data = ex_mul_num0_num0;
        ex_limbs = ossl_fn_get_dsize(res);
        break;
    default:
        /* Invalid call */
        ret = 0;
        goto end;
    }

    if (!TEST_true(OSSL_FN_mul(res, op1, op2, ctx))
        || !TEST_ptr(u = ossl_fn_get_words(res))
        || !TEST_mem_eq(u, ex_limbs * OSSL_FN_BYTES,
            ex_data, ex_limbs * OSSL_FN_BYTES))
        ret = 0;

    if (TEST_ptr(u = ossl_fn_get_words(a))) {
        if (res == a) {
            if (!TEST_mem_eq(u, ex_limbs * OSSL_FN_BYTES,
                    ex_data, ex_limbs * OSSL_FN_BYTES))
                ret = 0;
        } else {
            if (!TEST_mem_eq(u, a_limbs * OSSL_FN_BYTES,
                    a_data, a_limbs * OSSL_FN_BYTES))
                ret = 0;
        }
    }

    if (TEST_ptr(u = ossl_fn_get_words(b))) {
        if (res == b) {
            if (!TEST_mem_eq(u, ex_limbs * OSSL_FN_BYTES,
                    ex_data, ex_limbs * OSSL_FN_BYTES))
                ret = 0;
        } else {
            if (!TEST_mem_eq(u, b_limbs * OSSL_FN_BYTES,
                    b_data, b_limbs * OSSL_FN_BYTES))
                ret = 0;
        }
    }

end:
    OSSL_FN_CTX_free(ctx);
    if (res != a && res != b)
        OSSL_FN_free(res);
    OSSL_FN_free(a);
    OSSL_FN_free(b);
    return ret;
}

static int test_mul_common(struct test_case_st test_case)
{
    int ret = 1;
    const OSSL_FN_ULONG *n1 = test_case.op1;
    size_t n1_limbs = test_case.op1_size;
    const OSSL_FN_ULONG *n2 = test_case.op2;
    size_t n2_limbs = test_case.op2_size;
    const OSSL_FN_ULONG *ex = test_case.ex1;
    size_t n1_new_limbs = test_case.op1_live_size;
    size_t n2_new_limbs = test_case.op2_live_size;
    size_t res_limbs = test_case.res1_live_size;
    size_t check_limbs = test_case.check1_size;
    OSSL_FN_ULONG extended_value = test_case.extended_limb_value1;
    OSSL_FN *fn1 = NULL, *fn2 = NULL, *res = NULL;
    const OSSL_FN_ULONG *u = NULL;

    OSSL_FN_CTX *ctx = NULL;
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 1, 1, res_limbs))
        || !TEST_ptr(fn1 = OSSL_FN_new_limbs(n1_new_limbs))
        || !TEST_ptr(fn2 = OSSL_FN_new_limbs(n2_new_limbs))
        || !TEST_true(ossl_fn_set_words(fn1, n1, n1_limbs))
        || !TEST_true(ossl_fn_set_words(fn2, n2, n2_limbs))
        || !TEST_ptr(res = OSSL_FN_new_limbs(res_limbs))) {
        ret = 0;
        /* There's no way to continue tests in this case */
        goto end;
    }

    /* To test that OSSL_FN_mul() does a complete job, 'res' is pre-polluted */

    if (!TEST_true(pollute(res, 0, res_limbs))
        || !TEST_true(OSSL_FN_mul(res, fn1, fn2, ctx))
        || !TEST_ptr(u = ossl_fn_get_words(res))
        || !TEST_mem_eq(u, check_limbs * OSSL_FN_BYTES,
            ex, check_limbs * OSSL_FN_BYTES)
        || !TEST_true(check_limbs_value(res, check_limbs, res_limbs,
            extended_value)))
        ret = 0;

end:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fn1);
    OSSL_FN_free(fn2);
    OSSL_FN_free(res);

    return ret;
}

/* i should be set to match the iteration number that's displayed when testing */
#define MUL_CASE(i, op1, op2, ex)                                         \
    {                                                                     \
        /* op1 */ op1,                                                    \
        /* op1_size */ LIMBSOF(op1),                                      \
        /* op2 */ op2,                                                    \
        /* op2_size */ LIMBSOF(op2),                                      \
        /* ex1 */ ex,                                                     \
        /* ex1_size */ LIMBSOF(ex),                                       \
        /* ex2 */ ex,                                                     \
        /* ex2_size */ 0,                                                 \
        /* op1_live_size */ LIMBSOF(op1) + 1,                             \
        /* op2_live_size */ LIMBSOF(op2) + 2,                             \
        /* res1_live_size */ LIMBSOF(op1) + LIMBSOF(op2) + ((i - 1) % 4), \
        /* res2_live_size */ 0,                                           \
        /* check1_size */ LIMBSOF(ex),                                    \
        /* check2_size */ 0,                                              \
        /* extended_limb_value1 */ EXTENDED_LIMB_ZERO,                    \
        /* extended_limb_value2 */ 0,                                     \
    }

static struct test_case_st test_mul_cases[] = {
    MUL_CASE(1, num0, num0, ex_mul_num0_num0),
    MUL_CASE(2, num0, num1, ex_mul_num0_num1),
    MUL_CASE(3, num0, num2, ex_mul_num0_num2),
    MUL_CASE(4, num0, num3, ex_mul_num0_num3),
    MUL_CASE(5, num1, num0, ex_mul_num0_num1), /* Commutativity check */
    MUL_CASE(6, num1, num1, ex_mul_num1_num1),
    MUL_CASE(7, num1, num2, ex_mul_num1_num2),
    MUL_CASE(8, num1, num3, ex_mul_num1_num3),
    MUL_CASE(9, num2, num0, ex_mul_num0_num2), /* Commutativity check */
    MUL_CASE(10, num2, num1, ex_mul_num1_num2), /* Commutativity check */
    MUL_CASE(11, num2, num2, ex_mul_num2_num2),
    MUL_CASE(12, num2, num3, ex_mul_num2_num3),
    MUL_CASE(13, num3, num0, ex_mul_num0_num3), /* Commutativity check */
    MUL_CASE(14, num3, num1, ex_mul_num1_num3), /* Commutativity check */
    MUL_CASE(15, num3, num2, ex_mul_num2_num3), /* Commutativity check */
    MUL_CASE(16, num3, num3, ex_mul_num3_num3),

    /* Edge cases */
    MUL_CASE(17, num4, num4, ex_mul_num4_num4),
    MUL_CASE(18, num5, num5, ex_mul_num5_num5),
    MUL_CASE(19, num6, num6, ex_mul_num6_num6),
};

static int test_mul(int i)
{
    return test_mul_common(test_mul_cases[i]);
}

/* i should be set to match the iteration number that's displayed when testing */
#define MUL_TRUNCATED_CASE(i, op1, op2, ex)            \
    {                                                  \
        /* op1 */ op1,                                 \
        /* op1_size */ LIMBSOF(op1),                   \
        /* op2 */ op2,                                 \
        /* op2_size */ LIMBSOF(op2),                   \
        /* ex1 */ ex,                                  \
        /* ex1_size */ LIMBSOF(ex),                    \
        /* ex2 */ NULL,                                \
        /* ex2_size */ 0,                              \
        /* op1_live_size */ LIMBSOF(op1) + 1,          \
        /* op2_live_size */ LIMBSOF(op2) + 2,          \
        /* res1_live_size */ LIMBSOF(ex) / 2,          \
        /* res2_live_size */ 0,                        \
        /* check1_size */ LIMBSOF(ex) / 2,             \
        /* check2_size */ 0,                           \
        /* extended_limb_value1 */ EXTENDED_LIMB_ZERO, \
        /* extended_limb_value2 */ 0,                  \
    }
/* A special case, where the truncation is set to the size of ex minus 64 bits */
#define MUL_TRUNCATED_SPECIAL_CASE1(i, op1, op2, ex)          \
    {                                                         \
        /* op1 */ op1,                                        \
        /* op1_size */ LIMBSOF(op1),                          \
        /* op2 */ op2,                                        \
        /* op2_size */ LIMBSOF(op2),                          \
        /* ex1 */ ex,                                         \
        /* ex1_size */ LIMBSOF(ex),                           \
        /* ex2 */ NULL,                                       \
        /* ex2_size */ 0,                                     \
        /* op1_live_size */ LIMBSOF(op1) + 1,                 \
        /* op2_live_size */ LIMBSOF(op2) + 2,                 \
        /* res1_live_size */ LIMBSOF(ex) - 8 / OSSL_FN_BYTES, \
        /* res2_live_size */ 0,                               \
        /* check1_size */ LIMBSOF(ex) - 8 / OSSL_FN_BYTES,    \
        /* check2_size */ 0,                                  \
        /* extended_limb_value1 */ EXTENDED_LIMB_ZERO,        \
        /* extended_limb_value2 */ 0,                         \
    }

static struct test_case_st test_mul_truncate_cases[] = {
    MUL_TRUNCATED_CASE(1, num0, num0, ex_mul_num0_num0),
    MUL_TRUNCATED_CASE(2, num0, num1, ex_mul_num0_num1),
    MUL_TRUNCATED_CASE(3, num0, num2, ex_mul_num0_num2),
    MUL_TRUNCATED_CASE(4, num0, num3, ex_mul_num0_num3),
    MUL_TRUNCATED_CASE(5, num1, num0, ex_mul_num0_num1), /* Commutativity check */
    MUL_TRUNCATED_CASE(6, num1, num1, ex_mul_num1_num1),
    MUL_TRUNCATED_CASE(7, num1, num2, ex_mul_num1_num2),
    MUL_TRUNCATED_CASE(8, num1, num3, ex_mul_num1_num3),
    MUL_TRUNCATED_CASE(9, num2, num0, ex_mul_num0_num2), /* Commutativity check */
    MUL_TRUNCATED_CASE(10, num2, num1, ex_mul_num1_num2), /* Commutativity check */
    MUL_TRUNCATED_CASE(11, num2, num2, ex_mul_num2_num2),
    MUL_TRUNCATED_CASE(12, num2, num3, ex_mul_num2_num3),
    MUL_TRUNCATED_CASE(13, num3, num0, ex_mul_num0_num3), /* Commutativity check */
    MUL_TRUNCATED_CASE(14, num3, num1, ex_mul_num1_num3), /* Commutativity check */
    MUL_TRUNCATED_CASE(15, num3, num2, ex_mul_num2_num3), /* Commutativity check */
    MUL_TRUNCATED_CASE(16, num3, num3, ex_mul_num3_num3),

    /* Edge cases */
    MUL_TRUNCATED_CASE(17, num4, num4, ex_mul_num4_num4),
    MUL_TRUNCATED_CASE(18, num5, num5, ex_mul_num5_num5),
    MUL_TRUNCATED_SPECIAL_CASE1(19, num6, num6, ex_mul_num6_num6),
};

static int test_mul_truncated(int i)
{
    return test_mul_common(test_mul_truncate_cases[i]);
}

/* All sqr tests reuse selected mul result numbers (ex_mul_num{n}_num{n}), except one */
#define ex_sqr_num0 ex_mul_num0_num0
#define ex_sqr_num1 ex_mul_num1_num1
#define ex_sqr_num2 ex_mul_num2_num2
#define ex_sqr_num3 ex_mul_num3_num3
#define ex_sqr_num4 ex_mul_num4_num4
#define ex_sqr_num5 ex_mul_num5_num5
#define ex_sqr_num6 ex_mul_num6_num6
static const OSSL_FN_ULONG ex_sqr_num7[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
#if OSSL_FN_BYTES == 4
    OSSL_FN_ULONG64_C(0xFFFFFFFE, 0x00000001),
#elif OSSL_FN_BYTES == 8
    OSSL_FN_ULONG64_C(0x00000000, 0x00000001),
    OSSL_FN_ULONG64_C(0xFFFFFFFF, 0xFFFFFFFE),
#endif
};

static int test_sqr_feature_r_is_operand(int i)
{
    int ret = 1;
    const OSSL_FN_ULONG *a_data = num0;
    size_t a_limbs = sizeof(num0) / OSSL_FN_BYTES;
    OSSL_FN *a = NULL, *res = NULL;

    OSSL_FN_CTX *ctx = NULL;
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 1, 2, a_limbs * 4))
        || !TEST_ptr(a = OSSL_FN_new_limbs(a_limbs))
        || !TEST_true(ossl_fn_set_words(a, a_data, a_limbs))) {
        ret = 0;
        /* There's no way to continue tests in this case */
        goto end;
    }

    switch (i) {
    case 0:
        /* a ** 2, result in separate OSSL_FN */
        if (!TEST_ptr(res = OSSL_FN_new_limbs(a_limbs * 2))) {
            ret = 0;
            goto end;
        }
        break;
    case 1:
        /* a ** 2, result in a */
        res = a;
        break;
    default:
        /* Invalid call */
        ret = 0;
        goto end;
    }

    const OSSL_FN_ULONG *u = NULL;
    const OSSL_FN_ULONG *ex_data = ex_mul_num0_num0;
    size_t ex_limbs = ossl_fn_get_dsize(res);

    if (!TEST_true(OSSL_FN_sqr(res, a, ctx))
        || !TEST_ptr(u = ossl_fn_get_words(res))
        || !TEST_mem_eq(u, ex_limbs * OSSL_FN_BYTES,
            ex_data, ex_limbs * OSSL_FN_BYTES))
        ret = 0;

    if (TEST_ptr(u = ossl_fn_get_words(a))) {
        if (res == a) {
            if (!TEST_mem_eq(u, ex_limbs * OSSL_FN_BYTES,
                    ex_data, ex_limbs * OSSL_FN_BYTES))
                ret = 0;
        } else {
            if (!TEST_mem_eq(u, a_limbs * OSSL_FN_BYTES,
                    a_data, a_limbs * OSSL_FN_BYTES))
                ret = 0;
        }
    }

end:
    OSSL_FN_CTX_free(ctx);
    if (res != a)
        OSSL_FN_free(res);
    OSSL_FN_free(a);
    return ret;
}

static int test_sqr_common(struct test_case_st test_case)
{
    int ret = 1;
    const OSSL_FN_ULONG *n1 = test_case.op1;
    size_t n1_limbs = test_case.op1_size;
    const OSSL_FN_ULONG *ex = test_case.ex1;
    size_t n1_new_limbs = test_case.op1_live_size;
    size_t res_limbs = test_case.res1_live_size;
    size_t check_limbs = test_case.check1_size;
    OSSL_FN_ULONG extended_value = test_case.extended_limb_value1;
    OSSL_FN *fn1 = NULL, *res = NULL;
    const OSSL_FN_ULONG *u = NULL;

    OSSL_FN_CTX *ctx = NULL;
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 1, 2, n1_new_limbs * 4))
        || !TEST_ptr(fn1 = OSSL_FN_new_limbs(n1_new_limbs))
        || !TEST_true(ossl_fn_set_words(fn1, n1, n1_limbs))
        || !TEST_ptr(res = OSSL_FN_new_limbs(res_limbs))) {
        ret = 0;
        /* There's no way to continue tests in this case */
        goto end;
    }

    /* To test that OSSL_FN_sqr() does a complete job, 'res' is pre-polluted */

    if (!TEST_true(pollute(res, 0, res_limbs))
        || !TEST_true(OSSL_FN_sqr(res, fn1, ctx))
        || !TEST_ptr(u = ossl_fn_get_words(res))
        || !TEST_mem_eq(u, check_limbs * OSSL_FN_BYTES,
            ex, check_limbs * OSSL_FN_BYTES)
        || !TEST_true(check_limbs_value(res, check_limbs, res_limbs,
            extended_value)))
        ret = 0;

end:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fn1);
    OSSL_FN_free(res);

    return ret;
}

/* i should be set to match the iteration number that's displayed when testing */
#define SQR_CASE(i, op1, ex)                                   \
    {                                                          \
        /* op1 */ op1,                                         \
        /* op1_size */ LIMBSOF(op1),                           \
        /* op2 */ NULL,                                        \
        /* op2_size */ 0,                                      \
        /* ex1 */ ex,                                          \
        /* ex1_size */ LIMBSOF(ex),                            \
        /* ex2 */ NULL,                                        \
        /* ex2_size */ 0,                                      \
        /* op1_live_size */ LIMBSOF(op1) + 1,                  \
        /* op2_live_size */ 0,                                 \
        /* res1_live_size */ LIMBSOF(op1) * 2 + ((i - 1) % 4), \
        /* res2_live_size */ 0,                                \
        /* check_size */ LIMBSOF(ex),                          \
        /* check_size */ 0,                                    \
        /* extended_limb_value */ EXTENDED_LIMB_ZERO,          \
        /* extended_limb_value */ 0,                           \
    }

static struct test_case_st test_sqr_cases[] = {
    SQR_CASE(1, num0, ex_sqr_num0),
    SQR_CASE(2, num1, ex_sqr_num1),
    SQR_CASE(3, num2, ex_sqr_num2),
    SQR_CASE(4, num3, ex_sqr_num3),

    /* Edge cases */
    SQR_CASE(5, num4, ex_sqr_num4),
    SQR_CASE(6, num5, ex_sqr_num5),
    SQR_CASE(7, num6, ex_sqr_num6),
    SQR_CASE(8, num7, ex_sqr_num7),
};

static int test_sqr(int i)
{
    return test_sqr_common(test_sqr_cases[i]);
}

/* i should be set to match the iteration number that's displayed when testing */
#define SQR_TRUNCATED_CASE(i, op1, ex)                 \
    {                                                  \
        /* op1 */ op1,                                 \
        /* op1_size */ LIMBSOF(op1),                   \
        /* op2 */ NULL,                                \
        /* op2_size */ 0,                              \
        /* ex1 */ ex,                                  \
        /* ex1_size */ LIMBSOF(ex),                    \
        /* ex2 */ NULL,                                \
        /* ex2_size */ 0,                              \
        /* op1_live_size */ LIMBSOF(op1) + 1,          \
        /* op2_live_size */ 0,                         \
        /* res1_live_size */ LIMBSOF(ex) / 2,          \
        /* res2_live_size */ 0,                        \
        /* check1_size */ LIMBSOF(ex) / 2,             \
        /* check2_size */ 0,                           \
        /* extended_limb_value1 */ EXTENDED_LIMB_ZERO, \
        /* extended_limb_value2 */ 0,                  \
    }
/* A special case, where the truncation is set to the size of ex minus 64 bits */
#define SQR_TRUNCATED_SPECIAL_CASE1(i, op1, ex)               \
    {                                                         \
        /* op1 */ op1,                                        \
        /* op1_size */ LIMBSOF(op1),                          \
        /* op2 */ NULL,                                       \
        /* op2_size */ 0,                                     \
        /* ex1 */ ex,                                         \
        /* ex1_size */ LIMBSOF(ex),                           \
        /* ex2 */ NULL,                                       \
        /* ex2_size */ 0,                                     \
        /* op1_live_size */ LIMBSOF(op1) + 1,                 \
        /* op2_live_size */ 0,                                \
        /* res1_live_size */ LIMBSOF(ex) - 8 / OSSL_FN_BYTES, \
        /* res2_live_size */ 0,                               \
        /* check1_size */ LIMBSOF(ex) - 8 / OSSL_FN_BYTES,    \
        /* check2_size */ 0,                                  \
        /* extended_limb_value1 */ EXTENDED_LIMB_ZERO,        \
        /* extended_limb_value2 */ 0,                         \
    }

static struct test_case_st test_sqr_truncate_cases[] = {
    SQR_TRUNCATED_CASE(1, num0, ex_sqr_num0),
    SQR_TRUNCATED_CASE(2, num1, ex_sqr_num1),
    SQR_TRUNCATED_CASE(3, num2, ex_sqr_num2),
    SQR_TRUNCATED_CASE(4, num3, ex_sqr_num3),

    /* Edge cases */
    SQR_TRUNCATED_CASE(5, num4, ex_sqr_num4),
    SQR_TRUNCATED_CASE(6, num5, ex_sqr_num5),
    SQR_TRUNCATED_SPECIAL_CASE1(7, num6, ex_sqr_num6),
    SQR_TRUNCATED_CASE(7, num7, ex_sqr_num7),
};

static int test_sqr_truncated(int i)
{
    return test_sqr_common(test_sqr_truncate_cases[i]);
}

/* A set of expected results, also in OSSL_FN_ULONG array form */
/* : $num0 / $num0 == 1 */
static const OSSL_FN_ULONG ex_div_num0_num0[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000001),
};
/* : $num0 % $num0 == 0 */
static const OSSL_FN_ULONG ex_rem_num0_num0[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
/* : $num0 / $num1 == 0x55555555 */
static const OSSL_FN_ULONG ex_div_num0_num1[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x55555555),
};
/* : $num0 % $num1 == 0x80000001 */
static const OSSL_FN_ULONG ex_rem_num0_num1[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x80000001),
};
/* : $num0 / $num2 == 0x70 */
static const OSSL_FN_ULONG ex_div_num0_num2[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000070),
};
/* : $num0 % $num2 == 0x91a2b3 c4d5e771 */
static const OSSL_FN_ULONG ex_rem_num0_num2[] = {
    OSSL_FN_ULONG64_C(0x0091A2B3, 0xC4D5E771),
};
/* : $num0 / $num3 == 1 */
static const OSSL_FN_ULONG ex_div_num0_num3[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
/* : $num0 % $num3 == 0x9abcdef 01234569 */
static const OSSL_FN_ULONG ex_rem_num0_num3[] = {
    OSSL_FN_ULONG64_C(0x80000000, 0x00000001),
};
/* : $num1 / $num0 == 0 */
static const OSSL_FN_ULONG ex_div_num1_num0[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
/* : $num1 % $num0 == 0x180000000 */
static const OSSL_FN_ULONG ex_rem_num1_num0[] = {
    OSSL_FN_ULONG64_C(0x00000001, 0x80000000),
};
/* : $num1 / $num1 == 1 */
static const OSSL_FN_ULONG ex_div_num1_num1[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000001),
};
/* : $num1 % $num1 == 0 */
static const OSSL_FN_ULONG ex_rem_num1_num1[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
/* : $num1 / $num2 == 0 */
static const OSSL_FN_ULONG ex_div_num1_num2[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
/* : $num1 % $num2 == 0x180000000 */
static const OSSL_FN_ULONG ex_rem_num1_num2[] = {
    OSSL_FN_ULONG64_C(0x00000001, 0x80000000),
};
/* : $num1 / $num3 == 0 */
static const OSSL_FN_ULONG ex_div_num1_num3[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
/* : $num1 % $num3 == 0x180000000 */
static const OSSL_FN_ULONG ex_rem_num1_num3[] = {
    OSSL_FN_ULONG64_C(0x00000001, 0x80000000),
};
/* : $num2 / $num0 == 0 */
static const OSSL_FN_ULONG ex_div_num2_num0[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
/* : $num2 % $num0 == 0X123456789abcdef */
static const OSSL_FN_ULONG ex_rem_num2_num0[] = {
    OSSL_FN_ULONG64_C(0X01234567, 0x89ABCDEF),
};
/* : $num2 / $num1 == 0xc22e45 */
static const OSSL_FN_ULONG ex_div_num2_num1[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00C22E45),
};
/* : $num2 % $num1 == 0x9abcdef */
static const OSSL_FN_ULONG ex_rem_num2_num1[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x09ABCDEF),
};
/* : $num2 / $num2 == 1 */
static const OSSL_FN_ULONG ex_div_num2_num2[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000001),
};
/* : $num2 % $num2 == 0 */
static const OSSL_FN_ULONG ex_rem_num2_num2[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
/* : $num2 / $num3 == 0 */
static const OSSL_FN_ULONG ex_div_num2_num3[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
/* : $num2 % $num3 == 0X0123456789abcdef */
static const OSSL_FN_ULONG ex_rem_num2_num3[] = {
    OSSL_FN_ULONG64_C(0X01234567, 0x89ABCDEF),
};
/* : $num3 / $num0 == 1 */
static const OSSL_FN_ULONG ex_div_num3_num0[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000001),
};
/* : $num3 % $num0 == 0x7edcba987654320f */
static const OSSL_FN_ULONG ex_rem_num3_num0[] = {
    OSSL_FN_ULONG64_C(0x7edcba98, 0x7654320f),
};
/* : $num3 / $num1 == 0xa9e87c65 */
static const OSSL_FN_ULONG ex_div_num3_num1[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0xa9e87c65),
};
/* : $num3 % $num1 == 0x00000000f6543210 */
static const OSSL_FN_ULONG ex_rem_num3_num1[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0xf6543210),
};
/* : $num3 / $num2 == 0xe0 */
static const OSSL_FN_ULONG ex_div_num3_num2[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x000000e0),
};
/* : $num3 % $num2 == 0xf0 */
static const OSSL_FN_ULONG ex_rem_num3_num2[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x000000f0),
};
/* : $num3 / $num3 == 1 */
static const OSSL_FN_ULONG ex_div_num3_num3[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000001),
};
/* : $num3 % $num3 == o */
static const OSSL_FN_ULONG ex_rem_num3_num3[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
/* Expected results for edge cases */
/* $num5 / $num5 == 1 */
static const OSSL_FN_ULONG ex_div_num5_num5[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000001),
};
/* $num5 % $num5 == 0 */
static const OSSL_FN_ULONG ex_rem_num5_num5[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
/* $num6 / $num6 == 1 */
static const OSSL_FN_ULONG ex_div_num6_num6[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000001),
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};
/* $num6 % $num6 == 0 */
static const OSSL_FN_ULONG ex_rem_num6_num6[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
};

static int test_div_common(struct test_case_st test_case)
{
    int ret = 1;
    const OSSL_FN_ULONG *n = test_case.op1;
    size_t n_limbs = test_case.op1_size;
    const OSSL_FN_ULONG *d = test_case.op2;
    size_t d_limbs = test_case.op2_size;
    const OSSL_FN_ULONG *ex_q = test_case.ex1;
    const OSSL_FN_ULONG *ex_r = test_case.ex2;
    size_t n_new_limbs = test_case.op1_live_size;
    size_t d_new_limbs = test_case.op2_live_size;
    size_t q_limbs = test_case.res1_live_size;
    size_t r_limbs = test_case.res2_live_size;
    size_t check_q_limbs = test_case.check1_size;
    size_t check_r_limbs = test_case.check2_size;
    OSSL_FN_ULONG extended_q = test_case.extended_limb_value1;
    OSSL_FN_ULONG extended_r = test_case.extended_limb_value2;
    OSSL_FN *fn = NULL, *fd = NULL, *fq = NULL, *fr = NULL;
    const OSSL_FN_ULONG *u = NULL;
    /* Calculate total number of limbs for OSSL_FN_CTX */
    size_t ctx_numcopy_limbs = ((n_new_limbs <= d_new_limbs) ? d_new_limbs : n_new_limbs) + 1;
    size_t ctx_divcopy_limbs = d_new_limbs;
    size_t ctx_tmp_limbs = d_new_limbs + 1;
    size_t ctx_res_limbs = n_new_limbs;
    size_t ctx_max_limbs = ctx_numcopy_limbs + ctx_divcopy_limbs + ctx_res_limbs + ctx_tmp_limbs;

    OSSL_FN_CTX *ctx = NULL;
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 1, 4, ctx_max_limbs))
        || !TEST_ptr(fn = OSSL_FN_new_limbs(n_new_limbs))
        || !TEST_ptr(fd = OSSL_FN_new_limbs(d_new_limbs))
        || !TEST_true(ossl_fn_set_words(fn, n, n_limbs))
        || !TEST_true(ossl_fn_set_words(fd, d, d_limbs))
        || !TEST_ptr(fq = OSSL_FN_new_limbs(q_limbs))
        || !TEST_ptr(fr = OSSL_FN_new_limbs(r_limbs))) {
        ret = 0;
        /* There's no way to continue tests in this case */
        goto end;
    }

    /* To test that OSSL_FN_div() does a complete job, 'res' is pre-polluted */

    if (!TEST_true(pollute(fq, 0, q_limbs))
        || !TEST_true(pollute(fr, 0, r_limbs))
        || !TEST_true(OSSL_FN_div(fq, fr, fn, fd, ctx))
        || !TEST_ptr(u = ossl_fn_get_words(fq))
        || !TEST_mem_eq(u, check_q_limbs * OSSL_FN_BYTES,
            ex_q, check_q_limbs * OSSL_FN_BYTES)
        || !TEST_ptr(u = ossl_fn_get_words(fr))
        || !TEST_mem_eq(u, check_r_limbs * OSSL_FN_BYTES,
            ex_r, check_r_limbs * OSSL_FN_BYTES)
        || !TEST_true(check_limbs_value(fq, check_q_limbs, q_limbs, extended_q))
        || !TEST_true(check_limbs_value(fr, check_r_limbs, r_limbs, extended_r)))
        ret = 0;

end:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fn);
    OSSL_FN_free(fd);
    OSSL_FN_free(fq);
    OSSL_FN_free(fr);

    return ret;
}

/* i should be set to match the iteration number that's displayed when testing */
#define DIV_CASE(i, op1, op2, ex_q, ex_r)                  \
    {                                                      \
        /* op1 */ op1,                                     \
        /* op1_size */ LIMBSOF(op1),                       \
        /* op2 */ op2,                                     \
        /* op2_size */ LIMBSOF(op2),                       \
        /* ex1 */ ex_q,                                    \
        /* ex1_size */ LIMBSOF(ex_q),                      \
        /* ex2 */ ex_r,                                    \
        /* ex2_size */ LIMBSOF(ex_r),                      \
        /* op1_live_size */ LIMBSOF(op1) + 1,              \
        /* op2_live_size */ LIMBSOF(op2) + 2,              \
        /* res1_live_size */ LIMBSOF(op1) + ((i - 1) % 4), \
        /* res2_live_size */ LIMBSOF(op1) + ((i - 1) % 4), \
        /* check1_size */ LIMBSOF(ex_q),                   \
        /* check2_size */ LIMBSOF(ex_r),                   \
        /* extended_limb_value1 */ EXTENDED_LIMB_ZERO,     \
        /* extended_limb_value2 */ EXTENDED_LIMB_ZERO,     \
    }

static struct test_case_st test_div_cases[] = {
    DIV_CASE(1, num0, num0, ex_div_num0_num0, ex_rem_num0_num0),
    DIV_CASE(2, num0, num1, ex_div_num0_num1, ex_rem_num0_num1),
    DIV_CASE(3, num0, num2, ex_div_num0_num2, ex_rem_num0_num2),
    DIV_CASE(4, num0, num3, ex_div_num0_num3, ex_rem_num0_num3),
    DIV_CASE(5, num1, num0, ex_div_num1_num0, ex_rem_num1_num0),
    DIV_CASE(6, num1, num1, ex_div_num1_num1, ex_rem_num1_num1),
    DIV_CASE(7, num1, num2, ex_div_num1_num2, ex_rem_num1_num2),
    DIV_CASE(8, num1, num3, ex_div_num1_num3, ex_rem_num1_num3),
    DIV_CASE(9, num2, num0, ex_div_num2_num0, ex_rem_num2_num0),
    DIV_CASE(10, num2, num1, ex_div_num2_num1, ex_rem_num2_num1),
    DIV_CASE(11, num2, num2, ex_div_num2_num2, ex_rem_num2_num2),
    DIV_CASE(12, num2, num3, ex_div_num2_num3, ex_rem_num2_num3),
    DIV_CASE(13, num3, num0, ex_div_num3_num0, ex_rem_num3_num0),
    DIV_CASE(14, num3, num1, ex_div_num3_num1, ex_rem_num3_num1),
    DIV_CASE(15, num3, num2, ex_div_num3_num2, ex_rem_num3_num2),
    DIV_CASE(16, num3, num3, ex_div_num3_num3, ex_rem_num3_num3),

    /* Edge cases */
    DIV_CASE(17, num5, num5, ex_div_num5_num5, ex_rem_num5_num5),
    DIV_CASE(18, num6, num6, ex_div_num6_num6, ex_rem_num6_num6),
};

static int test_div(int i)
{
    return test_div_common(test_div_cases[i]);
}

/* i should be set to match the iteration number that's displayed when testing */
#define DIV_TRUNCATED_CASE(i, op1, op2, ex_q, ex_r)    \
    {                                                  \
        /* op1 */ op1,                                 \
        /* op1_size */ LIMBSOF(op1),                   \
        /* op2 */ op2,                                 \
        /* op2_size */ LIMBSOF(op2),                   \
        /* ex1 */ ex_q,                                \
        /* ex1_size */ LIMBSOF(ex_q),                  \
        /* ex2 */ ex_r,                                \
        /* ex2_size */ LIMBSOF(ex_r),                  \
        /* op1_live_size */ LIMBSOF(op1) + 1,          \
        /* op2_live_size */ LIMBSOF(op2) + 2,          \
        /* res1_live_size */ LIMBSOF(ex_q) / 2,        \
        /* res2_live_size */ LIMBSOF(ex_r) / 2,        \
        /* check1_size */ LIMBSOF(ex_q) / 2,           \
        /* check2_size */ LIMBSOF(ex_r) / 2,           \
        /* extended_limb_value1 */ EXTENDED_LIMB_ZERO, \
        /* extended_limb_value2 */ EXTENDED_LIMB_ZERO, \
    }

static struct test_case_st test_div_truncate_cases[] = {
    DIV_TRUNCATED_CASE(1, num0, num0, ex_div_num0_num0, ex_rem_num0_num0),
    DIV_TRUNCATED_CASE(2, num0, num1, ex_div_num0_num1, ex_rem_num0_num1),
    DIV_TRUNCATED_CASE(3, num0, num2, ex_div_num0_num2, ex_rem_num0_num2),
    DIV_TRUNCATED_CASE(4, num0, num3, ex_div_num0_num3, ex_rem_num0_num3),
    DIV_TRUNCATED_CASE(5, num1, num0, ex_div_num1_num0, ex_rem_num1_num0),
    DIV_TRUNCATED_CASE(6, num1, num1, ex_div_num1_num1, ex_rem_num1_num1),
    DIV_TRUNCATED_CASE(7, num1, num2, ex_div_num1_num2, ex_rem_num1_num2),
    DIV_TRUNCATED_CASE(8, num1, num3, ex_div_num1_num3, ex_rem_num1_num3),
    DIV_TRUNCATED_CASE(9, num2, num0, ex_div_num2_num0, ex_rem_num2_num0),
    DIV_TRUNCATED_CASE(10, num2, num1, ex_div_num2_num1, ex_rem_num2_num1),
    DIV_TRUNCATED_CASE(11, num2, num2, ex_div_num2_num2, ex_rem_num2_num2),
    DIV_TRUNCATED_CASE(12, num2, num3, ex_div_num2_num3, ex_rem_num2_num3),
    DIV_TRUNCATED_CASE(13, num3, num0, ex_div_num3_num0, ex_rem_num3_num0),
    DIV_TRUNCATED_CASE(14, num3, num1, ex_div_num3_num1, ex_rem_num3_num1),
    DIV_TRUNCATED_CASE(15, num3, num2, ex_div_num3_num2, ex_rem_num3_num2),
    DIV_TRUNCATED_CASE(16, num3, num3, ex_div_num3_num3, ex_rem_num3_num3),

    /* Edge cases */
    DIV_TRUNCATED_CASE(17, num5, num5, ex_div_num5_num5, ex_rem_num5_num5),
    DIV_TRUNCATED_CASE(18, num6, num6, ex_div_num6_num6, ex_rem_num6_num6),
};

static int test_div_truncated(int i)
{
    return test_div_common(test_div_truncate_cases[i]);
}

/*
 * The modulo tests are a bit silly, 'cause we know that OSSL_FN_mod()
 * simply calls OSSL_FN_div() with NULL for the quotient.  Still, these
 * tests ensure that calling OSSL_FN_div() like that works without flaws.
 */
static int test_mod_common(struct test_case_st test_case)
{
    int ret = 1;
    const OSSL_FN_ULONG *n = test_case.op1;
    size_t n_limbs = test_case.op1_size;
    const OSSL_FN_ULONG *d = test_case.op2;
    size_t d_limbs = test_case.op2_size;
    const OSSL_FN_ULONG *ex = test_case.ex1;
    size_t n_new_limbs = test_case.op1_live_size;
    size_t d_new_limbs = test_case.op2_live_size;
    size_t res_limbs = test_case.res1_live_size;
    size_t check_res_limbs = test_case.check1_size;
    OSSL_FN_ULONG extended_res = test_case.extended_limb_value1;
    OSSL_FN *fn = NULL, *fd = NULL, *fres = NULL;
    const OSSL_FN_ULONG *u = NULL;
    /* Calculate total number of limbs for OSSL_FN_CTX */
    size_t ctx_numcopy_limbs = ((n_new_limbs <= d_new_limbs) ? d_new_limbs : n_new_limbs) + 1;
    size_t ctx_divcopy_limbs = d_new_limbs;
    size_t ctx_tmp_limbs = d_new_limbs + 1;
    size_t ctx_res_limbs = n_new_limbs;
    size_t ctx_max_limbs = ctx_numcopy_limbs + ctx_divcopy_limbs + ctx_res_limbs + ctx_tmp_limbs;

    OSSL_FN_CTX *ctx = NULL;
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 1, 4, ctx_max_limbs))
        || !TEST_ptr(fn = OSSL_FN_new_limbs(n_new_limbs))
        || !TEST_ptr(fd = OSSL_FN_new_limbs(d_new_limbs))
        || !TEST_true(ossl_fn_set_words(fn, n, n_limbs))
        || !TEST_true(ossl_fn_set_words(fd, d, d_limbs))
        || !TEST_ptr(fres = OSSL_FN_new_limbs(res_limbs))) {
        ret = 0;
        /* There's no way to continue tests in this case */
        goto end;
    }

    /* To test that OSSL_FN_mod() does a complete job, 'res' is pre-polluted */

    if (!TEST_true(pollute(fres, 0, res_limbs))
        || !TEST_true(OSSL_FN_mod(fres, fn, fd, ctx))
        || !TEST_ptr(u = ossl_fn_get_words(fres))
        || !TEST_mem_eq(u, check_res_limbs * OSSL_FN_BYTES,
            ex, check_res_limbs * OSSL_FN_BYTES)
        || !TEST_true(check_limbs_value(fres, check_res_limbs, res_limbs, extended_res)))
        ret = 0;

end:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fn);
    OSSL_FN_free(fd);
    OSSL_FN_free(fres);

    return ret;
}

/* i should be set to match the iteration number that's displayed when testing */
#define MOD_CASE(i, op1, op2, ex)                          \
    {                                                      \
        /* op1 */ op1,                                     \
        /* op1_size */ LIMBSOF(op1),                       \
        /* op2 */ op2,                                     \
        /* op2_size */ LIMBSOF(op2),                       \
        /* ex1 */ ex,                                      \
        /* ex1_size */ LIMBSOF(ex),                        \
        /* ex2 */ NULL,                                    \
        /* ex2_size */ 0,                                  \
        /* op1_live_size */ LIMBSOF(op1) + 1,              \
        /* op2_live_size */ LIMBSOF(op2) + 2,              \
        /* res1_live_size */ LIMBSOF(op1) + ((i - 1) % 4), \
        /* res2_live_size */ LIMBSOF(op1) + ((i - 1) % 4), \
        /* check1_size */ LIMBSOF(ex),                     \
        /* check2_size */ 0,                               \
        /* extended_limb_value1 */ EXTENDED_LIMB_ZERO,     \
        /* extended_limb_value2 */ 0,                      \
    }

static struct test_case_st test_mod_cases[] = {
    MOD_CASE(1, num0, num0, ex_rem_num0_num0),
    MOD_CASE(2, num0, num1, ex_rem_num0_num1),
    MOD_CASE(3, num0, num2, ex_rem_num0_num2),
    MOD_CASE(4, num0, num3, ex_rem_num0_num3),
    MOD_CASE(5, num1, num0, ex_rem_num1_num0),
    MOD_CASE(6, num1, num1, ex_rem_num1_num1),
    MOD_CASE(7, num1, num2, ex_rem_num1_num2),
    MOD_CASE(8, num1, num3, ex_rem_num1_num3),
    MOD_CASE(9, num2, num0, ex_rem_num2_num0),
    MOD_CASE(10, num2, num1, ex_rem_num2_num1),
    MOD_CASE(11, num2, num2, ex_rem_num2_num2),
    MOD_CASE(12, num2, num3, ex_rem_num2_num3),
    MOD_CASE(13, num3, num0, ex_rem_num3_num0),
    MOD_CASE(14, num3, num1, ex_rem_num3_num1),
    MOD_CASE(15, num3, num2, ex_rem_num3_num2),
    MOD_CASE(16, num3, num3, ex_rem_num3_num3),

    /* Edge cases */
    MOD_CASE(17, num5, num5, ex_rem_num5_num5),
    MOD_CASE(18, num6, num6, ex_rem_num6_num6),
};

static int test_mod(int i)
{
    return test_mod_common(test_mod_cases[i]);
}

/* i should be set to match the iteration number that's displayed when testing */
#define MOD_TRUNCATED_CASE(i, op1, op2, ex)            \
    {                                                  \
        /* op1 */ op1,                                 \
        /* op1_size */ LIMBSOF(op1),                   \
        /* op2 */ op2,                                 \
        /* op2_size */ LIMBSOF(op2),                   \
        /* ex1 */ ex,                                  \
        /* ex1_size */ LIMBSOF(ex),                    \
        /* ex2 */ NULL,                                \
        /* ex2_size */ 0,                              \
        /* op1_live_size */ LIMBSOF(op1) + 1,          \
        /* op2_live_size */ LIMBSOF(op2) + 2,          \
        /* res1_live_size */ LIMBSOF(ex) / 2,          \
        /* res2_live_size */ 0,                        \
        /* check1_size */ LIMBSOF(ex) / 2,             \
        /* check2_size */ 0,                           \
        /* extended_limb_value1 */ EXTENDED_LIMB_ZERO, \
        /* extended_limb_value2 */ 0,                  \
    }

static struct test_case_st test_mod_truncate_cases[] = {
    MOD_TRUNCATED_CASE(1, num0, num0, ex_rem_num0_num0),
    MOD_TRUNCATED_CASE(2, num0, num1, ex_rem_num0_num1),
    MOD_TRUNCATED_CASE(3, num0, num2, ex_rem_num0_num2),
    MOD_TRUNCATED_CASE(4, num0, num3, ex_rem_num0_num3),
    MOD_TRUNCATED_CASE(5, num1, num0, ex_rem_num1_num0),
    MOD_TRUNCATED_CASE(6, num1, num1, ex_rem_num1_num1),
    MOD_TRUNCATED_CASE(7, num1, num2, ex_rem_num1_num2),
    MOD_TRUNCATED_CASE(8, num1, num3, ex_rem_num1_num3),
    MOD_TRUNCATED_CASE(9, num2, num0, ex_rem_num2_num0),
    MOD_TRUNCATED_CASE(10, num2, num1, ex_rem_num2_num1),
    MOD_TRUNCATED_CASE(11, num2, num2, ex_rem_num2_num2),
    MOD_TRUNCATED_CASE(12, num2, num3, ex_rem_num2_num3),
    MOD_TRUNCATED_CASE(13, num3, num0, ex_rem_num3_num0),
    MOD_TRUNCATED_CASE(14, num3, num1, ex_rem_num3_num1),
    MOD_TRUNCATED_CASE(15, num3, num2, ex_rem_num3_num2),
    MOD_TRUNCATED_CASE(16, num3, num3, ex_rem_num3_num3),

    /* Edge cases */
    MOD_TRUNCATED_CASE(17, num5, num5, ex_rem_num5_num5),
    MOD_TRUNCATED_CASE(18, num6, num6, ex_rem_num6_num6),
};

static int test_mod_truncated(int i)
{
    return test_mod_common(test_mod_truncate_cases[i]);
}

static int check_div_by_zero_error(void)
{
    unsigned long err = ERR_get_error();

    return TEST_ulong_ne(err, 0)
        && TEST_int_eq(ERR_GET_LIB(err), ERR_LIB_OSSL_FN)
        && TEST_int_eq(ERR_GET_REASON(err), OSSL_FN_R_DIV_BY_ZERO);
}

static int test_div_by_zero_common(int test_mod)
{
    int ret = 1;
    OSSL_FN *fn = NULL, *fd = NULL, *fq = NULL, *fr = NULL;
    OSSL_FN_CTX *ctx = NULL;
    size_t n_new_limbs = LIMBSOF(num0) + 1;
    size_t d_new_limbs = LIMBSOF(num4) + 2;
    size_t q_limbs = LIMBSOF(num0) + 1;
    size_t r_limbs = LIMBSOF(num0) + 1;
    size_t ctx_numcopy_limbs = ((n_new_limbs <= d_new_limbs) ? d_new_limbs : n_new_limbs) + 1;
    size_t ctx_divcopy_limbs = d_new_limbs;
    size_t ctx_tmp_limbs = d_new_limbs + 1;
    size_t ctx_res_limbs = n_new_limbs;
    size_t ctx_max_limbs = ctx_numcopy_limbs + ctx_divcopy_limbs + ctx_res_limbs + ctx_tmp_limbs;

    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 1, 4, ctx_max_limbs))
        || !TEST_ptr(fn = OSSL_FN_new_limbs(n_new_limbs))
        || !TEST_ptr(fd = OSSL_FN_new_limbs(d_new_limbs))
        || !TEST_ptr(fq = OSSL_FN_new_limbs(q_limbs))
        || !TEST_ptr(fr = OSSL_FN_new_limbs(r_limbs))
        || !TEST_true(ossl_fn_set_words(fn, num0, LIMBSOF(num0)))) {
        ret = 0;
        goto end;
    }

    ERR_clear_error();
    if (test_mod) {
        if (!TEST_false(OSSL_FN_mod(fr, fn, fd, ctx))
            || !TEST_true(check_div_by_zero_error()))
            ret = 0;
    } else {
        if (!TEST_false(OSSL_FN_div(fq, fr, fn, fd, ctx))
            || !TEST_true(check_div_by_zero_error()))
            ret = 0;
    }

end:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fn);
    OSSL_FN_free(fd);
    OSSL_FN_free(fq);
    OSSL_FN_free(fr);

    return ret;
}

static int test_div_by_zero(void)
{
    return test_div_by_zero_common(0);
}

static int test_mod_by_zero(void)
{
    return test_div_by_zero_common(1);
}

static struct mod_op_test_st test_mod_add_cases[] = {
    { num0, LIMBSOF(num0), num1, LIMBSOF(num1), num2, LIMBSOF(num2), 0 },
    { num2, LIMBSOF(num2), num3, LIMBSOF(num3), num2, LIMBSOF(num2), 0 },
    { num4, LIMBSOF(num4), num0, LIMBSOF(num0), num3, LIMBSOF(num3), 0 },
    { num5, LIMBSOF(num5), num5, LIMBSOF(num5), num6, LIMBSOF(num6), 0 },
};

static struct mod_op_test_st test_mod_sub_cases[] = {
    { num0, LIMBSOF(num0), num1, LIMBSOF(num1), num2, LIMBSOF(num2), 0 },
    { num3, LIMBSOF(num3), num2, LIMBSOF(num2), num2, LIMBSOF(num2), 0 },
    { num3, LIMBSOF(num3), num3, LIMBSOF(num3), num2, LIMBSOF(num2), 0 },
    { num5, LIMBSOF(num5), num4, LIMBSOF(num4), num6, LIMBSOF(num6), 0 },
};

static struct mod_op_test_st test_mod_mul_cases[] = {
    { num0, LIMBSOF(num0), num1, LIMBSOF(num1), num2, LIMBSOF(num2), 0 },
    { num2, LIMBSOF(num2), num3, LIMBSOF(num3), num2, LIMBSOF(num2), 0 },
    { num0, LIMBSOF(num0), num0, LIMBSOF(num0), num3, LIMBSOF(num3), 0 },
    { num5, LIMBSOF(num5), num5, LIMBSOF(num5), num6, LIMBSOF(num6), 0 },
};

static struct mod_op_test_st test_mod_sqr_cases[] = {
    { num0, LIMBSOF(num0), NULL, 0, num2, LIMBSOF(num2), 0 },
    { num2, LIMBSOF(num2), NULL, 0, num2, LIMBSOF(num2), 0 },
    { num5, LIMBSOF(num5), NULL, 0, num6, LIMBSOF(num6), 0 },
};

static struct mod_op_test_st test_mod_lshift1_cases[] = {
    { num0, LIMBSOF(num0), NULL, 0, num2, LIMBSOF(num2), 0 },
    { num2, LIMBSOF(num2), NULL, 0, num3, LIMBSOF(num3), 0 },
    { num5, LIMBSOF(num5), NULL, 0, num6, LIMBSOF(num6), 0 },
};

static struct mod_op_test_st test_mod_lshift_cases[] = {
    { num0, LIMBSOF(num0), NULL, 0, num2, LIMBSOF(num2), 1 },
    { num0, LIMBSOF(num0), NULL, 0, num2, LIMBSOF(num2), 3 },
    { num2, LIMBSOF(num2), NULL, 0, num3, LIMBSOF(num3), 5 },
    { num5, LIMBSOF(num5), NULL, 0, num6, LIMBSOF(num6), 7 },
};

static int test_mod_add(int i)
{
    struct mod_op_test_st *tc = &test_mod_add_cases[i];
    size_t m_size = tc->m_size;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *fa = NULL, *fb = NULL, *fm = NULL;
    OSSL_FN *r_gen = NULL, *r_quick = NULL, *expected = NULL;
    OSSL_FN *tmp = NULL, *fa_red = NULL, *fb_red = NULL;
    int ret = 0;
    const OSSL_FN_ULONG *u_gen, *u_quick, *u_exp;

    ctx = OSSL_FN_CTX_new(NULL, 4, 8, 8 * m_size + 8);
    if (!TEST_ptr(ctx))
        goto err;

    fa = OSSL_FN_new_limbs(m_size);
    fb = OSSL_FN_new_limbs(m_size);
    fm = OSSL_FN_new_limbs(m_size);
    r_gen = OSSL_FN_new_limbs(m_size);
    r_quick = OSSL_FN_new_limbs(m_size);
    expected = OSSL_FN_new_limbs(m_size);
    fa_red = OSSL_FN_new_limbs(m_size);
    fb_red = OSSL_FN_new_limbs(m_size);
    tmp = OSSL_FN_new_limbs(m_size + 1);
    if (!TEST_ptr(fa) || !TEST_ptr(fb) || !TEST_ptr(fm)
        || !TEST_ptr(r_gen) || !TEST_ptr(r_quick) || !TEST_ptr(expected)
        || !TEST_ptr(fa_red) || !TEST_ptr(fb_red) || !TEST_ptr(tmp))
        goto err;

    if (!TEST_true(ossl_fn_set_words(fa, tc->a, tc->a_size))
        || !TEST_true(ossl_fn_set_words(fb, tc->b, tc->b_size))
        || !TEST_true(ossl_fn_set_words(fm, tc->m, tc->m_size)))
        goto err;

    /* expected = (a + b) mod m */
    if (!TEST_true(OSSL_FN_add(tmp, fa, fb)))
        goto err;
    if (!TEST_true(OSSL_FN_mod(expected, tmp, fm, ctx)))
        goto err;

    /* general = mod_add(a, b, m, ctx) */
    if (!TEST_true(OSSL_FN_mod_add(r_gen, fa, fb, fm, ctx)))
        goto err;

    /* reduce a and b for quick variant */
    if (!TEST_true(OSSL_FN_mod(fa_red, fa, fm, ctx))
        || !TEST_true(OSSL_FN_mod(fb_red, fb, fm, ctx)))
        goto err;

    /* quick = mod_add_quick(a_red, b_red, m) */
    if (!TEST_true(OSSL_FN_mod_add_quick(r_quick, fa_red, fb_red, fm)))
        goto err;

    u_gen = ossl_fn_get_words(r_gen);
    u_quick = ossl_fn_get_words(r_quick);
    u_exp = ossl_fn_get_words(expected);

    if (!TEST_mem_eq(u_gen, m_size * OSSL_FN_BYTES,
            u_exp, m_size * OSSL_FN_BYTES))
        goto err;
    if (!TEST_mem_eq(u_quick, m_size * OSSL_FN_BYTES,
            u_exp, m_size * OSSL_FN_BYTES))
        goto err;
    if (!TEST_mem_eq(u_gen, m_size * OSSL_FN_BYTES,
            u_quick, m_size * OSSL_FN_BYTES))
        goto err;

    ret = 1;

err:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fa);
    OSSL_FN_free(fb);
    OSSL_FN_free(fm);
    OSSL_FN_free(r_gen);
    OSSL_FN_free(r_quick);
    OSSL_FN_free(expected);
    OSSL_FN_free(fa_red);
    OSSL_FN_free(fb_red);
    OSSL_FN_free(tmp);
    return ret;
}

static int test_mod_sub(int i)
{
    struct mod_op_test_st *tc = &test_mod_sub_cases[i];
    size_t m_size = tc->m_size;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *fa = NULL, *fb = NULL, *fm = NULL;
    OSSL_FN *r_gen = NULL, *r_quick = NULL, *expected = NULL;
    OSSL_FN *tmp = NULL, *fa_red = NULL, *fb_red = NULL;
    int ret = 0;
    const OSSL_FN_ULONG *u_gen, *u_quick, *u_exp;

    ctx = OSSL_FN_CTX_new(NULL, 4, 8, 8 * m_size + 8);
    if (!TEST_ptr(ctx))
        goto err;

    fa = OSSL_FN_new_limbs(m_size);
    fb = OSSL_FN_new_limbs(m_size);
    fm = OSSL_FN_new_limbs(m_size);
    r_gen = OSSL_FN_new_limbs(m_size);
    r_quick = OSSL_FN_new_limbs(m_size);
    expected = OSSL_FN_new_limbs(m_size);
    fa_red = OSSL_FN_new_limbs(m_size);
    fb_red = OSSL_FN_new_limbs(m_size);
    tmp = OSSL_FN_new_limbs(m_size);
    if (!TEST_ptr(fa) || !TEST_ptr(fb) || !TEST_ptr(fm)
        || !TEST_ptr(r_gen) || !TEST_ptr(r_quick) || !TEST_ptr(expected)
        || !TEST_ptr(fa_red) || !TEST_ptr(fb_red) || !TEST_ptr(tmp))
        goto err;

    if (!TEST_true(ossl_fn_set_words(fa, tc->a, tc->a_size))
        || !TEST_true(ossl_fn_set_words(fb, tc->b, tc->b_size))
        || !TEST_true(ossl_fn_set_words(fm, tc->m, tc->m_size)))
        goto err;

    /* expected = (a - b) mod m */
    if (!TEST_true(OSSL_FN_sub(tmp, fa, fb)))
        goto err;
    if (!TEST_true(OSSL_FN_mod(expected, tmp, fm, ctx)))
        goto err;

    /* general = mod_sub(a, b, m, ctx) */
    if (!TEST_true(OSSL_FN_mod_sub(r_gen, fa, fb, fm, ctx)))
        goto err;

    /* reduce a and b for quick variant */
    if (!TEST_true(OSSL_FN_mod(fa_red, fa, fm, ctx))
        || !TEST_true(OSSL_FN_mod(fb_red, fb, fm, ctx)))
        goto err;

    /* quick = mod_sub_quick(a_red, b_red, m) */
    if (!TEST_true(OSSL_FN_mod_sub_quick(r_quick, fa_red, fb_red, fm)))
        goto err;

    u_gen = ossl_fn_get_words(r_gen);
    u_quick = ossl_fn_get_words(r_quick);
    u_exp = ossl_fn_get_words(expected);

    if (!TEST_mem_eq(u_gen, m_size * OSSL_FN_BYTES,
            u_exp, m_size * OSSL_FN_BYTES))
        goto err;
    if (!TEST_mem_eq(u_quick, m_size * OSSL_FN_BYTES,
            u_exp, m_size * OSSL_FN_BYTES))
        goto err;
    if (!TEST_mem_eq(u_gen, m_size * OSSL_FN_BYTES,
            u_quick, m_size * OSSL_FN_BYTES))
        goto err;

    ret = 1;

err:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fa);
    OSSL_FN_free(fb);
    OSSL_FN_free(fm);
    OSSL_FN_free(r_gen);
    OSSL_FN_free(r_quick);
    OSSL_FN_free(expected);
    OSSL_FN_free(fa_red);
    OSSL_FN_free(fb_red);
    OSSL_FN_free(tmp);
    return ret;
}

static int test_mod_mul(int i)
{
    struct mod_op_test_st *tc = &test_mod_mul_cases[i];
    size_t m_size = tc->m_size;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *fa = NULL, *fb = NULL, *fm = NULL;
    OSSL_FN *r = NULL, *expected = NULL, *tmp = NULL;
    int ret = 0;
    const OSSL_FN_ULONG *u_r, *u_exp;

    ctx = OSSL_FN_CTX_new(NULL, 4, 8, 8 * m_size + 8);
    if (!TEST_ptr(ctx))
        goto err;

    fa = OSSL_FN_new_limbs(m_size);
    fb = OSSL_FN_new_limbs(m_size);
    fm = OSSL_FN_new_limbs(m_size);
    r = OSSL_FN_new_limbs(m_size);
    expected = OSSL_FN_new_limbs(m_size);
    tmp = OSSL_FN_new_limbs(m_size * 2);
    if (!TEST_ptr(fa) || !TEST_ptr(fb) || !TEST_ptr(fm)
        || !TEST_ptr(r) || !TEST_ptr(expected) || !TEST_ptr(tmp))
        goto err;

    if (!TEST_true(ossl_fn_set_words(fa, tc->a, tc->a_size))
        || !TEST_true(ossl_fn_set_words(fb, tc->b, tc->b_size))
        || !TEST_true(ossl_fn_set_words(fm, tc->m, tc->m_size)))
        goto err;

    /* expected = (a * b) mod m */
    if (!TEST_true(OSSL_FN_mul(tmp, fa, fb, ctx)))
        goto err;
    if (!TEST_true(OSSL_FN_mod(expected, tmp, fm, ctx)))
        goto err;

    /* r = mod_mul(a, b, m, ctx) */
    if (!TEST_true(OSSL_FN_mod_mul(r, fa, fb, fm, ctx)))
        goto err;

    u_r = ossl_fn_get_words(r);
    u_exp = ossl_fn_get_words(expected);

    if (!TEST_mem_eq(u_r, m_size * OSSL_FN_BYTES,
            u_exp, m_size * OSSL_FN_BYTES))
        goto err;

    ret = 1;

err:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fa);
    OSSL_FN_free(fb);
    OSSL_FN_free(fm);
    OSSL_FN_free(r);
    OSSL_FN_free(expected);
    OSSL_FN_free(tmp);
    return ret;
}

static int test_mod_sqr(int i)
{
    struct mod_op_test_st *tc = &test_mod_sqr_cases[i];
    size_t m_size = tc->m_size;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *fa = NULL, *fm = NULL;
    OSSL_FN *r = NULL, *expected = NULL, *tmp = NULL;
    int ret = 0;
    const OSSL_FN_ULONG *u_r, *u_exp;

    ctx = OSSL_FN_CTX_new(NULL, 4, 8, 8 * m_size + 8);
    if (!TEST_ptr(ctx))
        goto err;

    fa = OSSL_FN_new_limbs(m_size);
    fm = OSSL_FN_new_limbs(m_size);
    r = OSSL_FN_new_limbs(m_size);
    expected = OSSL_FN_new_limbs(m_size);
    tmp = OSSL_FN_new_limbs(m_size * 2);
    if (!TEST_ptr(fa) || !TEST_ptr(fm)
        || !TEST_ptr(r) || !TEST_ptr(expected) || !TEST_ptr(tmp))
        goto err;

    if (!TEST_true(ossl_fn_set_words(fa, tc->a, tc->a_size))
        || !TEST_true(ossl_fn_set_words(fm, tc->m, tc->m_size)))
        goto err;

    /* expected = (a * a) mod m */
    if (!TEST_true(OSSL_FN_sqr(tmp, fa, ctx)))
        goto err;
    if (!TEST_true(OSSL_FN_mod(expected, tmp, fm, ctx)))
        goto err;

    /* r = mod_sqr(a, m, ctx) */
    if (!TEST_true(OSSL_FN_mod_sqr(r, fa, fm, ctx)))
        goto err;

    u_r = ossl_fn_get_words(r);
    u_exp = ossl_fn_get_words(expected);

    if (!TEST_mem_eq(u_r, m_size * OSSL_FN_BYTES,
            u_exp, m_size * OSSL_FN_BYTES))
        goto err;

    ret = 1;

err:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fa);
    OSSL_FN_free(fm);
    OSSL_FN_free(r);
    OSSL_FN_free(expected);
    OSSL_FN_free(tmp);
    return ret;
}

static int test_mod_lshift1(int i)
{
    struct mod_op_test_st *tc = &test_mod_lshift1_cases[i];
    size_t m_size = tc->m_size;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *fa = NULL, *fm = NULL;
    OSSL_FN *r_gen = NULL, *r_quick = NULL, *expected = NULL;
    OSSL_FN *tmp = NULL, *fa_red = NULL;
    int ret = 0;
    const OSSL_FN_ULONG *u_gen, *u_quick, *u_exp;

    ctx = OSSL_FN_CTX_new(NULL, 4, 8, 8 * m_size + 8);
    if (!TEST_ptr(ctx))
        goto err;

    fa = OSSL_FN_new_limbs(m_size);
    fm = OSSL_FN_new_limbs(m_size);
    r_gen = OSSL_FN_new_limbs(m_size);
    r_quick = OSSL_FN_new_limbs(m_size);
    expected = OSSL_FN_new_limbs(m_size);
    tmp = OSSL_FN_new_limbs(m_size + 1);
    fa_red = OSSL_FN_new_limbs(m_size);
    if (!TEST_ptr(fa) || !TEST_ptr(fm)
        || !TEST_ptr(r_gen) || !TEST_ptr(r_quick) || !TEST_ptr(expected)
        || !TEST_ptr(tmp) || !TEST_ptr(fa_red))
        goto err;

    if (!TEST_true(ossl_fn_set_words(fa, tc->a, tc->a_size))
        || !TEST_true(ossl_fn_set_words(fm, tc->m, tc->m_size)))
        goto err;

    /* expected = (a + a) mod m */
    if (!TEST_true(OSSL_FN_add(tmp, fa, fa)))
        goto err;
    if (!TEST_true(OSSL_FN_mod(expected, tmp, fm, ctx)))
        goto err;

    /* general = mod_lshift1(a, m, ctx) */
    if (!TEST_true(OSSL_FN_mod_lshift1(r_gen, fa, fm, ctx)))
        goto err;

    /* reduce a for quick variant */
    if (!TEST_true(OSSL_FN_mod(fa_red, fa, fm, ctx)))
        goto err;

    /* quick = mod_lshift1_quick(a_red, m) */
    if (!TEST_true(OSSL_FN_mod_lshift1_quick(r_quick, fa_red, fm)))
        goto err;

    u_gen = ossl_fn_get_words(r_gen);
    u_quick = ossl_fn_get_words(r_quick);
    u_exp = ossl_fn_get_words(expected);

    if (!TEST_mem_eq(u_gen, m_size * OSSL_FN_BYTES,
            u_exp, m_size * OSSL_FN_BYTES))
        goto err;
    if (!TEST_mem_eq(u_quick, m_size * OSSL_FN_BYTES,
            u_exp, m_size * OSSL_FN_BYTES))
        goto err;
    if (!TEST_mem_eq(u_gen, m_size * OSSL_FN_BYTES,
            u_quick, m_size * OSSL_FN_BYTES))
        goto err;

    ret = 1;

err:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fa);
    OSSL_FN_free(fm);
    OSSL_FN_free(r_gen);
    OSSL_FN_free(r_quick);
    OSSL_FN_free(expected);
    OSSL_FN_free(tmp);
    OSSL_FN_free(fa_red);
    return ret;
}

static int test_mod_lshift(int i)
{
    struct mod_op_test_st *tc = &test_mod_lshift_cases[i];
    size_t m_size = tc->m_size;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *fa = NULL, *fm = NULL;
    OSSL_FN *r_gen = NULL, *r_quick = NULL, *expected = NULL;
    OSSL_FN *tmp = NULL, *fa_red = NULL, *pow2n = NULL;
    OSSL_FN_ULONG pow2_word;
    int ret = 0;
    const OSSL_FN_ULONG *u_gen, *u_quick, *u_exp;

    ctx = OSSL_FN_CTX_new(NULL, 4, 8, 8 * m_size + 8);
    if (!TEST_ptr(ctx))
        goto err;

    fa = OSSL_FN_new_limbs(m_size);
    fm = OSSL_FN_new_limbs(m_size);
    r_gen = OSSL_FN_new_limbs(m_size);
    r_quick = OSSL_FN_new_limbs(m_size);
    expected = OSSL_FN_new_limbs(m_size);
    tmp = OSSL_FN_new_limbs(m_size + 1);
    fa_red = OSSL_FN_new_limbs(m_size);
    pow2n = OSSL_FN_new_limbs(1);
    if (!TEST_ptr(fa) || !TEST_ptr(fm)
        || !TEST_ptr(r_gen) || !TEST_ptr(r_quick) || !TEST_ptr(expected)
        || !TEST_ptr(tmp) || !TEST_ptr(fa_red) || !TEST_ptr(pow2n))
        goto err;

    if (!TEST_true(ossl_fn_set_words(fa, tc->a, tc->a_size))
        || !TEST_true(ossl_fn_set_words(fm, tc->m, tc->m_size)))
        goto err;

    pow2_word = ((OSSL_FN_ULONG)1) << tc->n;
    if (!TEST_true(ossl_fn_set_words(pow2n, &pow2_word, 1)))
        goto err;

    /* expected = (a * 2^n) mod m */
    if (!TEST_true(OSSL_FN_mul(tmp, fa, pow2n, ctx)))
        goto err;
    if (!TEST_true(OSSL_FN_mod(expected, tmp, fm, ctx)))
        goto err;

    /* general = mod_lshift(a, n, m, ctx) */
    if (!TEST_true(OSSL_FN_mod_lshift(r_gen, fa, tc->n, fm, ctx)))
        goto err;

    /* reduce a for quick variant */
    if (!TEST_true(OSSL_FN_mod(fa_red, fa, fm, ctx)))
        goto err;

    /* quick = mod_lshift_quick(a_red, n, m) */
    if (!TEST_true(OSSL_FN_mod_lshift_quick(r_quick, fa_red, tc->n, fm)))
        goto err;

    u_gen = ossl_fn_get_words(r_gen);
    u_quick = ossl_fn_get_words(r_quick);
    u_exp = ossl_fn_get_words(expected);

    if (!TEST_mem_eq(u_gen, m_size * OSSL_FN_BYTES,
            u_exp, m_size * OSSL_FN_BYTES))
        goto err;
    if (!TEST_mem_eq(u_quick, m_size * OSSL_FN_BYTES,
            u_exp, m_size * OSSL_FN_BYTES))
        goto err;
    if (!TEST_mem_eq(u_gen, m_size * OSSL_FN_BYTES,
            u_quick, m_size * OSSL_FN_BYTES))
        goto err;

    ret = 1;

err:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fa);
    OSSL_FN_free(fm);
    OSSL_FN_free(r_gen);
    OSSL_FN_free(r_quick);
    OSSL_FN_free(expected);
    OSSL_FN_free(tmp);
    OSSL_FN_free(fa_red);
    OSSL_FN_free(pow2n);
    return ret;
}

static const OSSL_FN_ULONG mod_secp128r1_p[] = {
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff),
    OSSL_FN_ULONG64_C(0xfffffffd, 0xffffffff),
};
static const OSSL_FN_ULONG mod_secp128r1_a[] = {
    OSSL_FN_ULONG64_C(0xffffffff, 0xfffffffc),
    OSSL_FN_ULONG64_C(0xfffffff7, 0xffffffff),
};
static const OSSL_FN_ULONG mod_secp128r1_x2[] = {
    OSSL_FN_ULONG64_C(0x7f04aa75, 0x6b2f9496),
    OSSL_FN_ULONG64_C(0x74e2ecb0, 0x826a5208),
};
static const OSSL_FN_ULONG mod_secp128r1_x2_plus_a[] = {
    OSSL_FN_ULONG64_C(0x7f04aa75, 0x6b2f9493),
    OSSL_FN_ULONG64_C(0x74e2ecaa, 0x826a5208),
};

static const OSSL_FN_ULONG mod_sub_wide_a[] = {
    OSSL_FN_ULONG_C(0x7),
#if OSSL_FN_BYTES == 4
    OSSL_FN_ULONG_C(0),
#endif
    OSSL_FN_ULONG_C(0x1),
};
static const OSSL_FN_ULONG mod_sub_wide_b[] = {
    OSSL_FN_ULONG_C(0x1),
};
static const OSSL_FN_ULONG mod_sub_wide_m[] = {
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffc5),
};
static const OSSL_FN_ULONG mod_sub_wide_expected[] = {
    OSSL_FN_ULONG_C(0x41),
};
static const OSSL_FN_ULONG mod_sub_negative_a[] = {
    OSSL_FN_ULONG_C(0x1),
};
static const OSSL_FN_ULONG mod_sub_negative_b[] = {
    OSSL_FN_ULONG_C(0x3),
};
static const OSSL_FN_ULONG mod_sub_negative_m[] = {
    OSSL_FN_ULONG_C(0x5),
};
static const OSSL_FN_ULONG mod_sub_negative_expected[] = {
    OSSL_FN_ULONG_C(0x3),
};

static int test_mod_quick_wide_operands(void)
{
    size_t m_size = LIMBSOF(mod_secp128r1_p);
    size_t wide_size = m_size + 2;
    OSSL_FN *fa = NULL, *fb = NULL, *fm = NULL;
    OSSL_FN *r = NULL, *expected = NULL;
    const OSSL_FN_ULONG *u_r = NULL, *u_exp = NULL;
    int ret = 0;

    fa = OSSL_FN_new_limbs(wide_size);
    fb = OSSL_FN_new_limbs(m_size);
    fm = OSSL_FN_new_limbs(m_size);
    r = OSSL_FN_new_limbs(wide_size);
    expected = OSSL_FN_new_limbs(wide_size);
    if (!TEST_ptr(fa) || !TEST_ptr(fb) || !TEST_ptr(fm)
        || !TEST_ptr(r) || !TEST_ptr(expected))
        goto err;

    if (!TEST_true(ossl_fn_set_words(fa, mod_secp128r1_x2,
            LIMBSOF(mod_secp128r1_x2)))
        || !TEST_true(ossl_fn_set_words(fb, mod_secp128r1_a,
            LIMBSOF(mod_secp128r1_a)))
        || !TEST_true(ossl_fn_set_words(fm, mod_secp128r1_p,
            LIMBSOF(mod_secp128r1_p)))
        || !TEST_true(ossl_fn_set_words(expected, mod_secp128r1_x2_plus_a,
            LIMBSOF(mod_secp128r1_x2_plus_a)))
        || !TEST_true(pollute(r, 0, wide_size))
        || !TEST_true(OSSL_FN_mod_add_quick(r, fa, fb, fm)))
        goto err;

    u_r = ossl_fn_get_words(r);
    u_exp = ossl_fn_get_words(expected);
    if (!TEST_mem_eq(u_r, wide_size * OSSL_FN_BYTES,
            u_exp, wide_size * OSSL_FN_BYTES))
        goto err;

    if (!TEST_true(ossl_fn_set_words(fa, mod_secp128r1_x2_plus_a,
            LIMBSOF(mod_secp128r1_x2_plus_a)))
        || !TEST_true(ossl_fn_set_words(expected, mod_secp128r1_x2,
            LIMBSOF(mod_secp128r1_x2)))
        || !TEST_true(pollute(r, 0, wide_size))
        || !TEST_true(OSSL_FN_mod_sub_quick(r, fa, fb, fm)))
        goto err;

    u_r = ossl_fn_get_words(r);
    u_exp = ossl_fn_get_words(expected);
    if (!TEST_mem_eq(u_r, wide_size * OSSL_FN_BYTES,
            u_exp, wide_size * OSSL_FN_BYTES))
        goto err;

    ret = 1;
err:
    OSSL_FN_free(fa);
    OSSL_FN_free(fb);
    OSSL_FN_free(fm);
    OSSL_FN_free(r);
    OSSL_FN_free(expected);
    return ret;
}

static int test_mod_sub_general_wide_operands(void)
{
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *fa = NULL, *fb = NULL, *fm = NULL;
    OSSL_FN *r = NULL, *expected = NULL;
    const OSSL_FN_ULONG *u_r = NULL, *u_exp = NULL;
    int ret = 0;

    ctx = OSSL_FN_CTX_new(NULL, 4, 8, 32);
    fa = OSSL_FN_new_limbs(LIMBSOF(mod_sub_wide_a));
    fb = OSSL_FN_new_limbs(LIMBSOF(mod_sub_wide_b));
    fm = OSSL_FN_new_limbs(LIMBSOF(mod_sub_wide_m));
    r = OSSL_FN_new_limbs(LIMBSOF(mod_sub_wide_m));
    expected = OSSL_FN_new_limbs(LIMBSOF(mod_sub_wide_m));
    if (!TEST_ptr(ctx) || !TEST_ptr(fa) || !TEST_ptr(fb) || !TEST_ptr(fm)
        || !TEST_ptr(r) || !TEST_ptr(expected))
        goto err;

    if (!TEST_true(ossl_fn_set_words(fa, mod_sub_wide_a,
            LIMBSOF(mod_sub_wide_a)))
        || !TEST_true(ossl_fn_set_words(fb, mod_sub_wide_b,
            LIMBSOF(mod_sub_wide_b)))
        || !TEST_true(ossl_fn_set_words(fm, mod_sub_wide_m,
            LIMBSOF(mod_sub_wide_m)))
        || !TEST_true(ossl_fn_set_words(expected, mod_sub_wide_expected,
            LIMBSOF(mod_sub_wide_expected)))
        || !TEST_true(pollute(r, 0, LIMBSOF(mod_sub_wide_m)))
        || !TEST_true(OSSL_FN_mod_sub(r, fa, fb, fm, ctx)))
        goto err;

    u_r = ossl_fn_get_words(r);
    u_exp = ossl_fn_get_words(expected);
    if (!TEST_mem_eq(u_r, LIMBSOF(mod_sub_wide_m) * OSSL_FN_BYTES,
            u_exp, LIMBSOF(mod_sub_wide_m) * OSSL_FN_BYTES))
        goto err;

    if (!TEST_true(ossl_fn_set_words(fa, mod_sub_negative_a,
            LIMBSOF(mod_sub_negative_a)))
        || !TEST_true(ossl_fn_set_words(fb, mod_sub_negative_b,
            LIMBSOF(mod_sub_negative_b)))
        || !TEST_true(ossl_fn_set_words(fm, mod_sub_negative_m,
            LIMBSOF(mod_sub_negative_m)))
        || !TEST_true(ossl_fn_set_words(expected, mod_sub_negative_expected,
            LIMBSOF(mod_sub_negative_expected)))
        || !TEST_true(pollute(r, 0, LIMBSOF(mod_sub_negative_m)))
        || !TEST_true(OSSL_FN_mod_sub(r, fa, fb, fm, ctx)))
        goto err;

    u_r = ossl_fn_get_words(r);
    u_exp = ossl_fn_get_words(expected);
    if (!TEST_mem_eq(u_r, LIMBSOF(mod_sub_negative_m) * OSSL_FN_BYTES,
            u_exp, LIMBSOF(mod_sub_negative_m) * OSSL_FN_BYTES))
        goto err;

    ret = 1;
err:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fa);
    OSSL_FN_free(fb);
    OSSL_FN_free(fm);
    OSSL_FN_free(r);
    OSSL_FN_free(expected);
    return ret;
}

static int test_mod_ops_result_size(int i)
{
    size_t m_size = LIMBSOF(num7);
    size_t r_size = i == 0 ? m_size - 1 : i == 1 ? m_size
                                                 : m_size + 2;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *fa = NULL, *fb = NULL, *fm = NULL, *expected = NULL;
    OSSL_FN *r_gen = NULL, *r_quick = NULL, *tmp = NULL, *fa_red = NULL;
    OSSL_FN *fb_red = NULL, *pow2n = NULL;
    OSSL_FN_ULONG pow2_word = 1 << 7;
    const OSSL_FN_ULONG *u_gen = NULL, *u_quick = NULL, *u_exp = NULL;
    int ret = 0;

    ctx = OSSL_FN_CTX_new(NULL, 6, 12, 16 * m_size + 16);
    if (!TEST_ptr(ctx))
        goto err;

    fa = OSSL_FN_new_limbs(m_size);
    fb = OSSL_FN_new_limbs(m_size);
    fm = OSSL_FN_new_limbs(m_size);
    expected = OSSL_FN_new_limbs(r_size);
    r_gen = OSSL_FN_new_limbs(r_size);
    r_quick = OSSL_FN_new_limbs(r_size);
    tmp = OSSL_FN_new_limbs(2 * m_size);
    fa_red = OSSL_FN_new_limbs(m_size);
    fb_red = OSSL_FN_new_limbs(m_size);
    pow2n = OSSL_FN_new_limbs(1);
    if (!TEST_ptr(fa) || !TEST_ptr(fb) || !TEST_ptr(fm)
        || !TEST_ptr(expected) || !TEST_ptr(r_gen) || !TEST_ptr(r_quick)
        || !TEST_ptr(tmp) || !TEST_ptr(fa_red) || !TEST_ptr(fb_red)
        || !TEST_ptr(pow2n))
        goto err;

    if (!TEST_true(ossl_fn_set_words(fa, num5, LIMBSOF(num5)))
        || !TEST_true(ossl_fn_set_words(fb, num5, LIMBSOF(num5)))
        || !TEST_true(ossl_fn_set_words(fm, num7, LIMBSOF(num7)))
        || !TEST_true(ossl_fn_set_words(pow2n, &pow2_word, 1)))
        goto err;

#define CHECK_MOD_OP_RESULT(opname)                                \
    do {                                                           \
        u_gen = ossl_fn_get_words(r_gen);                          \
        u_quick = ossl_fn_get_words(r_quick);                      \
        u_exp = ossl_fn_get_words(expected);                       \
        if (!TEST_mem_eq(u_gen, r_size * OSSL_FN_BYTES,            \
                u_exp, r_size * OSSL_FN_BYTES)) {                  \
            TEST_note("%s general, r_size = %zu", opname, r_size); \
            goto err;                                              \
        }                                                          \
        if (!TEST_mem_eq(u_quick, r_size * OSSL_FN_BYTES,          \
                u_exp, r_size * OSSL_FN_BYTES)) {                  \
            TEST_note("%s quick, r_size = %zu", opname, r_size);   \
            goto err;                                              \
        }                                                          \
    } while (0)

    if (!TEST_true(pollute(expected, 0, r_size))
        || !TEST_true(pollute(r_gen, 0, r_size))
        || !TEST_true(pollute(r_quick, 0, r_size))
        || !TEST_true(OSSL_FN_add(tmp, fa, fb))
        || !TEST_true(OSSL_FN_mod(expected, tmp, fm, ctx))
        || !TEST_true(OSSL_FN_mod_add(r_gen, fa, fb, fm, ctx))
        || !TEST_true(OSSL_FN_mod(fa_red, fa, fm, ctx))
        || !TEST_true(OSSL_FN_mod(fb_red, fb, fm, ctx))
        || !TEST_true(OSSL_FN_mod_add_quick(r_quick, fa_red, fb_red, fm)))
        goto err;
    CHECK_MOD_OP_RESULT("mod_add");

    if (!TEST_true(ossl_fn_set_words(fa, num5, LIMBSOF(num5)))
        || !TEST_true(ossl_fn_set_words(fb, num4, LIMBSOF(num4)))
        || !TEST_true(pollute(expected, 0, r_size))
        || !TEST_true(pollute(r_gen, 0, r_size))
        || !TEST_true(pollute(r_quick, 0, r_size))
        || !TEST_true(OSSL_FN_sub(tmp, fa, fb))
        || !TEST_true(OSSL_FN_mod(expected, tmp, fm, ctx))
        || !TEST_true(OSSL_FN_mod_sub(r_gen, fa, fb, fm, ctx))
        || !TEST_true(OSSL_FN_mod(fa_red, fa, fm, ctx))
        || !TEST_true(OSSL_FN_mod(fb_red, fb, fm, ctx))
        || !TEST_true(OSSL_FN_mod_sub_quick(r_quick, fa_red, fb_red, fm)))
        goto err;
    CHECK_MOD_OP_RESULT("mod_sub");

    if (!TEST_true(ossl_fn_set_words(fb, num5, LIMBSOF(num5)))
        || !TEST_true(pollute(expected, 0, r_size))
        || !TEST_true(pollute(r_gen, 0, r_size))
        || !TEST_true(pollute(r_quick, 0, r_size))
        || !TEST_true(OSSL_FN_mul(tmp, fa, fb, ctx))
        || !TEST_true(OSSL_FN_mod(expected, tmp, fm, ctx))
        || !TEST_true(OSSL_FN_mod_mul(r_gen, fa, fb, fm, ctx))
        || !TEST_true(OSSL_FN_mod_mul(r_quick, fa, fb, fm, ctx)))
        goto err;
    CHECK_MOD_OP_RESULT("mod_mul");

    if (!TEST_true(pollute(expected, 0, r_size))
        || !TEST_true(pollute(r_gen, 0, r_size))
        || !TEST_true(pollute(r_quick, 0, r_size))
        || !TEST_true(OSSL_FN_sqr(tmp, fa, ctx))
        || !TEST_true(OSSL_FN_mod(expected, tmp, fm, ctx))
        || !TEST_true(OSSL_FN_mod_sqr(r_gen, fa, fm, ctx))
        || !TEST_true(OSSL_FN_mod_sqr(r_quick, fa, fm, ctx)))
        goto err;
    CHECK_MOD_OP_RESULT("mod_sqr");

    if (!TEST_true(pollute(expected, 0, r_size))
        || !TEST_true(pollute(r_gen, 0, r_size))
        || !TEST_true(pollute(r_quick, 0, r_size))
        || !TEST_true(OSSL_FN_add(tmp, fa, fa))
        || !TEST_true(OSSL_FN_mod(expected, tmp, fm, ctx))
        || !TEST_true(OSSL_FN_mod_lshift1(r_gen, fa, fm, ctx))
        || !TEST_true(OSSL_FN_mod(fa_red, fa, fm, ctx))
        || !TEST_true(OSSL_FN_mod_lshift1_quick(r_quick, fa_red, fm)))
        goto err;
    CHECK_MOD_OP_RESULT("mod_lshift1");

    if (!TEST_true(pollute(expected, 0, r_size))
        || !TEST_true(pollute(r_gen, 0, r_size))
        || !TEST_true(pollute(r_quick, 0, r_size))
        || !TEST_true(OSSL_FN_mul(tmp, fa, pow2n, ctx))
        || !TEST_true(OSSL_FN_mod(expected, tmp, fm, ctx))
        || !TEST_true(OSSL_FN_mod_lshift(r_gen, fa, 7, fm, ctx))
        || !TEST_true(OSSL_FN_mod(fa_red, fa, fm, ctx))
        || !TEST_true(OSSL_FN_mod_lshift_quick(r_quick, fa_red, 7, fm)))
        goto err;
    CHECK_MOD_OP_RESULT("mod_lshift");

#undef CHECK_MOD_OP_RESULT

    ret = 1;

err:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fa);
    OSSL_FN_free(fb);
    OSSL_FN_free(fm);
    OSSL_FN_free(expected);
    OSSL_FN_free(r_gen);
    OSSL_FN_free(r_quick);
    OSSL_FN_free(tmp);
    OSSL_FN_free(fa_red);
    OSSL_FN_free(fb_red);
    OSSL_FN_free(pow2n);
    return ret;
}

/*-
 * Focused tests for OSSL_FN_rand() / OSSL_FN_priv_rand() and the range
 * variants.  Random values cannot be compared against a fixed oracle, so
 * these tests verify the mathematical contract the functions guarantee:
 * the result fits in |bits|, the |top| and |bottom| bit constraints hold,
 * the destination's high limbs are zeroed, and range results satisfy
 * 0 <= r < range.  The byte-to-limb shaping is exercised through
 * non-limb-multiple bit counts and wider-than-needed destinations.
 */
struct rand_bits_case_st {
    int bits;
    int top;
    int bottom;
};

static const struct rand_bits_case_st rand_bits_cases[] = {
    /* bit counts that are not limb multiples, to stress the top-byte mask */
    { 1, OSSL_FN_RAND_TOP_ANY, OSSL_FN_RAND_BOTTOM_ANY },
    { 1, OSSL_FN_RAND_TOP_ONE, OSSL_FN_RAND_BOTTOM_ANY },
    { 7, OSSL_FN_RAND_TOP_ANY, OSSL_FN_RAND_BOTTOM_ANY },
    { 7, OSSL_FN_RAND_TOP_ONE, OSSL_FN_RAND_BOTTOM_ODD },
    { 7, OSSL_FN_RAND_TOP_TWO, OSSL_FN_RAND_BOTTOM_ODD },
    { OSSL_FN_BITS - 1, OSSL_FN_RAND_TOP_ANY, OSSL_FN_RAND_BOTTOM_ANY },
    { OSSL_FN_BITS - 1, OSSL_FN_RAND_TOP_ONE, OSSL_FN_RAND_BOTTOM_ODD },
    { OSSL_FN_BITS, OSSL_FN_RAND_TOP_ANY, OSSL_FN_RAND_BOTTOM_ANY },
    { OSSL_FN_BITS, OSSL_FN_RAND_TOP_TWO, OSSL_FN_RAND_BOTTOM_ODD },
    { OSSL_FN_BITS + 1, OSSL_FN_RAND_TOP_ANY, OSSL_FN_RAND_BOTTOM_ANY },
    { OSSL_FN_BITS + 1, OSSL_FN_RAND_TOP_ONE, OSSL_FN_RAND_BOTTOM_ANY },
    { 3 * OSSL_FN_BITS, OSSL_FN_RAND_TOP_TWO, OSSL_FN_RAND_BOTTOM_ODD },
};

static int test_rand_bits(int i)
{
    int ret = 0, bits = rand_bits_cases[i].bits;
    int top = rand_bits_cases[i].top;
    int bottom = rand_bits_cases[i].bottom;
    /* Destination sized with one extra limb to check zero-padding above bits. */
    size_t limbs_needed = (bits + OSSL_FN_BITS - 1) / OSSL_FN_BITS;
    size_t dst_limbs = limbs_needed + 1;
    OSSL_FN *r = NULL;
    const OSSL_FN_ULONG *words = NULL;
    size_t dsize, j;

    if (!TEST_ptr(r = OSSL_FN_new_limbs(dst_limbs))
        || !TEST_true(pollute(r, 0, dst_limbs))
        /* Use the private pool; the public one is exercised by test_rand below. */
        || !TEST_true(OSSL_FN_priv_rand(r, bits, top, bottom, 0, NULL)))
        goto err;

    /* The result must fit in |bits| bits. */
    if (!TEST_size_t_le(OSSL_FN_num_bits(r), (size_t)bits))
        goto err;

    /* top constraint: the requested high bit(s) must be set. */
    if (top == OSSL_FN_RAND_TOP_ONE
        && !TEST_int_eq(OSSL_FN_is_bit_set(r, bits - 1), 1))
        goto err;
    if (top == OSSL_FN_RAND_TOP_TWO) {
        if (!TEST_int_eq(OSSL_FN_is_bit_set(r, bits - 1), 1)
            || !TEST_int_eq(OSSL_FN_is_bit_set(r, bits - 2), 1))
            goto err;
    }

    /* bottom constraint: the low bit must be set when ODD is requested. */
    if (bottom == OSSL_FN_RAND_BOTTOM_ODD
        && !TEST_int_eq(OSSL_FN_is_bit_set(r, 0), 1))
        goto err;

    /*
     * Limbs above those needed for |bits| must be zeroed.  bytes =
     * (bits+7)/8, so limbs covering the bytes are (bytes + BYTES - 1) / BYTES;
     * anything above that is padding.
     */
    words = ossl_fn_get_words(r);
    dsize = ossl_fn_get_dsize(r);
    for (j = limbs_needed; j < dsize; j++)
        if (!TEST_size_t_eq(words[j], 0))
            goto err;

    ret = 1;
err:
    OSSL_FN_free(r);
    return ret;
}

/* The public-pool variant (OSSL_FN_rand) must satisfy the same contract. */
static int test_rand(int i)
{
    int ret = 0, bits = rand_bits_cases[i].bits;
    int top = rand_bits_cases[i].top;
    int bottom = rand_bits_cases[i].bottom;
    size_t limbs_needed = (bits + OSSL_FN_BITS - 1) / OSSL_FN_BITS;
    OSSL_FN *r = NULL;

    if (!TEST_ptr(r = OSSL_FN_new_limbs(limbs_needed))
        || !TEST_true(pollute(r, 0, limbs_needed))
        || !TEST_true(OSSL_FN_rand(r, bits, top, bottom, 0, NULL)))
        goto err;
    if (!TEST_size_t_le(OSSL_FN_num_bits(r), (size_t)bits))
        goto err;
    if (top == OSSL_FN_RAND_TOP_ONE
        && !TEST_int_eq(OSSL_FN_is_bit_set(r, bits - 1), 1))
        goto err;
    if (top == OSSL_FN_RAND_TOP_TWO
        && (!TEST_int_eq(OSSL_FN_is_bit_set(r, bits - 1), 1)
            || !TEST_int_eq(OSSL_FN_is_bit_set(r, bits - 2), 1)))
        goto err;
    if (bottom == OSSL_FN_RAND_BOTTOM_ODD
        && !TEST_int_eq(OSSL_FN_is_bit_set(r, 0), 1))
        goto err;
    ret = 1;
err:
    OSSL_FN_free(r);
    return ret;
}

/* A destination too small for |bits| is an error, not an expansion. */
static int test_rand_result_too_small(void)
{
    int ret = 0;
    OSSL_FN *r = NULL;

    /* bits needs 2 limbs on every platform; one-limb destination is too small. */
    if (!TEST_ptr(r = OSSL_FN_new_limbs(1))
        || !TEST_true(pollute(r, 0, 1))
        || !TEST_false(OSSL_FN_priv_rand(r, 2 * OSSL_FN_BITS,
            OSSL_FN_RAND_TOP_ANY,
            OSSL_FN_RAND_BOTTOM_ANY, 0, NULL))
        || !TEST_int_eq(ERR_GET_REASON(ERR_get_error()),
            OSSL_FN_R_RESULT_ARG_TOO_SMALL))
        goto err;
    ret = 1;
err:
    OSSL_FN_free(r);
    return ret;
}

/* bits == 0 with top/bottom set, or bits == 1 with top > 0, are BITS_TOO_SMALL errors. */
static int test_rand_bits_too_small(void)
{
    int ret = 0;
    OSSL_FN *r = NULL;

    if (!TEST_ptr(r = OSSL_FN_new_limbs(2)))
        goto err;

    ERR_clear_error();
    if (!TEST_false(OSSL_FN_priv_rand(r, 0, OSSL_FN_RAND_TOP_ONE,
            OSSL_FN_RAND_BOTTOM_ANY, 0, NULL))
        || !TEST_int_eq(ERR_GET_REASON(ERR_get_error()),
            OSSL_FN_R_BITS_TOO_SMALL))
        goto err;

    ERR_clear_error();
    if (!TEST_false(OSSL_FN_priv_rand(r, 1, OSSL_FN_RAND_TOP_TWO,
            OSSL_FN_RAND_BOTTOM_ANY, 0, NULL))
        || !TEST_int_eq(ERR_GET_REASON(ERR_get_error()),
            OSSL_FN_R_BITS_TOO_SMALL))
        goto err;

    /* bits == 0 with ANY/ANY is the one legal zero-bit case: result is zero. */
    if (!TEST_true(OSSL_FN_priv_rand(r, 0, OSSL_FN_RAND_TOP_ANY,
            OSSL_FN_RAND_BOTTOM_ANY, 0, NULL))
        || !TEST_true(OSSL_FN_is_zero(r)))
        goto err;

    ret = 1;
err:
    OSSL_FN_free(r);
    return ret;
}

/*
 * Range variants: 0 <= r < range must hold.  Covers both range shapes
 * (range = 100..._2 and range = 11..._2 / 101..._2) and the n == 1 case.
 */
static const OSSL_FN_ULONG range_words[][4] = {
    { OSSL_FN_ULONG_C(1) }, /* range == 1 */
    { OSSL_FN_ULONG_C(0), OSSL_FN_ULONG_C(1) }, /* 2^BITS: 100..._2 */
    { OSSL_FN_ULONG_C(3) }, /* 11_2 */
    { OSSL_FN_ULONG_C(5) }, /* 101_2 */
    { OSSL_FN_ULONG_C(0), OSSL_FN_ULONG_C(3) }, /* 3 * 2^BITS: 11..._2 */
    { OSSL_FN_ULONG_C(2), OSSL_FN_ULONG_C(1) }, /* 2^BITS + 2: 101..._2 */
};

static int test_rand_range(int i)
{
    int ret = 0;
    const OSSL_FN_ULONG *rw = range_words[i];
    size_t range_limbs = OSSL_NELEM(range_words[i]);
    OSSL_FN *range = NULL, *r = NULL;

    if (!TEST_ptr(range = OSSL_FN_new_limbs(range_limbs))
        || !TEST_true(ossl_fn_set_words(range, rw, range_limbs))
        || !TEST_ptr(r = OSSL_FN_new_limbs(range_limbs + 1))
        || !TEST_true(pollute(r, 0, range_limbs + 1)))
        goto err;

    if (!TEST_true(OSSL_FN_priv_rand_range(r, range, 0, NULL)))
        goto err;

    /* 0 <= r < range (OSSL_FN is unsigned, so the lower bound is implicit). */
    if (!TEST_int_lt(OSSL_FN_cmp(r, range), 0))
        goto err;

    ret = 1;
err:
    OSSL_FN_free(range);
    OSSL_FN_free(r);
    return ret;
}

/* A zero range is rejected as INVALID_RANGE. */
static int test_rand_range_zero(void)
{
    int ret = 0;
    OSSL_FN *range = NULL, *r = NULL;

    if (!TEST_ptr(range = OSSL_FN_new_limbs(2))
        || !TEST_true(OSSL_FN_zero(range))
        || !TEST_ptr(r = OSSL_FN_new_limbs(2))
        || !TEST_true(pollute(r, 0, 2))
        || !TEST_false(OSSL_FN_rand_range(r, range, 0, NULL))
        || !TEST_int_eq(ERR_GET_REASON(ERR_get_error()),
            OSSL_FN_R_INVALID_RANGE))
        goto err;
    ret = 1;
err:
    OSSL_FN_free(range);
    OSSL_FN_free(r);
    return ret;
}

/*
 * Regression test for an exactly-sized destination with a sparse range
 * (range = 100..._2): the optimized path draws n + 1 bits and needs room for
 * them, so an |r| sized to hold exactly num_bits(range) bits must fall back to
 * standard n-bit rejection sampling rather than fail with
 * OSSL_FN_R_RESULT_ARG_TOO_SMALL.
 */
static int test_rand_range_exactly_sized(void)
{
    int ret = 0;
    OSSL_FN_ULONG rw[1] = { OSSL_FN_ULONG_C(1) << (OSSL_FN_BITS - 1) };
    OSSL_FN *range = NULL, *r = NULL;

    /* range = 2^(BITS-1) = 100..._2, so num_bits(range) == BITS (1 limb). */
    if (!TEST_ptr(range = OSSL_FN_new_limbs(1))
        || !TEST_true(ossl_fn_set_words(range, rw, 1))
        /* r sized to hold exactly BITS bits: one limb, no slack for n + 1. */
        || !TEST_ptr(r = OSSL_FN_new_limbs(1))
        || !TEST_true(pollute(r, 0, 1)))
        goto err;

    if (!TEST_true(OSSL_FN_priv_rand_range(r, range, 0, NULL)))
        goto err;

    /* 0 <= r < range. */
    if (!TEST_int_lt(OSSL_FN_cmp(r, range), 0))
        goto err;

    ret = 1;
err:
    OSSL_FN_free(range);
    OSSL_FN_free(r);
    return ret;
}

/*-
 * OSSL_FN_mod_exp
 *
 * Tests use an independent reference oracle (plain left-to-right binary
 * square-and-multiply, distinct from the sliding-window implementation under
 * test) plus a handful of known-answer cases that anchor both.  The reference
 * is built on OSSL_FN_mod_mul, which has its own tests; a few KATs guard both
 * the reference and the implementation against a shared mod_mul bug.
 */

struct mod_exp_test_st {
    const OSSL_FN_ULONG *a;
    size_t a_size;
    const OSSL_FN_ULONG *p;
    size_t p_size;
    const OSSL_FN_ULONG *m;
    size_t m_size;
    /* Optional known answer; NULL => compare against the reference oracle. */
    const OSSL_FN_ULONG *ex;
    size_t ex_size;
};

/* Small operands. */
static const OSSL_FN_ULONG exp_a0[] = { OSSL_FN_ULONG_C(0) };
static const OSSL_FN_ULONG exp_a2[] = { OSSL_FN_ULONG_C(2) };
static const OSSL_FN_ULONG exp_a3[] = { OSSL_FN_ULONG_C(3) };
static const OSSL_FN_ULONG exp_a5[] = { OSSL_FN_ULONG_C(5) };
static const OSSL_FN_ULONG exp_a7[] = { OSSL_FN_ULONG_C(7) };
static const OSSL_FN_ULONG exp_p0[] = { OSSL_FN_ULONG_C(0) };
static const OSSL_FN_ULONG exp_p1[] = { OSSL_FN_ULONG_C(1) };
static const OSSL_FN_ULONG exp_p5[] = { OSSL_FN_ULONG_C(5) };
static const OSSL_FN_ULONG exp_p10[] = { OSSL_FN_ULONG_C(10) };
static const OSSL_FN_ULONG exp_p16[] = { OSSL_FN_ULONG_C(16) };
/* 30-bit exponent => sliding window size 3. */
static const OSSL_FN_ULONG exp_p30[] = { OSSL_FN_ULONG_C(0x3FFFFFFF) };
/* 256-bit exponent (all-ones) => sliding window size 5. */
static const OSSL_FN_ULONG exp_p256[] = {
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff),
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff),
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff),
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff),
};
static const OSSL_FN_ULONG exp_m0[] = { OSSL_FN_ULONG_C(0) };
static const OSSL_FN_ULONG exp_m1[] = { OSSL_FN_ULONG_C(1) };
static const OSSL_FN_ULONG exp_m5[] = { OSSL_FN_ULONG_C(5) };
static const OSSL_FN_ULONG exp_m7[] = { OSSL_FN_ULONG_C(7) };
static const OSSL_FN_ULONG exp_m6[] = { OSSL_FN_ULONG_C(6) }; /* even */
static const OSSL_FN_ULONG exp_m1000[] = { OSSL_FN_ULONG_C(1000) }; /* even */
static const OSSL_FN_ULONG exp_m65521[] = { OSSL_FN_ULONG_C(65521) };

/* Known answers. */
static const OSSL_FN_ULONG ex_2_10_m1000[] = { OSSL_FN_ULONG_C(24) }; /* 1024 mod 1000 */
static const OSSL_FN_ULONG ex_3_5_m7[] = { OSSL_FN_ULONG_C(5) }; /* 243 mod 7 */
static const OSSL_FN_ULONG ex_2_16_m65521[] = { OSSL_FN_ULONG_C(15) }; /* 65536 mod 65521 */
static const OSSL_FN_ULONG ex_5_0_m7[] = { OSSL_FN_ULONG_C(1) }; /* a^0 = 1 */
static const OSSL_FN_ULONG ex_5_0_m1[] = { OSSL_FN_ULONG_C(0) }; /* a^0 mod 1 = 0 */
static const OSSL_FN_ULONG ex_7_1_m5[] = { OSSL_FN_ULONG_C(2) }; /* 7 mod 5 */
static const OSSL_FN_ULONG ex_0_5_m7[] = { OSSL_FN_ULONG_C(0) }; /* 0^5 = 0 */

static struct mod_exp_test_st test_mod_exp_cases[] = {
    /* Known-answer cases (anchor both implementation and reference). */
    { exp_a2, LIMBSOF(exp_a2), exp_p10, LIMBSOF(exp_p10),
        exp_m1000, LIMBSOF(exp_m1000), ex_2_10_m1000, LIMBSOF(ex_2_10_m1000) },
    { exp_a3, LIMBSOF(exp_a3), exp_p5, LIMBSOF(exp_p5),
        exp_m7, LIMBSOF(exp_m7), ex_3_5_m7, LIMBSOF(ex_3_5_m7) },
    { exp_a2, LIMBSOF(exp_a2), exp_p16, LIMBSOF(exp_p16),
        exp_m65521, LIMBSOF(exp_m65521), ex_2_16_m65521, LIMBSOF(ex_2_16_m65521) },
    { exp_a5, LIMBSOF(exp_a5), exp_p0, LIMBSOF(exp_p0),
        exp_m7, LIMBSOF(exp_m7), ex_5_0_m7, LIMBSOF(ex_5_0_m7) },
    { exp_a5, LIMBSOF(exp_a5), exp_p0, LIMBSOF(exp_p0),
        exp_m1, LIMBSOF(exp_m1), ex_5_0_m1, LIMBSOF(ex_5_0_m1) },
    { exp_a7, LIMBSOF(exp_a7), exp_p1, LIMBSOF(exp_p1),
        exp_m5, LIMBSOF(exp_m5), ex_7_1_m5, LIMBSOF(ex_7_1_m5) },
    { exp_a0, LIMBSOF(exp_a0), exp_p5, LIMBSOF(exp_p5),
        exp_m7, LIMBSOF(exp_m7), ex_0_5_m7, LIMBSOF(ex_0_5_m7) },

    /* Reference-checked: small operands, window 3. */
    { exp_a3, LIMBSOF(exp_a3), exp_p30, LIMBSOF(exp_p30),
        exp_m7, LIMBSOF(exp_m7), NULL, 0 },
    { exp_a7, LIMBSOF(exp_a7), exp_p30, LIMBSOF(exp_p30),
        exp_m5, LIMBSOF(exp_m5), NULL, 0 },
    /* Reference-checked: even modulus (exercises the non-Montgomery path). */
    { exp_a5, LIMBSOF(exp_a5), exp_p10, LIMBSOF(exp_p10),
        exp_m6, LIMBSOF(exp_m6), NULL, 0 },
    { exp_a3, LIMBSOF(exp_a3), exp_p30, LIMBSOF(exp_p30),
        exp_m1000, LIMBSOF(exp_m1000), NULL, 0 },
    /* Reference-checked: base >= modulus (forces initial reduction). */
    { exp_m7, LIMBSOF(exp_m7), exp_p5, LIMBSOF(exp_p5),
        exp_m5, LIMBSOF(exp_m5), NULL, 0 },
    /* Reference-checked: wide operands under secp128r1 prime, window 5. */
    { num5, LIMBSOF(num5), exp_p256, LIMBSOF(exp_p256),
        mod_secp128r1_p, LIMBSOF(mod_secp128r1_p), NULL, 0 },
    { num2, LIMBSOF(num2), num8, LIMBSOF(num8),
        mod_secp128r1_p, LIMBSOF(mod_secp128r1_p), NULL, 0 },
    { mod_secp128r1_x2, LIMBSOF(mod_secp128r1_x2), exp_p256, LIMBSOF(exp_p256),
        mod_secp128r1_p, LIMBSOF(mod_secp128r1_p), NULL, 0 },
};

/* Local bit test is now the public-ish OSSL_FN_is_bit_set(), declared in
 * crypto/fn.h. */

/*
 * Independent reference: plain left-to-right binary square-and-multiply.
 * Distinct from the sliding-window implementation under test.
 */
static int mod_exp_reference(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *p,
    const OSSL_FN *m, OSSL_FN_CTX *ctx)
{
    const void *token = OSSL_FN_CTX_start(ctx);
    size_t ml = ossl_fn_get_dsize(m);
    OSSL_FN *base, *acc;
    OSSL_FN_ULONG *accw;
    int bits, i;
    int ret = 0;

    if (token == NULL)
        return 0;
    if ((base = OSSL_FN_CTX_get_limbs(ctx, ml)) == NULL
        || (acc = OSSL_FN_CTX_get_limbs(ctx, ml)) == NULL)
        goto end;

    if (!OSSL_FN_mod(base, a, m, ctx))
        goto end;
    OSSL_FN_clear(acc);
    accw = (OSSL_FN_ULONG *)ossl_fn_get_words(acc);
    if (ossl_fn_get_dsize(acc) > 0)
        accw[0] = OSSL_FN_ULONG_C(1);

    bits = (int)OSSL_FN_num_bits(p);
    for (i = bits - 1; i >= 0; i--) {
        if (!OSSL_FN_mod_mul(acc, acc, acc, m, ctx))
            goto end;
        if (OSSL_FN_is_bit_set(p, i))
            if (!OSSL_FN_mod_mul(acc, acc, base, m, ctx))
                goto end;
    }
    if (OSSL_FN_copy_truncate(r, acc) == NULL)
        goto end;
    ret = 1;
end:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

static int test_mod_exp_common(struct mod_exp_test_st *tc)
{
    size_t a_size = tc->a_size;
    size_t p_size = tc->p_size;
    size_t m_size = tc->m_size;
    size_t r_size = m_size;
    OSSL_FN_CTX *ctx_fn = NULL, *ctx_ref = NULL;
    OSSL_FN *fa = NULL, *fp = NULL, *fm = NULL, *r_got = NULL, *r_ref = NULL;
    size_t size;
    int ret = 0;

    fa = OSSL_FN_new_limbs(a_size > m_size ? a_size : m_size);
    fp = OSSL_FN_new_limbs(p_size);
    fm = OSSL_FN_new_limbs(m_size);
    r_got = OSSL_FN_new_limbs(r_size);
    r_ref = OSSL_FN_new_limbs(r_size);
    if (!TEST_ptr(fa) || !TEST_ptr(fp) || !TEST_ptr(fm)
        || !TEST_ptr(r_got) || !TEST_ptr(r_ref))
        goto err;

    if (!TEST_true(ossl_fn_set_words(fa, tc->a, a_size))
        || !TEST_true(ossl_fn_set_words(fp, tc->p, p_size))
        || !TEST_true(ossl_fn_set_words(fm, tc->m, m_size)))
        goto err;

    /* Validate the ctx-size helper by allocating the function ctx from it. */
    size = OSSL_FN_mod_exp_ctx_size(r_got, fa, fp, fm);
    if (!TEST_size_t_ne(size, 0))
        goto err;
    if (!TEST_ptr(ctx_fn = OSSL_FN_CTX_new_size(NULL, size)))
        goto err;
    /* Generous separate ctx for the reference oracle. */
    if (!TEST_ptr(ctx_ref = OSSL_FN_CTX_new(NULL, 8, 16, 16 * m_size + 16)))
        goto err;

    if (!TEST_true(pollute(r_got, 0, r_size)))
        goto err;
    if (!TEST_true(OSSL_FN_mod_exp(r_got, fa, fp, fm, ctx_fn)))
        goto err;

    if (tc->ex != NULL) {
        if (!TEST_mem_eq(ossl_fn_get_words(r_got), r_size * OSSL_FN_BYTES,
                tc->ex, tc->ex_size * OSSL_FN_BYTES))
            goto err;
    } else {
        if (!TEST_true(mod_exp_reference(r_ref, fa, fp, fm, ctx_ref)))
            goto err;
        if (!TEST_mem_eq(ossl_fn_get_words(r_got), r_size * OSSL_FN_BYTES,
                ossl_fn_get_words(r_ref), m_size * OSSL_FN_BYTES))
            goto err;
    }

    ret = 1;
err:
    OSSL_FN_CTX_free(ctx_fn);
    OSSL_FN_CTX_free(ctx_ref);
    OSSL_FN_free(fa);
    OSSL_FN_free(fp);
    OSSL_FN_free(fm);
    OSSL_FN_free(r_got);
    OSSL_FN_free(r_ref);
    return ret;
}

static int test_mod_exp(int i)
{
    return test_mod_exp_common(&test_mod_exp_cases[i]);
}

/* r == a and r == p aliasing: the result must match the reference. */
static int test_mod_exp_alias(int alias_p)
{
    /* 3^30 mod 7: small coprime, multi-bit exponent, window 3. */
    size_t a_size = LIMBSOF(exp_a3);
    size_t p_size = LIMBSOF(exp_p30);
    size_t m_size = LIMBSOF(exp_m7);
    size_t L = a_size > m_size ? a_size : m_size;
    OSSL_FN_CTX *ctx_fn = NULL, *ctx_ref = NULL;
    OSSL_FN *fa = NULL, *fp = NULL, *fm = NULL, *r_alias = NULL, *r_ref = NULL;
    OSSL_FN *fa_save = NULL, *fp_save = NULL;
    size_t size;
    int ret = 0;

    fa = OSSL_FN_new_limbs(L);
    fp = OSSL_FN_new_limbs(p_size);
    fm = OSSL_FN_new_limbs(m_size);
    fa_save = OSSL_FN_new_limbs(a_size);
    fp_save = OSSL_FN_new_limbs(p_size);
    r_ref = OSSL_FN_new_limbs(m_size);
    if (!TEST_ptr(fa) || !TEST_ptr(fp) || !TEST_ptr(fm)
        || !TEST_ptr(fa_save) || !TEST_ptr(fp_save) || !TEST_ptr(r_ref))
        goto err;

    if (!TEST_true(ossl_fn_set_words(fa, exp_a3, a_size))
        || !TEST_true(ossl_fn_set_words(fp, exp_p30, p_size))
        || !TEST_true(ossl_fn_set_words(fm, exp_m7, m_size))
        || !TEST_true(ossl_fn_set_words(fa_save, exp_a3, a_size))
        || !TEST_true(ossl_fn_set_words(fp_save, exp_p30, p_size)))
        goto err;

    size = OSSL_FN_mod_exp_ctx_size(alias_p ? fp : fa, fa, fp, fm);
    if (!TEST_size_t_ne(size, 0)
        || !TEST_ptr(ctx_fn = OSSL_FN_CTX_new_size(NULL, size))
        || !TEST_ptr(ctx_ref = OSSL_FN_CTX_new(NULL, 8, 16, 16 * m_size + 16)))
        goto err;

    /* Compute the reference first, before the alias run clobbers an operand. */
    if (!TEST_true(mod_exp_reference(r_ref, fa, fp, fm, ctx_ref)))
        goto err;

    r_alias = alias_p ? fp : fa;
    if (!TEST_true(OSSL_FN_mod_exp(r_alias, fa, fp, fm, ctx_fn)))
        goto err;

    if (!TEST_mem_eq(ossl_fn_get_words(r_alias), m_size * OSSL_FN_BYTES,
            ossl_fn_get_words(r_ref), m_size * OSSL_FN_BYTES))
        goto err;

    ret = 1;
err:
    OSSL_FN_CTX_free(ctx_fn);
    OSSL_FN_CTX_free(ctx_ref);
    OSSL_FN_free(fa);
    OSSL_FN_free(fp);
    OSSL_FN_free(fm);
    OSSL_FN_free(fa_save);
    OSSL_FN_free(fp_save);
    OSSL_FN_free(r_ref);
    return ret;
}

static int test_mod_exp_alias_a(void)
{
    return test_mod_exp_alias(0);
}

static int test_mod_exp_alias_p(void)
{
    return test_mod_exp_alias(1);
}

/* r == m must be rejected. */
static int test_mod_exp_alias_m_rejected(void)
{
    size_t a_size = LIMBSOF(exp_a3);
    size_t p_size = LIMBSOF(exp_p5);
    size_t m_size = LIMBSOF(exp_m7);
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *fa = NULL, *fp = NULL, *fm = NULL;
    int ret = 0;

    fa = OSSL_FN_new_limbs(a_size);
    fp = OSSL_FN_new_limbs(p_size);
    fm = OSSL_FN_new_limbs(m_size);
    if (!TEST_ptr(fa) || !TEST_ptr(fp) || !TEST_ptr(fm))
        goto err;
    if (!TEST_true(ossl_fn_set_words(fa, exp_a3, a_size))
        || !TEST_true(ossl_fn_set_words(fp, exp_p5, p_size))
        || !TEST_true(ossl_fn_set_words(fm, exp_m7, m_size)))
        goto err;
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 8, 40, 40 * m_size + 16)))
        goto err;

    if (!TEST_false(OSSL_FN_mod_exp(fm, fa, fp, fm, ctx)))
        goto err;
    if (!TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()),
            ERR_R_PASSED_INVALID_ARGUMENT))
        goto err;

    ret = 1;
err:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fa);
    OSSL_FN_free(fp);
    OSSL_FN_free(fm);
    return ret;
}

/* m == 0 must fail (DIV_BY_ZERO surfaces from the initial reduction). */
static int test_mod_exp_modulus_zero(void)
{
    size_t a_size = LIMBSOF(exp_a3);
    size_t p_size = LIMBSOF(exp_p5);
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *fa = NULL, *fp = NULL, *fm = NULL, *r = NULL;
    int ret = 0;

    fa = OSSL_FN_new_limbs(a_size);
    fp = OSSL_FN_new_limbs(p_size);
    fm = OSSL_FN_new_limbs(1);
    r = OSSL_FN_new_limbs(1);
    if (!TEST_ptr(fa) || !TEST_ptr(fp) || !TEST_ptr(fm) || !TEST_ptr(r))
        goto err;
    if (!TEST_true(ossl_fn_set_words(fa, exp_a3, a_size))
        || !TEST_true(ossl_fn_set_words(fp, exp_p5, p_size))
        || !TEST_true(ossl_fn_set_words(fm, exp_m0, LIMBSOF(exp_m0))))
        goto err;
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 8, 40, 40 * 1 + 16)))
        goto err;

    if (!TEST_false(OSSL_FN_mod_exp(r, fa, fp, fm, ctx)))
        goto err;
    if (!TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()),
            OSSL_FN_R_DIV_BY_ZERO))
        goto err;

    ret = 1;
err:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fa);
    OSSL_FN_free(fp);
    OSSL_FN_free(fm);
    OSSL_FN_free(r);
    return ret;
}

/* m == 0 with a zero exponent must also fail: the zero-modulus guard runs
 * before the zero-exponent fast path, so 0^0 mod 0 is rejected rather than
 * silently returning 1. */
static int test_mod_exp_modulus_zero_exp_zero(void)
{
    size_t a_size = LIMBSOF(exp_a3);
    size_t p_size = LIMBSOF(exp_p0);
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *fa = NULL, *fp = NULL, *fm = NULL, *r = NULL;
    int ret = 0;

    fa = OSSL_FN_new_limbs(a_size);
    fp = OSSL_FN_new_limbs(p_size);
    fm = OSSL_FN_new_limbs(1);
    r = OSSL_FN_new_limbs(1);
    if (!TEST_ptr(fa) || !TEST_ptr(fp) || !TEST_ptr(fm) || !TEST_ptr(r))
        goto err;
    if (!TEST_true(ossl_fn_set_words(fa, exp_a3, a_size))
        || !TEST_true(ossl_fn_set_words(fp, exp_p0, p_size))
        || !TEST_true(ossl_fn_set_words(fm, exp_m0, LIMBSOF(exp_m0))))
        goto err;
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 8, 40, 40 * 1 + 16)))
        goto err;

    if (!TEST_false(OSSL_FN_mod_exp(r, fa, fp, fm, ctx)))
        goto err;
    if (!TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()),
            OSSL_FN_R_DIV_BY_ZERO))
        goto err;

    ret = 1;
err:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fa);
    OSSL_FN_free(fp);
    OSSL_FN_free(fm);
    OSSL_FN_free(r);
    return ret;
}

/*
 * Result-width variations: r larger than m (must zero-pad high limbs) and r
 * smaller than m (must give the low limbs of the true result).  The reference
 * oracle is the comparison basis.
 */
static int test_mod_exp_result_size(int i)
{
    /* Wide case: num5 ^ exp_p256 mod secp128r1 prime, window 5. */
    size_t a_size = LIMBSOF(num5);
    size_t p_size = LIMBSOF(exp_p256);
    size_t m_size = LIMBSOF(mod_secp128r1_p);
    size_t L = a_size > m_size ? a_size : m_size;
    size_t r_size = i == 0 ? m_size + 2 : m_size - 1; /* oversized, then truncated */
    size_t check = i == 0 ? m_size : m_size - 1;
    OSSL_FN_CTX *ctx_fn = NULL, *ctx_ref = NULL;
    OSSL_FN *fa = NULL, *fp = NULL, *fm = NULL, *r_got = NULL, *r_ref = NULL;
    size_t size;
    int ret = 0;

    fa = OSSL_FN_new_limbs(L);
    fp = OSSL_FN_new_limbs(p_size);
    fm = OSSL_FN_new_limbs(m_size);
    r_got = OSSL_FN_new_limbs(r_size);
    r_ref = OSSL_FN_new_limbs(m_size);
    if (!TEST_ptr(fa) || !TEST_ptr(fp) || !TEST_ptr(fm)
        || !TEST_ptr(r_got) || !TEST_ptr(r_ref))
        goto err;
    if (!TEST_true(ossl_fn_set_words(fa, num5, a_size))
        || !TEST_true(ossl_fn_set_words(fp, exp_p256, p_size))
        || !TEST_true(ossl_fn_set_words(fm, mod_secp128r1_p, m_size)))
        goto err;

    size = OSSL_FN_mod_exp_ctx_size(r_got, fa, fp, fm);
    if (!TEST_size_t_ne(size, 0)
        || !TEST_ptr(ctx_fn = OSSL_FN_CTX_new_size(NULL, size))
        || !TEST_ptr(ctx_ref = OSSL_FN_CTX_new(NULL, 8, 16, 16 * m_size + 16)))
        goto err;

    if (!TEST_true(pollute(r_got, 0, r_size)))
        goto err;
    if (!TEST_true(OSSL_FN_mod_exp(r_got, fa, fp, fm, ctx_fn)))
        goto err;
    if (!TEST_true(mod_exp_reference(r_ref, fa, fp, fm, ctx_ref)))
        goto err;

    if (!TEST_mem_eq(ossl_fn_get_words(r_got), check * OSSL_FN_BYTES,
            ossl_fn_get_words(r_ref), check * OSSL_FN_BYTES))
        goto err;
    /* Oversized: high limbs beyond m_size must be zero-padded. */
    if (i == 0 && !TEST_true(check_limbs_value(r_got, m_size, r_size, 0)))
        goto err;

    ret = 1;
err:
    OSSL_FN_CTX_free(ctx_fn);
    OSSL_FN_CTX_free(ctx_ref);
    OSSL_FN_free(fa);
    OSSL_FN_free(fp);
    OSSL_FN_free(fm);
    OSSL_FN_free(r_got);
    OSSL_FN_free(r_ref);
    return ret;
}

/*
 * Validate OSSL_FN_mod_exp_ctx_size(): allocate from the helper and confirm
 * the operation succeeds with peak usage within the budgeted arena.
 */
static int test_mod_exp_ctx_size(void)
{
    size_t a_size = LIMBSOF(num5);
    size_t p_size = LIMBSOF(exp_p256);
    size_t m_size = LIMBSOF(mod_secp128r1_p);
    size_t L = a_size > m_size ? a_size : m_size;
    OSSL_FN_CTX *ctx = NULL, *ctx_ref = NULL;
    OSSL_FN *fa = NULL, *fp = NULL, *fm = NULL, *r = NULL, *r_ref = NULL;
    size_t size, peak_frames, peak_numbers, peak_limbs;
    int ret = 0;

    fa = OSSL_FN_new_limbs(L);
    fp = OSSL_FN_new_limbs(p_size);
    fm = OSSL_FN_new_limbs(m_size);
    r = OSSL_FN_new_limbs(m_size);
    r_ref = OSSL_FN_new_limbs(m_size);
    if (!TEST_ptr(fa) || !TEST_ptr(fp) || !TEST_ptr(fm)
        || !TEST_ptr(r) || !TEST_ptr(r_ref))
        goto err;
    if (!TEST_true(ossl_fn_set_words(fa, num5, a_size))
        || !TEST_true(ossl_fn_set_words(fp, exp_p256, p_size))
        || !TEST_true(ossl_fn_set_words(fm, mod_secp128r1_p, m_size)))
        goto err;

    size = OSSL_FN_mod_exp_ctx_size(r, fa, fp, fm);
    if (!TEST_size_t_ne(size, 0)
        || !TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL, size)))
        goto err;
    if (!TEST_ptr(ctx_ref = OSSL_FN_CTX_new(NULL, 8, 16, 16 * m_size + 16)))
        goto err;

    if (!TEST_true(OSSL_FN_mod_exp(r, fa, fp, fm, ctx)))
        goto err;
    OSSL_FN_CTX_peak_usage(ctx, &peak_frames, &peak_numbers, &peak_limbs);
    if (!TEST_size_t_gt(peak_frames, 0))
        goto err;

    /* Cross-check against the reference oracle. */
    if (!TEST_true(mod_exp_reference(r_ref, fa, fp, fm, ctx_ref)))
        goto err;
    if (!TEST_mem_eq(ossl_fn_get_words(r), m_size * OSSL_FN_BYTES,
            ossl_fn_get_words(r_ref), m_size * OSSL_FN_BYTES))
        goto err;

    ret = 1;
err:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_CTX_free(ctx_ref);
    OSSL_FN_free(fa);
    OSSL_FN_free(fp);
    OSSL_FN_free(fm);
    OSSL_FN_free(r);
    OSSL_FN_free(r_ref);
    return ret;
}

/*
 * OSSL_FN_mod_exp_mont() with a caller-supplied, reused OSSL_FN_MONT_CTX:
 * exercise the in_mont != NULL path (borrowed context, not freed here) across
 * two exponentiations against the same modulus, and confirm the result
 * matches the reference oracle.  Also verifies the NULL in_mont path produces
 * the same value, so the two entry points agree.
 */
static int test_mod_exp_mont_in_mont(void)
{
    /* num5 ^ exp_p256 mod secp128r1 prime, window 5. */
    size_t a_size = LIMBSOF(num5);
    size_t p_size = LIMBSOF(exp_p256);
    size_t m_size = LIMBSOF(mod_secp128r1_p);
    size_t L = a_size > m_size ? a_size : m_size;
    OSSL_FN_CTX *ctx_fn = NULL, *ctx_ref = NULL;
    OSSL_FN_MONT_CTX *mont = NULL;
    OSSL_FN *fa = NULL, *fp = NULL, *fm = NULL, *r = NULL, *r_ref = NULL;
    size_t size;
    int ret = 0;

    fa = OSSL_FN_new_limbs(L);
    fp = OSSL_FN_new_limbs(p_size);
    fm = OSSL_FN_new_limbs(m_size);
    r = OSSL_FN_new_limbs(m_size);
    r_ref = OSSL_FN_new_limbs(m_size);
    if (!TEST_ptr(fa) || !TEST_ptr(fp) || !TEST_ptr(fm)
        || !TEST_ptr(r) || !TEST_ptr(r_ref))
        goto err;
    if (!TEST_true(ossl_fn_set_words(fa, num5, a_size))
        || !TEST_true(ossl_fn_set_words(fp, exp_p256, p_size))
        || !TEST_true(ossl_fn_set_words(fm, mod_secp128r1_p, m_size)))
        goto err;

    /* Build a reusable Montgomery context for this modulus. */
    if (!TEST_ptr(mont = OSSL_FN_MONT_CTX_new(fm)))
        goto err;

    /* Size the arena for the mont path with the reused context.  The NULL
     * in_mont case is the same size (see mod_exp_mont_nested()), so the NULL
     * call below fits this arena too. */
    size = OSSL_FN_mod_exp_mont_ctx_size(r, fa, fp, fm, mont);
    if (!TEST_size_t_ne(size, 0)
        || !TEST_ptr(ctx_fn = OSSL_FN_CTX_new_size(NULL, size))
        || !TEST_ptr(ctx_ref = OSSL_FN_CTX_new(NULL, 8, 16, 16 * m_size + 16)))
        goto err;

    /* First call with the borrowed context. */
    if (!TEST_true(pollute(r, 0, m_size)))
        goto err;
    if (!TEST_true(OSSL_FN_mod_exp_mont(r, fa, fp, fm, ctx_fn, mont)))
        goto err;
    if (!TEST_true(mod_exp_reference(r_ref, fa, fp, fm, ctx_ref)))
        goto err;
    if (!TEST_mem_eq(ossl_fn_get_words(r), m_size * OSSL_FN_BYTES,
            ossl_fn_get_words(r_ref), m_size * OSSL_FN_BYTES))
        goto err;

    /*
     * Second call reusing the same |mont| with a fresh arena frame: confirms
     * the borrowed context is not freed by the first call and still works.
     * Vary the exponent to force a different window walk.
     */
    if (!TEST_true(ossl_fn_set_words(fp, exp_p30, LIMBSOF(exp_p30))))
        goto err;
    /* exp_p30 (30 bits) is smaller than the modulus; resize is fine. */
    if (!TEST_true(pollute(r, 0, m_size)))
        goto err;
    if (!TEST_true(OSSL_FN_mod_exp_mont(r, fa, fp, fm, ctx_fn, mont)))
        goto err;
    if (!TEST_true(mod_exp_reference(r_ref, fa, fp, fm, ctx_ref)))
        goto err;
    if (!TEST_mem_eq(ossl_fn_get_words(r), m_size * OSSL_FN_BYTES,
            ossl_fn_get_words(r_ref), m_size * OSSL_FN_BYTES))
        goto err;

    /* The NULL in_mont path must agree with the reused-context path. */
    if (!TEST_true(ossl_fn_set_words(fp, exp_p256, p_size)))
        goto err;
    if (!TEST_true(pollute(r, 0, m_size)))
        goto err;
    if (!TEST_true(OSSL_FN_mod_exp_mont(r, fa, fp, fm, ctx_fn, NULL)))
        goto err;
    if (!TEST_true(mod_exp_reference(r_ref, fa, fp, fm, ctx_ref)))
        goto err;
    if (!TEST_mem_eq(ossl_fn_get_words(r), m_size * OSSL_FN_BYTES,
            ossl_fn_get_words(r_ref), m_size * OSSL_FN_BYTES))
        goto err;

    ret = 1;
err:
    OSSL_FN_MONT_CTX_free(mont);
    OSSL_FN_CTX_free(ctx_fn);
    OSSL_FN_CTX_free(ctx_ref);
    OSSL_FN_free(fa);
    OSSL_FN_free(fp);
    OSSL_FN_free(fm);
    OSSL_FN_free(r);
    OSSL_FN_free(r_ref);
    return ret;
}

/*
 * OSSL_FN_mod_exp_mont_ctx_size(): the mont-only size must be positive, must
 * equal the dispatcher size or be smaller (dispatcher also budgets the
 * simple-path loop mul), and must not depend on whether in_mont is NULL or a
 * real reused context (the operand modelling makes them the same).
 */
static int test_mod_exp_mont_ctx_size(void)
{
    /* num5 ^ exp_p256 mod secp128r1 prime, window 5. */
    size_t a_size = LIMBSOF(num5);
    size_t p_size = LIMBSOF(exp_p256);
    size_t m_size = LIMBSOF(mod_secp128r1_p);
    size_t L = a_size > m_size ? a_size : m_size;
    OSSL_FN_MONT_CTX *mont = NULL;
    OSSL_FN *fa = NULL, *fp = NULL, *fm = NULL, *r = NULL;
    size_t sz_null, sz_mont, sz_disp;
    int ret = 0;

    fa = OSSL_FN_new_limbs(L);
    fp = OSSL_FN_new_limbs(p_size);
    fm = OSSL_FN_new_limbs(m_size);
    r = OSSL_FN_new_limbs(m_size);
    if (!TEST_ptr(fa) || !TEST_ptr(fp) || !TEST_ptr(fm) || !TEST_ptr(r))
        goto err;
    if (!TEST_true(ossl_fn_set_words(fa, num5, a_size))
        || !TEST_true(ossl_fn_set_words(fp, exp_p256, p_size))
        || !TEST_true(ossl_fn_set_words(fm, mod_secp128r1_p, m_size)))
        goto err;

    if (!TEST_ptr(mont = OSSL_FN_MONT_CTX_new(fm)))
        goto err;

    sz_null = OSSL_FN_mod_exp_mont_ctx_size(r, fa, fp, fm, NULL);
    sz_mont = OSSL_FN_mod_exp_mont_ctx_size(r, fa, fp, fm, mont);
    sz_disp = OSSL_FN_mod_exp_ctx_size(r, fa, fp, fm);
    if (!TEST_size_t_ne(sz_null, 0)
        || !TEST_size_t_ne(sz_mont, 0)
        || !TEST_size_t_ne(sz_disp, 0))
        goto err;
    /* NULL and real in_mont produce the same arena size. */
    if (!TEST_size_t_eq(sz_null, sz_mont))
        goto err;
    /* Mont-only is at most the dispatcher size (which also budgets the
     * simple-path loop mul); it can be smaller. */
    if (!TEST_size_t_ge(sz_disp, sz_mont))
        goto err;

    ret = 1;
err:
    OSSL_FN_MONT_CTX_free(mont);
    OSSL_FN_free(fa);
    OSSL_FN_free(fp);
    OSSL_FN_free(fm);
    OSSL_FN_free(r);
    return ret;
}

/*-
 * Focused tests for OSSL_FN_kronecker(), the Kronecker/Jacobi symbol.
 *
 * Two test strategies:
 *   1. test_kronecker: a table of hand-verified (a, b, expected) triples
 *      for small inputs, covering edge cases (B==0, both even, even B, the
 *      tab[] lookup for (a, 2)).
 *   2. test_kronecker_legendre: the Euler criterion cross-check — for odd
 *      prime p, kronecker(a, p) == legendre(a, p) == a^((p-1)/2) mod p,
 *      mapped to {-1, 0, 1}.  OSSL_FN_mod_exp() is the independent oracle.
 */
struct kronecker_case_st {
    OSSL_FN_ULONG a;
    OSSL_FN_ULONG b;
    int expected;
};

static const struct kronecker_case_st kronecker_cases[] = {
    { 0, 0, 0 }, /* B==0, A!=1 → 0 */
    { 1, 0, 1 }, /* B==0, A==1 → 1 */
    { 0, 1, 1 }, /* A==0, B==1 → 1 */
    { 2, 2, 0 }, /* both even → 0 */
    { 1, 2, 1 }, /* tab[1&7] = 1 */
    { 3, 2, -1 }, /* tab[3&7] = -1 */
    { 5, 2, -1 }, /* tab[5&7] = -1 */
    { 7, 2, 1 }, /* tab[7&7] = 1 */
    { 2, 3, -1 }, /* 2 is non-residue mod 3 */
    { 1, 3, 1 },
    { 4, 3, 1 }, /* 4 ≡ 1 mod 3 */
    { 2, 5, -1 }, /* 2 is non-residue mod 5 */
    { 4, 5, 1 }, /* 4 = 2^2 */
    { 3, 5, -1 },
    { 2, 7, 1 }, /* 2 is residue mod 7 */
    { 3, 7, -1 },
    { 1, 7, 1 },
    { 3, 4, 1 }, /* odd a, B = 2^2 → (a/2)^2 = 1 */
};

static int test_kronecker(int i)
{
    int ret = 0;
    OSSL_FN *fa = NULL, *fb = NULL;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN_ULONG aw = kronecker_cases[i].a;
    OSSL_FN_ULONG bw = kronecker_cases[i].b;
    int expected = kronecker_cases[i].expected;
    size_t L = 1; /* all table entries are single-limb */

    if (!TEST_ptr(fa = OSSL_FN_new_limbs(L))
        || !TEST_ptr(fb = OSSL_FN_new_limbs(L))
        || !TEST_true(OSSL_FN_set_word(fa, aw))
        || !TEST_true(OSSL_FN_set_word(fb, bw)))
        goto err;

    if (!TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL,
                      OSSL_FN_kronecker_ctx_size(fa, fb))))
        goto err;

    if (!TEST_int_eq(OSSL_FN_kronecker(fa, fb, ctx), expected))
        goto err;

    ret = 1;
err:
    OSSL_FN_free(fa);
    OSSL_FN_free(fb);
    OSSL_FN_CTX_free(ctx);
    return ret;
}

/*
 * Euler criterion cross-check: for odd prime p,
 *   kronecker(a, p) == a^((p-1)/2) mod p  (mapped to {-1, 0, 1}).
 * OSSL_FN_mod_exp() is the independent oracle.  Tested with a range of
 * a values for each prime, including a == 0, a == 1, and a >= p.
 */
static const OSSL_FN_ULONG legendre_primes[] = {
    3, 5, 7, 11, 13, 17, 19, 23
};

static int test_kronecker_legendre(int i)
{
    int ret = 0;
    OSSL_FN_ULONG p = legendre_primes[i];
    OSSL_FN *fa = NULL, *fp = NULL, *exp = NULL, *r = NULL, *p_minus_1 = NULL;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN_ULONG a;
    size_t L = 1;

    if (!TEST_ptr(fa = OSSL_FN_new_limbs(L))
        || !TEST_ptr(fp = OSSL_FN_new_limbs(L))
        || !TEST_ptr(exp = OSSL_FN_new_limbs(L))
        || !TEST_ptr(r = OSSL_FN_new_limbs(L))
        || !TEST_ptr(p_minus_1 = OSSL_FN_new_limbs(L))
        || !TEST_true(OSSL_FN_set_word(fp, p)))
        goto err;

    /* exp = (p - 1) / 2 ;  p_minus_1 = p - 1 */
    if (!TEST_true(OSSL_FN_set_word(exp, p))
        || !TEST_true(OSSL_FN_sub_word(exp, 1))
        || !TEST_true(OSSL_FN_rshift(exp, exp, 1))
        || !TEST_true(OSSL_FN_set_word(p_minus_1, p))
        || !TEST_true(OSSL_FN_sub_word(p_minus_1, 1)))
        goto err;

    /*
     * ctx must hold both kronecker's and mod_exp's scratch needs.
     * Size for the larger of the two (mod_exp typically needs more).
     */
    {
        size_t ksz = OSSL_FN_kronecker_ctx_size(fa, fp);
        size_t esz = OSSL_FN_mod_exp_ctx_size(r, fa, exp, fp);
        size_t sz = ksz > esz ? ksz : esz;

        if (!TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL, sz)))
            goto err;
    }

    for (a = 0; a <= p + 1; a++) {
        int kr, legendre;

        if (!TEST_true(OSSL_FN_set_word(fa, a)))
            goto err;

        kr = OSSL_FN_kronecker(fa, fp, ctx);
        if (!TEST_int_ge(kr, -1))
            goto err;

        /* legendre = a^((p-1)/2) mod p, mapped to {-1, 0, 1} */
        if (!TEST_true(OSSL_FN_mod_exp(r, fa, exp, fp, ctx)))
            goto err;

        if (OSSL_FN_is_zero(r)) {
            legendre = 0;
        } else if (OSSL_FN_is_one(r)) {
            legendre = 1;
        } else if (OSSL_FN_cmp(r, p_minus_1) == 0) {
            legendre = -1;
        } else {
            TEST_info("a=%lu, p=%lu: unexpected mod_exp result",
                (unsigned long)a, (unsigned long)p);
            goto err;
        }

        if (!TEST_int_eq(kr, legendre)) {
            TEST_info("kronecker(%lu, %lu) = %d, legendre = %d",
                (unsigned long)a, (unsigned long)p, kr, legendre);
            goto err;
        }
    }

    ret = 1;
err:
    OSSL_FN_free(fa);
    OSSL_FN_free(fp);
    OSSL_FN_free(exp);
    OSSL_FN_free(r);
    OSSL_FN_free(p_minus_1);
    OSSL_FN_CTX_free(ctx);
    return ret;
}

/*-
 * Focused smoke test for OSSL_FN_mod_sqrt().  For each small prime p (chosen
 * to exercise all three e paths: e==1 when p==3 mod 4, e==2 when p==5 mod 8,
 * e>2 otherwise), and each a in [0, p), compute sqrt(a) and verify:
 *   - if a is a quadratic residue (kronecker(a,p)==1, or a==0), then
 *     ret^2 == a mod p;
 *   - if a is a non-residue (kronecker(a,p)==-1), then OSSL_FN_mod_sqrt
 *     returns 0 with OSSL_FN_R_NOT_A_SQUARE.
 * OSSL_FN_kronecker() predicts residue/non-residue; OSSL_FN_mod_sqr() is the
 * independent verifier.
 */
static const OSSL_FN_ULONG mod_sqrt_primes[] = {
    3, /* e==1: p == 3 mod 4 */
    5, /* e==2: p == 5 mod 8 */
    7, /* e>2 */
    11, /* e==1: 11 mod 4 == 3 */
    13, /* e==2: 13 mod 8 == 5 */
    17, /* e>2 */
    23, /* e==1 */
    41, /* e>2: 41-1=40=2^3*5 */
};

static int test_mod_sqrt(int i)
{
    int ret = 0;
    OSSL_FN_ULONG p = mod_sqrt_primes[i];
    OSSL_FN *fa = NULL, *fp = NULL, *r = NULL, *r2 = NULL;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN_ULONG a;
    size_t L = 1;

    if (!TEST_ptr(fa = OSSL_FN_new_limbs(L))
        || !TEST_ptr(fp = OSSL_FN_new_limbs(L))
        || !TEST_ptr(r = OSSL_FN_new_limbs(L))
        || !TEST_ptr(r2 = OSSL_FN_new_limbs(L))
        || !TEST_true(OSSL_FN_set_word(fp, p)))
        goto err;

    {
        size_t sz = OSSL_FN_mod_sqrt_ctx_size(r, fa, fp);

        if (!TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL, sz)))
            goto err;
    }

    for (a = 0; a < p; a++) {
        int kr, sqrt_ok;

        if (!TEST_true(OSSL_FN_set_word(fa, a)))
            goto err;

        kr = OSSL_FN_kronecker(fa, fp, ctx);
        if (!TEST_int_ge(kr, -1))
            goto err;

        ERR_clear_error();
        sqrt_ok = OSSL_FN_mod_sqrt(r, fa, fp, ctx);

        if (a == 0) {
            /* a==0 -> ret==0 */
            if (!TEST_true(sqrt_ok) || !TEST_true(OSSL_FN_is_zero(r)))
                goto err;
        } else if (kr == 1) {
            /* residue: must succeed and ret^2 == a mod p */
            if (!TEST_true(sqrt_ok))
                goto err;
            if (!TEST_true(OSSL_FN_mod_sqr(r2, r, fp, ctx)))
                goto err;
            if (!TEST_int_eq(OSSL_FN_cmp(r2, fa), 0))
                goto err;
        } else {
            /* non-residue: must fail with NOT_A_SQUARE */
            if (!TEST_false(sqrt_ok))
                goto err;
            if (!TEST_int_eq(ERR_GET_REASON(ERR_get_error()),
                    OSSL_FN_R_NOT_A_SQUARE))
                goto err;
        }
    }

    ret = 1;
err:
    OSSL_FN_free(fa);
    OSSL_FN_free(fp);
    OSSL_FN_free(r);
    OSSL_FN_free(r2);
    OSSL_FN_CTX_free(ctx);
    return ret;
}

static const OSSL_FN_ULONG mod_sqrt_wide_prime[] = {
    OSSL_FN_ULONG_C(13),
#if OSSL_FN_BYTES == 4
    OSSL_FN_ULONG_C(0),
#endif
    OSSL_FN_ULONG_C(1),
};

static int test_mod_sqrt_result_truncation(void)
{
    int ret = 0;
    OSSL_FN *fa = NULL, *fp = NULL, *r = NULL;
    OSSL_FN_CTX *ctx = NULL;
    size_t p_limbs = OSSL_NELEM(mod_sqrt_wide_prime);
    size_t r_limbs = 1;
    size_t sz;

    if (!TEST_ptr(fa = OSSL_FN_new_limbs(p_limbs))
        || !TEST_ptr(fp = OSSL_FN_new_limbs(p_limbs))
        || !TEST_ptr(r = OSSL_FN_new_limbs(r_limbs))
        || !TEST_true(OSSL_FN_set_word(fa, 4))
        || !TEST_true(ossl_fn_set_words(fp, mod_sqrt_wide_prime, p_limbs)))
        goto err;

    sz = OSSL_FN_mod_sqrt_ctx_size(r, fa, fp);
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL, sz)))
        goto err;

    if (!TEST_true(OSSL_FN_mod_sqrt(r, fa, fp, ctx)))
        goto err;

    /* sqrt(4) is either 2 or p - 2; truncated to one limb, p - 2 is 11. */
    if (!TEST_true(OSSL_FN_is_word(r, 2) || OSSL_FN_is_word(r, 11)))
        goto err;

    ret = 1;
err:
    OSSL_FN_free(fa);
    OSSL_FN_free(fp);
    OSSL_FN_free(r);
    OSSL_FN_CTX_free(ctx);
    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_add, 17);
    ADD_ALL_TESTS(test_add_truncated, 17);
    ADD_ALL_TESTS(test_sub, 18);
    ADD_ALL_TESTS(test_sub_truncated, 18);
    ADD_TEST(test_num_bits);
    ADD_TEST(test_cmp);
    ADD_TEST(test_introspection);
    ADD_ALL_TESTS(test_add_word, OSSL_NELEM(add_word_cases));
    ADD_ALL_TESTS(test_sub_word, OSSL_NELEM(sub_word_cases));
    ADD_ALL_TESTS(test_set_word, OSSL_NELEM(set_word_cases));
    ADD_TEST(test_one);
    ADD_TEST(test_zero);
    ADD_ALL_TESTS(test_lshift1, 2);
    ADD_ALL_TESTS(test_lshift, 6);
    ADD_ALL_TESTS(test_rshift1, 2);
    ADD_ALL_TESTS(test_rshift, 9);
    ADD_ALL_TESTS(test_rshift_alias, 4);
    ADD_TEST(test_rshift_invalid_shift);
    ADD_ALL_TESTS(test_mul_feature_r_is_operand, 4);
    ADD_ALL_TESTS(test_mul, OSSL_NELEM(test_mul_cases));
    ADD_ALL_TESTS(test_mul_truncated, OSSL_NELEM(test_mul_truncate_cases));
    ADD_ALL_TESTS(test_sqr_feature_r_is_operand, 2);
    ADD_ALL_TESTS(test_sqr, OSSL_NELEM(test_sqr_cases));
    ADD_ALL_TESTS(test_sqr_truncated, OSSL_NELEM(test_sqr_truncate_cases));
    ADD_ALL_TESTS(test_div, OSSL_NELEM(test_div_cases));
    ADD_ALL_TESTS(test_div_truncated, OSSL_NELEM(test_div_truncate_cases));
    ADD_TEST(test_div_by_zero);
    ADD_ALL_TESTS(test_mod, OSSL_NELEM(test_mod_cases));
    ADD_ALL_TESTS(test_mod_truncated, OSSL_NELEM(test_mod_truncate_cases));
    ADD_TEST(test_mod_by_zero);
    ADD_ALL_TESTS(test_mod_add, OSSL_NELEM(test_mod_add_cases));
    ADD_ALL_TESTS(test_mod_sub, OSSL_NELEM(test_mod_sub_cases));
    ADD_ALL_TESTS(test_mod_mul, OSSL_NELEM(test_mod_mul_cases));
    ADD_ALL_TESTS(test_mod_sqr, OSSL_NELEM(test_mod_sqr_cases));
    ADD_ALL_TESTS(test_mod_lshift1, OSSL_NELEM(test_mod_lshift1_cases));
    ADD_ALL_TESTS(test_mod_lshift, OSSL_NELEM(test_mod_lshift_cases));
    ADD_TEST(test_mod_quick_wide_operands);
    ADD_TEST(test_mod_sub_general_wide_operands);
    ADD_ALL_TESTS(test_mod_ops_result_size, 3);
    ADD_ALL_TESTS(test_rand_bits, OSSL_NELEM(rand_bits_cases));
    ADD_ALL_TESTS(test_rand, OSSL_NELEM(rand_bits_cases));
    ADD_TEST(test_rand_result_too_small);
    ADD_TEST(test_rand_bits_too_small);
    ADD_ALL_TESTS(test_rand_range, OSSL_NELEM(range_words));
    ADD_TEST(test_rand_range_zero);
    ADD_TEST(test_rand_range_exactly_sized);
    ADD_ALL_TESTS(test_mod_exp, OSSL_NELEM(test_mod_exp_cases));
    ADD_TEST(test_mod_exp_alias_a);
    ADD_TEST(test_mod_exp_alias_p);
    ADD_TEST(test_mod_exp_alias_m_rejected);
    ADD_TEST(test_mod_exp_modulus_zero);
    ADD_TEST(test_mod_exp_modulus_zero_exp_zero);
    ADD_ALL_TESTS(test_mod_exp_result_size, 2);
    ADD_TEST(test_mod_exp_ctx_size);
    ADD_TEST(test_mod_exp_mont_in_mont);
    ADD_TEST(test_mod_exp_mont_ctx_size);
    ADD_ALL_TESTS(test_kronecker, OSSL_NELEM(kronecker_cases));
    ADD_ALL_TESTS(test_kronecker_legendre, OSSL_NELEM(legendre_primes));
    ADD_ALL_TESTS(test_mod_sqrt, OSSL_NELEM(mod_sqrt_primes));
    ADD_TEST(test_mod_sqrt_result_truncation);

    return 1;
}
