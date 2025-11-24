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

#include <openssl/rand.h>
#include "crypto/fn.h"
#include "crypto/fn_intern.h"
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

static int check_zero(const OSSL_FN *f, size_t start, size_t end)
{
    const OSSL_FN_ULONG *u = ossl_fn_get_words(f);
    size_t l = ossl_fn_get_dsize(f);

    if (end > l)
        end = l;
    if (start > end)
        start = end;

    for (size_t i = start; i < end; i++)
        if (u[i] != 0)
            return 0;
    return 1;
}

/* A set of numbers on OSSL_FN_ULONG array form */
static const OSSL_FN_ULONG num0[] = {OSSL_FN_ULONG64_C(0x80000000, 0x00000001)};
static const OSSL_FN_ULONG num1[] = {OSSL_FN_ULONG64_C(0x00000001, 0x80000000)};
static const OSSL_FN_ULONG num2[] = {OSSL_FN_ULONG64_C(0x01234567, 0x89abcdef)};
static const OSSL_FN_ULONG num3[] = {OSSL_FN_ULONG64_C(0xfedcba98, 0x76543210)};

/* Numbers for edge cases */
static const OSSL_FN_ULONG num4[] = {OSSL_FN_ULONG64_C(0x00000000, 0x00000000)};
static const OSSL_FN_ULONG num5[] = {OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff)};
static const OSSL_FN_ULONG num6[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x10000000, 0x00000000),
};

/*
 * For each test function using predefined numbers, set up an
 * arrays of test cases to simply run through, and call common
 * test function for the operation being tested.
 *
 * All sizes are in number of limbs, the LIMBSOF() macro is there to help
 */
#define LIMBSOF(num) ((sizeof(num) + OSSL_FN_BYTES - 1) / OSSL_FN_BYTES)
struct test_case_st {
    /* Two operands and expected full result */
    const OSSL_FN_ULONG *op1;
    size_t op1_size;
    const OSSL_FN_ULONG *op2;
    size_t op2_size;
    const OSSL_FN_ULONG *ex;
    size_t ex_size;

    /* Setup sizes for creating OSSL_FNs */
    size_t op1_live_size;
    size_t op2_live_size;
    size_t res_live_size;

    /* Number of limbs to compare the result's OSSL_FN_ULONG array against ex */
    size_t check_size;
};

static const OSSL_FN_ULONG ex_add_num0_num0[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000002),
    OSSL_FN_ULONG_C(0x1),
};
static const OSSL_FN_ULONG ex_add_num0_num1[] = {
    OSSL_FN_ULONG64_C(0x80000001, 0x80000001),
};
static const OSSL_FN_ULONG ex_add_num0_num2[] = {
    OSSL_FN_ULONG64_C(0x81234567, 0x89abcdf0),
};
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

#define ADD_CASE(i, op1, op2, ex)               \
    {                                           \
        /* op1, with size */ op1, LIMBSOF(op1), \
        /* op2, with size */ op2, LIMBSOF(op2), \
        /* ex, with size */ ex, LIMBSOF(ex),    \
        /* op1_live_size */ LIMBSOF(op1),       \
        /* op2_live_size */ LIMBSOF(op2),       \
        /* res_live_size */ LIMBSOF(ex),        \
        /* check_size */ LIMBSOF(ex),           \
    }  

static struct test_case_st test_add_cases[] = {
    ADD_CASE(1,  num0, num0, ex_add_num0_num0),
    ADD_CASE(2,  num0, num1, ex_add_num0_num1),
    ADD_CASE(3,  num0, num2, ex_add_num0_num2),
    ADD_CASE(4,  num0, num3, ex_add_num0_num3),
    ADD_CASE(5,  num1, num0, ex_add_num0_num1), /* Commutativity check */
    ADD_CASE(6,  num1, num1, ex_add_num1_num1),
    ADD_CASE(7,  num1, num2, ex_add_num1_num2),
    ADD_CASE(8,  num1, num3, ex_add_num1_num3),
    ADD_CASE(9,  num2, num0, ex_add_num0_num2), /* Commutativity check */
    ADD_CASE(10, num2, num1, ex_add_num1_num2), /* Commutativity check */
    ADD_CASE(11, num2, num2, ex_add_num2_num2),
    ADD_CASE(12, num2, num3, ex_add_num2_num3),
    ADD_CASE(13, num3, num0, ex_add_num0_num3), /* Commutativity check */
    ADD_CASE(14, num3, num1, ex_add_num1_num3), /* Commutativity check */
    ADD_CASE(15, num3, num2, ex_add_num2_num3), /* Commutativity check */
    ADD_CASE(16, num3, num3, ex_add_num3_num3),
};

static int test_add(int i)
{
    const OSSL_FN_ULONG *n1 = test_add_cases[i].op1;
    size_t n1_limbs = test_add_cases[i].op1_size;
    const OSSL_FN_ULONG *n2 = test_add_cases[i].op2;
    size_t n2_limbs = test_add_cases[i].op2_size;
    const OSSL_FN_ULONG *ex = test_add_cases[i].ex;
    size_t ex_limbs = test_add_cases[i].ex_size;
    size_t check_limbs = test_add_cases[i].check_size;
    int ret = 1;
    OSSL_FN *fn1 = NULL, *fn2 = NULL, *res = NULL;
    const OSSL_FN_ULONG *u = NULL;

    /* To test that OSSL_FN_add() does a complete job, 'res' is pre-polluted */

    if (!TEST_ptr(fn1 = OSSL_FN_new_limbs(n1_limbs))
        || !TEST_ptr(fn2 = OSSL_FN_new_limbs(n2_limbs))
        || !TEST_ptr(res = OSSL_FN_new_limbs(ex_limbs))
        || !TEST_true(pollute(res, 0, ex_limbs))
        || !TEST_true(ossl_fn_set_words(fn1, n1, n1_limbs))
        || !TEST_true(ossl_fn_set_words(fn2, n2, n2_limbs))
        || !TEST_true(OSSL_FN_add(res, fn1, fn2))
        || !TEST_ptr(u = ossl_fn_get_words(res))
        || !TEST_mem_eq(u, ossl_fn_get_dsize(res) * OSSL_FN_BYTES,
                        ex, check_limbs * OSSL_FN_BYTES))
        ret = 0;
    OSSL_FN_free(fn1);
    OSSL_FN_free(fn2);
    OSSL_FN_free(res);

    return ret;
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
    OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff)};
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

#define SUB_CASE(i, op1, op2, ex)               \
    {                                           \
        /* op1, with size */ op1, LIMBSOF(op1), \
        /* op2, with size */ op2, LIMBSOF(op2), \
        /* ex, with size */ ex, LIMBSOF(ex),    \
        /* op1_live_size */ LIMBSOF(op1),       \
        /* op2_live_size */ LIMBSOF(op2),       \
        /* res_live_size */ LIMBSOF(ex),        \
        /* check_size */ LIMBSOF(ex),           \
    }  

static struct test_case_st test_sub_cases[] = {
    SUB_CASE(1,  num0, num0, ex_sub_num0_num0),
    SUB_CASE(2,  num0, num1, ex_sub_num0_num1),
    SUB_CASE(3,  num0, num2, ex_sub_num0_num2),
    SUB_CASE(4,  num0, num3, ex_sub_num0_num3),
    SUB_CASE(5,  num1, num0, ex_sub_num1_num0),
    SUB_CASE(6,  num1, num1, ex_sub_num1_num1),
    SUB_CASE(7,  num1, num2, ex_sub_num1_num2),
    SUB_CASE(8,  num1, num3, ex_sub_num1_num3),
    SUB_CASE(9,  num2, num0, ex_sub_num2_num0),
    SUB_CASE(10, num2, num1, ex_sub_num2_num1),
    SUB_CASE(11, num2, num2, ex_sub_num2_num2),
    SUB_CASE(12, num2, num3, ex_sub_num2_num3),
    SUB_CASE(13, num3, num0, ex_sub_num3_num0),
    SUB_CASE(14, num3, num1, ex_sub_num3_num1),
    SUB_CASE(15, num3, num2, ex_sub_num3_num2),
    SUB_CASE(16, num3, num3, ex_sub_num3_num3),
};

static int test_sub(int i)
{
    const OSSL_FN_ULONG *n1 = test_sub_cases[i].op1;
    size_t n1_limbs = test_sub_cases[i].op1_size;
    const OSSL_FN_ULONG *n2 = test_sub_cases[i].op2;
    size_t n2_limbs = test_sub_cases[i].op2_size;
    const OSSL_FN_ULONG *ex = test_sub_cases[i].ex;
    size_t ex_limbs = test_sub_cases[i].ex_size;
    size_t check_limbs = test_sub_cases[i].check_size;
    int ret = 1;
    OSSL_FN *fn1 = NULL, *fn2 = NULL, *res = NULL;
    const OSSL_FN_ULONG *u = NULL;

    /* To test that OSSL_FN_sub() does a complete job, 'res' is pre-polluted */

    if (!TEST_ptr(fn1 = OSSL_FN_new_limbs(n1_limbs))
        || !TEST_ptr(fn2 = OSSL_FN_new_limbs(n2_limbs))
        || !TEST_ptr(res = OSSL_FN_new_limbs(ex_limbs))
        || !TEST_true(pollute(res, 0, ex_limbs))
        || !TEST_true(ossl_fn_set_words(fn1, n1, n1_limbs))
        || !TEST_true(ossl_fn_set_words(fn2, n2, n2_limbs))
        || !TEST_true(OSSL_FN_sub(res, fn1, fn2))
        || !TEST_ptr(u = ossl_fn_get_words(res))
        || !TEST_mem_eq(u, ossl_fn_get_dsize(res) * OSSL_FN_BYTES,
                        ex, check_limbs * OSSL_FN_BYTES))
        ret = 0;
    OSSL_FN_free(fn1);
    OSSL_FN_free(fn2);
    OSSL_FN_free(res);

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
                res = 0;
        } else {
            if (!TEST_mem_eq(u, a_limbs * OSSL_FN_BYTES,
                             a_data, a_limbs * OSSL_FN_BYTES))
                res = 0;
        }
    }

    if (TEST_ptr(u = ossl_fn_get_words(b))) {
        if (res == b) {
            if (!TEST_mem_eq(u, ex_limbs * OSSL_FN_BYTES,
                             ex_data, ex_limbs * OSSL_FN_BYTES))
                res = 0;
        } else {
            if (!TEST_mem_eq(u, b_limbs * OSSL_FN_BYTES,
                             b_data, b_limbs * OSSL_FN_BYTES))
                res = 0;
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
    const OSSL_FN_ULONG *ex = test_case.ex;
    size_t n1_new_limbs = test_case.op1_live_size;
    size_t n2_new_limbs = test_case.op2_live_size;
    size_t res_limbs = test_case.res_live_size;
    size_t check_limbs = test_case.check_size;
    OSSL_FN *fn1 = NULL, *fn2 = NULL, *res = NULL;
    const OSSL_FN_ULONG *u = NULL;
    
    OSSL_FN_CTX *ctx = NULL;
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 1, 1, res_limbs))
        || !TEST_ptr(fn1 = OSSL_FN_new_limbs(n1_new_limbs))
        || !TEST_ptr(fn2 = OSSL_FN_new_limbs(n2_new_limbs))
        || !TEST_true(ossl_fn_set_words(fn1, n1, n1_limbs))
        || !TEST_true(ossl_fn_set_words(fn2, n2, n2_limbs))
        || !TEST_ptr(res = OSSL_FN_new_limbs(res_limbs))) {
        res = 0;
        /* There's no way to continue tests in this case */
        goto end;
    }

    /* To test that OSSL_FN_mul() does a complete job, 'res' is pre-polluted */

    if (!TEST_true(pollute(res, 0, res_limbs))
        || !TEST_true(OSSL_FN_mul(res, fn1, fn2, ctx))
        || !TEST_ptr(u = ossl_fn_get_words(res))
        || !TEST_mem_eq(u, check_limbs * OSSL_FN_BYTES,
                        ex, check_limbs * OSSL_FN_BYTES)
        || !TEST_true(check_zero(res, check_limbs, res_limbs)))
        ret = 0;

 end:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fn1);
    OSSL_FN_free(fn2);
    OSSL_FN_free(res);

    return ret;
}

/* i should be set to match the iteration number that's displayed when testing */
#define MUL_CASE(i, op1, op2, ex)                                       \
    {                                                                   \
        /* op1, with size */ op1, LIMBSOF(op1),                         \
        /* op2, with size */ op2, LIMBSOF(op2),                         \
        /* ex, with size */ ex, LIMBSOF(ex),                            \
        /* op1_live_size */ LIMBSOF(op1) + 1,                           \
        /* op2_live_size */ LIMBSOF(op2) + 2,                           \
        /* res_live_size */ LIMBSOF(op1) + LIMBSOF(op2) + ((i - 1) % 4), \
        /* check_size */ LIMBSOF(ex),                                   \
    }

static struct test_case_st test_mul_cases[] = {
    MUL_CASE(1,  num0, num0, ex_mul_num0_num0),
    MUL_CASE(2,  num0, num1, ex_mul_num0_num1),
    MUL_CASE(3,  num0, num2, ex_mul_num0_num2),
    MUL_CASE(4,  num0, num3, ex_mul_num0_num3),
    MUL_CASE(5,  num1, num0, ex_mul_num0_num1), /* Commutativity check */
    MUL_CASE(6,  num1, num1, ex_mul_num1_num1),
    MUL_CASE(7,  num1, num2, ex_mul_num1_num2),
    MUL_CASE(8,  num1, num3, ex_mul_num1_num3),
    MUL_CASE(9,  num2, num0, ex_mul_num0_num2), /* Commutativity check */
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
#define MUL_TRUNCATED_CASE(i, op1, op2, ex)                             \
    {                                                                   \
        /* op1, with size */ op1, LIMBSOF(op1),                         \
        /* op2, with size */ op2, LIMBSOF(op2),                         \
        /* ex, with size */ ex, LIMBSOF(ex),                            \
        /* op1_live_size */ LIMBSOF(op1) + 1,                           \
        /* op2_live_size */ LIMBSOF(op2) + 2,                           \
        /* res_live_size */ LIMBSOF(ex) / 2,                            \
        /* check_size */ LIMBSOF(ex) / 2,                               \
    }
/* A special case, where the truncation is set to the size of ex minus 64 bits */
#define MUL_TRUNCATED_SPECIAL_CASE1(i, op1, op2, ex)                    \
    {                                                                   \
        /* op1, with size */ op1, LIMBSOF(op1),                         \
        /* op2, with size */ op2, LIMBSOF(op2),                         \
        /* ex, with size */ ex, LIMBSOF(ex),                            \
        /* op1_live_size */ LIMBSOF(op1) + 1,                           \
        /* op2_live_size */ LIMBSOF(op2) + 2,                           \
        /* res_live_size */ LIMBSOF(ex) - 8 / OSSL_FN_BYTES,            \
        /* check_size */ LIMBSOF(ex) - 8 / OSSL_FN_BYTES,               \
    }

static struct test_case_st test_mul_truncate_cases[] = {
    MUL_TRUNCATED_CASE(1,  num0, num0, ex_mul_num0_num0),
    MUL_TRUNCATED_CASE(2,  num0, num1, ex_mul_num0_num1),
    MUL_TRUNCATED_CASE(3,  num0, num2, ex_mul_num0_num2),
    MUL_TRUNCATED_CASE(4,  num0, num3, ex_mul_num0_num3),
    MUL_TRUNCATED_CASE(5,  num1, num0, ex_mul_num0_num1), /* Commutativity check */
    MUL_TRUNCATED_CASE(6,  num1, num1, ex_mul_num1_num1),
    MUL_TRUNCATED_CASE(7,  num1, num2, ex_mul_num1_num2),
    MUL_TRUNCATED_CASE(8,  num1, num3, ex_mul_num1_num3),
    MUL_TRUNCATED_CASE(9,  num2, num0, ex_mul_num0_num2), /* Commutativity check */
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

int setup_tests(void)
{
    ADD_ALL_TESTS(test_add, 16);
    ADD_ALL_TESTS(test_sub, 16);
    ADD_ALL_TESTS(test_mul_feature_r_is_operand, 4);
    ADD_ALL_TESTS(test_mul, OSSL_NELEM(test_mul_cases));
    ADD_ALL_TESTS(test_mul_truncated, OSSL_NELEM(test_mul_truncate_cases));

    return 1;
}
