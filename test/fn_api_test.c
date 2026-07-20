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
static const OSSL_FN_ULONG num0[] = { OSSL_FN_ULONG64_C(0x80000000, 0x00000001) };
static const OSSL_FN_ULONG num1[] = { OSSL_FN_ULONG64_C(0x00000001, 0x80000000) };
static const OSSL_FN_ULONG num2[] = { OSSL_FN_ULONG64_C(0x01234567, 0x89abcdef) };
static const OSSL_FN_ULONG num3[] = { OSSL_FN_ULONG64_C(0xfedcba98, 0x76543210) };

/* Numbers for edge cases */
static const OSSL_FN_ULONG num4[] = { OSSL_FN_ULONG64_C(0x00000000, 0x00000000) };
static const OSSL_FN_ULONG num5[] = { OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff) };
static const OSSL_FN_ULONG num6[] = {
    OSSL_FN_ULONG64_C(0x00000000, 0x00000000),
    OSSL_FN_ULONG64_C(0x10000000, 0x00000000),
};
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

    /* When the result is larger than check_size, the expected extended value */
    OSSL_FN_ULONG extended_limb_value;
#define EXTENDED_LIMB_ZERO ((OSSL_FN_ULONG)0)
#define EXTENDED_LIMB_MINUS_ONE ((OSSL_FN_ULONG)-1)
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
    const OSSL_FN_ULONG *ex = test_case.ex;
    size_t n1_new_limbs = test_case.op1_live_size;
    size_t n2_new_limbs = test_case.op2_live_size;
    size_t res_limbs = test_case.res_live_size;
    size_t check_limbs = test_case.check_size;
    OSSL_FN_ULONG extended_value = test_case.extended_limb_value;
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

#define ADD_CASE(i, op1, op2, ex)                     \
    {                                                 \
        /* op1 */ op1,                                \
        /* op1_size */ LIMBSOF(op1),                  \
        /* op2 */ op2,                                \
        /* op2_size */ LIMBSOF(op2),                  \
        /* ex */ ex,                                  \
        /* ex_size */ LIMBSOF(ex),                    \
        /* op1_live_size */ LIMBSOF(op1) + 1,         \
        /* op2_live_size */ LIMBSOF(op2) + 2,         \
        /* res_live_size */ LIMBSOF(ex) + 3,          \
        /* check_size */ LIMBSOF(ex),                 \
        /* extended_limb_value */ EXTENDED_LIMB_ZERO, \
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

#define ADD_TRUNCATED_CASE(i, op1, op2, ex)           \
    {                                                 \
        /* op1 */ op1,                                \
        /* op1_size */ LIMBSOF(op1),                  \
        /* op2 */ op2,                                \
        /* op2_size */ LIMBSOF(op2),                  \
        /* ex */ ex,                                  \
        /* ex_size */ LIMBSOF(ex),                    \
        /* op1_live_size */ LIMBSOF(op1) + 1,         \
        /* op2_live_size */ LIMBSOF(op2) + 2,         \
        /* res_live_size */ LIMBSOF(ex) - 1,          \
        /* check_size */ LIMBSOF(ex) - 1,             \
        /* extended_limb_value */ EXTENDED_LIMB_ZERO, \
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

static int test_sub_common(struct test_case_st test_case)
{
    const OSSL_FN_ULONG *n1 = test_case.op1;
    size_t n1_limbs = test_case.op1_size;
    const OSSL_FN_ULONG *n2 = test_case.op2;
    size_t n2_limbs = test_case.op2_size;
    const OSSL_FN_ULONG *ex = test_case.ex;
    size_t n1_new_limbs = test_case.op1_live_size;
    size_t n2_new_limbs = test_case.op2_live_size;
    size_t res_limbs = test_case.res_live_size;
    size_t check_limbs = test_case.check_size;
    OSSL_FN_ULONG extended_value = test_case.extended_limb_value;
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
        /* ex */ ex,                          \
        /* ex_size */ LIMBSOF(ex),            \
        /* op1_live_size */ LIMBSOF(op1) + 1, \
        /* op2_live_size */ LIMBSOF(op2) + 2, \
        /* res_live_size */ LIMBSOF(ex) + 3,  \
        /* check_size */ LIMBSOF(ex),         \
        /* extended_limb_value */ (ext),      \
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

#define SUB_TRUNCATED_CASE(i, op1, op2, ex)           \
    {                                                 \
        /* op1 */ op1,                                \
        /* op1_size */ LIMBSOF(op1),                  \
        /* op2 */ op2,                                \
        /* op2_size */ LIMBSOF(op2),                  \
        /* ex */ ex,                                  \
        /* ex_size */ LIMBSOF(ex),                    \
        /* op1_live_size */ LIMBSOF(op1) + 1,         \
        /* op2_live_size */ LIMBSOF(op2) + 2,         \
        /* res_live_size */ LIMBSOF(ex) - 1,          \
        /* check_size */ LIMBSOF(ex) - 1,             \
        /* extended_limb_value */ EXTENDED_LIMB_ZERO, \
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
    const OSSL_FN_ULONG *ex = test_case.ex;
    size_t n1_new_limbs = test_case.op1_live_size;
    size_t n2_new_limbs = test_case.op2_live_size;
    size_t res_limbs = test_case.res_live_size;
    size_t check_limbs = test_case.check_size;
    OSSL_FN_ULONG extended_value = test_case.extended_limb_value;
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
#define MUL_CASE(i, op1, op2, ex)                                        \
    {                                                                    \
        /* op1 */ op1,                                                   \
        /* op1_size */ LIMBSOF(op1),                                     \
        /* op2 */ op2,                                                   \
        /* op2_size */ LIMBSOF(op2),                                     \
        /* ex */ ex,                                                     \
        /* ex_size */ LIMBSOF(ex),                                       \
        /* op1_live_size */ LIMBSOF(op1) + 1,                            \
        /* op2_live_size */ LIMBSOF(op2) + 2,                            \
        /* res_live_size */ LIMBSOF(op1) + LIMBSOF(op2) + ((i - 1) % 4), \
        /* check_size */ LIMBSOF(ex),                                    \
        /* extended_limb_value */ EXTENDED_LIMB_ZERO,                    \
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
#define MUL_TRUNCATED_CASE(i, op1, op2, ex)           \
    {                                                 \
        /* op1 */ op1,                                \
        /* op1_size */ LIMBSOF(op1),                  \
        /* op2 */ op2,                                \
        /* op2_size */ LIMBSOF(op2),                  \
        /* ex */ ex,                                  \
        /* ex_size */ LIMBSOF(ex),                    \
        /* op1_live_size */ LIMBSOF(op1) + 1,         \
        /* op2_live_size */ LIMBSOF(op2) + 2,         \
        /* res_live_size */ LIMBSOF(ex) / 2,          \
        /* check_size */ LIMBSOF(ex) / 2,             \
        /* extended_limb_value */ EXTENDED_LIMB_ZERO, \
    }
/* A special case, where the truncation is set to the size of ex minus 64 bits */
#define MUL_TRUNCATED_SPECIAL_CASE1(i, op1, op2, ex)         \
    {                                                        \
        /* op1 */ op1,                                       \
        /* op1_size */ LIMBSOF(op1),                         \
        /* op2 */ op2,                                       \
        /* op2_size */ LIMBSOF(op2),                         \
        /* ex */ ex,                                         \
        /* ex_size */ LIMBSOF(ex),                           \
        /* op1_live_size */ LIMBSOF(op1) + 1,                \
        /* op2_live_size */ LIMBSOF(op2) + 2,                \
        /* res_live_size */ LIMBSOF(ex) - 8 / OSSL_FN_BYTES, \
        /* check_size */ LIMBSOF(ex) - 8 / OSSL_FN_BYTES,    \
        /* extended_limb_value */ EXTENDED_LIMB_ZERO,        \
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
    const OSSL_FN_ULONG *ex = test_case.ex;
    size_t n1_new_limbs = test_case.op1_live_size;
    size_t res_limbs = test_case.res_live_size;
    size_t check_limbs = test_case.check_size;
    OSSL_FN_ULONG extended_value = test_case.extended_limb_value;
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
#define SQR_CASE(i, op1, ex)                                  \
    {                                                         \
        /* op1 */ op1,                                        \
        /* op1_size */ LIMBSOF(op1),                          \
        /* op2 */ NULL,                                       \
        /* op2_size */ 0,                                     \
        /* ex */ ex,                                          \
        /* ex_size */ LIMBSOF(ex),                            \
        /* op1_live_size */ LIMBSOF(op1) + 1,                 \
        /* op2_live_size */ 0,                                \
        /* res_live_size */ LIMBSOF(op1) * 2 + ((i - 1) % 4), \
        /* check_size */ LIMBSOF(ex),                         \
        /* extended_limb_value */ EXTENDED_LIMB_ZERO,         \
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
#define SQR_TRUNCATED_CASE(i, op1, ex)                \
    {                                                 \
        /* op1 */ op1,                                \
        /* op1_size */ LIMBSOF(op1),                  \
        /* op2 */ NULL,                               \
        /* op2_size */ 0,                             \
        /* ex */ ex,                                  \
        /* ex_size */ LIMBSOF(ex),                    \
        /* op1_live_size */ LIMBSOF(op1) + 1,         \
        /* op2_live_size */ 0,                        \
        /* res_live_size */ LIMBSOF(ex) / 2,          \
        /* check_size */ LIMBSOF(ex) / 2,             \
        /* extended_limb_value */ EXTENDED_LIMB_ZERO, \
    }
/* A special case, where the truncation is set to the size of ex minus 64 bits */
#define SQR_TRUNCATED_SPECIAL_CASE1(i, op1, ex)              \
    {                                                        \
        /* op1 */ op1,                                       \
        /* op1_size */ LIMBSOF(op1),                         \
        /* op2 */ NULL,                                      \
        /* op2_size */ 0,                                    \
        /* ex */ ex,                                         \
        /* ex_size */ LIMBSOF(ex),                           \
        /* op1_live_size */ LIMBSOF(op1) + 1,                \
        /* op2_live_size */ 0,                               \
        /* res_live_size */ LIMBSOF(ex) - 8 / OSSL_FN_BYTES, \
        /* check_size */ LIMBSOF(ex) - 8 / OSSL_FN_BYTES,    \
        /* extended_limb_value */ EXTENDED_LIMB_ZERO,        \
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
    ADD_ALL_TESTS(test_mul_feature_r_is_operand, 4);
    ADD_ALL_TESTS(test_mul, OSSL_NELEM(test_mul_cases));
    ADD_ALL_TESTS(test_mul_truncated, OSSL_NELEM(test_mul_truncate_cases));
    ADD_ALL_TESTS(test_sqr_feature_r_is_operand, 2);
    ADD_ALL_TESTS(test_sqr, OSSL_NELEM(test_sqr_cases));
    ADD_ALL_TESTS(test_sqr_truncated, OSSL_NELEM(test_sqr_truncate_cases));
    ADD_ALL_TESTS(test_rand_bits, OSSL_NELEM(rand_bits_cases));
    ADD_ALL_TESTS(test_rand, OSSL_NELEM(rand_bits_cases));
    ADD_TEST(test_rand_result_too_small);
    ADD_TEST(test_rand_bits_too_small);
    ADD_ALL_TESTS(test_rand_range, OSSL_NELEM(range_words));
    ADD_TEST(test_rand_range_zero);
    ADD_TEST(test_rand_range_exactly_sized);

    return 1;
}
