/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file Internal tests of OSSL_FN
 *
 * This tests OSSL_FN internals only, i.e. anything that requires including
 * ../crypto/fn/fn_local.h, such as introspection.
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

static const OSSL_FN_ULONG num[][8 / OSSL_FN_BYTES] = {
    /* num[0] */ {OSSL_FN_ULONG64_C(0x80000000, 0x00000001)},
    /* num[1] */ {OSSL_FN_ULONG64_C(0x00000001, 0x80000000)},
    /* num[2] */ {OSSL_FN_ULONG64_C(0x01234567, 0x89abcdef)},
    /* num[3] */ {OSSL_FN_ULONG64_C(0xfedcba98, 0x76543210)},
};

static const OSSL_FN_ULONG expected_add_num_num[4][4][3] = {
    {
        /* num[0] + num[0] */ {OSSL_FN_ULONG64_C(0x00000000, 0x00000002), OSSL_FN_ULONG_C(0x1)},
        /* num[0] + num[1] */ {OSSL_FN_ULONG64_C(0x80000001, 0x80000001)},
        /* num[0] + num[2] */ {OSSL_FN_ULONG64_C(0x81234567, 0x89abcdf0)},
        /* num[0] + num[3] */ {OSSL_FN_ULONG64_C(0x7edcba98, 0x76543211), OSSL_FN_ULONG_C(0x1)},
    }, {
        /* num[1] + num[0] */ {OSSL_FN_ULONG64_C(0x80000001, 0x80000001)},
        /* num[1] + num[1] */ {OSSL_FN_ULONG64_C(0x00000003, 0x00000000)},
        /* num[1] + num[2] */ {OSSL_FN_ULONG64_C(0x01234569, 0x09abcdef)},
        /* num[1] + num[3] */ {OSSL_FN_ULONG64_C(0xfedcba99, 0xf6543210)},
    }, {
        /* num[2] + num[0] */ {OSSL_FN_ULONG64_C(0x81234567, 0x89abcdf0)},
        /* num[2] + num[1] */ {OSSL_FN_ULONG64_C(0x01234569, 0x09abcdef)},
        /* num[2] + num[2] */ {OSSL_FN_ULONG64_C(0x02468acf, 0x13579bde)},
        /* num[2] + num[3] */ {OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff)},
    }, {
        /* num[3] + num[0] */ {OSSL_FN_ULONG64_C(0x7edcba98, 0x76543211), OSSL_FN_ULONG_C(0x1)},
        /* num[3] + num[1] */ {OSSL_FN_ULONG64_C(0xfedcba99, 0xf6543210)},
        /* num[3] + num[2] */ {OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff)},
        /* num[3] + num[3] */ {OSSL_FN_ULONG64_C(0xfdb97530, 0xeca86420), OSSL_FN_ULONG_C(0x1)},
    },
};

static int test_add(int i)
{
    size_t i1 = i / 4;
    size_t i2 = i % 4;
    const OSSL_FN_ULONG *n1 = num[i1];
    size_t n1_limbs = sizeof(num[i1]) / OSSL_FN_BYTES;
    const OSSL_FN_ULONG *n2 = num[i2];
    size_t n2_limbs = sizeof(num[i2]) / OSSL_FN_BYTES;
    const OSSL_FN_ULONG *ex = expected_add_num_num[i1][i2];
    size_t ex_limbs = sizeof(expected_add_num_num[i1][i2]) / OSSL_FN_BYTES;
    int ret = 1;
    OSSL_FN *num1 = NULL, *num2 = NULL, *res = NULL;
    const OSSL_FN_ULONG *u = NULL;
    
    /* To test that OSSL_FN_add() does a complete job, 'res' is pre-polluted */

    if (!TEST_ptr(num1 = OSSL_FN_new_limbs(n1_limbs))
        || !TEST_ptr(num2 = OSSL_FN_new_limbs(n2_limbs))
        || !TEST_ptr(res = OSSL_FN_new_limbs(ex_limbs))
        || !TEST_true(pollute(res, 0, ex_limbs))
        || !TEST_true(ossl_fn_set_words(num1, n1, n1_limbs))
        || !TEST_true(ossl_fn_set_words(num2, n2, n2_limbs))
        || !TEST_true(OSSL_FN_add(res, num1, num2))
        || !TEST_ptr(u = ossl_fn_get_words(res))
        || !TEST_mem_eq(u, ossl_fn_get_dsize(res) * OSSL_FN_BYTES,
                        ex, ex_limbs * OSSL_FN_BYTES))
        ret = 0;
    OSSL_FN_free(num1);
    OSSL_FN_free(num2);
    OSSL_FN_free(res);

    return ret;
}

/* Dimension the expected arrays to fit 4 32-bit limbs */
#define EXPECTED_LIMBS ((16 + OSSL_FN_BYTES - 1) / OSSL_FN_BYTES)
static OSSL_FN_ULONG expected_sub_num_num[4][4][EXPECTED_LIMBS] = {
    {
        /* num[0] - num[0] */ {OSSL_FN_ULONG64_C(0x00000000, 0x00000000)},
        /* num[0] - num[1] */ {OSSL_FN_ULONG64_C(0x7ffffffe, 0x80000001)},
        /* num[0] - num[2] */ {OSSL_FN_ULONG64_C(0x7edcba98, 0x76543212)},
        /* num[0] - num[3] */ {OSSL_FN_ULONG64_C(0x81234567, 0x89abcdf1),
                               OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff)},
    }, {
        /* num[1] - num[0] */ {OSSL_FN_ULONG64_C(0x80000001, 0x7fffffff),
                               OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff)},
        /* num[1] - num[1] */ {OSSL_FN_ULONG64_C(0x00000000, 0x00000000)},
        /* num[1] - num[2] */ {OSSL_FN_ULONG64_C(0xfedcba99, 0xf6543211),
                               OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff)},
        /* num[1] - num[3] */ {OSSL_FN_ULONG64_C(0x01234569, 0x09abcdf0),
                               OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff)},
    }, {
        /* num[2] - num[0] */ {OSSL_FN_ULONG64_C(0x81234567, 0x89abcdee),
                               OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff)},
        /* num[2] - num[1] */ {OSSL_FN_ULONG64_C(0x01234566, 0x09abcdef)},
        /* num[2] - num[2] */ {OSSL_FN_ULONG64_C(0x00000000, 0x00000000)},
        /* num[2] - num[3] */ {OSSL_FN_ULONG64_C(0x02468acf, 0x13579bdf),
                               OSSL_FN_ULONG64_C(0xffffffff, 0xffffffff)},
    }, {
        /* num[3] - num[0] */ {OSSL_FN_ULONG64_C(0x7edcba98, 0x7654320f)},
        /* num[3] - num[1] */ {OSSL_FN_ULONG64_C(0xfedcba96, 0xf6543210)},
        /* num[3] - num[2] */ {OSSL_FN_ULONG64_C(0xfdb97530, 0xeca86421)},
        /* num[3] - num[3] */ {OSSL_FN_ULONG64_C(0x00000000, 0x00000000)},
    },
};

static int test_sub(int i)
{
    size_t i1 = i / 4;
    size_t i2 = i % 4;
    const OSSL_FN_ULONG *n1 = num[i1];
    size_t n1_limbs = sizeof(num[i1]) / OSSL_FN_BYTES;
    const OSSL_FN_ULONG *n2 = num[i2];
    size_t n2_limbs = sizeof(num[i2]) / OSSL_FN_BYTES;
    const OSSL_FN_ULONG *ex = expected_sub_num_num[i1][i2];
    size_t ex_limbs = sizeof(expected_sub_num_num[i1][i2]) / OSSL_FN_BYTES;
    int ret = 1;
    OSSL_FN *num1 = NULL, *num2 = NULL, *res = NULL;
    const OSSL_FN_ULONG *u = NULL;
    
    /* To test that OSSL_FN_sub() does a complete job, 'res' is pre-polluted */

    if (!TEST_ptr(num1 = OSSL_FN_new_limbs(n1_limbs))
        || !TEST_ptr(num2 = OSSL_FN_new_limbs(n2_limbs))
        || !TEST_ptr(res = OSSL_FN_new_limbs(ex_limbs))
        || !TEST_true(pollute(res, 0, ex_limbs))
        || !TEST_true(ossl_fn_set_words(num1, n1, n1_limbs))
        || !TEST_true(ossl_fn_set_words(num2, n2, n2_limbs))
        || !TEST_true(OSSL_FN_sub(res, num1, num2))
        || !TEST_ptr(u = ossl_fn_get_words(res))
        || !TEST_mem_eq(u, ossl_fn_get_dsize(res) * OSSL_FN_BYTES,
                        ex, ex_limbs * OSSL_FN_BYTES))
        ret = 0;
    OSSL_FN_free(num1);
    OSSL_FN_free(num2);
    OSSL_FN_free(res);

    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_add, 16);
    ADD_ALL_TESTS(test_sub, 16);

    return 1;
}
