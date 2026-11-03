/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal/nelem.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "testutil.h"

#define NUM_BITS (BN_BITS2 * 4)

#define BN_print_var(v) test_output_bignum(#v, v)

/*
 * Test that r == 0 in test_exp_mod_zero(). Returns one on success,
 * returns zero and prints debug output otherwise.
 */
static int a_is_zero_mod_one(const char *method, const BIGNUM *r,
    const BIGNUM *a)
{
    if (!BN_is_zero(r)) {
        TEST_error("%s failed: a ** 0 mod 1 = r (should be 0)", method);
        BN_print_var(a);
        BN_print_var(r);
        return 0;
    }
    return 1;
}

/*
 * test_mod_exp_zero tests that x**0 mod 1 == 0. It returns zero on success.
 */
static int test_mod_exp_zero(void)
{
    BIGNUM *a = NULL, *p = NULL, *m = NULL;
    BIGNUM *r = NULL;
    BN_ULONG one_word = 1;
    BN_CTX *ctx = BN_CTX_new();
    int ret = 0, failed = 0;
    BN_MONT_CTX *mont = NULL;

    if (!TEST_ptr(m = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(r = BN_new()))
        goto err;

    BN_one(m);
    BN_one(a);
    BN_zero(p);

    if (!TEST_true(BN_rand(a, 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)))
        goto err;

    if (!TEST_true(BN_mod_exp(r, a, p, m, ctx)))
        goto err;

    if (!TEST_true(a_is_zero_mod_one("BN_mod_exp", r, a)))
        failed = 1;

    if (!TEST_true(BN_mod_exp_recp(r, a, p, m, ctx)))
        goto err;

    if (!TEST_true(a_is_zero_mod_one("BN_mod_exp_recp", r, a)))
        failed = 1;

    if (!TEST_true(BN_mod_exp_simple(r, a, p, m, ctx)))
        goto err;

    if (!TEST_true(a_is_zero_mod_one("BN_mod_exp_simple", r, a)))
        failed = 1;

    if (!TEST_true(BN_mod_exp_mont(r, a, p, m, ctx, NULL)))
        goto err;

    if (!TEST_true(a_is_zero_mod_one("BN_mod_exp_mont", r, a)))
        failed = 1;

    if (!TEST_true(BN_mod_exp_mont_consttime(r, a, p, m, ctx, NULL)))
        goto err;

    if (!TEST_true(a_is_zero_mod_one("BN_mod_exp_mont_consttime", r, a)))
        failed = 1;

    if (!TEST_ptr(mont = BN_MONT_CTX_new()))
        goto err;

    ERR_set_mark();
    /* mont is not set but passed in */
    if (!TEST_false(BN_mod_exp_mont_consttime(r, p, a, m, ctx, mont)))
        goto err;
    if (!TEST_false(BN_mod_exp_mont(r, p, a, m, ctx, mont)))
        goto err;
    ERR_pop_to_mark();

    if (!TEST_true(BN_MONT_CTX_set(mont, m, ctx)))
        goto err;

    /* we compute 0 ** a mod 1 here, to execute code that uses mont */
    if (!TEST_true(BN_mod_exp_mont_consttime(r, p, a, m, ctx, mont)))
        goto err;

    if (!TEST_true(a_is_zero_mod_one("BN_mod_exp_mont_consttime", r, a)))
        failed = 1;

    if (!TEST_true(BN_mod_exp_mont(r, p, a, m, ctx, mont)))
        goto err;

    if (!TEST_true(a_is_zero_mod_one("BN_mod_exp_mont", r, a)))
        failed = 1;

    /*
     * A different codepath exists for single word multiplication
     * in non-constant-time only.
     */
    if (!TEST_true(BN_mod_exp_mont_word(r, one_word, p, m, ctx, NULL)))
        goto err;

    if (!TEST_BN_eq_zero(r)) {
        TEST_error("BN_mod_exp_mont_word failed: "
                   "1 ** 0 mod 1 = r (should be 0)");
        BN_print_var(r);
        goto err;
    }

    ret = !failed;
err:
    BN_free(r);
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_MONT_CTX_free(mont);
    BN_CTX_free(ctx);

    return ret;
}

static int test_mod_exp(int round)
{
    BN_CTX *ctx;
    unsigned char c;
    int ret = 0;
    BIGNUM *r_mont = NULL;
    BIGNUM *r_mont_const = NULL;
    BIGNUM *r_recp = NULL;
    BIGNUM *r_simple = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *m = NULL;

    if (!TEST_ptr(ctx = BN_CTX_new()))
        goto err;

    if (!TEST_ptr(r_mont = BN_new())
        || !TEST_ptr(r_mont_const = BN_new())
        || !TEST_ptr(r_recp = BN_new())
        || !TEST_ptr(r_simple = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(m = BN_new()))
        goto err;

    if (!TEST_int_gt(RAND_bytes(&c, 1), 0))
        goto err;
    c = (c % BN_BITS) - BN_BITS2;
    if (!TEST_true(BN_rand(a, NUM_BITS + c, BN_RAND_TOP_ONE,
            BN_RAND_BOTTOM_ANY)))
        goto err;

    if (!TEST_int_gt(RAND_bytes(&c, 1), 0))
        goto err;
    c = (c % BN_BITS) - BN_BITS2;
    if (!TEST_true(BN_rand(b, NUM_BITS + c, BN_RAND_TOP_ONE,
            BN_RAND_BOTTOM_ANY)))
        goto err;

    if (!TEST_int_gt(RAND_bytes(&c, 1), 0))
        goto err;
    c = (c % BN_BITS) - BN_BITS2;
    if (!TEST_true(BN_rand(m, NUM_BITS + c, BN_RAND_TOP_ONE,
            BN_RAND_BOTTOM_ODD)))
        goto err;

    if (!TEST_true(BN_mod(a, a, m, ctx))
        || !TEST_true(BN_mod(b, b, m, ctx))
        || !TEST_true(BN_mod_exp_mont(r_mont, a, b, m, ctx, NULL))
        || !TEST_true(BN_mod_exp_recp(r_recp, a, b, m, ctx))
        || !TEST_true(BN_mod_exp_simple(r_simple, a, b, m, ctx))
        || !TEST_true(BN_mod_exp_mont_consttime(r_mont_const, a, b, m, ctx, NULL)))
        goto err;

    if (!TEST_BN_eq(r_simple, r_mont)
        || !TEST_BN_eq(r_simple, r_recp)
        || !TEST_BN_eq(r_simple, r_mont_const)) {
        if (BN_cmp(r_simple, r_mont) != 0)
            TEST_info("simple and mont results differ");
        if (BN_cmp(r_simple, r_mont_const) != 0)
            TEST_info("simple and mont const time results differ");
        if (BN_cmp(r_simple, r_recp) != 0)
            TEST_info("simple and recp results differ");

        BN_print_var(a);
        BN_print_var(b);
        BN_print_var(m);
        BN_print_var(r_simple);
        BN_print_var(r_recp);
        BN_print_var(r_mont);
        BN_print_var(r_mont_const);
        goto err;
    }

    ret = 1;
err:
    BN_free(r_mont);
    BN_free(r_mont_const);
    BN_free(r_recp);
    BN_free(r_simple);
    BN_free(a);
    BN_free(b);
    BN_free(m);
    BN_CTX_free(ctx);

    return ret;
}

/*-
 * The factor sizes are what matters; the rounds are repetition on fresh
 * random inputs.  A defect showing on a fraction f of inputs is caught by
 * N rounds with probability 1 - (1 - f) ^ N, so twenty catch anything
 * affecting a seventh of inputs or more.  Rarer ones are not caught in a
 * single run at any affordable count, and are left to the inputs being
 * drawn afresh on every run.
 */
static const int factor_sizes[] = { 1024, 1536, 2048 };
#define ROUNDS_PER_FACTOR_SIZE 20

static int test_mod_exp_x2(int idx)
{
    BN_CTX *ctx;
    int ret = 0;
    BIGNUM *r_mont_const_x2_1 = NULL;
    BIGNUM *r_mont_const_x2_2 = NULL;
    BIGNUM *r_simple1 = NULL;
    BIGNUM *r_simple2 = NULL;
    BIGNUM *a1 = NULL;
    BIGNUM *b1 = NULL;
    BIGNUM *m1 = NULL;
    BIGNUM *a2 = NULL;
    BIGNUM *b2 = NULL;
    BIGNUM *m2 = NULL;
    int factor_size = factor_sizes[idx / ROUNDS_PER_FACTOR_SIZE];

    if (!TEST_ptr(ctx = BN_CTX_new()))
        goto err;

    if (!TEST_ptr(r_mont_const_x2_1 = BN_new())
        || !TEST_ptr(r_mont_const_x2_2 = BN_new())
        || !TEST_ptr(r_simple1 = BN_new())
        || !TEST_ptr(r_simple2 = BN_new())
        || !TEST_ptr(a1 = BN_new())
        || !TEST_ptr(b1 = BN_new())
        || !TEST_ptr(m1 = BN_new())
        || !TEST_ptr(a2 = BN_new())
        || !TEST_ptr(b2 = BN_new())
        || !TEST_ptr(m2 = BN_new()))
        goto err;

    BN_rand(a1, factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    BN_rand(b1, factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    BN_rand(m1, factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    BN_rand(a2, factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    BN_rand(b2, factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    BN_rand(m2, factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);

    if (!TEST_true(BN_mod(a1, a1, m1, ctx))
        || !TEST_true(BN_mod(b1, b1, m1, ctx))
        || !TEST_true(BN_mod(a2, a2, m2, ctx))
        || !TEST_true(BN_mod(b2, b2, m2, ctx))
        || !TEST_true(BN_mod_exp_simple(r_simple1, a1, b1, m1, ctx))
        || !TEST_true(BN_mod_exp_simple(r_simple2, a2, b2, m2, ctx))
        || !TEST_true(BN_mod_exp_mont_consttime_x2(r_mont_const_x2_1, a1, b1, m1, NULL,
            r_mont_const_x2_2, a2, b2, m2, NULL,
            ctx)))
        goto err;

    if (!TEST_BN_eq(r_simple1, r_mont_const_x2_1)
        || !TEST_BN_eq(r_simple2, r_mont_const_x2_2)) {
        if (BN_cmp(r_simple1, r_mont_const_x2_1) != 0)
            TEST_info("simple and mont const time x2 (#1) results differ");
        if (BN_cmp(r_simple2, r_mont_const_x2_2) != 0)
            TEST_info("simple and mont const time x2 (#2) results differ");

        BN_print_var(a1);
        BN_print_var(b1);
        BN_print_var(m1);
        BN_print_var(a2);
        BN_print_var(b2);
        BN_print_var(m2);
        BN_print_var(r_simple1);
        BN_print_var(r_simple2);
        BN_print_var(r_mont_const_x2_1);
        BN_print_var(r_mont_const_x2_2);
        goto err;
    }

    ret = 1;
err:
    BN_free(r_mont_const_x2_1);
    BN_free(r_mont_const_x2_2);
    BN_free(r_simple1);
    BN_free(r_simple2);
    BN_free(a1);
    BN_free(b1);
    BN_free(m1);
    BN_free(a2);
    BN_free(b2);
    BN_free(m2);
    BN_CTX_free(ctx);

    return ret;
}

/*
 * Compare BN_mod_exp_mont against BN_mod_exp_simple. On x86_64 with IFMA,
 * BN_mod_exp_mont uses the RSAZ x1 2048-bit public path when the operands
 * are not marked BN_FLG_CONSTTIME.
 */
static int rsaz_x1_compare(const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
    BN_CTX *ctx, BN_MONT_CTX *mont)
{
    int ret = 0;
    BIGNUM *r_mont = NULL, *r_simple = NULL, *r_const = NULL;
    BIGNUM *a_simple = NULL, *p_simple = NULL, *m_simple = NULL;

    /*
     * BN_mod_exp_simple refuses BN_FLG_CONSTTIME. BN_dup/BN_copy do not copy
     * that flag, so the simple path can still provide an independent reference.
     */
    if (!TEST_ptr(r_mont = BN_new())
        || !TEST_ptr(r_simple = BN_new())
        || !TEST_ptr(r_const = BN_new())
        || !TEST_ptr(a_simple = BN_dup(a))
        || !TEST_ptr(p_simple = BN_dup(p))
        || !TEST_ptr(m_simple = BN_dup(m))
        || !TEST_true(BN_mod_exp_simple(r_simple, a_simple, p_simple, m_simple,
            ctx))
        || !TEST_true(BN_mod_exp_mont(r_mont, a, p, m, ctx, mont))
        || !TEST_true(BN_mod_exp_mont_consttime(r_const, a, p, m, ctx, mont)))
        goto err;

    if (!TEST_BN_eq(r_simple, r_mont) || !TEST_BN_eq(r_simple, r_const)) {
        if (BN_cmp(r_simple, r_mont) != 0)
            TEST_info("simple and mont results differ");
        if (BN_cmp(r_simple, r_const) != 0)
            TEST_info("simple and mont const time results differ");
        BN_print_var(a);
        BN_print_var(p);
        BN_print_var(m);
        BN_print_var(r_simple);
        BN_print_var(r_mont);
        BN_print_var(r_const);
        goto err;
    }

    ret = 1;
err:
    BN_free(r_mont);
    BN_free(r_simple);
    BN_free(r_const);
    BN_free(a_simple);
    BN_free(p_simple);
    BN_free(m_simple);
    return ret;
}

/*
 * Exercise the 2048-bit BN_mod_exp_mont RSAZ IFMA x1 hook (or the generic
 * fallback on CPUs without IFMA). Cases cover RSA public e, the 80/81-bit
 * SQM vs w=5 split, a full-width exponent, short and zero bases, unreduced
 * base, a reused Montgomery context, and BN_FLG_CONSTTIME operands.
 */
static int test_mod_exp_rsaz_x1(int idx)
{
    BN_CTX *ctx = NULL;
    BN_MONT_CTX *mont = NULL;
    BIGNUM *a = NULL, *p = NULL, *m = NULL;
    int ret = 0;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_true(BN_rand(m, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD)))
        goto err;

    switch (idx) {
    case 0:
        /* Typical RSA public exponent (binary / SQM path). */
        if (!TEST_true(BN_set_word(p, 65537))
            || !TEST_true(BN_rand(a, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
            || !TEST_true(BN_mod(a, a, m, ctx)))
            goto err;
        break;
    case 1:
        /* SQM / window boundary: BN_num_bits(exp) == 80. */
        if (!TEST_true(BN_rand(p, 80, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
            || !TEST_true(BN_rand(a, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
            || !TEST_true(BN_mod(a, a, m, ctx)))
            goto err;
        break;
    case 2:
        /* First w=5 windowed path: BN_num_bits(exp) == 81. */
        if (!TEST_true(BN_rand(p, 81, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
            || !TEST_true(BN_rand(a, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
            || !TEST_true(BN_mod(a, a, m, ctx)))
            goto err;
        break;
    case 3:
        /* Full-width 2048-bit exponent. */
        if (!TEST_true(BN_rand(p, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
            || !TEST_true(BN_rand(a, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
            || !TEST_true(BN_mod(a, a, m, ctx)))
            goto err;
        break;
    case 4:
        /* Short base: BN_one() has top < 32; the mont hook pads and runs. */
        if (!TEST_true(BN_one(a)) || !TEST_true(BN_set_word(p, 65537)))
            goto err;
        break;
    case 5:
        /*
         * Zero base: BN_zero leaves top == 0 (d may still be NULL). The RSAZ
         * mont hook rejects that and falls back to generic BN_mod_exp_mont;
         * compare against BN_mod_exp_simple.
         */
        BN_zero(a);
        if (!TEST_true(BN_set_word(p, 65537)))
            goto err;
        break;
    case 6:
        /* Unreduced base (a > m) so BN_mod_exp_mont takes the nnmod path. */
        if (!TEST_true(BN_copy(a, m))
            || !TEST_true(BN_add_word(a, 3))
            || !TEST_true(BN_set_word(p, 65537)))
            goto err;
        break;
    case 7:
        /*
         * Reuse a Montgomery context: first a short base (pads RR), then a
         * reduced random base with the same mont.
         */
        if (!TEST_ptr(mont = BN_MONT_CTX_new())
            || !TEST_true(BN_MONT_CTX_set(mont, m, ctx))
            || !TEST_true(BN_one(a))
            || !TEST_true(BN_set_word(p, 65537))
            || !TEST_true(rsaz_x1_compare(a, p, m, ctx, mont))
            || !TEST_true(BN_rand(a, 64, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)))
            goto err;
        break;
    case 8:
        /*
         * CONSTTIME exponent: BN_mod_exp_mont must not use the variable-time
         * RSAZ x1 table lookup.
         */
        if (!TEST_true(BN_set_word(p, 65537))
            || !TEST_true(BN_rand(a, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
            || !TEST_true(BN_mod(a, a, m, ctx)))
            goto err;
        BN_set_flags(p, BN_FLG_CONSTTIME);
        break;
    case 9:
        /* CONSTTIME base: same diversion before the x1 hook. */
        if (!TEST_true(BN_set_word(p, 65537))
            || !TEST_true(BN_rand(a, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
            || !TEST_true(BN_mod(a, a, m, ctx)))
            goto err;
        BN_set_flags(a, BN_FLG_CONSTTIME);
        break;
    default:
        goto err;
    }

    if (!TEST_true(rsaz_x1_compare(a, p, m, ctx, mont)))
        goto err;

    ret = 1;
err:
    BN_MONT_CTX_free(mont);
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_CTX_free(ctx);
    return ret;
}

/*
 * Sizes the RSAZ x1 hook does not accept must still match BN_mod_exp_simple.
 */
static int test_mod_exp_mont_not_2048(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *a = NULL, *p = NULL, *m = NULL;
    int ret = 0;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_true(BN_rand(m, 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD))
        || !TEST_true(BN_set_word(p, 65537))
        || !TEST_true(BN_rand(a, 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
        || !TEST_true(BN_mod(a, a, m, ctx))
        || !TEST_true(rsaz_x1_compare(a, p, m, ctx, NULL)))
        goto err;

    ret = 1;
err:
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_CTX_free(ctx);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_mod_exp_zero);
    ADD_ALL_TESTS(test_mod_exp, 200);
    ADD_ALL_TESTS(test_mod_exp_x2,
        OSSL_NELEM(factor_sizes) * ROUNDS_PER_FACTOR_SIZE);
    ADD_ALL_TESTS(test_mod_exp_rsaz_x1, 10);
    ADD_TEST(test_mod_exp_mont_not_2048);
    return 1;
}
