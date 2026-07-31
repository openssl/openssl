/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file Cross-checks of OSSL_FN operations against their BN counterparts
 *
 * This tests that an OSSL_FN operation and its BN counterpart agree on the
 * verdict for the same number, for operations where an equivalent BN oracle
 * exists.  fn_api_test.c is kept purely OSSL_FN; anything that needs the
 * BIGNUM API for comparison lives here.
 */

#include <openssl/bn.h>
#include "crypto/fn.h"
#include "crypto/fn_intern.h"
#include "testutil.h"

/*-
 * Cross-check ossl_fn_check_prime() against BN_check_prime() on multi-limb
 * values: the two must agree on the verdict for the same number.
 */
static int test_check_prime_cross_bn(void)
{
    int ret = 0;
    OSSL_FN *w = NULL;
    OSSL_FN_CTX *ctx = NULL;
    BIGNUM *bw = NULL;
    BN_CTX *bctx = NULL;
    size_t i;
    /*
     * Multi-limb candidates: primes and composites wider than one limb,
     * spelled as 2^n - k so the same values are exercised on any limb
     * width.  All are odd, so every case reaches the primality machinery.
     */
    const struct {
        size_t n;
        OSSL_FN_ULONG k;
    } wide_cases[] = {
        { 127, 1 }, /* 2^127 - 1, a Mersenne prime */
        { 127, 3 }, /* 2^127 - 3, a wide odd composite */
        { 89, 1 }, /* 2^89 - 1, a Mersenne prime */
        { 101, 1 }, /* 2^101 - 1, a wide odd composite */
    };

    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 16, 32, 512))
        || !TEST_ptr(bctx = BN_CTX_new())
        || !TEST_ptr(bw = BN_new())
        || !TEST_ptr(w = OSSL_FN_new_limbs(4)))
        goto err;

    for (i = 0; i < OSSL_NELEM(wide_cases); i++) {
        int fn_verdict, bn_verdict;

        /* Build 2^n - k as an OSSL_FN and as a BIGNUM. */
        OSSL_FN_clear(w);
        if (!TEST_true(OSSL_FN_set_bit(w, wide_cases[i].n))
            || !TEST_true(OSSL_FN_sub_word(w, wide_cases[i].k)))
            goto err;
        if (!TEST_true(BN_set_word(bw, 0))
            || !TEST_true(BN_set_bit(bw, (int)wide_cases[i].n))
            || !TEST_true(BN_sub_word(bw, wide_cases[i].k)))
            goto err;

        fn_verdict = ossl_fn_check_prime(w, 0, ctx, 1, NULL, NULL);
        bn_verdict = BN_check_prime(bw, bctx, NULL);
        if (!TEST_int_eq(fn_verdict, bn_verdict))
            goto err;
    }

    ret = 1;
err:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(w);
    BN_free(bw);
    BN_CTX_free(bctx);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_check_prime_cross_bn);
    return 1;
}
