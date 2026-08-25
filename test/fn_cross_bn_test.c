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
    /* Multi-limb candidates: primes and composites wider than one limb. */
    const OSSL_FN_ULONG mask = (OSSL_FN_ULONG)-1;
    const struct {
        OSSL_FN_ULONG words[4];
        size_t limbs;
    } wide_cases[] = {
        /* 2^127 - 1, a Mersenne prime */
        { { mask, mask, mask, mask >> 1 }, 4 },
        /* 2^127 - 3, a wide odd composite */
        { { mask - 2, mask, mask, mask >> 1 }, 4 },
        /* 2^89 - 1, a Mersenne prime, in 2 limbs on 64-bit, 3 on 32-bit */
        { { mask, mask >> ((OSSL_FN_BYTES * 8) - 25), 0, 0 }, 2 },
        /* A wide odd composite */
        { { mask - 57, mask, 0, 0 }, 2 },
    };

    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 16, 32, 512))
        || !TEST_ptr(bctx = BN_CTX_new())
        || !TEST_ptr(bw = BN_new())
        || !TEST_ptr(w = OSSL_FN_new_limbs(4)))
        goto err;

    for (i = 0; i < OSSL_NELEM(wide_cases); i++) {
        int fn_verdict, bn_verdict;

        if (!TEST_true(ossl_fn_set_words(w, wide_cases[i].words,
                wide_cases[i].limbs)))
            goto err;
        /* Build the same value as a BIGNUM, little-endian limbs. */
        if (!TEST_true(BN_set_word(bw, 0)))
            goto err;
        {
            size_t l;

            for (l = wide_cases[i].limbs; l-- > 0;) {
                if (!TEST_true(BN_lshift(bw, bw, OSSL_FN_BYTES * 8))
                    || !TEST_true(BN_add_word(bw, wide_cases[i].words[l])))
                    goto err;
            }
        }

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
