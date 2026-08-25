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

/*
 * The BN side of the X9.31 cross-check calls the deprecated
 * BN_X931_derive_prime_ex(), same as its remaining in-tree consumer
 * crypto/rsa/rsa_x931g.c.
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/bn.h>
#include "crypto/bn.h"
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

    if (!TEST_ptr(w = OSSL_FN_new_limbs(4))
        || !TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL,
                         ossl_fn_check_prime_ctx_size(w)))
        || !TEST_ptr(bctx = BN_CTX_new())
        || !TEST_ptr(bw = BN_new()))
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

#ifndef OPENSSL_NO_DEPRECATED_3_0
/*
 * Return the limb count needed to hold a BIGNUM, matching the sizing that
 * bn_acquire_ossl_fn() is asked for.
 */
static int bn_nlimbs(const BIGNUM *bn)
{
    int ret = (BN_num_bits(bn) + BN_BITS2 - 1) / BN_BITS2;

    return ret > 0 ? ret : 1;
}

/*
 * Cross-check OSSL_FN_X931_derive_prime() against its BN counterpart
 * BN_X931_derive_prime_ex(): given identical odd Xp1 / Xp2, an Xp and an
 * odd exponent e, the two must derive the same prime p and the same
 * intermediate primes p1 / p2.
 */
static int test_x931_derive_prime_cross_bn(void)
{
    int ret = 0, nlimbs = 0, p_acq = 0, p1_acq = 0, p2_acq = 0;
    OSSL_FN *fp = NULL, *fp1 = NULL, *fp2 = NULL;
    OSSL_FN_CTX *fctx = NULL;
    BN_CTX *bctx = NULL;
    BIGNUM *bXp = NULL, *bXp1 = NULL, *bXp2 = NULL, *be = NULL;
    BIGNUM *bp = NULL, *bp1 = NULL, *bp2 = NULL;
    BIGNUM *fn_p = NULL, *fn_p1 = NULL, *fn_p2 = NULL;
    size_t size;

    if (!TEST_ptr(bctx = BN_CTX_new())
        || !TEST_ptr(bXp = BN_new())
        || !TEST_ptr(bXp1 = BN_new())
        || !TEST_ptr(bXp2 = BN_new())
        || !TEST_ptr(be = BN_new())
        || !TEST_ptr(bp = BN_new())
        || !TEST_ptr(bp1 = BN_new())
        || !TEST_ptr(bp2 = BN_new())
        || !TEST_ptr(fn_p = BN_new())
        || !TEST_ptr(fn_p1 = BN_new())
        || !TEST_ptr(fn_p2 = BN_new()))
        goto err;

    /*
     * Small auxiliary parameters keep the derived prime comfortably
     * inside one limb even on 32-bit builds, same as the corresponding
     * fn_api_test coverage.
     */
    if (!TEST_true(BN_set_word(bXp, 0xBEEF))
        || !TEST_true(BN_set_word(bXp1, 1021))
        || !TEST_true(BN_set_word(bXp2, 1031))
        || !TEST_true(BN_set_word(be, 65537)))
        goto err;

    /* The BN side derives p, p1 and p2 first, as the oracle. */
    if (!TEST_true(BN_X931_derive_prime_ex(bp, bp1, bp2, bXp, bXp1, bXp2,
            be, bctx, NULL)))
        goto err;

    /*
     * The OSSL_FN side works on bn_get_ossl_fn() views of the same inputs
     * and writes into acquired BIGNUMs sized to hold the oracle's results.
     */
    nlimbs = bn_nlimbs(bp);
    if (!TEST_ptr(fp = bn_acquire_ossl_fn(fn_p, nlimbs)))
        goto err;
    p_acq = 1;
    if (!TEST_ptr(fp1 = bn_acquire_ossl_fn(fn_p1, nlimbs)))
        goto err;
    p1_acq = 1;
    if (!TEST_ptr(fp2 = bn_acquire_ossl_fn(fn_p2, nlimbs)))
        goto err;
    p2_acq = 1;

    size = OSSL_FN_X931_derive_prime_ctx_size(fp, fp1, fp2,
        bn_get_ossl_fn(bXp), bn_get_ossl_fn(bXp1),
        bn_get_ossl_fn(bXp2), bn_get_ossl_fn(be));
    if (!TEST_size_t_ne(size, 0)
        || !TEST_ptr(fctx = OSSL_FN_CTX_new_size(NULL, size)))
        goto err;

    if (!TEST_true(OSSL_FN_X931_derive_prime(fp, fp1, fp2,
            bn_get_ossl_fn(bXp), bn_get_ossl_fn(bXp1),
            bn_get_ossl_fn(bXp2), bn_get_ossl_fn(be),
            fctx, NULL, NULL)))
        goto err;

    bn_release(fn_p, nlimbs);
    p_acq = 0;
    bn_release(fn_p1, nlimbs);
    p1_acq = 0;
    bn_release(fn_p2, nlimbs);
    p2_acq = 0;

    if (!TEST_BN_eq(fn_p, bp)
        || !TEST_BN_eq(fn_p1, bp1)
        || !TEST_BN_eq(fn_p2, bp2))
        goto err;

    ret = 1;
err:
    if (p_acq)
        bn_release(fn_p, nlimbs);
    if (p1_acq)
        bn_release(fn_p1, nlimbs);
    if (p2_acq)
        bn_release(fn_p2, nlimbs);
    OSSL_FN_CTX_free(fctx);
    BN_free(bXp);
    BN_free(bXp1);
    BN_free(bXp2);
    BN_free(be);
    BN_free(bp);
    BN_free(bp1);
    BN_free(bp2);
    BN_free(fn_p);
    BN_free(fn_p1);
    BN_free(fn_p2);
    BN_CTX_free(bctx);
    return ret;
}
#endif

int setup_tests(void)
{
    ADD_TEST(test_check_prime_cross_bn);
#ifndef OPENSSL_NO_DEPRECATED_3_0
    ADD_TEST(test_x931_derive_prime_cross_bn);
#endif
    return 1;
}
