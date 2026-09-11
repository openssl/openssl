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
#include "crypto/bn.h" /* For the BN counterpart being cross-checked */
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

/*
 * Cross-check of the OSSL_FN RSA FIPS 186-5 probable-prime peers against
 * their BN counterparts: with fixed Xp / Xp1 / Xp2 inputs the generation
 * is deterministic, so the two must return the same prime (and the same
 * random draw echo).  An invalid key size must fail on both sides.
 */
struct rsa_fips186_5_case_st {
    int nlen;
    uint32_t c;
    const char *xp;
    const char *xp1;
    const char *xp2;
    int expect_success;
};

/* A 1024-bit random draw image for Xin; a bit short of 2^1024. */
#define RSA_FIPS186_5_XP                                             \
    "B46CDD0E3E5B814F3A6C31BC7D2EAF252D13D4C6951C4C6E8B01E0A5B7B0C8" \
    "D6EE4F4675AF433A96DAF0C3B8F4070D0B7A24FEDCA1B95FB3C61A26FE96"   \
    "FCA5A60D1790A2B29B0CD2E6A59A3C9B8F63C3D21B7AD9F86C1B0F9E84"     \
    "A83D4C6920A2E05A9C2E3B6E00319A5D2E63E9F9B0C9CDF5D3AB741C"
/* Two 144-bit odd starting points for the auxiliary primes. */
#define RSA_FIPS186_5_XP1 "F18A3202B8FB0696C7D64A98AD3FC4B0D55D"
#define RSA_FIPS186_5_XP2 "DD79AC442F884A51D120A712B047B17DC553"

static const struct rsa_fips186_5_case_st rsa_fips186_5_cases[] = {
    { 2048, 0, RSA_FIPS186_5_XP, RSA_FIPS186_5_XP1, RSA_FIPS186_5_XP2, 1 },
    { 2048, 5, RSA_FIPS186_5_XP, RSA_FIPS186_5_XP1, RSA_FIPS186_5_XP2, 1 },
    { 1024, 0, RSA_FIPS186_5_XP, RSA_FIPS186_5_XP1, RSA_FIPS186_5_XP2, 0 },
};

static int test_rsa_fips186_5_gen_prob_primes_cross_bn(int idx)
{
    int ret = 0, bn_ok, fn_ok;
    const struct rsa_fips186_5_case_st *t = &rsa_fips186_5_cases[idx];
    int bits = t->nlen >> 1;
    size_t bits_limbs = (size_t)bits / (OSSL_FN_BYTES * 8)
        + ((size_t)bits % (OSSL_FN_BYTES * 8) != 0);
    BIGNUM *b_p = NULL, *b_x = NULL, *b_xp = NULL, *b_xp1 = NULL;
    BIGNUM *b_xp2 = NULL, *b_e = NULL;
    BN_CTX *bctx = NULL;
    OSSL_FN *f_p = NULL, *f_x = NULL;
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN *v_xp = NULL, *v_xp1 = NULL, *v_xp2 = NULL, *v_e = NULL;
    size_t fn_ctxsize;

    if (!TEST_ptr(bctx = BN_CTX_new())
        || !TEST_ptr(b_p = BN_new()) || !TEST_ptr(b_x = BN_new())
        || !TEST_ptr(b_e = BN_new())
        || !TEST_true(BN_hex2bn(&b_xp, t->xp) != 0)
        || !TEST_true(BN_hex2bn(&b_xp1, t->xp1) != 0)
        || !TEST_true(BN_hex2bn(&b_xp2, t->xp2) != 0)
        || !TEST_true(BN_set_word(b_e, 65537)))
        goto err;

    bn_ok = ossl_bn_rsa_fips186_5_gen_prob_primes(b_p, b_x, NULL, NULL,
        b_xp, b_xp1, b_xp2, t->nlen, b_e, bctx, NULL, t->c);
    if (!TEST_int_eq(bn_ok, t->expect_success))
        goto err;

    if (!TEST_ptr(f_p = OSSL_FN_new_limbs(bits_limbs + 1))
        || !TEST_ptr(f_x = OSSL_FN_new_limbs(bits_limbs + 1)))
        goto err;
    v_e = bn_get_ossl_fn(b_e);
    if (bn_ok) {
        v_xp = bn_get_ossl_fn(b_xp);
        v_xp1 = bn_get_ossl_fn(b_xp1);
        v_xp2 = bn_get_ossl_fn(b_xp2);
    }

    /*
     * Size the arena with the operation's sizing companion.  For the
     * invalid key size it returns 0; a minimal arena suffices then,
     * since the call fails before allocating more than its frame.
     */
    fn_ctxsize = ossl_fn_rsa_fips186_5_gen_prob_primes_ctx_size(f_p, f_x,
        NULL, NULL, v_xp1, v_xp2, t->nlen, v_e);
    if (fn_ctxsize == 0)
        fn_ctxsize = OSSL_FN_CTX_size(2, 1, 8);
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL, fn_ctxsize)))
        goto err;
    if (!bn_ok) {
        /* Invalid key size must fail on the FN side too. */
        fn_ok = ossl_fn_rsa_fips186_5_gen_prob_primes(f_p, f_x, NULL, NULL,
            NULL, NULL, NULL, t->nlen, v_e, ctx, NULL, t->c, NULL);
        if (!TEST_int_eq(fn_ok, t->expect_success))
            goto err;
    } else {
        fn_ok = ossl_fn_rsa_fips186_5_gen_prob_primes(f_p, f_x, NULL, NULL,
            v_xp, v_xp1, v_xp2, t->nlen, v_e, ctx, NULL, t->c, NULL);
        if (!TEST_int_eq(fn_ok, t->expect_success)
            || !TEST_int_eq(OSSL_FN_cmp(f_p, bn_get_ossl_fn(b_p)), 0)
            || !TEST_int_eq(OSSL_FN_cmp(f_x, bn_get_ossl_fn(b_x)), 0))
            goto err;
        /* The c mod 8 requirement must hold on the FN result. */
        if (t->c != 0
            && !TEST_ulong_eq(f_p->d[0] & 7, (OSSL_FN_ULONG)t->c))
            goto err;
    }

    ret = 1;
err:
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(f_p);
    OSSL_FN_free(f_x);
    BN_free(b_p);
    BN_free(b_x);
    BN_free(b_xp);
    BN_free(b_xp1);
    BN_free(b_xp2);
    BN_free(b_e);
    BN_CTX_free(bctx);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_check_prime_cross_bn);
#ifndef OPENSSL_NO_DEPRECATED_3_0
    ADD_TEST(test_x931_derive_prime_cross_bn);
#endif
    ADD_ALL_TESTS(test_rsa_fips186_5_gen_prob_primes_cross_bn, 3);
    return 1;
}
