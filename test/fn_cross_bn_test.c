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

    /* Generous arena; generation draws down a nested stack of frames. */
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new(NULL, 16, 48, 2048))
        || !TEST_ptr(f_p = OSSL_FN_new_limbs(bits_limbs + 1))
        || !TEST_ptr(f_x = OSSL_FN_new_limbs(bits_limbs + 1)))
        goto err;
    if (!bn_ok) {
        /* Invalid key size must fail on the FN side too. */
        v_e = bn_get_ossl_fn(b_e);
        fn_ok = ossl_fn_rsa_fips186_5_gen_prob_primes(f_p, f_x, NULL, NULL,
            NULL, NULL, NULL, t->nlen, v_e, ctx, NULL, t->c, NULL);
        if (!TEST_int_eq(fn_ok, t->expect_success))
            goto err;
    } else {
        v_xp = bn_get_ossl_fn(b_xp);
        v_xp1 = bn_get_ossl_fn(b_xp1);
        v_xp2 = bn_get_ossl_fn(b_xp2);
        v_e = bn_get_ossl_fn(b_e);
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
    ADD_ALL_TESTS(test_rsa_fips186_5_gen_prob_primes_cross_bn, 3);
    return 1;
}
