/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "internal/nelem.h"
#include "internal/numbers.h"
#include "testutil.h"
#include "bn_prime.h"
#include "crypto/bn.h"
#include "crypto/fn.h"
#include "crypto/fn_intern.h"

static BN_CTX *ctx;

static int test_is_prime_enhanced(void)
{
    int ret;
    int status = 0;
    BIGNUM *bn = NULL;

    ret = TEST_ptr(bn = BN_new())
        /* test passing a prime returns the correct status */
        && TEST_true(BN_set_word(bn, 11))
        /* return extra parameters related to composite */
        && TEST_true(ossl_bn_miller_rabin_is_prime(bn, 10, ctx, NULL, 1,
            &status))
        && TEST_int_eq(status, BN_PRIMETEST_PROBABLY_PRIME);
    BN_free(bn);
    return ret;
}

static int composites[] = {
    9, 21, 77, 81, 265
};

static int test_is_composite_enhanced(int id)
{
    int ret;
    int status = 0;
    BIGNUM *bn = NULL;

    ret = TEST_ptr(bn = BN_new())
        /* negative tests for different composite numbers */
        && TEST_true(BN_set_word(bn, composites[id]))
        && TEST_true(ossl_bn_miller_rabin_is_prime(bn, 10, ctx, NULL, 1,
            &status))
        && TEST_int_ne(status, BN_PRIMETEST_PROBABLY_PRIME);

    BN_free(bn);
    return ret;
}

/* Test that multiplying all the small primes from 3 to 751 equals a constant.
 * This test is mainly used to test that both 32 and 64 bit are correct.
 */
static int test_bn_small_factors(void)
{
    int ret = 0, i;
    BIGNUM *b = NULL;

    if (!(TEST_ptr(b = BN_new()) && TEST_true(BN_set_word(b, 3))))
        goto err;

    for (i = 1; i < NUMPRIMES; i++) {
        prime_t p = primes[i];
        if (p > 3 && p <= 751 && !BN_mul_word(b, p))
            goto err;
        if (p > 751)
            break;
    }
    ret = TEST_BN_eq(ossl_bn_get0_small_factors(), b);
err:
    BN_free(b);
    return ret;
}

static int test_bn_ctx_fn_ctx(void)
{
    int ret = 1;
    BN_CTX *bnctx = NULL;
    OSSL_FN_CTX *fnctx = NULL;
    OSSL_FN *fn = NULL;
    const void *token = NULL;

    /* Test non-secure BN_CTX */
    if (!TEST_ptr(bnctx = BN_CTX_new()))
        return 0;

    /* Acquire should create a new OSSL_FN_CTX */
    if (!TEST_ptr(fnctx = bn_ctx_acquire_ossl_fn_ctx(bnctx, 1, 1, 32)))
        ret = 0;

    /* The returned pointer should be cached inside BN_CTX */
    if (ret && !TEST_ptr_eq(fnctx, bn_ctx_acquire_ossl_fn_ctx(bnctx, 1, 1, 32)))
        ret = 0;

    /* Re-acquire with same size should return the same cached context */
    if (ret && !TEST_ptr_eq(fnctx, bn_ctx_acquire_ossl_fn_ctx(bnctx, 1, 1, 32)))
        ret = 0;

    /* Use the OSSL_FN_CTX */
    if (ret) {
        if (!TEST_ptr(token = OSSL_FN_CTX_start(fnctx))
            || !TEST_ptr(fn = OSSL_FN_CTX_get_limbs(fnctx, 4))
            || !TEST_true(OSSL_FN_CTX_end(fnctx, token)))
            ret = 0;
    }

    /*
     * Release does NOT free the cached OSSL_FN_CTX; it just asserts
     * no frames are outstanding.  Re-acquire should return the same
     * cached pointer.
     */
    bn_ctx_release_ossl_fn_ctx(bnctx);
    if (ret && !TEST_ptr_eq(fnctx, bn_ctx_acquire_ossl_fn_ctx(bnctx, 1, 1, 32)))
        ret = 0;

    /*
     * Re-acquire with a larger size should replace the cached context
     * because the old one is too small.  (Free + alloc may reuse the
     * same address, so only verify the new context satisfies the larger
     * request.)
     */
    if (ret) {
        OSSL_FN_CTX *small = bn_ctx_acquire_ossl_fn_ctx(bnctx, 1, 1, 8);
        if (!TEST_ptr(small))
            ret = 0;
        else {
            OSSL_FN_CTX *large = bn_ctx_acquire_ossl_fn_ctx(bnctx, 1, 1, 64);

            if (!TEST_ptr(large)
                || !TEST_ptr(token = OSSL_FN_CTX_start(large))
                || !TEST_ptr(fn = OSSL_FN_CTX_get_limbs(large, 64))
                || !TEST_true(OSSL_FN_CTX_end(large, token)))
                ret = 0;
        }
    }

    BN_CTX_free(bnctx);

    /* Test secure BN_CTX */
    if (ret) {
        if (!TEST_ptr(bnctx = BN_CTX_secure_new()))
            ret = 0;
        else {
            fn = NULL;
            token = NULL;
            fnctx = bn_ctx_acquire_ossl_fn_ctx(bnctx, 1, 1, 8);
            if (!TEST_ptr(fnctx)
                || !TEST_ptr(token = OSSL_FN_CTX_start(fnctx))
                || !TEST_ptr(fn = OSSL_FN_CTX_get_limbs(fnctx, 1))
                || !TEST_true(ossl_fn_is_securely_allocated(fn))
                || !TEST_true(OSSL_FN_CTX_end(fnctx, token)))
                ret = 0;
            BN_CTX_free(bnctx);
        }
    }

    return ret;
}

int setup_tests(void)
{
    if (!TEST_ptr(ctx = BN_CTX_new()))
        return 0;

    ADD_TEST(test_is_prime_enhanced);
    ADD_ALL_TESTS(test_is_composite_enhanced, (int)OSSL_NELEM(composites));
    ADD_TEST(test_bn_small_factors);
    ADD_TEST(test_bn_ctx_fn_ctx);

    return 1;
}

void cleanup_tests(void)
{
    BN_CTX_free(ctx);
}
