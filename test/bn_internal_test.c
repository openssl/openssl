/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#include "bn_local.h"

#if !defined(OPENSSL_NO_ASM)                     \
    && (defined(__x86_64) || defined(__x86_64__) \
        || defined(_M_AMD64) || defined(_M_X64))
#define TEST_RSAZ_X1
int ossl_rsaz_avx512ifma_eligible(void);
int ossl_rsaz_avxifma_eligible(void);
int ossl_rsaz_mod_exp_avx512_x1(BN_ULONG *res, const BN_ULONG *base,
    const BN_ULONG *exp, const BN_ULONG *m, const BN_ULONG *RR,
    BN_ULONG k0, int factor_size, int exp_bits);
#endif

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

#ifdef TEST_RSAZ_X1
static const int rsaz_x1_bad_sizes[] = { 0, 512, 1024, 1536, 3072, 4096 };

static int rsaz_ifma_available(void)
{
    return ossl_rsaz_avx512ifma_eligible() || ossl_rsaz_avxifma_eligible();
}

static int pad_bn_limbs(BIGNUM *bn, int limbs)
{
    if (bn_wexpand(bn, limbs) == NULL)
        return 0;
    if (bn->top < limbs)
        memset(bn->d + bn->top, 0, (size_t)(limbs - bn->top) * sizeof(BN_ULONG));
    return 1;
}

/*
 * Call ossl_rsaz_mod_exp_avx512_x1 directly so this fails (skip) on CPUs
 * without IFMA instead of silently using generic BN_mod_exp_mont.
 * Cases: RSA e, 80-bit SQM, 81-bit window, full-width exponent, and a short
 * base (top < 32; copy only live limbs into the 32-limb pad).
 */
static int test_rsaz_mod_exp_avx512_x1(int idx)
{
    BIGNUM *a = NULL, *p = NULL, *m = NULL, *r_ifma = NULL, *r_simple = NULL;
    BN_MONT_CTX *mont = NULL;
    BN_ULONG base_pad[32] = { 0 }, exp_pad[32] = { 0 };
    int ret = 0, exp_bits;

    if (!rsaz_ifma_available())
        return TEST_skip("RSAZ AVX512_IFMA / AVX_IFMA not available");

    if (!TEST_ptr(a = BN_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(r_ifma = BN_new())
        || !TEST_ptr(r_simple = BN_new())
        || !TEST_ptr(mont = BN_MONT_CTX_new())
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
        /* Short base: BN_one() has top < 32. */
        if (!TEST_true(BN_one(a)) || !TEST_true(BN_set_word(p, 65537)))
            goto err;
        break;
    default:
        goto err;
    }

    if (!TEST_true(BN_MONT_CTX_set(mont, m, ctx))
        || !TEST_true(pad_bn_limbs(m, 32))
        || !TEST_true(pad_bn_limbs(&mont->RR, 32))
        || !TEST_true(bn_wexpand(r_ifma, 32)))
        goto err;

    if (a->top > 0)
        memcpy(base_pad, a->d, (size_t)a->top * sizeof(BN_ULONG));
    if (p->top > 0)
        memcpy(exp_pad, p->d, (size_t)p->top * sizeof(BN_ULONG));

    exp_bits = BN_num_bits(p);
    if (!TEST_true(ossl_rsaz_mod_exp_avx512_x1(r_ifma->d, base_pad, exp_pad,
            m->d, mont->RR.d, mont->n0[0], 2048, exp_bits)))
        goto err;

    r_ifma->top = 32;
    r_ifma->neg = 0;
    bn_correct_top(r_ifma);

    if (!TEST_true(BN_mod_exp_simple(r_simple, a, p, m, ctx))
        || !TEST_BN_eq(r_simple, r_ifma))
        goto err;

    ret = 1;
err:
    BN_MONT_CTX_free(mont);
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_free(r_ifma);
    BN_free(r_simple);
    return ret;
}

static int test_rsaz_mod_exp_avx512_x1_bad_size(int idx)
{
    BN_ULONG buf[32] = { 1, 0 };

    if (!rsaz_ifma_available())
        return TEST_skip("RSAZ AVX512_IFMA / AVX_IFMA not available");

    if (!TEST_int_lt(idx, (int)OSSL_NELEM(rsaz_x1_bad_sizes)))
        return 0;

    return TEST_false(ossl_rsaz_mod_exp_avx512_x1(buf, buf, buf, buf, buf,
        (BN_ULONG)1, rsaz_x1_bad_sizes[idx], 17));
}
#endif

int setup_tests(void)
{
    if (!TEST_ptr(ctx = BN_CTX_new()))
        return 0;

    ADD_TEST(test_is_prime_enhanced);
    ADD_ALL_TESTS(test_is_composite_enhanced, (int)OSSL_NELEM(composites));
    ADD_TEST(test_bn_small_factors);
#ifdef TEST_RSAZ_X1
    ADD_ALL_TESTS(test_rsaz_mod_exp_avx512_x1, 5);
    ADD_ALL_TESTS(test_rsaz_mod_exp_avx512_x1_bad_size,
        (int)OSSL_NELEM(rsaz_x1_bad_sizes));
#endif

    return 1;
}

void cleanup_tests(void)
{
    BN_CTX_free(ctx);
}
