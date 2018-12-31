/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "openssl/evp.h"
#include "openssl/rand.h"

#include "testutil.h"

static size_t randint(size_t limit)
{
    size_t u;

    assert(limit > 0);
    RAND_bytes((unsigned char *)&u, sizeof(u));
    /* this is biased, but we don't need unbiased output here. */
    return (size_t)(u % limit);
}

static size_t constint_value = 99999;

static size_t constint(size_t limit)
{
    if (constint_value >= limit)
        return limit - 1;
    return
        constint_value;
}

#define BUFLEN 2048

/* Test whether the squeeze function of xof is correctly implemented by making
 * sure that it gives the same result no matter what sequence of output
 * lengths it gets.
 *
 * This test doesn't test the _correctness_ of the output -- only its
 * consistency.  The correctness tests are done with evp_test.c
 */
static int xof_squeeze_test(const EVP_MD *xof,
                            size_t (*stridefn)(size_t),
                            size_t total_len)
{
    int result = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    unsigned char buf1[BUFLEN], buf2[BUFLEN];

    size_t j;

    /* Compute the XOF output in one shot. */
    if (!TEST_true(EVP_DigestInit(ctx, xof)))
        goto out;
    if (!TEST_true(EVP_DigestFinalXOF(ctx, buf1, total_len)))
        goto out;

    /* Now compute the XOF output piece by piece. */
    if (!TEST_true(EVP_DigestInit(ctx, xof)))
        goto out;
    for (j = 0; j < total_len; ) {
      size_t n = stridefn(total_len - j + 1);
        assert(n+j <= total_len);
        if (!TEST_true(EVP_DigestSqueezeXOF(ctx, buf2+j, n)))
            goto out;
        j += n;
    }

    if (! TEST_mem_eq(buf1, total_len, buf2, total_len)) {
        goto out;
    }

    result = 1;
 out:
    EVP_MD_CTX_free(ctx);
    return result;
}

static int xof_rand_test(const EVP_MD *xof)
{
    int i;
    const int iterations = 512;
    int result = 1;

    for (i = 0; i < iterations; ++i) {
        if (! xof_squeeze_test(xof, randint, randint(BUFLEN)))
            result = 0;
    }
    return result;
}

static int xof_stride_test(const EVP_MD *xof)
{
    int i;
    int result = 1;

    for (i = 1; i < 512; ++i) {
        constint_value = i;
        if (!xof_squeeze_test(xof, constint, BUFLEN))
            result = 0;
    }
    return result;
}

static int shake128_rand_test(void)
{
    return xof_rand_test(EVP_shake128());
}
static int shake128_stride_test(void)
{
    return xof_stride_test(EVP_shake128());
}
static int shake256_rand_test(void)
{
    return xof_rand_test(EVP_shake256());
}
static int shake256_stride_test(void)
{
    return xof_stride_test(EVP_shake256());
}

int setup_tests(void)
{
    ADD_TEST(shake128_rand_test);
    ADD_TEST(shake128_stride_test);
    ADD_TEST(shake256_rand_test);
    ADD_TEST(shake256_stride_test);
    return 1;
}
