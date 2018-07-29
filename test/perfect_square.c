/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/bn.h>
#include "testutil.h"
#include "internal/nelem.h"

static const int squares [] = { 1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144 };

/* Check that we generate the list of Lucas strong pseudoprimes */
static int test_squares(void)
{
    int i, square = 0;
    int ret = 1;
    BIGNUM *n = BN_new();

    if (n == NULL) {
        ret = 0;
        goto err;
    }

    for (i = 1; i < squares[OSSL_NELEM(squares)-1]; i++) {
        if (!BN_set_word(n, i)) {
            ret = 0;
            goto err;
        }
        if (squares[square] == i) {
            ret &= TEST_int_eq(BN_is_perfect_square(n, NULL), 1);
            square++;
        } else {
            ret &= TEST_int_eq(BN_is_perfect_square(n, NULL), 0);
        }
    }

err:
    BN_free(n);
    return ret;
}

/* Test n*n, n*n-1 and n*n+1 for being perfect squares. */
static int test_rand_squares(void)
{
    BIGNUM *n = BN_new();
    BIGNUM *n1 = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    int ret = 1;
    int i;

    if (ctx == NULL || n == NULL || n1 == NULL) {
        ret = 0;
        goto err;
    }

    if (!BN_one(n1)) {
        ret = 0;
        goto err;
    }

    for (i = 0; i < 10000; i++) {
        int r;

        if (!BN_rand(n, 256, 0, 0) ||
            !BN_sqr(n, n, ctx)) {
            ret = 0;
            goto err;
        }
        r = TEST_int_eq(BN_is_perfect_square(n, ctx), 1);
        if (r == 0)
            test_output_bignum("n", n);
        ret &= r;
        if (!BN_sub(n, n, n1)) {
            ret = 0;
            goto err;
        }
        r = TEST_int_eq(BN_is_perfect_square(n, ctx), 0);
        if (r == 0)
            test_output_bignum("n", n);
        ret &= r;
        if (!BN_add(n, n, n1) || !BN_add(n, n, n1)) {
            ret = 0;
            goto err;
        }
        r = TEST_int_eq(BN_is_perfect_square(n, ctx), 0);
        if (r == 0)
            test_output_bignum("n", n);
        ret &= r;
    }

err:
    BN_free(n);
    BN_free(n1);
    BN_CTX_free(ctx);

    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_squares);
    ADD_TEST(test_rand_squares);
    return 1;
}

