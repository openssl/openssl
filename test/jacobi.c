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

static int test_jacobi(unsigned int a, unsigned int b, int result)
{
    BIGNUM *A, *B;
    int j;
    int ret = 0;

    A = BN_new();
    B = BN_new();
    if (A == NULL || B == NULL)
        return 0;

    if (!BN_set_word(A, a) || !BN_set_word(B, b)) {
        goto err;
    }

    j = BN_jacobi_symbol(A, B, NULL);
    if (j != result)
        TEST_info("Jacobi test failed: (%d/%d) = %d, expected %d\n",
                  a, b, j, result);
    else
        ret = 1;

err:
    BN_free(A);
    BN_free(B);
    return ret;
}

static int test_jacobi_symbol(void)
{
    int ret = 1;

    ret &= test_jacobi(1, 2, -2);
    ret &= test_jacobi(1, 0, -2);

    ret &= test_jacobi(0, 1, 1);
    ret &= test_jacobi(0, 3, 0);
    ret &= test_jacobi(1, 1, 1);
    ret &= test_jacobi(2, 1, 1);
    ret &= test_jacobi(0, 3, 0);
    ret &= test_jacobi(1, 3, 1);
    ret &= test_jacobi(2, 3, -1);
    ret &= test_jacobi(1, 5, 1);
    ret &= test_jacobi(2, 5, -1);
    ret &= test_jacobi(3, 5, -1);
    ret &= test_jacobi(4, 5, 1);
    ret &= test_jacobi(7, 5, -1);
    ret &= test_jacobi(16, 35, 1);
    ret &= test_jacobi(18, 39, 0);
    ret &= test_jacobi(6, 49, 1);
    ret &= test_jacobi(27, 17, -1);
    ret &= test_jacobi(1001, 9907, -1);

    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_jacobi_symbol);
    return 1;
}
