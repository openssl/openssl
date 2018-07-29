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


/*
 * List of strong Lucas-Selfridge pseudoprimes lower then 1000000
 * This is sequence https://oeis.org/A217255
 */
static int slpsp[] =
    { 5459, 5777, 10877, 16109, 18971, 22499, 24569, 25199, 40309, 58519, 75077,
      97439, 100127, 113573, 115639, 130139, 155819, 158399, 161027, 162133,
      176399, 176471, 189419, 192509, 197801, 224369, 230691, 231703, 243629,
      253259, 268349, 288919, 313499, 324899, 353219, 366799, 391169, 430127,
      436409, 455519, 487199, 510479, 572669, 611399, 622169, 635627, 636199,
      701999, 794611, 835999, 839159, 851927, 871859, 875879, 887879, 895439,
      950821, 960859 };

#define N 10000
#if N == 1000000
#define SLPSP_COUNT 58
#elif N == 100000
#define SLPSP_COUNT 12
#elif N == 10000
#define SLPSP_COUNT 2
#endif

/* Check that we generate the list of Lucas strong pseudoprimes */
static int test_lucas_pseudoprimes(void)
{
    int i;
    BIGNUM *p;
    int ret = 0;
    size_t idx = 0;

    p = BN_new();
    if (p == NULL)
        goto err;

    for (i = 3; i <= N; i+=2)
    {
        int lucas, prime;

        if (!BN_set_word(p, i))
            goto err;
        lucas = BN_strong_lucas_prime(p, NULL);
        if (lucas == -1) {
            TEST_info("Lucas test returned error: %d", i);
            goto err;
        }
        prime = BN_is_prime_fasttest_ex(p, BN_prime_checks, NULL, 1, NULL);
        if (prime == -1) {
            TEST_info("Prime test failed");
            goto err;
        }
        if (!lucas && prime) {
            TEST_info("Lucas returned composite and prime test returned prime: %d", i);
            goto err;
        }
        if (lucas && !prime) {
            if (idx >= SLPSP_COUNT) {
                TEST_info("Too many strong Lucas pseudoprimes found");
                goto err;
            }
            if (slpsp[idx] != i) {
                TEST_info("Unexpected strong Lucas pseudoprimes found. Found: %d, Expected: %d", i, slpsp[idx]);
                goto err;
            }
            idx++;
        }
    }
    if (idx != SLPSP_COUNT) {
        TEST_info("Not all pseudo primes founds");
        goto err;
    }
    ret = 1;

err:
    BN_free(p);
    return ret;
}

/* Check random numbers to see if it doesn't hang or take a very long time. */
static int test_rand(void)
{
    BIGNUM *p = BN_new();
    int ret = 0;
    int i;

    if (p == NULL)
        return 0;

    for (i = 0; i < 1000; i++) {
        if (!BN_rand(p, 256, 0, 1))
            goto err;
        if (BN_strong_lucas_prime(p, NULL) < 0)
            goto err;
    }
    ret = 1;

err:
    BN_free(p);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_lucas_pseudoprimes);
    ADD_TEST(test_rand);
    return 1;
}
