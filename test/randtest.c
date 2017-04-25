/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/rand.h>
#include "testutil.h"

/* some FIPS 140-1 random number test */
/* some simple tests */

static int fips_random_tests(void)
{
    unsigned char buf[2500];
    int i, j, k, s, sign, nsign, ret = 1;
    unsigned long n1;
    unsigned long n2[16];
    unsigned long runs[2][34];
    long d;

    if (!TEST_int_ge(RAND_bytes(buf, sizeof(buf)), 0))
        return 0;

    n1 = 0;
    for (i = 0; i < 16; i++)
        n2[i] = 0;
    for (i = 0; i < 34; i++)
        runs[0][i] = runs[1][i] = 0;

    /* test 1 and 2 */
    sign = 0;
    nsign = 0;
    for (i = 0; i < 2500; i++) {
        j = buf[i];

        n2[j & 0x0f]++;
        n2[(j >> 4) & 0x0f]++;

        for (k = 0; k < 8; k++) {
            s = (j & 0x01);
            if (s == sign)
                nsign++;
            else {
                if (nsign > 34)
                    nsign = 34;
                if (nsign != 0) {
                    runs[sign][nsign - 1]++;
                    if (nsign > 6)
                        runs[sign][5]++;
                }
                sign = s;
                nsign = 1;
            }

            if (s)
                n1++;
            j >>= 1;
        }
    }
    if (nsign > 34)
        nsign = 34;
    if (nsign != 0)
        runs[sign][nsign - 1]++;

    /* test 1 */
    if (!TEST_true(9654 < n1 && n1 < 10346)) {
        TEST_info("test 1 failed, X=%lu", n1);
        ret = 0;
    }

    /* test 2 */
    d = 0;
    for (i = 0; i < 16; i++)
        d += n2[i] * n2[i];
    d = (d * 8) / 25 - 500000;
    if (!TEST_true(103 < d && d < 5740)) {
        TEST_info("test 2 failed, X=%ld.%02ld", d / 100L, d % 100L);
        ret = 0;
    }

    /* test 3 */
    for (i = 0; i < 2; i++) {
        if (!TEST_true(2267 < runs[i][0] && runs[i][0] < 2733)
                || !TEST_true(1079 < runs[i][1] && runs[i][1] < 1421)
                || !TEST_true(502 < runs[i][2] && runs[i][2] < 748)
                || !TEST_true(223 < runs[i][3] && runs[i][3] < 402)
                || !TEST_true(90 < runs[i][4] && runs[i][4] < 223)
                || !TEST_true(90 < runs[i][5] && runs[i][5] < 223)) {
            TEST_info("During run %d", i);
            ret = 0;
        }
    }

    /* test 4 */
    if (!TEST_int_eq(runs[0][33], 0)
            || !TEST_int_eq(runs[1][33], 0))
        ret = 0;

    return ret;
}

void register_tests(void)
{
    ADD_TEST(fips_random_tests);
}
