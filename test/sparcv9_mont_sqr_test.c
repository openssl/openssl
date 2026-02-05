/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 *
 * Regression test for SPARCv9 asm bn_sqr_mont bug (sparcv9-mont.pl)
 *
 * The test:
 *  - Forces OPENSSL_sparcv9cap to "0:0" (done by recipe) to disable T4/etc.
 *  - Parses OPENSSL_sparcv9cap and requires it to be zero mask.
 *  - For known "problematic" a computes r = (a*a) mod p with
 *    BN_mod_mul_montgomery().
 *  - Compares the result with known correct (a*a) mod p.
 */

#include "testutil.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>

static int parse_u64_auto(const char *s, unsigned long long *out)
{
    char *end = NULL;
    unsigned long long v;

    if (s == NULL || *s == '\0')
        return 0;

    errno = 0;
    v = strtoull(s, &end, 0); /* base 0: accepts 0, 0x..., decimal */
    if (errno != 0 || end == s || *end != '\0')
        return 0;

    *out = v;
    return 1;
}

static int cap_is_zero_mask(void)
{
    const char *cap = getenv("OPENSSL_sparcv9cap");
    char *tmp = NULL, *colon = NULL;
    unsigned long long lo = 0, hi = 0;

    /* We require the recipe to set it; if not set, we treat as "fail" */
    if (cap == NULL)
        return 0;

    tmp = OPENSSL_strdup(cap);
    if (tmp == NULL)
        return 0;

    colon = strchr(tmp, ':');
    if (colon != NULL) {
        *colon++ = '\0';
        if (*colon == '\0') {
            OPENSSL_free(tmp);
            return 0;
        }
        if (!parse_u64_auto(colon, &hi)) {
            OPENSSL_free(tmp);
            return 0;
        }
    } else {
        hi = 0;
    }

    if (!parse_u64_auto(tmp, &lo)) {
        OPENSSL_free(tmp);
        return 0;
    }

    OPENSSL_free(tmp);
    return (lo == 0 && hi == 0);
}

static int test_sparcv9_mont_sqr_regression(void)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    BN_MONT_CTX *mont = NULL;
    BIGNUM *p = NULL, *a = NULL;
    BIGNUM *r_expected = NULL, *r_real = NULL;
    /* p = secp521r1 prime field from issue (same bytes) */
    static const unsigned char P_BIN[] = {
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
    /* Known-bad input from issue #15587 */
    const char *A_BAD = "1DEA64498CAE6197AB5283F8A8A05F343D0CCA7F5F05EDF3C989"
                        "2F80851E0E40A39BD8855B4824C5BCC86727312D6979965FA131"
                        "365CB24ED1C52E4E3B54CD01E0C";
    /* Expected correct result */
    const char *R_EXPECTED = "016A86598DB73518CFBA3A20B61336AE1F988AF5153F6CB"
                             "1C1B3E8FCAAFB3538BCF71E72F72F02731E233C0F88C95F"
                             "561D5D937F91C7AF697AA82D703001FFD99E53";

    if (!TEST_true(cap_is_zero_mask()))
        return 0;

    ctx = BN_CTX_new();
    mont = BN_MONT_CTX_new();
    p = BN_new();
    r_real = BN_new();

    if (!TEST_ptr(ctx) || !TEST_ptr(mont) || !TEST_ptr(p) || !TEST_ptr(r_real))
        goto end;

    if (!TEST_ptr(BN_bin2bn(P_BIN, (int)sizeof(P_BIN), p)))
        goto end;

    if (!TEST_int_gt(BN_hex2bn(&a, A_BAD), 0))
        goto end;

    if (!TEST_int_gt(BN_hex2bn(&r_expected, R_EXPECTED), 0))
        goto end;

    if (!TEST_true(BN_MONT_CTX_set(mont, p, ctx)))
        goto end;

    if (!TEST_true(BN_mod_mul_montgomery(r_real, a, a, mont, ctx)))
        goto end;

    if (!TEST_int_eq(BN_cmp(r_real, r_expected), 0))
        goto end;

    ok = 1;

end:
    BN_free(r_expected);
    BN_free(r_real);
    BN_free(a);
    BN_free(p);
    BN_MONT_CTX_free(mont);
    BN_CTX_free(ctx);
    return ok;
}

int setup_tests(void)
{
    ADD_TEST(test_sparcv9_mont_sqr_regression);
    return 1;
}
