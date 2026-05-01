/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include "crypto/fn.h"
#include "testutil.h"

OPT_TEST_DECLARE_USAGE("bnmod.txt\n")

static const char *testfile = NULL;

static const char *findattr(STANZA *s, const char *key)
{
    int i = s->numpairs;
    PAIR *pp = s->pairs;

    for (; --i >= 0; pp++)
        if (OPENSSL_strcasecmp(pp->key, key) == 0)
            return pp->value;
    return NULL;
}

static size_t hex_len_in_limbs(const char *hex)
{
    if (hex == NULL)
        return 0;

    if (hex[0] == '-')
        hex++;

    size_t n = strlen(hex);

    if (n == 0)
        return 1;

    return (n + OSSL_FN_BYTES * 2 - 1) / (OSSL_FN_BYTES * 2);
}

static int hex_is_odd(const char *hex)
{
    if (hex == NULL)
        return 0;

    size_t n = strlen(hex);

    if (n == 0)
        return 0;

    return hex[n - 1] & 1;
}

static int test_one_modmul(STANZA *s)
{
    const char *A_hex = findattr(s, "A");
    const char *B_hex = findattr(s, "B");
    const char *M_hex = findattr(s, "M");
    const char *ModMul_hex = findattr(s, "ModMul");
    OSSL_FN_CTX *ctx = NULL;
    OSSL_FN_MONT_CTX *mont = NULL;
    const void *token = NULL;
    OSSL_FN *A = NULL, *B = NULL, *M = NULL, *ModMul = NULL;
    OSSL_FN *Am = NULL, *Bm = NULL, *Rm = NULL, *R = NULL;
    size_t limbs;
    int ret = 0;

    if (!TEST_ptr(A_hex) || !TEST_ptr(B_hex)
        || !TEST_ptr(M_hex) || !TEST_ptr(ModMul_hex))
        return 0;

    limbs = hex_len_in_limbs(M_hex);
    if (!TEST_size_t_gt(limbs, 0))
        return 0;

    if (A_hex[0] == '-' || B_hex[0] == '-' || ModMul_hex[0] == '-'
        || !hex_is_odd(M_hex)
        || hex_len_in_limbs(A_hex) > limbs
        || hex_len_in_limbs(B_hex) > limbs
        || hex_len_in_limbs(ModMul_hex) > limbs) {
        /* TEST_info("Skipping %s:%d: unsuitable input for FN Montgomery",
                  s->test_file, s->start); */
        s->numskip++;
        return 1;
    }

    ctx = OSSL_FN_CTX_new(NULL, 2, 9, 9 * limbs + 2);
    if (!TEST_ptr(ctx))
        return 0;

    if (!TEST_ptr(token = OSSL_FN_CTX_start(ctx)))
        goto err;

    if (!TEST_ptr(ModMul = OSSL_FN_CTX_get_limbs(ctx, limbs))
        || !TEST_ptr(A = OSSL_FN_CTX_get_limbs(ctx, limbs))
        || !TEST_ptr(B = OSSL_FN_CTX_get_limbs(ctx, limbs))
        || !TEST_ptr(M = OSSL_FN_CTX_get_limbs(ctx, limbs))
        || !TEST_ptr(Am = OSSL_FN_CTX_get_limbs(ctx, limbs))
        || !TEST_ptr(Bm = OSSL_FN_CTX_get_limbs(ctx, limbs))
        || !TEST_ptr(Rm = OSSL_FN_CTX_get_limbs(ctx, limbs))
        || !TEST_ptr(R = OSSL_FN_CTX_get_limbs(ctx, limbs)))
        goto err;

    if (!TEST_true(OSSL_FN_hex2fn(ModMul, ModMul_hex))
        || !TEST_true(OSSL_FN_hex2fn(A, A_hex))
        || !TEST_true(OSSL_FN_hex2fn(B, B_hex))
        || !TEST_true(OSSL_FN_hex2fn(M, M_hex)))
        goto err;

    if (OSSL_FN_cmp(A, M) >= 0
        || OSSL_FN_cmp(B, M) >= 0
        || OSSL_FN_cmp(ModMul, M) >= 0) {
        /* TEST_info("Skipping %s:%d: operand/result is not less than modulus",
                  s->test_file, s->start); */
        s->numskip++;
        ret = 1;
        goto err;
    }

    if (!TEST_ptr(mont = OSSL_FN_MONT_CTX_new(M))
        || !TEST_true(OSSL_FN_to_mont(Am, A, mont, ctx))
        || !TEST_true(OSSL_FN_to_mont(Bm, B, mont, ctx))
        || !TEST_true(OSSL_FN_mul_mont(Rm, Am, Bm, mont, ctx))
        || !TEST_true(OSSL_FN_from_mont(R, Rm, mont, ctx))
        || !TEST_int_eq(OSSL_FN_cmp(R, ModMul), 0))
        goto err;

    ret = 1;

err:
    OSSL_FN_MONT_CTX_free(mont);
    OSSL_FN_CTX_end(ctx, token);
    OSSL_FN_CTX_free(ctx);
    return ret;
}

static int test_fn_modmul_file(void)
{
    STANZA s;
    int ret = 1;

    if (!TEST_ptr(testfile) || !test_start_file(&s, testfile))
        return 0;

    while (!BIO_eof(s.fp) && test_readstanza(&s)) {
        if (s.numpairs == 0)
            continue;

        if (findattr(&s, "ModMul") != NULL) {
            s.numtests++;
            if (!test_one_modmul(&s)) {
                s.errors++;
                ret = 0;
            }
        }

        test_clearstanza(&s);
    }

    test_end_file(&s);
    return ret;
}

int setup_tests(void)
{
    if (!TEST_size_t_eq(test_get_argument_count(), 1))
        return 0;

    testfile = test_get_argument(0);
    ADD_TEST(test_fn_modmul_file);
    return 1;
}
