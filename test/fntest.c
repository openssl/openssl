/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include "crypto/fn.h"
#include "crypto/bn.h"
#include "crypto/fn_intern.h"
#include "internal/nelem.h"
#include "testutil.h"

/*
 * This is a stanza-driven arithmetic test for OSSL_FN.  Non-stanza API tests
 * belong in fn_api_test.
 */

typedef struct filetest_st {
    const char *name;
    int (*func)(STANZA *s);
    int skipped;
} FILETEST;

static const char *findattr(STANZA *s, const char *key)
{
    int i = s->numpairs;
    PAIR *pp = s->pairs;

    for (; --i >= 0; pp++)
        if (OPENSSL_strcasecmp(pp->key, key) == 0)
            return pp->value;
    return NULL;
}

static int parseBN(BIGNUM **out, const char *in)
{
    *out = NULL;
    return BN_hex2bn(out, in);
}

static BIGNUM *getBN(STANZA *s, const char *attribute)
{
    const char *hex;
    BIGNUM *ret = NULL;

    if ((hex = findattr(s, attribute)) == NULL) {
        TEST_error("%s:%d: Can't find %s", s->test_file, s->start, attribute);
        return NULL;
    }

    if (parseBN(&ret, hex) != (int)strlen(hex)) {
        TEST_error("Could not decode '%s'", hex);
        BN_free(ret);
        return NULL;
    }
    return ret;
}

static int getint(STANZA *s, int *out, const char *attribute)
{
    BIGNUM *ret;
    BN_ULONG word;
    int st = 0;

    if (!TEST_ptr(ret = getBN(s, attribute))
        || !TEST_uint64_t_le(word = BN_get_word(ret), INT_MAX))
        goto err;

    *out = (int)word;
    st = 1;
err:
    BN_free(ret);
    return st;
}

static int equalBN(const char *op, const BIGNUM *expected, const BIGNUM *actual)
{
    if (!TEST_BN_eq(expected, actual)) {
        TEST_error("unexpected %s value", op);
        return 0;
    }
    return 1;
}

/*
 * Number of limbs needed to hold bn's value, equivalent to the (properly
 * adjusted) BIGNUM 'top' field, which is not directly accessible here.
 */
static int limbs(const BIGNUM *bn)
{
    int ret = (BN_num_bits(bn) + BN_BITS2 - 1) / BN_BITS2;

    return ret > 0 ? ret : 1;
}

static int set_result_addsub(OSSL_FN *r, OSSL_FN *a, int a_neg,
    OSSL_FN *b, int b_neg, int *neg)
{
    int cmp;

    *neg = 0;
    if (a_neg == b_neg) {
        *neg = a_neg;
        return OSSL_FN_add(r, a, b);
    }

    cmp = OSSL_FN_cmp(a, b);
    if (cmp >= 0) {
        *neg = a_neg;
        return OSSL_FN_sub(r, a, b);
    }

    *neg = b_neg;
    return OSSL_FN_sub(r, b, a);
}

static int file_sum(STANZA *s)
{
    BIGNUM *a = NULL, *b = NULL, *sum = NULL, *ret = NULL;
    OSSL_FN *af = NULL, *bf = NULL, *rf = NULL;
    int a_neg = 0, b_neg = 0, r_neg = 0, st = 0;
    int r_acq = 0;
    int nlimbs = 0;

    if (!TEST_ptr(a = getBN(s, "A"))
        || !TEST_ptr(b = getBN(s, "B"))
        || !TEST_ptr(sum = getBN(s, "Sum"))
        || !TEST_ptr(ret = BN_new()))
        goto err;

    a_neg = BN_is_negative(a);
    b_neg = BN_is_negative(b);
    nlimbs = limbs(sum);

    if (!TEST_ptr(af = bn_get_ossl_fn(a))
        || !TEST_ptr(bf = bn_get_ossl_fn(b))
        || !TEST_ptr(rf = bn_acquire_ossl_fn(ret, nlimbs)))
        goto err;
    r_acq = 1;

    if (!TEST_true(set_result_addsub(rf, af, a_neg, bf, b_neg, &r_neg)))
        goto err;
    bn_release(ret, nlimbs);
    BN_set_negative(ret, r_neg);
    r_acq = 0;
    if (!equalBN("A + B", sum, ret))
        goto err;

    st = 1;
err:
    if (r_acq)
        bn_release(ret, nlimbs);
    BN_free(a);
    BN_free(b);
    BN_free(sum);
    BN_free(ret);
    return st;
}

static int file_product(STANZA *s)
{
    BIGNUM *a = NULL, *b = NULL, *product = NULL, *ret = NULL;
    OSSL_FN *af = NULL, *bf = NULL, *rf = NULL;
    OSSL_FN_CTX *ctx = NULL;
    int a_neg = 0, b_neg = 0, r_neg = 0, st = 0;
    int r_acq = 0;
    int nlimbs = 0;

    if (!TEST_ptr(a = getBN(s, "A"))
        || !TEST_ptr(b = getBN(s, "B"))
        || !TEST_ptr(product = getBN(s, "Product"))
        || !TEST_ptr(ret = BN_new()))
        goto err;

    a_neg = BN_is_negative(a);
    b_neg = BN_is_negative(b);
    r_neg = a_neg ^ b_neg;
    nlimbs = limbs(product);

    if (!TEST_ptr(af = bn_get_ossl_fn(a))
        || !TEST_ptr(bf = bn_get_ossl_fn(b))
        || !TEST_ptr(rf = bn_acquire_ossl_fn(ret, nlimbs)))
        goto err;
    r_acq = 1;
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL,
                      OSSL_FN_mul_ctx_size(rf, af, bf))))
        goto err;

    if (!TEST_true(OSSL_FN_mul(rf, af, bf, ctx)))
        goto err;
    bn_release(ret, nlimbs);
    BN_set_negative(ret, r_neg);
    r_acq = 0;
    if (!equalBN("A * B", product, ret))
        goto err;

    st = 1;
err:
    if (r_acq)
        bn_release(ret, nlimbs);
    OSSL_FN_CTX_free(ctx);
    BN_free(a);
    BN_free(b);
    BN_free(product);
    BN_free(ret);
    return st;
}

static int file_square(STANZA *s)
{
    BIGNUM *a = NULL, *square = NULL, *ret = NULL;
    OSSL_FN *af = NULL, *rf = NULL;
    OSSL_FN_CTX *ctx = NULL;
    int st = 0;
    int r_acq = 0;
    int nlimbs = 0;

    if (!TEST_ptr(a = getBN(s, "A"))
        || !TEST_ptr(square = getBN(s, "Square"))
        || !TEST_ptr(ret = BN_new()))
        goto err;

    nlimbs = limbs(square);

    if (!TEST_ptr(af = bn_get_ossl_fn(a))
        || !TEST_ptr(rf = bn_acquire_ossl_fn(ret, nlimbs)))
        goto err;
    r_acq = 1;
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL,
                      OSSL_FN_sqr_ctx_size(rf, af))))
        goto err;

    if (!TEST_true(OSSL_FN_sqr(rf, af, ctx)))
        goto err;
    bn_release(ret, nlimbs);
    BN_set_negative(ret, 0);
    r_acq = 0;
    if (!equalBN("A^2", square, ret))
        goto err;

    st = 1;
err:
    if (r_acq)
        bn_release(ret, nlimbs);
    OSSL_FN_CTX_free(ctx);
    BN_free(a);
    BN_free(square);
    BN_free(ret);
    return st;
}

static int file_quotient(STANZA *s)
{
    BIGNUM *a = NULL, *b = NULL, *quotient = NULL, *remainder = NULL;
    BIGNUM *qret = NULL, *rret = NULL, *mret = NULL;
    OSSL_FN *af = NULL, *bf = NULL, *qf = NULL, *rf = NULL, *mf = NULL;
    OSSL_FN_CTX *ctx = NULL, *mod_ctx = NULL;
    int a_neg = 0, b_neg = 0, q_neg = 0, r_neg = 0, st = 0;
    int q_acq = 0, r_acq = 0, m_acq = 0;
    int q_limbs = 0, r_limbs = 0;

    if (!TEST_ptr(a = getBN(s, "A"))
        || !TEST_ptr(b = getBN(s, "B"))
        || !TEST_ptr(quotient = getBN(s, "Quotient"))
        || !TEST_ptr(remainder = getBN(s, "Remainder"))
        || !TEST_ptr(qret = BN_new())
        || !TEST_ptr(rret = BN_new())
        || !TEST_ptr(mret = BN_new()))
        goto err;

    a_neg = BN_is_negative(a);
    b_neg = BN_is_negative(b);
    q_neg = a_neg ^ b_neg;
    r_neg = a_neg;
    q_limbs = limbs(quotient);
    r_limbs = limbs(remainder);

    if (!TEST_ptr(af = bn_get_ossl_fn(a))
        || !TEST_ptr(bf = bn_get_ossl_fn(b))
        || !TEST_ptr(qf = bn_acquire_ossl_fn(qret, q_limbs)))
        goto err;
    q_acq = 1;
    if (!TEST_ptr(rf = bn_acquire_ossl_fn(rret, r_limbs)))
        goto err;
    r_acq = 1;
    if (!TEST_ptr(mf = bn_acquire_ossl_fn(mret, r_limbs)))
        goto err;
    m_acq = 1;
    if (!TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL,
                      OSSL_FN_div_ctx_size(qf, rf, af, bf)))
        || !TEST_ptr(mod_ctx = OSSL_FN_CTX_new_size(NULL,
                         OSSL_FN_mod_ctx_size(mf, af, bf))))
        goto err;

    if (!TEST_true(OSSL_FN_div(qf, rf, af, bf, ctx)))
        goto err;
    bn_release(qret, q_limbs);
    if (!BN_is_zero(qret))
        BN_set_negative(qret, q_neg);
    q_acq = 0;
    bn_release(rret, r_limbs);
    if (!BN_is_zero(rret))
        BN_set_negative(rret, r_neg);
    r_acq = 0;
    if (!equalBN("A / B", quotient, qret)
        || !equalBN("A % B", remainder, rret))
        goto err;

    if (!TEST_true(OSSL_FN_mod(mf, af, bf, mod_ctx)))
        goto err;
    bn_release(mret, r_limbs);
    if (!BN_is_zero(mret))
        BN_set_negative(mret, r_neg);
    m_acq = 0;
    if (!equalBN("A % B (mod)", remainder, mret))
        goto err;

    st = 1;
err:
    if (m_acq)
        bn_release(mret, r_limbs);
    if (r_acq)
        bn_release(rret, r_limbs);
    if (q_acq)
        bn_release(qret, q_limbs);
    OSSL_FN_CTX_free(mod_ctx);
    OSSL_FN_CTX_free(ctx);
    BN_free(a);
    BN_free(b);
    BN_free(quotient);
    BN_free(remainder);
    BN_free(qret);
    BN_free(rret);
    BN_free(mret);
    return st;
}

static int file_lshift1(STANZA *s)
{
    BIGNUM *a = NULL, *lshift1 = NULL, *ret = NULL;
    OSSL_FN *af = NULL, *rf = NULL;
    int a_neg = 0, st = 0;
    int r_acq = 0;
    int nlimbs = 0;

    if (!TEST_ptr(a = getBN(s, "A"))
        || !TEST_ptr(lshift1 = getBN(s, "LShift1"))
        || !TEST_ptr(ret = BN_new()))
        goto err;

    a_neg = BN_is_negative(a);
    nlimbs = limbs(lshift1);

    if (!TEST_ptr(af = bn_get_ossl_fn(a))
        || !TEST_ptr(rf = bn_acquire_ossl_fn(ret, nlimbs)))
        goto err;
    r_acq = 1;

    if (!TEST_true(OSSL_FN_lshift1(rf, af)))
        goto err;
    bn_release(ret, nlimbs);
    BN_set_negative(ret, a_neg);
    r_acq = 0;
    if (!equalBN("A << 1", lshift1, ret))
        goto err;

    st = 1;
err:
    if (r_acq)
        bn_release(ret, nlimbs);
    BN_free(a);
    BN_free(lshift1);
    BN_free(ret);
    return st;
}

static int file_lshift(STANZA *s)
{
    BIGNUM *a = NULL, *lshift = NULL, *ret = NULL;
    OSSL_FN *af = NULL, *rf = NULL;
    int a_neg = 0, n = 0, st = 0;
    int r_acq = 0;
    int nlimbs = 0;

    if (!TEST_ptr(a = getBN(s, "A"))
        || !TEST_ptr(lshift = getBN(s, "LShift"))
        || !TEST_ptr(ret = BN_new())
        || !getint(s, &n, "N"))
        goto err;

    a_neg = BN_is_negative(a);
    nlimbs = limbs(lshift);

    if (!TEST_ptr(af = bn_get_ossl_fn(a))
        || !TEST_ptr(rf = bn_acquire_ossl_fn(ret, nlimbs)))
        goto err;
    r_acq = 1;

    if (!TEST_true(OSSL_FN_lshift(rf, af, n)))
        goto err;
    bn_release(ret, nlimbs);
    BN_set_negative(ret, a_neg);
    r_acq = 0;
    if (!equalBN("A << N", lshift, ret))
        goto err;

    st = 1;
err:
    if (r_acq)
        bn_release(ret, nlimbs);
    BN_free(a);
    BN_free(lshift);
    BN_free(ret);
    return st;
}

static FILETEST filetests[] = {
    { "Sum", file_sum, 0 },
    { "LShift1", file_lshift1, 0 },
    { "LShift", file_lshift, 0 },
    { "RShift", NULL, 0 },
    { "Square", file_square, 0 },
    { "Product", file_product, 0 },
    { "Quotient", file_quotient, 0 },
    { "ModMul", NULL, 0 },
    { "ModSqr", NULL, 0 },
    { "ModExp", NULL, 0 },
    { "Exp", NULL, 0 },
    { "ModSqrt", NULL, 0 },
    { "GCD", NULL, 0 },
};

static int file_test_run(STANZA *s)
{
    const FILETEST *tp = filetests;
    size_t i;

    for (i = 0; i < OSSL_NELEM(filetests); i++, tp++) {
        if (findattr(s, tp->name) != NULL) {
            if (tp->func == NULL) {
                filetests[i].skipped++;
                return 1;
            }
            if (!tp->func(s)) {
                TEST_info("%s:%d: Failed %s test",
                    s->test_file, s->start, tp->name);
                return 0;
            }
            return 1;
        }
    }

    TEST_info("%s:%d: Unknown test, skipped", s->test_file, s->start);
    return 1;
}

static int run_file_tests(int i)
{
    STANZA *s = NULL;
    char *testfile = test_get_argument(i);
    int c;
    size_t j;

    for (j = 0; j < OSSL_NELEM(filetests); j++)
        filetests[j].skipped = 0;

    if (!TEST_ptr(s = OPENSSL_zalloc(sizeof(*s))))
        return 0;
    if (!test_start_file(s, testfile)) {
        OPENSSL_free(s);
        return 0;
    }

    while (!BIO_eof(s->fp) && test_readstanza(s)) {
        if (s->numpairs == 0)
            continue;
        if (!file_test_run(s))
            s->errors++;
        s->numtests++;
        test_clearstanza(s);
    }
    test_end_file(s);

    for (j = 0; j < OSSL_NELEM(filetests); j++)
        if (filetests[j].skipped > 0)
            TEST_info("%s: skipped %d unsupported %s stanzas",
                testfile, filetests[j].skipped, filetests[j].name);

    c = s->errors;
    OPENSSL_free(s);

    return c == 0;
}

OPT_TEST_DECLARE_USAGE("file...\n")

int setup_tests(void)
{
    size_t n = test_get_argument_count();

    if (!TEST_size_t_gt(n, 0))
        return 0;

    ADD_ALL_TESTS(run_file_tests, (int)n);
    return 1;
}
