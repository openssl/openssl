/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Functional and constant-time tests for the OSSL_FN "quick" modular
 * helpers, which the constant-time EC point arithmetic applies to secret
 * coordinates, and for OSSL_FN_mod_exp_mont() with a secret exponent.  Only
 * the widths and the modulus are public.
 *
 * When built with enable-ct-validation, CONSTTIME_SECRET marks the operands
 * as undefined for Valgrind's memcheck, so any branch or memory index derived
 * from them makes Valgrind exit non-zero.  Outside a CT build the macros are
 * no-ops and this is an ordinary functional test against BIGNUM.
 */

#include <openssl/bn.h>
#include "crypto/fn.h"
#include "crypto/fn_intern.h"
#include "internal/constant_time.h"
#include "internal/nelem.h"
#include "fn_local.h"
#include "testutil.h"

/* The P-384 and P-521 field primes: a full and a partial top limb */
static const char *moduli[] = {
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
    "ffffffff0000000000000000ffffffff",
    "01ff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
};

/* Operand values, all less than m; OP_PATTERN is a fixed value mod m */
enum operand {
    OP_ZERO,
    OP_ONE,
    OP_M_MINUS_1,
    OP_HALF,
    OP_PATTERN
};

/*
 * The (a, b) pairs, chosen for the cases of the quick add and subtract.  The
 * shifts use a alone, which takes each operand value in turn.
 */
static const struct {
    enum operand a, b;
} pairs[] = {
    /* add: largest sum that does not wrap; sub: borrow */
    { OP_ZERO, OP_M_MINUS_1 },
    /* add: no wrap; sub: borrow */
    { OP_ONE, OP_HALF },
    /* add: wraps to exactly 0, with no carry out of the top limb */
    { OP_M_MINUS_1, OP_ONE },
    /* add: wraps, with a carry out of the top limb for P-384 */
    { OP_M_MINUS_1, OP_PATTERN },
    /* add: a + a without wrapping; sub: result 0 */
    { OP_HALF, OP_HALF },
    /* b == 0 */
    { OP_PATTERN, OP_ZERO },
};

static const int shifts[] = { 0, 1, 2, 3, 7, 64, 130 };

static int set_operand(BIGNUM *a, const BIGNUM *m, enum operand k,
    BN_CTX *ctx)
{
    switch (k) {
    case OP_ZERO:
        BN_zero(a);
        return 1;
    case OP_ONE:
        return BN_one(a);
    case OP_M_MINUS_1:
        return BN_copy(a, m) != NULL && BN_sub_word(a, 1);
    case OP_HALF:
        return BN_copy(a, m) != NULL && BN_sub_word(a, 1) && BN_rshift1(a, a);
    case OP_PATTERN:
    default:
        return BN_hex2bn(&a, "a5a5a5a5c3c3c3c3f0f0f0f00ff00ff0"
                             "123456789abcdef0fedcba9876543210"
                             "deadbeefcafebabe0123456789abcdef")
            && BN_nnmod(a, a, m, ctx);
    }
}

static OSSL_FN *fn_from_bn(const BIGNUM *bn, size_t limbs, size_t len)
{
    unsigned char buf[256];
    OSSL_FN *f = OSSL_FN_new_limbs(limbs);

    if (f == NULL
        || BN_bn2binpad(bn, buf, (int)len) < 0
        || !OSSL_FN_from_bytes_be(f, buf, len)) {
        OSSL_FN_free(f);
        return NULL;
    }
    return f;
}

static void fn_secret(const OSSL_FN *f, size_t limbs)
{
    CONSTTIME_SECRET((void *)ossl_fn_get_words(f), limbs * OSSL_FN_BYTES);
}

static void fn_declassify(const OSSL_FN *f, size_t limbs)
{
    CONSTTIME_DECLASSIFY((void *)ossl_fn_get_words(f), limbs * OSSL_FN_BYTES);
}

/* Declassify |r| and compare it with |expected| */
static int check(const char *op, const OSSL_FN *r, size_t limbs,
    const BIGNUM *expected, size_t len)
{
    unsigned char got[128], want[128];

    fn_declassify(r, limbs);
    if (!TEST_true(OSSL_FN_to_bytes_be(r, got, len))
        || !TEST_int_ge(BN_bn2binpad(expected, want, (int)len), 0)
        || !TEST_mem_eq(got, len, want, len)) {
        TEST_info("%s", op);
        return 0;
    }
    return 1;
}

static int test_quick_ops(int idx)
{
    size_t mi = idx / OSSL_NELEM(pairs), pi = idx % OSSL_NELEM(pairs);
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *m = NULL, *a = BN_new(), *b = BN_new(), *e = BN_new();
    OSSL_FN *fm = NULL, *fa = NULL, *fb = NULL, *r = NULL;
    size_t len = 0, limbs = 0, i;
    int ret = 0;

    if (!TEST_ptr(bnctx) || !TEST_ptr(a) || !TEST_ptr(b) || !TEST_ptr(e)
        || !TEST_true(BN_hex2bn(&m, moduli[mi]))
        || !TEST_true(set_operand(a, m, pairs[pi].a, bnctx))
        || !TEST_true(set_operand(b, m, pairs[pi].b, bnctx)))
        goto err;

    len = (size_t)BN_num_bytes(m);
    limbs = (len + OSSL_FN_BYTES - 1) / OSSL_FN_BYTES;
    if (!TEST_ptr(fm = fn_from_bn(m, limbs, len))
        || !TEST_ptr(fa = fn_from_bn(a, limbs, len))
        || !TEST_ptr(fb = fn_from_bn(b, limbs, len))
        || !TEST_ptr(r = OSSL_FN_new_limbs(limbs)))
        goto err;

    fn_secret(fa, limbs);
    fn_secret(fb, limbs);

    if (!TEST_true(OSSL_FN_mod_add_quick(r, fa, fb, fm))
        || !TEST_true(BN_mod_add(e, a, b, m, bnctx))
        || !check("mod_add_quick", r, limbs, e, len))
        goto err;

    if (!TEST_true(OSSL_FN_mod_sub_quick(r, fa, fb, fm))
        || !TEST_true(BN_mod_sub(e, a, b, m, bnctx))
        || !check("mod_sub_quick", r, limbs, e, len))
        goto err;

    if (!TEST_true(OSSL_FN_mod_lshift1_quick(r, fa, fm))
        || !TEST_true(BN_mod_lshift1(e, a, m, bnctx))
        || !check("mod_lshift1_quick", r, limbs, e, len))
        goto err;

    for (i = 0; i < OSSL_NELEM(shifts); i++) {
        if (!TEST_true(OSSL_FN_mod_lshift_quick(r, fa, shifts[i], fm))
            || !TEST_true(BN_mod_lshift(e, a, shifts[i], m, bnctx))
            || !check("mod_lshift_quick", r, limbs, e, len)) {
            TEST_info("n = %d", shifts[i]);
            goto err;
        }
    }

    /* The result may alias the operand */
    if (!TEST_ptr(OSSL_FN_copy_truncate(r, fa))
        || !TEST_true(OSSL_FN_mod_lshift_quick(r, r, 3, fm))
        || !TEST_true(BN_mod_lshift(e, a, 3, m, bnctx))
        || !check("mod_lshift_quick, r == a", r, limbs, e, len))
        goto err;

    ret = 1;
err:
    if (fa != NULL)
        fn_declassify(fa, limbs);
    if (fb != NULL)
        fn_declassify(fb, limbs);
    OSSL_FN_free(fm);
    OSSL_FN_free(fa);
    OSSL_FN_free(fb);
    OSSL_FN_free(r);
    BN_free(m);
    BN_free(a);
    BN_free(b);
    BN_free(e);
    BN_CTX_free(bnctx);
    return ret;
}

/*
 * Montgomery arithmetic as used for constant-time modular multiplication:
 * mul_mont_quick(to_mont_quick(a), b) gives a * b mod m directly, and
 * from_mont undoes to_mont_quick.  from_mont also reduces wider inputs:
 * to_mont_quick of the result gives the input mod m.
 */
static int test_mont_ops(int idx)
{
    size_t mi = idx / OSSL_NELEM(pairs), pi = idx % OSSL_NELEM(pairs);
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *m = NULL, *a = BN_new(), *b = BN_new(), *e = BN_new();
    OSSL_FN *fm = NULL, *fa = NULL, *fb = NULL, *am = NULL, *r = NULL;
    OSSL_FN *wide = NULL, *wider = NULL;
    OSSL_FN_MONT_CTX *mont = NULL;
    OSSL_FN_CTX *ctx = NULL;
    size_t len = 0, limbs = 0;
    int ret = 0;

    if (!TEST_ptr(bnctx) || !TEST_ptr(a) || !TEST_ptr(b) || !TEST_ptr(e)
        || !TEST_true(BN_hex2bn(&m, moduli[mi]))
        || !TEST_true(set_operand(a, m, pairs[pi].a, bnctx))
        || !TEST_true(set_operand(b, m, pairs[pi].b, bnctx)))
        goto err;

    len = (size_t)BN_num_bytes(m);
    limbs = (len + OSSL_FN_BYTES - 1) / OSSL_FN_BYTES;
    if (!TEST_ptr(fm = fn_from_bn(m, limbs, len))
        || !TEST_ptr(fa = fn_from_bn(a, limbs, len))
        || !TEST_ptr(fb = fn_from_bn(b, limbs, len))
        || !TEST_ptr(am = OSSL_FN_new_limbs(limbs))
        || !TEST_ptr(r = OSSL_FN_new_limbs(limbs))
        || !TEST_ptr(mont = OSSL_FN_MONT_CTX_new(fm))
        || !TEST_ptr(OSSL_FN_MONT_CTX_get0_modulus(mont))
        || !TEST_int_eq(OSSL_FN_MONT_CTX_get0_modulus(mont)->dsize, (int)limbs)
        || !TEST_true(BN_mul(e, a, b, bnctx))
        || !TEST_ptr(wide = fn_from_bn(e, 2 * limbs, 2 * limbs * OSSL_FN_BYTES))
        || !TEST_ptr(wider = fn_from_bn(a, limbs + 1,
                         (limbs + 1) * OSSL_FN_BYTES))
        || !TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL,
                         OSSL_FN_from_mont_ctx_size(r, wide, mont))))
        goto err;

    fn_secret(fa, limbs);
    fn_secret(fb, limbs);
    fn_secret(wide, 2 * limbs);
    fn_secret(wider, limbs + 1);

    if (!TEST_true(OSSL_FN_to_mont_quick(am, fa, mont, ctx))
        || !TEST_true(OSSL_FN_mul_mont_quick(r, am, fb, mont, ctx))
        || !TEST_true(BN_mod_mul(e, a, b, m, bnctx))
        || !check("to_mont_quick + mul_mont_quick", r, limbs, e, len))
        goto err;

    if (!TEST_true(OSSL_FN_from_mont(r, am, mont, ctx))
        || !check("from_mont(to_mont_quick)", r, limbs, a, len))
        goto err;

    /*
     * from_mont multiplies by R^-1 and to_mont_quick by R, so together they
     * reduce a double-width value mod m without division.
     */
    if (!TEST_true(OSSL_FN_from_mont(am, wide, mont, ctx))
        || !TEST_true(OSSL_FN_to_mont_quick(r, am, mont, ctx))
        || !TEST_true(BN_mod_mul(e, a, b, m, bnctx))
        || !check("to_mont_quick(from_mont(a * b))", r, limbs, e, len))
        goto err;

    if (!TEST_true(OSSL_FN_from_mont(am, wider, mont, ctx))
        || !TEST_true(OSSL_FN_to_mont_quick(r, am, mont, ctx))
        || !check("to_mont_quick(from_mont(a, one limb wider))", r, limbs,
            a, len))
        goto err;

    ret = 1;
err:
    if (fa != NULL)
        fn_declassify(fa, limbs);
    if (fb != NULL)
        fn_declassify(fb, limbs);
    if (wide != NULL)
        fn_declassify(wide, 2 * limbs);
    if (wider != NULL)
        fn_declassify(wider, limbs + 1);
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_MONT_CTX_free(mont);
    OSSL_FN_free(fm);
    OSSL_FN_free(fa);
    OSSL_FN_free(fb);
    OSSL_FN_free(am);
    OSSL_FN_free(r);
    OSSL_FN_free(wide);
    OSSL_FN_free(wider);
    BN_free(m);
    BN_free(a);
    BN_free(b);
    BN_free(e);
    BN_CTX_free(bnctx);
    return ret;
}

static void mont_secret(OSSL_FN_MONT_CTX *mont, int on)
{
    size_t limbs = (size_t)mont->N->dsize;

    if (on) {
        fn_secret(mont->N, limbs);
        fn_secret(mont->RR, limbs);
        CONSTTIME_SECRET(mont->n0, sizeof(mont->n0));
    } else {
        fn_declassify(mont->N, limbs);
        fn_declassify(mont->RR, limbs);
        CONSTTIME_DECLASSIFY(mont->n0, sizeof(mont->n0));
    }
}

/*
 * OSSL_FN_mont_reduce() of a double-width product and of a narrower value.
 * Odd indices also make the modulus secret, as an RSA prime is.
 */
static int test_mont_reduce(int idx)
{
    int secret_mod = idx & 1;
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *m = NULL, *a = BN_new(), *b = BN_new(), *e = BN_new();
    OSSL_FN *fm = NULL, *wide = NULL, *narrow = NULL, *r = NULL;
    OSSL_FN_MONT_CTX *mont = NULL;
    OSSL_FN_CTX *ctx = NULL;
    size_t len = 0, limbs = 0;
    int ret = 0;

    if (!TEST_ptr(bnctx) || !TEST_ptr(a) || !TEST_ptr(b) || !TEST_ptr(e)
        || !TEST_true(BN_hex2bn(&m, moduli[idx / 2]))
        || !TEST_true(set_operand(a, m, OP_PATTERN, bnctx))
        || !TEST_true(set_operand(b, m, OP_M_MINUS_1, bnctx))
        || !TEST_true(BN_mul(e, a, b, bnctx)))
        goto err;

    len = (size_t)BN_num_bytes(m);
    limbs = (len + OSSL_FN_BYTES - 1) / OSSL_FN_BYTES;
    if (!TEST_ptr(fm = fn_from_bn(m, limbs, len))
        || !TEST_ptr(wide = fn_from_bn(e, 2 * limbs, 2 * limbs * OSSL_FN_BYTES))
        || !TEST_true(BN_rshift(a, a, OSSL_FN_BITS))
        || !TEST_ptr(narrow = fn_from_bn(a, limbs - 1,
                         (limbs - 1) * OSSL_FN_BYTES))
        || !TEST_ptr(r = OSSL_FN_new_limbs(limbs))
        || !TEST_ptr(mont = OSSL_FN_MONT_CTX_new(fm))
        || !TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL,
                         ossl_fn_ctx_max_size(
                             OSSL_FN_mont_reduce_ctx_size(r, wide, mont),
                             OSSL_FN_mont_reduce_ctx_size(r, narrow, mont)))))
        goto err;

    fn_secret(wide, 2 * limbs);
    fn_secret(narrow, limbs - 1);
    if (secret_mod)
        mont_secret(mont, 1);

    if (!TEST_true(OSSL_FN_mont_reduce(r, wide, mont, ctx))
        || !TEST_true(BN_nnmod(e, e, m, bnctx))
        || !check("mont_reduce(a * b)", r, limbs, e, len))
        goto err;

    if (!TEST_true(OSSL_FN_mont_reduce(r, narrow, mont, ctx))
        || !check("mont_reduce(narrower)", r, limbs, a, len))
        goto err;

    ret = 1;
err:
    if (mont != NULL && secret_mod)
        mont_secret(mont, 0);
    if (wide != NULL)
        fn_declassify(wide, 2 * limbs);
    if (narrow != NULL)
        fn_declassify(narrow, limbs - 1);
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_MONT_CTX_free(mont);
    OSSL_FN_free(fm);
    OSSL_FN_free(wide);
    OSSL_FN_free(narrow);
    OSSL_FN_free(r);
    BN_free(m);
    BN_free(a);
    BN_free(b);
    BN_free(e);
    BN_CTX_free(bnctx);
    return ret;
}

/*
 * Exponent widths in limbs.  They select fixed windows of 3, 4 and 5 bits:
 * window 3 uses the one-mask-per-entry gather and windows 4 and 5 the
 * four-way split one in mod_exp_ctime_copy_from_prebuf().
 */
static const size_t exp_limbs[] = { 1, 4, 6 };

static int test_mod_exp(int idx)
{
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *m = NULL, *a = BN_new(), *p = BN_new(), *e = BN_new();
    OSSL_FN *fm = NULL, *fa = NULL, *fp = NULL, *r = NULL;
    OSSL_FN_CTX *ctx = NULL;
    unsigned char pbuf[6 * OSSL_FN_BYTES];
    size_t len = 0, limbs = 0, plen = exp_limbs[idx] * OSSL_FN_BYTES, i;
    int ret = 0, secret = 0;

    /*
     * Constants chosen so that every table index occurs in the exponent, for
     * each exponent width and for both 32-bit and 64-bit limbs
     */
    for (i = 0; i < plen; i++)
        pbuf[i] = (unsigned char)(i * 0x2f + 0x18);

    if (!TEST_ptr(bnctx) || !TEST_ptr(a) || !TEST_ptr(p) || !TEST_ptr(e)
        || !TEST_true(BN_hex2bn(&m, moduli[0]))
        || !TEST_true(set_operand(a, m, OP_PATTERN, bnctx))
        || !TEST_ptr(BN_bin2bn(pbuf, (int)plen, p)))
        goto err;

    len = (size_t)BN_num_bytes(m);
    limbs = (len + OSSL_FN_BYTES - 1) / OSSL_FN_BYTES;
    if (!TEST_ptr(fm = fn_from_bn(m, limbs, len))
        || !TEST_ptr(fa = fn_from_bn(a, limbs, len))
        || !TEST_ptr(fp = fn_from_bn(p, exp_limbs[idx], plen))
        || !TEST_ptr(r = OSSL_FN_new_limbs(limbs))
        || !TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL,
                         OSSL_FN_mod_exp_mont_ctx_size(r, fa, fp, fm, NULL))))
        goto err;

    fn_secret(fp, exp_limbs[idx]);
    secret = 1;

    if (!TEST_true(OSSL_FN_mod_exp_mont(r, fa, fp, fm, ctx, NULL))
        || !TEST_true(BN_mod_exp(e, a, p, m, bnctx))
        || !check("mod_exp_mont", r, limbs, e, len)) {
        TEST_info("exponent limbs = %zu", exp_limbs[idx]);
        goto err;
    }

    ret = 1;
err:
    if (secret)
        fn_declassify(fp, exp_limbs[idx]);
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_free(fm);
    OSSL_FN_free(fa);
    OSSL_FN_free(fp);
    OSSL_FN_free(r);
    BN_free(m);
    BN_free(a);
    BN_free(p);
    BN_free(e);
    BN_CTX_free(bnctx);
    return ret;
}

/*
 * The Fermat inverse a^(m-2) mod m with a secret a, as used for ECDSA, DSA
 * and SM2 nonces and keys and for projective EC coordinates.
 */
static int test_mod_inverse_prime(int idx)
{
    size_t mi = idx / OSSL_NELEM(pairs), pi = idx % OSSL_NELEM(pairs);
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *m = NULL, *a = BN_new(), *e = BN_new();
    OSSL_FN *fm = NULL, *fa = NULL, *r = NULL;
    OSSL_FN_MONT_CTX *mont = NULL;
    OSSL_FN_CTX *ctx = NULL;
    size_t len = 0, limbs = 0;
    int ret = 0;

    if (!TEST_ptr(bnctx) || !TEST_ptr(a) || !TEST_ptr(e)
        || !TEST_true(BN_hex2bn(&m, moduli[mi]))
        || !TEST_true(set_operand(a, m, pairs[pi].a, bnctx)))
        goto err;
    /* Zero has no inverse */
    if (BN_is_zero(a)) {
        ret = 1;
        goto err;
    }

    len = (size_t)BN_num_bytes(m);
    limbs = (len + OSSL_FN_BYTES - 1) / OSSL_FN_BYTES;
    if (!TEST_ptr(fm = fn_from_bn(m, limbs, len))
        || !TEST_ptr(fa = fn_from_bn(a, limbs, len))
        || !TEST_ptr(r = OSSL_FN_new_limbs(limbs))
        || !TEST_ptr(mont = OSSL_FN_MONT_CTX_new(fm))
        || !TEST_ptr(ctx = OSSL_FN_CTX_new_size(NULL,
                         OSSL_FN_mod_inverse_prime_ctx_size(r, fa, fm, mont))))
        goto err;

    fn_secret(fa, limbs);

    if (!TEST_true(OSSL_FN_mod_inverse_prime(r, fa, fm, ctx, mont))
        || !TEST_ptr(BN_mod_inverse(e, a, m, bnctx))
        || !check("mod_inverse_prime", r, limbs, e, len))
        goto err;

    ret = 1;
err:
    if (fa != NULL)
        fn_declassify(fa, limbs);
    OSSL_FN_CTX_free(ctx);
    OSSL_FN_MONT_CTX_free(mont);
    OSSL_FN_free(fm);
    OSSL_FN_free(fa);
    OSSL_FN_free(r);
    BN_free(m);
    BN_free(a);
    BN_free(e);
    BN_CTX_free(bnctx);
    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_quick_ops, (int)(OSSL_NELEM(moduli) * OSSL_NELEM(pairs)));
    ADD_ALL_TESTS(test_mont_ops, (int)(OSSL_NELEM(moduli) * OSSL_NELEM(pairs)));
    ADD_ALL_TESTS(test_mont_reduce, (int)(2 * OSSL_NELEM(moduli)));
    ADD_ALL_TESTS(test_mod_exp, (int)OSSL_NELEM(exp_limbs));
    ADD_ALL_TESTS(test_mod_inverse_prime,
        (int)(OSSL_NELEM(moduli) * OSSL_NELEM(pairs)));
    return 1;
}
