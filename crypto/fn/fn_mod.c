/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "internal/nelem.h"
#include "internal/safe_math.h"
#include "crypto/fnerr.h"
#include "fn_local.h"

OSSL_SAFE_MATH_ADDU(size_t, size_t, OSSL_SAFE_MATH_MAXU(size_t))
OSSL_SAFE_MATH_MULU(size_t, size_t, OSSL_SAFE_MATH_MAXU(size_t))

static size_t ctx_add_size(size_t a, size_t b)
{
    int err = 0;
    size_t r = safe_add_size_t(a, b, &err);

    return err == 0 ? r : 0;
}

static size_t ctx_max_size(size_t a, size_t b)
{
    return a > b ? a : b;
}

/*
 * The *_ctx_size helpers below use local OSSL_FN headers with only |dsize|
 * set to represent temporaries that the corresponding operation allocates
 * with OSSL_FN_CTX_get_limbs().  This is enough for nested ctx-size helpers,
 * which only inspect operand sizes.
 */
size_t OSSL_FN_mod_add_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *b, const OSSL_FN *m)
{
    size_t tl, own_size, nested_size;

    if (r == NULL || a == NULL || b == NULL || m == NULL)
        return 0;
    int err = 0;

    tl = safe_add_size_t(a->dsize > b->dsize ? a->dsize : b->dsize,
        1, &err);
    if (err != 0 || ossl_fn_totalsize(tl) == 0)
        return 0;

    OSSL_FN t = { .dsize = (int)tl };

    own_size = OSSL_FN_CTX_size(1, 1, tl);
    nested_size = OSSL_FN_mod_ctx_size(r, &t, m);
    if (own_size == 0 || nested_size == 0)
        return 0;

    return ctx_add_size(own_size, nested_size);
}

int OSSL_FN_mod_add(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    const OSSL_FN *m, OSSL_FN_CTX *ctx)
{
    const void *token = OSSL_FN_CTX_start(ctx);
    OSSL_FN *t;
    int ret = 0;
    size_t tl = (a->dsize > b->dsize ? a->dsize : b->dsize) + 1;

    if (token == NULL)
        return 0;
    if ((t = OSSL_FN_CTX_get_limbs(ctx, tl)) == NULL)
        goto err;

    ret = OSSL_FN_add(t, a, b)
        && OSSL_FN_mod(r, t, m, ctx);

err:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

/*
 * OSSL_FN_mod_add variant that may be used if both a and b are less than m.
 * The original formula is:
 *
 * r' = a + b
 * r = r′ − m[r′ ≥ m]
 *
 * This is replaced with addition, subtracting modulus, and conditional move
 * depending on whether or not subtraction borrowed.
 */
int OSSL_FN_mod_add_quick(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    const OSSL_FN *m)
{
    size_t al = a->dsize;
    size_t bl = b->dsize;
    size_t rl = r->dsize;
    size_t ml = m->dsize;
    size_t aw = al < ml ? al : ml;
    size_t bw = bl < ml ? bl : ml;
    OSSL_FN_ULONG storage[2 * 1024 / OSSL_FN_BITS];
    OSSL_FN_ULONG *tp = storage;
    OSSL_FN_ULONG *mp = storage + ml;
    OSSL_FN_ULONG carry, borrow;
    size_t i;

    if (2 * ml > OSSL_NELEM(storage)) {
        tp = OPENSSL_malloc_array(2 * ml, sizeof(OSSL_FN_ULONG));
        if (tp == NULL)
            return 0;
        mp = tp + ml;
    }

    /* tp = a + b mod 2^(ml*bits) */
    carry = ossl_fn_add_words(tp, ml, a->d, aw, b->d, bw);

    /* mp = tp - m mod 2^(ml*bits) */
    borrow = ossl_fn_sub_words(mp, ml, tp, ml, m->d, ml);

    /*
     * Because a, b < m, we have a + b < 2m.  Therefore tp < m whenever
     * carry = 1, which forces borrow = 1. The mask carry − borrow thus
     * only produces 0 (select tp2) or ~0 (select tp), matching exactly
     * whether a + b ≥ m.
     *
     * Thus, we have the cases:
     *
     * a + b < m                => carry == 0, borrow == 1
     * m <= a+b < 2^(ml*bits)   => carry == 0, borrow == 0
     * 2^(ml*bits) <= a+b < 2m  => carry == 1, borrow == 1
     *
     * If (a + b < m), select tp; otherwise select tp2.  Done with the
     * help of a mask.
     */
    OSSL_FN_ULONG mask = carry - borrow;
    size_t end = (rl < ml) ? rl : ml;
    for (i = 0; i < end; i++)
        r->d[i] = (mask & tp[i]) | (~mask & mp[i]);
    /* Make sure to pad r with zeroes when rl > ml */
    for (; i < rl; i++)
        r->d[i] = 0;

    if (tp != storage)
        OPENSSL_free(tp);

    return 1;
}

size_t OSSL_FN_mod_sub_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *b, const OSSL_FN *m)
{
    size_t ml, n_numbers, own_size, mod_a_size, mod_b_size, nested_size;

    if (r == NULL || a == NULL || b == NULL || m == NULL)
        return 0;

    ml = m->dsize;
    n_numbers = (r == m) ? 3 : 2;
    if (ossl_fn_totalsize(ml) == 0)
        return 0;

    OSSL_FN am = { .dsize = (int)ml };
    OSSL_FN bm = { .dsize = (int)ml };

    own_size = OSSL_FN_CTX_size(1, n_numbers, n_numbers * ml);
    mod_a_size = OSSL_FN_mod_ctx_size(&am, a, m);
    mod_b_size = OSSL_FN_mod_ctx_size(&bm, b, m);
    nested_size = ctx_max_size(mod_a_size, mod_b_size);
    if (own_size == 0 || nested_size == 0)
        return 0;

    return ctx_add_size(own_size, nested_size);
}

int OSSL_FN_mod_sub(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    const OSSL_FN *m, OSSL_FN_CTX *ctx)
{
    const void *token = OSSL_FN_CTX_start(ctx);
    OSSL_FN *am, *bm, *rr = r;
    int ret = 0;

    if (token == NULL)
        return 0;
    if ((am = OSSL_FN_CTX_get_limbs(ctx, m->dsize)) == NULL
        || (bm = OSSL_FN_CTX_get_limbs(ctx, m->dsize)) == NULL)
        goto err;

    if (r == m && (rr = OSSL_FN_CTX_get_limbs(ctx, m->dsize)) == NULL)
        goto err;

    ret = OSSL_FN_mod(am, a, m, ctx)
        && OSSL_FN_mod(bm, b, m, ctx)
        && OSSL_FN_mod_sub_quick(rr, am, bm, m)
        && (rr == r || OSSL_FN_copy_truncate(r, rr) != NULL);

err:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

/*
 * OSSL_FN_mod_sub variant that may be used if a is less than m, while b is
 * of same bit width as m.  It's implemented as subtraction followed by two
 * conditional additions.
 *
 * 0 <= a < m
 * 0 <= b < 2^w < 2*m
 *
 * after subtraction
 *
 * -2*m < r = a - b < m
 *
 * The original formula is:
 *
 * r' = a - b
 * r'' = r' + m[r' < 0]
 * r = r′' + m[r′' < 0]
 *
 * Because masking techniques are used, this is most efficiently
 * carried out with local loops rather than calling functions like
 * ossl_fn_add_words().
 */
int OSSL_FN_mod_sub_quick(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    const OSSL_FN *m)
{
    if (r == m) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    size_t al = a->dsize;
    size_t bl = b->dsize;
    size_t rl = r->dsize;
    size_t ml = m->dsize;
    size_t aw = al < ml ? al : ml;
    size_t bw = bl < ml ? bl : ml;
    OSSL_FN_ULONG storage[1024 / OSSL_FN_BITS];
    OSSL_FN_ULONG *tp = storage;
    size_t i;
    OSSL_FN_ULONG borrow, carry, ta, mask;

    if (ml > OSSL_NELEM(storage)) {
        tp = OPENSSL_malloc_array(ml, sizeof(OSSL_FN_ULONG));
        if (tp == NULL)
            return 0;
    }

    /* tp = a - b mod 2^(ml*bits) */
    borrow = ossl_fn_sub_words(tp, ml, a->d, aw, b->d, bw);

    /* If borrow, add m */
    for (i = 0, mask = 0 - borrow, carry = 0; i < ml; i++) {
        ta = ((m->d[i] & mask) + carry) & OSSL_FN_MASK;
        carry = (ta < carry);
        tp[i] = (tp[i] + ta) & OSSL_FN_MASK;
        carry += (tp[i] < ta);
    }

    /* If still borrow, add m again */
    borrow -= carry;
    for (i = 0, mask = 0 - borrow, carry = 0; i < ml; i++) {
        ta = ((m->d[i] & mask) + carry) & OSSL_FN_MASK;
        carry = (ta < carry);
        tp[i] = (tp[i] + ta) & OSSL_FN_MASK;
        carry += (tp[i] < ta);
    }

    for (i = 0; i < rl && i < ml; i++)
        r->d[i] = tp[i];
    /* Make sure to pad r with zeroes when rl > ml */
    for (; i < rl; i++)
        r->d[i] = 0;

    if (tp != storage)
        OPENSSL_free(tp);

    return 1;
}

size_t OSSL_FN_mod_mul_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *b, const OSSL_FN *m)
{
    size_t tl, own_size, mul_size, mod_size, nested_size;

    if (r == NULL || a == NULL || b == NULL || m == NULL)
        return 0;

    if (a == b) {
        int err = 0;

        tl = safe_mul_size_t(2, a->dsize, &err);
        if (err != 0 || ossl_fn_totalsize(tl) == 0)
            return 0;
        OSSL_FN t = { .dsize = (int)tl };

        mul_size = OSSL_FN_sqr_ctx_size(&t, a);
        mod_size = OSSL_FN_mod_ctx_size(r, &t, m);
    } else {
        int err = 0;

        tl = safe_add_size_t(a->dsize, b->dsize, &err);
        if (err != 0 || ossl_fn_totalsize(tl) == 0)
            return 0;
        OSSL_FN t = { .dsize = (int)tl };

        mul_size = OSSL_FN_mul_ctx_size(&t, a, b);
        mod_size = OSSL_FN_mod_ctx_size(r, &t, m);
    }

    own_size = OSSL_FN_CTX_size(1, 1, tl);
    nested_size = ctx_max_size(mul_size, mod_size);
    if (own_size == 0 || nested_size == 0)
        return 0;

    return ctx_add_size(own_size, nested_size);
}

/* slow but works */
int OSSL_FN_mod_mul(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    const OSSL_FN *m, OSSL_FN_CTX *ctx)
{
    const void *token = OSSL_FN_CTX_start(ctx);
    OSSL_FN *t;
    int ret = 0;

    if (token == NULL)
        return 0;

    if (a == b) {
        size_t tl = 2 * a->dsize;

        if ((t = OSSL_FN_CTX_get_limbs(ctx, tl)) == NULL
            || !OSSL_FN_sqr(t, a, ctx))
            goto err;
    } else {
        size_t tl = a->dsize + b->dsize;

        if ((t = OSSL_FN_CTX_get_limbs(ctx, tl)) == NULL
            || !OSSL_FN_mul(t, a, b, ctx))
            goto err;
    }
    if (!OSSL_FN_mod(r, t, m, ctx))
        goto err;
    ret = 1;
err:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

size_t OSSL_FN_mod_sqr_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *m)
{
    size_t tl, own_size, sqr_size, mod_size, nested_size;

    if (r == NULL || a == NULL || m == NULL)
        return 0;
    int err = 0;

    tl = safe_mul_size_t(2, a->dsize, &err);
    if (err != 0 || ossl_fn_totalsize(tl) == 0)
        return 0;

    OSSL_FN t = { .dsize = (int)tl };

    own_size = OSSL_FN_CTX_size(1, 1, tl);
    sqr_size = OSSL_FN_sqr_ctx_size(&t, a);
    mod_size = OSSL_FN_mod_ctx_size(r, &t, m);
    nested_size = ctx_max_size(sqr_size, mod_size);
    if (own_size == 0 || nested_size == 0)
        return 0;

    return ctx_add_size(own_size, nested_size);
}

int OSSL_FN_mod_sqr(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *m,
    OSSL_FN_CTX *ctx)
{
    const void *token = OSSL_FN_CTX_start(ctx);
    OSSL_FN *t;
    int ret = 0;

    if (token == NULL)
        return 0;
    if ((t = OSSL_FN_CTX_get_limbs(ctx, (size_t)(2 * a->dsize))) == NULL)
        goto err;

    ret = OSSL_FN_sqr(t, a, ctx)
        && OSSL_FN_mod(r, t, m, ctx);

err:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

size_t OSSL_FN_mod_lshift1_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *m)
{
    size_t tl, own_size, nested_size;

    if (r == NULL || a == NULL || m == NULL)
        return 0;
    int err = 0;

    tl = safe_add_size_t(m->dsize, 1, &err);
    if (err != 0 || ossl_fn_totalsize(tl) == 0)
        return 0;

    OSSL_FN t = { .dsize = (int)tl };

    own_size = OSSL_FN_CTX_size(1, 1, tl);
    nested_size = OSSL_FN_mod_ctx_size(r, &t, m);
    if (own_size == 0 || nested_size == 0)
        return 0;

    return ctx_add_size(own_size, nested_size);
}

int OSSL_FN_mod_lshift1(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *m,
    OSSL_FN_CTX *ctx)
{
    const void *token = OSSL_FN_CTX_start(ctx);
    OSSL_FN *t;
    int ret = 0;

    if (token == NULL)
        return 0;
    if ((t = OSSL_FN_CTX_get_limbs(ctx, (size_t)(m->dsize + 1))) == NULL)
        goto err;

    ret = OSSL_FN_lshift1(t, a)
        && OSSL_FN_mod(r, t, m, ctx);

err:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

/* OSSL_FN_mod_lshift1 variant that may be used if a is less than m */
int OSSL_FN_mod_lshift1_quick(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *m)
{
    OSSL_FN *t = OSSL_FN_new_limbs((size_t)(m->dsize + 1));
    int ret = 0;

    if (t == NULL)
        return 0;
    if (!OSSL_FN_lshift1(t, a))
        goto err;
    if (OSSL_FN_cmp(t, m) >= 0) {
        if (!OSSL_FN_sub(t, t, m))
            goto err;
    }
    OSSL_FN_copy_truncate(r, t);
    ret = 1;
err:
    OSSL_FN_free(t);
    return ret;
}

size_t OSSL_FN_mod_lshift_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    int n, const OSSL_FN *m)
{
    size_t ml, own_size, nested_size;

    if (r == NULL || a == NULL || m == NULL)
        return 0;
    (void)n;

    ml = m->dsize;
    if (ossl_fn_totalsize(ml) == 0)
        return 0;

    OSSL_FN ra = { .dsize = (int)ml };

    own_size = OSSL_FN_CTX_size(1, 1, ml);
    nested_size = OSSL_FN_mod_ctx_size(&ra, a, m);
    if (own_size == 0 || nested_size == 0)
        return 0;

    return ctx_add_size(own_size, nested_size);
}

int OSSL_FN_mod_lshift(OSSL_FN *r, const OSSL_FN *a, int n, const OSSL_FN *m,
    OSSL_FN_CTX *ctx)
{
    const void *token = OSSL_FN_CTX_start(ctx);
    OSSL_FN *ra;
    int ret = 0;

    if (token == NULL)
        return 0;
    if ((ra = OSSL_FN_CTX_get_limbs(ctx, m->dsize)) == NULL)
        goto err;

    ret = OSSL_FN_mod(ra, a, m, ctx)
        && OSSL_FN_mod_lshift_quick(r, ra, n, m);

err:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

/* OSSL_FN_mod_lshift variant that may be used if a is less than m */
int OSSL_FN_mod_lshift_quick(OSSL_FN *r, const OSSL_FN *a, int n,
    const OSSL_FN *m)
{
    OSSL_FN *t = NULL;
    int ret = 0;

    if (n <= 0)
        return n == 0 ? (OSSL_FN_copy_truncate(r, a) != NULL) : 0;

    t = OSSL_FN_new_limbs((size_t)(m->dsize + 1));
    if (t == NULL)
        goto err;

    if (OSSL_FN_copy_truncate(t, a) == NULL)
        goto err;

    while (n > 0) {
        size_t m_bits = OSSL_FN_num_bits(m);
        size_t t_bits = OSSL_FN_num_bits(t);
        size_t max_shift;

        /* 0 <= t < m */
        if (m_bits < t_bits) {
            ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_INPUT_NOT_REDUCED);
            goto err;
        }
        max_shift = m_bits - t_bits;

        if (max_shift > (size_t)n)
            max_shift = (size_t)n;

        if (max_shift) {
            int shift = (int)max_shift;

            if (!OSSL_FN_lshift(t, t, shift))
                goto err;
            n -= shift;
        } else {
            if (!OSSL_FN_lshift1(t, t))
                goto err;
            n--;
        }

        if (OSSL_FN_cmp(t, m) >= 0) {
            if (!OSSL_FN_sub(t, t, m))
                goto err;
        }
    }

    if (OSSL_FN_copy_truncate(r, t) == NULL)
        goto err;
    ret = 1;

err:
    OSSL_FN_free(t);
    return ret;
}
