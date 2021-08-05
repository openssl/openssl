/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "bn_local.h"

/* same as bn_mod_inverse_pow2, but with a single word */
static int bn_mod_inverse_pow2_word(BIGNUM *r, const BIGNUM *a, int e)
{
    int i;
    BN_ULONG ibs, x, t0, t1;

    x = 0;
    t0 = a->d[0];
    t1 = 1;

    for (i = 0; i < e; i++) {
        ibs = t1 & 1;
        x |= ibs << i;
        /*-
         * the "0 - " silliness is to avoid MSVC warning C4146:
         * unary minus operator applied to unsigned type, result still unsigned
         */
        t1 = (t1 - (t0 & (0 - ibs))) >> 1;
    }

    return BN_set_word(r, x);
}

/*-
 * Inversion modulo 2**e
 * See Sect. 7, (Koc 2017), "A New Algorithm for Inversion mod p**k",
 * http://eprint.iacr.org/2017/411
 */
static BIGNUM *bn_mod_inverse_pow2(BIGNUM *r, const BIGNUM *a, int e,
                                   BN_CTX *ctx, int *pnoinv)
{
    BIGNUM *rv = NULL, *t0 = NULL, *t1 = NULL, *t2 = NULL;
    BN_ULONG ibs;
    int i, top, wi, bi;

    if (!BN_is_odd(a)) {
        *pnoinv = 1;
        return NULL;
    }

    /* early exit if we can work with a single word instead of BIGNUM */
    if (e <= BN_BITS2)
        return (!bn_mod_inverse_pow2_word(r, a, e)) ? NULL : r;

    BN_CTX_start(ctx);
    t2 = BN_CTX_get(ctx);
    t1 = BN_CTX_get(ctx);
    if ((t0 = BN_CTX_get(ctx)) == NULL
        || !BN_one(t1)
        || BN_copy(t0, a) == NULL
        || !BN_set_bit(t0, e)
        || !(top = t0->top)
        || bn_wexpand(r, top) == NULL
        || bn_wexpand(t1, top) == NULL
        || bn_wexpand(t2, top) == NULL
        || !BN_mask_bits(t0, e))
        goto err;

    BN_zero(r);
    wi = bi = 0;

    for (i = 0; i < e; i++) {
        if (!bi)
            r->d[wi] = 0;
        /* assign bit i value to the result */
        ibs = t1->d[0] & 1 && t1->top;
        r->d[wi] |= ibs << bi;
        /* subtract conditionally on bit i value */
        if (!BN_sub(t2, t1, t0))
            goto err;
        BN_consttime_swap(ibs, t1, t2, top);
        if (!BN_rshift1(t1, t1))
            goto err;

        if (++bi == BN_BITS2) {
            wi++;
            bi = 0;
        }
    }

    r->top = top;
    *pnoinv = 0;
    rv = r;

 err:
    BN_CTX_end(ctx);
    bn_check_top(r);
    return rv;
}

/*-
 * Inversion modulo odd n.
 * Computes the modular inverse using the constant-time algorithm
 * by Bernstein and Yang (https://eprint.iacr.org/2019/266)
 * "Fast constant-time gcd computation and modular inversion"
 */
static BIGNUM *bn_mod_inverse_odd(BIGNUM *in, const BIGNUM *a, const BIGNUM *n,
                                  BN_CTX *ctx, int *pnoinv)
{
    BIGNUM *v = NULL, *r = NULL, *f = NULL, *g = NULL, *temp = NULL, *rv = NULL;
    int i, top, flen, glen, its, cond, delta = 1;

    BN_CTX_start(ctx);
    temp = BN_CTX_get(ctx);
    g = BN_CTX_get(ctx);
    f = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    if ((v = BN_CTX_get(ctx)) == NULL
        || !BN_one(r)
        || BN_copy(g, a) == NULL
        || BN_copy(f, n) == NULL)
        goto err;

    BN_zero(v);

    /* grow BIGNUMs */
    top = 1 + ((f->top >= g->top) ? f->top : g->top);
    if (bn_wexpand(temp, top) == NULL
        || bn_wexpand(g, top) == NULL
        || bn_wexpand(f, top) == NULL
        || bn_wexpand(r, top) == NULL
        || bn_wexpand(v, top) == NULL)
        goto err;

    /* Upper bound for the total iterations. */
    flen = BN_num_bits(f);
    glen = BN_num_bits(g);
    its = 4 + 3 * ((flen >= glen) ? flen : glen);

    for (i = 0; i < its; i++) {
        /* Step 1: conditional swap. */
        /* Set cond if delta > 0 and g is odd. */
        cond = (-delta >> (8 * sizeof(delta) - 1)) & g->d[0] & 1 && g->top;
        /* If cond is set replace (delta,f,v) with (-delta,-f,-v). */
        delta = (-cond & -delta) | ((cond - 1) & delta);
        f->neg ^= cond;
        v->neg ^= cond;
        /* If cond is set swap (f,v) with (g,r). */
        BN_consttime_swap(cond, f, g, top);
        BN_consttime_swap(cond, v, r, top);

        /* Step 2: elemination. */
        /* Update delta */
        delta++;
        /* If g is odd replace r with (r+v). */
        if (!BN_add(temp, r, v))
            goto err;
        cond = g->d[0] & 1 && g->top;
        BN_consttime_swap(cond, r, temp, top);
        /* If g is odd, right shift (g+f) else right shift g. */
        if (!BN_add(temp, g, f))
            goto err;
        cond = g->d[0] & 1 && g->top;
        BN_consttime_swap(cond, g, temp, top);
        if (!BN_rshift1(g, g))
            goto err;
        /*-
         * If r is even, right shift it.
         * If r is odd, right shift (r+n) which is even because n is odd.
         * We want the result modulo n, so adding multiples of n here vanish.
         */
        if (!BN_add(temp, r, n))
            goto err;
        cond = r->d[0] & 1 && r->top;
        BN_consttime_swap(cond, r, temp, top);
        if (!BN_rshift1(r, r))
            goto err;
    }

    /* We have the inverse in v, propagate sign from f. */
    v->neg ^= f->neg;

    /* If f = GCD != 1, not invertible. */
    if (!BN_abs_is_word(f, 1)) {
        *pnoinv = 1;
        goto err;
    }

    /* Return inverse modulo n. */
    if (!BN_nnmod(in, v, n, ctx))
        goto err;

    *pnoinv = 0;
    rv = in;

 err:
    BN_CTX_end(ctx);
    bn_check_top(in);
    return rv;
}

/*
 * This is an internal function, we assume all callers pass valid arguments:
 * all pointers passed here are assumed non-NULL.
 */
BIGNUM *int_bn_mod_inverse(BIGNUM *in, const BIGNUM *a, const BIGNUM *n,
                           BN_CTX *ctx, int *pnoinv)
{
    BIGNUM *rv = NULL, *m_e = NULL, *m_o = NULL, *a_e = NULL, *a_o = NULL;
    int idx_o = 1;

    /* This is invalid input so we don't worry about constant time here */
    if (BN_abs_is_word(n, 1) || BN_is_zero(n)) {
        *pnoinv = 1;
        return NULL;
    }

    /* If the modulus is odd, skip directly to the result */
    if (BN_is_odd(n))
        return bn_mod_inverse_odd(in, a, n, ctx, pnoinv);

    /*-
     * Otherwise, express the modulus as n = m_o * 2**idx_o
     * where m_o is odd. Assumes idx_o is public.
     */
    while (!BN_is_bit_set(n, idx_o))
        idx_o++;

    /* If the modulus is a power of two, skip directly to the result */
    if (BN_num_bits(n) == idx_o + 1)
        return bn_mod_inverse_pow2(in, a, idx_o, ctx, pnoinv);

    /*-
     * Otherwise, we have an even modulus that is not a power of two.
     * Compute the inverses modulo m_o and m_e = 2**idx_o,
     * then combine with the Chinese Remainder Theorem (CRT).
     */
    BN_CTX_start(ctx);
    a_o = BN_CTX_get(ctx);
    a_e = BN_CTX_get(ctx);
    m_o = BN_CTX_get(ctx);

    if ((m_e = BN_CTX_get(ctx)) == NULL)
        goto err;

    BN_zero(m_e);

    /* construct m_o and m_e */
    if (!BN_rshift(m_o, n, idx_o)
        || !BN_set_bit(m_e, idx_o))
        goto err;

    /* Garner's alg for CRT: Handbook of Applied Crypto, 14.5.2, Note 14.75i */
    if (bn_mod_inverse_odd(a_o, a, m_o, ctx, pnoinv) == NULL
        || bn_mod_inverse_pow2(a_e, a, idx_o, ctx, pnoinv) == NULL
        || bn_mod_inverse_pow2(in, m_o, idx_o, ctx, pnoinv) == NULL
        || !BN_sub(a_e, a_e, a_o)
        || !BN_mul(in, in, a_e, ctx)
        /* now the mod m_e part */
        || !BN_set_bit(in, idx_o)
        || !BN_mask_bits(in, idx_o)
        /* result is now in [-2**idx_o + 1, 2**idx_o - 1] */
        || !BN_add(in, in, m_e)
        /* result is now in [1, 2**(idx_o + 1) - 1] */
        || !BN_set_bit(in, idx_o)
        || !BN_mask_bits(in, idx_o)
        /* result is now in [0, 2**idx_o - 1] */
        || !BN_mul(in, in, m_o, ctx)
        || !BN_add(in, in, a_o))
        goto err;

    *pnoinv = 0;
    rv = in;

 err:
    BN_CTX_end(ctx);
    return rv;
}

/* solves ax == 1 (mod n) */
BIGNUM *BN_mod_inverse(BIGNUM *in,
                       const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    BIGNUM *rv = NULL, *a_pos = NULL, *n_pos = NULL;
    int noinv = 0;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new_ex(NULL);
        if (ctx == NULL) {
            ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    }

    BN_CTX_start(ctx);

    /* ensure n is non-negative */
    if (BN_is_negative(n)) {
        if ((n_pos = BN_CTX_get(ctx)) == NULL
            || BN_copy(n_pos, n) == NULL)
            goto err;
        n_pos->neg = 0;
    }

    /* ensure a is non-negative */
    if (BN_is_negative(a) && !BN_is_zero(n)) {
        if ((a_pos = BN_CTX_get(ctx)) == NULL
            || !BN_nnmod(a_pos, a, (n_pos == NULL) ? n : n_pos, ctx))
            goto err;
    }

    rv = int_bn_mod_inverse(in, (a_pos == NULL) ? a : a_pos,
                                (n_pos == NULL) ? n : n_pos, ctx, &noinv);
    if (noinv)
        ERR_raise(ERR_LIB_BN, BN_R_NO_INVERSE);
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return rv;
}

/*-
 * This function is based on the constant-time GCD work by Bernstein and Yang:
 * https://eprint.iacr.org/2019/266
 * Generalized fast GCD function to allow even inputs.
 * The algorithm first finds the shared powers of 2 between
 * the inputs, and removes them, reducing at least one of the
 * inputs to an odd value. Then it proceeds to calculate the GCD.
 * Before returning the resulting GCD, we take care of adding
 * back the powers of two removed at the beginning.
 * Note 1: we assume the bit length of both inputs is public information,
 * since access to top potentially leaks this information.
 */
int BN_gcd(BIGNUM *r, const BIGNUM *in_a, const BIGNUM *in_b, BN_CTX *ctx)
{
    BIGNUM *g, *temp = NULL;
    BN_ULONG mask = 0;
    int i, j, top, rlen, glen, m, bit = 1, delta = 1, cond = 0, shifts = 0, ret = 0;

    /* Note 2: zero input corner cases are not constant-time since they are
     * handled immediately. An attacker can run an attack under this
     * assumption without the need of side-channel information. */
    if (BN_is_zero(in_b)) {
        ret = BN_copy(r, in_a) != NULL;
        r->neg = 0;
        return ret;
    }
    if (BN_is_zero(in_a)) {
        ret = BN_copy(r, in_b) != NULL;
        r->neg = 0;
        return ret;
    }

    bn_check_top(in_a);
    bn_check_top(in_b);

    BN_CTX_start(ctx);
    temp = BN_CTX_get(ctx);
    g = BN_CTX_get(ctx);

    /* make r != 0, g != 0 even, so BN_rshift is not a potential nop */
    if (g == NULL
        || !BN_lshift1(g, in_b)
        || !BN_lshift1(r, in_a))
        goto err;

    /* find shared powers of two, i.e. "shifts" >= 1 */
    for (i = 0; i < r->dmax && i < g->dmax; i++) {
        mask = ~(r->d[i] | g->d[i]);
        for (j = 0; j < BN_BITS2; j++) {
            bit &= mask;
            shifts += bit;
            mask >>= 1;
        }
    }

    /* subtract shared powers of two; shifts >= 1 */
    if (!BN_rshift(r, r, shifts)
        || !BN_rshift(g, g, shifts))
        goto err;

    /* expand to biggest nword, with room for a possible extra word */
    top = 1 + ((r->top >= g->top) ? r->top : g->top);
    if (bn_wexpand(r, top) == NULL
        || bn_wexpand(g, top) == NULL
        || bn_wexpand(temp, top) == NULL)
        goto err;

    /* re arrange inputs s.t. r is odd */
    BN_consttime_swap((~r->d[0]) & 1, r, g, top);

    /* compute the number of iterations */
    rlen = BN_num_bits(r);
    glen = BN_num_bits(g);
    m = 4 + 3 * ((rlen >= glen) ? rlen : glen);

    for (i = 0; i < m; i++) {
        /* conditionally flip signs if delta is positive and g is odd */
        cond = (-delta >> (8 * sizeof(delta) - 1)) & g->d[0] & 1
            /* make sure g->top > 0 (i.e. if top == 0 then g == 0 always) */
            & (~((g->top - 1) >> (sizeof(g->top) * 8 - 1)));
        delta = (-cond & -delta) | ((cond - 1) & delta);
        r->neg ^= cond;
        /* swap */
        BN_consttime_swap(cond, r, g, top);

        /* elimination step */
        delta++;
        if (!BN_add(temp, g, r))
            goto err;
        BN_consttime_swap(g->d[0] & 1 /* g is odd */
                /* make sure g->top > 0 (i.e. if top == 0 then g == 0 always) */
                & (~((g->top - 1) >> (sizeof(g->top) * 8 - 1))),
                g, temp, top);
        if (!BN_rshift1(g, g))
            goto err;
    }

    /* remove possible negative sign */
    r->neg = 0;
    /* add powers of 2 removed, then correct the artificial shift */
    if (!BN_lshift(r, r, shifts)
        || !BN_rshift1(r, r))
        goto err;

    ret = 1;

 err:
    BN_CTX_end(ctx);
    bn_check_top(r);
    return ret;
}
