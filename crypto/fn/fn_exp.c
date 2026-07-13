/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "internal/safe_math.h"
#include "crypto/fnerr.h"
#include "fn_local.h"

/*
 * Exponentiation strategy macros.  Only the simple mod-exp is currently implemented.
 *
 * The Montgomery path (MONT_MUL_MOD), and even-modulus reciprocal remaindering
 * (RECP_MUL_MOD) are placeholders, and left for future implementations.
 *
 * Both the runtime dispatcher (OSSL_FN_mod_exp) and the sizing dispatcher
 * (OSSL_FN_mod_exp_ctx_size) guard against these, so the two always agree on
 * which path a given modulus selects.
 */
#undef MONT_MUL_MOD
#undef RECP_MUL_MOD

OSSL_SAFE_MATH_ADDU(size_t, size_t, OSSL_SAFE_MATH_MAXU(size_t))

/* maximum precomputation table size for *variable* sliding windows */
#define TABLE_SIZE 32

/*
 * Sliding-window size selection: a function of the exponent bit count (a
 * public magnitude), capped at 6, so TABLE_SIZE == 1 << 5 always suffices.
 */
#define OSSL_FN_WINDOW_BITS_FOR_EXPONENT_SIZE(b) \
    ((b) > 671 ? 6 : (b) > 239 ? 5               \
            : (b) > 79         ? 4               \
            : (b) > 23         ? 3               \
                               : 1)

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
 * OSSL_FN_mod_exp_simple_ctx_size() -- arena sizing for OSSL_FN_mod_exp_simple().
 */
size_t OSSL_FN_mod_exp_simple_ctx_size(const OSSL_FN *r,
    const OSSL_FN *a, const OSSL_FN *p, const OSSL_FN *m)
{
    if (r == NULL || a == NULL || p == NULL || m == NULL)
        return 0;

    /* A zero-limb modulus is invalid; ossl_fn_mod_exp_simple() rejects it. */
    if (m->dsize <= 0)
        return 0;

    size_t ml = (size_t)m->dsize;
    /* A zero-limb modulus is invalid; OSSL_FN_mod_exp_simple() rejects it. */
    if (ml == 0 || ossl_fn_totalsize(ml) == 0)
        return 0;

    size_t n_numbers = 1 + 1 + TABLE_SIZE;
    size_t own_size = OSSL_FN_CTX_size(1, n_numbers, n_numbers * ml);

    /* Initial reduction OSSL_FN_mod(val[0], a, m); |a| may be wider than |m|. */
    size_t mod_size = OSSL_FN_mod_ctx_size(NULL, a, m);

    /*
     * Loop multiply OSSL_FN_mod_mul(rr, rr, rr|val, m): all operands are
     * ml-wide, so four |m| pointers model them (sizing reads only dsize).
     * The aliased (a == b, square) sizing dominates the mul sizing, so one
     * call covers both loop steps.
     */
    size_t mul_size = OSSL_FN_mod_mul_ctx_size(m, m, m, m);

    size_t nested_size = ctx_max_size(mod_size, mul_size);
    if (own_size == 0 || nested_size == 0)
        return 0;

    return ctx_add_size(own_size, nested_size);
}

#ifdef MONT_MUL_MOD
static size_t ossl_fn_mod_exp_mont_ctx_size(const OSSL_FN *r,
    const OSSL_FN *a, const OSSL_FN *p, const OSSL_FN *m)
{
    /* Not implemented; see ossl_fn_mod_exp_mont(). */
    return 0;
}
#endif

#ifdef RECP_MUL_MOD
static size_t ossl_fn_mod_exp_recp_ctx_size(const OSSL_FN *r,
    const OSSL_FN *a, const OSSL_FN *p, const OSSL_FN *m)
{
    /* Not implemented; see ossl_fn_mod_exp_recp(). */
    return 0;
}
#endif

/*-
 * OSSL_FN_mod_exp_ctx_size() -- arena sizing for OSSL_FN_mod_exp().
 *
 * Mirrors the OSSL_FN_mod_exp() dispatch under the same strategy macros; the
 * returned size is the exact budget for whichever path the modulus selects.
 */
size_t OSSL_FN_mod_exp_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *p, const OSSL_FN *m)
{
    if (r == NULL || a == NULL || p == NULL || m == NULL)
        return 0;

#ifdef MONT_MUL_MOD
    if (m->dsize > 0 && (m->d[0] & OSSL_FN_ULONG_C(1)))
        return OSSL_FN_mod_exp_mont_ctx_size(r, a, p, m, NULL);
    else
#endif
#ifdef RECP_MUL_MOD
    {
        return ossl_fn_mod_exp_recp_ctx_size(r, a, p, m);
    }
#else
    {
        return OSSL_FN_mod_exp_simple_ctx_size(r, a, p, m);
    }
#endif
}

/*-
 * OSSL_FN_mod_exp_simple() -- sliding-window modular exponentiation (even
 * moduli and the non-Montgomery fallback).  Public: this is the entry point
 * OSSL_FN_mod_exp() dispatches to for even moduli.
 *
 * Not constant-time: branches on the exponent's bits; do not use for secret
 * exponents (see the leak note in OSSL_FN_mod_exp() and TODO(FIXNUM) in
 * OSSL_FN_mod_exp_mont()).  Fixed-width:
 * runs in an ml-limb accumulator |rr|, copy-truncated to |r| at the end, so
 * |r == p| is safe and |r == m| is rejected; |a| is reduced into [0, m) first.
 * OSSL_FN is unsigned.
 */
int OSSL_FN_mod_exp_simple(OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *p, const OSSL_FN *m, OSSL_FN_CTX *ctx)
{
    const void *token = OSSL_FN_CTX_start(ctx);
    int i, j;
    int ret = 0;

    if (token == NULL)
        return 0;

    if (r == m) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    if (OSSL_FN_is_zero(m)) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_DIV_BY_ZERO);
        goto err;
    }

    int bits = (int)OSSL_FN_num_bits(p);
    if (bits == 0) {
        /*
         * TODO(FIXNUM): BN parity returns 1 for 0**0; mathematically
         * undefined, so consider erroring out instead.  Kept as-is until
         * existing call sites are analysed.
         */
        OSSL_FN_clear(r);
        if (!OSSL_FN_is_one(m)) {
            /* Set r = 1 directly; OSSL_FN_one() would raise
             * OSSL_FN_R_RESULT_ARG_TOO_SMALL on a zero-limb r. */
            if (r->dsize > 0)
                r->d[0] = OSSL_FN_ULONG_C(1);
        }
        ret = 1;
        goto err;
    }

    size_t ml = (size_t)m->dsize;

    OSSL_FN *rr = OSSL_FN_CTX_get_limbs(ctx, ml);
    OSSL_FN *d = OSSL_FN_CTX_get_limbs(ctx, ml);
    if (rr == NULL || d == NULL)
        goto err;

    OSSL_FN *val[TABLE_SIZE];

    /* Clear the val[] table so OSSL_FN_CTX_end() never sees stale pointers. */
    for (i = 0; i < TABLE_SIZE; i++)
        val[i] = NULL;

    if ((val[0] = OSSL_FN_CTX_get_limbs(ctx, ml)) == NULL)
        goto err;
    if (!OSSL_FN_mod(val[0], a, m, ctx))
        goto err;
    if (OSSL_FN_is_zero(val[0])) {
        OSSL_FN_clear(r);
        ret = 1;
        goto err;
    }

    int window = OSSL_FN_WINDOW_BITS_FOR_EXPONENT_SIZE(bits);
    if (window > 1) {
        if (!OSSL_FN_mod_mul(d, val[0], val[0], m, ctx))
            goto err;
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            if ((val[i] = OSSL_FN_CTX_get_limbs(ctx, ml)) == NULL)
                goto err;
            if (!OSSL_FN_mod_mul(val[i], val[i - 1], d, m, ctx))
                goto err;
        }
    }

    int start = 1; /* skip the leading mul while the accumulator is still 1 */
    int wstart = bits - 1;
    int wend = 0;

    /* ml > 0 is guaranteed (m is non-zero), so OSSL_FN_one() cannot fail. */
    OSSL_FN_one(rr);

    for (;;) {
        int wvalue;

        if (OSSL_FN_is_bit_set(p, wstart) == 0) {
            if (!start)
                if (!OSSL_FN_mod_mul(rr, rr, rr, m, ctx))
                    goto err;
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        /* wstart is on a set bit; scan forward to find the window end. */
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart < i)
                break;
            if (OSSL_FN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        j = wend + 1;
        if (!start)
            for (i = 0; i < j; i++) {
                if (!OSSL_FN_mod_mul(rr, rr, rr, m, ctx))
                    goto err;
            }

        /* wvalue will be an odd number < 2^window */
        if (!OSSL_FN_mod_mul(rr, rr, val[wvalue >> 1], m, ctx))
            goto err;

        wstart -= wend + 1;
        start = 0;
        if (wstart < 0)
            break;
    }

    if (OSSL_FN_copy_truncate(r, rr) == NULL)
        goto err;
    ret = 1;

err:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

/*-
 * OSSL_FN_mod_exp() -- dispatcher.
 *
 * Prepared to pick among Montgomery (odd modulus), reciprocal-based (even
 * modulus), and a simple fallback, gated by the MONT_MUL_MOD / RECP_MUL_MOD
 * preprocessor symbols.
 */
#ifdef MONT_MUL_MOD
static int ossl_fn_mod_exp_mont(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *p,
    const OSSL_FN *m, OSSL_FN_CTX *ctx)
{
    ERR_raise(ERR_LIB_OSSL_FN, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return 0;
}
#endif

#ifdef RECP_MUL_MOD
static int ossl_fn_mod_exp_recp(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *p,
    const OSSL_FN *m, OSSL_FN_CTX *ctx)
{
    ERR_raise(ERR_LIB_OSSL_FN, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return 0;
}
#endif

int OSSL_FN_mod_exp(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *p,
    const OSSL_FN *m, OSSL_FN_CTX *ctx)
{
#ifdef MONT_MUL_MOD
    if (m->dsize > 0 && (m->d[0] & OSSL_FN_ULONG_C(1))) {
        return ossl_fn_mod_exp_mont(r, a, p, m, ctx);
    } else
#endif
#ifdef RECP_MUL_MOD
    {
        return ossl_fn_mod_exp_recp(r, a, p, m, ctx);
    }
#else
    {
        return OSSL_FN_mod_exp_simple(r, a, p, m, ctx);
    }
#endif
}
