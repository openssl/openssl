/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include "internal/cryptlib.h"
#include "internal/safe_math.h"
#include "internal/constant_time.h"
#include "crypto/fnerr.h"
#include "fn_local.h"

/*
 * Exponentiation strategy macros.
 *
 * The Montgomery path (MONT_MUL_MOD) and the simple fallback are currently
 * implemented.
 *
 * The even-modulus reciprocal remaindering (RECP_MUL_MOD) is a placeholder,
 * left for future implementations.
 *
 * Both the runtime dispatcher (OSSL_FN_mod_exp) and the sizing dispatcher
 * (OSSL_FN_mod_exp_ctx_size) guard against these, so the two always agree on
 * which path a given modulus selects.
 */
#define MONT_MUL_MOD
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

/*
 * The fixed-window Montgomery path assumes the L1 data cache line width of
 * the target processor is at least the following value.
 */
#define MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH (64)
#define MOD_EXP_CTIME_MIN_CACHE_LINE_MASK (MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - 1)

/*
 * Given a pointer value, compute the next address that is a cache line
 * multiple.
 */
#define MOD_EXP_CTIME_ALIGN(x_) \
    ((unsigned char *)(x_) + (MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - (((size_t)(x_)) & (MOD_EXP_CTIME_MIN_CACHE_LINE_MASK))))

/*
 * Window size selection for the fixed-window Montgomery path.  To keep the
 * table gather cache-line uniform, the window size must not exceed
 * log_2(MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH).
 *
 * TODO(FIXNUM): thresholds follow the cache-line-width reasoning above;
 * revisit if dedicated accelerated Montgomery paths appear.
 */
#if MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH == 64

#define OSSL_FN_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE(b) \
    ((b) > 937 ? 6 : (b) > 306 ? 5                     \
            : (b) > 89         ? 4                     \
            : (b) > 22         ? 3                     \
                               : 1)

#elif MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH == 32

#define OSSL_FN_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE(b) \
    ((b) > 306 ? 5 : (b) > 89 ? 4                      \
            : (b) > 22        ? 3                      \
                              : 1)

#endif

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
 * Number of limbs the fixed-window precomputed-powers buffer needs:
 * |numpowers| powers of |ml| limbs each, plus slack to align the buffer to
 * the minimum cache line width within the containing OSSL_FN's limb array.
 * Returns 0 on overflow (the buffer must fit in one OSSL_FN, whose limb
 * count is an int).
 */
static int mod_exp_mont_power_limbs(size_t *power_limbs, size_t numpowers,
    size_t ml)
{
    size_t slack = MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH / OSSL_FN_BYTES;

    if (ml == 0 || numpowers > ((size_t)INT_MAX - slack) / ml)
        return 0;
    *power_limbs = numpowers * ml + slack;
    return 1;
}

/*
 * Read a limb's worth of exponent bits starting at |bitpos|.  Reads at
 * fixed offsets derived from the (public) bit position only; the bounds
 * checks are width-based, not value-based.
 */
static OSSL_FN_ULONG fn_get_bits(const OSSL_FN *a, size_t bitpos)
{
    OSSL_FN_ULONG ret = 0;
    size_t wordpos = bitpos / OSSL_FN_BITS;

    bitpos %= OSSL_FN_BITS;
    if (wordpos < (size_t)a->dsize) {
        ret = a->d[wordpos];
        if (bitpos != 0) {
            ret >>= bitpos;
            if (++wordpos < (size_t)a->dsize)
                ret |= a->d[wordpos] << (OSSL_FN_BITS - bitpos);
        }
    }
    return ret;
}

/*
 * The fixed-window Montgomery path stores the precomputed powers in a
 * strided layout -- limb i of power j lives at table[j + i * width] -- so
 * that gathering any power shows the same cache-line access pattern
 * regardless of the exponent's value.  These helpers transfer an OSSL_FN
 * to and from that table.
 */
static void mod_exp_ctime_copy_to_prebuf(const OSSL_FN *b,
    OSSL_FN_ULONG *table, size_t idx, size_t width)
{
    size_t i, j;
    size_t top = (size_t)b->dsize;

    for (i = 0, j = idx; i < top; i++, j += width)
        table[j] = b->d[i];
}

static void mod_exp_ctime_copy_from_prebuf(OSSL_FN *b,
    const OSSL_FN_ULONG *buf, size_t idx, size_t window, size_t top)
{
    size_t i, j;
    size_t width = (size_t)1 << window;
    /*
     * We declare table 'volatile' in order to discourage the compiler from
     * reordering loads from the table.  The concern is that if reordered
     * in a specific manner, loads might give away the information we are
     * trying to conceal.
     */
    volatile OSSL_FN_ULONG *table = (volatile OSSL_FN_ULONG *)buf;

    if (window <= 3) {
        for (i = 0; i < top; i++, table += width) {
            OSSL_FN_ULONG acc = 0;

            for (j = 0; j < width; j++) {
                acc |= table[j]
                    & ((OSSL_FN_ULONG)0
                        - (constant_time_eq_int((int)j, (int)idx) & 1));
            }
            b->d[i] = acc;
        }
    } else {
        size_t xstride = (size_t)1 << (window - 2);
        OSSL_FN_ULONG y0, y1, y2, y3;

        i = idx >> (window - 2); /* equivalent of idx / xstride */
        idx &= xstride - 1; /* equivalent of idx % xstride */

        y0 = (OSSL_FN_ULONG)0 - (constant_time_eq_int((int)i, 0) & 1);
        y1 = (OSSL_FN_ULONG)0 - (constant_time_eq_int((int)i, 1) & 1);
        y2 = (OSSL_FN_ULONG)0 - (constant_time_eq_int((int)i, 2) & 1);
        y3 = (OSSL_FN_ULONG)0 - (constant_time_eq_int((int)i, 3) & 1);

        for (i = 0; i < top; i++, table += width) {
            OSSL_FN_ULONG acc = 0;

            for (j = 0; j < xstride; j++) {
                acc |= ((table[j + 0 * xstride] & y0)
                           | (table[j + 1 * xstride] & y1)
                           | (table[j + 2 * xstride] & y2)
                           | (table[j + 3 * xstride] & y3))
                    & ((OSSL_FN_ULONG)0
                        - (constant_time_eq_int((int)j, (int)idx) & 1));
            }
            b->d[i] = acc;
        }
    }
}

/*-
 * mod_exp_mont_nested() -- Montgomery-path nested arena size for
 * OSSL_FN_mod_exp_mont().  |own_size| is added by the callers.  Nested frames
 * are sequential, so the size is their max.
 *
 * |in_mont| mirrors OSSL_FN_mod_exp_mont(): NULL models the function-owned
 * context, a real value sizes for a reused one.  Both give the same size:
 * to_mont_ctx_size() gates |a|'s reduction on a comparison against |N|, and
 * |N| equals |m| either way (the model points it at |m|; a reused context
 * holds a copy made by OSSL_FN_MONT_CTX_new()).  The loop and from_mont
 * operate on reduced ml-wide Montgomery-domain values; their sizing helpers
 * read only mont->N->dsize (== ml), so those operands are not modelled here.
 */
static size_t mod_exp_mont_nested(const OSSL_FN *a, const OSSL_FN *m,
    OSSL_FN_MONT_CTX *in_mont)
{
    OSSL_FN_MONT_CTX mont_model = { .N = m };
    size_t mont_size;

    if (in_mont == NULL)
        in_mont = &mont_model;

    /*
     * to_mont / loop mul_mont_quick / from_mont, via their ctx_size
     * companions in fn_mont.c; only one is live at a time, so take the max.
     * to_mont() performs the initial reduction of a internally (via the
     * reducing OSSL_FN_mul_mont), so no separate OSSL_FN_mod() frame is
     * sized.  The fixed-window loop multiplies only already-reduced
     * Montgomery-domain values, so it uses the non-reducing
     * OSSL_FN_mul_mont_quick() and its smaller ctx_size.
     */
    mont_size = ctx_max_size(OSSL_FN_to_mont_ctx_size(NULL, a, in_mont),
        ctx_max_size(OSSL_FN_mul_mont_quick_ctx_size(NULL, NULL, NULL, in_mont),
            OSSL_FN_from_mont_ctx_size(NULL, NULL, in_mont)));

    return mont_size;
}

/*-
 * OSSL_FN_mod_exp_mont_ctx_size() -- arena sizing for OSSL_FN_mod_exp_mont().
 * Sizes only the Montgomery path; see mod_exp_mont_nested() for the |in_mont|
 * modelling and the NULL/reused equivalence.
 */
size_t OSSL_FN_mod_exp_mont_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *p, const OSSL_FN *m, OSSL_FN_MONT_CTX *in_mont)
{
    if (a == NULL || p == NULL || m == NULL)
        return 0;

    size_t ml = (size_t)m->dsize;
    /* A zero-limb modulus is invalid; OSSL_FN_mod_exp_mont() rejects it. */
    if (ml == 0 || ossl_fn_totalsize(ml) == 0)
        return 0;

    /*
     * The window size derives from the exponent's width only, so the sizing
     * matches the runtime choice exactly.
     */
    size_t bits = (size_t)p->dsize * OSSL_FN_BITS;
    size_t window = OSSL_FN_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE(bits);
    size_t power_limbs;

    if (!mod_exp_mont_power_limbs(&power_limbs, (size_t)1 << window, ml))
        return 0;

    /* power table, accumulator (tmp), gathered power (am) */
    size_t n_numbers = 3;
    size_t own_size = OSSL_FN_CTX_size(1, n_numbers, power_limbs + 2 * ml);

    size_t nested_size = mod_exp_mont_nested(a, m, in_mont);
    if (own_size == 0 || nested_size == 0)
        return 0;

    return ctx_add_size(own_size, nested_size);
}

/*
 * OSSL_FN_mod_exp_simple_ctx_size() -- arena sizing for OSSL_FN_mod_exp_simple().
 */
size_t OSSL_FN_mod_exp_simple_ctx_size(const OSSL_FN *r,
    const OSSL_FN *a, const OSSL_FN *p, const OSSL_FN *m)
{
    if (r == NULL || a == NULL || p == NULL || m == NULL)
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
 * Dispatches on the modulus parity, exactly like OSSL_FN_mod_exp(), so the
 * two always agree on which path a given modulus selects.
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
 * OSSL_FN_mod_exp_mont() -- Montgomery fixed-window modular exponentiation
 * (odd moduli).  Public: callers reusing a Montgomery context across
 * exponentiations with the same modulus may call directly and pass |in_mont|
 * (mirroring BN_mod_exp_mont()); NULL => build and free a temporary one.  A
 * non-NULL |in_mont| is borrowed (never freed here) and its modulus must be
 * |m|.
 *
 * Constant-time profile:
 *   - Fixed-width windows over the exponent's full allocation width; the
 *     window size and the loop iteration count depend only on |p|'s and
 *     |m|'s widths, never on their values, and there is no early exit on
 *     the exponent's value.
 *   - The precomputed powers are stored in a strided table layout and
 *     gathered with value-masked selection (every table entry is read at
 *     fixed offsets and combined with masks), so the table access pattern
 *     does not depend on the exponent's value.
 *   - What may leak: the operand widths (which set the window size and
 *     iteration count) and the modulus: the m == 1 early exit (a degenerate
 *     case that never occurs in cryptographic calculations), the parity
 *     dispatch, and the mont(1) init branch on m's top bit all branch on
 *     the modulus, which is public.
 *
 * Fixed-width: OSSL_FN_mul_mont / OSSL_FN_from_mont require ml-limb, <N
 * operands, so the algorithm runs in ml-limb accumulators, copy-truncated
 * to |r| at the end (|r == p| / |r == a| safe, |r == m| rejected); |a| is
 * reduced by to_mont() itself.  OSSL_FN is unsigned; |m| is odd by dispatch.
 */
int OSSL_FN_mod_exp_mont(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *p,
    const OSSL_FN *m, OSSL_FN_CTX *ctx, OSSL_FN_MONT_CTX *in_mont)
{
    const void *token = OSSL_FN_CTX_start(ctx);
    OSSL_FN_MONT_CTX *mont = NULL;
    OSSL_FN *powerfn = NULL;
    OSSL_FN_ULONG *powerbuf = NULL;
    size_t table_limbs = 0;
    size_t i;
    int ret = 0;

    if (token == NULL)
        return 0;

    if (r == m) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    /*
     * Defensive: dispatcher routes only odd moduli and OSSL_FN_MONT_CTX_new()
     * rejects even ones, but diagnose explicitly.
     */
    if (m->dsize <= 0 || (m->d[0] & OSSL_FN_ULONG_C(1)) == 0) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    /*
     * m == 1: the result is always zero.  Exited explicitly (branching on
     * the modulus is public, like the parity dispatch above) because the
     * mont(1) accumulator init below assumes N > 1; with N == 1, to_mont(1)
     * would force a reduction that the sizing model does not budget.
     */
    if (OSSL_FN_is_one(m)) {
        OSSL_FN_clear(r);
        ret = 1;
        goto err;
    }

    size_t ml = (size_t)m->dsize;

    /*
     * Use all bits allocated for |p| rather than scanning for the most
     * significant set bit, so the loop count does not leak whether the top
     * bits are zero.  An exponent of value zero in a non-zero-width |p|
     * therefore flows through the loop and yields 1 naturally (table entry
     * 0 holds mont(1), and multiplying by it is the identity).
     */
    size_t bits = (size_t)p->dsize * OSSL_FN_BITS;
    if (bits == 0) {
        /*
         * TODO(FIXNUM): BN parity returns 1 for 0**0; mathematically
         * undefined, so consider erroring out instead.  Kept as-is until
         * existing call sites are analysed.
         */
        OSSL_FN_clear(r);
        if (r->dsize > 0)
            r->d[0] = OSSL_FN_ULONG_C(1);
        ret = 1;
        goto err;
    }

    size_t window = OSSL_FN_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE(bits);
    size_t numpowers = (size_t)1 << window;
    size_t power_limbs;

    if (!mod_exp_mont_power_limbs(&power_limbs, numpowers, ml)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    table_limbs = numpowers * ml;

    OSSL_FN *tmp = OSSL_FN_CTX_get_limbs(ctx, ml);
    OSSL_FN *am = OSSL_FN_CTX_get_limbs(ctx, ml);

    powerfn = OSSL_FN_CTX_get_limbs(ctx, power_limbs);
    if (tmp == NULL || am == NULL || powerfn == NULL)
        goto err;
    powerbuf = (OSSL_FN_ULONG *)MOD_EXP_CTIME_ALIGN(powerfn->d);
    /*
     * No memset of the table: every slot of every power is written by
     * mod_exp_ctime_copy_to_prebuf() below, since the copied values are all
     * ml limbs wide.
     */

    if (in_mont != NULL) {
        /* A reused context must have been built for this same modulus. */
        /*
         * TODO(FIXNUM): the width check shouldn't be necessary; a size
         * difference should generally not matter.  Reconsider if the mont
         * functions are ever made width-agnostic.
         */
        if (m->dsize != in_mont->N->dsize || OSSL_FN_cmp(m, in_mont->N) != 0) {
            ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_INVALID_ARGUMENT);
            goto err;
        }
        mont = in_mont;
    } else {
        mont = OSSL_FN_MONT_CTX_new(m);
        if (mont == NULL)
            goto err;
    }

    /*
     * a^0 = mont(1) = R mod N.  When N's top bit is set, R mod N == R - N
     * (the two's complement of N); otherwise convert 1 to Montgomery form.
     * Branches on the modulus, which is public.
     */
    if (m->d[ml - 1] & OSSL_FN_HIGH_BIT_MASK) {
        tmp->d[0] = OSSL_FN_ULONG_C(0) - m->d[0];
        for (i = 1; i < ml; i++)
            tmp->d[i] = ~m->d[i];
    } else {
        /* ml > 0 is guaranteed, so OSSL_FN_one() cannot fail. */
        if (!ossl_assert(OSSL_FN_one(am)))
            goto err;
        if (!OSSL_FN_to_mont(tmp, am, mont, ctx))
            goto err;
    }
    mod_exp_ctime_copy_to_prebuf(tmp, powerbuf, 0, numpowers);

    /*
     * a^1 in Montgomery domain.  to_mont() reduces a modulo m internally
     * when a is not already reduced, so no separate OSSL_FN_mod() is
     * needed.  When a == 0 (mod m), mont(a) == 0 and the fixed-window loop
     * yields 0 for any non-zero exponent.
     */
    if (!OSSL_FN_to_mont(am, a, mont, ctx))
        goto err;
    mod_exp_ctime_copy_to_prebuf(am, powerbuf, 1, numpowers);

    /* a^i = a^(i-1) * a for i = 2..numpowers-1 */
    if (window > 1) {
        if (!OSSL_FN_mul_mont_quick(tmp, am, am, mont, ctx))
            goto err;
        mod_exp_ctime_copy_to_prebuf(tmp, powerbuf, 2, numpowers);
        for (i = 3; i < numpowers; i++) {
            if (!OSSL_FN_mul_mont_quick(tmp, am, tmp, mont, ctx))
                goto err;
            mod_exp_ctime_copy_to_prebuf(tmp, powerbuf, i, numpowers);
        }
    }

    /*
     * The exponent may not have a whole number of fixed-size windows.  To
     * simplify the main loop, the initial window has between 1 and
     * full-window-size bits such that what remains is always a whole
     * number of windows.
     */
    size_t window0 = (bits - 1) % window + 1;
    size_t wmask = ((size_t)1 << window0) - 1;

    bits -= window0;
    size_t wvalue = fn_get_bits(p, bits) & wmask;

    mod_exp_ctime_copy_from_prebuf(tmp, powerbuf, wvalue, window, ml);

    wmask = ((size_t)1 << window) - 1;
    /*
     * Scan the exponent one window at a time starting from the most
     * significant bits.
     */
    while (bits > 0) {
        /* Square the result window-size times */
        for (i = 0; i < window; i++) {
            if (!OSSL_FN_mul_mont_quick(tmp, tmp, tmp, mont, ctx))
                goto err;
        }

        /*
         * Get a window's worth of bits from the exponent, at fixed offsets,
         * rather than testing bit by bit (each per-bit test would make that
         * bit individually vulnerable to EM-style side-channel attacks).
         */
        bits -= window;
        wvalue = fn_get_bits(p, bits) & wmask;

        /* Fetch the appropriate pre-computed power from the table */
        mod_exp_ctime_copy_from_prebuf(am, powerbuf, wvalue, window, ml);

        /* Multiply the result into the intermediate result */
        if (!OSSL_FN_mul_mont_quick(tmp, tmp, am, mont, ctx))
            goto err;
    }

    /* from_mont needs an ml-limb destination; reuse |am| and copy-truncate to |r|. */
    if (!OSSL_FN_from_mont(am, tmp, mont, ctx))
        goto err;
    if (OSSL_FN_copy_truncate(r, am) == NULL)
        goto err;
    ret = 1;

err:
    /* The table holds powers of a possibly secret base; cleanse it. */
    if (powerbuf != NULL)
        OPENSSL_cleanse(powerbuf, table_limbs * OSSL_FN_BYTES);
    if (in_mont == NULL)
        OSSL_FN_MONT_CTX_free(mont);
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

/*-
 * OSSL_FN_mod_exp() -- dispatcher.
 *
 * Pick among Montgomery (odd modulus), reciprocal-based (even modulus),
 * and a simple fallback, gated by the MONT_MUL_MOD / RECP_MUL_MOD
 * preprocessor symbols.
 */
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
        return OSSL_FN_mod_exp_mont(r, a, p, m, ctx, NULL);
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
