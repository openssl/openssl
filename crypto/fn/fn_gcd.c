/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You may obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <openssl/err.h>
#include "internal/safe_math.h"
#include "crypto/cryptlib.h"
#include "crypto/fnerr.h"
#include "internal/constant_time.h"
#include "fn_local.h"

OSSL_SAFE_MATH_MULU(size_t, size_t, OSSL_SAFE_MATH_MAXU(size_t))

/*
 * Constant-time helpers.
 *
 * OSSL_FN values are fixed-width: there is no |top|, so any zero/nonzero
 * classification must scan the full |dsize|.  These helpers perform such scans
 * without branching on the scanned value.  They branch only on the (public)
 * limb count.
 */

/* Returns all-ones if |a| is zero, zero otherwise. */
static OSSL_FN_ULONG ossl_fn_ct_is_zero_mask(const OSSL_FN *a)
{
    OSSL_FN_ULONG acc = 0;

    for (int i = 0; i < a->dsize; i++)
        acc |= a->d[i];

    return constant_time_is_zero_bn(acc);
}

/*
 * Returns all-ones if |a| is odd, zero otherwise.  Odd implies non-zero
 * (d[0] & 1 == 1 implies d[0] >= 1), so a separate full-width non-zero
 * scan would not affect the result and is omitted: testing d[0] alone is
 * sufficient and avoids an extra scan of the whole |dsize|.
 *
 * Precondition: |a| has at least one limb (dsize >= 1), so a->d[0] is a
 * valid access.  In OSSL_FN_gcd() the operands are always allocated with
 * scratch = max(dsize) + 1 >= 1 limbs.
 */
static OSSL_FN_ULONG ossl_fn_ct_odd_mask(const OSSL_FN *a)
{
    return 0 - (a->d[0] & 1);
}

/*
 * Conditionally swap the limb contents of |a| and |b|, and the accompanying
 * sign flags, without branching on |mask|.  |mask| is all-ones to swap or
 * zero to leave both untouched.  |a| and |b| must have the same |dsize|,
 * which is asserted below.  The limbs are swapped with a per-limb XOR under
 * |mask|, and the sign flags with a masked XOR of their low bit.
 */
static int ossl_fn_ct_swap(OSSL_FN_ULONG mask, OSSL_FN *a, OSSL_FN *b,
    int *aneg, int *bneg)
{
    if (!ossl_assert(a->dsize == b->dsize))
        return 0;

    for (int i = 0; i < a->dsize; i++) {
        OSSL_FN_ULONG t = (a->d[i] ^ b->d[i]) & mask;

        a->d[i] ^= t;
        b->d[i] ^= t;
    }

    int bit = (int)(mask & (OSSL_FN_ULONG)1);
    int t = (*aneg ^ *bneg) & bit;

    *aneg ^= t;
    *bneg ^= t;
    return 1;
}

/*
 * Compute r = a + b as a signed sum, where |aneg|/|bneg| carry the signs of
 * |a|/|b| (0 = non-negative, 1 = negative).  |rneg| receives the sign of the
 * result.  OSSL_FN storage is unsigned, so the magnitude operation is chosen
 * with ordinary branches on the sign flags: same signs add (OSSL_FN_add),
 * opposite signs subtract the smaller magnitude from the larger
 * (OSSL_FN_sub, selected via OSSL_FN_cmp()).  That add/subtract selection is
 * the only value-dependent branch; the trailing zero-sign normalisation is
 * performed in constant time.
 */
static int ossl_fn_signed_add(OSSL_FN *r, int *rneg,
    const OSSL_FN *a, int aneg, const OSSL_FN *b, int bneg)
{
    OSSL_FN_ULONG z;

    if (aneg == bneg) {
        if (!OSSL_FN_add(r, a, b))
            return 0;
        *rneg = aneg;
    } else if (OSSL_FN_cmp(a, b) >= 0) {
        if (!OSSL_FN_sub(r, a, b))
            return 0;
        *rneg = aneg;
    } else {
        if (!OSSL_FN_sub(r, b, a))
            return 0;
        *rneg = bneg;
    }

    /*
     * A zero result is non-negative; clear the sign without branching.
     * OSSL_FN_add() / OSSL_FN_sub() are unsigned and carry no sign, so the
     * non-negative-zero guard is applied here on the external |rneg| flag in
     * constant time.
     */
    z = ossl_fn_ct_is_zero_mask(r);
    *rneg = constant_time_select_int((unsigned int)z, 0, *rneg);

    return 1;
}

size_t OSSL_FN_gcd_ctx_size(const OSSL_FN *a, const OSSL_FN *b)
{
    size_t max, scratch, limbs;
    int err = 0;

    if (a == NULL || b == NULL)
        return 0;

    /*
     * dsize is an int, so max <= INT_MAX and max + 1 cannot overflow a
     * size_t.  The 4 * scratch product is checked via safe_mul_size_t.
     */
    max = (size_t)((a->dsize > b->dsize) ? a->dsize : b->dsize);
    scratch = max + 1;
    limbs = safe_mul_size_t(4, scratch, &err);

    return err == 0 ? OSSL_FN_CTX_size(1, 4, limbs) : 0;
}

int OSSL_FN_gcd(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    OSSL_FN_CTX *ctx)
{
    const void *token = OSSL_FN_CTX_start(ctx);
    if (token == NULL)
        return 0;

    int ret = 0;
    size_t al = (size_t)a->dsize;
    size_t bl = (size_t)b->dsize;
    size_t max = al > bl ? al : bl;
    size_t scratch = max + 1;
    OSSL_FN *u = NULL, *v = NULL, *t = NULL, *rr = NULL;
    int uneg = 0, vneg = 0, tneg = 0, delta = 1;
    int shift;
    size_t ubits, vbits, m;

    if ((u = OSSL_FN_CTX_get_limbs(ctx, scratch)) == NULL
        || (v = OSSL_FN_CTX_get_limbs(ctx, scratch)) == NULL
        || (t = OSSL_FN_CTX_get_limbs(ctx, scratch)) == NULL
        || (rr = OSSL_FN_CTX_get_limbs(ctx, scratch)) == NULL)
        goto err;

    /*
     * Constant-time binary GCD (Bernstein-Yang style).  Control flow is
     * mask-driven throughout so that limb values never select a branch:
     *
     *   - The shared power of two is removed via a constant-time scan over
     *     u | v (the |pow2_*| block below) rather than a value-branching
     *     trailing-zero count.
     *   - The loop condition, conditional swaps, conditional delta negation,
     *     and sign flips are all computed as masks and applied with
     *     ossl_fn_ct_swap(), never with "if (cond) swap".
     *   - Zero inputs are not short-circuited.  This is a deliberate
     *     constant-time strengthening: gcd(0, x) = x and gcd(0, 0) = 0 are
     *     reduced through the loop instead of via early returns.  The
     *     oversized |shift| that an all-zero u | v produces is safe:
     *     OSSL_FN_rshift() / OSSL_FN_lshift() zero the result when the shift
     *     reaches or exceeds the width.
     *
     *   - The per-iteration zero-sign normalisation (in ossl_fn_signed_add()
     *     and after OSSL_FN_rshift1()) keeps intermediates from going
     *     negative zero.  OSSL_FN_add() / OSSL_FN_sub() / OSSL_FN_rshift1()
     *     are unsigned and carry no sign, so that guard is applied here on the
     *     external rneg/vneg flags, in constant time.
     *
     * What still leaks: the iteration count |m| (derived from
     * OSSL_FN_num_bits(), which reveals input magnitudes), and the
     * add/subtract selection inside ossl_fn_signed_add().  Limb values
     * themselves do not drive any branch.
     *
     * The loop treats |u|, |v|, and |t| as signed intermediate values via the
     * separate |uneg|, |vneg|, and |tneg| flags.  OSSL_FN remains unsigned
     * throughout; the flags only choose the correct unsigned add/sub for these
     * intermediates, and travel with the values through ossl_fn_ct_swap().
     */
    if (!OSSL_FN_lshift1(u, a)
        || !OSSL_FN_lshift1(v, b))
        goto err;

    /*
     * Find the shared power of two as v2(u | v).  Since u = 2*a and v = 2*b,
     * this equals 1 + min(v2(a), v2(b)), which is exactly the |shift| to
     * remove (the artificial lshift1 bit plus the shared trailing zeros).
     * The scan counts trailing zero limbs and captures the first non-zero OR
     * limb without branching on limb values.
     */
    OSSL_FN_ULONG pow2_flag = (OSSL_FN_ULONG)1;
    OSSL_FN_ULONG pow2_numbits = 0;
    int pow2_shifts = 0;

    for (int i = 0; i < u->dsize; i++) {
        OSSL_FN_ULONG temp = u->d[i] | v->d[i];
        OSSL_FN_ULONG cond = constant_time_is_zero_bn(pow2_flag);

        pow2_flag &= constant_time_is_zero_bn(temp);
        pow2_shifts += (int)pow2_flag;
        pow2_numbits = constant_time_select_bn(cond, pow2_numbits, temp);
    }

    pow2_numbits = ~pow2_numbits;
    pow2_shifts *= OSSL_FN_BITS;
    pow2_flag = (OSSL_FN_ULONG)1;
    for (int j = 0; j < OSSL_FN_BITS; j++) {
        pow2_flag &= pow2_numbits;
        pow2_shifts += (int)pow2_flag;
        pow2_numbits >>= 1;
    }

    shift = pow2_shifts;

    if (!OSSL_FN_rshift(u, u, shift)
        || !OSSL_FN_rshift(v, v, shift))
        goto err;

    /* Rearrange so that u is odd, without branching on u's value. */
    if (!ossl_fn_ct_swap(0 - (OSSL_FN_ULONG)(~u->d[0] & 1), u, v,
            &uneg, &vneg))
        goto err;

    ubits = OSSL_FN_num_bits(u);
    vbits = OSSL_FN_num_bits(v);
    m = ubits > vbits ? ubits : vbits;
    if (m > ((size_t)INT_MAX - 4) / 3)
        goto err;
    m = 4 + 3 * m;

    for (size_t i = 0; i < m; i++) {
        /*
         * Conditionally flip signs if delta is positive and v is odd and
         * non-zero.  |cond| is a full-width all-ones/zero mask used for the
         * constant-time swap; |condb| is the 0/1 bit used for the delta and
         * sign arithmetic.
         */
        OSSL_FN_ULONG v_odd = ossl_fn_ct_odd_mask(v);
        OSSL_FN_ULONG delta_pos = 0
            - (OSSL_FN_ULONG)(((unsigned int)-delta
                                  >> (8 * sizeof(delta) - 1))
                & 1u);
        OSSL_FN_ULONG cond = delta_pos & v_odd;
        unsigned int condb = (unsigned int)(cond & (OSSL_FN_ULONG)1);

        delta = ((0 - condb) & (unsigned int)-delta)
            | ((condb - 1) & (unsigned int)delta);
        uneg ^= (int)condb;
        if (!ossl_fn_ct_swap(cond, u, v, &uneg, &vneg))
            goto err;

        /* Elimination step: t = v + u (signed). */
        delta++;
        if (!ossl_fn_signed_add(t, &tneg, v, vneg, u, uneg))
            goto err;

        /* If v is odd and non-zero, v = t.  Recompute after the swap above. */
        v_odd = ossl_fn_ct_odd_mask(v);
        if (!ossl_fn_ct_swap(v_odd, v, t, &vneg, &tneg))
            goto err;

        if (!OSSL_FN_rshift1(v, v))
            goto err;

        /*
         * A zero v is non-negative; clear the sign without branching.
         * OSSL_FN_rshift1() is unsigned and carries no sign, so the
         * non-negative-zero guard is applied here on |vneg| in constant time.
         */
        OSSL_FN_ULONG z = ossl_fn_ct_is_zero_mask(v);
        vneg = constant_time_select_int((unsigned int)z, 0, vneg);
    }

    if (!OSSL_FN_lshift(rr, u, shift)
        || !OSSL_FN_rshift1(rr, rr))
        goto err;

    OSSL_FN_copy_truncate(r, rr);
    ret = 1;
err:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}
