/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "crypto/fnerr.h"
#include "../bn/bn_local.h" /* For using the low level bignum functions */
#include "fn_local.h"

/*
 * ossl_fn_add_words and ossl_fn_sub_words perform fixed-width unsigned
 * addition and subtraction of multi-limb integers.
 *
 * The carry or borrow is always propagated through every limb of both
 * operands (and through any extra result limbs when rl exceeds the operand
 * sizes).  The operation is effectively performed at the precision of the
 * wider operand, then truncated to rl limbs — analogous to performing an
 * unsigned operation in the wider of the operand types and then casting
 * the result to a narrower type.
 *
 * The returned carry (addition) or borrow (subtraction) is the true
 * overflow / borrow out of the most significant processed limb:
 *
 *   - When rl <= max(al, bl), it is the carry / borrow out of max(al, bl)
 *     limbs.  Note that this does NOT indicate whether the result fits in
 *     rl limbs; non-zero high limbs may have been truncated without
 *     generating a carry.  If the caller needs the exact magnitude, rl
 *     must be at least max(al, bl).
 *
 *   - For addition, when rl > max(al, bl), the carry is absorbed into the
 *     result (written to r[max(al,bl)], higher limbs zeroed) and the
 *     function returns 0.
 *
 *   - For subtraction, when rl > max(al, bl), the borrow is propagated
 *     through all remaining result limbs (two's complement sign extension)
 *     and the function returns the borrow out of rl limbs.
 */

/* unsigned addition of a and b, returns carry if there is one past the result size */
OSSL_FN_ULONG ossl_fn_add_words(OSSL_FN_ULONG *r, size_t rl,
    const OSSL_FN_ULONG *a, size_t al,
    const OSSL_FN_ULONG *b, size_t bl)
{
    /*
     * Addition is commutative, so we switch 'a' and 'b' around to
     * ensure that 'a' is physically the largest, so a maximum of
     * work is done with 'bn_add_words'
     */
    if (al < bl) {
        const OSSL_FN_ULONG *tmp;
        size_t tmpl;

        tmp = a;
        tmpl = al;
        a = b;
        al = bl;
        b = tmp;
        bl = tmpl;
    }

    /*
     * Four stages.
     *
     * For each stage, |stage_limbs| is used to hold the number
     * of limbs being treated in that stage, |i| is used as an
     * index into the arrays, and |carry| is used to transport
     * the carry from one stage to the other.
     *
     * Note: |stage_limbs| is passed cast to 'int' when calling
     * bn_add_words().  This is fine because the maximum size of
     * any OSSL_FN_ULONG is BN_MAX_WORDS, which is small enough.
     * Should that change some day, there's trouble ahead.
     */
    size_t stage_limbs;
    OSSL_FN_ULONG carry;
    size_t i;

    /*
     * Stage 1: calculate the least min(rl,bl) limbs
     *
     * This uses bn_add_words, with what performance benefits that gives.
     */

    stage_limbs = (bl > rl) ? rl : bl;
    carry = bn_add_words(r, a, b, (int)stage_limbs);

    /* Record the array position past what bn_add_words calculated */
    i = stage_limbs;

    /*
     * Stage 2: calculate min(rl,bl) to bl limbs
     *
     * Because this loop only engages when rl < bl, it cannot affect r.
     * The only purpose of this loop is to propagate carry in this particular
     * scenario.
     */

    stage_limbs = bl - stage_limbs;

    for (size_t dif = stage_limbs; dif > 0; dif--, i++) {
        OSSL_FN_ULONG t1, t2;

        t1 = (a[i] + carry) & OSSL_FN_MASK;
        carry = (t1 < carry);
        t2 = (b[i] + t1) & OSSL_FN_MASK;
        carry |= (t2 < t1);
    }

    assert(i == bl);

    /*
     * Stage 3: calculate bl to al limbs
     *
     * Note: at any time, the end of r may be reached.  This is solved
     * with a temporary pointer that's set appropriately inside the loop.
     */

    stage_limbs = al - bl;

    for (size_t dif = stage_limbs; dif > 0; dif--, i++) {
        OSSL_FN_ULONG tmp = 0;
        OSSL_FN_ULONG *rp = (i < rl) ? &r[i] : &tmp;
        OSSL_FN_ULONG t1;

        t1 = (a[i] + carry) & OSSL_FN_MASK;
        carry = (t1 < carry);

        *rp = t1;
    }

    assert(i == al);

    /* If |r| is exhausted, there's nothing more to do */
    if (i >= rl)
        return carry;

    /*
     * Stage 4: calculate a final carry, for when rl > al
     *
     * This is relatively simple, compare to earlier loops.
     */

    stage_limbs = rl - al;

    for (size_t dif = stage_limbs; dif > 0; dif--, i++) {
        r[i] = carry;
        carry = 0;
    }

    return carry;
}

int OSSL_FN_add(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b)
{
    (void)ossl_fn_add_words(r->d, r->dsize, a->d, a->dsize, b->d, b->dsize);
    return 1;
}

/*-
 * Adds the single-limb word |w| to |a| in place, propagating the carry
 * through |a|'s limbs and truncating any carry out past a->dsize (OSSL_FN is
 * fixed-size, so a carry past the last limb is discarded rather than grown
 * into).  The degenerate w == 0 case is a no-op.
 *
 * Not constant-time: the carry-propagation loop stops early once the carry
 * is exhausted, so the number of limbs touched depends on the operand's
 * value.
 */
int OSSL_FN_add_word(OSSL_FN *a, OSSL_FN_ULONG w)
{
    size_t i;
    size_t dsize = (size_t)a->dsize;

    if (w == 0)
        return 1;

    for (i = 0; i < dsize && w != 0; i++) {
        OSSL_FN_ULONG l = (a->d[i] + w) & OSSL_FN_MASK;

        a->d[i] = l;
        w = (w > l);
    }
    /* Any remaining carry out past dsize is truncated. */
    return 1;
}

/* unsigned subtraction of b from a, returns borrow if there is one past the result size */
OSSL_FN_ULONG ossl_fn_sub_words(OSSL_FN_ULONG *r, size_t rl,
    const OSSL_FN_ULONG *a, size_t al,
    const OSSL_FN_ULONG *b, size_t bl)
{
    size_t max = (al >= bl) ? al : bl;
    size_t min = (al <= bl) ? al : bl;

    /*
     * Four stages.
     *
     * For each stage, |stage_limbs| is used to hold the number
     * of limbs being treated in that stage, |i| is used as an
     * index into the arrays, and |borrow| is used to transport
     * the borrow from one stage to the other.
     *
     * Note: |stage_limbs| is passed cast to 'int' when calling
     * bn_sub_words().  This is fine because the maximum size of
     * any OSSL_FN_ULONG is BN_MAX_WORDS, which is small enough.
     * Should that change some day, there's trouble ahead.
     */
    size_t stage_limbs;
    OSSL_FN_ULONG borrow;
    size_t i;

    /*
     * Stage 1: calculate the least min(rl,al,bl) limbs
     *
     * This uses bn_sub_words, with what performance benefits that gives.
     */

    stage_limbs = (min > rl) ? rl : min;
    borrow = bn_sub_words(r, a, b, (int)stage_limbs);

    /* Record the array position past what bn_sub_words calculated */
    i = stage_limbs;

    /*
     * Stage 2: calculate the min(rl,al,bl) to min(al,bl) limbs
     *
     * Because this loop only engages when rl < min(al,bl), it cannot affect r.
     * The only purpose of this loop is to propagate borrow in this particular
     * scenario.
     */

    stage_limbs = min - stage_limbs;

    for (size_t dif = stage_limbs; dif > 0; dif--, i++) {
        OSSL_FN_ULONG t1, t2;

        t1 = a[i];
        t2 = (t1 - borrow) & OSSL_FN_MASK;
        borrow = (t2 > t1);
        t1 = b[i];
        t1 = (t2 - t1) & OSSL_FN_MASK;
        borrow |= (t1 > t2);
    }

    assert(i == min);

    /*
     * Stage 3: calculate the min(al,bl) to max(al,bl) limbs
     *
     * Note: at any time, the end of r may be reached.  This is solved
     * with a temporary pointer that's set appropriately inside the loop.
     */

    const OSSL_FN_ULONG *maxp = (al >= bl) ? a : b;
    const OSSL_FN_ULONG s2_mask1 = (al >= bl) ? OSSL_FN_MASK : 0;
    const OSSL_FN_ULONG s2_mask2 = ~s2_mask1;

    stage_limbs = max - min;

    /* calculate the result of borrowing from more significant limbs */
    for (size_t dif = stage_limbs; dif > 0; dif--, i++) {
        OSSL_FN_ULONG tmp = 0;
        OSSL_FN_ULONG *rp = (i < rl) ? &r[i] : &tmp;
        OSSL_FN_ULONG t1, t2;

        t1 = maxp[i] & s2_mask1;
        t2 = (t1 - borrow) & OSSL_FN_MASK;
        borrow = (t2 > t1);
        t1 = maxp[i] & s2_mask2;
        t1 = (t2 - t1) & OSSL_FN_MASK;
        borrow |= (t1 > t2);

        *rp = t1;
    }

    assert(i == max);

    /* If |r| is exhausted, there's nothing more to do */
    if (i >= rl)
        return borrow;

    /*
     * Stage 4: calculate a final borrow, for when rl > max
     *
     * This is relatively simple, compare to earlier loops.
     */

    stage_limbs = rl - max;

    /* Finally, fill in the rest of the result array by borrowing from zeros */
    for (size_t dif = stage_limbs; dif > 0; dif--, i++) {
        OSSL_FN_ULONG t1 = (0 - borrow) & OSSL_FN_MASK;

        borrow = (t1 > 0);

        r[i] = t1;
    }

    return borrow;
}

int OSSL_FN_sub(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b)
{
    (void)ossl_fn_sub_words(r->d, r->dsize, a->d, a->dsize, b->d, b->dsize);
    return 1;
}

/*-
 * Subtracts the single-limb word |w| from |a| in place, propagating the
 * borrow through |a|'s limbs.  If the borrow runs past a->dsize (i.e. the
 * unsigned value of |a| is less than |w|), the result is the 2's-complement
 * wrap-around truncated to dsize, per OSSL_FN's fixed-size unsigned
 * semantics: there is no sign to record, so the wrapped value is kept.  The
 * degenerate w == 0 case is a no-op.
 *
 * Not constant-time: the borrow-propagation loop returns early once the
 * borrow is repaid, so the number of limbs touched depends on the operand's
 * value.
 */
int OSSL_FN_sub_word(OSSL_FN *a, OSSL_FN_ULONG w)
{
    size_t i;
    size_t dsize = (size_t)a->dsize;

    if (w == 0)
        return 1;

    for (i = 0; i < dsize; i++) {
        if (a->d[i] >= w) {
            a->d[i] -= w;
            return 1; /* borrow repaid */
        }
        a->d[i] = (a->d[i] - w) & OSSL_FN_MASK;
        w = 1;
    }
    /* Borrow out past dsize is truncated (2's complement). */
    return 1;
}
