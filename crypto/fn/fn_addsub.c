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

/* add of b to a. */
/* unsigned add of b to a, r can be equal to a or b. */
int OSSL_FN_add(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b)
{
    /*
     * Addition is commutative, so we switch 'a' and 'b' around to
     * ensure that 'a' is physically the largest, so a maximum of
     * work is done with 'bn_add_words'
     */
    if (a->dsize < b->dsize) {
        const OSSL_FN *tmp;

        tmp = a;
        a = b;
        b = tmp;
    }

    /* At this point, we know that a->dsize >= b->dsize */
    size_t max = a->dsize;
    size_t min = b->dsize;
    size_t rs = r->dsize;
    const OSSL_FN_ULONG *ap = a->d;
    const OSSL_FN_ULONG *bp = b->d;
    OSSL_FN_ULONG *rp = r->d;

    /*
     * Three stages, after which there's a possible return.
     * Each stage is limited by the number of remaining limbs
     * in |r|.
     *
     * For each stage, |stage_limbs| is used to hold the number
     * of limbs being treated in that stage, and |carry| is
     * used to transport the carry from one stage to the other.
     */
    size_t stage_limbs;
    OSSL_FN_ULONG carry;

    /* Stage 1 */

    stage_limbs = (min > rs) ? rs : min;
    carry = bn_add_words(rp, ap, bp, (int)stage_limbs);
    if (stage_limbs == rs)
        return 1;

    /* At this point, we know that |min| limbs have been used so far */
    rp += min;
    ap += min;

    /* Stage 2 */

    stage_limbs = ((max > rs) ? rs : max) - min;

    for (size_t dif = stage_limbs; dif > 0; dif--, ap++, rp++) {
        OSSL_FN_ULONG t1 = *ap;
        OSSL_FN_ULONG t2 = (t1 + carry) & OSSL_FN_MASK;

        *rp = t2;
        carry &= (t2 == 0);
    }
    if (stage_limbs == rs - min)
        return 1;

    /* Stage 3 */

    /* We know that |max| limbs have been used */
    stage_limbs = rs - max;

    for (size_t dif = stage_limbs; dif > 0; dif--, rp++) {
        OSSL_FN_ULONG t1 = 0;
        OSSL_FN_ULONG t2 = (t1 + carry) & OSSL_FN_MASK;

        *rp = carry;
        carry &= (t2 == 0);
    }

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

/* unsigned subtraction of b from a */
int OSSL_FN_sub(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b)
{
    size_t max = (a->dsize >= b->dsize) ? a->dsize : b->dsize;
    size_t min = (a->dsize <= b->dsize) ? a->dsize : b->dsize;
    size_t rs = r->dsize;
    const OSSL_FN_ULONG *ap = a->d;
    const OSSL_FN_ULONG *bp = b->d;
    OSSL_FN_ULONG *rp = r->d;

    /*
     * Three stages, after which there's a possible return.
     * Each stage is limited by the number of remaining limbs
     * in |r|.
     *
     * For each stage, |stage_limbs| is used to hold the number
     * of limbs being treated in that stage, and |borrow| is
     * used to transport the borrow from one stage to the other.
     */
    size_t stage_limbs;
    OSSL_FN_ULONG borrow;

    /* Stage 1 */

    stage_limbs = (min > rs) ? rs : min;
    borrow = bn_sub_words(rp, ap, bp, (int)stage_limbs);
    if (stage_limbs == rs)
        return 1;

    /* At this point, we know that |min| limbs have been used so far */
    ap += min;
    bp += min;
    rp += min;

    /* Stage 2 */

    const OSSL_FN_ULONG *maxp = (a->dsize >= b->dsize) ? ap : bp;
    const OSSL_FN_ULONG s2_mask1 = (a->dsize >= b->dsize) ? OSSL_FN_MASK : 0;
    const OSSL_FN_ULONG s2_mask2 = ~s2_mask1;

    stage_limbs = ((max > rs) ? rs : max) - min;

    /* calculate the result of borrowing from more significant limbs */
    for (size_t dif = stage_limbs; dif > 0; dif--, maxp++, rp++) {
        OSSL_FN_ULONG t1 = (*maxp & s2_mask1);
        OSSL_FN_ULONG t2 = (*maxp & s2_mask2);
        OSSL_FN_ULONG t3 = (t1 - t2 - borrow) & OSSL_FN_MASK;

        *rp = t3;
        borrow = (t1 < t2 + borrow);
    }
    if (stage_limbs == rs - min)
        return 1;

    /* Stage 3 */

    /* We know that |max| limbs have been used */
    stage_limbs = rs - max;

    /* Finally, fill in the rest of the result array by borrowing from zeros */
    for (size_t dif = stage_limbs; dif > 0; dif--, rp++) {
        OSSL_FN_ULONG t1 = 0;
        OSSL_FN_ULONG t2 = (t1 - borrow) & OSSL_FN_MASK;

        *rp = t2;
        borrow &= (t1 == 0);
    }

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
