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
     * of limbs being treated in that stage, and |borrow| is
     * used to transport the borrow from one stage to the other.
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
    if (stage_limbs == rs)
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
        borrow &= (t1 <= t2);
    }
    if (stage_limbs == rs)
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
