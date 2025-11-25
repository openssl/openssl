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
#include "../bn/bn_local.h"         /* For using the low level bignum functions */
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

    /*
     * 'r' must be able to contain the result.  This is on the caller.
     */
    if (!ossl_assert(max <= rs)) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_RESULT_ARG_TOO_SMALL);
        return 0;
    }

    const OSSL_FN_ULONG *ap = a->d;
    const OSSL_FN_ULONG *bp = b->d;

    OSSL_FN_ULONG *rp = r->d;
    OSSL_FN_ULONG carry = bn_add_words(rp, ap, bp, (int)min);

    rp += min;
    ap += min;

    for (size_t dif = max - min; dif > 0; dif--, ap++, rp++) {
        OSSL_FN_ULONG t1 = *ap;
        OSSL_FN_ULONG t2 = (t1 + carry) & OSSL_FN_MASK;

        *rp = t2;
        carry &= (t2 == 0);
    }

    for (size_t dif = r->dsize - max; dif > 0; dif--, rp++) {
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

    /*
     * 'r' must be able to contain the result.  This is on the caller.
     */
    if (!ossl_assert(max <= rs)) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_RESULT_ARG_TOO_SMALL);
        return 0;
    }

    const OSSL_FN_ULONG *ap = a->d;
    const OSSL_FN_ULONG *bp = b->d;
    OSSL_FN_ULONG *rp = r->d;
    OSSL_FN_ULONG borrow = bn_sub_words(rp, ap, bp, (int)min);

    /*
     * TODO(FIXNUM): everything following isn't strictly constant-time,
     * and could use improvement in that regard.
     */

    ap += min;
    bp += min;
    rp += min;

    const OSSL_FN_ULONG *maxp = (a->dsize >= b->dsize) ? ap : bp;

    /* "sign" borrow, depending on if maxp == ap or maxp == bp */
    borrow *= (OSSL_FN_ULONG)((a->dsize >= b->dsize) ? 1 : -1);

    /* calculate the result of borrowing from more significant limbs */
    for (size_t dif = max - min; dif > 0; dif--, maxp++, rp++) {
        OSSL_FN_ULONG t1 = *maxp;
        OSSL_FN_ULONG t2 = (t1 - borrow) & OSSL_FN_MASK;

        *rp = t2;
        borrow &= (t1 == 0);
    }

    /* Finally, fill in the rest of the result array by borrowing from zeros */
    for (size_t dif = rs - max; dif > 0; dif--, rp++) {
        OSSL_FN_ULONG t1 = 0;
        OSSL_FN_ULONG t2 = (t1 - borrow) & OSSL_FN_MASK;

        *rp = t2;
        borrow &= (t1 == 0);
    }

    return 1;
}
