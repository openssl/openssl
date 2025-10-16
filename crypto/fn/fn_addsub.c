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

/* signed add of b to a. */
int OSSL_FN_add(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b)
{
    int ret, r_neg;
    int cmp_res = OSSL_FN_ucmp(a, b);

    if (a->is_negative == b->is_negative) {
        r_neg = a->is_negative;
        ret = ossl_fn_uadd(r, a, b);
    } else if (cmp_res > 0) {
        r_neg = a->is_negative;
        ret = ossl_fn_usub(r, a, b);
    } else {
        r_neg = (cmp_res == 0) ? 0 : !b->is_negative;
        ret = ossl_fn_usub(r, b, a);
    }

    r->is_negative = r_neg;
    return ret;
}

/* signed sub of b from a. */
int OSSL_FN_sub(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b)
{
    int ret, r_neg;
    int cmp_res = OSSL_FN_ucmp(a, b);

    if (a->is_negative != b->is_negative) {
        r_neg = a->is_negative;
        ret = ossl_fn_uadd(r, a, b);
    } else if (cmp_res > 0) {
        r_neg = a->is_negative;
        ret = ossl_fn_usub(r, a, b);
    } else {
        r_neg = (cmp_res == 0) ? 0 : !b->is_negative;
        ret = ossl_fn_usub(r, b, a);
    }

    r->is_negative = r_neg;
    return ret;
}

/* unsigned add of b to a, r can be equal to a or b. */
int ossl_fn_uadd(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b)
{
    if (a->dsize < b->dsize) {
        const OSSL_FN *tmp;

        tmp = a;
        a = b;
        b = tmp;
    }

    /* At this point, we know that a->dsize >= b->dsize */
    size_t max = a->dsize;
    size_t min = b->dsize;

    const OSSL_FN_ULONG *ap = a->d;
    const OSSL_FN_ULONG *bp = b->d;

    /*
     * If the highest bit is set on both 'a' and 'b', we know that
     * the result will grow by one limb, so we must ensure that 'r'
     * has that amount of space.
     */
    size_t rs = max + ((ap[max - 1] & bp[min - 1] & OSSL_FN_HIGH_BIT_MASK) != 0);

    if (rs > (size_t)r->dsize) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_RESULT_ARG_TOO_SMALL);
        return 0;
    }

    OSSL_FN_ULONG *rp = r->d;
    OSSL_FN_ULONG carry = bn_add_words(rp, ap, bp, min);

    rp += min;
    ap += min;

    for (size_t dif = max - min; dif > 0; dif--, ap++, rp++) {
        OSSL_FN_ULONG t1 = *ap;
        OSSL_FN_ULONG t2 = (t1 + carry) & OSSL_FN_MASK;

        *rp = t2;
        carry &= (t2 == 0);
    }

    for (size_t dif = r->dsize - max; dif > 0; dif--, rp++) {
        *rp = carry;
        carry = 0;
    }

    return 1;
}

/* unsigned subtraction of b from a, a must be larger than b. */
int ossl_fn_usub(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b)
{
    size_t max = a->dsize;
    size_t min = b->dsize;
    size_t rs = r->dsize;

    /*
     * Check that a doesn't have a smaller size than b.  Note that this
     * is only a cheap guarantee that a is larger than be, so there may
     * be corner cases where a is a larger number than b.
     */
    if (max < min) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_ARG2_LT_ARG3);
        return 0;
    }

    if (max > (size_t)r->dsize) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_RESULT_ARG_TOO_SMALL);
        return 0;
    }

    const OSSL_FN_ULONG *ap = a->d;
    const OSSL_FN_ULONG *bp = b->d;
    OSSL_FN_ULONG *rp = r->d;
    OSSL_FN_ULONG borrow = bn_sub_words(rp, ap, bp, min);

    ap += min;
    rp += min;

    for (size_t dif = max - min; dif > 0; dif--, ap++, rp++) {
        OSSL_FN_ULONG t1 = *ap;
        OSSL_FN_ULONG t2 = (t1 - borrow) & OSSL_FN_MASK;

        *rp = t2;
        borrow &= (t1 == 0);
    }

    /*
     * Last check that 'a' was effectively larger than 'b';
     * 'borrow' should be zero
     */
    if (ossl_unlikely(borrow != 0)) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_ARG2_LT_ARG3);
        return 0;
    }
    
    for (size_t dif = rs - max; dif > 0; dif--, rp++) {
        *rp = 0;
    }

    return 1;
}
