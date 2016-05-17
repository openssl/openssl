/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "bn_lcl.h"

/* r can == a or b */
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    const BIGNUM *tmp;
    int a_neg = a->neg, ret;

    bn_check_top(a);
    bn_check_top(b);

    /*-
     *  a +  b      a+b
     *  a + -b      a-b
     * -a +  b      b-a
     * -a + -b      -(a+b)
     */
    if (a_neg ^ b->neg) {
        /* only one is negative */
        if (a_neg) {
            tmp = a;
            a = b;
            b = tmp;
        }

        /* we are now a - b */

        if (BN_ucmp(a, b) < 0) {
            if (!BN_usub(r, b, a))
                return (0);
            r->neg = 1;
        } else {
            if (!BN_usub(r, a, b))
                return (0);
            r->neg = 0;
        }
        return (1);
    }

    ret = BN_uadd(r, a, b);
    r->neg = a_neg;
    bn_check_top(r);
    return ret;
}

/* unsigned add of b to a */
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int max, min, dif;
    const BN_ULONG *ap, *bp;
    BN_ULONG *rp, carry, t1, t2;
    const BIGNUM *tmp;

    bn_check_top(a);
    bn_check_top(b);

    if (a->top < b->top) {
        tmp = a;
        a = b;
        b = tmp;
    }
    max = a->top;
    min = b->top;
    dif = max - min;

    if (bn_wexpand(r, max + 1) == NULL)
        return 0;

    r->top = max;

    ap = a->d;
    bp = b->d;
    rp = r->d;

    carry = bn_add_words(rp, ap, bp, min);
    rp += min;
    ap += min;
    bp += min;

    if (carry) {
        while (dif) {
            dif--;
            t1 = *(ap++);
            t2 = (t1 + 1) & BN_MASK2;
            *(rp++) = t2;
            if (t2) {
                carry = 0;
                break;
            }
        }
        if (carry) {
            /* carry != 0 => dif == 0 */
            *rp = 1;
            r->top++;
        }
    }
    if (dif && rp != ap)
        while (dif--)
            /* copy remaining words if ap != rp */
            *(rp++) = *(ap++);
    r->neg = 0;
    bn_check_top(r);
    return 1;
}

/* unsigned subtraction of b from a, a must be larger than b. */
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int max, min, dif;
    register BN_ULONG t1, t2, *rp;
    register const BN_ULONG *ap, *bp;
    int i, carry;

    bn_check_top(a);
    bn_check_top(b);

    max = a->top;
    min = b->top;
    dif = max - min;

    if (dif < 0) {              /* hmm... should not be happening */
        BNerr(BN_F_BN_USUB, BN_R_ARG2_LT_ARG3);
        return (0);
    }

    if (bn_wexpand(r, max) == NULL)
        return (0);

    ap = a->d;
    bp = b->d;
    rp = r->d;

#if 1
    carry = 0;
    for (i = min; i != 0; i--) {
        t1 = *(ap++);
        t2 = *(bp++);
        if (carry) {
            carry = (t1 <= t2);
            t1 = (t1 - t2 - 1) & BN_MASK2;
        } else {
            carry = (t1 < t2);
            t1 = (t1 - t2) & BN_MASK2;
        }
        *(rp++) = t1 & BN_MASK2;
    }
#else
    carry = bn_sub_words(rp, ap, bp, min);
    ap += min;
    bp += min;
    rp += min;
#endif
    if (carry) {                /* subtracted */
        if (!dif)
            /* error: a < b */
            return 0;
        while (dif) {
            dif--;
            t1 = *(ap++);
            t2 = (t1 - 1) & BN_MASK2;
            *(rp++) = t2;
            if (t1)
                break;
        }
    }
    if (dif && ap != rp)
        memcpy(rp, ap, sizeof(*rp) * dif);

    r->top = max;
    r->neg = 0;
    bn_correct_top(r);
    return (1);
}

int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int max;
    int add = 0, neg = 0;
    const BIGNUM *tmp;

    bn_check_top(a);
    bn_check_top(b);

    /*-
     *  a -  b      a-b
     *  a - -b      a+b
     * -a -  b      -(a+b)
     * -a - -b      b-a
     */
    if (a->neg) {
        if (b->neg) {
            tmp = a;
            a = b;
            b = tmp;
        } else {
            add = 1;
            neg = 1;
        }
    } else {
        if (b->neg) {
            add = 1;
            neg = 0;
        }
    }

    if (add) {
        if (!BN_uadd(r, a, b))
            return (0);
        r->neg = neg;
        return (1);
    }

    /* We are actually doing a - b :-) */

    max = (a->top > b->top) ? a->top : b->top;
    if (bn_wexpand(r, max) == NULL)
        return (0);
    if (BN_ucmp(a, b) < 0) {
        if (!BN_usub(r, b, a))
            return (0);
        r->neg = 1;
    } else {
        if (!BN_usub(r, a, b))
            return (0);
        r->neg = 0;
    }
    bn_check_top(r);
    return (1);
}
