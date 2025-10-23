/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "bn_local.h"

static size_t calculate_max_limbs(const BIGNUM *a, const BIGNUM *b)
{
    OSSL_FN *af = a->data;
    OSSL_FN *bf = b->data;

    return (af->dsize > bf->dsize) ? af->dsize : bf->dsize;
}

static bool is_highest_bit_set(const BIGNUM *a)
{
    OSSL_FN *af = a->data;

    return (af->d[af->dsize - 1] & OSSL_FN_HIGH_BIT_MASK) != 0;
}

/* TODO(FIXNUM): TO BE REMOVED */
/* pure BIGNUM signed add of b to a. */
static int bn_add_legacy(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int ret, r_neg, cmp_res;

    bn_check_top(a);
    bn_check_top(b);

    if (bn_is_negative_internal(a) == bn_is_negative_internal(b)) {
        r_neg = bn_is_negative_internal(a);
        ret = BN_uadd(r, a, b);
    } else {
        cmp_res = BN_ucmp(a, b);
        if (cmp_res > 0) {
            r_neg = bn_is_negative_internal(a);
            ret = BN_usub(r, a, b);
        } else if (cmp_res < 0) {
            r_neg = bn_is_negative_internal(b);
            ret = BN_usub(r, b, a);
        } else {
            r_neg = 0;
            BN_zero(r);
            ret = 1;
        }
    }

    bn_set_negative_internal(r, r_neg);
    bn_check_top(r);
    return ret;
}

/* signed add of b to a. */
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    /* TODO(FIXNUM): TO BE REMOVED */
    if (r->data == NULL || a->data == NULL || b->data == NULL)
        return bn_add_legacy(r, a, b);

    bn_check_top(a);
    bn_check_top(b);

    size_t max = calculate_max_limbs(a, b);

    /*
     * If both operands have the highest bit set and have the same sign,
     * the result will become one limb larger.
     */
    if (bn_is_negative_internal(a) == bn_is_negative_internal(b)
        && is_highest_bit_set(a)
        && is_highest_bit_set(b))
        max++;

    OSSL_FN *rf = bn_acquire_ossl_fn(r, max);
    int ret = OSSL_FN_add(rf, a->data, b->data);
    bn_release(r);

    return ret;
}

/* TODO(FIXNUM): TO BE REMOVED */
/* pure BIGNUM signed sub of b from a. */
static int bn_sub_legacy(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int ret, r_neg, cmp_res;

    bn_check_top(a);
    bn_check_top(b);

    if (bn_is_negative_internal(a) != bn_is_negative_internal(b)) {
        r_neg = bn_is_negative_internal(a);;
        ret = BN_uadd(r, a, b);
    } else {
        cmp_res = BN_ucmp(a, b);
        if (cmp_res > 0) {
            r_neg = bn_is_negative_internal(a);;
            ret = BN_usub(r, a, b);
        } else if (cmp_res < 0) {
            r_neg = !bn_is_negative_internal(b);;
            ret = BN_usub(r, b, a);
        } else {
            r_neg = 0;
            BN_zero(r);
            ret = 1;
        }
    }

    bn_set_negative_internal(r, r_neg);
    bn_check_top(r);
    return ret;
}

/* signed sub of b from a. */
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    /* TODO(FIXNUM): TO BE REMOVED */
    if (r->data == NULL || a->data == NULL || b->data == NULL)
        return bn_sub_legacy(r, a, b);

    bn_check_top(a);
    bn_check_top(b);

    size_t max = calculate_max_limbs(a, b);

    /*
     * If both operands have the highest bit set and their signs differ,
     * the result will become one limb larger.
     */
    if (bn_is_negative_internal(a) != bn_is_negative_internal(b)
        && is_highest_bit_set(a)
        && is_highest_bit_set(b))
        max++;

    OSSL_FN *rf = bn_acquire_ossl_fn(r, max);
    int ret = OSSL_FN_sub(rf, a->data, b->data);
    bn_release(r);

    return ret;
}

/* TODO(FIXNUM): TO BE REMOVED */
/* pure BIGNUM unsigned add of b to a, r can be equal to a or b. */
static int bn_uadd_legacy(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int max, min, dif;
    const BN_ULONG *ap, *bp;
    BN_ULONG *rp, carry, t1, t2;

    bn_check_top(a);
    bn_check_top(b);

    if (a->top < b->top) {
        const BIGNUM *tmp;

        tmp = a;
        a = b;
        b = tmp;
    }
    max = a->top;
    min = b->top;
    dif = max - min;

    if (bn_wexpand(r, max + 1) == NULL)
        return 0;

    bn_set_top(r, max);

    ap = a->d;
    bp = b->d;
    rp = r->d;

    carry = bn_add_words(rp, ap, bp, min);
    rp += min;
    ap += min;

    while (dif) {
        dif--;
        t1 = *(ap++);
        t2 = (t1 + carry) & BN_MASK2;
        *(rp++) = t2;
        carry &= (t2 == 0);
    }
    *rp = carry;
    bn_set_top(r, r->top + (int)carry);

    bn_set_negative_internal(r, 0);
    bn_check_top(r);
    return 1;
}

/* unsigned add of b to a, r can be equal to a or b. */
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    /* TODO(FIXNUM): TO BE REMOVED */
    if (r->data == NULL || a->data == NULL || b->data == NULL)
        return bn_uadd_legacy(r, a, b);

    bn_check_top(a);
    bn_check_top(b);

    size_t max = calculate_max_limbs(a, b);

    /*
     * If both operands have the highest bit set the result will become
     * one limb larger.
     */
    if (is_highest_bit_set(a) && is_highest_bit_set(b))
        max++;

    OSSL_FN *rf = bn_acquire_ossl_fn(r, max);
    int ret = ossl_fn_uadd(rf, a->data, b->data);
    bn_release(r);

    return ret;
}

/* TODO(FIXNUM): TO BE REMOVED */
/* pure BIGNUM unsigned subtraction of b from a, a must be larger than b. */
static int bn_usub_legacy(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    int max, min, dif;
    BN_ULONG t1, t2, borrow, *rp;
    const BN_ULONG *ap, *bp;

    bn_check_top(a);
    bn_check_top(b);

    max = a->top;
    min = b->top;
    dif = max - min;

    if (dif < 0) {              /* hmm... should not be happening */
        ERR_raise(ERR_LIB_BN, BN_R_ARG2_LT_ARG3);
        return 0;
    }

    if (bn_wexpand(r, max) == NULL)
        return 0;

    ap = a->d;
    bp = b->d;
    rp = r->d;

    borrow = bn_sub_words(rp, ap, bp, min);
    ap += min;
    rp += min;

    while (dif) {
        dif--;
        t1 = *(ap++);
        t2 = (t1 - borrow) & BN_MASK2;
        *(rp++) = t2;
        borrow &= (t1 == 0);
    }

    while (max && *--rp == 0)
        max--;

    bn_set_top(r, max);
    bn_set_negative_internal(r, 0);

    return 1;
}

/* unsigned subtraction of b from a, a must be larger than b. */
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
    /* TODO(FIXNUM): TO BE REMOVED */
    if (r->data == NULL || a->data == NULL || b->data == NULL)
        return bn_usub_legacy(r, a, b);

    bn_check_top(a);
    bn_check_top(b);

    size_t max = calculate_max_limbs(a, b);

    OSSL_FN *rf = bn_acquire_ossl_fn(r, max);
    int ret = ossl_fn_usub(rf, a->data, b->data);
    bn_release(r);

    return ret;
}
