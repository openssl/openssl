/*
 * Copyright 2001-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * ECDSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"
#include "internal/safe_math.h"

#include <string.h>
#include <openssl/err.h>

#include "internal/cryptlib.h"
#include "crypto/bn.h"
#include "crypto/fn.h"
#include "crypto/fn_intern.h" /* ossl_fn_get_dsize() */
#include "ec_local.h"
#include "internal/refcount.h"

OSSL_SAFE_MATH_ADDU(size_t, size_t, OSSL_SAFE_MATH_MAXU(size_t))

/*
 * This file implements the wNAF-based interleaving multi-exponentiation method
 * Formerly at:
 *   http://www.informatik.tu-darmstadt.de/TI/Mitarbeiter/moeller.html#multiexp
 * You might now find it here:
 *   http://link.springer.com/chapter/10.1007%2F3-540-45537-X_13
 *   http://www.bmoeller.de/pdf/TI-01-08.multiexp.pdf
 * For multiplication with precomputation, we use wNAF splitting, formerly at:
 *   http://www.informatik.tu-darmstadt.de/TI/Mitarbeiter/moeller.html#fastexp
 */

/* structure for precomputed multiples of the generator */
struct ec_pre_comp_st {
    const EC_GROUP *group; /* parent EC_GROUP object */
    size_t blocksize; /* block size for wNAF splitting */
    size_t numblocks; /* max. number of blocks for which we have
                       * precomputation */
    size_t w; /* window size */
    EC_POINT **points; /* array with pre-calculated multiples of
                        * generator: 'num' pointers to EC_POINT
                        * objects followed by a NULL */
    size_t num; /* numblocks * 2^(w-1) */
    CRYPTO_REF_COUNT references;
};

static EC_PRE_COMP *ec_pre_comp_new(const EC_GROUP *group)
{
    EC_PRE_COMP *ret = NULL;

    if (!group)
        return NULL;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL)
        return ret;

    ret->group = group;
    ret->blocksize = 8; /* default */
    ret->w = 4; /* default */

    if (!CRYPTO_NEW_REF(&ret->references, 1)) {
        OPENSSL_free(ret);
        return NULL;
    }
    return ret;
}

EC_PRE_COMP *EC_ec_pre_comp_dup(EC_PRE_COMP *pre)
{
    int i;
    if (pre != NULL)
        CRYPTO_UP_REF(&pre->references, &i);
    return pre;
}

void EC_ec_pre_comp_free(EC_PRE_COMP *pre)
{
    int i;

    if (pre == NULL)
        return;

    CRYPTO_DOWN_REF(&pre->references, &i);
    REF_PRINT_COUNT("EC_ec", i, pre);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (pre->points != NULL) {
        EC_POINT **pts;

        for (pts = pre->points; *pts != NULL; pts++)
            EC_POINT_free(*pts);
        OPENSSL_free(pre->points);
    }
    CRYPTO_FREE_REF(&pre->references);
    OPENSSL_free(pre);
}

#define EC_POINT_BN_set_flags(P, flags) \
    do {                                \
        BN_set_flags((P)->X, (flags));  \
        BN_set_flags((P)->Y, (flags));  \
        BN_set_flags((P)->Z, (flags));  \
    } while (0)

/*-
 * This functions computes a single point multiplication over the EC group,
 * using, at a high level, a Montgomery ladder with conditional swaps, with
 * various timing attack defenses.
 *
 * It performs either a fixed point multiplication
 *          (scalar * generator)
 * when point is NULL, or a variable point multiplication
 *          (scalar * point)
 * when point is not NULL.
 *
 * `scalar` cannot be NULL and should be in the range [0,n) otherwise all
 * constant time bets are off (where n is the cardinality of the EC group).
 *
 * This function expects `group->order` and `group->cardinality` to be well
 * defined and non-zero: it fails with an error code otherwise.
 *
 * NB: This says nothing about the constant-timeness of the ladder step
 * implementation (i.e., the default implementation is based on EC_POINT_add and
 * EC_POINT_dbl, which of course are not constant time themselves) or the
 * underlying multiprecision arithmetic.
 *
 * The product is stored in `r`.
 *
 * This is an internal function: callers are in charge of ensuring that the
 * input parameters `group`, `r`, `scalar` and `ctx` are not NULL.
 *
 * Returns 1 on success, 0 otherwise.
 */
int ossl_ec_scalar_mul_ladder(const EC_GROUP *group, EC_POINT *r,
    const BIGNUM *scalar, const EC_POINT *point,
    BN_CTX *ctx)
{
    int i, cardinality_bits, group_top, kbit, pbit, Z_is_one;
    EC_POINT *p = NULL;
    EC_POINT *s = NULL;
    BIGNUM *k = NULL;
    BIGNUM *lambda = NULL;
    BIGNUM *cardinality = NULL;
    int ret = 0;

    /* early exit if the input point is the point at infinity */
    if (point != NULL && EC_POINT_is_at_infinity(group, point))
        return EC_POINT_set_to_infinity(group, r);

    if (BN_is_zero(group->order)) {
        ERR_raise(ERR_LIB_EC, EC_R_UNKNOWN_ORDER);
        return 0;
    }
    if (BN_is_zero(group->cofactor)) {
        ERR_raise(ERR_LIB_EC, EC_R_UNKNOWN_COFACTOR);
        return 0;
    }

    BN_CTX_start(ctx);

    if (((p = EC_POINT_new(group)) == NULL)
        || ((s = EC_POINT_new(group)) == NULL)) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    if (point == NULL) {
        if (!EC_POINT_copy(p, group->generator)) {
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }
    } else {
        if (!EC_POINT_copy(p, point)) {
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }
    }

    EC_POINT_BN_set_flags(p, BN_FLG_CONSTTIME);
    EC_POINT_BN_set_flags(r, BN_FLG_CONSTTIME);
    EC_POINT_BN_set_flags(s, BN_FLG_CONSTTIME);

    cardinality = BN_CTX_get(ctx);
    lambda = BN_CTX_get(ctx);
    k = BN_CTX_get(ctx);
    if (k == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_mul(cardinality, group->order, group->cofactor, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    /*
     * Group cardinalities are often on a word boundary.
     * So when we pad the scalar, some timing diff might
     * pop if it needs to be expanded due to carries.
     * So expand ahead of time.
     */
    cardinality_bits = BN_num_bits(cardinality);
    group_top = bn_get_top(cardinality);
    if ((bn_wexpand(k, group_top + 2) == NULL)
        || (bn_wexpand(lambda, group_top + 2) == NULL)) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    if (BN_copy(k, scalar) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    BN_set_flags(k, BN_FLG_CONSTTIME);

    if ((BN_num_bits(k) > cardinality_bits) || (BN_is_negative(k))) {
        /*-
         * this is an unusual input, and we don't guarantee
         * constant-timeness
         */
        if (!BN_nnmod(k, k, cardinality, ctx)) {
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            goto err;
        }
    }

    if (!BN_add(lambda, k, cardinality)) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }
    BN_set_flags(lambda, BN_FLG_CONSTTIME);
    if (!BN_add(k, lambda, cardinality)) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }
    /*
     * lambda := scalar + cardinality
     * k := scalar + 2*cardinality
     */
    kbit = BN_is_bit_set(lambda, cardinality_bits);
    BN_consttime_swap(kbit, k, lambda, group_top + 2);

    group_top = bn_get_top(group->field);
    if ((bn_wexpand(s->X, group_top) == NULL)
        || (bn_wexpand(s->Y, group_top) == NULL)
        || (bn_wexpand(s->Z, group_top) == NULL)
        || (bn_wexpand(r->X, group_top) == NULL)
        || (bn_wexpand(r->Y, group_top) == NULL)
        || (bn_wexpand(r->Z, group_top) == NULL)
        || (bn_wexpand(p->X, group_top) == NULL)
        || (bn_wexpand(p->Y, group_top) == NULL)
        || (bn_wexpand(p->Z, group_top) == NULL)) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    /* ensure input point is in affine coords for ladder step efficiency */
    if (!p->Z_is_one && (group->meth->make_affine == NULL || !group->meth->make_affine(group, p, ctx))) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    /* Initialize the Montgomery ladder */
    if (!ec_point_ladder_pre(group, r, s, p, ctx)) {
        ERR_raise(ERR_LIB_EC, EC_R_LADDER_PRE_FAILURE);
        goto err;
    }

    /* top bit is a 1, in a fixed pos */
    pbit = 1;

#define EC_POINT_CSWAP(c, a, b, w, t)              \
    do {                                           \
        BN_consttime_swap(c, (a)->X, (b)->X, w);   \
        BN_consttime_swap(c, (a)->Y, (b)->Y, w);   \
        BN_consttime_swap(c, (a)->Z, (b)->Z, w);   \
        t = ((a)->Z_is_one ^ (b)->Z_is_one) & (c); \
        (a)->Z_is_one ^= (t);                      \
        (b)->Z_is_one ^= (t);                      \
    } while (0)

    /*-
     * The ladder step, with branches, is
     *
     * k[i] == 0: S = add(R, S), R = dbl(R)
     * k[i] == 1: R = add(S, R), S = dbl(S)
     *
     * Swapping R, S conditionally on k[i] leaves you with state
     *
     * k[i] == 0: T, U = R, S
     * k[i] == 1: T, U = S, R
     *
     * Then perform the ECC ops.
     *
     * U = add(T, U)
     * T = dbl(T)
     *
     * Which leaves you with state
     *
     * k[i] == 0: U = add(R, S), T = dbl(R)
     * k[i] == 1: U = add(S, R), T = dbl(S)
     *
     * Swapping T, U conditionally on k[i] leaves you with state
     *
     * k[i] == 0: R, S = T, U
     * k[i] == 1: R, S = U, T
     *
     * Which leaves you with state
     *
     * k[i] == 0: S = add(R, S), R = dbl(R)
     * k[i] == 1: R = add(S, R), S = dbl(S)
     *
     * So we get the same logic, but instead of a branch it's a
     * conditional swap, followed by ECC ops, then another conditional swap.
     *
     * Optimization: The end of iteration i and start of i-1 looks like
     *
     * ...
     * CSWAP(k[i], R, S)
     * ECC
     * CSWAP(k[i], R, S)
     * (next iteration)
     * CSWAP(k[i-1], R, S)
     * ECC
     * CSWAP(k[i-1], R, S)
     * ...
     *
     * So instead of two contiguous swaps, you can merge the condition
     * bits and do a single swap.
     *
     * k[i]   k[i-1]    Outcome
     * 0      0         No Swap
     * 0      1         Swap
     * 1      0         Swap
     * 1      1         No Swap
     *
     * This is XOR. pbit tracks the previous bit of k.
     */

    for (i = cardinality_bits - 1; i >= 0; i--) {
        kbit = BN_is_bit_set(k, i) ^ pbit;
        EC_POINT_CSWAP(kbit, r, s, group_top, Z_is_one);

        /* Perform a single step of the Montgomery ladder */
        if (!ec_point_ladder_step(group, r, s, p, ctx)) {
            ERR_raise(ERR_LIB_EC, EC_R_LADDER_STEP_FAILURE);
            goto err;
        }
        /*
         * pbit logic merges this cswap with that of the
         * next iteration
         */
        pbit ^= kbit;
    }
    /* one final cswap to move the right value into r */
    EC_POINT_CSWAP(pbit, r, s, group_top, Z_is_one);
#undef EC_POINT_CSWAP

    /* Finalize ladder (and recover full point coordinates) */
    if (!ec_point_ladder_post(group, r, s, p, ctx)) {
        ERR_raise(ERR_LIB_EC, EC_R_LADDER_POST_FAILURE);
        goto err;
    }

    ret = 1;

err:
    EC_POINT_free(p);
    EC_POINT_clear_free(s);
    BN_CTX_end(ctx);

    return ret;
}

/*-
 * The OSSL_FN counterpart of ossl_ec_scalar_mul_ladder(), above.  Same
 * ladder, same conditional swaps, same timing-attack defenses; the only
 * difference is that the secret scalar arrives as an OSSL_FN and is never
 * materialised as a BIGNUM.  The Montgomery-ladder point arithmetic runs
 * directly on the coordinates' OSSL_FN views (ossl_ec_GFp_mont_ladder_*_fn),
 * so this path requires a group with Montgomery field arithmetic.
 *
 * The point coordinates stay BIGNUMs and the point half of the algorithm is
 * untouched.  Nothing is lost by that: the scalar and the coordinates never
 * meet in a single arithmetic operation.  The scalar is only ever added to
 * the (public) cardinality and read a bit at a time to steer the swaps.
 *
 * Two contortions of the BIGNUM version fall away here.  It has to cope with
 * a negative scalar, which an unsigned OSSL_FN cannot present; and it expands
 * k and lambda to group_top + 2 words up front, because otherwise a carry
 * could provoke a reallocation whose timing would leak.  OSSL_FN is
 * fixed-width, so there is no reallocation to hide, and group_top + 1 words
 * are provably enough: k starts below the cardinality, and the two additions
 * of the cardinality can carry it up by less than two bits, which one extra
 * limb absorbs.
 *
 * Returns 1 on success, 0 otherwise.
 */
int ossl_ec_scalar_mul_ladder_fn(const EC_GROUP *group, EC_POINT *r,
    const OSSL_FN *scalar, const EC_POINT *point,
    OSSL_FN_CTX *fnctx)
{
    int i, cardinality_bits, group_top, kbit, pbit, Z_is_one;
    EC_POINT *p = NULL;
    EC_POINT *s = NULL;
    const OSSL_FN *cardinality_fn = NULL;
    OSSL_FN *k = NULL;
    OSSL_FN *lambda = NULL;
    const void *token = NULL;
    size_t width;
    int ret = 0;

    /* early exit if the input point is the point at infinity */
    if (point != NULL && EC_POINT_is_at_infinity(group, point))
        return EC_POINT_set_to_infinity(group, r);

    if (BN_is_zero(group->order)) {
        ERR_raise(ERR_LIB_EC, EC_R_UNKNOWN_ORDER);
        return 0;
    }
    if (BN_is_zero(group->cofactor)) {
        ERR_raise(ERR_LIB_EC, EC_R_UNKNOWN_COFACTOR);
        return 0;
    }
    /*
     * The OSSL_FN ladder point arithmetic is Montgomery-only; there is no
     * BIGNUM fallback on the secret path.  Refuse groups with no field
     * Montgomery context (e.g. GF(2^m) groups).
     */
    if (group->fn_mont_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_NOT_INITIALIZED);
        return 0;
    }
    /* The scratch arena is caller-owned; EC_POINT_mul_fn() sizes/allocates it. */
    if (fnctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (((p = EC_POINT_new(group)) == NULL)
        || ((s = EC_POINT_new(group)) == NULL)) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    if (point == NULL) {
        if (!EC_POINT_copy(p, group->generator)) {
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }
    } else {
        if (!EC_POINT_copy(p, point)) {
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }
    }

    EC_POINT_BN_set_flags(p, BN_FLG_CONSTTIME);
    EC_POINT_BN_set_flags(r, BN_FLG_CONSTTIME);
    EC_POINT_BN_set_flags(s, BN_FLG_CONSTTIME);

    /*
     * The cardinality (order * cofactor) is a public, immutable group
     * attribute, precomputed by EC_GROUP_set_generator(); use its OSSL_FN view
     * directly (no BN_mul(), no allocation, no release).
     */
    if ((cardinality_fn = bn_get_ossl_fn(group->cardinality)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    cardinality_bits = BN_num_bits(group->cardinality);
    width = (size_t)bn_get_top(group->cardinality) + 1;

    /*
     * |k| and |lambda| are secret-derived; they live in the outer frame of the
     * caller-provided arena for the whole ladder, while the ladder helpers push
     * their own nested frames on top for their scratch.  The arena is sized for
     * both by ossl_ec_scalar_mul_ladder_fn_ctx_size().  The reduction on the
     * unusual-input path is rare and gets its own short-lived OSSL_FN_CTX rather
     * than bloating this arena.
     *
     * The OSSL_FN calls from here on raise their own errors, so failures are
     * not re-raised under ERR_LIB_EC - there is no ERR_R_*_LIB code for the
     * OSSL_FN library to tag them with.
     */
    if ((token = OSSL_FN_CTX_start(fnctx)) == NULL)
        goto err;

    if ((k = OSSL_FN_CTX_get_limbs(fnctx, width)) == NULL
        || (lambda = OSSL_FN_CTX_get_limbs(fnctx, width)) == NULL)
        goto err;

    if (ossl_unlikely(OSSL_FN_num_bits(scalar) > (size_t)cardinality_bits)) {
        /*-
         * This is an unusual input, and we don't guarantee constant-timeness.
         * The reduction is the only step that needs scratch, so it gets a
         * short-lived OSSL_FN_CTX of its own, sized by the library rather
         * than by hand, instead of widening the arena above for a rare path.
         */
        OSSL_FN_CTX *modctx = OSSL_FN_CTX_secure_new_size(group->libctx,
            OSSL_FN_mod_ctx_size(k, scalar, cardinality_fn));
        int ok;

        if (modctx == NULL)
            goto err;
        ok = OSSL_FN_mod(k, scalar, cardinality_fn, modctx);
        OSSL_FN_CTX_free(modctx);
        if (!ok)
            goto err;
    } else if (OSSL_FN_copy_truncate(k, scalar) == NULL) {
        /* No significant limb is dropped: the test above just ruled that out. */
        goto err;
    }

    if (!OSSL_FN_add(lambda, k, cardinality_fn)
        || !OSSL_FN_add(k, lambda, cardinality_fn))
        goto err;
    /*
     * lambda := scalar + cardinality
     * k := scalar + 2*cardinality
     */
    kbit = OSSL_FN_is_bit_set(lambda, cardinality_bits);
    if (!OSSL_FN_consttime_swap(kbit, k, lambda))
        goto err;

    /*
     * Ensure the input point is affine.  On the ladder path make_affine is
     * always ossl_ec_GFp_simple_make_affine (every GF(p) method uses it), which
     * allocates its own BN_CTX when passed NULL - so no BN_CTX is threaded here.
     */
    if (!p->Z_is_one
        && (group->meth->make_affine == NULL
            || !group->meth->make_affine(group, p, NULL))) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    /*
     * The coordinate CSWAPs below run at the field width; capture it for the
     * swap width.  The _fn ladder helpers copy the public base point's
     * coordinates into field-width temporaries themselves and widen r/s in
     * place, so nothing about p or r/s needs preparing here.
     */
    group_top = (int)ossl_fn_get_dsize(bn_get_ossl_fn(group->field));

    /* Initialize the Montgomery ladder */
    if (!ossl_ec_GFp_mont_ladder_pre_fn(group, r, s, p, fnctx)) {
        ERR_raise(ERR_LIB_EC, EC_R_LADDER_PRE_FAILURE);
        goto err;
    }

    /* top bit is a 1, in a fixed pos */
    pbit = 1;

#define EC_POINT_CSWAP(c, a, b, w, t)              \
    do {                                           \
        BN_consttime_swap(c, (a)->X, (b)->X, w);   \
        BN_consttime_swap(c, (a)->Y, (b)->Y, w);   \
        BN_consttime_swap(c, (a)->Z, (b)->Z, w);   \
        t = ((a)->Z_is_one ^ (b)->Z_is_one) & (c); \
        (a)->Z_is_one ^= (t);                      \
        (b)->Z_is_one ^= (t);                      \
    } while (0)

    /* The ladder logic is spelled out in ossl_ec_scalar_mul_ladder(), above. */
    for (i = cardinality_bits - 1; i >= 0; i--) {
        kbit = OSSL_FN_is_bit_set(k, i) ^ pbit;
        EC_POINT_CSWAP(kbit, r, s, group_top, Z_is_one);

        /* Perform a single step of the Montgomery ladder */
        if (!ossl_ec_GFp_mont_ladder_step_fn(group, r, s, p, fnctx)) {
            ERR_raise(ERR_LIB_EC, EC_R_LADDER_STEP_FAILURE);
            goto err;
        }
        /*
         * pbit logic merges this cswap with that of the
         * next iteration
         */
        pbit ^= kbit;
    }
    /* one final cswap to move the right value into r */
    EC_POINT_CSWAP(pbit, r, s, group_top, Z_is_one);
#undef EC_POINT_CSWAP

    /* Finalize ladder (and recover full point coordinates) */
    if (!ossl_ec_GFp_mont_ladder_post_fn(group, r, s, p, fnctx)) {
        ERR_raise(ERR_LIB_EC, EC_R_LADDER_POST_FAILURE);
        goto err;
    }

    ret = 1;

err:
    /*
     * Pop our outer frame if we started one (an early error may jump here
     * before that); the caller retains ownership of the arena either way.
     */
    if (token != NULL)
        OSSL_FN_CTX_end(fnctx, token);
    EC_POINT_free(p);
    EC_POINT_clear_free(s);

    return ret;
}

#undef EC_POINT_BN_set_flags

/*
 * Arena size ossl_ec_scalar_mul_ladder_fn() needs: an outer frame holding k and
 * lambda (cardinality-top + 1 limbs each), plus the largest of the pre/step/post
 * helper arenas, which push nested frames on top of that outer frame.
 */
size_t ossl_ec_scalar_mul_ladder_fn_ctx_size(const EC_GROUP *group,
    EC_POINT *r, const OSSL_FN *scalar, const EC_POINT *point)
{
    size_t width, klam, pre_sz, step_sz, post_sz, max_sz, ret;
    int err = 0;

    if (group->fn_mont_ctx == NULL || group->cardinality == NULL)
        return 0;

    width = (size_t)bn_get_top(group->cardinality) + 1;
    klam = OSSL_FN_CTX_size(1, 2, 2 * width);
    pre_sz = ossl_ec_GFp_mont_ladder_pre_fn_ctx_size(group, r, NULL, NULL);
    step_sz = ossl_ec_GFp_mont_ladder_step_fn_ctx_size(group, r, NULL, NULL);
    post_sz = ossl_ec_GFp_mont_ladder_post_fn_ctx_size(group, r, NULL, NULL);
    if (klam == 0 || pre_sz == 0 || step_sz == 0 || post_sz == 0)
        return 0;

    max_sz = pre_sz;
    if (step_sz > max_sz)
        max_sz = step_sz;
    if (post_sz > max_sz)
        max_sz = post_sz;
    ret = safe_add_size_t(klam, max_sz, &err);
    return err == 0 ? ret : 0;
}

/*
 * Table could be optimised for the wNAF-based implementation,
 * sometimes smaller windows will give better performance (thus the
 * boundaries should be increased)
 */
#define EC_window_bits_for_scalar_size(b)      \
    ((size_t)((b) >= 2000 ? 6 : (b) >= 800 ? 5 \
            : (b) >= 300                   ? 4 \
            : (b) >= 70                    ? 3 \
            : (b) >= 20                    ? 2 \
                                           : 1))

/*-
 * Compute
 *      \sum scalars[i]*points[i],
 * also including
 *      scalar*generator
 * in the addition if scalar != NULL
 */
int ossl_ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
    size_t num, const EC_POINT *points[],
    const BIGNUM *scalars[], BN_CTX *ctx)
{
    const EC_POINT *generator = NULL;
    EC_POINT *tmp = NULL;
    size_t totalnum;
    size_t blocksize = 0, numblocks = 0; /* for wNAF splitting */
    size_t pre_points_per_block = 0;
    size_t i, j;
    int k;
    int r_is_inverted = 0;
    int r_is_at_infinity = 1;
    size_t *wsize = NULL; /* individual window sizes */
    signed char **wNAF = NULL; /* individual wNAFs */
    size_t *wNAF_len = NULL;
    size_t max_len = 0;
    size_t num_val;
    EC_POINT **val = NULL; /* precomputation */
    EC_POINT **v;
    EC_POINT ***val_sub = NULL; /* pointers to sub-arrays of 'val' or
                                 * 'pre_comp->points' */
    const EC_PRE_COMP *pre_comp = NULL;
    int num_scalar = 0; /* flag: will be set to 1 if 'scalar' must be
                         * treated like other scalars, i.e.
                         * precomputation is not available */
    int ret = 0;

    if (!BN_is_zero(group->order) && !BN_is_zero(group->cofactor)) {
        /*-
         * Handle the common cases where the scalar is secret, enforcing a
         * scalar multiplication implementation based on a Montgomery ladder,
         * with various timing attack defenses.
         */
        if ((scalar != group->order) && (scalar != NULL) && (num == 0)) {
            /*-
             * In this case we want to compute scalar * GeneratorPoint: this
             * codepath is reached most prominently by (ephemeral) key
             * generation of EC cryptosystems (i.e. ECDSA keygen and sign setup,
             * ECDH keygen/first half), where the scalar is always secret. This
             * is why we ignore if BN_FLG_CONSTTIME is actually set and we
             * always call the ladder version.
             */
            return ossl_ec_scalar_mul_ladder(group, r, scalar, NULL, ctx);
        }
        if ((scalar == NULL) && (num == 1) && (scalars[0] != group->order)) {
            /*-
             * In this case we want to compute scalar * VariablePoint: this
             * codepath is reached most prominently by the second half of ECDH,
             * where the secret scalar is multiplied by the peer's public point.
             * To protect the secret scalar, we ignore if BN_FLG_CONSTTIME is
             * actually set and we always call the ladder version.
             */
            return ossl_ec_scalar_mul_ladder(group, r, scalars[0], points[0],
                ctx);
        }
    }

    if (scalar != NULL) {
        generator = EC_GROUP_get0_generator(group);
        if (generator == NULL) {
            ERR_raise(ERR_LIB_EC, EC_R_UNDEFINED_GENERATOR);
            goto err;
        }

        /* look if we can use precomputed multiples of generator */

        pre_comp = group->pre_comp.ec;
        if (pre_comp && pre_comp->numblocks
            && (EC_POINT_cmp(group, generator, pre_comp->points[0], ctx) == 0)) {
            blocksize = pre_comp->blocksize;

            /*
             * determine maximum number of blocks that wNAF splitting may
             * yield (NB: maximum wNAF length is bit length plus one)
             */
            numblocks = (BN_num_bits(scalar) / blocksize) + 1;

            /*
             * we cannot use more blocks than we have precomputation for
             */
            if (numblocks > pre_comp->numblocks)
                numblocks = pre_comp->numblocks;

            pre_points_per_block = (size_t)1 << (pre_comp->w - 1);

            /* check that pre_comp looks sane */
            if (pre_comp->num != (pre_comp->numblocks * pre_points_per_block)) {
                ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else {
            /* can't use precomputation */
            pre_comp = NULL;
            numblocks = 1;
            num_scalar = 1; /* treat 'scalar' like 'num'-th element of
                             * 'scalars' */
        }
    }

    totalnum = num + numblocks;

    wsize = OPENSSL_malloc_array(totalnum, sizeof(wsize[0]));
    wNAF_len = OPENSSL_malloc_array(totalnum, sizeof(wNAF_len[0]));
    /* include space for pivot */
    wNAF = OPENSSL_malloc_array(totalnum + 1, sizeof(wNAF[0]));
    val_sub = OPENSSL_malloc_array(totalnum, sizeof(val_sub[0]));

    /* Ensure wNAF is initialised in case we end up going to err */
    if (wNAF != NULL)
        wNAF[0] = NULL; /* preliminary pivot */

    if (wsize == NULL || wNAF_len == NULL || wNAF == NULL || val_sub == NULL)
        goto err;

    /*
     * num_val will be the total number of temporarily precomputed points
     */
    num_val = 0;

    for (i = 0; i < num + num_scalar; i++) {
        size_t bits;

        bits = i < num ? BN_num_bits(scalars[i]) : BN_num_bits(scalar);
        wsize[i] = EC_window_bits_for_scalar_size(bits);
        num_val += (size_t)1 << (wsize[i] - 1);
        wNAF[i + 1] = NULL; /* make sure we always have a pivot */
        wNAF[i] = bn_compute_wNAF((i < num ? scalars[i] : scalar), (int)wsize[i],
            &wNAF_len[i]);
        if (wNAF[i] == NULL)
            goto err;
        if (wNAF_len[i] > max_len)
            max_len = wNAF_len[i];
    }

    if (numblocks) {
        /* we go here iff scalar != NULL */

        if (pre_comp == NULL) {
            if (num_scalar != 1) {
                ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /* we have already generated a wNAF for 'scalar' */
        } else {
            signed char *tmp_wNAF = NULL;
            size_t tmp_len = 0;

            if (num_scalar != 0) {
                ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
                goto err;
            }

            /*
             * use the window size for which we have precomputation
             */
            wsize[num] = pre_comp->w;
            tmp_wNAF = bn_compute_wNAF(scalar, (int)wsize[num], &tmp_len);
            if (!tmp_wNAF)
                goto err;

            if (tmp_len <= max_len) {
                /*
                 * One of the other wNAFs is at least as long as the wNAF
                 * belonging to the generator, so wNAF splitting will not buy
                 * us anything.
                 */

                numblocks = 1;
                totalnum = num + 1; /* don't use wNAF splitting */
                wNAF[num] = tmp_wNAF;
                wNAF[num + 1] = NULL;
                wNAF_len[num] = tmp_len;
                /*
                 * pre_comp->points starts with the points that we need here:
                 */
                val_sub[num] = pre_comp->points;
            } else {
                /*
                 * don't include tmp_wNAF directly into wNAF array - use wNAF
                 * splitting and include the blocks
                 */

                signed char *pp;
                EC_POINT **tmp_points;

                if (tmp_len < numblocks * blocksize) {
                    /*
                     * possibly we can do with fewer blocks than estimated
                     */
                    numblocks = (tmp_len + blocksize - 1) / blocksize;
                    if (numblocks > pre_comp->numblocks) {
                        ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
                        OPENSSL_free(tmp_wNAF);
                        goto err;
                    }
                    totalnum = num + numblocks;
                }

                /* split wNAF in 'numblocks' parts */
                pp = tmp_wNAF;
                tmp_points = pre_comp->points;

                for (i = num; i < totalnum; i++) {
                    if (i < totalnum - 1) {
                        wNAF_len[i] = blocksize;
                        if (tmp_len < blocksize) {
                            ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
                            OPENSSL_free(tmp_wNAF);
                            goto err;
                        }
                        tmp_len -= blocksize;
                    } else
                        /*
                         * last block gets whatever is left (this could be
                         * more or less than 'blocksize'!)
                         */
                        wNAF_len[i] = tmp_len;

                    wNAF[i + 1] = NULL;
                    wNAF[i] = OPENSSL_malloc(wNAF_len[i]);
                    if (wNAF[i] == NULL) {
                        OPENSSL_free(tmp_wNAF);
                        goto err;
                    }
                    memcpy(wNAF[i], pp, wNAF_len[i]);
                    if (wNAF_len[i] > max_len)
                        max_len = wNAF_len[i];

                    if (*tmp_points == NULL) {
                        ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
                        OPENSSL_free(tmp_wNAF);
                        goto err;
                    }
                    val_sub[i] = tmp_points;
                    tmp_points += pre_points_per_block;
                    pp += blocksize;
                }
                OPENSSL_free(tmp_wNAF);
            }
        }
    }

    /*
     * All points we precompute now go into a single array 'val'.
     * 'val_sub[i]' is a pointer to the subarray for the i-th point, or to a
     * subarray of 'pre_comp->points' if we already have precomputation.
     */
    val = OPENSSL_malloc_array(num_val + 1, sizeof(val[0]));
    if (val == NULL)
        goto err;
    val[num_val] = NULL; /* pivot element */

    /* allocate points for precomputation */
    v = val;
    for (i = 0; i < num + num_scalar; i++) {
        val_sub[i] = v;
        for (j = 0; j < ((size_t)1 << (wsize[i] - 1)); j++) {
            *v = EC_POINT_new(group);
            if (*v == NULL)
                goto err;
            v++;
        }
    }
    if (!(v == val + num_val)) {
        ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((tmp = EC_POINT_new(group)) == NULL)
        goto err;

    /*-
     * prepare precomputed values:
     *    val_sub[i][0] :=     points[i]
     *    val_sub[i][1] := 3 * points[i]
     *    val_sub[i][2] := 5 * points[i]
     *    ...
     */
    for (i = 0; i < num + num_scalar; i++) {
        if (i < num) {
            if (!EC_POINT_copy(val_sub[i][0], points[i]))
                goto err;
        } else {
            if (!EC_POINT_copy(val_sub[i][0], generator))
                goto err;
        }

        if (wsize[i] > 1) {
            if (!EC_POINT_dbl(group, tmp, val_sub[i][0], ctx))
                goto err;
            for (j = 1; j < ((size_t)1 << (wsize[i] - 1)); j++) {
                if (!EC_POINT_add(group, val_sub[i][j], val_sub[i][j - 1], tmp, ctx))
                    goto err;
            }
        }
    }

    if (group->meth->points_make_affine == NULL
        || !group->meth->points_make_affine(group, num_val, val, ctx))
        goto err;

    r_is_at_infinity = 1;

    if (max_len > INT_MAX)
        goto err;
    for (k = (int)(max_len - 1); k >= 0; k--) {
        if (!r_is_at_infinity) {
            if (!EC_POINT_dbl(group, r, r, ctx))
                goto err;
        }

        for (i = 0; i < totalnum; i++) {
            if (wNAF_len[i] > (size_t)k) {
                int digit = wNAF[i][k];
                int is_neg;

                if (digit) {
                    is_neg = digit < 0;

                    if (is_neg)
                        digit = -digit;

                    if (is_neg != r_is_inverted) {
                        if (!r_is_at_infinity) {
                            if (!EC_POINT_invert(group, r, ctx))
                                goto err;
                        }
                        r_is_inverted = !r_is_inverted;
                    }

                    /* digit > 0 */

                    if (r_is_at_infinity) {
                        if (!EC_POINT_copy(r, val_sub[i][digit >> 1]))
                            goto err;

                        /*-
                         * Apply coordinate blinding for EC_POINT.
                         *
                         * The underlying EC_METHOD can optionally implement this function:
                         * ossl_ec_point_blind_coordinates() returns 0 in case of errors or 1 on
                         * success or if coordinate blinding is not implemented for this
                         * group.
                         */
                        if (!ossl_ec_point_blind_coordinates(group, r, ctx)) {
                            ERR_raise(ERR_LIB_EC, EC_R_POINT_COORDINATES_BLIND_FAILURE);
                            goto err;
                        }

                        r_is_at_infinity = 0;
                    } else {
                        if (!EC_POINT_add(group, r, r, val_sub[i][digit >> 1], ctx))
                            goto err;
                    }
                }
            }
        }
    }

    if (r_is_at_infinity) {
        if (!EC_POINT_set_to_infinity(group, r))
            goto err;
    } else {
        if (r_is_inverted)
            if (!EC_POINT_invert(group, r, ctx))
                goto err;
    }

    ret = 1;

err:
    EC_POINT_free(tmp);
    OPENSSL_free(wsize);
    OPENSSL_free(wNAF_len);
    if (wNAF != NULL) {
        signed char **w;

        for (w = wNAF; *w != NULL; w++)
            OPENSSL_free(*w);

        OPENSSL_free(wNAF);
    }
    if (val != NULL) {
        for (v = val; *v != NULL; v++)
            EC_POINT_clear_free(*v);

        OPENSSL_free(val);
    }
    OPENSSL_free(val_sub);
    return ret;
}

/*-
 * ossl_ec_wNAF_precompute_mult()
 * creates an EC_PRE_COMP object with preprecomputed multiples of the generator
 * for use with wNAF splitting as implemented in ossl_ec_wNAF_mul().
 *
 * 'pre_comp->points' is an array of multiples of the generator
 * of the following form:
 * points[0] =     generator;
 * points[1] = 3 * generator;
 * ...
 * points[2^(w-1)-1] =     (2^(w-1)-1) * generator;
 * points[2^(w-1)]   =     2^blocksize * generator;
 * points[2^(w-1)+1] = 3 * 2^blocksize * generator;
 * ...
 * points[2^(w-1)*(numblocks-1)-1] = (2^(w-1)) *  2^(blocksize*(numblocks-2)) * generator
 * points[2^(w-1)*(numblocks-1)]   =              2^(blocksize*(numblocks-1)) * generator
 * ...
 * points[2^(w-1)*numblocks-1]     = (2^(w-1)) *  2^(blocksize*(numblocks-1)) * generator
 * points[2^(w-1)*numblocks]       = NULL
 */
int ossl_ec_wNAF_precompute_mult(EC_GROUP *group, BN_CTX *ctx)
{
    const EC_POINT *generator;
    EC_POINT *tmp_point = NULL, *base = NULL, **var;
    const BIGNUM *order;
    size_t i, bits, w, pre_points_per_block, blocksize, numblocks, num;
    EC_POINT **points = NULL;
    EC_PRE_COMP *pre_comp;
    int ret = 0;
    int used_ctx = 0;
#ifndef FIPS_MODULE
    BN_CTX *new_ctx = NULL;
#endif

    /* if there is an old EC_PRE_COMP object, throw it away */
    EC_pre_comp_free(group);
    if ((pre_comp = ec_pre_comp_new(group)) == NULL)
        return 0;

    generator = EC_GROUP_get0_generator(group);
    if (generator == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_UNDEFINED_GENERATOR);
        goto err;
    }

#ifndef FIPS_MODULE
    if (ctx == NULL)
        ctx = new_ctx = BN_CTX_new();
#endif
    if (ctx == NULL)
        goto err;

    BN_CTX_start(ctx);
    used_ctx = 1;

    order = EC_GROUP_get0_order(group);
    if (order == NULL)
        goto err;
    if (BN_is_zero(order)) {
        ERR_raise(ERR_LIB_EC, EC_R_UNKNOWN_ORDER);
        goto err;
    }

    bits = BN_num_bits(order);
    /*
     * The following parameters mean we precompute (approximately) one point
     * per bit. TBD: The combination 8, 4 is perfect for 160 bits; for other
     * bit lengths, other parameter combinations might provide better
     * efficiency.
     */
    blocksize = 8;
    w = 4;
    if (EC_window_bits_for_scalar_size(bits) > w) {
        /* let's not make the window too small ... */
        w = EC_window_bits_for_scalar_size(bits);
    }

    numblocks = (bits + blocksize - 1) / blocksize; /* max. number of blocks
                                                     * to use for wNAF
                                                     * splitting */

    pre_points_per_block = (size_t)1 << (w - 1);
    num = pre_points_per_block * numblocks; /* number of points to compute
                                             * and store */

    points = OPENSSL_malloc_array(num + 1, sizeof(*points));
    if (points == NULL)
        goto err;

    var = points;
    var[num] = NULL; /* pivot */
    for (i = 0; i < num; i++) {
        if ((var[i] = EC_POINT_new(group)) == NULL) {
            ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }
    }

    if ((tmp_point = EC_POINT_new(group)) == NULL
        || (base = EC_POINT_new(group)) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_POINT_copy(base, generator))
        goto err;

    /* do the precomputation */
    for (i = 0; i < numblocks; i++) {
        size_t j;

        if (!EC_POINT_dbl(group, tmp_point, base, ctx))
            goto err;

        if (!EC_POINT_copy(*var++, base))
            goto err;

        for (j = 1; j < pre_points_per_block; j++, var++) {
            /*
             * calculate odd multiples of the current base point
             */
            if (!EC_POINT_add(group, *var, tmp_point, *(var - 1), ctx))
                goto err;
        }

        if (i < numblocks - 1) {
            /*
             * get the next base (multiply current one by 2^blocksize)
             */
            size_t k;

            if (blocksize <= 2) {
                ERR_raise(ERR_LIB_EC, ERR_R_INTERNAL_ERROR);
                goto err;
            }

            if (!EC_POINT_dbl(group, base, tmp_point, ctx))
                goto err;
            for (k = 2; k < blocksize; k++) {
                if (!EC_POINT_dbl(group, base, base, ctx))
                    goto err;
            }
        }
    }

    if (group->meth->points_make_affine == NULL
        || !group->meth->points_make_affine(group, num, points, ctx))
        goto err;

    pre_comp->group = group;
    pre_comp->blocksize = blocksize;
    pre_comp->numblocks = numblocks;
    pre_comp->w = w;
    pre_comp->points = points;
    points = NULL;
    pre_comp->num = num;
    SETPRECOMP(group, ec, pre_comp);
    pre_comp = NULL;
    ret = 1;

err:
    if (used_ctx)
        BN_CTX_end(ctx);
#ifndef FIPS_MODULE
    BN_CTX_free(new_ctx);
#endif
    EC_ec_pre_comp_free(pre_comp);
    if (points) {
        EC_POINT **p;

        for (p = points; *p != NULL; p++)
            EC_POINT_free(*p);
        OPENSSL_free(points);
    }
    EC_POINT_free(tmp_point);
    EC_POINT_free(base);
    return ret;
}

int ossl_ec_wNAF_have_precompute_mult(const EC_GROUP *group)
{
    return HAVEPRECOMP(group, ec);
}
