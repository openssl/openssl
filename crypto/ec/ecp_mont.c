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
 * ECDSA low-level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"
#include "internal/safe_math.h"

#include <openssl/err.h>

#include "ec_local.h"
#include "crypto/bn.h" /* bn_get_ossl_fn(), bn_acquire_ossl_fn(), bn_release() */
#include "crypto/fn.h"
#include "crypto/fn_intern.h" /* ossl_fn_get_dsize() */

OSSL_SAFE_MATH_ADDU(size_t, size_t, OSSL_SAFE_MATH_MAXU(size_t))

const EC_METHOD *EC_GFp_mont_method(void)
{
    static const EC_METHOD ret = {
        EC_FLAGS_DEFAULT_OCT,
        NID_X9_62_prime_field,
        ossl_ec_GFp_mont_group_init,
        ossl_ec_GFp_mont_group_finish,
        ossl_ec_GFp_mont_group_clear_finish,
        ossl_ec_GFp_mont_group_copy,
        ossl_ec_GFp_mont_group_set_curve,
        ossl_ec_GFp_simple_group_get_curve,
        ossl_ec_GFp_simple_group_get_degree,
        ossl_ec_group_simple_order_bits,
        ossl_ec_GFp_simple_group_check_discriminant,
        ossl_ec_GFp_simple_point_init,
        ossl_ec_GFp_simple_point_finish,
        ossl_ec_GFp_simple_point_clear_finish,
        ossl_ec_GFp_simple_point_copy,
        ossl_ec_GFp_simple_point_set_to_infinity,
        ossl_ec_GFp_simple_point_set_affine_coordinates,
        ossl_ec_GFp_simple_point_get_affine_coordinates,
        0, 0, 0,
        ossl_ec_GFp_simple_add,
        ossl_ec_GFp_simple_dbl,
        ossl_ec_GFp_simple_invert,
        ossl_ec_GFp_simple_is_at_infinity,
        ossl_ec_GFp_simple_is_on_curve,
        ossl_ec_GFp_simple_cmp,
        ossl_ec_GFp_simple_make_affine,
        ossl_ec_GFp_simple_points_make_affine,
        0 /* mul */,
        0 /* precompute_mult */,
        0 /* have_precompute_mult */,
        ossl_ec_GFp_mont_field_mul,
        ossl_ec_GFp_mont_field_sqr,
        0 /* field_div */,
        ossl_ec_GFp_mont_field_inv,
        ossl_ec_GFp_mont_field_encode,
        ossl_ec_GFp_mont_field_decode,
        ossl_ec_GFp_mont_field_set_to_one,
        ossl_ec_key_simple_priv2oct,
        ossl_ec_key_simple_oct2priv,
        0, /* set private */
        ossl_ec_key_simple_generate_key,
        ossl_ec_key_simple_check_key,
        ossl_ec_key_simple_generate_public_key,
        0, /* keycopy */
        0, /* keyfinish */
        ossl_ecdh_simple_compute_key,
        ossl_ecdsa_simple_sign_setup,
        ossl_ecdsa_simple_sign_sig,
        ossl_ecdsa_simple_verify_sig,
        0, /* field_inverse_mod_ord */
        ossl_ec_GFp_simple_blind_coordinates,
        ossl_ec_GFp_simple_ladder_pre,
        ossl_ec_GFp_simple_ladder_step,
        ossl_ec_GFp_simple_ladder_post
    };

    return &ret;
}

int ossl_ec_GFp_mont_group_init(EC_GROUP *group)
{
    int ok;

    ok = ossl_ec_GFp_simple_group_init(group);
    group->field_data1 = NULL;
    group->field_data2 = NULL;
    return ok;
}

void ossl_ec_GFp_mont_group_finish(EC_GROUP *group)
{
    BN_MONT_CTX_free(group->field_data1);
    group->field_data1 = NULL;
    BN_free(group->field_data2);
    group->field_data2 = NULL;
    ossl_ec_GFp_simple_group_finish(group);
}

void ossl_ec_GFp_mont_group_clear_finish(EC_GROUP *group)
{
    BN_MONT_CTX_free(group->field_data1);
    group->field_data1 = NULL;
    BN_clear_free(group->field_data2);
    group->field_data2 = NULL;
    ossl_ec_GFp_simple_group_clear_finish(group);
}

int ossl_ec_GFp_mont_group_copy(EC_GROUP *dest, const EC_GROUP *src)
{
    BN_MONT_CTX_free(dest->field_data1);
    dest->field_data1 = NULL;
    BN_clear_free(dest->field_data2);
    dest->field_data2 = NULL;

    if (!ossl_ec_GFp_simple_group_copy(dest, src))
        return 0;

    if (src->field_data1 != NULL) {
        dest->field_data1 = BN_MONT_CTX_new();
        if (dest->field_data1 == NULL)
            return 0;
        if (!BN_MONT_CTX_copy(dest->field_data1, src->field_data1))
            goto err;
    }
    if (src->field_data2 != NULL) {
        dest->field_data2 = BN_dup(src->field_data2);
        if (dest->field_data2 == NULL)
            goto err;
    }

    return 1;

err:
    BN_MONT_CTX_free(dest->field_data1);
    dest->field_data1 = NULL;
    return 0;
}

int ossl_ec_GFp_mont_group_set_curve(EC_GROUP *group, const BIGNUM *p,
    const BIGNUM *a, const BIGNUM *b,
    BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    BN_MONT_CTX *mont = NULL;
    BIGNUM *one = NULL;
    int ret = 0;

    BN_MONT_CTX_free(group->field_data1);
    group->field_data1 = NULL;
    BN_free(group->field_data2);
    group->field_data2 = NULL;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new_ex(group->libctx);
        if (ctx == NULL)
            return 0;
    }

    mont = BN_MONT_CTX_new();
    if (mont == NULL)
        goto err;
    if (!BN_MONT_CTX_set(mont, p, ctx)) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }
    one = BN_new();
    if (one == NULL)
        goto err;
    if (!BN_to_montgomery(one, BN_value_one(), mont, ctx))
        goto err;

    group->field_data1 = mont;
    mont = NULL;
    group->field_data2 = one;
    one = NULL;

    ret = ossl_ec_GFp_simple_group_set_curve(group, p, a, b, ctx);

    if (!ret) {
        BN_MONT_CTX_free(group->field_data1);
        group->field_data1 = NULL;
        BN_free(group->field_data2);
        group->field_data2 = NULL;
    }

err:
    BN_free(one);
    BN_CTX_free(new_ctx);
    BN_MONT_CTX_free(mont);
    return ret;
}

int ossl_ec_GFp_mont_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
    const BIGNUM *b, BN_CTX *ctx)
{
    if (group->field_data1 == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_NOT_INITIALIZED);
        return 0;
    }

    return BN_mod_mul_montgomery(r, a, b, group->field_data1, ctx);
}

int ossl_ec_GFp_mont_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
    BN_CTX *ctx)
{
    if (group->field_data1 == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_NOT_INITIALIZED);
        return 0;
    }

    return BN_mod_mul_montgomery(r, a, a, group->field_data1, ctx);
}

/*-
 * Computes the multiplicative inverse of a in GF(p), storing the result in r.
 * If a is zero (or equivalent), you'll get an EC_R_CANNOT_INVERT error.
 * We have a Mont structure, so SCA hardening is FLT inversion.
 */
int ossl_ec_GFp_mont_field_inv(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
    BN_CTX *ctx)
{
    BIGNUM *e = NULL;
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (group->field_data1 == NULL)
        return 0;

    if (ctx == NULL
        && (ctx = new_ctx = BN_CTX_secure_new_ex(group->libctx)) == NULL)
        return 0;

    BN_CTX_start(ctx);
    if ((e = BN_CTX_get(ctx)) == NULL)
        goto err;

    /* Inverse in constant time with Fermats Little Theorem */
    if (!BN_set_word(e, 2))
        goto err;
    if (!BN_sub(e, group->field, e))
        goto err;
    /*-
     * Exponent e is public.
     * No need for scatter-gather or BN_FLG_CONSTTIME.
     */
    if (!BN_mod_exp_mont(r, a, e, group->field, ctx, group->field_data1))
        goto err;

    /* throw an error on zero */
    if (BN_is_zero(r)) {
        ERR_raise(ERR_LIB_EC, EC_R_CANNOT_INVERT);
        goto err;
    }

    ret = 1;

err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

int ossl_ec_GFp_mont_field_encode(const EC_GROUP *group, BIGNUM *r,
    const BIGNUM *a, BN_CTX *ctx)
{
    if (group->field_data1 == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_NOT_INITIALIZED);
        return 0;
    }

    return BN_to_montgomery(r, a, (BN_MONT_CTX *)group->field_data1, ctx);
}

int ossl_ec_GFp_mont_field_decode(const EC_GROUP *group, BIGNUM *r,
    const BIGNUM *a, BN_CTX *ctx)
{
    if (group->field_data1 == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_NOT_INITIALIZED);
        return 0;
    }

    return BN_from_montgomery(r, a, group->field_data1, ctx);
}

int ossl_ec_GFp_mont_field_set_to_one(const EC_GROUP *group, BIGNUM *r,
    BN_CTX *ctx)
{
    if (group->field_data2 == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_NOT_INITIALIZED);
        return 0;
    }

    if (BN_copy(r, group->field_data2) == NULL)
        return 0;
    return 1;
}

/*-
 * OSSL_FN x-only (differential) Montgomery-ladder step; see the banner in
 * ec_local.h.  Mirrors ossl_ec_GFp_simple_ladder_step() operation for
 * operation, with the field arithmetic on the coordinates' OSSL_FN view.  The
 * BIGNUM original is already branchless, so this port is genuinely
 * constant-time: no value-dependent control flow.
 */
int ossl_ec_GFp_mont_ladder_step_fn(const EC_GROUP *group, EC_POINT *r,
    EC_POINT *s, EC_POINT *p, OSSL_FN_CTX *ctx)
{
    OSSL_FN_MONT_CTX *mont = group->fn_mont_ctx;
    const void *token = NULL;
    const OSSL_FN *p_fn = bn_get_ossl_fn(group->field);
    OSSL_FN *t0, *t1, *t2, *t3, *t4, *t5, *t6, *ca, *cb, *px;
    OSSL_FN *rx = NULL, *rz = NULL, *sx = NULL, *sz = NULL;
    int w = (int)ossl_fn_get_dsize(p_fn);
    int ret = 0;

    if ((token = OSSL_FN_CTX_start(ctx)) == NULL)
        return 0;

    if ((t0 = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (t1 = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (t2 = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (t3 = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (t4 = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (t5 = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (t6 = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (ca = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (cb = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (px = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL)
        goto err;

    /* r, s, p are distinct; acquire r/s coords, then copy p->X, a and b to w. */
    if ((rx = bn_acquire_ossl_fn(r->X, w)) == NULL
        || (rz = bn_acquire_ossl_fn(r->Z, w)) == NULL
        || (sx = bn_acquire_ossl_fn(s->X, w)) == NULL
        || (sz = bn_acquire_ossl_fn(s->Z, w)) == NULL)
        goto err;
    if (OSSL_FN_copy_truncate(px, bn_get_ossl_fn(p->X)) == NULL
        || OSSL_FN_copy_truncate(ca, bn_get_ossl_fn(group->a)) == NULL
        || OSSL_FN_copy_truncate(cb, bn_get_ossl_fn(group->b)) == NULL)
        goto err;

#define MUL(R, A, B) OSSL_FN_mul_mont_quick((R), (A), (B), mont, ctx)
#define SQR(R, A) OSSL_FN_mul_mont_quick((R), (A), (A), mont, ctx)
    if (!MUL(t6, rx, sx)
        || !MUL(t0, rz, sz)
        || !MUL(t4, rx, sz)
        || !MUL(t3, rz, sx)
        || !MUL(t5, ca, t0)
        || !OSSL_FN_mod_add_quick(t5, t6, t5, p_fn)
        || !OSSL_FN_mod_add_quick(t6, t3, t4, p_fn)
        || !MUL(t5, t6, t5)
        || !SQR(t0, t0)
        || !OSSL_FN_mod_lshift_quick(t2, cb, 2, p_fn)
        || !MUL(t0, t2, t0)
        || !OSSL_FN_mod_lshift1_quick(t5, t5, p_fn)
        || !OSSL_FN_mod_sub_quick(t3, t4, t3, p_fn)
        /* s->Z output */
        || !SQR(sz, t3)
        || !MUL(t4, sz, px)
        || !OSSL_FN_mod_add_quick(t0, t0, t5, p_fn)
        /* s->X output */
        || !OSSL_FN_mod_sub_quick(sx, t0, t4, p_fn)
        || !SQR(t4, rx)
        || !SQR(t5, rz)
        || !MUL(t6, t5, ca)
        || !OSSL_FN_mod_add_quick(t1, rx, rz, p_fn)
        || !SQR(t1, t1)
        || !OSSL_FN_mod_sub_quick(t1, t1, t4, p_fn)
        || !OSSL_FN_mod_sub_quick(t1, t1, t5, p_fn)
        || !OSSL_FN_mod_sub_quick(t3, t4, t6, p_fn)
        || !SQR(t3, t3)
        || !MUL(t0, t5, t1)
        || !MUL(t0, t2, t0)
        /* r->X output */
        || !OSSL_FN_mod_sub_quick(rx, t3, t0, p_fn)
        || !OSSL_FN_mod_add_quick(t3, t4, t6, p_fn)
        || !SQR(t4, t5)
        || !MUL(t4, t4, t2)
        || !MUL(t1, t1, t3)
        || !OSSL_FN_mod_lshift1_quick(t1, t1, p_fn)
        /* r->Z output */
        || !OSSL_FN_mod_add_quick(rz, t4, t1, p_fn))
        goto err;
#undef MUL
#undef SQR

    ret = 1;

err:
    if (rx != NULL)
        bn_release(r->X, w);
    if (rz != NULL)
        bn_release(r->Z, w);
    if (sx != NULL)
        bn_release(s->X, w);
    if (sz != NULL)
        bn_release(s->Z, w);
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

size_t ossl_ec_GFp_mont_ladder_step_fn_ctx_size(const EC_GROUP *group,
    EC_POINT *r, EC_POINT *s, EC_POINT *p)
{
    OSSL_FN_MONT_CTX *mont = group->fn_mont_ctx;
    const OSSL_FN *p_fn = bn_get_ossl_fn(group->field);
    size_t w = ossl_fn_get_dsize(p_fn);
    size_t own = OSSL_FN_CTX_size(1, 10, 10 * w); /* t0..t6, ca, cb, px */
    size_t mul = OSSL_FN_mul_mont_quick_ctx_size(NULL, NULL, NULL, mont);
    int err = 0;
    size_t ret = safe_add_size_t(own, mul, &err);

    if (own == 0 || mul == 0)
        return 0;
    return err == 0 ? ret : 0;
}

/*-
 * OSSL_FN x-only ladder setup; see the banner in ec_local.h.  Mirrors
 * ossl_ec_GFp_simple_ladder_pre() operation for operation: r := 2p and s := p
 * in projective x-only coordinates, followed by independent coordinate
 * blinding.  Like the original it reuses the output-point coordinates as
 * scratch.  The only branch is on the public p->Z_is_one.
 */
int ossl_ec_GFp_mont_ladder_pre_fn(const EC_GROUP *group, EC_POINT *r,
    EC_POINT *s, EC_POINT *p, OSSL_FN_CTX *ctx)
{
    OSSL_FN_MONT_CTX *mont = group->fn_mont_ctx;
    const void *token = NULL;
    const OSSL_FN *p_fn = bn_get_ossl_fn(group->field);
    OSSL_FN *ca, *cb, *px;
    OSSL_FN *rx = NULL, *rz = NULL, *ry = NULL;
    OSSL_FN *sx = NULL, *sz = NULL, *sy = NULL;
    int w = (int)ossl_fn_get_dsize(p_fn);
    int ret = 0;

    if (!p->Z_is_one) /* the ladder always passes p in affine form */
        return 0;

    if ((token = OSSL_FN_CTX_start(ctx)) == NULL)
        return 0;

    if ((ca = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (cb = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (px = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL)
        goto err;

    if ((rx = bn_acquire_ossl_fn(r->X, w)) == NULL
        || (rz = bn_acquire_ossl_fn(r->Z, w)) == NULL
        || (ry = bn_acquire_ossl_fn(r->Y, w)) == NULL
        || (sx = bn_acquire_ossl_fn(s->X, w)) == NULL
        || (sz = bn_acquire_ossl_fn(s->Z, w)) == NULL
        || (sy = bn_acquire_ossl_fn(s->Y, w)) == NULL)
        goto err;
    if (OSSL_FN_copy_truncate(px, bn_get_ossl_fn(p->X)) == NULL
        || OSSL_FN_copy_truncate(ca, bn_get_ossl_fn(group->a)) == NULL
        || OSSL_FN_copy_truncate(cb, bn_get_ossl_fn(group->b)) == NULL)
        goto err;

#define MUL(R, A, B) OSSL_FN_mul_mont_quick((R), (A), (B), mont, ctx)
#define SQR(R, A) OSSL_FN_mul_mont_quick((R), (A), (A), mont, ctx)
    /*
     * r := 2p, x-only.  Scratch layout matches the BIGNUM original:
     * t1=s->Z, t2=r->Z, t3=s->X, t4=r->X, t5=s->Y.
     */
    if (!SQR(sx, px) /* t3 = p->X^2 */
        || !OSSL_FN_mod_sub_quick(rx, sx, ca, p_fn) /* t4 = t3 - a */
        || !SQR(rx, rx) /* t4 = t4^2 */
        || !MUL(sy, px, cb) /* t5 = p->X * b */
        || !OSSL_FN_mod_lshift_quick(sy, sy, 3, p_fn) /* t5 <<= 3 */
        || !OSSL_FN_mod_sub_quick(rx, rx, sy, p_fn) /* r->X = t4 - t5 */
        || !OSSL_FN_mod_add_quick(sz, sx, ca, p_fn) /* t1 = t3 + a */
        || !MUL(rz, px, sz) /* t2 = p->X * t1 */
        || !OSSL_FN_mod_add_quick(rz, cb, rz, p_fn) /* t2 = b + t2 */
        || !OSSL_FN_mod_lshift_quick(rz, rz, 2, p_fn)) /* r->Z = t2 << 2 */
        goto err;

    /* lambda_r (r->Y) and lambda_s (s->Z): nonzero blinding factors */
    do {
        if (!OSSL_FN_priv_rand_range(ry, p_fn, 0, group->libctx))
            goto err;
    } while (OSSL_FN_is_zero(ry));
    do {
        if (!OSSL_FN_priv_rand_range(sz, p_fn, 0, group->libctx))
            goto err;
    } while (OSSL_FN_is_zero(sz));

    /* convert the blinding factors to the Montgomery domain, then blind */
    if (!OSSL_FN_to_mont(ry, ry, mont, ctx)
        || !OSSL_FN_to_mont(sz, sz, mont, ctx)
        || !MUL(rz, rz, ry)
        || !MUL(rx, rx, ry)
        || !MUL(sx, px, sz)) /* s := p (blinded) */
        goto err;
#undef MUL
#undef SQR

    if (rx != NULL)
        bn_release(r->X, w);
    if (rz != NULL)
        bn_release(r->Z, w);
    if (ry != NULL)
        bn_release(r->Y, w);
    if (sx != NULL)
        bn_release(s->X, w);
    if (sz != NULL)
        bn_release(s->Z, w);
    if (sy != NULL)
        bn_release(s->Y, w);
    r->Z_is_one = 0;
    s->Z_is_one = 0;
    ret = 1;

err:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

size_t ossl_ec_GFp_mont_ladder_pre_fn_ctx_size(const EC_GROUP *group,
    EC_POINT *r, EC_POINT *s, EC_POINT *p)
{
    OSSL_FN_MONT_CTX *mont = group->fn_mont_ctx;
    const OSSL_FN *p_fn = bn_get_ossl_fn(group->field);
    size_t w = ossl_fn_get_dsize(p_fn);
    size_t own = OSSL_FN_CTX_size(1, 3, 3 * w); /* ca, cb, px */
    size_t mul = OSSL_FN_mul_mont_quick_ctx_size(NULL, NULL, NULL, mont);
    /*
     * The blinding factors fed to OSSL_FN_to_mont() are always w-wide and
     * reduced (< field), so p_fn (== field, w-wide) is a safe upper bound on
     * the encode context; passing r == NULL matches the in-place r->dsize.
     */
    size_t enc = OSSL_FN_to_mont_ctx_size(NULL, p_fn, mont);
    size_t nested = mul > enc ? mul : enc;
    int err = 0;
    size_t ret = safe_add_size_t(own, nested, &err);

    if (own == 0 || mul == 0 || enc == 0)
        return 0;
    return err == 0 ? ret : 0;
}

/*-
 * OSSL_FN Y-recovery and back-conversion to affine; see the banner in
 * ec_local.h.  Mirrors ossl_ec_GFp_simple_ladder_post() operation for
 * operation, working on the coordinates' OSSL_FN view.  The two early returns
 * and the FLT inversion match the original's constant-time profile.
 */
int ossl_ec_GFp_mont_ladder_post_fn(const EC_GROUP *group, EC_POINT *r,
    EC_POINT *s, EC_POINT *p, OSSL_FN_CTX *ctx)
{
    OSSL_FN_MONT_CTX *mont = group->fn_mont_ctx;
    const void *token = NULL;
    const OSSL_FN *p_fn = bn_get_ossl_fn(group->field);
    const OSSL_FN *sx, *sz;
    OSSL_FN *t0, *t1, *t2, *t3, *t4, *t5, *t6, *ca, *cb, *e, *px, *py;
    OSSL_FN *rx = NULL, *ry = NULL, *rz = NULL;
    int w = (int)ossl_fn_get_dsize(p_fn);
    int ret = 0;

    /* Edge cases, branching on the public result -- as the BIGNUM original. */
    if (BN_is_zero(r->Z))
        return EC_POINT_set_to_infinity(group, r);
    if (BN_is_zero(s->Z)) {
        if (!EC_POINT_copy(r, p) || !EC_POINT_invert(group, r, NULL))
            return 0;
        return 1;
    }

    if ((token = OSSL_FN_CTX_start(ctx)) == NULL)
        return 0;

    if ((t0 = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (t1 = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (t2 = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (t3 = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (t4 = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (t5 = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (t6 = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (ca = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (cb = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (e = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (px = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL
        || (py = OSSL_FN_CTX_get_limbs(ctx, w)) == NULL)
        goto err;

    if ((rx = bn_acquire_ossl_fn(r->X, w)) == NULL
        || (ry = bn_acquire_ossl_fn(r->Y, w)) == NULL
        || (rz = bn_acquire_ossl_fn(r->Z, w)) == NULL)
        goto err;
    sx = bn_get_ossl_fn(s->X);
    sz = bn_get_ossl_fn(s->Z);
    if (OSSL_FN_copy_truncate(px, bn_get_ossl_fn(p->X)) == NULL
        || OSSL_FN_copy_truncate(py, bn_get_ossl_fn(p->Y)) == NULL
        || OSSL_FN_copy_truncate(ca, bn_get_ossl_fn(group->a)) == NULL
        || OSSL_FN_copy_truncate(cb, bn_get_ossl_fn(group->b)) == NULL)
        goto err;

    /* e = field - 2, the public FLT inversion exponent */
    if (OSSL_FN_copy(e, p_fn) == NULL || !OSSL_FN_sub_word(e, 2))
        goto err;

#define MUL(R, A, B) OSSL_FN_mul_mont_quick((R), (A), (B), mont, ctx)
#define SQR(R, A) OSSL_FN_mul_mont_quick((R), (A), (A), mont, ctx)
    if (!OSSL_FN_mod_lshift1_quick(t4, py, p_fn) /* t4 = 2*p->Y */
        || !MUL(t6, rx, t4)
        || !MUL(t6, sz, t6)
        || !MUL(t5, rz, t6)
        || !OSSL_FN_mod_lshift1_quick(t1, cb, p_fn) /* t1 = 2*b */
        || !MUL(t1, sz, t1)
        || !SQR(t3, rz)
        || !MUL(t2, t3, t1)
        || !MUL(t6, rz, ca)
        || !MUL(t1, px, rx)
        || !OSSL_FN_mod_add_quick(t1, t1, t6, p_fn)
        || !MUL(t1, sz, t1)
        || !MUL(t0, px, rz)
        || !OSSL_FN_mod_add_quick(t6, rx, t0, p_fn)
        || !MUL(t6, t6, t1)
        || !OSSL_FN_mod_add_quick(t6, t6, t2, p_fn)
        || !OSSL_FN_mod_sub_quick(t0, t0, rx, p_fn)
        || !SQR(t0, t0)
        || !MUL(t0, t0, sx)
        || !OSSL_FN_mod_sub_quick(t0, t6, t0, p_fn)
        || !MUL(t1, sz, t4)
        || !MUL(t1, t3, t1)
        /* t1 := t1^-1 in the Montgomery domain via FLT (public exponent) */
        || !OSSL_FN_from_mont(t1, t1, mont, ctx)
        || !OSSL_FN_mod_exp_mont(t1, t1, e, p_fn, ctx, mont)
        || !OSSL_FN_to_mont(t1, t1, mont, ctx)
        /* r->X, r->Y outputs */
        || !MUL(rx, t5, t1)
        || !MUL(ry, t0, t1)
        /* r->Z := Montgomery 1 */
        || !OSSL_FN_set_word(rz, 1)
        || !OSSL_FN_to_mont(rz, rz, mont, ctx))
        goto err;
#undef MUL
#undef SQR

    if (rz != NULL)
        bn_release(r->X, w);
    if (ry != NULL)
        bn_release(r->Y, w);
    if (rz != NULL)
        bn_release(r->Z, w);
    r->Z_is_one = 1;
    ret = 1;

err:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

size_t ossl_ec_GFp_mont_ladder_post_fn_ctx_size(const EC_GROUP *group,
    EC_POINT *r, EC_POINT *s, EC_POINT *p)
{
    OSSL_FN_MONT_CTX *mont = group->fn_mont_ctx;
    const OSSL_FN *p_fn = bn_get_ossl_fn(group->field);
    size_t w = ossl_fn_get_dsize(p_fn);
    size_t own = OSSL_FN_CTX_size(1, 12, 12 * w); /* t0..t6, ca, cb, e, px, py */
    size_t mul = OSSL_FN_mul_mont_quick_ctx_size(NULL, NULL, NULL, mont);
    size_t frm = OSSL_FN_from_mont_ctx_size(NULL, p_fn, mont);
    size_t tom = OSSL_FN_to_mont_ctx_size(NULL, p_fn, mont);
    size_t exp = OSSL_FN_mod_exp_mont_ctx_size(p_fn, p_fn, p_fn, p_fn, mont);
    size_t nested, ret;
    int err = 0;

    if (own == 0 || mul == 0 || frm == 0 || tom == 0 || exp == 0)
        return 0;
    nested = mul;
    if (frm > nested)
        nested = frm;
    if (tom > nested)
        nested = tom;
    if (exp > nested)
        nested = exp;
    ret = safe_add_size_t(own, nested, &err);
    return err == 0 ? ret : 0;
}
