/*
 * ====================================================================
 * Copyright 2015 MIRACL UK Ltd., All Rights Reserved. Portions of the
 * attached software ("Contribution") are developed by MIRACL UK LTD., and
 * are contributed to the OpenSSL project. The Contribution is licensed
 * pursuant to the OpenSSL open source license provided above.
 */

#include "bp_lcl.h"

FP2 *FP2_new()
{
    FP2 *ret = NULL;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL) {
        return (NULL);
    }

    ret->f[0] = BN_new();
    ret->f[1] = BN_new();

    if (ret->f[0] == NULL || ret->f[1] == NULL) {
        BN_free(ret->f[0]);
        BN_free(ret->f[1]);
        return NULL;
    }
    return ret;
}

void FP2_clear(FP2 *a)
{
    BN_clear(a->f[0]);
    BN_clear(a->f[1]);
}

void FP2_free(FP2 *a)
{
    if (a == NULL) {
        return;
    } else {
        BN_free(a->f[0]);
        BN_free(a->f[1]);
    }
    OPENSSL_free(a);
}

void FP2_clear_free(FP2 *a)
{
    if (a == NULL) {
        return;
    } else {
        BN_clear_free(a->f[0]);
        BN_clear_free(a->f[1]);
    }
    OPENSSL_free(a);
}

int FP2_rand(const BP_GROUP *group, FP2 *a)
{
    if (!BN_rand_range(a->f[0], group->field)) {
        return 0;
    }
    if (!BN_rand_range(a->f[1], group->field)) {
        return 0;
    }
    return 1;
}

void FP2_print(const FP2 *a)
{
    BN_print_fp(stdout, a->f[0]);
    printf("\n");
    BN_print_fp(stdout, a->f[1]);
    printf("\n");
}

int FP2_zero(FP2 *a)
{
    if (!BN_zero(a->f[0]))
        return 0;
    if (!BN_zero(a->f[1]))
        return 0;
    return 1;
}

int FP2_cmp(const FP2 *a, const FP2 *b)
{
    if (BN_cmp(a->f[0], b->f[0]) != 0)
        return 1;
    if (BN_cmp(a->f[1], b->f[1]) != 0)
        return 1;
    return 0;
}

int FP2_copy(FP2 *a, const FP2 *b)
{
    if (!BN_copy(a->f[0], b->f[0]))
        return 0;
    if (!BN_copy(a->f[1], b->f[1]))
        return 0;
    return 1;
}

int FP2_is_zero(const FP2 *a)
{
    return BN_is_zero(a->f[0]) & BN_is_zero(a->f[1]);
}

int FP2_add(const BP_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b)
{
    if (!BN_mod_add_quick(r->f[0], a->f[0], b->f[0], group->field))
        return 0;
    if (!BN_mod_add_quick(r->f[1], a->f[1], b->f[1], group->field))
        return 0;
    return 1;
}

int FP2_dbl(const BP_GROUP *group, FP2 *r, const FP2 *a)
{
    if (!BN_mod_lshift1_quick(r->f[0], a->f[0], group->field))
        return 0;
    if (!BN_mod_lshift1_quick(r->f[1], a->f[1], group->field))
        return 0;
    return 1;
}

int FP2_sub(const BP_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b)
{
    if (!BN_mod_sub_quick(r->f[0], a->f[0], b->f[0], group->field))
        return 0;
    if (!BN_mod_sub_quick(r->f[1], a->f[1], b->f[1], group->field))
        return 0;
    return 1;
}

int FP2_neg(const BP_GROUP *group, FP2 *r, const FP2 *a)
{
    if (!BN_sub(r->f[0], group->field, a->f[0]))
        return 0;
    if (!BN_sub(r->f[1], group->field, a->f[1]))
        return 0;
    return 1;
}

int FP2_mul_frb(const BP_GROUP *group, FP2 *r, const FP2 *a, int i,
                BN_CTX *ctx)
{
    FP2 *frb = NULL;
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (ctx == NULL)
        if ((ctx = new_ctx = BN_CTX_new()) == NULL)
            return 0;

    if ((frb = FP2_new()) == NULL)
        goto err;

    /*
     * Multiply by powers of residue powered to (p-1)/6.
     */
    if (i == 1) {
        if (!FP2_mul(group, r, a, group->frb, ctx))
            goto err;
    }

    if (i == 2) {
        if (!FP2_sqr(group, frb, group->frb, ctx))
            goto err;
        if (!FP2_mul(group, r, a, frb, ctx))
            goto err;
    }

    if (i == 3) {
        if (!FP2_sqr(group, frb, group->frb, ctx))
            goto err;
        if (!FP2_mul(group, r, a, frb, ctx))
            goto err;
        if (!FP2_mul(group, r, a, group->frb, ctx))
            goto err;
    }

    if (i == 4) {
        if (!FP2_sqr(group, frb, group->frb, ctx))
            goto err;
        if (!FP2_sqr(group, frb, frb, ctx))
            goto err;
        if (!FP2_mul(group, r, a, frb, ctx))
            goto err;
    }

    if (i == 5) {
        if (!FP2_sqr(group, frb, group->frb, ctx))
            goto err;
        if (!FP2_sqr(group, frb, frb, ctx))
            goto err;
        if (!FP2_mul(group, r, a, frb, ctx))
            goto err;
        if (!FP2_mul(group, r, a, group->frb, ctx))
            goto err;
    }

    ret = 1;

 err:
    FP2_free(frb);
    BN_CTX_free(new_ctx);
    return ret;
}

int FP2_mul(const BP_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b,
            BN_CTX *ctx)
{
    BIGNUM *t0, *t1, *t2, *t3, *t4;
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (ctx == NULL)
        if ((ctx = new_ctx = BN_CTX_new()) == NULL)
            return 0;

    BN_CTX_start(ctx);
    if (((t0 = BN_CTX_get(ctx)) == NULL) ||
        ((t1 = BN_CTX_get(ctx)) == NULL) ||
        ((t2 = BN_CTX_get(ctx)) == NULL) ||
        ((t3 = BN_CTX_get(ctx)) == NULL) ||
        ((t4 = BN_CTX_get(ctx)) == NULL)) {
        goto err;
    }

    /*
     * Karatsuba algorithm.
     */

    /*
     * t2 = a_0 + a_1, t1 = b_0 + b_1.
     */
    if (!BN_mod_add_quick(t2, a->f[0], a->f[1], group->field))
        goto err;
    if (!BN_mod_add_quick(t1, b->f[0], b->f[1], group->field))
        goto err;

    /*
     * t3 = (a_0 + a_1) * (b_0 + b_1).
     */
    if (!BN_mod_mul_montgomery(t3, t2, t1, group->mont, ctx))
        goto err;

    /*
     * t0 = a_0 * b_0, t4 = a_1 * b_1.
     */
    if (!BN_mod_mul_montgomery(t0, a->f[0], b->f[0], group->mont, ctx))
        goto err;
    if (!BN_mod_mul_montgomery(t4, a->f[1], b->f[1], group->mont, ctx))
        goto err;

    /*
     * t2 = (a_0 * b_0) + (a_1 * b_1).
     */
    if (!BN_mod_add_quick(t2, t0, t4, group->field))
        goto err;

    /*
     * t1 = (a_0 * b_0) + u^2 * (a_1 * b_1).
     */
    if (!BN_mod_sub_quick(r->f[0], t0, t4, group->field))
        goto err;

    /*
     * t4 = t3 - t2.
     */
    if (!BN_mod_sub_quick(r->f[1], t3, t2, group->field))
        goto err;

    ret = 1;
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

int FP2_mul_nor(const BP_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx)
{
    BIGNUM *t;
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (ctx == NULL)
        if ((ctx = new_ctx = BN_CTX_new()) == NULL)
            return 0;

    BN_CTX_start(ctx);
    if ((t = BN_CTX_get(ctx)) == NULL) {
        goto err;
    }

    /*
     * Multiply by non-quadratic/cubic residue.
     */
    if (!BN_sub(t, group->field, a->f[1]))
        goto err;
    if (!BN_mod_add_quick(r->f[1], a->f[0], a->f[1], group->field))
        goto err;
    if (!BN_mod_add_quick(r->f[0], t, a->f[0], group->field))
        goto err;

    ret = 1;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

int FP2_mul_art(const BP_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx)
{
    BIGNUM *t;
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (ctx == NULL)
        if ((ctx = new_ctx = BN_CTX_new()) == NULL)
            return 0;

    BN_CTX_start(ctx);
    if ((t = BN_CTX_get(ctx)) == NULL) {
        goto err;
    }

    /*
     * Multiply by adjoined root.
     */
    BN_copy(t, a->f[0]);
    if (!BN_sub(r->f[0], group->field, a->f[1]))
        goto err;
    BN_copy(r->f[1], t);

    ret = 1;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

int FP2_sqr(const BP_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx)
{
    BIGNUM *t0, *t1, *t2;
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (ctx == NULL)
        if ((ctx = new_ctx = BN_CTX_new()) == NULL)
            return 0;

    BN_CTX_start(ctx);
    if (((t0 = BN_CTX_get(ctx)) == NULL) ||
        ((t1 = BN_CTX_get(ctx)) == NULL) ||
        ((t2 = BN_CTX_get(ctx)) == NULL)) {
        goto err;
    }

    /*
     * t0 = (a_0 + a_1).
     */
    if (!BN_mod_add_quick(t0, a->f[0], a->f[1], group->field))
        goto err;

    /*
     * t1 = (a_0 - a_1).
     */
    if (!BN_mod_sub_quick(t1, a->f[0], a->f[1], group->field))
        goto err;

    /*
     * t2 = 2 * a_0.
     */
    if (!BN_mod_lshift1_quick(t2, a->f[0], group->field))
        goto err;

    /*
     * c_1 = 2 * a_0 * a_1.
     */
    if (!BN_mod_mul_montgomery(r->f[1], t2, a->f[1], group->mont, ctx))
        goto err;
    /*
     * c_0 = a_0^2 + a_1^2 * u^2.
     */
    if (!BN_mod_mul_montgomery(r->f[0], t0, t1, group->mont, ctx))
        goto err;

    ret = 1;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

int FP2_inv(const BP_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx)
{
    BIGNUM *t0, *t1;
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (ctx == NULL)
        if ((ctx = new_ctx = BN_CTX_new()) == NULL)
            return 0;

    BN_CTX_start(ctx);
    if (((t0 = BN_CTX_get(ctx)) == NULL) || ((t1 = BN_CTX_get(ctx)) == NULL)) {
        goto err;
    }

    /*
     * t0 = a_0^2, t1 = a_1^2.
     */
    if (!BN_mod_mul_montgomery(t0, a->f[0], a->f[0], group->mont, ctx))
        goto err;
    if (!BN_mod_mul_montgomery(t1, a->f[1], a->f[1], group->mont, ctx))
        goto err;

    /*
     * t1 = 1/(a_0^2 + a_1^2).
     */
    if (!BN_mod_add_quick(t0, t0, t1, group->field))
        goto err;

    if (!BN_from_montgomery(t0, t0, group->mont, ctx))
        goto err;
    if (!BN_mod_inverse(t1, t0, group->field, ctx))
        goto err;
    if (!BN_to_montgomery(t1, t1, group->mont, ctx))
        goto err;

    /*
     * c_0 = a_0/(a_0^2 + a_1^2).
     */
    if (!BN_mod_mul_montgomery(r->f[0], a->f[0], t1, group->mont, ctx))
        goto err;

    /*
     * c_1 = - a_1/(a_0^2 + a_1^2).
     */
    if (!BN_mod_mul_montgomery(r->f[1], a->f[1], t1, group->mont, ctx))
        goto err;
    if (!BN_sub(r->f[1], group->field, r->f[1]))
        goto err;

    ret = 1;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

int FP2_conj(const BP_GROUP *group, FP2 *r, const FP2 *a)
{
    BN_copy(r->f[0], a->f[0]);
    if (!BN_sub(r->f[1], group->field, a->f[1]))
        return 0;
    return 1;
}

int FP2_inv_sim(const BP_GROUP *group, FP2 *r[], FP2 *a[], int num,
                BN_CTX *ctx)
{
    FP2 *t[num], *u = NULL;
    int i, ret = 0;

    if (num == 0)
        return 1;

    if ((u = FP2_new()) == NULL)
        goto err;
    for (i = 0; i < num; i++) {
        if (((t[i] = FP2_new()) == NULL))
            goto err;
    }

    /*
     * Simultaneous inversion or Montgomery's trick.
     * Begin by copying the first element to invert.
     */
    if (!FP2_copy(r[0], a[0]))
        goto err;
    if (!FP2_copy(t[0], a[0]))
        goto err;

    /*
     * Multiply all elements together.
     */
    for (i = 1; i < num; i++) {
        if (!FP2_copy(t[i], a[i]))
            goto err;
        if (!FP2_mul(group, r[i], r[i - 1], t[i], ctx))
            goto err;
    }

    /*
     * Invert the multiplication.
     */
    if (!FP2_inv(group, u, r[num - 1], ctx))
        goto err;

    /*
     * Recover individual elements.
     */
    for (i = num - 1; i > 0; i--) {
        if (!FP2_mul(group, r[i], r[i - 1], u, ctx))
            goto err;
        if (!FP2_mul(group, u, u, t[i], ctx))
            goto err;
    }
    if (!FP2_copy(r[0], u))
        goto err;

    ret = 1;
 err:
    FP2_free(u);
    for (i = 0; i < num; i++) {
        FP2_free(t[i]);
    }
    return ret;
}

int FP2_exp(const BP_GROUP *group, FP2 *r, const FP2 *a, const BIGNUM *b, BN_CTX *ctx)
{
    int i, ret = 0;
    FP2 *t = NULL;

    if (((t = FP2_new()) == NULL)) {
        goto err;
    }

    if (!FP2_copy(t, a))
        goto err;

    for (i = BN_num_bits(b) - 2; i >= 0; i--) {
        if (!FP2_sqr(group, t, t, ctx))
            goto err;
        if (BN_is_bit_set(b, i)) {
            if (!FP2_mul(group, t, t, a, ctx))
                goto err;
        }
    }

    if (!FP2_copy(r, t))
        goto err;

    ret = 1;
 err:
    FP2_free(t);
    return ret;
}
