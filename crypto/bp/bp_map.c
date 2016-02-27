/*
 * Written by Diego F. Aranha (d@miracl.com) and contributed to the
 * the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/*
 * ====================================================================
 * Copyright 2016 MIRACL UK Ltd., All Rights Reserved. Portions of the
 * attached software ("Contribution") are developed by MIRACL UK LTD., and
 * are contributed to the OpenSSL project. The Contribution is licensed
 * pursuant to the OpenSSL open source license provided above.
 */

#include "bp_lcl.h"

static int GT_miller_double(const BP_GROUP *group, FP12 *l, FP2 *x3,
                            FP2 *y3, FP2 *z3, const FP2 *x1,
                            const FP2 *y1, const FP2 *z1, const BIGNUM *xp,
                            const BIGNUM *yp, BN_CTX *ctx)
{
    FP2 *t0 = NULL, *t1 = NULL, *t2 = NULL, *t3 = NULL;
    FP2 *t4 = NULL, *t5 = NULL, *t6 = NULL, *u0 = NULL, *u1 = NULL;
    int ret = 0;

    if ((t0 = FP2_new()) == NULL || (t1 = FP2_new()) == NULL
        || (t2 = FP2_new()) == NULL || (t3 = FP2_new()) == NULL
        || (t4 = FP2_new()) == NULL || (t5 = FP2_new()) == NULL
        || (t6 = FP2_new()) == NULL || (u0 = FP2_new()) == NULL
        || (u1 = FP2_new()) == NULL)
        goto err;

    /*
     * C = z1^2.
     */
    if (!FP2_sqr(group, t0, z1, ctx))
        goto err;
    /*
     * B = y1^2.
     */
    if (!FP2_sqr(group, t1, y1, ctx))
        goto err;
    /*
     * t5 = B + C.
     */
    if (!FP2_add(group, t5, t0, t1))
        goto err;
    /*
     * t3 = E = 3b'C = 3C * (1 - i).
     */
    if (!FP2_add(group, t3, t0, t0))
        goto err;
    if (!FP2_add(group, t0, t0, t3))
        goto err;

    if (!BN_mod_add(t2->f[0], t0->f[0], t0->f[1], group->field, ctx))
        goto err;
    if (!BN_mod_sub(t2->f[1], t0->f[1], t0->f[0], group->field, ctx))
        goto err;

    /*
     * t0 = x1^2.
     */
    if (!FP2_sqr(group, t0, x1, ctx))
        goto err;
    /*
     * t4 = A = (x1 * y1)/2.
     */
    if (!FP2_mul(group, t4, x1, y1, ctx))
        goto err;

    if (BN_is_bit_set(t4->f[0], 0)
        && !BN_add(t4->f[0], t4->f[0], group->field))
        goto err;
    if (!BN_rshift1(t4->f[0], t4->f[0]))
        goto err;
    if (BN_is_bit_set(t4->f[1], 0)
        && !BN_add(t4->f[1], t4->f[1], group->field))
        goto err;
    if (!BN_rshift1(t4->f[1], t4->f[1]))
        goto err;

    /*
     * t3 = F = 3E.
     */
    if (!FP2_dbl(group, t3, t2))
        goto err;
    if (!FP2_add(group, t3, t3, t2))
        goto err;
    /*
     * x3 = A * (B - F).
     */
    if (!FP2_sub(group, x3, t1, t3))
        goto err;
    if (!FP2_mul(group, x3, x3, t4, ctx))
        goto err;

    /*
     * G = (B + F)/2.
     */
    if (!FP2_add(group, t3, t1, t3))
        goto err;
    if (BN_is_bit_set(t3->f[0], 0)
        && !BN_add(t3->f[0], t3->f[0], group->field))
        goto err;
    if (!BN_rshift1(t3->f[0], t3->f[0]))
        goto err;
    if (BN_is_bit_set(t3->f[1], 0)
        && !BN_add(t3->f[1], t3->f[1], group->field))
        goto err;
    if (!BN_rshift1(t3->f[1], t3->f[1]))
        goto err;

    /*
     * y3 = G^2 - 3E^2.
     */
    if (!FP2_sqr(group, u0, t2, ctx))
        goto err;
    if (!FP2_dbl(group, u1, u0))
        goto err;
    if (!FP2_add(group, u1, u1, u0))
        goto err;
    if (!FP2_sqr(group, u0, t3, ctx))
        goto err;
    if (!FP2_sub(group, u0, u0, u1))
        goto err;

    /*
     * H = (Y + Z)^2 - B - C.
     */
    if (!FP2_add(group, t3, y1, z1))
        goto err;
    if (!FP2_sqr(group, t3, t3, ctx))
        goto err;
    if (!FP2_sub(group, t3, t3, t5))
        goto err;
    if (!FP2_copy(y3, u0))
        goto err;

    /*
     * z3 = B * H.
     */
    if (!FP2_mul(group, z3, t1, t3, ctx))
        goto err;

    /*
     * l11 = E - B.
     */
    if (!FP2_sub(group, l->f[1]->f[1], t2, t1))
        goto err;

    /*
     * l10 = (3 * xp) * t0.
     */
    if (!BN_mod_mul_montgomery
        (l->f[1]->f[0]->f[0], xp, t0->f[0], group->mont, ctx))
        goto err;
    if (!BN_mod_mul_montgomery
        (l->f[1]->f[0]->f[1], xp, t0->f[1], group->mont, ctx))
        goto err;

    /*
     * l01 = F * (-yp).
     */
    if (!BN_mod_mul_montgomery
        (l->f[0]->f[0]->f[0], t3->f[0], yp, group->mont, ctx))
        goto err;
    if (!BN_mod_mul_montgomery
        (l->f[0]->f[0]->f[1], t3->f[1], yp, group->mont, ctx))
        goto err;

    ret = 1;

 err:
    FP2_free(t0);
    FP2_free(t1);
    FP2_free(t2);
    FP2_free(t3);
    FP2_free(t4);
    FP2_free(t5);
    FP2_free(t6);
    FP2_free(u0);
    FP2_free(u1);
    return ret;
}

static int GT_miller_add(const BP_GROUP *group, FP12 *l, FP2 *x3, FP2 *y3,
                         FP2 *z3, const FP2 *x1, const FP2 *y1,
                         const BIGNUM *xp, const BIGNUM *yp, BN_CTX *ctx)
{
    FP2 *t0 = NULL, *t1 = NULL, *t2 = NULL, *t3 = NULL;
    FP2 *t4 = NULL, *u0 = NULL, *u1 = NULL, *u2 = NULL;
    int ret = 0;

    if ((t0 = FP2_new()) == NULL || (t1 = FP2_new()) == NULL
        || (t2 = FP2_new()) == NULL || (t3 = FP2_new()) == NULL
        || (t4 = FP2_new()) == NULL || (u0 = FP2_new()) == NULL
        || (u1 = FP2_new()) == NULL || (u2 = FP2_new()) == NULL)
        goto err;

    if (!FP2_mul(group, t1, z3, x1, ctx))
        goto err;
    if (!FP2_sub(group, t1, x3, t1))
        goto err;
    if (!FP2_mul(group, t2, z3, y1, ctx))
        goto err;
    if (!FP2_sub(group, t2, y3, t2))
        goto err;

    if (!FP2_sqr(group, t3, t1, ctx))
        goto err;
    if (!FP2_mul(group, x3, t3, x3, ctx))
        goto err;
    if (!FP2_mul(group, t3, t1, t3, ctx))
        goto err;
    if (!FP2_sqr(group, t4, t2, ctx))
        goto err;
    if (!FP2_mul(group, t4, t4, z3, ctx))
        goto err;
    if (!FP2_add(group, t4, t3, t4))
        goto err;

    if (!FP2_sub(group, t4, t4, x3))
        goto err;
    if (!FP2_sub(group, t4, t4, x3))
        goto err;
    if (!FP2_sub(group, x3, x3, t4))
        goto err;
    if (!FP2_mul(group, u1, t2, x3, ctx))
        goto err;
    if (!FP2_mul(group, u2, t3, y3, ctx))
        goto err;
    if (!FP2_sub(group, y3, u1, u2))
        goto err;
    if (!FP2_mul(group, x3, t1, t4, ctx))
        goto err;
    if (!FP2_mul(group, z3, z3, t3, ctx))
        goto err;

    if (!BN_mod_mul_montgomery
        (l->f[1]->f[0]->f[0], t2->f[0], xp, group->mont, ctx))
        goto err;
    if (!BN_mod_mul_montgomery
        (l->f[1]->f[0]->f[1], t2->f[1], xp, group->mont, ctx))
        goto err;

    if (!FP2_neg(group, l->f[1]->f[0], l->f[1]->f[0]))
        goto err;

    if (!FP2_mul(group, u1, x1, t2, ctx))
        goto err;
    if (!FP2_mul(group, u2, y1, t1, ctx))
        goto err;
    if (!FP2_sub(group, l->f[1]->f[1], u1, u2))
        goto err;

    if (!BN_mod_mul_montgomery
        (l->f[0]->f[0]->f[0], t1->f[0], yp, group->mont, ctx))
        goto err;
    if (!BN_mod_mul_montgomery
        (l->f[0]->f[0]->f[1], t1->f[1], yp, group->mont, ctx))
        goto err;

    ret = 1;

 err:
    FP2_free(t1);
    FP2_free(t2);
    FP2_free(t3);
    FP2_free(t4);
    FP2_free(u1);
    FP2_free(u2);
    return ret;
}

static int GT_miller_final(const BP_GROUP *group, FP12 *r, FP2 *x3,
                           FP2 *y3, FP2 *z3, const FP2 *x1, const FP2 *y1,
                           const BIGNUM *xp, const BIGNUM *yp, BN_CTX *ctx)
{
    FP2 *x2 = NULL, *y2 = NULL;
    FP12 *l = NULL;
    int ret = 0;

    if ((x2 = FP2_new()) == NULL || (y2 = FP2_new()) == NULL
        || (l = FP12_new()) == NULL)
        goto err;

    if (!FP12_zero(l))
        goto err;
    if (!FP2_conjugate(group, x2, x1))
        goto err;
    if (!FP2_conjugate(group, y2, y1))
        goto err;
    if (!FP2_mul_frb(group, x2, x2, 2, ctx))
        goto err;
    if (!FP2_mul_frb(group, y2, y2, 3, ctx))
        goto err;
    if (!GT_miller_add(group, l, x3, y3, z3, x2, y2, xp, yp, ctx))
        goto err;
    if (!FP12_mul_sparse(group, r, r, l, ctx))
        goto err;

    if (!FP2_conjugate(group, x2, x2))
        goto err;
    if (!FP2_conjugate(group, y2, y2))
        goto err;
    if (!FP2_mul_frb(group, x2, x2, 2, ctx))
        goto err;
    if (!FP2_mul_frb(group, y2, y2, 3, ctx))
        goto err;
    if (!FP2_neg(group, y2, y2))
        goto err;

    if (!GT_miller_add(group, l, x3, y3, z3, x2, y2, xp, yp, ctx))
        goto err;
    if (!FP12_mul_sparse(group, r, r, l, ctx))
        goto err;

    ret = 1;

 err:
    FP2_free(x2);
    FP2_free(y2);
    FP12_free(l);
    return ret;
}

static int GT_final_exp(const BP_GROUP *group, FP12 *r, const FP12 *a,
                        BN_CTX *ctx)
{
    FP12 *t0 = NULL, *t1 = NULL, *t2 = NULL, *t3 = NULL, *t4 = NULL;
    int ret = 0;

    if ((t0 = FP12_new()) == NULL || (t1 = FP12_new()) == NULL
        || (t2 = FP12_new()) == NULL || (t3 = FP12_new()) == NULL
        || (t4 = FP12_new()) == NULL) {
        goto err;
    }

    /*
     * First, compute m = f^(p^6 - 1)(p^2 + 1).
     */
    if (!FP12_to_cyclotomic(group, r, a, ctx))
        goto err;
    /*
     * Now compute m^((p^4 - p^2 + 1) / r) using Duquesne-Ghamman approach
     * from https://eprint.iacr.org/2015/192.pdf
     */
    if (!FP12_exp_compressed(group, t0, r, group->param, ctx))
        goto err;
    if (!BN_is_negative(group->param) && !FP12_conjugate(group, t0, t0))
        goto err;
    if (!FP12_sqr_cyclotomic(group, t4, t0, ctx))
        goto err;
    if (!FP12_mul(group, t1, t0, t4, ctx))
        goto err;
    if (!FP12_frobenius(group, t3, t4, ctx))
        goto err;
    if (!FP12_mul(group, t3, t3, t4, ctx))
        goto err;
    if (!FP12_sqr_cyclotomic(group, t3, t3, ctx))
        goto err;
    if (!FP12_mul(group, t3, t3, t4, ctx))
        goto err;

    if (!FP12_exp_compressed(group, t0, t1, group->param, ctx))
        goto err;
    if (!BN_is_negative(group->param) && !FP12_conjugate(group, t0, t0))
        goto err;
    if (!FP12_conjugate(group, t1, r))
        goto err;
    if (!FP12_frobenius(group, t2, t0, ctx))
        goto err;
    if (!FP12_frobenius(group, t2, t2, ctx))
        goto err;
    if (!FP12_mul(group, t2, t2, t1, ctx))
        goto err;
    if (!FP12_conjugate(group, t0, t0))
        goto err;
    if (!FP12_frobenius(group, t4, t0, ctx))
        goto err;
    if (!FP12_mul(group, t4, t0, t4, ctx))
        goto err;
    if (!FP12_sqr_cyclotomic(group, t0, t0, ctx))
        goto err;
    if (!FP12_mul(group, t2, t2, t0, ctx))
        goto err;

    if (!FP12_exp_compressed(group, t0, t4, group->param, ctx))
        goto err;
    if (!BN_is_negative(group->param) && !FP12_conjugate(group, t0, t0))
        goto err;
    if (!FP12_sqr_cyclotomic(group, t0, t0, ctx))
        goto err;
    if (!FP12_conjugate(group, t0, t0))
        goto err;
    if (!FP12_mul(group, t4, t0, t4, ctx))
        goto err;
    if (!FP12_frobenius(group, t1, r, ctx))
        goto err;
    if (!FP12_frobenius(group, r, t1, ctx))
        goto err;
    if (!FP12_mul(group, t1, t1, r, ctx))
        goto err;
    if (!FP12_frobenius(group, r, r, ctx))
        goto err;
    if (!FP12_mul(group, t1, t1, r, ctx))
        goto err;

    if (!FP12_sqr_cyclotomic(group, r, t4, ctx))
        goto err;
    if (!FP12_mul(group, r, t3, r, ctx))
        goto err;
    if (!FP12_mul(group, t4, r, t1, ctx))
        goto err;
    if (!FP12_mul(group, r, r, t2, ctx))
        goto err;
    if (!FP12_sqr_cyclotomic(group, r, r, ctx))
        goto err;
    if (!FP12_mul(group, r, r, t4, ctx))
        goto err;

    ret = 1;
 err:
    FP12_free(t0);
    FP12_free(t1);
    FP12_free(t2);
    FP12_free(t3);
    FP12_free(t4);
    return ret;
}

int GT_ELEMs_pairing(const BP_GROUP *group, GT_ELEM *r, size_t num,
                     const G1_ELEM *p[], const G2_ELEM *q[], BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    size_t i, j, m;
    int ret = 0;
    BIGNUM *xp[num], *yp[num], *s[num], *t[num], *miller = NULL;
    FP2 *x[num], *y[num], *xq[num], *yq[num], *zq[num];
    G2_ELEM *qs[num];
    FP12 *l = NULL;

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    BN_CTX_start(ctx);
    for (i = 0; i < num; i++) {
        xp[i] = yp[i] = s[i] = t[i] = NULL;
        if ((xp[i] = BN_CTX_get(ctx)) == NULL
            || (yp[i] = BN_CTX_get(ctx)) == NULL
            || (s[i] = BN_CTX_get(ctx)) == NULL
            || (t[i] = BN_CTX_get(ctx)) == NULL
            || (miller = BN_CTX_get(ctx)) == NULL) {
            goto err;
        }
        x[i] = y[i] = xq[i] = yq[i] = zq[i] = NULL;
        if ((x[i] = FP2_new()) == NULL || (y[i] = FP2_new()) == NULL
            || (xq[i] = FP2_new()) == NULL || (yq[i] = FP2_new()) == NULL
            || (zq[i] = FP2_new()) == NULL) {
            goto err;
        }
        if ((qs[i] = G2_ELEM_new(group)) == NULL)
            goto err;
    }

    m = 0;
    for (i = 0; i < num; i++)
        if (!G1_ELEM_is_at_infinity(group, p[i]) &&
            !G2_ELEM_is_at_infinity(group, q[i])) {
            /*
             * Copy only the valid pairs and remember amount.
             */
            if (!G1_ELEM_get_affine_coordinates
                (group, p[i], xp[m], yp[m], ctx))
                goto err;
            if (!BN_to_montgomery(xp[m], xp[m], group->mont, ctx))
                goto err;
            if (!BN_to_montgomery(yp[m], yp[m], group->mont, ctx))
                goto err;
            if (!BN_mod_add_quick(s[m], xp[m], xp[m], group->field))
                goto err;
            if (!BN_mod_add_quick(s[m], s[m], xp[m], group->field))
                goto err;
            if (!BN_sub(t[i], group->field, yp[m]))
                goto err;
            /*
             * Copy directly grom G2 to save conversion operations.
             */
            if (!G2_ELEM_copy(qs[m], q[i]))
                goto err;
            if (!G2_ELEM_make_affine(group, qs[m], ctx))
                goto err;
            if (!FP2_copy(x[m], qs[m]->X))
                goto err;
            if (!FP2_copy(y[m], qs[m]->Y))
                goto err;
            if (!FP2_copy(xq[m], qs[m]->X))
                goto err;
            if (!FP2_copy(yq[m], qs[m]->Y))
                goto err;
            if (!FP2_copy(zq[m], qs[m]->Z))
                goto err;
            m++;
        }

    if (m == 0)
        return GT_ELEM_set_to_unity(group, r);

    /*
     * Initialize line function.
     */
    if ((l = FP12_new()) == NULL)
        goto err;
    if (!FP12_zero(l))
        goto err;

    /*
     * Initialize Miller variables.
     */
    if (!FP12_zero(r->f))
        goto err;
    if (!BN_copy(r->f->f[0]->f[0]->f[0], group->one))
        goto err;
    if (!BN_copy(miller, group->param))
        goto err;
    if (!BN_mul_word(miller, 6))
        goto err;
    if (!BN_add_word(miller, 2))
        goto err;

    /*
     * Compute Miller loops simultaneously using square-and-multiply.
     */
    for (i = BN_num_bits(miller) - 1; i > 0;) {
        i--;
        if (!FP12_sqr(group, r->f, r->f, ctx))
            goto err;
        for (j = 0; j < m; j++) {
            if (!GT_miller_double
                (group, l, xq[j], yq[j], zq[j], xq[j], yq[j], zq[j], s[j],
                 t[j], ctx))
                goto err;
            if (!FP12_mul_sparse(group, r->f, r->f, l, ctx))
                goto err;
        }
        if (BN_is_bit_set(miller, i)) {
            for (j = 0; j < m; j++) {
                if (!GT_miller_add
                    (group, l, xq[j], yq[j], zq[j], x[j], y[j], xp[j], yp[j],
                     ctx))
                    goto err;
                if (!FP12_mul_sparse(group, r->f, r->f, l, ctx))
                    goto err;
            }
        }
    }

    if (BN_is_negative(group->param) && !FP12_conjugate(group, r->f, r->f))
        goto err;

    for (i = 0; i < m; i++) {
        if (BN_is_negative(group->param) && !FP2_neg(group, yq[i], yq[i]))
            goto err;
        if (!GT_miller_final
            (group, r->f, xq[i], yq[i], zq[i], x[i], y[i], xp[i], yp[i],
             ctx)) {
            goto err;
        }
    }
    if (!GT_final_exp(group, r->f, r->f, ctx))
        goto err;

    ret = 1;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    for (i = 0; i < num; i++) {
        FP2_free(x[i]);
        FP2_free(y[i]);
        FP2_free(xq[i]);
        FP2_free(yq[i]);
        FP2_free(zq[i]);
        G2_ELEM_free(qs[i]);
    }
    FP12_free(l);
    return ret;
}

int GT_ELEM_pairing(const BP_GROUP *group, GT_ELEM *r, const G1_ELEM *p,
                    const G2_ELEM *q, BN_CTX *ctx)
{
    const G1_ELEM *ps[1];
    const G2_ELEM *qs[1];

    ps[0] = p;
    qs[0] = q;

    return GT_ELEMs_pairing(group, r, 1, ps, qs, ctx);
}
