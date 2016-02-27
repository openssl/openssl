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

FP12 *FP12_new()
{
    FP12 *ret = NULL;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL)
        return NULL;

    ret->f[0] = FP6_new();
    ret->f[1] = FP6_new();
    if (ret->f[0] == NULL || ret->f[1] == NULL) {
        FP6_free(ret->f[0]);
        FP6_free(ret->f[1]);
        return NULL;
    }
    return ret;
}

void FP12_clear(FP12 *a)
{
    FP6_clear(a->f[0]);
    FP6_clear(a->f[1]);
}

void FP12_free(FP12 *a)
{
    if (a == NULL)
        return;
    FP6_free(a->f[0]);
    FP6_free(a->f[1]);
    OPENSSL_free(a);
}

void FP12_clear_free(FP12 *a)
{
    if (a == NULL)
        return;
    FP6_clear_free(a->f[0]);
    FP6_clear_free(a->f[1]);
    OPENSSL_free(a);
}

int FP12_zero(FP12 *a)
{
    if (!FP6_zero(a->f[0]) || !FP6_zero(a->f[1]))
        return 0;
    return 1;
}

int FP12_cmp(const FP12 *a, const FP12 *b)
{
    if ((FP6_cmp(a->f[0], b->f[0]) == 0) && (FP6_cmp(a->f[1], b->f[1]) == 0))
        return 0;
    return 1;
}

int FP12_copy(FP12 *a, const FP12 *b)
{
    if (!FP6_copy(a->f[0], b->f[0]) || !FP6_copy(a->f[1], b->f[1]))
        return 0;
    return 1;
}

int FP12_is_zero(const FP12 *a)
{
    return FP6_is_zero(a->f[0]) && FP6_is_zero(a->f[1]);
}

int FP12_add(const BP_GROUP *group, FP12 *r, const FP12 *a, const FP12 *b)
{
    if (!FP6_add(group, r->f[0], a->f[0], b->f[0]))
        return 0;
    if (!FP6_add(group, r->f[1], a->f[1], b->f[1]))
        return 0;
    return 1;
}

int FP12_sub(const BP_GROUP *group, FP12 *r, const FP12 *a, const FP12 *b)
{
    if (!FP6_sub(group, r->f[0], a->f[0], b->f[0]))
        return 0;
    if (!FP6_sub(group, r->f[1], a->f[1], b->f[1]))
        return 0;
    return 1;
}

int FP12_neg(const BP_GROUP *group, FP12 *r, const FP12 *a)
{
    if (!FP6_neg(group, r->f[0], a->f[0]))
        return 0;
    if (!FP6_neg(group, r->f[1], a->f[1]))
        return 0;
    return 1;
}

int FP12_mul(const BP_GROUP *group, FP12 *r, const FP12 *a, const FP12 *b,
             BN_CTX *ctx)
{
    FP6 *t0 = NULL, *t1 = NULL, *t2 = NULL;
    int ret = 0;

    if ((t0 = FP6_new()) == NULL || (t1 = FP6_new()) == NULL
        || (t2 = FP6_new()) == NULL) {
        goto err;
    }

    /*
     * Karatsuba algorithm.
     */

    /*
     * t0 = a_0 * b_0.
     */
    if (!FP6_mul(group, t0, a->f[0], b->f[0], ctx))
        goto err;
    /*
     * t1 = a_1 * b_1.
     */
    if (!FP6_mul(group, t1, a->f[1], b->f[1], ctx))
        goto err;
    /*
     * t2 = b_0 + b_1.
     */
    if (!FP6_add(group, t2, b->f[0], b->f[1]))
        goto err;

    /*
     * c_1 = a_0 + a_1.
     */
    if (!FP6_add(group, r->f[1], a->f[0], a->f[1]))
        goto err;

    /*
     * c_1 = (a_0 + a_1) * (b_0 + b_1)
     */
    if (!FP6_mul(group, r->f[1], r->f[1], t2, ctx))
        goto err;
    if (!FP6_sub(group, r->f[1], r->f[1], t0))
        goto err;
    if (!FP6_sub(group, r->f[1], r->f[1], t1))
        goto err;

    /*
     * c_0 = a_0b_0 + v * a_1b_1.
     */
    if (!FP6_mul_art(group, t1, t1, ctx))
        goto err;
    if (!FP6_add(group, r->f[0], t0, t1))
        goto err;

    ret = 1;

 err:
    FP6_free(t0);
    FP6_free(t1);
    FP6_free(t2);
    return ret;
}

int FP12_mul_sparse(const BP_GROUP *group, FP12 *r, const FP12 *a,
                    const FP12 *b, BN_CTX *ctx)
{
    FP6 *t0 = NULL, *t1 = NULL, *t2 = NULL;
    int ret = 0;

    if ((t0 = FP6_new()) == NULL || (t1 = FP6_new()) == NULL
        || (t2 = FP6_new()) == NULL) {
        goto err;
    }

    /*
     * t0 = a_0 * b_0
     */
    if (!FP2_mul(group, t0->f[0], a->f[0]->f[0], b->f[0]->f[0], ctx))
        goto err;
    if (!FP2_mul(group, t0->f[1], a->f[0]->f[1], b->f[0]->f[0], ctx))
        goto err;
    if (!FP2_mul(group, t0->f[2], a->f[0]->f[2], b->f[0]->f[0], ctx))
        goto err;

    /*
     * t2 = b_0 + b_1.
     */
    if (!FP2_add(group, t2->f[0], b->f[0]->f[0], b->f[1]->f[0]))
        goto err;
    FP2_copy(t2->f[1], b->f[1]->f[1]);

    /*
     * t1 = a_1 * b_1.
     */
    if (!FP6_mul_sparse(group, t1, a->f[1], b->f[1], ctx))
        goto err;

    /*
     * c_1 = a_0 + a_1.
     */
    if (!FP6_add(group, r->f[1], a->f[0], a->f[1]))
        goto err;

    /*
     * c_1 = (a_0 + a_1) * (b_0 + b_1) - a_0 * b_0 - a_1 * b_1.
     */
    if (!FP6_mul_sparse(group, r->f[1], r->f[1], t2, ctx))
        goto err;
    if (!FP6_sub(group, r->f[1], r->f[1], t0))
        goto err;
    if (!FP6_sub(group, r->f[1], r->f[1], t1))
        goto err;
    /*
     * c_0 = a_0 * b_0 + v * a_1 * b_1.
     */
    if (!FP6_mul_art(group, t1, t1, ctx))
        goto err;
    if (!FP6_add(group, r->f[0], t0, t1))
        goto err;

    ret = 1;
 err:
    FP6_free(t0);
    FP6_free(t1);
    FP6_free(t2);
    return ret;
}

int FP12_inv(const BP_GROUP *group, FP12 *r, const FP12 *a, BN_CTX *ctx)
{
    FP6 *t0 = NULL, *t1 = NULL;
    int ret = 0;

    if ((t0 = FP6_new()) == NULL || (t1 = FP6_new()) == NULL)
        goto err;

    if (!FP6_sqr(group, t0, a->f[0], ctx))
        goto err;
    if (!FP6_sqr(group, t1, a->f[1], ctx))
        goto err;
    if (!FP6_mul_art(group, t1, t1, ctx))
        goto err;
    if (!FP6_sub(group, t0, t0, t1))
        goto err;
    if (!FP6_inv(group, t0, t0, ctx))
        goto err;
    if (!FP6_mul(group, r->f[0], a->f[0], t0, ctx))
        goto err;
    if (!FP6_neg(group, r->f[1], a->f[1]))
        goto err;
    if (!FP6_mul(group, r->f[1], r->f[1], t0, ctx))
        goto err;

    ret = 1;
 err:
    FP6_free(t0);
    FP6_free(t1);
    return ret;
}

int FP12_conjugate(const BP_GROUP *group, FP12 *r, const FP12 *a)
{
    if (!FP6_copy(r->f[0], a->f[0]))
        return 0;
    if (!FP6_neg(group, r->f[1], a->f[1]))
        return 0;
    return 1;
}

int FP12_frobenius(const BP_GROUP *group, FP12 *r, const FP12 *a, BN_CTX *ctx)
{
    int ret = 0;

    if (!FP2_conjugate(group, r->f[0]->f[0], a->f[0]->f[0]))
        goto err;
    if (!FP2_conjugate(group, r->f[1]->f[0], a->f[1]->f[0]))
        goto err;
    if (!FP2_conjugate(group, r->f[0]->f[1], a->f[0]->f[1]))
        goto err;
    if (!FP2_conjugate(group, r->f[1]->f[1], a->f[1]->f[1]))
        goto err;
    if (!FP2_conjugate(group, r->f[0]->f[2], a->f[0]->f[2]))
        goto err;
    if (!FP2_conjugate(group, r->f[1]->f[2], a->f[1]->f[2]))
        goto err;
    if (!FP2_mul_frb(group, r->f[1]->f[0], r->f[1]->f[0], 1, ctx))
        goto err;
    if (!FP2_mul_frb(group, r->f[0]->f[1], r->f[0]->f[1], 2, ctx))
        goto err;
    if (!FP2_mul_frb(group, r->f[1]->f[1], r->f[1]->f[1], 3, ctx))
        goto err;
    if (!FP2_mul_frb(group, r->f[0]->f[2], r->f[0]->f[2], 4, ctx))
        goto err;
    if (!FP2_mul_frb(group, r->f[1]->f[2], r->f[1]->f[2], 5, ctx))
        goto err;
    ret = 1;
 err:
    return ret;
}

int FP12_to_cyclotomic(const BP_GROUP *group, FP12 *r, const FP12 *a,
                       BN_CTX *ctx)
{
    FP12 *t = NULL;
    int ret = 0;

    if ((t = FP12_new()) == NULL)
        goto err;

    if (!FP12_inv(group, t, a, ctx))
        goto err;
    if (!FP12_conjugate(group, r, a))
        goto err;
    if (!FP12_mul(group, r, r, t, ctx))
        goto err;

    if (!FP12_frobenius(group, t, r, ctx))
        goto err;
    if (!FP12_frobenius(group, t, t, ctx))
        goto err;
    if (!FP12_mul(group, r, r, t, ctx))
        goto err;

    ret = 1;
 err:
    FP12_free(t);
    return ret;
}

int FP12_exp_cyclotomic(const BP_GROUP *group, FP12 *r, const FP12 *a,
                        const BIGNUM *b, BN_CTX *ctx)
{
    int i, ret = 0;
    FP12 *t = NULL;

    if ((t = FP12_new()) == NULL)
        goto err;

    if (!FP12_copy(t, a))
        goto err;

    for (i = BN_num_bits(b) - 2; i >= 0; i--) {
        if (!FP12_sqr_cyclotomic(group, t, t, ctx))
            goto err;
        if (BN_is_bit_set(b, i)) {
            if (!FP12_mul(group, t, t, a, ctx))
                goto err;
        }
    }

    if (!FP12_copy(r, t))
        goto err;

    ret = 1;
 err:
    FP12_free(t);
    return ret;
}

int FP12_exp_compressed(const BP_GROUP *group, FP12 *r, const FP12 *a,
                        const BIGNUM *b, BN_CTX *ctx)
{
    int i, j, w, ret = 0;

    w = 0;
    for (i = 1; i < BN_num_bits(b); i++) {
        if (BN_is_bit_set(b, i))
            w++;
    }

    FP12 *t[w];
    for (i = 0; i < w; i++) {
        if ((t[i] = FP12_new()) == NULL)
            goto err;
    }

    i = 1;
    j = 0;
    if (!FP12_sqr(group, t[j], a, ctx))
        goto err;
    while (i < BN_num_bits(b) - 1) {
        if (BN_is_bit_set(b, i)) {
            if (!FP12_copy(t[j + 1], t[j]))
                goto err;
            j++;
        }
        if (!FP12_sqr_compressed(group, t[j], t[j], ctx))
            goto err;
        i++;
    }

    /*
     * Decompress partial results simultaneously.
     */
    if (!FP12_decompress(group, t, (const FP12 **)t, w, ctx))
        goto err;
    /*
     * Combine partial results into t[0].
     */
    for (i = 1; i < w; i++) {
        if (!FP12_mul(group, t[0], t[0], t[i], ctx))
            goto err;
    }
    /*
     * Handle remaining bit.
     */
    if (BN_is_bit_set(b, 0)) {
        if (!FP12_mul(group, r, t[0], a, ctx))
            goto err;
    }

    ret = 1;
 err:
    for (i = 0; i < w; i++) {
        FP12_free(t[i]);
    }
    return ret;
}

int FP12_sqr(const BP_GROUP *group, FP12 *r, const FP12 *a, BN_CTX *ctx)
{
    FP6 *t0 = NULL, *t1 = NULL;
    int ret = 0;

    if ((t0 = FP6_new()) == NULL || (t1 = FP6_new()) == NULL)
        goto err;

    if (!FP6_add(group, t0, a->f[0], a->f[1]))
        goto err;
    if (!FP6_add(group, t0, a->f[0], a->f[1]))
        goto err;
    if (!FP6_mul_art(group, t1, a->f[1], ctx))
        goto err;
    if (!FP6_add(group, t1, a->f[0], t1))
        goto err;
    if (!FP6_mul(group, t0, t0, t1, ctx))
        goto err;
    if (!FP6_mul(group, r->f[1], a->f[0], a->f[1], ctx))
        goto err;
    if (!FP6_sub(group, r->f[0], t0, r->f[1]))
        goto err;
    if (!FP6_mul_art(group, t1, r->f[1], ctx))
        goto err;
    if (!FP6_sub(group, r->f[0], r->f[0], t1))
        goto err;
    if (!FP6_add(group, r->f[1], r->f[1], r->f[1]))
        goto err;

    ret = 1;
 err:
    FP6_free(t0);
    FP6_free(t1);
    return ret;
}

int FP12_sqr_cyclotomic(const BP_GROUP *group, FP12 *r, const FP12 *a,
                        BN_CTX *ctx)
{
    FP2 *t0 = NULL, *t1 = NULL, *t2 = NULL, *t3 = NULL;
    FP2 *t4 = NULL, *t5 = NULL, *t6 = NULL;
    int ret = 0;

    if ((t0 = FP2_new()) == NULL || (t1 = FP2_new()) == NULL
        || (t2 = FP2_new()) == NULL || (t3 = FP2_new()) == NULL
        || (t4 = FP2_new()) == NULL || (t5 = FP2_new()) == NULL
        || (t6 = FP2_new()) == NULL) {
        goto err;
    }

    /*
     * Granger-Scott squaring.
     */
    if (!FP2_sqr(group, t2, a->f[0]->f[0], ctx))
        goto err;
    if (!FP2_sqr(group, t3, a->f[1]->f[1], ctx))
        goto err;
    if (!FP2_add(group, t1, a->f[0]->f[0], a->f[1]->f[1]))
        goto err;

    if (!FP2_mul_nor(group, t0, t3, ctx))
        goto err;
    if (!FP2_add(group, t0, t0, t2))
        goto err;

    if (!FP2_sqr(group, t1, t1, ctx))
        goto err;
    if (!FP2_sub(group, t1, t1, t2))
        goto err;
    if (!FP2_sub(group, t1, t1, t3))
        goto err;

    if (!FP2_sub(group, r->f[0]->f[0], t0, a->f[0]->f[0]))
        goto err;
    if (!FP2_add(group, r->f[0]->f[0], r->f[0]->f[0], r->f[0]->f[0]))
        goto err;
    if (!FP2_add(group, r->f[0]->f[0], t0, r->f[0]->f[0]))
        goto err;

    if (!FP2_add(group, r->f[1]->f[1], t1, a->f[1]->f[1]))
        goto err;
    if (!FP2_add(group, r->f[1]->f[1], r->f[1]->f[1], r->f[1]->f[1]))
        goto err;
    if (!FP2_add(group, r->f[1]->f[1], t1, r->f[1]->f[1]))
        goto err;

    if (!FP2_sqr(group, t0, a->f[0]->f[1], ctx))
        goto err;
    if (!FP2_sqr(group, t1, a->f[1]->f[2], ctx))
        goto err;
    if (!FP2_add(group, t5, a->f[0]->f[1], a->f[1]->f[2]))
        goto err;
    if (!FP2_sqr(group, t2, t5, ctx))
        goto err;

    if (!FP2_add(group, t3, t0, t1))
        goto err;
    if (!FP2_sub(group, t5, t2, t3))
        goto err;

    if (!FP2_add(group, t6, a->f[1]->f[0], a->f[0]->f[2]))
        goto err;
    if (!FP2_sqr(group, t3, t6, ctx))
        goto err;
    if (!FP2_sqr(group, t2, a->f[1]->f[0], ctx))
        goto err;

    if (!FP2_mul_nor(group, t6, t5, ctx))
        goto err;
    if (!FP2_add(group, t5, t6, a->f[1]->f[0]))
        goto err;
    if (!FP2_dbl(group, t5, t5))
        goto err;
    if (!FP2_add(group, r->f[1]->f[0], t5, t6))
        goto err;

    if (!FP2_mul_nor(group, t4, t1, ctx))
        goto err;
    if (!FP2_add(group, t5, t0, t4))
        goto err;
    if (!FP2_sub(group, t6, t5, a->f[0]->f[2]))
        goto err;

    if (!FP2_sqr(group, t1, a->f[0]->f[2], ctx))
        goto err;

    if (!FP2_dbl(group, t6, t6))
        goto err;
    if (!FP2_add(group, r->f[0]->f[2], t6, t5))
        goto err;

    if (!FP2_mul_nor(group, t4, t1, ctx))
        goto err;
    if (!FP2_add(group, t5, t2, t4))
        goto err;
    if (!FP2_sub(group, t6, t5, a->f[0]->f[1]))
        goto err;
    if (!FP2_dbl(group, t6, t6))
        goto err;
    if (!FP2_add(group, r->f[0]->f[1], t6, t5))
        goto err;

    if (!FP2_add(group, t0, t2, t1))
        goto err;
    if (!FP2_sub(group, t5, t3, t0))
        goto err;
    if (!FP2_add(group, t6, t5, a->f[1]->f[2]))
        goto err;
    if (!FP2_dbl(group, t6, t6))
        goto err;
    if (!FP2_add(group, r->f[1]->f[2], t5, t6))
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
    return ret;
}

int FP12_sqr_compressed(const BP_GROUP *group, FP12 *r, const FP12 *a,
                        BN_CTX *ctx)
{
    FP2 *t0 = NULL, *t1 = NULL, *t2 = NULL, *t3 = NULL;
    FP2 *t4 = NULL, *t5 = NULL, *t6 = NULL;
    int ret = 0;

    if ((t0 = FP2_new()) == NULL || (t1 = FP2_new()) == NULL
        || (t2 = FP2_new()) == NULL || (t3 = FP2_new()) == NULL
        || (t4 = FP2_new()) == NULL || (t5 = FP2_new()) == NULL
        || (t6 = FP2_new()) == NULL) {
        goto err;
    }

    /*
     * Karabina compressed squaring.
     */
    if (!FP2_sqr(group, t0, a->f[0]->f[1], ctx))
        goto err;
    if (!FP2_sqr(group, t1, a->f[1]->f[2], ctx))
        goto err;
    if (!FP2_add(group, t5, a->f[0]->f[1], a->f[1]->f[2]))
        goto err;
    if (!FP2_sqr(group, t2, t5, ctx))
        goto err;

    if (!FP2_add(group, t3, t0, t1))
        goto err;
    if (!FP2_sub(group, t5, t2, t3))
        goto err;

    if (!FP2_add(group, t6, a->f[1]->f[0], a->f[0]->f[2]))
        goto err;
    if (!FP2_sqr(group, t3, t6, ctx))
        goto err;
    if (!FP2_sqr(group, t2, a->f[1]->f[0], ctx))
        goto err;

    if (!FP2_mul_nor(group, t6, t5, ctx))
        goto err;
    if (!FP2_add(group, t5, t6, a->f[1]->f[0]))
        goto err;
    if (!FP2_add(group, t5, t5, t5))
        goto err;
    if (!FP2_add(group, r->f[1]->f[0], t5, t6))
        goto err;

    if (!FP2_mul_nor(group, t4, t1, ctx))
        goto err;
    if (!FP2_add(group, t5, t0, t4))
        goto err;
    if (!FP2_sub(group, t6, t5, a->f[0]->f[2]))
        goto err;

    if (!FP2_sqr(group, t1, a->f[0]->f[2], ctx))
        goto err;

    if (!FP2_add(group, t6, t6, t6))
        goto err;
    if (!FP2_add(group, r->f[0]->f[2], t5, t6))
        goto err;

    if (!FP2_mul_nor(group, t4, t1, ctx))
        goto err;
    if (!FP2_add(group, t5, t2, t4))
        goto err;
    if (!FP2_sub(group, t6, t5, a->f[0]->f[1]))
        goto err;
    if (!FP2_add(group, t6, t6, t6))
        goto err;
    if (!FP2_add(group, r->f[0]->f[1], t5, t6))
        goto err;

    if (!FP2_add(group, t0, t2, t1))
        goto err;
    if (!FP2_sub(group, t5, t3, t0))
        goto err;
    if (!FP2_add(group, t6, t5, a->f[1]->f[2]))
        goto err;
    if (!FP2_add(group, t6, t6, t6))
        goto err;
    if (!FP2_add(group, r->f[1]->f[2], t5, t6))
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
    return ret;
}

int FP12_decompress(const BP_GROUP *group, FP12 *r[], const FP12 *a[],
                    int num, BN_CTX *ctx)
{
    FP2 *t0[num], *t1[num], *t2[num];
    BN_CTX *new_ctx = NULL;
    int i, ret = 0;

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    for (i = 0; i < num; i++) {
        t0[i] = t1[i] = t2[i] = NULL;
        if (((t0[i] = FP2_new()) == NULL) ||
            ((t1[i] = FP2_new()) == NULL) || ((t2[i] = FP2_new()) == NULL)) {
            goto err;
        }
    }

    for (i = 0; i < num; i++) {
        /*
         * t0 = g4^2.
         */
        if (!FP2_sqr(group, t0[i], a[i]->f[0]->f[1], ctx))
            goto err;
        /*
         * t1 = 3 * g4^2 - 2 * g3.
         */
        if (!FP2_sub(group, t1[i], t0[i], a[i]->f[0]->f[2]))
            goto err;
        if (!FP2_add(group, t1[i], t1[i], t1[i]))
            goto err;
        if (!FP2_add(group, t1[i], t1[i], t0[i]))
            goto err;
        /*
         * t0 = E * g5^2 + t1.
         */
        if (!FP2_sqr(group, t2[i], a[i]->f[1]->f[2], ctx))
            goto err;
        if (!FP2_mul_nor(group, t0[i], t2[i], ctx))
            goto err;
        if (!FP2_add(group, t0[i], t0[i], t1[i]))
            goto err;
        /*
         * t1 = (4 * g2).
         */
        if (!FP2_add(group, t1[i], a[i]->f[1]->f[0], a[i]->f[1]->f[0]))
            goto err;
        if (!FP2_add(group, t1[i], t1[i], t1[i]))
            goto err;
    }

    /*
     * t1 = 1 / t1.
     */
    if (!FP2_inv_simultaneous(group, t1, t1, num, ctx))
        goto err;

    for (i = 0; i < num; i++) {
        /*
         * t0 = g1.
         */
        if (!FP2_mul(group, r[i]->f[1]->f[1], t0[i], t1[i], ctx))
            goto err;

        /*
         * t1 = g3 * g4.
         */
        if (!FP2_mul(group, t1[i], a[i]->f[0]->f[2], a[i]->f[0]->f[1], ctx))
            goto err;

        /*
         * t2 = 2 * g1^2 - 3 * g3 * g4.
         */
        if (!FP2_sqr(group, t2[i], r[i]->f[1]->f[1], ctx))
            goto err;
        if (!FP2_sub(group, t2[i], t2[i], t1[i]))
            goto err;
        if (!FP2_add(group, t2[i], t2[i], t2[i]))
            goto err;
        if (!FP2_sub(group, t2[i], t2[i], t1[i]))
            goto err;

        /*
         * t1 = g2 * g5.
         */
        if (!FP2_mul(group, t1[i], a[i]->f[1]->f[0], a[i]->f[1]->f[2], ctx))
            goto err;

        /*
         * t2 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1.
         */
        if (!FP2_add(group, t2[i], t2[i], t1[i]))
            goto err;
        if (!FP2_mul_nor(group, r[i]->f[0]->f[0], t2[i], ctx))
            goto err;
        if (!BN_add
            (r[i]->f[0]->f[0]->f[0], r[i]->f[0]->f[0]->f[0], group->one))
            goto err;

        if (!FP2_copy(r[i]->f[0]->f[1], a[i]->f[0]->f[1]))
            goto err;
        if (!FP2_copy(r[i]->f[0]->f[2], a[i]->f[0]->f[2]))
            goto err;
        if (!FP2_copy(r[i]->f[1]->f[0], a[i]->f[1]->f[0]))
            goto err;
        if (!FP2_copy(r[i]->f[1]->f[2], a[i]->f[1]->f[2]))
            goto err;
    }

    ret = 1;
 err:
    for (i = 0; i < num; i++) {
        FP2_free(t0[i]);
        FP2_free(t1[i]);
        FP2_free(t2[i]);
    }
    BN_CTX_free(new_ctx);
    return ret;
}
