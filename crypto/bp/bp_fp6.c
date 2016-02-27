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

FP6 *FP6_new()
{
    FP6 *ret = NULL;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL)
        return NULL;

    ret->f[0] = FP2_new();
    ret->f[1] = FP2_new();
    ret->f[2] = FP2_new();
    if (ret->f[0] == NULL || ret->f[1] == NULL || ret->f[2] == NULL) {
        FP2_free(ret->f[0]);
        FP2_free(ret->f[1]);
        FP2_free(ret->f[2]);
        return NULL;
    }
    return ret;
}

void FP6_clear(FP6 *a)
{
    FP2_clear(a->f[0]);
    FP2_clear(a->f[1]);
    FP2_clear(a->f[2]);
}

void FP6_free(FP6 *a)
{
    if (a == NULL)
        return;
    FP2_free(a->f[0]);
    FP2_free(a->f[1]);
    FP2_free(a->f[2]);
    OPENSSL_free(a);
}

void FP6_clear_free(FP6 *a)
{
    if (a == NULL)
        return;
    FP2_clear_free(a->f[0]);
    FP2_clear_free(a->f[1]);
    FP2_clear_free(a->f[2]);
    OPENSSL_free(a);
}

int FP6_zero(FP6 *a)
{
    if (!FP2_zero(a->f[0]) || !FP2_zero(a->f[1]) || !FP2_zero(a->f[2]))
        return 0;
    return 1;
}

int FP6_cmp(const FP6 *a, const FP6 *b)
{
    if ((FP2_cmp(a->f[0], b->f[0]) == 0) && (FP2_cmp(a->f[1], b->f[1]) != 0)
        && (FP2_cmp(a->f[2], b->f[2]) == 0))
        return 0;
    return 1;
}

int FP6_copy(FP6 *a, const FP6 *b)
{
    if (!FP2_copy(a->f[0], b->f[0]))
        return 0;
    if (!FP2_copy(a->f[1], b->f[1]))
        return 0;
    if (!FP2_copy(a->f[2], b->f[2]))
        return 0;
    return 1;
}

int FP6_is_zero(const FP6 *a)
{
    return FP2_is_zero(a->f[0]) && FP2_is_zero(a->f[1])
        && FP2_is_zero(a->f[2]);
}

int FP6_add(const BP_GROUP *group, FP6 *r, const FP6 *a, const FP6 *b)
{
    if (!FP2_add(group, r->f[0], a->f[0], b->f[0]))
        return 0;
    if (!FP2_add(group, r->f[1], a->f[1], b->f[1]))
        return 0;
    if (!FP2_add(group, r->f[2], a->f[2], b->f[2]))
        return 0;
    return 1;
}

int FP6_sub(const BP_GROUP *group, FP6 *r, const FP6 *a, const FP6 *b)
{
    if (!FP2_sub(group, r->f[0], a->f[0], b->f[0]))
        return 0;
    if (!FP2_sub(group, r->f[1], a->f[1], b->f[1]))
        return 0;
    if (!FP2_sub(group, r->f[2], a->f[2], b->f[2]))
        return 0;
    return 1;
}

int FP6_neg(const BP_GROUP *group, FP6 *r, const FP6 *a)
{
    if (!FP2_neg(group, r->f[0], a->f[0]))
        return 0;
    if (!FP2_neg(group, r->f[1], a->f[1]))
        return 0;
    if (!FP2_neg(group, r->f[2], a->f[2]))
        return 0;
    return 1;
}

int FP6_mul(const BP_GROUP *group, FP6 *r, const FP6 *a, const FP6 *b,
            BN_CTX *ctx)
{
    FP2 *v0, *v1 = NULL, *v2 = NULL, *t0 = NULL, *t1 = NULL, *t2 = NULL;
    int ret = 0;

    if ((v0 = FP2_new()) == NULL || (v1 = FP2_new()) == NULL
        || (v2 = FP2_new()) == NULL || (t0 = FP2_new()) == NULL
        || (t1 = FP2_new()) == NULL || (t2 = FP2_new()) == NULL) {
        goto err;
    }

    /*
     * v0 = a_0b_0
     */
    if (!FP2_mul(group, v0, a->f[0], b->f[0], ctx))
        goto err;

    /*
     * v1 = a_1b_1
     */
    if (!FP2_mul(group, v1, a->f[1], b->f[1], ctx))
        goto err;

    /*
     * v2 = a_2b_2
     */
    if (!FP2_mul(group, v2, a->f[2], b->f[2], ctx))
        goto err;

    /*
     * t2 (c_0) = v0 + E((a_1 + a_2)(b_1 + b_2) - v1 - v2)
     */
    if (!FP2_add(group, t0, a->f[1], a->f[2]))
        goto err;
    if (!FP2_add(group, t1, b->f[1], b->f[2]))
        goto err;
    if (!FP2_mul(group, t2, t0, t1, ctx))
        goto err;
    if (!FP2_sub(group, t2, t2, v1))
        goto err;
    if (!FP2_sub(group, t2, t2, v2))
        goto err;
    if (!FP2_mul_nor(group, t0, t2, ctx))
        goto err;
    if (!FP2_add(group, t2, t0, v0))
        goto err;

    /*
     * c_1 = (a_0 + a_1)(b_0 + b_1) - v0 - v1 + Ev2
     */
    if (!FP2_add(group, t0, a->f[0], a->f[1]))
        goto err;
    if (!FP2_add(group, t1, b->f[0], b->f[1]))
        goto err;
    if (!FP2_mul(group, r->f[1], t0, t1, ctx))
        goto err;
    if (!FP2_sub(group, r->f[1], r->f[1], v0))
        goto err;
    if (!FP2_sub(group, r->f[1], r->f[1], v1))
        goto err;
    if (!FP2_mul_nor(group, t0, v2, ctx))
        goto err;
    if (!FP2_add(group, r->f[1], r->f[1], t0))
        goto err;

    /*
     * c_2 = (a_0 + a_2)(b_0 + b_2) - v0 + v1 - v2
     */
    if (!FP2_add(group, t0, a->f[0], a->f[2]))
        goto err;
    if (!FP2_add(group, t1, b->f[0], b->f[2]))
        goto err;
    if (!FP2_mul(group, r->f[2], t0, t1, ctx))
        goto err;
    if (!FP2_sub(group, r->f[2], r->f[2], v0))
        goto err;
    if (!FP2_add(group, r->f[2], r->f[2], v1))
        goto err;
    if (!FP2_sub(group, r->f[2], r->f[2], v2))
        goto err;

    /*
     * c_0 = t2
     */
    FP2_copy(r->f[0], t2);

    ret = 1;
 err:
    FP2_free(t2);
    FP2_free(t1);
    FP2_free(t0);
    FP2_free(v2);
    FP2_free(v1);
    FP2_free(v0);
    return ret;
}

int FP6_mul_sparse(const BP_GROUP *group, FP6 *r, const FP6 *a,
                   const FP6 *b, BN_CTX *ctx)
{
    FP2 *v0, *v1 = NULL, *v2 = NULL, *t0 = NULL, *t1 = NULL, *t2 = NULL;
    int ret = 0;

    if ((v0 = FP2_new()) == NULL || (v1 = FP2_new()) == NULL
        || (v2 = FP2_new()) == NULL || (t0 = FP2_new()) == NULL
        || (t1 = FP2_new()) == NULL || (t2 = FP2_new()) == NULL) {
        goto err;
    }

    /*
     * v0 = a_0b_0
     */
    if (!FP2_mul(group, v0, a->f[0], b->f[0], ctx))
        goto err;

    /*
     * v1 = a_1b_1
     */
    if (!FP2_mul(group, v1, a->f[1], b->f[1], ctx))
        goto err;

    /*
     * t2 (c_0) = v0 + E((a_1 + a_2)(b_1 + b_2) - v1 - v2)
     */
    if (!FP2_add(group, t0, a->f[1], a->f[2]))
        goto err;
    if (!FP2_mul(group, t0, t0, b->f[1], ctx))
        goto err;
    if (!FP2_sub(group, t0, t0, v1))
        goto err;
    if (!FP2_mul_nor(group, t2, t0, ctx))
        goto err;
    if (!FP2_add(group, t2, t2, v0))
        goto err;

    /*
     * c_1 = (a_0 + a_1)(b_0 + b_1) - v0 - v1 + Ev2
     */
    if (!FP2_add(group, t0, a->f[0], a->f[1]))
        goto err;
    if (!FP2_add(group, t1, b->f[0], b->f[1]))
        goto err;
    if (!FP2_mul(group, r->f[1], t0, t1, ctx))
        goto err;
    if (!FP2_sub(group, r->f[1], r->f[1], v0))
        goto err;
    if (!FP2_sub(group, r->f[1], r->f[1], v1))
        goto err;

    /*
     * c_2 = (a_0 + a_2)(b_0 + b_2) - v0 + v1 - v2
     */
    if (!FP2_add(group, t0, a->f[0], a->f[2]))
        goto err;
    if (!FP2_mul(group, r->f[2], t0, b->f[0], ctx))
        goto err;
    if (!FP2_sub(group, r->f[2], r->f[2], v0))
        goto err;
    if (!FP2_add(group, r->f[2], r->f[2], v1))
        goto err;

    /*
     * c_0 = t2
     */
    FP2_copy(r->f[0], t2);

    ret = 1;
 err:
    FP2_free(t2);
    FP2_free(t1);
    FP2_free(t0);
    FP2_free(v2);
    FP2_free(v1);
    FP2_free(v0);
    return ret;
}

int FP6_mul_art(const BP_GROUP *group, FP6 *r, const FP6 *a, BN_CTX *ctx)
{
    FP2 *t0;
    int ret = 0;

    if ((t0 = FP2_new()) == NULL)
        goto err;

    FP2_copy(t0, a->f[0]);
    if (!FP2_mul_nor(group, r->f[0], a->f[2], ctx))
        goto err;
    FP2_copy(r->f[2], a->f[1]);
    FP2_copy(r->f[1], t0);

    ret = 1;
 err:
    FP2_free(t0);
    return ret;
}

int FP6_sqr(const BP_GROUP *group, FP6 *r, const FP6 *a, BN_CTX *ctx)
{
    FP2 *t0, *t1 = NULL, *t2 = NULL, *t3 = NULL, *t4 = NULL;
    int ret = 0;

    if ((t0 = FP2_new()) == NULL || (t1 = FP2_new()) == NULL
        || (t2 = FP2_new()) == NULL || (t3 = FP2_new()) == NULL
        || (t4 = FP2_new()) == NULL) {
        goto err;
    }

    /*
     * t0 = a_0^2
     */
    if (!FP2_sqr(group, t0, a->f[0], ctx))
        goto err;

    /*
     * t1 = 2 * a_1 * a_2
     */
    if (!FP2_mul(group, t1, a->f[1], a->f[2], ctx))
        goto err;
    if (!FP2_add(group, t1, t1, t1))
        goto err;

    /*
     * t2 = a_2^2.
     */
    if (!FP2_sqr(group, t2, a->f[2], ctx))
        goto err;

    /*
     * c2 = a_0 + a_2.
     */
    if (!FP2_add(group, r->f[2], a->f[0], a->f[2]))
        goto err;

    /*
     * t3 = (a_0 + a_2 + a_1)^2.
     */
    if (!FP2_add(group, t3, r->f[2], a->f[1]))
        goto err;
    if (!FP2_sqr(group, t3, t3, ctx))
        goto err;

    /*
     * c2 = (a_0 + a_2 - a_1)^2.
     */
    if (!FP2_sub(group, r->f[2], r->f[2], a->f[1]))
        goto err;
    if (!FP2_sqr(group, r->f[2], r->f[2], ctx))
        goto err;

    /*
     * c2 = (c2 + t3)/2.
     */
    if (!FP2_add(group, r->f[2], r->f[2], t3))
        goto err;
    if (BN_is_odd(r->f[2]->f[0])) {
        if (!BN_add(r->f[2]->f[0], r->f[2]->f[0], group->field))
            goto err;
    }
    if (!BN_rshift1(r->f[2]->f[0], r->f[2]->f[0]))
        goto err;
    if (BN_is_odd(r->f[2]->f[1])) {
        if (!BN_add(r->f[2]->f[1], r->f[2]->f[1], group->field))
            goto err;
    }
    if (!BN_rshift1(r->f[2]->f[1], r->f[2]->f[1]))
        goto err;

    /*
     * t3 = t3 - c2 - t1.
     */
    if (!FP2_sub(group, t3, t3, r->f[2]))
        goto err;
    if (!FP2_sub(group, t3, t3, t1))
        goto err;

    /*
     * c2 = c2 - t0 - t2.
     */
    if (!FP2_sub(group, r->f[2], r->f[2], t0))
        goto err;
    if (!FP2_sub(group, r->f[2], r->f[2], t2))
        goto err;

    /*
     * c0 = t0 + t1 * E.
     */
    if (!FP2_mul_nor(group, t4, t1, ctx))
        goto err;
    if (!FP2_add(group, r->f[0], t0, t4))
        goto err;

    /*
     * c1 = t3 + t2 * E.
     */
    if (!FP2_mul_nor(group, t4, t2, ctx))
        goto err;
    if (!FP2_add(group, r->f[1], t3, t4))
        goto err;

    ret = 1;
 err:
    FP2_free(t0);
    FP2_free(t1);
    FP2_free(t2);
    FP2_free(t3);
    FP2_free(t4);
    return ret;
}

int FP6_inv(const BP_GROUP *group, FP6 *r, const FP6 *a, BN_CTX *ctx)
{
    FP2 *v0, *v1 = NULL, *v2 = NULL, *t0 = NULL;
    int ret = 0;

    if ((v0 = FP2_new()) == NULL || (v1 = FP2_new()) == NULL
        || (v2 = FP2_new()) == NULL || (t0 = FP2_new()) == NULL) {
        goto err;
    }

    /*
     * v0 = a_0^2 - E * a_1 * a_2.
     */
    if (!FP2_sqr(group, t0, a->f[0], ctx))
        goto err;
    if (!FP2_mul(group, v0, a->f[1], a->f[2], ctx))
        goto err;
    if (!FP2_mul_nor(group, v2, v0, ctx))
        goto err;
    if (!FP2_sub(group, v0, t0, v2))
        goto err;

    /*
     * v1 = E * a_2^2 - a_0 * a_1.
     */
    if (!FP2_sqr(group, t0, a->f[2], ctx))
        goto err;
    if (!FP2_mul_nor(group, v2, t0, ctx))
        goto err;
    if (!FP2_mul(group, v1, a->f[0], a->f[1], ctx))
        goto err;
    if (!FP2_sub(group, v1, v2, v1))
        goto err;

    /*
     * v2 = a_1^2 - a_0 * a_2.
     */
    if (!FP2_sqr(group, t0, a->f[1], ctx))
        goto err;
    if (!FP2_mul(group, v2, a->f[0], a->f[2], ctx))
        goto err;
    if (!FP2_sub(group, v2, t0, v2))
        goto err;

    if (!FP2_mul(group, t0, a->f[1], v2, ctx))
        goto err;
    if (!FP2_mul_nor(group, r->f[1], t0, ctx))
        goto err;

    if (!FP2_mul(group, r->f[0], a->f[0], v0, ctx))
        goto err;

    if (!FP2_mul(group, t0, a->f[2], v1, ctx))
        goto err;
    if (!FP2_mul_nor(group, r->f[2], t0, ctx))
        goto err;

    if (!FP2_add(group, t0, r->f[0], r->f[1]))
        goto err;
    if (!FP2_add(group, t0, t0, r->f[2]))
        goto err;
    if (!FP2_inv(group, t0, t0, ctx))
        goto err;

    if (!FP2_mul(group, r->f[0], v0, t0, ctx))
        goto err;
    if (!FP2_mul(group, r->f[1], v1, t0, ctx))
        goto err;
    if (!FP2_mul(group, r->f[2], v2, t0, ctx))
        goto err;

    ret = 1;
 err:
    FP2_free(v0);
    FP2_free(v1);
    FP2_free(v2);
    FP2_free(t0);
    return ret;
}
