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

#include <openssl/ec.h>

#include "bp_lcl.h"

G2_ELEM *G2_ELEM_new(const BP_GROUP *group)
{
    G2_ELEM *ret = NULL;

    if ((ret = OPENSSL_malloc(sizeof(*ret))) == NULL)
        return NULL;

    ret->X = FP2_new();
    ret->Y = FP2_new();
    ret->Z = FP2_new();
    ret->Z_is_one = 0;

    if (ret->X == NULL || ret->Y == NULL || ret->Z == NULL) {
        FP2_free(ret->X);
        FP2_free(ret->Y);
        FP2_free(ret->Z);
        OPENSSL_free(ret);
        return NULL;
    }
    return ret;
}

void G2_ELEM_free(G2_ELEM *a)
{
    if (a == NULL)
        return;
    FP2_free(a->X);
    FP2_free(a->Y);
    FP2_free(a->Z);
    OPENSSL_free(a);
}

void G2_ELEM_clear_free(G2_ELEM *a)
{
    if (a == NULL)
        return;
    FP2_clear_free(a->X);
    FP2_clear_free(a->Y);
    FP2_clear_free(a->Z);
    OPENSSL_free(a);
}

int G2_ELEM_copy(G2_ELEM *a, const G2_ELEM *b)
{
    if (a == b)
        return 1;

    if (!FP2_copy(a->X, b->X))
        return 0;
    if (!FP2_copy(a->Y, b->Y))
        return 0;
    if (!FP2_copy(a->Z, b->Z))
        return 0;
    a->Z_is_one = b->Z_is_one;
    return 1;
}

G2_ELEM *G2_ELEM_dup(const G2_ELEM *a, const BP_GROUP *group)
{
    G2_ELEM *t = NULL;

    if (a == NULL)
        return NULL;

    t = G2_ELEM_new(group);
    if (t == NULL)
        return NULL;
    if (!G2_ELEM_copy(t, a)) {
        G2_ELEM_free(t);
        return NULL;
    }
    return t;
}

int G2_ELEM_set_to_infinity(const BP_GROUP *group, G2_ELEM *point)
{
    point->Z_is_one = 0;
    FP2_zero(point->Z);
    return 1;
}

int G2_ELEM_set_Jprojective_coordinates(const BP_GROUP *group,
                                        G2_ELEM *point, const BIGNUM *x[2],
                                        const BIGNUM *y[2],
                                        const BIGNUM *z[2], BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    if (x != NULL) {
        if (x[0] != NULL) {
            if (!BN_nnmod(point->X->f[0], x[0], group->field, ctx))
                goto err;
            if (!BN_to_montgomery
                (point->X->f[0], point->X->f[0], group->mont, ctx))
                goto err;
        }
        if (x[1] != NULL) {
            if (!BN_nnmod(point->X->f[1], x[1], group->field, ctx))
                goto err;
            if (!BN_to_montgomery
                (point->X->f[1], point->X->f[1], group->mont, ctx))
                goto err;
        }
    }

    if (y != NULL) {
        if (y[0] != NULL) {
            if (!BN_nnmod(point->Y->f[0], y[0], group->field, ctx))
                goto err;
            if (!BN_to_montgomery
                (point->Y->f[0], point->Y->f[0], group->mont, ctx))
                goto err;
        }
        if (y[1] != NULL) {
            if (!BN_nnmod(point->Y->f[1], y[1], group->field, ctx))
                goto err;
            if (!BN_to_montgomery
                (point->Y->f[1], point->Y->f[1], group->mont, ctx))
                goto err;
        }
    }

    if ((z != NULL) && (z[0] != NULL) && (z[1] != NULL)) {
        int Z_is_one;

        if (!BN_nnmod(point->Z->f[0], z[0], group->field, ctx))
            goto err;
        if (!BN_nnmod(point->Z->f[1], z[1], group->field, ctx))
            goto err;
        Z_is_one = BN_is_one(point->Z->f[0]) && BN_is_zero(point->Z->f[1]);
        if (!BN_to_montgomery
            (point->Z->f[0], point->Z->f[0], group->mont, ctx))
            goto err;
        if (!BN_to_montgomery
            (point->Z->f[1], point->Z->f[1], group->mont, ctx))
            goto err;
        point->Z_is_one = Z_is_one;
    }

    ret = 1;
 err:
    BN_CTX_free(new_ctx);
    return ret;
}

int G2_ELEM_get_Jprojective_coordinates(const BP_GROUP *group,
                                        const G2_ELEM *point, BIGNUM *x[2],
                                        BIGNUM *y[2], BIGNUM *z[2],
                                        BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    if ((x != NULL) & (x[0] != NULL) && (x[1] != NULL)) {
        if (!BN_from_montgomery(x[0], point->X->f[0], group->mont, ctx))
            goto err;
        if (!BN_from_montgomery(x[1], point->X->f[1], group->mont, ctx))
            goto err;
    }

    if ((y != NULL) & (y[0] != NULL) && (y[1] != NULL)) {
        if (!BN_from_montgomery(y[0], point->Y->f[0], group->mont, ctx))
            goto err;
        if (!BN_from_montgomery(y[1], point->Y->f[1], group->mont, ctx))
            goto err;
    }

    if ((z != NULL) & (z[0] != NULL) && (z[1] != NULL)) {
        if (!BN_from_montgomery(z[0], point->Z->f[0], group->mont, ctx))
            goto err;
        if (!BN_from_montgomery(z[1], point->Z->f[1], group->mont, ctx))
            goto err;
    }

    ret = 1;
 err:
    BN_CTX_free(new_ctx);
    return ret;
}

int G2_ELEM_set_affine_coordinates(const BP_GROUP *group, G2_ELEM *point,
                                   const BIGNUM *x[2], const BIGNUM *y[2],
                                   BN_CTX *ctx)
{
    BIGNUM *z[2];
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    BN_CTX_start(ctx);
    if ((z[0] = BN_CTX_get(ctx)) == NULL || (z[1] = BN_CTX_get(ctx)) == NULL)
        goto err;

    if (x == NULL || x[0] == NULL || x[1] == NULL || y == NULL || y[0] == NULL
        || y[1] == NULL) {
        goto err;
    }

    BN_one(z[0]);
    BN_zero(z[1]);

    ret = G2_ELEM_set_Jprojective_coordinates(group, point, x, y,
                                              (const BIGNUM **)z, ctx);
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

int G2_ELEM_get_affine_coordinates(const BP_GROUP *group,
                                   const G2_ELEM *point, BIGNUM *x[2],
                                   BIGNUM *y[2], BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    FP2 *z, *z1 = NULL, *z2 = NULL, *z3 = NULL;
    int ret = 0;

    if (G2_ELEM_is_at_infinity(group, point)) {
        return 0;
    }

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    BN_CTX_start(ctx);
    if ((z = FP2_new()) == NULL || (z1 = FP2_new()) == NULL
        || (z2 = FP2_new()) == NULL || (z3 = FP2_new()) == NULL) {
        goto err;
    }

    if (!BN_from_montgomery(z->f[0], point->Z->f[0], group->mont, ctx))
        goto err;
    if (!BN_from_montgomery(z->f[1], point->Z->f[1], group->mont, ctx))
        goto err;

    if (BN_is_one(z->f[0]) && BN_is_zero(z->f[1])) {
        if (x != NULL && x[0] != NULL
            && !BN_from_montgomery(x[0], point->X->f[0], group->mont, ctx))
            goto err;
        if (x != NULL && x[1] != NULL
            && !BN_from_montgomery(x[1], point->X->f[1], group->mont, ctx))
            goto err;
        if (y != NULL && y[0] != NULL
            && !BN_from_montgomery(y[0], point->Y->f[0], group->mont, ctx))
            goto err;
        if (y != NULL && y[1] != NULL
            && !BN_from_montgomery(y[1], point->Y->f[1], group->mont, ctx))
            goto err;
    } else {
        if (!FP2_inv(group, z1, point->Z, ctx))
            goto err;
        if (!FP2_sqr(group, z2, z1, ctx))
            goto err;
        if (!FP2_mul(group, z3, z2, z1, ctx))
            goto err;
        if (!FP2_mul(group, z2, z2, point->X, ctx))
            goto err;
        if (!FP2_mul(group, z3, z3, point->Y, ctx))
            goto err;

        if (x != NULL && x[0] != NULL && x[1] != NULL) {
            if (!BN_from_montgomery(x[0], z2->f[0], group->mont, ctx))
                goto err;
            if (!BN_from_montgomery(x[1], z2->f[1], group->mont, ctx))
                goto err;
        }
        if (y != NULL && y[0] != NULL && y[1] != NULL) {
            if (!BN_from_montgomery(y[0], z3->f[0], group->mont, ctx))
                goto err;
            if (!BN_from_montgomery(y[1], z3->f[1], group->mont, ctx))
                goto err;
        }
    }

    ret = 1;
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    FP2_free(z);
    FP2_free(z1);
    FP2_free(z2);
    FP2_free(z3);
    return ret;
}

size_t G2_ELEM_point2oct(const BP_GROUP *group, const G2_ELEM *point,
                         point_conversion_form_t form, unsigned char *buf,
                         size_t len, BN_CTX *ctx)
{
    size_t ret;
    BN_CTX *new_ctx = NULL;
    int used_ctx = 0;
    BIGNUM *x[2], *y[2];
    size_t field_len, i, skip;

    if (form != POINT_CONVERSION_UNCOMPRESSED)
        goto err;

    if (G2_ELEM_is_at_infinity(group, point)) {
        /*
         * encodes to a single 0 octet
         */
        if (buf != NULL) {
            if (len < 1)
                return 0;
            buf[0] = 0;
        }
        return 1;
    }

    /*
     * ret := required output buffer length
     */
    field_len = BN_num_bytes(group->field);
    ret = 4 * field_len;

    /*
     * if 'buf' is NULL, just return required length
     */
    if (buf != NULL) {
        if (len < ret)
            goto err;

        if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
            return 0;

        used_ctx = 1;
        BN_CTX_start(ctx);
        if ((x[0] = BN_CTX_get(ctx)) == NULL
            || (x[1] = BN_CTX_get(ctx)) == NULL
            || (y[0] = BN_CTX_get(ctx)) == NULL
            || (y[1] = BN_CTX_get(ctx)) == NULL) {
            goto err;
        }

        if (!G2_ELEM_get_affine_coordinates(group, point, x, y, ctx))
            goto err;

        i = 0;
        skip = field_len - BN_num_bytes(x[0]);
        if (skip > field_len)
            goto err;
        while (skip > 0) {
            buf[i++] = 0;
            skip--;
        }
        skip = BN_bn2bin(x[0], buf + i);
        i += skip;
        if (i != field_len)
            goto err;

        skip = field_len - BN_num_bytes(x[1]);
        if (skip > field_len)
            goto err;
        while (skip > 0) {
            buf[i++] = 0;
            skip--;
        }
        skip = BN_bn2bin(x[1], buf + i);
        i += skip;
        if (i != 2 * field_len)
            goto err;

        if (form == POINT_CONVERSION_UNCOMPRESSED) {
            skip = field_len - BN_num_bytes(y[0]);
            if (skip > field_len)
                goto err;
            while (skip > 0) {
                buf[i++] = 0;
                skip--;
            }
            skip = BN_bn2bin(y[0], buf + i);
            i += skip;

            skip = field_len - BN_num_bytes(y[1]);
            if (skip > field_len)
                goto err;
            while (skip > 0) {
                buf[i++] = 0;
                skip--;
            }
            skip = BN_bn2bin(y[1], buf + i);
            i += skip;
        }

        if (i != ret)
            goto err;
    }

    if (used_ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;

 err:
    if (used_ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return 0;
}

int G2_ELEM_oct2point(const BP_GROUP *group, G2_ELEM *point,
                      const unsigned char *buf, size_t len, BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    BIGNUM *x[2], *y[2];
    size_t field_len, enc_len;
    int ret = 0;

    if (len == 0)
        return 0;

    if (len == 1)
        return G2_ELEM_set_to_infinity(group, point);

    field_len = BN_num_bytes(group->field);
    enc_len = 4 * field_len;

    if (len != enc_len)
        return 0;

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    BN_CTX_start(ctx);
    if ((x[0] = BN_CTX_get(ctx)) == NULL || (x[1] = BN_CTX_get(ctx)) == NULL
        || (y[0] = BN_CTX_get(ctx)) == NULL
        || (y[1] = BN_CTX_get(ctx)) == NULL) {
        goto err;
    }

    if (!BN_bin2bn(buf, field_len, x[0]))
        goto err;
    if (BN_ucmp(x[0], group->field) >= 0)
        goto err;
    if (!BN_bin2bn(buf + field_len, field_len, x[1]))
        goto err;
    if (BN_ucmp(x[1], group->field) >= 0)
        goto err;

    if (!BN_bin2bn(buf + 2 * field_len, field_len, y[0]))
        goto err;
    if (BN_ucmp(y[0], group->field) >= 0)
        goto err;
    if (!BN_bin2bn(buf + 3 * field_len, field_len, y[1]))
        goto err;
    if (BN_ucmp(y[1], group->field) >= 0)
        goto err;

    if (!G2_ELEM_set_affine_coordinates(group, point, (const BIGNUM **)x,
                                        (const BIGNUM **)y, ctx))
        goto err;

    /*
     * test required by X9.62
     */
    if (G2_ELEM_is_on_curve(group, point, ctx) <= 0)
        goto err;

    ret = 1;
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

int G2_ELEM_add(const BP_GROUP *group, G2_ELEM *r, const G2_ELEM *a,
                const G2_ELEM *b, BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    FP2 *t0, *t1 = NULL, *t2 = NULL, *t3 = NULL, *t4 = NULL, *t5 = NULL,
        *t6 = NULL;
    int ret = 0;

    if (a == b)
        return G2_ELEM_dbl(group, r, a, ctx);
    if (G2_ELEM_is_at_infinity(group, a))
        return G2_ELEM_copy(r, b);
    if (G2_ELEM_is_at_infinity(group, b))
        return G2_ELEM_copy(r, a);

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    BN_CTX_start(ctx);
    if ((t0 = FP2_new()) == NULL || (t1 = FP2_new()) == NULL
        || (t2 = FP2_new()) == NULL || (t3 = FP2_new()) == NULL
        || (t4 = FP2_new()) == NULL || (t5 = FP2_new()) == NULL
        || (t6 = FP2_new()) == NULL) {
        goto err;
    }

    /*
     * Note that in this function we must not read components of 'a' or 'b'
     * once we have written the corresponding components of 'r'. ('r' might
     * be one of 'a' or 'b'.)
     */

    /*
     * t1 = X_a, t2 = Y_a
     */
    if (b->Z_is_one) {
        if (!FP2_copy(t1, a->X))
            goto err;
        if (!FP2_copy(t2, a->Y))
            goto err;
    } else {
        /*
         * t1 = X_a * Z_b^2
         */
        if (!FP2_sqr(group, t0, b->Z, ctx))
            goto err;
        if (!FP2_mul(group, t1, a->X, t0, ctx))
            goto err;

        /*
         * t2 = Y_a * Z_b^3
         */
        if (!FP2_mul(group, t0, t0, b->Z, ctx))
            goto err;
        if (!FP2_mul(group, t2, a->Y, t0, ctx))
            goto err;
    }

    /*
     * t3 = X_b, t4 = Y_b
     */
    if (a->Z_is_one) {
        if (!FP2_copy(t3, b->X))
            goto err;
        if (!FP2_copy(t4, b->Y))
            goto err;
    } else {
        /*
         * t3 = X_b * Z_a^2
         */
        if (!FP2_sqr(group, t0, a->Z, ctx))
            goto err;
        if (!FP2_mul(group, t3, b->X, t0, ctx))
            goto err;
        /*
         * t4 = Y_b * Z_a^3
         */
        if (!FP2_mul(group, t0, t0, a->Z, ctx))
            goto err;
        if (!FP2_mul(group, t4, b->Y, t0, ctx))
            goto err;
    }

    /*
     * t5 = t1 - t2, t6 = t2 - t4
     */
    if (!FP2_sub(group, t5, t1, t3))
        goto err;
    if (!FP2_sub(group, t6, t2, t4))
        goto err;

    if (FP2_is_zero(t5)) {
        if (FP2_is_zero(t6)) {
            /*
             * a is the same point as b
             */
            BN_CTX_end(ctx);
            ret = G2_ELEM_dbl(group, r, a, ctx);
            ctx = NULL;
            goto err;
        } else {
            /*
             * a is the inverse of b
             */
            FP2_zero(r->Z);
            r->Z_is_one = 0;
            ret = 1;
            goto err;
        }
    }

    /*
     * 'n7', 'n8'
     */
    if (!FP2_add(group, t1, t1, t3))
        goto err;
    if (!FP2_add(group, t2, t2, t4))
        goto err;
    /*
     * 'n7' = t1 + t3
     */
    /*
     * 'n8' = t2 + t4
     */

    /*
     * Z_r
     */
    if (a->Z_is_one && b->Z_is_one) {
        if (!FP2_copy(r->Z, t5))
            goto err;
    } else {
        if (a->Z_is_one) {
            if (!FP2_copy(t0, b->Z))
                goto err;
        } else if (b->Z_is_one) {
            if (!FP2_copy(t0, a->Z))
                goto err;
        } else {
            if (!FP2_mul(group, t0, a->Z, b->Z, ctx))
                goto err;
        }
        if (!FP2_mul(group, r->Z, t0, t5, ctx))
            goto err;
    }
    r->Z_is_one = 0;
    /*
     * Z_r = Z_a * Z_b * t5
     */

    /*
     * X_r
     */
    if (!FP2_sqr(group, t0, t6, ctx))
        goto err;
    if (!FP2_sqr(group, t4, t5, ctx))
        goto err;
    if (!FP2_mul(group, t3, t1, t4, ctx))
        goto err;
    if (!FP2_sub(group, r->X, t0, t3))
        goto err;
    /*
     * X_r = t6^2 - t5^2 * 'n7'
     */

    /*
     * 'n9'
     */
    if (!FP2_dbl(group, t0, r->X))
        goto err;
    if (!FP2_sub(group, t0, t3, t0))
        goto err;
    /*
     * n9 = t5^2 * 'n7' - 2 * X_r
     */

    /*
     * Y_r
     */
    if (!FP2_mul(group, t0, t0, t6, ctx))
        goto err;
    if (!FP2_mul(group, t5, t4, t5, ctx))
        goto err;               /* now t5 is t5^3 */
    if (!FP2_mul(group, t1, t2, t5, ctx))
        goto err;
    if (!FP2_sub(group, t0, t0, t1))
        goto err;
    if (BN_is_odd(t0->f[0])) {
        if (!BN_add(t0->f[0], t0->f[0], group->field))
            goto err;
    }
    if (!BN_rshift1(r->Y->f[0], t0->f[0]))
        goto err;
    if (BN_is_odd(t0->f[1]) && !BN_add(t0->f[1], t0->f[1], group->field))
        goto err;
    if (!BN_rshift1(r->Y->f[1], t0->f[1]))
        goto err;

    /*
     * Y_r = (t6 * 'n9' - 'n8' * 't5^3') / 2
     */

    ret = 1;
 err:
    if (ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    FP2_free(t0);
    FP2_free(t1);
    FP2_free(t2);
    FP2_free(t3);
    FP2_free(t4);
    FP2_free(t5);
    FP2_free(t6);
    return ret;
}

int G2_ELEM_dbl(const BP_GROUP *group, G2_ELEM *r, const G2_ELEM *a,
                BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    FP2 *t0, *t1 = NULL, *t2 = NULL, *t3 = NULL;
    int ret = 0;

    if (G2_ELEM_is_at_infinity(group, a)) {
        FP2_zero(r->Z);
        r->Z_is_one = 0;
        return 1;
    }

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    BN_CTX_start(ctx);
    if ((t0 = FP2_new()) == NULL || (t1 = FP2_new()) == NULL
        || (t2 = FP2_new()) == NULL || (t3 = FP2_new()) == NULL) {
        goto err;
    }

    /*
     * Note that in this function we must not read components of 'a' once we
     * have written the corresponding components of 'r'. ('r' might the same
     * as 'a'.)
     */

    /*
     * t1 = 3 * X_a^2 + a_curve * Z_a^4
     */
    if (!FP2_sqr(group, t0, a->X, ctx))
        goto err;
    if (!FP2_dbl(group, t1, t0))
        goto err;
    if (!FP2_add(group, t1, t1, t0))
        goto err;

    /*
     * Z_r = 2 * Y_a * Z_a
     */
    if (a->Z_is_one) {
        if (!FP2_copy(t0, a->Y))
            goto err;
    } else {
        if (!FP2_mul(group, t0, a->Y, a->Z, ctx))
            goto err;
    }
    if (!FP2_dbl(group, r->Z, t0))
        goto err;
    r->Z_is_one = 0;

    /*
     * t2 = 4 * X_a * Y_a^2
     */
    if (!FP2_sqr(group, t3, a->Y, ctx))
        goto err;
    if (!FP2_mul(group, t2, a->X, t3, ctx))
        goto err;
    if (!FP2_dbl(group, t2, t2))
        goto err;
    if (!FP2_dbl(group, t2, t2))
        goto err;

    /*
     * X_r = t1^2 - 2 * t2
     */
    if (!FP2_dbl(group, t0, t2))
        goto err;
    if (!FP2_sqr(group, r->X, t1, ctx))
        goto err;
    if (!FP2_sub(group, r->X, r->X, t0))
        goto err;

    /*
     * t3 = 8 * Y_a^4
     */
    if (!FP2_sqr(group, t0, t3, ctx))
        goto err;
    if (!FP2_dbl(group, t3, t0))
        goto err;
    if (!FP2_dbl(group, t3, t3))
        goto err;
    if (!FP2_dbl(group, t3, t3))
        goto err;

    /*
     * Y_r = t1 * (t2 - X_r) - t3
     */
    if (!FP2_sub(group, t0, t2, r->X))
        goto err;
    if (!FP2_mul(group, t0, t1, t0, ctx))
        goto err;
    if (!FP2_sub(group, r->Y, t0, t3))
        goto err;

    ret = 1;
 err:
    FP2_free(t0);
    FP2_free(t1);
    FP2_free(t2);
    FP2_free(t3);
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

int G2_ELEM_invert(const BP_GROUP *group, G2_ELEM *point, BN_CTX *ctx)
{
    if (G2_ELEM_is_at_infinity(group, point) || FP2_is_zero(point->Y))
        /*
         * point is its own inverse
         */
        return 1;

    return FP2_neg(group, point->Y, point->Y);

}

int G2_ELEM_is_at_infinity(const BP_GROUP *group, const G2_ELEM *point)
{
    return FP2_is_zero(point->Z);
}

int G2_ELEM_is_on_curve(const BP_GROUP *group, const G2_ELEM *point,
                        BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    FP2 *rh, *t = NULL, *z4 = NULL, *z6 = NULL;
    int ret = -1;

    if (G2_ELEM_is_at_infinity(group, point))
        return 1;

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    BN_CTX_start(ctx);
    if ((rh = FP2_new()) == NULL || (t = FP2_new()) == NULL
        || (z4 = FP2_new()) == NULL || (z6 = FP2_new()) == NULL) {
        goto err;
    }

    /*-
     * We have a curve defined by a Weierstrass equation
     *      y^2 = x^3 + a*x + b'.
     * The point to consider is given in Jacobian projective coordinates
     * where  (X, Y, Z)  represents  (x, y) = (X/Z^2, Y/Z^3).
     * Substituting this and multiplying by  Z^6  transforms the above equation into
     *      Y^2 = X^3 + a*X*Z^4 + b'*Z^6.
     * To test this, we add up the right-hand side in 'rh'.
     */

    /*
     * rh := X^3
     */
    if (!FP2_sqr(group, rh, point->X, ctx))
        goto err;
    if (!FP2_mul(group, rh, rh, point->X, ctx))
        goto err;

    if (!point->Z_is_one) {
        /*
         * Full projective coordinates (Z != 1).
         */
        if (!FP2_sqr(group, t, point->Z, ctx))
            goto err;
        if (!FP2_sqr(group, z4, t, ctx))
            goto err;
        if (!FP2_mul(group, z6, z4, t, ctx))
            goto err;

        /*
         * rh := (rh + a*Z^4)*X + b*Z^6
         */
        if (!BN_mod_add_quick(t->f[0], z6->f[0], z6->f[1], group->field))
            goto err;
        if (!BN_mod_sub_quick(t->f[1], z6->f[1], z6->f[0], group->field))
            goto err;
        if (!FP2_add(group, rh, rh, t))
            goto err;
    } else {
        /*
         * Affine coordinates (Z = 1).
         */

        /*
         * rh := rh + b, b = 1 - i.
         */
        if (!BN_mod_add_quick(rh->f[0], rh->f[0], group->one, group->field))
            goto err;
        if (!BN_mod_sub_quick(rh->f[1], rh->f[1], group->one, group->field))
            goto err;
    }

    /*
     * 'lh' := Y^2
     */
    if (!FP2_sqr(group, t, point->Y, ctx))
        goto err;

    ret = (0 == FP2_cmp(t, rh));

 err:
    FP2_free(rh);
    FP2_free(t);
    FP2_free(z4);
    FP2_free(z6);
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

int G2_ELEM_cmp(const BP_GROUP *group, const G2_ELEM *a, const G2_ELEM *b,
                BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    FP2 *tmp1 = NULL, *tmp2 = NULL, *Za23 = NULL, *Zb23 = NULL;
    const FP2 *tmp1_, *tmp2_;
    int ret = -1;

    if (G2_ELEM_is_at_infinity(group, a))
        return G2_ELEM_is_at_infinity(group, b) ? 0 : 1;

    if (G2_ELEM_is_at_infinity(group, b))
        return 1;

    if (a->Z_is_one && b->Z_is_one) {
        return ((FP2_cmp(a->X, b->X) == 0)
                && FP2_cmp(a->Y, b->Y) == 0) ? 0 : 1;
    }

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    if ((tmp1 = FP2_new()) == NULL || (tmp2 = FP2_new()) == NULL
        || (Za23 = FP2_new()) == NULL || (Zb23 = FP2_new()) == NULL) {
        goto end;
    }

    /*-
     * We have to decide whether
     *     (X_a/Z_a^2, Y_a/Z_a^3) = (X_b/Z_b^2, Y_b/Z_b^3),
     * or equivalently, whether
     *     (X_a*Z_b^2, Y_a*Z_b^3) = (X_b*Z_a^2, Y_b*Z_a^3).
     */

    if (!b->Z_is_one) {
        if (!FP2_sqr(group, Zb23, b->Z, ctx))
            goto end;
        if (!FP2_mul(group, tmp1, a->X, Zb23, ctx))
            goto end;
        tmp1_ = tmp1;
    } else
        tmp1_ = a->X;
    if (!a->Z_is_one) {
        if (!FP2_sqr(group, Za23, a->Z, ctx))
            goto end;
        if (!FP2_mul(group, tmp2, b->X, Za23, ctx))
            goto end;
        tmp2_ = tmp2;
    } else
        tmp2_ = b->X;

    /*
     * compare X_a*Z_b^2 with X_b*Z_a^2
     */
    if (FP2_cmp(tmp1_, tmp2_) != 0) {
        ret = 1;                /* points differ */
        goto end;
    }

    if (!b->Z_is_one) {
        if (!FP2_mul(group, Zb23, Zb23, b->Z, ctx))
            goto end;
        if (!FP2_mul(group, tmp1, a->Y, Zb23, ctx))
            goto end;
        /*
         * tmp1_ = tmp1
         */
    } else {
        tmp1_ = a->Y;
    }
    if (!a->Z_is_one) {
        if (!FP2_mul(group, Za23, Za23, a->Z, ctx))
            goto end;
        if (!FP2_mul(group, tmp2, b->Y, Za23, ctx))
            goto end;
        /*
         * tmp2_ = tmp2
         */
    } else {
        tmp2_ = b->Y;
    }

    /*
     * compare Y_a*Z_b^3 with Y_b*Z_a^3
     */
    if (FP2_cmp(tmp1_, tmp2_) != 0) {
        ret = 1;                /* points differ */
        goto end;
    }

    /*
     * points are equal
     */
    ret = 0;

 end:
    FP2_free(tmp1);
    FP2_free(tmp2);
    FP2_free(Za23);
    FP2_free(Zb23);
    BN_CTX_free(new_ctx);
    return ret;
}

int G2_ELEM_make_affine(const BP_GROUP *group, G2_ELEM *point, BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    BIGNUM *x[2], *y[2];
    int ret = 0;

    if (point->Z_is_one || G2_ELEM_is_at_infinity(group, point))
        return 1;

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    BN_CTX_start(ctx);
    if ((x[0] = BN_CTX_get(ctx)) == NULL || (x[1] = BN_CTX_get(ctx)) == NULL
        || (y[0] = BN_CTX_get(ctx)) == NULL
        || (y[1] = BN_CTX_get(ctx)) == NULL) {
        goto err;
    }

    if (!G2_ELEM_get_affine_coordinates(group, point, x, y, ctx))
        goto err;
    if (!G2_ELEM_set_affine_coordinates
        (group, point, (const BIGNUM **)x, (const BIGNUM **)y, ctx))
        goto err;
    if (!point->Z_is_one)
        goto err;

    ret = 1;
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

int G2_ELEMs_make_affine(const BP_GROUP *group, size_t num,
                         G2_ELEM *points[], BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    FP2 *zs[num], *z2 = NULL, *z3 = NULL;
    size_t i, m = 0;
    int ret = 0;

    if (num == 0)
        return 1;

    if (num == 1)
        return G2_ELEM_make_affine(group, points[0], ctx);

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    if ((z2 = FP2_new()) == NULL || (z3 = FP2_new()) == NULL)
        goto err;

    m = 0;
    for (i = 0; i < num; i++) {
        if (points[i]->Z_is_one || G2_ELEM_is_at_infinity(group, points[i]))
            continue;
        if ((zs[m] = FP2_new()) == NULL)
            goto err;
        if (!FP2_copy(zs[m++], points[i]->Z))
            goto err;
    }

    if (!FP2_inv_simultaneous(group, zs, zs, m, ctx))
        goto err;

    m = 0;
    for (i = 0; i < num; i++) {
        if (points[i]->Z_is_one || G2_ELEM_is_at_infinity(group, points[i]))
            continue;
        if (!FP2_sqr(group, z2, zs[m], ctx))
            goto err;
        if (!FP2_mul(group, z3, z2, zs[m++], ctx))
            goto err;
        if (!FP2_mul(group, points[i]->X, z2, points[i]->X, ctx))
            goto err;
        if (!FP2_mul(group, points[i]->Y, z3, points[i]->Y, ctx))
            goto err;
        points[i]->Z_is_one = 1;
    }

    ret = 1;
 err:
    BN_CTX_free(new_ctx);
    FP2_free(z2);
    FP2_free(z3);
    for (i = 0; i < m; i++) {
        FP2_free(zs[i]);
    }
    return ret;
}
