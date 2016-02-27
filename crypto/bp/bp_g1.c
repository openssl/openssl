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

G1_ELEM *G1_ELEM_new(const BP_GROUP *group)
{
    G1_ELEM *ret = NULL;

    if ((ret = OPENSSL_malloc(sizeof(*ret))) == NULL)
        return NULL;

    ret->p = EC_POINT_new(group->ec);
    if (ret->p == NULL) {
        return NULL;
    }
    return (ret);
}

void G1_ELEM_free(G1_ELEM *a)
{
    if (a == NULL)
        return;
    EC_POINT_free(a->p);
    OPENSSL_free(a);
}

void G1_ELEM_clear_free(G1_ELEM *a)
{
    if (a == NULL)
        return;
    EC_POINT_clear_free(a->p);
    OPENSSL_free(a);
}

int G1_ELEM_copy(G1_ELEM *a, const G1_ELEM *b)
{
    return EC_POINT_copy(a->p, b->p);
}

G1_ELEM *G1_ELEM_dup(const G1_ELEM *a, const BP_GROUP *group)
{
    G1_ELEM *t = NULL;

    if (a == NULL)
        return NULL;

    t = G1_ELEM_new(group);
    if (t == NULL)
        return NULL;
    if (!G1_ELEM_copy(t, a)) {
        G1_ELEM_free(t);
        return NULL;
    }
    return t;
}

int G1_ELEM_set_to_infinity(const BP_GROUP *group, G1_ELEM *point)
{
    return EC_POINT_set_to_infinity(group->ec, point->p);
}

int G1_ELEM_set_Jprojective_coordinates(const BP_GROUP *group,
                                        G1_ELEM *point, const BIGNUM *x,
                                        const BIGNUM *y, const BIGNUM *z,
                                        BN_CTX *ctx)
{
    return EC_POINT_set_Jprojective_coordinates_GFp(group->ec, point->p, x, y,
                                                    z, ctx);
}

int G1_ELEM_get_Jprojective_coordinates(const BP_GROUP *group,
                                        const G1_ELEM *point, BIGNUM *x,
                                        BIGNUM *y, BIGNUM *z, BN_CTX *ctx)
{
    return EC_POINT_get_Jprojective_coordinates_GFp(group->ec, point->p, x, y,
                                                    z, ctx);
}

int G1_ELEM_set_affine_coordinates(const BP_GROUP *group, G1_ELEM *point,
                                   const BIGNUM *x, const BIGNUM *y,
                                   BN_CTX *ctx)
{
    return EC_POINT_set_affine_coordinates_GFp(group->ec, point->p, x, y,
                                               ctx);
}

int G1_ELEM_get_affine_coordinates(const BP_GROUP *group,
                                   const G1_ELEM *point, BIGNUM *x,
                                   BIGNUM *y, BN_CTX *ctx)
{
    return EC_POINT_get_affine_coordinates_GFp(group->ec, point->p, x, y,
                                               ctx);
}

int G1_ELEM_set_compressed_coordinates(const BP_GROUP *group,
                                       G1_ELEM *point, const BIGNUM *x,
                                       int y_bit, BN_CTX *ctx)
{
    return EC_POINT_set_compressed_coordinates_GFp(group->ec, point->p, x,
                                                   y_bit, ctx);
}

size_t G1_ELEM_point2oct(const BP_GROUP *group, const G1_ELEM *point,
                         point_conversion_form_t form, unsigned char *buf,
                         size_t len, BN_CTX *ctx)
{
    return EC_POINT_point2oct(group->ec, point->p, form, buf, len, ctx);
}

int G1_ELEM_oct2point(const BP_GROUP *group, const G1_ELEM *point,
                      const unsigned char *buf, size_t len, BN_CTX *ctx)
{
    return EC_POINT_oct2point(group->ec, point->p, buf, len, ctx);
}

int G1_ELEM_add(const BP_GROUP *group, G1_ELEM *r, const G1_ELEM *point,
                const G1_ELEM *b, BN_CTX *ctx)
{
    return EC_POINT_add(group->ec, r->p, point->p, b->p, ctx);
}

int G1_ELEM_dbl(const BP_GROUP *group, G1_ELEM *r, const G1_ELEM *point,
                BN_CTX *ctx)
{
    return EC_POINT_dbl(group->ec, r->p, point->p, ctx);
}

int G1_ELEM_invert(const BP_GROUP *group, G1_ELEM *point, BN_CTX *ctx)
{
    return EC_POINT_invert(group->ec, point->p, ctx);
}

int G1_ELEM_is_at_infinity(const BP_GROUP *group, const G1_ELEM *point)
{
    return EC_POINT_is_at_infinity(group->ec, point->p);
}

int G1_ELEM_is_on_curve(const BP_GROUP *group, const G1_ELEM *point,
                        BN_CTX *ctx)
{
    return EC_POINT_is_on_curve(group->ec, point->p, ctx);
}

int G1_ELEM_cmp(const BP_GROUP *group, const G1_ELEM *point,
                const G1_ELEM *b, BN_CTX *ctx)
{
    return EC_POINT_cmp(group->ec, point->p, b->p, ctx);
}

int G1_ELEM_make_affine(const BP_GROUP *group, G1_ELEM *point, BN_CTX *ctx)
{
    return EC_POINT_make_affine(group->ec, point->p, ctx);
}

int G1_ELEMs_make_affine(const BP_GROUP *group, size_t num,
                         G1_ELEM *points[], BN_CTX *ctx)
{
    size_t i;
    EC_POINT *p[num];

    for (i = 0; i < num; i++)
        p[i] = points[i]->p;
    return EC_POINTs_make_affine(group->ec, num, p, ctx);
}

int G1_ELEM_mul(const BP_GROUP *group, G1_ELEM *r, const BIGNUM *g_scalar,
                const G1_ELEM *point, const BIGNUM *p_scalar, BN_CTX *ctx)
{
    const G1_ELEM *points[1];
    const BIGNUM *scalars[1];

    points[0] = point;
    scalars[0] = p_scalar;
    return G1_ELEMs_mul(group, r, g_scalar,
                        (point != NULL
                         && p_scalar != NULL), points, scalars, ctx);
}

int G1_ELEMs_mul(const BP_GROUP *group, G1_ELEM *r, const BIGNUM *scalar,
                 size_t num, const G1_ELEM *points[],
                 const BIGNUM *scalars[], BN_CTX *ctx)
{
    size_t i;
    const EC_POINT *p[num];

    for (i = 0; i < num; i++)
        p[i] = points[i]->p;
    return EC_POINTs_mul(group->ec, r->p, scalar, num, p, scalars, ctx);
}
