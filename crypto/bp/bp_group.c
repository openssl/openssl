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
 * Authored by Diego F. Aranha (d@miracl.com).
 */

#include <openssl/ec.h>
#include <openssl/bp.h>
#include <openssl/err.h>

#include "bp_lcl.h"

/*
 * These are the parameters of curve fpbn254b, taken from IETF draft
 * https://tools.ietf.org/html/draft-kasamatsu-bncurves and
 * represented in big-endian.
 */
static const uint8_t fpbn254b_params[11][32] = {
    {0x25, 0x23, 0x64, 0x82, 0x40, 0x00, 0x00, 0x01, /* p */
     0xBA, 0x34, 0x4D, 0x80, 0x00, 0x00, 0x00, 0x08,
     0x61, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
     0xA7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* a = 0 */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* b = 2 */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
    {0x25, 0x23, 0x64, 0x82, 0x40, 0x00, 0x00, 0x01, /* x */
     0xBA, 0x34, 0x4D, 0x80, 0x00, 0x00, 0x00, 0x08,
     0x61, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
     0xA7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* y */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
    {0x25, 0x23, 0x64, 0x82, 0x40, 0x00, 0x00, 0x01, /* order */
     0xBA, 0x34, 0x4D, 0x80, 0x00, 0x00, 0x00, 0x07,
     0xFF, 0x9F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x10,
     0xA1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D},
    {0x06, 0x1A, 0x10, 0xBB, 0x51, 0x9E, 0xB6, 0x2F, /* x_0 */
     0xEB, 0x8D, 0x8C, 0x7E, 0x8C, 0x61, 0xED, 0xB6,
     0xA4, 0x64, 0x8B, 0xBB, 0x48, 0x98, 0xBF, 0x0D,
     0x91, 0xEE, 0x42, 0x24, 0xC8, 0x03, 0xFB, 0x2B},
    {0x05, 0x16, 0xAA, 0xF9, 0xBA, 0x73, 0x78, 0x33, /* x_1 */
     0x31, 0x0A, 0xA7, 0x8C, 0x59, 0x82, 0xAA, 0x5B,
     0x1F, 0x4D, 0x74, 0x6B, 0xAE, 0x37, 0x84, 0xB7,
     0x0D, 0x8C, 0x34, 0xC1, 0xE7, 0xD5, 0x4C, 0xF3},
    {0x02, 0x18, 0x97, 0xA0, 0x6B, 0xAF, 0x93, 0x43, /* y_0 */
     0x9A, 0x90, 0xE0, 0x96, 0x69, 0x8C, 0x82, 0x23,
     0x29, 0xBD, 0x0A, 0xE6, 0xBD, 0xBE, 0x09, 0xBD,
     0x19, 0xF0, 0xE0, 0x78, 0x91, 0xCD, 0x2B, 0x9A},
    {0x0E, 0xBB, 0x2B, 0x0E, 0x7C, 0x8B, 0x15, 0x26, /* y_1 */
     0x8F, 0x6D, 0x44, 0x56, 0xF5, 0xF3, 0x8D, 0x37,
     0xB0, 0x90, 0x06, 0xFF, 0xD7, 0x39, 0xC9, 0x57,
     0x8A, 0x2D, 0x1A, 0xEC, 0x6B, 0x3A, 0xCE, 0x9B},
    {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Negative */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Miller */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* parameter */
     0x40, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
};

static int BP_GROUP_init(BP_GROUP *group)
{
    if (group != NULL) {
        group->field = BN_new();
        group->param = BN_new();
        group->one = BN_new();
        group->mont = BN_MONT_CTX_new();
        group->frb = FP2_new();
        group->ec = EC_GROUP_new(EC_GFp_mont_method());
        group->gen2 = G2_ELEM_new(group);
        group->g2_pre_comp = NULL;
        if (group->field == NULL || group->param == NULL || group->one == NULL
            || group->mont == NULL || group->frb == NULL || group->ec == NULL
            || group->gen2 == NULL) {
            BN_free(group->one);
            BN_free(group->param);
            BN_free(group->field);
            FP2_free(group->frb);
            BN_MONT_CTX_free(group->mont);
            EC_GROUP_free(group->ec);
            G2_ELEM_free(group->gen2);
            return 0;
        }
    }
    return 1;
}

BP_GROUP *BP_GROUP_new(void)
{
    BP_GROUP *ret;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        BPerr(BP_F_BP_GROUP_NEW, BP_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!BP_GROUP_init(ret))
        return NULL;

    return ret;
}

BP_GROUP *BP_GROUP_new_curve(const BIGNUM *p, const BIGNUM *a,
                             const BIGNUM *b, BN_CTX *ctx)
{
    BP_GROUP *ret;

    ret = BP_GROUP_new();
    if (ret == NULL)
        return NULL;

    if (!BP_GROUP_set_curve(ret, p, a, b, ctx)) {
        BP_GROUP_clear_free(ret);
        return NULL;
    }

    return ret;
}

BP_GROUP *BP_GROUP_new_by_curve_name(int nid)
{
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    BP_GROUP *ret = NULL;

    if ((p = BN_new()) == NULL || (a = BN_new()) == NULL
        || (b = BN_new()) == NULL || (ret = BP_GROUP_new()) == NULL) {
        goto err;
    }

    switch (nid) {
    case NID_fp254bnb:
        BN_bin2bn(fpbn254b_params[0], sizeof(fpbn254b_params[0]), p);
        BN_bin2bn(fpbn254b_params[1], sizeof(fpbn254b_params[1]), a);
        BN_bin2bn(fpbn254b_params[2], sizeof(fpbn254b_params[2]), b);
        if (!BP_GROUP_set_curve(ret, p, a, b, NULL))
            goto err;
        break;
    default:
        BP_GROUP_free(ret);
        ret = NULL;
        break;
    }

 err:
    BN_free(p);
    BN_free(a);
    BN_free(b);
    return ret;
}

void BP_GROUP_free(BP_GROUP *group)
{
    if (group != NULL) {
        BN_clear_free(group->one);
        BN_clear_free(group->param);
        BN_clear_free(group->field);
        FP2_clear_free(group->frb);
        BN_MONT_CTX_free(group->mont);
        EC_GROUP_free(group->ec);
        G2_ELEM_free(group->gen2);
        if (group->g2_pre_comp != NULL)
            g2_pre_comp_free(group->g2_pre_comp);
    }
}

void BP_GROUP_clear_free(BP_GROUP *group)
{
    BN_free(group->one);
    BN_free(group->param);
    BN_free(group->field);
    FP2_free(group->frb);
    BN_MONT_CTX_free(group->mont);
    EC_GROUP_free(group->ec);
    G2_ELEM_clear_free(group->gen2);
    if (group->g2_pre_comp != NULL)
        g2_pre_comp_free(group->g2_pre_comp);
}

int BP_GROUP_copy(BP_GROUP *dest, const BP_GROUP *src)
{
    if (dest == src)
        return 1;

    /* Copy G_2. */
    dest->g2_pre_comp = g2_pre_comp_dup(src->g2_pre_comp);

    if (!BN_copy(dest->field, src->field))
        return 0;

    if (src->mont != NULL) {
        if (dest->mont == NULL) {
            dest->mont = BN_MONT_CTX_new();
            if (dest->mont == NULL)
                return 0;
        }
        if (!BN_MONT_CTX_copy(dest->mont, src->mont))
            return 0;
    } else {
        /* src->generator == NULL */
        BN_MONT_CTX_free(dest->mont);
        dest->mont = NULL;
    }

    if (!BN_copy(dest->one, src->one))
        return 0;

    if (!BN_copy(dest->param, src->param))
        return 0;

    if (src->gen2 != NULL) {
        if (dest->gen2 == NULL) {
            dest->gen2 = G2_ELEM_new(dest);
            if (dest->gen2 == NULL)
                return 0;
        }
        if (!G2_ELEM_copy(dest->gen2, src->gen2))
            return 0;
    } else {
        /* src->generator == NULL */
        G2_ELEM_clear_free(dest->gen2);
        dest->gen2 = NULL;
    }

    if (src->frb != NULL) {
        if (dest->frb == NULL) {
            dest->frb = FP2_new();
            if (dest->frb == NULL)
                return 0;
        }
        if (!FP2_copy(dest->frb, src->frb))
            return 0;
    } else {
        FP2_clear_free(dest->frb);
        dest->frb = NULL;
    }

    /* Copy G_1. */
    return EC_GROUP_copy(dest->ec, src->ec);
}

BP_GROUP *BP_GROUP_dup(const BP_GROUP *a)
{
    BP_GROUP *t = NULL;
    int ok = 0;

    if (a == NULL)
        return NULL;

    if ((t = BP_GROUP_new()) == NULL)
        return NULL;
    if (!BP_GROUP_copy(t, a))
        goto err;

    ok = 1;

 err:
    if (!ok) {
        BP_GROUP_free(t);
        return NULL;
    }
    return t;
}

int BP_GROUP_set_curve(BP_GROUP *group, const BIGNUM *p, const BIGNUM *a,
                       const BIGNUM *b, BN_CTX *ctx)
{
    int found, ret = 0;
    BN_CTX *new_ctx = NULL;
    EC_POINT *g1 = NULL;
    BIGNUM *curve_p, *curve_a, *curve_b, *curve_x, *curve_y, *order;
    BIGNUM *x[2], *y[2], *m, *d, *r;

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    /*
     * Allocate space for parameters and check if input is right.
     */
    BN_CTX_start(ctx);
    if ((curve_p = BN_CTX_get(ctx)) == NULL
        || (curve_a = BN_CTX_get(ctx)) == NULL
        || (curve_b = BN_CTX_get(ctx)) == NULL
        || (curve_x = BN_CTX_get(ctx)) == NULL
        || (curve_y = BN_CTX_get(ctx)) == NULL
        || (order = BN_CTX_get(ctx)) == NULL
        || (x[0] = BN_CTX_get(ctx)) == NULL
        || (x[1] = BN_CTX_get(ctx)) == NULL
        || (y[0] = BN_CTX_get(ctx)) == NULL
        || (y[1] = BN_CTX_get(ctx)) == NULL || (d = BN_CTX_get(ctx)) == NULL
        || (r = BN_CTX_get(ctx)) == NULL || (m = BN_CTX_get(ctx)) == NULL) {
        goto err;
    }

    found = 0;

    BN_bin2bn(fpbn254b_params[0], sizeof(fpbn254b_params[0]), curve_p);
    BN_bin2bn(fpbn254b_params[1], sizeof(fpbn254b_params[1]), curve_a);
    BN_bin2bn(fpbn254b_params[2], sizeof(fpbn254b_params[2]), curve_b);
    if ((BN_cmp(curve_p, p) == 0) && (BN_cmp(curve_a, a) == 0)
        && (BN_cmp(curve_b, b)) == 0) {
        found = 1;
        BN_bin2bn(fpbn254b_params[3], sizeof(fpbn254b_params[3]), curve_x);
        BN_bin2bn(fpbn254b_params[4], sizeof(fpbn254b_params[4]), curve_y);
        BN_bin2bn(fpbn254b_params[5], sizeof(fpbn254b_params[5]), order);
        BN_bin2bn(fpbn254b_params[6], sizeof(fpbn254b_params[6]), x[0]);
        BN_bin2bn(fpbn254b_params[7], sizeof(fpbn254b_params[7]), x[1]);
        BN_bin2bn(fpbn254b_params[8], sizeof(fpbn254b_params[8]), y[0]);
        BN_bin2bn(fpbn254b_params[9], sizeof(fpbn254b_params[9]), y[1]);
        BN_bin2bn(fpbn254b_params[10], sizeof(fpbn254b_params[10]), m);
    }

    if (found == 0) {
        if (!BN_copy(curve_p, p))
            goto err;
        if (!BN_copy(curve_a, a))
            goto err;
        if (!BN_copy(curve_b, b))
            goto err;
    }

    /*
     * Check that p = 3 mod 4 and = 1 mod 6, initialize field and extension.
     */
    if (!BN_is_bit_set(curve_p, 0) || !BN_is_bit_set(curve_p, 1)) {
        BPerr(BP_F_BP_GROUP_SET_CURVE, BP_R_INVALID_PRIME_FIELD);
        goto err;
    }
    if (!BN_set_word(r, 6))
        goto err;
    if (!BN_div(d, r, curve_p, r, ctx))
        goto err;
    if (!BN_is_one(r)) {
        BPerr(BP_F_BP_GROUP_SET_CURVE, BP_R_INVALID_PRIME_FIELD);
        goto err;
    }

    if (!BN_copy(group->field, curve_p))
        goto err;
    if (!BN_MONT_CTX_set(group->mont, group->field, ctx))
        goto err;
    if (!BN_to_montgomery(group->one, BN_value_one(), group->mont, ctx))
        goto err;
    if (!BN_copy(group->param, m))
        goto err;
    if (BN_is_bit_set(group->param, 8 * BN_num_bytes(group->field) - 1)) {
        BN_clear_bit(group->param, 8 * BN_num_bytes(group->field) - 1);
        BN_set_negative(group->param, 1);
    }
    if (!BN_copy(group->frb->f[0], group->one))
        goto err;
    if (!BN_copy(group->frb->f[1], group->one))
        goto err;
    if (!FP2_exp(group, group->frb, group->frb, d, ctx))
        goto err;

    /*
     * Initialize elliptic curve group G_1.
     */
    if (!EC_GROUP_set_curve_GFp(group->ec, group->field, curve_a,
                                curve_b, ctx)) {
        goto err;
    }
    if ((g1 = EC_POINT_new(group->ec)) == NULL)
        goto err;
    if (!EC_POINT_set_affine_coordinates_GFp
        (group->ec, g1, curve_x, BN_value_one(), ctx)) {
        goto err;
    }
    if (!EC_GROUP_set_generator(group->ec, g1, order, BN_value_one()))
        goto err;

    /*
     * Initialize elliptic curve group G_2.
     */
    if (!G2_ELEM_set_affine_coordinates
        (group, group->gen2, (const BIGNUM **)x, (const BIGNUM **)y, ctx)) {
        goto err;
    }

    ret = 1;
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    EC_POINT_free(g1);
    return ret;
}

int BP_GROUP_get_curve(const BP_GROUP *group, BIGNUM *p, BIGNUM *a,
                       BIGNUM *b, BN_CTX *ctx)
{
    return EC_GROUP_get_curve_GFp(group->ec, p, a, b, ctx);
}

int BP_GROUP_set_param(BP_GROUP *group, BIGNUM *param)
{
    return BN_copy(group->param, param) != NULL;
}

int BP_GROUP_get_param(const BP_GROUP *group, BIGNUM *param)
{
    return BN_copy(group->param, param) != NULL;
}

int BP_GROUP_set_generator_G1(const BP_GROUP *group, G1_ELEM *g, BIGNUM *n)
{
    /* This is a prime-order Barreto-Naehrig curve, no cofactor needed. */
    return EC_GROUP_set_generator(group->ec, g->p, n, BN_value_one());
}

int BP_GROUP_get_generator_G1(const BP_GROUP *group, G1_ELEM *g)
{
    return EC_POINT_copy(g->p, EC_GROUP_get0_generator(group->ec));
}

const EC_GROUP *BP_GROUP_get_group_G1(BP_GROUP *group)
{
    return group->ec;
}

int BP_GROUP_get_order(const BP_GROUP *group, BIGNUM *order, BN_CTX *ctx)
{
    return EC_GROUP_get_order(group->ec, order, ctx);
}

int BP_GROUP_precompute_mult_G1(BP_GROUP *group, BN_CTX *ctx)
{
    return EC_GROUP_precompute_mult(group->ec, ctx);
}

int BP_GROUP_have_precompute_mult_G1(const BP_GROUP *group)
{
    return EC_GROUP_have_precompute_mult(group->ec);
}

int BP_GROUP_set_generator_G2(const BP_GROUP *group, G2_ELEM *g)
{
    /* G1 and G2 must have the same order, so no need to receive parameter. */
    return G2_ELEM_copy(group->gen2, g);
}

int BP_GROUP_get_generator_G2(const BP_GROUP *group, G2_ELEM *g)
{
    return G2_ELEM_copy(g, group->gen2);
}

int BP_GROUP_precompute_mult_G2(BP_GROUP *group, BN_CTX *ctx)
{
    return g2_wNAF_precompute_mult(group, ctx);
}

int BP_GROUP_have_precompute_mult_G2(const BP_GROUP *group)
{
    return group->g2_pre_comp != NULL;
}
