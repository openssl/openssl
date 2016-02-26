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

/*
 * Largely based on ectest.c
 */
#include <stdio.h>
#include <stdlib.h>
#ifdef FLAT_INC
# include "e_os.h"
#else
# include "../e_os.h"
#endif
#include <string.h>
#include <time.h>

#ifdef OPENSSL_NO_BP
int main(int argc, char *argv[])
{
    puts("Bilinear pairings are disabled.");
    return 0;
}
#else

# include <openssl/bp.h>
# include <openssl/err.h>
# include <openssl/rand.h>
# include <openssl/bn.h>

# define ABORT do { \
        fflush(stdout); \
        fprintf(stderr, "%s:%d: ABORT\n", __FILE__, __LINE__); \
        ERR_print_errors_fp(stderr); \
        EXIT(1); \
} while (0)

static BP_GROUP *setup() {
    BP_GROUP *group;
    BIGNUM *p, *a, *b;

    p = BN_new();
    a = BN_new();
    b = BN_new();
    if (!p || !a || !b)
        ABORT;

    if (!BN_hex2bn(&p, "2523648240000001BA344D80000000086121000000000013A700000000000013"))
        ABORT;
    if (!BN_hex2bn(&a, "0"))
        ABORT;
    if (!BN_hex2bn(&b, "2"))
        ABORT;

    group = BP_GROUP_new();
    if (!group)
        ABORT;

    if (!BP_GROUP_set_curve(group, p, a, b, NULL))
        ABORT;

    {
        BP_GROUP *tmp;
        tmp = BP_GROUP_new();
        if (!tmp)
            ABORT;
        if (!BP_GROUP_copy(tmp, group))
            ABORT;
        BP_GROUP_free(group);
        group = tmp;
    }

    if (!BP_GROUP_get_curve(group, p, a, b, NULL))
        ABORT;

    fprintf(stdout,
            "Curve defined by Weierstrass equation\n     y^2 = x^3 + a*x + b  (mod 0x");
    BN_print_fp(stdout, p);
    fprintf(stdout, ")\n     a = 0x");
    BN_print_fp(stdout, a);
    fprintf(stdout, "\n     b = 0x");
    BN_print_fp(stdout, b);
    fprintf(stdout, "\n");

    BN_free(p);
    BN_free(a);
    BN_free(b);
    return group;
}

/* test multiplication with group order, long and negative scalars */
static void g1_order_tests(BP_GROUP *group)
{
    BIGNUM *n1, *n2, *order;
    G1_ELEM *P = G1_ELEM_new(group);
    G1_ELEM *Q = G1_ELEM_new(group);
    BN_CTX *ctx = BN_CTX_new();
    int i;

    n1 = BN_new();
    n2 = BN_new();
    order = BN_new();
    fprintf(stdout, "verify group order ...");
    fflush(stdout);
    if (!BP_GROUP_get_order(group, order, ctx))
        ABORT;
    if (!G1_ELEM_mul(group, Q, order, NULL, NULL, ctx))
        ABORT;
    if (!G1_ELEM_is_at_infinity(group, Q))
        ABORT;
    fprintf(stdout, ".");
    fflush(stdout);
    if (!G1_ELEM_mul(group, Q, order, NULL, NULL, ctx))
        ABORT;
    if (!G1_ELEM_is_at_infinity(group, Q))
        ABORT;
    fprintf(stdout, " ok\n");
    fprintf(stdout, "long/negative scalar tests ");
    for (i = 1; i <= 2; i++) {
        const BIGNUM *scalars[6];
        const G1_ELEM *points[6];

        fprintf(stdout, i == 1 ?
                "allowing precomputation ... " :
                "without precomputation ... ");
        if (!BN_set_word(n1, i))
            ABORT;
        /*
         * If i == 1, P will be the predefined generator for which
         * BP_GROUP_precompute_mult has set up precomputation.
         */
        if (!G1_ELEM_mul(group, P, n1, NULL, NULL, ctx))
            ABORT;

        if (!BN_one(n1))
            ABORT;
        /* n1 = 1 - order */
        if (!BN_sub(n1, n1, order))
            ABORT;
        if (!G1_ELEM_mul(group, Q, NULL, P, n1, ctx))
            ABORT;
        if (0 != G1_ELEM_cmp(group, Q, P, ctx))
            ABORT;

        /* n2 = 1 + order */
        if (!BN_add(n2, order, BN_value_one()))
            ABORT;
        if (!G1_ELEM_mul(group, Q, NULL, P, n2, ctx))
            ABORT;
        if (0 != G1_ELEM_cmp(group, Q, P, ctx))
            ABORT;

        /* n2 = (1 - order) * (1 + order) = 1 - order^2 */
        if (!BN_mul(n2, n1, n2, ctx))
            ABORT;
        if (!G1_ELEM_mul(group, Q, NULL, P, n2, ctx))
            ABORT;
        if (0 != G1_ELEM_cmp(group, Q, P, ctx))
            ABORT;

        /* n2 = order^2 - 1 */
        BN_set_negative(n2, 0);
        if (!G1_ELEM_mul(group, Q, NULL, P, n2, ctx))
            ABORT;
        /* Add P to verify the result. */
        if (!G1_ELEM_add(group, Q, Q, P, ctx))
            ABORT;
        if (!G1_ELEM_is_at_infinity(group, Q))
            ABORT;

        /* Exercise G1_ELEMs_mul, including corner cases. */
        if (G1_ELEM_is_at_infinity(group, P))
            ABORT;
        scalars[0] = n1;
        points[0] = Q;          /* => infinity */
        scalars[1] = n2;
        points[1] = P;          /* => -P */
        scalars[2] = n1;
        points[2] = Q;          /* => infinity */
        scalars[3] = n2;
        points[3] = Q;          /* => infinity */
        scalars[4] = n1;
        points[4] = P;          /* => P */
        scalars[5] = n2;
        points[5] = Q;          /* => infinity */
        if (!G1_ELEMs_mul(group, P, NULL, 6, points, scalars, ctx))
            ABORT;
        if (!G1_ELEM_is_at_infinity(group, P))
            ABORT;
    }
    fprintf(stdout, "ok\n");

    G1_ELEM_free(P);
    G1_ELEM_free(Q);
    BN_free(n1);
    BN_free(n2);
    BN_free(order);
    BN_CTX_free(ctx);
}

/* test multiplication with group order, long and negative scalars */
static void g2_order_tests(BP_GROUP *group)
{
    BIGNUM *n1, *n2, *order;
    G2_ELEM *P = G2_ELEM_new(group);
    G2_ELEM *Q = G2_ELEM_new(group);
    BN_CTX *ctx = BN_CTX_new();
    int i;

    n1 = BN_new();
    n2 = BN_new();
    order = BN_new();
    fprintf(stdout, "verify group order ...");
    fflush(stdout);
    if (!BP_GROUP_get_order(group, order, ctx))
        ABORT;
    if (!G2_ELEM_mul(group, Q, order, NULL, NULL, ctx))
        ABORT;
    if (!G2_ELEM_is_at_infinity(group, Q))
        ABORT;
    fprintf(stdout, ".");
    fflush(stdout);
    if (!G2_ELEM_mul(group, Q, order, NULL, NULL, ctx))
        ABORT;
    if (!G2_ELEM_is_at_infinity(group, Q))
        ABORT;
    fprintf(stdout, " ok\n");
    fprintf(stdout, "long/negative scalar tests ");
    for (i = 1; i <= 2; i++) {
        const BIGNUM *scalars[6];
        const G2_ELEM *points[6];

        fprintf(stdout, i == 1 ?
                "allowing precomputation ... " :
                "without precomputation ... ");
        if (!BN_set_word(n1, i))
            ABORT;
        /*
         * If i == 1, P will be the predefined generator for which
         * BP_GROUP_precompute_mult has set up precomputation.
         */
        if (!G2_ELEM_mul(group, P, n1, NULL, NULL, ctx))
            ABORT;

        if (!BN_one(n1))
            ABORT;
        /* n1 = 1 - order */
        if (!BN_sub(n1, n1, order))
            ABORT;
        if (!G2_ELEM_mul(group, Q, NULL, P, n1, ctx))
            ABORT;
        if (0 != G2_ELEM_cmp(group, Q, P, ctx))
            ABORT;

        /* n2 = 1 + order */
        if (!BN_add(n2, order, BN_value_one()))
            ABORT;
        if (!G2_ELEM_mul(group, Q, NULL, P, n2, ctx))
            ABORT;
        if (0 != G2_ELEM_cmp(group, Q, P, ctx))
            ABORT;

        /* n2 = (1 - order) * (1 + order) = 1 - order^2 */
        if (!BN_mul(n2, n1, n2, ctx))
            ABORT;
        if (!G2_ELEM_mul(group, Q, NULL, P, n2, ctx))
            ABORT;
        if (0 != G2_ELEM_cmp(group, Q, P, ctx))
            ABORT;

        /* n2 = order^2 - 1 */
        BN_set_negative(n2, 0);
        if (!G2_ELEM_mul(group, Q, NULL, P, n2, ctx))
            ABORT;
        /* Add P to verify the result. */
        if (!G2_ELEM_add(group, Q, Q, P, ctx))
            ABORT;
        if (!G2_ELEM_is_at_infinity(group, Q))
            ABORT;

        /* Exercise G1_ELEMs_mul, including corner cases. */
        if (G2_ELEM_is_at_infinity(group, P))
            ABORT;
        scalars[0] = n1;
        points[0] = Q;          /* => infinity */
        scalars[1] = n2;
        points[1] = P;          /* => -P */
        scalars[2] = n1;
        points[2] = Q;          /* => infinity */
        scalars[3] = n2;
        points[3] = Q;          /* => infinity */
        scalars[4] = n1;
        points[4] = P;          /* => P */
        scalars[5] = n2;
        points[5] = Q;          /* => infinity */
        if (!G2_ELEMs_mul(group, P, NULL, 6, points, scalars, ctx))
            ABORT;
        if (!G2_ELEM_is_at_infinity(group, P))
            ABORT;
    }
    fprintf(stdout, "ok\n");

    G2_ELEM_free(P);
    G2_ELEM_free(Q);
    BN_free(n1);
    BN_free(n2);
    BN_free(order);
    BN_CTX_free(ctx);
}

static void g1_tests(BP_GROUP *group)
{
    BN_CTX *ctx = NULL;
    G1_ELEM *P, *Q, *R;
    BIGNUM *x, *y, *z;
    unsigned char buf[128];
    size_t i, len;

    ctx = BN_CTX_new();
    if (!ctx)
        ABORT;

    P = G1_ELEM_new(group);
    Q = G1_ELEM_new(group);
    R = G1_ELEM_new(group);
    if (!P || !Q || !R)
        ABORT;

    fprintf(stdout, "\nTests for group G1:\n");
    fflush(stdout);

    if (!G1_ELEM_set_to_infinity(group, P))
        ABORT;
    if (!G1_ELEM_is_at_infinity(group, P))
        ABORT;

    buf[0] = 0;
    if (!G1_ELEM_oct2point(group, Q, buf, 1, ctx))
        ABORT;

    if (!G1_ELEM_add(group, P, P, Q, ctx))
        ABORT;
    if (!G1_ELEM_is_at_infinity(group, P))
        ABORT;

    x = BN_new();
    y = BN_new();
    z = BN_new();
    if (!x || !y || !z)
        ABORT;

    if (!BN_hex2bn(&x, "-1"))
        ABORT;
    if (!G1_ELEM_set_compressed_coordinates(group, Q, x, 1, ctx))
        ABORT;
    if (G1_ELEM_is_on_curve(group, Q, ctx) <= 0) {
        if (!G1_ELEM_get_affine_coordinates(group, Q, x, y, ctx))
            ABORT;
        fprintf(stderr, "Point is not on curve: x = 0x");
        BN_print_fp(stderr, x);
        fprintf(stderr, ", y = 0x");
        BN_print_fp(stderr, y);
        fprintf(stderr, "\n");
        ABORT;
    }

    if (!G1_ELEM_copy(R, Q))
        ABORT;
    if (!G1_ELEM_invert(group, R, ctx))
        ABORT;
    if (!G1_ELEM_add(group, P, Q, R, ctx))
        ABORT;
    if (!G1_ELEM_is_at_infinity(group, P))
        ABORT;

    len =
        G1_ELEM_point2oct(group, Q, POINT_CONVERSION_COMPRESSED, buf,
                           sizeof buf, ctx);
    if (len == 0)
        ABORT;
    if (!G1_ELEM_oct2point(group, P, buf, len, ctx))
        ABORT;
    if (0 != G1_ELEM_cmp(group, P, Q, ctx))
        ABORT;
    fprintf(stdout, "Generator as octet string, compressed form:\n     ");
    for (i = 0; i < len; i++)
        fprintf(stdout, "%02X", buf[i]);

    len =
        G1_ELEM_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED, buf,
                           sizeof buf, ctx);
    if (len == 0)
        ABORT;
    if (!G1_ELEM_oct2point(group, P, buf, len, ctx))
        ABORT;
    if (0 != G1_ELEM_cmp(group, P, Q, ctx))
        ABORT;
    fprintf(stdout, "\nGenerator as octet string, uncompressed form:\n     ");
    for (i = 0; i < len; i++)
        fprintf(stdout, "%02X", buf[i]);

    len =
        G1_ELEM_point2oct(group, Q, POINT_CONVERSION_HYBRID, buf, sizeof buf,
                           ctx);
    if (len == 0)
        ABORT;
    if (!G1_ELEM_oct2point(group, P, buf, len, ctx))
        ABORT;
    if (0 != G1_ELEM_cmp(group, P, Q, ctx))
        ABORT;
    fprintf(stdout, "\nGenerator as octet string, hybrid form:\n     ");
    for (i = 0; i < len; i++)
        fprintf(stdout, "%02X", buf[i]);

    if (!G1_ELEM_get_Jprojective_coordinates(group, R, x, y, z, ctx))
        ABORT;
    fprintf(stdout,
            "\nA representation of the inverse of that generator in\nJacobian projective coordinates:\n     X = 0x");
    BN_print_fp(stdout, x);
    fprintf(stdout, ", Y = 0x");
    BN_print_fp(stdout, y);
    fprintf(stdout, ", Z = 0x");
    BN_print_fp(stdout, z);
    fprintf(stdout, "\n");

    if (!G1_ELEM_invert(group, P, ctx))
        ABORT;
    if (0 != G1_ELEM_cmp(group, P, R, ctx))
        ABORT;

    g1_order_tests(group);

    /* more tests using the last curve */

    if (!G1_ELEM_copy(Q, P))
        ABORT;
    if (G1_ELEM_is_at_infinity(group, Q))
        ABORT;
    if (!G1_ELEM_dbl(group, P, P, ctx))
        ABORT;
    if (G1_ELEM_is_on_curve(group, P, ctx) <= 0)
        ABORT;
    if (!G1_ELEM_invert(group, Q, ctx))
        ABORT;                  /* P = -2Q */

    if (!G1_ELEM_add(group, R, P, Q, ctx))
        ABORT;
    if (!G1_ELEM_add(group, R, R, Q, ctx))
        ABORT;
    if (!G1_ELEM_is_at_infinity(group, R))
        ABORT;                  /* R = P + 2Q */

    {
        const G1_ELEM *points[4];
        const BIGNUM *scalars[4];
        BIGNUM *scalar3;

        if (G1_ELEM_is_at_infinity(group, Q))
            ABORT;
        points[0] = Q;
        points[1] = Q;
        points[2] = Q;
        points[3] = Q;

        if (!BP_GROUP_get_order(group, z, ctx))
            ABORT;
        if (!BN_add(y, z, BN_value_one()))
            ABORT;
        if (BN_is_odd(y))
            ABORT;
        if (!BN_rshift1(y, y))
            ABORT;
        scalars[0] = y;         /* (group order + 1)/2, so y*Q + y*Q = Q */
        scalars[1] = y;

        fprintf(stdout, "combined multiplication ...");
        fflush(stdout);

        /* z is still the group order */
        if (!G1_ELEMs_mul(group, P, NULL, 2, points, scalars, ctx))
            ABORT;
        if (!G1_ELEMs_mul(group, R, z, 2, points, scalars, ctx))
            ABORT;
        if (0 != G1_ELEM_cmp(group, P, R, ctx))
            ABORT;
        if (0 != G1_ELEM_cmp(group, R, Q, ctx))
            ABORT;

        fprintf(stdout, ".");
        fflush(stdout);

        if (!BN_pseudo_rand(y, BN_num_bits(y), 0, 0))
            ABORT;
        if (!BN_add(z, z, y))
            ABORT;
        BN_set_negative(z, 1);
        scalars[0] = y;
        scalars[1] = z;         /* z = -(order + y) */

        if (!G1_ELEMs_mul(group, P, NULL, 2, points, scalars, ctx))
            ABORT;
        if (!G1_ELEM_is_at_infinity(group, P))
            ABORT;

        fprintf(stdout, ".");
        fflush(stdout);

        if (!BN_pseudo_rand(x, BN_num_bits(y) - 1, 0, 0))
            ABORT;
        if (!BN_add(z, x, y))
            ABORT;
        BN_set_negative(z, 1);
        scalars[0] = x;
        scalars[1] = y;
        scalars[2] = z;         /* z = -(x+y) */

        scalar3 = BN_new();
        if (!scalar3)
            ABORT;
        BN_zero(scalar3);
        scalars[3] = scalar3;

        if (!G1_ELEMs_mul(group, P, NULL, 4, points, scalars, ctx))
            ABORT;
        if (!G1_ELEM_is_at_infinity(group, P))
            ABORT;

        fprintf(stdout, " ok\n\n");

        BN_free(scalar3);
    }

    BN_CTX_free(ctx);
    G1_ELEM_free(P);
    G1_ELEM_free(Q);
    G1_ELEM_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
}

static void g2_tests(BP_GROUP *group)
{
    BN_CTX *ctx = NULL;
    G2_ELEM *P, *Q, *R;
    BIGNUM *x[2], *y[2], *z[2];
    unsigned char buf[128];
    size_t i, len;

    ctx = BN_CTX_new();
    if (!ctx)
        ABORT;

    P = G2_ELEM_new(group);
    Q = G2_ELEM_new(group);
    R = G2_ELEM_new(group);
    if (!P || !Q || !R)
        ABORT;

    fprintf(stdout, "Tests for group G2:\n");
    fflush(stdout);

    if (!G2_ELEM_set_to_infinity(group, P))
        ABORT;
    if (!G2_ELEM_is_at_infinity(group, P))
        ABORT;

    buf[0] = 0;
    if (!G2_ELEM_oct2point(group, Q, buf, 1, ctx))
        ABORT;

    if (!G2_ELEM_add(group, P, P, Q, ctx))
        ABORT;
    if (!G2_ELEM_is_at_infinity(group, P))
        ABORT;

    x[0] = BN_new();
    x[1] = BN_new();
    y[0] = BN_new();
    y[1] = BN_new();
    z[0] = BN_new();
    z[1] = BN_new();
    if (!x[0] || !x[1] || !y[0] || !y[1] || !z[0] || !z[1])
        ABORT;

    if (!BP_GROUP_get_generator_G2(group, Q))
        ABORT;
    if (!G2_ELEM_get_affine_coordinates(group, Q, x, y, ctx))
        ABORT;
    if (!G2_ELEM_set_affine_coordinates(group, Q, (const BIGNUM **)x, (const BIGNUM **)y, ctx))
        ABORT;
    if (G2_ELEM_is_on_curve(group, Q, ctx) <= 0) {
        ABORT;
    }

    if (!G2_ELEM_copy(R, Q))
        ABORT;
    if (!G2_ELEM_invert(group, R, ctx))
        ABORT;
    if (!G2_ELEM_add(group, P, Q, R, ctx))
        ABORT;
    if (!G2_ELEM_is_at_infinity(group, P))
        ABORT;

    len =
        G2_ELEM_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED, buf,
                           sizeof buf, ctx);
    if (len == 0)
        ABORT;
    if (!G2_ELEM_oct2point(group, P, buf, len, ctx))
        ABORT;
    if (0 != G2_ELEM_cmp(group, P, Q, ctx))
        ABORT;
    fprintf(stdout, "Generator as octet string, uncompressed form:\n     ");
    for (i = 0; i < len; i++)
        fprintf(stdout, "%02X", buf[i]);
    printf("\n");

    if (!G2_ELEM_get_Jprojective_coordinates(group, R, x, y, z, ctx))
        ABORT;

    if (!G2_ELEM_invert(group, P, ctx))
        ABORT;
    if (0 != G2_ELEM_cmp(group, P, R, ctx))
        ABORT;

    g2_order_tests(group);

    if (!G2_ELEM_copy(Q, P))
        ABORT;
    if (G2_ELEM_is_at_infinity(group, Q))
        ABORT;
    if (!G2_ELEM_dbl(group, P, P, ctx))
        ABORT;
    if (G2_ELEM_is_on_curve(group, P, ctx) <= 0)
        ABORT;
    if (!G2_ELEM_invert(group, Q, ctx))
        ABORT;                  /* P = -2Q */

    if (!G2_ELEM_add(group, R, P, Q, ctx))
        ABORT;
    if (!G2_ELEM_add(group, R, R, Q, ctx))
        ABORT;
    if (!G2_ELEM_is_at_infinity(group, R))
        ABORT;                  /* R = P + 2Q */

    {
        const G2_ELEM *points[4];
        const BIGNUM *scalars[4];
        BIGNUM *scalar3;

        if (G2_ELEM_is_at_infinity(group, Q))
            ABORT;
        points[0] = Q;
        points[1] = Q;
        points[2] = Q;
        points[3] = Q;

        if (!BP_GROUP_get_order(group, z[0], ctx))
            ABORT;
        if (!BN_add(y[0], z[0], BN_value_one()))
            ABORT;
        if (BN_is_odd(y[0]))
            ABORT;
        if (!BN_rshift1(y[0], y[0]))
            ABORT;
        scalars[0] = y[0];         /* (group order + 1)/2, so y*Q + y*Q = Q */
        scalars[1] = y[0];

        fprintf(stdout, "combined multiplication ...");
        fflush(stdout);

        /* z is still the group order */
        if (!G2_ELEMs_mul(group, P, NULL, 2, points, scalars, ctx))
            ABORT;
        if (!G2_ELEMs_mul(group, R, z[0], 2, points, scalars, ctx))
            ABORT;
        if (0 != G2_ELEM_cmp(group, P, R, ctx))
            ABORT;
        if (0 != G2_ELEM_cmp(group, R, Q, ctx))
            ABORT;

        fprintf(stdout, ".");
        fflush(stdout);

        if (!BN_pseudo_rand(y[0], BN_num_bits(y[0]), 0, 0))
            ABORT;
        if (!BN_add(z[0], z[0], y[0]))
            ABORT;
        BN_set_negative(z[0], 1);
        scalars[0] = y[0];
        scalars[1] = z[0];         /* z = -(order + y) */

        if (!G2_ELEMs_mul(group, P, NULL, 2, points, scalars, ctx))
            ABORT;
        if (!G2_ELEM_is_at_infinity(group, P))
            ABORT;

        fprintf(stdout, ".");
        fflush(stdout);

        if (!BN_pseudo_rand(x[0], BN_num_bits(y[0]) - 1, 0, 0))
            ABORT;
        if (!BN_add(z[0], x[0], y[0]))
            ABORT;
        BN_set_negative(z[0], 1);
        scalars[0] = x[0];
        scalars[1] = y[0];
        scalars[2] = z[0];         /* z = -(x+y) */

        scalar3 = BN_new();
        if (!scalar3)
            ABORT;
        BN_zero(scalar3);
        scalars[3] = scalar3;

        if (!G2_ELEMs_mul(group, P, NULL, 4, points, scalars, ctx))
            ABORT;
        if (!G2_ELEM_is_at_infinity(group, P))
            ABORT;

        fprintf(stdout, " ok\n\n");

        BN_free(scalar3);
    }

    BN_CTX_free(ctx);
    G2_ELEM_free(P);
    G2_ELEM_free(Q);
    G2_ELEM_free(R);
    BN_free(x[0]);
    BN_free(x[1]);
    BN_free(y[0]);
    BN_free(y[1]);
    BN_free(z[0]);
    BN_free(z[1]);
}

static int gt_tests(const BP_GROUP *group)
{
    BN_CTX *ctx;
    G1_ELEM *p, *g1;
    G2_ELEM *q, *g2;
    const G1_ELEM *ps[2];
    const G2_ELEM *qs[2];
    GT_ELEM *d, *e, *f;
    BIGNUM *k, *order;

    uint8_t _g1[65] = {0x04,
        0x20, 0x74, 0xA8, 0x1D, 0x44, 0x02, 0xA0, 0xB6,
        0x3B, 0x94, 0x73, 0x35, 0xC1, 0x4B, 0x2F, 0xC3,
        0xC2, 0x8F, 0xEA, 0x29, 0x73, 0x86, 0x0F, 0x68,
        0x61, 0x14, 0xBE, 0xC4, 0x67, 0x0E, 0x4E, 0xB7,
        0x06, 0xA4, 0x11, 0x08, 0x08, 0x7B, 0x20, 0x03,
        0x87, 0x71, 0xFC, 0x89, 0xFB, 0x94, 0xA8, 0x2B,
        0x20, 0x06, 0x03, 0x4A, 0x6E, 0x8D, 0x87, 0x1B,
        0x3B, 0xC2, 0x84, 0x84, 0x66, 0x31, 0xCB, 0xEB,
    };
    uint8_t _g2[128] = {
        0x04, 0x9E, 0xED, 0xB1, 0x08, 0xB7, 0x1A, 0x87,
        0xBF, 0xCF, 0xC9, 0xB6, 0x5E, 0xB5, 0xCF, 0x1C,
        0x2F, 0x89, 0x55, 0x4E, 0x02, 0xDF, 0x4F, 0x83,
        0x54, 0xE4, 0xA0, 0x0F, 0x52, 0x18, 0x3C, 0x77,
        0x1F, 0xB9, 0x3A, 0xB6, 0x76, 0x14, 0x0E, 0x87,
        0xD9, 0x72, 0x26, 0x18, 0x5B, 0xA0, 0x5B, 0xF5,
        0xEC, 0x08, 0x8A, 0x9C, 0xC7, 0x6D, 0x96, 0x66,
        0x97, 0xCF, 0xB8, 0xFA, 0x9A, 0xA8, 0x84, 0x5D,
        0x0C, 0xD0, 0x4A, 0x1E, 0xD1, 0x4A, 0xD3, 0xCD,
        0xF6, 0xA1, 0xFE, 0x44, 0x53, 0xDA, 0x2B, 0xB9,
        0xE6, 0x86, 0xA6, 0x37, 0xFB, 0x3F, 0xF8, 0xE2,
        0x57, 0x36, 0x44, 0xCC, 0x1E, 0xDF, 0x20, 0x8A,
        0x11, 0xFF, 0x77, 0x95, 0xCF, 0x59, 0xD1, 0xA1,
        0xA7, 0xD6, 0xEE, 0x3C, 0x3C, 0x2D, 0xFC, 0x76,
        0x5D, 0xEF, 0x1C, 0xAA, 0x9F, 0x14, 0xEA, 0x26,
        0x4E, 0x71, 0xBD, 0x76, 0x30, 0xA4, 0x3C, 0x14,
    };
    uint8_t _gt[12 * 32] = {
        0x03, 0xE1, 0xF2, 0x69, 0x3A, 0xC6, 0xD5, 0x49,
        0x89, 0x8C, 0x78, 0x89, 0x7E, 0xB1, 0x58, 0x49,
        0x0A, 0x48, 0x32, 0xE2, 0x96, 0xF8, 0x88, 0xD3,
        0x01, 0x40, 0x50, 0x0D, 0xB7, 0xBD, 0x3D, 0x12,
        0x1E, 0xBC, 0x54, 0xA7, 0x6E, 0x84, 0x4E, 0xB5,
        0xD3, 0x52, 0x94, 0x52, 0x26, 0xFB, 0x10, 0x3D,
        0xE9, 0xEC, 0x1A, 0x4F, 0xC6, 0x89, 0xB8, 0x7F,
        0xAA, 0x66, 0xEF, 0x8A, 0xBA, 0x79, 0xD3, 0xED,
        0x0A, 0x5A, 0x54, 0x05, 0x54, 0x2F, 0x67, 0x38,
        0x4D, 0x68, 0x3A, 0x48, 0xC2, 0x81, 0xF3, 0x67,
        0x6B, 0x67, 0x55, 0x4E, 0xD5, 0xDA, 0x17, 0x00,
        0x78, 0x41, 0x69, 0xA0, 0xB4, 0x7A, 0x57, 0xE4,
        0x04, 0x8B, 0x66, 0xDA, 0xFC, 0xAE, 0xE8, 0x6D,
        0xB4, 0xD4, 0x6A, 0xB7, 0x1A, 0x9F, 0xE8, 0x48,
        0x44, 0x3E, 0xF8, 0x1F, 0x48, 0x8D, 0x83, 0x66,
        0xA7, 0x27, 0xB3, 0x96, 0x98, 0xCF, 0x72, 0x01,
        0x14, 0x27, 0x15, 0xD6, 0x48, 0x2B, 0xC6, 0xFA,
        0x77, 0x37, 0x7C, 0x9C, 0xBC, 0x2A, 0x51, 0xC0,
        0x47, 0xC1, 0x6D, 0xE8, 0x84, 0x83, 0xD5, 0xA8,
        0x89, 0xC7, 0xEF, 0x4D, 0xF5, 0xF0, 0x3B, 0xDB,
        0x11, 0xEE, 0x0C, 0x12, 0x16, 0x41, 0x33, 0x04,
        0x1C, 0x3D, 0xCF, 0x31, 0x2C, 0xE1, 0x11, 0xC8,
        0x45, 0xB6, 0x00, 0x92, 0x81, 0x8F, 0x7B, 0x72,
        0x80, 0x5D, 0x4A, 0xFF, 0x61, 0x42, 0x79, 0x34,
        0x22, 0x37, 0x1A, 0xF9, 0x75, 0xDA, 0xE5, 0x62,
        0xF6, 0x86, 0x98, 0x8C, 0xDB, 0xBD, 0x02, 0x70,
        0x2C, 0x95, 0x9B, 0xBF, 0x84, 0x3A, 0x1F, 0xB3,
        0xC7, 0x53, 0x2D, 0x07, 0xBE, 0x3D, 0x7A, 0x3A,
        0x04, 0x05, 0x2C, 0xA9, 0x60, 0x90, 0x06, 0x84,
        0xA1, 0xB2, 0x6C, 0x43, 0x4B, 0x27, 0x76, 0xAA,
        0x70, 0x73, 0x68, 0x41, 0x47, 0x4C, 0x16, 0x20,
        0x8C, 0xCD, 0x1A, 0x7C, 0x27, 0x92, 0x7E, 0x19,
        0x05, 0xD2, 0x59, 0xDA, 0x3F, 0x3A, 0xAA, 0xA5,
        0x4A, 0x6A, 0xE5, 0xFE, 0x82, 0x72, 0xA5, 0xB7,
        0x9D, 0x7F, 0x4E, 0x5B, 0xDF, 0x3B, 0x5E, 0x3C,
        0x81, 0x5A, 0xD7, 0x81, 0x11, 0x3F, 0x75, 0x48,
        0x08, 0x43, 0xC3, 0x7B, 0xC5, 0xBD, 0xBF, 0x25,
        0x3E, 0x3B, 0xCE, 0x56, 0x8F, 0x59, 0x05, 0xA6,
        0x38, 0x67, 0xD8, 0x83, 0x68, 0x55, 0xB7, 0x4C,
        0xBA, 0x0C, 0x80, 0x0D, 0x5D, 0xC4, 0x1B, 0x71,
        0x13, 0xCA, 0x93, 0xE1, 0x37, 0x7E, 0xF0, 0xF6,
        0xDD, 0x38, 0xFC, 0x2F, 0x96, 0xDB, 0xD3, 0xE8,
        0xB0, 0x92, 0x2F, 0x60, 0xD1, 0xF2, 0x74, 0xEA,
        0xC6, 0x3D, 0xC1, 0xAF, 0x2E, 0xE9, 0x75, 0x4C,
        0x0D, 0x46, 0x7F, 0x3D, 0xA4, 0xFB, 0x32, 0x9A,
        0x5C, 0xB4, 0x06, 0xD0, 0xA7, 0xB7, 0x43, 0xA3,
        0xA2, 0xFF, 0xCD, 0x09, 0xBF, 0x95, 0xEE, 0x8A,
        0x85, 0x6B, 0x94, 0xAF, 0x19, 0x1D, 0x96, 0xAF,
    };

    ctx = BN_CTX_new();
    if (!ctx)
        ABORT;

    g1 = G1_ELEM_new(group);
    g2 = G2_ELEM_new(group);
    d = GT_ELEM_new(group);
    e = GT_ELEM_new(group);
    f = GT_ELEM_new(group);
    if (g1 == NULL || g2 == NULL || d == NULL || e == NULL || f == NULL)
        ABORT;

    k = BN_new();
    order = BN_new();
    if (!BP_GROUP_get_order(group, order, ctx))
        ABORT;

    fprintf(stdout, "Tests for group GT:\n");
    fflush(stdout);

    fprintf(stdout, "verify pairing non-degeneracy ...");
    fflush(stdout);

    if (!G1_ELEM_set_to_infinity(group, g1))
        ABORT;
    if (!G2_ELEM_set_to_infinity(group, g2))
        ABORT;

    if (!GT_ELEM_pairing(group, e, g1, g2, ctx))
        ABORT;
    if (GT_ELEM_is_unity(group, e) == 0)
        ABORT;
    fprintf(stdout, ".");
    fflush(stdout);

    if (!BP_GROUP_get_generator_G1(group, g1))
        ABORT;
    if (!GT_ELEM_pairing(group, e, g1, g2, ctx))
        ABORT;
    if (GT_ELEM_is_unity(group, e) == 0)
        ABORT;
    fprintf(stdout, ".");
    fflush(stdout);

    if (!G1_ELEM_set_to_infinity(group, g1))
        ABORT;
    if (!BP_GROUP_get_generator_G2(group, g2))
        ABORT;
    if (!GT_ELEM_pairing(group, e, g1, g2, ctx))
        ABORT;
    if (GT_ELEM_is_unity(group, e) == 0)
        ABORT;
    fprintf(stdout, ".");
    fflush(stdout);

    if (!BP_GROUP_get_generator_G1(group, g1))
        ABORT;
    if (!BP_GROUP_get_generator_G2(group, g2))
        ABORT;
    if (!GT_ELEM_pairing(group, e, g1, g2, ctx))
        ABORT;
    if (GT_ELEM_is_unity(group, e))
        ABORT;

    fprintf(stdout, " group order ...");
    fflush(stdout);


    if (!GT_ELEM_exp(group, d, e, order, ctx))
        ABORT;
    if (GT_ELEM_is_unity(group, d) == 0)
        ABORT;

    fprintf(stdout, " test vectors ...");
    fflush(stdout);

    p = G1_ELEM_dup(g1, group);
    q = G2_ELEM_dup(g2, group);

    if (!G1_ELEM_oct2point(group, g1, _g1, sizeof(_g1), NULL))
        ABORT;
    if (!G2_ELEM_oct2point(group, g2, _g2, sizeof(_g2), NULL))
        ABORT;
    if (!GT_ELEM_pairing(group, e, g1, g2, NULL))
        ABORT;
    if (!GT_ELEM_oct2elem(group, f, _gt, sizeof(_gt), NULL))
        ABORT;
    if (GT_ELEM_cmp(e, f) != 0)
        ABORT;

    fprintf(stdout, " bilinearity ...");
    fflush(stdout);

    if (!BP_GROUP_get_generator_G1(group, g1))
        ABORT;
    if (!BP_GROUP_get_generator_G2(group, g2))
        ABORT;
    if (!GT_ELEM_pairing(group, e, g1, g2, ctx))
        ABORT;
    if (!G1_ELEM_dbl(group, p, g1, ctx))
        ABORT;
    if (!GT_ELEM_sqr(group, d, e, ctx))
        ABORT;
    if (!GT_ELEM_pairing(group, f, p, g2, ctx))
        ABORT;
    if (GT_ELEM_cmp(d, f) != 0)
        ABORT;
    fprintf(stdout, ".");
    fflush(stdout);

    ps[0] = ps[1] = g1;
    qs[0] = qs[1] = g2;
    if (!GT_ELEMs_pairing(group, f, 2, ps, qs, ctx))
        ABORT;
    if (GT_ELEM_cmp(d, f) != 0)
        ABORT;
    fprintf(stdout, ".");
    fflush(stdout);

    if (!G1_ELEM_add(group, p, p, g1, ctx))
        ABORT;
    if (!GT_ELEM_mul(group, d, d, e, ctx))
        ABORT;
    if (!GT_ELEM_pairing(group, f, p, g2, ctx))
        ABORT;
    if (GT_ELEM_cmp(d, f) != 0)
        ABORT;
    fprintf(stdout, ".");
    fflush(stdout);

    if (!BN_pseudo_rand(k, BN_num_bits(order), 0, 0))
        ABORT;
    if (!G1_ELEM_mul(group, p, NULL, g1, k, ctx))
        ABORT;
    if (!GT_ELEM_pairing(group, d, p, g2, ctx))
        ABORT;
    if (!GT_ELEM_exp(group, f, e, k, ctx))
        ABORT;
    if (GT_ELEM_cmp(d, f) != 0)
        ABORT;
    fprintf(stdout, ".");
    fflush(stdout);

    if (!G2_ELEM_dbl(group, q, g2, ctx))
        ABORT;
    if (!GT_ELEM_sqr(group, d, e, ctx))
        ABORT;
    if (!GT_ELEM_pairing(group, f, g1, q, ctx))
        ABORT;
    if (GT_ELEM_cmp(d, f) != 0)
        ABORT;
    fprintf(stdout, ".");
    fflush(stdout);

    if (!G2_ELEM_add(group, q, q, g2, ctx))
        ABORT;
    if (!GT_ELEM_mul(group, d, d, e, ctx))
        ABORT;
    if (!GT_ELEM_pairing(group, f, g1, q, ctx))
        ABORT;
    if (GT_ELEM_cmp(d, f) != 0)
        ABORT;
    fprintf(stdout, ".");
    fflush(stdout);

    if (!BN_pseudo_rand(k, BN_num_bits(order), 0, 0))
        ABORT;
    if (!G2_ELEM_mul(group, q, NULL, g2, k, ctx))
        ABORT;
    if (!GT_ELEM_pairing(group, d, g1, q, ctx))
        ABORT;
    if (!GT_ELEM_exp(group, f, e, k, ctx))
        ABORT;
    if (GT_ELEM_cmp(d, f) != 0)
        ABORT;

    fprintf(stdout, " ok\n");
    fflush(stdout);

    BN_free(k);
    BN_free(order);
    GT_ELEM_free(d);
    GT_ELEM_free(e);
    GT_ELEM_free(f);
    G1_ELEM_free(p);
    G2_ELEM_free(q);
    G1_ELEM_free(g1);
    G2_ELEM_free(g2);
    BN_CTX_free(ctx);
    return 0;
}

static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";

int main(int argc, char *argv[])
{
    BP_GROUP *group;
    char *p;

    p = getenv("OPENSSL_DEBUG_MEMORY");
    if (p != NULL && strcmp(p, "on") == 0)
        CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    RAND_seed(rnd_seed, sizeof rnd_seed); /* or BN_generate_prime may fail */

    group = setup();
    g1_tests(group);
    g2_tests(group);
    gt_tests(group);
    puts("");

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks_fp(stderr) <= 0)
        return 1;
#endif

    BP_GROUP_free(group);
    return 0;
}
#endif
