/*
 * Copyright 2001-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

#include "e_os.h"
#include "testutil.h"

#ifndef OPENSSL_NO_EC
# include <openssl/ec.h>
# ifndef OPENSSL_NO_ENGINE
#  include <openssl/engine.h>
# endif
# include <openssl/err.h>
# include <openssl/obj_mac.h>
# include <openssl/objects.h>
# include <openssl/rand.h>
# include <openssl/bn.h>
# include <openssl/opensslconf.h>

# if defined(_MSC_VER) && defined(_MIPS_) && (_MSC_VER/100==12)
/* suppress "too big too optimize" warning */
#  pragma warning(disable:4959)
# endif

static size_t crv_len = 0;
static EC_builtin_curve *curves = NULL;

/* test multiplication with group order, long and negative scalars */
static int group_order_tests(EC_GROUP *group)
{
    BIGNUM *n1 = NULL, *n2 = NULL, *order = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL, *S = NULL;
    BN_CTX *ctx = NULL;
    int i = 0, r = 0;

    if (!TEST_ptr(n1 = BN_new())
        || !TEST_ptr(n2 = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_ptr(S = EC_POINT_new(group)))
        goto err;

    if (!TEST_true(EC_GROUP_get_order(group, order, ctx))
        || !TEST_true(EC_POINT_mul(group, Q, order, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, Q))
        || !TEST_true(EC_GROUP_precompute_mult(group, ctx))
        || !TEST_true(EC_POINT_mul(group, Q, order, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, Q)))
        goto err;

    for (i = 1; i <= 2; i++) {
        const BIGNUM *scalars[6];
        const EC_POINT *points[6];

        if (!TEST_true(BN_set_word(n1, i))
            /*
             * If i == 1, P will be the predefined generator for which
             * EC_GROUP_precompute_mult has set up precomputation.
             */
            || !TEST_true(EC_POINT_mul(group, P, n1, NULL, NULL, ctx))
            || !TEST_true(BN_one(n1))
            /* n1 = 1 - order */
            || !TEST_true(BN_sub(n1, n1, order))
            || !TEST_true(EC_POINT_mul(group, Q, NULL, P, n1, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx))

            /* n2 = 1 + order */
            || !TEST_true(BN_add(n2, order, BN_value_one()))
            || !TEST_true(EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx))

            /* n2 = (1 - order) * (1 + order) = 1 - order^2 */
            || !TEST_true(BN_mul(n2, n1, n2, ctx))
            || !TEST_true(EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx)))
            goto err;

        /* n2 = order^2 - 1 */
        BN_set_negative(n2, 0);
        if (!TEST_true(EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            /* Add P to verify the result. */
            || !TEST_true(EC_POINT_add(group, Q, Q, P, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, Q))

            /* Exercise EC_POINTs_mul, including corner cases. */
            || !TEST_false(EC_POINT_is_at_infinity(group, P)))
            goto err;

        scalars[0] = scalars[1] = BN_value_one();
        points[0]  = points[1]  = P;

        if (!TEST_true(EC_POINTs_mul(group, R, NULL, 2, points, scalars, ctx))
            || !TEST_true(EC_POINT_dbl(group, S, points[0], ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, R, S, ctx)))
            goto err;

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
        if (!TEST_true(EC_POINTs_mul(group, P, NULL, 6, points, scalars, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, P)))
            goto err;
    }

    r = 1;
err:
    if (r == 0 && i != 0)
        TEST_info(i == 1 ? "allowing precomputation" :
                           "without precomputation");
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_POINT_free(S);
    BN_free(n1);
    BN_free(n2);
    BN_free(order);
    BN_CTX_free(ctx);
    return r;
}

static int prime_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *scalar3 = NULL;
    EC_GROUP *group = NULL, *tmp = NULL;
    EC_GROUP *P_160 = NULL, *P_192 = NULL, *P_224 = NULL,
             *P_256 = NULL, *P_384 = NULL, *P_521 = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *yplusone = NULL;
    const EC_POINT *points[4];
    const BIGNUM *scalars[4];
    unsigned char buf[100];
    size_t i, len, r = 0;
    int k;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "17"))
        || !TEST_true(BN_hex2bn(&a, "1"))
        || !TEST_true(BN_hex2bn(&b, "1"))
        /*
         * applications should use EC_GROUP_new_curve_GFp so
         * that the library gets to choose the EC_METHOD
         */
        || !TEST_ptr(group = EC_GROUP_new(EC_GFp_mont_method()))
        || !TEST_true(EC_GROUP_set_curve_GFp(group, p, a, b, ctx))
        || !TEST_ptr(tmp = EC_GROUP_new(EC_GROUP_method_of(group)))
        || !TEST_true(EC_GROUP_copy(tmp, group)))
        goto err;
    EC_GROUP_free(group);
    group = tmp;
    tmp = NULL;

    if (!TEST_true(EC_GROUP_get_curve_GFp(group, p, a, b, ctx)))
        goto err;

    BIO_printf(bio_out,
            "Curve defined by Weierstrass equation\n"
            "     y^2 = x^3 + a*x + b  (mod 0x");
    BN_print(bio_out, p);
    BIO_printf(bio_out, ")\n     a = 0x");
    BN_print(bio_out, a);
    BIO_printf(bio_out, "\n     b = 0x");
    BN_print(bio_out, b);
    BIO_printf(bio_out, "\n");

    buf[0] = 0;
    if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&x, "D"))
        || !TEST_true(EC_POINT_set_compressed_coordinates_GFp(group, Q, x, 1,
                                                              ctx)))
        goto err;

    if (!TEST_int_gt(EC_POINT_is_on_curve(group, Q, ctx), 0)) {
        if (!TEST_true(EC_POINT_get_affine_coordinates_GFp(group, Q, x, y,
                                                           ctx)))
            goto err;
        BIO_printf(bio_err, "Point is not on curve: x = 0x");
        BN_print_fp(stderr, x);
        BIO_printf(bio_err, ", y = 0x");
        BN_print_fp(stderr, y);
        BIO_printf(bio_err, "\n");
        goto err;
    }

    BIO_printf(bio_out, "A cyclic subgroup:\n");
    k = 100;
    do {
        if (!TEST_int_ne(k--, 0))
            goto err;

        if (EC_POINT_is_at_infinity(group, P)) {
            BIO_printf(bio_out, "     point at infinity\n");
        } else {
            if (!TEST_true(EC_POINT_get_affine_coordinates_GFp(group, P, x, y,
                                                               ctx)))
                goto err;

            BIO_printf(bio_out, "     x = 0x");
            BN_print(bio_out, x);
            BIO_printf(bio_out, ", y = 0x");
            BN_print(bio_out, y);
            BIO_printf(bio_out, "\n");
        }

        if (!TEST_true(EC_POINT_copy(R, P))
            || !TEST_true(EC_POINT_add(group, P, P, Q, ctx)))
            goto err;

    } while (!EC_POINT_is_at_infinity(group, P));

    if (!TEST_true(EC_POINT_add(group, P, Q, R, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;

    len =
        EC_POINT_point2oct(group, Q, POINT_CONVERSION_COMPRESSED, buf,
                           sizeof buf, ctx);
    if (!TEST_size_t_ne(len, 0)
        || !TEST_true(EC_POINT_oct2point(group, P, buf, len, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, P, Q, ctx)))
        goto err;
    BIO_printf(bio_out, "Generator as octet string, compressed form:\n     ");
    for (i = 0; i < len; i++)
        BIO_printf(bio_out, "%02X", buf[i]);

    len = EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED,
                             buf, sizeof buf, ctx);
    if (!TEST_size_t_ne(len, 0)
        || !TEST_true(EC_POINT_oct2point(group, P, buf, len, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, P, Q, ctx)))
        goto err;
    BIO_printf(bio_out, "\nGenerator as octet string, uncompressed form:\n"
                        "     ");
    for (i = 0; i < len; i++)
        BIO_printf(bio_out, "%02X", buf[i]);

    len = EC_POINT_point2oct(group, Q, POINT_CONVERSION_HYBRID,
                             buf, sizeof buf, ctx);
    if (!TEST_size_t_ne(len, 0)
        || !TEST_true(EC_POINT_oct2point(group, P, buf, len, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, P, Q, ctx)))
        goto err;
    BIO_printf(bio_out, "\nGenerator as octet string, hybrid form:\n     ");
    for (i = 0; i < len; i++)
        BIO_printf(bio_out, "%02X", buf[i]);

    if (!TEST_true(EC_POINT_get_Jprojective_coordinates_GFp(group, R, x, y, z,
                                                            ctx)))
        goto err;
    BIO_printf(bio_out,
               "\nA representation of the inverse of that generator in\n"
               "Jacobian projective coordinates:\n"
               "     X = 0x");
    BN_print(bio_out, x);
    BIO_printf(bio_out, ", Y = 0x");
    BN_print(bio_out, y);
    BIO_printf(bio_out, ", Z = 0x");
    BN_print(bio_out, z);
    BIO_printf(bio_out, "\n");

    if (!TEST_true(EC_POINT_invert(group, P, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, P, R, ctx))

    /*
     * Curve secp160r1 (Certicom Research SEC 2 Version 1.0, section 2.4.2,
     * 2000) -- not a NIST curve, but commonly used
     */

        || !TEST_true(BN_hex2bn(&p,                         "FFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF"))
        || !TEST_int_eq(1, BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a,                         "FFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC"))
        || !TEST_true(BN_hex2bn(&b,                         "1C97BEFC"
                                    "54BD7A8B65ACF89F81D4D4ADC565FA45"))
        || !TEST_true(EC_GROUP_set_curve_GFp(group, p, a, b, ctx))
        || !TEST_true(BN_hex2bn(&x,                         "4A96B568"
                                    "8EF573284664698968C38BB913CBFC82"))
        || !TEST_true(BN_hex2bn(&y,                         "23a62855"
                                    "3168947d59dcc912042351377ac5fb32"))
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
        || !TEST_false(EC_POINT_set_affine_coordinates_GFp(group, P, x,
                                                           yplusone, ctx))
        || !TEST_true(EC_POINT_set_affine_coordinates_GFp(group, P, x, y, ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z,                       "0100000000"
                                    "000000000001F4C8F927AED3CA752257"))
        || !TEST_true(EC_GROUP_set_generator(group, P, z, BN_value_one()))
        || !TEST_true(EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)))
        goto err;
    BIO_printf(bio_out, "\nSEC2 curve secp160r1 -- Generator:\n     x = 0x");
    BN_print(bio_out, x);
    BIO_printf(bio_out, "\n     y = 0x");
    BN_print(bio_out, y);
    BIO_printf(bio_out, "\n");
    /* G_y value taken from the standard: */
    if (!TEST_true(BN_hex2bn(&z,                         "23a62855"
                                 "3168947d59dcc912042351377ac5fb32"))
        || !TEST_BN_eq(y, z)
        || !TEST_int_eq(EC_GROUP_get_degree(group), 160)
        || !group_order_tests(group)
        || !TEST_ptr(P_160 = EC_GROUP_new(EC_GROUP_method_of(group)))
        || !TEST_true(EC_GROUP_copy(P_160, group))

    /* Curve P-192 (FIPS PUB 186-2, App. 6) */

        || !TEST_true(BN_hex2bn(&p,                 "FFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF"))
        || !TEST_int_eq(1, BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a,                 "FFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC"))
        || !TEST_true(BN_hex2bn(&b,                 "64210519E59C80E7"
                                    "0FA7E9AB72243049FEB8DEECC146B9B1"))
        || !TEST_true(EC_GROUP_set_curve_GFp(group, p, a, b, ctx))
        || !TEST_true(BN_hex2bn(&x,                 "188DA80EB03090F6"
                                    "7CBF20EB43A18800F4FF0AFD82FF1012"))
        || !TEST_true(EC_POINT_set_compressed_coordinates_GFp(group, P, x, 1,
                                                              ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z,                 "FFFFFFFFFFFFFFFF"
                                    "FFFFFFFF99DEF836146BC9B1B4D22831"))
        || !TEST_true(EC_GROUP_set_generator(group, P, z, BN_value_one()))
        || !TEST_true(EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)))
        goto err;

    BIO_printf(bio_out, "\nNIST curve P-192 -- Generator:\n     x = 0x");
    BN_print(bio_out, x);
    BIO_printf(bio_out, "\n     y = 0x");
    BN_print(bio_out, y);
    BIO_printf(bio_out, "\n");
    /* G_y value taken from the standard: */
    if (!TEST_true(BN_hex2bn(&z,                 "07192B95FFC8DA78"
                                 "631011ED6B24CDD573F977A11E794811"))
        || !TEST_BN_eq(y, z)
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
        || !TEST_false(EC_POINT_set_affine_coordinates_GFp(group, P, x,
                                                           yplusone, ctx))
        || !TEST_int_eq(EC_GROUP_get_degree(group), 192)
        || !group_order_tests(group)
        || !TEST_ptr(P_192 = EC_GROUP_new(EC_GROUP_method_of(group)))
        || !TEST_true(EC_GROUP_copy(P_192, group))

    /* Curve P-224 (FIPS PUB 186-2, App. 6) */

        || !TEST_true(BN_hex2bn(&p,         "FFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFF000000000000000000000001"))
        || !TEST_int_eq(1, BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a,         "FFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE"))
        || !TEST_true(BN_hex2bn(&b,         "B4050A850C04B3ABF5413256"
                                    "5044B0B7D7BFD8BA270B39432355FFB4"))
        || !TEST_true(EC_GROUP_set_curve_GFp(group, p, a, b, ctx))
        || !TEST_true(BN_hex2bn(&x,         "B70E0CBD6BB4BF7F321390B9"
                                    "4A03C1D356C21122343280D6115C1D21"))
        || !TEST_true(EC_POINT_set_compressed_coordinates_GFp(group, P, x, 0,
                                                              ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z,         "FFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFF16A2E0B8F03E13DD29455C5C2A3D"))
        || !TEST_true(EC_GROUP_set_generator(group, P, z, BN_value_one()))
        || !TEST_true(EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)))
        goto err;

    BIO_printf(bio_out, "\nNIST curve P-224 -- Generator:\n     x = 0x");
    BN_print(bio_out, x);
    BIO_printf(bio_out, "\n     y = 0x");
    BN_print(bio_out, y);
    BIO_printf(bio_out, "\n");
    /* G_y value taken from the standard: */
    if (!TEST_true(BN_hex2bn(&z,         "BD376388B5F723FB4C22DFE6"
                                 "CD4375A05A07476444D5819985007E34"))
        || !TEST_BN_eq(y, z)
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
        || !TEST_false(EC_POINT_set_affine_coordinates_GFp(group, P, x,
                                                           yplusone, ctx))
        || !TEST_int_eq(EC_GROUP_get_degree(group), 224)
        || !group_order_tests(group)
        || !TEST_ptr(P_224 = EC_GROUP_new(EC_GROUP_method_of(group)))
        || !TEST_true(EC_GROUP_copy(P_224, group))

    /* Curve P-256 (FIPS PUB 186-2, App. 6) */

        || !TEST_true(BN_hex2bn(&p, "FFFFFFFF000000010000000000000000"
                                    "00000000FFFFFFFFFFFFFFFFFFFFFFFF"))
        || !TEST_int_eq(1, BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, "FFFFFFFF000000010000000000000000"
                                    "00000000FFFFFFFFFFFFFFFFFFFFFFFC"))
        || !TEST_true(BN_hex2bn(&b, "5AC635D8AA3A93E7B3EBBD55769886BC"
                                    "651D06B0CC53B0F63BCE3C3E27D2604B"))
        || !TEST_true(EC_GROUP_set_curve_GFp(group, p, a, b, ctx))

        || !TEST_true(BN_hex2bn(&x, "6B17D1F2E12C4247F8BCE6E563A440F2"
                                    "77037D812DEB33A0F4A13945D898C296"))
        || !TEST_true(EC_POINT_set_compressed_coordinates_GFp(group, P, x, 1,
                                                              ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z, "FFFFFFFF00000000FFFFFFFFFFFFFFFF"
                                    "BCE6FAADA7179E84F3B9CAC2FC632551"))
        || !TEST_true(EC_GROUP_set_generator(group, P, z, BN_value_one()))
        || !TEST_true(EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)))
        goto err;

    BIO_printf(bio_out, "\nNIST curve P-256 -- Generator:\n     x = 0x");
    BN_print(bio_out, x);
    BIO_printf(bio_out, "\n     y = 0x");
    BN_print(bio_out, y);
    BIO_printf(bio_out, "\n");
    /* G_y value taken from the standard: */
    if (!TEST_true(BN_hex2bn(&z, "4FE342E2FE1A7F9B8EE7EB4A7C0F9E16"
                                 "2BCE33576B315ECECBB6406837BF51F5"))
        || !TEST_BN_eq(y, z)
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
        || !TEST_false(EC_POINT_set_affine_coordinates_GFp(group, P, x,
                                                           yplusone, ctx))
        || !TEST_int_eq(EC_GROUP_get_degree(group), 256)
        || !group_order_tests(group)
        || !TEST_ptr(P_256 = EC_GROUP_new(EC_GROUP_method_of(group)))
        || !TEST_true(EC_GROUP_copy(P_256, group))

    /* Curve P-384 (FIPS PUB 186-2, App. 6) */

        || !TEST_true(BN_hex2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
                                    "FFFFFFFF0000000000000000FFFFFFFF"))
        || !TEST_int_eq(1, BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
                                    "FFFFFFFF0000000000000000FFFFFFFC"))
        || !TEST_true(BN_hex2bn(&b, "B3312FA7E23EE7E4988E056BE3F82D19"
                                    "181D9C6EFE8141120314088F5013875A"
                                    "C656398D8A2ED19D2A85C8EDD3EC2AEF"))
        || !TEST_true(EC_GROUP_set_curve_GFp(group, p, a, b, ctx))

        || !TEST_true(BN_hex2bn(&x, "AA87CA22BE8B05378EB1C71EF320AD74"
                                    "6E1D3B628BA79B9859F741E082542A38"
                                    "5502F25DBF55296C3A545E3872760AB7"))
        || !TEST_true(EC_POINT_set_compressed_coordinates_GFp(group, P, x, 1,
                                                              ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFC7634D81F4372DDF"
                                    "581A0DB248B0A77AECEC196ACCC52973"))
        || !TEST_true(EC_GROUP_set_generator(group, P, z, BN_value_one()))
        || !TEST_true(EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)))
        goto err;

    BIO_printf(bio_out, "\nNIST curve P-384 -- Generator:\n     x = 0x");
    BN_print(bio_out, x);
    BIO_printf(bio_out, "\n     y = 0x");
    BN_print(bio_out, y);
    BIO_printf(bio_out, "\n");
    /* G_y value taken from the standard: */
    if (!TEST_true(BN_hex2bn(&z, "3617DE4A96262C6F5D9E98BF9292DC29"
                                 "F8F41DBD289A147CE9DA3113B5F0B8C0"
                                 "0A60B1CE1D7E819D7A431D7C90EA0E5F"))
        || !TEST_BN_eq(y, z)
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
        || !TEST_false(EC_POINT_set_affine_coordinates_GFp(group, P, x,
                                                           yplusone, ctx))
        || !TEST_int_eq(EC_GROUP_get_degree(group), 384)
        || !group_order_tests(group)
        || !TEST_ptr(P_384 = EC_GROUP_new(EC_GROUP_method_of(group)))
        || !TEST_true(EC_GROUP_copy(P_384, group))

    /* Curve P-521 (FIPS PUB 186-2, App. 6) */
        || !TEST_true(BN_hex2bn(&p,                              "1FF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))
        || !TEST_int_eq(1, BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a,                              "1FF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC"))
        || !TEST_true(BN_hex2bn(&b,                              "051"
                                    "953EB9618E1C9A1F929A21A0B68540EE"
                                    "A2DA725B99B315F3B8B489918EF109E1"
                                    "56193951EC7E937B1652C0BD3BB1BF07"
                                    "3573DF883D2C34F1EF451FD46B503F00"))
        || !TEST_true(EC_GROUP_set_curve_GFp(group, p, a, b, ctx))
        || !TEST_true(BN_hex2bn(&x,                               "C6"
                                    "858E06B70404E9CD9E3ECB662395B442"
                                    "9C648139053FB521F828AF606B4D3DBA"
                                    "A14B5E77EFE75928FE1DC127A2FFA8DE"
                                    "3348B3C1856A429BF97E7E31C2E5BD66"))
        || !TEST_true(EC_POINT_set_compressed_coordinates_GFp(group, P, x, 0,
                                                              ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z,                              "1FF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA"
                                    "51868783BF2F966B7FCC0148F709A5D0"
                                    "3BB5C9B8899C47AEBB6FB71E91386409"))
        || !TEST_true(EC_GROUP_set_generator(group, P, z, BN_value_one()))
        || !TEST_true(EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)))
        goto err;

    BIO_printf(bio_out, "\nNIST curve P-521 -- Generator:\n     x = 0x");
    BN_print(bio_out, x);
    BIO_printf(bio_out, "\n     y = 0x");
    BN_print(bio_out, y);
    BIO_printf(bio_out, "\n");
    /* G_y value taken from the standard: */
    if (!TEST_true(BN_hex2bn(&z,                              "118"
                                 "39296A789A3BC0045C8A5FB42C7D1BD9"
                                 "98F54449579B446817AFBD17273E662C"
                                 "97EE72995EF42640C550B9013FAD0761"
                                 "353C7086A272C24088BE94769FD16650"))
        || !TEST_BN_eq(y, z)
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
        || !TEST_false(EC_POINT_set_affine_coordinates_GFp(group, P, x,
                                                           yplusone, ctx))
        || !TEST_int_eq(EC_GROUP_get_degree(group), 521)
        || !group_order_tests(group)
        || !TEST_ptr(P_521 = EC_GROUP_new(EC_GROUP_method_of(group)))
        || !TEST_true(EC_GROUP_copy(P_521, group))

    /* more tests using the last curve */

    /* Restore the point that got mangled in the (x, y + 1) test. */
        || !TEST_true(EC_POINT_set_affine_coordinates_GFp(group, P, x, y, ctx))
        || !TEST_true(EC_POINT_copy(Q, P))
        || !TEST_false(EC_POINT_is_at_infinity(group, Q))
        || !TEST_true(EC_POINT_dbl(group, P, P, ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(EC_POINT_invert(group, Q, ctx))       /* P = -2Q */
        || !TEST_true(EC_POINT_add(group, R, P, Q, ctx))
        || !TEST_true(EC_POINT_add(group, R, R, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, R))    /* R = P + 2Q */
        || !TEST_false(EC_POINT_is_at_infinity(group, Q)))
        goto err;
    points[0] = Q;
    points[1] = Q;
    points[2] = Q;
    points[3] = Q;

    if (!TEST_true(EC_GROUP_get_order(group, z, ctx))
        || !TEST_true(BN_add(y, z, BN_value_one()))
        || !TEST_BN_even(y)
        || !TEST_true(BN_rshift1(y, y)))
        goto err;
    scalars[0] = y;         /* (group order + 1)/2, so y*Q + y*Q = Q */
    scalars[1] = y;

    BIO_printf(bio_out, "combined multiplication ...");

    /* z is still the group order */
    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx))
        || !TEST_true(EC_POINTs_mul(group, R, z, 2, points, scalars, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, P, R, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, R, Q, ctx))
        || !TEST_true(BN_pseudo_rand(y, BN_num_bits(y), 0, 0))
        || !TEST_true(BN_add(z, z, y)))
        goto err;
    BN_set_negative(z, 1);
    scalars[0] = y;
    scalars[1] = z;         /* z = -(order + y) */

    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_true(BN_pseudo_rand(x, BN_num_bits(y) - 1, 0, 0))
        || !TEST_true(BN_add(z, x, y)))
        goto err;
    BN_set_negative(z, 1);
    scalars[0] = x;
    scalars[1] = y;
    scalars[2] = z;         /* z = -(x+y) */

    if (!TEST_ptr(scalar3 = BN_new()))
        goto err;
    BN_zero(scalar3);
    scalars[3] = scalar3;

    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 4, points, scalars, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;

    BIO_printf(bio_out, " ok\n\n");


    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_GROUP_free(tmp);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(scalar3);

    EC_GROUP_free(P_160);
    EC_GROUP_free(P_192);
    EC_GROUP_free(P_224);
    EC_GROUP_free(P_256);
    EC_GROUP_free(P_384);
    EC_GROUP_free(P_521);
    return r;
}

# ifndef OPENSSL_NO_EC2M

static struct c2_curve_test {
    const char *name;
    const char *p;
    const char *a;
    const char *b;
    const char *x;
    const char *y;
    int ybit;
    const char *order;
    const char *cof;
    int degree;
} char2_curve_tests[] = {
    /* Curve K-163 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve K-163",
        "0800000000000000000000000000000000000000C9",
        "1",
        "1",
        "02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8",
        "0289070FB05D38FF58321F2E800536D538CCDAA3D9",
        1, "04000000000000000000020108A2E0CC0D99F8A5EF", "2", 163
    },
    /* Curve B-163 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve B-163",
        "0800000000000000000000000000000000000000C9",
        "1",
        "020A601907B8C953CA1481EB10512F78744A3205FD",
        "03F0EBA16286A2D57EA0991168D4994637E8343E36",
        "00D51FBC6C71A0094FA2CDD545B11C5C0C797324F1",
        1, "040000000000000000000292FE77E70C12A4234C33", "2", 163
    },
    /* Curve K-233 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve K-233",
        "020000000000000000000000000000000000000004000000000000000001",
        "0",
        "1",
        "017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD6126",
        "01DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3",
        0,
        "008000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF",
        "4", 233
    },
    /* Curve B-233 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve B-233",
        "020000000000000000000000000000000000000004000000000000000001",
        "000000000000000000000000000000000000000000000000000000000001",
        "0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD",
        "00FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B",
        "01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052",
        1,
        "01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7",
        "2", 233
    },
    /* Curve K-283 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve K-283",
                                                                "08000000"
        "00000000000000000000000000000000000000000000000000000000000010A1",
        "0",
        "1",
                                                                "0503213F"
        "78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC2458492836",
                                                                "01CCDA38"
        "0F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259",
        0,
                                                                "01FFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61",
        "4", 283
    },
    /* Curve B-283 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve B-283",
                                                                "08000000"
        "00000000000000000000000000000000000000000000000000000000000010A1",
                                                                "00000000"
        "0000000000000000000000000000000000000000000000000000000000000001",
                                                                "027B680A"
        "C8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5",
                                                                "05F93925"
        "8DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B12053",
                                                                "03676854"
        "FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4",
        1,
                                                                "03FFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307",
        "2", 283
    },
    /* Curve K-409 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve K-409",
                                "0200000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000008000000000000000000001",
        "0",
        "1",
                                "0060F05F658F49C1AD3AB1890F7184210EFD0987"
        "E307C84C27ACCFB8F9F67CC2C460189EB5AAAA62EE222EB1B35540CFE9023746",
                                "01E369050B7C4E42ACBA1DACBF04299C3460782F"
        "918EA427E6325165E9EA10E3DA5F6C42E9C55215AA9CA27A5863EC48D8E0286B",
        1,
                                "007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFE5F83B2D4EA20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF",
        "4", 409
    },
    /* Curve B-409 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve B-409",
                                "0200000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000008000000000000000000001",
                                "0000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000001",
                                "0021A5C2C8EE9FEB5C4B9A753B7B476B7FD6422E"
        "F1F3DD674761FA99D6AC27C8A9A197B272822F6CD57A55AA4F50AE317B13545F",
                                "015D4860D088DDB3496B0C6064756260441CDE4A"
        "F1771D4DB01FFE5B34E59703DC255A868A1180515603AEAB60794E54BB7996A7",
                                "0061B1CFAB6BE5F32BBFA78324ED106A7636B9C5"
        "A7BD198D0158AA4F5488D08F38514F1FDF4B4F40D2181B3681C364BA0273C706",
        1,
                                "0100000000000000000000000000000000000000"
        "00000000000001E2AAD6A612F33307BE5FA47C3C9E052F838164CD37D9A21173",
        "2", 409
    },
    /* Curve K-571 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve K-571",
                                                         "800000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000425",
        "0",
        "1",
                                                        "026EB7A859923FBC"
        "82189631F8103FE4AC9CA2970012D5D46024804801841CA44370958493B205E6"
        "47DA304DB4CEB08CBBD1BA39494776FB988B47174DCA88C7E2945283A01C8972",
                                                        "0349DC807F4FBF37"
        "4F4AEADE3BCA95314DD58CEC9F307A54FFC61EFC006D8A2C9D4979C0AC44AEA7"
        "4FBEBBB9F772AEDCB620B01A7BA7AF1B320430C8591984F601CD4C143EF1C7A3",
        0,
                                                        "0200000000000000"
        "00000000000000000000000000000000000000000000000000000000131850E1"
        "F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001",
        "4", 571
    },
    /* Curve B-571 (FIPS PUB 186-2, App. 6) */
    {
        "NIST curve B-571",
                                                         "800000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000425",
                                                        "0000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000001",
                                                        "02F40E7E2221F295"
        "DE297117B7F3D62F5C6A97FFCB8CEFF1CD6BA8CE4A9A18AD84FFABBD8EFA5933"
        "2BE7AD6756A66E294AFD185A78FF12AA520E4DE739BACA0C7FFEFF7F2955727A",
                                                        "0303001D34B85629"
        "6C16C0D40D3CD7750A93D1D2955FA80AA5F40FC8DB7B2ABDBDE53950F4C0D293"
        "CDD711A35B67FB1499AE60038614F1394ABFA3B4C850D927E1E7769C8EEC2D19",
                                                        "037BF27342DA639B"
        "6DCCFFFEB73D69D78C6C27A6009CBBCA1980F8533921E8A684423E43BAB08A57"
        "6291AF8F461BB2A8B3531D2F0485C19B16E2F1516E23DD3C1A4827AF1B8AC15B",
        1,
                                                        "03FFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE661CE18"
        "FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47",
        "2", 571
    }
};

static int char2_curve_test(int n)
{
    int r = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    EC_GROUP *group = NULL, *variable = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    const EC_POINT *points[3];
    const BIGNUM *scalars[3];
    struct c2_curve_test *const test = char2_curve_tests + n;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(group = EC_GROUP_new(EC_GF2m_simple_method()))
        || !TEST_true(EC_GROUP_set_curve_GF2m(group, p, a, b, ctx))
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(BN_hex2bn(&x, test->x))
        || !TEST_true(BN_hex2bn(&y, test->y))
        || !TEST_true(BN_add(yplusone, y, BN_value_one())))
        goto err;

/* Change test based on whether binary point compression is enabled or not. */
# ifdef OPENSSL_EC_BIN_PT_COMP
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
    if (!TEST_false(EC_POINT_set_affine_coordinates_GF2m(group, P, x, yplusone,
                                                         ctx))
        || !TEST_true(EC_POINT_set_compressed_coordinates_GF2m(group, P, x,
                                                               test->y_bit,
                                                               ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z, test->order))
        || !TEST_true(BN_hex2bn(&cof, test->cof))
        || !TEST_true(EC_GROUP_set_generator(group, P, z, cof))
        || !TEST_true(EC_POINT_get_affine_coordinates_GF2m(group, P, x, y,
                                                           ctx)))
        goto err;
    BIO_printf(bio_out, "\n%s -- Generator:\n     x = 0x", test->name);
    BN_print(bio_out, x);
    BIO_printf(bio_out, "\n     y = 0x");
    BN_print(bio_out, y);
    BIO_printf(bio_out, "\n");
    /* G_y value taken from the standard: */
    if (!TEST_true(BN_hex2bn(&z, test->y))
        || !TEST_BN_eq(y, z))
        goto err;
# else
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
    if (!TEST_false(EC_POINT_set_affine_coordinates_GF2m(group, P, x, yplusone,
                    ctx))
        || !TEST_true(EC_POINT_set_affine_coordinates_GF2m(group, P, x, y, ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z, test->order))
        || !TEST_true(BN_hex2bn(&cof, test->cof))
        || !TEST_true(EC_GROUP_set_generator(group, P, z, cof)))
        goto err;
    BIO_printf(bio_out, "\n%s -- Generator:\n     x = 0x", test->name); \
    BN_print(bio_out, x); \
    BIO_printf(bio_out, "\n     y = 0x"); \
    BN_print(bio_out, y); \
    BIO_printf(bio_out, "\n");
# endif

    if (!TEST_int_eq(EC_GROUP_get_degree(group), test->degree)
        || !group_order_tests(group)
        || !TEST_ptr(variable = EC_GROUP_new(EC_GROUP_method_of(group)))
        || !TEST_true(EC_GROUP_copy(variable, group)))
        goto err;

    /* more tests using the last curve */
    if (n == OSSL_NELEM(char2_curve_tests) - 1) {
        if (!TEST_true(EC_POINT_set_affine_coordinates_GF2m(group, P, x, y,
                                                                ctx))
            || !TEST_true(EC_POINT_copy(Q, P))
            || !TEST_false(EC_POINT_is_at_infinity(group, Q))
            || !TEST_true(EC_POINT_dbl(group, P, P, ctx))
            || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
            || !TEST_true(EC_POINT_invert(group, Q, ctx))       /* P = -2Q */
            || !TEST_true(EC_POINT_add(group, R, P, Q, ctx))
            || !TEST_true(EC_POINT_add(group, R, R, Q, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, R))   /* R = P + 2Q */
            || !TEST_false(EC_POINT_is_at_infinity(group, Q)))
            goto err;

        points[0] = Q;
        points[1] = Q;
        points[2] = Q;

        if (!TEST_true(BN_add(y, z, BN_value_one()))
            || !TEST_BN_even(y)
            || !TEST_true(BN_rshift1(y, y)))
            goto err;
        scalars[0] = y;         /* (group order + 1)/2, so y*Q + y*Q = Q */
        scalars[1] = y;

        BIO_printf(bio_out, "combined multiplication ...");

        /* z is still the group order */
        if (!TEST_true(EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx))
            || !TEST_true(EC_POINTs_mul(group, R, z, 2, points, scalars, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, P, R, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, R, Q, ctx)))
            goto err;

        if (!TEST_true(BN_pseudo_rand(y, BN_num_bits(y), 0, 0))
            || !TEST_true(BN_add(z, z, y)))
            goto err;
        BN_set_negative(z, 1);
        scalars[0] = y;
        scalars[1] = z;         /* z = -(order + y) */

        if (!TEST_true(EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, P)))
            goto err;

        if (!TEST_true(BN_pseudo_rand(x, BN_num_bits(y) - 1, 0, 0))
            || !TEST_true(BN_add(z, x, y)))
            goto err;
        BN_set_negative(z, 1);
        scalars[0] = x;
        scalars[1] = y;
        scalars[2] = z;         /* z = -(x+y) */

        if (!TEST_true(EC_POINTs_mul(group, P, NULL, 3, points, scalars, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, P)))
            goto err;;
    }

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(cof);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_GROUP_free(group);
    EC_GROUP_free(variable);
    return r;
}

static int char2_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL, *tmp = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *cof = NULL, *yplusone = NULL;
    unsigned char buf[100];
    size_t i, len;
    int k, r = 0;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "13"))
        || !TEST_true(BN_hex2bn(&a, "3"))
        || !TEST_true(BN_hex2bn(&b, "1")))
        goto err;

    group = EC_GROUP_new(EC_GF2m_simple_method()); /* applications should use
                                                    * EC_GROUP_new_curve_GF2m
                                                    * so that the library gets
                                                    * to choose the EC_METHOD */
    if (!TEST_ptr(group)
        || !TEST_true(EC_GROUP_set_curve_GF2m(group, p, a, b, ctx))
        || !TEST_ptr(tmp = EC_GROUP_new(EC_GROUP_method_of(group)))
        || !TEST_true(EC_GROUP_copy(tmp, group)))
        goto err;
    EC_GROUP_free(group);
    group = tmp;
    tmp = NULL;

    if (!TEST_true(EC_GROUP_get_curve_GF2m(group, p, a, b, ctx)))
        goto err;

    BIO_printf(bio_out,
            "Curve defined by Weierstrass equation\n"
            "     y^2 + x*y = x^3 + a*x^2 + b  (mod 0x");
    BN_print(bio_out, p);
    BIO_printf(bio_out, ")\n     a = 0x");
    BN_print(bio_out, a);
    BIO_printf(bio_out, "\n     b = 0x");
    BN_print(bio_out, b);
    BIO_printf(bio_out, "\n(0x... means binary polynomial)\n");

     if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_true(EC_POINT_set_to_infinity(group, P))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;

    buf[0] = 0;
    if (!TEST_true(EC_POINT_oct2point(group, Q, buf, 1, ctx))
        || !TEST_true(EC_POINT_add(group, P, P, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(cof = BN_new())
        || !TEST_ptr(yplusone = BN_new())
        || !TEST_true(BN_hex2bn(&x, "6"))
/* Change test based on whether binary point compression is enabled or not. */
#  ifdef OPENSSL_EC_BIN_PT_COMP
        || !TEST_true(EC_POINT_set_compressed_coordinates_GF2m(group, Q, x, 1,
                                                               ctx))
#  else
        || !TEST_true(BN_hex2bn(&y, "8"))
        || !TEST_true(EC_POINT_set_affine_coordinates_GF2m(group, Q, x, y, ctx))
#  endif
       )
        goto err;
    if (!TEST_int_gt(EC_POINT_is_on_curve(group, Q, ctx), 0)) {
/* Change test based on whether binary point compression is enabled or not. */
#  ifdef OPENSSL_EC_BIN_PT_COMP
        if (!TEST_true(EC_POINT_get_affine_coordinates_GF2m(group, Q, x, y,
                                                            ctx)))
            goto err;
#  endif
        BIO_printf(bio_err, "Point is not on curve: x = 0x");
        BN_print_fp(stderr, x);
        BIO_printf(bio_err, ", y = 0x");
        BN_print_fp(stderr, y);
        BIO_printf(bio_err, "\n");
        goto err;
    }

    BIO_printf(bio_out, "A cyclic subgroup:\n");
    k = 100;
    do {
        if (!TEST_int_ne(k--, 0))
            goto err;

        if (EC_POINT_is_at_infinity(group, P))
            BIO_printf(bio_out, "     point at infinity\n");
        else {
            if (!TEST_true(EC_POINT_get_affine_coordinates_GF2m(group, P, x, y,
                                                                ctx)))
                goto err;

            BIO_printf(bio_out, "     x = 0x");
            BN_print(bio_out, x);
            BIO_printf(bio_out, ", y = 0x");
            BN_print(bio_out, y);
            BIO_printf(bio_out, "\n");
        }

        if (!TEST_true(EC_POINT_copy(R, P))
            || !TEST_true(EC_POINT_add(group, P, P, Q, ctx)))
            goto err;
    }
    while (!EC_POINT_is_at_infinity(group, P));

    if (!TEST_true(EC_POINT_add(group, P, Q, R, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;

/* Change test based on whether binary point compression is enabled or not. */
#  ifdef OPENSSL_EC_BIN_PT_COMP
    len = EC_POINT_point2oct(group, Q, POINT_CONVERSION_COMPRESSED,
                             buf, sizeof buf, ctx);
    if (!TEST_size_t_ne(len, 0)
        || !TEST_true(EC_POINT_oct2point(group, P, buf, len, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, P, Q, ctx)))
        goto err;
    BIO_printf(bio_out, "Generator as octet string, compressed form:\n     ");
    for (i = 0; i < len; i++)
        BIO_printf(bio_out, "%02X", buf[i]);
#  endif

    len = EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED,
                             buf, sizeof buf, ctx);
    if (!TEST_size_t_ne(len, 0)
        || !TEST_true(EC_POINT_oct2point(group, P, buf, len, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, P, Q, ctx)))
        goto err;
    BIO_printf(bio_out, "\nGenerator as octet string, uncompressed form:\n"
                        "     ");
    for (i = 0; i < len; i++)
        BIO_printf(bio_out, "%02X", buf[i]);

/* Change test based on whether binary point compression is enabled or not. */
#  ifdef OPENSSL_EC_BIN_PT_COMP
    len =
        EC_POINT_point2oct(group, Q, POINT_CONVERSION_HYBRID, buf, sizeof buf,
                           ctx);
    if (!TEST_size_t_ne(len, 0)
        || !TEST_true(EC_POINT_oct2point(group, P, buf, len, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, P, Q, ctx)))
        goto err;
    BIO_printf(bio_out, "\nGenerator as octet string, hybrid form:\n     ");
    for (i = 0; i < len; i++)
        BIO_printf(bio_out, "%02X", buf[i]);
#  endif
    BIO_printf(bio_out, "\n");

    if (!TEST_true(EC_POINT_invert(group, P, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, P, R, ctx)))
        goto err;


#if 0
#endif
    BIO_printf(bio_out, "\n\n");

    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_GROUP_free(tmp);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(cof);
    BN_free(yplusone);
    return r;
}
# endif

static int internal_curve_test(int n)
{
    EC_GROUP *group = NULL;
    int nid = curves[n].nid;

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(nid))) {
        TEST_info("EC_GROUP_new_curve_name() failed with curve %s\n",
                  OBJ_nid2sn(nid));
        return 0;
    }
    if (!TEST_true(EC_GROUP_check(group, NULL))) {
        TEST_info("EC_GROUP_check() failed with curve %s\n", OBJ_nid2sn(nid));
        EC_GROUP_free(group);
        return 0;
    }
    EC_GROUP_free(group);
    return 1;
}

static int internal_curve_test_method(int n)
{
    int r, nid = curves[n].nid;
    EC_GROUP *group;

    /*
     * Skip for X25519 because low level operations such as EC_POINT_mul()
     * are not supported for this curve
     */
    if (nid == NID_X25519)
        return 1;
    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(nid))) {
        TEST_info("Curve %s failed\n", OBJ_nid2sn(nid));
        return 0;
    }
    r = group_order_tests(group);
    EC_GROUP_free(group);
    return r;
}

# ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
/*
 * nistp_test_params contains magic numbers for testing our optimized
 * implementations of several NIST curves with characteristic > 3.
 */
struct nistp_test_params {
    const EC_METHOD *(*meth) ();
    int degree;
    /*
     * Qx, Qy and D are taken from
     * http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/ECDSA_Prime.pdf
     * Otherwise, values are standard curve parameters from FIPS 180-3
     */
    const char *p, *a, *b, *Qx, *Qy, *Gx, *Gy, *order, *d;
};

static const struct nistp_test_params nistp_tests_params[] = {
    {
     /* P-224 */
     EC_GFp_nistp224_method,
     224,
     /* p */
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
     /* a */
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
     /* b */
     "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
     /* Qx */
     "E84FB0B8E7000CB657D7973CF6B42ED78B301674276DF744AF130B3E",
     /* Qy */
     "4376675C6FC5612C21A0FF2D2A89D2987DF7A2BC52183B5982298555",
     /* Gx */
     "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
     /* Gy */
     "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
     /* order */
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
     /* d */
     "3F0C488E987C80BE0FEE521F8D90BE6034EC69AE11CA72AA777481E8",
     },
    {
     /* P-256 */
     EC_GFp_nistp256_method,
     256,
     /* p */
     "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
     /* a */
     "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
     /* b */
     "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
     /* Qx */
     "b7e08afdfe94bad3f1dc8c734798ba1c62b3a0ad1e9ea2a38201cd0889bc7a19",
     /* Qy */
     "3603f747959dbf7a4bb226e41928729063adc7ae43529e61b563bbc606cc5e09",
     /* Gx */
     "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
     /* Gy */
     "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
     /* order */
     "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
     /* d */
     "c477f9f65c22cce20657faa5b2d1d8122336f851a508a1ed04e479c34985bf96",
     },
    {
     /* P-521 */
     EC_GFp_nistp521_method,
     521,
     /* p */
                                                                  "1ff"
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     /* a */
                                                                  "1ff"
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
     "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
     /* b */
                                                                  "051"
     "953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e1"
     "56193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
     /* Qx */
                                                                 "0098"
     "e91eef9a68452822309c52fab453f5f117c1da8ed796b255e9ab8f6410cca16e"
     "59df403a6bdc6ca467a37056b1e54b3005d8ac030decfeb68df18b171885d5c4",
     /* Qy */
                                                                 "0164"
     "350c321aecfc1cca1ba4364c9b15656150b4b78d6a48d7d28e7f31985ef17be8"
     "554376b72900712c4b83ad668327231526e313f5f092999a4632fd50d946bc2e",
     /* Gx */
                                                                   "c6"
     "858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dba"
     "a14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
     /* Gy */
                                                                  "118"
     "39296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c"
     "97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
     /* order */
                                                                  "1ff"
     "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa"
     "51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
     /* d */
                                                                 "0100"
     "085f47b8e1b8b11b7eb33028c0b2888e304bfc98501955b45bba1478dc184eee"
     "df09b86a5f7c21994406072787205e69a63709fe35aa93ba333514b24f961722",
     },
};

static int nistp_single_test(int idx)
{
    const struct nistp_test_params *test = nistp_tests_params + idx;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL;
    BIGNUM *n = NULL, *m = NULL, *order = NULL, *yplusone = NULL;
    EC_GROUP *NISTP = NULL;
    EC_POINT *G = NULL, *P = NULL, *Q = NULL, *Q_CHECK = NULL;
    int r = 0;

    BIO_printf(bio_out, "\nNIST curve P-%d (optimised implementation):\n",
            test->degree);
    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(yplusone = BN_new())

        || !TEST_ptr(NISTP = EC_GROUP_new(test->meth()))
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_int_eq(1, BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(EC_GROUP_set_curve_GFp(NISTP, p, a, b, ctx))
        || !TEST_ptr(G = EC_POINT_new(NISTP))
        || !TEST_ptr(P = EC_POINT_new(NISTP))
        || !TEST_ptr(Q = EC_POINT_new(NISTP))
        || !TEST_ptr(Q_CHECK = EC_POINT_new(NISTP))
        || !TEST_true(BN_hex2bn(&x, test->Qx))
        || !TEST_true(BN_hex2bn(&y, test->Qy))
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
        || !TEST_false(EC_POINT_set_affine_coordinates_GFp(NISTP, Q_CHECK, x,
                                                           yplusone, ctx))
        || !TEST_true(EC_POINT_set_affine_coordinates_GFp(NISTP, Q_CHECK, x, y,
                                                          ctx))
        || !TEST_true(BN_hex2bn(&x, test->Gx))
        || !TEST_true(BN_hex2bn(&y, test->Gy))
        || !TEST_true(EC_POINT_set_affine_coordinates_GFp(NISTP, G, x, y, ctx))
        || !TEST_true(BN_hex2bn(&order, test->order))
        || !TEST_true(EC_GROUP_set_generator(NISTP, G, order, BN_value_one()))
        || !TEST_int_eq(EC_GROUP_get_degree(NISTP), test->degree))
        goto err;

    BIO_printf(bio_out, "NIST test vectors ... ");
    if (!TEST_true(BN_hex2bn(&n, test->d)))
        goto err;
    /* fixed point multiplication */
    EC_POINT_mul(NISTP, Q, n, NULL, NULL, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)))
        goto err;
    /* random point multiplication */
    EC_POINT_mul(NISTP, Q, NULL, G, n, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx))

        /* set generator to P = 2*G, where G is the standard generator */
        || !TEST_true(EC_POINT_dbl(NISTP, P, G, ctx))
        || !TEST_true(EC_GROUP_set_generator(NISTP, P, order, BN_value_one()))
        /* set the scalar to m=n/2, where n is the NIST test scalar */
        || !TEST_true(BN_rshift(m, n, 1)))
        goto err;

    /* test the non-standard generator */
    /* fixed point multiplication */
    EC_POINT_mul(NISTP, Q, m, NULL, NULL, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)))
        goto err;
    /* random point multiplication */
    EC_POINT_mul(NISTP, Q, NULL, P, m, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx))

    /*
     * We have not performed precomputation so have_precompute mult should be
     * false
     */
        || !TEST_false(EC_GROUP_have_precompute_mult(NISTP))

    /* now repeat all tests with precomputation */
        || !TEST_true(EC_GROUP_precompute_mult(NISTP, ctx))
        || !TEST_true(EC_GROUP_have_precompute_mult(NISTP)))
        goto err;

    /* fixed point multiplication */
    EC_POINT_mul(NISTP, Q, m, NULL, NULL, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)))
        goto err;
    /* random point multiplication */
    EC_POINT_mul(NISTP, Q, NULL, P, m, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx))

    /* reset generator */
        || !TEST_true(EC_GROUP_set_generator(NISTP, G, order, BN_value_one())))
        goto err;
    /* fixed point multiplication */
    EC_POINT_mul(NISTP, Q, n, NULL, NULL, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)))
        goto err;
    /* random point multiplication */
    EC_POINT_mul(NISTP, Q, NULL, G, n, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)))
        goto err;

    r = group_order_tests(NISTP);
err:
    EC_GROUP_free(NISTP);
    EC_POINT_free(G);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(Q_CHECK);
    BN_free(n);
    BN_free(m);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(order);
    BN_free(yplusone);
    BN_CTX_free(ctx);
    return r;
}
# endif

static int parameter_test(void)
{
    EC_GROUP *group = NULL, *group2 = NULL;
    ECPARAMETERS *ecparameters = NULL;
    int r;

    r = TEST_ptr(group = EC_GROUP_new_by_curve_name(NID_secp112r1))
        && TEST_ptr(ecparameters = EC_GROUP_get_ecparameters(group, NULL))
        && TEST_ptr(group2 = EC_GROUP_new_from_ecparameters(ecparameters))
        && TEST_int_eq(EC_GROUP_cmp(group, group2, NULL), 0);

    EC_GROUP_free(group);
    EC_GROUP_free(group2);
    ECPARAMETERS_free(ecparameters);
    return r;
}

static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";
#endif

int test_main(int argc, char *argv[])
{
    int result = EXIT_SUCCESS;
#ifndef OPENSSL_NO_EC

    crv_len = EC_get_builtin_curves(NULL, 0);
    if (!TEST_ptr(curves = OPENSSL_malloc(sizeof(*curves) * crv_len))
        || !TEST_true(EC_get_builtin_curves(curves, crv_len)))
        return EXIT_FAILURE;

    RAND_seed(rnd_seed, sizeof rnd_seed); /* or BN_generate_prime may fail */

    ADD_TEST(parameter_test);
    ADD_TEST(prime_field_tests);
# ifndef OPENSSL_NO_EC2M
    ADD_TEST(char2_field_tests);
    ADD_ALL_TESTS(char2_curve_test, OSSL_NELEM(char2_curve_tests));
# endif
# ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
    ADD_ALL_TESTS(nistp_single_test, OSSL_NELEM(nistp_tests_params));
# endif
    ADD_ALL_TESTS(internal_curve_test, crv_len);
    ADD_ALL_TESTS(internal_curve_test_method, crv_len);

    result = run_tests(argv[0]);
    OPENSSL_free(curves);
#endif
    return result;
}
