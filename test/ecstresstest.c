/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include "e_os.h"
#include "testutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define NUM_REPEATS "1000000"

static int64_t num_repeats;
static int print_mode = 0;

#ifndef OPENSSL_NO_EC
# include <openssl/ec.h>
# include <openssl/err.h>
# include <openssl/obj_mac.h>
# include <openssl/objects.h>
# include <openssl/rand.h>
# include <openssl/bn.h>
# include <openssl/opensslconf.h>

static const char *kP256DefaultResult =
    "A1E24B223B8E81BC1FFF99BAFB909EDB895FACDE7D6DA5EF5E7B3255FB378E0F";

/*
 * Perform a deterministic walk on the curve, by starting from |point| and
 * using the X-coordinate of the previous point as the next scalar for
 * point multiplication.
 * Returns the X-coordinate of the end result or NULL on error.
 */
static BIGNUM *walk_curve(const EC_GROUP *group, EC_POINT *point, int64_t num)
{
    BIGNUM *scalar = NULL;
    int64_t i;

    if (!TEST_ptr(scalar = BN_new())
            || !TEST_true(EC_POINT_get_affine_coordinates_GFp(group, point,
                                                              scalar,
                                                              NULL, NULL)))
        goto err;

    for (i = 0; i < num; i++) {
        if (!TEST_true(EC_POINT_mul(group, point, NULL, point, scalar, NULL))
                || !TEST_true(EC_POINT_get_affine_coordinates_GFp(group, point,
                                                                  scalar,
                                                                  NULL, NULL)))
            goto err;
    }
    return scalar;

err:
    BN_free(scalar);
    return NULL;
}

static int test_curve()
{
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *result = NULL, *expected_result = NULL;
    int ret = 0;

    /*
     * We currently hard-code P-256, though adaptation to other curves.
     * would be straightforward.
     */
    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1))
            || !TEST_ptr(point = EC_POINT_dup(EC_GROUP_get0_generator(group),
                                              group))
            || !TEST_ptr(result = walk_curve(group, point, num_repeats)))
        return 0;

    if (print_mode) {
        BN_print(bio_out, result);
        BIO_printf(bio_out, "\n");
        ret = 1;
    } else {
        if (!TEST_true(BN_hex2bn(&expected_result, kP256DefaultResult))
                || !TEST_ptr(expected_result)
                || !TEST_BN_eq(result, expected_result))
            goto err;
        ret = 1;
    }

err:
    EC_GROUP_free(group);
    EC_POINT_free(point);
    BN_free(result);
    BN_free(expected_result);
    return ret;
}
#endif

static int atoi64(const char *in, int64_t *result)
{
    int64_t ret = 0;

    for ( ; *in != '\0'; in++) {
        char c = *in;

        if (!isdigit(c))
            return 0;
        ret *= 10;
        ret += (c - '0');
    }
    *result = ret;
    return 1;
}

/*
 * Stress test the curve. If the '-num' argument is given, runs the loop
 * |num| times and prints the resulting X-coordinate. Otherwise runs the test
 * the default number of times and compares against the expected result.
 */
int test_main(int argc, char *argv[])
{
    const char *argv0 = argv[0];

    if (!atoi64(NUM_REPEATS, &num_repeats)) {
        TEST_error("Cannot parse " NUM_REPEATS);
        return EXIT_FAILURE;
    }
    /*
     * TODO(openssl-team): code under test/ should be able to reuse the option
     * parsing framework currently in apps/.
     */
    argc--;
    argv++;
    while (argc >= 1) {
        if (strcmp(*argv, "-num") == 0) {
            if (--argc < 1
                    || !atoi64(*++argv, &num_repeats)
                    || num_repeats < 0) {
                TEST_error("Bad -num argument\n");
                return EXIT_FAILURE;
            }
            print_mode = 1;
        } else {
            TEST_error("Unknown option %s\n", *argv);
            return EXIT_FAILURE;
        }
        argc--;
        argv++;
    }

#ifndef OPENSSL_NO_EC
    ADD_TEST(test_curve);
#endif
    return run_tests(argv0);
}
