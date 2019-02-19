/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ec.h>
#include "ec_lcl.h"
#include <openssl/objects.h>

#include "testutil.h"

static size_t crv_len = 0;
static EC_builtin_curve *curves = NULL;

/* sanity checks field_inv function pointer in EC_METHOD */
static int group_field_tests(const EC_GROUP *group, BN_CTX *ctx)
{
    BIGNUM *a = NULL, *b = NULL, *c = NULL;
    int ret = 0;

    if (group->meth->field_inv == NULL || group->meth->field_mul == NULL)
        return 1;

    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    TEST_check(NULL != (c = BN_CTX_get(ctx)));

    /* 1/1 = 1 */
    TEST_check(group->meth->field_inv(group, b, BN_value_one(), ctx));
    TEST_check(BN_is_one(b));

    /* (1/a)*a = 1 */
    TEST_check(BN_pseudo_rand(a, BN_num_bits(group->field) - 1,
                              BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY));
    TEST_check(group->meth->field_inv(group, b, a, ctx));
    if (group->meth->field_encode) {
        TEST_check(group->meth->field_encode(group, a, a, ctx));
        TEST_check(group->meth->field_encode(group, b, b, ctx));
    }
    TEST_check(group->meth->field_mul(group, c, a, b, ctx));
    if (group->meth->field_decode) {
        TEST_check(group->meth->field_decode(group, c, c, ctx));
    }
    TEST_check(BN_is_one(c));

    /* 1/0 = error */
    BN_zero(a);
    TEST_check(!group->meth->field_inv(group, b, a, ctx));
    TEST_check(ERR_GET_LIB(ERR_peek_last_error()) == ERR_LIB_EC);
    TEST_check(ERR_GET_REASON(ERR_peek_last_error()) == EC_R_CANNOT_INVERT);

    /* 1/p = error */
    TEST_check(!group->meth->field_inv(group, b, group->field, ctx));
    TEST_check(ERR_GET_LIB(ERR_peek_last_error()) == ERR_LIB_EC);
    TEST_check(ERR_GET_REASON(ERR_peek_last_error()) == EC_R_CANNOT_INVERT);

    ERR_clear_error();
    ret = 1;

    BN_CTX_end(ctx);
    return ret;
}

#define EC_GROUP_set_curve(g,p,a,b,ctx) \
    EC_GROUP_set_curve_GFp(g,p,a,b,ctx)

/* wrapper for group_field_tests for explicit curve params and EC_METHOD */
static int field_tests(const EC_METHOD *meth, const unsigned char *params,
                       int len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL;
    int ret = 0;

    TEST_check(NULL != (ctx = BN_CTX_new()));

    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    TEST_check(NULL != (b = BN_CTX_get(ctx)));

    TEST_check(NULL != (group = EC_GROUP_new(meth)));
    TEST_check(BN_bin2bn(params, len, p));
    TEST_check(BN_bin2bn(params + len, len, a));
    TEST_check(BN_bin2bn(params + 2 * len, len, b));
    TEST_check(EC_GROUP_set_curve(group, p, a, b, ctx));
    TEST_check(group_field_tests(group, ctx));

    ret = 1;


    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    if (group != NULL)
        EC_GROUP_free(group);
    return ret;
}
#undef EC_GROUP_set_curve

/* NIST prime curve P-256 */
static const unsigned char params_p256[] = {
    /* p */
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* a */
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
    /* b */
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55,
    0x76, 0x98, 0x86, 0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
    0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
};

#ifndef OPENSSL_NO_EC2M
/* NIST binary curve B-283 */
static const unsigned char params_b283[] = {
    /* p */
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xA1,
    /* a */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    /* b */
    0x02, 0x7B, 0x68, 0x0A, 0xC8, 0xB8, 0x59, 0x6D, 0xA5, 0xA4, 0xAF, 0x8A,
    0x19, 0xA0, 0x30, 0x3F, 0xCA, 0x97, 0xFD, 0x76, 0x45, 0x30, 0x9F, 0xA2,
    0xA5, 0x81, 0x48, 0x5A, 0xF6, 0x26, 0x3E, 0x31, 0x3B, 0x79, 0xA2, 0xF5
};
#endif

/* test EC_GFp_simple_method directly */
static int field_tests_ecp_simple(void)
{
    fprintf(stdout, "Testing EC_GFp_simple_method()\n");
    return field_tests(EC_GFp_simple_method(), params_p256,
                       sizeof(params_p256) / 3);
}

/* test EC_GFp_mont_method directly */
static int field_tests_ecp_mont(void)
{
    fprintf(stdout, "Testing EC_GFp_mont_method()\n");
    return field_tests(EC_GFp_mont_method(), params_p256,
                       sizeof(params_p256) / 3);
}

#ifndef OPENSSL_NO_EC2M
/* test EC_GF2m_simple_method directly */
static int field_tests_ec2_simple(void)
{
    fprintf(stdout, "Testing EC_GF2m_simple_method()\n");
    return field_tests(EC_GF2m_simple_method(), params_b283,
                       sizeof(params_b283) / 3);
}
#endif

/* test default method for a named curve */
static int field_tests_default(int n)
{
    BN_CTX *ctx = NULL;
    EC_GROUP *group = NULL;
    int nid = curves[n].nid;
    int ret = 0;

    fprintf(stdout, "Testing curve %s\n", OBJ_nid2sn(nid));

    TEST_check(NULL != (group = EC_GROUP_new_by_curve_name(nid)));
    TEST_check(NULL != (ctx = BN_CTX_new()));
    TEST_check(group_field_tests(group, ctx));

    ret = 1;

    if (group != NULL)
        EC_GROUP_free(group);
    if (ctx != NULL)
        BN_CTX_free(ctx);
    return ret;
}

static int setup_tests(void)
{
    crv_len = EC_get_builtin_curves(NULL, 0);
    TEST_check(NULL != (curves = OPENSSL_malloc(sizeof(*curves) * crv_len)));
    TEST_check(EC_get_builtin_curves(curves, crv_len));

    ADD_TEST(field_tests_ecp_simple);
    ADD_TEST(field_tests_ecp_mont);
#ifndef OPENSSL_NO_EC2M
    ADD_TEST(field_tests_ec2_simple);
#endif
    ADD_ALL_TESTS(field_tests_default, crv_len);
    return 1;
}

static void cleanup_tests(void)
{
    OPENSSL_free(curves);
}

int main(int argc, char **argv)
{
    int ret;

    setup_tests();

    ret = run_tests(argv[0]);

    cleanup_tests();

    return ret;
}
