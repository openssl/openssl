/*
 * Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Low level APIs are deprecated for public use, but still ok for internal use.
 */
#include "internal/deprecated.h"

#include "internal/nelem.h"
#include "testutil.h"
#include <openssl/ec.h>
#include "ec_local.h"
#include <crypto/bn.h>
#include "crypto/fn.h"
#include "crypto/fn_intern.h"
#include <openssl/objects.h>

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
    if (!TEST_ptr(c = BN_CTX_get(ctx))
        /* 1/1 = 1 */
        || !TEST_true(group->meth->field_inv(group, b, BN_value_one(), ctx))
        || !TEST_true(BN_is_one(b))
        /* (1/a)*a = 1 */
        || !TEST_true(BN_rand(a, BN_num_bits(group->field) - 1,
            BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
        || !TEST_true(group->meth->field_inv(group, b, a, ctx))
        || (group->meth->field_encode && !TEST_true(group->meth->field_encode(group, a, a, ctx)))
        || (group->meth->field_encode && !TEST_true(group->meth->field_encode(group, b, b, ctx)))
        || !TEST_true(group->meth->field_mul(group, c, a, b, ctx))
        || (group->meth->field_decode && !TEST_true(group->meth->field_decode(group, c, c, ctx)))
        || !TEST_true(BN_is_one(c)))
        goto err;

    /* 1/0 = error */
    BN_zero(a);
    if (!TEST_false(group->meth->field_inv(group, b, a, ctx))
        || !TEST_true(ERR_GET_LIB(ERR_peek_last_error()) == ERR_LIB_EC)
        || !TEST_true(ERR_GET_REASON(ERR_peek_last_error()) == EC_R_CANNOT_INVERT)
        /* 1/p = error */
        || !TEST_false(group->meth->field_inv(group, b, group->field, ctx))
        || !TEST_true(ERR_GET_LIB(ERR_peek_last_error()) == ERR_LIB_EC)
        || !TEST_true(ERR_GET_REASON(ERR_peek_last_error()) == EC_R_CANNOT_INVERT))
        goto err;

    ERR_clear_error();
    ret = 1;
err:
    BN_CTX_end(ctx);
    return ret;
}

/* wrapper for group_field_tests for explicit curve params and EC_METHOD */
static int field_tests(const EC_METHOD *meth, const unsigned char *params,
    int len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL;
    int ret = 0;

    if (!TEST_ptr(ctx = BN_CTX_new()))
        return 0;

    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    if (!TEST_ptr(b = BN_CTX_get(ctx))
        || !TEST_ptr(group = EC_GROUP_new(meth))
        || !TEST_true(BN_bin2bn(params, len, p))
        || !TEST_true(BN_bin2bn(params + len, len, a))
        || !TEST_true(BN_bin2bn(params + 2 * len, len, b))
        || !TEST_true(EC_GROUP_set_curve(group, p, a, b, ctx))
        || !group_field_tests(group, ctx))
        goto err;
    ret = 1;

err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    if (group != NULL)
        EC_GROUP_free(group);
    return ret;
}

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
    TEST_info("Testing EC_GFp_simple_method()\n");
    return field_tests(EC_GFp_simple_method(), params_p256,
        sizeof(params_p256) / 3);
}

/* test EC_GFp_mont_method directly */
static int field_tests_ecp_mont(void)
{
    TEST_info("Testing EC_GFp_mont_method()\n");
    return field_tests(EC_GFp_mont_method(), params_p256,
        sizeof(params_p256) / 3);
}

#ifndef OPENSSL_NO_EC2M
/* Test that decoding of invalid GF2m field parameters fails. */
static int ec2m_field_sanity(void)
{
    int ret = 0;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p, *a, *b;
    EC_GROUP *group1 = NULL, *group2 = NULL, *group3 = NULL;

    TEST_info("Testing GF2m hardening\n");

    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    if (!TEST_ptr(b = BN_CTX_get(ctx))
        || !TEST_true(BN_one(a))
        || !TEST_true(BN_one(b)))
        goto out;

    /* Even pentanomial value should be rejected */
    if (!TEST_true(BN_set_word(p, 0xf2)))
        goto out;
    if (!TEST_ptr_null(group1 = EC_GROUP_new_curve_GF2m(p, a, b, ctx)))
        TEST_error("Zero constant term accepted in GF2m polynomial");

    /* Odd hexanomial should also be rejected */
    if (!TEST_true(BN_set_word(p, 0xf3)))
        goto out;
    if (!TEST_ptr_null(group2 = EC_GROUP_new_curve_GF2m(p, a, b, ctx)))
        TEST_error("Hexanomial accepted as GF2m polynomial");

    /* Excessive polynomial degree should also be rejected */
    if (!TEST_true(BN_set_word(p, 0x71))
        || !TEST_true(BN_set_bit(p, OPENSSL_ECC_MAX_FIELD_BITS + 1)))
        goto out;
    if (!TEST_ptr_null(group3 = EC_GROUP_new_curve_GF2m(p, a, b, ctx)))
        TEST_error("GF2m polynomial degree > %d accepted",
            OPENSSL_ECC_MAX_FIELD_BITS);

    ret = group1 == NULL && group2 == NULL && group3 == NULL;

out:
    EC_GROUP_free(group1);
    EC_GROUP_free(group2);
    EC_GROUP_free(group3);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}

/* test EC_GF2m_simple_method directly */
static int field_tests_ec2_simple(void)
{
    TEST_info("Testing EC_GF2m_simple_method()\n");
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

    TEST_info("Testing curve %s\n", OBJ_nid2sn(nid));

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(nid))
        || !TEST_ptr(ctx = BN_CTX_new())
        || !group_field_tests(group, ctx))
        goto err;

    ret = 1;
err:
    if (group != NULL)
        EC_GROUP_free(group);
    if (ctx != NULL)
        BN_CTX_free(ctx);
    return ret;
}

#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
/*
 * Tests a point known to cause an incorrect underflow in an old version of
 * ecp_nist521.c
 */
static int underflow_test(void)
{
    BN_CTX *ctx = NULL;
    EC_GROUP *grp = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x1 = NULL, *y1 = NULL, *z1 = NULL, *x2 = NULL, *y2 = NULL;
    BIGNUM *k = NULL;
    int testresult = 0;
    const char *x1str = "1534f0077fffffe87e9adcfe000000000000000000003e05a21d2400002e031b1f4"
                        "b80000c6fafa4f3c1288798d624a247b5e2ffffffffffffffefe099241900004";
    const char *p521m1 = "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                         "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe";

    ctx = BN_CTX_new();
    if (!TEST_ptr(ctx))
        return 0;

    BN_CTX_start(ctx);
    x1 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    z1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);
    k = BN_CTX_get(ctx);
    if (!TEST_ptr(k))
        goto err;

    grp = EC_GROUP_new_by_curve_name(NID_secp521r1);
    P = EC_POINT_new(grp);
    Q = EC_POINT_new(grp);
    R = EC_POINT_new(grp);
    if (!TEST_ptr(grp) || !TEST_ptr(P) || !TEST_ptr(Q) || !TEST_ptr(R))
        goto err;

    if (!TEST_int_gt(BN_hex2bn(&x1, x1str), 0)
        || !TEST_int_gt(BN_hex2bn(&y1, p521m1), 0)
        || !TEST_int_gt(BN_hex2bn(&z1, p521m1), 0)
        || !TEST_int_gt(BN_hex2bn(&k, "02"), 0)
        || !TEST_true(ossl_ec_GFp_simple_set_Jprojective_coordinates_GFp(grp, P, x1,
            y1, z1, ctx))
        || !TEST_true(EC_POINT_mul(grp, Q, NULL, P, k, ctx))
        || !TEST_true(EC_POINT_get_affine_coordinates(grp, Q, x1, y1, ctx))
        || !TEST_true(EC_POINT_dbl(grp, R, P, ctx))
        || !TEST_true(EC_POINT_get_affine_coordinates(grp, R, x2, y2, ctx)))
        goto err;

    if (!TEST_int_eq(BN_cmp(x1, x2), 0)
        || !TEST_int_eq(BN_cmp(y1, y2), 0))
        goto err;

    testresult = 1;

err:
    BN_CTX_end(ctx);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_GROUP_free(grp);
    BN_CTX_free(ctx);

    return testresult;
}
#endif

/*
 * Tests behavior of the EC_KEY_set_private_key
 */
static int set_private_key(void)
{
    EC_KEY *key = NULL, *aux_key = NULL;
    int testresult = 0;

    key = EC_KEY_new_by_curve_name(NID_secp224r1);
    aux_key = EC_KEY_new_by_curve_name(NID_secp224r1);
    if (!TEST_ptr(key)
        || !TEST_ptr(aux_key)
        || !TEST_int_eq(EC_KEY_generate_key(key), 1)
        || !TEST_int_eq(EC_KEY_generate_key(aux_key), 1))
        goto err;

    /* Test setting a valid private key */
    if (!TEST_int_eq(EC_KEY_set_private_key(key, aux_key->priv_key), 1))
        goto err;

    /* Test compliance with legacy behavior for NULL private keys */
    if (!TEST_int_eq(EC_KEY_set_private_key(key, NULL), 0)
        || !TEST_ptr_null(key->priv_key))
        goto err;

    testresult = 1;

err:
    EC_KEY_free(key);
    EC_KEY_free(aux_key);
    return testresult;
}

/*
 * Tests behavior of the decoded_from_explicit_params flag and API
 */
static int decoded_flag_test(void)
{
    EC_GROUP *grp;
    EC_GROUP *grp_copy = NULL;
    ECPARAMETERS *ecparams = NULL;
    ECPKPARAMETERS *ecpkparams = NULL;
    EC_KEY *key = NULL;
    unsigned char *encodedparams = NULL;
    const unsigned char *encp;
    int encodedlen;
    int testresult = 0;

    /* Test EC_GROUP_new not setting the flag */
    grp = EC_GROUP_new(EC_GFp_simple_method());
    if (!TEST_ptr(grp)
        || !TEST_int_eq(grp->decoded_from_explicit_params, 0))
        goto err;
    EC_GROUP_free(grp);

    /* Test EC_GROUP_new_by_curve_name not setting the flag */
    grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!TEST_ptr(grp)
        || !TEST_int_eq(grp->decoded_from_explicit_params, 0))
        goto err;

    /* Test EC_GROUP_new_from_ecparameters not setting the flag */
    if (!TEST_ptr(ecparams = EC_GROUP_get_ecparameters(grp, NULL))
        || !TEST_ptr(grp_copy = EC_GROUP_new_from_ecparameters(ecparams))
        || !TEST_int_eq(grp_copy->decoded_from_explicit_params, 0))
        goto err;
    EC_GROUP_free(grp_copy);
    grp_copy = NULL;
    ECPARAMETERS_free(ecparams);
    ecparams = NULL;

    /* Test EC_GROUP_new_from_ecpkparameters not setting the flag */
    if (!TEST_int_eq(EC_GROUP_get_asn1_flag(grp), OPENSSL_EC_NAMED_CURVE)
        || !TEST_ptr(ecpkparams = EC_GROUP_get_ecpkparameters(grp, NULL))
        || !TEST_ptr(grp_copy = EC_GROUP_new_from_ecpkparameters(ecpkparams))
        || !TEST_int_eq(grp_copy->decoded_from_explicit_params, 0)
        || !TEST_ptr(key = EC_KEY_new())
        /* Test EC_KEY_decoded_from_explicit_params on key without a group */
        || !TEST_int_eq(EC_KEY_decoded_from_explicit_params(key), -1)
        || !TEST_int_eq(EC_KEY_set_group(key, grp_copy), 1)
        /* Test EC_KEY_decoded_from_explicit_params negative case */
        || !TEST_int_eq(EC_KEY_decoded_from_explicit_params(key), 0))
        goto err;
    EC_GROUP_free(grp_copy);
    grp_copy = NULL;
    ECPKPARAMETERS_free(ecpkparams);
    ecpkparams = NULL;

    /* Test d2i_ECPKParameters with named params not setting the flag */
    if (!TEST_int_gt(encodedlen = i2d_ECPKParameters(grp, &encodedparams), 0)
        || !TEST_ptr(encp = encodedparams)
        || !TEST_ptr(grp_copy = d2i_ECPKParameters(NULL, &encp, encodedlen))
        || !TEST_int_eq(grp_copy->decoded_from_explicit_params, 0))
        goto err;
    EC_GROUP_free(grp_copy);
    grp_copy = NULL;
    OPENSSL_free(encodedparams);
    encodedparams = NULL;

    /* Asn1 flag stays set to explicit with EC_GROUP_new_from_ecpkparameters */
    EC_GROUP_set_asn1_flag(grp, OPENSSL_EC_EXPLICIT_CURVE);
    if (!TEST_ptr(ecpkparams = EC_GROUP_get_ecpkparameters(grp, NULL))
        || !TEST_ptr(grp_copy = EC_GROUP_new_from_ecpkparameters(ecpkparams))
        || !TEST_int_eq(EC_GROUP_get_asn1_flag(grp_copy), OPENSSL_EC_EXPLICIT_CURVE)
        || !TEST_int_eq(grp_copy->decoded_from_explicit_params, 0))
        goto err;
    EC_GROUP_free(grp_copy);
    grp_copy = NULL;

    /* Test d2i_ECPKParameters with explicit params setting the flag */
    if (!TEST_int_gt(encodedlen = i2d_ECPKParameters(grp, &encodedparams), 0)
        || !TEST_ptr(encp = encodedparams)
        || !TEST_ptr(grp_copy = d2i_ECPKParameters(NULL, &encp, encodedlen))
        || !TEST_int_eq(EC_GROUP_get_asn1_flag(grp_copy), OPENSSL_EC_EXPLICIT_CURVE)
        || !TEST_int_eq(grp_copy->decoded_from_explicit_params, 1)
        || !TEST_int_eq(EC_KEY_set_group(key, grp_copy), 1)
        /* Test EC_KEY_decoded_from_explicit_params positive case */
        || !TEST_int_eq(EC_KEY_decoded_from_explicit_params(key), 1))
        goto err;

    testresult = 1;

err:
    EC_KEY_free(key);
    EC_GROUP_free(grp);
    EC_GROUP_free(grp_copy);
    ECPARAMETERS_free(ecparams);
    ECPKPARAMETERS_free(ecpkparams);
    OPENSSL_free(encodedparams);

    return testresult;
}

static int ecpkparams_i2d2i_test(int n)
{
    EC_GROUP *g1 = NULL, *g2 = NULL;
    FILE *fp = NULL;
    int nid = curves[n].nid;
    int testresult = 0;

    /* create group */
    if (!TEST_ptr(g1 = EC_GROUP_new_by_curve_name(nid)))
        goto end;

    /* encode params to file */
    if (!TEST_ptr(fp = fopen("params.der", "wb"))
        || !TEST_true(i2d_ECPKParameters_fp(fp, g1)))
        goto end;

    /* flush and close file */
    if (!TEST_int_eq(fclose(fp), 0)) {
        fp = NULL;
        goto end;
    }
    fp = NULL;

    /* decode params from file */
    if (!TEST_ptr(fp = fopen("params.der", "rb"))
        || !TEST_ptr(g2 = d2i_ECPKParameters_fp(fp, NULL)))
        goto end;

    testresult = 1; /* PASS */

end:
    if (fp != NULL)
        fclose(fp);

    EC_GROUP_free(g1);
    EC_GROUP_free(g2);

    return testresult;
}

static int check_bn_mont_ctx(BN_MONT_CTX *mont, BIGNUM *mod, BN_CTX *ctx)
{
    int ret = 0;
    BN_MONT_CTX *regenerated = BN_MONT_CTX_new();

    if (!TEST_ptr(regenerated))
        return ret;
    if (!TEST_ptr(mont))
        goto err;

    if (!TEST_true(BN_MONT_CTX_set(regenerated, mod, ctx)))
        goto err;

    if (!TEST_true(ossl_bn_mont_ctx_eq(regenerated, mont)))
        goto err;

    ret = 1;

err:
    BN_MONT_CTX_free(regenerated);
    return ret;
}

static int montgomery_correctness_test(EC_GROUP *group)
{
    int ret = 0;
    BN_CTX *ctx = NULL;

    ctx = BN_CTX_new();
    if (!TEST_ptr(ctx))
        return ret;
    if (!TEST_true(check_bn_mont_ctx(group->mont_data, group->order, ctx))) {
        TEST_error("group order issue");
        goto err;
    }
    if (group->field_data1 != NULL) {
        if (!TEST_true(check_bn_mont_ctx(group->field_data1, group->field, ctx)))
            goto err;
    }
    ret = 1;
err:
    BN_CTX_free(ctx);
    return ret;
}

static int named_group_creation_test(void)
{
    int ret = 0;
    EC_GROUP *group = NULL;

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1))
        || !TEST_true(montgomery_correctness_test(group)))
        goto err;

    ret = 1;

err:
    EC_GROUP_free(group);
    return ret;
}

static const int fn_ladder_curves[] = {
    NID_X9_62_prime256v1, /* nistz256/nistp256 mul_fn (or mont ladder) */
    NID_brainpoolP256r1, /* mont ladder */
    NID_secp224r1, /* nistp224 mul_fn, when built */
    NID_secp384r1, /* nistp384 mul_fn, when built */
    NID_secp521r1, /* nistp521 mul_fn, when built */
#ifndef OPENSSL_NO_SM2
    NID_sm2, /* sm2p256 mul_fn on ECP_SM2P256_ASM targets; mont ladder elsewhere */
#endif
};

/* Zero the limbs above 'top', widening to w limbs; caller ensures value public. */
static int clean_above_top(BIGNUM *bn, int w)
{
    BN_ULONG *d;
    int i, dmax;

    if (bn_wexpand(bn, w) == NULL)
        return 0;
    d = bn_get_words(bn);
    dmax = bn_get_dmax(bn);
    for (i = bn_get_top(bn); i < dmax; i++)
        d[i] = 0;
    return 1;
}

static int clean_point(EC_POINT *P, int w)
{
    return clean_above_top(P->X, w) && clean_above_top(P->Y, w)
        && clean_above_top(P->Z, w);
}

/*
 * ossl_ec_point_ladder_step_fn() must reproduce, bit for bit, the output of
 * the BIGNUM ossl_ec_GFp_simple_ladder_step() from the same ladder state.
 */
static int test_ladder_step_fn(int idx)
{
    int ret = 0, w;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *r0 = NULL, *s0 = NULL;
    EC_POINT *r1 = NULL, *s1 = NULL, *r2 = NULL, *s2 = NULL;
    BIGNUM *k = NULL;
    OSSL_FN_CTX *fnctx = NULL;
    BN_CTX *ctx = NULL;

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(fn_ladder_curves[idx])))
        return 0;
    if (group->fn_mont_ctx == NULL) { /* not a Montgomery-representation method */
        EC_GROUP_free(group);
        return 1;
    }

    w = (int)ossl_fn_get_dsize(bn_get_ossl_fn(group->field));
    if (!TEST_true(clean_above_top(group->field, w))
        || !TEST_true(clean_above_top(group->a, w))
        || !TEST_true(clean_above_top(group->b, w)))
        goto err;
    w = (int)ossl_fn_get_dsize(bn_get_ossl_fn(group->field));

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(fnctx = OSSL_FN_CTX_secure_new_size(NULL,
                         ossl_ec_point_ladder_step_fn_ctx_size(group, 0, 0, 0)))
        || !TEST_ptr(k = BN_new())
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(r0 = EC_POINT_new(group)) || !TEST_ptr(s0 = EC_POINT_new(group))
        || !TEST_ptr(r1 = EC_POINT_new(group)) || !TEST_ptr(s1 = EC_POINT_new(group))
        || !TEST_ptr(r2 = EC_POINT_new(group)) || !TEST_ptr(s2 = EC_POINT_new(group)))
        goto err;

    /* Build a valid ladder state (r0, s0) from an affine base point P. */
    if (!TEST_true(BN_set_word(k, 0xC0FFEE))
        || !TEST_true(EC_POINT_mul(group, P, k, NULL, NULL, NULL))
        || !TEST_true(EC_POINT_make_affine(group, P, NULL))
        || !TEST_true(ossl_ec_GFp_simple_ladder_pre(group, r0, s0, P, ctx)))
        goto err;

    if (!TEST_true(EC_POINT_copy(r1, r0)) || !TEST_true(EC_POINT_copy(s1, s0))
        || !TEST_true(EC_POINT_copy(r2, r0)) || !TEST_true(EC_POINT_copy(s2, s0)))
        goto err;

    /* OSSL_FN side needs clean, w-wide coordinates. */
    if (!TEST_true(clean_point(r2, w)) || !TEST_true(clean_point(s2, w))
        || !TEST_true(clean_point(P, w)))
        goto err;

    if (!TEST_true(ossl_ec_GFp_simple_ladder_step(group, r1, s1, P, ctx))
        || !TEST_true(ossl_ec_point_ladder_step_fn(group, r2, s2, P, fnctx)))
        goto err;

    /* x-only step: compare the X and Z coordinates of both r and s. */
    if (!TEST_int_eq(BN_cmp(r1->X, r2->X), 0)
        || !TEST_int_eq(BN_cmp(r1->Z, r2->Z), 0)
        || !TEST_int_eq(BN_cmp(s1->X, s2->X), 0)
        || !TEST_int_eq(BN_cmp(s1->Z, s2->Z), 0))
        goto err;

    ret = 1;
err:
    OSSL_FN_CTX_free(fnctx);
    BN_CTX_free(ctx);
    BN_free(k);
    EC_POINT_free(P);
    EC_POINT_free(r0);
    EC_POINT_free(s0);
    EC_POINT_free(r1);
    EC_POINT_free(s1);
    EC_POINT_free(r2);
    EC_POINT_free(s2);
    EC_GROUP_free(group);
    return ret;
}

/*
 * ossl_ec_point_ladder_pre_fn() must set up a valid x-only ladder state:
 * r represents 2P and s represents P.  Blinding randomises the coordinates but
 * preserves the affine x = X/Z, so we compare x(r) against x(2P) and x(s)
 * against x(P).  (r and s carry no meaningful Y after pre, so y is ignored.)
 */
static int test_ladder_pre_fn(int idx)
{
    int ret = 0, w;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *dbl = NULL, *r = NULL, *s = NULL;
    BIGNUM *k = NULL, *xexp = NULL, *xgot = NULL, *zi = NULL;
    OSSL_FN_CTX *fnctx = NULL;
    BN_CTX *ctx = NULL;

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(fn_ladder_curves[idx])))
        return 0;
    if (group->fn_mont_ctx == NULL) {
        EC_GROUP_free(group);
        return 1;
    }

    w = (int)ossl_fn_get_dsize(bn_get_ossl_fn(group->field));
    if (!TEST_true(clean_above_top(group->field, w))
        || !TEST_true(clean_above_top(group->a, w))
        || !TEST_true(clean_above_top(group->b, w)))
        goto err;
    w = (int)ossl_fn_get_dsize(bn_get_ossl_fn(group->field));

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(fnctx = OSSL_FN_CTX_secure_new_size(NULL,
                         ossl_ec_point_ladder_pre_fn_ctx_size(group, NULL, NULL, NULL)))
        || !TEST_ptr(k = BN_new())
        || !TEST_ptr(xexp = BN_new()) || !TEST_ptr(xgot = BN_new())
        || !TEST_ptr(zi = BN_new())
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(dbl = EC_POINT_new(group))
        || !TEST_ptr(r = EC_POINT_new(group)) || !TEST_ptr(s = EC_POINT_new(group)))
        goto err;

    if (!TEST_true(BN_set_word(k, 0xBADF00D))
        || !TEST_true(EC_POINT_mul(group, P, k, NULL, NULL, NULL))
        || !TEST_true(EC_POINT_make_affine(group, P, NULL))
        || !TEST_true(EC_POINT_dbl(group, dbl, P, NULL))) /* expected 2P */
        goto err;

    if (!TEST_true(clean_point(P, w)))
        goto err;

    if (!TEST_true(ossl_ec_point_ladder_pre_fn(group, r, s, P, fnctx)))
        goto err;

    /*
     * Ladder points are (X:Z) homogeneous with affine x = X/Z, so recover x by
     * hand via the field methods -- EC_POINT_get_affine_coordinates() would use
     * the Jacobian x = X/Z^2 convention and disagree.  2P and P are ordinary
     * (affine) points, so their x comes from get_affine_coordinates().
     */
    /* x(r) == x(2P); field_inv works in the plain domain, so decode/encode. */
    if (!TEST_true(EC_POINT_get_affine_coordinates(group, dbl, xexp, NULL, ctx))
        || !TEST_true(group->meth->field_decode(group, zi, r->Z, ctx))
        || !TEST_true(group->meth->field_inv(group, zi, zi, ctx))
        || !TEST_true(group->meth->field_encode(group, zi, zi, ctx))
        || !TEST_true(group->meth->field_mul(group, xgot, r->X, zi, ctx))
        || !TEST_true(group->meth->field_decode(group, xgot, xgot, ctx))
        || !TEST_int_eq(BN_cmp(xexp, xgot), 0))
        goto err;

    /* x(s) == x(P) */
    if (!TEST_true(EC_POINT_get_affine_coordinates(group, P, xexp, NULL, ctx))
        || !TEST_true(group->meth->field_decode(group, zi, s->Z, ctx))
        || !TEST_true(group->meth->field_inv(group, zi, zi, ctx))
        || !TEST_true(group->meth->field_encode(group, zi, zi, ctx))
        || !TEST_true(group->meth->field_mul(group, xgot, s->X, zi, ctx))
        || !TEST_true(group->meth->field_decode(group, xgot, xgot, ctx))
        || !TEST_int_eq(BN_cmp(xexp, xgot), 0))
        goto err;

    ret = 1;
err:
    OSSL_FN_CTX_free(fnctx);
    BN_CTX_free(ctx);
    BN_free(k);
    BN_free(xexp);
    BN_free(xgot);
    BN_free(zi);
    EC_POINT_free(P);
    EC_POINT_free(dbl);
    EC_POINT_free(r);
    EC_POINT_free(s);
    EC_GROUP_free(group);
    return ret;
}

/*
 * ossl_ec_point_ladder_post_fn() must reproduce the affine point recovered
 * by the BIGNUM ossl_ec_GFp_simple_ladder_post() from the same final ladder
 * state.  We build a genuine state (BIGNUM pre + a few steps) and run both
 * posts on identical copies.
 */
static int test_ladder_post_fn(int idx)
{
    int ret = 0, w, i;
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL, *r0 = NULL, *s0 = NULL;
    EC_POINT *r1 = NULL, *s1 = NULL, *r2 = NULL, *s2 = NULL;
    BIGNUM *k = NULL;
    OSSL_FN_CTX *fnctx = NULL;
    BN_CTX *ctx = NULL;

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(fn_ladder_curves[idx])))
        return 0;
    if (group->fn_mont_ctx == NULL) {
        EC_GROUP_free(group);
        return 1;
    }

    w = (int)ossl_fn_get_dsize(bn_get_ossl_fn(group->field));
    if (!TEST_true(clean_above_top(group->field, w))
        || !TEST_true(clean_above_top(group->a, w))
        || !TEST_true(clean_above_top(group->b, w)))
        goto err;
    w = (int)ossl_fn_get_dsize(bn_get_ossl_fn(group->field));

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(fnctx = OSSL_FN_CTX_secure_new_size(NULL,
                         ossl_ec_point_ladder_post_fn_ctx_size(group, NULL, NULL, NULL)))
        || !TEST_ptr(k = BN_new())
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(r0 = EC_POINT_new(group)) || !TEST_ptr(s0 = EC_POINT_new(group))
        || !TEST_ptr(r1 = EC_POINT_new(group)) || !TEST_ptr(s1 = EC_POINT_new(group))
        || !TEST_ptr(r2 = EC_POINT_new(group)) || !TEST_ptr(s2 = EC_POINT_new(group)))
        goto err;

    if (!TEST_true(BN_set_word(k, 0x1234567))
        || !TEST_true(EC_POINT_mul(group, P, k, NULL, NULL, NULL))
        || !TEST_true(EC_POINT_make_affine(group, P, NULL))
        || !TEST_true(ossl_ec_GFp_simple_ladder_pre(group, r0, s0, P, ctx)))
        goto err;
    for (i = 0; i < 5; i++)
        if (!TEST_true(ossl_ec_GFp_simple_ladder_step(group, r0, s0, P, ctx)))
            goto err;

    if (!TEST_true(EC_POINT_copy(r1, r0)) || !TEST_true(EC_POINT_copy(s1, s0))
        || !TEST_true(EC_POINT_copy(r2, r0)) || !TEST_true(EC_POINT_copy(s2, s0)))
        goto err;

    if (!TEST_true(clean_point(r2, w)) || !TEST_true(clean_point(s2, w))
        || !TEST_true(clean_point(P, w)))
        goto err;

    if (!TEST_true(ossl_ec_GFp_simple_ladder_post(group, r1, s1, P, ctx))
        || !TEST_true(ossl_ec_point_ladder_post_fn(group, r2, s2, P, fnctx)))
        goto err;

    if (!TEST_int_eq(EC_POINT_cmp(group, r1, r2, ctx), 0))
        goto err;

    ret = 1;
err:
    OSSL_FN_CTX_free(fnctx);
    BN_CTX_free(ctx);
    BN_free(k);
    EC_POINT_free(P);
    EC_POINT_free(r0);
    EC_POINT_free(s0);
    EC_POINT_free(r1);
    EC_POINT_free(s1);
    EC_POINT_free(r2);
    EC_POINT_free(s2);
    EC_GROUP_free(group);
    return ret;
}

/*
 * End-to-end check that EC_POINT_mul_fn() agrees with the BIGNUM
 * EC_POINT_mul() for both k*G and k*P, over several random scalars.  For the
 * plain Montgomery method this exercises ossl_ec_scalar_mul_ladder_fn() and the
 * ossl_ec_GFp_mont_ladder_*_fn helpers; for methods with a specialised mul_fn
 * (nistz256, nistp*) it exercises that.
 */
static int fn_check_scalar_mul(EC_GROUP *group)
{
    int ret = 0, iter;
    EC_POINT *P = NULL, *R1 = NULL, *R2 = NULL;
    const BIGNUM *order;
    BIGNUM *k = NULL;
    BN_CTX *ctx = NULL;
    OSSL_FN_CTX *fnctx = NULL;
    size_t fnsz;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(k = BN_new())
        || !TEST_ptr(order = EC_GROUP_get0_order(group))
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(R1 = EC_POINT_new(group))
        || !TEST_ptr(R2 = EC_POINT_new(group)))
        goto err;

    /*
     * EC_POINT_mul_fn() serves only groups with a method mul_fn or (via the
     * generic ladder) Montgomery-representation groups.  Any other group
     * (plain-representation methods without a mul_fn, e.g. EC_GFp_nist_method,
     * which NIST primes fall back to on no-asm targets) has no OSSL_FN
     * scalar-mult path - nothing to check for it.
     */
    if (group->meth->mul_fn == NULL && group->fn_mont_ctx == NULL) {
        ret = 1;
        goto err;
    }
    /* A group with a path must size successfully; a 0 here is a real error. */
    fnsz = EC_POINT_mul_fn_ctx_size(group, NULL, NULL, NULL);
    if (!TEST_size_t_ne(fnsz, 0))
        goto err;
    /* Pre-size a caller-owned arena to exercise the non-NULL ctx path too. */
    if (fnsz != OSSL_FN_CTX_SIZE_NONE
        && !TEST_ptr(fnctx = OSSL_FN_CTX_secure_new_size(NULL, fnsz)))
        goto err;

    /* A fixed random base point P for the variable-point checks. */
    if (!TEST_true(BN_rand_range(k, order))
        || !TEST_true(EC_POINT_mul(group, P, k, NULL, NULL, ctx)))
        goto err;

    /* Alternate a NULL and a caller-provided arena to cover both ctx paths. */
    for (iter = 0; iter < 16; iter++) {
        OSSL_FN_CTX *c = (iter & 1) ? fnctx : NULL;

        if (!TEST_true(BN_rand_range(k, order))
            || !TEST_true(EC_POINT_mul(group, R1, k, NULL, NULL, ctx))
            || !TEST_true(EC_POINT_mul_fn(group, R2, bn_get_ossl_fn(k), NULL, c))
            || !TEST_int_eq(EC_POINT_cmp(group, R1, R2, ctx), 0))
            goto err;

        if (!TEST_true(BN_rand_range(k, order))
            || !TEST_true(EC_POINT_mul(group, R1, NULL, P, k, ctx))
            || !TEST_true(EC_POINT_mul_fn(group, R2, bn_get_ossl_fn(k), P, c))
            || !TEST_int_eq(EC_POINT_cmp(group, R1, R2, ctx), 0))
            goto err;
    }

    ret = 1;
err:
    OSSL_FN_CTX_free(fnctx);
    BN_free(k);
    EC_POINT_free(P);
    EC_POINT_free(R1);
    EC_POINT_free(R2);
    BN_CTX_free(ctx);
    return ret;
}

static int test_scalar_mul_fn(int idx)
{
    int ret;
    EC_GROUP *group = NULL;

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(fn_ladder_curves[idx])))
        return 0;

    ret = fn_check_scalar_mul(group);
    EC_GROUP_free(group);
    return ret;
}

#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
/*
 * Rebuild a named curve's parameters into a group that uses the given method,
 * so a method not selected for any built-in curve on this platform (e.g.
 * nistp256 when the nistz256 assembly is present) can still be exercised.
 */
static EC_GROUP *fn_clone_group_with_method(int nid, const EC_METHOD *meth)
{
    EC_GROUP *src = NULL, *dst = NULL, *ret = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *gx = NULL, *gy = NULL;
    const BIGNUM *order, *cofactor;
    const EC_POINT *g;
    EC_POINT *gpt = NULL;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(src = EC_GROUP_new_by_curve_name(nid))
        || !TEST_ptr(p = BN_new()) || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new()) || !TEST_ptr(gx = BN_new())
        || !TEST_ptr(gy = BN_new())
        || !TEST_true(EC_GROUP_get_curve(src, p, a, b, ctx))
        || !TEST_ptr(order = EC_GROUP_get0_order(src))
        || !TEST_ptr(cofactor = EC_GROUP_get0_cofactor(src))
        || !TEST_ptr(g = EC_GROUP_get0_generator(src))
        || !TEST_true(EC_POINT_get_affine_coordinates(src, g, gx, gy, ctx))
        || !TEST_ptr(dst = EC_GROUP_new(meth))
        || !TEST_true(EC_GROUP_set_curve(dst, p, a, b, ctx))
        || !TEST_ptr(gpt = EC_POINT_new(dst))
        || !TEST_true(EC_POINT_set_affine_coordinates(dst, gpt, gx, gy, ctx))
        || !TEST_true(EC_GROUP_set_generator(dst, gpt, order, cofactor)))
        goto err;
    ret = dst;
    dst = NULL;
err:
    EC_POINT_free(gpt);
    EC_GROUP_free(dst);
    EC_GROUP_free(src);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(gx);
    BN_free(gy);
    BN_CTX_free(ctx);
    return ret;
}

/*
 * nistp256's method is not selected for any built-in curve when nistz256 is
 * present, so exercise its mul_fn on a P-256 group built explicitly with it.
 */
static int test_scalar_mul_fn_nistp256(void)
{
    int ret;
    EC_GROUP *group = fn_clone_group_with_method(NID_X9_62_prime256v1,
        EC_GFp_nistp256_method());

    if (group == NULL)
        return 0;
    ret = fn_check_scalar_mul(group);
    EC_GROUP_free(group);
    return ret;
}
#endif /* OPENSSL_NO_EC_NISTP_64_GCC_128 */

int setup_tests(void)
{
    crv_len = EC_get_builtin_curves(NULL, 0);
    if (!TEST_ptr(curves = OPENSSL_malloc_array(crv_len, sizeof(*curves)))
        || !TEST_true(EC_get_builtin_curves(curves, crv_len)))
        return 0;

    ADD_TEST(field_tests_ecp_simple);
    ADD_TEST(field_tests_ecp_mont);
#ifndef OPENSSL_NO_EC2M
    ADD_TEST(ec2m_field_sanity);
    ADD_TEST(field_tests_ec2_simple);
#endif
    ADD_ALL_TESTS(field_tests_default, (int)crv_len);
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
    ADD_TEST(underflow_test);
#endif
    ADD_TEST(set_private_key);
    ADD_TEST(decoded_flag_test);
    ADD_ALL_TESTS(ecpkparams_i2d2i_test, (int)crv_len);
    ADD_TEST(named_group_creation_test);
    ADD_ALL_TESTS(test_ladder_step_fn, OSSL_NELEM(fn_ladder_curves));
    ADD_ALL_TESTS(test_ladder_pre_fn, OSSL_NELEM(fn_ladder_curves));
    ADD_ALL_TESTS(test_ladder_post_fn, OSSL_NELEM(fn_ladder_curves));
    ADD_ALL_TESTS(test_scalar_mul_fn, OSSL_NELEM(fn_ladder_curves));
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
    ADD_TEST(test_scalar_mul_fn_nistp256);
#endif

    return 1;
}

void cleanup_tests(void)
{
    OPENSSL_free(curves);
}
