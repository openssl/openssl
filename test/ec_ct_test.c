/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Constant-time tests for the EC private-key arithmetic that runs outside
 * the scalar multiplication: ECDSA and SM2 signing, and the conversion of a
 * secret projective point (an ECDH shared point, an SM2 kP) to bytes.
 *
 * When built with enable-ct-validation, CONSTTIME_SECRET marks the secrets
 * as undefined for Valgrind's memcheck, so any branch or memory index derived
 * from them makes Valgrind exit non-zero.  Outside a CT build the macros are
 * no-ops and this is an ordinary functional test.
 */

/* Low level APIs are deprecated for public use, but still ok for internal use */
#include "internal/deprecated.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include "crypto/bn.h"
#include "crypto/ec.h"
#include "crypto/sm2.h"
#include "ec_local.h"
#include "internal/constant_time.h"
#include "internal/nelem.h"
#include "testutil.h"

static const int curves[] = {
    NID_X9_62_prime256v1,
    NID_secp384r1,
    NID_secp521r1,
    NID_secp256k1,
};

static void bn_secret(const BIGNUM *bn)
{
    CONSTTIME_SECRET(bn_get_words(bn), bn_get_dmax(bn) * sizeof(BN_ULONG));
}

static void bn_declassify(const BIGNUM *bn)
{
    CONSTTIME_DECLASSIFY(bn_get_words(bn), bn_get_dmax(bn) * sizeof(BN_ULONG));
}

/*
 * ECDSA s = kinv * (r * d + m) mod n, with the setup values supplied so that
 * only this computation runs on the secret d and kinv.
 */
static int test_ecdsa_sign_sig(int idx)
{
    static const unsigned char dgst[32] = {
        0x9a, 0x3b, 0x77, 0x10, 0x5e, 0xc2, 0x41, 0xfe,
        0x08, 0xd6, 0x2b, 0x93, 0x6f, 0xa4, 0x1c, 0x55,
        0xe0, 0x37, 0x8c, 0x29, 0xb1, 0x4d, 0xf2, 0x66,
        0x03, 0xca, 0x98, 0x7e, 0x45, 0x1b, 0xd9, 0x80
    };
    EC_KEY *key = NULL;
    BIGNUM *kinv = NULL, *r = NULL;
    ECDSA_SIG *sig = NULL;
    const BIGNUM *priv;
    int ret = 0;

    if (!TEST_ptr(key = EC_KEY_new_by_curve_name(curves[idx]))
        || !TEST_true(EC_KEY_generate_key(key))
        || !TEST_true(ECDSA_sign_setup(key, NULL, &kinv, &r))
        || !TEST_ptr(priv = EC_KEY_get0_private_key(key)))
        goto err;

    bn_secret(priv);
    bn_secret(kinv);
    sig = ECDSA_do_sign_ex(dgst, sizeof(dgst), kinv, r, key);
    bn_declassify(priv);
    bn_declassify(kinv);

    if (!TEST_ptr(sig)
        || !TEST_int_eq(ECDSA_do_verify(dgst, sizeof(dgst), sig, key), 1))
        goto err;

    ret = 1;
err:
    if (!ret)
        TEST_info("curve %s", OBJ_nid2sn(curves[idx]));
    ECDSA_SIG_free(sig);
    BN_clear_free(kinv);
    BN_free(r);
    EC_KEY_free(key);
    return ret;
}

/* The affine conversion is done by each GF(p) method; cover each kind */
static const int prime_curves[] = {
    NID_secp224r1,
    NID_X9_62_prime256v1,
    NID_secp384r1,
    NID_secp521r1,
    NID_secp256k1,
#ifndef OPENSSL_NO_SM2
    NID_sm2,
#endif
};

/*
 * Mark the projective coordinates of a random point on @group secret, extract
 * its affine coordinates as fixed-width bytes, and check them against the
 * reference.  Under ct-validation Valgrind fails on any branch or memory index
 * derived from a coordinate.
 */
static int check_point_to_bytes(EC_GROUP *group)
{
    EC_POINT *P = NULL;
    BIGNUM *k = NULL, *x = NULL, *y = NULL;
    unsigned char rx[66], ry[66], gx[66], gy[66];
    size_t flen = 0;
    int ret = 0;

    if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(k = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new()))
        goto err;
    flen = (size_t)((EC_GROUP_get_degree(group) + 7) / 8);

    /* A random point, doubled to obtain a projective (Z != 1) one */
    if (!TEST_size_t_le(flen, sizeof(rx))
        || !TEST_true(BN_rand_range(k, EC_GROUP_get0_order(group)))
        || !TEST_true(EC_POINT_mul(group, P, k, NULL, NULL, NULL))
        || !TEST_true(EC_POINT_dbl(group, P, P, NULL))
        || !TEST_int_eq(P->Z_is_one, 0)
        || !TEST_true(EC_POINT_get_affine_coordinates(group, P, x, y, NULL))
        || !TEST_int_ge(BN_bn2binpad(x, rx, (int)flen), 0)
        || !TEST_int_ge(BN_bn2binpad(y, ry, (int)flen), 0))
        goto err;

    bn_secret(P->X);
    bn_secret(P->Y);
    bn_secret(P->Z);
    ret = EC_POINT_get_affine_coords_bytes(group, P, gx, gy, flen);
    bn_declassify(P->X);
    bn_declassify(P->Y);
    bn_declassify(P->Z);
    CONSTTIME_DECLASSIFY(gx, flen);
    CONSTTIME_DECLASSIFY(gy, flen);

    if (!TEST_true(ret)
        || !TEST_mem_eq(gx, flen, rx, flen)
        || !TEST_mem_eq(gy, flen, ry, flen))
        ret = 0;
err:
    BN_free(k);
    BN_free(x);
    BN_free(y);
    EC_POINT_free(P);
    return ret;
}

static int test_point_to_bytes(int idx)
{
    EC_GROUP *group = NULL;
    int ret = 0;

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(prime_curves[idx])))
        goto err;
    ret = check_point_to_bytes(group);
err:
    if (!ret)
        TEST_info("curve %s", OBJ_nid2sn(prime_curves[idx]));
    EC_GROUP_free(group);
    return ret;
}

#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
/* Rebuild a built-in curve's group with a specific method. */
static EC_GROUP *clone_group_with_method(int nid, const EC_METHOD *meth)
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
 * When nistz256 is present prime256v1 uses it, so the nistp256 method is not
 * reached through any curve name on an assembly build (only the no-asm matrix
 * entries reach it, through prime256v1).  Force it so its field inverse is
 * ct-validated regardless of the build.
 */
static int test_point_to_bytes_nistp256(void)
{
    EC_GROUP *group = clone_group_with_method(NID_X9_62_prime256v1,
        EC_GFp_nistp256_method());
    int ret;

    if (group == NULL)
        return 0;
    ret = check_point_to_bytes(group);
    EC_GROUP_free(group);
    return ret;
}
#endif /* OPENSSL_NO_EC_NISTP_64_GCC_128 */

#ifndef OPENSSL_NO_SM2
/* SM2 s = (1 + dA)^-1 * (k - r * dA) mod n, on the secret dA */
static int test_sm2_sign(void)
{
    static const uint8_t id[] = "alice@example.com";
    static const uint8_t msg[] = "message digest";
    EC_KEY *key = NULL;
    ECDSA_SIG *sig = NULL;
    const BIGNUM *priv;
    int ret = 0;

    if (!TEST_ptr(key = EC_KEY_new_by_curve_name(NID_sm2))
        || !TEST_true(EC_KEY_generate_key(key))
        || !TEST_ptr(priv = EC_KEY_get0_private_key(key)))
        goto err;

    bn_secret(priv);
    sig = ossl_sm2_do_sign(key, EVP_sm3(), id, sizeof(id) - 1, msg,
        sizeof(msg) - 1);
    bn_declassify(priv);

    if (!TEST_ptr(sig)
        || !TEST_int_eq(ossl_sm2_do_verify(key, EVP_sm3(), sig, id,
                            sizeof(id) - 1, msg, sizeof(msg) - 1),
            1))
        goto err;

    ret = 1;
err:
    ECDSA_SIG_free(sig);
    EC_KEY_free(key);
    return ret;
}
#endif

int setup_tests(void)
{
    ADD_ALL_TESTS(test_ecdsa_sign_sig, (int)OSSL_NELEM(curves));
    ADD_ALL_TESTS(test_point_to_bytes, (int)OSSL_NELEM(prime_curves));
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
    ADD_TEST(test_point_to_bytes_nistp256);
#endif
#ifndef OPENSSL_NO_SM2
    ADD_TEST(test_sm2_sign);
#endif
    return 1;
}
