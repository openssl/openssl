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
 * the scalar multiplication.
 *
 * When built with enable-ct-validation, CONSTTIME_SECRET marks the secrets
 * as undefined for Valgrind's memcheck, so any branch or memory index derived
 * from them makes Valgrind exit non-zero.  Outside a CT build the macros are
 * no-ops and this is an ordinary functional test.
 */

/* Low level APIs are deprecated for public use, but still ok for internal use */
#include "internal/deprecated.h"

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include "crypto/bn.h"
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

int setup_tests(void)
{
    ADD_ALL_TESTS(test_ecdsa_sign_sig, (int)OSSL_NELEM(curves));
    return 1;
}
