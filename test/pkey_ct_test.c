/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * End-to-end constant-time tests for private-key operations, run through the
 * EVP API on provider keys.  Covered so far: DH and DHX.
 *
 * Two kinds of secret are marked with CONSTTIME_SECRET: the limbs of the
 * private key, after it has been loaded, and every byte the private DRBG
 * returns, so that nonces are secret from the moment they are drawn.  The
 * public DRBG is left alone.  When built with enable-ct-validation, any
 * branch or memory index derived from either makes Valgrind's memcheck exit
 * non-zero.  Outside a CT build the macros are no-ops and this is an
 * ordinary functional test.
 *
 * The length of the private key (its BIGNUM's top) is treated as public: it
 * is not marked.  For a key of the size of the group order it reveals
 * nothing in all but a negligible fraction of keys.
 */

/* Low level APIs are deprecated for public use, but still ok for internal use */
#include "internal/deprecated.h"

#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include "crypto/bn.h"
#include "crypto/evp.h"
#include "internal/constant_time.h"
#include "internal/nelem.h"
#include "testutil.h"

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *fake_rand = NULL;
static int taint_rng = 0;

/* Real random bytes from the default library context, secret on request */
static int private_rng(unsigned char *out, size_t outlen,
    ossl_unused const char *name, ossl_unused EVP_RAND_CTX *ctx)
{
    if (RAND_priv_bytes_ex(NULL, out, outlen, 0) <= 0)
        return 0;
    if (taint_rng) {
        CONSTTIME_SECRET(out, outlen);
    }
    return 1;
}

static int public_rng(unsigned char *out, size_t outlen,
    ossl_unused const char *name, ossl_unused EVP_RAND_CTX *ctx)
{
    return RAND_bytes_ex(NULL, out, outlen, 0) > 0;
}

#ifndef OPENSSL_NO_DH
static void bn_secret(const BIGNUM *bn, int on)
{
    if (on) {
        CONSTTIME_SECRET(bn_get_words(bn), bn_get_dmax(bn) * sizeof(BN_ULONG));
    } else {
        CONSTTIME_DECLASSIFY(bn_get_words(bn),
            bn_get_dmax(bn) * sizeof(BN_ULONG));
    }
}

/* The private key held by the provider, not a legacy copy of it */
static const BIGNUM *priv_bn(const EVP_PKEY *pkey)
{
    switch (EVP_PKEY_get_base_id(pkey)) {
    case EVP_PKEY_DH:
    case EVP_PKEY_DHX:
        return DH_get0_priv_key(pkey->keydata);
    }
    return NULL;
}

static void secrets_on(const EVP_PKEY *pkey)
{
    bn_secret(priv_bn(pkey), 1);
    taint_rng = 1;
}

static void secrets_off(const EVP_PKEY *pkey)
{
    taint_rng = 0;
    bn_secret(priv_bn(pkey), 0);
}

static EVP_PKEY *keygen(const char *alg, const OSSL_PARAM *gparams)
{
    EVP_PKEY_CTX *gctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (!TEST_ptr(gctx = EVP_PKEY_CTX_new_from_name(libctx, alg, NULL))
        || !TEST_int_gt(EVP_PKEY_keygen_init(gctx), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_params(gctx, gparams), 0)
        || !TEST_int_gt(EVP_PKEY_keygen(gctx, &pkey), 0)
        || !TEST_ptr(priv_bn(pkey))) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(gctx);
    return pkey;
}

/*
 * Derive with |pkey| secret against |peer|, and compare with the publicly
 * computed derivation in the other direction.  |params|, if not NULL, are
 * set on both.
 */
static int derive_check(EVP_PKEY *pkey, EVP_PKEY *peer,
    const OSSL_PARAM *params)
{
    EVP_PKEY_CTX *ctx = NULL, *pctx = NULL;
    unsigned char out[512], expect[512];
    size_t outlen = sizeof(out), expectlen = sizeof(expect);
    int ok, ret = 0;

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL))
        || !TEST_int_gt(EVP_PKEY_derive_init(ctx), 0)
        || !TEST_int_gt(EVP_PKEY_derive_set_peer(ctx, peer), 0)
        || (params != NULL
            && !TEST_int_gt(EVP_PKEY_CTX_set_params(ctx, params), 0))
        || !TEST_ptr(pctx = EVP_PKEY_CTX_new_from_pkey(libctx, peer, NULL))
        || !TEST_int_gt(EVP_PKEY_derive_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_derive_set_peer(pctx, pkey), 0)
        || (params != NULL
            && !TEST_int_gt(EVP_PKEY_CTX_set_params(pctx, params), 0))
        || !TEST_int_gt(EVP_PKEY_derive(pctx, expect, &expectlen), 0))
        goto err;

    secrets_on(pkey);
    ok = EVP_PKEY_derive(ctx, out, &outlen);
    secrets_off(pkey);
    CONSTTIME_DECLASSIFY(&outlen, sizeof(outlen));
    CONSTTIME_DECLASSIFY(out, outlen);

    if (!TEST_int_gt(ok, 0)
        || !TEST_mem_eq(out, outlen, expect, expectlen))
        goto err;

    ret = 1;
err:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static const struct {
    const char *alg, *group;
    int kdf;
} dh_tests[] = {
    { "DH", "ffdhe2048", 0 },
    { "DH", "modp_2048", 0 },
    { "DHX", "dh_2048_224", 0 },
    { "DHX", "dh_2048_224", 1 },
};

static int test_dh(int idx)
{
    OSSL_PARAM gparams[2], params[6], *p = params;
    unsigned int pad = 1;
    size_t outlen = 32;
    EVP_PKEY *pkey = NULL, *peer = NULL;
    int ret = 0;

    gparams[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
        (char *)dh_tests[idx].group, 0);
    gparams[1] = OSSL_PARAM_construct_end();

    /* Unpadded output strips leading zero bytes, so it is not constant time */
    *p++ = OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, &pad);
    if (dh_tests[idx].kdf) {
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE,
            OSSL_KDF_NAME_X942KDF_ASN1, 0);
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST,
            "SHA256", 0);
        *p++ = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
            &outlen);
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG,
            "id-aes256-wrap", 0);
    }
    *p = OSSL_PARAM_construct_end();

    if (!TEST_ptr(pkey = keygen(dh_tests[idx].alg, gparams))
        || !TEST_ptr(peer = keygen(dh_tests[idx].alg, gparams))
        || !TEST_true(derive_check(pkey, peer, params)))
        TEST_info("%s %s%s", dh_tests[idx].alg, dh_tests[idx].group,
            dh_tests[idx].kdf ? " with X9.42 KDF" : "");
    else
        ret = 1;
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peer);
    return ret;
}
#endif

int setup_tests(void)
{
    if (!TEST_ptr(libctx = OSSL_LIB_CTX_new())
        || !TEST_ptr(fake_rand = fake_rand_start(libctx)))
        return 0;
    fake_rand_set_callback(RAND_get0_private(libctx), private_rng);
    fake_rand_set_callback(RAND_get0_public(libctx), public_rng);

#ifndef OPENSSL_NO_DH
    ADD_ALL_TESTS(test_dh, (int)OSSL_NELEM(dh_tests));
#endif
    return 1;
}

void cleanup_tests(void)
{
    fake_rand_finish(fake_rand);
    OSSL_LIB_CTX_free(libctx);
}
