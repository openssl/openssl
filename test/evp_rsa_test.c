/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include "testutil.h"

static OSSL_LIB_CTX *testctx = NULL;
static char *testpropq = "";

#include "evp_extra_test.inc"

static OSSL_PROVIDER *nullprov = NULL;
static OSSL_PROVIDER *deflprov = NULL;

static int test_RSA_get_set_params(void)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    /*
     * Setup the parameters for our RSA object. For our purposes they don't
     * have to actually be *valid* parameters. We just need to set something.
     */
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_name(testctx, "RSA", NULL))
        || !TEST_ptr(bld = OSSL_PARAM_BLD_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_ptr(d = BN_new()))
        goto err;
    if (!TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e))
        || !TEST_true(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d)))
        goto err;
    if (!TEST_ptr(params = OSSL_PARAM_BLD_to_param(bld)))
        goto err;

    if (!TEST_int_gt(EVP_PKEY_fromdata_init(pctx), 0)
        || !TEST_int_gt(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
                                          params), 0))
        goto err;

    if (!TEST_ptr(pkey))
        goto err;

    ret = test_EVP_PKEY_CTX_get_set_params(pkey);

 err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
    BN_free(d);

    return ret;
}

/* Test OAEP with OSSL_PARAM to set and get */
static int test_RSA_OAEP_set_get_params(void)
{
    int ret = 0;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *key_ctx = NULL;

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    if (!TEST_ptr(key = load_example_rsa_key())
        || !TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(0, key, 0)))
        goto err;

    {
        int padding = RSA_PKCS1_OAEP_PADDING;
        OSSL_PARAM params[4];

        params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_PAD_MODE, &padding);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                                     OSSL_DIGEST_NAME_SHA2_256, 0);
        params[2] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
                                                     OSSL_DIGEST_NAME_SHA1, 0);
        params[3] = OSSL_PARAM_construct_end();

        if (!TEST_int_gt(EVP_PKEY_encrypt_init_ex(key_ctx, params),0))
            goto err;
    }
    {
        OSSL_PARAM params[3];
        char oaepmd[30] = { '\0' };
        char mgf1md[30] = { '\0' };

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                                     oaepmd, sizeof(oaepmd));
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
                                                     mgf1md, sizeof(mgf1md));
        params[2] = OSSL_PARAM_construct_end();

        if (!TEST_true(EVP_PKEY_CTX_get_params(key_ctx, params)))
            goto err;

        if (!TEST_str_eq(oaepmd, OSSL_DIGEST_NAME_SHA2_256)
            || !TEST_str_eq(mgf1md, OSSL_DIGEST_NAME_SHA1))
            goto err;
    }

    ret = 1;

 err:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(key_ctx);

    return ret;
}

/* Test OAEP using EVP_PKEY_CTX_ API's to set and get */
static int test_RSA_OAEP_set_get_api(void)
{
    int ret = 0;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    int pad = 0;
    char *label = NULL;
    unsigned char *label2;
    char name[32];
    const EVP_MD *mgf1md, *oaepmd;

    if (nullprov != NULL)
        return TEST_skip("Test does not support a non-default library context");

    if (!TEST_ptr(md = EVP_MD_fetch(testctx, OSSL_DIGEST_NAME_SHA2_256, testpropq)))
        goto err;

    if (!TEST_ptr(label = OPENSSL_strdup("label")))
        goto err;

    if (!TEST_ptr(key = load_example_rsa_key())
        || !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(0, key, 0)))
        goto err;

    /* Test that the ctx setters and getters all fail if the operation is not set yet */
    if (!TEST_int_eq(EVP_PKEY_CTX_get_rsa_padding(ctx, &pad), -1)
        || !TEST_int_eq(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING), -1))
        goto err;
    if (!TEST_int_eq(EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, OSSL_DIGEST_NAME_SHA2_512, "provider=default"), -2)
        || !TEST_int_eq(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md), -1)
        || !TEST_int_eq(EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, OSSL_DIGEST_NAME_SHA2_512, "provider=default"), -2)
        || !TEST_int_eq(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md), -1)
        || !TEST_int_eq(EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, "label", 0), -2))
        goto err;
    if (!TEST_int_eq(EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx, name, sizeof(name)), -2)
        || !TEST_int_eq(EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx, name, sizeof(name)), -2)
        || !TEST_int_eq(EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1md), -1)
        || !TEST_int_eq(EVP_PKEY_CTX_get_rsa_oaep_md(ctx, &oaepmd), -1))
        goto err;
    if (!TEST_int_eq(EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, "label", 6), -2)
        || !TEST_int_eq(EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, &label2), -2))
        goto err;

    /* Set the operation */
    if (!TEST_int_gt(EVP_PKEY_encrypt_init_ex(ctx, NULL),0))
        goto err;

    /* Test that the API's work pass if the operation is set */
    if (!TEST_int_eq(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING), 1)
        || !TEST_int_eq(EVP_PKEY_CTX_get_rsa_padding(ctx, &pad), RSA_PKCS1_OAEP_PADDING))
        goto err;

    /* Test the defaults for the digests **/
    if (!TEST_int_eq(EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1md), 1)
        || !TEST_true(EVP_MD_is_a(mgf1md, "SHA1"))
        || !TEST_int_eq(EVP_PKEY_CTX_get_rsa_oaep_md(ctx, &oaepmd), 1)
        || !TEST_true(EVP_MD_is_a(oaepmd, "SHA1")))
        goto err;

    /* Test setting the digests */
    if (!TEST_int_eq(EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, "SHA384", "provider=default"), 1)
        || !TEST_int_eq(EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1md), 1)
        || !TEST_true(EVP_MD_is_a(mgf1md, "SHA384"))
        || !TEST_int_eq(EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx, name, sizeof(name)), 1)
        || !TEST_str_eq(name, "SHA2-384"))
        goto err;
    if (!TEST_int_eq(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md), 1)
        || !TEST_int_eq(EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1md), 1)
        || !TEST_true(EVP_MD_is_a(mgf1md, "SHA256")))
        goto err;
    if (!TEST_int_eq(EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, OSSL_DIGEST_NAME_SHA2_512, "provider=default"), 1)
        || !TEST_int_eq(EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx, name, sizeof(name)), 1)
        || !TEST_str_eq(name, OSSL_DIGEST_NAME_SHA2_512))
        goto err;
    if (!TEST_int_eq(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md), 1)
        || !TEST_int_eq(EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx, name, sizeof(name)), 1)
        || !TEST_str_eq(name, "SHA2-256")
        || !TEST_int_eq(EVP_PKEY_CTX_get_rsa_oaep_md(ctx, &oaepmd), 1)
        || !TEST_true(EVP_MD_is_a(oaepmd, "SHA256")))
        goto err;

    /* Fail if the name md buffer is too small */
    if (!TEST_int_eq(EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx, name, 1), 0)
        || !TEST_int_eq(EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx, name, 1), 0))
        goto err;

    /* Test the oaep label */
    if (!TEST_int_eq(EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label, 6), 1))
        goto err;
    label = NULL;
    if (!TEST_int_eq(EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, &label2), 6))
        goto err;

    /* Pass bad inputs label param */
    if (!TEST_int_eq(EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, NULL, 0), 0)
        /* This call just returns the size */
        || !TEST_int_eq(EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, NULL), 6))
        goto err;

    ret = 1;
err:
    OPENSSL_free(label);
    EVP_MD_free(md);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int test_EVP_rsa_keygen_pubexp(void)
{
    int ret = 0;
    EVP_PKEY_CTX *rsapssctx = NULL, *rsactx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD *md = NULL;
    BIGNUM *exp = NULL, *zeroexp = NULL;

    ret = TEST_ptr(exp = BN_new())
        && TEST_ptr(zeroexp = BN_new())
        && TEST_true(BN_set_word(exp, 65537))
        && TEST_true(BN_set_word(zeroexp, 0))
        && TEST_ptr(md = EVP_MD_fetch(testctx, "sha256", testpropq))
        && TEST_ptr((rsactx = EVP_PKEY_CTX_new_from_name(testctx, "RSA", testpropq)))
        && TEST_ptr((rsapssctx = EVP_PKEY_CTX_new_from_name(testctx, "RSA-PSS", testpropq)))
        && TEST_int_eq(EVP_PKEY_keygen_init(rsactx), 1)
        /* Fail on bad inputs */
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_keygen_pubexp(NULL, zeroexp), -2)
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_keygen_pubexp(NULL, exp), -2)
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_keygen_pubexp(rsactx, zeroexp), 0)
        && TEST_int_eq(EVP_PKEY_keygen_init(rsapssctx), 1)
        /* Fail if used for a PSS key */
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_keygen_pubexp(rsapssctx, zeroexp), -2)
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_keygen_pubexp(rsapssctx, exp), -2)
        && TEST_true(EVP_PKEY_keygen(rsapssctx, &pkey));
    if (ret == 0)
        goto err;

    ret = TEST_int_eq(EVP_PKEY_CTX_set_rsa_keygen_pubexp(rsactx, exp), 1);
    /* Deal with exp being owned by the rsactx on success */
    if (ret == 1)
        exp = NULL;
err:
    BN_free(exp);
    BN_free(zeroexp);
    EVP_MD_free(md);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(rsapssctx);
    EVP_PKEY_CTX_free(rsactx);
    return ret;
}

static int test_EVP_rsa_pss_with_keygen_bits(void)
{
    int ret = 0;
    EVP_PKEY_CTX *rsapssctx = NULL, *rsactx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD *md = NULL;

    ret = TEST_ptr(md = EVP_MD_fetch(testctx, "sha256", testpropq))
        /* Fail if calling a PSS operation on a RSA key */
        && TEST_ptr((rsactx = EVP_PKEY_CTX_new_from_name(testctx, "RSA", testpropq)))
        && TEST_ptr((rsapssctx = EVP_PKEY_CTX_new_from_name(testctx, "RSA-PSS", testpropq)))
        && TEST_int_gt(EVP_PKEY_keygen_init(rsactx), 0)
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_keygen_bits(rsapssctx, 512), -2)
        && TEST_int_gt(EVP_PKEY_keygen_init(rsapssctx), 0)
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_keygen_bits(NULL, 512), -2)
        && TEST_int_gt(EVP_PKEY_CTX_set_rsa_keygen_bits(rsapssctx, 512), 0)
        && TEST_int_gt(EVP_PKEY_CTX_set_rsa_pss_keygen_md(rsapssctx, md), 0)
        && TEST_true(EVP_PKEY_keygen(rsapssctx, &pkey));

    EVP_MD_free(md);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(rsapssctx);
    EVP_PKEY_CTX_free(rsactx);
    return ret;
}

static int test_EVP_rsa_pss_with_keygen_mdname(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *rsactx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD *md = NULL;

    ret = TEST_ptr(md = EVP_MD_fetch(testctx, "sha512", testpropq))
        && TEST_ptr((rsactx = EVP_PKEY_CTX_new_from_name(testctx, "RSA", testpropq)))
        && TEST_int_gt(EVP_PKEY_keygen_init(rsactx), 0)
        /* Fail if calling a PSS operation on a RSA key */
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(rsactx, "SHA256", testpropq), -1)
        && TEST_ptr((ctx = EVP_PKEY_CTX_new_from_name(testctx, "RSA-PSS", testpropq)))
        /* Fail if setting on a RSA PSS ctx with no operation set */
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx, "SHA256", testpropq), -2)
        && TEST_int_gt(EVP_PKEY_keygen_init(ctx), 0)
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx, "SHA256", testpropq), 1)
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx, "SHA384"), 1)
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, md), 1)
        && TEST_true(EVP_PKEY_keygen(ctx, &pkey));

    EVP_MD_free(md);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(rsactx);
    return ret;
}

static int test_EVP_rsa_pss_with_keygen_primes(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *rsactx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD *md = NULL;

    ret = TEST_ptr(md = EVP_MD_fetch(testctx, "sha256", testpropq))
        /* Fail if calling a PSS operation on a RSA key */
        && TEST_ptr((rsactx = EVP_PKEY_CTX_new_from_name(testctx, "RSA", testpropq)))
        && TEST_int_gt(EVP_PKEY_keygen_init(rsactx), 0)
        && TEST_ptr((ctx = EVP_PKEY_CTX_new_from_name(testctx, "RSA-PSS", testpropq)))
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, 2), -2)
        && TEST_int_gt(EVP_PKEY_keygen_init(ctx), 0)
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_keygen_primes(NULL, 2), -2)
        && TEST_true(EVP_PKEY_keygen(ctx, &pkey));

    EVP_MD_free(md);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(rsactx);
    return ret;
}

static int test_EVP_rsa_pss_with_keygen_saltlen(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *rsactx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD *md;

    ret = TEST_ptr(md = EVP_MD_fetch(testctx, "sha256", testpropq))
        /* Fail if calling a PSS operation on a RSA key */
        && TEST_ptr((rsactx = EVP_PKEY_CTX_new_from_name(testctx, "RSA", testpropq)))
        && TEST_int_gt(EVP_PKEY_keygen_init(rsactx), 0)
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(rsactx, RSA_PSS_SALTLEN_DIGEST), -1)
        && TEST_ptr((ctx = EVP_PKEY_CTX_new_from_name(testctx, "RSA-PSS", testpropq)))
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(NULL, RSA_PSS_SALTLEN_DIGEST), -2)
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST), -2)
        && TEST_int_gt(EVP_PKEY_keygen_init(ctx), 0)
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST), 1)
        && TEST_true(EVP_PKEY_keygen(ctx, &pkey));

    EVP_MD_free(md);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(rsactx);
    return ret;
}

static int test_EVP_rsa_pss_set_saltlen(void)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD *sha256 = NULL;
    EVP_MD_CTX *sha256_ctx = NULL;
    int saltlen = 9999; /* buggy EVP_PKEY_CTX_get_rsa_pss_saltlen() didn't update this */
    const int test_value = 32;

    ret = TEST_ptr(pkey = load_example_rsa_key())
        && TEST_ptr(sha256 = EVP_MD_fetch(testctx, "sha256", NULL))
        && TEST_ptr(sha256_ctx = EVP_MD_CTX_new())
        && TEST_true(EVP_DigestSignInit(sha256_ctx, &ctx, sha256, NULL, pkey))
        && TEST_true(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING))
        && TEST_int_gt(EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, test_value), 0)
        && TEST_int_gt(EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &saltlen), 0)
        && TEST_int_eq(saltlen, test_value);

    EVP_MD_CTX_free(sha256_ctx);
    EVP_PKEY_free(pkey);
    EVP_MD_free(sha256);

    return ret;
}

#ifndef OPENSSL_NO_EC

/* Fail if we try to use RSA API's on an EC key */
static int test_EVP_ec_rsa_sign_api(void)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD *sha256 = NULL;
    EVP_MD_CTX *sha256_ctx = NULL;
    int saltlen = 0;

    ret = TEST_ptr(pkey = load_example_ec_key())
        && TEST_ptr(sha256 = EVP_MD_fetch(testctx, "sha256", NULL))
        && TEST_ptr(sha256_ctx = EVP_MD_CTX_new())
        && TEST_true(EVP_DigestSignInit(sha256_ctx, &ctx, sha256, NULL, pkey))
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING), -2)
        && TEST_int_eq(EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 10), -2)
        && TEST_int_eq(EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &saltlen), -2);

    EVP_MD_CTX_free(sha256_ctx);
    EVP_PKEY_free(pkey);
    EVP_MD_free(sha256);
    return ret;
}

static int test_EVP_ec_rsa_keygen_api(void)
{
    int ret = 0;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM *exp = NULL;
    const EVP_MD *md = EVP_sha256();

    ret = TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(testctx, "EC", testpropq))
          && TEST_int_eq(EVP_PKEY_keygen_init(ctx), 1)
          && TEST_int_lt(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 512), 0)
          && TEST_int_lt(EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, exp) , 0)
          && TEST_int_lt(EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, 2), 0)
          && TEST_int_lt(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, 8), 0)
          && TEST_int_lt(EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, exp), 0)
          && TEST_int_lt(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, md), 0)
          && TEST_int_lt(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx, "SHA256"), 0)
          && TEST_int_lt(EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md), 0)
          && TEST_int_lt(EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx, "SHA256", ""), 0);

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}
#endif

/* Fail if we try to use RSA API's on another key that handles asym encryption. */
#ifndef OPENSSL_NO_SM2
static int test_EVP_sm2_rsa_encrypt_api(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    const EVP_MD *md = EVP_sha256();
    const EVP_MD *mdret;
    char name[64];
    unsigned char *labelret;

    ret = TEST_ptr(key = EVP_PKEY_Q_keygen(testctx, NULL, "SM2"))
          && TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(testctx, key, NULL))
          && TEST_int_eq(EVP_PKEY_encrypt_init(ctx), 1)
          && TEST_int_lt(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md), 0)
          && TEST_int_lt(EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, "SHA256", NULL), 0)
          && TEST_int_lt(EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mdret), 0)
          && TEST_int_lt(EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx, name, sizeof(name)), 0)
          && TEST_int_lt(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md), 0)
          && TEST_int_lt(EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, "SHA256", NULL), 0)
          && TEST_int_lt(EVP_PKEY_CTX_get_rsa_oaep_md(ctx, &mdret), 0)
          && TEST_int_lt(EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx, name, sizeof(name)), 0)
          && TEST_int_lt(EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, "label", 4), 0)
          && TEST_int_lt(EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, &labelret), 0);

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}
#endif

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_CONTEXT,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "context", OPT_CONTEXT, '-', "Explicitly use a non-default library context" },
        { NULL }
    };
    return options;
}

int setup_tests(void)
{
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_CONTEXT:
            if (!test_get_libctx(&testctx, &nullprov, NULL, &deflprov, "default"))
                return 0;
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }
    ADD_TEST(test_RSA_get_set_params);
    ADD_TEST(test_RSA_OAEP_set_get_params);
    ADD_TEST(test_RSA_OAEP_set_get_api);
    ADD_TEST(test_EVP_rsa_pss_with_keygen_bits);
    ADD_TEST(test_EVP_rsa_pss_with_keygen_mdname);
    ADD_TEST(test_EVP_rsa_pss_with_keygen_primes);
    ADD_TEST(test_EVP_rsa_pss_with_keygen_saltlen);
    ADD_TEST(test_EVP_rsa_keygen_pubexp);
    ADD_TEST(test_EVP_rsa_pss_set_saltlen);
#ifndef OPENSSL_NO_EC
    ADD_TEST(test_EVP_ec_rsa_sign_api);
    ADD_TEST(test_EVP_ec_rsa_keygen_api);
#endif
#ifndef OPENSSL_NO_SM2
    ADD_TEST(test_EVP_sm2_rsa_encrypt_api);
#endif
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(nullprov);
    OSSL_PROVIDER_unload(deflprov);
    OSSL_LIB_CTX_free(testctx);
}
