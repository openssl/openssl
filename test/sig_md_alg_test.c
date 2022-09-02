/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include "testutil.h"

typedef struct {
    int success;
    EVP_PKEY *pkey;
    OSSL_LIB_CTX *libctx_no_signing;
    OSSL_LIB_CTX *libctx_no_verification;
} signature_md_algs_test_t;

typedef struct {
    EVP_MD *md;
    EVP_PKEY *pkey;
    OSSL_LIB_CTX *libctx_no_signing;
    OSSL_LIB_CTX *libctx_no_verification;
    char *conf_str;
    int success;
} signature_md_alg_test_t;

static void test_signature_md_alg_name(const char *name,
                                       signature_md_alg_test_t *test)
{
    EVP_MD *md = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    BN_CTX *bn_ctx = NULL;
    OSSL_PARAM params[3];
    OSSL_PARAM params_no_signing[4];
    OSSL_PARAM params_no_verification[4];
    const char *canonical_name = NULL;
    char *namebuf = NULL;
    unsigned char *sig = NULL;
    size_t siglen;
    const char *tbs = "Hello, World!";
    size_t tbslen = strlen(tbs);

    md = EVP_MD_fetch(OSSL_LIB_CTX_get0_global_default(), name, NULL);
    if (md == NULL)
        goto err;
    canonical_name = EVP_MD_get0_name(md);

    TEST_info("Testing digest '%s' with its alias '%s'", canonical_name, name);

    /* When explicitly disabled, EVP_signature_md_algorithm_allowed should say
     * so */
    if (!TEST_int_ne(1,
                     EVP_signature_md_algorithm_allowed(
                         test->libctx_no_signing,
                         EVP_SIGNATURE_MD_ALGORITHMS_SIGNING,
                         md, NULL)))
        goto err;
    if (!TEST_int_ne(1,
                     EVP_signature_md_algorithm_allowed(
                         test->libctx_no_verification,
                         EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION,
                         md, NULL)))
        goto err;

    /* When not explicitly disabled, EVP_signature_md_algorithm_allowed should
     * return 1 */
    if (!TEST_int_gt(EVP_signature_md_algorithm_allowed(
                        test->libctx_no_signing,
                        EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION,
                        md, NULL),
                     0))
        goto err;
    if (!TEST_int_gt(EVP_signature_md_algorithm_allowed(
                        test->libctx_no_verification,
                        EVP_SIGNATURE_MD_ALGORITHMS_SIGNING,
                        md, NULL),
                     0))
        goto err;

    /* In the default libctx, EVP_signature_md_algorithm_allowed should always
     * return 1 */
    if (!TEST_int_gt(EVP_signature_md_algorithm_allowed(
                        OSSL_LIB_CTX_get0_global_default(),
                        EVP_SIGNATURE_MD_ALGORITHMS_SIGNING,
                        md, NULL),
                     0))
        goto err;
    if (!TEST_int_gt(EVP_signature_md_algorithm_allowed(
                        OSSL_LIB_CTX_get0_global_default(),
                        EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION,
                        md, NULL),
                     0))
        goto err;

    /* RSA PSS only supports SHA1, SHA224, SHA256, SHA384, SHA512, MD5,
     * MD5_SHA1, MD2, MD4, MDC2, SHA3-224, SHA3-256, SHA3-384, SHA3-512.
     *
     * Specifically SHA2-256/192 is also not supported. */
    if (strstr(canonical_name, "SHAKE") != NULL
            || strstr(canonical_name, "SM3") != NULL
            || strstr(canonical_name, "NULL") != NULL
            || strstr(canonical_name, "KECCAK") != NULL
            || strstr(canonical_name, "BLAKE") != NULL
            || strcmp(canonical_name, OSSL_DIGEST_NAME_SHA2_256_192) == 0)
        goto out;

    if (!TEST_ptr(namebuf = OPENSSL_strdup(name)))
        goto err;
    params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_SIGNATURE_PARAM_PAD_MODE, "pss", 0);
    params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_SIGNATURE_PARAM_DIGEST, namebuf, 0);
    params[2] = OSSL_PARAM_construct_end();

    /* Copy these params, but add a local deny for signing */
    params_no_signing[0] = params[0];
    params_no_signing[1] = params[1];
    params_no_signing[2] = OSSL_PARAM_construct_utf8_string(
            OSSL_SIGNATURE_PARAM_DIGEST_ALGORITHMS_SIGNING,
            test->conf_str, 0);
    params_no_signing[3] = params[2];

    /* Copy these params, but add a local deny for verification */
    params_no_verification[0] = params[0];
    params_no_verification[1] = params[1];
    params_no_verification[2] = OSSL_PARAM_construct_utf8_string(
            OSSL_SIGNATURE_PARAM_DIGEST_ALGORITHMS_VERIFICATION,
            test->conf_str, 0);
    params_no_verification[3] = params[2];

    if (!TEST_ptr(bn_ctx = BN_CTX_new()))
        goto err;

    /* Generate a valid signature in the default library context */
    TEST_info(" - %s (%s) signature in default library context",
              canonical_name, name);
    if (!TEST_ptr(md_ctx = EVP_MD_CTX_new()))
        goto err;
    if (!TEST_true(EVP_DigestSignInit_ex(md_ctx, &pkey_ctx, name,
                                         OSSL_LIB_CTX_get0_global_default(),
                                         NULL, test->pkey, params)))
        goto err;
    if (!TEST_true(EVP_DigestSign(md_ctx, NULL, &siglen,
                                  (const unsigned char *)tbs, tbslen)))
        goto err;
    if (!TEST_ptr(sig = OPENSSL_malloc(siglen)))
        goto err;
    if (!TEST_true(EVP_DigestSign(md_ctx, sig, &siglen,
                                  (const unsigned char *)tbs, tbslen)))
        goto err;
    EVP_MD_CTX_reset(md_ctx);
    pkey_ctx = NULL;

    /* Validate the signature in the default library context */
    TEST_info(" - %s (%s) validation in default library context",
              canonical_name, name);
    if (!TEST_true(EVP_DigestVerifyInit_ex(md_ctx, &pkey_ctx, name,
                                           OSSL_LIB_CTX_get0_global_default(),
                                           NULL, test->pkey, params)))
        goto err;
    if (!TEST_true(EVP_DigestVerify(md_ctx, sig, siglen,
                                    (const unsigned char *)tbs, tbslen)))
        goto err;
    EVP_MD_CTX_reset(md_ctx);
    pkey_ctx = NULL;

    /* Attempt to validate the signature in a library context where this digest
     * cannot be verified, this should fail.
     *
     * Also check that EVP_signature_md_algorithm_allowed() returns the correct
     * values when invoked with the EVP_PKEY_CTX. */
    TEST_info(" - %s (%s) validation failure when disallowed",
              canonical_name, name);
    if (!TEST_false(EVP_DigestVerifyInit_ex(md_ctx, &pkey_ctx, name,
                                            test->libctx_no_verification, NULL,
                                            test->pkey, params)))
        goto err;
    if (!TEST_int_gt(EVP_signature_md_algorithm_allowed(
                         OSSL_LIB_CTX_get0_global_default(),
                         EVP_SIGNATURE_MD_ALGORITHMS_SIGNING,
                         md, pkey_ctx),
                     0))
        goto err;
    if (!TEST_int_ne(1,
                     EVP_signature_md_algorithm_allowed(
                         OSSL_LIB_CTX_get0_global_default(),
                         EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION,
                         md, pkey_ctx)))
        goto err;
    EVP_MD_CTX_reset(md_ctx);
    pkey_ctx = NULL;

    /* Attempt to validate the signature with a EVP_MD_CTX where this digest
     * cannot be verified; this should fail.
     *
     * Also check that EVP_signature_md_algorithm_allowed() returns the correct
     * values when invoked with the EVP_PKEY_CTX. */
    TEST_info(" - %s (%s) validation failure when disallowed in EVP_MD_CTX",
              canonical_name, name);
    if (!TEST_false(EVP_DigestVerifyInit_ex(md_ctx, &pkey_ctx, name,
                                            OSSL_LIB_CTX_get0_global_default(),
                                            NULL, test->pkey, params_no_verification)))
        goto err;
    if (!TEST_int_gt(EVP_signature_md_algorithm_allowed(
                         OSSL_LIB_CTX_get0_global_default(),
                         EVP_SIGNATURE_MD_ALGORITHMS_SIGNING,
                         md, pkey_ctx),
                     0))
        goto err;
    if (!TEST_int_ne(1,
                     EVP_signature_md_algorithm_allowed(
                         OSSL_LIB_CTX_get0_global_default(),
                         EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION,
                         md, pkey_ctx)))
        goto err;
    EVP_MD_CTX_reset(md_ctx);
    pkey_ctx = NULL;

    /* Attempt to re-create the signature in a library context where this
     * digest cannot be signed, this should fail.
     *
     * Also check that EVP_signature_md_algorithm_allowed() returns the correct
     * values when invoked with the EVP_PKEY_CTX. */
    TEST_info(" - %s (%s) signature failure when disallowed",
              canonical_name, name);
    if (!TEST_false(EVP_DigestSignInit_ex(md_ctx, &pkey_ctx, name,
                                          test->libctx_no_signing, NULL,
                                          test->pkey, params)))
        goto err;
    if (!TEST_int_ne(1,
                     EVP_signature_md_algorithm_allowed(
                         OSSL_LIB_CTX_get0_global_default(),
                         EVP_SIGNATURE_MD_ALGORITHMS_SIGNING,
                         md, pkey_ctx)))
        goto err;
    if (!TEST_int_gt(EVP_signature_md_algorithm_allowed(
                         OSSL_LIB_CTX_get0_global_default(),
                         EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION,
                         md, pkey_ctx),
                     0))
        goto err;
    ERR_clear_error();
    EVP_MD_CTX_reset(md_ctx);
    pkey_ctx = NULL;

    /* Attempt to re-create the signature with a EVP_MD_CTX where this digest
     * cannot be signed, this should fail.
     *
     * Also check that EVP_signature_md_algorithm_allowed() returns the correct
     * values when invoked with the EVP_PKEY_CTX. */
    TEST_info(" - %s (%s) signature failure when disallowed in EVP_MD_CTX",
              canonical_name, name);
    if (!TEST_false(EVP_DigestSignInit_ex(md_ctx, &pkey_ctx, name,
                                          OSSL_LIB_CTX_get0_global_default(),
                                          NULL, test->pkey, params_no_signing)))
        goto err;
    if (!TEST_int_ne(1,
                     EVP_signature_md_algorithm_allowed(
                         OSSL_LIB_CTX_get0_global_default(),
                         EVP_SIGNATURE_MD_ALGORITHMS_SIGNING,
                         md, pkey_ctx)))
        goto err;
    if (!TEST_int_gt(EVP_signature_md_algorithm_allowed(
                         OSSL_LIB_CTX_get0_global_default(),
                         EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION,
                         md, pkey_ctx),
                     0))
        goto err;
    ERR_clear_error();
    EVP_MD_CTX_reset(md_ctx);
    pkey_ctx = NULL;

    /* Validate the signature in a library context where this digest cannot be
     * signed, this should still succeed. */
    TEST_info(" - %s (%s) validation success when signature is disallowed",
              canonical_name, name);
    if (!TEST_true(EVP_DigestVerifyInit_ex(md_ctx, &pkey_ctx, name,
                                           test->libctx_no_signing, NULL,
                                           test->pkey, params)))
        goto err;
    if (!TEST_true(EVP_DigestVerify(md_ctx, sig, siglen,
                                    (const unsigned char *)tbs, tbslen)))
        goto err;
    EVP_MD_CTX_reset(md_ctx);
    pkey_ctx = NULL;

    /* Change the configuration to allow verification and re-attempt. This
     * should succeed. */
    TEST_info(" - %s (%s) validation success with explicit override",
              canonical_name, name);
    if (!TEST_true(EVP_signature_md_algorithm_set(
                        test->libctx_no_verification,
                        EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION,
                        md, 1)))
        goto err;
    if (!TEST_true(EVP_DigestVerifyInit_ex(md_ctx, &pkey_ctx, name,
                                           test->libctx_no_verification, NULL,
                                           test->pkey, params)))
        goto err;
    if (!TEST_true(EVP_DigestVerify(md_ctx, sig, siglen,
                                    (const unsigned char *)tbs, tbslen)))
        goto err;
    if (!TEST_true(EVP_signature_md_algorithm_set(
                        test->libctx_no_verification,
                        EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION,
                        md, 0)))
        goto err;
    EVP_MD_CTX_reset(md_ctx);
    pkey_ctx = NULL;

    /* Re-create the signature in a library context where this digest cannot be
     * verified. This is uncommon, but technically still supported and should
     * succeed. */
    TEST_info(" - %s (%s) signature success when validation is disallowed",
              canonical_name, name);
    OPENSSL_free(sig);
    sig = NULL;
    if (!TEST_true(EVP_DigestSignInit_ex(md_ctx, &pkey_ctx, name,
                                         test->libctx_no_verification, NULL,
                                         test->pkey, params)))
        goto err;
    if (!TEST_true(EVP_DigestSign(md_ctx, NULL, &siglen,
                                  (const unsigned char *)tbs, tbslen)))
        goto err;
    if (!TEST_ptr(sig = OPENSSL_malloc(siglen)))
        goto err;
    if (!TEST_true(EVP_DigestSign(md_ctx, sig, &siglen,
                                  (const unsigned char *)tbs, tbslen)))
        goto err;

    goto out;
err:
    TEST_openssl_errors();
    test->success = 0;
out:
    OPENSSL_free(sig);
    OPENSSL_free(namebuf);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    BN_CTX_free(bn_ctx);
    EVP_MD_free(md);
}

static void test_signature_md_alg(EVP_MD *md, signature_md_algs_test_t *result)
{
    int called = 0;
    char conf_str[256];
    signature_md_alg_test_t test = {0};

    test.md = md;
    test.pkey = result->pkey;
    test.libctx_no_signing = result->libctx_no_signing;
    test.libctx_no_verification = result->libctx_no_verification;
    test.conf_str = conf_str;
    test.success = 1;

    if (snprintf(conf_str, sizeof(conf_str), "ALL:!%s",
                 EVP_MD_get0_name(md)) >= (int) sizeof(conf_str))
        goto err;

    if (!EVP_signature_md_algorithms_set(result->libctx_no_signing,
                                         EVP_SIGNATURE_MD_ALGORITHMS_SIGNING,
                                         conf_str))
        goto err;
    if (!EVP_signature_md_algorithms_set(result->libctx_no_verification,
                                         EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION,
                                         conf_str))
        goto err;

    called = EVP_MD_names_do_all(
        md, (void (*)(const char *, void *)) test_signature_md_alg_name,
        &test);

    if (!called || !test.success) {
        goto err;
    }

    goto out;
err:
    result->success = 0;
out:
    return;
}

static int test_signature_md_algs(void)
{
    signature_md_algs_test_t result = { 1 };

    EVP_PKEY *rsa = NULL;
#ifndef OPENSSL_NO_EC
    EVP_PKEY *ecdsa = NULL;
#endif /* !defined(OPENSSL_NO_EC) */
#ifndef OPENSSL_NO_DSA
    EVP_PKEY_CTX *dsaparams_ctx = NULL;
    EVP_PKEY_CTX *dsa_ctx = NULL;
    unsigned int pbits = 2048;
    unsigned int qbits = 256;
    OSSL_PARAM dsa_gen_params[3];
    EVP_PKEY *dsaparams = NULL;
    EVP_PKEY *dsa = NULL;

    dsa_gen_params[0] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_FFC_PBITS, &pbits);
    dsa_gen_params[1] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_FFC_QBITS, &qbits);
    dsa_gen_params[2] = OSSL_PARAM_construct_end();
#endif /* !defined(OPENSSL_NO_DSA) */

    if (!TEST_ptr(result.libctx_no_signing = OSSL_LIB_CTX_new()))
        goto err;
    if (!TEST_ptr(result.libctx_no_verification = OSSL_LIB_CTX_new()))
        goto err;

    if (!TEST_ptr(rsa = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 1024)))
        goto err;
#ifndef OPENSSL_NO_EC
    if (!TEST_ptr(ecdsa = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "secp256k1")))
        goto err;
#endif /* !defined(OPENSSL_NO_EC) */
#ifndef OPENSSL_NO_DSA
    if (!TEST_ptr(dsaparams_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL)))
        goto err;
    if (!TEST_true(EVP_PKEY_paramgen_init(dsaparams_ctx) > 0))
        goto err;
    if (!TEST_true(EVP_PKEY_CTX_set_params(dsaparams_ctx, dsa_gen_params)))
        goto err;
    if (!TEST_true(EVP_PKEY_generate(dsaparams_ctx, &dsaparams) > 0))
        goto err;
    if (!TEST_ptr(dsa_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dsaparams, NULL)))
        goto err;
    if (!TEST_true(EVP_PKEY_keygen_init(dsa_ctx) > 0))
        goto err;
    if (!TEST_true(EVP_PKEY_generate(dsa_ctx, &dsa) > 0))
        goto err;
#endif /* !defined(OPENSSL_NO_DSA) */

    TEST_info("Testing with a 1024-bit RSA key...");
    result.pkey = rsa;
    EVP_MD_do_all_provided(OSSL_LIB_CTX_get0_global_default(),
                           (void (*)(EVP_MD *, void *)) test_signature_md_alg,
                           &result);

#ifndef OPENSSL_NO_EC
    TEST_info("Testing with a secp256k1 ECDSA key...");
    result.pkey = ecdsa;
    EVP_MD_do_all_provided(OSSL_LIB_CTX_get0_global_default(),
                           (void (*)(EVP_MD *, void *)) test_signature_md_alg,
                           &result);
#endif /* !defined(OPENSSL_NO_EC) */

#ifndef OPENSSL_NO_DSA
    TEST_info("Testing with a DSA key...");
    result.pkey = dsa;
    EVP_MD_do_all_provided(OSSL_LIB_CTX_get0_global_default(),
                           (void (*)(EVP_MD *, void *)) test_signature_md_alg,
                           &result);
#endif /* !defined(OPENSSL_NO_DSA) */

    goto out;

err:
    result.success = 0;
out:
    EVP_PKEY_free(rsa);
#ifndef OPENSSL_NO_EC
    EVP_PKEY_free(ecdsa);
#endif /* !defined(OPENSSL_NO_EC) */
#ifndef OPENSSL_NO_DSA
    EVP_PKEY_free(dsa);
    EVP_PKEY_free(dsaparams);
    EVP_PKEY_CTX_free(dsaparams_ctx);
    EVP_PKEY_CTX_free(dsa_ctx);
#endif /* !defined(OPENSSL_NO_DSA) */
    OSSL_LIB_CTX_free(result.libctx_no_signing);
    OSSL_LIB_CTX_free(result.libctx_no_verification);
    return result.success;
}

typedef struct {
    const char *what;
    const char *policy;
    const char *md;
    int allowed_before;
    int allow;
    int allowed_after;
    const char *expected;
} signature_md_alg_set_test_t;

static signature_md_alg_set_test_t signature_md_alg_set_tests[] = {
    {
        "duplicate deny entries are removed",
        "ALL:!SHA-1:!SHA1:!MD-5",
        "SHA1",
        0,
        0,
        0,
        "ALL:!SHA-1:!MD-5"
    },
    {
        "duplicate allow entries are removed (if we modify them)",
        "SHA1:SHA256:SHA1:SHA256:SHA3-512",
        "SHA1",
        1,
        1,
        1,
        "SHA1:SHA256:SHA256:SHA3-512"
    },
    {
        "allowing another algorithm works and uses the canonical name",
        "SHA256:SHA512",
        "2.16.840.1.101.3.4.2.8",
        0,
        1,
        1,
        "SHA256:SHA512:SHA3-256"
    },
    {
        "denying an algorithm works and uses the canonical name",
        "ALL",
        "SHA-1",
        1,
        0,
        0,
        "ALL:!SHA1"
    },
    {
        "a non-canonical entry in the list is recognized",
        "ALL:!1.3.14.3.2.26",
        "SHA-1",
        0,
        1,
        1,
        "ALL"
    },
    {
        "deny entries in an allow-only list are removed",
        "!SHA1:SHA256:SHA512:!SHA3-512",
        "SHA3-512",
        0,
        1,
        1,
        "SHA256:SHA512:SHA3-512"
    },
    {
        "allow entries in an allow-by-default list are removed",
        "ALL:SHA256:SHA512:SHA3-256",
        "MD5",
        1,
        0,
        0,
        "ALL:!MD5"
    }
};

static int test_signature_md_algorithm_set(void)
{
    int success = 1;
    int usecase = 0;
    size_t idx = 0;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_MD *md = NULL;
    char *algorithm_list = NULL;

    if (!TEST_ptr(libctx = OSSL_LIB_CTX_new()))
        goto err;

    for (idx = 0; idx < OSSL_NELEM(signature_md_alg_set_tests); ++idx) {
        signature_md_alg_set_test_t *test = &signature_md_alg_set_tests[idx];

        TEST_info("Testing that %s with policy %s", test->what, test->policy);

        EVP_MD_free(md);
        if (!TEST_ptr(md = EVP_MD_fetch(NULL, test->md, NULL)))
            goto err;
        for (usecase = EVP_SIGNATURE_MD_ALGORITHMS_SIGNING; usecase <= EVP_SIGNATURE_MD_ALGORITHMS_VERIFICATION; ++usecase) {
            if (!TEST_true(EVP_signature_md_algorithms_set(libctx, usecase, test->policy)))
                goto err;
            if (!TEST_int_eq(test->allowed_before, EVP_signature_md_algorithm_allowed(libctx, usecase, md, NULL)))
                goto err;
            if (!TEST_true(EVP_signature_md_algorithm_set(libctx, usecase, md, test->allow)))
                goto err;
            if (!TEST_int_eq(test->allowed_after, EVP_signature_md_algorithm_allowed(libctx, usecase, md, NULL)))
                goto err;

            OPENSSL_free(algorithm_list);
            if (!TEST_ptr(algorithm_list = EVP_signature_md_algorithms_get(libctx, usecase)))
                goto err;

            if (!TEST_str_eq(test->expected, algorithm_list))
                goto err;
            TEST_info("  -> policy after %s %s is %s", test->allow ? "allowing" : "denying", test->md, algorithm_list);
        }
    }

    goto out;

err:
    success = 0;

out:
    OPENSSL_free(algorithm_list);
    EVP_MD_free(md);
    OSSL_LIB_CTX_free(libctx);

    return success;
}

int setup_tests(void)
{
    ADD_TEST(test_signature_md_algs);
    ADD_TEST(test_signature_md_algorithm_set);
    return 1;
}
