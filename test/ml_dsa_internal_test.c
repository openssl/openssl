/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal ML-DSA test exercising the low-level sign/verify path directly.
 *
 * Primary purpose: constant-time validation.  When the library is built with
 * enable-ct-validation and the test is run under Valgrind, any control-flow
 * branch or memory index that depends on secret key material (other than the
 * explicitly declassified rejection decisions) will be reported as an error.
 *
 * Secondary purpose: a quick sanity check that sign→verify round-trips for
 * all three parameter sets using a fully deterministic key and message.
 */

#include <string.h>
#include <openssl/evp.h>
#include "crypto/ml_dsa.h"
#include "testutil.h"

/* Fixed 32-byte seed used for all three parameter-set tests. */
static const uint8_t test_seed[ML_DSA_SEED_BYTES] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

/* A short, fixed test message. */
static const uint8_t test_msg[] = "ML-DSA constant-time validation test";

/*
 * Exercise keygen + sign + verify for one ML-DSA parameter set.
 *
 * The sign call uses rnd=NULL (deterministic mode) so the output is fully
 * determined by the seed and message.  Correctness against ACVP test vectors
 * is verified separately in ml_dsa_test.c; here we only check that the
 * round-trip succeeds, giving Valgrind something to instrument.
 */
static int test_sign_verify(int evp_type)
{
    ML_DSA_KEY *key = NULL;
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    const ML_DSA_PARAMS *params;
    int ret = 0;

    if (!TEST_ptr(key = ossl_ml_dsa_key_new(NULL, NULL, evp_type)))
        goto err;
    if (!TEST_true(ossl_ml_dsa_key_fetch_digests(key, NULL)))
        goto err;
    if (!TEST_ptr(params = ossl_ml_dsa_key_params(key)))
        goto err;

    /* Load the fixed seed and expand into a full key pair. */
    if (!TEST_true(ossl_ml_dsa_set_prekey(key, ML_DSA_KEY_PREFER_SEED,
            0, test_seed, sizeof(test_seed),
            NULL, 0)))
        goto err;
    if (!TEST_true(ossl_ml_dsa_generate_key(key)))
        goto err;

    sig_len = params->sig_len;
    if (!TEST_ptr(sig = OPENSSL_malloc(sig_len)))
        goto err;

    /*
     * Sign deterministically (rnd=NULL).  This exercises the rejection loop
     * under Valgrind without relying on external randomness.
     */
    if (!TEST_true(ossl_ml_dsa_sign(key,
            0 /* msg_is_mu */,
            test_msg, sizeof(test_msg) - 1,
            NULL, 0 /* no context */,
            NULL, 0 /* deterministic */,
            1 /* encode */,
            sig, &sig_len, params->sig_len)))
        goto err;
    if (!TEST_size_t_eq(sig_len, params->sig_len))
        goto err;

    /* Verify the signature we just produced. */
    if (!TEST_true(ossl_ml_dsa_verify(key,
            0 /* msg_is_mu */,
            test_msg, sizeof(test_msg) - 1,
            NULL, 0 /* no context */,
            1 /* encode */,
            sig, sig_len)))
        goto err;

    ret = 1;
err:
    ossl_ml_dsa_key_free(key);
    OPENSSL_free(sig);
    return ret;
}

static int test_ml_dsa_44(void) { return test_sign_verify(EVP_PKEY_ML_DSA_44); }
static int test_ml_dsa_65(void) { return test_sign_verify(EVP_PKEY_ML_DSA_65); }
static int test_ml_dsa_87(void) { return test_sign_verify(EVP_PKEY_ML_DSA_87); }

int setup_tests(void)
{
    ADD_TEST(test_ml_dsa_44);
    ADD_TEST(test_ml_dsa_65);
    ADD_TEST(test_ml_dsa_87);
    return 1;
}
