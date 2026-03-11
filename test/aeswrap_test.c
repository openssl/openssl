/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "testutil.h"

/* Test that calling EVP_CipherUpdate() twice fails for AES_WRAP_PAD */
static int aeswrap_multi_update_fail_test(void)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    uint8_t in[32] = { 0 }; /* multiple of 8 */
    uint8_t out[64];
    int outlen = sizeof(in) + 8;
    uint8_t key[32] = { 0 };

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_ptr(cipher = EVP_CIPHER_fetch(NULL, "AES-256-WRAP-PAD", NULL))
        || !TEST_int_eq(EVP_CipherInit_ex2(ctx, cipher, key, NULL, 1, NULL), 1)
        || !TEST_int_eq(EVP_CipherUpdate(ctx, out, &outlen, in, sizeof(in)), 1)
        || !TEST_int_eq(EVP_CipherUpdate(ctx, out, &outlen, in, sizeof(in)), 0))
        goto err;
    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* Test that an invalid input size fails when padding is not enabled */
static int aeswrap_input_size_fail_test(void)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    uint8_t in[32] = { 0 }; /* multiple of 8 */
    uint8_t out[64];
    int outlen = sizeof(in) + 8;
    uint8_t key[32] = { 0 };

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_ptr(cipher = EVP_CIPHER_fetch(NULL, "AES-256-WRAP", NULL))
        || !TEST_int_eq(EVP_CipherInit_ex2(ctx, cipher, key, NULL, 1, NULL), 1)
        || !TEST_int_eq(EVP_CipherUpdate(ctx, out, &outlen, in, 7), 0))
        goto err;
    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(aeswrap_input_size_fail_test);
    ADD_TEST(aeswrap_multi_update_fail_test);
    return 1;
}
