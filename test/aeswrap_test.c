/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
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

#define GUARD_BYTE 0x7f
#define GUARD_LEN 8

/*
 * Wrap with one ICV, unwrap with a different ICV so the AIV check fails.
 * The output buffer has guard bytes to detect buffer overwriting on error.
 */
static int aeswrap_unwrap_pad_overflow_test(int plaintext_len)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    static const unsigned char aeswrap_test_key[16] = { 0 };
    unsigned char plaintext[16] = { 0 }, ciphertext[40], expected[24] = { 0 };
    int ct_len = 0, tmplen = 0;
    size_t out_len;
    unsigned char *out = NULL;
    static const unsigned char wrap_icv[4] = { 0xA6, 0x59, 0x59, 0xA7 };
    static const unsigned char unwrap_icv[4] = { 0xA6, 0x59, 0x59, 0xA6 };

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_ptr(cipher = EVP_CIPHER_fetch(NULL, "AES-128-WRAP-PAD", NULL)))
        goto err;

    if (!TEST_int_eq(EVP_CipherInit_ex2(ctx, cipher, aeswrap_test_key,
                         wrap_icv, 1, NULL),
            1)
        || !TEST_int_eq(EVP_CipherUpdate(ctx, ciphertext, &ct_len,
                            plaintext, plaintext_len),
            1)
        || !TEST_int_gt(ct_len, GUARD_LEN))
        goto err;

    out_len = (size_t)(ct_len - 8);
    if (!TEST_ptr(out = OPENSSL_malloc(out_len + GUARD_LEN)))
        goto err;
    memset(out, GUARD_BYTE, out_len + GUARD_LEN);

    if (!TEST_int_eq(EVP_CipherInit_ex2(ctx, cipher, aeswrap_test_key,
                         unwrap_icv, 0, NULL),
            1)
        || !TEST_int_eq(EVP_CipherUpdate(ctx, out, &tmplen,
                            ciphertext, ct_len),
            0))
        goto err;

    /* output area cleansed to zero, guard bytes untouched */
    memset(expected + out_len, GUARD_BYTE, GUARD_LEN);
    if (!TEST_mem_eq(out, out_len + GUARD_LEN, expected, out_len + GUARD_LEN))
        goto err;

    ret = 1;
err:
    OPENSSL_free(out);
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* 1 byte plaintext -> 16-byte ciphertext */
static int aeswrap_unwrap_pad_n1_overflow_test(void)
{
    return aeswrap_unwrap_pad_overflow_test(1);
}

/* 16 bytes plaintext -> 24-byte ciphertext */
static int aeswrap_unwrap_pad_n2_overflow_test(void)
{
    return aeswrap_unwrap_pad_overflow_test(16);
}

int setup_tests(void)
{
    ADD_TEST(aeswrap_input_size_fail_test);
    ADD_TEST(aeswrap_multi_update_fail_test);
    ADD_TEST(aeswrap_unwrap_pad_n1_overflow_test);
    ADD_TEST(aeswrap_unwrap_pad_n2_overflow_test);
    return 1;
}
