/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../ssl/record/methods/recmethod_local.h"
#include "testutil.h"
#include <openssl/evp.h>

static const char *cipher_names[] = {
    "aes-128-ecb",
    "aes-256-ecb",
#if !defined(OPENSSL_NO_CHACHA)
    "chacha20",
#endif
};

static int test_dtls_crypt_sequence_number(int idx)
{
    /*
     * Test all possiblie Encryption Algorithms for dtls_crypt_sequence_number function
     * aes-128-ecb, "aes-256-ecb" and "chacha20"
     */
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char key[32] = { 0 };
    unsigned char iv[16] = { 0 };
    unsigned char initial_seq[2] = { 0, 0 };
    unsigned char zero_seq[2] = { 0, 0 };
    unsigned char rec_data[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    cipher = EVP_CIPHER_fetch(NULL, cipher_names[idx], NULL);
    if (!TEST_ptr(cipher))
        goto err;

    ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(ctx))
        goto err;

    if (!TEST_true(EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1)))
        goto err;

    if (!TEST_int_eq(dtls_crypt_sequence_number(ctx, initial_seq, sizeof(initial_seq), rec_data), 1))
        goto err;

    /* Verify Sequence Number is no longer zero */
    if (!TEST_mem_ne(initial_seq, sizeof(initial_seq), zero_seq, sizeof(zero_seq)))
        goto err;

    if (!TEST_int_eq(dtls_crypt_sequence_number(ctx, initial_seq, sizeof(initial_seq), rec_data), 1))
        goto err;

    /* Verify Sequence Number is back to zero */
    if (!TEST_mem_eq(initial_seq, sizeof(initial_seq), zero_seq, sizeof(zero_seq)))
        goto err;

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return 1;
err:
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    if (cipher != NULL)
        EVP_CIPHER_free(cipher);
    return 0;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_dtls_crypt_sequence_number, OSSL_NELEM(cipher_names));
    return 1;
}
