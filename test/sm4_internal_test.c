/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal tests for the SM4 module.
 */

#include <string.h>
#include <openssl/opensslconf.h>
#include "testutil.h"

#ifndef OPENSSL_NO_SM4

#define OPENSSL_CPUID_OBJ
#define VPSM4_ASM

#if defined(OPENSSL_CPUID_OBJ) && (defined(__aarch64__) || defined(_M_ARM64))
# include "crypto/arm_arch.h"
#endif

# include "crypto/sm4.h"
# include "crypto/modes.h"
# include "crypto/sm4_platform.h"

static int test_sm4_ecb(void)
{
    static const uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    /*
     * This test vector comes from Example 1 of GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     */
    static const uint8_t expected[SM4_BLOCK_SIZE] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };

    /*
     * This test vector comes from Example 2 from GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     * After 1,000,000 iterations.
     */
    static const uint8_t expected_iter[SM4_BLOCK_SIZE] = {
        0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
        0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66
    };

    int i;
    SM4_KEY key;
    uint8_t block[SM4_BLOCK_SIZE];

    ossl_sm4_set_key(k, &key);
    memcpy(block, input, SM4_BLOCK_SIZE);

#if defined(VPSM4_EX_CAPABLE)
    if (vpsm4_ex_capable()) {
        vpsm4_ex_ecb_encrypt(block, block, sizeof(block), &key, SM4_ENCRYPT);
    } else
#endif
#if defined(VPSM4_CAPABLE)
    if (vpsm4_capable()) {
        vpsm4_ecb_encrypt(block, block, sizeof(block), &key, SM4_ENCRYPT);
    } else
#endif
    {
        ossl_sm4_encrypt(block, block, &key);
    }
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE))
        return 0;

    for (i = 0; i != 999999; ++i) {
#if defined(VPSM4_EX_CAPABLE)
        if (vpsm4_ex_capable()) {
            vpsm4_ex_ecb_encrypt(block, block, sizeof(block), &key, SM4_ENCRYPT);
        } else
#endif
#if defined(VPSM4_CAPABLE)
        if (vpsm4_capable()) {
            vpsm4_ecb_encrypt(block, block, sizeof(block), &key, SM4_ENCRYPT);
        } else
#endif
        {
            ossl_sm4_encrypt(block, block, &key);
        }
    }
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected_iter, SM4_BLOCK_SIZE))
        return 0;

#if defined(VPSM4_EX_CAPABLE)
    if (vpsm4_ex_capable()) {
        vpsm4_ex_set_decrypt_key(k, &key);
    } else
#endif
#if defined(VPSM4_CAPABLE)
    if (vpsm4_capable()) {
        vpsm4_set_decrypt_key(k, &key);
    }
#endif

    for (i = 0; i != 1000000; ++i) {
#if defined(VPSM4_EX_CAPABLE)
        if (vpsm4_ex_capable()) {
            vpsm4_ex_ecb_encrypt(block, block, sizeof(block), &key, SM4_DECRYPT);
        } else
#endif
#if defined(VPSM4_CAPABLE)
        if (vpsm4_capable()) {
            vpsm4_ecb_encrypt(block, block, sizeof(block), &key, SM4_DECRYPT);
        } else
#endif
        {
        ossl_sm4_decrypt(block, block, &key);
        }
    }
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE))
        return 0;

    return 1;
}

/*
 * Internal SM4 CBC test. This uses the low-level ossl_sm4_cbc_encrypt
 * function to directly test the internal implementation.
 */
static int test_vpsm4_cbc(void)
{
    /* Test vector from IETF draft-ribose-cfrg-sm4-04 section 8.4.1 */
    static const uint8_t key_bytes[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const uint8_t iv_bytes[SM4_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const uint8_t plaintext[32] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
        0xcc, 0xcc, 0xcc, 0xcc, 0xdd, 0xdd, 0xdd, 0xdd,
        0xee, 0xee, 0xee, 0xee, 0xff, 0xff, 0xff, 0xff,
        0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb
    };
    static const uint8_t expected_ciphertext[32] = {
        0x78, 0xeb, 0xb1, 0x1c, 0xc4, 0x0b, 0x0a, 0x48,
        0x31, 0x2a, 0xae, 0xb2, 0x04, 0x02, 0x44, 0xcb,
        0x4c, 0xb7, 0x01, 0x69, 0x51, 0x90, 0x92, 0x26,
        0x97, 0x9b, 0x0d, 0x15, 0xdc, 0x6a, 0x8f, 0x6d
    };

    SM4_KEY key;
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t decrypted[sizeof(plaintext)];
    uint8_t iv[SM4_BLOCK_SIZE];

    /* --- Test Encryption --- */
    ossl_sm4_set_key(key_bytes, &key);
    memcpy(iv, iv_bytes, SM4_BLOCK_SIZE); /* Use a working copy of the IV */
#if defined(VPSM4_EX_CAPABLE)
    if (vpsm4_ex_capable()) {
        vpsm4_ex_cbc_encrypt(plaintext, ciphertext, sizeof(plaintext), &key, iv,
                             SM4_ENCRYPT);
    } else
#endif
#if defined(VPSM4_CAPABLE)
    if (vpsm4_capable()) {
        vpsm4_cbc_encrypt(plaintext, ciphertext, sizeof(plaintext), &key, iv,
                          SM4_ENCRYPT);
    } else
#endif
    {
        CRYPTO_cbc128_encrypt(plaintext, ciphertext, sizeof(plaintext), &key, iv,
                              (block128_f)ossl_sm4_encrypt);
    }

    if (!TEST_mem_eq(ciphertext, sizeof(ciphertext),
                     expected_ciphertext, sizeof(expected_ciphertext)))
        return 0;

    /* --- Test Decryption --- */
    memcpy(iv, iv_bytes, SM4_BLOCK_SIZE); /* Reset IV for decryption */
#if defined(VPSM4_EX_CAPABLE)
    if (vpsm4_ex_capable()) {
	    vpsm4_ex_set_decrypt_key(key_bytes, &key);
        vpsm4_ex_cbc_encrypt(ciphertext, decrypted, sizeof(ciphertext), &key, iv,
                             SM4_DECRYPT);
    } else
#endif
#if defined(VPSM4_CAPABLE)
    if (vpsm4_capable()) {
	    vpsm4_set_decrypt_key(key_bytes, &key);
        vpsm4_cbc_encrypt(ciphertext, decrypted, sizeof(ciphertext), &key, iv,
                          SM4_DECRYPT);
    } else
#endif
    {
        CRYPTO_cbc128_decrypt(ciphertext, decrypted, sizeof(ciphertext), &key, iv,
                              (block128_f)ossl_sm4_decrypt);
    }

    if (!TEST_mem_eq(decrypted, sizeof(decrypted), plaintext, sizeof(plaintext)))
        return 0;

    return 1;
}

/*
 * Internal SM4 CBC test - compiled C implementation. 
 */
static int test_sm4_cbc(void)
{
    /* Test vector from IETF draft-ribose-cfrg-sm4-04 section 8.4.1 */
    static const uint8_t key_bytes[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const uint8_t iv_bytes[SM4_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const uint8_t plaintext[32] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
        0xcc, 0xcc, 0xcc, 0xcc, 0xdd, 0xdd, 0xdd, 0xdd,
        0xee, 0xee, 0xee, 0xee, 0xff, 0xff, 0xff, 0xff,
        0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb
    };
    static const uint8_t expected_ciphertext[32] = {
        0x78, 0xeb, 0xb1, 0x1c, 0xc4, 0x0b, 0x0a, 0x48,
        0x31, 0x2a, 0xae, 0xb2, 0x04, 0x02, 0x44, 0xcb,
        0x4c, 0xb7, 0x01, 0x69, 0x51, 0x90, 0x92, 0x26,
        0x97, 0x9b, 0x0d, 0x15, 0xdc, 0x6a, 0x8f, 0x6d
    };

    SM4_KEY key;
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t decrypted[sizeof(plaintext)];
    uint8_t iv[SM4_BLOCK_SIZE];

    /* --- Test Encryption --- */
    ossl_sm4_set_key(key_bytes, &key);
    memcpy(iv, iv_bytes, SM4_BLOCK_SIZE); /* Use a working copy of the IV */
    CRYPTO_cbc128_encrypt(plaintext, ciphertext, sizeof(plaintext), &key, iv,
                          (block128_f)ossl_sm4_encrypt);

    if (!TEST_mem_eq(ciphertext, sizeof(ciphertext),
                     expected_ciphertext, sizeof(expected_ciphertext)))
        return 0;

    /* --- Test Decryption --- */
    memcpy(iv, iv_bytes, SM4_BLOCK_SIZE); /* Reset IV for decryption */
    CRYPTO_cbc128_decrypt(ciphertext, decrypted, sizeof(ciphertext), &key, iv,
                          (block128_f)ossl_sm4_decrypt);

    if (!TEST_mem_eq(decrypted, sizeof(decrypted), plaintext, sizeof(plaintext)))
        return 0;

    return 1;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_SM4
    ADD_TEST(test_sm4_ecb);
    ADD_TEST(test_vpsm4_cbc);
    ADD_TEST(test_sm4_cbc);
#endif
    return 1;
}
