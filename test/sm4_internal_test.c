/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#include "crypto/sm4.h"
#include "crypto/sm4_platform.h"

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

    ossl_sm4_encrypt(block, block, &key);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE))
        return 0;

    for (i = 0; i != 999999; ++i)
        ossl_sm4_encrypt(block, block, &key);

    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected_iter, SM4_BLOCK_SIZE))
        return 0;

    for (i = 0; i != 1000000; ++i)
        ossl_sm4_decrypt(block, block, &key);

    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE))
        return 0;

    return 1;
}

#ifdef HWSM4_CAPABLE
static int test_sm4_asm_key_setup(int idx)
{
    static const uint8_t k[SM4_BLOCK_SIZE] = { 0 };
    SM4_KEY key, expected;
    int (*set_encrypt_key)(const unsigned char *, SM4_KEY *);
    int (*set_decrypt_key)(const unsigned char *, SM4_KEY *);
    int i;

    switch (idx) {
    case 0:
        if (!HWSM4_CAPABLE)
            return TEST_skip("SM4 instructions are unavailable");
        set_encrypt_key = HWSM4_set_encrypt_key;
        set_decrypt_key = HWSM4_set_decrypt_key;
        break;
#ifdef VPSM4_CAPABLE
    case 1:
        if ((OPENSSL_armcap_P & ARMV7_NEON) == 0)
            return TEST_skip("NEON instructions are unavailable");
        set_encrypt_key = vpsm4_set_encrypt_key;
        set_decrypt_key = vpsm4_set_decrypt_key;
        break;
#endif
#ifdef VPSM4_EX_CAPABLE
    case 2:
        if ((OPENSSL_armcap_P & ARMV8_AES) == 0)
            return TEST_skip("AES instructions are unavailable");
        set_encrypt_key = vpsm4_ex_set_encrypt_key;
        set_decrypt_key = vpsm4_ex_set_decrypt_key;
        break;
#endif
    default:
        return TEST_skip("SM4 implementation is unavailable");
    }

    if (!TEST_int_eq(ossl_sm4_set_key(k, &expected), 1)
        || !TEST_int_eq(set_encrypt_key(k, &key), 1)
        || !TEST_mem_eq(key.rk, sizeof(key.rk), expected.rk, sizeof(expected.rk)))
        return 0;

    /* Assembly decryption uses the round keys in reverse order. */
    for (i = 0; i < SM4_KEY_SCHEDULE / 2; i++) {
        uint32_t tmp = expected.rk[i];

        expected.rk[i] = expected.rk[SM4_KEY_SCHEDULE - 1 - i];
        expected.rk[SM4_KEY_SCHEDULE - 1 - i] = tmp;
    }

    return TEST_int_eq(set_decrypt_key(k, &key), 1)
        && TEST_mem_eq(key.rk, sizeof(key.rk), expected.rk, sizeof(expected.rk));
}
#endif
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_SM4
    ADD_TEST(test_sm4_ecb);
#ifdef HWSM4_CAPABLE
    ADD_ALL_TESTS(test_sm4_asm_key_setup, 3);
#endif
#endif
    return 1;
}
