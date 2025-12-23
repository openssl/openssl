/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal tests for the camellia module.
 * Currently only tests Armv8 Neon implementation. 
 */

#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/camellia.h>
#include <openssl/modes.h>
#define CMLL_ASM
#include "crypto/cmll_platform.h"
#include "testutil.h"

#include <stdio.h>
#include <stdint.h>


#ifdef CMLL_AES_CAPABLE
static void fill_blks(uint8_t *fill, const uint8_t *blk, unsigned int nblks)
{
  while (nblks) {
    memcpy(fill, blk, 16);
    fill += 16;
    nblks--;
  }
}
static void camellia_encrypt_armv8_wrapper(const unsigned char *in, unsigned char *out,
                                   const CAMELLIA_KEY *key)
{

    /*Treating key memory block as an optimized SIMD context, not the standard key struct.*/
    
    camellia_encrypt_1blk_armv8((struct camellia_simd_ctx *)key, out, in);
}
#endif

/* Internal API deprecated and causes compilation warning */

/*static int test_camellia_128_ref(void)
{
    static const uint8_t k[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t expected_1rnd[CAMELLIA_BLOCK_SIZE] = {
        0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
        0x08, 0x57, 0x06, 0x56, 0x48, 0xEA, 0xBE, 0x43
    };

    CAMELLIA_KEY ctx;
    uint8_t block[CAMELLIA_BLOCK_SIZE];

    Camellia_set_key(k, 128, &ctx);
    memcpy(block, input, CAMELLIA_BLOCK_SIZE);

    Camellia_encrypt(block, block, &ctx);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, expected_1rnd, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Initial 1-round encryption failed.");
        return 0;
    }

    Camellia_decrypt(block, block, &ctx);

    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, input, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Decryption roundtrip failed.");
        return 0;
    }

    return 1;
}*/

#ifdef CMLL_AES_CAPABLE
static int test_camellia_1blk_key128_aese(void)
{

    /* Test Vectors (Standard Camellia KAT) */

    static const uint8_t k[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    /* Expected Ciphertext after 1 round */

    static const uint8_t expected_1rnd[CAMELLIA_BLOCK_SIZE] = {
        0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
        0x08, 0x57, 0x06, 0x56, 0x48, 0xEA, 0xBE, 0x43
    };

    /* Use the standard C context struct */

    CAMELLIA_KEY ctx;
    uint8_t block[CAMELLIA_BLOCK_SIZE];

    camellia_keysetup_neon((struct camellia_simd_ctx *)&ctx, k, 128 / 8);
    memcpy(block, input, CAMELLIA_BLOCK_SIZE);

    camellia_encrypt_1blk_aese((struct camellia_simd_ctx *)&ctx, block, block);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, expected_1rnd, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Initial 1-round encryption failed.");
        return 0;
    }

    camellia_decrypt_1blk_aese((struct camellia_simd_ctx *)&ctx, block, block);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, input, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Decryption roundtrip failed.");
        return 0;
    }

    return 1;
}

static int test_camellia_1blk_key128_armv8(void)
{

    /* Test Vectors (Standard Camellia KAT) */

    static const uint8_t k[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    /* Expected Ciphertext after 1 round */

    static const uint8_t expected_1rnd[CAMELLIA_BLOCK_SIZE] = {
        0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
        0x08, 0x57, 0x06, 0x56, 0x48, 0xEA, 0xBE, 0x43
    };

    /* Use the standard C context struct */

    CAMELLIA_KEY ctx;
    uint8_t block[CAMELLIA_BLOCK_SIZE];

    camellia_keysetup_neon((struct camellia_simd_ctx *)&ctx, k, 128 / 8);
    memcpy(block, input, CAMELLIA_BLOCK_SIZE);

    camellia_encrypt_1blk_armv8((struct camellia_simd_ctx *)&ctx, block, block);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, expected_1rnd, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Initial 1-round encryption failed.");
        return 0;
    }

    camellia_decrypt_1blk_armv8((struct camellia_simd_ctx *)&ctx, block, block);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, input, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Decryption roundtrip failed.");
        return 0;
    }

    return 1;
}

static int test_camellia_16blk_key128_neon(void)
{
    static const uint8_t k[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t expected_1rnd[CAMELLIA_BLOCK_SIZE] = {
        0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
        0x08, 0x57, 0x06, 0x56, 0x48, 0xEA, 0xBE, 0x43
    };

    CAMELLIA_KEY ctx;
    uint8_t input_simd[32 * 16];
    uint8_t tmp[32 * 16];

    fill_blks(input_simd, input, 16);

    camellia_keysetup_neon((struct camellia_simd_ctx *)&ctx, k, 128 / 8);
    camellia_encrypt_16blks_neon((struct camellia_simd_ctx *)&ctx, tmp, input_simd);
    for (int i = 0; i < 16; i++){
        if (!TEST_mem_eq(tmp + (i * 16), CAMELLIA_BLOCK_SIZE, expected_1rnd, CAMELLIA_BLOCK_SIZE)) {
            TEST_error("Initial 1-round encryption failed for block %d.", i);
            return 0;
        }
    }
    camellia_decrypt_16blks_neon((struct camellia_simd_ctx *)&ctx, tmp, tmp);
    if (!TEST_mem_eq(tmp, 16 * 16, input_simd, 16 * 16)) {
        TEST_error("Decryption roundtrip failed.");
        return 0;
    }
    return 1;
}

static int test_camellia_1blk_key192_armv8(void)
{
    static const uint8_t k[24] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77
    };

    static const uint8_t input[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t expected_1rnd[CAMELLIA_BLOCK_SIZE] = {
        0xb4,0x99,0x34,0x01,0xb3,0xe9,0x96,0xf8,
        0x4e,0xe5,0xce,0xe7,0xd7,0x9b,0x09,0xb9
    };

    CAMELLIA_KEY ctx;
    uint8_t block[CAMELLIA_BLOCK_SIZE];

    camellia_keysetup_neon((struct camellia_simd_ctx *)&ctx, k, 192 / 8);
    memcpy(block, input, CAMELLIA_BLOCK_SIZE);

    camellia_encrypt_1blk_armv8((struct camellia_simd_ctx *)&ctx, block, block);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, expected_1rnd, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Initial 1-round encryption failed.");
        return 0;
    }

    camellia_decrypt_1blk_armv8((struct camellia_simd_ctx *)&ctx, block, block);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, input, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Decryption roundtrip failed.");
        return 0;
    }

    return 1;
}

static int test_camellia_16blk_key192_neon(void)
{
    static const uint8_t k[24] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77
    };

    static const uint8_t input[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t expected_1rnd[CAMELLIA_BLOCK_SIZE] = {
        0xb4,0x99,0x34,0x01,0xb3,0xe9,0x96,0xf8,
        0x4e,0xe5,0xce,0xe7,0xd7,0x9b,0x09,0xb9
    };

    CAMELLIA_KEY ctx;
    uint8_t input_simd[32 * 16];
    uint8_t tmp[32 * 16];

    fill_blks(input_simd, input, 16);

    camellia_keysetup_neon((struct camellia_simd_ctx *)&ctx, k, 192 / 8);
    camellia_encrypt_16blks_neon((struct camellia_simd_ctx *)&ctx, tmp, input_simd);
    for (int i = 0; i < 16; i++){
        if (!TEST_mem_eq(tmp + (i * 16), CAMELLIA_BLOCK_SIZE, expected_1rnd, CAMELLIA_BLOCK_SIZE)) {
            TEST_error("Initial 1-round encryption failed for block %d.", i);
            return 0;
        }
    }
    camellia_decrypt_16blks_neon((struct camellia_simd_ctx *)&ctx, tmp, tmp);
    if (!TEST_mem_eq(tmp, 16 * 16, input_simd, 16 * 16)) {
        TEST_error("Decryption roundtrip failed.");
        return 0;
    }
    return 1;
}

static int test_camellia_1blk_key256_armv8(void)
{
    static const uint8_t k[32] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };

    static const uint8_t input[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t expected_1rnd[CAMELLIA_BLOCK_SIZE] = {
        0x9a,0xcc,0x23,0x7d,0xff,0x16,0xd7,0x6c,
        0x20,0xef,0x7c,0x91,0x9e,0x3a,0x75,0x09
    };

    CAMELLIA_KEY ctx;
    uint8_t block[CAMELLIA_BLOCK_SIZE];

    camellia_keysetup_neon((struct camellia_simd_ctx *)&ctx, k, 256 / 8);
    memcpy(block, input, CAMELLIA_BLOCK_SIZE);

    camellia_encrypt_1blk_armv8((struct camellia_simd_ctx *)&ctx, block, block);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, expected_1rnd, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Initial 1-round encryption failed.");
        return 0;
    }

    camellia_decrypt_1blk_armv8((struct camellia_simd_ctx *)&ctx, block, block);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, input, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Decryption roundtrip failed.");
        return 0;
    }

    return 1;
}

static int test_camellia_16blk_key256_neon(void)
{
    static const uint8_t k[32] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };

    static const uint8_t input[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t expected_1rnd[CAMELLIA_BLOCK_SIZE] = {
        0x9a,0xcc,0x23,0x7d,0xff,0x16,0xd7,0x6c,
        0x20,0xef,0x7c,0x91,0x9e,0x3a,0x75,0x09
    };

    CAMELLIA_KEY ctx;
    uint8_t input_simd[32 * 16];
    uint8_t tmp[32 * 16];

    fill_blks(input_simd, input, 16);

    camellia_keysetup_neon((struct camellia_simd_ctx *)&ctx, k, 256 / 8);
    camellia_encrypt_16blks_neon((struct camellia_simd_ctx *)&ctx, tmp, input_simd);
    for (int i = 0; i < 16; i++){
        if (!TEST_mem_eq(tmp + (i * 16), CAMELLIA_BLOCK_SIZE, expected_1rnd, CAMELLIA_BLOCK_SIZE)) {
            TEST_error("Initial 1-round encryption failed for block %d.", i);
            return 0;
        }
    }
    camellia_decrypt_16blks_neon((struct camellia_simd_ctx *)&ctx, tmp, tmp);
    if (!TEST_mem_eq(tmp, 16 * 16, input_simd, 16 * 16)) {
        TEST_error("Decryption roundtrip failed.");
        return 0;
    }
    return 1;
}

static int test_camellia_cbc_neon(void)
{
    static const uint8_t k[16] = { 
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input_std[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    const size_t NUM_BLOCKS = 95;
    const size_t LEN = NUM_BLOCKS * 16;
    CAMELLIA_KEY ctx;
    uint8_t input_full[LEN];
    uint8_t iv_asm[16];
    uint8_t iv_ref[16];
    uint8_t iv_dec[16];
    uint8_t ref[LEN];
    uint8_t ciphertext[LEN];
    uint8_t plaintext_out[LEN];

    camellia_keysetup_neon((struct camellia_simd_ctx *)&ctx, k, 128 / 8);

    fill_blks(input_full, input_std, NUM_BLOCKS);

    /* Arbitrary IV */

    static const uint8_t iv_random[16] = { 
        0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 
        0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22 
    };

    memcpy(iv_asm, iv_random, 16);
    memcpy(iv_ref, iv_random, 16);
    memcpy(iv_dec, iv_random, 16);

    /* Run reference (OpenSSL Generic Logic using 1-block encryption routine) */

    CRYPTO_cbc128_encrypt(input_full, ref, LEN, &ctx, iv_ref, 
                          (block128_f)camellia_encrypt_armv8_wrapper);

    /* Run candidate (ASM CBC) */

    camellia_cbc_encrypt_neon(input_full, ciphertext, LEN, (struct camellia_simd_ctx *)&ctx, iv_asm);

    /* Compare outputs */

    if (!TEST_mem_eq(ciphertext, LEN, ref, LEN)) {
        TEST_error("CBC Encryption Test : ASM output differs from Reference Logic");
        return 0;
    }

    /* Compare IV updates. The IV pointer should now contain the last ciphertext block */

    if (!TEST_mem_eq(iv_asm, 16, iv_ref, 16)) {
        TEST_error("CBC Encryption Test: IV update differs from Reference Logic");
        return 0;
    }

    /* Test decryption */

    camellia_cbc_decrypt_neon(ciphertext, plaintext_out, LEN, (struct camellia_simd_ctx *)&ctx, iv_dec);

    if (!TEST_mem_eq(plaintext_out, LEN, input_full, LEN)) {
        TEST_error("CBC Decryption Test: Decrypted text mismatch");
        return 0;
    }

    if (!TEST_mem_eq(iv_dec, 16, iv_asm, 16)) {
        TEST_error("CBC Decryption Test: Decryption did not update IV correctly");
        return 0;
    }

    return 1;
}

static int test_camellia_ctr_neon(void)
{
    /* Use enough blocks to trigger several iterations of the bulk loop and tail loop */

    #define CTR_TEST_BLKS 95
    #define CTR_TEST_LEN  (CTR_TEST_BLKS * 16)

    static const uint8_t k[16] = { 
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input_std[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    /* Arbitrary IV (Nonce + Counter) */

    static const uint8_t iv_original[16] = { 
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, /* Nonce */
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xF0  /* Counter near overflow */
    };

    uint8_t input_full[CTR_TEST_LEN];
    uint8_t ref_out[CTR_TEST_LEN];
    uint8_t asm_out[CTR_TEST_LEN];
    
    uint8_t iv_ref[16];
    uint8_t iv_asm[16];
    
    /* Stream State Buffers */

    unsigned char ecount_buf_ref[16];
    unsigned int num_ref = 0;
    
    unsigned char ecount_buf_asm[16];
    unsigned int num_asm = 0;

    CAMELLIA_KEY ctx;

    /* Initialize Input */

    fill_blks(input_full, input_std, CTR_TEST_BLKS);

    camellia_keysetup_neon((struct camellia_simd_ctx *)&ctx, k, 128 / 8);

    /* Run reference (generic C + 1-block ASM) */
    
    memcpy(iv_ref, iv_original, 16);
    memset(ecount_buf_ref, 0, 16);
    num_ref = 0;

    CRYPTO_ctr128_encrypt(input_full, ref_out, CTR_TEST_LEN, 
                          &ctx, iv_ref, 
                          ecount_buf_ref, &num_ref, 
                          (block128_f)camellia_encrypt_armv8_wrapper);
    
    memcpy(iv_asm, iv_original, 16);
    memset(ecount_buf_asm, 0, 16);
    num_asm = 0;

    /* Run target (parallel ASM)*/

    CRYPTO_ctr128_encrypt_ctr32(input_full, asm_out, CTR_TEST_LEN, 
                                &ctx, iv_asm, 
                                ecount_buf_asm, &num_asm, 
                                (ctr128_f)camellia_ctr32_encrypt_blocks_neon);

    if (!TEST_mem_eq(asm_out, CTR_TEST_LEN, ref_out, CTR_TEST_LEN)) {
        TEST_error("CTR Test: ASM output mismatches Reference");
        return 0;
    }

    /* Verify IV State */
    if (!TEST_mem_eq(iv_asm, 16, iv_ref, 16)) {
        TEST_error("CTR Test: IV (Counter) update mismatch");
        return 0;
    }

    /* Run decryption (round trip) */

    uint8_t roundtrip_out[CTR_TEST_LEN];
    
    memcpy(iv_asm, iv_original, 16);
    memset(ecount_buf_asm, 0, 16);
    num_asm = 0;

    CRYPTO_ctr128_encrypt_ctr32(asm_out, roundtrip_out, CTR_TEST_LEN, 
                                &ctx, iv_asm, 
                                ecount_buf_asm, &num_asm, 
                                (ctr128_f)camellia_ctr32_encrypt_blocks_neon);

    if (!TEST_mem_eq(roundtrip_out, CTR_TEST_LEN, input_full, CTR_TEST_LEN)) {
        TEST_error("CTR Round Trip: Decryption failed to recover plaintext");
        return 0;
    }

    if (!TEST_mem_eq(iv_asm, 16, iv_ref, 16)) {
        TEST_error("CTR Round Trip: IV state inconsistent after decryption");
        return 0;
    }

    return 1;
}
#endif

int setup_tests(void)
{
    /*ADD_TEST(test_camellia_128_ref);*/
#ifdef CMLL_AES_CAPABLE
    ADD_TEST(test_camellia_1blk_key128_aese);
    ADD_TEST(test_camellia_1blk_key128_armv8);
    ADD_TEST(test_camellia_16blk_key128_neon);
    ADD_TEST(test_camellia_1blk_key192_armv8);
    ADD_TEST(test_camellia_16blk_key192_neon);
    ADD_TEST(test_camellia_1blk_key256_armv8);
    ADD_TEST(test_camellia_16blk_key256_neon);
    ADD_TEST(test_camellia_cbc_neon);
    ADD_TEST(test_camellia_ctr_neon);
#endif
    return 1;
}
