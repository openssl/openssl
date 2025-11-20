/* camellia_internal_test.c */

#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/camellia.h> // Includes CAMELLIA_KEY definition
#define CMLL_ASM
#include "crypto/cmll_platform.h"
#include "testutil.h"
//#include "cmll_local.h"       // Includes Camellia_encrypt/decrypt declarations

//#define CAMELLIA_BLOCK_SIZE 16
#include <stdio.h>
#include <stdint.h>
// KEY_TABLE_WORD_LEN is defined in camellia.h as 68 (32-bit words)

void print_key_schedule(const CAMELLIA_KEY *ctx, int key_bits)
{
    // The key table is 68 u32s. We cast and print them as 34 u64s.
    const uint64_t *keys = (const uint64_t *)ctx->u.rd_key;
    int num_pairs = key_bits == 128 ? 26 : 34; // 26 pairs for 128-bit, 34 for 256/192

    printf("\n--- GENERATED OPTIMIZED KEY SCHEDULE (KeyBits: %d) ---\n", key_bits);
    printf(" Index | Subkey Value (64-bit Hex)\n");
    printf("----------------------------------------------------\n");
    
    for (int i = 0; i < num_pairs; ++i) {
        // Print the raw 64-bit value, which represents a pair of 32-bit subkeys (subr|subl).
        // The first 26 are the most important for 128-bit check.
        printf(" %04d | %016llX\n", i, keys[i]);
    }

    // Optional: Print the metadata integer (key_length) at offset 272
    printf("----------------------------------------------------\n");
    printf(" Offset 272 (Key Length/Rounds): %d\n", ctx->grand_rounds);
    printf("----------------------------------------------------\n");
}

#ifdef CMLL_AES_CAPABLE
void camellia_encrypt_armv8_wrapper(const unsigned char *in, unsigned char *out, 
                                   const CAMELLIA_KEY *key) 
{
    /*Treating key memory block as an optimized SIMD context, not the standard key struct.*/
    camellia_encrypt_1blk_armv8((struct camellia_simd_ctx *)key, out, in);
}
void camellia_decrypt_armv8_wrapper(const unsigned char *in, unsigned char *out, 
                                   const CAMELLIA_KEY *key) 
{
    /*Treating key memory block as an optimized SIMD context, not the standard key struct.*/
    camellia_decrypt_1blk_armv8((struct camellia_simd_ctx *)key, out, in);
}
#endif

static int test_camellia_128_ref(void)
{
    // Test Vectors (Standard Camellia KAT)
    static const uint8_t k[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    // Expected Ciphertext after 1 round
    static const uint8_t expected_1rnd[CAMELLIA_BLOCK_SIZE] = {
        0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
        0x08, 0x57, 0x06, 0x56, 0x48, 0xEA, 0xBE, 0x43
    };

    // Expected Ciphertext after 1,000,000 iterations (pre-computed vector)
    //static const uint8_t expected_iter[CAMELLIA_BLOCK_SIZE] = {
    //    0x1A, 0x68, 0xB7, 0x02, 0xD1, 0xC9, 0x5A, 0xC8,
    //    0x24, 0x3D, 0x13, 0x86, 0x52, 0xEE, 0xC6, 0x49
    //};

    CAMELLIA_KEY ctx; // Use the standard C context struct
    uint8_t block[CAMELLIA_BLOCK_SIZE];
    //int i;

    // 1. Setup the Standard Key
    // Calls Camellia_Ekeygen internally, populating ctx.
    Camellia_set_key(k, 128, &ctx);
    memcpy(block, input, CAMELLIA_BLOCK_SIZE);

    // 2. Single Round Test (Validation of core logic)
    Camellia_encrypt(block, block, &ctx);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, expected_1rnd, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Initial 1-round encryption failed.");
        return 0;
    }

    // 3. Decrypt (Single Round)
    Camellia_decrypt(block, block, &ctx);

    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, input, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Decryption roundtrip failed.");
        return 0;
    }
    // 3. 1,000,000 Iteration Stress Test
    // The loop iterates 999,999 times (one iteration was done above).
    //for (i = 0; i != 999999; ++i)
    //    Camellia_encrypt(block, block, &ctx);
//
//    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, expected_iter, CAMELLIA_BLOCK_SIZE)) {
//        TEST_error("1M iteration stress test failed.");
//        return 0;
//    }

    // 4. Decrypt Back to Original Input
    // The loop runs 1,000,000 times to undo the encryption.
    //for (i = 0; i != 1000000; ++i)
    //    Camellia_decrypt(block, block, &ctx);

    //if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, input, CAMELLIA_BLOCK_SIZE)) {
    //    TEST_error("Decryption roundtrip failed.");
    //    return 0;
    //}

    return 1;
}

#ifdef CMLL_AES_CAPABLE
static int test_camellia_128bit_key_armv8(void)
{
    // Test Vectors (Standard Camellia KAT)
    static const uint8_t k[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    // Expected Ciphertext after 1 round
    static const uint8_t expected_1rnd[CAMELLIA_BLOCK_SIZE] = {
        0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
        0x08, 0x57, 0x06, 0x56, 0x48, 0xEA, 0xBE, 0x43
    };

    CAMELLIA_KEY ctx; // Use the standard C context struct
    uint8_t block[CAMELLIA_BLOCK_SIZE];

    camellia_keysetup_neon((struct camellia_simd_ctx *)&ctx, k, 128 / 8);
    print_key_schedule(&ctx, 128);
    memcpy(block, input, CAMELLIA_BLOCK_SIZE);

    camellia_encrypt_armv8_wrapper(block, block, &ctx);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, expected_1rnd, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Initial 1-round encryption failed.");
        return 0;
    }

    camellia_decrypt_armv8_wrapper(block, block, &ctx);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, input, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Decryption roundtrip failed.");
        return 0;
    }

    return 1;
}

static int test_camellia_192bit_key_armv8(void)
{
    // Test Vectors (Standard Camellia KAT)
    static const uint8_t k[24] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77
    };

    static const uint8_t input[CAMELLIA_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    // Expected Ciphertext after 1 round
    static const uint8_t expected_1rnd[CAMELLIA_BLOCK_SIZE] = {
        0xb4,0x99,0x34,0x01,0xb3,0xe9,0x96,0xf8,
        0x4e,0xe5,0xce,0xe7,0xd7,0x9b,0x09,0xb9
    };

    CAMELLIA_KEY ctx; // Use the standard C context struct
    uint8_t block[CAMELLIA_BLOCK_SIZE];

    camellia_keysetup_neon((struct camellia_simd_ctx *)&ctx, k, 192 / 8);
    print_key_schedule(&ctx, 192);
    memcpy(block, input, CAMELLIA_BLOCK_SIZE);

    camellia_encrypt_armv8_wrapper(block, block, &ctx);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, expected_1rnd, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Initial 1-round encryption failed.");
        return 0;
    }

    camellia_decrypt_armv8_wrapper(block, block, &ctx);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, input, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Decryption roundtrip failed.");
        return 0;
    }

    return 1;
}

static int test_camellia_256bit_key_armv8(void)
{
    // Test Vectors (Standard Camellia KAT)
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

    // Expected Ciphertext after 1 round
    static const uint8_t expected_1rnd[CAMELLIA_BLOCK_SIZE] = {
        0x9a,0xcc,0x23,0x7d,0xff,0x16,0xd7,0x6c,
        0x20,0xef,0x7c,0x91,0x9e,0x3a,0x75,0x09
    };

    CAMELLIA_KEY ctx; // Use the standard C context struct
    uint8_t block[CAMELLIA_BLOCK_SIZE];

    camellia_keysetup_neon((struct camellia_simd_ctx *)&ctx, k, 256 / 8);
    print_key_schedule(&ctx, 256);
    memcpy(block, input, CAMELLIA_BLOCK_SIZE);

    camellia_encrypt_armv8_wrapper(block, block, &ctx);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, expected_1rnd, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Initial 1-round encryption failed.");
        return 0;
    }

    camellia_decrypt_armv8_wrapper(block, block, &ctx);
    if (!TEST_mem_eq(block, CAMELLIA_BLOCK_SIZE, input, CAMELLIA_BLOCK_SIZE)) {
        TEST_error("Decryption roundtrip failed.");
        return 0;
    }

    return 1;
}
#endif

int setup_tests(void)
{
    ADD_TEST(test_camellia_128_ref);
#ifdef CMLL_AES_CAPABLE
    ADD_TEST(test_camellia_128bit_key_armv8);
    ADD_TEST(test_camellia_192bit_key_armv8);
    ADD_TEST(test_camellia_256bit_key_armv8);
#endif
    return 1;
}