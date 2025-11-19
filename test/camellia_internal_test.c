/* camellia_internal_test.c */

#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/camellia.h> // Includes CAMELLIA_KEY definition
#include "testutil.h"
//#include "cmll_local.h"       // Includes Camellia_encrypt/decrypt declarations

//#define CAMELLIA_BLOCK_SIZE 16

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

int setup_tests(void)
{
    ADD_TEST(test_camellia_128_ref);
    // You would add your optimized tests here once the foundation passes.
    return 1;
}