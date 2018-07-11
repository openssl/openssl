/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "testutil.h"
#include "../crypto/jpake/ecjpake.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

static const char *TEST_CLIENT_NAME = "client";
static const char *TEST_SERVER_NAME = "server";
static const char *NIST_P256 = "P-256";

static const unsigned char TEST_PASSWORD[18] = {
        0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x6c, 0x65, 0x63, 0x6a, 0x70, 0x61, 0x6b, 0x65, 0x74, 0x65, 0x73, 0x74
};

static const unsigned char BAD_PASSWORD[11] = {
        0x62, 0x61, 0x64, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64
};

static const unsigned char TEST_CLIENT_1A[65] = { // EC point.
        4, -84, -49, 1, 6, -17, -123, -113, -94, -39, 25, 51, 19, 70, -128, 90, 120, -75, -117, -70, -48, -72,
        68, -27, -57, -119, 40, 121, 20, 97, -121, -35, 38, 102, -83, -89, -127, -69, 127, 17, 19, 114, 37, 26,
        -119, 16, 98, 31, 99, 77, -15, 40, -84, 72, -29, -127, -3, 110, -7, 6, 7, 49, -10, -108, -92
};

static const unsigned char TEST_CLIENT_1B[65] = { // EC point.
        4, 29, -48, -67, 93, 69, 102, -55, -66, -39, -50, 125, -25, 1, -75, -24, 46, 8, -24, 75, 115, 4, 102, 1,
        -118, -71, 3, -57, -98, -71, -126, 23, 34, 54, -64, -63, 114, -118, -28, -65, 115, 97, 13, 52, -34, 68,
        36, 110, -13, -39, -64, 90, 34, 54, -5, 102, -90, 88, 61, 116, 73, 48, -117, -85, -50
};

static const unsigned char TEST_CLIENT_1C[32] = { // Big integer.
        114, -2, 22, 102, 41, -110, -23, 35, 92, 37, 0, 47, 17, -79, 80, -121, -72, 39, 56, -32, 60, -108, 91,
        -9, -94, -103, 93, -38, 30, -104, 52, 88
};

static const unsigned char TEST_CLIENT_1D[65] = { // EC point.
        4, 126, -90, -29, -92, 72, 112, 55, -87, -32, -37, -41, -110, 98, -78, -52, 39, 62, 119, -103, 48, -4, 24,
        64, -102, -59, 54, 28, 95, -26, 105, -41, 2, -31, 71, 121, 10, -21, 76, -25, -3, 101, 117, -85, 15, 108,
        127, -47, -61, 53, -109, -102, -88, 99, -70, 55, -20, -111, -73, -29, 43, -80, 19, -69, 43
};

static const unsigned char TEST_CLIENT_1E[65] = { // EC point.
        4, -92, -107, 88, -45, 46, -47, -21, -4, 24, 22, -81, 79, -16, -101, 85, -4, -76, -54, 71, -78, -96, 45,
        30, 124, -81, 17, 121, -22, 63, -31, 57, 91, 34, -72, 97, -106, 64, 22, -6, -70, -9, 44, -105, 86, -107,
        -39, 61, 77, -16, -27, 25, 127, -23, -16, 64, 99, 78, -43, -105, 100, -109, 119, -121, -66
};

static const unsigned char TEST_CLIENT_1F[32] = { // Big integer.
        -68, 77, -18, -69, -7, -72, -42, 10, 51, 95, 4, 108, -93, -86, -108, 30, 69, -122, 76, 124, -83, -17,
        -100, -9, 91, 61, -117, 1, 14, 68, 62, -16
};

static const unsigned char TEST_SERVER_1A[65] = {
        4, 126, -90, -29, -92, 72, 112, 55, -87, -32, -37, -41, -110, 98, -78, -52, 39, 62, 119, -103, 48, -4,
        24, 64, -102, -59, 54, 28, 95, -26, 105, -41, 2, -31, 71, 121, 10, -21, 76, -25, -3, 101, 117, -85, 15,
        108, 127, -47, -61, 53, -109, -102, -88, 99, -70, 55, -20, -111, -73, -29, 43, -80, 19, -69, 43
};

static const unsigned char TEST_SERVER_1B[65] = {
        4, 9, -8, 91, 61, 32, -21, -41, -120, 92, -28, 100, -64, -115, 5, 109, 100, 40, -2, 77, -39, 40, 122,
        -93, 101, -15, 49, -12, 54, 15, -13, -122, -40, 70, -119, -117, -60, -76, 21, -125, -62, -91, 25, 127,
        101, -41, -121, 66, 116, 108, 18, -91, -20, 10, 79, -2, 47, 39, 10, 117, 10, 29, -113, -75, 22
};

static const unsigned char TEST_SERVER_1C[32] = {
        -109, 77, 116, -21, 67, -27, 77, -12, 36, -3, -106, 48, 108, 1, 23, -65, 19, 26, -6, -65, -112, -87,
        -45, 61, 17, -104, -39, 5, 25, 55, 53, 20
};

static const unsigned char TEST_SERVER_1D[65] = {
        4, 25, 10, 7, 112, 15, -6, 75, -26, -82, 29, 121, -18, 15, 6, -82, -75, 68, -51, 90, -35, -86, -66,
        -33, 112, -8, 98, 51, 33, 51, 44, 84, -13, 85, -16, -5, -2, -57, -125, -19, 53, -98, 93, 11, -9, 55,
        122, 15, -60, -22, 122, -50, 71, 60, -100, 17, 43, 65, -52, -44, 26, -59, 106, 86, 18
};

static const unsigned char TEST_SERVER_1E[65] = {
        4, 54, 10, 28, -22, 51, -4, -26, 65, 21, 100, 88, -32, -92, -22, -62, 25, -23, 104, 49, -26, -82, -68,
        -120, -77, -13, 117, 47, -109, -96, 40, 29, 27, -15, -5, 16, 96, 81, -37, -106, -108, -88, -42, -24, 98,
        -91, -17, 19, 36, -93, -39, -30, 120, -108, -15, -18, 79, 124, 89, 25, -103, 101, -88, -35, 74
};

static const unsigned char TEST_SERVER_1F[32] = {
        -111, -124, 125, 45, 34, -33, 62, -27, 95, -86, 42, 63, -77, 63, -46, -47, -32, 85, -96, 122, 124, 97,
        -20, -5, -115, -128, -20, 0, -62, -55, -21, 18
};

/**
 * Performs a test using locally created participants.  Assures that
 * we can create and validate payloads and shared keys from random
 * values generated for a particular curve.
 *  0 = error
 *  1 = success
 * */
static int test_ecjpake_successful_exchange_with_self(void) 
{
    const EVP_MD *digestMethod = EVP_sha256();

    EC_JPAKE_CTX *aliceContext = NULL, *bobContext = NULL;
    EC_JPAKE_STEP1 aliceStep1, bobStep1;
    EC_JPAKE_STEP2 aliceStep2, bobStep2;
    EC_JPAKE_STEP3 aliceStep3, bobStep3;
    int st = 0;

    BIGNUM *secretBn = BN_new();
    BN_bin2bn(TEST_PASSWORD, sizeof(TEST_PASSWORD), secretBn);

    aliceContext = EC_JPAKE_CTX_new(TEST_CLIENT_NAME, NIST_P256, secretBn);
    bobContext = EC_JPAKE_CTX_new(TEST_SERVER_NAME, NIST_P256, secretBn);

    EC_JPAKE_STEP1_init(&aliceStep1);
    EC_JPAKE_STEP1_init(&bobStep1);

    if(!TEST_int_eq(EC_JPAKE_STEP1_generate(&aliceStep1, aliceContext, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_info("Alice's Step One Generate Failed");
        goto err;
    }
    
    if(!TEST_int_eq(EC_JPAKE_STEP1_generate(&bobStep1, bobContext, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_error("Bob's Step One Generate Failed");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP1_process(aliceContext, TEST_SERVER_NAME, &bobStep1, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_info("Alice doesn't understand the first round data sent by Bob");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP1_process(bobContext, TEST_CLIENT_NAME, &aliceStep1, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_info("Bob doesn't understand the first round data sent by Alice");
        goto err;
    }

    EC_JPAKE_STEP2_init(&aliceStep2);
    EC_JPAKE_STEP2_init(&bobStep2);
    
    if(!TEST_int_eq(EC_JPAKE_STEP2_generate(&aliceStep2, aliceContext, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_info("Alice's Step Two Generate Failed");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP2_generate(&bobStep2, bobContext, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_info("Bob's step Two Generate Failed");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP2_process(aliceContext, TEST_SERVER_NAME, &bobStep2, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_info("Alice doesn't understand the second round data sent by Bob");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP2_process(bobContext, TEST_CLIENT_NAME, &aliceStep2, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_info("Bob doesn't understand the second round data sent by Alice");
        goto err;
    }

    const BIGNUM *aliceKey = EC_JPAKE_get_shared_key(aliceContext, digestMethod);
    const BIGNUM *bobKey = EC_JPAKE_get_shared_key(bobContext, digestMethod);

    if(!TEST_BN_eq(aliceKey, bobKey)) {
        TEST_info("Shared keys don't match!");
        goto err;
    }

    EC_JPAKE_STEP3_init(&aliceStep3, digestMethod);
    EC_JPAKE_STEP3_init(&bobStep3, digestMethod);

    if(!TEST_int_eq(EC_JPAKE_STEP3_generate(aliceContext, &aliceStep3, aliceKey), JPAKE_RET_SUCCESS)) {
        TEST_info("Alice's Step Three Generate Failed");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP3_generate(bobContext, &bobStep3, bobKey), JPAKE_RET_SUCCESS)) {
        TEST_info("Bob's Step Three Generate Failed");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP3_process(aliceContext, TEST_SERVER_NAME, &bobStep3, aliceKey), JPAKE_RET_SUCCESS)) {
        TEST_info("Alice doesn't understand the HMAC generated by Bob!");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP3_process(bobContext, TEST_CLIENT_NAME, &aliceStep3, bobKey), JPAKE_RET_SUCCESS)) {
        TEST_info("Bob doesn't understand the HMAC generated by Alice!");
        goto err;     
    }

    st = 1;

err:
    EC_JPAKE_STEP1_release(&aliceStep1);
    EC_JPAKE_STEP1_release(&bobStep1);
    EC_JPAKE_STEP2_release(&aliceStep2);
    EC_JPAKE_STEP2_release(&bobStep2);
    EC_JPAKE_STEP3_release(&aliceStep3);
    EC_JPAKE_STEP3_release(&bobStep3);
    EC_JPAKE_CTX_free(aliceContext);
    EC_JPAKE_CTX_free(bobContext);
    
    return st;
}

/**
 * Performs a test using locally created participants.  Assures that
 * we fail validation with mismatched passwords.
 *  0 = error
 *  1 = success
 * */
static int test_ecjpake_failed_exchange_with_self(void) 
{
    const EVP_MD *digestMethod = EVP_sha256();

    EC_JPAKE_CTX *aliceContext = NULL, *bobContext = NULL;
    EC_JPAKE_STEP1 aliceStep1, bobStep1;
    EC_JPAKE_STEP2 aliceStep2, bobStep2;
    EC_JPAKE_STEP3 aliceStep3, bobStep3;
    int st = 0;

    BIGNUM *secretBn = BN_new();
    BIGNUM *badSecretBn = BN_new();

    BN_bin2bn(TEST_PASSWORD, sizeof(TEST_PASSWORD), secretBn);
    BN_bin2bn(BAD_PASSWORD, sizeof(BAD_PASSWORD), badSecretBn);

    aliceContext = EC_JPAKE_CTX_new(TEST_CLIENT_NAME, NIST_P256, secretBn);
    bobContext = EC_JPAKE_CTX_new(TEST_SERVER_NAME, NIST_P256, badSecretBn);

    EC_JPAKE_STEP1_init(&aliceStep1);
    EC_JPAKE_STEP1_init(&bobStep1);

    if(!TEST_int_eq(EC_JPAKE_STEP1_generate(&aliceStep1, aliceContext, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_info("Alice's Step One Generate Failed");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP1_generate(&bobStep1, bobContext, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_error("Bob's Step One Generate Failed");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP1_process(aliceContext, TEST_SERVER_NAME, &bobStep1, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_info("Alice doesn't understand the first round data sent by Bob");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP1_process(bobContext, TEST_CLIENT_NAME, &aliceStep1, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_info("Bob doesn't understand the first round data sent by Alice");
        goto err;
    }

    EC_JPAKE_STEP2_init(&aliceStep2);
    EC_JPAKE_STEP2_init(&bobStep2);
    
    if(!TEST_int_eq(EC_JPAKE_STEP2_generate(&aliceStep2, aliceContext, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_info("Alice's Step Two Generate Failed");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP2_generate(&bobStep2, bobContext, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_info("Bob's step Two Generate Failed");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP2_process(aliceContext, TEST_SERVER_NAME, &bobStep2, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_info("Alice doesn't understand the second round data sent by Bob");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP2_process(bobContext, TEST_CLIENT_NAME, &aliceStep2, digestMethod), JPAKE_RET_SUCCESS)) {
        TEST_info("Bob doesn't understand the second round data sent by Alice");
        goto err;
    }

    const BIGNUM *aliceKey = EC_JPAKE_get_shared_key(aliceContext, digestMethod);
    const BIGNUM *bobKey = EC_JPAKE_get_shared_key(bobContext, digestMethod);

    if(!TEST_BN_ne(aliceKey, bobKey)) {
        TEST_info("Shared keys shouldn't match!");
        goto err;
    }

    EC_JPAKE_STEP3_init(&aliceStep3, digestMethod);
    EC_JPAKE_STEP3_init(&bobStep3, digestMethod);

    if(!TEST_int_eq(EC_JPAKE_STEP3_generate(aliceContext, &aliceStep3, aliceKey), JPAKE_RET_SUCCESS)) {
        TEST_info("Alice's Step Three Generate Failed");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP3_generate(bobContext, &bobStep3, bobKey), JPAKE_RET_SUCCESS)) {
        TEST_info("Bob's Step Three Generate Failed");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP3_process(aliceContext, TEST_SERVER_NAME, &bobStep3, aliceKey), JPAKE_RET_FAILURE)) {
        TEST_info("Alice shouldn't validate the HMAC generated by Bob!");
        goto err;
    }

    if(!TEST_int_eq(EC_JPAKE_STEP3_process(bobContext, TEST_CLIENT_NAME, &aliceStep3, bobKey), JPAKE_RET_FAILURE)) {
        TEST_info("Bob shouldn't validate the HMAC generated by Alice!");
        goto err;     
    }

    st = 1;

err:
    EC_JPAKE_STEP1_release(&aliceStep1);
    EC_JPAKE_STEP1_release(&bobStep1);
    EC_JPAKE_STEP2_release(&aliceStep2);
    EC_JPAKE_STEP2_release(&bobStep2);
    EC_JPAKE_STEP3_release(&aliceStep3);
    EC_JPAKE_STEP3_release(&bobStep3);
    EC_JPAKE_CTX_free(aliceContext);
    EC_JPAKE_CTX_free(bobContext);
    
    return st;
}

/**
 * Performs a test against zero-knowledge proofs created with
 * hard-coded values.
 *  0 = error
 *  1 = success
 */
static int test_ec_zero_knowledge_proof(void) 
{
    int st = 0; /* Error state */

    const EVP_MD *digestMethod = EVP_sha256();

    BN_CTX *bnCtx = BN_CTX_new();

    /* Get the curve group. */
    EC_GROUP *group = EC_GROUP_new_by_curve_name(EC_curve_nist2nid(NIST_P256));

    /* Get the curve's generator (G) */
    const EC_POINT *G = EC_GROUP_get0_generator(group);

    /* Client Points */
    EC_POINT *clientPoint1 = EC_POINT_new(group);
    EC_POINT *clientPoint2 = EC_POINT_new(group);
    EC_POINT *clientPoint4 = EC_POINT_new(group);
    EC_POINT *clientPoint5 = EC_POINT_new(group);

    /* Server Points */
    EC_POINT *serverPoint1 = EC_POINT_new(group);
    EC_POINT *serverPoint2 = EC_POINT_new(group);
    EC_POINT *serverPoint4 = EC_POINT_new(group);
    EC_POINT *serverPoint5 = EC_POINT_new(group);

    EC_POINT_oct2point(group, clientPoint1, TEST_CLIENT_1A, sizeof(TEST_CLIENT_1A), bnCtx);
    EC_POINT_oct2point(group, clientPoint2, TEST_CLIENT_1B, sizeof(TEST_CLIENT_1B), bnCtx);
    EC_POINT_oct2point(group, clientPoint4, TEST_CLIENT_1D, sizeof(TEST_CLIENT_1D), bnCtx);
    EC_POINT_oct2point(group, clientPoint5, TEST_CLIENT_1E, sizeof(TEST_CLIENT_1E), bnCtx);

    BIGNUM *clientInteger3 = BN_new();
    BIGNUM *clientInteger6 = BN_new();

    clientInteger3 = BN_bin2bn(TEST_CLIENT_1C, sizeof(TEST_CLIENT_1C), clientInteger3);
    clientInteger6 = BN_bin2bn(TEST_CLIENT_1F, sizeof(TEST_CLIENT_1F), clientInteger6);

    /* Check the client proofs. */
    const EC_POINT *Gx1 = EC_POINT_dup(clientPoint1, group);
    const EC_POINT *Gx2 = EC_POINT_dup(clientPoint4, group);

    EC_JPAKE_ZKP zkpForX1;
    zkpForX1.gr = EC_POINT_point2bn(group, clientPoint2, POINT_CONVERSION_UNCOMPRESSED, NULL, bnCtx);
    zkpForX1.b = BN_dup(clientInteger3);

    EC_JPAKE_ZKP zkpForX2;
    zkpForX2.gr = EC_POINT_point2bn(group, clientPoint5, POINT_CONVERSION_UNCOMPRESSED, NULL, bnCtx);
    zkpForX2.b = BN_dup(clientInteger6);

    if(!TEST_int_eq(ec_verify_zkp(group, G, Gx1, &zkpForX1, digestMethod, bnCtx, TEST_CLIENT_NAME), JPAKE_RET_SUCCESS)) {
        TEST_info("Error checking the ZKP for x1");
        goto err;

    }

    if(!TEST_int_eq(ec_verify_zkp(group, G, Gx2, &zkpForX2, digestMethod, bnCtx, TEST_CLIENT_NAME), JPAKE_RET_SUCCESS)) {
        TEST_info("Error checking the ZKP for x2");
        goto err;
    }

    /* Decode the server side data */
    EC_POINT_oct2point(group, serverPoint1, TEST_SERVER_1A, sizeof(TEST_SERVER_1A), bnCtx);
    EC_POINT_oct2point(group, serverPoint2, TEST_SERVER_1B, sizeof(TEST_SERVER_1B), bnCtx);
    EC_POINT_oct2point(group, serverPoint4, TEST_SERVER_1D, sizeof(TEST_SERVER_1D), bnCtx);
    EC_POINT_oct2point(group, serverPoint5, TEST_SERVER_1E, sizeof(TEST_SERVER_1E), bnCtx);

    BIGNUM *serverInteger3 = BN_new();
    BIGNUM *serverInteger6 = BN_new();

    serverInteger3 = BN_bin2bn(TEST_SERVER_1C, sizeof(TEST_SERVER_1C), serverInteger3);
    serverInteger6 = BN_bin2bn(TEST_SERVER_1F, sizeof(TEST_SERVER_1F), serverInteger6);

    /* Check the server proofs. */
    const EC_POINT *Gx3 = EC_POINT_dup(serverPoint1, group);
    const EC_POINT *Gx4 = EC_POINT_dup(serverPoint4, group);

    /* Server Proofs */
    EC_JPAKE_ZKP zkpForX3;
    EC_JPAKE_ZKP zkpForX4;

    zkpForX3.gr = EC_POINT_point2bn(group, serverPoint2, POINT_CONVERSION_UNCOMPRESSED, NULL, bnCtx);
    zkpForX3.b = BN_dup(serverInteger3);

    zkpForX4.gr = EC_POINT_point2bn(group, serverPoint5, POINT_CONVERSION_UNCOMPRESSED, NULL, bnCtx);
    zkpForX4.b = BN_dup(serverInteger6);


    if(!TEST_int_eq(ec_verify_zkp(group, G, Gx3, &zkpForX3, digestMethod, bnCtx, TEST_SERVER_NAME), 1)) {
        TEST_info("Error checking the ZKP for x3");
        goto err;
    }

    if(!TEST_int_eq(ec_verify_zkp(group, G, Gx4, &zkpForX4, digestMethod, bnCtx, TEST_SERVER_NAME), 1)) {
        TEST_info("Error checking the ZKP for x4");
        goto err;
    }

    st = 1;

err:
    EC_POINT_free(clientPoint1);
    EC_POINT_free(clientPoint2);
    EC_POINT_free(clientPoint4);
    EC_POINT_free(clientPoint5);

    EC_POINT_free(serverPoint1);
    EC_POINT_free(serverPoint2);
    EC_POINT_free(serverPoint4);
    EC_POINT_free(serverPoint5);

    BN_clear_free(clientInteger3);
    BN_clear_free(clientInteger6);

    return st;
}

int setup_tests(void)
{
    ADD_TEST(test_ecjpake_successful_exchange_with_self);
    ADD_TEST(test_ecjpake_failed_exchange_with_self);
    ADD_TEST(test_ec_zero_knowledge_proof);
    return 1; /* Indicate success */
}
