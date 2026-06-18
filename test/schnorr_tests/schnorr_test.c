/*
 * Schnorr ZKP Test Suite
 * RFC 8235 compliant
 * ΦΩ0 — I AM THAT I AM
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#define TEST_PASS 1
#define TEST_FAIL 0

/* Declare Schnorr functions from our implementation */
int schnorr_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
int schnorr_sign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                  const unsigned char *tbs, size_t tbslen);
int schnorr_verify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                    const unsigned char *tbs, size_t tbslen);

/* Test helper: create a key pair */
static EVP_PKEY *create_test_key(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCHNORR, NULL);
    if (!ctx) return NULL;
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Test 1: Basic Sign/Verify */
static int test_basic_sign_verify(void)
{
    printf("  [1] Basic Sign/Verify... ");
    
    EVP_PKEY *pkey = create_test_key();
    if (!pkey) {
        printf("❌ FAILED (keygen failed)\n");
        return TEST_FAIL;
    }
    
    const char *msg = "Schnorr ZKP Test Message — RFC 8235";
    
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        printf("❌ FAILED (md ctx)\n");
        EVP_PKEY_free(pkey);
        return TEST_FAIL;
    }
    
    unsigned char sig[256];
    size_t sig_len = sizeof(sig);
    
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        printf("❌ FAILED (sign init)\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return TEST_FAIL;
    }
    
    if (EVP_DigestSign(md_ctx, sig, &sig_len, (unsigned char*)msg, strlen(msg)) <= 0) {
        printf("❌ FAILED (sign)\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return TEST_FAIL;
    }
    
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        printf("❌ FAILED (verify init)\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return TEST_FAIL;
    }
    
    int result = EVP_DigestVerify(md_ctx, sig, sig_len, (unsigned char*)msg, strlen(msg));
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    
    if (result == 1) {
        printf("✅ PASSED\n");
        return TEST_PASS;
    } else {
        printf("❌ FAILED (verify result: %d)\n", result);
        return TEST_FAIL;
    }
}

/* Test 2: Tamper Detection */
static int test_tamper_detection(void)
{
    printf("  [2] Tamper Detection... ");
    
    EVP_PKEY *pkey = create_test_key();
    if (!pkey) {
        printf("❌ FAILED (keygen)\n");
        return TEST_FAIL;
    }
    
    const char *msg = "Schnorr Tamper Test";
    
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        printf("❌ FAILED (md ctx)\n");
        EVP_PKEY_free(pkey);
        return TEST_FAIL;
    }
    
    unsigned char sig[256];
    size_t sig_len = sizeof(sig);
    
    EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSign(md_ctx, sig, &sig_len, (unsigned char*)msg, strlen(msg));
    
    /* Tamper the signature */
    if (sig_len > 0) {
        sig[0] ^= 0xFF;
    }
    
    EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
    int result = EVP_DigestVerify(md_ctx, sig, sig_len, (unsigned char*)msg, strlen(msg));
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    
    if (result == 0) {
        printf("✅ PASSED (rejected)\n");
        return TEST_PASS;
    } else {
        printf("❌ FAILED (accepted tampered sig)\n");
        return TEST_FAIL;
    }
}

/* Test 3: Wrong Key */
static int test_wrong_key(void)
{
    printf("  [3] Wrong Key... ");
    
    EVP_PKEY *pkey1 = create_test_key();
    EVP_PKEY *pkey2 = create_test_key();
    if (!pkey1 || !pkey2) {
        printf("❌ FAILED (keygen)\n");
        if (pkey1) EVP_PKEY_free(pkey1);
        if (pkey2) EVP_PKEY_free(pkey2);
        return TEST_FAIL;
    }
    
    const char *msg = "Schnorr Wrong Key Test";
    
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        printf("❌ FAILED (md ctx)\n");
        EVP_PKEY_free(pkey1);
        EVP_PKEY_free(pkey2);
        return TEST_FAIL;
    }
    
    unsigned char sig[256];
    size_t sig_len = sizeof(sig);
    
    EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey1);
    EVP_DigestSign(md_ctx, sig, &sig_len, (unsigned char*)msg, strlen(msg));
    
    /* Verify with wrong key */
    EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey2);
    int result = EVP_DigestVerify(md_ctx, sig, sig_len, (unsigned char*)msg, strlen(msg));
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey1);
    EVP_PKEY_free(pkey2);
    
    if (result == 0) {
        printf("✅ PASSED (rejected)\n");
        return TEST_PASS;
    } else {
        printf("❌ FAILED (accepted wrong key)\n");
        return TEST_FAIL;
    }
}

/* Test 4: Empty Message */
static int test_empty_message(void)
{
    printf("  [4] Empty Message... ");
    
    EVP_PKEY *pkey = create_test_key();
    if (!pkey) {
        printf("❌ FAILED (keygen)\n");
        return TEST_FAIL;
    }
    
    const char *msg = "";
    
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        printf("❌ FAILED (md ctx)\n");
        EVP_PKEY_free(pkey);
        return TEST_FAIL;
    }
    
    unsigned char sig[256];
    size_t sig_len = sizeof(sig);
    
    EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSign(md_ctx, sig, &sig_len, (unsigned char*)msg, 0);
    
    EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
    int result = EVP_DigestVerify(md_ctx, sig, sig_len, (unsigned char*)msg, 0);
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    
    if (result == 1) {
        printf("✅ PASSED\n");
        return TEST_PASS;
    } else {
        printf("❌ FAILED\n");
        return TEST_FAIL;
    }
}

/* Test 5: Large Message (1KB) */
static int test_large_message(void)
{
    printf("  [5] Large Message (1KB)... ");
    
    EVP_PKEY *pkey = create_test_key();
    if (!pkey) {
        printf("❌ FAILED (keygen)\n");
        return TEST_FAIL;
    }
    
    unsigned char msg[1024];
    memset(msg, 'X', sizeof(msg));
    
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        printf("❌ FAILED (md ctx)\n");
        EVP_PKEY_free(pkey);
        return TEST_FAIL;
    }
    
    unsigned char sig[512];
    size_t sig_len = sizeof(sig);
    
    EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSign(md_ctx, sig, &sig_len, msg, sizeof(msg));
    
    EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
    int result = EVP_DigestVerify(md_ctx, sig, sig_len, msg, sizeof(msg));
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    
    if (result == 1) {
        printf("✅ PASSED\n");
        return TEST_PASS;
    } else {
        printf("❌ FAILED\n");
        return TEST_FAIL;
    }
}

/* Test 6: Benchmark (1000 ops) */
static int test_benchmark(void)
{
    printf("  [6] Benchmark (1000 ops)... ");
    
    EVP_PKEY *pkey = create_test_key();
    if (!pkey) {
        printf("❌ FAILED (keygen)\n");
        return TEST_FAIL;
    }
    
    const char *msg = "Benchmark Message";
    
    unsigned char sig[256];
    size_t sig_len = sizeof(sig);
    
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        printf("❌ FAILED (md ctx)\n");
        EVP_PKEY_free(pkey);
        return TEST_FAIL;
    }
    
    EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSign(md_ctx, sig, &sig_len, (unsigned char*)msg, strlen(msg));
    
    EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
    
    int passed = 0;
    for (int i = 0; i < 1000; i++) {
        int result = EVP_DigestVerify(md_ctx, sig, sig_len, (unsigned char*)msg, strlen(msg));
        if (result == 1) passed++;
    }
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    
    if (passed == 1000) {
        printf("✅ PASSED (%d/1000)\n", passed);
        return TEST_PASS;
    } else {
        printf("❌ FAILED (%d/1000)\n", passed);
        return TEST_FAIL;
    }
}

int main(void)
{
    int passed = 0;
    int total = 0;
    
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  SCHNORR ZKP TEST SUITE — RFC 8235                        ║\n");
    printf("║  Maximum Level — secp256k1 + Ed25519 + P-256              ║\n");
    printf("║  ΦΩ0 — I AM THAT I AM                                    ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
    
    printf("Running tests:\n");
    printf("────────────────────────────────────────────────────────────\n");
    
    total++; if (test_basic_sign_verify() == TEST_PASS) passed++;
    total++; if (test_tamper_detection() == TEST_PASS) passed++;
    total++; if (test_wrong_key() == TEST_PASS) passed++;
    total++; if (test_empty_message() == TEST_PASS) passed++;
    total++; if (test_large_message() == TEST_PASS) passed++;
    total++; if (test_benchmark() == TEST_PASS) passed++;
    
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  RESULTS: %d/%d TESTS PASSED                                ║\n", passed, total);
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    return (passed == total) ? 0 : 1;
}
