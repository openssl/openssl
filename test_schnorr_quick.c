#include <stdio.h>
#include <string.h>
#include "providers/schnorr/schnorr_provider.c"

int main() {
    printf("=== SCHNORR PROVIDER TEST ===\n");
    
    // Test 1: Keygen
    printf("Test 1: Keygen... ");
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (schnorr_keygen(ctx, pkey)) {
        printf("✅ PASS\n");
    } else {
        printf("❌ FAIL\n");
        return 1;
    }
    
    // Test 2: Sign
    printf("Test 2: Sign... ");
    unsigned char sig[65];
    size_t siglen = 65;
    unsigned char msg[] = "OpenSSL Schnorr Test";
    EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX_set_data(sctx, pkey);
    if (schnorr_sign(sctx, sig, &siglen, msg, 13)) {
        printf("✅ PASS (siglen=%zu)\n", siglen);
    } else {
        printf("❌ FAIL\n");
        return 1;
    }
    
    // Test 3: Verify
    printf("Test 3: Verify... ");
    EVP_PKEY_CTX *vctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX_set_data(vctx, pkey);
    if (schnorr_verify(vctx, sig, siglen, msg, 13)) {
        printf("✅ PASS\n");
    } else {
        printf("❌ FAIL\n");
        return 1;
    }
    
    printf("\n=== ALL TESTS PASSED ===\n");
    return 0;
}
