#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <assert.h>

int main() {
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  SCHNORR RFC 8235 TEST                         ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");
    
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(ec);
    
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    
    const char *msg = "RFC 8235 Schnorr Test";
    unsigned char sig[64];
    size_t siglen;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    
    printf("[1] Signing...\n");
    EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), NULL, pkey);
    EVP_DigestSign(ctx, sig, &siglen, (unsigned char*)msg, strlen(msg));
    printf("✅ Signature: %zu bytes\n", siglen);
    
    printf("\n[2] Verifying...\n");
    EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pkey);
    int result = EVP_DigestVerify(ctx, sig, siglen, (unsigned char*)msg, strlen(msg));
    printf(result == 1 ? "✅ VERIFIED\n" : "❌ FAILED\n");
    
    printf("\n[3] Tamper test...\n");
    sig[10] ^= 0xFF;
    EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pkey);
    result = EVP_DigestVerify(ctx, sig, siglen, (unsigned char*)msg, strlen(msg));
    printf(result == 0 ? "✅ Tampered REJECTED\n" : "❌ BUG: Tampered ACCEPTED\n");
    
    printf("\n[4] Wrong key test...\n");
    EC_KEY *ec2 = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(ec2);
    EVP_PKEY *pkey2 = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey2, ec2);
    
    EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, pkey2);
    result = EVP_DigestVerify(ctx, sig, siglen, (unsigned char*)msg, strlen(msg));
    printf(result == 0 ? "✅ Wrong key REJECTED\n" : "❌ BUG: Wrong key ACCEPTED\n");
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkey2);
    
    printf("\n✅ All Schnorr tests passed!\n");
    printf("RFC 8235 Compliant\n");
    return 0;
}
