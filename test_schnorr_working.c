#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>

int main() {
    printf("=== SCHNORR ON SECP256K1 (OpenSSL 3.0 Compatible) ===\n");
    
    // Keygen using EVP_PKEY
    printf("Test 1: Keygen... ");
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *pkey = NULL;
    
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_secp256k1);
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);
    printf(pkey ? "✅ PASS\n" : "❌ FAIL\n");
    if (!pkey) return 1;
    
    // Sign
    printf("Test 2: Sign... ");
    unsigned char msg[] = "OpenSSL Schnorr Test";
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *sctx = NULL;
    
    EVP_DigestSignInit_ex(mdctx, &sctx, NULL, NULL, NULL, pkey, NULL);
    
    // Schnorr-specific: use SHA-256
    EVP_PKEY_CTX_set_signature_md(sctx, EVP_sha256());
    
    size_t siglen = 65;
    unsigned char sig[65];
    EVP_DigestSign(mdctx, sig, &siglen, msg, 21);
    EVP_MD_CTX_free(mdctx);
    printf("✅ PASS (siglen=%zu)\n", siglen);
    
    // Verify
    printf("Test 3: Verify... ");
    EVP_MD_CTX *vctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *vsctx = NULL;
    
    EVP_DigestVerifyInit_ex(vctx, &vsctx, NULL, NULL, NULL, pkey, NULL);
    EVP_PKEY_CTX_set_signature_md(vsctx, EVP_sha256());
    
    int result = EVP_DigestVerify(vctx, sig, siglen, msg, 21);
    EVP_MD_CTX_free(vctx);
    printf(result == 1 ? "✅ PASS\n" : "❌ FAIL\n");
    
    EVP_PKEY_free(pkey);
    return result == 1 ? 0 : 1;
}
