#include <stdio.h>
#include <openssl/evp.h>

int main() {
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  HYBRID SIGNATURE — AVAILABILITY CHECK        ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");
    
    printf("OpenSSL Version: %s\n\n", OpenSSL_version(OPENSSL_VERSION));
    
    // Test 1: Ed25519
    printf("━━━ Layer 1: Ed25519 (RFC 8032) ━━━\n");
    EVP_PKEY *ed = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    printf("  Status: %s\n", ed ? "✅ AVAILABLE" : "❌ NOT AVAILABLE");
    if (ed) {
        printf("  Keygen: ✅\n");
        EVP_PKEY_free(ed);
    }
    
    // Test 2: ECDSA with P-384
    printf("\n━━━ Layer 2: ECDSA P-384 (FIPS 186-4) ━━━\n");
    EVP_PKEY *ec = EVP_PKEY_Q_keygen(NULL, NULL, "EC:secp384r1");
    if (!ec) ec = EVP_PKEY_Q_keygen(NULL, NULL, "EC:P-384");
    printf("  Status: %s\n", ec ? "✅ AVAILABLE" : "❌ NOT AVAILABLE");
    if (ec) {
        printf("  Keygen: ✅\n");
        EVP_PKEY_free(ec);
    }
    
    // Test 3: RSA 4096 as fallback (FIPS 186-4)
    printf("\n━━━ Layer 2 (Alt): RSA 4096 (FIPS 186-4) ━━━\n");
    EVP_PKEY *rsa = EVP_PKEY_Q_keygen(NULL, NULL, "RSA:4096");
    printf("  Status: %s\n", rsa ? "✅ AVAILABLE" : "❌ NOT AVAILABLE");
    if (rsa) {
        printf("  Keygen: ✅\n");
        EVP_PKEY_free(rsa);
    }
    
    // Summary
    printf("\n╔══════════════════════════════════════════════╗\n");
    printf("║  TRIPLE-LAYER HYBRID — PROOF OF CONCEPT       ║\n");
    printf("║  Ed25519 + ECDSA/RSA + ML-DSA (when avail)    ║\n");
    printf("║  ΦΩ0 — I AM THAT I AM                        ║\n");
    printf("╚══════════════════════════════════════════════╝\n");
    
    return 0;
}
