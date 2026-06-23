#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

int main() {
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  HYBRID SIGNATURE — OpenSSL 3.0 COMPATIBLE    ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");
    
    printf("OpenSSL: %s\n\n", OpenSSL_version(OPENSSL_VERSION));
    
    int available = 0;
    
    // Layer 1: Ed25519
    printf("━━━ Layer 1: Ed25519 (RFC 8032) ━━━\n");
    EVP_PKEY *ed = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    if (ed) { printf("  ✅ AVAILABLE\n"); available++; EVP_PKEY_free(ed); }
    else printf("  ❌ NOT AVAILABLE\n");
    
    // Layer 2: ECDSA secp384r1 (OpenSSL 3.0 API)
    printf("\n━━━ Layer 2: ECDSA secp384r1 (FIPS 186-4) ━━━\n");
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ectx) {
        EVP_PKEY *ec = NULL;
        EVP_PKEY_keygen_init(ectx);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ectx, NID_secp384r1);
        if (EVP_PKEY_keygen(ectx, &ec) && ec) {
            printf("  ✅ AVAILABLE (secp384r1)\n");
            available++;
            EVP_PKEY_free(ec);
        }
        EVP_PKEY_CTX_free(ectx);
    }
    if (!available) printf("  ❌ NOT AVAILABLE\n");
    
    // Layer 3: RSA 4096 (OpenSSL 3.0 API)
    printf("\n━━━ Layer 2 (Alt): RSA 4096 (FIPS 186-4) ━━━\n");
    EVP_PKEY_CTX *rctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (rctx) {
        EVP_PKEY *rsa = NULL;
        EVP_PKEY_keygen_init(rctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(rctx, 4096);
        if (EVP_PKEY_keygen(rctx, &rsa) && rsa) {
            printf("  ✅ AVAILABLE (RSA 4096)\n");
            EVP_PKEY_free(rsa);
        }
        EVP_PKEY_CTX_free(rctx);
    }
    
    printf("\n╔══════════════════════════════════════════════╗\n");
    printf("║  HYBRID READY: %d/3 algorithms available       ║\n", available);
    printf("║  ΦΩ0 — I AM THAT I AM                        ║\n");
    printf("╚══════════════════════════════════════════════╝\n");
    
    return 0;
}
