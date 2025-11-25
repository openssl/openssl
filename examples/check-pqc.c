/*
 * check-pqc.c - Check for PQC algorithm availability in OpenSSL
 *
 * This utility checks if ML-KEM and ML-DSA are available and prints
 * information about supported PQC algorithms.
 *
 * Compile:
 *   gcc -o check-pqc check-pqc.c -I/opt/openssl-dsmil/include \
 *       -L/opt/openssl-dsmil/lib64 -lssl -lcrypto
 *
 * Run:
 *   ./check-pqc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>

#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[0;34m"
#define COLOR_RED     "\033[0;31m"
#define COLOR_RESET   "\033[0m"

void check_algorithm(const char *name, const char *type)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);

    if (ctx != NULL) {
        printf(COLOR_GREEN "  ✓ %s (%s)" COLOR_RESET "\n", name, type);
        EVP_PKEY_CTX_free(ctx);
    } else {
        printf(COLOR_RED "  ✗ %s (%s)" COLOR_RESET "\n", name, type);
    }
}

void check_kem_algorithm(const char *name)
{
    check_algorithm(name, "KEM");
}

void check_signature_algorithm(const char *name)
{
    check_algorithm(name, "Signature");
}

void print_openssl_version(void)
{
    printf(COLOR_BLUE "OpenSSL Version:" COLOR_RESET "\n");
    printf("  %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("  %s\n", OpenSSL_version(OPENSSL_BUILT_ON));
    printf("  %s\n\n", OpenSSL_version(OPENSSL_CFLAGS));
}

void print_loaded_providers(void)
{
    printf(COLOR_BLUE "Loaded Providers:" COLOR_RESET "\n");

    /* Iterate through all providers */
    OSSL_PROVIDER *prov;
    const char *provname;

    /* Try to get some common providers */
    const char *provider_names[] = {
        "default",
        "base",
        "fips",
        "legacy",
        "pqc",
        "dsmil-policy",
        NULL
    };

    for (int i = 0; provider_names[i] != NULL; i++) {
        prov = OSSL_PROVIDER_try_load(NULL, provider_names[i], 0);
        if (prov != NULL) {
            provname = OSSL_PROVIDER_get0_name(prov);
            printf(COLOR_GREEN "  ✓ %s" COLOR_RESET "\n", provname);
            /* Don't unload - keep it loaded for checks */
        } else {
            printf(COLOR_YELLOW "  - %s (not loaded)" COLOR_RESET "\n", provider_names[i]);
        }
    }

    printf("\n");
}

int main(void)
{
    printf("\n");
    printf(COLOR_BLUE "========================================\n");
    printf("DSMIL PQC Algorithm Checker\n");
    printf("========================================" COLOR_RESET "\n\n");

    print_openssl_version();
    print_loaded_providers();

    /* Check for ML-KEM variants */
    printf(COLOR_BLUE "ML-KEM (Key Encapsulation):" COLOR_RESET "\n");
    check_kem_algorithm("ML-KEM-512");
    check_kem_algorithm("ML-KEM-768");
    check_kem_algorithm("ML-KEM-1024");
    printf("\n");

    /* Check for ML-DSA variants */
    printf(COLOR_BLUE "ML-DSA (Digital Signatures):" COLOR_RESET "\n");
    check_signature_algorithm("ML-DSA-44");
    check_signature_algorithm("ML-DSA-65");
    check_signature_algorithm("ML-DSA-87");
    printf("\n");

    /* Check for classical algorithms */
    printf(COLOR_BLUE "Classical Algorithms:" COLOR_RESET "\n");
    check_algorithm("X25519", "KEX");
    check_algorithm("P-256", "KEX");
    check_algorithm("Ed25519", "Signature");
    check_algorithm("RSA", "Signature/KEX");
    printf("\n");

    /* Check for hybrid groups (these may not be directly queryable) */
    printf(COLOR_BLUE "Hybrid Support:" COLOR_RESET "\n");
    printf(COLOR_YELLOW "  Note: Hybrid algorithms checked at TLS layer\n" COLOR_RESET);
    printf("  X25519+ML-KEM-768 (expected)\n");
    printf("  P-256+ML-KEM-768 (expected)\n");
    printf("  X25519+ML-KEM-1024 (expected)\n");
    printf("\n");

    /* Configuration info */
    const char *conf = getenv("OPENSSL_CONF");
    const char *profile = getenv("DSMIL_PROFILE");

    printf(COLOR_BLUE "Configuration:" COLOR_RESET "\n");
    printf("  OPENSSL_CONF: %s\n", conf ? conf : "(default)");
    printf("  DSMIL_PROFILE: %s\n", profile ? profile : "(default)");
    printf("\n");

    printf(COLOR_GREEN "✓ PQC check complete\n" COLOR_RESET);
    printf("\n");

    return 0;
}

/*
 * Example Output:
 *
 * ========================================
 * DSMIL PQC Algorithm Checker
 * ========================================
 *
 * OpenSSL Version:
 *   OpenSSL 3.x.x (DSMIL fork)
 *   ...
 *
 * Loaded Providers:
 *   ✓ default
 *   ✓ base
 *   - fips (not loaded)
 *   - legacy (not loaded)
 *   ✓ pqc
 *   ✓ dsmil-policy
 *
 * ML-KEM (Key Encapsulation):
 *   ✓ ML-KEM-512 (KEM)
 *   ✓ ML-KEM-768 (KEM)
 *   ✓ ML-KEM-1024 (KEM)
 *
 * ML-DSA (Digital Signatures):
 *   ✓ ML-DSA-44 (Signature)
 *   ✓ ML-DSA-65 (Signature)
 *   ✓ ML-DSA-87 (Signature)
 *
 * Classical Algorithms:
 *   ✓ X25519 (KEX)
 *   ✓ P-256 (KEX)
 *   ✓ Ed25519 (Signature)
 *   ✓ RSA (Signature/KEX)
 *
 * Hybrid Support:
 *   Note: Hybrid algorithms checked at TLS layer
 *   X25519+ML-KEM-768 (expected)
 *   P-256+ML-KEM-768 (expected)
 *   X25519+ML-KEM-1024 (expected)
 *
 * Configuration:
 *   OPENSSL_CONF: /opt/openssl-dsmil/ssl/dsmil-secure.cnf
 *   DSMIL_PROFILE: DSMIL_SECURE
 *
 * ✓ PQC check complete
 */
