#!/bin/bash
#
# DSMIL Fuzzing Preparation Script
# Sets up fuzzing infrastructure for DSMIL OpenSSL
#
# Copyright 2025 DSMIL Security Team. All Rights Reserved.
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "=========================================="
echo "DSMIL Fuzzing Infrastructure Setup"
echo "Phase 8: Security Testing"
echo "=========================================="
echo ""

# Check for fuzzing tools
echo -e "${BLUE}[INFO]${NC} Checking for fuzzing tools..."
echo ""

FUZZING_AVAILABLE=0

# Check for AFL++
if command -v afl-fuzz >/dev/null 2>&1; then
    AFL_VERSION=$(afl-fuzz --version 2>&1 | head -1 || echo "unknown")
    echo -e "${GREEN}✓${NC} AFL++ found: $AFL_VERSION"
    ((FUZZING_AVAILABLE++))
else
    echo -e "${YELLOW}✗${NC} AFL++ not found"
    echo "  Install: apt-get install afl++ (Ubuntu/Debian)"
    echo "       or: brew install afl++(macOS)"
fi

# Check for libFuzzer
if command -v clang >/dev/null 2>&1; then
    if clang --version 2>&1 | grep -q "clang"; then
        echo -e "${GREEN}✓${NC} Clang found (libFuzzer available)"
        ((FUZZING_AVAILABLE++))
    fi
else
    echo -e "${YELLOW}✗${NC} Clang not found (needed for libFuzzer)"
fi

# Check for Honggfuzz
if command -v honggfuzz >/dev/null 2>&1; then
    HONGGFUZZ_VERSION=$(honggfuzz --version 2>&1 | head -1 || echo "unknown")
    echo -e "${GREEN}✓${NC} Honggfuzz found: $HONGGFUZZ_VERSION"
    ((FUZZING_AVAILABLE++))
else
    echo -e "${YELLOW}✗${NC} Honggfuzz not found"
fi

echo ""

if [ $FUZZING_AVAILABLE -eq 0 ]; then
    echo -e "${RED}[ERROR]${NC} No fuzzing tools available"
    echo ""
    echo "Install at least one fuzzing tool:"
    echo "  - AFL++: https://github.com/AFLplusplus/AFLplusplus"
    echo "  - libFuzzer: Part of Clang/LLVM"
    echo "  - Honggfuzz: https://github.com/google/honggfuzz"
    echo ""
    exit 1
fi

echo -e "${GREEN}[OK]${NC} Fuzzing tools available ($FUZZING_AVAILABLE found)"
echo ""

# Fuzzing targets
echo "=========================================="
echo "Fuzzing Targets"
echo "=========================================="
echo ""

echo "Recommended fuzzing targets for DSMIL:"
echo ""

echo -e "${BLUE}1. TLS Handshake State Machine${NC}"
echo "   - Target: TLS server/client handshake"
echo "   - Input: Malformed TLS messages"
echo "   - Coverage: SSL_accept(), SSL_connect()"
echo "   - Priority: HIGH"
echo ""

echo -e "${BLUE}2. X.509 Certificate Parsing${NC}"
echo "   - Target: Certificate validation"
echo "   - Input: Malformed X.509 certificates"
echo "   - Coverage: X509_verify_cert(), d2i_X509()"
echo "   - Priority: HIGH"
echo ""

echo -e "${BLUE}3. PQC Algorithm Implementations${NC}"
echo "   - Target: ML-KEM decapsulation"
echo "   - Input: Malformed ciphertexts"
echo "   - Coverage: ML-KEM private key operations"
echo "   - Priority: CRITICAL (constant-time sensitive)"
echo ""

echo -e "${BLUE}4. Policy Provider Decision Logic${NC}"
echo "   - Target: Policy enforcement"
echo "   - Input: Various profile/algorithm combinations"
echo "   - Coverage: dsmil_policy_check_*()"
echo "   - Priority: MEDIUM"
echo ""

echo -e "${BLUE}5. Event Telemetry JSON Generation${NC}"
echo "   - Target: Event formatting"
echo "   - Input: Malformed event data"
echo "   - Coverage: dsmil_event_create_json()"
echo "   - Priority: LOW"
echo ""

echo "=========================================="
echo "Building for Fuzzing"
echo "=========================================="
echo ""

echo "To build OpenSSL for fuzzing:"
echo ""

echo -e "${YELLOW}Using AFL++:${NC}"
echo "  export CC=afl-clang-fast"
echo "  export CXX=afl-clang-fast++"
echo "  ./Configure linux-x86_64 --debug"
echo "  make clean && make -j\$(nproc)"
echo ""

echo -e "${YELLOW}Using libFuzzer:${NC}"
echo "  export CC=clang"
echo "  export CXX=clang++"
echo "  export CFLAGS=\"-fsanitize=fuzzer,address -g\""
echo "  ./Configure linux-x86_64 --debug"
echo "  make clean && make -j\$(nproc)"
echo ""

echo -e "${YELLOW}With ASAN (Address Sanitizer):${NC}"
echo "  export CFLAGS=\"-fsanitize=address,undefined -g\""
echo "  ./Configure linux-x86_64 --debug"
echo "  make clean && make -j\$(nproc)"
echo ""

# Create fuzzing harness examples
FUZZ_DIR="$REPO_ROOT/fuzz/dsmil"
mkdir -p "$FUZZ_DIR"

echo "=========================================="
echo "Creating Fuzzing Harnesses"
echo "=========================================="
echo ""

# TLS handshake fuzzer
cat > "$FUZZ_DIR/fuzz_tls_server.c" << 'EOF'
/*
 * TLS Server Handshake Fuzzer
 * Fuzzes the TLS server handshake state machine
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdint.h>
#include <stdlib.h>

/* libFuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *rbio = NULL, *wbio = NULL;

    /* Initialize SSL context */
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return 0;

    /* Load DSMIL configuration */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    /* Create SSL object */
    ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return 0;
    }

    /* Set up BIOs with fuzzed input */
    rbio = BIO_new_mem_buf(data, size);
    wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, rbio, wbio);

    /* Attempt handshake with fuzzed input */
    SSL_set_accept_state(ssl);
    (void)SSL_do_handshake(ssl);

    /* Cleanup */
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
EOF

echo -e "${GREEN}✓${NC} Created: fuzz/dsmil/fuzz_tls_server.c"

# X.509 certificate fuzzer
cat > "$FUZZ_DIR/fuzz_x509_cert.c" << 'EOF'
/*
 * X.509 Certificate Parsing Fuzzer
 * Fuzzes certificate parsing and validation
 */

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <stdint.h>
#include <stdlib.h>

/* libFuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    X509 *cert = NULL;
    BIO *bio = NULL;
    const uint8_t *p = data;

    /* Try DER format */
    cert = d2i_X509(NULL, &p, size);
    if (cert) {
        /* Validate certificate */
        X509_check_ca(cert);
        X509_check_purpose(cert, X509_PURPOSE_SSL_SERVER, 0);
        X509_free(cert);
        cert = NULL;
    }

    /* Try PEM format */
    bio = BIO_new_mem_buf(data, size);
    if (bio) {
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (cert) {
            X509_check_ca(cert);
            X509_free(cert);
        }
        BIO_free(bio);
    }

    return 0;
}
EOF

echo -e "${GREEN}✓${NC} Created: fuzz/dsmil/fuzz_x509_cert.c"

# Policy provider fuzzer
cat > "$FUZZ_DIR/fuzz_policy.c" << 'EOF'
/*
 * DSMIL Policy Provider Fuzzer
 * Fuzzes policy decision logic
 */

#include "providers/dsmil/policy.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* libFuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    DSMIL_POLICY_CTX *ctx = NULL;

    if (size < 2) return 0;

    /* Create policy context */
    ctx = dsmil_policy_ctx_new(NULL);
    if (!ctx) return 0;

    /* Fuzz profile selection */
    DSMIL_PROFILE profile = (DSMIL_PROFILE)(data[0] % 3);
    dsmil_policy_set_profile(ctx, profile);

    /* Fuzz algorithm checks */
    if (size > 2) {
        char alg_name[256];
        size_t name_len = (size - 2 < sizeof(alg_name) - 1) ?
                          (size - 2) : (sizeof(alg_name) - 1);
        memcpy(alg_name, data + 2, name_len);
        alg_name[name_len] = '\0';

        int is_hybrid = data[1] & 0x01;

        /* Fuzz KEM check */
        dsmil_policy_check_kem(ctx, alg_name, is_hybrid);

        /* Fuzz signature check */
        dsmil_policy_check_signature(ctx, alg_name, is_hybrid);

        /* Fuzz cipher check */
        dsmil_policy_check_cipher(ctx, alg_name);
    }

    /* Cleanup */
    dsmil_policy_ctx_free(ctx);

    return 0;
}
EOF

echo -e "${GREEN}✓${NC} Created: fuzz/dsmil/fuzz_policy.c"

# Create Makefile for fuzzers
cat > "$FUZZ_DIR/Makefile" << 'EOF'
# DSMIL Fuzzing Harnesses Makefile

OPENSSL_DIR = ../..
OPENSSL_LIB = $(OPENSSL_DIR)/libssl.a $(OPENSSL_DIR)/libcrypto.a

CC = clang
CFLAGS = -g -fsanitize=fuzzer,address -I$(OPENSSL_DIR)/include
LDFLAGS = -L$(OPENSSL_DIR) -lssl -lcrypto -lpthread -ldl

FUZZERS = fuzz_tls_server fuzz_x509_cert fuzz_policy

all: $(FUZZERS)

fuzz_tls_server: fuzz_tls_server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

fuzz_x509_cert: fuzz_x509_cert.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

fuzz_policy: fuzz_policy.c
	$(CC) $(CFLAGS) -o $@ $< -I$(OPENSSL_DIR)/providers/dsmil $(LDFLAGS)

clean:
	rm -f $(FUZZERS)
	rm -rf corpus_* crashes_* hangs_*

.PHONY: all clean
EOF

echo -e "${GREEN}✓${NC} Created: fuzz/dsmil/Makefile"
echo ""

echo "=========================================="
echo "Running Fuzzers"
echo "=========================================="
echo ""

echo "To run the fuzzers:"
echo ""

echo -e "${YELLOW}1. Build OpenSSL with fuzzing instrumentation${NC}"
echo "   cd $REPO_ROOT"
echo "   export CC=clang"
echo "   export CFLAGS=\"-fsanitize=fuzzer-no-link,address -g\""
echo "   ./Configure linux-x86_64 --debug"
echo "   make clean && make -j\$(nproc)"
echo ""

echo -e "${YELLOW}2. Build fuzzing harnesses${NC}"
echo "   cd fuzz/dsmil"
echo "   make"
echo ""

echo -e "${YELLOW}3. Create corpus directories${NC}"
echo "   mkdir -p corpus_tls corpus_x509 corpus_policy"
echo ""

echo -e "${YELLOW}4. Run fuzzers${NC}"
echo "   ./fuzz_tls_server corpus_tls/ -max_total_time=3600"
echo "   ./fuzz_x509_cert corpus_x509/ -max_total_time=3600"
echo "   ./fuzz_policy corpus_policy/ -max_total_time=3600"
echo ""

echo -e "${YELLOW}5. Monitor for crashes${NC}"
echo "   Crashes will be saved in: crashes_*/"
echo "   Hangs will be saved in: hangs_*/"
echo ""

echo "=========================================="
echo "Integration with CI/CD"
echo "=========================================="
echo ""

echo "For continuous fuzzing:"
echo ""

echo "1. OSS-Fuzz Integration:"
echo "   - Submit to https://github.com/google/oss-fuzz"
echo "   - Get 24/7 continuous fuzzing on Google infrastructure"
echo ""

echo "2. Local CI Pipeline:"
echo "   - Run fuzzers for 1-2 hours per commit"
echo "   - Fail build on new crashes"
echo "   - Archive corpus for regression testing"
echo ""

echo "3. Regression Testing:"
echo "   - Save all crash inputs to corpus"
echo "   - Re-run corpus on each build"
echo "   - Ensure fixed crashes don't reappear"
echo ""

echo "=========================================="
echo "Fuzzing Preparation Complete"
echo "=========================================="
echo ""

if [ $FUZZING_AVAILABLE -gt 0 ]; then
    echo -e "${GREEN}✓ Fuzzing infrastructure ready${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Build OpenSSL with fuzzing instrumentation"
    echo "  2. Build harnesses: cd fuzz/dsmil && make"
    echo "  3. Run fuzzers on critical components"
    echo "  4. Review crashes and fix issues"
    echo ""
else
    echo -e "${YELLOW}⚠ Install fuzzing tools to proceed${NC}"
    echo ""
fi
