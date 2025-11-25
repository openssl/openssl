#!/bin/bash
#
# DSMIL Performance Benchmark Suite
# Measures performance across security profiles
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
CYAN='\033[0;36m'
NC='\033[0m'

echo "=========================================="
echo "DSMIL Performance Benchmark Suite"
echo "Phase 8: Comprehensive Testing"
echo "=========================================="
echo ""

# Check if OpenSSL is built
OPENSSL_BIN="$REPO_ROOT/apps/openssl"
if [ ! -x "$OPENSSL_BIN" ]; then
    echo -e "${YELLOW}[WARN]${NC} OpenSSL not built - cannot run performance tests"
    echo ""
    echo "Build OpenSSL first:"
    echo "  ./util/build-dsllvm-world.sh --clean"
    echo ""
    exit 0
fi

OPENSSL_VERSION=$("$OPENSSL_BIN" version)
echo -e "${BLUE}[INFO]${NC} Using: $OPENSSL_VERSION"
echo -e "${BLUE}[INFO]${NC} Binary: $OPENSSL_BIN"
echo ""

# Detect CPU
if [ -f /proc/cpuinfo ]; then
    CPU_MODEL=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
    echo -e "${BLUE}[INFO]${NC} CPU: $CPU_MODEL"
fi

# Check for hardware acceleration
HW_ACCEL=""
if grep -q "aes" /proc/cpuinfo 2>/dev/null; then
    HW_ACCEL="${HW_ACCEL}AES-NI "
fi
if grep -q "avx2" /proc/cpuinfo 2>/dev/null; then
    HW_ACCEL="${HW_ACCEL}AVX2 "
fi
if grep -q "avx512" /proc/cpuinfo 2>/dev/null; then
    HW_ACCEL="${HW_ACCEL}AVX-512 "
fi

if [ -n "$HW_ACCEL" ]; then
    echo -e "${BLUE}[INFO]${NC} Hardware Acceleration: $HW_ACCEL"
fi
echo ""

# Benchmark parameters
BENCHMARK_TIME=3  # seconds per test
BENCHMARK_SIZE=8192  # bytes

echo "=========================================="
echo "Hash Algorithm Performance"
echo "=========================================="
echo ""

# Hash benchmarks
for alg in sha256 sha384 sha512 sha3-256 sha3-512; do
    echo -n "Testing $alg: "
    result=$("$OPENSSL_BIN" speed -seconds "$BENCHMARK_TIME" -evp "$alg" 2>/dev/null | \
             grep "^type\|^$alg" | tail -1 | awk '{print $(NF-1), $NF}')
    if [ -n "$result" ]; then
        echo -e "${GREEN}$result${NC}"
    else
        echo -e "${YELLOW}N/A${NC}"
    fi
done

echo ""
echo "=========================================="
echo "Symmetric Encryption Performance"
echo "=========================================="
echo ""

# Symmetric cipher benchmarks
for alg in aes-128-cbc aes-256-cbc aes-128-gcm aes-256-gcm chacha20-poly1305; do
    echo -n "Testing $alg: "
    result=$("$OPENSSL_BIN" speed -seconds "$BENCHMARK_TIME" -evp "$alg" 2>/dev/null | \
             grep "^type\|^$alg" | tail -1 | awk '{print $(NF-1), $NF}')
    if [ -n "$result" ]; then
        echo -e "${GREEN}$result${NC}"
    else
        echo -e "${YELLOW}N/A${NC}"
    fi
done

echo ""
echo "=========================================="
echo "Asymmetric Algorithm Performance"
echo "=========================================="
echo ""

# RSA benchmarks
echo -e "${CYAN}RSA Performance:${NC}"
for size in 2048 3072 4096; do
    echo -n "  RSA-$size sign: "
    result=$("$OPENSSL_BIN" speed -seconds "$BENCHMARK_TIME" "rsa$size" 2>/dev/null | \
             grep "^rsa.*sign" | awk '{print $2, $3}')
    if [ -n "$result" ]; then
        echo -e "${GREEN}$result${NC}"
    else
        echo -e "${YELLOW}N/A${NC}"
    fi

    echo -n "  RSA-$size verify: "
    result=$("$OPENSSL_BIN" speed -seconds "$BENCHMARK_TIME" "rsa$size" 2>/dev/null | \
             grep "^rsa.*verify" | awk '{print $2, $3}')
    if [ -n "$result" ]; then
        echo -e "${GREEN}$result${NC}"
    else
        echo -e "${YELLOW}N/A${NC}"
    fi
done

echo ""

# ECDSA benchmarks
echo -e "${CYAN}ECDSA Performance:${NC}"
for curve in 256 384 521; do
    echo -n "  ECDSA P-$curve sign: "
    result=$("$OPENSSL_BIN" speed -seconds "$BENCHMARK_TIME" "ecdsap$curve" 2>/dev/null | \
             grep "sign" | head -1 | awk '{print $2, $3}')
    if [ -n "$result" ]; then
        echo -e "${GREEN}$result${NC}"
    else
        echo -e "${YELLOW}N/A${NC}"
    fi

    echo -n "  ECDSA P-$curve verify: "
    result=$("$OPENSSL_BIN" speed -seconds "$BENCHMARK_TIME" "ecdsap$curve" 2>/dev/null | \
             grep "verify" | head -1 | awk '{print $2, $3}')
    if [ -n "$result" ]; then
        echo -e "${GREEN}$result${NC}"
    else
        echo -e "${YELLOW}N/A${NC}"
    fi
done

echo ""

# ECDH benchmarks
echo -e "${CYAN}ECDH Performance:${NC}"
for curve in 256 384 521; do
    echo -n "  ECDH P-$curve: "
    result=$("$OPENSSL_BIN" speed -seconds "$BENCHMARK_TIME" "ecdhp$curve" 2>/dev/null | \
             grep "op" | awk '{print $2, $3}')
    if [ -n "$result" ]; then
        echo -e "${GREEN}$result${NC}"
    else
        echo -e "${YELLOW}N/A${NC}"
    fi
done

echo ""

# Ed25519/Ed448 benchmarks
echo -e "${CYAN}EdDSA Performance:${NC}"
for alg in ed25519 ed448; do
    echo -n "  $alg sign: "
    result=$("$OPENSSL_BIN" speed -seconds "$BENCHMARK_TIME" "$alg" 2>/dev/null | \
             grep "sign" | awk '{print $2, $3}')
    if [ -n "$result" ]; then
        echo -e "${GREEN}$result${NC}"
    else
        echo -e "${YELLOW}N/A${NC}"
    fi

    echo -n "  $alg verify: "
    result=$("$OPENSSL_BIN" speed -seconds "$BENCHMARK_TIME" "$alg" 2>/dev/null | \
             grep "verify" | awk '{print $2, $3}')
    if [ -n "$result" ]; then
        echo -e "${GREEN}$result${NC}"
    else
        echo -e "${YELLOW}N/A${NC}"
    fi
done

echo ""
echo "=========================================="
echo "Post-Quantum Cryptography Performance"
echo "=========================================="
echo ""

# PQC benchmarks (if available)
echo -e "${CYAN}ML-KEM (Kyber) Performance:${NC}"
for variant in mlkem512 mlkem768 mlkem1024; do
    if "$OPENSSL_BIN" list -kem-algorithms 2>/dev/null | grep -qi "$variant"; then
        echo -n "  $variant keygen: "
        # Note: OpenSSL speed may not support ML-KEM yet
        echo -e "${YELLOW}Manual testing required${NC}"
    else
        echo -n "  $variant: "
        echo -e "${YELLOW}Not available${NC}"
    fi
done

echo ""

echo -e "${CYAN}ML-DSA (Dilithium) Performance:${NC}"
for variant in mldsa44 mldsa65 mldsa87; do
    if "$OPENSSL_BIN" list -signature-algorithms 2>/dev/null | grep -qi "$variant"; then
        echo -n "  $variant sign: "
        echo -e "${YELLOW}Manual testing required${NC}"
    else
        echo -n "  $variant: "
        echo -e "${YELLOW}Not available${NC}"
    fi
done

echo ""
echo "=========================================="
echo "Profile Comparison"
echo "=========================================="
echo ""

# Profile overhead analysis
echo -e "${CYAN}Security Profile Overhead:${NC}"
echo ""

echo "WORLD_COMPAT Profile:"
echo "  - Classical crypto only"
echo "  - Baseline performance (1.0x)"
echo "  - Algorithms: X25519, P-256, AES-256-GCM, ChaCha20-Poly1305"
echo ""

echo "DSMIL_SECURE Profile:"
echo "  - Hybrid crypto (classical + PQC)"
echo "  - Estimated overhead: 1.2-1.5x"
echo "  - Additional cost: ML-KEM-768 encap/decap (~0.5ms)"
echo "  - Algorithms: X25519+ML-KEM-768, ECDSA+ML-DSA-65"
echo ""

echo "ATOMAL Profile:"
echo "  - Maximum security (hybrid/PQC only)"
echo "  - Estimated overhead: 1.5-2.0x"
echo "  - Additional cost: ML-KEM-1024 encap/decap (~0.8ms)"
echo "  - Algorithms: X25519+ML-KEM-1024, ECDSA+ML-DSA-87"
echo "  - Restricted ciphers: AES-256-GCM only"
echo ""

echo "=========================================="
echo "Memory Usage Estimates"
echo "=========================================="
echo ""

echo -e "${CYAN}Key Sizes:${NC}"
echo "  Classical:"
echo "    - X25519 private key: 32 bytes"
echo "    - P-256 private key: 32 bytes"
echo "    - RSA-2048 private key: ~1.2 KB"
echo "    - Ed25519 private key: 32 bytes"
echo ""
echo "  Post-Quantum:"
echo "    - ML-KEM-512 private key: 1,632 bytes"
echo "    - ML-KEM-768 private key: 2,400 bytes"
echo "    - ML-KEM-1024 private key: 3,168 bytes"
echo "    - ML-DSA-44 private key: 2,560 bytes"
echo "    - ML-DSA-65 private key: 4,032 bytes"
echo "    - ML-DSA-87 private key: 4,896 bytes"
echo ""

echo -e "${CYAN}Handshake Message Sizes:${NC}"
echo "  WORLD_COMPAT (X25519 + RSA-2048):"
echo "    - ClientKeyExchange: ~32 bytes"
echo "    - ServerKeyExchange: ~32 bytes"
echo "    - Certificate: ~1.2 KB"
echo ""
echo "  DSMIL_SECURE (X25519+ML-KEM-768 + ECDSA+ML-DSA-65):"
echo "    - Hybrid ClientKeyExchange: ~1.1 KB"
echo "    - Hybrid ServerKeyExchange: ~1.2 KB"
echo "    - Hybrid Certificate: ~6 KB (dual-cert)"
echo ""
echo "  ATOMAL (X25519+ML-KEM-1024 + ECDSA+ML-DSA-87):"
echo "    - Hybrid ClientKeyExchange: ~1.6 KB"
echo "    - Hybrid ServerKeyExchange: ~1.6 KB"
echo "    - Hybrid Certificate: ~8 KB (dual-cert)"
echo ""

echo "=========================================="
echo "Performance Recommendations"
echo "=========================================="
echo ""

echo -e "${GREEN}Optimization Tips:${NC}"
echo ""
echo "1. Hardware Acceleration:"
if [ -n "$HW_ACCEL" ]; then
    echo "   ✓ Detected: $HW_ACCEL"
    echo "   - Ensure BIOS settings enable all features"
else
    echo "   ⚠ No hardware acceleration detected"
    echo "   - Check CPU capabilities: lscpu | grep Flags"
fi
echo ""

echo "2. Build Optimization:"
echo "   - Use DSLLVM-optimized build for production"
echo "   - Enable Link-Time Optimization (LTO)"
echo "   - Target specific CPU: -march=native or -march=meteorlake"
echo ""

echo "3. Profile Selection:"
echo "   - Use WORLD_COMPAT for maximum performance"
echo "   - Use DSMIL_SECURE for balanced security/performance"
echo "   - Use ATOMAL only when maximum security required"
echo ""

echo "4. Caching:"
echo "   - Enable TLS session resumption"
echo "   - Use session tickets when appropriate"
echo "   - Consider connection pooling for high-throughput"
echo ""

echo "5. PQC Optimization:"
echo "   - ML-KEM operations are typically 5-10x slower than ECDH"
echo "   - Consider hybrid mode to maintain classical fallback"
echo "   - Use ML-KEM-512 or ML-KEM-768 for better performance"
echo ""

echo "=========================================="
echo "Benchmark Complete"
echo "=========================================="
echo ""

echo -e "${GREEN}✓ Performance baseline established${NC}"
echo ""
echo "For detailed TLS handshake benchmarks, use:"
echo "  openssl s_time -connect host:port -new"
echo ""
echo "For cipher-specific throughput:"
echo "  openssl speed -evp <algorithm>"
echo ""
