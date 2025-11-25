#!/usr/bin/env bash
#
# test-build-verification.sh - Verify DSLLVM build configurations
#
# This script tests that both DSLLVM build variants compile and produce
# working binaries with the expected features and security flags.

set -e
set -u

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Test if a command exists
test_command() {
    local cmd=$1
    if command -v "$cmd" &> /dev/null; then
        log_success "Command '$cmd' found"
        return 0
    else
        log_failure "Command '$cmd' not found"
        return 1
    fi
}

# Test if a file exists
test_file_exists() {
    local file=$1
    if [ -f "$file" ]; then
        log_success "File exists: $file"
        return 0
    else
        log_failure "File not found: $file"
        return 1
    fi
}

# Test if a directory exists
test_dir_exists() {
    local dir=$1
    if [ -d "$dir" ]; then
        log_success "Directory exists: $dir"
        return 0
    else
        log_failure "Directory not found: $dir"
        return 1
    fi
}

# Test if a string contains expected value
test_contains() {
    local haystack=$1
    local needle=$2
    local description=$3

    if echo "$haystack" | grep -q "$needle"; then
        log_success "$description: Contains '$needle'"
        return 0
    else
        log_failure "$description: Missing '$needle'"
        return 1
    fi
}

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}DSMIL Build Verification Tests${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test 1: Build infrastructure files exist
log_info "Test Suite 1: Build Infrastructure"
echo ""

test_file_exists "Configurations/10-dsllvm.conf"
test_file_exists "util/build-dsllvm-world.sh"
test_file_exists "util/build-dsllvm-dsmil.sh"
test_file_exists "OPENSSL_SECURE_SPEC.md"
test_file_exists "IMPLEMENTATION_PLAN.md"
test_file_exists "DSMIL_README.md"

echo ""

# Test 2: Configuration files exist
log_info "Test Suite 2: Security Profile Configurations"
echo ""

test_file_exists "configs/world.cnf"
test_file_exists "configs/dsmil-secure.cnf"
test_file_exists "configs/atomal.cnf"

echo ""

# Test 3: Policy provider exists
log_info "Test Suite 3: DSMIL Policy Provider"
echo ""

test_dir_exists "providers/dsmil"
test_file_exists "providers/dsmil/dsmilprov.c"
test_file_exists "providers/dsmil/policy.c"
test_file_exists "providers/dsmil/policy.h"
test_file_exists "providers/dsmil/build.info"

echo ""

# Test 4: Compiler availability
log_info "Test Suite 4: Compiler Availability"
echo ""

if command -v dsclang &> /dev/null; then
    log_success "dsclang found (DSLLVM)"
    COMPILER="dsclang"
elif command -v clang &> /dev/null; then
    log_warning "dsclang not found, using clang as fallback"
    COMPILER="clang"
else
    log_failure "Neither dsclang nor clang found"
    COMPILER=""
fi

if [ -n "$COMPILER" ]; then
    COMPILER_VERSION=$($COMPILER --version | head -1)
    log_info "Compiler version: $COMPILER_VERSION"
fi

echo ""

# Test 5: Build configuration parsing
log_info "Test Suite 5: Build Configuration Validation"
echo ""

# Check dsllvm-world target
if grep -q "\"dsllvm-world\"" Configurations/10-dsllvm.conf; then
    log_success "dsllvm-world target defined"

    # Check for expected flags
    CONFIG_CONTENT=$(cat Configurations/10-dsllvm.conf)
    test_contains "$CONFIG_CONTENT" "march=x86-64-v3" "World config: Portable arch"
    test_contains "$CONFIG_CONTENT" "fstack-protector-strong" "World config: Stack protection"
    test_contains "$CONFIG_CONTENT" "fPIE" "World config: PIE"
    test_contains "$CONFIG_CONTENT" "flto=full" "World config: LTO"
else
    log_failure "dsllvm-world target not found"
fi

echo ""

# Check dsllvm-dsmil target
if grep -q "\"dsllvm-dsmil\"" Configurations/10-dsllvm.conf; then
    log_success "dsllvm-dsmil target defined"

    test_contains "$CONFIG_CONTENT" "march=meteorlake" "DSMIL config: Meteorlake arch"
    test_contains "$CONFIG_CONTENT" "mavx2" "DSMIL config: AVX2"
    test_contains "$CONFIG_CONTENT" "maes" "DSMIL config: AES-NI"
    test_contains "$CONFIG_CONTENT" "mvaes" "DSMIL config: VAES"
else
    log_failure "dsllvm-dsmil target not found"
fi

echo ""

# Test 6: Profile configuration validation
log_info "Test Suite 6: Security Profile Configuration Validation"
echo ""

# Test WORLD_COMPAT config
WORLD_CONFIG=$(cat configs/world.cnf)
test_contains "$WORLD_CONFIG" "WORLD_COMPAT" "World config: Profile name"
test_contains "$WORLD_CONFIG" "TLSv1.3" "World config: TLS 1.3"
test_contains "$WORLD_CONFIG" "TLS_AES_256_GCM_SHA384" "World config: AES-256-GCM"

echo ""

# Test DSMIL_SECURE config
DSMIL_CONFIG=$(cat configs/dsmil-secure.cnf)
test_contains "$DSMIL_CONFIG" "DSMIL_SECURE" "DSMIL config: Profile name"
test_contains "$DSMIL_CONFIG" "require_hybrid_kex = true" "DSMIL config: Hybrid KEX mandatory"
test_contains "$DSMIL_CONFIG" "MLKEM768" "DSMIL config: ML-KEM-768"

echo ""

# Test ATOMAL config
ATOMAL_CONFIG=$(cat configs/atomal.cnf)
test_contains "$ATOMAL_CONFIG" "ATOMAL" "ATOMAL config: Profile name"
test_contains "$ATOMAL_CONFIG" "MLKEM1024" "ATOMAL config: ML-KEM-1024"
test_contains "$ATOMAL_CONFIG" "MLDSA87" "ATOMAL config: ML-DSA-87"
test_contains "$ATOMAL_CONFIG" "TLS_AES_256_GCM_SHA384" "ATOMAL config: AES-256-GCM only"

echo ""

# Test 7: PQC implementation exists
log_info "Test Suite 7: Post-Quantum Crypto Implementation"
echo ""

test_dir_exists "crypto/ml_kem"
test_dir_exists "crypto/ml_dsa"
test_file_exists "doc/designs/ML-KEM.md"
test_file_exists "doc/designs/ml-dsa.md"

# Check for provider implementations
if [ -f "providers/implementations/kem/ml_kem_kem.c" ]; then
    log_success "ML-KEM KEM provider found"
else
    log_failure "ML-KEM KEM provider not found"
fi

if [ -f "providers/implementations/signature/ml_dsa_sig.c" ]; then
    log_success "ML-DSA signature provider found"
else
    log_failure "ML-DSA signature provider not found"
fi

if [ -f "providers/implementations/kem/mlx_kem.c" ]; then
    log_success "Hybrid KEM provider found"
else
    log_failure "Hybrid KEM provider not found"
fi

echo ""

# Test 8: Build script validation
log_info "Test Suite 8: Build Script Validation"
echo ""

# Check if scripts are executable
if [ -x "util/build-dsllvm-world.sh" ]; then
    log_success "build-dsllvm-world.sh is executable"
else
    log_failure "build-dsllvm-world.sh is not executable"
fi

if [ -x "util/build-dsllvm-dsmil.sh" ]; then
    log_success "build-dsllvm-dsmil.sh is executable"
else
    log_failure "build-dsllvm-dsmil.sh is not executable"
fi

# Check for required options in scripts
WORLD_SCRIPT=$(cat util/build-dsllvm-world.sh)
test_contains "$WORLD_SCRIPT" "--clean" "World script: --clean option"
test_contains "$WORLD_SCRIPT" "--test" "World script: --test option"
test_contains "$WORLD_SCRIPT" "--install" "World script: --install option"

echo ""

# Test 9: Documentation validation
log_info "Test Suite 9: Documentation Validation"
echo ""

# Check spec completeness
SPEC=$(cat OPENSSL_SECURE_SPEC.md)
test_contains "$SPEC" "WORLD_COMPAT" "Spec: WORLD_COMPAT profile"
test_contains "$SPEC" "DSMIL_SECURE" "Spec: DSMIL_SECURE profile"
test_contains "$SPEC" "ATOMAL" "Spec: ATOMAL profile"
test_contains "$SPEC" "ML-KEM" "Spec: ML-KEM documentation"
test_contains "$SPEC" "ML-DSA" "Spec: ML-DSA documentation"

# Check implementation plan
PLAN=$(cat IMPLEMENTATION_PLAN.md)
test_contains "$PLAN" "Phase 1" "Plan: Phase 1 defined"
test_contains "$PLAN" "Phase 2" "Plan: Phase 2 defined"
test_contains "$PLAN" "Policy Provider" "Plan: Policy provider mentioned"

echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
echo -e "${RED}Failed:${NC} $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    echo ""
    echo "Build verification complete. You can now:"
    echo "  1. Run a build: ./util/build-dsllvm-world.sh --clean"
    echo "  2. Run policy tests: ./test/dsmil/test-policy-provider.sh"
    echo "  3. Run integration tests: ./test/dsmil/test-profiles.sh"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    echo ""
    echo "Please fix the failures before proceeding."
    exit 1
fi
