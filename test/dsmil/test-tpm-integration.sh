#!/bin/bash
#
# DSMIL TPM Integration Test Suite
# Tests for TPM2 hardware-backed cryptography integration
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

# Counters
PASS=0
FAIL=0
TOTAL=0

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASS++))
    ((TOTAL++))
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAIL++))
    ((TOTAL++))
}

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

echo "=========================================="
echo "DSMIL TPM Integration Test Suite"
echo "Phase 7: TPM Integration"
echo "=========================================="
echo ""

# Check for TPM2 compatibility header
log_test "Checking TPM2 compatibility header"
TPM2_H="$REPO_ROOT/providers/dsmil/tpm2_compat.h"
if [ -f "$TPM2_H" ]; then
    log_success "TPM2 compatibility header exists"
else
    log_failure "TPM2 compatibility header not found"
fi

# Check for TPM integration header
log_test "Checking TPM integration header"
TPM_INT_H="$REPO_ROOT/providers/dsmil/tpm_integration.h"
if [ -f "$TPM_INT_H" ]; then
    log_success "TPM integration header exists"
else
    log_failure "TPM integration header not found"
fi

# Check for TPM integration implementation
log_test "Checking TPM integration implementation"
TPM_INT_C="$REPO_ROOT/providers/dsmil/tpm_integration.c"
if [ -f "$TPM_INT_C" ]; then
    log_success "TPM integration implementation exists"
else
    log_failure "TPM integration implementation not found"
fi

# Check TPM2 return codes
log_test "Checking TPM2 return code definitions"
if grep -q "TPM2_RC_SUCCESS" "$TPM2_H" 2>/dev/null; then
    log_success "TPM2_RC_SUCCESS defined"
else
    log_failure "TPM2_RC_SUCCESS not found"
fi

if grep -q "TPM2_RC_FAILURE" "$TPM2_H" 2>/dev/null; then
    log_success "TPM2_RC_FAILURE defined"
else
    log_failure "TPM2_RC_FAILURE not found"
fi

if grep -q "TPM2_RC_NOT_SUPPORTED" "$TPM2_H" 2>/dev/null; then
    log_success "TPM2_RC_NOT_SUPPORTED defined"
else
    log_failure "TPM2_RC_NOT_SUPPORTED not found"
fi

# Check algorithm support (88 algorithms)
log_test "Checking comprehensive algorithm support"

# Hash algorithms (10)
HASH_ALGS="SHA1 SHA256 SHA384 SHA512 SHA3_256 SHA3_384 SHA3_512 SM3_256 SHAKE128 SHAKE256"
HASH_COUNT=0
for alg in $HASH_ALGS; do
    if grep -q "CRYPTO_ALG_$alg" "$TPM2_H" 2>/dev/null; then
        ((HASH_COUNT++))
    fi
done
if [ $HASH_COUNT -eq 10 ]; then
    log_success "All 10 hash algorithms defined"
else
    log_failure "Only $HASH_COUNT/10 hash algorithms found"
fi

# AES modes (16)
AES_MODES="AES_128_ECB AES_256_ECB AES_128_CBC AES_256_CBC AES_128_CTR AES_256_CTR AES_128_OFB AES_256_OFB AES_128_CFB AES_256_CFB AES_128_GCM AES_256_GCM AES_128_CCM AES_256_CCM AES_128_XTS AES_256_XTS"
AES_COUNT=0
for mode in $AES_MODES; do
    if grep -q "CRYPTO_ALG_$mode" "$TPM2_H" 2>/dev/null; then
        ((AES_COUNT++))
    fi
done
if [ $AES_COUNT -eq 16 ]; then
    log_success "All 16 AES modes defined"
else
    log_failure "Only $AES_COUNT/16 AES modes found"
fi

# ECC curves (12)
ECC_CURVES="ECC_P192 ECC_P224 ECC_P256 ECC_P384 ECC_P521 ECC_SM2_P256 ECC_BN_P256 ECC_BN_P638 ECC_CURVE25519 ECC_CURVE448 ECC_ED25519 ECC_ED448"
ECC_COUNT=0
for curve in $ECC_CURVES; do
    if grep -q "CRYPTO_ALG_$curve" "$TPM2_H" 2>/dev/null; then
        ((ECC_COUNT++))
    fi
done
if [ $ECC_COUNT -eq 12 ]; then
    log_success "All 12 ECC curves defined"
else
    log_failure "Only $ECC_COUNT/12 ECC curves found"
fi

# Post-quantum algorithms (8)
PQC_ALGS="KYBER512 KYBER768 KYBER1024 DILITHIUM2 DILITHIUM3 DILITHIUM5 FALCON512 FALCON1024"
PQC_COUNT=0
for alg in $PQC_ALGS; do
    if grep -q "CRYPTO_ALG_$alg" "$TPM2_H" 2>/dev/null; then
        ((PQC_COUNT++))
    fi
done
if [ $PQC_COUNT -eq 8 ]; then
    log_success "All 8 post-quantum algorithms defined"
else
    log_failure "Only $PQC_COUNT/8 PQC algorithms found"
fi

# Check TPM API functions
log_test "Checking TPM2 API functions"

TPM_FUNCTIONS="tpm2_crypto_init tpm2_crypto_cleanup tpm2_crypto_hash tpm2_crypto_hmac tpm2_crypto_encrypt tpm2_crypto_decrypt tpm2_crypto_aead_encrypt tpm2_crypto_aead_decrypt tpm2_crypto_hkdf tpm2_crypto_pbkdf2 tpm2_crypto_ecdh tpm2_key_seal tpm2_key_unseal tpm2_key_create"

FUNC_COUNT=0
for func in $TPM_FUNCTIONS; do
    if grep -q "$func" "$TPM2_H" 2>/dev/null; then
        ((FUNC_COUNT++))
    fi
done

if [ $FUNC_COUNT -eq 14 ]; then
    log_success "All $FUNC_COUNT core TPM2 API functions declared"
else
    log_failure "Only $FUNC_COUNT/14 TPM2 API functions found"
fi

# Check security levels
log_test "Checking TPM security level definitions"
if grep -q "TPM2_SECURITY_LEGACY" "$TPM2_H" 2>/dev/null && \
   grep -q "TPM2_SECURITY_BASELINE" "$TPM2_H" 2>/dev/null && \
   grep -q "TPM2_SECURITY_STANDARD" "$TPM2_H" 2>/dev/null && \
   grep -q "TPM2_SECURITY_HIGH" "$TPM2_H" 2>/dev/null && \
   grep -q "TPM2_SECURITY_MAXIMUM" "$TPM2_H" 2>/dev/null; then
    log_success "All 5 security levels defined"
else
    log_failure "Not all security levels found"
fi

# Check acceleration flags
log_test "Checking hardware acceleration flags"
if grep -q "TPM2_ACCEL_AES_NI" "$TPM2_H" 2>/dev/null && \
   grep -q "TPM2_ACCEL_SHA_NI" "$TPM2_H" 2>/dev/null && \
   grep -q "TPM2_ACCEL_AVX2" "$TPM2_H" 2>/dev/null && \
   grep -q "TPM2_ACCEL_AVX512" "$TPM2_H" 2>/dev/null && \
   grep -q "TPM2_ACCEL_NPU" "$TPM2_H" 2>/dev/null && \
   grep -q "TPM2_ACCEL_GNA" "$TPM2_H" 2>/dev/null; then
    log_success "All acceleration flags defined"
else
    log_failure "Not all acceleration flags found"
fi

# Check TPM integration context
log_test "Checking TPM integration context structures"
if grep -q "DSMIL_TPM_CONFIG" "$TPM_INT_H" 2>/dev/null; then
    log_success "DSMIL_TPM_CONFIG structure defined"
else
    log_failure "DSMIL_TPM_CONFIG not found"
fi

if grep -q "DSMIL_TPM_CTX" "$TPM_INT_H" 2>/dev/null; then
    log_success "DSMIL_TPM_CTX structure defined"
else
    log_failure "DSMIL_TPM_CTX not found"
fi

if grep -q "DSMIL_KEY_STORAGE_TYPE" "$TPM_INT_H" 2>/dev/null; then
    log_success "DSMIL_KEY_STORAGE_TYPE enum defined"
else
    log_failure "DSMIL_KEY_STORAGE_TYPE not found"
fi

# Check TPM integration functions
log_test "Checking TPM integration API functions"

TPM_INT_FUNCTIONS="dsmil_tpm_init dsmil_tpm_cleanup dsmil_tpm_configure_for_profile dsmil_tpm_is_available dsmil_tpm_seal_key dsmil_tpm_unseal_key dsmil_tpm_generate_key dsmil_tpm_get_key_storage_type dsmil_tpm_hash dsmil_tpm_hmac dsmil_tpm_random dsmil_tpm_get_stats"

INT_FUNC_COUNT=0
for func in $TPM_INT_FUNCTIONS; do
    if grep -q "$func" "$TPM_INT_H" 2>/dev/null; then
        ((INT_FUNC_COUNT++))
    fi
done

if [ $INT_FUNC_COUNT -eq 12 ]; then
    log_success "All $INT_FUNC_COUNT TPM integration functions declared"
else
    log_failure "Only $INT_FUNC_COUNT/12 integration functions found"
fi

# Check implementation
log_test "Checking TPM integration implementation"
if grep -q "dsmil_tpm_init.*DSMIL_TPM_CTX" "$TPM_INT_C" 2>/dev/null; then
    log_success "dsmil_tpm_init implementation found"
else
    log_failure "dsmil_tpm_init implementation not found"
fi

if grep -q "tpm2_crypto_init" "$TPM_INT_C" 2>/dev/null; then
    log_success "Calls TPM2 initialization"
else
    log_failure "TPM2 initialization call not found"
fi

# Check profile-based configuration
log_test "Checking profile-based TPM configuration"
if grep -q "DSMIL_PROFILE_WORLD_COMPAT" "$TPM_INT_C" 2>/dev/null && \
   grep -q "DSMIL_PROFILE_DSMIL_SECURE" "$TPM_INT_C" 2>/dev/null && \
   grep -q "DSMIL_PROFILE_ATOMAL" "$TPM_INT_C" 2>/dev/null; then
    log_success "Profile-based configuration implemented"
else
    log_failure "Profile-based configuration incomplete"
fi

# Check statistics tracking
log_test "Checking TPM statistics tracking"
if grep -q "tpm_operations" "$TPM_INT_C" 2>/dev/null && \
   grep -q "tpm_failures" "$TPM_INT_C" 2>/dev/null && \
   grep -q "software_fallbacks" "$TPM_INT_C" 2>/dev/null; then
    log_success "TPM statistics tracking implemented"
else
    log_failure "Statistics tracking incomplete"
fi

# Check fallback behavior
log_test "Checking software fallback behavior"
if grep -q "software_fallbacks++" "$TPM_INT_C" 2>/dev/null; then
    log_success "Software fallback counting present"
else
    log_failure "Software fallback tracking not found"
fi

if grep -q "TPM2_RC_NOT_SUPPORTED" "$TPM_INT_C" 2>/dev/null; then
    log_success "Handles TPM not supported case"
else
    log_failure "TPM not supported handling missing"
fi

# Check key sealing
log_test "Checking TPM key sealing support"
if grep -q "tpm2_key_seal" "$TPM_INT_C" 2>/dev/null; then
    log_success "TPM key sealing implemented"
else
    log_failure "TPM key sealing not found"
fi

if grep -q "tpm2_key_unseal" "$TPM_INT_C" 2>/dev/null; then
    log_success "TPM key unsealing implemented"
else
    log_failure "TPM key unsealing not found"
fi

# Check security level mapping
log_test "Checking security level mapping for profiles"
if grep -q "TPM2_SECURITY_BASELINE.*WORLD_COMPAT" "$TPM_INT_C" 2>/dev/null || \
   grep -A 5 "DSMIL_PROFILE_WORLD_COMPAT" "$TPM_INT_C" 2>/dev/null | grep -q "TPM2_SECURITY_BASELINE"; then
    log_success "WORLD_COMPAT uses TPM2_SECURITY_BASELINE"
else
    log_failure "WORLD_COMPAT security level mapping incorrect"
fi

if grep -q "TPM2_SECURITY_HIGH.*DSMIL_SECURE" "$TPM_INT_C" 2>/dev/null || \
   grep -A 5 "DSMIL_PROFILE_DSMIL_SECURE" "$TPM_INT_C" 2>/dev/null | grep -q "TPM2_SECURITY_HIGH"; then
    log_success "DSMIL_SECURE uses TPM2_SECURITY_HIGH"
else
    log_failure "DSMIL_SECURE security level mapping incorrect"
fi

if grep -q "TPM2_SECURITY_MAXIMUM.*ATOMAL" "$TPM_INT_C" 2>/dev/null || \
   grep -A 5 "DSMIL_PROFILE_ATOMAL" "$TPM_INT_C" 2>/dev/null | grep -q "TPM2_SECURITY_MAXIMUM"; then
    log_success "ATOMAL uses TPM2_SECURITY_MAXIMUM"
else
    log_failure "ATOMAL security level mapping incorrect"
fi

# Check acceleration flag mapping
log_test "Checking hardware acceleration mapping for profiles"
if grep -q "TPM2_ACCEL_ALL" "$TPM_INT_C" 2>/dev/null; then
    log_success "ATOMAL uses all accelerators"
else
    log_failure "ATOMAL acceleration mapping not found"
fi

# Check key storage type logic
log_test "Checking key storage type selection"
if grep -q "DSMIL_KEY_STORAGE_SOFTWARE" "$TPM_INT_C" 2>/dev/null && \
   grep -q "DSMIL_KEY_STORAGE_TPM_BACKED" "$TPM_INT_C" 2>/dev/null && \
   grep -q "DSMIL_KEY_STORAGE_TPM_ONLY" "$TPM_INT_C" 2>/dev/null; then
    log_success "All key storage types used"
else
    log_failure "Not all key storage types implemented"
fi

# Check error handling
log_test "Checking error handling"
if grep -q "if.*==.*NULL" "$TPM_INT_C" 2>/dev/null; then
    log_success "NULL pointer checks present"
else
    log_failure "NULL pointer checks missing"
fi

if grep -q "TPM2_RC_SUCCESS" "$TPM_INT_C" 2>/dev/null; then
    log_success "Checks for TPM2 success codes"
else
    log_failure "Success code checking missing"
fi

# Check cleanup
log_test "Checking TPM cleanup implementation"
if grep -q "tpm2_crypto_cleanup" "$TPM_INT_C" 2>/dev/null; then
    log_success "TPM cleanup function called"
else
    log_failure "TPM cleanup not implemented"
fi

if grep -q "memset.*0.*sizeof" "$TPM_INT_C" 2>/dev/null; then
    log_success "Context cleared on cleanup"
else
    log_failure "Context cleanup incomplete"
fi

# Check documentation
log_test "Checking code documentation"
if grep -q "/\*\*" "$TPM_INT_H" 2>/dev/null || grep -q "/\*" "$TPM_INT_H" 2>/dev/null; then
    log_success "Header documentation present"
else
    log_failure "Header missing documentation"
fi

if grep -q "@param\|@return" "$TPM_INT_H" 2>/dev/null; then
    log_success "Function parameters documented"
else
    log_info "Note: Parameter documentation could be improved"
fi

# Check header guards
log_test "Checking header include guards"
if grep -q "#ifndef DSMIL_TPM_INTEGRATION_H" "$TPM_INT_H" 2>/dev/null && \
   grep -q "#define DSMIL_TPM_INTEGRATION_H" "$TPM_INT_H" 2>/dev/null; then
    log_success "TPM integration header guards present"
else
    log_failure "Header guards missing"
fi

if grep -q "#ifndef DSMIL_TPM2_COMPAT_H" "$TPM2_H" 2>/dev/null && \
   grep -q "#define DSMIL_TPM2_COMPAT_H" "$TPM2_H" 2>/dev/null; then
    log_success "TPM2 compat header guards present"
else
    log_failure "TPM2 header guards missing"
fi

# Check C++ compatibility
log_test "Checking C++ compatibility"
if grep -q "#ifdef __cplusplus" "$TPM_INT_H" 2>/dev/null && \
   grep -q "extern \"C\"" "$TPM_INT_H" 2>/dev/null; then
    log_success "C++ compatibility guards present"
else
    log_failure "C++ guards missing"
fi

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "Total tests: $TOTAL"
echo -e "${GREEN}Passed: $PASS${NC}"
echo -e "${RED}Failed: $FAIL${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✓ All TPM integration tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
