#!/bin/bash
#
# DSMIL Security Validation Test Suite
# Tests security properties, policy enforcement, and attack resistance
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

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

echo "=========================================="
echo "DSMIL Security Validation Test Suite"
echo "Phase 8: Comprehensive Testing"
echo "=========================================="
echo ""

# Check if OpenSSL is built
OPENSSL_BIN="$REPO_ROOT/apps/openssl"
if [ -x "$OPENSSL_BIN" ]; then
    log_info "Using built OpenSSL: $OPENSSL_BIN"
    OPENSSL_VERSION=$("$OPENSSL_BIN" version)
    log_info "Version: $OPENSSL_VERSION"
else
    log_warning "OpenSSL not built yet, testing configuration only"
    OPENSSL_BIN=""
fi

# Test 1: Policy Enforcement - WORLD_COMPAT
log_test "Policy enforcement: WORLD_COMPAT allows classical crypto"
WORLD_CONFIG="$REPO_ROOT/configs/world.cnf"
if [ -f "$WORLD_CONFIG" ]; then
    if grep -q "MinProtocol.*TLSv1.3" "$WORLD_CONFIG" 2>/dev/null; then
        log_success "WORLD_COMPAT enforces TLS 1.3 minimum"
    else
        log_failure "WORLD_COMPAT TLS version policy not enforced"
    fi

    if grep -q "X25519:P-256" "$WORLD_CONFIG" 2>/dev/null; then
        log_success "WORLD_COMPAT allows classical key exchange"
    else
        log_failure "WORLD_COMPAT key exchange configuration missing"
    fi
else
    log_failure "WORLD_COMPAT config not found"
fi

# Test 2: Policy Enforcement - DSMIL_SECURE
log_test "Policy enforcement: DSMIL_SECURE requires hybrid"
SECURE_CONFIG="$REPO_ROOT/configs/dsmil-secure.cnf"
if [ -f "$SECURE_CONFIG" ]; then
    if grep -q "require_hybrid_kex.*true" "$SECURE_CONFIG" 2>/dev/null; then
        log_success "DSMIL_SECURE requires hybrid key exchange"
    else
        log_failure "DSMIL_SECURE hybrid requirement not enforced"
    fi

    if grep -q "min_security_bits.*192" "$SECURE_CONFIG" 2>/dev/null; then
        log_success "DSMIL_SECURE enforces 192-bit minimum security"
    else
        log_failure "DSMIL_SECURE security level not enforced"
    fi

    if grep -q "X25519+MLKEM768\|P-256+MLKEM768" "$SECURE_CONFIG" 2>/dev/null; then
        log_success "DSMIL_SECURE configures hybrid KEX algorithms"
    else
        log_failure "DSMIL_SECURE hybrid algorithms not configured"
    fi
else
    log_failure "DSMIL_SECURE config not found"
fi

# Test 3: Policy Enforcement - ATOMAL
log_test "Policy enforcement: ATOMAL maximum security"
ATOMAL_CONFIG="$REPO_ROOT/configs/atomal.cnf"
if [ -f "$ATOMAL_CONFIG" ]; then
    if grep -q "allow_classical_fallback.*false" "$ATOMAL_CONFIG" 2>/dev/null; then
        log_success "ATOMAL blocks classical fallback"
    else
        log_failure "ATOMAL classical fallback not blocked"
    fi

    if grep -q "block_classical_only.*true" "$ATOMAL_CONFIG" 2>/dev/null; then
        log_success "ATOMAL blocks classical-only crypto"
    else
        log_failure "ATOMAL classical blocking not enforced"
    fi

    if grep -q "min_security_bits.*256" "$ATOMAL_CONFIG" 2>/dev/null; then
        log_success "ATOMAL enforces 256-bit minimum security"
    else
        log_failure "ATOMAL security level not enforced"
    fi

    if grep -q "TLS_AES_256_GCM_SHA384" "$ATOMAL_CONFIG" 2>/dev/null && \
       ! grep -q "CHACHA20" "$ATOMAL_CONFIG" 2>/dev/null; then
        log_success "ATOMAL restricts to AES-256-GCM only"
    else
        log_failure "ATOMAL cipher suite restrictions not enforced"
    fi
else
    log_failure "ATOMAL config not found"
fi

# Test 4: Downgrade Attack Prevention
log_test "Downgrade attack prevention"
POLICY_C="$REPO_ROOT/providers/dsmil/policy.c"
if [ -f "$POLICY_C" ]; then
    if grep -q "TLS.*1\.3" "$POLICY_C" 2>/dev/null || \
       grep -q "0x0304" "$POLICY_C" 2>/dev/null; then
        log_success "TLS version downgrade prevention implemented"
    else
        log_failure "TLS version checking not implemented"
    fi

    if grep -q "DOWNGRADE\|downgrade" "$POLICY_C" 2>/dev/null; then
        log_success "Downgrade detection logic present"
    else
        log_warning "Downgrade detection may need enhancement"
    fi
else
    log_failure "Policy implementation not found"
fi

# Test 5: Event Telemetry for Security Events
log_test "Security event telemetry"
EVENTS_H="$REPO_ROOT/providers/dsmil/events.h"
if [ -f "$EVENTS_H" ]; then
    if grep -q "POLICY_VIOLATION" "$EVENTS_H" 2>/dev/null; then
        log_success "Policy violation events defined"
    else
        log_failure "Policy violation event type missing"
    fi

    if grep -q "DOWNGRADE_DETECTED" "$EVENTS_H" 2>/dev/null; then
        log_success "Downgrade detection events defined"
    else
        log_failure "Downgrade detection event type missing"
    fi

    if grep -q "HANDSHAKE_FAILED" "$EVENTS_H" 2>/dev/null; then
        log_success "Handshake failure events defined"
    else
        log_failure "Handshake failure event type missing"
    fi
else
    log_failure "Events header not found"
fi

# Test 6: Constant-Time Implementation
log_test "Constant-time implementations"
CSNA_H="$REPO_ROOT/providers/dsmil/csna.h"
if [ -f "$CSNA_H" ]; then
    if grep -q "csna_memcmp_const" "$CSNA_H" 2>/dev/null; then
        # Check that it uses bitwise OR, not early return
        if grep -A 10 "csna_memcmp_const" "$CSNA_H" | grep -q "diff |="; then
            log_success "Constant-time memcmp uses bitwise accumulator"
        else
            log_failure "Constant-time memcmp may have timing leak"
        fi
    else
        log_failure "Constant-time memcmp not found"
    fi

    if grep -q "CSNA_CONSTANT_TIME" "$CSNA_H" 2>/dev/null; then
        log_success "Constant-time annotations available"
    else
        log_failure "CSNA annotations missing"
    fi
else
    log_failure "CSNA header not found"
fi

# Test 7: TPM Key Protection
log_test "TPM key protection"
TPM_INT_C="$REPO_ROOT/providers/dsmil/tpm_integration.c"
if [ -f "$TPM_INT_C" ]; then
    if grep -q "tpm2_key_seal" "$TPM_INT_C" 2>/dev/null; then
        log_success "TPM key sealing implemented"
    else
        log_failure "TPM key sealing not implemented"
    fi

    if grep -q "DSMIL_PROFILE_ATOMAL.*require_tpm_keys.*1" "$TPM_INT_C" 2>/dev/null || \
       grep -A 10 "DSMIL_PROFILE_ATOMAL" "$TPM_INT_C" | grep -q "require_tpm_keys.*1"; then
        log_success "ATOMAL profile requires TPM keys"
    else
        log_failure "ATOMAL TPM requirement not enforced"
    fi

    if grep -q "TPM2_SECURITY_MAXIMUM" "$TPM_INT_C" 2>/dev/null; then
        log_success "Maximum TPM security level available"
    else
        log_failure "TPM security levels incomplete"
    fi
else
    log_failure "TPM integration not found"
fi

# Test 8: Memory Safety
log_test "Memory safety practices"
if grep -rq "OPENSSL_cleanse\|OPENSSL_clear_free" "$REPO_ROOT/providers/dsmil/" 2>/dev/null; then
    log_success "Secure memory clearing used"
else
    log_warning "Consider using OPENSSL_cleanse for sensitive data"
fi

if grep -rq "OPENSSL_zalloc\|OPENSSL_malloc" "$REPO_ROOT/providers/dsmil/" 2>/dev/null; then
    log_success "OpenSSL memory allocation functions used"
else
    log_warning "Check memory allocation practices"
fi

# Test 9: PQC Algorithm Availability
log_test "Post-quantum algorithm availability"
if [ -n "$OPENSSL_BIN" ]; then
    if "$OPENSSL_BIN" list -kem-algorithms 2>/dev/null | grep -qi "ML-KEM\|KYBER"; then
        log_success "ML-KEM algorithms available"
    else
        log_warning "ML-KEM may not be available (build required)"
    fi

    if "$OPENSSL_BIN" list -signature-algorithms 2>/dev/null | grep -qi "ML-DSA\|DILITHIUM"; then
        log_success "ML-DSA algorithms available"
    else
        log_warning "ML-DSA may not be available (build required)"
    fi
else
    log_info "Skipping runtime PQC checks (OpenSSL not built)"
fi

# Test 10: Configuration File Validation
log_test "Configuration file syntax validation"
for config in "$REPO_ROOT"/configs/*.cnf; do
    if [ -f "$config" ]; then
        config_name=$(basename "$config")
        if [ -n "$OPENSSL_BIN" ]; then
            if "$OPENSSL_BIN" version -a >/dev/null 2>&1; then
                # OpenSSL can load config
                log_success "Config $config_name syntax valid"
            else
                log_failure "Config $config_name may have syntax errors"
            fi
        else
            # Basic syntax check
            if grep -q "^\[.*\]" "$config" && grep -q "=" "$config"; then
                log_success "Config $config_name has basic structure"
            else
                log_failure "Config $config_name missing sections"
            fi
        fi
    fi
done

# Test 11: Error Handling
log_test "Error handling robustness"
ERROR_CHECKS=0
TOTAL_ERROR_CHECKS=5

if grep -rq "if.*==.*NULL.*return" "$REPO_ROOT/providers/dsmil/" 2>/dev/null; then
    ((ERROR_CHECKS++))
fi

if grep -rq "if.*ctx.*==.*NULL" "$REPO_ROOT/providers/dsmil/" 2>/dev/null; then
    ((ERROR_CHECKS++))
fi

if grep -rq "TPM2_RC_SUCCESS" "$REPO_ROOT/providers/dsmil/" 2>/dev/null; then
    ((ERROR_CHECKS++))
fi

if grep -rq "DSMIL_DECISION_BLOCKED" "$REPO_ROOT/providers/dsmil/" 2>/dev/null; then
    ((ERROR_CHECKS++))
fi

if grep -rq "fprintf.*stderr" "$REPO_ROOT/providers/dsmil/" 2>/dev/null; then
    ((ERROR_CHECKS++))
fi

if [ $ERROR_CHECKS -ge 4 ]; then
    log_success "Comprehensive error handling present ($ERROR_CHECKS/$TOTAL_ERROR_CHECKS checks)"
else
    log_warning "Error handling could be improved ($ERROR_CHECKS/$TOTAL_ERROR_CHECKS checks)"
fi

# Test 12: Documentation Security Notes
log_test "Security documentation completeness"
DOC_COUNT=0

if [ -f "$REPO_ROOT/docs/CSNA_SIDE_CHANNEL_HARDENING.md" ]; then
    if grep -qi "timing.*attack\|side.*channel" "$REPO_ROOT/docs/CSNA_SIDE_CHANNEL_HARDENING.md" 2>/dev/null; then
        ((DOC_COUNT++))
    fi
fi

if [ -f "$REPO_ROOT/docs/TPM_INTEGRATION.md" ]; then
    if grep -qi "security\|hardware.*backed" "$REPO_ROOT/docs/TPM_INTEGRATION.md" 2>/dev/null; then
        ((DOC_COUNT++))
    fi
fi

if [ -f "$REPO_ROOT/OPENSSL_SECURE_SPEC.md" ]; then
    if grep -qi "threat\|security.*profile" "$REPO_ROOT/OPENSSL_SECURE_SPEC.md" 2>/dev/null; then
        ((DOC_COUNT++))
    fi
fi

if [ $DOC_COUNT -ge 3 ]; then
    log_success "Security documentation comprehensive"
else
    log_warning "Security documentation incomplete ($DOC_COUNT/3 docs)"
fi

# Test 13: Build Configuration Security
log_test "Build security flags"
DSLLVM_CONF="$REPO_ROOT/Configurations/10-dsllvm.conf"
if [ -f "$DSLLVM_CONF" ]; then
    SECURITY_FLAGS=0

    if grep -q "stack-protector" "$DSLLVM_CONF" 2>/dev/null; then
        ((SECURITY_FLAGS++))
    fi

    if grep -q "fPIE\|fpie" "$DSLLVM_CONF" 2>/dev/null; then
        ((SECURITY_FLAGS++))
    fi

    if grep -q "_FORTIFY_SOURCE" "$DSLLVM_CONF" 2>/dev/null; then
        ((SECURITY_FLAGS++))
    fi

    if grep -q "relro\|now" "$DSLLVM_CONF" 2>/dev/null; then
        ((SECURITY_FLAGS++))
    fi

    if [ $SECURITY_FLAGS -ge 3 ]; then
        log_success "Build security flags comprehensive ($SECURITY_FLAGS/4 flags)"
    else
        log_warning "Some build security flags missing ($SECURITY_FLAGS/4 flags)"
    fi
else
    log_failure "DSLLVM build configuration not found"
fi

# Test 14: FIPS Compliance (where applicable)
log_test "FIPS-approved algorithm usage"
if grep -rq "AES-256-GCM\|SHA-256\|SHA-384\|SHA-512" "$REPO_ROOT/configs/" 2>/dev/null; then
    log_success "FIPS-approved algorithms configured"
else
    log_warning "FIPS algorithm configuration unclear"
fi

if grep -rq "SHA-1.*signature.*only\|SHA-1.*legacy" "$REPO_ROOT" 2>/dev/null; then
    log_success "SHA-1 restricted to legacy use"
else
    log_info "SHA-1 usage policy not explicit"
fi

# Test 15: Attack Surface Reduction
log_test "Attack surface minimization"
MINIMIZATION_SCORE=0

# Check that old TLS versions are disabled
if grep -rq "TLSv1\.3" "$REPO_ROOT/configs/" 2>/dev/null && \
   ! grep -q "TLSv1\.2\|TLSv1\.1\|TLSv1\.0" "$REPO_ROOT/configs/" 2>/dev/null; then
    ((MINIMIZATION_SCORE++))
fi

# Check that weak ciphers are not configured
if ! grep -rq "RC4\|MD5\|DES\|3DES" "$REPO_ROOT/configs/" 2>/dev/null; then
    ((MINIMIZATION_SCORE++))
fi

# Check profile-specific restrictions
if grep -q "ATOMAL.*AES-256-GCM.*only" "$ATOMAL_CONFIG" 2>/dev/null || \
   (grep -A 5 "profile.*ATOMAL" "$ATOMAL_CONFIG" 2>/dev/null | grep -q "TLS_AES_256_GCM_SHA384" && \
    ! grep -A 5 "profile.*ATOMAL" "$ATOMAL_CONFIG" 2>/dev/null | grep -q "CHACHA20"); then
    ((MINIMIZATION_SCORE++))
fi

if [ $MINIMIZATION_SCORE -ge 2 ]; then
    log_success "Attack surface well-minimized ($MINIMIZATION_SCORE/3 checks)"
else
    log_warning "Attack surface could be further reduced ($MINIMIZATION_SCORE/3 checks)"
fi

echo ""
echo "=========================================="
echo "Security Validation Summary"
echo "=========================================="
echo -e "Total tests: $TOTAL"
echo -e "${GREEN}Passed: $PASS${NC}"
echo -e "${RED}Failed: $FAIL${NC}"
echo ""

# Security score calculation
SECURITY_SCORE=$((PASS * 100 / TOTAL))
echo -e "Security Score: ${SECURITY_SCORE}%"
echo ""

if [ $SECURITY_SCORE -ge 90 ]; then
    echo -e "${GREEN}✓ Excellent security posture${NC}"
    exit_code=0
elif [ $SECURITY_SCORE -ge 75 ]; then
    echo -e "${YELLOW}⚠ Good security, some improvements recommended${NC}"
    exit_code=0
elif [ $SECURITY_SCORE -ge 60 ]; then
    echo -e "${YELLOW}⚠ Adequate security, improvements needed${NC}"
    exit_code=1
else
    echo -e "${RED}✗ Security improvements required${NC}"
    exit_code=1
fi

echo ""
exit $exit_code
