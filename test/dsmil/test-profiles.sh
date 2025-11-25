#!/usr/bin/env bash
#
# test-profiles.sh - Integration tests for DSMIL security profiles
#
# This script tests that the security profile configurations are valid
# and contain the expected settings for each profile.

set -e
set -u

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Test if config contains expected content
test_config_contains() {
    local config_file=$1
    local search_string=$2
    local test_name=$3

    if [ ! -f "$config_file" ]; then
        log_failure "$test_name: Config file not found: $config_file"
        return 1
    fi

    if grep -q "$search_string" "$config_file"; then
        log_success "$test_name"
        return 0
    else
        log_failure "$test_name: Missing '$search_string'"
        return 1
    fi
}

# Test if config does NOT contain something
test_config_not_contains() {
    local config_file=$1
    local search_string=$2
    local test_name=$3

    if [ ! -f "$config_file" ]; then
        log_failure "$test_name: Config file not found: $config_file"
        return 1
    fi

    if ! grep -q "$search_string" "$config_file"; then
        log_success "$test_name"
        return 0
    else
        log_failure "$test_name: Should not contain '$search_string'"
        return 1
    fi
}

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}DSMIL Security Profile Tests${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test Suite 1: WORLD_COMPAT Profile
log_info "Test Suite 1: WORLD_COMPAT Profile Configuration"
echo ""

WORLD_CFG="configs/world.cnf"

test_config_contains "$WORLD_CFG" "WORLD_COMPAT" "Profile name present"
test_config_contains "$WORLD_CFG" "openssl_conf = openssl_init" "OpenSSL init section"
test_config_contains "$WORLD_CFG" "default = default_sect" "Default provider"
test_config_contains "$WORLD_CFG" "base = base_sect" "Base provider"

# TLS configuration
test_config_contains "$WORLD_CFG" "MinProtocol = TLSv1.3" "TLS 1.3 minimum protocol"
test_config_contains "$WORLD_CFG" "TLS_AES_256_GCM_SHA384" "AES-256-GCM cipher suite"
test_config_contains "$WORLD_CFG" "TLS_CHACHA20_POLY1305_SHA256" "ChaCha20-Poly1305 cipher suite"

# Key exchange groups
test_config_contains "$WORLD_CFG" "Groups = X25519:P-256" "Classical KEX groups"

# Signature algorithms
test_config_contains "$WORLD_CFG" "SignatureAlgorithms" "Signature algorithms defined"
test_config_contains "$WORLD_CFG" "ECDSA" "ECDSA signatures"
test_config_contains "$WORLD_CFG" "ed25519" "Ed25519 signatures"

# PQC is optional (commented out)
if grep -q "^# pqc = pqc_sect" "$WORLD_CFG"; then
    log_success "PQC provider optional (commented)"
else
    log_warning "PQC provider section formatting unexpected"
fi

echo ""

# Test Suite 2: DSMIL_SECURE Profile
log_info "Test Suite 2: DSMIL_SECURE Profile Configuration"
echo ""

DSMIL_CFG="configs/dsmil-secure.cnf"

test_config_contains "$DSMIL_CFG" "DSMIL_SECURE" "Profile name present"
test_config_contains "$DSMIL_CFG" "default = default_sect" "Default provider"
test_config_contains "$DSMIL_CFG" "pqc = pqc_sect" "PQC provider enabled"
test_config_contains "$DSMIL_CFG" "dsmil-policy = dsmil_policy_sect" "Policy provider enabled"

# Policy provider settings
test_config_contains "$DSMIL_CFG" "profile = DSMIL_SECURE" "Profile set to DSMIL_SECURE"
test_config_contains "$DSMIL_CFG" "event_socket = /run/crypto-events.sock" "Event socket configured"
test_config_contains "$DSMIL_CFG" "threatcon_env = THREATCON_LEVEL" "THREATCON environment variable"
test_config_contains "$DSMIL_CFG" "require_hybrid_kex = true" "Hybrid KEX required"
test_config_contains "$DSMIL_CFG" "min_security_bits = 192" "Minimum security bits = 192"

# TLS configuration
test_config_contains "$DSMIL_CFG" "MinProtocol = TLSv1.3" "TLS 1.3 minimum"
test_config_contains "$DSMIL_CFG" "MaxProtocol = TLSv1.3" "TLS 1.3 maximum (strict)"

# Hybrid KEX groups
test_config_contains "$DSMIL_CFG" "MLKEM768" "ML-KEM-768 support"
test_config_contains "$DSMIL_CFG" "X25519+MLKEM768" "X25519+ML-KEM-768 hybrid"
test_config_contains "$DSMIL_CFG" "P-256+MLKEM768" "P-256+ML-KEM-768 hybrid"

# Hybrid signatures
test_config_contains "$DSMIL_CFG" "MLDSA65" "ML-DSA-65 support"
test_config_contains "$DSMIL_CFG" "ECDSA+SHA256+MLDSA65" "Hybrid ECDSA+ML-DSA-65"

# Cipher suites
test_config_contains "$DSMIL_CFG" "TLS_AES_256_GCM_SHA384" "AES-256-GCM"
test_config_contains "$DSMIL_CFG" "TLS_CHACHA20_POLY1305_SHA256" "ChaCha20 allowed"

# Telemetry
test_config_contains "$DSMIL_CFG" "\\[telemetry\\]" "Telemetry section"
test_config_contains "$DSMIL_CFG" "enabled = true" "Telemetry enabled"
test_config_contains "$DSMIL_CFG" "format = json" "JSON format"

echo ""

# Test Suite 3: ATOMAL Profile
log_info "Test Suite 3: ATOMAL Profile Configuration"
echo ""

ATOMAL_CFG="configs/atomal.cnf"

test_config_contains "$ATOMAL_CFG" "ATOMAL" "Profile name present"
test_config_contains "$ATOMAL_CFG" "pqc = pqc_sect" "PQC provider enabled"
test_config_contains "$ATOMAL_CFG" "dsmil-policy = dsmil_policy_sect" "Policy provider enabled"

# Policy provider settings (strict)
test_config_contains "$ATOMAL_CFG" "profile = ATOMAL" "Profile set to ATOMAL"
test_config_contains "$ATOMAL_CFG" "require_hybrid_kex = true" "Hybrid KEX required"
test_config_contains "$ATOMAL_CFG" "allow_classical_fallback = false" "No classical fallback"
test_config_contains "$ATOMAL_CFG" "block_classical_only = true" "Block classical-only"
test_config_contains "$ATOMAL_CFG" "min_security_bits = 256" "Minimum security bits = 256"
test_config_contains "$ATOMAL_CFG" "require_constant_time = true" "Constant-time required"

# TLS configuration (strict)
test_config_contains "$ATOMAL_CFG" "MinProtocol = TLSv1.3" "TLS 1.3 minimum"
test_config_contains "$ATOMAL_CFG" "MaxProtocol = TLSv1.3" "TLS 1.3 maximum"

# Cipher suite (AES-256-GCM ONLY)
test_config_contains "$ATOMAL_CFG" "Ciphersuites = TLS_AES_256_GCM_SHA384" "AES-256-GCM only"
test_config_not_contains "$ATOMAL_CFG" "CHACHA20" "ChaCha20 not allowed (outside comments)"

# ML-KEM-1024 support
test_config_contains "$ATOMAL_CFG" "MLKEM1024" "ML-KEM-1024 support"
test_config_contains "$ATOMAL_CFG" "X25519+MLKEM1024" "X25519+ML-KEM-1024 hybrid"

# ML-DSA-87 support
test_config_contains "$ATOMAL_CFG" "MLDSA87" "ML-DSA-87 support"
test_config_contains "$ATOMAL_CFG" "ECDSA+SHA256+MLDSA87" "Hybrid ECDSA+ML-DSA-87"

# Certificate verification (strict)
test_config_contains "$ATOMAL_CFG" "require_pqc_certs = true" "PQC certs required"
test_config_contains "$ATOMAL_CFG" "allow_classical_only_chain = false" "Classical-only chains blocked"

# Side-channel protections
test_config_contains "$ATOMAL_CFG" "\\[sidechannel\\]" "Side-channel section"
test_config_contains "$ATOMAL_CFG" "enforce_constant_time = true" "Constant-time enforced"
test_config_contains "$ATOMAL_CFG" "use_hardware_aes = true" "Hardware AES required"

# Telemetry (enhanced for ATOMAL)
test_config_contains "$ATOMAL_CFG" "events = all" "All events emitted"
test_config_contains "$ATOMAL_CFG" "alert_on_violation = true" "Alert on violations"

echo ""

# Test Suite 4: Profile Comparison
log_info "Test Suite 4: Profile Security Level Comparison"
echo ""

# Check that DSMIL_SECURE is stricter than WORLD_COMPAT
if grep -q "MinProtocol = TLSv1.3" "$DSMIL_CFG" && \
   grep -q "MaxProtocol = TLSv1.3" "$DSMIL_CFG"; then
    log_success "DSMIL_SECURE: Strict TLS 1.3 only (stricter than WORLD)"
else
    log_failure "DSMIL_SECURE: Should enforce strict TLS 1.3"
fi

# Check that ATOMAL is stricter than DSMIL_SECURE
ATOMAL_MIN_BITS=$(grep "min_security_bits" "$ATOMAL_CFG" | grep -o "[0-9]\+" | head -1)
DSMIL_MIN_BITS=$(grep "min_security_bits" "$DSMIL_CFG" | grep -o "[0-9]\+" | head -1)

if [ "$ATOMAL_MIN_BITS" -gt "$DSMIL_MIN_BITS" ]; then
    log_success "ATOMAL: Higher security bits than DSMIL_SECURE ($ATOMAL_MIN_BITS > $DSMIL_MIN_BITS)"
else
    log_failure "ATOMAL: Should have higher security bits than DSMIL_SECURE"
fi

echo ""

# Test Suite 5: Profile-Specific Features
log_info "Test Suite 5: Profile-Specific Security Features"
echo ""

# WORLD_COMPAT: Backward compatibility
if grep -q "# MinProtocol = TLSv1.2" "$WORLD_CFG"; then
    log_success "WORLD: TLS 1.2 fallback option documented"
else
    log_warning "WORLD: TLS 1.2 fallback not documented"
fi

# DSMIL_SECURE: Event telemetry
if grep -q "handshake_start,handshake_complete,handshake_failed" "$DSMIL_CFG"; then
    log_success "DSMIL: Comprehensive event types configured"
else
    log_warning "DSMIL: Event types not fully specified"
fi

# ATOMAL: Hardware RNG only
if grep -q "seed_sources = rdcpu,rdseed" "$ATOMAL_CFG" && \
   ! grep -q "devrandom" "$ATOMAL_CFG"; then
    log_success "ATOMAL: Hardware RNG only (no /dev/random fallback)"
else
    log_failure "ATOMAL: Should use hardware RNG only"
fi

echo ""

# Test Suite 6: Configuration Syntax Validation
log_info "Test Suite 6: Configuration Syntax Validation"
echo ""

for profile_cfg in "$WORLD_CFG" "$DSMIL_CFG" "$ATOMAL_CFG"; do
    profile_name=$(basename "$profile_cfg" .cnf)

    # Check for section headers
    if grep -q "\\[openssl_init\\]" "$profile_cfg"; then
        log_success "$profile_name: openssl_init section present"
    else
        log_failure "$profile_name: openssl_init section missing"
    fi

    # Check for provider section
    if grep -q "\\[provider_sect\\]" "$profile_cfg"; then
        log_success "$profile_name: provider_sect section present"
    else
        log_failure "$profile_name: provider_sect section missing"
    fi

    # Check for algorithm section
    if grep -q "\\[algorithm_sect\\]" "$profile_cfg"; then
        log_success "$profile_name: algorithm_sect section present"
    else
        log_failure "$profile_name: algorithm_sect section missing"
    fi
done

echo ""

# Test Suite 7: Documentation in Config Files
log_info "Test Suite 7: Configuration Documentation"
echo ""

for profile_cfg in "$WORLD_CFG" "$DSMIL_CFG" "$ATOMAL_CFG"; do
    profile_name=$(basename "$profile_cfg" .cnf)

    # Check for comments
    comment_lines=$(grep -c "^#" "$profile_cfg" || true)
    if [ "$comment_lines" -gt 10 ]; then
        log_success "$profile_name: Well-documented ($comment_lines comment lines)"
    else
        log_warning "$profile_name: Could use more documentation"
    fi

    # Check for usage notes
    if grep -q "To use this profile" "$profile_cfg"; then
        log_success "$profile_name: Usage instructions included"
    else
        log_warning "$profile_name: Usage instructions missing"
    fi
done

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
    echo -e "${GREEN}✓ All profile tests passed!${NC}"
    echo ""
    echo "Security profiles are correctly configured:"
    echo "  - WORLD_COMPAT: Public internet, backward compatible"
    echo "  - DSMIL_SECURE: Internal/allies, hybrid mandatory"
    echo "  - ATOMAL: Maximum security, PQC/hybrid only"
    echo ""
    echo "Next steps:"
    echo "  - Test build: ./util/build-dsllvm-world.sh --test"
    echo "  - Test with profile: export OPENSSL_CONF=configs/dsmil-secure.cnf"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    echo ""
    echo "Please fix the configuration files."
    exit 1
fi
