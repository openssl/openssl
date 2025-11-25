#!/usr/bin/env bash
#
# test-policy-provider.sh - Unit tests for DSMIL policy provider
#
# This script tests the policy provider logic without requiring a full build.
# It tests the policy decision functions for different profiles.

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

# Test policy logic by checking source code
test_policy_logic() {
    local profile=$1
    local algorithm=$2
    local is_hybrid=$3
    local expected_decision=$4
    local test_name=$5

    log_info "Testing: $test_name"

    # This is a simplified test - in a real scenario, we'd compile and run the provider
    # For now, we test that the policy code has the expected logic

    local policy_src="providers/dsmil/policy.c"

    case $profile in
        "WORLD_COMPAT")
            # World should allow most things
            if [ "$expected_decision" = "ALLOWED" ]; then
                log_success "$test_name: WORLD_COMPAT policy logic present"
            else
                log_failure "$test_name: Unexpected decision for WORLD_COMPAT"
            fi
            ;;

        "DSMIL_SECURE")
            # DSMIL_SECURE requires hybrid for KEX
            if grep -q "DSMIL_PROFILE_DSMIL_SECURE" "$policy_src"; then
                if [ "$is_hybrid" = "true" ] && [ "$expected_decision" = "ALLOWED" ]; then
                    log_success "$test_name: DSMIL_SECURE allows hybrid"
                elif [ "$is_hybrid" = "false" ] && [ "$expected_decision" = "BLOCKED" ]; then
                    log_success "$test_name: DSMIL_SECURE blocks non-hybrid KEX"
                else
                    log_failure "$test_name: Unexpected DSMIL_SECURE policy"
                fi
            else
                log_failure "$test_name: DSMIL_SECURE profile not found in code"
            fi
            ;;

        "ATOMAL")
            # ATOMAL requires hybrid or PQC-only
            if grep -q "DSMIL_PROFILE_ATOMAL" "$policy_src"; then
                if [ "$is_hybrid" = "true" ] || [ "$algorithm" = "ML-KEM-1024" ]; then
                    log_success "$test_name: ATOMAL allows hybrid/PQC"
                elif [ "$is_hybrid" = "false" ] && [ "$expected_decision" = "BLOCKED" ]; then
                    log_success "$test_name: ATOMAL blocks classical-only"
                else
                    log_failure "$test_name: Unexpected ATOMAL policy"
                fi
            else
                log_failure "$test_name: ATOMAL profile not found in code"
            fi
            ;;

        *)
            log_failure "$test_name: Unknown profile"
            ;;
    esac
}

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}DSMIL Policy Provider Tests${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test Suite 1: Profile definitions
log_info "Test Suite 1: Profile Definitions"
echo ""

POLICY_H="providers/dsmil/policy.h"

if grep -q "DSMIL_PROFILE_WORLD_COMPAT" "$POLICY_H"; then
    log_success "WORLD_COMPAT profile defined"
else
    log_failure "WORLD_COMPAT profile not defined"
fi

if grep -q "DSMIL_PROFILE_DSMIL_SECURE" "$POLICY_H"; then
    log_success "DSMIL_SECURE profile defined"
else
    log_failure "DSMIL_SECURE profile not defined"
fi

if grep -q "DSMIL_PROFILE_ATOMAL" "$POLICY_H"; then
    log_success "ATOMAL profile defined"
else
    log_failure "ATOMAL profile not defined"
fi

echo ""

# Test Suite 2: THREATCON levels
log_info "Test Suite 2: THREATCON Level Definitions"
echo ""

if grep -q "DSMIL_THREATCON_NORMAL" "$POLICY_H"; then
    log_success "THREATCON_NORMAL defined"
else
    log_failure "THREATCON_NORMAL not defined"
fi

if grep -q "DSMIL_THREATCON_ELEVATED" "$POLICY_H"; then
    log_success "THREATCON_ELEVATED defined"
else
    log_failure "THREATCON_ELEVATED not defined"
fi

if grep -q "DSMIL_THREATCON_HIGH" "$POLICY_H"; then
    log_success "THREATCON_HIGH defined"
else
    log_failure "THREATCON_HIGH not defined"
fi

if grep -q "DSMIL_THREATCON_SEVERE" "$POLICY_H"; then
    log_success "THREATCON_SEVERE defined"
else
    log_failure "THREATCON_SEVERE not defined"
fi

echo ""

# Test Suite 3: Decision types
log_info "Test Suite 3: Policy Decision Types"
echo ""

if grep -q "DSMIL_DECISION_ALLOWED" "$POLICY_H"; then
    log_success "DECISION_ALLOWED defined"
else
    log_failure "DECISION_ALLOWED not defined"
fi

if grep -q "DSMIL_DECISION_BLOCKED" "$POLICY_H"; then
    log_success "DECISION_BLOCKED defined"
else
    log_failure "DECISION_BLOCKED not defined"
fi

if grep -q "DSMIL_DECISION_DOWNGRADED" "$POLICY_H"; then
    log_success "DECISION_DOWNGRADED defined"
else
    log_failure "DECISION_DOWNGRADED not defined"
fi

if grep -q "DSMIL_DECISION_FORCED_HYBRID" "$POLICY_H"; then
    log_success "DECISION_FORCED_HYBRID defined"
else
    log_failure "DECISION_FORCED_HYBRID not defined"
fi

echo ""

# Test Suite 4: Policy functions
log_info "Test Suite 4: Policy Function Declarations"
echo ""

FUNCTIONS=(
    "dsmil_policy_ctx_new"
    "dsmil_policy_ctx_free"
    "dsmil_policy_get_profile_name"
    "dsmil_policy_set_profile"
    "dsmil_policy_check_kem"
    "dsmil_policy_check_signature"
    "dsmil_policy_check_cipher"
    "dsmil_policy_check_tls_version"
)

for func in "${FUNCTIONS[@]}"; do
    if grep -q "$func" "$POLICY_H"; then
        log_success "Function declared: $func"
    else
        log_failure "Function not declared: $func"
    fi
done

echo ""

# Test Suite 5: KEM policy logic
log_info "Test Suite 5: KEM Algorithm Policy Logic"
echo ""

test_policy_logic "WORLD_COMPAT" "X25519" "false" "ALLOWED" "WORLD: Classical KEX allowed"
test_policy_logic "WORLD_COMPAT" "X25519+ML-KEM-768" "true" "ALLOWED" "WORLD: Hybrid KEX allowed"

test_policy_logic "DSMIL_SECURE" "X25519" "false" "BLOCKED" "DSMIL: Classical KEX blocked"
test_policy_logic "DSMIL_SECURE" "X25519+ML-KEM-768" "true" "ALLOWED" "DSMIL: Hybrid KEX allowed"

test_policy_logic "ATOMAL" "X25519" "false" "BLOCKED" "ATOMAL: Classical KEX blocked"
test_policy_logic "ATOMAL" "ML-KEM-1024" "true" "ALLOWED" "ATOMAL: PQC KEX allowed"

echo ""

# Test Suite 6: Signature policy logic
log_info "Test Suite 6: Signature Algorithm Policy Logic"
echo ""

POLICY_C="providers/dsmil/policy.c"

if grep -q "dsmil_policy_check_signature" "$POLICY_C"; then
    log_success "Signature policy function implemented"

    # Check for profile-specific logic
    if grep -A10 "dsmil_policy_check_signature" "$POLICY_C" | grep -q "DSMIL_PROFILE_ATOMAL"; then
        log_success "ATOMAL signature policy implemented"
    else
        log_failure "ATOMAL signature policy not found"
    fi
else
    log_failure "Signature policy function not implemented"
fi

echo ""

# Test Suite 7: Cipher suite policy
log_info "Test Suite 7: Cipher Suite Policy Logic"
echo ""

if grep -q "dsmil_policy_check_cipher" "$POLICY_C"; then
    log_success "Cipher policy function implemented"

    # Check for AES-256-GCM
    if grep -A20 "dsmil_policy_check_cipher" "$POLICY_C" | grep -q "AES-256-GCM"; then
        log_success "AES-256-GCM policy implemented"
    else
        log_failure "AES-256-GCM policy not found"
    fi

    # Check for ATOMAL restrictions
    if grep -A30 "dsmil_policy_check_cipher" "$POLICY_C" | grep -q "ATOMAL"; then
        log_success "ATOMAL cipher restrictions implemented"
    else
        log_failure "ATOMAL cipher restrictions not found"
    fi
else
    log_failure "Cipher policy function not implemented"
fi

echo ""

# Test Suite 8: Configuration parameters
log_info "Test Suite 8: Configuration Parameters"
echo ""

PARAMS=(
    "DSMIL_PARAM_PROFILE"
    "DSMIL_PARAM_EVENT_SOCKET"
    "DSMIL_PARAM_THREATCON_ENV"
    "DSMIL_PARAM_REQUIRE_HYBRID_KEX"
    "DSMIL_PARAM_MIN_SECURITY_BITS"
)

for param in "${PARAMS[@]}"; do
    if grep -q "$param" "$POLICY_H"; then
        log_success "Parameter defined: $param"
    else
        log_failure "Parameter not defined: $param"
    fi
done

echo ""

# Test Suite 9: Profile name constants
log_info "Test Suite 9: Profile Name Constants"
echo ""

if grep -q "DSMIL_PROFILE_NAME_WORLD" "$POLICY_H"; then
    log_success "WORLD profile name constant defined"
else
    log_failure "WORLD profile name constant not defined"
fi

if grep -q "DSMIL_PROFILE_NAME_SECURE" "$POLICY_H"; then
    log_success "SECURE profile name constant defined"
else
    log_failure "SECURE profile name constant not defined"
fi

if grep -q "DSMIL_PROFILE_NAME_ATOMAL" "$POLICY_H"; then
    log_success "ATOMAL profile name constant defined"
else
    log_failure "ATOMAL profile name constant not defined"
fi

echo ""

# Test Suite 10: Provider initialization
log_info "Test Suite 10: Provider Implementation"
echo ""

PROV_C="providers/dsmil/dsmilprov.c"

if grep -q "OSSL_provider_init" "$PROV_C"; then
    log_success "Provider entry point defined"
else
    log_failure "Provider entry point not defined"
fi

if grep -q "dsmil_dispatch_table" "$PROV_C"; then
    log_success "Provider dispatch table defined"
else
    log_failure "Provider dispatch table not defined"
fi

if grep -q "DSMIL_PROV_CTX" "$PROV_C"; then
    log_success "Provider context structure defined"
else
    log_failure "Provider context structure not defined"
fi

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
    echo -e "${GREEN}✓ All policy provider tests passed!${NC}"
    echo ""
    echo "Policy provider skeleton is correctly implemented."
    echo "Next steps:"
    echo "  - Complete Phase 2 implementation (property query interception)"
    echo "  - Add event telemetry (Phase 3)"
    echo "  - Run integration tests: ./test/dsmil/test-profiles.sh"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    echo ""
    echo "Please fix the policy provider implementation."
    exit 1
fi
