#!/usr/bin/env bash
#
# run-all-tests.sh - Run all DSMIL test suites
#
# This script runs all DSMIL-specific tests in sequence.

set -u

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}DSMIL OpenSSL Test Suite${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Track results
TOTAL_PASSED=0
TOTAL_FAILED=0
SUITES_PASSED=0
SUITES_FAILED=0

# Run a test suite
run_test_suite() {
    local test_script=$1
    local test_name=$2

    if [ ! -f "$test_script" ]; then
        echo -e "${RED}✗ Test script not found: $test_script${NC}"
        ((SUITES_FAILED++))
        return 1
    fi

    if [ ! -x "$test_script" ]; then
        chmod +x "$test_script"
    fi

    echo -e "${BLUE}Running: $test_name${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # Run test and capture output
    if "$test_script"; then
        echo ""
        echo -e "${GREEN}✓ $test_name passed${NC}"
        ((SUITES_PASSED++))
        return 0
    else
        echo ""
        echo -e "${RED}✗ $test_name failed${NC}"
        ((SUITES_FAILED++))
        return 1
    fi
}

# Test Suite 1: Build Verification
echo ""
run_test_suite "$SCRIPT_DIR/test-build-verification.sh" "Build Verification Tests"
echo ""

# Test Suite 2: Policy Provider
echo ""
run_test_suite "$SCRIPT_DIR/test-policy-provider.sh" "Policy Provider Tests"
echo ""

# Test Suite 3: Security Profiles
echo ""
run_test_suite "$SCRIPT_DIR/test-profiles.sh" "Security Profile Tests"
echo ""

# Test Suite 4: Event Telemetry (Phase 3)
echo ""
run_test_suite "$SCRIPT_DIR/test-event-telemetry.sh" "Event Telemetry Tests (Phase 3)"
echo ""

# Test Suite 5: Timing Variance & Side-Channel Hardening (Phase 6)
echo ""
run_test_suite "$SCRIPT_DIR/test-timing-variance.sh" "Timing Variance Tests (Phase 6)"
echo ""

# Test Suite 6: TPM Integration (Phase 7)
echo ""
run_test_suite "$SCRIPT_DIR/test-tpm-integration.sh" "TPM Integration Tests (Phase 7)"
echo ""

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Overall Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Test Suites Run:    $(($SUITES_PASSED + $SUITES_FAILED))"
echo -e "${GREEN}Suites Passed:${NC}      $SUITES_PASSED"
echo -e "${RED}Suites Failed:${NC}      $SUITES_FAILED"
echo ""

if [ $SUITES_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓✓✓ All DSMIL test suites passed! ✓✓✓${NC}"
    echo ""
    echo "The DSMIL OpenSSL implementation is correctly configured."
    echo ""
    echo "Next steps:"
    echo "  1. Build: ./util/build-dsllvm-world.sh --clean --test"
    echo "  2. Examples: cd examples && make && ./check-pqc"
    echo "  3. See docs/TESTING.md for more information"
    echo ""
    exit 0
else
    echo -e "${RED}✗✗✗ Some test suites failed ✗✗✗${NC}"
    echo ""
    echo "Please review the failures above and fix issues."
    echo "See docs/TESTING.md for troubleshooting help."
    echo ""
    exit 1
fi
