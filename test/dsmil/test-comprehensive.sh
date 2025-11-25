#!/bin/bash
#
# DSMIL Comprehensive Test Runner
# Runs all test suites and OpenSSL native tests
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
MAGENTA='\033[0;35m'
NC='\033[0m'

# Parse options
RUN_OPENSSL_TESTS=0
RUN_PERFORMANCE=0
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --openssl-tests)
            RUN_OPENSSL_TESTS=1
            shift
            ;;
        --performance)
            RUN_PERFORMANCE=1
            shift
            ;;
        --all)
            RUN_OPENSSL_TESTS=1
            RUN_PERFORMANCE=1
            shift
            ;;
        --verbose|-v)
            VERBOSE=1
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --openssl-tests     Run native OpenSSL test suite"
            echo "  --performance       Run performance benchmarks"
            echo "  --all               Run all tests (DSMIL + OpenSSL + performance)"
            echo "  --verbose, -v       Verbose output"
            echo "  --help, -h          Show this help message"
            echo ""
            echo "By default, runs DSMIL-specific test suites only."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${MAGENTA}╔════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║   DSMIL Comprehensive Test Suite      ║${NC}"
echo -e "${MAGENTA}║   Phase 8: Production Validation       ║${NC}"
echo -e "${MAGENTA}╔════════════════════════════════════════╗${NC}"
echo ""

# Track results
SUITES_PASSED=0
SUITES_FAILED=0
START_TIME=$(date +%s)

# Run a test suite
run_test_suite() {
    local test_script=$1
    local test_name=$2
    local required=${3:-1}  # 1 = required, 0 = optional

    if [ ! -f "$test_script" ]; then
        if [ $required -eq 1 ]; then
            echo -e "${RED}✗ Test script not found: $test_script${NC}"
            ((SUITES_FAILED++))
            return 1
        else
            echo -e "${YELLOW}⊘ Test script not found (optional): $test_script${NC}"
            return 0
        fi
    fi

    if [ ! -x "$test_script" ]; then
        chmod +x "$test_script"
    fi

    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}Running: $test_name${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Run test
    if [ $VERBOSE -eq 1 ]; then
        "$test_script"
        result=$?
    else
        "$test_script" 2>&1 | tee /tmp/dsmil_test_$$.log | \
            grep -E "PASS|FAIL|TEST|Summary|Score|✓|✗|⚠" || cat /tmp/dsmil_test_$$.log
        result=${PIPESTATUS[0]}
        rm -f /tmp/dsmil_test_$$.log
    fi

    if [ $result -eq 0 ]; then
        echo ""
        echo -e "${GREEN}✓ $test_name PASSED${NC}"
        ((SUITES_PASSED++))
        return 0
    else
        echo ""
        echo -e "${RED}✗ $test_name FAILED${NC}"
        ((SUITES_FAILED++))
        return 1
    fi
}

# Phase 1: DSMIL Core Tests
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo -e "${BLUE}Phase 1: DSMIL Core Functionality${NC}"
echo -e "${BLUE}═══════════════════════════════════════════${NC}"

run_test_suite "$SCRIPT_DIR/test-build-verification.sh" "Build Verification"
run_test_suite "$SCRIPT_DIR/test-policy-provider.sh" "Policy Provider"
run_test_suite "$SCRIPT_DIR/test-profiles.sh" "Security Profiles"

# Phase 2: Advanced Features
echo ""
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo -e "${BLUE}Phase 2: Advanced Features${NC}"
echo -e "${BLUE}═══════════════════════════════════════════${NC}"

run_test_suite "$SCRIPT_DIR/test-event-telemetry.sh" "Event Telemetry (Phase 3)"
run_test_suite "$SCRIPT_DIR/test-timing-variance.sh" "Timing Variance (Phase 6)"
run_test_suite "$SCRIPT_DIR/test-tpm-integration.sh" "TPM Integration (Phase 7)"

# Phase 3: Security Validation
echo ""
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo -e "${BLUE}Phase 3: Security Validation${NC}"
echo -e "${BLUE}═══════════════════════════════════════════${NC}"

run_test_suite "$SCRIPT_DIR/test-security-validation.sh" "Security Validation (Phase 8)"

# Phase 4: OpenSSL Native Tests (optional)
if [ $RUN_OPENSSL_TESTS -eq 1 ]; then
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${BLUE}Phase 4: OpenSSL Native Test Suite${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo ""

    if [ -f "$REPO_ROOT/Makefile" ] && command -v make >/dev/null 2>&1; then
        echo -e "${CYAN}Running OpenSSL test suite (this may take 10-30 minutes)...${NC}"
        echo ""

        cd "$REPO_ROOT"
        if make test; then
            echo ""
            echo -e "${GREEN}✓ OpenSSL Native Tests PASSED${NC}"
            ((SUITES_PASSED++))
        else
            echo ""
            echo -e "${RED}✗ OpenSSL Native Tests FAILED${NC}"
            ((SUITES_FAILED++))
        fi
    else
        echo -e "${YELLOW}⊘ OpenSSL not built or make not available${NC}"
        echo "   Build first: ./util/build-dsllvm-world.sh --clean --test"
    fi
fi

# Phase 5: Performance Benchmarks (optional)
if [ $RUN_PERFORMANCE -eq 1 ]; then
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${BLUE}Phase 5: Performance Benchmarks${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"

    run_test_suite "$SCRIPT_DIR/test-performance-benchmarks.sh" "Performance Benchmarks" 0
fi

# Calculate elapsed time
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
MINUTES=$((ELAPSED / 60))
SECONDS=$((ELAPSED % 60))

# Final Summary
echo ""
echo ""
echo -e "${MAGENTA}╔════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║      COMPREHENSIVE TEST SUMMARY        ║${NC}"
echo -e "${MAGENTA}╚════════════════════════════════════════╝${NC}"
echo ""

TOTAL_SUITES=$((SUITES_PASSED + SUITES_FAILED))
echo -e "Total Test Suites:  $TOTAL_SUITES"
echo -e "${GREEN}Passed:${NC}             $SUITES_PASSED"
echo -e "${RED}Failed:${NC}             $SUITES_FAILED"
echo ""
echo -e "Execution Time:     ${MINUTES}m ${SECONDS}s"
echo ""

# Calculate success rate
if [ $TOTAL_SUITES -gt 0 ]; then
    SUCCESS_RATE=$((SUITES_PASSED * 100 / TOTAL_SUITES))
    echo -e "Success Rate:       ${SUCCESS_RATE}%"
    echo ""
fi

# Overall status
if [ $SUITES_FAILED -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   ✓✓✓ ALL TESTS PASSED ✓✓✓            ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}The DSMIL OpenSSL implementation is production-ready.${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Review performance benchmarks (if not run)"
    echo "  2. Deploy to test environment"
    echo "  3. Run interoperability tests with clients"
    echo "  4. See docs/TESTING.md for deployment guidelines"
    echo ""
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════╗${NC}"
    echo -e "${RED}║   ✗✗✗ SOME TESTS FAILED ✗✗✗           ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}Please review the failures above and address issues.${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Check build configuration"
    echo "  2. Review docs/TESTING.md"
    echo "  3. Ensure all dependencies installed"
    echo "  4. Check system requirements"
    echo ""
    exit 1
fi
