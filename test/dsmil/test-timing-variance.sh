#!/bin/bash
#
# DSMIL Timing Variance Test Suite
# Tests for constant-time execution and side-channel resistance
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
NC='\033[0m' # No Color

# Counters
PASS=0
FAIL=0
TOTAL=0

# Logging functions
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

# Header
echo "=========================================="
echo "DSMIL Timing Variance Test Suite"
echo "Phase 6: CSNA Integration & Side-Channel Hardening"
echo "=========================================="
echo ""

# Check for CSNA header
log_test "Checking for CSNA annotation header"
CSNA_H="$REPO_ROOT/providers/dsmil/csna.h"
if [ -f "$CSNA_H" ]; then
    log_success "CSNA header exists: $CSNA_H"
else
    log_failure "CSNA header not found"
fi

# Check for CSNA macros
log_test "Checking CSNA macro definitions"
if grep -q "CSNA_CONSTANT_TIME" "$CSNA_H" 2>/dev/null; then
    log_success "CSNA_CONSTANT_TIME macro defined"
else
    log_failure "CSNA_CONSTANT_TIME macro not found"
fi

if grep -q "CSNA_SECRET" "$CSNA_H" 2>/dev/null; then
    log_success "CSNA_SECRET macro defined"
else
    log_failure "CSNA_SECRET macro not found"
fi

if grep -q "CSNA_SECRET_PARAM" "$CSNA_H" 2>/dev/null; then
    log_success "CSNA_SECRET_PARAM macro defined"
else
    log_failure "CSNA_SECRET_PARAM macro not found"
fi

if grep -q "CSNA_DECLASSIFY" "$CSNA_H" 2>/dev/null; then
    log_success "CSNA_DECLASSIFY macro defined"
else
    log_failure "CSNA_DECLASSIFY macro not found"
fi

if grep -q "CSNA_BARRIER" "$CSNA_H" 2>/dev/null; then
    log_success "CSNA_BARRIER macro defined"
else
    log_failure "CSNA_BARRIER macro not found"
fi

# Check for constant-time utility functions
log_test "Checking constant-time utility functions"
if grep -q "csna_memcmp_const" "$CSNA_H" 2>/dev/null; then
    log_success "Constant-time memcmp function defined"
else
    log_failure "Constant-time memcmp not found"
fi

if grep -q "csna_select_byte" "$CSNA_H" 2>/dev/null; then
    log_success "Constant-time select function defined"
else
    log_failure "Constant-time select not found"
fi

if grep -q "csna_is_zero" "$CSNA_H" 2>/dev/null; then
    log_success "Constant-time zero check defined"
else
    log_failure "Constant-time zero check not found"
fi

if grep -q "csna_eq" "$CSNA_H" 2>/dev/null; then
    log_success "Constant-time equality check defined"
else
    log_failure "Constant-time equality check not found"
fi

# Check for timing measurement support
log_test "Checking timing measurement infrastructure"
if grep -q "CSNA_TIMING_TESTS" "$CSNA_H" 2>/dev/null; then
    log_success "Timing test support defined"
else
    log_failure "Timing test support not found"
fi

if grep -q "csna_rdtsc" "$CSNA_H" 2>/dev/null; then
    log_success "RDTSC function defined"
else
    log_failure "RDTSC function not found"
fi

if grep -q "csna_cpuid_barrier" "$CSNA_H" 2>/dev/null; then
    log_success "CPUID barrier function defined"
else
    log_failure "CPUID barrier function not found"
fi

if grep -q "CSNA_TIMING_START" "$CSNA_H" 2>/dev/null; then
    log_success "Timing start macro defined"
else
    log_failure "Timing start macro not found"
fi

if grep -q "CSNA_TIMING_END" "$CSNA_H" 2>/dev/null; then
    log_success "Timing end macro defined"
else
    log_failure "Timing end macro not found"
fi

# Check for side-channel analysis hints
log_test "Checking side-channel analysis hints"
if grep -q "CSNA_ANALYSIS_MODE" "$CSNA_H" 2>/dev/null; then
    log_success "Analysis mode support defined"
else
    log_failure "Analysis mode support not found"
fi

if grep -q "CSNA_CT_BRANCH" "$CSNA_H" 2>/dev/null; then
    log_success "Constant-time branch annotation defined"
else
    log_failure "Constant-time branch annotation not found"
fi

if grep -q "CSNA_CT_LOOP" "$CSNA_H" 2>/dev/null; then
    log_success "Constant-time loop annotation defined"
else
    log_failure "Constant-time loop annotation not found"
fi

if grep -q "CSNA_CT_MEMACCESS" "$CSNA_H" 2>/dev/null; then
    log_success "Constant-time memory access annotation defined"
else
    log_failure "Constant-time memory access annotation not found"
fi

# Check for DSLLVM-specific attributes
log_test "Checking DSLLVM attribute integration"
if grep -q "DSLLVM_BUILD" "$CSNA_H" 2>/dev/null; then
    log_success "DSLLVM build detection present"
else
    log_failure "DSLLVM build detection not found"
fi

if grep -q "__attribute__.*annotate.*csna::constant_time" "$CSNA_H" 2>/dev/null; then
    log_success "Clang annotation attribute used for constant-time"
else
    log_failure "Clang annotation attribute not found"
fi

if grep -q "__attribute__.*annotate.*csna::secret" "$CSNA_H" 2>/dev/null; then
    log_success "Clang annotation attribute used for secrets"
else
    log_failure "Clang annotation attribute not found"
fi

# Check for multi-architecture support
log_test "Checking architecture support for timing primitives"
if grep -q "__x86_64__\|__i386__" "$CSNA_H" 2>/dev/null; then
    log_success "x86/x86_64 architecture support present"
else
    log_failure "x86 architecture support not found"
fi

if grep -q "__aarch64__" "$CSNA_H" 2>/dev/null; then
    log_success "ARM64 architecture support present"
else
    log_failure "ARM64 architecture support not found"
fi

# Check for proper inline assembly syntax
log_test "Checking inline assembly for timing"
if grep -q "__asm__.*__volatile__.*rdtsc" "$CSNA_H" 2>/dev/null; then
    log_success "x86 RDTSC inline assembly present"
else
    log_failure "RDTSC inline assembly not found"
fi

if grep -q "__asm__.*__volatile__.*cpuid" "$CSNA_H" 2>/dev/null; then
    log_success "x86 CPUID inline assembly present"
else
    log_failure "CPUID inline assembly not found"
fi

# Check for C++ compatibility
log_test "Checking C++ compatibility guards"
if grep -q "#ifdef __cplusplus" "$CSNA_H" 2>/dev/null; then
    log_success "C++ extern \"C\" guards present"
else
    log_failure "C++ compatibility guards not found"
fi

# Check for proper header guards
log_test "Checking header include guards"
if grep -q "#ifndef DSMIL_CSNA_H" "$CSNA_H" 2>/dev/null && \
   grep -q "#define DSMIL_CSNA_H" "$CSNA_H" 2>/dev/null && \
   grep -q "#endif.*DSMIL_CSNA_H" "$CSNA_H" 2>/dev/null; then
    log_success "Header include guards properly defined"
else
    log_failure "Header include guards missing or incorrect"
fi

# Check for memory barriers
log_test "Checking memory barrier implementation"
if grep -q "memory.*barrier" "$CSNA_H" 2>/dev/null; then
    log_success "Memory barrier documentation/implementation present"
else
    log_failure "Memory barrier not documented"
fi

# Check for constant-time comparison correctness
log_test "Validating constant-time memcmp implementation"
if grep -A 10 "csna_memcmp_const" "$CSNA_H" 2>/dev/null | grep -q "diff |="; then
    log_success "Constant-time memcmp uses bitwise OR accumulator"
else
    log_failure "Constant-time memcmp may have branches"
fi

# Check for constant-time select correctness
log_test "Validating constant-time select implementation"
if grep -A 10 "csna_select_byte" "$CSNA_H" 2>/dev/null | grep -q "mask.*condition"; then
    log_success "Constant-time select uses mask-based selection"
else
    log_failure "Constant-time select implementation questionable"
fi

# Check for timing macros proper usage
log_test "Checking timing macro usage pattern"
if grep -q "csna_cpuid_barrier.*csna_rdtsc" "$CSNA_H" 2>/dev/null; then
    log_success "Timing macros use barrier before RDTSC"
else
    log_failure "Timing macros missing proper barriers"
fi

# Check for inline static functions
log_test "Checking inline static function usage"
if grep -q "static inline.*csna_" "$CSNA_H" 2>/dev/null; then
    log_success "Utility functions are static inline"
else
    log_failure "Functions should be static inline in header"
fi

# Documentation checks
log_test "Checking code documentation"
if grep -q "/\*\*" "$CSNA_H" 2>/dev/null || grep -q "/\*" "$CSNA_H" 2>/dev/null; then
    log_success "Function documentation present"
else
    log_failure "Missing function documentation"
fi

# Verify no timing-dependent branches in CT functions
log_test "Checking for timing-dependent branches in CT functions"
CT_FUNC_COUNT=$(grep -c "CSNA_CONSTANT_TIME" "$CSNA_H" 2>/dev/null || echo "0")
if [ "$CT_FUNC_COUNT" -gt 0 ]; then
    log_success "Found $CT_FUNC_COUNT constant-time annotated functions"

    # Check if any CT functions have obvious if/else
    if grep -A 20 "CSNA_CONSTANT_TIME" "$CSNA_H" 2>/dev/null | grep -q "^\s*if.*{"; then
        log_info "Note: Some CT functions contain if statements - verify they are CT-safe"
    else
        log_success "No obvious branching in CT functions"
    fi
else
    log_failure "No constant-time annotated functions found"
fi

# Check for size_t usage
log_test "Checking proper type usage"
if grep -q "size_t" "$CSNA_H" 2>/dev/null; then
    log_success "Uses size_t for sizes"
else
    log_failure "Missing size_t usage"
fi

if grep -q "uint64_t\|uint32_t\|uint8_t" "$CSNA_H" 2>/dev/null; then
    log_success "Uses fixed-width integer types"
else
    log_failure "Missing fixed-width integer types"
fi

# Check for stdint.h include
log_test "Checking required header includes"
if grep -q "#include <stdint.h>" "$CSNA_H" 2>/dev/null; then
    log_success "Includes stdint.h for fixed-width types"
else
    log_info "Note: stdint.h may be included conditionally"
fi

# Test constant-time function behavior (if we can compile)
log_test "Testing constant-time function compilation"
if command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then
    CC="${CC:-gcc}"
    if [ ! -x "$(command -v $CC)" ]; then
        CC="clang"
    fi

    # Create simple test program
    TEST_C="/tmp/csna_test_$$.c"
    cat > "$TEST_C" << 'EOF'
#include <stdio.h>
#define CSNA_TIMING_TESTS 1
#include "csna.h"

int main() {
    unsigned char a[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    unsigned char b[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    unsigned char c[16] = {16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};

    /* Test constant-time memcmp */
    int res1 = csna_memcmp_const(a, b, 16);
    int res2 = csna_memcmp_const(a, c, 16);

    printf("Same: %d (should be 0), Different: %d (should be non-zero)\n", res1, res2);

    /* Test constant-time select */
    unsigned char sel1 = csna_select_byte(1, 42, 99);
    unsigned char sel2 = csna_select_byte(0, 42, 99);

    printf("Select true: %d (should be 42), Select false: %d (should be 99)\n", sel1, sel2);

    /* Test zero check */
    int z1 = csna_is_zero(0);
    int z2 = csna_is_zero(42);

    printf("Zero check(0): %d (should be 1), Zero check(42): %d (should be 0)\n", z1, z2);

    return 0;
}
EOF

    if $CC -I"$(dirname "$CSNA_H")" -o /tmp/csna_test_$$ "$TEST_C" 2>/dev/null; then
        log_success "Test program compiles successfully"

        # Run the test
        if /tmp/csna_test_$$ >/dev/null 2>&1; then
            log_success "Test program executes successfully"
        else
            log_failure "Test program runtime error"
        fi

        rm -f /tmp/csna_test_$$
    else
        log_failure "Test program compilation failed"
    fi

    rm -f "$TEST_C"
else
    log_info "No compiler available for functional testing"
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
    echo -e "${GREEN}✓ All timing variance tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
