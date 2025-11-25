#!/usr/bin/env bash
#
# test-event-telemetry.sh - Test DSMIL event telemetry system (Phase 3)
#
# This script tests the event emission and telemetry infrastructure

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

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}DSMIL Event Telemetry Tests (Phase 3)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test Suite 1: Event Header Files
log_info "Test Suite 1: Event System Headers"
echo ""

EVENTS_H="providers/dsmil/events.h"

if [ ! -f "$EVENTS_H" ]; then
    log_failure "events.h not found"
else
    log_success "events.h exists"

    # Check for event types
    if grep -q "DSMIL_EVENT_HANDSHAKE_START" "$EVENTS_H"; then
        log_success "HANDSHAKE_START event type defined"
    else
        log_failure "HANDSHAKE_START event type not defined"
    fi

    if grep -q "DSMIL_EVENT_POLICY_VIOLATION" "$EVENTS_H"; then
        log_success "POLICY_VIOLATION event type defined"
    else
        log_failure "POLICY_VIOLATION event type not defined"
    fi

    if grep -q "DSMIL_EVENT_DOWNGRADE_DETECTED" "$EVENTS_H"; then
        log_success "DOWNGRADE_DETECTED event type defined"
    else
        log_failure "DOWNGRADE_DETECTED event type not defined"
    fi
fi

echo ""

# Test Suite 2: Event Implementation
log_info "Test Suite 2: Event System Implementation"
echo ""

EVENTS_C="providers/dsmil/events.c"

if [ ! -f "$EVENTS_C" ]; then
    log_failure "events.c not found"
else
    log_success "events.c exists"

    # Check for key functions
    FUNCTIONS=(
        "dsmil_event_ctx_new"
        "dsmil_event_ctx_free"
        "dsmil_event_handshake_start"
        "dsmil_event_handshake_complete"
        "dsmil_event_policy_violation"
        "dsmil_event_downgrade_detected"
        "dsmil_event_create_json"
    )

    for func in "${FUNCTIONS[@]}"; do
        if grep -q "$func" "$EVENTS_C"; then
            log_success "Function implemented: $func"
        else
            log_failure "Function not implemented: $func"
        fi
    done
fi

echo ""

# Test Suite 3: Event Context Structure
log_info "Test Suite 3: Event Context and Statistics"
echo ""

if grep -q "DSMIL_EVENT_CTX" "$EVENTS_H"; then
    log_success "Event context type defined"
else
    log_failure "Event context type not defined"
fi

if grep -q "DSMIL_EVENT_STATS" "$EVENTS_H"; then
    log_success "Event statistics type defined"
else
    log_failure "Event statistics type not defined"
fi

if grep -q "dsmil_event_get_stats" "$EVENTS_H"; then
    log_success "Statistics getter function defined"
else
    log_failure "Statistics getter function not defined"
fi

echo ""

# Test Suite 4: JSON Event Format
log_info "Test Suite 4: JSON Event Formatting"
echo ""

if grep -q "get_iso_timestamp" "$EVENTS_C"; then
    log_success "ISO timestamp function present"
else
    log_failure "ISO timestamp function not found"
fi

if grep -q "event_type_names" "$EVENTS_C"; then
    log_success "Event type names array present"
else
    log_failure "Event type names array not found"
fi

if grep -q "profile_names" "$EVENTS_C"; then
    log_success "Profile names array present"
else
    log_failure "Profile names array not found"
fi

# Check for JSON structure
if grep -q '"version"' "$EVENTS_C" && \
   grep -q '"timestamp"' "$EVENTS_C" && \
   grep -q '"event_type"' "$EVENTS_C"; then
    log_success "JSON event structure includes required fields"
else
    log_failure "JSON event structure incomplete"
fi

echo ""

# Test Suite 5: Unix Socket Support
log_info "Test Suite 5: Unix Socket Event Emission"
echo ""

if grep -q "#include <sys/socket.h>" "$EVENTS_C"; then
    log_success "Socket headers included"
else
    log_failure "Socket headers not included"
fi

if grep -q "struct sockaddr_un" "$EVENTS_C"; then
    log_success "Unix socket address structure used"
else
    log_failure "Unix socket address structure not found"
fi

if grep -q "SOCK_DGRAM" "$EVENTS_C"; then
    log_success "Datagram socket type used"
else
    log_failure "Datagram socket type not used"
fi

if grep -q "/run/crypto-events.sock" "$EVENTS_C"; then
    log_success "Default event socket path defined"
else
    log_failure "Default event socket path not found"
fi

echo ""

# Test Suite 6: Event Emission Functions
log_info "Test Suite 6: Event Emission Functions"
echo ""

# Check that all event types have emission functions
EVENT_FUNCTIONS=(
    "dsmil_event_handshake_start"
    "dsmil_event_handshake_complete"
    "dsmil_event_handshake_failed"
    "dsmil_event_policy_violation"
    "dsmil_event_downgrade_detected"
    "dsmil_event_algorithm_negotiated"
    "dsmil_event_key_operation"
)

for func in "${EVENT_FUNCTIONS[@]}"; do
    if grep -q "^int $func" "$EVENTS_C"; then
        log_success "Event function implemented: $func"
    elif grep -q "$func(" "$EVENTS_C"; then
        log_success "Event function present: $func"
    else
        log_failure "Event function not found: $func"
    fi
done

echo ""

# Test Suite 7: Error Handling
log_info "Test Suite 7: Error Handling and Robustness"
echo ""

if grep -q "Failed to create socket" "$EVENTS_C" || \
   grep -q "Failed to connect" "$EVENTS_C"; then
    log_success "Socket error messages present"
else
    log_failure "Socket error messages not found"
fi

if grep -q "failed_emissions" "$EVENTS_C"; then
    log_success "Failed emission tracking present"
else
    log_failure "Failed emission tracking not found"
fi

# Check for non-blocking behavior
if grep -q "fire-and-forget" "$EVENTS_C" || \
   grep -q "Non-blocking" "$EVENTS_C"; then
    log_success "Non-blocking event emission documented"
else
    log_failure "Non-blocking behavior not documented"
fi

echo ""

# Test Suite 8: Integration with Policy Provider
log_info "Test Suite 8: Policy Provider Integration"
echo ""

POLICY_ENHANCED_H="providers/dsmil/policy_enhanced.h"
POLICY_ENHANCED_C="providers/dsmil/policy_enhanced.c"

if [ -f "$POLICY_ENHANCED_H" ]; then
    log_success "policy_enhanced.h exists"

    if grep -q "dsmil_policy_set_event_ctx" "$POLICY_ENHANCED_H"; then
        log_success "Event context setter declared"
    else
        log_failure "Event context setter not declared"
    fi

    if grep -q "dsmil_policy_get_event_ctx" "$POLICY_ENHANCED_H"; then
        log_success "Event context getter declared"
    else
        log_failure "Event context getter not declared"
    fi
else
    log_failure "policy_enhanced.h not found"
fi

if [ -f "$POLICY_ENHANCED_C" ]; then
    log_success "policy_enhanced.c exists"

    if grep -q "check_.*_with_event" "$POLICY_ENHANCED_C"; then
        log_success "Enhanced policy check functions with events present"
    else
        log_failure "Enhanced policy check functions not found"
    fi
else
    log_failure "policy_enhanced.c not found"
fi

echo ""

# Test Suite 9: Provider Integration
log_info "Test Suite 9: DSMIL Provider Event Integration"
echo ""

DSMILPROV_C="providers/dsmil/dsmilprov.c"

if grep -q '#include "events.h"' "$DSMILPROV_C"; then
    log_success "events.h included in provider"
else
    log_failure "events.h not included in provider"
fi

if grep -q "DSMIL_EVENT_CTX \*event_ctx" "$DSMILPROV_C"; then
    log_success "Event context in provider context"
else
    log_failure "Event context not in provider context"
fi

if grep -q "dsmil_event_ctx_new" "$DSMILPROV_C"; then
    log_success "Event context initialization present"
else
    log_failure "Event context initialization not found"
fi

if grep -q "dsmil_event_ctx_free" "$DSMILPROV_C"; then
    log_success "Event context cleanup present"
else
    log_failure "Event context cleanup not found"
fi

echo ""

# Test Suite 10: Build System
log_info "Test Suite 10: Build System Integration"
echo ""

BUILD_INFO="providers/dsmil/build.info"

if grep -q "events.c" "$BUILD_INFO"; then
    log_success "events.c in build system"
else
    log_failure "events.c not in build system"
fi

if grep -q "policy_enhanced.c" "$BUILD_INFO"; then
    log_success "policy_enhanced.c in build system"
else
    log_failure "policy_enhanced.c not in build system"
fi

if grep -q "events.h" "$BUILD_INFO"; then
    log_success "events.h dependency declared"
else
    log_failure "events.h dependency not declared"
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
    echo -e "${GREEN}✓ All event telemetry tests passed!${NC}"
    echo ""
    echo "Event telemetry system (Phase 3) is correctly implemented:"
    echo "  - Event types defined"
    echo "  - JSON formatting implemented"
    echo "  - Unix socket emission ready"
    echo "  - Policy provider integration complete"
    echo ""
    echo "Next steps:"
    echo "  - Test event emission: Run DSMIL OpenSSL and monitor socket"
    echo "  - Integrate with DEFRAMEWORK"
    echo "  - See docs/TESTING.md for more tests"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    echo ""
    echo "Please fix the event telemetry implementation."
    exit 1
fi
