# DSMIL OpenSSL Testing Guide

This document describes the comprehensive test suite for DSMIL-grade OpenSSL.

## Overview

The DSMIL OpenSSL test suite consists of:

1. **Build Verification Tests** - Verify build system and configurations
2. **Policy Provider Tests** - Unit tests for security policy enforcement
3. **Profile Integration Tests** - Test security profile configurations
4. **Example Programs** - Practical usage examples
5. **OpenSSL Core Tests** - Standard OpenSSL test suite

## Quick Start

```bash
# Run all DSMIL tests
cd test/dsmil
./run-all-tests.sh

# Or run individually
./test-build-verification.sh
./test-policy-provider.sh
./test-profiles.sh
```

## Test Suites

### 1. Build Verification Tests

**File:** `test/dsmil/test-build-verification.sh`

**Purpose:** Verify that the DSMIL build system is correctly configured.

**What it tests:**
- Build infrastructure files exist
- Security profile configurations exist
- Policy provider source code exists
- Compiler availability (dsclang or clang)
- Build configuration parsing
- Profile configuration validation
- PQC implementation exists
- Build scripts are executable
- Documentation completeness

**Run:**
```bash
./test/dsmil/test-build-verification.sh
```

**Expected Output:**
```
========================================
DSMIL Build Verification Tests
========================================

Test Suite 1: Build Infrastructure
✓ File exists: Configurations/10-dsllvm.conf
✓ File exists: util/build-dsllvm-world.sh
...

========================================
Test Summary
========================================
Passed: 45
Failed: 0

✓ All tests passed!
```

### 2. Policy Provider Tests

**File:** `test/dsmil/test-policy-provider.sh`

**Purpose:** Unit test the DSMIL policy provider implementation.

**What it tests:**
- Profile definitions (WORLD_COMPAT, DSMIL_SECURE, ATOMAL)
- THREATCON level definitions
- Policy decision types
- Policy function declarations
- KEM algorithm policy logic
- Signature algorithm policy logic
- Cipher suite policy logic
- Configuration parameters
- Provider initialization

**Run:**
```bash
./test/dsmil/test-policy-provider.sh
```

**Expected Output:**
```
========================================
DSMIL Policy Provider Tests
========================================

Test Suite 1: Profile Definitions
✓ WORLD_COMPAT profile defined
✓ DSMIL_SECURE profile defined
✓ ATOMAL profile defined

...

Test Suite 5: KEM Algorithm Policy Logic
✓ WORLD: Classical KEX allowed
✓ DSMIL: Classical KEX blocked
✓ ATOMAL: PQC KEX allowed

========================================
Test Summary
========================================
Passed: 38
Failed: 0

✓ All policy provider tests passed!
```

### 3. Profile Integration Tests

**File:** `test/dsmil/test-profiles.sh`

**Purpose:** Integration test the three security profiles.

**What it tests:**
- WORLD_COMPAT profile configuration
  - TLS 1.3 support
  - Classical crypto baseline
  - Optional PQC
  - Cipher suites
- DSMIL_SECURE profile configuration
  - Hybrid KEX mandatory
  - Event telemetry
  - THREATCON integration
  - ML-KEM-768 support
- ATOMAL profile configuration
  - Maximum security settings
  - ML-KEM-1024 + ML-DSA-87
  - AES-256-GCM only
  - Hardware RNG only
  - Side-channel protections
- Profile security level comparison
- Configuration syntax validation
- Documentation completeness

**Run:**
```bash
./test/dsmil/test-profiles.sh
```

**Expected Output:**
```
========================================
DSMIL Security Profile Tests
========================================

Test Suite 1: WORLD_COMPAT Profile Configuration
✓ Profile name present
✓ TLS 1.3 minimum protocol
✓ AES-256-GCM cipher suite
...

Test Suite 2: DSMIL_SECURE Profile Configuration
✓ Hybrid KEX required
✓ ML-KEM-768 support
✓ Event telemetry configured
...

Test Suite 3: ATOMAL Profile Configuration
✓ ML-KEM-1024 support
✓ AES-256-GCM only
✓ Hardware RNG only
...

========================================
Test Summary
========================================
Passed: 52
Failed: 0

✓ All profile tests passed!
```

## Example Programs

### Location

`examples/`

### Building Examples

```bash
cd examples
make

# Or specify OpenSSL prefix
make OPENSSL_PREFIX=/opt/openssl-dsmil
```

### Available Examples

#### 1. check-pqc

**Purpose:** Check for PQC algorithm availability

**Usage:**
```bash
./check-pqc
```

**Output:**
```
========================================
DSMIL PQC Algorithm Checker
========================================

OpenSSL Version:
  OpenSSL 3.x.x

Loaded Providers:
  ✓ default
  ✓ base
  ✓ pqc
  ✓ dsmil-policy

ML-KEM (Key Encapsulation):
  ✓ ML-KEM-512 (KEM)
  ✓ ML-KEM-768 (KEM)
  ✓ ML-KEM-1024 (KEM)

ML-DSA (Digital Signatures):
  ✓ ML-DSA-44 (Signature)
  ✓ ML-DSA-65 (Signature)
  ✓ ML-DSA-87 (Signature)

✓ PQC check complete
```

#### 2. dsmil-client

**Purpose:** TLS client demonstrating profile usage

**Usage:**
```bash
# With WORLD_COMPAT profile
export OPENSSL_CONF=configs/world.cnf
./dsmil-client google.com 443

# With DSMIL_SECURE profile
export OPENSSL_CONF=configs/dsmil-secure.cnf
export THREATCON_LEVEL=NORMAL
./dsmil-client internal-server.local 443
```

**Output:**
```
DSMIL TLS Client Example
Connecting to google.com:443

=== DSMIL Configuration ===
  Profile:   WORLD_COMPAT
  THREATCON: NORMAL
  Config:    configs/world.cnf

Performing TLS handshake...
✓ TLS handshake successful

=== TLS Connection Info ===
  Protocol: TLSv1.3
  Cipher:   TLS_AES_256_GCM_SHA384
  ⚠ Classical Key Exchange Only
  Server:   CN=google.com

✓ Connection closed successfully
```

## OpenSSL Core Tests

### Running OpenSSL Test Suite

```bash
# After building
make test

# Run specific tests
make test TESTS=test_tls13

# Verbose output
make VERBOSE=1 test
```

### Important Tests for DSMIL

```bash
# ML-KEM tests
make test TESTS=test_evp_kem

# ML-DSA tests
make test TESTS=test_evp_sig

# TLS 1.3 tests
make test TESTS=test_tls13

# Provider tests
make test TESTS=test_provider
```

## Continuous Integration

### CI Test Script

Create `.github/workflows/dsmil-tests.yml`:

```yaml
name: DSMIL Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang perl make

      - name: Create dsclang symlinks
        run: |
          sudo ln -s $(which clang) /usr/local/bin/dsclang
          sudo ln -s $(which clang++) /usr/local/bin/dsclang++

      - name: Run DSMIL tests
        run: |
          cd test/dsmil
          ./test-build-verification.sh
          ./test-policy-provider.sh
          ./test-profiles.sh

      - name: Build world variant
        run: |
          ./util/build-dsllvm-world.sh --clean --test
```

## Performance Testing

### Handshake Performance

```bash
# Benchmark TLS handshake performance
./apps/openssl s_time -connect example.com:443 -new

# With different profiles
export OPENSSL_CONF=configs/world.cnf
./apps/openssl s_time -connect example.com:443 -new

export OPENSSL_CONF=configs/dsmil-secure.cnf
./apps/openssl s_time -connect example.com:443 -new
```

### Throughput Testing

```bash
# Benchmark bulk encryption performance
./apps/openssl speed aes-256-gcm
./apps/openssl speed chacha20-poly1305

# PQC performance
./apps/openssl speed ml-kem-768
./apps/openssl speed ml-dsa-65
```

## Security Testing

### Side-Channel Testing

Side-channel testing requires specialized tools and will be added in Phase 6.

Planned tests:
- Timing variance analysis
- Constant-time verification
- Cache-timing analysis

### Fuzzing

```bash
# Build with fuzzing enabled
./Configure dsllvm-world enable-fuzz-libfuzzer --with-fuzzer-include=/path/to/fuzzer

# Run TLS fuzzer
cd fuzz
./run-fuzzer.sh tls
```

## Test Coverage

### Coverage Report

```bash
# Build with coverage
./Configure dsllvm-world --coverage

# Run tests
make test

# Generate coverage report
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage-report
```

### Current Coverage (Estimated)

| Component | Coverage | Notes |
|-----------|----------|-------|
| ML-KEM implementation | 95% | Core OpenSSL tests |
| ML-DSA implementation | 95% | Core OpenSSL tests |
| Policy provider | 60% | Skeleton only (Phase 2) |
| Build system | 100% | Verification tests |
| Configurations | 100% | Profile tests |

## Troubleshooting Tests

### Common Issues

#### 1. dsclang not found

**Solution:**
```bash
sudo ln -s $(which clang) /usr/local/bin/dsclang
sudo ln -s $(which clang++) /usr/local/bin/dsclang++
```

#### 2. Tests fail on build verification

**Check:**
```bash
# Ensure all files exist
ls Configurations/10-dsllvm.conf
ls util/build-dsllvm-world.sh
ls configs/world.cnf
```

#### 3. Policy provider tests fail

**Reason:** Policy provider is a skeleton (Phase 2 incomplete)

**Expected:** Some tests may be marked as warnings, not failures

#### 4. Examples don't compile

**Check OpenSSL installation:**
```bash
# Verify OpenSSL is installed
ls /opt/openssl-dsmil/include/openssl/ssl.h

# Update Makefile
cd examples
make OPENSSL_PREFIX=/opt/openssl-dsmil
```

## Test Development

### Adding New Tests

1. **Create test script** in `test/dsmil/`
2. **Use standard format:**

```bash
#!/usr/bin/env bash
set -e
set -u

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

# Test suites
# ...

# Summary
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
exit $TESTS_FAILED
```

3. **Make executable:** `chmod +x test-new-feature.sh`
4. **Add to run-all-tests.sh**

### Test Naming Convention

- `test-<component>-<feature>.sh` for specific tests
- `test-<component>.sh` for component test suites
- Use descriptive names

## Best Practices

1. **Run all tests before committing**
   ```bash
   cd test/dsmil && ./run-all-tests.sh
   ```

2. **Test with both builds**
   ```bash
   # Test world build
   ./util/build-dsllvm-world.sh --test

   # Test DSMIL build
   ./util/build-dsllvm-dsmil.sh --test
   ```

3. **Test all profiles**
   ```bash
   for profile in world dsmil-secure atomal; do
       export OPENSSL_CONF=configs/$profile.cnf
       # Run tests
   done
   ```

4. **Use THREATCON levels**
   ```bash
   for level in NORMAL ELEVATED HIGH SEVERE; do
       export THREATCON_LEVEL=$level
       # Run tests
   done
   ```

5. **Check for memory leaks**
   ```bash
   valgrind ./examples/check-pqc
   ```

## Future Testing (Roadmap)

### Phase 2: Policy Provider Testing
- Property query interception tests
- SNI/IP-based profile selection tests
- Algorithm filtering tests

### Phase 3: Event Telemetry Testing
- Event emission tests
- CBOR/JSON format validation
- Socket communication tests

### Phase 5: Hybrid Crypto Testing
- Hybrid KEX composition tests
- Hybrid signature tests
- TLS 1.3 hybrid negotiation tests

### Phase 6: Side-Channel Testing
- Timing variance analysis
- Constant-time verification
- DSLLVM CSNA validation

### Phase 7: TPM Integration Testing
- TPM key storage tests
- Key sealing/unsealing tests
- Hardware-backed TLS tests

### Phase 8: Full Test Suite
- Wycheproof tests
- Interoperability tests
- Fuzzing campaigns
- Performance benchmarks

## References

- [OpenSSL Testing](https://github.com/openssl/openssl/blob/master/test/README.md)
- [IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md)
- [OPENSSL_SECURE_SPEC.md](../OPENSSL_SECURE_SPEC.md)

---

*Last updated: 2025-11-25*
*DSMIL Security Team*
