# DSMIL OpenSSL - Quick Testing Guide

This is a quick reference for testing the DSMIL OpenSSL implementation. For comprehensive testing documentation, see [docs/TESTING.md](docs/TESTING.md).

## Quick Test

```bash
# Run all DSMIL tests
cd test/dsmil
./run-all-tests.sh
```

## Test Suites

### 1. Build Verification

```bash
./test/dsmil/test-build-verification.sh
```

Tests:
- ✓ Build files exist
- ✓ Configurations valid
- ✓ Policy provider present
- ✓ Documentation complete

### 2. Policy Provider

```bash
./test/dsmil/test-policy-provider.sh
```

Tests:
- ✓ Profile definitions
- ✓ THREATCON levels
- ✓ Policy decisions
- ✓ Algorithm filtering

### 3. Security Profiles

```bash
./test/dsmil/test-profiles.sh
```

Tests:
- ✓ WORLD_COMPAT config
- ✓ DSMIL_SECURE config
- ✓ ATOMAL config
- ✓ Profile comparison

## Build & Test

```bash
# World build
./util/build-dsllvm-world.sh --clean --test

# DSMIL build
./util/build-dsllvm-dsmil.sh --clean --test
```

## Examples

```bash
# Build examples
cd examples
make

# Check PQC support
./check-pqc

# Test TLS client
export OPENSSL_CONF=../configs/world.cnf
./dsmil-client google.com 443
```

## Test Matrix

| Test | What | Status |
|------|------|--------|
| Build Verification | Infrastructure & configs | ✅ Complete |
| Policy Provider | Unit tests | ✅ Complete |
| Security Profiles | Integration tests | ✅ Complete |
| Examples | Usage demos | ✅ Complete |
| OpenSSL Core | Standard tests | ⏳ Run with `make test` |
| Side-Channel | Timing analysis | 📋 Phase 6 |
| Fuzzing | Security testing | 📋 Phase 8 |

## Expected Results

All tests should pass:

```
========================================
Overall Test Summary
========================================
Test Suites Run:    3
Suites Passed:      3
Suites Failed:      0

✓✓✓ All DSMIL test suites passed! ✓✓✓
```

## Troubleshooting

### dsclang not found

```bash
sudo ln -s $(which clang) /usr/local/bin/dsclang
```

### Tests show warnings

Some warnings are expected for Phase 2 skeleton implementation. Look for:
- `[PASS]` = Test passed ✅
- `[FAIL]` = Test failed ❌
- `[WARN]` = Warning (not a failure) ⚠️

### Examples don't compile

```bash
cd examples
make OPENSSL_PREFIX=/opt/openssl-dsmil
```

## Full Documentation

See **[docs/TESTING.md](docs/TESTING.md)** for:
- Detailed test descriptions
- Performance testing
- Security testing
- CI/CD integration
- Test development guide

## Quick Links

- [OPENSSL_SECURE_SPEC.md](OPENSSL_SECURE_SPEC.md) - Security specification
- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) - Implementation roadmap
- [DSMIL_README.md](DSMIL_README.md) - User guide
- [docs/TESTING.md](docs/TESTING.md) - Comprehensive testing guide

---

*DSMIL Security Team • 2025*
