# DSMIL-Grade OpenSSL Implementation Plan

## Executive Summary

This document outlines the implementation plan for adapting the DSSSL (OpenSSL fork) into a DSMIL-grade secure build as specified in `OPENSSL_SECURE_SPEC.md`. The implementation leverages existing ML-KEM and ML-DSA implementations while adding DSLLVM build configurations, policy enforcement, and event telemetry.

## Current State Analysis

### What Already Exists ✓

1. **Post-Quantum Crypto Implementation**
   - ✓ ML-KEM-512/768/1024 (`crypto/ml_kem/`, `providers/implementations/kem/ml_kem_kem.c`)
   - ✓ ML-DSA-44/65/87 (`crypto/ml_dsa/`, `providers/implementations/signature/ml_dsa_sig.c`)
   - ✓ SLH-DSA (`crypto/slh_dsa/`)
   - ✓ Hybrid KEM support started (`providers/implementations/kem/mlx_kem.c`)

2. **Infrastructure**
   - ✓ OpenSSL 3.x provider architecture
   - ✓ Default, Legacy, FIPS, Base, Null providers
   - ✓ Configure script with extensive build options
   - ✓ Constant-time implementation considerations (see ML-KEM.md, ml-dsa.md)

3. **Testing Frameworks**
   - ✓ Wycheproof test suite (submodule)
   - ✓ TLS fuzzer (submodule)
   - ✓ Existing OpenSSL test suite

4. **External Provider Support**
   - ✓ oqs-provider submodule (not initialized)
   - ✓ pkcs11-provider submodule for HSM/TPM

### What Needs to Be Implemented

1. **DSLLVM Build System Integration**
   - Build configurations for portable (world) and optimized (DSMIL) builds
   - Compiler flag profiles with CSNA 2.0 annotations
   - Dual-build infrastructure

2. **DSMIL Policy Provider**
   - New provider for policy enforcement (WORLD_COMPAT/DSMIL_SECURE/ATOMAL)
   - Algorithm selection based on security profiles
   - Property query system integration

3. **Event Telemetry System**
   - Event emission to `/run/crypto-events.sock`
   - CBOR/JSON event formatting
   - Integration points for DEFRAMEWORK

4. **Configuration System**
   - OpenSSL config files for each security profile
   - Profile-specific algorithm allowlists/denylists
   - THREATCON integration

5. **Build Scripts & Tools**
   - Wrapper scripts for DSLLVM compilation
   - Installation scripts for both variants
   - Version management

6. **Enhanced Hybrid Support**
   - Expand existing mlx_kem.c for full hybrid composition
   - Hybrid signature support (dual-cert or composite)
   - TLS 1.3 integration

---

## Implementation Phases

### Phase 1: Build System Foundation (Current Sprint)

**Goal:** Enable DSLLVM-based builds with proper compiler flags

**Tasks:**

1. **Create DSLLVM Build Configurations**
   - File: `Configurations/10-dsllvm.conf`
   - Define two targets:
     - `dsllvm-world`: Portable x86-64-v3 build
     - `dsllvm-dsmil`: Meteorlake-optimized build
   - Configure compiler flags as per spec

2. **Create Build Wrapper Scripts**
   - File: `util/build-dsllvm-world.sh`
   - File: `util/build-dsllvm-dsmil.sh`
   - Automate configure + build + test process

3. **Verification**
   - Test build with mock `dsclang` (alias to clang for now)
   - Verify compiler flags are applied
   - Run basic test suite

**Deliverables:**
- Working DSLLVM build configurations
- Build scripts
- Build verification documentation

---

### Phase 2: DSMIL Policy Provider (Next Sprint)

**Goal:** Implement policy enforcement provider

**Tasks:**

1. **Create Provider Skeleton**
   - Directory: `providers/dsmil/`
   - File: `providers/dsmil/dsmilprov.c`
   - File: `providers/dsmil/build.info`
   - Implement provider initialization and query interface

2. **Implement Policy Logic**
   - File: `providers/dsmil/policy.c`
   - Profile definitions (WORLD_COMPAT, DSMIL_SECURE, ATOMAL)
   - Algorithm filtering based on profiles
   - Property query handling

3. **Property Query Integration**
   - Map OpenSSL property queries to policy decisions
   - Implement profile selection logic
   - SNI/IP-based profile mapping

4. **Testing**
   - Unit tests for policy decisions
   - Integration tests with existing providers
   - Verify algorithm selection per profile

**Deliverables:**
- Functional DSMIL policy provider
- Policy enforcement tests
- Configuration documentation

---

### Phase 3: Event Telemetry System

**Goal:** Implement observable crypto operations for DEFRAMEWORK

**Tasks:**

1. **Event Infrastructure**
   - File: `providers/dsmil/events.c`
   - File: `providers/dsmil/events.h`
   - Unix domain socket to `/run/crypto-events.sock`
   - CBOR/JSON event formatting

2. **Event Emission Points**
   - Hook into policy provider decisions
   - Capture handshake events
   - Log algorithm negotiations
   - Detect downgrade attempts

3. **Event Schema Implementation**
   - Implement event types per spec Appendix C
   - Include metadata (profile, KEX type, cipher, etc.)
   - Ensure no secret leakage

4. **Testing**
   - Mock DEFRAMEWORK consumer
   - Verify event format and content
   - Performance impact assessment

**Deliverables:**
- Event telemetry system
- Event schema documentation
- Integration test suite

---

### Phase 4: Configuration System

**Goal:** Provide configuration files for each security profile

**Tasks:**

1. **Create Configuration Templates**
   - File: `config/world.cnf`
   - File: `config/dsmil-secure.cnf`
   - File: `config/atomal.cnf`

2. **Profile Configuration**
   - Define provider activation per profile
   - Configure algorithm allowlists/denylists
   - Set security levels
   - THREATCON integration placeholders

3. **Documentation**
   - Configuration reference guide
   - Profile selection guide
   - Migration guide

**Deliverables:**
- Configuration templates
- Configuration documentation
- Example use cases

---

### Phase 5: Hybrid Crypto Enhancement

**Goal:** Complete hybrid KEM and signature support

**Tasks:**

1. **Expand Hybrid KEM**
   - Enhance `providers/implementations/kem/mlx_kem.c`
   - Implement X25519+ML-KEM-768/1024
   - Implement P-256+ML-KEM-768/1024
   - HKDF composition with explicit labels

2. **Hybrid Signature Support**
   - Design composite or dual-cert approach
   - Implement ECDSA+ML-DSA composition
   - Certificate validation logic

3. **TLS 1.3 Integration**
   - Ensure hybrid algorithms negotiate properly
   - Implement downgrade detection
   - Add logging for classical fallback

4. **Testing**
   - Interop tests with browsers
   - Hybrid composition correctness tests
   - KAT for hybrid operations

**Deliverables:**
- Complete hybrid crypto support
- TLS 1.3 integration
- Interoperability test results

---

### Phase 6: Hardening & CSNA Integration

**Goal:** Apply DSLLVM constant-time annotations and side-channel mitigations

**Tasks:**

1. **CSNA Annotations**
   - Add constant-time annotations to ML-KEM code
   - Add annotations to ML-DSA code
   - Add annotations to hybrid composition code

2. **Side-Channel Testing**
   - Implement timing variance harness
   - Test KEM decapsulation
   - Test signature operations
   - Statistical analysis of timing

3. **Compiler Checks**
   - Enable DSLLVM constant-time enforcement
   - Enable side-channel alert mode
   - Fix any identified issues

**Deliverables:**
- CSNA-annotated crypto code
- Timing test harness
- Side-channel assessment report

---

### Phase 7: TPM/HSM Integration

**Goal:** Integrate hardware-backed key storage

**Tasks:**

1. **TPM2 Provider Integration**
   - Initialize pkcs11-provider submodule
   - Configure for TPM2 support
   - Test key sealing/unsealing

2. **Key Management**
   - Implement long-term key storage in TPM
   - Secure key access controls
   - Key lifecycle management

3. **Testing**
   - TPM-backed TLS handshake
   - Key persistence tests
   - Fallback to software keys

**Deliverables:**
- TPM2 integration
- Key management tools
- TPM integration guide

---

### Phase 8: Testing & Validation

**Goal:** Comprehensive testing across all profiles and scenarios

**Tasks:**

1. **Functional Testing**
   - Full OpenSSL test suite on both builds
   - TLS interop tests (browsers, curl, etc.)
   - SSH/VPN integration tests

2. **Crypto Correctness**
   - Wycheproof tests for classical crypto
   - PQC KAT tests
   - Hybrid composition tests

3. **Security Testing**
   - Fuzzing campaign (TLS state machine, X.509)
   - Timing side-channel tests
   - Policy enforcement validation

4. **Performance Benchmarking**
   - Handshake performance per profile
   - Throughput tests
   - Overhead analysis

**Deliverables:**
- Test results report
- Performance benchmarks
- Security assessment

---

### Phase 9: Documentation & Deployment

**Goal:** Complete documentation and deployment tools

**Tasks:**

1. **Documentation**
   - Build guide
   - Configuration reference
   - Deployment guide
   - API documentation updates

2. **Packaging**
   - Create .deb packages for both builds
   - Package dependencies
   - Installation scripts

3. **Deployment Tools**
   - System integration scripts
   - Configuration management
   - Update procedures

**Deliverables:**
- Complete documentation set
- Deployment packages
- Installation guides

---

## Implementation Priority

### Must-Have (Critical Path)

1. DSLLVM build configurations (Phase 1)
2. DSMIL policy provider (Phase 2)
3. Configuration system (Phase 4)
4. Hybrid crypto completion (Phase 5)

### Should-Have (High Priority)

5. Event telemetry (Phase 3)
6. CSNA annotations (Phase 6)
7. Testing & validation (Phase 8)

### Nice-to-Have (Medium Priority)

8. TPM integration (Phase 7)
9. Advanced documentation (Phase 9)

---

## File Structure (Planned)

```
DSSSL/
├── OPENSSL_SECURE_SPEC.md          # ✓ Created
├── IMPLEMENTATION_PLAN.md           # ✓ Created
├── Configurations/
│   └── 10-dsllvm.conf              # New: DSLLVM build configs
├── config/
│   ├── world.cnf                   # New: WORLD_COMPAT profile
│   ├── dsmil-secure.cnf           # New: DSMIL_SECURE profile
│   └── atomal.cnf                  # New: ATOMAL profile
├── providers/
│   └── dsmil/                      # New: DSMIL policy provider
│       ├── dsmilprov.c
│       ├── policy.c
│       ├── events.c
│       ├── events.h
│       └── build.info
├── util/
│   ├── build-dsllvm-world.sh      # New: Build script
│   ├── build-dsllvm-dsmil.sh      # New: Build script
│   └── deploy-dsmil.sh             # New: Deployment script
├── crypto/
│   ├── ml_kem/                     # ✓ Exists - will enhance
│   └── ml_dsa/                     # ✓ Exists - will enhance
└── test/
    └── recipes/
        └── 95-test_dsmil_policy.t  # New: Policy tests
```

---

## Dependencies & Prerequisites

### Build Environment

- DSLLVM (dsclang) compiler
  - For initial work: can use clang as mock
  - For production: need real DSLLVM with CSNA 2.0

### External Libraries

- liboqs (via oqs-provider submodule) - optional, using built-in ML-KEM/ML-DSA
- TPM2 libraries (for Phase 7)
- JSON/CBOR library for event formatting

### System Requirements

- Linux kernel with Xen support (for production)
- Intel Meteor Lake CPU (for DSMIL-optimized build)
- TPM 2.0 (for Phase 7)

---

## Risk Assessment

### High Risk

1. **DSLLVM availability**
   - Mitigation: Use clang with feature flags as stand-in during development
   - Mitigation: Document required DSLLVM features

2. **Hybrid crypto complexity**
   - Mitigation: Leverage existing mlx_kem.c as foundation
   - Mitigation: Comprehensive testing

### Medium Risk

3. **Performance overhead of policy provider**
   - Mitigation: Optimize hot paths
   - Mitigation: Profile-based caching

4. **Event telemetry performance impact**
   - Mitigation: Async event emission
   - Mitigation: Buffering and batching

### Low Risk

5. **Configuration complexity**
   - Mitigation: Good documentation and examples
   - Mitigation: Validation tools

---

## Success Criteria

### Phase 1 Success (Build System)
- [ ] Both DSLLVM build targets compile successfully
- [ ] Compiler flags verified in build output
- [ ] Basic test suite passes on both builds
- [ ] Build time < 2x baseline

### Phase 2 Success (Policy Provider)
- [ ] Policy provider loads and initializes
- [ ] Correct algorithm selection per profile
- [ ] No performance regression > 5%
- [ ] Policy tests pass

### Phase 3 Success (Telemetry)
- [ ] Events emitted to Unix socket
- [ ] Event format matches schema
- [ ] No secrets leaked in events
- [ ] Performance overhead < 2%

### Overall Success
- [ ] All three profiles (WORLD/SECURE/ATOMAL) functional
- [ ] TLS 1.3 with hybrid KEX works
- [ ] Interop with major browsers
- [ ] Side-channel tests pass
- [ ] Documentation complete

---

## Timeline Estimate

| Phase | Duration | Dependencies |
|-------|----------|-------------|
| Phase 1: Build System | 1 week | None |
| Phase 2: Policy Provider | 2 weeks | Phase 1 |
| Phase 3: Telemetry | 1 week | Phase 2 |
| Phase 4: Configuration | 1 week | Phase 2 |
| Phase 5: Hybrid Crypto | 2 weeks | Phase 1, 2 |
| Phase 6: CSNA/Hardening | 2 weeks | Phase 5 |
| Phase 7: TPM Integration | 2 weeks | Phase 2, 4 |
| Phase 8: Testing | 2 weeks | Phase 1-6 |
| Phase 9: Documentation | 1 week | All |

**Total: ~14 weeks (3.5 months)**

Note: Phases can overlap; this is serial estimate.

---

## Next Steps (Immediate)

1. **Create DSLLVM build configuration** (`Configurations/10-dsllvm.conf`)
2. **Create build wrapper scripts** (`util/build-dsllvm-*.sh`)
3. **Test build with clang** (as DSLLVM stand-in)
4. **Begin DSMIL policy provider skeleton**

---

## Appendix: Key Design Decisions

### Decision 1: Build-in ML-KEM/ML-DSA vs OQS Provider

**Decision:** Use built-in ML-KEM and ML-DSA implementations in DSSSL, not oqs-provider

**Rationale:**
- DSSSL already has native ML-KEM and ML-DSA with design docs
- Easier to add CSNA annotations to code we control
- Better integration with policy provider
- OQS provider can still be optional add-on

### Decision 2: Policy Provider Architecture

**Decision:** Implement as separate provider, not as part of default provider

**Rationale:**
- Clean separation of concerns
- Can be loaded/unloaded independently
- Easier testing and validation
- Follows OpenSSL provider model

### Decision 3: Event Format

**Decision:** Use JSON for events (CBOR optional/future)

**Rationale:**
- JSON easier to debug and test
- CBOR can be added later for efficiency
- Both formats supported by most logging systems

### Decision 4: Configuration Strategy

**Decision:** Separate config files per profile, not runtime switching

**Rationale:**
- Clearer security boundaries
- Easier to audit
- Prevents accidental profile mixing
- Can still override via environment

---

*Version: 1.0*
*Date: 2025-11-25*
*Author: DSMIL Security Team*
