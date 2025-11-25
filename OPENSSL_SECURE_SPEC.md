# DSMIL-Grade OpenSSL Build – Secure/Compatible Spec

## 0. Overview

This spec defines a **secure, PQC-aware, DSLLVM-compiled OpenSSL 3.x build** for the DSMIL stack that:

* Remains **compatible with the public internet** (browsers, standard TLS, public CAs).
* Enforces **much stricter policies** for DSMIL internal traffic.
* Is built **only via our LLVM fork (DSLLVM + CSNA 2.0)** and integrated into the host defenses.

We explicitly support:

* Classical + PQC + **hybrid** KEM/signatures.
* Multiple security profiles: `WORLD_COMPAT`, `DSMIL_SECURE`, `ATOMAL`.
* Integration with DEFRAMEWORK and local Crypto Fabric components.

---

## 1. Scope & Assumptions

* Target OS: Debian/Forky-class Linux with Xen & DSMIL kernel.
* CPU: Intel Meteor Lake, AVX2 / AES-NI / VAES / VNNI available.
* Toolchain: DSLLVM (our hardened LLVM/Clang fork), CSNA 2.0 compatible.
* OpenSSL branch: 3.x LTS line (exact minor pinned in build scripts).
* PQC provider: **liboqs/oqsprovider-style** or equivalent PQC implementation.

Non-goals:

* No TLS 1.0/1.1; TLS 1.2 allowed only in legacy outbound.
* No FIPS certification, but **FIPS-like discipline**.

---

## 2. Threat Model & Goals

### 2.1 Threat Model (Condensed)

We assume:

* Adversaries with passive and active network control.
* Adversaries that can influence protocol negotiation (downgrades, MITM).
* Adversaries that can observe timing/perf side-channels on shared hardware.
* Future attackers with practical quantum capabilities.

We do *not* assume:

* Compromise of DSLLVM build chain (that is covered separately in DSLLVM spec).
* Physical attacks on the TPM beyond our standard hardware security assumptions.

### 2.2 Goals

* **Forward secrecy** even under classical or quantum future compromise.
* **Downgrade resistance** (classical-only negotiation should be visible and policy-gated).
* **Side-channel minimisation** (constant-time primitives; DSLLVM CSNA annotations used).
* **Hard isolation** between:

  * World-facing compatibility mode.
  * DSMIL internal secure modes.

---

## 3. Crypto Profile & Policy

### 3.1 Classical Algorithms

**Key exchange**

* Preferred: `X25519`, `P-256` (ECDHE).
* No RSA key exchange.

**Signatures**

* `ECDSA P-256`
* `Ed25519`

**Bulk ciphers**

* Primary: `AES-256-GCM`
* Secondary: `ChaCha20-Poly1305` (for non-AES hardware / fallback).

**Disabled**

* RSA key exchange.
* 3DES, RC4, export ciphers.
* CBC modes inbound; legacy outbound CBC only via explicit allowlist.

### 3.2 PQC & Hybrid Algorithms (CSNA 2.0 Aware)

**KEM (for key exchange)**

* ML-KEM-768 (Kyber-768 eq.)
* ML-KEM-1024 (Kyber-1024 eq.) – **preferred for ATOMAL**

**Signatures**

* ML-DSA-65
* ML-DSA-87 – **preferred for ATOMAL**

**Hybrid composition**

* KEX: `ECDHE (X25519|P-256) + ML-KEM-768/1024`
* SIG: `ECDSA P-256 + ML-DSA-65/87`

Hybrids are the **default** where supported; pure classical is allowed only in compatibility profile.

### 3.3 Profiles

We define three policy tiers:

1. **WORLD_COMPAT (Public internet)**

   * TLS 1.3 only (TLS 1.2 outbound if explicitly allowed).
   * Classical mandatory, PQC/hybrid **offered opportunistically**.
   * Allowed TLS 1.3 cipher suites:

     * `TLS_AES_256_GCM_SHA384`
     * `TLS_CHACHA20_POLY1305_SHA256`

2. **DSMIL_SECURE (Private infra / allies)**

   * TLS 1.3 only.
   * Hybrid KEX **mandatory**; connection fails if hybrid cannot be negotiated.
   * Hybrid signatures preferred for internal PKI.
   * Minimum effective security ~192-bit classical equivalent.

3. **ATOMAL (Highest tier)**

   * TLS 1.3 only.
   * **Hybrid-only or PQC-only** trust chains internally.
   * Enforce:

     * `AES-256-GCM` only (no ChaCha).
     * ML-KEM-1024 + ML-DSA-87 wherever possible.
   * No pure classical handshake allowed; classical fallback only at perimeter gateways under strict policy.

---

## 4. Build & Toolchain (DSLLVM + Hardening)

### 4.1 Compiler & Flags

Compiler: `dsclang` (DSLLVM's Clang), with CSNA 2.0 and constant-time annotations enabled.

**Portable build flags (for WORLD_COMPAT binaries)**

* `-O2 -pipe`
* `-fstack-protector-strong`
* `-D_FORTIFY_SOURCE=2`
* `-fPIE`
* `-fdata-sections -ffunction-sections`
* `-flto=full`
* `-march=x86-64-v3` (or negotiated baseline)
* DSLLVM-specific:

  * Enable constant-time enforcement pass on annotated functions.
  * Enable side-channel alerting mode (warnings for branches on secret).

**DSMIL-optimized build flags (internal use)**

* Start from your Meteorlake profile:

  `-O3 -pipe -fomit-frame-pointer -funroll-loops -fstrict-aliasing -fno-plt -fdata-sections -ffunction-sections -flto=full -march=meteorlake -mtune=meteorlake -mavx2 -mfma -mavxvnni -maes -mvaes -mpclmulqdq`

* Add same security flags:

  * `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE`

### 4.2 Linker & Binary Hardening

* PIE everywhere.
* `-Wl,-z,relro,-z,now`
* `-Wl,--gc-sections`
* LTO with `-Wl,-plugin-opt=O3`
* DSLLVM/Clang CFI for non-provider OpenSSL code where feasible.

---

## 5. Provider Architecture

Use OpenSSL 3 provider model with a curated set of providers.

### 5.1 Providers

1. **default**

   * Classical primitives only.
   * AES, SHA-2, ECDHE, ECDSA/EdDSA.

2. **pqc**

   * KEM: ML-KEM-768/1024
   * Signatures: ML-DSA-65/87
   * All implementations annotated with DSLLVM constant-time attributes.

3. **dsmil-policy** (no crypto)

   * Enforces:

     * profile-based allow/deny (WORLD/SECURE/ATOMAL),
     * minimum key lengths,
     * hybrid requirements.
   * Emits a structured event for each decision via a local socket (`/run/crypto-events.sock`) for DEFRAMEWORK.

4. **(optional) fips-like**

   * Wraps default provider, restricting to FIPS-aligned algorithms if you ever need that regime.

### 5.2 Provider Selection & Properties

Use OpenSSL property queries:

* WORLD_COMPAT context:

  * `property: "profile=WORLD_COMPAT, security-level=high"`
* DSMIL_SECURE context:

  * `property: "profile=DSMIL_SECURE, require=pqc, security-level=very-high"`
* ATOMAL context:

  * `property: "profile=ATOMAL, require=pqc-hybrid, sidechannel=locked"`

`dsmil-policy` examines:

* SNI / target IP
* local profile mapping
* current THREATCON level
* and routes between classical + pqc providers or blocks.

---

## 6. Protocol Profiles

### 6.1 TLS

* Min version: TLS 1.3 everywhere.
* TLS 1.2 outbound allowed via explicit opt-in (legacy servers only).

**WORLD_COMPAT**

* Classical suites only as baseline, PQC offered via named groups/extensions.
* If peer supports PQC groups, hybrid is used; otherwise log downgrade.

**DSMIL_SECURE**

* Must negotiate hybrid KEX if peer supports; otherwise fail (or require explicit policy override).
* Internal services use certs with at least:

  * ECDSA P-256 sig,
  * PQC side metadata or parallel cert.

**ATOMAL**

* Only hybrid or PQC-only internal paths.
* Perimeter gateways allowed to terminate PQC and re-expose classical for the outside world, but internal leg remains PQC/hybrid.

### 6.2 X.509 PKI

Public internet:

* Classical X.509 chains (ECDSA/Ed25519) trusted as normal.

Internal PKI:

* Local CA issues certs with:

  * Classical keypair + PQC keypair,
  * Hybrid or dual-cert strategy:

    * Classical cert for external compatibility.
    * PQC "shadow identity" for internal validation (extensions or parallel cert).

DSMIL trust engine:

* Treats:

  * `classical-only` as degraded,
  * `hybrid` as normal,
  * `PQC-only` as highest trust, internal-only.

### 6.3 SSH / VPN / Misc

* Reuse OpenSSL providers where possible (OpenSSH w/ OpenSSL, VPN endpoints).
* Maintain classical host keys for compatibility plus PQC keys for internal trust decisions.
* Policy mapping:

  * WORLD = standard SSH config,
  * DSMIL_SECURE/ATOMAL = additional constraint in key types allowed for host/user auth.

---

## 7. Runtime Hardening & OS Integration

### 7.1 Key Storage

* Long-term keys:

  * Prefer TPM-sealed keys or HSM/SmartCard (Yubi) via engine/provider.
  * on-disk keys must be encrypted and access-controlled.

* Session keys:

  * Short-lived, securely zeroed when done.
  * Hybrid secrets folded via HKDF with explicit labels (`"classical"`, `"pqc"`).

### 7.2 Side-Channel Controls

* Only constant-time implementations allowed in PQC provider; enforced by DSLLVM annotations + build checks.
* Automated pre-release **timing variance tests** on critical operations (KEM decap, signature, etc.).
* Disable variable-time code paths on Meteor Lake by default.

### 7.3 Sandboxing (optional, per service)

* Encourage running OpenSSL-terminating frontends under:

  * seccomp filters generated from known syscall profile,
  * minimal capabilities,
  * chroot/namespace isolation.

---

## 8. Telemetry & Local Integration

OpenSSL must be **observable** without leaking secrets.

### 8.1 Event Emission

`dsmil-policy` provider emits:

* For each handshake / crypto context decision:

  * profile (WORLD/SECURE/ATOMAL),
  * protocol (TLS/SSH/VPN),
  * version,
  * KEX type (classical / hybrid / PQC),
  * cipher suite,
  * signature type,
  * decision (`allowed`, `blocked`, `downgraded`, `forced_hybrid`),
  * non-sensitive peer metadata (e.g. fingerprint hash, not full cert).

Sent as CBOR/JSON records to `/run/crypto-events.sock`.

### 8.2 DEFRAMEWORK Consumption

* DEFRAMEWORK ingests events, enriches with:

  * pid, binary hash, DSMIL device layer, THREATCON,
  * network context (interface, route classification).

* DEFRAMEWORK may:

  * escalate policy (ask OpenSSL to move service from WORLD to SECURE),
  * block certain peers/algos temporarily,
  * log anomalies locally for SHRINK.

---

## 9. Deployment Modes

We build **two binaries / configs** from the same source:

1. **Public Build (`openssl-world`)**

   * Compiled with portable flags.
   * Default profile: `WORLD_COMPAT`.
   * PQC provider loaded but optional.
   * No aggressive self-hardening that might break common workloads.

2. **DSMIL Build (`openssl-dsmil`)**

   * Compiled with Meteorlake-optimized flags.
   * Default profiles: `DSMIL_SECURE` / `ATOMAL` by config.
   * PQC provider mandatory.
   * Full integration with TPM, DEFRAMEWORK, local Crypto Fabric.

Config selection via:

* `OPENSSL_CONF=/etc/openssl/world.cnf` vs `/etc/openssl/dsmil.cnf`
* Service-specific environment or wrapper scripts.

---

## 10. Testing & Validation

### 10.1 Functional

* OpenSSL test suite (core + providers).
* TLS interop tests with:

  * major browsers,
  * major HTTP stacks,
  * classical-only peers.

### 10.2 Crypto Correctness

* Wycheproof tests for all classical primitives used.
* PQC KATs for ML-KEM/ML-DSA.
* Additional randomized tests for hybrid composition.

### 10.3 Side-Channel & Timing

* Custom timing harness:

  * Repeated KEM decap, signature, etc. with varied secrets.
  * Check statistical variance for DSLLVM-marked constant-time functions.

### 10.4 Fuzzing

* TLS state machine fuzzing (libFuzzer/honggfuzz).
* X.509 parsing fuzzing (certs, CRLs, OCSP).

### 10.5 Integration Tests

* Ensure OpenSSL events correctly feed DEFRAMEWORK.
* Ensure policy transitions (WORLD → SECURE → ATOMAL) behave as expected with real services.

---

## 11. Configuration Skeleton (High-Level)

Not full config, just conceptual knobs:

```ini
# /etc/openssl/dsmil.cnf (conceptual)

[openssl_init]
providers = default_provider, pqc_provider, dsmil_policy
alg_section = algorithm_sect

[default_provider]
activate = 1

[pqc_provider]
activate = 1

[dsmil_policy]
activate = 1
profile = DSMIL_SECURE
event_socket = /run/crypto-events.sock
threatcon_env = THREATCON_LEVEL

[algorithm_sect]
# allowlists/denylists per profile, mapped via dsmil_policy
```

---

## 12. Implementation Roadmap

### Phase 1: Foundation (Weeks 1-4)

1. **Build System Integration**
   * Create DSLLVM-based build configurations for both `openssl-world` and `openssl-dsmil`
   * Implement compiler flag profiles for portable and Meteorlake-optimized builds
   * Set up dual-build infrastructure in existing build system

2. **PQC Provider Enhancement**
   * Review and enhance existing `oqs-provider` with DSLLVM constant-time annotations
   * Implement ML-KEM-768/1024 and ML-DSA-65/87 support
   * Add CSNA 2.0 awareness to PQC primitives

3. **Testing Infrastructure**
   * Integrate Wycheproof test suite
   * Set up PQC KAT testing framework
   * Create initial timing variance test harness

### Phase 2: Policy Layer (Weeks 5-8)

1. **DSMIL Policy Provider**
   * Design and implement `dsmil-policy` provider
   * Create profile enforcement logic (WORLD_COMPAT, DSMIL_SECURE, ATOMAL)
   * Implement property query system for profile selection

2. **Event Telemetry**
   * Design CBOR/JSON event schema
   * Implement event emission to `/run/crypto-events.sock`
   * Create integration stubs for DEFRAMEWORK

3. **Configuration System**
   * Design and document OpenSSL config file format for profiles
   * Create example configs for each security tier
   * Implement config validation tools

### Phase 3: Hybrid Crypto (Weeks 9-12)

1. **Hybrid KEM Implementation**
   * Implement ECDHE + ML-KEM composition logic
   * Add HKDF key derivation with explicit labeling
   * Create test vectors for hybrid operations

2. **Hybrid Signature Support**
   * Implement dual-signature certificate handling
   * Create certificate validation logic for hybrid/classical/PQC modes
   * Design certificate chain evaluation for DSMIL trust engine

3. **TLS Integration**
   * Integrate hybrid algorithms into TLS 1.3 handshake
   * Implement negotiation logic for hybrid/classical fallback
   * Add downgrade detection and logging

### Phase 4: Hardening & Integration (Weeks 13-16)

1. **Side-Channel Mitigation**
   * Apply DSLLVM constant-time annotations to all crypto paths
   * Implement timing variance testing for critical operations
   * Review and harden variable-time code paths

2. **TPM/HSM Integration**
   * Design key storage provider using TPM2
   * Implement engine/provider for hardware-backed keys
   * Create key management utilities

3. **Security Validation**
   * Run comprehensive fuzzing campaigns
   * Perform interoperability testing with major browsers
   * Execute full test suite across all profiles

### Phase 5: Documentation & Deployment (Weeks 17-20)

1. **Documentation**
   * Write deployment guides for both build variants
   * Create configuration reference documentation
   * Document integration points with DEFRAMEWORK

2. **Deployment Tools**
   * Create installation scripts for both variants
   * Build package manifests (deb/rpm)
   * Design version pinning and update strategy

3. **Validation & Sign-off**
   * Final security review
   * Performance benchmarking across profiles
   * Production deployment planning

---

## 13. Related Documentation

* [ML-KEM Design](doc/designs/ML-KEM.md)
* [ML-DSA Design](doc/designs/ml-dsa.md)
* [OpenSSL Provider Documentation](README-PROVIDERS.md)
* DSLLVM CSNA 2.0 Specification (external)
* DEFRAMEWORK Integration Guide (external)

---

## 14. Open Questions & Future Work

### Open Questions

1. **Certificate Format**
   * Should we use composite certificates (single cert with both classical and PQC keys) or parallel certificates?
   * What's the optimal strategy for gradual migration of internal PKI?

2. **Performance Trade-offs**
   * What's the acceptable performance overhead for hybrid operations in WORLD_COMPAT mode?
   * Should we cache hybrid KEM results for connection resumption?

3. **Interoperability**
   * How do we handle peers that support PQC but with different parameter sets?
   * What's the fallback behavior when hybrid negotiation fails in DSMIL_SECURE mode?

### Future Enhancements

1. **SLH-DSA Integration**
   * Add support for stateless hash-based signatures as third signature option
   * Evaluate for specific high-security, low-performance-requirement scenarios

2. **Hardware Acceleration**
   * Explore Intel QAT integration for PQC operations
   * Investigate GPU acceleration for ML-KEM/ML-DSA operations

3. **Advanced Monitoring**
   * Real-time performance metrics for crypto operations
   * Anomaly detection for unusual cipher suite negotiations
   * Integration with SHRINK for long-term trend analysis

4. **Policy Automation**
   * Dynamic policy adjustment based on THREATCON levels
   * Automated testing of policy transitions
   * Policy simulation and impact analysis tools

---

## Appendix A: Cipher Suite Reference

### TLS 1.3 Cipher Suites (WORLD_COMPAT)

```
TLS_AES_256_GCM_SHA384           (mandatory)
TLS_CHACHA20_POLY1305_SHA256     (fallback)
```

### TLS 1.3 Cipher Suites (DSMIL_SECURE, ATOMAL)

```
TLS_AES_256_GCM_SHA384           (mandatory)
TLS_CHACHA20_POLY1305_SHA256     (DSMIL_SECURE only)
```

### Key Exchange Groups

**Classical (WORLD_COMPAT)**
```
X25519                           (preferred)
secp256r1 (P-256)               (allowed)
```

**Hybrid (DSMIL_SECURE)**
```
X25519+ML-KEM-768                (preferred)
P-256+ML-KEM-768                 (allowed)
```

**Hybrid/PQC (ATOMAL)**
```
X25519+ML-KEM-1024               (preferred)
ML-KEM-1024                      (allowed, internal only)
```

### Signature Algorithms

**Classical (WORLD_COMPAT)**
```
ecdsa_secp256r1_sha256
ed25519
```

**Hybrid (DSMIL_SECURE)**
```
ecdsa_secp256r1_sha256+mldsa65
ed25519+mldsa65
```

**Hybrid/PQC (ATOMAL)**
```
ecdsa_secp256r1_sha256+mldsa87   (preferred)
mldsa87                          (allowed, internal only)
```

---

## Appendix B: Compiler Flag Reference

### World Build (Portable)

```bash
CC=dsclang
CFLAGS="-O2 -pipe \
        -fstack-protector-strong \
        -D_FORTIFY_SOURCE=2 \
        -fPIE \
        -fdata-sections -ffunction-sections \
        -flto=full \
        -march=x86-64-v3 \
        -fcsna-enable \
        -fcsna-constant-time-check"

LDFLAGS="-Wl,-z,relro,-z,now \
         -Wl,--gc-sections \
         -Wl,-plugin-opt=O3"
```

### DSMIL Build (Meteorlake-Optimized)

```bash
CC=dsclang
CFLAGS="-O3 -pipe \
        -fomit-frame-pointer \
        -funroll-loops \
        -fstrict-aliasing \
        -fno-plt \
        -fstack-protector-strong \
        -D_FORTIFY_SOURCE=2 \
        -fPIE \
        -fdata-sections -ffunction-sections \
        -flto=full \
        -march=meteorlake \
        -mtune=meteorlake \
        -mavx2 -mfma -mavxvnni \
        -maes -mvaes -mpclmulqdq \
        -fcsna-enable \
        -fcsna-constant-time-check \
        -fcsna-side-channel-alert"

LDFLAGS="-Wl,-z,relro,-z,now \
         -Wl,--gc-sections \
         -Wl,-plugin-opt=O3 \
         -flto=full"
```

---

## Appendix C: Event Schema

### Crypto Event Structure (JSON)

```json
{
  "version": "1.0",
  "timestamp": "2025-11-25T12:34:56.789Z",
  "event_type": "handshake_complete",
  "profile": "DSMIL_SECURE",
  "protocol": "TLS",
  "protocol_version": "1.3",
  "kex": {
    "type": "hybrid",
    "classical": "X25519",
    "pqc": "ML-KEM-768",
    "security_level": 192
  },
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "signature": {
    "type": "hybrid",
    "classical": "ecdsa_secp256r1_sha256",
    "pqc": "ML-DSA-65"
  },
  "decision": "allowed",
  "peer": {
    "cert_fingerprint": "sha256:abcd1234...",
    "trust_level": "internal"
  },
  "metadata": {
    "downgrade_attempted": false,
    "policy_override": false,
    "threatcon_level": "NORMAL"
  }
}
```

### Event Types

* `handshake_start` - TLS/SSL handshake initiated
* `handshake_complete` - Handshake successfully completed
* `handshake_failed` - Handshake failed (includes reason)
* `policy_violation` - Policy check failed
* `downgrade_detected` - Protocol/algorithm downgrade attempt detected
* `algorithm_negotiated` - Specific algorithm selected
* `key_operation` - Private key operation (sign, decrypt, etc.)

---

## Appendix D: Build Commands

### Configure for World Build

```bash
./Configure linux-x86_64 \
    --prefix=/opt/openssl-world \
    --openssldir=/opt/openssl-world/ssl \
    enable-ec_nistp_64_gcc_128 \
    no-ssl3 no-weak-ssl-ciphers \
    enable-tls1_3 \
    --with-rand-seed=rdcpu,rdseed,devrandom \
    CC=dsclang \
    CFLAGS="-O2 -pipe -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -march=x86-64-v3" \
    LDFLAGS="-Wl,-z,relro,-z,now"
```

### Configure for DSMIL Build

```bash
./Configure linux-x86_64 \
    --prefix=/opt/openssl-dsmil \
    --openssldir=/opt/openssl-dsmil/ssl \
    enable-ec_nistp_64_gcc_128 \
    no-ssl3 no-weak-ssl-ciphers \
    enable-tls1_3 \
    --with-rand-seed=rdcpu,rdseed,devrandom \
    CC=dsclang \
    CFLAGS="-O3 -pipe -march=meteorlake -mtune=meteorlake -mavx2 -mfma -mavxvnni -maes -mvaes -mpclmulqdq -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE" \
    LDFLAGS="-Wl,-z,relro,-z,now -Wl,--gc-sections"
```

### Build and Install

```bash
# Build
make -j$(nproc)

# Test
make test

# Install
sudo make install
```

---

## Appendix E: Security Considerations

### Threat Matrix

| Threat | Mitigation | Profile Coverage |
|--------|-----------|------------------|
| MITM Attack | Hybrid KEX + mutual auth | DSMIL_SECURE, ATOMAL |
| Quantum Adversary | PQC/Hybrid algorithms | All profiles (opportunistic in WORLD) |
| Side-channel | Constant-time crypto + DSLLVM checks | All profiles |
| Downgrade Attack | Policy enforcement + logging | All profiles |
| Certificate Forgery | Multi-signature validation | DSMIL_SECURE, ATOMAL |
| Key Compromise | Forward secrecy + short-lived keys | All profiles |
| Protocol Exploit | TLS 1.3 only, no legacy | All profiles |

### Attack Surface Reduction

1. **Disabled Features**
   * SSLv3, TLS 1.0, TLS 1.1
   * RSA key exchange
   * Weak ciphers (3DES, RC4, export)
   * Compression
   * Renegotiation (except secure renegotiation in TLS 1.2)

2. **Minimal Dependencies**
   * No external crypto libraries except liboqs for PQC
   * Minimal runtime dependencies
   * Static linking where appropriate for DSMIL build

3. **Privilege Separation**
   * Separate processes for key operations when using TPM
   * Sandboxed providers where feasible
   * Capability-based access control

### Compliance Considerations

While not pursuing formal certification, this build aligns with:

* **NIST SP 800-52r2** (TLS guidelines)
* **NIST SP 800-56Cr2** (Key derivation)
* **NIST PQC Standards** (ML-KEM, ML-DSA)
* **BSI TR-02102-2** (Cryptographic mechanisms)
* **NSA CNSA 2.0** (Commercial National Security Algorithm Suite)

---

## Version History

* **v1.0** (2025-11-25): Initial specification
  * Defined three security profiles (WORLD_COMPAT, DSMIL_SECURE, ATOMAL)
  * Specified build configurations for DSLLVM
  * Outlined PQC and hybrid crypto requirements
  * Designed provider architecture and event telemetry
  * Created implementation roadmap
