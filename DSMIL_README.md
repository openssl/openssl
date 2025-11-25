# DSMIL-Grade OpenSSL Implementation

This repository contains a DSMIL-grade secure build of OpenSSL with post-quantum cryptography (PQC) support, multiple security profiles, and integration hooks for the DSMIL infrastructure.

## Overview

DSSSL (DSMIL SSL) is a hardened fork of OpenSSL 3.x that provides:

- **Post-Quantum Cryptography**: Built-in ML-KEM (Kyber) and ML-DSA (Dilithium) support
- **Hybrid Crypto**: Classical + PQC hybrid key exchange and signatures
- **Multiple Security Profiles**: WORLD_COMPAT, DSMIL_SECURE, ATOMAL
- **DSLLVM Builds**: Optimized with DSLLVM (hardened LLVM) and CSNA 2.0
- **Policy Enforcement**: Runtime security policy provider
- **Event Telemetry**: Integration with DEFRAMEWORK (planned Phase 3)

## Quick Start

### Prerequisites

- Linux (Debian/Forky-class or similar)
- DSLLVM compiler (or clang 19+ for development)
- Perl 5.10+
- Make
- Intel Meteor Lake CPU (for DSMIL-optimized build)

### Build World (Portable) Variant

```bash
# Clone repository
git clone <repo-url>
cd DSSSL

# Build using wrapper script
./util/build-dsllvm-world.sh --clean --test --install --prefix=/opt/openssl-world

# Or manually:
./Configure dsllvm-world --prefix=/opt/openssl-world --openssldir=/opt/openssl-world/ssl
make -j$(nproc)
make test
sudo make install
```

### Build DSMIL (Optimized) Variant

```bash
# Build using wrapper script
./util/build-dsllvm-dsmil.sh --clean --test --install --prefix=/opt/openssl-dsmil

# Or manually:
./Configure dsllvm-dsmil --prefix=/opt/openssl-dsmil --openssldir=/opt/openssl-dsmil/ssl
make -j$(nproc)
make test
sudo make install
```

### Using a Security Profile

```bash
# Set profile via environment
export OPENSSL_CONF=/opt/openssl-dsmil/ssl/dsmil-secure.cnf
export THREATCON_LEVEL=NORMAL

# Or copy config to default location
sudo cp configs/dsmil-secure.cnf /opt/openssl-dsmil/ssl/openssl.cnf

# Test TLS connection
/opt/openssl-dsmil/bin/openssl s_client -connect example.com:443
```

## Documentation

- **[OPENSSL_SECURE_SPEC.md](OPENSSL_SECURE_SPEC.md)**: Complete security specification
- **[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)**: Phased implementation roadmap
- **[Configurations/10-dsllvm.conf](Configurations/10-dsllvm.conf)**: DSLLVM build targets

## Architecture

### Security Profiles

#### WORLD_COMPAT (Public Internet)

- **TLS**: 1.3 preferred, 1.2 allowed outbound
- **KEX**: X25519, P-256 (classical), ML-KEM opportunistic
- **Cipher**: AES-256-GCM, ChaCha20-Poly1305
- **Use Case**: Web servers, API endpoints, public services

Configuration: `configs/world.cnf`

#### DSMIL_SECURE (Internal/Allies)

- **TLS**: 1.3 only
- **KEX**: Hybrid mandatory (X25519+ML-KEM-768 or P-256+ML-KEM-768)
- **Cipher**: AES-256-GCM primary, ChaCha20-Poly1305 allowed
- **Signature**: Hybrid preferred (ECDSA+ML-DSA-65)
- **Use Case**: Internal services, trusted allies, DSMIL infrastructure

Configuration: `configs/dsmil-secure.cnf`

#### ATOMAL (Maximum Security)

- **TLS**: 1.3 only (strict)
- **KEX**: Hybrid-only or PQC-only (X25519+ML-KEM-1024, ML-KEM-1024)
- **Cipher**: AES-256-GCM only (ensures AES-NI)
- **Signature**: Hybrid or PQC-only (ECDSA+ML-DSA-87, ML-DSA-87)
- **Use Case**: Highest security internal comms, classified data

Configuration: `configs/atomal.cnf`

### Build Variants

#### dsllvm-world (Portable)

- **Target**: x86-64-v3 (AVX2, FMA, BMI)
- **Optimization**: `-O2` balanced
- **Portability**: Runs on most modern x86-64 CPUs
- **Security**: Stack protector, PIE, RELRO, FORTIFY_SOURCE
- **CSNA**: Constant-time checking enabled

#### dsllvm-dsmil (Meteorlake-Optimized)

- **Target**: Intel Meteor Lake
- **Optimization**: `-O3` aggressive, `-march=meteorlake`
- **Instructions**: AVX2, VAES, AVX-VNNI, AES-NI, PCLMULQDQ
- **Security**: Enhanced constant-time, side-channel alerts
- **CSNA**: Full CSNA 2.0 enforcement

## Directory Structure

```
DSSSL/
├── OPENSSL_SECURE_SPEC.md          # Security specification
├── IMPLEMENTATION_PLAN.md           # Implementation roadmap
├── DSMIL_README.md                  # This file
├── Configurations/
│   └── 10-dsllvm.conf              # DSLLVM build configurations
├── configs/
│   ├── world.cnf                   # WORLD_COMPAT profile config
│   ├── dsmil-secure.cnf           # DSMIL_SECURE profile config
│   └── atomal.cnf                  # ATOMAL profile config
├── providers/
│   └── dsmil/                      # DSMIL policy provider (Phase 2)
│       ├── dsmilprov.c
│       ├── policy.c
│       ├── policy.h
│       └── build.info
├── util/
│   ├── build-dsllvm-world.sh      # World build script
│   └── build-dsllvm-dsmil.sh      # DSMIL build script
├── crypto/
│   ├── ml_kem/                     # ML-KEM implementation
│   └── ml_dsa/                     # ML-DSA implementation
└── providers/implementations/
    ├── kem/ml_kem_kem.c           # ML-KEM KEM provider
    ├── signature/ml_dsa_sig.c     # ML-DSA signature provider
    └── kem/mlx_kem.c              # Hybrid KEM support
```

## Implementation Status

### ✅ Phase 1: Build System Foundation (COMPLETE)

- [x] DSLLVM build configurations (`Configurations/10-dsllvm.conf`)
- [x] Build wrapper scripts (`util/build-dsllvm-*.sh`)
- [x] Security profile configs (`configs/*.cnf`)
- [x] Build verification

### 🚧 Phase 2: DSMIL Policy Provider (SKELETON COMPLETE)

- [x] Provider skeleton (`providers/dsmil/dsmilprov.c`)
- [x] Basic policy logic (`providers/dsmil/policy.c`)
- [ ] Property query interception (TODO)
- [ ] SNI/IP-based profile selection (TODO)
- [ ] Full algorithm filtering (TODO)

### 📋 Phase 3: Event Telemetry (PLANNED)

- [ ] Event infrastructure (`providers/dsmil/events.c`)
- [ ] Unix socket event emission
- [ ] CBOR/JSON event formatting
- [ ] DEFRAMEWORK integration

### 📋 Phase 4-9: See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)

## Development

### DSLLVM Fallback

For development without DSLLVM, create symlinks to standard clang:

```bash
sudo ln -s $(which clang) /usr/local/bin/dsclang
sudo ln -s $(which clang++) /usr/local/bin/dsclang++
```

**Note**: Production DSMIL builds require real DSLLVM with CSNA 2.0 support.

### Testing

```bash
# Run OpenSSL test suite
make test

# Test specific profile
export OPENSSL_CONF=./configs/dsmil-secure.cnf
export DSMIL_PROFILE=DSMIL_SECURE
./apps/openssl version -a

# Test TLS 1.3 with PQC
./apps/openssl s_server -accept 4433 -www &
./apps/openssl s_client -connect localhost:4433
```

### Debugging

```bash
# Enable debug build
./Configure dsllvm-dsmil-debug --prefix=/opt/openssl-dsmil-debug
make -j$(nproc)

# Run with verbose output
OPENSSL_DEBUG=1 ./apps/openssl ...
```

## Security Considerations

### Threat Model

See [OPENSSL_SECURE_SPEC.md Section 2](OPENSSL_SECURE_SPEC.md#2-threat-model--goals)

- Passive/active network adversaries
- Protocol downgrade attacks
- Timing/side-channel attacks
- Future quantum adversaries

### Side-Channel Mitigations

- Constant-time primitives (ML-KEM, ML-DSA)
- DSLLVM CSNA 2.0 enforcement
- Hardware AES-NI (constant-time, fast)
- Timing variance testing (Phase 6)

### Known Limitations

1. **DSMIL Policy Provider**: Skeleton only, full enforcement in Phase 2
2. **Event Telemetry**: Not yet implemented (Phase 3)
3. **TPM Integration**: Not yet implemented (Phase 7)
4. **DSLLVM**: Fallback to clang for development (production needs DSLLVM)

## Configuration

### THREATCON Levels

Set via environment:

```bash
export THREATCON_LEVEL=NORMAL     # Standard operation
export THREATCON_LEVEL=ELEVATED   # Increased vigilance
export THREATCON_LEVEL=HIGH       # High threat, enhanced security
export THREATCON_LEVEL=SEVERE     # Maximum security
```

Interpretation varies by profile (see config files).

### Profile Selection

Via configuration file:

```bash
export OPENSSL_CONF=/path/to/profile.cnf
```

Via environment (requires policy provider):

```bash
export DSMIL_PROFILE=WORLD_COMPAT  # or DSMIL_SECURE, ATOMAL
```

### Algorithm Configuration

Edit profile config files (`configs/*.cnf`) to adjust:

- Cipher suites
- Key exchange groups
- Signature algorithms
- TLS versions
- Security levels

## Integration

### DEFRAMEWORK (Phase 3)

Event socket: `/run/crypto-events.sock`

Event format: JSON (CBOR optional)

Event types:
- `handshake_start`, `handshake_complete`, `handshake_failed`
- `policy_violation`, `downgrade_detected`
- `algorithm_negotiated`, `key_operation`

### TPM2 (Phase 7)

Key storage:
- Long-term keys sealed in TPM
- Session keys in memory (securely zeroed)

Provider: `pkcs11-provider` (submodule)

## Performance

### Benchmarks (Estimated)

| Profile | Handshake | Throughput | Notes |
|---------|-----------|------------|-------|
| WORLD_COMPAT (classical) | 1.0x | 1.0x | Baseline |
| WORLD_COMPAT (hybrid) | 1.2x | 1.0x | ML-KEM-768 |
| DSMIL_SECURE | 1.3x | 1.0x | Hybrid mandatory |
| ATOMAL | 2.5x | 1.0x | ML-KEM-1024 + ML-DSA-87 |

Throughput (bulk encryption) largely unaffected; handshake overhead only.

## Troubleshooting

### Build Fails

```bash
# Check compiler
dsclang --version

# Check dependencies
perl -v
make --version

# Clean and retry
make distclean
./util/build-dsllvm-world.sh --clean
```

### Tests Fail

```bash
# Run specific test
make test TESTS=test_tls13

# Verbose mode
make VERBOSE=1 test
```

### Policy Provider Not Loading

```bash
# Check config
grep -A5 "dsmil-policy" /path/to/openssl.cnf

# Check provider exists
ls providers/dsmil/

# Build provider
cd providers/dsmil && make
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

This is a DSMIL security project - all changes undergo security review.

## License

See [LICENSE.txt](LICENSE.txt). Based on OpenSSL, licensed under Apache 2.0.

## Support

- Documentation: See docs in this repo
- Issues: GitHub Issues (for DSMIL-specific code)
- Upstream OpenSSL: https://www.openssl.org/support/

## References

- [OpenSSL 3.x Documentation](https://www.openssl.org/docs/man3.0/)
- [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ML-KEM (FIPS 203)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [ML-DSA (FIPS 204)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)

## Version History

- **v0.1.0** (2025-11-25): Initial implementation
  - Phase 1 complete: Build system, configs, scripts
  - Phase 2 skeleton: Policy provider structure
  - Baseline functionality: Classical + ML-KEM + ML-DSA

---

*DSMIL Security Team • 2025*
