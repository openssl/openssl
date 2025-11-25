# Hybrid Cryptography in DSMIL OpenSSL

This document describes hybrid post-quantum cryptography support in DSMIL OpenSSL.

## Overview

Hybrid cryptography combines classical and post-quantum algorithms to provide:
- **Immediate PQC protection** against future quantum attacks
- **Backwards compatibility** with classical-only systems
- **Defense in depth** - security holds if either component is secure

## Hybrid Key Exchange (KEM)

### Supported Hybrid KEMs

| Hybrid KEM | Classical | PQC | Security Level | Profile |
|------------|-----------|-----|----------------|---------|
| X25519+ML-KEM-768 | X25519 | ML-KEM-768 | ~192-bit | DSMIL_SECURE |
| P-256+ML-KEM-768 | P-256 (secp256r1) | ML-KEM-768 | ~192-bit | DSMIL_SECURE |
| X25519+ML-KEM-1024 | X25519 | ML-KEM-1024 | ~256-bit | ATOMAL |
| P-256+ML-KEM-1024 | P-256 | ML-KEM-1024 | ~256-bit | ATOMAL |

### How Hybrid KEM Works

1. **Key Generation**: Generate both classical and PQC keypairs
2. **Encapsulation**:
   - Encapsulate with classical KEM (ECDH)
   - Encapsulate with PQC KEM (ML-KEM)
   - Combine shared secrets via HKDF
3. **Decapsulation**:
   - Decapsulate both components
   - Derive combined shared secret

### TLS 1.3 Named Groups

Hybrid KEMs appear as named groups in TLS 1.3:

```
Groups = X25519+MLKEM768:P-256+MLKEM768:X25519+MLKEM1024
```

### Configuration

**WORLD_COMPAT**: Classical preferred, hybrid offered
```ini
Groups = X25519:P-256
# Hybrid groups offered if PQC provider loaded
```

**DSMIL_SECURE**: Hybrid mandatory
```ini
Groups = X25519+MLKEM768:P-256+MLKEM768:X25519:P-256
require_hybrid_kex = true
```

**ATOMAL**: ML-KEM-1024 preferred
```ini
Groups = X25519+MLKEM1024:MLKEM1024
```

## Hybrid Signatures

### Supported Hybrid Signatures

| Hybrid Signature | Classical | PQC | Security Level | Profile |
|------------------|-----------|-----|----------------|---------|
| ECDSA-P256+ML-DSA-65 | ECDSA P-256 | ML-DSA-65 | ~192-bit | DSMIL_SECURE |
| Ed25519+ML-DSA-65 | Ed25519 | ML-DSA-65 | ~192-bit | DSMIL_SECURE |
| ECDSA-P256+ML-DSA-87 | ECDSA P-256 | ML-DSA-87 | ~256-bit | ATOMAL |
| Ed25519+ML-DSA-87 | Ed25519 | ML-DSA-87 | ~256-bit | ATOMAL |

### Hybrid Signature Approaches

#### 1. Dual Certificates (Recommended)

Two separate certificates presented in parallel:
- Classical certificate (ECDSA or Ed25519)
- PQC certificate (ML-DSA)

Both must validate for DSMIL_SECURE/ATOMAL profiles.

**Advantages**:
- Backwards compatible
- Clear separation
- Easy to implement

**Disadvantages**:
- Larger handshake
- Two certificate chains

#### 2. Composite Signatures (Future)

Single certificate with composite public key and signature.

**Status**: RFC draft, not yet standardized

### Configuration

**WORLD_COMPAT**: Classical signatures only
```ini
SignatureAlgorithms = ECDSA+SHA256:ed25519
```

**DSMIL_SECURE**: Hybrid preferred
```ini
SignatureAlgorithms = ECDSA+SHA256+MLDSA65:ed25519+MLDSA65:ECDSA+SHA256:ed25519
```

**ATOMAL**: ML-DSA-87 required
```ini
SignatureAlgorithms = ECDSA+SHA256+MLDSA87:MLDSA87
```

## Hybrid Secret Derivation

### HKDF-based Combination

Hybrid shared secrets are combined using HKDF:

```
shared_secret = HKDF-Expand(
    HKDF-Extract(
        salt=NULL,
        IKM=classical_secret || pqc_secret
    ),
    info="hybrid-kem" || classical_name || pqc_name,
    L=32
)
```

**Labels**:
- `"hybrid-kem"` - Base label
- Classical algorithm name (e.g., `"X25519"`)
- PQC algorithm name (e.g., `"ML-KEM-768"`)

**Properties**:
- Security holds if *either* component is secure
- Quantum-safe (via ML-KEM)
- Backwards compatible (via classical)

## Implementation Details

### Hybrid KEM Provider

**File**: `providers/implementations/kem/mlx_kem.c`

**Key Functions**:
- `ossl_mlx_kem_newctx()` - Create hybrid KEM context
- `ossl_mlx_kem_encapsulate()` - Hybrid encapsulation
- `ossl_mlx_kem_decapsulate()` - Hybrid decapsulation

**Supported Combinations**:
- X25519 + ML-KEM-512/768/1024
- P-256 + ML-KEM-512/768/1024

### Key Generation Example

```c
#include <openssl/evp.h>

/* Generate hybrid keypair */
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519+MLKEM768", NULL);
EVP_PKEY *pkey = NULL;

if (EVP_PKEY_keygen_init(ctx) > 0 &&
    EVP_PKEY_keygen(ctx, &pkey) > 0) {
    printf("Generated hybrid keypair\n");
}

EVP_PKEY_free(pkey);
EVP_PKEY_CTX_free(ctx);
```

### Encapsulation Example

```c
/* Encapsulate with hybrid KEM */
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(peer_pubkey, NULL);
unsigned char *ciphertext = NULL;
size_t ctlen = 0;
unsigned char shared_secret[32];
size_t sslen = sizeof(shared_secret);

if (EVP_PKEY_encapsulate_init(ctx, NULL) > 0 &&
    EVP_PKEY_encapsulate(ctx, NULL, &ctlen, shared_secret, &sslen) > 0) {
    ciphertext = OPENSSL_malloc(ctlen);
    if (EVP_PKEY_encapsulate(ctx, ciphertext, &ctlen, shared_secret, &sslen) > 0) {
        printf("Encapsulation successful\n");
        /* Use shared_secret for key derivation */
    }
}
```

## Testing Hybrid Crypto

### Check Hybrid Support

```bash
# Use check-pqc example
./examples/check-pqc

# Expected output includes:
# Hybrid Support:
#   X25519+ML-KEM-768 (expected)
#   P-256+ML-KEM-768 (expected)
```

### Test Hybrid TLS Connection

```bash
# Server with hybrid support
openssl s_server -accept 4433 \
    -cert server.crt -key server.key \
    -groups X25519+MLKEM768:P-256+MLKEM768

# Client forcing hybrid
openssl s_client -connect localhost:4433 \
    -groups X25519+MLKEM768
```

### Verify Hybrid Negotiation

```bash
# Use dsmil-client example
export OPENSSL_CONF=configs/dsmil-secure.cnf
./examples/dsmil-client localhost 4433

# Output should show:
#   ✓ Hybrid/PQC Key Exchange Detected
```

## Performance Considerations

### Handshake Overhead

| Configuration | Relative Performance | Notes |
|---------------|---------------------|-------|
| Classical only | 1.0x (baseline) | X25519 or P-256 |
| Hybrid X25519+ML-KEM-768 | ~1.2x | +200 bytes ciphertext |
| Hybrid X25519+ML-KEM-1024 | ~2.5x | +300 bytes ciphertext |

**Breakdown**:
- Classical ECDH: ~50 μs
- ML-KEM-768 encap: ~80 μs
- ML-KEM-1024 encap: ~120 μs
- HKDF combination: ~5 μs

### Size Overhead

| Component | Classical | Hybrid (ML-KEM-768) | Hybrid (ML-KEM-1024) |
|-----------|-----------|---------------------|----------------------|
| Public key | 32 bytes | ~1216 bytes | ~1600 bytes |
| Ciphertext | 32 bytes | ~1120 bytes | ~1568 bytes |
| Shared secret | 32 bytes | 32 bytes | 32 bytes |

**Mitigation**:
- Use connection reuse/session resumption
- ML-KEM-768 sufficient for most use cases
- ML-KEM-1024 only for ATOMAL profile

### Optimization Tips

1. **Connection Pooling**: Amortize handshake cost
2. **Session Resumption**: Use TLS 1.3 0-RTT when appropriate
3. **Hardware Acceleration**: Use AES-NI for HKDF
4. **Right-Sizing**: Use ML-KEM-768 unless ATOMAL required

## Security Considerations

### Threat Model

**Protected Against**:
- ✅ Quantum computer attacks (via ML-KEM)
- ✅ Classical attacks (via ECDH)
- ✅ Harvest-now-decrypt-later
- ✅ Future breaks of either component

**Not Protected Against**:
- ❌ Simultaneous break of both components (unlikely)
- ❌ Implementation bugs in crypto code
- ❌ Side-channel attacks (mitigated by constant-time)

### Security Levels

**Hybrid Security Property**:
> The hybrid construction is at least as secure as the stronger of the two components.

**Quantum Security**:
- ML-KEM-768: NIST Level 3 (equivalent to AES-192)
- ML-KEM-1024: NIST Level 5 (equivalent to AES-256)

**Classical Security**:
- X25519: ~128-bit
- P-256: ~128-bit

**Combined Security**:
- X25519+ML-KEM-768: max(128, 192) = 192-bit equivalent
- X25519+ML-KEM-1024: max(128, 256) = 256-bit equivalent

### Best Practices

1. **Always use hybrid in production**
   - Provides quantum safety
   - Maintains classical security
   - No significant performance cost

2. **Prefer X25519 over P-256**
   - Faster
   - Simpler implementation
   - Less side-channel risk

3. **Use ML-KEM-1024 for highest security**
   - ATOMAL profile
   - Classified data
   - Long-term secrets (>10 years)

4. **Monitor for downgrade attacks**
   - Policy provider logs classical-only connections
   - DSMIL_SECURE/ATOMAL reject classical-only

5. **Keep certificates updated**
   - Rotate regularly
   - Monitor PQC algorithm lifecycle
   - Prepare for algorithm agility

## Migration Path

### Phase 1: Opportunistic (WORLD_COMPAT)
- Classical baseline
- Hybrid offered if available
- Log hybrid usage

### Phase 2: Hybrid Preferred (DSMIL_SECURE)
- Hybrid required for internal
- Classical allowed for internet
- Downgrade logged

### Phase 3: Hybrid Mandatory (ATOMAL)
- Only hybrid or PQC-only
- No classical allowed
- Perimeter gateways handle conversion

### Timeline

| Date | Milestone |
|------|-----------|
| 2025 | WORLD_COMPAT deployed |
| 2026 | DSMIL_SECURE for internal |
| 2027 | ATOMAL for classified |
| 2030+ | PQC-only consideration |

## Troubleshooting

### Hybrid Handshake Fails

**Symptoms**: TLS handshake fails with DSMIL_SECURE profile

**Causes**:
1. Server doesn't support hybrid KEX
2. PQC provider not loaded
3. Incompatible group configuration

**Solutions**:
```bash
# Check server support
openssl s_client -connect server:443 -showcerts

# Verify PQC provider loaded
./examples/check-pqc

# Try with explicit group
openssl s_client -connect server:443 -groups X25519+MLKEM768
```

### Performance Too Slow

**Symptoms**: Handshakes take >500ms

**Solutions**:
1. Use ML-KEM-768 instead of 1024
2. Enable session resumption
3. Check for software fallback (no AES-NI)
4. Consider connection pooling

### Compatibility Issues

**Symptoms**: Can't connect to public servers with DSMIL_SECURE

**Expected**: Public servers don't support PQC yet

**Solution**: Use WORLD_COMPAT profile for public internet

## References

- [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ML-KEM (FIPS 203)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [ML-DSA (FIPS 204)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [Hybrid KEX RFC Draft](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)
- [doc/designs/ML-KEM.md](../doc/designs/ML-KEM.md)
- [providers/implementations/kem/mlx_kem.c](../providers/implementations/kem/mlx_kem.c)

---

*Last updated: 2025-11-25*
*DSMIL Security Team*
