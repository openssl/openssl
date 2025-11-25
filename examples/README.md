# DSMIL OpenSSL Examples

This directory contains example programs demonstrating DSMIL OpenSSL features.

## Building Examples

```bash
make

# Or specify OpenSSL location
make OPENSSL_PREFIX=/opt/openssl-dsmil
```

## Examples

### 1. check-pqc

**Purpose:** Check for PQC algorithm availability

**Files:** `check-pqc.c`

**Usage:**
```bash
./check-pqc
```

**Output:**
```
========================================
DSMIL PQC Algorithm Checker
========================================

ML-KEM (Key Encapsulation):
  ✓ ML-KEM-512 (KEM)
  ✓ ML-KEM-768 (KEM)
  ✓ ML-KEM-1024 (KEM)

ML-DSA (Digital Signatures):
  ✓ ML-DSA-44 (Signature)
  ✓ ML-DSA-65 (Signature)
  ✓ ML-DSA-87 (Signature)
```

### 2. dsmil-client

**Purpose:** TLS client with profile support

**Files:** `dsmil-client.c`

**Usage:**
```bash
# With WORLD_COMPAT profile (public internet)
export OPENSSL_CONF=../configs/world.cnf
./dsmil-client google.com 443

# With DSMIL_SECURE profile (internal)
export OPENSSL_CONF=../configs/dsmil-secure.cnf
export THREATCON_LEVEL=NORMAL
./dsmil-client internal-server.local 443

# With ATOMAL profile (maximum security)
export OPENSSL_CONF=../configs/atomal.cnf
export THREATCON_LEVEL=HIGH
./dsmil-client high-security-server.local 443
```

**Features:**
- Displays security profile in use
- Shows TLS version and cipher
- Detects hybrid vs classical crypto
- Identifies PQC certificates
- Color-coded output

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
  ✓ Hybrid/PQC Key Exchange Detected
  Server:   CN=google.com

✓ Connection closed successfully
```

### 3. dsmil-server (Future)

**Purpose:** TLS server example

**Status:** Planned for Phase 5

**Planned features:**
- Hybrid crypto server
- Profile enforcement
- Event logging
- Client certificate validation

## Compiling Without Make

### check-pqc

```bash
gcc -o check-pqc check-pqc.c \
    -I/opt/openssl-dsmil/include \
    -L/opt/openssl-dsmil/lib64 \
    -lssl -lcrypto \
    -Wl,-rpath,/opt/openssl-dsmil/lib64
```

### dsmil-client

```bash
gcc -o dsmil-client dsmil-client.c \
    -I/opt/openssl-dsmil/include \
    -L/opt/openssl-dsmil/lib64 \
    -lssl -lcrypto \
    -Wl,-rpath,/opt/openssl-dsmil/lib64
```

## Security Profiles

### WORLD_COMPAT

**Use case:** Public internet, backwards compatible

**Config:** `../configs/world.cnf`

**Features:**
- TLS 1.3 preferred
- Classical crypto baseline
- Opportunistic PQC

**Example:**
```bash
export OPENSSL_CONF=../configs/world.cnf
./dsmil-client public-website.com 443
```

### DSMIL_SECURE

**Use case:** Internal services, trusted allies

**Config:** `../configs/dsmil-secure.cnf`

**Features:**
- TLS 1.3 only
- Hybrid KEX mandatory
- Event telemetry
- THREATCON integration

**Example:**
```bash
export OPENSSL_CONF=../configs/dsmil-secure.cnf
export THREATCON_LEVEL=NORMAL
./dsmil-client internal-api.local 443
```

### ATOMAL

**Use case:** Maximum security, classified data

**Config:** `../configs/atomal.cnf`

**Features:**
- TLS 1.3 strict
- PQC/hybrid only
- ML-KEM-1024 + ML-DSA-87
- Hardware RNG only
- Constant-time enforcement

**Example:**
```bash
export OPENSSL_CONF=../configs/atomal.cnf
export THREATCON_LEVEL=HIGH
./dsmil-client classified-server.local 443
```

## THREATCON Levels

Set via environment:

```bash
export THREATCON_LEVEL=NORMAL     # Standard operation
export THREATCON_LEVEL=ELEVATED   # Increased vigilance
export THREATCON_LEVEL=HIGH       # High threat
export THREATCON_LEVEL=SEVERE     # Maximum security
```

Effect varies by profile (see config files).

## Troubleshooting

### Compiler Error: openssl/ssl.h not found

**Solution:**
```bash
# Check OpenSSL installation
ls /opt/openssl-dsmil/include/openssl/ssl.h

# Specify prefix
make OPENSSL_PREFIX=/opt/openssl-dsmil
```

### Runtime Error: libssl.so not found

**Solution:**
```bash
# Add to LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/opt/openssl-dsmil/lib64:$LD_LIBRARY_PATH

# Or rebuild with rpath (make does this automatically)
gcc ... -Wl,-rpath,/opt/openssl-dsmil/lib64
```

### TLS Handshake Failed

**Possible causes:**

1. **Profile mismatch**
   - DSMIL_SECURE/ATOMAL require hybrid crypto
   - Server may not support PQC
   - Solution: Use WORLD_COMPAT for public servers

2. **THREATCON too high**
   - Higher levels = stricter policy
   - Solution: Lower THREATCON or use appropriate profile

3. **Certificate issues**
   - Missing CA certificates
   - Solution: Check `/etc/ssl/certs/`

## Example Code Snippets

### Basic TLS Client

```c
SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

SSL *ssl = SSL_new(ctx);
SSL_set_fd(ssl, sockfd);
SSL_set_tlsext_host_name(ssl, hostname);

if (SSL_connect(ssl) == 1) {
    printf("Connected!\n");
}
```

### Check Cipher Suite

```c
const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
const char *cipher_name = SSL_CIPHER_get_name(cipher);

if (strstr(cipher_name, "ML-KEM") != NULL) {
    printf("Hybrid/PQC key exchange\n");
}
```

### Get Certificate Info

```c
X509 *cert = SSL_get_peer_certificate(ssl);
if (cert != NULL) {
    char subject[256];
    X509_NAME_oneline(X509_get_subject_name(cert),
                      subject, sizeof(subject));
    printf("Server: %s\n", subject);
    X509_free(cert);
}
```

## Performance Notes

### Handshake Overhead

| Profile | Handshake Time | Notes |
|---------|----------------|-------|
| WORLD (classical) | 1.0x | Baseline |
| WORLD (hybrid) | ~1.2x | ML-KEM-768 |
| DSMIL_SECURE | ~1.3x | Hybrid mandatory |
| ATOMAL | ~2.5x | ML-KEM-1024 + ML-DSA-87 |

### Optimization Tips

1. **Connection reuse** - Amortize handshake cost
2. **Session resumption** - Use TLS 1.3 session tickets
3. **Hardware crypto** - Ensure AES-NI enabled

## Development

### Adding New Examples

1. Create `example-name.c`
2. Add to `Makefile`:
   ```make
   EXAMPLES = ... example-name

   example-name: example-name.c
       $(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
   ```
3. Update this README

### Code Style

- Follow OpenSSL example style
- Add color output for better UX
- Include error handling
- Document usage in comments

## References

- [DSMIL_README.md](../DSMIL_README.md) - Main documentation
- [OPENSSL_SECURE_SPEC.md](../OPENSSL_SECURE_SPEC.md) - Specification
- [docs/TESTING.md](../docs/TESTING.md) - Testing guide
- [OpenSSL Manual](https://www.openssl.org/docs/man3.0/)

---

*DSMIL Security Team • 2025*
