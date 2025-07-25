**Dual Certificate Implementation for OpenSSL**


This project implements the "dual certificate" approach as defined in [IETF draft-yusef-tls-pqt-dual-certs](https://datatracker.ietf.org/doc/draft-yusef-tls-pqt-dual-certs/) for the OpenSSL cryptographic library. The implementation provides support for dual certificates with classic and post-quantum cryptography (PQC) chains in TLS handshakes.

**Table of Contents**


 - [Overview](#overview)
 - [Features](#features)
 - [ASN.1 Structures](#asn1-structures)
 - [Building and Testing](#building-and-testing)
 - [Test Script](#test-script)
 - [TLS Handshake Testing](#tls-handshake-testing)
 - [OID Registration](#oid-registration)


**Overview**


The IETF draft defines a mechanism to use dual certificates in TLS handshakes, allowing one certificate chain for classic cryptography and another for post-quantum cryptography. This is particularly useful for:

- Post-quantum cryptography migration
- Hybrid security approaches
- Backward compatibility with classic cryptography
- Future-proofing TLS connections

The implementation provides a complete solution for creating and using dual certificates according to the draft specification.

**Features**


**Implemented Components**


1. **Dual Certificate Structure** (`CERT`)
   - Added to SSL_CONNECTION structure
   - Contains classic and PQC certificate chains
   - Includes dual certificate enablement flag
   - Supports separate key management

2. **TLS Dual Signature Algorithms Extension** (`TLSEXT_TYPE_dual_signature_algorithms`)
   - Added to TLS handshake messages
   - Contains two signature algorithm lists (classic + PQC)
   - Supports all major PQC algorithms
   - Format compliant with draft specification


**Building and Testing**


**Prerequisites**


- OpenSSL 3.3.4 or later
- Make
- liboqs (for PQC algorithms)
- oqs provider

**Build Options**


```bash
git clone -b DUAL_Chain_approach https://github.com/wibs2401/opensslForPQCert.git
cd opensslForPQCert
./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl
make -j$(nproc)
sudo make install
```

**Test Program**


**Testing Process**

This section describes how to test the dual certificate implementation using OpenSSL 3.3.4 with OQS (Open Quantum Safe) support.

### Prerequisites

- OpenSSL 3.3.4 with OQS provider enabled
- Working directory for test certificates

### Test Setup

```bash
# Create a working directory
mkdir -p test_dual_certs
cd test_dual_certs
```

### Step 1: Generate CA Infrastructure

```bash
# Generate classic CA private key (RSA)
openssl genpkey -algorithm RSA -out ca_rsa_key.pem 

# Generate PQC CA private key ()
openssl genpkey -algorithm mldsa65 -out ca_mldsa65_key.pem

# Create classic CA certificate    
openssl-oqs req -new -x509 -key ca_rsa_key.pem \
-out ca_rsa.pem -days 365 \
-subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=TestClassicCA"

# Create PQC CA certificate
openssl-oqs req -new -x509 -key ca_mldsa65_key.pem \
-out ca_mldsa65_cert.pem -days 365 \
-subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=TestPQCA"
```

### Step 2: Generate Dual Certificates

```bash
# Generate classic certificate private key (RSA)
openssl genpkey -algorithm RSA -out server_rsa_key.pem

# Create classic certificate request
openssl req -new -key server_rsa_key.pem \
-out server_rsa_req.pem \
-subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com"

# Sign classic certificate
openssl x509 -req -in server_rsa_req.pem \
-CA ca_rsa.pem -CAkey ca_rsa_key.pem -CAcreateserial \
-out server_rsa_cert.pem -days 365
    
# Generate PQC certificate private key (mldsa65)
openssl genpkey -algorithm mldsa65 -out server_mldsa65_key.pem

# Create PQC certificate request
openssl req -new -key server_mldsa65_key.pem \
-out server_mldsa65_req.pem \
-subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com"

# Sign PQC certificate
openssl x509 -req -in server_mldsa65_req.pem \
-CA ca_mldsa65_cert.pem -CAkey ca_mldsa65_key.pem -CAcreateserial \
-out server_mldsa65_cert.pem -days 365

```

### Step 3: Test Dual Certificate Usage

```bash
# Test dual certificate validation
openssl s_server -cert server_classic_cert.pem -key server_classic_key.pem \
    -pqcert server_pq_cert.pem -pqkey server_pq_key.pem -pqcafile ca_pq_cert.pem  -enable_dual_certs \
    -accept 4433 -www

# In another terminal, test client connection
openssl s_client -connect localhost:4433 -CAfile ca_classic_cert.pem \
    -pqcafile ca_pq_cert.pem -enable_dual_certs
```

### Step 4: Verification

```bash
# Verify classic certificate
openssl x509 -in server_classic_cert.pem -text -noout

# Verify PQC certificate
openssl x509 -in server_pq_cert.pem -text -noout

# Check dual certificate configuration
openssl s_client -connect localhost:4433 -CAfile ca_classic_cert.pem \
    -pqcafile ca_pq_cert.pem -enable_dual_certs -msg
```

### Step 2: TLS Handshake Testing

#### 2.1 Starting the OpenSSL Server

```bash
# Start the TLS server with dual certificates
openssl s_server \
  -cert server_rsa_cert.pem \
  -key server_rsa_key.pem \
  -pqcert server_mldsa65_cert.pem \
  -pqkey server_mldsa65_key.pem \
  -CAfile ca_rsa.pem \
  -pqcafile ca_mldsa65_cert.pem \
  -enable_dual_certs \
  -msg -debug

```

Options used:
- `-cert server_rsa_cert.pem` : Classic server certificate
- `-key server_rsa_key.pem` : Classic server private key
- `-pqcert server_mldsa65_cert.pem` : PQC server certificate
- `-pqkey server_mldsa65_key.pem` : PQC server private key
- `-enable_dual_certs` : Enable dual certificate mode
- `-CAfile ca_rsa.pem` : Classic CA certificate for validation
- `-pqcafile ca_mldsa65_cert.pem` : PQC CA certificate for validation

#### 2.2 Connecting the OpenSSL Client

```bash
# In another terminal, connect a TLS client
openssl s_client -connect localhost:4433 \
  -CAfile ca_rsa.pem \
  -pqcafile ca_mldsa65_cert.pem \
  -msg -debug

```

Options used:
- `-connect localhost:4433` : Connect to local server
- `-CAfile ca_rsa.pem` : Classic CA certificate for validation
- `-pqcafile ca_mldsa65_cert.pem` : PQC CA certificate for validation
- `-enable_dual_certs` : Enable dual certificate mode
- `-msg` : Display detailed TLS messages

### Step 3: Results Analysis

#### 3.1 Expected TLS Messages

The TLS 1.3 handshake should proceed as follows:

1. **ClientHello** → **ServerHello**
2. **EncryptedExtensions**
3. **Certificate** (contains both classic and PQC certificate chains)
4. **CertificateVerify** (contains classic signature)
5. **PQCertificateVerify** (contains PQC signature)
6. **Finished** (successful exchange)




