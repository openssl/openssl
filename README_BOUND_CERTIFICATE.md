**Bound Certificate Implementation for OpenSSL**


This project implements the "bound certificate" approach as defined in [RFC 9763](https://datatracker.ietf.org/doc/html/rfc9763) for the OpenSSL cryptographic library. The implementation provides support for the `relatedCertRequest` attribute in Certificate Signing Requests (CSRs) and the `RelatedCertificate` extension in X.509 certificates.

**Table of Contents**


 - [Overview](#overview)
 - [Features](#features)
 - [ASN.1 Structures](#asn1-structures)
 - [Building and Testing](#building-and-testing)
 - [Test Script](#test-script)
 


**Overview**


RFC 9763 defines a mechanism to bind certificates together, allowing one certificate to reference another certificate through cryptographic means. This is particularly useful for:

- Certificate chaining and relationship verification
- Cross-certification scenarios
- Certificate binding in multi-certificate environments
- Post-quantum cryptography certificate binding

The implementation provides a complete solution for creating and verifying bound certificates according to the RFC 9763 specification.

**Features**


**Implemented Components**


1. **relatedCertRequest Attribute** (`id-aa-relatedCertRequest`)
   - Added to Certificate Signing Requests (CSRs)
   - Contains requester certificate information
   - Includes timestamp and location information
   - Digitally signed for integrity

2. **RelatedCertificate Extension** (`id-pe-relatedCert`)
   - Added to X.509 certificates
   - Contains hash of the related certificate
   - Supports multiple hash algorithms (SHA-256, SHA-512, etc.)


**Building and Testing**


**Prerequisites**


- OpenSSL 3.3.4 or later
- Make
- liboqs
- oqs provider

**Build Options**


```bash
git clone -b bound-openssl-3.3 https://github.com/wibs2401/opensslForPQCert.git
cd opensslForPQCert
./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl
make -j$(nproc)
sudo make install
```

**Testing Process**

This section describes how to test the RFC 9763 implementation using OpenSSL 3.3.4 with OQS (Open Quantum Safe) support.

### Prerequisites

- OpenSSL 3.3.4 with OQS provider enabled
- Working directory for test certificates

### Test Setup

```bash
# Create a working directory
mkdir -p test_bound_certs
cd test_bound_certs
```

### Step 1: Generate CA Infrastructure

```bash
cccc

```

### Step 2: Generate Bound Certificate for server (RSA)

```bash
# Generate bound certificate private key (RSA)
openssl genpkey -algorithm RSA -out server_rsa_key.pem

# Create bound certificate request
openssl req -new -key server_rsa_key.pem -out server_rsa_req.pem \
  -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com"


# Sign bound certificate
openssl x509 -req -in server_rsa_req.pem \
  -CA ca_rsa.pem -CAkey ca_rsa_key.pem -CAcreateserial \
  -out server_rsa_cert.pem -days 365

```

### Step 3: Generate New Certificate (Mldsa65)

```bash
# Generate new certificate private key (Mldsa65)
openssl genpkey -algorithm mldsa65 -out server_mldsa65_key.pem


# Create CSR with relatedCertRequest attribute
openssl req -new \
  -key server_mldsa65_key.pem \
  -out server_mldsa65_bound_req.pem \
  -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com" \
  -add_related_cert server_rsa_cert.pem \
  -related_uri "file://$(pwd)/server_rsa_cert.pem"

# Sign the CSR to create the new certificate
openssl x509 -req -in server_mldsa65_bound_req.pem \
  -CA ca_mldsa65_cert.pem -CAkey ca_mldsa65_key.pem -CAcreateserial \
  -out server_mldsa65_bound_cert.pem -days 365

```

### Step 4: Verification

```bash
# Verify the CSR with relatedCertRequest attribute
openssl req -in server_mldsa65_bound_req.pem -text -noout

# Check the relatedCertRequest attribute specifically
openssl req -in server_mldsa65_bound_req.pem -text -noout | grep -A 20 "relatedCertRequest"

# Verify the final certificate
openssl x509 -in server_mldsa65_bound_cert.pem -text -noout

# Check the RelatedCertificate extension
openssl x509 -in server_mldsa65_bound_cert.pem -text -noout | grep -A 20 "Bound certificate extension"

# Verify the signature of the relatedCertRequest attribute
openssl req -in server_mldsa65_bound_req.pem -verify -noout
```


### Step 5: TLS Handshake Testing

#### 5.1 Starting the OpenSSL Server

```bash
# Start the TLS server with the generated certificates
openssl s_server \
  -cert server_rsa_cert.pem -key server_rsa_key.pem \
  -pqcert server_mldsa65_bound_cert.pem -pqkey server_mldsa65_key.pem \
  -CAfile ca_rsa.pem -pqcafile ca_mldsa65_cert.pem \
  -enable_dual_certs \
  -msg -debug

```

#### 5.2 Connecting the OpenSSL Client

```bash
# In another terminal, connect a TLS client
openssl s_client -connect localhost:4433 -CAfile ca_cert.pem -pqcafile ca_mldsa65_cert.pem -msg
```


### Step 6: Results Analysis

#### 6.1 Expected TLS Messages

The TLS 1.3 handshake should proceed as follows:

1. **ClientHello** → **ServerHello**
2. **EncryptedExtensions**
3. **Certificate** (contains the RelatedCertificate extension)
4. **CertificateVerify**
5. **PQCertificateVerify**
6. **Finished** (successful exchange)






