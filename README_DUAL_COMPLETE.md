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

**Key Functions**


- `SSL_CTX_enable_dual_certs()` - Enable dual certificate mode
- `SSL_CTX_set_pq_certificate()` - Set PQC certificate and chain
- `validate_dual_certificates()` - Validate dual certificates
- `verify_pqc_signature_enhanced()` - Verify PQC signatures
- `handle_dual_cert_error()` - Handle dual certificate errors
- `print_dual_cert_info()` - Print dual certificate information
- `get_pq_certificate_chain()` - Get PQC certificate chain
- `set_dual_signature_algorithms()` - Set dual signature algorithms

**ASN.1 Structures**


The implementation defines the following ASN.1 structures according to the draft:

```asn.1
DualSignatureAlgorithms ::= SEQUENCE {
    first_signature_algorithms    SignatureSchemeList,  -- Classic algorithms
    second_signature_algorithms   SignatureSchemeList   -- PQC algorithms
}

CertificateMessage ::= SEQUENCE {
    certificate_request_context   [0] CertificateRequestContext OPTIONAL,
    certificates                  SEQUENCE OF CertificateEntry,
    delimiter                     [1] OCTET STRING OPTIONAL,  -- 0x00 0x00 0x00
    pq_certificates              [2] SEQUENCE OF CertificateEntry OPTIONAL
}

CertificateVerify ::= SEQUENCE {
    algorithm                     SignatureScheme,
    signature                     OCTET STRING,
    pq_algorithm                  [1] SignatureScheme OPTIONAL,
    pq_signature                  [2] OCTET STRING OPTIONAL
}
```


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


The included test program (`test_dual_certificates.c`) performs comprehensive testing:

1. **Test 1**: Enabling dual certificate mode
2. **Test 2**: Setting PQC certificates and chains
3. **Test 3**: Validating dual certificates
4. **Test 4**: Verifying PQC signatures
5. **Test 5**: Testing dual signature algorithms
6. **Test 6**: Handling dual certificate errors
7. **Test 7**: Printing dual certificate information
8. **Test 8**: Testing certificate chain validation
9. **Test 9**: Testing signature generation
10.**Test 10**: Testing TLS extension handling

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
openssl genpkey -algorithm RSA -out ca_classic_key.pem 

# Generate PQC CA private key (Falcon512)
openssl genpkey -algorithm falcon512 -out ca_pq_key.pem

# Create classic CA certificate
openssl req -new -x509 -key ca_classic_key.pem -out ca_classic_cert.pem -days 365 \
    -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=TestClassicCA"

# Create PQC CA certificate
openssl req -new -x509 -key ca_pq_key.pem -out ca_pq_cert.pem -days 365 \
    -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=TestPQCA"
```

### Step 2: Generate Dual Certificates

```bash
# Generate classic certificate private key (RSA)
openssl genpkey -algorithm RSA -out server_classic_key.pem

# Create classic certificate request
openssl req -new -key server_classic_key.pem -out server_classic_req.pem \
    -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com"

    # Sign classic certificate
openssl x509 -req -in server_classic_req.pem -CA ca_classic_cert.pem -CAkey ca_classic_key.pem \
    -CAcreateserial -out server_classic_cert.pem -days 365
    
# Generate PQC certificate private key (Falcon512)
openssl genpkey -algorithm falcon512 -out server_pq_key.pem



# Create PQC certificate request
openssl req -new -key server_pq_key.pem -out server_pq_req.pem \
    -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=server.example.com"



# Sign PQC certificate
openssl x509 -req -in server_pq_req.pem -CA ca_pq_cert.pem -CAkey ca_pq_key.pem \
    -CAcreateserial -out server_pq_cert.pem -days 365
```

### Step 3: Test Dual Certificate Usage

```bash
# Test dual certificate validation
openssl s_server -cert server_classic_cert.pem -key server_classic_key.pem \
    -pqcert server_pq_cert.pem -pqkey server_pq_key.pem -enable_dual_certs \
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

**Test Script**


A bash script (`test_dual_certificates.sh`) is provided to automate the entire testing process. This script performs all the steps described above and includes additional verification and error handling.

### Compilation and Usage

```bash
# Make the script executable
chmod +x test_dual_certificates.sh

# Run the test script
./test_dual_certificates.sh
```


**TLS Handshake Testing Process**

This section describes how to test the dual certificate implementation in a real TLS handshake context using OpenSSL.

### Step 1: Test Certificate Generation

#### 1.1 Compiling the Test Program

```bash
# Compile the TLS test program
gcc -o test_tls_dual_cert test_tls_dual_cert.c -lssl -lcrypto -ldl -lpthread

# Verify that compilation was successful
./test_tls_dual_cert
```

The program automatically generates:
- `ca_classic_cert.pem` : Classic CA certificate
- `ca_classic_key.pem` : Classic CA private key
- `ca_pq_cert.pem` : PQC CA certificate
- `ca_pq_key.pem` : PQC CA private key
- `server_classic_cert.pem` : Server classic certificate
- `server_classic_key.pem` : Server classic private key
- `server_pq_cert.pem` : Server PQC certificate
- `server_pq_key.pem` : Server PQC private key

#### 1.2 Verifying the Dual Certificate Configuration

```bash
# Verify that dual certificates are properly configured
openssl s_server -cert server_classic_cert.pem -key server_classic_key.pem \
    -pqcert server_pq_cert.pem -pqkey server_pq_key.pem -enable_dual_certs \
    -accept 4433 -www -msg
```

### Step 2: TLS Handshake Testing

#### 2.1 Starting the OpenSSL Server

```bash
# Start the TLS server with dual certificates
openssl s_server -cert server_classic_cert.pem -key server_classic_key.pem \
    -pqcert server_pq_cert.pem -pqkey server_pq_key.pem -enable_dual_certs \
    -accept 4433 -www -msg
```

Options used:
- `-cert server_classic_cert.pem` : Classic server certificate
- `-key server_classic_key.pem` : Classic server private key
- `-pqcert server_pq_cert.pem` : PQC server certificate
- `-pqkey server_pq_key.pem` : PQC server private key
- `-enable_dual_certs` : Enable dual certificate mode
- `-accept 4433` : Listening port
- `-www` : Simple web server mode
- `-msg` : Display detailed TLS messages

#### 2.2 Connecting the OpenSSL Client

```bash
# In another terminal, connect a TLS client
openssl s_client -connect localhost:4433 -CAfile ca_classic_cert.pem \
    -pqcafile ca_pq_cert.pem -enable_dual_certs -msg
```

Options used:
- `-connect localhost:4433` : Connect to local server
- `-CAfile ca_classic_cert.pem` : Classic CA certificate for validation
- `-pqcafile ca_pq_cert.pem` : PQC CA certificate for validation
- `-enable_dual_certs` : Enable dual certificate mode
- `-msg` : Display detailed TLS messages

### Step 3: Results Analysis

#### 3.1 Expected TLS Messages

The TLS 1.3 handshake should proceed as follows:

1. **ClientHello** → **ServerHello**
2. **EncryptedExtensions**
3. **Certificate** (contains both classic and PQC certificate chains)
4. **CertificateVerify** (contains both classic and PQC signatures)
5. **Finished** (successful exchange)

#### 3.2 Dual Certificate Validation

In the server's `Certificate` message, you should see:

```
Certificate Message:
  - Classic certificate chain
  - Delimiter (0x00 0x00 0x00)
  - PQC certificate chain
```

In the `CertificateVerify` message, you should see:

```
CertificateVerify Message:
  - Classic signature
  - PQC signature
```

#### 3.3 Success Indicators

**Successful handshake** if you see:
- Complete TLS 1.3 message exchange
- Both classic and PQC certificates in Certificate message
- Both classic and PQC signatures in CertificateVerify message
- `NewSessionTicket` generation
- No errors related to dual certificates
- TLS session successfully established

⚠️ **Note** : The `fatal decode_error` at the end is normal - it occurs when the client closes the connection after receiving session tickets.

### Step 4: Automated Test Script

To automate the complete process:

```bash
#!/bin/bash
# test_tls_dual_handshake.sh

echo "=== TLS Handshake Test with Dual Certificates ==="

# 1. Generate certificates
echo "1. Generating dual certificates..."
./test_tls_dual_cert

# 2. Verify dual certificate configuration
echo "2. Verifying dual certificate configuration..."
if openssl x509 -in server_classic_cert.pem -text -noout && \
   openssl x509 -in server_pq_cert.pem -text -noout; then
    echo "Dual certificates generated successfully"
else
    echo "Dual certificate generation failed"
    exit 1
fi

# 3. Start server in background
echo "3. Starting TLS server with dual certificates..."
openssl s_server -cert server_classic_cert.pem -key server_classic_key.pem \
    -pqcert server_pq_cert.pem -pqkey server_pq_key.pem -enable_dual_certs \
    -accept 4433 -www &
SERVER_PID=$!

# 4. Wait for server to start
sleep 2

# 5. Test client connection
echo "4. Testing client connection with dual certificates..."
timeout 10 openssl s_client -connect localhost:4433 -CAfile ca_classic_cert.pem \
    -pqcafile ca_pq_cert.pem -enable_dual_certs -quiet

# 6. Cleanup
echo "5. Cleaning up..."
kill $SERVER_PID 2>/dev/null
echo "=== Test completed ==="
```

### Step 5: Troubleshooting

#### Common Issues

1. **Port already in use** :
   ```bash
   # Change port
   openssl s_server -cert server_classic_cert.pem -key server_classic_key.pem \
       -pqcert server_pq_cert.pem -pqkey server_pq_key.pem -enable_dual_certs \
       -accept 8443 -www
   ```

2. **Certificate not found** :
   ```bash
   # Verify that files exist
   ls -la *.pem
   ```

3. **Validation error** :
   ```bash
   # Verify certificate chains
   openssl verify -CAfile ca_classic_cert.pem server_classic_cert.pem
   openssl verify -CAfile ca_pq_cert.pem server_pq_cert.pem
   ```

#### Additional Verifications

```bash
# Verify the dual certificate configuration
openssl s_client -connect localhost:4433 -CAfile ca_classic_cert.pem \
    -pqcafile ca_pq_cert.pem -enable_dual_certs -msg | grep -A 10 "Certificate"

# Check for dual signature algorithms
openssl s_client -connect localhost:4433 -CAfile ca_classic_cert.pem \
    -pqcafile ca_pq_cert.pem -enable_dual_certs -msg | grep -A 5 "dual_signature_algorithms"
```

**OID Registration**


The implementation uses the following Object Identifiers as defined in the draft:

- `id-pe-dualSignatureAlgorithms`: `1.3.6.1.5.5.7.1.37`
- `id-ce-dualCertificate`: `1.3.6.1.5.5.7.1.38`

