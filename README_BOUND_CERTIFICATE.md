**Bound Certificate Implementation for OpenSSL**


This project implements the "bound certificate" approach as defined in [RFC 9763](https://datatracker.ietf.org/doc/html/rfc9763) for the OpenSSL cryptographic library. The implementation provides support for the `relatedCertRequest` attribute in Certificate Signing Requests (CSRs) and the `RelatedCertificate` extension in X.509 certificates.

**Table of Contents**


 - [Overview](#overview)
 - [Features](#features)
 - [ASN.1 Structures](#asn1-structures)
 - [Building and Testing](#building-and-testing)
 - [Test Script](#test-script)
 - [OID Registration](#oid-registration)


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

**Key Functions**


- `add_related_cert_request_to_csr()` - Add relatedCertRequest attribute to CSR
- `add_related_certificate_extension()` - Add RelatedCertificate extension to certificate
- `add_related_certificate_extension_with_uri()` - Add RelatedCertificate extension with URI to certificate
- `extract_uri_from_related_cert_request()` - Extract URI from relatedCertRequest attribute
- `verify_related_cert_request()` - Verify relatedCertRequest attribute
- `verify_related_certificate_extension()` - Verify RelatedCertificate extension
- `get_related_certificate_extension()` - Extract RelatedCertificate extension
- `print_related_cert_request()` - Print relatedCertRequest attribute details
- `print_related_certificate_extension()` - Print RelatedCertificate extension details

**ASN.1 Structures**


The implementation defines the following ASN.1 structures according to RFC 9763:

```asn.1
CertID ::= SEQUENCE {
    issuer           Name,
    serialNumber     CertificateSerialNumber
}

BinaryTime ::= SEQUENCE {
    time            OCTET STRING (SIZE(8))
}

UniformResourceIdentifiers ::= SEQUENCE OF IA5String

RequesterCertificate ::= SEQUENCE {
    certID          CertID,
    requestTime     BinaryTime,
    locationInfo    UniformResourceIdentifiers,
    signature       BIT STRING OPTIONAL
}

RelatedCertificate ::= SEQUENCE {
    hashAlgorithm   AlgorithmIdentifier,
    hashValue       OCTET STRING
    uri             IA5String 
}
```


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

**Test Program**


The included test program (`test_certbind.c`) performs comprehensive testing:

1. **Test 1**: Adding relatedCertRequest attribute to CSR
2. **Test 2**: Saving CSR with attribute
3. **Test 3**: Printing relatedCertRequest attribute
4. **Test 4**: Verifying relatedCertRequest attribute
5. **Test 5**: Creating certificate with RelatedCertificate extension
6. **Test 6**: Saving certificate with extension
7. **Test 7**: Printing RelatedCertificate extension
8. **Test 8**: Verifying RelatedCertificate extension
9. **Test 9**: Extracting RelatedCertificate extension
10.**Test 10**: Testing with SHA-512 hash algorithm

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
# Generate CA private key (RSA)
openssl genpkey -algorithm RSA -out ca_key.pem 

# Create CA certificate
openssl req -new -x509 -key ca_key.pem -out ca_cert.pem -days 365 \
    -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=TestCA"
```

### Step 2: Generate Bound Certificate (RSA)

```bash
# Generate bound certificate private key (RSA)
openssl genpkey -algorithm RSA -out bound_key.pem

# Create bound certificate request
openssl req -new -key bound_key.pem -out bound_cert_req.pem \
    -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=bound.example.com"

# Sign bound certificate
openssl x509 -req -in bound_cert_req.pem -CA ca_cert.pem -CAkey ca_key.pem \
    -CAcreateserial -out bound_cert.pem -days 365
```

### Step 3: Generate New Certificate (Falcon512)

```bash
# Generate new certificate private key (Falcon512)
openssl genpkey -algorithm falcon512 -out new_key.pem

# Create CSR with relatedCertRequest attribute
openssl req -new -key new_key.pem -out new_cert_req.pem \
    -subj "/C=US/ST=CA/L=San Francisco/O=TestOrg/CN=new.example.com" \
    -add_related_cert bound_cert.pem \
    -related_uri "file://$(pwd)/bound_cert.pem"

# Sign the CSR to create the new certificate
openssl x509 -req -in new_cert_req.pem -CA ca_cert.pem -CAkey ca_key.pem \
    -CAcreateserial -out new_cert.pem -days 365
```

### Step 4: Verification

```bash
# Verify the CSR with relatedCertRequest attribute
openssl req -in new_cert_req.pem -text -noout

# Check the relatedCertRequest attribute specifically
openssl req -in new_cert_req.pem -text -noout | grep -A 20 "relatedCertRequest"

# Verify the final certificate
openssl x509 -in new_cert.pem -text -noout

# Check the RelatedCertificate extension
openssl x509 -in new_cert.pem -text -noout | grep -A 10 "Bound"

# Verify the signature of the relatedCertRequest attribute
openssl req -in new_cert_req.pem -verify -noout
```

**Test Script**


A bash script (`test_Bound_certificate.sh`) is provided to automate the entire testing process. This script performs all the steps described above and includes additional verification and error handling.

### Compilation and Usage

```bash
# Make the script executable
chmod +x test_Bound_certificate.sh

# Run the test script
./test_Bound_certificate.sh
```


**TLS Handshake Testing Process**

This section describes how to test the RelatedCertificate extension in a real TLS handshake context using OpenSSL.

### Step 1: Test Certificate Generation

#### 1.1 Compiling the Test Program

```bash
# Compile the TLS test program
gcc -o test_tls_related_cert test_tls_related_cert.c -lssl -lcrypto -ldl -lpthread

# Verify that compilation was successful
./test_tls_related_cert
```

The program automatically generates:
- `ca_cert.pem` : CA certificate
- `ca_key.pem` : CA private key
- `server_cert.pem` : Server certificate with RelatedCertificate extension
- `server_key.pem` : Server private key
- `server_chain.pem` : Server certificate chain
- `related_cert.pem` : Related certificate

#### 1.2 Verifying the RelatedCertificate Extension

```bash
# Verify that the RelatedCertificate extension is present
openssl x509 -in server_cert.pem -text -noout | grep -A 10 "RelatedCertificate"

# Verify the detailed content of the extension
openssl x509 -in server_cert.pem -text -noout | grep -A 20 "RelatedCertificate"
```

### Step 2: TLS Handshake Testing

#### 2.1 Starting the OpenSSL Server

```bash
# Start the TLS server with the generated certificates
openssl s_server -cert server_cert.pem -key server_key.pem -CAfile ca_cert.pem -accept 4433 -www -msg
```

Options used:
- `-cert server_cert.pem` : Server certificate with RelatedCertificate extension
- `-key server_key.pem` : Server private key
- `-CAfile ca_cert.pem` : CA certificate for validation
- `-accept 4433` : Listening port
- `-www` : Simple web server mode
- `-msg` : Display detailed TLS messages

#### 2.2 Connecting the OpenSSL Client

```bash
# In another terminal, connect a TLS client
openssl s_client -connect localhost:4433 -CAfile ca_cert.pem -msg
```

Options used:
- `-connect localhost:4433` : Connect to local server
- `-CAfile ca_cert.pem` : CA certificate for validation
- `-msg` : Display detailed TLS messages

### Step 3: Results Analysis

#### 3.1 Expected TLS Messages

The TLS 1.3 handshake should proceed as follows:

1. **ClientHello** → **ServerHello**
2. **EncryptedExtensions**
3. **Certificate** (contains the RelatedCertificate extension)
4. **CertificateVerify**
5. **Finished** (successful exchange)

#### 3.2 Extension Validation

In the server's `Certificate` message, you should see:

```
30 56 06 08 2b 06 01 05 05 07 01 24 04 4a 30 48 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 30 07 15 56 cd 39 67 c7 f4 c4 45 92 84 28 12 03 ab 37 e3 c8 c5 31 60 20 af b4 b5 0f aa 38 65 c6 16 15 66 69 6c 65 3a 72 65 6c 61 74 65 64 5f 63 65 72 74 2e 70 65 6d
```

This hexadecimal sequence contains:
- **Extension OID** : `2b 06 01 05 05 07 01 24` (RelatedCertificate)
- **SHA-256 hash** of the related certificate
`

#### 3.3 Success Indicators

**Successful handshake** if you see:
- Complete TLS 1.3 message exchange
- `NewSessionTicket` generation
- No errors related to the RelatedCertificate extension
- TLS session successfully established

⚠️ **Note** : The `fatal decode_error` at the end is normal - it occurs when the client closes the connection after receiving session tickets.

### Step 4: Automated Test Script

To automate the complete process:

```bash
#!/bin/bash
# test_tls_handshake.sh

echo "=== TLS Handshake Test with RelatedCertificate ==="

# 1. Generate certificates
echo "1. Generating certificates..."
./test_tls_related_cert

# 2. Verify extension
echo "2. Verifying RelatedCertificate extension..."
if openssl x509 -in server_cert.pem -text -noout | grep -q "RelatedCertificate"; then
    echo "RelatedCertificate extension found"
else
    echo " RelatedCertificate extension not found"
    exit 1
fi

# 3. Start server in background
echo "3. Starting TLS server..."
openssl s_server -cert server_cert.pem -key server_key.pem -CAfile ca_cert.pem -accept 4433 -www &
SERVER_PID=$!

# 4. Wait for server to start
sleep 2

# 5. Test client connection
echo "4. Testing client connection..."
timeout 10 openssl s_client -connect localhost:4433 -CAfile ca_cert.pem -quiet

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
   openssl s_server -cert server_cert.pem -key server_key.pem -CAfile ca_cert.pem -accept 8443 -www
   ```

2. **Certificate not found** :
   ```bash
   # Verify that files exist
   ls -la *.pem
   ```

3. **Validation error** :
   ```bash
   # Verify certificate chain
   openssl verify -CAfile ca_cert.pem server_cert.pem
   ```

#### Additional Verifications

```bash
# Verify the hash of the related certificate
openssl x509 -in related_cert.pem -outform DER | openssl dgst -sha256

# Compare with the extension
openssl x509 -in server_cert.pem -text -noout | grep -A 5 "RelatedCertificate"
```

**OID Registration**


The implementation uses the following Object Identifiers as defined in RFC 9763:

- `id-aa-relatedCertRequest`: `1.2.840.113549.1.9.16.2.60`
- `id-pe-relatedCert`: `1.3.6.1.5.5.7.1.36`




