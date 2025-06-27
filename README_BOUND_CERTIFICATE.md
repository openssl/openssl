**Bound Certificate Implementation for OpenSSL**


This project implements the "bound certificate" approach as defined in [RFC 9763](https://datatracker.ietf.org/doc/html/rfc9763) for the OpenSSL cryptographic library. The implementation provides support for the `relatedCertRequest` attribute in Certificate Signing Requests (CSRs) and the `RelatedCertificate` extension in X.509 certificates.

**Table of Contents**


 - [Overview](#overview)
 - [Features](#features)
 - [ASN.1 Structures](#asn1-structures)
 - [Building and Testing](#building-and-testing)
 - [Test Script](#test-script)
 - [OID Registration](#oid-registration)
 - [Conformance to RFC 9763](#conformance-to-rfc-9763)
 - [Security Considerations](#security-considerations)
 - [Limitations](#limitations)

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
git clone -b bound-openssl3.3 https://github.com/wibs2401/opensslForPQCert.git
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
openssl genpkey -algorithm RSA -out ca_key.pem -aes256

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
    -add-related-cert bound_cert.pem \
    -related-uri "file://$(pwd)/bound_cert.pem"

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
openssl x509 -in new_cert.pem -text -noout | grep -A 10 "RelatedCertificate"

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

### Script Features

- **Automatic environment setup**: Creates test directory and cleans up old files
- **Prerequisite checking**: Verifies OpenSSL installation and OQS provider availability
- **Error handling**: Graceful fallback if Falcon512 is not available
- **Colored output**: Clear status messages with color coding
- **Comprehensive verification**: Checks all certificates and signatures
- **File information**: Displays generated files and their sizes


### Troubleshooting

If the script fails:

1. **OQS provider not found**: Ensure OpenSSL is compiled with OQS support
2. **Falcon512 not available**: The script will fall back to RSA for testing
3. **relatedCertRequest not supported**: Check that RFC 9763 implementation is properly integrated

**OID Registration**


The implementation uses the following Object Identifiers as defined in RFC 9763:

- `id-aa-relatedCertRequest`: `1.2.840.113549.1.9.16.2.60`
- `id-pe-relatedCert`: `1.3.6.1.5.5.7.1.36`

These OIDs are already defined in OpenSSL's `objects.txt` and will be available after regenerating the object macros.

**Conformance to RFC 9763**


The implementation follows RFC 9763 specifications:

- Correct ASN.1 structure definitions
- BinaryTime format for timestamps (RFC 6019)
- UniformResourceIdentifiers as SEQUENCE OF IA5String
- Proper signature handling in RequesterCertificate
- Hash algorithm support in RelatedCertificate
- OID usage as specified in the RFC
- Timestamp freshness checking (5-minute timeout)


**Copyright**

Copyright (c) 2024 The OpenSSL Project Authors. All Rights Reserved.

Licensed under the Apache License 2.0 (the "License"). You may not use this file except in compliance with the License. You can obtain a copy in the file LICENSE in the source distribution or at https://www.openssl.org/source/license.html. 
