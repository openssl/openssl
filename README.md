Welcome to the OpenSSL Project
==============================

[![openssl logo]][www.openssl.org]

[![github actions ci badge]][github actions ci]
[![appveyor badge]][appveyor jobs]

OpenSSL is a robust, commercial-grade, full-featured Open Source Toolkit
for the TLS (formerly SSL), DTLS and QUIC (currently client side only)
protocols.

The protocol implementations are based on a full-strength general purpose
cryptographic library, which can also be used stand-alone. Also included is a
cryptographic module validated to conform with FIPS standards.

OpenSSL is descended from the SSLeay library developed by Eric A. Young
and Tim J. Hudson.

The official Home Page of the OpenSSL Project is [www.openssl.org].

Table of Contents
=================

 - [Overview](#overview)
 - [Download](#download)
 - [Build and Install](#build-and-install)
 - [Documentation](#documentation)
 - [License](#license)
 - [Support](#support)
 - [Contributing](#contributing)
 - [Legalities](#legalities)

Overview
========

The OpenSSL toolkit includes:

- **libssl**
  an implementation of all TLS protocol versions up to TLSv1.3 ([RFC 8446]),
  DTLS protocol versions up to DTLSv1.2 ([RFC 6347]) and
  the QUIC (currently client side only) version 1 protocol ([RFC 9000]).

- **libcrypto**
  a full-strength general purpose cryptographic library. It constitutes the
  basis of the TLS implementation, but can also be used independently.

- **openssl**
  the OpenSSL command line tool, a swiss army knife for cryptographic tasks,
  testing and analyzing. It can be used for
  - creation of key parameters
  - creation of X.509 certificates, CSRs and CRLs
  - calculation of message digests
  - encryption and decryption
  - SSL/TLS/DTLS and client and server tests
  - QUIC client tests
  - handling of S/MIME signed or encrypted mail
  - and more...

Download
========

For Production Use
------------------

Source code tarballs of the official releases can be downloaded from
[openssl-library.org/source/](https://openssl-library.org/source/).
The OpenSSL project does not distribute the toolkit in binary form.

However, for a large variety of operating systems precompiled versions
of the OpenSSL toolkit are available. In particular, on Linux and other
Unix operating systems, it is normally recommended to link against the
precompiled shared libraries provided by the distributor or vendor.

We also maintain a list of third parties that produce OpenSSL binaries for
various Operating Systems (including Windows) on the [Binaries] page on our
wiki.

For Testing and Development
---------------------------

Although testing and development could in theory also be done using
the source tarballs, having a local copy of the git repository with
the entire project history gives you much more insight into the
code base.

The main OpenSSL Git repository is private.
There is a public GitHub mirror of it at [github.com/openssl/openssl],
which is updated automatically from the former on every commit.

A local copy of the Git repository can be obtained by cloning it from
the GitHub mirror using

    git clone https://github.com/openssl/openssl.git

If you intend to contribute to OpenSSL, either to fix bugs or contribute
new features, you need to fork the GitHub mirror and clone your public fork
instead.

    git clone https://github.com/yourname/openssl.git

This is necessary because all development of OpenSSL nowadays is done via
GitHub pull requests. For more details, see [Contributing](#contributing).

Build and Install
=================

After obtaining the Source, have a look at the [INSTALL](INSTALL.md) file for
detailed instructions about building and installing OpenSSL. For some
platforms, the installation instructions are amended by a platform specific
document.

 * [Notes for UNIX-like platforms](NOTES-UNIX.md)
 * [Notes for Android platforms](NOTES-ANDROID.md)
 * [Notes for Windows platforms](NOTES-WINDOWS.md)
 * [Notes for the DOS platform with DJGPP](NOTES-DJGPP.md)
 * [Notes for the OpenVMS platform](NOTES-VMS.md)
 * [Notes on Perl](NOTES-PERL.md)
 * [Notes on Valgrind](NOTES-VALGRIND.md)

Specific notes on upgrading to OpenSSL 3.x from previous versions can be found
in the [ossl-guide-migration(7ossl)] manual page.

Documentation
=============

README Files
------------

There are some README.md files in the top level of the source distribution
containing additional information on specific topics.

 * [Information about the OpenSSL QUIC protocol implementation](README-QUIC.md)
 * [Information about the OpenSSL Provider architecture](README-PROVIDERS.md)
 * [Information about using the OpenSSL FIPS validated module](README-FIPS.md)
 * [Information about the legacy OpenSSL Engine architecture](README-ENGINES.md)

The OpenSSL Guide
-----------------

There are some tutorial and introductory pages on some important OpenSSL topics
within the [OpenSSL Guide].

Manual Pages
------------

The manual pages for the master branch and all current stable releases are
available online.

- [OpenSSL master](https://www.openssl.org/docs/manmaster)
- [OpenSSL 3.0](https://www.openssl.org/docs/man3.0)
- [OpenSSL 3.1](https://www.openssl.org/docs/man3.1)
- [OpenSSL 3.2](https://www.openssl.org/docs/man3.2)

Demos
-----

There are numerous source code demos for using various OpenSSL capabilities in the
[demos subfolder](./demos).

Wiki
----

There is a [GitHub Wiki] which is currently not very active.

License
=======

OpenSSL is licensed under the Apache License 2.0, which means that
you are free to get and use it for commercial and non-commercial
purposes as long as you fulfill its conditions.

See the [LICENSE.txt](LICENSE.txt) file for more details.

Support
=======

There are various ways to get in touch. The correct channel depends on
your requirement. See the [SUPPORT](SUPPORT.md) file for more details.

Contributing
============

If you are interested and willing to contribute to the OpenSSL project,
please take a look at the [CONTRIBUTING](CONTRIBUTING.md) file.

Legalities
==========

A number of nations restrict the use or export of cryptography. If you are
potentially subject to such restrictions, you should seek legal advice before
attempting to develop or distribute cryptographic code.

Copyright
=========

Copyright (c) 1998-2025 The OpenSSL Project Authors

Copyright (c) 1995-1998 Eric A. Young, Tim J. Hudson

All rights reserved.

<!-- Links  -->

[www.openssl.org]:
    <https://www.openssl.org>
    "OpenSSL Homepage"

[github.com/openssl/openssl]:
    <https://github.com/openssl/openssl>
    "OpenSSL GitHub Mirror"

[GitHub Wiki]:
    <https://github.com/openssl/openssl/wiki>
    "OpenSSL Wiki"

[ossl-guide-migration(7ossl)]:
    <https://www.openssl.org/docs/manmaster/man7/ossl-guide-migration.html>
    "OpenSSL Migration Guide"

[RFC 8446]:
     <https://tools.ietf.org/html/rfc8446>

[RFC 6347]:
     <https://tools.ietf.org/html/rfc6347>

[RFC 9000]:
     <https://tools.ietf.org/html/rfc9000>

[Binaries]:
    <https://github.com/openssl/openssl/wiki/Binaries>
    "List of third party OpenSSL binaries"

[OpenSSL Guide]:
    <https://www.openssl.org/docs/manmaster/man7/ossl-guide-introduction.html>
    "An introduction to OpenSSL"

<!-- Logos and Badges -->

[openssl logo]:
    doc/images/openssl.svg
    "OpenSSL Logo"

[github actions ci badge]:
    <https://github.com/openssl/openssl/workflows/GitHub%20CI/badge.svg>
    "GitHub Actions CI Status"

[github actions ci]:
    <https://github.com/openssl/openssl/actions?query=workflow%3A%22GitHub+CI%22>
    "GitHub Actions CI"

[appveyor badge]:
    <https://ci.appveyor.com/api/projects/status/8e10o7xfrg73v98f/branch/master?svg=true>
    "AppVeyor Build Status"

[appveyor jobs]:
    <https://ci.appveyor.com/project/openssl/openssl/branch/master>
    "AppVeyor Jobs"

# RFC 9763 Related Certificate Implementation for OpenSSL

This project implements the "bound certificate" approach as defined in [RFC 9763](https://datatracker.ietf.org/doc/html/rfc9763) for the OpenSSL cryptographic library. The implementation provides support for the `relatedCertRequest` attribute in Certificate Signing Requests (CSRs) and the `RelatedCertificate` extension in X.509 certificates.

## Overview

RFC 9763 defines a mechanism to bind certificates together, allowing one certificate to reference another certificate through cryptographic means. This is particularly useful for:

- Certificate chaining and relationship verification
- Cross-certification scenarios
- Certificate binding in multi-certificate environments
- Post-quantum cryptography certificate binding

## Features

### Implemented Components

1. **relatedCertRequest Attribute** (`id-aa-relatedCertRequest`)
   - Added to Certificate Signing Requests (CSRs)
   - Contains requester certificate information
   - Includes timestamp and location information
   - Digitally signed for integrity

2. **RelatedCertificate Extension** (`id-pe-relatedCert`)
   - Added to X.509 certificates
   - Contains hash of the related certificate
   - Supports multiple hash algorithms (SHA-256, SHA-512, etc.)

### Key Functions

- `add_related_cert_request_to_csr()` - Add relatedCertRequest attribute to CSR
- `add_related_certificate_extension()` - Add RelatedCertificate extension to certificate
- `verify_related_cert_request()` - Verify relatedCertRequest attribute
- `verify_related_certificate_extension()` - Verify RelatedCertificate extension
- `get_related_certificate_extension()` - Extract RelatedCertificate extension
- `print_related_cert_request()` - Print relatedCertRequest attribute details
- `print_related_certificate_extension()` - Print RelatedCertificate extension details

## ASN.1 Structures

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

## Building and Testing

### Prerequisites

- OpenSSL 3.0 or later
- GCC compiler
- Make

### Build Options

```bash
# Build with system OpenSSL (recommended)
make test_certbind_system

# Build with custom OpenSSL installation
make test_certbind

# Build with debug information
make debug

# Run tests
make test

# Clean build artifacts
make clean
```

### Test Program

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
10. **Test 10**: Testing with SHA-512 hash algorithm

## Usage Examples

### Adding relatedCertRequest to CSR

```c
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "crypto/x509/v3_certbind.h"

// Create CSR and related certificate
X509_REQ *req = /* your CSR */;
EVP_PKEY *pkey = /* your private key */;
X509 *related_cert = /* related certificate */;

// Add relatedCertRequest attribute
if (add_related_cert_request_to_csr(req, pkey, related_cert, 
                                   "related_cert.pem", EVP_sha256())) {
    printf("relatedCertRequest attribute added successfully\n");
}
```

### Adding RelatedCertificate Extension

```c
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "crypto/x509/v3_certbind.h"

// Create certificate and related certificate
X509 *cert = /* your certificate */;
X509 *related_cert = /* related certificate */;

// Add RelatedCertificate extension
if (add_related_certificate_extension(cert, related_cert, EVP_sha256())) {
    printf("RelatedCertificate extension added successfully\n");
}
```

### Verification

```c
// Verify relatedCertRequest attribute
if (verify_related_cert_request(req)) {
    printf("relatedCertRequest verification passed\n");
}

// Verify RelatedCertificate extension
if (verify_related_certificate_extension(cert, related_cert)) {
    printf("RelatedCertificate verification passed\n");
}
```

## OID Registration

The implementation uses the following Object Identifiers as defined in RFC 9763:

- `id-aa-relatedCertRequest`: `1.2.840.113549.1.9.16.2.60`
- `id-pe-relatedCert`: `1.3.6.1.5.5.7.1.36`

These OIDs are already defined in OpenSSL's `objects.txt` and will be available after regenerating the object macros.

## Conformance to RFC 9763

The implementation follows RFC 9763 specifications:

- ✅ Correct ASN.1 structure definitions
- ✅ BinaryTime format for timestamps (RFC 6019)
- ✅ UniformResourceIdentifiers as SEQUENCE OF IA5String
- ✅ Proper signature handling in RequesterCertificate
- ✅ Hash algorithm support in RelatedCertificate
- ✅ OID usage as specified in the RFC
- ✅ Timestamp freshness checking (5-minute timeout)

## Security Considerations

1. **Timestamp Freshness**: The implementation enforces a 5-minute timeout for requestTime freshness as recommended in RFC 9763.

2. **Signature Verification**: All relatedCertRequest attributes are digitally signed and verified using the requester's private key.

3. **Hash Algorithm Support**: The implementation supports multiple hash algorithms, with SHA-256 as the default.

4. **Memory Management**: Proper cleanup of ASN.1 structures and memory allocation.

## Limitations

1. **Extension Registration**: The implementation uses raw ASN.1 encoding for extensions to avoid OpenSSL extension registration complexities.

2. **URI Handling**: Currently supports file-based URIs for testing. Production use may require HTTP/HTTPS URI support.

3. **Stack API Compatibility**: Some OpenSSL stack API functions may show deprecation warnings but remain functional.

## Contributing

This implementation is designed to be integrated into the OpenSSL codebase. Contributions should:

1. Follow OpenSSL coding standards
2. Include comprehensive tests
3. Maintain RFC 9763 compliance
4. Handle error conditions gracefully

## License

This implementation follows the OpenSSL license model. See the Apache License 2.0 for details.

## References

- [RFC 9763: Related Certificate Request and Response](https://datatracker.ietf.org/doc/html/rfc9763)
- [RFC 6019: BinaryTime: An Alternate Format for Representing Date and Time in ASN.1](https://datatracker.ietf.org/doc/html/rfc6019)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
