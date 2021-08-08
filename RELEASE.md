OQS-OpenSSL_1\_1\_1-stable snapshot 2021-08-rc1
===============================================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**open-quantum-safe/openssl** is an integration of liboqs into (a fork of) OpenSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography in TLS 1.3, X.509 certificates, CMS, and S/MIME.  The integration should not be considered "production quality".

Release notes
=============

This is release candidate 1 for the the 2021-08 snapshot release of OQS-OpenSSL, which was released on August 8, 2021. This release is intended to be used with liboqs version 0.7.0.

What's New
----------

This is the sixth snapshot release of OQS-OpenSSL_1\_1\_1-stable.  It is based on OpenSSL 1.1.1k.

- Updates algorithms to those used in liboqs 0.7.0, as described in the [liboqs release notes](https://github.com/open-quantum-safe/liboqs/blob/main/RELEASE.md).
- Improves signing support with different digest algorithms
- Enables building OQS-OpenSSL for UEFI/EDKII (contributed by Jiewen Yao, Intel)
- Improved documentation of algorithm identifiers

Previous release notes
----------------------

- [OQS-OpenSSL 1.1.1 snapshot 2021-03](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2021-03) aligned with liboqs 0.5.0 (March 26, 2021)
- [OQS-OpenSSL 1.1.1 snapshot 2020-08](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2020-08) aligned with liboqs 0.4.0 (August 11, 2020)
- [OQS-OpenSSL 1.1.1 snapshot 2020-07](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2020-07) aligned with liboqs 0.3.0 (July 10, 2020)
- [OQS-OpenSSL 1.1.1 snapshot 2019-10](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2019-10) aligned with liboqs 0.2.0 (October 8, 2019)
- [OQS-OpenSSL 1.1.1 snapshot 2018-11](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2018-11) aligned with liboqs 0.1.0 (November 13, 2018)
