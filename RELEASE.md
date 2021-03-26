OQS-OpenSSL_1\_1\_1-stable snapshot 2021-03
===========================================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**open-quantum-safe/openssl** is an integration of liboqs into (a fork of) OpenSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography in TLS 1.3, X.509 certificates, CMS, and S/MIME.  The integration should not be considered "production quality".

Release notes
=============

This is the 2021-03 snapshot release of OQS-OpenSSL, which was released on March 26, 2021. Its release page on GitHub is https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2021-03.  This release is intended to be used with liboqs version 0.5.0.

What's New
----------

This is the fifth snapshot release of OQS-OpenSSL_1\_1\_1-stable.  It is based on OpenSSL 1.1.1k.

- Removes algorithms from NIST PQC Round 2 that did not advance to Round 3: NewHope, ThreeBears, MQDSS, qTesla.
- Updates algorithms to those used in liboqs 0.5.0, as described in the [liboqs release notes](https://github.com/open-quantum-safe/liboqs/blob/main/RELEASE.md).
- Adds HQC, NTRUPrime.
- Improvements to continuous integration testing and build process, including building of shared libraries.
- Change format of hybrid key exchange in TLS 1.3 to follow https://tools.ietf.org/html/draft-ietf-tls-hybrid-design-01

Previous release notes
----------------------

- [OQS-OpenSSL 1.1.1 snapshot 2020-08](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2020-08) aligned with liboqs 0.4.0 (August 11, 2020)
- [OQS-OpenSSL 1.1.1 snapshot 2020-07](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2020-07) aligned with liboqs 0.3.0 (July 10, 2020)
- [OQS-OpenSSL 1.1.1 snapshot 2019-10](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2019-10) aligned with liboqs 0.2.0 (October 8, 2019)
- [OQS-OpenSSL 1.1.1 snapshot 2018-11](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2018-11) aligned with liboqs 0.1.0 (November 13, 2018)
