OQS-OpenSSL_1\_1\_1-stable snapshot 2020-07
===========================================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**open-quantum-safe/openssl** is an integration of liboqs into (a fork of) OpenSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography in TLS 1.3, X.509 certificates, CMS, and S/MIME.  The integration should not be considered "production quality".

Release notes
=============

This is the 2020-07 snapshot release of OQS-OpenSSL, which was released on July 10, 2020. Its release page on GitHub is https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2020-07.  This release is intended to be used with liboqs version 0.3.0.

What's New
----------

This is the fourth snapshot release of OQS-OpenSSL_1\_1\_1-stable.  It is based on OpenSSL 1.1.1g.

- Uses the updated NIST Round 2 submissions added to liboqs 0.3.0, as described in the [liboqs release notes](https://github.com/open-quantum-safe/liboqs/blob/master/RELEASE.md).
- Adds support for post-quantum signatures in S/MIME and CMS features of OQS-OpenSSL.
- Adds post-quantum algorithms to OpenSSL's `speed` command.
- Implements hybrid key exchange in TLS 1.3 in accordance with [draft-ietf-tls-hybrid-design-00](https://tools.ietf.org/html/draft-ietf-tls-hybrid-design-00).
- More reliable building and use of shared libraries.
- Improves testing of post-quantum functionality, including interoperability with [OQS-BoringSSL](https://github.com/open-quantum-safe/boringssl).
