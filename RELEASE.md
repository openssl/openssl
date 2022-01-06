OQS-OpenSSL_1\_1\_1-stable snapshot 2022-01
===========================================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**open-quantum-safe/openssl** is an integration of liboqs into (a fork of) OpenSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography in TLS 1.3, X.509 certificates, CMS, and S/MIME.  The integration should not be considered "production quality".

Release notes
=============

This is the 2022-01 snapshot release of OQS-OpenSSL. The release candidate was released on January 6, 2022.  This release is intended to be used with liboqs version 0.7.1.

What's New
----------

This is the eighth snapshot release of OQS-OpenSSL_1\_1\_1-stable.  It is based on OpenSSL 1.1.1m.

- Update OpenSSL to version 1.1.1m.
- Add support for NTRU and NTRU Prime level 5 KEMs.

Previous release notes
----------------------

- [OQS-OpenSSL 1.1.1 snapshot 2021-08](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2021-08), based on OpenSSL 1.1.1k, aligned with liboqs 0.7.0 (August 11, 2021)
- [OQS-OpenSSL 1.1.1 snapshot 2021-03](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2021-03), based on OpenSSL 1.1.1k, aligned with liboqs 0.5.0 (March 26, 2021)
- [OQS-OpenSSL 1.1.1 snapshot 2020-08](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2020-08), based on OpenSSL 1.1.1g, aligned with liboqs 0.4.0 (August 11, 2020)
- [OQS-OpenSSL 1.1.1 snapshot 2020-07](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2020-07), based on OpenSSL 1.1.1g, aligned with liboqs 0.3.0 (July 10, 2020)
- [OQS-OpenSSL 1.1.1 snapshot 2019-10](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2019-10), based on OpenSSL 1.1.1d, aligned with liboqs 0.2.0 (October 8, 2019)
- [OQS-OpenSSL 1.1.1 snapshot 2018-11](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2018-11), based on OpenSSL 1.1.1, aligned with liboqs 0.1.0 (November 13, 2018)

---

Detailed changelog
------------------

* Update to OpenSSL 1.1.1l by @dstebila in https://github.com/open-quantum-safe/openssl/pull/330
* adding ntrup1277 by @baentsch in https://github.com/open-quantum-safe/openssl/pull/334
* ntru1229 by @baentsch in https://github.com/open-quantum-safe/openssl/pull/336
* OSSL ID registry by @baentsch in https://github.com/open-quantum-safe/openssl/pull/340
* adding M1 build instruction [skip ci] by @baentsch in https://github.com/open-quantum-safe/openssl/pull/342
* simplify documentation [skip ci] by @baentsch in https://github.com/open-quantum-safe/openssl/pull/345
* Merging OpenSSL 1.1.1m by @baentsch in https://github.com/open-quantum-safe/openssl/pull/346

**Full Changelog**: https://github.com/open-quantum-safe/openssl/compare/OQS-OpenSSL_1_1_1-stable-snapshot-2021-08...OQS-OpenSSL-1_1_1-stable-snapshot-2022-01
