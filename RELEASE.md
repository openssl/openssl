OQS-OpenSSL_1\_1\_1-stable snapshot 2022-08
===========================================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**open-quantum-safe/openssl** is an integration of liboqs into (a fork of) OpenSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography in TLS 1.3, X.509 certificates, CMS, and S/MIME.  The integration should not be considered "production quality".

Release notes
=============

This is the 2022-08 snapshot release of OQS-OpenSSL, which was released on August 23, 2022.  This release is intended to be used with liboqs version 0.7.2.

What's New
----------

This is the ninth snapshot release of OQS-OpenSSL_1\_1\_1-stable.  It is based on OpenSSL 1.1.1q.

- Update OpenSSL to version 1.1.1q.
- Remove support for Rainbow level 1 and SIKE/SIDH.
- Adding support for setting default client KEM algorithms via TLS_DEFAULT_GROUPS environment variable.

Previous release notes
----------------------

- [OQS-OpenSSL 1.1.1 snapshot 2022-01](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2022-01), based on OpenSSL 1.1.1m, aligned with liboqs 0.7.1 (January 6, 2022)
- [OQS-OpenSSL 1.1.1 snapshot 2021-08](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2021-08), based on OpenSSL 1.1.1k, aligned with liboqs 0.7.0 (August 11, 2021)
- [OQS-OpenSSL 1.1.1 snapshot 2021-03](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2021-03), based on OpenSSL 1.1.1k, aligned with liboqs 0.5.0 (March 26, 2021)
- [OQS-OpenSSL 1.1.1 snapshot 2020-08](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2020-08), based on OpenSSL 1.1.1g, aligned with liboqs 0.4.0 (August 11, 2020)
- [OQS-OpenSSL 1.1.1 snapshot 2020-07](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2020-07), based on OpenSSL 1.1.1g, aligned with liboqs 0.3.0 (July 10, 2020)
- [OQS-OpenSSL 1.1.1 snapshot 2019-10](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2019-10), based on OpenSSL 1.1.1d, aligned with liboqs 0.2.0 (October 8, 2019)
- [OQS-OpenSSL 1.1.1 snapshot 2018-11](https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2018-11), based on OpenSSL 1.1.1, aligned with liboqs 0.1.0 (November 13, 2018)

---

Detailed changelog
------------------

* more explanation pointers for NIST levels [skip ci] by @baentsch in https://github.com/open-quantum-safe/openssl/pull/350
* adding TLS_DEFAULT_GROUPS env var by @baentsch in https://github.com/open-quantum-safe/openssl/pull/354
* Updating interop test suite for BoringSSL update. by @xvzcf in https://github.com/open-quantum-safe/openssl/pull/355
* generalize openssl install regarding liboqs lib location by @baentsch in https://github.com/open-quantum-safe/openssl/pull/358
* fix out of source build by @baentsch in https://github.com/open-quantum-safe/openssl/pull/359
* 1.1.1n merge by @baentsch in https://github.com/open-quantum-safe/openssl/pull/361
* merge with upstream 1.1.1o by @baentsch in https://github.com/open-quantum-safe/openssl/pull/370
* openssl test cert update by @baentsch in https://github.com/open-quantum-safe/openssl/pull/373
* Upstream 111p merge by @baentsch in https://github.com/open-quantum-safe/openssl/pull/375
* upstream 111q merge by @baentsch in https://github.com/open-quantum-safe/openssl/pull/377
* re-run generator for corrected dilithium2 level by @baentsch in https://github.com/open-quantum-safe/openssl/pull/381
* remove RainbowI by @baentsch in https://github.com/open-quantum-safe/openssl/pull/382
* remove SIDH/SIKE by @baentsch in https://github.com/open-quantum-safe/openssl/pull/383
* trigger CI also on main branch by @baentsch in https://github.com/open-quantum-safe/openssl/pull/386
* fix liboqs.so.version install by @baentsch in https://github.com/open-quantum-safe/openssl/pull/387

**Full Changelog**: https://github.com/open-quantum-safe/openssl/compare/OQS-OpenSSL_1_1_1-stable-snapshot-2022-01...OQS-OpenSSL-1_1_1-stable-snapshot-2022-08
