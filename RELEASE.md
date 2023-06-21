OQS-OpenSSL_1\_1\_1-stable snapshot 2023-06-rc1
===============================================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**open-quantum-safe/openssl** is an integration of liboqs into (a fork of) OpenSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography in TLS 1.3, X.509 certificates, CMS, and S/MIME.  The integration should not be considered "production quality".

Release notes
=============

This is release candidate 1 of the 2023-06 snapshot release of OQS-OpenSSL, which was released on June 20, 2023.  This release is intended to be used with liboqs version 0.8.0.

END OF LIFE NOTICE
------------------

As the OpenSSL team has announced that OpenSSL 1.1.1 will reach [end of life in September 2023](https://www.openssl.org/blog/blog/2023/03/28/1.1.1-EOL/), this release is intended to be the final release of OQS-OpenSSL_1\_1\_1-stable.  Users are recommended to migrate to OpenSSL 3 and make use of the [OQS Provider](https://github.com/open-quantum-safe/oqs-provider/) which provides full post-quantum support in OpenSSL 3.

What's New
----------

This is the tenth snapshot release of OQS-OpenSSL_1\_1\_1-stable.  It is based on OpenSSL 1.1.1u.

- Update OpenSSL to version 1.1.1u.
- Key encapsulation mechanism algorithm changes:
  - BIKE: updated to Round 4 version.
  - Kyber: 90s variants were removed.
  - NTRU Prime: All variants were removed.
  - Saber: removed.
- Digital signature scheme algorithm changes:
  - Dilithium; AES variants were removed.
  - Falcon: updated to the 2023-02-07 version.
  - Picnic: removed.
  - Rainbow: removed.
  - SPHINCS+: updated to version 3.1; SPHINCS+-Haraka variants were removed; SPHINCS+-SHA256 and SPHINCS+-SHAKE variants were renamed
- Update OIDs and TLS key exchange code points

Detailed changelog
------------------

* documentation generator fix by @baentsch in https://github.com/open-quantum-safe/openssl/pull/394
* Upstream 1.1.1s by @baentsch in https://github.com/open-quantum-safe/openssl/pull/407
* removing Picnic,NTRUprime,Rainbow,Saber by @baentsch in https://github.com/open-quantum-safe/openssl/pull/411
* adds IDs for proper wireshark sigalg dissection by @baentsch in https://github.com/open-quantum-safe/openssl/pull/412
* Updated upstream tag reference to 1.1.1s. by @christianpaquin in https://github.com/open-quantum-safe/openssl/pull/414
* Removed NTRU. by @xvzcf in https://github.com/open-quantum-safe/openssl/pull/415
* remove boringssl interop by @baentsch in https://github.com/open-quantum-safe/openssl/pull/417
* change sphincs variant enablement by @baentsch in https://github.com/open-quantum-safe/openssl/pull/425
* Upgrade to upstream 1.1.1t by @baentsch in https://github.com/open-quantum-safe/openssl/pull/430
* (O)ID update for BIKE and Falcon using oqs-provider template by @baentsch in https://github.com/open-quantum-safe/openssl/pull/438
* version and build instruction update by @baentsch in https://github.com/open-quantum-safe/openssl/pull/443
* Algorithm & ID updates by @baentsch in https://github.com/open-quantum-safe/openssl/pull/447
* Merged 1.1.1u by @christianpaquin in https://github.com/open-quantum-safe/openssl/pull/453
* Code point documentation update by @baentsch in https://github.com/open-quantum-safe/openssl/pull/458
* Updated generate.yml to support liboqs 0.8.0 algorithm changes by @crt26 in https://github.com/open-quantum-safe/openssl/pull/456

## New Contributors
* @crt26 made their first contribution in https://github.com/open-quantum-safe/openssl/pull/456

**Full Changelog**: https://github.com/open-quantum-safe/openssl/compare/OQS-OpenSSL-1_1_1-stable-snapshot-2022-08...OQS-OpenSSL-1_1_1-stable-snapshot-2023-06-rc-1