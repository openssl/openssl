OQS-OpenSSL_1\_1\_1-stable snapshot 2019-09-rc1
===============================================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**open-quantum-safe/openssl** is an integration of liboqs into (a fork of) OpenSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

This branch of our fork of OpenSSL aims to provide integration of post-quantum algorithms from liboqs into TLS 1.3 in OpenSSL 1.1.1.

This branch of our fork of OpenSSL can be used with the following versions of liboqs:

- **liboqs master branch** 0.2.0

Release notes
=============

This snapshot of the OQS fork of OpenSSL 1.1.1d (`OQS-OpenSSL_1_1_1-stable`) was released on TODO.  Its release page on Github is https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2019-09.

What's New
----------

This is the second snapshot release of OQS-OpenSSL_1\_1\_1-stable.  It is based on the upstream OpenSSL 1.1.1d release.

This release adds hybrid (post-quantum + elliptic curve) authentication in TLS 1.3.

This release adds/updates post-quantum KEMs for TLS 1.3 key exchange and signature algorithms for TLS 1.3 authentication based on NIST Round 2 submissions.  See the README.md file for the list of algorithms.

Previous releases of liboqs differentiated between "master branch" and "nist-branch", with nist-branch supporting more algorithms.  liboqs nist-branch is no longer be developed or released, and this release of OQS-OpenSSL_1\_1\_1-stable only builds against liboqs master branch.


Future work
-----------

Snapshot releases of OQS-OpenSSL_1\_1\_1-stable will be made approximately bi-monthly.  These will include syncing the branch with upstream releases of OpenSSL, and changes required to sync with new releases of liboqs.
