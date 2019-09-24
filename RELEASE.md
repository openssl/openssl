OQS-OpenSSL_1\_1\_1-stable snapshot 2018-11-rc3
===============================================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**open-quantum-safe/openssl** is an integration of liboqs into (a fork of) OpenSSL.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

This branch of our fork of OpenSSL aims to provide integration of post-quantum algorithms from liboqs into TLS 1.3 in OpenSSL 1.1.1.

This branch of our fork of OpenSSL can be used with the following versions of liboqs:

- **liboqs master branch** 0.1.0

Release notes
=============

This snapshot of the OQS fork of OpenSSL 1.1.1 (`OQS-OpenSSL_1_1_1-stable`) was released on November 13, 2018.  Its release page on Github is https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2018-11.

What's New
----------

This is the first snapshot release of OQS-OpenSSL_1\_1\_1-stable.

It is based on the upstream OpenSSL 1.1.1 release.

It provides:

- post-quantum key exchange in TLS 1.3
- hybrid (post-quantum + elliptic curve) key exchange in TLS 1.3
- post-quantum authentication in TLS 1.3

Future work
-----------

Snapshot releases of OQS-OpenSSL_1\_1\_1-stable will be made approximately bi-monthly.  These will include syncing the branch with upstream releases of OpenSSL, and changes required to sync with new releases of liboqs.
