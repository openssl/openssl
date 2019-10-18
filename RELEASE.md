OQS-OpenSSL_1\_1\_1-stable snapshot 2019-11-dev
===========================================

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

This snapshot of the OQS fork of OpenSSL 1.1.1d (`OQS-OpenSSL_1_1_1-stable`) was released on TODO.  Its release page on Github is https://github.com/open-quantum-safe/openssl/releases/tag/OQS-OpenSSL_1_1_1-stable-snapshot-2019-11.

What's New
----------

This is the third snapshot release of OQS-OpenSSL_1\_1\_1-stable.  It is based on the upstream OpenSSL 1.1.1d release.

Update to use NIST Round 2 submissions added to liboqs 0.2.1.

### Key encapsulation mechanisms

- Update BIKE to Round 2 submission; removes `BIKE2-*`, `BIKE3-*`, `BIKE1-L5`, renames `BIKE1-L1` and `BIKE1-L3` to `BIKE1-L1-CPA` and `BIKE1-L3-CPA`, and adds `BIKE1-L1-FO` and `BIKE-L3-FO`

### Digital signature schemes

- TBA

Future work
-----------

Snapshot releases of OQS-OpenSSL_1\_1\_1-stable will be made approximately bi-monthly.  These will include syncing the branch with upstream releases of OpenSSL, and changes required to sync with new releases of liboqs.
