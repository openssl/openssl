Description
===========

The OpenSSL Project is a collaborative effort to develop a robust,
commercial-grade, fully featured, and Open Source toolkit implementing the
Transport Layer Security (TLS) protocols (including SSLv3) as well as a
full-strength general purpose cryptographic library.

OpenSSL is descended from the SSLeay library developed by Eric A. Young
and Tim J. Hudson.

The OpenSSL toolkit is licensed under the Apache License 2.0, which means
that you are free to get and use it for commercial and non-commercial
purposes as long as you fulfill its conditions.

Overview
========

The OpenSSL toolkit includes:

 * **libssl**
     Provides the client and server-side implementations for SSLv3 and TLS.

 * **libcrypto:**
     Provides general cryptographic and X.509 support needed by SSL/TLS but
     not logically part of it.

 * **openssl:**
     A command line tool that can be used for:
        Creation of key parameters
        Creation of X.509 certificates, CSRs and CRLs
        Calculation of message digests
        Encryption and decryption
        SSL/TLS client and server tests
        Handling of S/MIME signed or encrypted mail
        And more...

Installation
============

See the appropriate file:

 * [INSTALL](INSTALL): General installation instructions for all platforms
 * Additional instructions for specific platforms
    * [NOTES.ANDROID](NOTES.ANDROID)
    * [NOTES.DJGPP](NOTES.DJGPP)
    * [NOTES.PERL](NOTES.PERL)
    * [NOTES.UNIX](NOTES.UNIX)
    * [NOTES.VALGRIND](NOTES.VALGRIND)
    * [NOTES.VMS](NOTES.VMS)
    * [NOTES.WIN](NOTES.WIN)

Support
=======

See the OpenSSL website www.openssl.org for details on how to obtain
commercial technical support. Free community support is available through the
openssl-users email list (see
https://www.openssl.org/community/mailinglists.html for further details).

If you have any problems with OpenSSL then please take the following steps
first:

 - Download the latest version from the repository
   to see if the problem has already been addressed
 - Configure with no-asm
 - Remove compiler optimization flags

If you wish to report a bug then please include the following information
and create an issue on GitHub:

 - OpenSSL version: output of 'openssl version -a'
 - Configuration data: output of 'perl configdata.pm --dump'
 - OS Name, Version, Hardware platform
 - Compiler Details (name, version)
 - Application Details (name, version)
 - Problem Description (steps that will reproduce the problem, if known)
 - Stack Traceback (if the application dumps core)

Just because something doesn't work the way you expect does not mean it
is necessarily a bug in OpenSSL. Use the openssl-users email list for this type
of query.

How to contribute to OpenSSL
============================

 See [CONTRIBUTING](CONTRIBUTING.md)

 Legalities
 ==========

 A number of nations restrict the use or export of cryptography. If you
 are potentially subject to such restrictions you should seek competent
 professional legal advice before attempting to develop or distribute
 cryptographic code.


Copyright
=========

Copyright (c) 1998-2018 The OpenSSL Project

Copyright (c) 1995-1998 Eric A. Young, Tim J. Hudson

All rights reserved.
