open-quantum-safe/openssl
=========================

OpenSSL is an open-source TLS/SSL and crypto library [https://openssl.org/](https://openssl.org/).  ([View the original README file for OpenSSL](https://github.com/open-quantum-safe/openssl/blob/master/README).)

This repository contains a fork of OpenSSL that adds quantum-safe cryptographic algorithms and ciphersuites.

OQS REVIEW NOTES:
 * This is an experimental integration of OQS into TLS 1.3.
 * Currently, only PQC and hybrid (classical+PQC) KEX in TLS 1.3 are supported. Next in line: auth, hybrid auth, and TLS 1.2.
 * One goal is to minimize the OQS footprint into the OpenSSL code, to improve readability. Therefore, some redundant code is implemented using macros to avoid creating functions and registrating them in OpenSSL.
 * The TLS 1.3 integration is done at the TLS layer (start looking in ssl/statem/extensions_(clnt,srvr).c). It would have been nice to integrate in the crypto EVP layer, but it wasn't possible given the KEM asymetric API (genkey, encrypt, decrypt) and the lack of role context when the Diffie-Hellman EVP functions are invoked.
 * If you have an oqs-related build error, try building it manually, and re-run openssl's make:
   - cd vendor/liboqs
   - autoreconf -i
   - ./configure --enable-shared
   - make
   - cd ../..
   - make

Overview
--------

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  

**liboqs** is an open source C library for quantum-safe cryptographic algorithms.  See more about liboqs at [https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/), including a list of supported algorithms.

**open-quantum-safe/openssl** is an integration of liboqs into OpenSSL 1.1.1.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

More information on OQS can be found on our website: [https://openquantumsafe.org/](https://openquantumsafe.org/).

Contents
--------

This project integrates post-quantum key exchange from liboqs in TLS 1.3 in OpenSSL v1.1.1, and appear only on the [master branch](https://github.com/open-quantum-safe/openssl/tree/master). For TLS 1.2, see the [OpenSSL\_1\_0\_2-stable branch](https://github.com/open-quantum-safe/openssl/tree/OpenSSL_1_0_2-stable).

### Key exchange mechanisms

Currently, only Frodo, Sike503, Sike751, Newhope, and NTRU are supported. Others will be added when OQS is updated.


### Authentication mechanisms

TODO: add them

Building
--------

Builds have been tested on Ubuntu 16.04.1.

### Linux and macOS

To build, clone or download the source from Github:

	git clone --branch master https://github.com/open-quantum-safe/openssl.git
	cd openssl

To configure OpenSSL, on Linux type:

	./config
	
and on Mac OS X type:

	./Configure darwin64-x86_64-cc
	
Then type:
	make
	
This will build both liboqs and OpenSSL.  

Running
-------

See the [liboqs Github site](https://github.com/open-quantum-safe/liboqs/) for information on test programs in liboqs.

### TLS demo

OpenSSL contains a basic TLS server (`s_server`) and TLS client (`s_client`) which can be used to demonstrate and test SSL/TLS connections.

To run a server, we first need to generate a self-signed X.509 certificate.  Run the following command:

	apps/openssl req -x509 -new -newkey rsa:2048 -keyout rsa.key -nodes -out rsa.crt -sha256 -days 365 -config apps/openssl.cnf

Hit enter in response to all the prompts to accept the defaults.  

When done, type to combine the key and certificate (as required by `s_server`):

	cat server.key server.cer > server.pem

To run a basic TLS server with all OQS ciphersuites enabled:

	apps/openssl s_server -cert rsa.crt -key rsa.key -HTTP -tls1_3

In another terminal window, you can run a TLS client for any or all of the supported ciphersuites (<OQSALG> = newhope, frodo, sike503, sike751, ntru) or the hybrid ciphersuites ("p256-<OQSALG>", only the NIST p256 curve is supported for now), for example:

        apps/openssl s_client -curves p256-frodo -connect localhost:4433

License
-------

All modifications in the open-quantum-safe/openssl repository are released under the same terms as OpenSSL, namely as described in the file [LICENSE](https://github.com/open-quantum-safe/openssl/blob/master/LICENSE).  

Team
----

The Open Quantum Safe project is lead by [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) (University of Waterloo) and [Douglas Stebila](https://www.douglas.stebila.ca/research/) (McMaster University).

### Support

Development of Open Quantum Safe has been supported in part by the Tutte Institute for Mathematics and Computing.  Research projects which developed specific components of Open Quantum Safe have been supported by various research grants; see the source papers for funding acknowledgements.

### Contributors

Contributors to the liboqs fork of OpenSSL include:

- Christian Paquin (Microsoft Research)