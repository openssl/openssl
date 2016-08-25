# open-quantum-safe/openssl

OpenSSL is an open-source TLS/SSL and crypto library [https://openssl.org/](https://openssl.org/).  ([View the original README file for OpenSSL](https://github.com/open-quantum-safe/openssl/blob/OpenSSL_1_0_2-stable/README).)

This repository contains a fork of OpenSSL that adds quantum-safe cryptographic algorithms and ciphersuites.

## Overview

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  

**liboqs** is an open source C library for quantum-safe cryptographic algorithms.  liboqs initially focuses on key exchange algorithms.  See more about liboqs at [https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/), including a list of supported algorithms.

**open-quantum-safe/openssl** is an integration of liboqs into OpenSSL 1.0.2.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

More information on OQS can be found in slides 64–67 of [this presentation](https://www.douglas.stebila.ca/files/research/presentations/20160812-SAC.pdf) by Douglas Stebila.

## Contents

open-quantum-safe/openssl currently contains:

- Integration of post-quantum key exchange primitives from liboqs into OpenSSL's `speed` command
- Ciphersuites using post-quantum key exchange based on primitives from liboqs, including hybrid ciphersuites which also use ECDHE key exchange

### Key exchange mechanisms

liboqs currently supports the following key exchange mechanisms:

- `RLWE_BCNS15`: key exchange from the ring learning with errors problem (Bos, Costello, Naehrig, Stebila, *IEEE Symposium on Security & Privacy 2015*, [https://eprint.iacr.org/2014/599](https://eprint.iacr.org/2014/599))

### Ciphersuites

For each post-quantum key exchange primitive `X`, there are the following ciphersuites:

- `X-RSA-AES128-GCM-SHA256`
- `X-ECDSA-AES128-GCM-SHA256`
- `X-RSA-AES256-GCM-SHA384`
- `X-ECDSA-AES256-GCM-SHA384`
- `X-ECDHE-RSA-AES128-GCM-SHA256`
- `X-ECDHE-ECDSA-AES128-GCM-SHA256`
- `X-ECDHE-RSA-AES256-GCM-SHA384`
- `X-ECDHE-ECDSA-AES256-GCM-SHA384`

There is also a "generic" ciphersuite (`X` = `GENERIC`) which uses whichever key exchange primitive is configured as the default key exchange primitive in liboqs.  It is set to `GENERIC` = `RLWE_BCNS15`, but this can be changed.


## Building

Builds have been tested on Mac OS X 10.11.6 and Ubuntu 16.04.1.

To build, clone or download the source from Github:

	git clone --branch OpenSSL_1_0_2-stable --recursive https://github.com/open-quantum-safe/openssl.git
	cd openssl

To configure OpenSSL, on Linux type:

	./config
	
and on Mac OS X type:

	./Configure darwin64-x86_64-cc
	
Then type:

	make depend
	make
	
This will build both liboqs and OpenSSL.  

## Running

See the [liboqs Github site](https://github.com/open-quantum-safe/liboqs/) for information on test programs in liboqs.

### openssl speed

OpenSSL's `speed` command performs basic benchmarking of cryptographic primitives.  You can see results for primitives from liboqs by typing

	apps/openssl speed oqskex

### TLS demo

OpenSSL contains a basic TLS server (`s_server`) and TLS client (`s_client`) which can be used to demonstrate and test SSL/TLS connections.

To see the list of supported ciphersuites from OQS, type:

	apps/openssl ciphers OQSKEX-GENERIC:OQSKEX-GENERIC-ECDHE:OQSKEX-RLWE-BCNS15:OQSKEX-RLWE-BCNS15-ECDHE

To run a server, we first need to generate a self-signed X.509 certificate.  Run the following command:

	apps/openssl req -x509 -new -newkey rsa:2048 -keyout server.key -nodes -out server.cer -sha256 -days 365 -config apps/openssl.cnf

Hit enter in response to all the prompts to accept the defaults.  

When done, type to combine the key and certificate (as required by `s_server`):

	cat server.key server.cer > server.pem

To run a basic TLS server with all OQS ciphersuites enabled:

	apps/openssl s_server -cipher OQSKEX-GENERIC:OQSKEX-GENERIC-ECDHE:OQSKEX-RLWE-BCNS15:OQSKEX-RLWE-BCNS15-ECDHE

In another terminal window, you can run a TLS client for any or all of the supported ciphersuites, for example:

	apps/openssl s_client -cipher OQSKEX-GENERIC
	apps/openssl s_client -cipher OQSKEX-GENERIC-ECDHE
	apps/openssl s_client -cipher OQSKEX-RLWE-BCNS15
	apps/openssl s_client -cipher OQSKEX-RLWE-BCNS15-ECDHE

## Team

The Open Quantum Safe project is lead by [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) (University of Waterloo) and [Douglas Stebila](https://www.douglas.stebila.ca/research/) (McMaster University).

### Support

Development of Open Quantum Safe has been supported in part by the Tutte Institute for Mathematics and Computing.  Research projects which developed specific components of Open Quantum Safe have been supported by various research grants; see the source papers for funding acknowledgements.
