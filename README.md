open-quantum-safe/openssl
=========================

OpenSSL is an open-source TLS/SSL and crypto library [https://openssl.org/](https://openssl.org/).  ([View the original README file for OpenSSL](https://github.com/open-quantum-safe/openssl/blob/master/README).)

This repository contains a fork of OpenSSL that adds quantum-safe cryptographic algorithms and ciphersuites.

OQS REVIEW NOTES:
 * This is an experimental integration of OQS into TLS 1.3.
 * Currently, PQC and hybrid (classical+PQC) KEX and PQC auth in TLS 1.3 are supported. Further down the line: hybrid auth, and TLS 1.2.
 * One goal is to minimize the OQS footprint into the OpenSSL code, to improve readability. Therefore, some redundant code is implemented using macros to avoid creating functions and registrating them in OpenSSL.
 * The TLS 1.3 KEX integration is done at the TLS layer (start looking in ssl/statem/extensions_(clnt,srvr).c). It would have been nice to integrate in the crypto EVP layer, but it wasn't possible given the KEM asymetric API (genkey, encrypt, decrypt) and the lack of role context when the Diffie-Hellman EVP functions are invoked.

Overview
--------

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  

**liboqs** is an open source C library for quantum-safe cryptographic algorithms.  See more about liboqs at [https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/), including a list of supported algorithms.

**open-quantum-safe/openssl** is an integration of liboqs into OpenSSL 1.1.1.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

More information on OQS can be found on our website: [https://openquantumsafe.org/](https://openquantumsafe.org/).

Contents
--------

This project integrates post-quantum key exchange from liboqs in TLS 1.3 in OpenSSL v1.1.1, and appear only on the [master branch](https://github.com/open-quantum-safe/openssl/tree/OQS-master). For TLS 1.2, see the [OpenSSL\_1\_0\_2-stable branch](https://github.com/open-quantum-safe/openssl/tree/OpenSSL_1_0_2-stable) and [OQS-OpenSSL\_1\_0\_2-stable branch](https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_0_2-stable).

### Key exchange mechanisms

Currently, only Frodo, Sike503, Sike751, Newhope, and NTRU are supported. Others will be added when OQS is updated.

### Authentication mechanisms

Currently, only picnicL1FS, qteslaI, qteslaIIIsize, qteslaIIIspeed are supported. Others will be added when OQS is updated.

Building on Linux and macOS
---------------------------

Builds have been tested on macOS 10.13.3 (clang), Ubuntu 14.04.5 (gcc-7).

### Step 1: Download fork of OpenSSL

Clone or download the source from Github:

    git clone --branch master https://github.com/open-quantum-safe/openssl.git

### Step 2: Build liboqs

Next, you must download and build liboqs.  You must use a version of liboqs that uses the old liboqs API, such as the liboqs master branch as of May 2018. (This project will be updated once the new KEM API in integrated in liboqs's master branch.( 

Follow the instructions there to download and build that branch of liboqs and install into a subdirectory inside the OpenSSL folder.

    git clone --branch master https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    autoreconf -i
    ./configure --prefix=<path-to-openssl-dir>/oqs
    make
    make install

This will create a directory `oqs` in your newly download OpenSSL directory, with subdirectories `include` and `lib` containing the headers and library files of liboqs.

### Step 3: Build fork of OpenSSL

Now we follow the standard instructions for building OpenSSL.

To configure OpenSSL, on Linux type:

    ./config

and on macOS type:

    ./Configure darwin64-x86_64-cc

Then type:

	make
		
Running
-------

See the [liboqs Github site](https://github.com/open-quantum-safe/liboqs/) for information on test programs in liboqs.

### TLS demo

OpenSSL contains a basic TLS server (`s_server`) and TLS client (`s_client`) which can be used to demonstrate and test SSL/TLS connections.

To run a server, we first need to generate a self-signed X.509 certificate, using either a classical or post-quantum algorithm. Run the following command, with <SIGALG> = rsa, picnicl1fs, qteslaI, qteslaIIIsize, qteslaIIIspeed):

	apps/openssl req -x509 -new -newkey <SIGALG> -keyout <SIGALG>.key -out <SIGALG>.crt -nodes -subj "/CN=oqstest" -days 365 -config apps/openssl.cnf
	
On macOS, you may need to set an environment variable for the dynamic library path:

	DYLD_LIBRARY_PATH=<path-to-openssl>
	export DYLD_LIBRARY_PATH

To run a basic TLS server with all OQS ciphersuites enabled:

	apps/openssl s_server -cert <SIGALG>.crt -key <SIGALG>.key -HTTP -tls1_3

In another terminal window, you can run a TLS client for any or all of the supported ciphersuites (<KEXALG> = newhope, frodo, sike503, sike751, ntru) or the hybrid ciphersuites ("p256-<KEXALG>", only the NIST p256 curve is supported for now), for example:

    apps/openssl s_client -curves <KEXALG> -connect localhost:4433

Contributing
------------

Follow these steps to add additional key exchange and signature algorithms from liboqs.

### Adding a key exchange algorithm

FIXMEOQS: explain this

### Adding an authentication mechanism

To add a new algorithm <NEWALG> with OID <NEWOID>:

 1. Define <NEWOID> in crypto/objects/objects.txt, add <NEWALG> to crypto/objects/obj_mac.num,
    incrementing the last NID value, and Run "make generate_crypto_objects" to re-generate
    objects-related files (obj_dat.h, obj_mac.num, obj_mac.h)
 2. Run "grep -r ADD_MORE_OQS_SIG_HERE" and add new code following the example of other
    OQS schemes.

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
