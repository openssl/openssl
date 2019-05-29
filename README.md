OQS-OpenSSL\_1\_1\_1-stable
==========================

[![CircleCI](https://circleci.com/gh/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable.svg?style=svg)](https://circleci.com/gh/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable)

---

**OpenSSL** ([https://openssl.org/](https://openssl.org/)) is an open-source TLS/SSL and crypto library.  (View the original [README file](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/README) for OpenSSL.)

This branch (OQS-OpenSSL\_1\_1\_1-stable) is a fork of OpenSSL 1.1.1 (currently in sync with the [OpenSSL_1_1_1c tag](https://github.com/openssl/openssl/tree/OpenSSL_1_1_1c)) that adds the following:

- post-quantum key exchange in TLS 1.3
- hybrid (post-quantum + elliptic curve) key exchange in TLS 1.3
- post-quantum authentication in TLS 1.3
- hybrid (post-quantum + elliptic curve) authentication in TLS 1.3

Overview
--------

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.  See more about liboqs at [https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/), including a list of supported algorithms. OpenSSL can use either the [master](https://github.com/open-quantum-safe/liboqs/tree/master) or the [nist](https://github.com/open-quantum-safe/liboqs/tree/nist-branch) branch of liboqs; the former is recommended for normal uses of OpenSSL as included mechanisms follow a stricter set of requirements, the latter contains more algorithms and is better suited for experimentation.

**OQS-OpenSSL\_1\_1\_1-stable** is an integration of liboqs into (a fork of) OpenSSL 1.1.1.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography in the TLS 1.3 protocol.  The integration should not be considered "production quality".

More information on OQS can be found on our website: [https://openquantumsafe.org/](https://openquantumsafe.org/).

Contents of branch OQS-OpenSSL\_1\_1\_1-stable
----------------------------------------------

This branch ([OQS-OpenSSL\_1\_1\_1-stable branch](https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable)) integrates post-quantum key exchange from liboqs in TLS 1.3 in OpenSSL v1.1.1.  

(For TLS 1.2, see the [OQS-OpenSSL\_1\_0\_2-stable](https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_0_2-stable) branch.)

### Key exchange mechanisms

The following key exchange / key encapsulation mechanisms from liboqs are supported (assuming they have been enabled in liboqs):

- `oqs_kem_default`: this special mechanisms uses the liboqs's default configured scheme. This is useful to test schemes not yet directly supported by OpenSSL.
- `bike1l1`, `bike1l3`, `bike1l5`, `bike2l1`, `bike2l3`, `bike2l5`, `bike3l1`, `bike3l3`, `bike3l5` (not currently on Windows)
- `frodo640aes`, `frodo640cshake`, `frodo976aes`, `frodo976cshake`
- `newhope512cca`, `newhope1024cca`
- `sidh503`, `sidh751`
- `sike503`, `sike751`

The following additional mechanisms are supported only when using liboqs's nist-branch (assuming they have been enabled in liboqs):

- `kyber512`, `kyber768`, `kyber1024`
- `ledakem_C1_N02`, `ledakem_C1_N03`, `ledakem_C1_N04`, `ledakem_C3_N02`, `ledakem_C3_N03`, `ledakem_C3_N04`, `ledakem_C5_N02`
- `saber_light_saber` (not for hybrid), `saber_saber`, `saber_fire_saber`

Note that some mechanisms from the nist-branch have been disabled in OpenSSL because they use keys/ciphertexts too large for TLS 1.3.

### Authentication mechanisms

Authentication mechanisms are currently only enabled when using liboqs's master branch (due to the nist-branch's incompatible signature API). The following signature schemes from liboqs are supported (assuming they have been enabled in liboqs):

- `picnicL1FS`
- `qteslaI`, `qteslaIIIsize`, `qteslaIIIspeed` (not currently on Windows)

The following hybrid schemes are supported, using either the NIST P-256 curve or 3072-bit RSA for L1 schemes, or the NIST P-384 curve for L3 schemes:

- `p256_picnicL1FS`, `rsa3072_picnicL1FS`
- `p256_qteslaI`, `rsa3072_qteslaI`, `p384_qteslaIIIsize`, `p384_qteslaIIIspeed` (not currently on Windows)


Limitations and security
------------------------

liboqs and this integration into OpenSSL are designed for prototyping and evaluating quantum-resistant cryptography.  Security of proposed quantum-resistant algorithms may rapidly change as research advances, and may ultimately be completely insecure against either classical or quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms.  liboqs does not intend to "pick winners", and we strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying post-quantum cryptography.

We acknowledge that some parties may want to begin deploying post-quantum cryptography prior to the conclusion of the NIST standardization project.  We strongly recommend that any attempts to do make use of so-called **hybrid cryptography**, in which post-quantum public-key algorithms are used alongside traditional public key algorithms (like RSA or elliptic curves) so that the solution is at least no less secure than existing traditional cryptography.

liboqs and our integration into OpenSSL is provided "as is", without warranty of any kind.  See [LICENSE.txt](https://github.com/open-quantum-safe/liboqs/blob/master/LICENSE.txt) for the full disclaimer.

The integration of liboqs into our fork of OpenSSL is currently at an experimental stage, and has not received significant review.  At this stage, we do not recommend relying on it in any production environment or to protect any sensitive data.

The OQS fork of OpenSSL is not endorsed by the OpenSSL project.

Proofs of TLS such as [[JKSS12]](https://eprint.iacr.org/2011/219) and [[KPW13]](https://eprint.iacr.org/2013/339) require a key exchange mechanism that has a form of active security, either in the form of the PRF-ODH assumption, or an IND-CCA KEM.  Some of the KEMs provided in liboqs do provide IND-CCA security; others do not, in which case existing proofs of security of TLS against active attackers do not apply.

Currently, this branch supports post-quantum and hybrid (traditional + post-quantum) key exchange and post-quantum-only authentication in TLS 1.3.  We intend to add support for hybrid authentication in TLS 1.3 and post-quantum/hybrid key exchange and authentication in TLS 1.2.

Lifecycle for OQS-OpenSSL\_1\_1\_1-stable
-----------------------------------------

**Release cycle:** We aim to make releases of OQS-OpenSSL\_1\_1\_1-stable on a bi-monthly basis, either when there has been a new release of OpenSSL 1.1.1 or when we have made changes to our fork.

See the README.md files of [liboqs master branch](https://github.com/open-quantum-safe/liboqs/blob/master/README.md) and [liboqs nist-branch](https://github.com/open-quantum-safe/liboqs/blob/nist-branch/README.md) for information about the algorithm lifecycle within the corresponding libraries.

**TLS compatibility:** The ciphersuite numbers and message formats used for post-quantum and hybrid key exchange and authentication are experimental, and may change between releases of OQS-OpenSSL\_1\_1\_1-stable.

Building on Linux and macOS
---------------------------

Builds have been tested manually on macOS 10.14 (clang 10.0.0), Ubuntu 14.04 (gcc-5), Ubuntu 16.04 (gcc-5), and Ubuntu 18.04.1 (gcc-7).

### Step 0: Install dependencies

For **Ubuntu**, you need to install the following packages:

	sudo apt install autoconf automake gcc libtool libssl-dev make unzip xsltproc

For **macOS**, you need to install the following packages using brew (or a package manager of your choice):

	brew install autoconf automake libtool openssl wget

### Step 1: Download fork of OpenSSL

Clone or download the source from Github:

	git clone --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git

### Step 2: Build liboqs

You can use the either the [master](https://github.com/open-quantum-safe/liboqs/tree/master) or the [nist](https://github.com/open-quantum-safe/liboqs/tree/nist-branch) branch of liboqs with the OQS-OpenSSL\_1\_1\_1-stable branch. Each branch support a different set of KEX/KEM mechanisms (see above), and authentication is currently only supported with the master branch.

The following instructions will download and build liboqs, then install it into a subdirectory inside the OpenSSL folder.

For the **master branch**:

	git clone --branch master https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	autoreconf -i
	./configure --prefix=<path-to-openssl-dir>/oqs --enable-shared=no --enable-openssl --with-openssl-dir=<path-to-system-openssl-dir>
	make -j
	make install

On **Ubuntu**, `<path-to-system-openssl-dir>` is probably `/usr`.  On **macOS** with brew, `<path-to-system-openssl-dir>` is probably `/usr/local/opt/openssl`.

For the **nist branch**:

	git clone --branch nist-branch https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	make -j
	make install-noshared PREFIX=<path-to-openssl-dir>/oqs

### Step 3: Build fork of OpenSSL

Now we follow the standard instructions for building OpenSSL.

For **Ubuntu**:

	cd <path-to-openssl-dir>
	./Configure no-shared linux-x86_64 -lm
	make -j

For **macOS**:

	cd <path-to-openssl-dir>
	./Configure no-shared darwin64-x86_64-cc
	make -j

The OQS fork of OpenSSL can also be built with shared libraries, but we have used `no-shared` in the instructions above to avoid having to get the shared libraries in the right place for the runtime linker.

Building on Windows
-------------------

Builds have been tested on Windows 10 (VS2017 build tools). Make sure you can build the unmodified version of OpenSSL by following the instructions in [INSTALL](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/INSTALL) and [NOTES.WIN](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/NOTES.WIN).

### Step 1: Download fork of OpenSSL

Clone or download the source from Github:

git clone --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git

### Step 2: Build liboqs

Next, you must download and build liboqs using the master branch of liboqs (the nist branch is not currently supported on Windows).  The following instructions will download (using git, alternatively, [download](https://github.com/open-quantum-safe/liboqs/archive/master.zip) and unzip the project) and build the x64 release configuration of liboqs, then copy the required files it into a subdirectory inside the OpenSSL folder.  You may need to install dependencies before building liboqs; see the [liboqs master branch README.md](https://github.com/open-quantum-safe/liboqs/blob/master/README.md).

	git clone --branch master https://github.com/open-quantum-safe/liboqs.git
	msbuild liboqs\VisualStudio\liboqs.sln /p:Configuration=Release;Platform=x64
	mkdir openssl\oqs
	mkdir openssl\oqs\lib
	mkdir openssl\oqs\include
	xcopy liboqs\VisualStudio\x64\Release\oqs.lib openssl\oqs\lib\
	xcopy /S liboqs\VisualStudio\include openssl\oqs\include\

### Step 3: Build fork of OpenSSL

Now we follow the standard instructions for building OpenSSL, for example:

	perl Configure VC-WIN64A
	nmake

Running
-------

See the [liboqs documentation](https://github.com/open-quantum-safe/liboqs/) for information on test programs in liboqs.

### TLS demo

OpenSSL contains a basic TLS server (`s_server`) and TLS client (`s_client`) which can be used to demonstrate and test SSL/TLS connections.

To run a server, you first need to generate a X.509 certificate, using either a classical (`rsa`), post-quantum (`picnicl1fs`, `qteslaI`, `qteslaIIIsize`, `qteslaIIIspeed`), or hybrid (`p256_picnicl1fs`, `rsa3072_picnicl1fs`, `p256_qteslaI`, `rsa3072_qteslaI`, `p384_qteslaIIIsize`, `p384_qteslaIIIspeed`) algorithm. The server certificate can either be self-signed or part of a chain. In either case, you need to generate a self-signed root CA certificate using the following command, replacing `<SIGALG>` with one supported algorithm:

	apps/openssl req -x509 -new -newkey <SIGALG> -keyout <SIGALG>_CA.key -out <SIGALG>_CA.crt -nodes -subj "/CN=oqstest CA" -days 365 -config apps/openssl.cnf

If you want an ECDSA certificate (`<SIGALG>` = `ecdsa`), you instead need to use:

	apps/openssl req -x509 -new -newkey ec:<(apps/openssl ecparam -name secp384r1) -keyout <SIGALG>_CA.key -out <SIGALG>_CA.crt -nodes -subj "/CN=oqstest" -days 365 -config apps/openssl.cnf

The root CA certificate can be used directly to start the server (see below), or can be used to issue a server certificate, using the usual OpenSSL process (note that for simplicity, we use the same algorithm for the server and CA certificates; in practice the CA is likely to use a stronger one):

1. The server generates its key pair:

		apps/openssl genpkey -algorithm <SIGALG> -out <SIGALG>_srv.key

2. The server generates a certificate request and sends it the to CA:

		apps/openssl req -new -newkey <SIGALG> -keyout <SIGALG>_srv.key -out <SIGALG>_srv.csr -nodes -subj "/CN=oqstest server" -config apps/openssl.cnf

3. The CA generates the signed server certificate:

		apps/openssl x509 -req -in <SIGALG>_srv.csr -out <SIGALG>_srv.crt -CA <SIGALG>_CA.crt -CAkey <SIGALG>_CA.key -CAcreateserial -days 365

To run a basic TLS server with all OQS ciphersuites enabled, run the following command, replacing `<SERVER>` with either `<SIGALG>_CA` or `<SIGALG>_srv`:

	apps/openssl s_server -cert <SERVER>.crt -key <SERVER>.key -www -tls1_3

In another terminal window, you can run a TLS client requesting one of the supported ciphersuites (`<KEXALG>` = one of the key exchange mechanisms listed above) or the hybrid ciphersuites (`p256-<KEXALG>`, only the NIST p256 curve in combination with L1 PQC KEM schemes are supported for now):

	apps/openssl s_client -curves <KEXALG> -CAfile <SIGALG>_CA.crt -connect localhost:4433

Integration tests
-----------------

Integration tests are available under the `oqs_test` directory; see the [README.md](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/oqs_test/README.md) for details on how to run the tests locally.

Contributing
------------

Follow these steps to add additional key exchange and signature algorithms from liboqs.

One goal is to minimize the OQS footprint into the OpenSSL code, to improve readability. Therefore, some redundant code is implemented using macros to avoid creating functions and registering them in OpenSSL.

### Adding a key exchange algorithm

The TLS 1.3 key exchange integration is done at the TLS layer (start looking in `ssl/statem/extensions_(clnt,srvr).c`). It would have been nice to integrate in the crypto EVP layer, but it wasn't possible given the asymmetric nature of the KEM API (genkey, encrypt, decrypt) and the lack of role context when the Diffie-Hellman EVP functions are invoked. To add a new algorithm, run `grep -r ADD_MORE_OQS_KEM_HERE` and add new code following the example of other OQS schemes.

### Adding an authentication mechanism

To add a new algorithm <NEWALG> with OID <NEWOID>:

1. Define `<NEWOID>` in `crypto/objects/objects.txt`, add `<NEWALG>` to `crypto/objects/obj_mac.num`, incrementing the last NID value, and run `make generate_crypto_objects` to re-generate objects-related files (`obj_dat.h`, `obj_mac.num`, `obj_mac.h`)
2. Run `grep -r ADD_MORE_OQS_SIG_HERE` and add new code following the example of other OQS schemes.

License
-------

All modifications in the open-quantum-safe/openssl repository are released under the same terms as OpenSSL, namely as described in the file [LICENSE](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/LICENSE).

Team
----

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

### Contributors

Contributors to open-quantum-safe/openssl branch OQS-OpenSSL\_1\_1\_1-stable include:

- Christian Paquin (Microsoft Research)
- Douglas Stebila (University of Waterloo)

### Support

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Tutte Institute for Mathematics and Computing.  

We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, evolutionQ, and Microsoft Research.  

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see the source papers for funding acknowledgments.
