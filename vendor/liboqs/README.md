[![Build Status](https://travis-ci.org/open-quantum-safe/liboqs.svg?branch=master)](https://travis-ci.org/open-quantum-safe/liboqs)
[![Build status](https://ci.appveyor.com/api/projects/status/9d2ts78x88r8wnii/branch/master?svg=true)](https://ci.appveyor.com/project/dstebila/liboqs/branch/master)

liboqs
======

liboqs is a C library for quantum-resistant cryptographic algorithms.

Overview
--------

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.  liboqs initially focuses on key exchange algorithms.  liboqs provides a common API suitable for post-quantum key exchange algorithms, and will collect together various implementations.  liboqs will also include a test harness and benchmarking routines to compare performance of post-quantum implementations.

OQS will also include integrations into application-level protocols to provide easy prototyping of quantum-resistant cryptography.  Our first integration is in OpenSSL:

- **open-quantum-safe/openssl** is an integration of liboqs into OpenSSL 1.0.2.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".  See more about this integration in its GitHub repository [open-quantum-safe/openssl/](https://github.com/open-quantum-safe/openssl/).

More information on OQS can be found on our website: [https://openquantumsafe.org/](https://openquantumsafe.org/).

Contents
--------

liboqs currently contains:

- `kex_rlwe_bcns15`: key exchange from the ring learning with errors problem (Bos, Costello, Naehrig, Stebila, *IEEE Symposium on Security & Privacy 2015*, [https://eprint.iacr.org/2014/599](https://eprint.iacr.org/2014/599))
- `kex_rlwe_newhope`: "NewHope": key exchange from the ring learning with errors problem (Alkim, Ducas, Pöppelmann, Schwabe, *USENIX Security 2016*, [https://eprint.iacr.org/2015/1092](https://eprint.iacr.org/2015/1092)) (using the reference C implementation of NewHope from [https://github.com/tpoeppelmann/newhope](https://github.com/tpoeppelmann/newhope))
- `kex_rlwe_msrln16`: Microsoft Research implementation of Peikert's ring-LWE key exchange (Longa, Naehrig, *CANS 2016*, [https://eprint.iacr.org/2016/504](https://eprint.iacr.org/2016/504)) (based on the implementation of Alkim, Ducas, Pöppelmann, and Schwabe, with improvements from Longa and Naehrig, see [https://www.microsoft.com/en-us/research/project/lattice-cryptography-library/](https://www.microsoft.com/en-us/research/project/lattice-cryptography-library/))
- `kex_lwe_frodo`: "Frodo": key exchange from the learning with errors problem (Bos, Costello, Ducas, Mironov, Naehrig, Nikolaenko, Raghunathan, Stebila, *ACM Conference on Computer and Communications Security 2016*, [https://eprint.iacr.org/2016/659](https://eprint.iacr.org/2016/659))
- `kex_sidh_cln16`: key exchange from the supersingular isogeny Diffie-Hellman problem (Costello, Naehrig, Longa, *CRYPTO 2016*, [https://eprint.iacr.org/2016/413](https://eprint.iacr.org/2016/413)), using the implementation of Microsoft Research [https://www.microsoft.com/en-us/research/project/sidh-library/](https://www.microsoft.com/en-us/research/project/sidh-library/)
- `kex_sidh_iqc_ref`: key exchange from the supersingular isogeny Diffie-Hellman problem (De Feo, Jao, Plût, *J. Math. Cryptol.* 8(3):209, 2014, [https://eprint.iacr.org/2011/506](https://eprint.iacr.org/2011/506)), using a reference implementation by Javad Doliskani
- `kex_code_mcbits`: "McBits": key exchange from the error correcting codes, specifically Niederreiter's form of McEliece public key encryption using hidden Goppa codes (Bernstein, Chou, Schwabe, *CHES 2013*, [https://eprint.iacr.org/2015/610](https://eprint.iacr.org/2015/610)), using the implementation of McBits from [https://www.win.tue.nl/~tchou/mcbits/](https://www.win.tue.nl/~tchou/mcbits/))
- `kex_ntru`: NTRU: key transport using NTRU public key encryption (Hoffstein, Pipher, Silverman, *ANTS 1998*) with the EES743EP1 parameter set, wrapper around the implementation from the NTRU Open Source project [https://github.com/NTRUOpenSourceProject/NTRUEncrypt](https://github.com/NTRUOpenSourceProject/NTRUEncrypt))
- `kex_mlwe_kyber`: Kyber: a CCA-secure module-lattice-based key exchange mechanism (Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schwabe, Shanck, Stehlé, *Real World Crypto 2017*, [https://eprint.iacr.org/2017/634](https://eprint.iacr.org/2017/634)), using the reference C implementation of Kyber from [pq-crystals/kyber](https://github.com/pq-crystals/kyber)
- `sig_picnic`: signature based on zero-knowledge proof as specified in Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives (Melissa Chase and David Derler and Steven Goldfeder and Claudio Orlandi and Sebastian Ramacher and Christian Rechberger and Daniel Slamanig and Greg Zaverucha, [https://eprint.iacr.org/2017/279.pdf](https://eprint.iacr.org/2017/279.pdf))

Building and Running on Linux and macOS
---------------------------------------

Builds have been tested on Mac OS X 10.11.6, macOS 10.12.5, Ubuntu 16.04.1.

### Install dependencies for macOS

You need to install `autoconf`, `automake` and `libtool`:

	brew install autoconf automake libtool

### Install dependencies for Ubuntu

You need to install autoconf, automake and libtool:

	sudo apt install autoconf automake libtool

### Building

To build, clone or download the source from GitHub, then simply type:

	autoreconf -i
	./configure
	make clean
	make

This will generate:

- `liboqs.a`: A static library with implementations for the algorithms listed in "Contents" above.
- `test_rand`: A simple test harness for the random number generator.  This will test the distance of PRNG output from uniform using statistical distance.
- `test_aes`: A simple test harness for AES.  This will test the correctness of the C implementation (and of the AES-NI implementation, if not disabled) of AES, and will compare the speed of these implementations against OpenSSL's AES implementation.
- `test_kex`: A simple test harness for the default key exchange algorithm.  This will output key exchange messages; indicate whether the parties agree on the session key or not over a large number of trials; and measure the distance of the sessions keys from uniform using statistical distance.
- `test_sig`: A simple test harness for the signature algorithms.

### Running

To run the tests, simply type:

	make test

To run benchmarks, run

	./test_kex --bench

To run benchmark only on some ciphers, run

	./test_kex --help

to list the available ciphers and then run e.g.

	./test_kex --bench rlwe_bcns15 rlwe_newhope

### Additional build options

#### Building with OpenSSL algorithms enabled:

OpenSSL can be used for some symmetric crypto algorithms, which may result in better performance.

To build with OpenSSL enabled:

	./configure --enable-openssl
	make clean
	make

You may need to specify the path to your OpenSSL directory:

	./configure --enable-openssl --with-openssl-dir=/path/to/openssl/directory
	make clean
	make

### Building with `kex_sidh_iqc_ref` enabled

The `kex_sidh_iqc_ref ` key exchange method is not enabled by default since it requires an external library (libgmp).

To install the library on macOS:

	brew install gmp

To build with `kex_sidh_iqc_ref ` enabled:

	./configure --enable-sidhiqc
	make clean
	make

You may need to specify the path to your libgmp directory:

	./configure --enable-sidhiqc --with-gmp-dir=/path/to/gmp/directory
	make clean
	make

### Building with `kex_code_mcbits` enabled

The `kex_code_mcbits` key exchange method is not enabled by default since it requires an external library (libsodium).

To install the library on macOS:

	brew install libsodium

To install the library on Ubuntu:

	sudo apt install libsodium-dev

To build with `kex_code_mcbits ` enabled:

	./configure --enable-mcbits
	make clean
	make

### Building with the following KEX algorithms disabled

  ./configure --disable-kex-ntru --disable-kex-lwe-frodo --disable-kex-mlwe-kyber --disable-kex-rlwe-msrln16  --disable-kex-rlwe-newhope --disable-kex-sidh-cln16
  make clean
  make

### Building with `sig_picnic` enabled

The `sig_picnic` signature algorithm is not enabled by default since it requires:

- external libraries (`openssl` and `m4ri`);
- to download and setup Picnic;
- a parameters generation preprocessing step.

To install the libraries on macOS:

	brew install openssl homebrew/science/m4ri

To install the libraries on Ubuntu:

	sudo apt install libssl-dev libm4ri-dev

To download the Picnic source code:

	./download-and-setup-picnic.sh

To build with `sig_picnic` enabled:

	./configure --enable-picnic --enable-openssl [--with-openssl-dir=<..> --with-m4r-dir=<..>]
	make clean
	make
	make test   (this generates data needed by the Picnic library)

Building and running on Windows
-------------------------------

Windows binaries can be generated using the Visual Studio solution in the VisualStudio folder.  Builds have been tested on Windows 10.

McBits is disabled by default in the Visual Studio build; follow these steps to enable it:

- Obtain the [libsodium library](https://libsodium.org); compile the static library from the Visual Studio projects.
- Add `ENABLE_CODE_MCBITS` and `SODIUM_STATIC` to the preprocessor definitions of the `oqs` and `test_kex` projects.
- Add the sodium "src/include" location to the "Additional Include Directories" in the oqs project C properties.
- Add the libsodium library to the "Additional Dependencies" in the `test_kex` project Linker properties.

Documentation
-------------

The directory `docs/Algorithm data sheets` contains information about some of the algorithms supported by liboqs.

### Doxygen documentation

Some source files contain inline Doxygen-formatted comments which can be used to generate additional documentation.

On macOS, you may need to install several dependencies first:

	brew install doxygen graphviz

The documentation can be generated by running:

	make docs

This will generate the `docs/doxygen/html` directory.  Check `./configure --help` for generating other formats.

Contributing and using
----------------------

We hope OQS will provide a framework for many post-quantum implementations.

In the immediate term, if you have feedback on our API ([kex.h](https://github.com/open-quantum-safe/liboqs/blob/master/src/kex/kex.h), [sig.h](https://github.com/open-quantum-safe/liboqs/blob/master/src/sig/sig.h) or [rand.h](https://github.com/open-quantum-safe/liboqs/blob/master/src/rand/rand.h)), please contact us so we can ensure our API covers a wide range of implementation needs.

If you have or are writing an implementation of a post-quantum key exchange algorithm, we hope you will consider making an implementation that meets our API so that others may use it and would be happy to discuss including it directly in liboqs.  Please take a look at our [coding conventions](https://github.com/open-quantum-safe/liboqs/wiki/Coding-conventions).

If you would like to use liboqs in an application-level protocol, please get in touch and we can provide some guidance on options for using liboqs.

We are also interested in assistance from code reviewers.

Please contact Douglas Stebila <[stebilad@mcmaster.ca](mailto:stebilad@mcmaster.ca)>.

License
-------

liboqs is licensed under the MIT License; see [LICENSE.txt](https://github.com/open-quantum-safe/liboqs/blob/master/LICENSE.txt) for details.  liboqs includes some third party libraries or modules that are licensed differently; the corresponding subfolder contains the license that applies in that case.  In particular:

- `src/crypto/aes/aes_c.c`: public domain
- `src/crypto/rand_urandom_chacha20/external`: public domain
- `src/kex_code_mcbits`: public domain
- `src/kex_mlwe_kyber`: public domain
- `src/kex_rlwe_bcns15`: public domain ([Unlicense](http://unlicense.org))
- `src/kex_rlwe_msrln16`: MIT License
- `src/kex_rlwe_msrln16/external`: public domain ([CC0](http://creativecommons.org/publicdomain/zero/1.0/))
- `src/kex_rlwe_newhope`: public domain
- `src/kex_sidh_cln16`: MIT License
- `src/kex_sidh_iqc_ref`: MIT License
- `src/sig_picnic`: MIT License

Team
----

The Open Quantum Safe project is lead by [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) (University of Waterloo) and [Douglas Stebila](https://www.douglas.stebila.ca/research/) (McMaster University).

### Contributors

- Javad Doliskani (University of Waterloo)
- Tancrède Lepoint (SRI International)
- Shravan Mishra (University of Waterloo)
- Christian Paquin (Microsoft Research)
- Alex Parent (University of Waterloo)
- Sebastian Verschoor (University of Waterloo)

### Support

Development of Open Quantum Safe has been supported in part by the Tutte Institute for Mathematics and Computing.  Research projects which developed specific components of Open Quantum Safe have been supported by various research grants; see the source papers for funding acknowledgments.
