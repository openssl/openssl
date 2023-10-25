The OpenSSL Guide Demos
=======================

The demos in this directory are the complete source code for the applications
developed in the OpenSSL Guide tutorials. Refer to the various tutorial pages in
the [guide] for an extensive discussion on the demos available here.

To run the demos when linked with a shared library (default) ensure that
libcrypto and libssl are on the library path. For example, assuming you have
already built OpenSSL from this source and in the default location then to run
the tls-client-block demo do this:

LD_LIBRARY_PATH=../.. ./tls-client-block

[guide]: https://www.openssl.org/docs/manmaster/man7/ossl-guide-introduction.html
