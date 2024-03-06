The OpenSSL Guide Demos
=======================

The demos in this directory are the complete source code for the applications
developed in the OpenSSL Guide tutorials. Refer to the various tutorial pages in
the [guide] for an extensive discussion on the demos available here.

They must be built before they can be run. An example UNIX style Makefile is
supplied. Just type "make" from this directory on a Linux/UNIX system.

Running the TLS Demos
---------------------

To run the demos when linked with a shared library (default) ensure that
libcrypto and libssl are on the library path. For example, assuming you have
already built OpenSSL from this source and in the default location then to run
the tls-client-block demo do this:

LD_LIBRARY_PATH=../.. ./tls-client-block hostname port

In the above replace "hostname" and "port" with the hostname and the port number
of the server you are connecting to.

The above assumes that your default trusted certificate store containing trusted
CA certificates has been properly setup and configured as described on the
[TLS Introduction] page.

You can run a test server to try out these demos using the "openssl s_server"
command line utility and using the test server certificate and key provided in
this directory. For example:

LD_LIBRARY_PATH=../.. ../../apps/openssl s_server -www -accept localhost:4443 -cert servercert.pem -key serverkey.pem

The test server certificate in this directory will use a CA that will not be in
your default trusted certificate store. The CA certificate to use is also
available in this directory. To use it you can override the default trusted
certificate store like this:

SSL_CERT_FILE=rootcert.pem LD_LIBRARY_PATH=../.. ./tls-client-block localhost 4443

If the above command is successful it will connect to the test "s_server" and
send a simple HTTP request to it. The server will respond with a page of
information giving details about the TLS connection that was used.

Note that the test server certificate used here is only suitable for use on
"localhost".

The tls-client-non-block demo can be run in exactly the same way. Just replace
"tls-client-block" in the above example commands with "tls-client-non-block".

Running the QUIC Demos
----------------------

The QUIC demos can be run in a very similar way to the TLS demos. However, a
different server implementation will need to be used.

The OpenSSL source distribution includes a test QUIC server implementation for
use with the demos. Note that, although this server does get built when building
OpenSSL from source, it does not get installed via "make install". After
building OpenSSL from source you will find the "quicserver" utility in the
"util" sub-directory of the top of the build tree. This server utility is not
suitable for production use and exists for test purposes only. It will be
removed from a future version of OpenSSL.

While in the demos directory the quic server can be run like this:

./../util/quicserver localhost 4443 servercert.pem serverkey.pem

The QUIC demos can then be run in the same was as the TLS demos. For example
to run the quic-client-block demo:

SSL_CERT_FILE=rootcert.pem LD_LIBRARY_PATH=../.. ./quic-client-block localhost 4443

<!-- Links  -->

[guide]: https://www.openssl.org/docs/manmaster/man7/ossl-guide-introduction.html
[TLS Introduction]: https://www.openssl.org/docs/manmaster/man7/ossl-guide-tls-introduction.html
