OpenSSL Simple Echo Client/Server
=================================

This project implements a simple echo client/server.

It is a console application, with command line parameters determining the mode
of operation (client or server). Start it with no parameters to see usage.

The server code was adapted from the Simple TLS Server on the OpenSSL Wiki.
The server code was modified to perform the echo function, and client code
was added to open a connection with the server and to send keyboard input
to the server.

The new client code illustrates that:

- Connection to the SSL server starts as a standard TCP 'connect'.
- Once connected with TCP, the client 'upgrades' to SSL using
  SSL_connect().
- When the SSL connection completes, data is sent and received using
  SSL_write() and SSL_read().
- Pretty simple.

Library Versions:
-----------------

This program was built on a Linux Mint 20.2 system which comes with
V1.1.1 of OpenSSL. It supplies libssl.so.1.1.
The OpenSSL git tree will produce headers and libs for V3 of Openssl;
libssl.so.3.

The function configure_client_context() will not compile with V1.1.1,
but WILL compile with V3. Note that OpenSSL must
be built (Configure/make) in order to generate the header and library files
for V3.

The program and makefile have provisions to build for either platform;
be sure that both main.c and the makefile define OPENSSL_V3 the same way.

Certificate and Key files:
--------------------------

The supplied certificate and key files were genterated by taking the default
values (CR's) for all fields presented when executing:
openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out cert.pem
-keyout key.pem

The program will work with these files if compiled and linked with
V1.1.1. The client can be run on the same machine or a different
machine. If run on the same machine,
the client can connect with any of the machine's IP's, or with 'localhost'.

The program will not work with these files if compiled with V3.

If you generate keys with 'LOCALHOST' supplied for the FQDN request, the
program will work with V3. However, I've only been able to use the client
and server on the same machine with 'localhost' supplied as the IP when
starting the client.