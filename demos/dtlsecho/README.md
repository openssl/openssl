OpenSSL Simple DTLSv1.3 Echo Client/Server
==========================================

This project implements a simple DTLSv1.3 echo client/server.

It is a console application, with command line parameters determining the mode
of operation (client or server). Start it with no parameters to see usage.

The code adapted the sslecho demo to support DTLSv1.3.

The  client code illustrates that:

- Connection to the DTLS server is established.
- When the DTLSv1.3 connection completes, data is sent and received using
  SSL_write() and SSL_read().
- Pretty simple.

The cert.pem and key.pem files included are self signed certificates with the
"Common Name" of 'localhost'.

Best to create the 'pem' files using an actual hostname.
