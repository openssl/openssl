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

The cert.pem and key.pem files included are self signed certificates with the
"Common Name" of 'localhost'.

Best to create the 'pem' files using an actual hostname.

Encrypted Client Hello (ECH) Variant
====================================

``echecho.c`` implements the same functionality but demonstrates minimal code
changes needed to use ECH. The ``echecho`` binary has the same user interface
discussed above but enables ECH for the connection, based on hard-coded ECH
configuration data. A real server would load file(s), and a real client would
acquire an ECHConfigList from the DNS.

All that's required to use ECH is for the server to enable ECH via
``SSL_CTX_ech_server_enable_buffer()`` and for the client to do
similarly via ``SSL_CTX_ech_set1_echconfig()``. Both client and
server check and print out the status of ECH using ``SSL_ech_get_status()``,
but that's optional.

To run the server:

            $ LD_LIBRARY_PATH=../.. ./echecho s

To run the client:

            $ LD_LIBRARY_PATH=../.. ./echecho c localhost

All going well both server and client will print the ECH status at the
start of each connection. That looks like:

            ECH worked (status: 1, inner: localhost, outer: example.com)

If the non-ECH demo client (``sslecho``) is used instead the server will
output:

            ECH failed/not-tried (status: -101, inner: (null), outer: (null))

If the non-ECH demo server (i.e., ``sslecho``) is used, the client will exit
with an error as ECH was attempted and failed. In a debug build, that looks
like:

            80EBEE54227F0000:error:0A000163:SSL routines:tls_process_initial_server_flight:ech required:ssl/statem/statem_clnt.c:3274:

A real client would likely fall back to not using ECH, but the above
is ok for a demo.

In that case, the server will also exit based on the ECH alert from the client:

            403787A8307F0000:error:0A000461:SSL routines:ssl3_read_bytes:reason(1121):../ssl/record/rec_layer_s3.c:1588:SSL alert number 121
