Using OpenSSL with QUIC
=======================

From OpenSSL 3.2, OpenSSL features support for making QUIC connections as a
client.

Users interested in using the new QUIC functionality are encouraged to look at
some of the following resources:

- The [openssl-quic(7) manual page], which provides a basic reference overview
  of QUIC functionality and how use of QUIC differs from use of TLS with regard
  to our API;
- The new [OpenSSL Guide], which provides introductory guides
  on the use of TLS, QUIC, and other OpenSSL functionality. See the
  [ossl-guide-introduction(7) manual page][OpenSSL Guide] for the index.
- The [Demo-Driven Design (DDD)][DDD] demos, which demonstrate the use of QUIC
  using simple examples. These can be [found in the source tree under
  `doc/designs/ddd`].
- The [demo found in `demos/http3`], which provides an HTTP/3 client example
  using the nghttp3 HTTP/3 library.

FAQ
---

### Why would I want to use QUIC, and what functionality does QUIC offer relative to TLS or DTLS?

QUIC is a state-of-the-art secure transport protocol carried over UDP. It can
serve many of the use cases of TLS as well as those of DTLS. QUIC delivers
a number of advantages:

- It supports multiple streams of communication, allowing application protocols
  built on QUIC to create arbitrarily many bytestreams for communication between
  a client and server. This allows an application protocol to avoid head-of-line
  blocking and allows an application to open additional logical streams without
  any round trip penalty, unlike opening an additional TCP connection.

- Since QUIC is the basis of HTTP/3, support for QUIC also enables applications
  to use HTTP/3 using a suitable third-party library.

- Future versions of OpenSSL will offer support for 0-RTT connection
  initiation, allowing a connection to be initiated to a server and application
  data to be transmitted without any waiting time. This is similar to TLS 1.3's
  0-RTT functionality but also avoids the round trip needed to open a TCP
  socket; thus, it is similar to a combination of TLS 1.3 0-RTT and TCP Fast
  Open.

- Future versions of OpenSSL will offer support for connection
  migration, allowing connections to seamlessly survive IP address changes.

- Future versions of OpenSSL will offer support for the QUIC
  datagram extension, allowing support for both TLS and DTLS-style use cases on
  a single connection.

- Because most QUIC implementations, including OpenSSL's implementation, are
  implemented as an application library rather than by an operating system, an
  application can gain the benefit of QUIC without needing to wait for an OS
  update to be deployed. Future evolutions and enhancements to the QUIC protocol
  can be delivered as quickly as an application can be updated without
  dependency on an OS update cadence.

- Because QUIC is UDP-based, it is possible to multiplex a QUIC connection
  on the same UDP socket as some other UDP-based protocols, such as RTP.

For more background information on OpenSSL's QUIC implementation, see the
[openssl-quic(7) manual page].

### How can I use HTTP/3 with OpenSSL?

There are many HTTP/3 implementations in C available. The use of one such HTTP/3
library with OpenSSL QUIC is demonstrated via the [demo found in `demos/http3`].

### How can I use OpenSSL QUIC in my own application for a different protocol?

The [OpenSSL Guide] provides introductory examples for how to make use of
OpenSSL QUIC.

The [openssl-quic(7) manual page] and the [Demo-Driven Design (DDD)][DDD] demos
may also be helpful to illustrate the changes needed if you are trying to adapt
an existing application.

### How can I test QUIC using `openssl s_client`?

There is basic support for single-stream QUIC using `openssl s_client`:

```shell
$ openssl s_client -quic -alpn ossltest -connect www.example.com:12345
```

This connects to a QUIC server using the specified ALPN protocol name and opens
a single bidirectional stream. Data can be passed via stdin/stdout as usual.
This allows test usage of QUIC using simple TCP/TLS-like usage.

[openssl-quic(7) manual page]: https://www.openssl.org/docs/manmaster/man7/openssl-quic.html
[OpenSSL guide]: https://www.openssl.org/docs/manmaster/man7/ossl-guide-introduction.html
[DDD]: https://github.com/openssl/openssl/tree/master/doc/designs/ddd
[found in the source tree under `doc/designs/ddd`]: ./doc/designs/ddd/
[demo found in `demos/http3`]: ./demos/http3/
[openssl-quic-background(7) manual page]: https://www.openssl.org/docs/manmaster/man7/openssl-quic-background.html
