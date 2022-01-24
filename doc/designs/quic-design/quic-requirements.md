# OTC QUIC Requirements

There are differents types of application that we need to cater for:

* Simple clients that just do basic SSL_read/SSL_write or BIO_read/BIO_write
interactions. We want to be able to enable them to transfer to using single
stream QUIC easily. (MVP)
* Simple servers that just do basic SSL_read/SSL_write or BIO_read/BIO_write
interactions. We want to be able to enable them to transfer to using single
stream QUIC easily. More likely to want to do multi-stream.
* High performance applications (primarily server based) using existing libssl
APIs; using custom network interaction BIOs in order to get the best performance
at a network level as well as OS interactions (IO handling, thread handling,
using fibres). Would prefer to use the existing APIs - they don’t want to throw
away what they’ve got. Where QUIC necessitates a change they would be willing to
make minor changes.
* New applications. Would be willing to use new APIs to achieve their goals.

Required properties of any new API:

* The differences between QUIC, TLS, DTLS etc, should be minimised at an API
level - the structure of the application should be the same. At runtime
applications should be able to pick whatever protocol they want to use
* It shouldn’t be harder to do single stream just because multi stream as a
concept exists.
* It shouldn’t be harder to do TLS just because you have the ability to do DTLS
or QUIC.
* Application authors will need good documentation, demos, examples etc.

QUIC performance:

* Should be comparable with other major implementations
* Measured by
    * Handshakes per second
    * Application data throughput (bytes per second) for a single stream/connection

"Single copy" must be possible to achieve for application data being sent or
received via QUIC. The "single" copy allowed is to allow for the implicit copy
in an encrypt or decrypt operation.

Single copy for sending data occurs when the application supplies a buffer of
data to be sent. No copies of that data are made until it is encrypted. Once
encrypted no further copies of the encrypted data are made until it is provided
to the kernel for sending via a system call.

Single copy for receiving data occurs when a library supplied buffer is filled
by the kernel via a system call from the socket. No further copies of that data
are made until it is decrypted. It is decrypted directly into a buffer made
available to (or supplied by) the application with no further internal copies
made.
