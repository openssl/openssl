/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <internal/quic_tserver.h>

/* Type to represent the Fault Injector */
typedef struct qtest_fault QTEST_FAULT;

/*
 * Structure representing a parsed EncryptedExtension message. Listeners can
 * make changes to the contents of structure objects as required and the fault
 * injector will reconstruct the message to be sent on
 */
typedef struct qtest_fault_encrypted_extensions {
    /* EncryptedExtension messages just have an extensions block */
    unsigned char *extensions;
    size_t extensionslen;
} QTEST_ENCRYPTED_EXTENSIONS;

/*
 * Given an SSL_CTX for the client and filenames for the server certificate and
 * keyfile, create a server and client instances as well as a fault injector
 * instance. |block| indicates whether we are using blocking mode or not.
 */
int qtest_create_quic_objects(OSSL_LIB_CTX *libctx, SSL_CTX *clientctx,
                              char *certfile, char *keyfile, int block,
                              QUIC_TSERVER **qtserv, SSL **cssl,
                              QTEST_FAULT **fault);

/*
 * Free up a Fault Injector instance
 */
void qtest_fault_free(QTEST_FAULT *fault);

/* Returns 1 if the quictestlib supports blocking tests */
int qtest_supports_blocking(void);

/*
 * Run the TLS handshake to create a QUIC connection between the client and
 * server.
 */
int qtest_create_quic_connection(QUIC_TSERVER *qtserv, SSL *clientssl);

/*
 * Shutdown the client SSL object gracefully
 */
int qtest_shutdown(QUIC_TSERVER *qtserv, SSL *clientssl);

/*
 * Confirm that the server has received the given transport error code.
 */
int qtest_check_server_transport_err(QUIC_TSERVER *qtserv, uint64_t code);

/*
 * Confirm the server has received a protocol error. Equivalent to calling
 * qtest_check_server_transport_err with a code of QUIC_ERR_PROTOCOL_VIOLATION
 */
int qtest_check_server_protocol_err(QUIC_TSERVER *qtserv);

/*
 * Enable tests to listen for pre-encryption QUIC packets being sent
 */
typedef int (*qtest_fault_on_packet_plain_cb)(QTEST_FAULT *fault,
                                              QUIC_PKT_HDR *hdr,
                                              unsigned char *buf,
                                              size_t len,
                                              void *cbarg);

int qtest_fault_set_packet_plain_listener(QTEST_FAULT *fault,
                                          qtest_fault_on_packet_plain_cb pplaincb,
                                          void *pplaincbarg);


/*
 * Helper function to be called from a packet_plain_listener callback if it
 * wants to resize the packet (either to add new data to it, or to truncate it).
 * The buf provided to packet_plain_listener is over allocated, so this just
 * changes the logical size and never changes the actual address of the buf.
 * This will fail if a large resize is attempted that exceeds the over
 * allocation.
 */
int qtest_fault_resize_plain_packet(QTEST_FAULT *fault, size_t newlen);

/*
 * Prepend frame data into a packet. To be called from a packet_plain_listener
 * callback
 */
int qtest_fault_prepend_frame(QTEST_FAULT *fault, unsigned char *frame,
                              size_t frame_len);

/*
 * The general handshake message listener is sent the entire handshake message
 * data block, including the handshake header itself
 */
typedef int (*qtest_fault_on_handshake_cb)(QTEST_FAULT *fault,
                                           unsigned char *msg,
                                           size_t msglen,
                                           void *handshakecbarg);

int qtest_fault_set_handshake_listener(QTEST_FAULT *fault,
                                       qtest_fault_on_handshake_cb handshakecb,
                                       void *handshakecbarg);

/*
 * Helper function to be called from a handshake_listener callback if it wants
 * to resize the handshake message (either to add new data to it, or to truncate
 * it). newlen must include the length of the handshake message header. The
 * handshake message buffer is over allocated, so this just changes the logical
 * size and never changes the actual address of the buf.
 * This will fail if a large resize is attempted that exceeds the over
 * allocation.
 */
int qtest_fault_resize_handshake(QTEST_FAULT *fault, size_t newlen);

/*
 * TODO(QUIC): Add listeners for specifc types of frame here. E.g. we might
 * expect to see an "ACK" frame listener which will be passed pre-parsed ack
 * data that can be modified as required.
 */

/*
 * Handshake message specific listeners. Unlike the general handshake message
 * listener these messages are pre-parsed and supplied with message specific
 * data and exclude the handshake header
 */
typedef int (*qtest_fault_on_enc_ext_cb)(QTEST_FAULT *fault,
                                         QTEST_ENCRYPTED_EXTENSIONS *ee,
                                         size_t eelen,
                                         void *encextcbarg);

int qtest_fault_set_hand_enc_ext_listener(QTEST_FAULT *fault,
                                          qtest_fault_on_enc_ext_cb encextcb,
                                          void *encextcbarg);

/* TODO(QUIC): Add listeners for other types of handshake message here */


/*
 * Helper function to be called from message specific listener callbacks. newlen
 * is the new length of the specific message excluding the handshake message
 * header.  The buffers provided to the message specific listeners are over
 * allocated, so this just changes the logical size and never changes the actual
 * address of the buffer. This will fail if a large resize is attempted that
 * exceeds the over allocation.
 */
int qtest_fault_resize_message(QTEST_FAULT *fault, size_t newlen);

/*
 * Helper function to delete an extension from an extension block. |exttype| is
 * the type of the extension to be deleted. |ext| points to the extension block.
 * On entry |*extlen| contains the length of the extension block. It is updated
 * with the new length on exit.
 */
int qtest_fault_delete_extension(QTEST_FAULT *fault,
                                 unsigned int exttype, unsigned char *ext,
                                 size_t *extlen);

/*
 * TODO(QUIC): Add additional helper functions for querying extensions here (e.g.
 * finding or adding them). We could also provide a "listener" API for listening
 * for specific extension types
 */

/*
 * Enable tests to listen for post-encryption QUIC packets being sent
 */
typedef int (*qtest_fault_on_packet_cipher_cb)(QTEST_FAULT *fault,
                                               /* The parsed packet header */
                                               QUIC_PKT_HDR *hdr,
                                               /* The packet payload data */
                                               unsigned char *buf,
                                               /* Length of the payload */
                                               size_t len,
                                               void *cbarg);

int qtest_fault_set_packet_cipher_listener(QTEST_FAULT *fault,
                                           qtest_fault_on_packet_cipher_cb pciphercb,
                                           void *picphercbarg);

/*
 * Enable tests to listen for datagrams being sent
 */
typedef int (*qtest_fault_on_datagram_cb)(QTEST_FAULT *fault,
                                          BIO_MSG *m,
                                          size_t stride,
                                          void *cbarg);

int qtest_fault_set_datagram_listener(QTEST_FAULT *fault,
                                      qtest_fault_on_datagram_cb datagramcb,
                                      void *datagramcbarg);

/*
 * To be called from a datagram_listener callback. The datagram buffer is over
 * allocated, so this just changes the logical size and never changes the actual
 * address of the buffer. This will fail if a large resize is attempted that
 * exceeds the over allocation.
 */
int qtest_fault_resize_datagram(QTEST_FAULT *fault, size_t newlen);
