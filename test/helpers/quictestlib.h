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

typedef struct ossl_quic_fault OSSL_QUIC_FAULT;

typedef struct ossl_qf_encrypted_extensions {
    unsigned char *extensions;
    size_t extensionslen;
} OSSL_QF_ENCRYPTED_EXTENSIONS;

int qtest_create_quic_objects(SSL_CTX *clientctx, char *certfile, char *keyfile,
                              QUIC_TSERVER **qtserv, SSL **cssl,
                              OSSL_QUIC_FAULT **fault);
int qtest_create_quic_connection(QUIC_TSERVER *qtserv, SSL *clientssl);

void ossl_quic_fault_free(OSSL_QUIC_FAULT *fault);

typedef int (*ossl_quic_fault_on_packet_plain_cb)(OSSL_QUIC_FAULT *fault,
                                                  QUIC_PKT_HDR *hdr,
                                                  unsigned char *buf,
                                                  size_t len,
                                                  void *cbarg);

int ossl_quic_fault_set_packet_plain_listener(OSSL_QUIC_FAULT *fault,
                                              ossl_quic_fault_on_packet_plain_cb pplaincb,
                                              void *pplaincbarg);

/* To be called from a packet_plain_listener callback */
int ossl_quic_fault_resize_plain_packet(OSSL_QUIC_FAULT *fault, size_t newlen);

/*
 * The general handshake message listener is sent the entire handshake message
 * data block, including the handshake header itself
 */
typedef int (*ossl_quic_fault_on_handshake_cb)(OSSL_QUIC_FAULT *fault,
                                               unsigned char *msg,
                                               size_t msglen,
                                               void *handshakecbarg);

int ossl_quic_fault_set_handshake_listener(OSSL_QUIC_FAULT *fault,
                                           ossl_quic_fault_on_handshake_cb handshakecb,
                                           void *handshakecbarg);

/*
 * To be called from a handshake_listener callback. newlen must include the
 * length of the handshake message header.
 */
int ossl_quic_fault_resize_handshake(OSSL_QUIC_FAULT *fault, size_t newlen);

/*
 * Handshake message specific listeners. Unlike the general handshake message
 * listener these messages are pre-parsed and supplied with message specific
 * data and exclude the handshake header
 */
typedef int (*ossl_quic_fault_on_enc_ext_cb)(OSSL_QUIC_FAULT *fault,
                                             OSSL_QF_ENCRYPTED_EXTENSIONS *ee,
                                             size_t eelen,
                                             void *encextcbarg);

int ossl_quic_fault_set_hand_enc_ext_listener(OSSL_QUIC_FAULT *fault,
                                              ossl_quic_fault_on_enc_ext_cb encextcb,
                                              void *encextcbarg);


/*
 * To be called from message specific listener callbacks. newlen is the new
 * length of the specific message excluding the handshake message header.
 */
int ossl_quic_fault_resize_message(OSSL_QUIC_FAULT *fault, size_t newlen);

/*
 * Delete an extension from an extension block. |exttype| is the type of the
 * extension to be deleted. |ext| points to the extension block. On entry
 * |*extlen| contains the length of the extension block. It is updated with the
 * new length on exit. On entry |*msglen| is the length of the handshake message
 * (without the header). On exit it is updated with the new message length.
 * ossl_quic_fault_resize_handshake() is called automatically so there is no
 * need to call it explicitly.
 */
int ossl_quic_fault_delete_extension(OSSL_QUIC_FAULT *fault,
                                     unsigned int exttype, unsigned char *ext,
                                     size_t *extlen, size_t *msglen);
