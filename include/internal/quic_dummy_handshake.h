/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_DUMMY_HANDSHAKE_H
# define OSSL_QUIC_DUMMY_HANDSHAKE_H

# include <openssl/ssl.h>
# include "internal/quic_stream.h"

# ifndef OPENSSL_NO_QUIC

/*
 * QUIC Dummy Handshake Module
 * ===========================
 *
 * This implements a fake "handshake layer" for QUIC to be used for testing
 * purposes until the real handshake layer is ready.
 *
 * Each message is of the following form, which reuses the TLS 1.3 framing:
 *
 *   1  ui  Type
 *   3  ui  Length
 *   ...    Data
 *
 * The following message types are implemented, which use values from the TLS
 * HandshakeType registry. Most of them have no body data, except for messages
 * which transport QUIC Transport Parameters.
 *
 *   0x01   Psuedo-ClientHello
 *              (QUIC Transport Parameters)
 *   0x02   Pseudo-ServerHello
 *              (no data)
 *   0x08   Pseudo-EncryptedExtensions
 *              (QUIC Transport Parameters)
 *   0x0B   Pseudo-Certificate
 *              (no data)
 *   0x0F   Pseudo-CertificateVerify
 *              (no data)
 *   0x14   Pseudo-Finished
 *              (no data)
 *
 */
typedef struct quic_dhs_st QUIC_DHS;

typedef struct quic_dhs_args_st {
    /*
     * Called to send data on the crypto stream. We use a callback rather than
     * passing the crypto stream QUIC_SSTREAM directly because this lets the CSM
     * dynamically select the correct outgoing crypto stream based on the
     * current EL.
     */
    int (*crypto_send_cb)(const unsigned char *buf, size_t buf_len,
                          size_t *consumed, void *arg);
    void *crypto_send_cb_arg;
    int (*crypto_recv_cb)(unsigned char *buf, size_t buf_len,
                          size_t *bytes_read, void *arg);
    void *crypto_recv_cb_arg;

    /* Called when a traffic secret is available for a given encryption level. */
    int (*yield_secret_cb)(uint32_t enc_level, int direction /* 0=RX, 1=TX */,
                           uint32_t suite_id, EVP_MD *md,
                           const unsigned char *secret, size_t secret_len,
                           void *arg);
    void *yield_secret_cb_arg;

    /*
     * Called when we receive transport parameters from the peer.
     *
     * Note: These parameters are not authenticated until the handshake is
     * marked as completed.
     */
    int (*got_transport_params_cb)(const unsigned char *params,
                                   size_t params_len,
                                   void *arg);
    void *got_transport_params_cb_arg;

    /*
     * Called when the handshake has been completed as far as the handshake
     * protocol is concerned, meaning that the connection has been
     * authenticated.
     */
    int (*handshake_complete_cb)(void *arg);
    void *handshake_complete_cb_arg;

    /*
     * Called when something has gone wrong with the connection as far as the
     * handshake layer is concerned, meaning that it should be immediately torn
     * down. Note that this may happen at any time, including after a connection
     * has been fully established.
     */
    int (*alert_cb)(void *arg, unsigned char alert_code);
    void *alert_cb_arg;

    /* Set to 1 if we are running in the server role. */
    int is_server;
} QUIC_DHS_ARGS;

QUIC_DHS *ossl_quic_dhs_new(const QUIC_DHS_ARGS *args);

void ossl_quic_dhs_free(QUIC_DHS *dhs);

/*
 * Advance the state machine. The DHS considers the receive stream and produces
 * output on the send stream. Note that after a connection is established this
 * is unlikely to ever produce any more output, but the handshake layer
 * nonetheless reserves the right to and it should continue being called
 * regularly. (When a real handshake layer is used, TLS 1.3 might e.g. produce a
 * new session ticket; or it might decide to spontaneously produce an alert,
 * however unlikely.)
 */
int ossl_quic_dhs_tick(QUIC_DHS *dhs);

/*
 * Set the transport parameters buffer. The lifetime of the buffer must last
 * until either the DHS is freed or the handshake complete callback is called.
 * This must be called before the transport parameters are needed by the DHS.
 * For a client, this means before ossl_quic_dhs_tick() is first called; for a
 * server, this should generally be immediately after the
 * got_transport_params_cb callback is called.
 */
int ossl_quic_dhs_set_transport_params(QUIC_DHS *dhs,
                                       const unsigned char *transport_params,
                                       size_t transport_params_len);

# endif

#endif
