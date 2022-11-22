/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/macros.h>
#include <openssl/objects.h>
#include "internal/quic_dummy_handshake.h"

#define QUIC_DHS_MSG_TYPE_CH            0x01
#define QUIC_DHS_MSG_TYPE_SH            0x02
#define QUIC_DHS_MSG_TYPE_EE            0x08
#define QUIC_DHS_MSG_TYPE_CERT          0x0B
#define QUIC_DHS_MSG_TYPE_CERT_VERIFY   0x0F
#define QUIC_DHS_MSG_TYPE_FINISHED      0x14

#define QUIC_DHS_CLIENT_STATE_INITIAL               0x00
#define QUIC_DHS_CLIENT_STATE_SENT_CH               0x01
#define QUIC_DHS_CLIENT_STATE_RECEIVED_SH           0x02
#define QUIC_DHS_CLIENT_STATE_RECEIVED_EE_HDR       0x08
#define QUIC_DHS_CLIENT_STATE_RECEIVED_EE           0x03
#define QUIC_DHS_CLIENT_STATE_RECEIVED_CERT         0x04
#define QUIC_DHS_CLIENT_STATE_RECEIVED_CERT_VERIFY  0x05
#define QUIC_DHS_CLIENT_STATE_RECEIVED_FINISHED     0x06
#define QUIC_DHS_CLIENT_STATE_SENT_FINISHED         0x07
#define QUIC_DHS_CLIENT_STATE_ERROR                 0xFF

#define QUIC_DHS_SERVER_STATE_INITIAL               0x00
#define QUIC_DHS_SERVER_STATE_RECEIVED_CH_HDR       0x01
#define QUIC_DHS_SERVER_STATE_RECEIVED_CH           0x02
#define QUIC_DHS_SERVER_STATE_SENT_SH               0x03
#define QUIC_DHS_SERVER_STATE_SENT_EE               0x04
#define QUIC_DHS_SERVER_STATE_SENT_CERT             0x05
#define QUIC_DHS_SERVER_STATE_SENT_CERT_VERIFY      0x06
#define QUIC_DHS_SERVER_STATE_SENT_FINISHED         0x07
#define QUIC_DHS_SERVER_STATE_RECEIVED_FINISHED     0x08
#define QUIC_DHS_SERVER_STATE_ERROR                 0xFF

struct quic_dhs_st {
    QUIC_DHS_ARGS   args;
    unsigned char   state;
    unsigned char   *remote_transport_params;
    size_t          remote_transport_params_len;
    const unsigned char *local_transport_params;
    size_t          local_transport_params_len;
    unsigned char   rx_hdr[4];
    size_t          rx_hdr_bytes_read;
    size_t          rx_bytes_read;
};

QUIC_DHS *ossl_quic_dhs_new(const QUIC_DHS_ARGS *args)
{
    QUIC_DHS *dhs;

    if (args->crypto_send_cb == NULL
        || args->crypto_recv_cb == NULL)
        return NULL;

    dhs = OPENSSL_zalloc(sizeof(*dhs));
    if (dhs == NULL)
        return NULL;

    dhs->args = *args;
    return dhs;
}

void ossl_quic_dhs_free(QUIC_DHS *dhs)
{
    if (dhs == NULL)
        return;

    OPENSSL_free(dhs->remote_transport_params);
    OPENSSL_free(dhs);
}

/* Send a handshake message. */
static int dhs_send(QUIC_DHS *dhs, unsigned char type,
                    const void *buf, size_t buf_len)
{
    size_t consumed = 0;
    uint32_t len;
    unsigned char hdr[4];

    len = buf_len;
    hdr[0] = type;
    hdr[1] = (len >> 16) & 0xFF;
    hdr[2] = (len >>  8) & 0xFF;
    hdr[3] = (len      ) & 0xFF;

    if (!dhs->args.crypto_send_cb(hdr, sizeof(hdr), &consumed,
                                  dhs->args.crypto_send_cb_arg)
        || consumed < sizeof(hdr)
        || (buf_len > 0 && (!dhs->args.crypto_send_cb(buf, buf_len, &consumed,
                                                      dhs->args.crypto_send_cb_arg)
                            || consumed < buf_len)))
        /*
         * We do not handle a full buffer here properly but the DHS produces so
         * little data this should not matter. By the time we want to fix this
         * the real handshake layer will be ready.
         */
        return 0;

    return 1;
}

/*
 * Receive header of a handshake message. Length of body is written to
 * *frame_len, and if non-zero this call should be followed by one or more calls
 * to dhs_recv_body.
 */
static int dhs_recv_sof(QUIC_DHS *dhs, uint32_t *type, size_t *frame_len)
{
    size_t bytes_read = 0;
    uint32_t l;

    if (!dhs->args.crypto_recv_cb(dhs->rx_hdr + dhs->rx_hdr_bytes_read,
                                  sizeof(dhs->rx_hdr) - dhs->rx_hdr_bytes_read,
                                  &bytes_read,
                                  dhs->args.crypto_recv_cb_arg))
        return 0;

    dhs->rx_hdr_bytes_read += bytes_read;
    if (dhs->rx_hdr_bytes_read < sizeof(dhs->rx_hdr)) {
        /* Not got entire header yet. */
        *type       = UINT32_MAX;
        *frame_len  = 0;
        return 2;
    }

    l = (((uint32_t)dhs->rx_hdr[1]) << 16)
      | (((uint32_t)dhs->rx_hdr[2]) <<  8)
      |   (uint32_t)dhs->rx_hdr[3];

    if (l > SIZE_MAX)
        return 0;

    *type       = dhs->rx_hdr[0];
    *frame_len  = (size_t)l;

    dhs->rx_hdr_bytes_read = 0;
    return 1;
}

/* Receive the body of an incoming message, or part thereof. */
static int dhs_recv_body(QUIC_DHS *dhs, unsigned char *buf, size_t buf_len,
                         size_t *bytes_read)
{
    if (!dhs->args.crypto_recv_cb(buf, buf_len, bytes_read,
                                  dhs->args.crypto_recv_cb_arg))
        return 0;

    if (*bytes_read == 0)
        return 2;

    return 1;
}

static const unsigned char default_handshake_read[32] = {42, 2};
static const unsigned char default_handshake_write[32] = {42, 1};
static const unsigned char default_1rtt_read[32] = {43, 2};
static const unsigned char default_1rtt_write[32] = {43, 1};

int ossl_quic_dhs_set_transport_params(QUIC_DHS *dhs, const unsigned char *transport_params,
                                       size_t transport_params_len)
{
    if (!dhs->args.is_server && dhs->state != QUIC_DHS_CLIENT_STATE_INITIAL)
        return 0;

    dhs->local_transport_params       = transport_params;
    dhs->local_transport_params_len   = transport_params_len;
    return 1;
}

/* Tick implementation for the client role. */
static int dhs_tick_client(QUIC_DHS *dhs)
{
    int ret;
    uint32_t type;
    size_t frame_len, bytes_read = 0;

    for (;;) {
        switch (dhs->state) {
            case QUIC_DHS_CLIENT_STATE_INITIAL:
                /* We need to send a CH */
                if (!dhs_send(dhs, QUIC_DHS_MSG_TYPE_CH,
                              dhs->local_transport_params,
                              dhs->local_transport_params_len))
                    return 0;

                dhs->state = QUIC_DHS_CLIENT_STATE_SENT_CH;
                break;

            case QUIC_DHS_CLIENT_STATE_SENT_CH:
                ret = dhs_recv_sof(dhs, &type, &frame_len);
                if (ret == 1) {
                    if (type == QUIC_DHS_MSG_TYPE_SH && frame_len == 0) {
                        dhs->state = QUIC_DHS_CLIENT_STATE_RECEIVED_SH;

                        if (!dhs->args.yield_secret_cb(QUIC_ENC_LEVEL_HANDSHAKE,
                                                       /*TX=*/0,
                                                       QRL_SUITE_AES128GCM,
                                                       NULL,
                                                       default_handshake_read,
                                                       sizeof(default_handshake_read),
                                                       dhs->args.yield_secret_cb_arg)) {
                            dhs->state = QUIC_DHS_CLIENT_STATE_ERROR;
                            return 0;
                        }

                        if (!dhs->args.yield_secret_cb(QUIC_ENC_LEVEL_HANDSHAKE,
                                                       /*TX=*/1,
                                                       QRL_SUITE_AES128GCM,
                                                       NULL,
                                                       default_handshake_write,
                                                       sizeof(default_handshake_write),
                                                       dhs->args.yield_secret_cb_arg)) {
                            dhs->state = QUIC_DHS_CLIENT_STATE_ERROR;
                            return 0;
                        }

                    } else {
                        dhs->state = QUIC_DHS_CLIENT_STATE_ERROR;
                        return 0; /* error state, unexpected type */
                    }
                } else if (ret == 2) {
                    return 1; /* no more data yet, not an error */
                } else {
                    return 0;
                }
                break;

            case QUIC_DHS_CLIENT_STATE_RECEIVED_SH:
                ret = dhs_recv_sof(dhs, &type, &frame_len);
                if (ret == 1) {
                    if (type == QUIC_DHS_MSG_TYPE_EE) {
                        dhs->state = QUIC_DHS_CLIENT_STATE_RECEIVED_EE_HDR;
                        dhs->rx_bytes_read               = 0;
                        dhs->remote_transport_params_len    = frame_len;
                        dhs->remote_transport_params
                            = OPENSSL_malloc(dhs->remote_transport_params_len);
                        if (dhs->remote_transport_params == NULL)
                            return 0;
                    } else {
                        dhs->state = QUIC_DHS_CLIENT_STATE_ERROR;
                        return 0; /* error state, unexpected type */
                    }
                } else if (ret == 2) {
                    return 1; /* no more data yet, not an error */
                } else {
                    return 0;
                }
                break;

            case QUIC_DHS_CLIENT_STATE_RECEIVED_EE_HDR:
                ret = dhs_recv_body(dhs, dhs->remote_transport_params + dhs->rx_bytes_read,
                                    dhs->remote_transport_params_len - dhs->rx_bytes_read,
                                    &bytes_read);
                if (ret == 1) {
                    dhs->rx_bytes_read += bytes_read;
                    if (bytes_read == dhs->remote_transport_params_len) {
                        if (!dhs->args.got_transport_params_cb(dhs->remote_transport_params,
                                                               dhs->remote_transport_params_len,
                                                               dhs->args.got_transport_params_cb_arg)) {
                            dhs->state = QUIC_DHS_CLIENT_STATE_ERROR;
                            return 0;
                        }

                        dhs->state = QUIC_DHS_CLIENT_STATE_RECEIVED_EE;
                    }
                } else if (ret == 2) {
                    return 1; /* no more data yet, not an error */
                } else {
                    return 0;
                }
                break;

            case QUIC_DHS_CLIENT_STATE_RECEIVED_EE:
                /* Expect Cert */
                ret = dhs_recv_sof(dhs, &type, &frame_len);
                if (ret == 1) {
                    if (type == QUIC_DHS_MSG_TYPE_CERT && frame_len == 0) {
                        dhs->state = QUIC_DHS_CLIENT_STATE_RECEIVED_CERT;
                    } else {
                        dhs->state = QUIC_DHS_CLIENT_STATE_ERROR;
                        return 0; /* error state, unexpected type */
                    }
                } else if (ret == 2) {
                    return 1; /* no more data yet, not an error */
                } else {
                    return 0;
                }
                break;

            case QUIC_DHS_CLIENT_STATE_RECEIVED_CERT:
                /* Expect CertVerify */
                ret = dhs_recv_sof(dhs, &type, &frame_len);
                if (ret == 1) {
                    if (type == QUIC_DHS_MSG_TYPE_CERT_VERIFY && frame_len == 0) {
                        dhs->state = QUIC_DHS_CLIENT_STATE_RECEIVED_CERT_VERIFY;
                    } else {
                        dhs->state = QUIC_DHS_CLIENT_STATE_ERROR;
                        return 0; /* error state, unexpected type */
                    }
                } else if (ret == 2) {
                    return 1; /* no more data yet, not an error */
                } else {
                    return 0;
                }
                break;

            case QUIC_DHS_CLIENT_STATE_RECEIVED_CERT_VERIFY:
                /* Expect Finished */
                ret = dhs_recv_sof(dhs, &type, &frame_len);
                if (ret == 1) {
                    if (type == QUIC_DHS_MSG_TYPE_FINISHED && frame_len == 0) {
                        dhs->state = QUIC_DHS_CLIENT_STATE_RECEIVED_FINISHED;
                    } else {
                        dhs->state = QUIC_DHS_CLIENT_STATE_ERROR;
                        return 0; /* error state, unexpected type */
                    }
                } else if (ret == 2) {
                    return 1; /* no more data yet, not an error */
                } else {
                    return 0;
                }
                break;

            case QUIC_DHS_CLIENT_STATE_RECEIVED_FINISHED:
                /* Send Finished */
                if (!dhs_send(dhs, QUIC_DHS_MSG_TYPE_FINISHED, NULL, 0))
                    return 0;

                dhs->state = QUIC_DHS_CLIENT_STATE_SENT_FINISHED;

                if (!dhs->args.yield_secret_cb(QUIC_ENC_LEVEL_1RTT,
                                               /*TX=*/0,
                                               QRL_SUITE_AES128GCM,
                                               NULL,
                                               default_1rtt_read,
                                               sizeof(default_1rtt_read),
                                               dhs->args.yield_secret_cb_arg))
                    return 0;

                if (!dhs->args.yield_secret_cb(QUIC_ENC_LEVEL_1RTT,
                                               /*TX=*/1,
                                               QRL_SUITE_AES128GCM,
                                               NULL,
                                               default_1rtt_write,
                                               sizeof(default_1rtt_write),
                                               dhs->args.yield_secret_cb_arg))
                    return 0;

                if (!dhs->args.handshake_complete_cb(dhs->args.handshake_complete_cb_arg))
                    return 0;

                dhs->local_transport_params       = NULL;
                dhs->local_transport_params_len   = 0;
                break;

            case QUIC_DHS_CLIENT_STATE_SENT_FINISHED:
                /* Nothing to do, handshake complete. */
                return 1;

            default:
                return 0; /* error state */
        }
    }

    return 1;
}

/* Tick implementation for the server role. */
static int dhs_tick_server(QUIC_DHS *dhs)
{
    int ret;
    uint32_t type;
    size_t frame_len, bytes_read = 0;

    for (;;) {
        switch (dhs->state) {
            case QUIC_DHS_SERVER_STATE_INITIAL:
                /* Waiting for ClientHello message */
                ret = dhs_recv_sof(dhs, &type, &frame_len);
                if (ret == 1) {
                    if (type == QUIC_DHS_MSG_TYPE_CH && frame_len > 0) {
                        dhs->state = QUIC_DHS_SERVER_STATE_RECEIVED_CH_HDR;
                        dhs->rx_bytes_read = 0;
                        dhs->remote_transport_params_len = frame_len;
                        dhs->remote_transport_params
                            = OPENSSL_malloc(dhs->remote_transport_params_len);

                        if (dhs->remote_transport_params == NULL)
                            return 0;

                    } else {
                        dhs->state = QUIC_DHS_SERVER_STATE_ERROR;
                        return 0; /* error state, unexpected type */
                    }
                } else if (ret == 2) {
                    return 1; /* no more data yet, not an error */
                } else {
                    return 0;
                }

                break;

            case QUIC_DHS_SERVER_STATE_RECEIVED_CH_HDR:
                ret = dhs_recv_body(dhs, dhs->remote_transport_params + dhs->rx_bytes_read,
                                    dhs->remote_transport_params_len - dhs->rx_bytes_read,
                                    &bytes_read);
                if (ret == 1) {
                    dhs->rx_bytes_read += bytes_read;
                    if (dhs->rx_bytes_read == dhs->remote_transport_params_len) {
                        if (!dhs->args.got_transport_params_cb(dhs->remote_transport_params,
                                                               dhs->remote_transport_params_len,
                                                               dhs->args.got_transport_params_cb_arg)) {
                            dhs->state = QUIC_DHS_SERVER_STATE_ERROR;
                            return 0;
                        }

                        dhs->state = QUIC_DHS_SERVER_STATE_RECEIVED_CH;
                    }
                } else if (ret == 2) {
                    return 1; /* no more data yet, not an error */
                } else {
                    return 0;
                }
                break;

            case QUIC_DHS_SERVER_STATE_RECEIVED_CH:
                /* We need to send a ServerHello message */
                if (!dhs_send(dhs, QUIC_DHS_MSG_TYPE_SH, NULL, 0))
                    return 0;

                /*
                 * Our send function automatically sends at the highest
                 * available EL so we need to do this after sending the SH.
                 */
                if (!dhs->args.yield_secret_cb(QUIC_ENC_LEVEL_HANDSHAKE,
                                               /* (Keys reversed - server) */
                                               /*TX=*/0,
                                               QRL_SUITE_AES128GCM,
                                               NULL,
                                               default_handshake_write,
                                               sizeof(default_handshake_write),
                                               dhs->args.yield_secret_cb_arg)) {
                    dhs->state = QUIC_DHS_SERVER_STATE_ERROR;
                    return 0;
                }

                if (!dhs->args.yield_secret_cb(QUIC_ENC_LEVEL_HANDSHAKE,
                                               /* (Keys reversed - server) */
                                               /*TX=*/1,
                                               QRL_SUITE_AES128GCM,
                                               NULL,
                                               default_handshake_read,
                                               sizeof(default_handshake_read),
                                               dhs->args.yield_secret_cb_arg)) {
                    dhs->state = QUIC_DHS_SERVER_STATE_ERROR;
                    return 0;
                }

                dhs->state = QUIC_DHS_SERVER_STATE_SENT_SH;
                break;

            case QUIC_DHS_SERVER_STATE_SENT_SH:
                /* We need to send an EncryptedExtensions message */
                if (dhs->local_transport_params == NULL
                    || dhs->local_transport_params_len == 0)
                    return 0;

                if (!dhs_send(dhs, QUIC_DHS_MSG_TYPE_EE,
                              dhs->local_transport_params,
                              dhs->local_transport_params_len))
                    return 0;

                dhs->local_transport_params       = NULL;
                dhs->local_transport_params_len   = 0;

                dhs->state = QUIC_DHS_SERVER_STATE_SENT_EE;
                break;

            case QUIC_DHS_SERVER_STATE_SENT_EE:
                /* We need to send a Certificate message */
                if (!dhs_send(dhs, QUIC_DHS_MSG_TYPE_CERT, NULL, 0))
                    return 0;

                dhs->state = QUIC_DHS_SERVER_STATE_SENT_CERT;
                break;

            case QUIC_DHS_SERVER_STATE_SENT_CERT:
                /* We need to send a CertificateVerify message */
                if (!dhs_send(dhs, QUIC_DHS_MSG_TYPE_CERT_VERIFY, NULL, 0))
                    return 0;

                dhs->state = QUIC_DHS_SERVER_STATE_SENT_CERT_VERIFY;
                break;

            case QUIC_DHS_SERVER_STATE_SENT_CERT_VERIFY:
                /* We need to send a Finished message */
                if (!dhs_send(dhs, QUIC_DHS_MSG_TYPE_FINISHED, NULL, 0))
                    return 0;

                dhs->state = QUIC_DHS_SERVER_STATE_SENT_FINISHED;
                break;

            case QUIC_DHS_SERVER_STATE_SENT_FINISHED:
                /* We are waiting for a Finished message. */
                ret = dhs_recv_sof(dhs, &type, &frame_len);
                if (ret == 1) {
                    if (type == QUIC_DHS_MSG_TYPE_FINISHED && frame_len == 0) {
                        if (!dhs->args.yield_secret_cb(QUIC_ENC_LEVEL_1RTT,
                                                       /* (Keys reversed - server) */
                                                       /*TX=*/0,
                                                       QRL_SUITE_AES128GCM,
                                                       NULL,
                                                       default_1rtt_write,
                                                       sizeof(default_1rtt_write),
                                                       dhs->args.yield_secret_cb_arg)) {
                            dhs->state = QUIC_DHS_SERVER_STATE_ERROR;
                            return 0;
                        }

                        if (!dhs->args.yield_secret_cb(QUIC_ENC_LEVEL_1RTT,
                                                       /* (Keys reversed - server) */
                                                       /*TX=*/1,
                                                       QRL_SUITE_AES128GCM,
                                                       NULL,
                                                       default_1rtt_read,
                                                       sizeof(default_1rtt_read),
                                                       dhs->args.yield_secret_cb_arg)) {
                            dhs->state = QUIC_DHS_SERVER_STATE_ERROR;
                            return 0;
                        }

                        if (!dhs->args.handshake_complete_cb(dhs->args.handshake_complete_cb_arg)) {
                            dhs->state = QUIC_DHS_SERVER_STATE_ERROR;
                            return 0;
                        }

                        dhs->state = QUIC_DHS_SERVER_STATE_RECEIVED_FINISHED;
                    } else {
                        dhs->state = QUIC_DHS_SERVER_STATE_ERROR;
                        return 0; /* error state, unexpected type */
                    }
                } else if (ret == 2) {
                    return 1; /* no more data yet, not an error */
                } else {
                    return 0;
                }
                break;

            case QUIC_DHS_SERVER_STATE_RECEIVED_FINISHED:
                /* Nothing to do, handshake complete. */
                return 1;

            default:
                return 0; /* error state */
        }
    }

    return 1;
}

int ossl_quic_dhs_tick(QUIC_DHS *dhs)
{
    if (dhs->args.is_server)
        return dhs_tick_server(dhs);
    else
        return dhs_tick_client(dhs);
}
