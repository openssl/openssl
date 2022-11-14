/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_LOCAL_H
# define OSSL_QUIC_LOCAL_H

# include <openssl/ssl.h>
# include "internal/quic_ssl.h"       /* QUIC_CONNECTION */
# include "internal/quic_txp.h"
# include "internal/quic_statm.h"
# include "internal/quic_demux.h"
# include "internal/quic_record_rx.h"
# include "internal/quic_dummy_handshake.h"
# include "internal/quic_fc.h"
# include "internal/quic_stream.h"
# include "../ssl_local.h"

# ifndef OPENSSL_NO_QUIC

typedef struct quic_tick_result_st {
    char        want_net_read;
    char        want_net_write;
    OSSL_TIME   tick_deadline;
} QUIC_TICK_RESULT;

typedef struct quic_reactor_st {
    /*
     * BIO poll descriptors which can be polled. poll_r is a poll descriptor
     * which becomes readable when the QUIC state machine can potentially do
     * work, and poll_w is a poll descriptor which becomes writable when the
     * QUIC state machine can potentially do work. Generally, either of these
     * conditions means that SSL_tick() should be called, or another SSL
     * function which implicitly calls SSL_tick() (e.g. SSL_read/SSL_write()).
     */
    BIO_POLL_DESCRIPTOR poll_r, poll_w;
    OSSL_TIME tick_deadline; /* ossl_time_infinite() if none currently applicable */

    void (*tick_cb)(QUIC_TICK_RESULT *res, void *arg);
    void *tick_cb_arg;

    /*
     * These are true if we would like to know when we can read or write from
     * the network respectively.
     */
    unsigned int want_net_read  : 1;
    unsigned int want_net_write : 1;
} QUIC_REACTOR;

/* Represents the cause for a connection's termination. */
typedef struct quic_terminate_cause_st {
    /*
     * If we are in a TERMINATING or TERMINATED state, this is the error code
     * associated with the error. This field is valid iff we are in the
     * TERMINATING or TERMINATED states.
     */
    uint64_t                        error_code;

    /*
     * If terminate_app is set and this is nonzero, this is the frame type which
     * caused the connection to be terminated.
     */
    uint64_t                        frame_type;

    /* Is this error code in the transport (0) or application (1) space? */
    unsigned int                    app : 1;

    /*
     * If set, the cause of the termination is a received CONNECTION_CLOSE
     * frame. Otherwise, we decided to terminate ourselves and sent a
     * CONNECTION_CLOSE frame (regardless of whether the peer later also sends
     * one).
     */
    unsigned int                    remote : 1;
} QUIC_TERMINATE_CAUSE;

#define QUIC_CONN_STATE_IDLE                        0
#define QUIC_CONN_STATE_ACTIVE                      1
#define QUIC_CONN_STATE_TERMINATING_CLOSING         2
#define QUIC_CONN_STATE_TERMINATING_DRAINING        3
#define QUIC_CONN_STATE_TERMINATED                  4

struct quic_conn_st {
    /*
     * ssl_st is a common header for ordinary SSL objects, QUIC connection
     * objects and QUIC stream objects, allowing objects of these different
     * types to be disambiguated at runtime and providing some common fields.
     *
     * Note: This must come first in the QUIC_CONNECTION structure.
     */
    struct ssl_st                   ssl;

    /*
     * The associated TLS 1.3 connection data. Used to provide the handshake
     * layer; its 'network' side is plugged into the crypto stream for each EL
     * (other than the 0-RTT EL).
     */
    SSL                             *tls;
    QUIC_DHS                        *dhs;

    /*
     * The transport parameter block we will send or have sent.
     * Freed after sending or when connection is freed.
     */
    unsigned char                   *client_transport_params;

    /* Asynchronous I/O reactor. */
    QUIC_REACTOR                    rtor;

    /* The initial L4 address of the peer to use. */
    BIO_ADDR                        init_peer_addr;

    /* Network-side read and write BIOs. */
    BIO                             *net_rbio, *net_wbio;

    /*
     * Subcomponents of the connection. All of these components are instantiated
     * and owned by us.
     */
    OSSL_QUIC_TX_PACKETISER         *txp;
    QUIC_TXPIM                      *txpim;
    QUIC_CFQ                        *cfq;
    /* Connection level FC. */
    QUIC_TXFC                       conn_txfc;
    QUIC_RXFC                       conn_rxfc;
    QUIC_STREAM_MAP                 qsm;
    OSSL_STATM                      statm;
    OSSL_CC_DATA                    *cc_data;
    const OSSL_CC_METHOD            *cc_method;
    OSSL_ACKM                       *ackm;

    /*
     * RX demuxer. We register incoming DCIDs with this. Since we currently only
     * support client operation and use one L4 port per connection, we own the
     * demuxer and register a single zero-length DCID with it.
     */
    QUIC_DEMUX                      *demux;

    /* Record layers in the TX and RX directions, plus the RX demuxer. */
    OSSL_QTX                        *qtx;
    OSSL_QRX                        *qrx;

    /*
     * Send and receive parts of the crypto streams.
     * crypto_send[QUIC_PN_SPACE_APP] is the 1-RTT crypto stream. There is no
     * 0-RTT crypto stream.
     */
    QUIC_SSTREAM                    *crypto_send[QUIC_PN_SPACE_NUM];
    QUIC_RSTREAM                    *crypto_recv[QUIC_PN_SPACE_NUM];

    /*
     * Our (currently only) application data stream. This is a bidirectional
     * client-initiated stream and thus (in QUICv1) always has a stream ID of 0.
     */
    QUIC_STREAM                     *stream0;

    /* Internal state. */
    /*
     * The DCID used in the first Initial packet we transmit as a client.
     * Randomly generated and required by RFC to be at least 8 bytes.
     */
    QUIC_CONN_ID                    init_dcid;

    /*
     * The SCID found in the first Initial packet from the server.
     * Valid if have_received_enc_pkt is set.
     */
    QUIC_CONN_ID                    init_scid;

    /* The SCID found in an incoming Retry packet we handled. */
    QUIC_CONN_ID                    retry_scid;

    /* Transport parameter values received from server. */
    uint64_t                        init_max_stream_data_bidi_local;
    uint64_t                        init_max_stream_data_bidi_remote;
    uint64_t                        init_max_stream_data_uni_remote;
    uint64_t                        rx_max_ack_delay; /* ms */
    unsigned char                   rx_ack_delay_exp;

    /*
     * Temporary staging area to store information about the incoming packet we
     * are currently processing.
     */
    OSSL_QRX_PKT                    *qrx_pkt;

    /*
     * Current limit on number of streams we may create. Set by transport
     * parameters initially and then by MAX_STREAMS frames.
     */
    uint64_t                        max_local_streams_bidi;
    uint64_t                        max_local_streams_uni;

    /* The negotiated maximum idle timeout in milliseconds. */
    uint64_t                        max_idle_timeout;

    /*
     * Maximum payload size in bytes for datagrams sent to our peer, as
     * negotiated by transport parameters.
     */
    uint64_t                        rx_max_udp_payload_size;
    /* Maximum active CID limit, as negotiated by transport parameters. */
    uint64_t                        rx_active_conn_id_limit;

    /* Valid if we are in the TERMINATING or TERMINATED states. */
    QUIC_TERMINATE_CAUSE            terminate_cause;

    /*
     * Deadline at which we move to TERMINATING state. Valid if in the
     * TERMINATING state.
     */
    OSSL_TIME                       terminate_deadline;

    /*
     * Deadline at which connection dies due to idle timeout if no further
     * events occur.
     */
    OSSL_TIME                       idle_deadline;

    /*
     * State tracking. QUIC connection-level state is best represented based on
     * whether various things have happened yet or not, rather than as an
     * explicit FSM. We do have a coarse state variable which tracks the basic
     * state of the connection's lifecycle, but more fine-grained conditions of
     * the Active state are tracked via flags below. For more details, see
     * doc/designs/quic-design/connection-state-machine.md. We are in the Open
     * state if the state is QUIC_CSM_STATE_ACTIVE and handshake_confirmed is
     * set.
     */
    unsigned int                    state                   : 3;

    /*
     * Have we received at least one encrypted packet from the peer?
     * (If so, Retry and Version Negotiation messages should no longer
     *  be received and should be ignored if they do occur.)
     */
    unsigned int                    have_received_enc_pkt   : 1;

    /*
     * Have we sent literally any packet yet? If not, there is no point polling
     * RX.
     */
    unsigned int                    have_sent_any_pkt       : 1;

    /*
     * Are we currently doing proactive version negotiation?
     */
    unsigned int                    doing_proactive_ver_neg : 1;

    /* We have received transport parameters from the peer. */
    unsigned int                    got_transport_params    : 1;

    /*
     * This monotonically transitions to 1 once the TLS state machine is
     * 'complete', meaning that it has both sent a Finished and successfully
     * verified the peer's Finished (see RFC 9001 s. 4.1.1). Note that it
     * does not transition to 1 at both peers simultaneously.
     *
     * Handshake completion is not the same as handshake confirmation (see
     * below).
     */
    unsigned int                    handshake_complete      : 1;

    /*
     * This monotonically transitions to 1 once the handshake is confirmed.
     * This happens on the client when we receive a HANDSHAKE_DONE frame.
     * At our option, we may also take acknowledgement of any 1-RTT packet
     * we sent as a handshake confirmation.
     */
    unsigned int                    handshake_confirmed     : 1;

    /*
     * We are sending Initial packets based on a Retry. This means we definitely
     * should not receive another Retry, and if we do it is an error.
     */
    unsigned int                    doing_retry             : 1;

    /*
     * We don't store the current EL here; the TXP asks the QTX which ELs
     * are provisioned to determine which ELs to use.
     */

    /* Have statm, qsm been initialised? Used to track cleanup. */
    unsigned int                    have_statm              : 1;
    unsigned int                    have_qsm                : 1;

    /*
     * Preferred EL for transmission. This is not strictly needed as it can be
     * inferred from what keys we have provisioned, but makes determining the
     * current EL simpler and faster.
     */
    unsigned int                    tx_enc_level            : 3;

    /* If bit n is set, EL n has been discarded. */
    unsigned int                    el_discarded            : 4;

    /* Are we in blocking mode? */
    unsigned int                    blocking                : 1;

    /*
     * While in TERMINATING - CLOSING, set when we should generate a connection
     * close frame.
     */
    unsigned int                    conn_close_queued       : 1;

    /*
     * This state tracks SSL_write all-or-nothing (AON) write semantics
     * emulation.
     *
     * Example chronology:
     *
     *   t=0:  aon_write_in_progress=0
     *   t=1:  SSL_write(ssl, b1, l1) called;
     *         too big to enqueue into sstream at once, SSL_ERROR_WANT_WRITE;
     *         aon_write_in_progress=1; aon_buf_base=b1; aon_buf_len=l1;
     *         aon_buf_pos < l1 (depends on how much room was in sstream);
     *   t=2:  SSL_write(ssl, b2, l2);
     *         b2 must equal b1 (validated unless ACCEPT_MOVING_WRITE_BUFFER)
     *         l2 must equal l1 (always validated)
     *         append into sstream from [b2 + aon_buf_pos, b2 + aon_buf_len)
     *         if done, aon_write_in_progess=0
     *
     */
    /* Is an AON write in progress? */
    unsigned int                    aon_write_in_progress   : 1;
    /*
     * The base buffer pointer the caller passed us for the initial AON write
     * call. We use this for validation purposes unless
     * ACCEPT_MOVING_WRITE_BUFFER is enabled.
     *
     * NOTE: We never dereference this, as the caller might pass a different
     * (but identical) buffer if using ACCEPT_MOVING_WRITE_BUFFER. It is for
     * validation by pointer comparison only.
     */
    const unsigned char             *aon_buf_base;
    /* The total length of the AON buffer being sent, in bytes. */
    size_t                          aon_buf_len;
    /*
     * The position in the AON buffer up to which we have successfully sent data
     * so far.
     */
    size_t                          aon_buf_pos;

    /* SSL_set_mode */
    uint32_t                        ssl_mode;

    /*
     * Last 'normal' error during an app-level I/O operation, used by
     * SSL_get_error(); used to track data-path errors like SSL_ERROR_WANT_READ
     * and SSL_ERROR_WANT_WRITE.
     */
    int                             last_error;
};

/* Internal calls to the QUIC CSM which come from various places. */
int ossl_quic_conn_on_handshake_confirmed(QUIC_CONNECTION *qc);

/*
 * To be called when a protocol violation occurs. The connection is torn down
 * with the given error code, which should be a QUIC_ERR_* value. Reason string
 * is optional and copied if provided. frame_type should be 0 if not applicable.
 */
void ossl_quic_conn_raise_protocol_error(QUIC_CONNECTION *qc,
                                         uint64_t error_code,
                                         uint64_t frame_type,
                                         const char *reason);

void ossl_quic_conn_on_remote_conn_close(QUIC_CONNECTION *qc,
                                         OSSL_QUIC_FRAME_CONN_CLOSE *f);

#  define OSSL_QUIC_ANY_VERSION 0xFFFFF

#  define QUIC_CONNECTION_FROM_SSL_int(ssl, c)   \
     ((ssl) == NULL ? NULL                       \
      : ((ssl)->type == SSL_TYPE_QUIC_CONNECTION \
         ? (c QUIC_CONNECTION *)(ssl)            \
         : NULL))

#  define QUIC_STREAM_FROM_SSL_int(ssl, c)       \
     ((ssl) == NULL ? NULL                       \
      : ((ssl)->type == SSL_TYPE_QUIC_CONNECTION \
          || (ssl)->type == SSL_TYPE_QUIC_STREAM \
         ? (c QUIC_STREAM *)(ssl)                \
         : NULL))

#  define SSL_CONNECTION_FROM_QUIC_SSL_int(ssl, c)               \
     ((ssl) == NULL ? NULL                                       \
      : ((ssl)->type == SSL_TYPE_QUIC_CONNECTION                 \
         ? (c SSL_CONNECTION *)((c QUIC_CONNECTION *)(ssl))->tls \
         : NULL))
# else
#  define QUIC_CONNECTION_FROM_SSL_int(ssl, c) NULL
#  define QUIC_STREAM_FROM_SSL_int(ssl, c) NULL
#  define SSL_CONNECTION_FROM_QUIC_SSL_int(ssl, c) NULL
# endif

# define QUIC_CONNECTION_FROM_SSL(ssl) \
    QUIC_CONNECTION_FROM_SSL_int(ssl, SSL_CONNECTION_NO_CONST)
# define QUIC_CONNECTION_FROM_CONST_SSL(ssl) \
    QUIC_CONNECTION_FROM_SSL_int(ssl, const)
# define QUIC_STREAM_FROM_SSL(ssl) \
    QUIC_STREAM_FROM_SSL_int(ssl, SSL_CONNECTION_NO_CONST)
# define QUIC_STREAM_FROM_CONST_SSL(ssl) \
    QUIC_STREAM_FROM_SSL_int(ssl, const)
# define SSL_CONNECTION_FROM_QUIC_SSL(ssl) \
    SSL_CONNECTION_FROM_QUIC_SSL_int(ssl, SSL_CONNECTION_NO_CONST)
# define SSL_CONNECTION_FROM_CONST_QUIC_SSL(ssl) \
    SSL_CONNECTION_FROM_CONST_QUIC_SSL_int(ssl, const)

# define IMPLEMENT_quic_meth_func(version, func_name, q_accept, \
                                 q_connect, enc_data) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                version, \
                0, \
                0, \
                ossl_quic_new, \
                ossl_quic_free, \
                ossl_quic_reset, \
                ossl_quic_init, \
                ossl_quic_clear, \
                ossl_quic_deinit, \
                q_accept, \
                q_connect, \
                ossl_quic_read, \
                ossl_quic_peek, \
                ossl_quic_write, \
                ossl_quic_shutdown, \
                NULL /* renegotiate */, \
                ossl_quic_renegotiate_check, \
                NULL /* read_bytes */, \
                NULL /* write_bytes */, \
                NULL /* dispatch_alert */, \
                ossl_quic_ctrl, \
                ossl_quic_ctx_ctrl, \
                NULL /* get_cipher_by_char */, \
                NULL /* put_cipher_by_char */, \
                ossl_quic_pending, \
                ossl_quic_num_ciphers, \
                ossl_quic_get_cipher, \
                tls1_default_timeout, \
                &enc_data, \
                ssl_undefined_void_function, \
                ossl_quic_callback_ctrl, \
                ossl_quic_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }

#endif
