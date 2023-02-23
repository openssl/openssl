#ifndef OSSL_QUIC_CHANNEL_LOCAL_H
# define OSSL_QUIC_CHANNEL_LOCAL_H

# include "internal/quic_channel.h"

# ifndef OPENSSL_NO_QUIC

/*
 * QUIC Channel Structure
 * ======================
 *
 * QUIC channel internals. It is intended that only the QUIC_CHANNEL
 * implementation and the RX depacketiser be allowed to access this structure
 * directly. As the RX depacketiser has no state of its own and computes over a
 * QUIC_CHANNEL structure, it can be viewed as an extention of the QUIC_CHANNEL
 * implementation. While the RX depacketiser could be provided with adequate
 * accessors to do what it needs, this would weaken the abstraction provided by
 * the QUIC_CHANNEL to other components; moreover the coupling of the RX
 * depacketiser to QUIC_CHANNEL internals is too deep and bespoke to make this
 * desirable.
 *
 * Other components should not include this header.
 */
struct quic_channel_st {
    OSSL_LIB_CTX                    *libctx;
    const char                      *propq;

    /*
     * Master synchronisation mutex used for thread assisted mode
     * synchronisation. We don't own this; the instantiator of the channel
     * passes it to us and is responsible for freeing it after channel
     * destruction.
     */
    CRYPTO_MUTEX                    *mutex;

    /*
     * Callback used to get the current time.
     */
    OSSL_TIME                       (*now_cb)(void *arg);
    void                            *now_cb_arg;

    /*
     * The associated TLS 1.3 connection data. Used to provide the handshake
     * layer; its 'network' side is plugged into the crypto stream for each EL
     * (other than the 0-RTT EL).
     */
    QUIC_TLS                        *qtls;
    SSL                             *tls;

    /*
     * The transport parameter block we will send or have sent.
     * Freed after sending or when connection is freed.
     */
    unsigned char                   *local_transport_params;

    /* Asynchronous I/O reactor. */
    QUIC_REACTOR                    rtor;

    /* Our current L4 peer address, if any. */
    BIO_ADDR                        cur_peer_addr;

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
     * Client: The DCID used in the first Initial packet we transmit as a client.
     * Server: The DCID used in the first Initial packet the client transmitted.
     * Randomly generated and required by RFC to be at least 8 bytes.
     */
    QUIC_CONN_ID                    init_dcid;

    /*
     * Client: The SCID found in the first Initial packet from the server.
     * Not valid for servers.
     * Valid if have_received_enc_pkt is set.
     */
    QUIC_CONN_ID                    init_scid;

    /*
     * Client only: The SCID found in an incoming Retry packet we handled.
     * Not valid for servers.
     */
    QUIC_CONN_ID                    retry_scid;

    /* Server only: The DCID we currently use to talk to the peer. */
    QUIC_CONN_ID                    cur_remote_dcid;
    /* Server only: The DCID we currently expect the peer to use to talk to us. */
    QUIC_CONN_ID                    cur_local_dcid;

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
     * Deadline at which we should send an ACK-eliciting packet to ensure
     * idle timeout does not occur.
     */
    OSSL_TIME                       ping_deadline;

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
    unsigned int                    got_remote_transport_params    : 1;

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
     * Preferred ELs for transmission and reception. This is not strictly needed
     * as it can be inferred from what keys we have provisioned, but makes
     * determining the current EL simpler and faster. A separate EL for
     * transmission and reception is not strictly necessary but makes things
     * easier for interoperation with the handshake layer, which likes to invoke
     * the yield secret callback at different times for TX and RX.
     */
    unsigned int                    tx_enc_level            : 3;
    unsigned int                    rx_enc_level            : 3;

    /* If bit n is set, EL n has been discarded. */
    unsigned int                    el_discarded            : 4;

    /*
     * While in TERMINATING - CLOSING, set when we should generate a connection
     * close frame.
     */
    unsigned int                    conn_close_queued       : 1;

    /* Are we in server mode? Never changes after instantiation. */
    unsigned int                    is_server               : 1;

    /*
     * Set temporarily when the handshake layer has given us a new RX secret.
     * Used to determine if we need to check our RX queues again.
     */
    unsigned int                    have_new_rx_secret      : 1;

    /*
     * Have we sent an ack-eliciting packet since the last successful packet
     * reception? Used to determine when to bump idle timer (see RFC 9000 s.
     * 10.1).
     */
    unsigned int                    have_sent_ack_eliciting_since_rx    : 1;
};

# endif

#endif
