/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/quic_port.h"
#include "internal/quic_channel.h"
#include "internal/quic_lcidm.h"
#include "internal/quic_srtm.h"
#include "internal/ssl_unwrap.h"
#include "quic_port_local.h"
#include "quic_channel_local.h"
#include "quic_engine_local.h"
#include "../ssl_local.h"

/*
 * QUIC Port Structure
 * ===================
 */
#define INIT_DCID_LEN                   8

static int port_init(QUIC_PORT *port);
static void port_cleanup(QUIC_PORT *port);
static OSSL_TIME get_time(void *arg);
static void port_default_packet_handler(QUIC_URXE *e, void *arg,
                                        const QUIC_CONN_ID *dcid);
static void port_rx_pre(QUIC_PORT *port);

/**
 * @struct validation_token
 * @brief Represents a validation token for secure connection handling.
 *
 * This struct is used to store information related to a validation token,
 * including the token buffer, original connection ID, and an integrity tag
 * for secure validation of QUIC connections.
 *
 * @var validation_token::token_buf
 * A character array holding the token data. The size of this array is
 * based on the length of the string "openssltoken" minus one for the null
 * terminator.
 *
 * @var validation_token::token_odcid
 * An original connection ID (`QUIC_CONN_ID`) used to identify the QUIC
 * connection. This ID helps associate the token with a specific connection.
 *
 * @var validation_token::integrity_tag
 * A character array for the integrity tag, with a length defined by
 * `QUIC_RETRY_INTEGRITY_TAG_LEN`. This tag is used to verify the integrity
 * of the token during the connection process.
 */
struct validation_token {
    char token_buf[sizeof("openssltoken") - 1];
    QUIC_CONN_ID token_odcid;
    char integrity_tag[QUIC_RETRY_INTEGRITY_TAG_LEN];
};

DEFINE_LIST_OF_IMPL(ch, QUIC_CHANNEL);
DEFINE_LIST_OF_IMPL(incoming_ch, QUIC_CHANNEL);
DEFINE_LIST_OF_IMPL(port, QUIC_PORT);

QUIC_PORT *ossl_quic_port_new(const QUIC_PORT_ARGS *args)
{
    QUIC_PORT *port;

    if ((port = OPENSSL_zalloc(sizeof(QUIC_PORT))) == NULL)
        return NULL;

    port->engine        = args->engine;
    port->channel_ctx   = args->channel_ctx;
    port->is_multi_conn = args->is_multi_conn;

    if (!port_init(port)) {
        OPENSSL_free(port);
        return NULL;
    }

    return port;
}

void ossl_quic_port_free(QUIC_PORT *port)
{
    if (port == NULL)
        return;

    port_cleanup(port);
    OPENSSL_free(port);
}

static int port_init(QUIC_PORT *port)
{
    size_t rx_short_dcid_len = (port->is_multi_conn ? INIT_DCID_LEN : 0);

    if (port->engine == NULL || port->channel_ctx == NULL)
        goto err;

    if ((port->err_state = OSSL_ERR_STATE_new()) == NULL)
        goto err;

    if ((port->demux = ossl_quic_demux_new(/*BIO=*/NULL,
                                           /*Short CID Len=*/rx_short_dcid_len,
                                           get_time, port)) == NULL)
        goto err;

    ossl_quic_demux_set_default_handler(port->demux,
                                        port_default_packet_handler,
                                        port);

    if ((port->srtm = ossl_quic_srtm_new(port->engine->libctx,
                                         port->engine->propq)) == NULL)
        goto err;

    if ((port->lcidm = ossl_quic_lcidm_new(port->engine->libctx,
                                           rx_short_dcid_len)) == NULL)
        goto err;

    port->rx_short_dcid_len = (unsigned char)rx_short_dcid_len;
    port->tx_init_dcid_len  = INIT_DCID_LEN;
    port->state             = QUIC_PORT_STATE_RUNNING;

    ossl_list_port_insert_tail(&port->engine->port_list, port);
    port->on_engine_list    = 1;
    port->bio_changed       = 1;
    return 1;

err:
    port_cleanup(port);
    return 0;
}

static void port_cleanup(QUIC_PORT *port)
{
    assert(ossl_list_ch_num(&port->channel_list) == 0);

    ossl_quic_demux_free(port->demux);
    port->demux = NULL;

    ossl_quic_srtm_free(port->srtm);
    port->srtm = NULL;

    ossl_quic_lcidm_free(port->lcidm);
    port->lcidm = NULL;

    OSSL_ERR_STATE_free(port->err_state);
    port->err_state = NULL;

    if (port->on_engine_list) {
        ossl_list_port_remove(&port->engine->port_list, port);
        port->on_engine_list = 0;
    }
}

static void port_transition_failed(QUIC_PORT *port)
{
    if (port->state == QUIC_PORT_STATE_FAILED)
        return;

    port->state = QUIC_PORT_STATE_FAILED;
}

int ossl_quic_port_is_running(const QUIC_PORT *port)
{
    return port->state == QUIC_PORT_STATE_RUNNING;
}

QUIC_ENGINE *ossl_quic_port_get0_engine(QUIC_PORT *port)
{
    return port->engine;
}

QUIC_REACTOR *ossl_quic_port_get0_reactor(QUIC_PORT *port)
{
    return ossl_quic_engine_get0_reactor(port->engine);
}

QUIC_DEMUX *ossl_quic_port_get0_demux(QUIC_PORT *port)
{
    return port->demux;
}

CRYPTO_MUTEX *ossl_quic_port_get0_mutex(QUIC_PORT *port)
{
    return ossl_quic_engine_get0_mutex(port->engine);
}

OSSL_TIME ossl_quic_port_get_time(QUIC_PORT *port)
{
    return ossl_quic_engine_get_time(port->engine);
}

static OSSL_TIME get_time(void *port)
{
    return ossl_quic_port_get_time((QUIC_PORT *)port);
}

int ossl_quic_port_get_rx_short_dcid_len(const QUIC_PORT *port)
{
    return port->rx_short_dcid_len;
}

int ossl_quic_port_get_tx_init_dcid_len(const QUIC_PORT *port)
{
    return port->tx_init_dcid_len;
}

size_t ossl_quic_port_get_num_incoming_channels(const QUIC_PORT *port)
{
    return ossl_list_incoming_ch_num(&port->incoming_channel_list);
}

/*
 * QUIC Port: Network BIO Configuration
 * ====================================
 */

/* Determines whether we can support a given poll descriptor. */
static int validate_poll_descriptor(const BIO_POLL_DESCRIPTOR *d)
{
    if (d->type == BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD && d->value.fd < 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    return 1;
}

BIO *ossl_quic_port_get_net_rbio(QUIC_PORT *port)
{
    return port->net_rbio;
}

BIO *ossl_quic_port_get_net_wbio(QUIC_PORT *port)
{
    return port->net_wbio;
}

static int port_update_poll_desc(QUIC_PORT *port, BIO *net_bio, int for_write)
{
    BIO_POLL_DESCRIPTOR d = {0};

    if (net_bio == NULL
        || (!for_write && !BIO_get_rpoll_descriptor(net_bio, &d))
        || (for_write && !BIO_get_wpoll_descriptor(net_bio, &d)))
        /* Non-pollable BIO */
        d.type = BIO_POLL_DESCRIPTOR_TYPE_NONE;

    if (!validate_poll_descriptor(&d))
        return 0;

    /*
     * TODO(QUIC MULTIPORT): We currently only support one port per
     * engine/domain. This is necessitated because QUIC_REACTOR only supports a
     * single pollable currently. In the future, once complete polling
     * infrastructure has been implemented, this limitation can be removed.
     *
     * For now, just update the descriptor on the engine's reactor as we are
     * guaranteed to be the only port under it.
     */
    if (for_write)
        ossl_quic_reactor_set_poll_w(&port->engine->rtor, &d);
    else
        ossl_quic_reactor_set_poll_r(&port->engine->rtor, &d);

    return 1;
}

int ossl_quic_port_update_poll_descriptors(QUIC_PORT *port, int force)
{
    int ok = 1;

    if (!force && !port->bio_changed)
        return 0;

    if (!port_update_poll_desc(port, port->net_rbio, /*for_write=*/0))
        ok = 0;

    if (!port_update_poll_desc(port, port->net_wbio, /*for_write=*/1))
        ok = 0;

    port->bio_changed = 0;
    return ok;
}

/*
 * We need to determine our addressing mode. There are basically two ways we can
 * use L4 addresses:
 *
 *   - Addressed mode, in which our BIO_sendmmsg calls have destination
 *     addresses attached to them which we expect the underlying network BIO to
 *     handle;
 *
 *   - Unaddressed mode, in which the BIO provided to us on the network side
 *     neither provides us with L4 addresses nor is capable of honouring ones we
 *     provide. We don't know where the QUIC traffic we send ends up exactly and
 *     trust the application to know what it is doing.
 *
 * Addressed mode is preferred because it enables support for connection
 * migration, multipath, etc. in the future. Addressed mode is automatically
 * enabled if we are using e.g. BIO_s_datagram, with or without BIO_s_connect.
 *
 * If we are passed a BIO_s_dgram_pair (or some custom BIO) we may have to use
 * unaddressed mode unless that BIO supports capability flags indicating it can
 * provide and honour L4 addresses.
 *
 * Our strategy for determining address mode is simple: we probe the underlying
 * network BIOs for their capabilities. If the network BIOs support what we
 * need, we use addressed mode. Otherwise, we use unaddressed mode.
 *
 * If addressed mode is chosen, we require an initial peer address to be set. If
 * this is not set, we fail. If unaddressed mode is used, we do not require
 * this, as such an address is superfluous, though it can be set if desired.
 */
static void port_update_addressing_mode(QUIC_PORT *port)
{
    long rcaps = 0, wcaps = 0;

    if (port->net_rbio != NULL)
        rcaps = BIO_dgram_get_effective_caps(port->net_rbio);

    if (port->net_wbio != NULL)
        wcaps = BIO_dgram_get_effective_caps(port->net_wbio);

    port->addressed_mode_r = ((rcaps & BIO_DGRAM_CAP_PROVIDES_SRC_ADDR) != 0);
    port->addressed_mode_w = ((wcaps & BIO_DGRAM_CAP_HANDLES_DST_ADDR) != 0);
    port->bio_changed = 1;
}

int ossl_quic_port_is_addressed_r(const QUIC_PORT *port)
{
    return port->addressed_mode_r;
}

int ossl_quic_port_is_addressed_w(const QUIC_PORT *port)
{
    return port->addressed_mode_w;
}

int ossl_quic_port_is_addressed(const QUIC_PORT *port)
{
    return ossl_quic_port_is_addressed_r(port) && ossl_quic_port_is_addressed_w(port);
}

/*
 * QUIC_PORT does not ref any BIO it is provided with, nor is any ref
 * transferred to it. The caller (e.g., QUIC_CONNECTION) is responsible for
 * ensuring the BIO lasts until the channel is freed or the BIO is switched out
 * for another BIO by a subsequent successful call to this function.
 */
int ossl_quic_port_set_net_rbio(QUIC_PORT *port, BIO *net_rbio)
{
    if (port->net_rbio == net_rbio)
        return 1;

    if (!port_update_poll_desc(port, net_rbio, /*for_write=*/0))
        return 0;

    ossl_quic_demux_set_bio(port->demux, net_rbio);
    port->net_rbio = net_rbio;
    port_update_addressing_mode(port);
    return 1;
}

int ossl_quic_port_set_net_wbio(QUIC_PORT *port, BIO *net_wbio)
{
    QUIC_CHANNEL *ch;

    if (port->net_wbio == net_wbio)
        return 1;

    if (!port_update_poll_desc(port, net_wbio, /*for_write=*/1))
        return 0;

    OSSL_LIST_FOREACH(ch, ch, &port->channel_list)
        ossl_qtx_set_bio(ch->qtx, net_wbio);

    port->net_wbio = net_wbio;
    port_update_addressing_mode(port);
    return 1;
}

/*
 * QUIC Port: Channel Lifecycle
 * ============================
 */

static SSL *port_new_handshake_layer(QUIC_PORT *port)
{
    SSL *tls = NULL;
    SSL_CONNECTION *tls_conn = NULL;

    /*
     * TODO(QUIC SERVER): NULL below needs to be replaced with a real user SSL
     * object of either the listener or the domain which is associated with
     * the port. https://github.com/openssl/project/issues/918
     */
    tls = ossl_ssl_connection_new_int(port->channel_ctx, NULL, TLS_method());
    if (tls == NULL || (tls_conn = SSL_CONNECTION_FROM_SSL(tls)) == NULL)
        return NULL;

    /* Override the user_ssl of the inner connection. */
    tls_conn->s3.flags      |= TLS1_FLAGS_QUIC;

    /* Restrict options derived from the SSL_CTX. */
    tls_conn->options       &= OSSL_QUIC_PERMITTED_OPTIONS_CONN;
    tls_conn->pha_enabled   = 0;
    return tls;
}

static QUIC_CHANNEL *port_make_channel(QUIC_PORT *port, SSL *tls, int is_server)
{
    QUIC_CHANNEL_ARGS args = {0};
    QUIC_CHANNEL *ch;

    args.port       = port;
    args.is_server  = is_server;
    args.tls        = (tls != NULL ? tls : port_new_handshake_layer(port));
    args.lcidm      = port->lcidm;
    args.srtm       = port->srtm;
    if (args.tls == NULL)
        return NULL;

#ifndef OPENSSL_NO_QLOG
    args.use_qlog   = 1; /* disabled if env not set */
    args.qlog_title = args.tls->ctx->qlog_title;
#endif

    ch = ossl_quic_channel_new(&args);
    if (ch == NULL) {
        if (tls == NULL)
            SSL_free(args.tls);

        return NULL;
    }

    ossl_qtx_set_bio(ch->qtx, port->net_wbio);
    return ch;
}

QUIC_CHANNEL *ossl_quic_port_create_outgoing(QUIC_PORT *port, SSL *tls)
{
    return port_make_channel(port, tls, /*is_server=*/0);
}

QUIC_CHANNEL *ossl_quic_port_create_incoming(QUIC_PORT *port, SSL *tls)
{
    QUIC_CHANNEL *ch;

    assert(port->tserver_ch == NULL);

    ch = port_make_channel(port, tls, /*is_server=*/1);
    port->tserver_ch = ch;
    port->allow_incoming = 1;
    return ch;
}

QUIC_CHANNEL *ossl_quic_port_pop_incoming(QUIC_PORT *port)
{
    QUIC_CHANNEL *ch;

    ch = ossl_list_incoming_ch_head(&port->incoming_channel_list);
    if (ch == NULL)
        return NULL;

    ossl_list_incoming_ch_remove(&port->incoming_channel_list, ch);
    return ch;
}

int ossl_quic_port_have_incoming(QUIC_PORT *port)
{
    return ossl_list_incoming_ch_head(&port->incoming_channel_list) != NULL;
}

void ossl_quic_port_drop_incoming(QUIC_PORT *port)
{
    QUIC_CHANNEL *ch;
    SSL *tls;

    for (;;) {
        ch = ossl_quic_port_pop_incoming(port);
        if (ch == NULL)
            break;

        tls = ossl_quic_channel_get0_tls(ch);
        ossl_quic_channel_free(ch);
        SSL_free(tls);
    }
}

void ossl_quic_port_set_allow_incoming(QUIC_PORT *port, int allow_incoming)
{
    port->allow_incoming = allow_incoming;
}

/*
 * QUIC Port: Ticker-Mutator
 * =========================
 */

/*
 * Tick function for this port. This does everything related to network I/O for
 * this port's network BIOs, and services child channels.
 */
void ossl_quic_port_subtick(QUIC_PORT *port, QUIC_TICK_RESULT *res,
                            uint32_t flags)
{
    QUIC_CHANNEL *ch;

    res->net_read_desired       = ossl_quic_port_is_running(port);
    res->net_write_desired      = 0;
    res->notify_other_threads   = 0;
    res->tick_deadline          = ossl_time_infinite();

    if (!port->engine->inhibit_tick) {
        /* Handle any incoming data from network. */
        if (ossl_quic_port_is_running(port))
            port_rx_pre(port);

        /* Iterate through all channels and service them. */
        OSSL_LIST_FOREACH(ch, ch, &port->channel_list) {
            QUIC_TICK_RESULT subr = {0};

            ossl_quic_channel_subtick(ch, &subr, flags);
            ossl_quic_tick_result_merge_into(res, &subr);
        }
    }
}

/* Process incoming datagrams, if any. */
static void port_rx_pre(QUIC_PORT *port)
{
    int ret;

    /*
     * Originally, this check (don't RX before we have sent anything if we are
     * not a server, because there can't be anything) was just intended as a
     * minor optimisation. However, it is actually required on Windows, and
     * removing this check will cause Windows to break.
     *
     * The reason is that under Win32, recvfrom() does not work on a UDP socket
     * which has not had bind() called (???). However, calling sendto() will
     * automatically bind an unbound UDP socket. Therefore, if we call a Winsock
     * recv-type function before calling a Winsock send-type function, that call
     * will fail with WSAEINVAL, which we will regard as a permanent network
     * error.
     *
     * Therefore, this check is essential as we do not require our API users to
     * bind a socket first when using the API in client mode.
     */
    if (!port->allow_incoming && !port->have_sent_any_pkt)
        return;

    /*
     * Get DEMUX to BIO_recvmmsg from the network and queue incoming datagrams
     * to the appropriate QRX instances.
     */
    ret = ossl_quic_demux_pump(port->demux);
    if (ret == QUIC_DEMUX_PUMP_RES_PERMANENT_FAIL)
        /*
         * We don't care about transient failure, but permanent failure means we
         * should tear down the port. All connections skip straight to the
         * Terminated state as there is no point trying to send CONNECTION_CLOSE
         * frames if the network BIO is not operating correctly.
         */
        ossl_quic_port_raise_net_error(port, NULL);
}

/*
 * Handles an incoming connection request and potentially decides to make a
 * connection from it. If a new connection is made, the new channel is written
 * to *new_ch.
 */
static void port_bind_channel(QUIC_PORT *port, const BIO_ADDR *peer,
                              const QUIC_CONN_ID *scid, const QUIC_CONN_ID *dcid,
                              const QUIC_CONN_ID *odcid, QUIC_CHANNEL **new_ch)
{
    QUIC_CHANNEL *ch;

    /*
     * If we're running with a simulated tserver, it will already have
     * a dummy channel created, use that instead
     */
    if (port->tserver_ch != NULL) {
        ch = port->tserver_ch;
        port->tserver_ch = NULL;
    } else {
        ch = port_make_channel(port, NULL, /* is_server= */1);
    }

    if (ch == NULL)
        return;

    if (!ossl_quic_bind_channel(ch, peer, scid, dcid, odcid)) {
        ossl_quic_channel_free(ch);
        return;
    }

    ossl_list_incoming_ch_insert_tail(&port->incoming_channel_list, ch);
    *new_ch = ch;
}

static int port_try_handle_stateless_reset(QUIC_PORT *port, const QUIC_URXE *e)
{
    size_t i;
    const unsigned char *data = ossl_quic_urxe_data(e);
    void *opaque = NULL;

    /*
     * Perform some fast and cheap checks for a packet not being a stateless
     * reset token.  RFC 9000 s. 10.3 specifies this layout for stateless
     * reset packets:
     *
     *  Stateless Reset {
     *      Fixed Bits (2) = 1,
     *      Unpredictable Bits (38..),
     *      Stateless Reset Token (128),
     *  }
     *
     * It also specifies:
     *      However, endpoints MUST treat any packet ending in a valid
     *      stateless reset token as a Stateless Reset, as other QUIC
     *      versions might allow the use of a long header.
     *
     * We can rapidly check for the minimum length and that the first pair
     * of bits in the first byte are 01 or 11.
     *
     * The function returns 1 if it is a stateless reset packet, 0 if it isn't
     * and -1 if an error was encountered.
     */
    if (e->data_len < QUIC_STATELESS_RESET_TOKEN_LEN + 5
        || (0100 & *data) != 0100)
        return 0;

    for (i = 0;; ++i) {
        if (!ossl_quic_srtm_lookup(port->srtm,
                                   (QUIC_STATELESS_RESET_TOKEN *)(data + e->data_len
                                   - sizeof(QUIC_STATELESS_RESET_TOKEN)),
                                   i, &opaque, NULL))
            break;

        assert(opaque != NULL);
        ossl_quic_channel_on_stateless_reset((QUIC_CHANNEL *)opaque);
    }

    return i > 0;
}

#define TOKEN_LEN (sizeof("openssltoken") + \
                   QUIC_RETRY_INTEGRITY_TAG_LEN - 1 + \
                   sizeof(unsigned char))

/**
 * @brief Sends a QUIC Retry packet to a client.
 *
 * This function constructs and sends a Retry packet to the specified client
 * using the provided connection header information. The Retry packet
 * includes a generated validation token and a new connection ID, following
 * the QUIC protocol specifications for connection establishment.
 *
 * @param port        Pointer to the QUIC port from which to send the packet.
 * @param peer        Address of the client peer receiving the packet.
 * @param client_hdr  Header of the client's initial packet, containing
 *                    connection IDs and other relevant information.
 *
 * This function performs the following steps:
 * - Generates a validation token for the client.
 * - Sets the destination and source connection IDs.
 * - Calculates the integrity tag and sets the token length.
 * - Encodes and sends the packet via the BIO network interface.
 *
 * Error handling is included for failures in CID generation, encoding, and
 * network transmiss
 */
static void port_send_retry(QUIC_PORT *port,
                            BIO_ADDR *peer,
                            QUIC_PKT_HDR *client_hdr)
{
    BIO_MSG msg[1];
    unsigned char buffer[512];
    WPACKET wpkt;
    size_t written;
    QUIC_PKT_HDR hdr;
    struct validation_token token;
    size_t token_len = TOKEN_LEN;
    unsigned char *integrity_tag;
    int ok;

    /* TODO(QUIC_SERVER): generate proper validation token */
    memcpy(token.token_buf, "openssltoken", sizeof("openssltoken") - 1);

    token.token_odcid = client_hdr->dst_conn_id;
    token_len += token.token_odcid.id_len;
    integrity_tag = (unsigned char *)&token.token_odcid +
        token.token_odcid.id_len + sizeof(token.token_odcid.id_len);
    /*
     * 17.2.5.1 Sending a Retry packet
     *   dst ConnId is src ConnId we got from client
     *   src ConnId comes from local conn ID manager
     */
    memset(&hdr, 0, sizeof(QUIC_PKT_HDR));
    hdr.dst_conn_id = client_hdr->src_conn_id;
    /*
     * this is the random connection ID, we expect client is
     * going to send the ID with next INITIAL packet which
     * will also come with token we generate here.
     */
    ok = ossl_quic_lcidm_get_unused_cid(port->lcidm, &hdr.src_conn_id);
    if (ok == 0)
        return;

    hdr.dst_conn_id = client_hdr->src_conn_id;
    hdr.type = QUIC_PKT_TYPE_RETRY;
    hdr.fixed = 1;
    hdr.version = 1;
    hdr.len = token_len;
    hdr.data = (unsigned char *)&token;
    ok = ossl_quic_calculate_retry_integrity_tag(port->engine->libctx,
                                                 port->engine->propq, &hdr,
                                                 &client_hdr->dst_conn_id,
                                                 integrity_tag);
    if (ok == 0)
        return;

    hdr.token = (unsigned char *)&token;
    hdr.token_len = token_len;

    msg[0].data = buffer;
    msg[0].peer = peer;
    msg[0].local = NULL;
    msg[0].flags = 0;

    ok = WPACKET_init_static_len(&wpkt, buffer, sizeof(buffer), 0);
    if (ok == 0)
        return;

    ok = ossl_quic_wire_encode_pkt_hdr(&wpkt, client_hdr->dst_conn_id.id_len,
                                       &hdr, NULL);
    if (ok == 0)
        return;

    ok = WPACKET_get_total_written(&wpkt, &msg[0].data_len);
    if (ok == 0)
        return;

    ok = WPACKET_finish(&wpkt);
    if (ok == 0)
        return;

    /*
     * TODO(QUIC SERVER) need to retry this in the event it return EAGAIN
     * on a non-blocking BIO
     */
    if (!BIO_sendmmsg(port->net_wbio, msg, sizeof(BIO_MSG), 1, 0, &written))
        ERR_raise_data(ERR_LIB_SSL, SSL_R_QUIC_NETWORK_ERROR,
                       "port retry send failed due to network BIO I/O error");

}

/**
 * @brief Sends a QUIC Version Negotiation packet to the specified peer.
 *
 * This function constructs and sends a Version Negotiation packet using
 * the connection IDs from the client's initial packet header. The
 * Version Negotiation packet indicates support for QUIC version 1.
 *
 * @param port      Pointer to the QUIC_PORT structure representing the port
 *                  context used for network communication.
 * @param peer      Pointer to the BIO_ADDR structure specifying the address
 *                  of the peer to which the Version Negotiation packet
 *                  will be sent.
 * @param client_hdr Pointer to the QUIC_PKT_HDR structure containing the
 *                  client's packet header used to extract connection IDs.
 *
 * @note The function will raise an error if sending the message fails.
 */
static void port_send_version_negotiation(QUIC_PORT *port, BIO_ADDR *peer,
                                          QUIC_PKT_HDR *client_hdr)
{
    BIO_MSG msg[1];
    unsigned char buffer[1024];
    QUIC_PKT_HDR hdr;
    WPACKET wpkt;
    uint32_t supported_versions[1];
    size_t written;
    size_t i;

    memset(&hdr, 0, sizeof(QUIC_PKT_HDR));
    /*
     * Reverse the source and dst conn ids
     */
    hdr.dst_conn_id = client_hdr->src_conn_id;
    hdr.src_conn_id = client_hdr->dst_conn_id;

    /*
     * This is our list of supported protocol versions
     * Currently only QUIC_VERSION_1
     */
    supported_versions[0] = QUIC_VERSION_1;

    /*
     * Fill out the header fields
     * Note: Version negotiation packets, must, unlike
     * other packet types have a version of 0
     */
    hdr.type = QUIC_PKT_TYPE_VERSION_NEG;
    hdr.version = 0;
    hdr.token = 0;
    hdr.token_len = 0;
    hdr.len = sizeof(supported_versions);
    hdr.data = (unsigned char *)supported_versions;

    msg[0].data = buffer;
    msg[0].peer = peer;
    msg[0].local = NULL;
    msg[0].flags = 0;

    if (!WPACKET_init_static_len(&wpkt, buffer, sizeof(buffer), 0))
        return;

    if (!ossl_quic_wire_encode_pkt_hdr(&wpkt, client_hdr->dst_conn_id.id_len,
                                       &hdr, NULL))
        return;

    /*
     * Add the array of supported versions to the end of the packet
     */
    for (i = 0; i < OSSL_NELEM(supported_versions); i++) {
        if (!WPACKET_put_bytes_u32(&wpkt, htonl(supported_versions[i])))
            return;
    }

    if (!WPACKET_get_total_written(&wpkt, &msg[0].data_len))
        return;

    if (!WPACKET_finish(&wpkt))
        return;

    /*
     * Send it back to the client attempting to connect
     * TODO(QUIC SERVER): Need to handle the EAGAIN case here, if the
     * BIO_sendmmsg call falls in a retryable manner
     */
    if (!BIO_sendmmsg(port->net_wbio, msg, sizeof(BIO_MSG), 1, 0, &written))
        ERR_raise_data(ERR_LIB_SSL, SSL_R_QUIC_NETWORK_ERROR,
                       "port version negotiation send failed");
}

/**
 * @brief Validates a received token in a QUIC packet header.
 *
 * This function checks the validity of a token contained in the provided
 * QUIC packet header (`QUIC_PKT_HDR *hdr`). The validation process involves
 * verifying that the token matches an expected format and value. If the
 * token is valid, the function extracts the original connection ID (ODCID)
 * and stores it in the provided `QUIC_CONN_ID *odcid`.
 *
 * @param hdr   Pointer to the QUIC packet header containing the token.
 * @param odcid Pointer to the connection ID structure to store the ODCID if
 *              the token is valid.
 * @return      1 if the token is valid and ODCID is extracted successfully,
 *              0 otherwise.
 *
 * The function performs the following checks:
 * - Verifies that the token length meets the required minimum.
 * - Confirms the token buffer matches the expected "openssltoken" string.
 * -
 */
static int port_validate_token(QUIC_PKT_HDR *hdr, QUIC_CONN_ID *odcid)
{
    int valid;
    struct validation_token *token;

    memset(odcid, 0, sizeof(QUIC_CONN_ID));

    token = (struct validation_token *)hdr->token;
    if (token == NULL || hdr->token_len <= (TOKEN_LEN - QUIC_RETRY_INTEGRITY_TAG_LEN))
        return 0;

    valid = memcmp(token->token_buf, "openssltoken", sizeof("openssltoken") - 1);
    if (valid != 0)
        return 0;

    odcid->id_len = token->token_odcid.id_len;
    memcpy(odcid->id, token->token_odcid.id, token->token_odcid.id_len);

    return 1;
}

/*
 * This is called by the demux when we get a packet not destined for any known
 * DCID.
 */
static void port_default_packet_handler(QUIC_URXE *e, void *arg,
                                        const QUIC_CONN_ID *dcid)
{
    QUIC_PORT *port = arg;
    PACKET pkt;
    QUIC_PKT_HDR hdr;
    QUIC_CHANNEL *ch = NULL, *new_ch = NULL;
    QUIC_CONN_ID odcid;
    uint64_t cause_flags = 0;

    /* Don't handle anything if we are no longer running. */
    if (!ossl_quic_port_is_running(port))
        goto undesirable;

    if (port_try_handle_stateless_reset(port, e))
        goto undesirable;

    if (dcid != NULL
        && ossl_quic_lcidm_lookup(port->lcidm, dcid, NULL,
                                  (void **)&ch)) {
        assert(ch != NULL);
        ossl_quic_channel_inject(ch, e);
        return;
    }

    /*
     * If we have an incoming packet which doesn't match any existing connection
     * we assume this is an attempt to make a new connection.
     */
    if (!port->allow_incoming)
        goto undesirable;

    /*
     * We have got a packet for an unknown DCID. This might be an attempt to
     * open a new connection.
     */
    if (e->data_len < QUIC_MIN_INITIAL_DGRAM_LEN)
        goto undesirable;

    if (!PACKET_buf_init(&pkt, ossl_quic_urxe_data(e), e->data_len))
        goto undesirable;

    /*
     * We set short_conn_id_len to SIZE_MAX here which will cause the decode
     * operation to fail if we get a 1-RTT packet. This is fine since we only
     * care about Initial packets.
     */
    if (!ossl_quic_wire_decode_pkt_hdr(&pkt, SIZE_MAX, 1, 0, &hdr, NULL,
                                       &cause_flags)) {
        /*
         * If we fail due to a bad version, we know the packet up to the version
         * number was decoded, and we use it below to send a version
         * negotiation packet
         */
        if ((cause_flags & QUIC_PKT_HDR_DECODE_BAD_VERSION) == 0)
            goto undesirable;
    }

    switch (hdr.version) {
    case QUIC_VERSION_1:
        break;

    case QUIC_VERSION_NONE:
    default:

        /*
         * If we get here, then we have a bogus version, and might need
         * to send a version negotiation packet.  According to
         * RFC 9000 s. 6 and 14.1, we only do so however, if the UDP datagram
         * is a minimum of 1200 bytes in size
         */

        if (e->data_len < 1200)
            goto undesirable;

        /*
         * If we don't get a supported version, respond with a ver
         * negotiation packet, and discard
         * TODO(QUIC SERVER): Rate limit the reception of these
         */
        port_send_version_negotiation(port, &e->peer, &hdr);
        goto undesirable;
    }

    /*
     * We only care about Initial packets which might be trying to establish a
     * connection.
     */
    if (hdr.type != QUIC_PKT_TYPE_INITIAL)
        goto undesirable;

    /*
     * TODO(QUIC SERVER): there should be some logic similar to accounting half-open
     * states in TCP. If we reach certain threshold, then we want to
     * validate clients.
     */
    if (hdr.token == NULL) {
        port_send_retry(port, &e->peer, &hdr);
        goto undesirable;
    } else if (port_validate_token(&hdr, &odcid) == 0) {
        goto undesirable;
    }

    port_bind_channel(port, &e->peer, &hdr.src_conn_id, &hdr.dst_conn_id,
                      &odcid, &new_ch);

    /*
     * The channel will do all the LCID registration needed, but as an
     * optimization inject this packet directly into the channel's QRX for
     * processing without going through the DEMUX again.
     */
    if (new_ch != NULL) {
        ossl_qrx_inject_urxe(new_ch->qrx, e);
        return;
    }

undesirable:
    ossl_quic_demux_release_urxe(port->demux, e);
}

void ossl_quic_port_raise_net_error(QUIC_PORT *port,
                                    QUIC_CHANNEL *triggering_ch)
{
    QUIC_CHANNEL *ch;

    if (!ossl_quic_port_is_running(port))
        return;

    /*
     * Immediately capture any triggering error on the error stack, with a
     * cover error.
     */
    ERR_raise_data(ERR_LIB_SSL, SSL_R_QUIC_NETWORK_ERROR,
                   "port failed due to network BIO I/O error");
    OSSL_ERR_STATE_save(port->err_state);

    port_transition_failed(port);

    /* Give the triggering channel (if any) the first notification. */
    if (triggering_ch != NULL)
        ossl_quic_channel_raise_net_error(triggering_ch);

    OSSL_LIST_FOREACH(ch, ch, &port->channel_list)
        if (ch != triggering_ch)
            ossl_quic_channel_raise_net_error(ch);
}

void ossl_quic_port_restore_err_state(const QUIC_PORT *port)
{
    ERR_clear_error();
    OSSL_ERR_STATE_restore(port->err_state);
}
