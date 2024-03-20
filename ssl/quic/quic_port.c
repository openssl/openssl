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

DEFINE_LIST_OF_IMPL(ch, QUIC_CHANNEL);
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
     * For now, just update the descriptor on the the engine's reactor as we are
     * guaranteed to be the only port under it.
     */
    if (for_write)
        ossl_quic_reactor_set_poll_w(&port->engine->rtor, &d);
    else
        ossl_quic_reactor_set_poll_r(&port->engine->rtor, &d);

    return 1;
}

int ossl_quic_port_update_poll_descriptors(QUIC_PORT *port)
{
    int ok = 1;

    if (!port_update_poll_desc(port, port->net_rbio, /*for_write=*/0))
        ok = 0;

    if (!port_update_poll_desc(port, port->net_wbio, /*for_write=*/1))
        ok = 0;

    return ok;
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
    return 1;
}

int ossl_quic_port_set_net_wbio(QUIC_PORT *port, BIO *net_wbio)
{
    QUIC_CHANNEL *ch;

    if (port->net_wbio == net_wbio)
        return 1;

    if (!port_update_poll_desc(port, net_wbio, /*for_write=*/1))
        return 0;

    LIST_FOREACH(ch, ch, &port->channel_list)
        ossl_qtx_set_bio(ch->qtx, net_wbio);

    port->net_wbio = net_wbio;
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

    tls = ossl_ssl_connection_new_int(port->channel_ctx, TLS_method());
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
    port->is_server  = 1;
    return ch;
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

    res->net_read_desired   = 0;
    res->net_write_desired  = 0;
    res->tick_deadline      = ossl_time_infinite();

    if (!port->engine->inhibit_tick) {
        /* Handle any incoming data from network. */
        if (ossl_quic_port_is_running(port))
            port_rx_pre(port);

        /* Iterate through all channels and service them. */
        LIST_FOREACH(ch, ch, &port->channel_list) {
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
    if (!port->is_server && !port->have_sent_any_pkt)
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
static void port_on_new_conn(QUIC_PORT *port, const BIO_ADDR *peer,
                             const QUIC_CONN_ID *scid,
                             const QUIC_CONN_ID *dcid,
                             QUIC_CHANNEL **new_ch)
{
    if (port->tserver_ch != NULL) {
        /* Specially assign to existing channel */
        if (!ossl_quic_channel_on_new_conn(port->tserver_ch, peer, scid, dcid))
            return;

        *new_ch = port->tserver_ch;
        port->tserver_ch = NULL;
        return;
    }
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
     * we assume this is an attempt to make a new connection. Currently we
     * require our caller to have precreated a latent 'incoming' channel via
     * TSERVER which then gets turned into the new connection.
     *
     * TODO(QUIC SERVER): In the future we will construct channels dynamically
     * in this case.
     */
    if (port->tserver_ch == NULL)
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
    if (!ossl_quic_wire_decode_pkt_hdr(&pkt, SIZE_MAX, 1, 0, &hdr, NULL))
        goto undesirable;

    switch (hdr.version) {
        case QUIC_VERSION_1:
            break;

        case QUIC_VERSION_NONE:
        default:
            /* Unknown version or proactive version negotiation request, bail. */
            /* TODO(QUIC SERVER): Handle version negotiation on server side */
            goto undesirable;
    }

    /*
     * We only care about Initial packets which might be trying to establish a
     * connection.
     */
    if (hdr.type != QUIC_PKT_TYPE_INITIAL)
        goto undesirable;

    /*
     * Try to process this as a valid attempt to initiate a connection.
     *
     * The channel will do all the LCID registration needed, but as an
     * optimization inject this packet directly into the channel's QRX for
     * processing without going through the DEMUX again.
     */
    port_on_new_conn(port, &e->peer, &hdr.src_conn_id, &hdr.dst_conn_id,
                     &new_ch);
    if (new_ch != NULL)
        ossl_qrx_inject_urxe(new_ch->qrx, e);

    return;

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

    LIST_FOREACH(ch, ch, &port->channel_list)
        if (ch != triggering_ch)
            ossl_quic_channel_raise_net_error(ch);
}

void ossl_quic_port_restore_err_state(const QUIC_PORT *port)
{
    ERR_clear_error();
    OSSL_ERR_STATE_restore(port->err_state);
}
