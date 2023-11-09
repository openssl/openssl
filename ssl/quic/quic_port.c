/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
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
#include "../ssl_local.h"

/*
 * QUIC Port Structure
 * ===================
 */
#define INIT_DCID_LEN                   8

static int port_init(QUIC_PORT *port);
static void port_cleanup(QUIC_PORT *port);
static OSSL_TIME get_time(void *arg);
static void port_tick(QUIC_TICK_RESULT *res, void *arg, uint32_t flags);
static void port_default_packet_handler(QUIC_URXE *e, void *arg);
static void port_rx_pre(QUIC_PORT *port);

DEFINE_LIST_OF_IMPL(ch, QUIC_CHANNEL);

QUIC_PORT *ossl_quic_port_new(const QUIC_PORT_ARGS *args)
{
    QUIC_PORT *port;

    if ((port = OPENSSL_zalloc(sizeof(QUIC_PORT))) == NULL)
        return NULL;

    port->libctx        = args->libctx;
    port->propq         = args->propq;
    port->mutex         = args->mutex;
    port->now_cb        = args->now_cb;
    port->now_cb_arg    = args->now_cb_arg;
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

    if (port->channel_ctx == NULL)
        goto err;

    if ((port->demux = ossl_quic_demux_new(/*BIO=*/NULL,
                                           /*Short CID Len=*/rx_short_dcid_len,
                                           get_time, port)) == NULL)
        goto err;

    /*
     * If we are a server, setup our handler for packets not corresponding to
     * any known DCID on our end. This is for handling clients establishing new
     * connections.
     */
    // if (is_server)
    ossl_quic_demux_set_default_handler(port->demux,
                                        port_default_packet_handler,
                                        port);

    if ((port->srtm = ossl_quic_srtm_new(port->libctx, port->propq)) == NULL)
        goto err;

    if ((port->lcidm = ossl_quic_lcidm_new(port->libctx, rx_short_dcid_len)) == NULL)
        goto err;

    ossl_quic_reactor_init(&port->rtor, port_tick, port, ossl_time_zero());
    port->rx_short_dcid_len = (unsigned char)rx_short_dcid_len;
    port->tx_init_dcid_len  = INIT_DCID_LEN;
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
}

QUIC_REACTOR *ossl_quic_port_get0_reactor(QUIC_PORT *port)
{
    return &port->rtor;
}

QUIC_DEMUX *ossl_quic_port_get0_demux(QUIC_PORT *port)
{
    return port->demux;
}

CRYPTO_MUTEX *ossl_quic_port_get0_mutex(QUIC_PORT *port)
{
    return port->mutex;
}

OSSL_TIME ossl_quic_port_get_time(QUIC_PORT *port)
{
    if (port->now_cb == NULL)
        return ossl_time_now();

    return port->now_cb(port->now_cb_arg);
}

static OSSL_TIME get_time(void *port)
{
    return ossl_quic_port_get_time(port);
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

    if (for_write)
        ossl_quic_reactor_set_poll_w(&port->rtor, &d);
    else
        ossl_quic_reactor_set_poll_r(&port->rtor, &d);

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
    if (args.tls == NULL)
        return NULL;

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
    return ch;
}

/*
 * QUIC Port: Ticker-Mutator
 * =========================
 */

/*
 * The central ticker function called by the reactor. This does everything, or
 * at least everything network I/O related. Best effort - not allowed to fail
 * "loudly".
 */
static void port_tick(QUIC_TICK_RESULT *res, void *arg, uint32_t flags)
{
    QUIC_PORT *port = arg;
    QUIC_CHANNEL *ch;

    res->net_read_desired   = 0;
    res->net_write_desired  = 0;
    res->tick_deadline      = ossl_time_infinite();

    if (!port->inhibit_tick) {
        /* Handle any incoming data from network. */
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

    // TODO !have_sent_any_pkt

    /*
     * Get DEMUX to BIO_recvmmsg from the network and queue incoming datagrams
     * to the appropriate QRX instances.
     */
    ret = ossl_quic_demux_pump(port->demux);
    // TODO: handle ret, stateless reset

    if (ret == QUIC_DEMUX_PUMP_RES_PERMANENT_FAIL)
        /*
         * We don't care about transient failure, but permanent failure means we
         * should tear down the port. All connections skip straight to the
         * Terminated state as there is no point trying to send CONNECTION_CLOSE
         * frames if the network BIO is not operating correctly.
         */
        ossl_quic_port_raise_net_error(port);
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
static void port_default_packet_handler(QUIC_URXE *e, void *arg)
{
    QUIC_PORT *port = arg;
    PACKET pkt;
    QUIC_PKT_HDR hdr;
    QUIC_CHANNEL *new_ch = NULL;

    if (port_try_handle_stateless_reset(port, e))
        goto undesirable;

    // TODO review this
    if (port->tserver_ch == NULL)
        goto undesirable;

    // TODO allow_incoming
    //if (!ossl_assert(ch->is_server))
    //    goto undesirable;

    //TODO if (ch->state != QUIC_CHANNEL_STATE_IDLE)
    //    goto undesirable;

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
     * We do not register the DCID in the Initial packet we received as
     * that DCID is not actually used again, thus after provisioning
     * the new connection and associated Initial keys, we inject the
     * received packet directly to the new channel's QRX so that it can
     * process it as a one-time thing, instead of going through the usual
     * DEMUX DCID-based routing.
     */
    port_on_new_conn(port, &e->peer, &hdr.src_conn_id, &hdr.dst_conn_id,
                     &new_ch);
    if (new_ch != NULL)
        ossl_qrx_inject_urxe(new_ch->qrx, e);

    return;

undesirable:
    ossl_quic_demux_release_urxe(port->demux, e);
}

void ossl_quic_port_set_inhibit_tick(QUIC_PORT *port, int inhibit)
{
    port->inhibit_tick = (inhibit != 0);
}

void ossl_quic_port_raise_net_error(QUIC_PORT *port)
{
    QUIC_CHANNEL *ch;

    // TODO fsm

    LIST_FOREACH(ch, ch, &port->channel_list)
        ossl_quic_channel_raise_net_error(ch);
}
