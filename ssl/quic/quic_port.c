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
#include "quic_port_local.h"
#include "quic_channel_local.h"
#include "../ssl_local.h"

/*
 * QUIC Port Structure
 * ===================
 */
static int port_init(QUIC_PORT *port);
static void port_cleanup(QUIC_PORT *port);
static OSSL_TIME get_time(void *arg);
static void port_tick(QUIC_TICK_RESULT *res, void *arg, uint32_t flags);
//static void port_default_packet_handler(QUIC_URXE *e, void *arg);

QUIC_PORT *ossl_quic_port_new(const QUIC_PORT_ARGS *args)
{
    QUIC_PORT *port;

    if ((port = OPENSSL_zalloc(sizeof(QUIC_PORT))) == NULL)
        return NULL;

    port->libctx      = args->libctx;
    port->propq       = args->propq;
    port->mutex       = args->mutex;
    port->now_cb      = args->now_cb;
    port->now_cb_arg  = args->now_cb_arg;

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
    size_t rx_short_cid_len = 8;

    if ((port->demux = ossl_quic_demux_new(/*BIO=*/NULL,
                                           /*Short CID Len=*/rx_short_cid_len,
                                           get_time, port)) == NULL)
        goto err;

    /*
     * If we are a server, setup our handler for packets not corresponding to
     * any known DCID on our end. This is for handling clients establishing new
     * connections.
     */
    // if (is_server)
    //ossl_quic_demux_set_default_handler(port->demux,
    //                                    port_default_packet_handler,
    //                                    port);

    ossl_quic_reactor_init(&port->rtor, port_tick, port, ossl_time_zero());
    return 1;

err:
    port_cleanup(port);
    return 0;
}

static void port_cleanup(QUIC_PORT *port)
{
    ossl_quic_demux_free(port->demux);
    port->demux = NULL;
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
    if (port->net_wbio == net_wbio)
        return 1;

    if (!port_update_poll_desc(port, net_wbio, /*for_write=*/1))
        return 0;

    //ossl_qtx_set_bio(port->qtx, net_wbio);
    port->net_wbio = net_wbio;
    return 1;
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
    /* TODO */
}
