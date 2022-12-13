/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/quic_tserver.h"
#include "internal/quic_channel.h"
#include "internal/quic_statm.h"
#include "internal/common.h"

/*
 * QUIC Test Server Module
 * =======================
 */
struct quic_tserver_st {
    QUIC_TSERVER_ARGS   args;

    /*
     * The QUIC channel providing the core QUIC connection implementation.
     */
    QUIC_CHANNEL    *ch;

    /* Our single bidirectional application data stream. */
    QUIC_STREAM     *stream0;

    /* The current peer L4 address. AF_UNSPEC if we do not have a peer yet. */
    BIO_ADDR        cur_peer_addr;

    /* Are we connected to a peer? */
    unsigned int    connected       : 1;
};

QUIC_TSERVER *ossl_quic_tserver_new(const QUIC_TSERVER_ARGS *args)
{
    QUIC_TSERVER *srv = NULL;
    QUIC_CHANNEL_ARGS ch_args = {0};

    if (args->net_rbio == NULL || args->net_wbio == NULL)
        goto err;

    if ((srv = OPENSSL_zalloc(sizeof(*srv))) == NULL)
        goto err;

    srv->args = *args;

    ch_args.libctx      = srv->args.libctx;
    ch_args.propq       = srv->args.propq;
    ch_args.is_server   = 1;

    if ((srv->ch = ossl_quic_channel_new(&ch_args)) == NULL)
        goto err;

    if (!ossl_quic_channel_set_net_rbio(srv->ch, srv->args.net_rbio)
        || !ossl_quic_channel_set_net_wbio(srv->ch, srv->args.net_wbio))
        goto err;

    srv->stream0 = ossl_quic_channel_get_stream_by_id(srv->ch, 0);
    if (srv->stream0 == NULL)
        goto err;

    return srv;

err:
    if (srv != NULL)
        ossl_quic_channel_free(srv->ch);

    OPENSSL_free(srv);
    return NULL;
}

void ossl_quic_tserver_free(QUIC_TSERVER *srv)
{
    if (srv == NULL)
        return;

    ossl_quic_channel_free(srv->ch);
    BIO_free(srv->args.net_rbio);
    BIO_free(srv->args.net_wbio);
    OPENSSL_free(srv);
}

int ossl_quic_tserver_tick(QUIC_TSERVER *srv)
{
    ossl_quic_reactor_tick(ossl_quic_channel_get_reactor(srv->ch));

    if (ossl_quic_channel_is_active(srv->ch))
        srv->connected = 1;

    return 1;
}

int ossl_quic_tserver_is_connected(QUIC_TSERVER *srv)
{
    return ossl_quic_channel_is_active(srv->ch);
}

int ossl_quic_tserver_read(QUIC_TSERVER *srv,
                           unsigned char *buf,
                           size_t buf_len,
                           size_t *bytes_read)
{
    int is_fin = 0;

    if (!ossl_quic_channel_is_active(srv->ch))
        return 0;

    if (srv->stream0->recv_fin_retired)
        return 0;

    if (!ossl_quic_rstream_read(srv->stream0->rstream, buf, buf_len,
                                bytes_read, &is_fin))
        return 0;

    if (*bytes_read > 0) {
        /*
         * We have read at least one byte from the stream. Inform stream-level
         * RXFC of the retirement of controlled bytes. Update the active stream
         * status (the RXFC may now want to emit a frame granting more credit to
         * the peer).
         */
        OSSL_RTT_INFO rtt_info;

        ossl_statm_get_rtt_info(ossl_quic_channel_get_statm(srv->ch), &rtt_info);

        if (!ossl_quic_rxfc_on_retire(&srv->stream0->rxfc, *bytes_read,
                                      rtt_info.smoothed_rtt))
            return 0;
    }

    if (is_fin)
        srv->stream0->recv_fin_retired = 1;

    if (*bytes_read > 0)
        ossl_quic_stream_map_update_state(ossl_quic_channel_get_qsm(srv->ch),
                                          srv->stream0);

    return 1;
}

int ossl_quic_tserver_has_read_ended(QUIC_TSERVER *srv)
{
    return srv->stream0->recv_fin_retired;
}

int ossl_quic_tserver_write(QUIC_TSERVER *srv,
                            const unsigned char *buf,
                            size_t buf_len,
                            size_t *bytes_written)
{
    if (!ossl_quic_channel_is_active(srv->ch))
        return 0;

    if (!ossl_quic_sstream_append(srv->stream0->sstream,
                                  buf, buf_len, bytes_written))
        return 0;

    if (*bytes_written > 0)
        /*
         * We have appended at least one byte to the stream. Potentially mark
         * the stream as active, depending on FC.
         */
        ossl_quic_stream_map_update_state(ossl_quic_channel_get_qsm(srv->ch),
                                          srv->stream0);

    /* Try and send. */
    ossl_quic_tserver_tick(srv);
    return 1;
}

int ossl_quic_tserver_conclude(QUIC_TSERVER *srv)
{
    if (!ossl_quic_channel_is_active(srv->ch))
        return 0;

    if (!ossl_quic_sstream_get_final_size(srv->stream0->sstream, NULL)) {
        ossl_quic_sstream_fin(srv->stream0->sstream);
        ossl_quic_stream_map_update_state(ossl_quic_channel_get_qsm(srv->ch),
                                          srv->stream0);
    }

    ossl_quic_tserver_tick(srv);
    return 1;
}
