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

    /* The mutex we give to the QUIC channel. */
    CRYPTO_MUTEX    *mutex;

    /* SSL_CTX for creating the underlying TLS connection */
    SSL_CTX *ctx;

    /* SSL for the underlying TLS connection */
    SSL *tls;

    /* The current peer L4 address. AF_UNSPEC if we do not have a peer yet. */
    BIO_ADDR        cur_peer_addr;

    /* Are we connected to a peer? */
    unsigned int    connected       : 1;
};

static int alpn_select_cb(SSL *ssl, const unsigned char **out,
                          unsigned char *outlen, const unsigned char *in,
                          unsigned int inlen, void *arg)
{
    static const unsigned char alpn[] = { 8, 'o', 's', 's', 'l', 't', 'e', 's', 't' };

    if (SSL_select_next_proto((unsigned char **)out, outlen, alpn, sizeof(alpn),
                              in, inlen) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    return SSL_TLSEXT_ERR_OK;
}

QUIC_TSERVER *ossl_quic_tserver_new(const QUIC_TSERVER_ARGS *args,
                                    const char *certfile, const char *keyfile)
{
    QUIC_TSERVER *srv = NULL;
    QUIC_CHANNEL_ARGS ch_args = {0};

    if (args->net_rbio == NULL || args->net_wbio == NULL)
        goto err;

    if ((srv = OPENSSL_zalloc(sizeof(*srv))) == NULL)
        goto err;

    srv->args = *args;

#if defined(OPENSSL_THREADS)
    if ((srv->mutex = ossl_crypto_mutex_new()) == NULL)
        goto err;
#endif

    srv->ctx = SSL_CTX_new_ex(srv->args.libctx, srv->args.propq, TLS_method());
    if (srv->ctx == NULL)
        goto err;

    if (SSL_CTX_use_certificate_file(srv->ctx, certfile, SSL_FILETYPE_PEM) <= 0)
        goto err;

    if (SSL_CTX_use_PrivateKey_file(srv->ctx, keyfile, SSL_FILETYPE_PEM) <= 0)
        goto err;

    SSL_CTX_set_alpn_select_cb(srv->ctx, alpn_select_cb, srv);

    srv->tls = SSL_new(srv->ctx);
    if (srv->tls == NULL)
        goto err;

    ch_args.libctx      = srv->args.libctx;
    ch_args.propq       = srv->args.propq;
    ch_args.tls         = srv->tls;
    ch_args.mutex       = srv->mutex;
    ch_args.is_server   = 1;
    ch_args.now_cb      = srv->args.now_cb;
    ch_args.now_cb_arg  = srv->args.now_cb_arg;

    if ((srv->ch = ossl_quic_channel_new(&ch_args)) == NULL)
        goto err;

    if (!ossl_quic_channel_set_net_rbio(srv->ch, srv->args.net_rbio)
        || !ossl_quic_channel_set_net_wbio(srv->ch, srv->args.net_wbio))
        goto err;

    return srv;

err:
    if (srv != NULL) {
        ossl_quic_channel_free(srv->ch);
#if defined(OPENSSL_THREADS)
        ossl_crypto_mutex_free(&srv->mutex);
#endif
    }

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
    SSL_free(srv->tls);
    SSL_CTX_free(srv->ctx);
#if defined(OPENSSL_THREADS)
    ossl_crypto_mutex_free(&srv->mutex);
#endif
    OPENSSL_free(srv);
}

/* Set mutator callbacks for test framework support */
int ossl_quic_tserver_set_plain_packet_mutator(QUIC_TSERVER *srv,
                                               ossl_mutate_packet_cb mutatecb,
                                               ossl_finish_mutate_cb finishmutatecb,
                                               void *mutatearg)
{
    return ossl_quic_channel_set_mutator(srv->ch, mutatecb, finishmutatecb,
                                         mutatearg);
}

int ossl_quic_tserver_set_handshake_mutator(QUIC_TSERVER *srv,
                                            ossl_statem_mutate_handshake_cb mutate_handshake_cb,
                                            ossl_statem_finish_mutate_handshake_cb finish_mutate_handshake_cb,
                                            void *mutatearg)
{
    return ossl_statem_set_mutator(ossl_quic_channel_get0_ssl(srv->ch),
                                   mutate_handshake_cb,
                                   finish_mutate_handshake_cb,
                                   mutatearg);
}

int ossl_quic_tserver_tick(QUIC_TSERVER *srv)
{
    ossl_quic_reactor_tick(ossl_quic_channel_get_reactor(srv->ch), 0);

    if (ossl_quic_channel_is_active(srv->ch))
        srv->connected = 1;

    return 1;
}

int ossl_quic_tserver_is_connected(QUIC_TSERVER *srv)
{
    return ossl_quic_channel_is_active(srv->ch);
}

/* Returns 1 if the server is in any terminating or terminated state */
int ossl_quic_tserver_is_term_any(const QUIC_TSERVER *srv)
{
    return ossl_quic_channel_is_term_any(srv->ch);
}

const QUIC_TERMINATE_CAUSE *
ossl_quic_tserver_get_terminate_cause(const QUIC_TSERVER *srv)
{
    return ossl_quic_channel_get_terminate_cause(srv->ch);
}

/* Returns 1 if the server is in a terminated state */
int ossl_quic_tserver_is_terminated(const QUIC_TSERVER *srv)
{
    return ossl_quic_channel_is_terminated(srv->ch);
}

int ossl_quic_tserver_is_handshake_confirmed(const QUIC_TSERVER *srv)
{
    return ossl_quic_channel_is_handshake_confirmed(srv->ch);
}

int ossl_quic_tserver_read(QUIC_TSERVER *srv,
                           uint64_t stream_id,
                           unsigned char *buf,
                           size_t buf_len,
                           size_t *bytes_read)
{
    int is_fin = 0;
    QUIC_STREAM *qs;

    if (!ossl_quic_channel_is_active(srv->ch))
        return 0;

    qs = ossl_quic_stream_map_get_by_id(ossl_quic_channel_get_qsm(srv->ch),
                                        stream_id);
    if (qs == NULL) {
        int is_client_init
            = ((stream_id & QUIC_STREAM_INITIATOR_MASK)
               == QUIC_STREAM_INITIATOR_CLIENT);

        /*
         * A client-initiated stream might spontaneously come into existence, so
         * allow trying to read on a client-initiated stream before it exists.
         * Otherwise, fail.
         */
        if (!is_client_init)
            return 0;

        *bytes_read = 0;
        return 1;
    }

    if (qs->recv_fin_retired || qs->rstream == NULL)
        return 0;

    if (!ossl_quic_rstream_read(qs->rstream, buf, buf_len,
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

        if (!ossl_quic_rxfc_on_retire(&qs->rxfc, *bytes_read,
                                      rtt_info.smoothed_rtt))
            return 0;
    }

    if (is_fin)
        qs->recv_fin_retired = 1;

    if (*bytes_read > 0)
        ossl_quic_stream_map_update_state(ossl_quic_channel_get_qsm(srv->ch), qs);

    return 1;
}

int ossl_quic_tserver_has_read_ended(QUIC_TSERVER *srv, uint64_t stream_id)
{
    QUIC_STREAM *qs;
    unsigned char buf[1];
    size_t bytes_read = 0;
    int is_fin = 0;

    qs = ossl_quic_stream_map_get_by_id(ossl_quic_channel_get_qsm(srv->ch),
                                        stream_id);

    if (qs == NULL || qs->rstream == NULL)
        return 0;

    if (qs->recv_fin_retired)
        return 1;

    /*
     * If we do not have recv_fin_retired, it is possible we should still return
     * 1 if there is a lone FIN (but no more data) remaining to be retired from
     * the RSTREAM, for example because ossl_quic_tserver_read() has not been
     * called since the FIN was received.
     */
    if (!ossl_quic_rstream_peek(qs->rstream, buf, sizeof(buf),
                                &bytes_read, &is_fin))
        return 0;

    if (is_fin && bytes_read == 0) {
        /* If we have a FIN awaiting retirement and no data before it... */
        /* Let RSTREAM know we've consumed this FIN. */
        ossl_quic_rstream_read(qs->rstream, buf, sizeof(buf),
                               &bytes_read, &is_fin); /* best effort */
        assert(is_fin && bytes_read == 0);

        qs->recv_fin_retired = 1;
        ossl_quic_stream_map_update_state(ossl_quic_channel_get_qsm(srv->ch), qs);
        return 1;
    }

    return 0;
}

int ossl_quic_tserver_write(QUIC_TSERVER *srv,
                            uint64_t stream_id,
                            const unsigned char *buf,
                            size_t buf_len,
                            size_t *bytes_written)
{
    QUIC_STREAM *qs;

    if (!ossl_quic_channel_is_active(srv->ch))
        return 0;

    qs = ossl_quic_stream_map_get_by_id(ossl_quic_channel_get_qsm(srv->ch),
                                        stream_id);
    if (qs == NULL || qs->sstream == NULL)
        return 0;

    if (!ossl_quic_sstream_append(qs->sstream,
                                  buf, buf_len, bytes_written))
        return 0;

    if (*bytes_written > 0)
        /*
         * We have appended at least one byte to the stream. Potentially mark
         * the stream as active, depending on FC.
         */
        ossl_quic_stream_map_update_state(ossl_quic_channel_get_qsm(srv->ch), qs);

    /* Try and send. */
    ossl_quic_tserver_tick(srv);
    return 1;
}

int ossl_quic_tserver_conclude(QUIC_TSERVER *srv, uint64_t stream_id)
{
    QUIC_STREAM *qs;

    if (!ossl_quic_channel_is_active(srv->ch))
        return 0;

    qs = ossl_quic_stream_map_get_by_id(ossl_quic_channel_get_qsm(srv->ch),
                                        stream_id);
    if  (qs == NULL || qs->sstream == NULL)
        return 0;

    if (!ossl_quic_sstream_get_final_size(qs->sstream, NULL)) {
        ossl_quic_sstream_fin(qs->sstream);
        ossl_quic_stream_map_update_state(ossl_quic_channel_get_qsm(srv->ch), qs);
    }

    ossl_quic_tserver_tick(srv);
    return 1;
}

int ossl_quic_tserver_stream_new(QUIC_TSERVER *srv,
                                 int is_uni,
                                 uint64_t *stream_id)
{
    QUIC_STREAM *qs;

    if (!ossl_quic_channel_is_active(srv->ch))
        return 0;

    if ((qs = ossl_quic_channel_new_stream_local(srv->ch, is_uni)) == NULL)
        return 0;

    *stream_id = qs->id;
    return 1;
}

BIO *ossl_quic_tserver_get0_rbio(QUIC_TSERVER *srv)
{
    return srv->args.net_rbio;
}

int ossl_quic_tserver_stream_has_peer_stop_sending(QUIC_TSERVER *srv,
                                                   uint64_t stream_id,
                                                   uint64_t *app_error_code)
{
    QUIC_STREAM *qs;

    qs = ossl_quic_stream_map_get_by_id(ossl_quic_channel_get_qsm(srv->ch),
                                        stream_id);
    if (qs == NULL)
        return 0;

    if (qs->peer_stop_sending && app_error_code != NULL)
        *app_error_code = qs->peer_stop_sending_aec;

    return qs->peer_stop_sending;
}

int ossl_quic_tserver_stream_has_peer_reset_stream(QUIC_TSERVER *srv,
                                                   uint64_t stream_id,
                                                   uint64_t  *app_error_code)
{
    QUIC_STREAM *qs;

    qs = ossl_quic_stream_map_get_by_id(ossl_quic_channel_get_qsm(srv->ch),
                                        stream_id);
    if (qs == NULL)
        return 0;

    if (qs->peer_reset_stream && app_error_code != NULL)
        *app_error_code = qs->peer_reset_stream_aec;

    return qs->peer_reset_stream;
}

int ossl_quic_tserver_set_new_local_cid(QUIC_TSERVER *srv,
                                        const QUIC_CONN_ID *conn_id)
{
    /* Replace existing local connection ID in the QUIC_CHANNEL */
    return ossl_quic_channel_replace_local_cid(srv->ch, conn_id);
}

uint64_t ossl_quic_tserver_pop_incoming_stream(QUIC_TSERVER *srv)
{
    QUIC_STREAM_MAP *qsm = ossl_quic_channel_get_qsm(srv->ch);
    QUIC_STREAM *qs = ossl_quic_stream_map_peek_accept_queue(qsm);

    if (qs == NULL)
        return UINT64_MAX;

    ossl_quic_stream_map_remove_from_accept_queue(qsm, qs, ossl_time_zero());

    return qs->id;
}
