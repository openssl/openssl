#include "ossl-nghttp3.h"
#include <openssl/err.h>
#include <assert.h>

#define ARRAY_LEN(x) (sizeof(x)/sizeof((x)[0]))

enum {
    H3_STREAM_TYPE_CTRL_SEND,
    H3_STREAM_TYPE_QPACK_ENC_SEND,
    H3_STREAM_TYPE_QPACK_DEC_SEND,
    H3_STREAM_TYPE_REQ,
};

#define BUF_SIZE    4096

struct h3_stream_st {
    uint64_t            id;             /* QUIC stream ID */
    SSL                 *s;             /* QUIC stream SSL object */
    int                 done_recv_fin;  /* Received FIN */
    void                *user_data;

    uint8_t             buf[BUF_SIZE];
    size_t              buf_cur, buf_total;
};

DEFINE_LHASH_OF_EX(H3_STREAM);

static void h3_stream_free(H3_STREAM *s)
{
    if (s == NULL)
        return;

    SSL_free(s->s);
    OPENSSL_free(s);
}

static unsigned long h3_stream_hash(const H3_STREAM *s)
{
    return (unsigned long)s->id;
}

static int h3_stream_eq(const H3_STREAM *a, const H3_STREAM *b)
{
    if (a->id < b->id) return -1;
    if (a->id > b->id) return 1;
    return 0;
}

void *H3_STREAM_get_user_data(const H3_STREAM *s)
{
    return s->user_data;
}

struct h3_conn_st {
    SSL                 *qconn;         /* QUIC connection SSL object */
    BIO                 *qconn_bio;     /* BIO wrapping QCSO */
    nghttp3_conn        *h3conn;        /* HTTP/3 connection object */
    LHASH_OF(H3_STREAM) *streams;       /* map of stream IDs to H3_STREAMs */
    void                *user_data;     /* opaque user data pointer */

    int                 pump_res;
    size_t              consumed_app_data;

    /* Forwarding callbacks */
    nghttp3_recv_data           recv_data_cb;
    nghttp3_stream_close        stream_close_cb;
    nghttp3_stop_sending        stop_sending_cb;
    nghttp3_reset_stream        reset_stream_cb;
    nghttp3_deferred_consume    deferred_consume_cb;
};

void H3_CONN_free(H3_CONN *conn)
{
    if (conn == NULL)
        return;

    lh_H3_STREAM_doall(conn->streams, h3_stream_free);

    nghttp3_conn_del(conn->h3conn);
    BIO_free_all(conn->qconn_bio);
    lh_H3_STREAM_free(conn->streams);
    OPENSSL_free(conn);
}

static H3_STREAM *h3_conn_create_stream(H3_CONN *conn, int type)
{
    H3_STREAM *s;
    uint64_t flags = SSL_STREAM_FLAG_ADVANCE;

    if ((s = OPENSSL_zalloc(sizeof(H3_STREAM))) == NULL)
        return NULL;

    if (type != H3_STREAM_TYPE_REQ)
        flags |= SSL_STREAM_FLAG_UNI;

    if ((s->s = SSL_new_stream(conn->qconn, flags)) == NULL) {
        ERR_raise_data(ERR_LIB_USER, ERR_R_INTERNAL_ERROR,
                       "could not create QUIC stream object");
        goto err;
    }

    s->id   = SSL_get_stream_id(s->s);
    lh_H3_STREAM_insert(conn->streams, s);
    return s;

err:
    OPENSSL_free(s);
    return NULL;
}

static H3_STREAM *h3_conn_accept_stream(H3_CONN *conn, SSL *qstream)
{
    H3_STREAM *s;

    if ((s = OPENSSL_zalloc(sizeof(H3_STREAM))) == NULL)
        return NULL;

    s->id   = SSL_get_stream_id(qstream);
    s->s    = qstream;
    lh_H3_STREAM_insert(conn->streams, s);
    return s;
}

static void h3_conn_remove_stream(H3_CONN *conn, H3_STREAM *s)
{
    if (s == NULL)
        return;

    lh_H3_STREAM_delete(conn->streams, s);
    h3_stream_free(s);
}

static int h3_conn_recv_data(nghttp3_conn *h3conn, int64_t stream_id,
                             const uint8_t *data, size_t datalen,
                             void *conn_user_data, void *stream_user_data)
{
    H3_CONN *conn = conn_user_data;

    conn->consumed_app_data += datalen;
    if (conn->recv_data_cb == NULL)
        return 0;

    return conn->recv_data_cb(h3conn, stream_id, data, datalen,
                              conn_user_data, stream_user_data);
}

static int h3_conn_stream_close(nghttp3_conn *h3conn, int64_t stream_id,
                                uint64_t app_error_code,
                                void *conn_user_data, void *stream_user_data)
{
    int ret = 0;
    H3_CONN *conn = conn_user_data;
    H3_STREAM *stream = stream_user_data;

    if (conn->stream_close_cb != NULL)
        ret = conn->stream_close_cb(h3conn, stream_id, app_error_code,
                                    conn_user_data, stream_user_data);

    h3_conn_remove_stream(conn, stream);
    return ret;
}

static int h3_conn_stop_sending(nghttp3_conn *h3conn, int64_t stream_id,
                                uint64_t app_error_code,
                                void *conn_user_data, void *stream_user_data)
{
    int ret = 0;
    H3_CONN *conn = conn_user_data;
    H3_STREAM *stream = stream_user_data;

    if (conn->stop_sending_cb != NULL)
        ret = conn->stop_sending_cb(h3conn, stream_id, app_error_code,
                                    conn_user_data, stream_user_data);

    SSL_free(stream->s);
    stream->s = NULL;
    return ret;
}

static int h3_conn_reset_stream(nghttp3_conn *h3conn, int64_t stream_id,
                                uint64_t app_error_code,
                                void *conn_user_data, void *stream_user_data)
{
    int ret = 0;
    H3_CONN *conn = conn_user_data;
    H3_STREAM *stream = stream_user_data;
    SSL_STREAM_RESET_ARGS args = {0};

    if (conn->reset_stream_cb != NULL)
        ret = conn->reset_stream_cb(h3conn, stream_id, app_error_code,
                                   conn_user_data, stream_user_data);

    if (stream->s != NULL) {
        args.quic_error_code = app_error_code;

        if (!SSL_stream_reset(stream->s, &args, sizeof(args)))
            return 1;
    }

    return ret;
}

static int h3_conn_deferred_consume(nghttp3_conn *h3conn, int64_t stream_id,
                                    size_t consumed,
                                    void *conn_user_data, void *stream_user_data)
{
    int ret = 0;
    H3_CONN *conn = conn_user_data;

    if (conn->deferred_consume_cb != NULL)
        ret = conn->deferred_consume_cb(h3conn, stream_id, consumed,
                                        conn_user_data, stream_user_data);

    conn->consumed_app_data += consumed;
    return ret;
}

H3_CONN *H3_CONN_new_for_conn(BIO *qconn_bio,
                              const nghttp3_callbacks *callbacks,
                              const nghttp3_settings *settings,
                              void *user_data)
{
    int ec;
    H3_CONN *conn;
    H3_STREAM *s_ctl_send = NULL, *s_qpenc_send = NULL, *s_qpdec_send = NULL;
    nghttp3_settings dsettings = {0};
    nghttp3_callbacks intl_callbacks = {0};
    static const unsigned char alpn[] = {2, 'h', '3'};

    if (qconn_bio == NULL) {
        ERR_raise_data(ERR_LIB_USER, ERR_R_PASSED_NULL_PARAMETER,
                       "QUIC connection BIO must be provided");
        return NULL;
    }

    if ((conn = OPENSSL_zalloc(sizeof(H3_CONN))) == NULL)
        return NULL;

    conn->qconn_bio = qconn_bio;
    conn->user_data = user_data;

    if (BIO_get_ssl(qconn_bio, &conn->qconn) == 0) {
        ERR_raise_data(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT,
                       "BIO must be an SSL BIO");
        goto err;
    }

    if ((conn->streams = lh_H3_STREAM_new(h3_stream_hash, h3_stream_eq)) == NULL)
        goto err;

    if (SSL_in_before(conn->qconn))
        if (SSL_set_alpn_protos(conn->qconn, alpn, sizeof(alpn))) {
            /* SSL_set_alpn_protos returns 1 on failure */
            ERR_raise_data(ERR_LIB_USER, ERR_R_INTERNAL_ERROR,
                           "failed to configure ALPN");
            goto err;
        }

    BIO_set_nbio(conn->qconn_bio, 1);

    if (!SSL_set_default_stream_mode(conn->qconn, SSL_DEFAULT_STREAM_MODE_NONE)) {
        ERR_raise_data(ERR_LIB_USER, ERR_R_INTERNAL_ERROR,
                       "failed to configure default stream mode");
        goto err;
    }

    if ((s_ctl_send = h3_conn_create_stream(conn, H3_STREAM_TYPE_CTRL_SEND)) == NULL)
        goto err;

    if ((s_qpenc_send = h3_conn_create_stream(conn, H3_STREAM_TYPE_QPACK_ENC_SEND)) == NULL)
        goto err;

    if ((s_qpdec_send = h3_conn_create_stream(conn, H3_STREAM_TYPE_QPACK_DEC_SEND)) == NULL)
        goto err;

    if (settings == NULL) {
        nghttp3_settings_default(&dsettings);
        settings = &dsettings;
    }

    if (callbacks != NULL)
        intl_callbacks = *callbacks;

    conn->recv_data_cb          = intl_callbacks.recv_data;
    conn->stream_close_cb       = intl_callbacks.stream_close;
    conn->stop_sending_cb       = intl_callbacks.stop_sending;
    conn->reset_stream_cb       = intl_callbacks.reset_stream;
    conn->deferred_consume_cb   = intl_callbacks.deferred_consume;

    intl_callbacks.recv_data        = h3_conn_recv_data;
    intl_callbacks.stream_close     = h3_conn_stream_close;
    intl_callbacks.stop_sending     = h3_conn_stop_sending;
    intl_callbacks.reset_stream     = h3_conn_reset_stream;
    intl_callbacks.deferred_consume = h3_conn_deferred_consume;

    ec = nghttp3_conn_client_new(&conn->h3conn, &intl_callbacks, settings,
                                 NULL, conn);
    if (ec < 0) {
        ERR_raise_data(ERR_LIB_USER, ERR_R_INTERNAL_ERROR,
                       "cannot create nghttp3 connection: %s (%d)",
                       nghttp3_strerror(ec), ec);
        goto err;
    }

    ec = nghttp3_conn_bind_control_stream(conn->h3conn, s_ctl_send->id);
    if (ec < 0) {
        ERR_raise_data(ERR_LIB_USER, ERR_R_INTERNAL_ERROR,
                       "cannot bind nghttp3 control stream: %s (%d)",
                       nghttp3_strerror(ec), ec);
        goto err;
    }

    ec = nghttp3_conn_bind_qpack_streams(conn->h3conn,
                                         s_qpenc_send->id,
                                         s_qpdec_send->id);
    if (ec < 0) {
        ERR_raise_data(ERR_LIB_USER, ERR_R_INTERNAL_ERROR,
                       "cannot bind nghttp3 QPACK streams: %s (%d)",
                       nghttp3_strerror(ec), ec);
        goto err;
    }

    return conn;

err:
    nghttp3_conn_del(conn->h3conn);
    h3_stream_free(s_ctl_send);
    h3_stream_free(s_qpenc_send);
    h3_stream_free(s_qpdec_send);
    lh_H3_STREAM_free(conn->streams);
    OPENSSL_free(conn);
    return NULL;
}

H3_CONN *H3_CONN_new_for_addr(SSL_CTX *ctx, const char *addr,
                              const nghttp3_callbacks *callbacks,
                              const nghttp3_settings *settings,
                              void *user_data)
{
    BIO *qconn_bio = NULL;
    SSL *qconn = NULL;
    H3_CONN *conn = NULL;
    const char *bare_hostname;

    /* QUIC connection setup */
    if ((qconn_bio = BIO_new_ssl_connect(ctx)) == NULL)
        goto err;

    if (BIO_set_conn_hostname(qconn_bio, addr) == 0)
        goto err;

    bare_hostname = BIO_get_conn_hostname(qconn_bio);
    if (bare_hostname == NULL)
        goto err;

    if (BIO_get_ssl(qconn_bio, &qconn) == 0)
        goto err;

    if (SSL_set1_host(qconn, bare_hostname) <= 0)
        goto err;

    conn = H3_CONN_new_for_conn(qconn_bio, callbacks, settings, user_data);
    if (conn == NULL)
        goto err;

    return conn;

err:
    BIO_free_all(qconn_bio);
    return NULL;
}

int H3_CONN_connect(H3_CONN *conn)
{
    return SSL_connect(H3_CONN_get0_connection(conn));
}

void *H3_CONN_get_user_data(const H3_CONN *conn)
{
    return conn->user_data;
}

SSL *H3_CONN_get0_connection(const H3_CONN *conn)
{
    return conn->qconn;
}

/* Pumps received data to the HTTP/3 stack for a single stream. */
static void h3_conn_pump_stream(H3_STREAM *s, void *conn_)
{
    int ec;
    H3_CONN *conn = conn_;
    size_t num_bytes, consumed;
    uint64_t aec;

    if (!conn->pump_res)
        return;

    for (;;) {
        if (s->s == NULL
            || SSL_get_stream_read_state(s->s) == SSL_STREAM_STATE_WRONG_DIR
            || s->done_recv_fin)
            break;

        /*
         * Pump data from OpenSSL QUIC to the HTTP/3 stack by calling SSL_peek
         * to get received data and passing it to nghttp3 using
         * nghttp3_conn_read_stream. Note that this function is confusingly
         * named and inputs data to the HTTP/3 stack.
         */
        if (s->buf_cur == s->buf_total) {
            /* Need more data. */
            ec = SSL_read_ex(s->s, s->buf, sizeof(s->buf), &num_bytes);
            if (ec <= 0) {
                num_bytes = 0;
                if (SSL_get_error(s->s, ec) == SSL_ERROR_ZERO_RETURN) {
                    /* Stream concluded normally. Pass FIN to HTTP/3 stack. */
                    ec = nghttp3_conn_read_stream(conn->h3conn, s->id, NULL, 0,
                                                  /*fin=*/1);
                    if (ec < 0) {
                        ERR_raise_data(ERR_LIB_USER, ERR_R_INTERNAL_ERROR,
                                       "cannot pass FIN to nghttp3: %s (%d)",
                                       nghttp3_strerror(ec), ec);
                        goto err;
                    }

                    s->done_recv_fin = 1;
                } else if (SSL_get_stream_read_state(s->s)
                            == SSL_STREAM_STATE_RESET_REMOTE) {
                    /* Stream was reset by peer. */
                    if (!SSL_get_stream_read_error_code(s->s, &aec))
                        goto err;

                    ec = nghttp3_conn_close_stream(conn->h3conn, s->id, aec);
                    if (ec < 0) {
                        ERR_raise_data(ERR_LIB_USER, ERR_R_INTERNAL_ERROR,
                                       "cannot mark stream as reset: %s (%d)",
                                       nghttp3_strerror(ec), ec);
                        goto err;
                    }

                    s->done_recv_fin = 1;
                } else {
                    /* Other error. */
                    goto err;
                }
            }

            s->buf_cur      = 0;
            s->buf_total    = num_bytes;
        }

        if (s->buf_cur == s->buf_total)
            break;

        assert(conn->consumed_app_data == 0);
        ec = nghttp3_conn_read_stream(conn->h3conn, s->id, s->buf + s->buf_cur,
                                      s->buf_total - s->buf_cur, /*fin=*/0);
        if (ec < 0) {
            ERR_raise_data(ERR_LIB_USER, ERR_R_INTERNAL_ERROR,
                           "nghttp3 failed to process incoming data: %s (%d)",
                           nghttp3_strerror(ec), ec);
            goto err;
        }

        consumed = ec + conn->consumed_app_data;
        assert(consumed <= s->buf_total - s->buf_cur);
        s->buf_cur += consumed;
        conn->consumed_app_data = 0;
    }

    return;
err:
    conn->pump_res = 0;
}

int H3_CONN_handle_events(H3_CONN *conn)
{
    int ec, fin;
    size_t i, num_vecs, written, total_written, total_len;
    int64_t stream_id;
    nghttp3_vec vecs[8] = {0};
    H3_STREAM key, *s;
    SSL *snew;

    if (conn == NULL)
        return 0;

    /* Check for new incoming streams */
    for (;;) {
        if ((snew = SSL_accept_stream(conn->qconn, SSL_ACCEPT_STREAM_NO_BLOCK)) == NULL)
            break;

        if (h3_conn_accept_stream(conn, snew) == NULL) {
            SSL_free(snew);
            return 0;
        }
    }

    /* Pump outgoing data from HTTP/3 engine to QUIC. */
    for (;;) {
        /* Get a number of send vectors from the HTTP/3 engine. */
        ec = nghttp3_conn_writev_stream(conn->h3conn, &stream_id, &fin,
                                        vecs, ARRAY_LEN(vecs));
        if (ec < 0)
            return 0;
        if (ec == 0)
            break;

        /* For each of the vectors returned, pass it to OpenSSL QUIC. */
        key.id = stream_id;
        if ((s = lh_H3_STREAM_retrieve(conn->streams, &key)) == NULL) {
            ERR_raise_data(ERR_LIB_USER, ERR_R_INTERNAL_ERROR,
                           "no stream for ID %zd", stream_id);
            return 0;
        }

        num_vecs = ec;
        total_len = nghttp3_vec_len(vecs, num_vecs);
        total_written = 0;
        for (i = 0; i < num_vecs; ++i) {
            if (vecs[i].len == 0)
                continue;

            if (s->s == NULL) {
                written = vecs[i].len;
            } else if (!SSL_write_ex(s->s, vecs[i].base, vecs[i].len, &written)) {
                if (SSL_get_error(s->s, 0) == SSL_ERROR_WANT_WRITE) {
                    written = 0;
                    nghttp3_conn_block_stream(conn->h3conn, stream_id);
                } else {
                    ERR_raise_data(ERR_LIB_USER, ERR_R_INTERNAL_ERROR,
                                   "writing HTTP/3 data to network failed");
                    return 0;
                }
            } else {
                nghttp3_conn_unblock_stream(conn->h3conn, stream_id);
            }

            total_written += written;
            if (written > 0) {
                ec = nghttp3_conn_add_write_offset(conn->h3conn, stream_id, written);
                if (ec < 0)
                    return 0;

                ec = nghttp3_conn_add_ack_offset(conn->h3conn, stream_id, written);
                if (ec < 0)
                    return 0;
            }
        }

        if (fin && total_written == total_len) {
            SSL_stream_conclude(s->s, 0);
            if (total_len == 0) {
                ec = nghttp3_conn_add_write_offset(conn->h3conn, stream_id, 0);
                if (ec < 0)
                    return 0;
            }
        }
    }

    /* Pump incoming data from QUIC to HTTP/3 engine. */
    conn->pump_res = 1;
    lh_H3_STREAM_doall_arg(conn->streams, h3_conn_pump_stream, conn);
    if (!conn->pump_res)
        return 0;

    return 1;
}

int H3_CONN_submit_request(H3_CONN *conn, const nghttp3_nv *nva, size_t nvlen,
                           const nghttp3_data_reader *dr,
                           void *user_data)
{
    int ec;
    H3_STREAM *s_req = NULL;

    if (conn == NULL) {
        ERR_raise_data(ERR_LIB_USER, ERR_R_PASSED_NULL_PARAMETER,
                       "connection must be specified");
        return 0;
    }

    if ((s_req = h3_conn_create_stream(conn, H3_STREAM_TYPE_REQ)) == NULL)
        goto err;

    s_req->user_data = user_data;

    ec = nghttp3_conn_submit_request(conn->h3conn, s_req->id, nva, nvlen,
                                     dr, s_req);
    if (ec < 0) {
        ERR_raise_data(ERR_LIB_USER, ERR_R_INTERNAL_ERROR,
                       "cannot submit HTTP/3 request: %s (%d)",
                       nghttp3_strerror(ec), ec);
        goto err;
    }

    return 1;

err:
    h3_conn_remove_stream(conn, s_req);
    return 0;
}
