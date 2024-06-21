/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <assert.h>
#include <netinet/in.h>
#include <nghttp3/nghttp3.h>
#include <openssl/err.h>
#include <openssl/quic.h>
#include <openssl/ssl.h>
#include <unistd.h>

#define MAKE_NV(NAME, VALUE)                                                   \
    { (uint8_t *)(NAME), (uint8_t *)(VALUE), sizeof((NAME)) - 1,               \
      sizeof((VALUE)) - 1, NGHTTP3_NV_FLAG_NONE }
#define nghttp3_arraylen(A) (sizeof(A) / sizeof(*(A)))

/* CURL according to trace has 2 more streams 7 and 11 */
struct ssl_id {
    SSL *s;
    uint64_t id;
};

#define MAXSSL_IDS 20
struct h3ssl {
    struct ssl_id ssl_ids[MAXSSL_IDS];
    int end_headers_received;
    int datadone;
    int has_uni;
    int done;
};

static void init_ids(struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        ssl_ids[i].s = NULL;
        ssl_ids[i].id = -1;
    }
    h3ssl->end_headers_received = 0;
    h3ssl->datadone = 0;
    h3ssl->has_uni = 0;
    h3ssl->done = 0;
}

static void add_id(uint64_t id, SSL *ssl, struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].s == NULL) {
            ssl_ids[i].s = ssl;
            ssl_ids[i].id = id;
            return;
        }
    }
    printf("Oops too many streams to add!!!\n");
    exit(1);
}

static void h3close(struct h3ssl *h3ssl, uint64_t id)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].id == id) {
            if (!SSL_stream_conclude(ssl_ids[i].s, 0))
                fprintf(stderr, "h3close: SSL_stream_conclude on %llu failed\n", (unsigned long long) id);
            SSL_shutdown(ssl_ids[i].s);
        }
    }
}

static int on_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                          nghttp3_rcbuf *name, nghttp3_rcbuf *value,
                          uint8_t flags, void *user_data,
                          void *stream_user_data)
{
    nghttp3_vec vname, vvalue;

    /* Received a single HTTP header. */
    vname = nghttp3_rcbuf_get_buf(name);
    vvalue = nghttp3_rcbuf_get_buf(value);

    fwrite(vname.base, vname.len, 1, stderr);
    fprintf(stderr, ": ");
    fwrite(vvalue.base, vvalue.len, 1, stderr);
    fprintf(stderr, "\n");

    return 0;
}

static int on_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin,
                          void *user_data, void *stream_user_data)
{
    struct h3ssl *h3ssl = (struct h3ssl *)user_data;

    fprintf(stderr, "on_end_headers!\n");
    h3ssl->end_headers_received = 1;
    return 0;
}

static int on_recv_data(nghttp3_conn *conn, int64_t stream_id,
                        const uint8_t *data, size_t datalen,
                        void *conn_user_data, void *stream_user_data)
{
    fprintf(stderr, "on_recv_data! %ld\n", (unsigned long)datalen);
    fprintf(stderr, "on_recv_data! %.*s\n", (int)datalen, data);
    return 0;
}

static int on_end_stream(nghttp3_conn *h3conn, int64_t stream_id,
                         void *conn_user_data, void *stream_user_data)
{
    struct h3ssl *h3ssl = (struct h3ssl *)conn_user_data;

    printf("on_end_stream!\n");
    h3ssl->done = 1;
    return 0;
}

static int read_from_ssl_ids(nghttp3_conn *h3conn, struct h3ssl *h3ssl)
{
    uint8_t msg2[16000];
    int hassomething = 0, i;
    struct ssl_id *ssl_ids = h3ssl->ssl_ids;
    SSL_POLL_ITEM items[MAXSSL_IDS] = {0}, *item = items;
    static const struct timeval nz_timeout = {0, 0};
    size_t result_count = SIZE_MAX;
    int numitem = 0, ret;

    /*
     * Process all the streams
     * the first one is the connection if we get something here is a new stream
     */
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].s != NULL) {
            item->desc = SSL_as_poll_descriptor(ssl_ids[i].s);
            item->events = UINT64_MAX;  /* TODO adjust to the event we need process */
            item->revents = UINT64_MAX; /* TODO adjust to the event we need process */
            numitem++;
            item++;
        }
    }
    ret = SSL_poll(items, numitem, sizeof(SSL_POLL_ITEM), &nz_timeout, 0,
                   &result_count);
    if (!ret) {
        fprintf(stderr, "SSL_poll failed\n");
        return -1; /* something is wrong */
    }
    if (result_count == 0) {
        /* Timeout may be something somewhere */
        return 0;
    }

    /* We have something */
    item = items;
    /* SSL_accept_stream if anyway */
    if ((item->revents & SSL_POLL_EVENT_ISB) ||
        (item->revents & SSL_POLL_EVENT_ISU)) {
        SSL *stream = SSL_accept_stream(ssl_ids[0].s, 0);

        if (stream == NULL) {
            return -1; /* something is wrong */
        }
        printf("=> Received connection on %lld\n",
               (unsigned long long)SSL_get_stream_id(stream));
        add_id(SSL_get_stream_id(stream), stream, h3ssl);
        printf("read_from_ssl_ids %ld events\n", (unsigned long)result_count);
        if (result_count == 1) {
            return 1; /* loop until we have all the streams */
        }
    }
    /* Create new streams when allowed */
    if (item->revents & SSL_POLL_EVENT_OSB) {
        /* at least one bidi */
        printf("Create bidi?\n");
    }
    if (item->revents & SSL_POLL_EVENT_OSU) {
        /* at least one uni */
        printf("Create uni\n");
        /* we have 4 streams from the client 2, 6 , 10 and 0 */
        /* need 2 streams to the client */
        if (!h3ssl->has_uni) {
            SSL *rstream;
            SSL *pstream;
            uint64_t r_streamid, p_streamid;

            printf("Create uni beacause !h3ssl->has_uni\n");
            rstream = SSL_new_stream(ssl_ids[0].s, SSL_STREAM_FLAG_UNI);
            if (rstream != NULL) {
                fprintf(stderr, "=> Opened on %llu\n",
                        (unsigned long long)SSL_get_stream_id(rstream));
                fflush(stderr);
            } else {
                fprintf(stderr, "=> Stream == NULL!\n");
                fflush(stderr);
                return -1;
            }
            pstream = SSL_new_stream(ssl_ids[0].s, SSL_STREAM_FLAG_UNI);
            if (pstream != NULL) {
                fprintf(stderr, "=> Opened on %llu\n",
                        (unsigned long long)SSL_get_stream_id(pstream));
                fflush(stderr);
            } else {
                fprintf(stderr, "=> Stream == NULL!\n");
                fflush(stderr);
                return -1;
            }
            r_streamid = SSL_get_stream_id(rstream);
            p_streamid = SSL_get_stream_id(pstream);
            if (nghttp3_conn_bind_qpack_streams(h3conn, p_streamid,
                                                r_streamid)) {
                fprintf(stderr, "nghttp3_conn_bind_qpack_streams failed!\n");
                return -1;
            }
            printf("control: NONE enc %llu dec %llu\n",
                   (unsigned long long)p_streamid,
                   (unsigned long long)r_streamid);
            add_id(SSL_get_stream_id(rstream), rstream, h3ssl);
            add_id(SSL_get_stream_id(pstream), pstream, h3ssl);
            h3ssl->has_uni = 1;
            if (result_count == 1) {
                printf("read_from_ssl_ids 1 event only!\n");
                return 0; /* one event only so we are done */
            }
        }
    }
    /* Well trying... */
    if (numitem <= 1) {
        return 0; /* Assume nothing for the moment */
    }

    /* Process the other stream */
    for (i = 1; i < numitem; i++) {
        item++;

        if (item->revents & SSL_POLL_EVENT_R) {
            /* try to read */
            size_t l = sizeof(msg2) - 1;
            int r;

            if (!SSL_net_read_desired(ssl_ids[i].s)) {
                continue;
            }
            ret = SSL_read(ssl_ids[i].s, msg2, l);
            if (ret <= 0) {
                fprintf(stderr, "SSL_read on %llu failed\n",
                       (unsigned long long)ssl_ids[i].id);
                continue; /* TODO */
            }
            r = nghttp3_conn_read_stream(h3conn, ssl_ids[i].id, msg2,
                                             ret, 0);

            printf("reading something %d on %llu\n", ret,
                   (unsigned long long)ssl_ids[i].id);
            printf("nghttp3_conn_read_stream used %d of %d on %llu\n", r,
                   ret, (unsigned long long)ssl_ids[i].id);
            hassomething++;
        } else {
            /* Figure out ??? */
            printf("revent %llu (%d) on %llu\n",
                   (unsigned long long)item->revents, SSL_POLL_EVENT_W,
                   (unsigned long long)ssl_ids[i].id);
        }
    }
    return hassomething;
}

static int nothing_from_ssl_ids(nghttp3_conn *h3conn, struct h3ssl *h3ssl)
{
    int hassomething = 0;
    struct ssl_id *ssl_ids;
    SSL_POLL_ITEM items[MAXSSL_IDS] = {0}, *item = items;
    static const struct timeval nz_timeout = {0, 0};
    size_t result_count = SIZE_MAX;
    int numitem = 0, i, ret;

    ssl_ids = h3ssl->ssl_ids;
    /* Process all the streams */
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].s) {
            item->desc = SSL_as_poll_descriptor(ssl_ids[i].s);
            item->events = UINT64_MAX;  /* TODO adjust to the event we need process */
            item->revents = UINT64_MAX; /* TODO adjust to the event we need process */
            numitem++;
            item++;
        }
    }
    ret = SSL_poll(items, numitem, sizeof(SSL_POLL_ITEM), &nz_timeout, 0,
                   &result_count);
    if (!ret) {
        fprintf(stderr, "SSL_poll failed\n");
        return -1; /* something is wrong */
    }
    if (result_count == 0) {
        /* Timeout may be something somewhere */
        return 0;
    }

    /* We have something */
    item = items;
    for (i = 0; i < numitem; i++) {
        item++;
        if (item->revents == SSL_POLL_EVENT_NONE) {
            continue;
        } else if (item->revents == SSL_POLL_EVENT_W) {
            printf("revent %llu (%d) on %llu\n",
                   (unsigned long long)item->revents, SSL_POLL_EVENT_W,
                   (unsigned long long)ssl_ids[i].id);
        } else if (item->revents == SSL_POLL_EVENT_ER) {
            printf("revent %llu (%d) on %llu\n",
                   (unsigned long long)item->revents, SSL_POLL_EVENT_ER,
                   (unsigned long long)ssl_ids[i].id);
        } else {
            /* Figure out ??? */
            printf("revent %llu (%d) on %llu\n",
                   (unsigned long long)item->revents, SSL_POLL_EVENT_NONE,
                   (unsigned long long)ssl_ids[i].id);
            hassomething++;
        }
    }
    return hassomething;
}

/* The crappy test wants 20 bytes */
static uint8_t nulldata[20] = "12345678901234567890";
static nghttp3_ssize step_read_data(nghttp3_conn *conn, int64_t stream_id,
                                    nghttp3_vec *vec, size_t veccnt,
                                    uint32_t *pflags, void *user_data,
                                    void *stream_user_data) {
    struct h3ssl *h3ssl = (struct h3ssl *)user_data;

    if (h3ssl->datadone) {
        *pflags = NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    vec[0].base = nulldata;
    vec[0].len = 20;
    h3ssl->datadone++;

    return 1;
}

static int quic_server_write(struct h3ssl *h3ssl, uint64_t streamid,
                             uint8_t *buff, size_t len, uint64_t flags,
                             size_t *written) {
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].id == streamid) {
            if (!SSL_write_ex2(ssl_ids[i].s, buff, len, flags, written) ||
                *written != len) {
                fprintf(stderr, "couldn't write on connection\n");
                ERR_print_errors_fp(stderr);
                return 0;
            }
            printf("written %ld on %lld flags %lld\n", (unsigned long)len,
                   (unsigned long long)streamid, (unsigned long long)flags);
            return 1;
        }
    }
    printf("quic_server_write %ld on %lld (NOT FOUND!)\n", (unsigned long)len,
           (unsigned long long)streamid);
    return 0;
}

#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

/*
 * This is a basic demo of QUIC server functionality in which one connection at
 * a time is accepted in a blocking loop.
 */

/* ALPN string for TLS handshake. We pretent h3-29 and h3 */
static const unsigned char alpn_ossltest[] = { 5,   'h', '3', '-', '2',
                                               '9', 2,   'h', '3' };

/*
 * This callback validates and negotiates the desired ALPN on the server side.
 */
static int select_alpn(SSL *ssl, const unsigned char **out,
                       unsigned char *out_len, const unsigned char *in,
                       unsigned int in_len, void *arg) {
    if (SSL_select_next_proto((unsigned char **)out, out_len, alpn_ossltest,
                              sizeof(alpn_ossltest), in,
                              in_len) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    return SSL_TLSEXT_ERR_OK;
}

/* Create SSL_CTX. */
static SSL_CTX *create_ctx(const char *cert_path, const char *key_path)
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (ctx == NULL)
        goto err;

    /* Load certificate and corresponding private key. */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0) {
        fprintf(stderr, "couldn't load certificate file: %s\n", cert_path);
        goto err;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "couldn't load key file: %s\n", key_path);
        goto err;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "private key check failed\n");
        goto err;
    }

    /* Setup ALPN negotiation callback. */
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    return ctx;

err:
    SSL_CTX_free(ctx);
    return NULL;
}

/* Create UDP socket using given port. */
static int create_socket(uint16_t port)
{
    int fd = -1;
    struct sockaddr_in sa = {0};

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        fprintf(stderr, "cannot create socket");
        goto err;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "cannot bind to %u\n", port);
        goto err;
    }

    return fd;

err:
    if (fd >= 0)
        BIO_closesocket(fd);

    return -1;
}

static int waitsocket(int fd, int sec)
{
    fd_set read_fds;
    int fdmax = fd;
    int ret;

    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);
    if (sec) {
        struct timeval tv;

        tv.tv_sec = sec;
        tv.tv_usec = 0;
        printf("waitsocket for %d\n", sec);
        ret = select(fdmax + 1, &read_fds, NULL, NULL, &tv);
    } else {
        ret = select(fdmax + 1, &read_fds, NULL, NULL, NULL);
    }
    if (ret == -1) {
        fprintf(stderr, "waitsocket failed\n");
        exit(1);
    } else if (ret) {
        printf("waitsocket %d\n", FD_ISSET(fd, &read_fds));
        return 0;
    }
    return -1; /* Timeout */
}

/* Main loop for server to accept QUIC connections. */
static int run_quic_server(SSL_CTX *ctx, int fd)
{
    int ok = 0;
    SSL *listener = NULL, *conn = NULL;

    /* Create a new QUIC listener. */
    if ((listener = SSL_new_listener(ctx, 0)) == NULL)
        goto err;

    /* Provide the listener with our UDP socket. */
    if (!SSL_set_fd(listener, fd))
        goto err;

    /* Begin listening. */
    if (!SSL_listen(listener))
        goto err;

    /*
     * Listeners, and other QUIC objects, default to operating in blocking mode.
     * The configured behaviour is inherited by child objects.
     * Make sure we won't block as we use select().
     */
    if (!SSL_set_blocking_mode(listener, 0))
        goto err;

    for (;;) {
        nghttp3_conn *h3conn;
        nghttp3_settings settings;
        nghttp3_callbacks callbacks = {0};
        struct h3ssl h3ssl;
        const nghttp3_mem *mem = nghttp3_mem_default();
        int hassomething = 0;
        nghttp3_nv resp[] = {
            MAKE_NV(":status", "200"),
            MAKE_NV("content-length", "20"),
        };
        nghttp3_data_reader dr;

        fprintf(stderr, "waiting on socket\n");
        fflush(stderr);
        waitsocket(fd, 0);
        fprintf(stderr, "before SSL_accept_connection\n");
        fflush(stderr);

        /*
         * SSL_accept_connection will return NULL if there is nothing to accept
         */
        conn = SSL_accept_connection(listener, 0);
        fprintf(stderr, "after SSL_accept_connection\n");
        fflush(stderr);
        if (conn == NULL) {
            fprintf(stderr, "error while accepting connection\n");
            continue;
        }

        /* set the incoming stream policy to accept */
        if (!SSL_set_incoming_stream_policy(
                conn, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0)) {
            fprintf(stderr, "error while setting inccoming stream policy\n");
            goto err;
        }

        /*
         * Service the connection. In a real application this would be done
         * concurrently. In this demonstration program a single connection is
         * accepted and serviced at a time.
         */

        /* try to use nghttp3 to send a response */
        init_ids(&h3ssl);
        nghttp3_settings_default(&settings);

        /* Setup callbacks. */
        callbacks.recv_header = on_recv_header;
        callbacks.end_headers = on_end_headers;
        callbacks.recv_data = on_recv_data;
        callbacks.end_stream = on_end_stream;

        if (nghttp3_conn_server_new(&h3conn, &callbacks, &settings, mem,
                                    &h3ssl)) {
            fprintf(stderr, "nghttp3_conn_client_new failed!\n");
            exit(1);
        }

        /* add accepted SSL conn to the ids we will poll */
        add_id(-1, conn, &h3ssl);
        printf("process_server starting...\n");
        fflush(stdout);

        /* wait until we have received the headers */
        while (!h3ssl.end_headers_received) {
            if (!hassomething)
                if (waitsocket(fd, 5)) {
                    printf("read_from_ssl_ids timeout\n");
                    goto err;
                }
            hassomething = read_from_ssl_ids(h3conn, &h3ssl);
            if (hassomething == -1) {
                fprintf(stderr, "read_from_ssl_ids hassomething failed\n");
                goto err;
            } else if (hassomething == 0) {
                printf("read_from_ssl_ids hassomething nothing...\n");
            } else {
                printf("read_from_ssl_ids hassomething %d...\n", hassomething);
            }
        }
        printf("end_headers_received!!!\n");

        /* we have receive the request build the response and send it */
        /* XXX add  MAKE_NV("connection", "close"), to resp[] and recheck */
        dr.read_data = step_read_data;
        if (nghttp3_conn_submit_response(h3conn, 0, resp, 2, &dr)) {
            fprintf(stderr, "nghttp3_conn_submit_response failed!\n");
            goto err;
        }
        printf("nghttp3_conn_submit_response...\n");
        for (;;) {
            nghttp3_vec vec[256];
            nghttp3_ssize sveccnt;
            int fin, i;
            int64_t streamid;

            sveccnt = nghttp3_conn_writev_stream(h3conn, &streamid, &fin, vec,
                                                 nghttp3_arraylen(vec));
            if (sveccnt <= 0) {
                printf("nghttp3_conn_writev_stream done: %ld\n",
                       (long int)sveccnt);
                break;
            }
            printf("nghttp3_conn_writev_stream: %ld fin: %d\n", (long int)sveccnt, fin);
            for (i = 0; i < sveccnt; i++) {
                size_t numbytes = vec[i].len;
                int flagwrite = 0;

                printf("quic_server_write on %llu for %ld\n",
                       (unsigned long long)streamid, (unsigned long)vec[i].len);
                if (flagwrite && i == sveccnt - 1) {
                    flagwrite = SSL_WRITE_FLAG_CONCLUDE;
                }
                if (!quic_server_write(&h3ssl, streamid, vec[i].base,
                                       vec[i].len, flagwrite, &numbytes)) {
                    fprintf(stderr, "quic_server_write failed!\n");
                    goto err;
                }
            }
            if (nghttp3_conn_add_write_offset(
                    h3conn, streamid,
                    (size_t)nghttp3_vec_len(vec, (size_t)sveccnt))) {
                fprintf(stderr, "nghttp3_conn_add_write_offset failed!\n");
                goto err;
            }
        }
        printf("nghttp3_conn_submit_response DONE!!!\n");

        if (h3ssl.datadone) {
            /*
             * All the data was sent.
             * close stream zero
             */
            h3close(&h3ssl, 0);
        }

        /* wait until closed */
        for (;;) {
            int hasnothing;

            if (waitsocket(fd, 5)) {
                printf("hasnothing timeout\n");
                goto err;
            }
            hasnothing = nothing_from_ssl_ids(h3conn, &h3ssl);
            if (hasnothing == -1) {
                printf("hasnothing failed\n");
                goto err;
            } else if (hasnothing == 0) {
                printf("hasnothing nothing...\n");
                break;
            } else {
                printf("hasnothing something...\n");
            }
        }

        /*
         * Free the connection, then loop again, accepting another connection.
         */
        SSL_free(conn);
    }

    ok = 1;
err:
    if (!ok)
        ERR_print_errors_fp(stderr);

    SSL_free(listener);
    return ok;
}

/*
 * demo server... just return a 20 bytes ascii string as response for any
 * request single h3 connection and single threaded.
 */
int main(int argc, char **argv)
{
    int rc = 1;
    SSL_CTX *ctx = NULL;
    int fd = -1;
    unsigned long port;

    if (argc < 4) {
        fprintf(stderr, "usage: %s <port> <server.crt> <server.key>\n",
                argv[0]);
        goto err;
    }

    /* Create SSL_CTX. */
    if ((ctx = create_ctx(argv[2], argv[3])) == NULL)
        goto err;

    /* Parse port number from command line arguments. */
    port = strtoul(argv[1], NULL, 0);
    if (port == 0 || port > UINT16_MAX) {
        fprintf(stderr, "invalid port: %lu\n", port);
        goto err;
    }

    /* Create UDP socket. */
    if ((fd = create_socket((uint16_t)port)) < 0)
        goto err;

    /* Enter QUIC server connection acceptance loop. */
    if (!run_quic_server(ctx, fd))
        goto err;

    rc = 0;
err:
    if (rc != 0)
        ERR_print_errors_fp(stderr);

    SSL_CTX_free(ctx);

    if (fd != -1)
        BIO_closesocket(fd);

    return rc;
}
