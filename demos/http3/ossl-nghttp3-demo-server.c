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
#include <sys/stat.h>
#include <fcntl.h>

#define nghttp3_arraylen(A) (sizeof(A) / sizeof(*(A)))

/* The crappy test wants 20 bytes */
static uint8_t nulldata[20] = "12345678901234567890";

/* 3 streams created by the server and 4 by the client (one is bidi) */
struct ssl_id {
    SSL *s;      /* the stream openssl uses in SSL_read(),  SSL_write etc */
    uint64_t id; /* the stream identifier the nghttp3 uses */
    int status;  /* 0, CLIENTUNIOPEN or CLIENTUNIOPEN|CLIENTCLOSED (for the moment) */
};
/* status and origin of the streams the possible values are: */
#define CLIENTUNIOPEN  0x01 /* unidirectional open by the client (2, 6 and 10) */
#define CLIENTCLOSED   0x02 /* closed by the client */
#define CLIENTBIDIOPEN 0x04 /* bidirectional open by the client (something like 0, 4, 8 ...) */
#define SERVERUNIOPEN  0x08 /* unidirectional open by the server (3, 7 and 11) */
#define SERVERCLOSED   0x10 /* closed by the server (us) */

#define MAXSSL_IDS 20
#define MAXURL 255

struct h3ssl {
    struct ssl_id ssl_ids[MAXSSL_IDS];
    int end_headers_received; /* h3 header received call back called */
    int datadone;             /* h3 has given openssl all the data of the response */
    int has_uni;              /* we have the 3 uni directional stream needed */
    int close_done;           /* connection begins terminating EVENT_EC */
    int close_wait;           /* we are wait for a close or a new request */
    int done;                 /* connection terminated EVENT_ECD, after EVENT_EC */
    int new_conn;             /* a new connection has been received */
    int received_from_two;    /* workaround for -607 on nghttp3_conn_read_stream on stream 2 */
    int restart;              /* new request/response cycle started */
    uint64_t id_bidi;         /* the id of the stream used to read request and send response */
    char url[MAXURL];         /* url to serve the request */
    uint8_t *ptr_data;        /* pointer to the data to send */
    unsigned int ldata;       /* amount of bytes to send */
    int offset_data;          /* offset to next data to send */
};

static void make_nv(nghttp3_nv *nv, const char *name, const char *value)
{
    nv->name        = (uint8_t *)name;
    nv->value       = (uint8_t *)value;
    nv->namelen     = strlen(name);
    nv->valuelen    = strlen(value);
    nv->flags       = NGHTTP3_NV_FLAG_NONE;
}

static void init_ids(struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        ssl_ids[i].s = NULL;
        ssl_ids[i].id = UINT64_MAX;
        ssl_ids[i].status = 0;
    }
    h3ssl->end_headers_received = 0;
    h3ssl->datadone = 0;
    h3ssl->has_uni = 0;
    h3ssl->close_done = 0;
    h3ssl->close_wait = 0;
    h3ssl->done = 0;
    h3ssl->new_conn = 0;
    h3ssl->received_from_two = 0;
    h3ssl->restart = 0;
    memset(h3ssl->url, '\0', sizeof(h3ssl->url));
    h3ssl->ptr_data = NULL;
    h3ssl->offset_data = 0;
    h3ssl->ldata = 0;
    h3ssl->id_bidi = UINT64_MAX;
}

static void reuse_h3ssl(struct h3ssl *h3ssl)
{
    h3ssl->end_headers_received = 0;
    h3ssl->datadone = 0;
    h3ssl->close_done = 0;
    h3ssl->close_wait = 0;
    h3ssl->done = 0;
    memset(h3ssl->url, '\0', sizeof(h3ssl->url));
    if (h3ssl->ptr_data != NULL && h3ssl->ptr_data != nulldata)
        free(h3ssl->ptr_data);
    h3ssl->ptr_data = NULL;
    h3ssl->offset_data = 0;
    h3ssl->ldata = 0;
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
static void add_id_at(uint64_t id, SSL *ssl, int at, struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids;

    ssl_ids = h3ssl->ssl_ids;
    if (ssl_ids[at].s == NULL) {
        ssl_ids[at].s = ssl;
        ssl_ids[at].id = id;
        return;
    }
    printf("Oops %d already used\n", at);
    exit(1);
}

static void remove_id(uint64_t id, struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    if (id == UINT64_MAX)
        return;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].id == id) {
            printf("remove_id %llu\n", (unsigned long long) ssl_ids[i].id);
            /* XXX: don't work SSL_clear(ssl_ids[i].s); */
            SSL_free(ssl_ids[i].s);
            ssl_ids[i].s = NULL;
            ssl_ids[i].id = UINT64_MAX;
            ssl_ids[i].status = 0;
            return;
        }
    }
}

static void set_id_status(uint64_t id, int status, struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].id == id) {
            printf("set_id_status: %llu to %d\n", (unsigned long long) ssl_ids[i].id, status);
            ssl_ids[i].status = status;
            return;
        }
    }
    printf("Oops can't set status, can't find stream!!!\n");
    assert(0);
}
static int get_id_status(uint64_t id, struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].id == id) {
            printf("get_id_status: %llu to %d\n",
                   (unsigned long long) ssl_ids[i].id, ssl_ids[i].status);
            return ssl_ids[i].status;
        }
    }
    printf("Oops can't set status, can't find stream!!!\n");
    assert(0);
    return -1;
}

static int are_all_clientid_closed(struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].id == UINT64_MAX)
            continue;
        if (ssl_ids[i].status == CLIENTUNIOPEN) {
            printf("are_all_clientid_closed: %llu open\n", (unsigned long long) ssl_ids[i].id);
            return 0;
        }
        printf("are_all_clientid_closed: %llu status %d : %d\n",
               (unsigned long long) ssl_ids[i].id, ssl_ids[i].status, CLIENTUNIOPEN | CLIENTCLOSED);
        if (ssl_ids[i].status == (CLIENTUNIOPEN | CLIENTCLOSED)) {
            printf("are_all_clientid_closed: %llu closed\n", (unsigned long long) ssl_ids[i].id);
            SSL_free(ssl_ids[i].s);
            ssl_ids[i].s = NULL;
            ssl_ids[i].id = UINT64_MAX;
        }
    }
    return 1;
}

static void close_all_ids(struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].id == UINT64_MAX)
            continue;
        SSL_free(ssl_ids[i].s);
        ssl_ids[i].s = NULL;
        ssl_ids[i].id = UINT64_MAX;
    }
}

static int on_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                          nghttp3_rcbuf *name, nghttp3_rcbuf *value,
                          uint8_t flags, void *user_data,
                          void *stream_user_data)
{
    nghttp3_vec vname, vvalue;
    struct h3ssl *h3ssl = (struct h3ssl *)user_data;

    /* Received a single HTTP header. */
    vname = nghttp3_rcbuf_get_buf(name);
    vvalue = nghttp3_rcbuf_get_buf(value);

    fwrite(vname.base, vname.len, 1, stderr);
    fprintf(stderr, ": ");
    fwrite(vvalue.base, vvalue.len, 1, stderr);
    fprintf(stderr, "\n");

    if (token == NGHTTP3_QPACK_TOKEN__PATH) {
        memcpy(h3ssl->url, vvalue.base, vvalue.len);
        if (h3ssl->url[0] == '/') {
            if (h3ssl->url[1] == '\0') {
                strcpy(h3ssl->url, "index.html");
            } else {
                memcpy(h3ssl->url, h3ssl->url + 1, vvalue.len - 1);
                h3ssl->url[vvalue.len - 1] = '\0';
            }
        }
    }

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

/* Read from the stream and push to the h3conn */
static int quic_server_read(nghttp3_conn *h3conn, SSL *stream, uint64_t id, struct h3ssl *h3ssl)
{
    int ret, r;
    uint8_t msg2[16000];
    size_t l = sizeof(msg2);

    if (!SSL_has_pending(stream))
        return 0; /* Nothing to read */

    ret = SSL_read(stream, msg2, l);
    if (ret <= 0) {
        fprintf(stderr, "SSL_read %d on %llu failed\n",
                SSL_get_error(stream, ret),
                (unsigned long long) id);
        if (SSL_get_error(stream, ret) == SSL_ERROR_WANT_READ)
            return 0; /* retry we need more data */
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* XXX: work around nghttp3_conn_read_stream returning  -607 on stream 2 */
    if (!h3ssl->received_from_two && id != 2) {
        r = nghttp3_conn_read_stream(h3conn, id, msg2, ret, 0);
    } else {
        r = ret; /* ignore it for the moment ... */
    }

    printf("nghttp3_conn_read_stream used %d of %d on %llu\n", r,
           ret, (unsigned long long) id);
    if (r != ret) {
        /* chrome returns -607 on stream 2 */
        if (!nghttp3_err_is_fatal(r)) {
            printf("nghttp3_conn_read_stream used %d of %d (not fatal) on %llu\n", r,
                   ret, (unsigned long long) id);
            if (id == 2)
                h3ssl->received_from_two = 1;
            return 1;
        }
        return -1;
    }
    return 1;
}

/*
 * creates the control stream, the encoding and decoding streams.
 * nghttp3_conn_bind_control_stream() is for the control stream.
 */
static int quic_server_h3streams(nghttp3_conn *h3conn, struct h3ssl *h3ssl)
{
    SSL *rstream;
    SSL *pstream;
    SSL *cstream;
    uint64_t r_streamid, p_streamid, c_streamid;
    struct ssl_id *ssl_ids = h3ssl->ssl_ids;

    rstream = SSL_new_stream(ssl_ids[1].s, SSL_STREAM_FLAG_UNI);
    if (rstream != NULL) {
        fprintf(stderr, "=> Opened on %llu\n",
                (unsigned long long)SSL_get_stream_id(rstream));
        fflush(stderr);
    } else {
        fprintf(stderr, "=> Stream == NULL!\n");
        fflush(stderr);
        return -1;
    }
    pstream = SSL_new_stream(ssl_ids[1].s, SSL_STREAM_FLAG_UNI);
    if (pstream != NULL) {
        fprintf(stderr, "=> Opened on %llu\n",
                (unsigned long long)SSL_get_stream_id(pstream));
        fflush(stderr);
    } else {
        fprintf(stderr, "=> Stream == NULL!\n");
        fflush(stderr);
        return -1;
    }
    cstream = SSL_new_stream(ssl_ids[1].s, SSL_STREAM_FLAG_UNI);
    if (cstream != NULL) {
        fprintf(stderr, "=> Opened on %llu\n",
                (unsigned long long)SSL_get_stream_id(cstream));
        fflush(stderr);
    } else {
        fprintf(stderr, "=> Stream == NULL!\n");
        fflush(stderr);
        return -1;
    }
    r_streamid = SSL_get_stream_id(rstream);
    p_streamid = SSL_get_stream_id(pstream);
    c_streamid = SSL_get_stream_id(cstream);
    if (nghttp3_conn_bind_qpack_streams(h3conn, p_streamid, r_streamid)) {
        fprintf(stderr, "nghttp3_conn_bind_qpack_streams failed!\n");
        return -1;
    }
    if (nghttp3_conn_bind_control_stream(h3conn, c_streamid)) {
        fprintf(stderr, "nghttp3_conn_bind_qpack_streams failed!\n");
        return -1;
    }
    printf("control: %llu enc %llu dec %llu\n",
           (unsigned long long)c_streamid,
           (unsigned long long)p_streamid,
           (unsigned long long)r_streamid);
    add_id(SSL_get_stream_id(rstream), rstream, h3ssl);
    add_id(SSL_get_stream_id(pstream), pstream, h3ssl);
    add_id(SSL_get_stream_id(cstream), cstream, h3ssl);

    return 0;
}

/* Try to read from the streams we have */
static int read_from_ssl_ids(nghttp3_conn *h3conn, struct h3ssl *h3ssl)
{
    int hassomething = 0, i;
    struct ssl_id *ssl_ids = h3ssl->ssl_ids;
    SSL_POLL_ITEM items[MAXSSL_IDS] = {0}, *item = items;
    static const struct timeval nz_timeout = {0, 0};
    size_t result_count = SIZE_MAX;
    int numitem = 0, ret;
    uint64_t processed_event = 0;
    uint64_t id_to_remove = UINT64_MAX;

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

    /*
     * SSL_POLL_FLAG_NO_HANDLE_EVENTS would require to use:
     * SSL_get_event_timeout on the connection stream
     * select/wait using the timeout value (which could be no wait time)
     * SSL_handle_events
     * SSL_poll
     * for the moment we let SSL_poll to performs ticking internally
     * on an automatic basis.
     */
    ret = SSL_poll(items, numitem, sizeof(SSL_POLL_ITEM), &nz_timeout,
                   SSL_POLL_FLAG_NO_HANDLE_EVENTS, &result_count);
    if (!ret) {
        fprintf(stderr, "SSL_poll failed\n");
        printf("SSL_poll failed\n");
        return -1; /* something is wrong */
    }
    printf("read_from_ssl_ids %ld events\n", (unsigned long)result_count);
    if (result_count == 0) {
        /* Timeout may be something somewhere */
        return 0;
    }

    /* Process all the item we have polled */
    item = NULL;
    for (i = 0; i < numitem; i++) {
        SSL *s;

        if (!item)
            item = items;
        else
            item++;
        if (item->revents == SSL_POLL_EVENT_NONE)
            continue;
        processed_event = 0;
        /* get the stream */
        s = item->desc.value.ssl;

        /* New connection */
        if (item->revents & SSL_POLL_EVENT_IC) {
            SSL *conn = SSL_accept_connection(item->desc.value.ssl, 0);

            printf("SSL_accept_connection\n");
            if (conn == NULL) {
                fprintf(stderr, "error while accepting connection\n");
                ret = -1;
                goto err;
            }
            if (!SSL_set_incoming_stream_policy(conn,
                                                SSL_INCOMING_STREAM_POLICY_ACCEPT, 0)) {
                fprintf(stderr, "error while setting inccoming stream policy\n");
                ret = -1;
                goto err;
            }

            /* the previous might be still there */
            if (ssl_ids[1].s) {
                /* XXX we support only one connection for the moment */
                printf("SSL_accept_connection closing previous\n");
                SSL_free(h3ssl->ssl_ids[1].s);
                h3ssl->ssl_ids[1].s = NULL;
                reuse_h3ssl(h3ssl);
                h3ssl->new_conn = 1;
            }
            add_id_at(-1, conn, 1, h3ssl);
            printf("SSL_accept_connection\n");
            processed_event = processed_event + SSL_POLL_EVENT_IC;
        }
        /* SSL_accept_stream if SSL_POLL_EVENT_ISB or SSL_POLL_EVENT_ISU */
        if ((item->revents & SSL_POLL_EVENT_ISB) ||
            (item->revents & SSL_POLL_EVENT_ISU)) {
            SSL *stream = SSL_accept_stream(item->desc.value.ssl, 0);
            uint64_t new_id;
            int r;

            if (stream == NULL) {
                ret = -1;
                goto err;
            }
            new_id = SSL_get_stream_id(stream);
            printf("=> Received connection on %lld %d\n", (unsigned long long) new_id,
                   SSL_get_stream_type(stream));
            add_id(new_id, stream, h3ssl);
            if (h3ssl->close_wait) {
                printf("in close_wait so we will have a new request\n");
                reuse_h3ssl(h3ssl);
                h3ssl->restart = 1; /* Checked in wait_close loop */
            }
            if (SSL_get_stream_type(stream) == SSL_STREAM_TYPE_BIDI) {
                /* bidi that is the id  where we have to send the response */
                printf("=> Received connection on %lld ISBIDI\n",
                       (unsigned long long) new_id);
                if (h3ssl->id_bidi != UINT64_MAX)
                    id_to_remove = h3ssl->id_bidi;
                h3ssl->id_bidi = new_id;
                reuse_h3ssl(h3ssl);
                h3ssl->restart = 1;
            } else {
                set_id_status(new_id, CLIENTUNIOPEN, h3ssl);
            }

            r = quic_server_read(h3conn, stream, new_id, h3ssl);
            if (r == -1) {
                ret = -1;
                goto err;
            }
            if (r == 1)
                hassomething++;

            if (item->revents & SSL_POLL_EVENT_ISB)
                processed_event = processed_event + SSL_POLL_EVENT_ISB;
            if (item->revents & SSL_POLL_EVENT_ISU)
                processed_event = processed_event + SSL_POLL_EVENT_ISU;
        }
        if (item->revents & SSL_POLL_EVENT_OSB) {
            /* Create new streams when allowed */
            /* at least one bidi */
            processed_event = processed_event + SSL_POLL_EVENT_OSB;
            printf("Create bidi?\n");
        }
        if (item->revents & SSL_POLL_EVENT_OSU) {
            /* at least one uni */
            /* we have 4 streams from the client 2, 6 , 10 and 0 */
            /* need 3 streams to the client */
            printf("Create uni?\n");
            processed_event = processed_event + SSL_POLL_EVENT_OSU;
            if (!h3ssl->has_uni) {
                printf("Create uni\n");
                ret = quic_server_h3streams(h3conn, h3ssl);
                if (ret == -1) {
                    fprintf(stderr, "quic_server_h3streams failed!\n");
                    goto err;
                }
                h3ssl->has_uni = 1;
                hassomething++;
            }
        }
        if (item->revents & SSL_POLL_EVENT_EC) {
            /* the connection begins terminating */
            printf("Connection terminating\n");
            printf("Connection terminating restart %d\n", h3ssl->restart);
            if (!h3ssl->close_done) {
                h3ssl->close_done = 1;
            } else {
                h3ssl->done = 1;
            }
            hassomething++;
            processed_event = processed_event + SSL_POLL_EVENT_EC;
        }
        if (item->revents & SSL_POLL_EVENT_ECD) {
            /* the connection is terminated */
            printf("Connection terminated\n");
            h3ssl->done = 1;
            hassomething++;
            processed_event = processed_event + SSL_POLL_EVENT_ECD;
        }

        if (item->revents & SSL_POLL_EVENT_R) {
            /* try to read */
            uint64_t id = UINT64_MAX;
            int r;

            /* get the id, well the connection has no id... */
            id = SSL_get_stream_id(item->desc.value.ssl);
            printf("revent READ on %llu\n", (unsigned long long)id);
            r = quic_server_read(h3conn, s, id, h3ssl);
            if (r == 0)
                continue;
            if (r == -1) {
                ret = -1;
                goto err;
            }
            hassomething++;
            processed_event = processed_event + SSL_POLL_EVENT_R;
        }
        if (item->revents & SSL_POLL_EVENT_ER) {
            /* mark it closed */
            uint64_t id = UINT64_MAX;
            int status;

            id = SSL_get_stream_id(item->desc.value.ssl);
            status = get_id_status(id, h3ssl);

            printf("revent exception READ on %llu\n", (unsigned long long)id);
            if (status == CLIENTUNIOPEN) {
                status = status | CLIENTCLOSED;
                set_id_status(id, status, h3ssl);
                hassomething++;
            }
            processed_event = processed_event + SSL_POLL_EVENT_ER;
        }
        if (item->revents & SSL_POLL_EVENT_W) {
            /* we ignore those for the moment */
            processed_event = processed_event + SSL_POLL_EVENT_W;
        }
        if (item->revents & SSL_POLL_EVENT_EW) {
            /* write part received a STOP_SENDING */
            uint64_t id = UINT64_MAX;
            int status;

            id = SSL_get_stream_id(item->desc.value.ssl);
            status = get_id_status(id, h3ssl);

            if (status == SERVERCLOSED) {
                printf("both sides closed on  %llu\n", (unsigned long long)id);
                id_to_remove = id;
                hassomething++;
            }
            processed_event = processed_event + SSL_POLL_EVENT_EW;
        }
        if (item->revents != processed_event) {
            /* Figure out ??? */
            uint64_t id = UINT64_MAX;

            id = SSL_get_stream_id(item->desc.value.ssl);
            printf("revent %llu (%d) on %llu NOT PROCESSED!\n",
                   (unsigned long long)item->revents, SSL_POLL_EVENT_W,
                   (unsigned long long)id);
        }
    }
    ret = hassomething;
err:
    if (id_to_remove != UINT64_MAX)
        remove_id(id_to_remove, h3ssl);
    return ret;
}

static void handle_events_from_ids(struct h3ssl *h3ssl)
{
    struct ssl_id *ssl_ids = h3ssl->ssl_ids;
    int i;

    ssl_ids = h3ssl->ssl_ids;
    for (i = 0; i < MAXSSL_IDS; i++) {
        if (ssl_ids[i].s != NULL) {
            if (SSL_handle_events(ssl_ids[i].s))
                ERR_print_errors_fp(stderr);
        }
    }
}

static int get_file_length(char *filename)
{
    struct stat st;

    if (strcmp(filename, "big") == 0) {
        printf("big!!!\n");
        return INT_MAX;
    }
    if (stat(filename, &st) == 0) {
        /* Only process regular files */
        if (S_ISREG(st.st_mode)) {
            printf("get_file_length %s %ld\n", filename, st.st_size);
            return st.st_size;
        }
    }
    printf("Can't get_file_length %s\n", filename);
    return 0;
}

static char *get_file_data(char *filename)
{
    int size = get_file_length(filename);
    char *res;
    int fd;

    if (size == 0)
        return NULL;

    res = malloc(size+1);
    res[size] = '\0';
    fd = open(filename, O_RDONLY);
    if (read(fd, res, size) == -1) {
        close(fd);
        free(res);
        return NULL;
    }
    close(fd);
    printf("read from %s : %d\n", filename, size);
    return res;
}

static nghttp3_ssize step_read_data(nghttp3_conn *conn, int64_t stream_id,
                                    nghttp3_vec *vec, size_t veccnt,
                                    uint32_t *pflags, void *user_data,
                                    void *stream_user_data)
{
    struct h3ssl *h3ssl = (struct h3ssl *)user_data;

    if (h3ssl->datadone) {
        *pflags = NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    /* send the data */
    printf("step_read_data for %s %d\n", h3ssl->url, h3ssl->ldata);
    if (h3ssl->ldata <= 4096) {
        vec[0].base = &(h3ssl->ptr_data[h3ssl->offset_data]);
        vec[0].len = h3ssl->ldata;
        h3ssl->datadone++;
        *pflags = NGHTTP3_DATA_FLAG_EOF;
    } else {
        vec[0].base = &(h3ssl->ptr_data[h3ssl->offset_data]);
        vec[0].len = 4096;
        if (h3ssl->ldata == INT_MAX) {
            printf("big = endless!\n");
        } else {
            h3ssl->offset_data = h3ssl->offset_data + 4096;
            h3ssl->ldata = h3ssl->ldata - 4096;
        }
    }

    return 1;
}

static int quic_server_write(struct h3ssl *h3ssl, uint64_t streamid,
                             uint8_t *buff, size_t len, uint64_t flags,
                             size_t *written)
{
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
                       unsigned int in_len, void *arg)
{
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

/* Copied from demos/guide/quic-server-non-block.c */
/**
 * @brief Waits for activity on the SSL socket, either for reading or writing.
 *
 * This function monitors the underlying file descriptor of the given SSL
 * connection to determine when it is ready for reading or writing, or both.
 * It uses the select function to wait until the socket is either readable
 * or writable, depending on what the SSL connection requires.
 *
 * @param ssl A pointer to the SSL object representing the connection.
 *
 * @note This function blocks until there is activity on the socket. In a real
 * application, you might want to perform other tasks while waiting, such as
 * updating a GUI or handling other connections.
 *
 * @note This function uses select for simplicity and portability. Depending
 * on your application's requirements, you might consider using other
 * mechanisms like poll or epoll for handling multiple file descriptors.
 */
static int wait_for_activity(SSL *ssl)
{
    int sock, isinfinite;
    fd_set read_fd, write_fd;
    struct timeval tv;
    struct timeval *tvp = NULL;

    /* Get hold of the underlying file descriptor for the socket */
    if ((sock = SSL_get_fd(ssl)) == -1) {
        fprintf(stderr, "Unable to get file descriptor");
        return -1;
    }

    /* Initialize the fd_set structure */
    FD_ZERO(&read_fd);
    FD_ZERO(&write_fd);

    /*
     * Determine if we would like to write to the socket, read from it, or both.
     */
    if (SSL_net_write_desired(ssl))
        FD_SET(sock, &write_fd);
    if (SSL_net_read_desired(ssl))
        FD_SET(sock, &read_fd);

    /* Add the socket file descriptor to the fd_set */
    FD_SET(sock, &read_fd);

    /*
     * Find out when OpenSSL would next like to be called, regardless of
     * whether the state of the underlying socket has changed or not.
     */
    if (SSL_get_event_timeout(ssl, &tv, &isinfinite) && !isinfinite)
        tvp = &tv;

    /*
     * Wait until the socket is writeable or readable. We use select here
     * for the sake of simplicity and portability, but you could equally use
     * poll/epoll or similar functions
     *
     * NOTE: For the purposes of this demonstration code this effectively
     * makes this demo block until it has something more useful to do. In a
     * real application you probably want to go and do other work here (e.g.
     * update a GUI, or service other connections).
     *
     * Let's say for example that you want to update the progress counter on
     * a GUI every 100ms. One way to do that would be to use the timeout in
     * the last parameter to "select" below. If the tvp value is greater
     * than 100ms then use 100ms instead. Then, when select returns, you
     * check if it did so because of activity on the file descriptors or
     * because of the timeout. If the 100ms GUI timeout has expired but the
     * tvp timeout has not then go and update the GUI and then restart the
     * "select" (with updated timeouts).
     */

    return (select(sock + 1, &read_fd, &write_fd, NULL, tvp));
}

/* Main loop for server to accept QUIC connections. */
static int run_quic_server(SSL_CTX *ctx, int fd)
{
    int ok = 0;
    int hassomething = 0;
    SSL *listener = NULL;

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
        nghttp3_nv resp[10];
        size_t num_nv;
        nghttp3_data_reader dr;
        int ret;
        int numtimeout;
        char slength[11];
        int hasnothing;

        if (!hassomething) {
            printf("waiting on socket\n");
            fflush(stdout);
            ret = wait_for_activity(listener);
            if (ret == -1) {
                fprintf(stderr, "wait_for_activity failed!\n");
                goto err;
            }
        }
        printf("before SSL_accept_connection\n");
        fflush(stdout);

        /*
         * Service the connection. In a real application this would be done
         * concurrently. In this demonstration program a single connection is
         * accepted and serviced at a time.
         */

        /* try to use nghttp3 to send a response */
        init_ids(&h3ssl);
        printf("listener: %p\n", (void *)listener);
        add_id_at(-1, listener, 0, &h3ssl);

        /* Setup callbacks. */
        callbacks.recv_header = on_recv_header;
        callbacks.end_headers = on_end_headers;
        callbacks.recv_data = on_recv_data;
        callbacks.end_stream = on_end_stream;

        handle_events_from_ids(&h3ssl);

    newconn:
        nghttp3_settings_default(&settings);
        if (nghttp3_conn_server_new(&h3conn, &callbacks, &settings, mem,
                                    &h3ssl)) {
            fprintf(stderr, "nghttp3_conn_client_new failed!\n");
            exit(1);
        }

        printf("process_server starting...\n");
        fflush(stdout);

        /* wait until we have received the headers */
    restart:
        numtimeout = 0;
        num_nv = 0;
        while (!h3ssl.end_headers_received) {
            if (!hassomething) {
                printf("listener: %p waiting for end_headers_received\n",
                       (void *) h3ssl.ssl_ids[0].s);
                if (wait_for_activity(h3ssl.ssl_ids[0].s) == 0) {
                    printf("waiting for end_headers_received timeout %d\n", numtimeout);
                    numtimeout++;
                    if (numtimeout == 25)
                        goto err;
                }
                handle_events_from_ids(&h3ssl);
            }
            hassomething = read_from_ssl_ids(h3conn, &h3ssl);
            if (hassomething == -1) {
                fprintf(stderr, "read_from_ssl_ids hassomething failed\n");
                goto err;
            } else if (hassomething == 0) {
                printf("read_from_ssl_ids hassomething nothing...\n");
            } else {
                numtimeout = 0;
                printf("read_from_ssl_ids hassomething %d...\n", hassomething);
                if (h3ssl.close_done) {
                    /* Other side has closed */
                    break;
                }
                h3ssl.restart = 0;
            }
        }
        if (h3ssl.close_done) {
            printf("Other side close without request\n");
            goto wait_close;
        }
        printf("end_headers_received!!!\n");
        if (!h3ssl.has_uni) {
            /* time to create those otherwise we can't push anything to the client */
            printf("Create uni\n");
            if (quic_server_h3streams(h3conn, &h3ssl) == -1) {
                fprintf(stderr, "quic_server_h3streams failed!\n");
                goto err;
            }
            h3ssl.has_uni = 1;
        }

        /* we have receive the request build the response and send it */
        /* XXX add  MAKE_NV("connection", "close"), to resp[] and recheck */
        make_nv(&resp[num_nv++], ":status", "200");
        h3ssl.ldata = get_file_length(h3ssl.url);
        if (h3ssl.ldata == 0) {
            /* We don't find the file: use default test string */
            sprintf(slength, "%d", 20);
            h3ssl.ptr_data = nulldata;
            h3ssl.ldata = 20;
            /* content-type: text/html */
            make_nv(&resp[num_nv++], "content-type", "text/html");
        } else if (h3ssl.ldata == INT_MAX) {
            /* endless file for tests */
            sprintf(slength, "%d", h3ssl.ldata);
            h3ssl.ptr_data = (uint8_t *) malloc(4096);
            memset(h3ssl.ptr_data, 'A', 4096);
        } else {
            /* normal file we have opened */
            sprintf(slength, "%d", h3ssl.ldata);
            h3ssl.ptr_data = (uint8_t *) get_file_data(h3ssl.url);
            if (h3ssl.ptr_data == NULL)
                abort();
            printf("before nghttp3_conn_submit_response on %llu for %s ...\n",
                   (unsigned long long) h3ssl.id_bidi, h3ssl.url);
            if (strstr(h3ssl.url, ".png"))
                make_nv(&resp[num_nv++], "content-type", "image/png");
            else if (strstr(h3ssl.url, ".ico"))
                make_nv(&resp[num_nv++], "content-type", "image/vnd.microsoft.icon");
            else
                make_nv(&resp[num_nv++], "content-type", "text/html");
        }

        dr.read_data = step_read_data;
        if (nghttp3_conn_submit_response(h3conn, h3ssl.id_bidi, resp, num_nv, &dr)) {
            fprintf(stderr, "nghttp3_conn_submit_response failed!\n");
            goto err;
        }
        printf("nghttp3_conn_submit_response on %llu...\n", (unsigned long long) h3ssl.id_bidi);
        for (;;) {
            nghttp3_vec vec[256];
            nghttp3_ssize sveccnt;
            int fin, i;
            int64_t streamid;

            sveccnt = nghttp3_conn_writev_stream(h3conn, &streamid, &fin, vec,
                                                 nghttp3_arraylen(vec));
            if (sveccnt <= 0) {
                printf("nghttp3_conn_writev_stream done: %ld stream: %llu fin %d\n",
                       (long int)sveccnt,
                       (unsigned long long)streamid,
                       fin);
                if (streamid != -1 && fin) {
                    printf("Sending end data on %llu fin %d\n",
                           (unsigned long long) streamid, fin);
                    nghttp3_conn_add_write_offset(h3conn, streamid, 0);
                    continue;
                }
                if (!h3ssl.datadone)
                    goto err;
                else
                    break; /* Done */
            }
            printf("nghttp3_conn_writev_stream: %ld fin: %d\n", (long int)sveccnt, fin);
            for (i = 0; i < sveccnt; i++) {
                size_t numbytes = vec[i].len;
                int flagwrite = 0;

                printf("quic_server_write on %llu for %ld\n",
                       (unsigned long long)streamid, (unsigned long)vec[i].len);
                if (fin && i == sveccnt - 1)
                    flagwrite = SSL_WRITE_FLAG_CONCLUDE;
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
            if (!h3ssl.close_done) {
                int status = get_id_status(h3ssl.id_bidi, &h3ssl);

                status = status | SERVERCLOSED;
                set_id_status(h3ssl.id_bidi, status, &h3ssl);
                h3ssl.close_wait = 1;
            }
        } else {
            printf("nghttp3_conn_submit_response still not finished\n");
        }

        /* wait until closed */
    wait_close:
        hasnothing = 0;
        for (;;) {

            if (!hasnothing) {
                printf("hasnothing nothing WAIT %d!!!\n", h3ssl.close_done);
                ret = wait_for_activity(h3ssl.ssl_ids[1].s);
                if (ret == -1)
                    goto err;
                if (ret == 0)
                    printf("hasnothing timeout\n");
                /* we have something or a timeout */
                handle_events_from_ids(&h3ssl);
            }
            hasnothing = read_from_ssl_ids(h3conn, &h3ssl);
            if (hasnothing == -1) {
                printf("hasnothing failed\n");
                break;
                /* goto err; well in fact not */
            } else if (hasnothing == 0) {
                printf("hasnothing nothing\n");
                continue;
            } else {
                printf("hasnothing something\n");
                if (h3ssl.done) {
                    printf("hasnothing something... DONE\n");
                    /* we might already have the next connection to accept */
                    hassomething = 1;
                    break;
                }
                if (h3ssl.new_conn) {
                    printf("hasnothing something... NEW CONN\n");
                    close_all_ids(&h3ssl);
                    h3ssl.new_conn = 0;
                    goto newconn;
                }
                if (h3ssl.restart) {
                    printf("hasnothing something... RESTART\n");
                    h3ssl.restart = 0;
                    goto restart;
                }
                if (are_all_clientid_closed(&h3ssl)) {
                    printf("hasnothing something... DONE other side closed\n");
                    /* there might 2 or 3 message we will ignore */
                    hassomething = 0;
                    break;
                }
            }
        }

        /*
         * Free the connection, then loop again, accepting another connection.
         */
        close_all_ids(&h3ssl);
        SSL_free(h3ssl.ssl_ids[1].s);
        h3ssl.ssl_ids[1].s = NULL;
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
