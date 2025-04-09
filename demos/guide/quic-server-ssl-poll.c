/*
 *  Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

/*
 * NB: Changes to this file should also be reflected in
 * doc/man7/ossl-guide-quic-server-non-block.pod
 */

#include <string.h>
#include <assert.h>

/* Include the appropriate header file for SOCK_STREAM */
#ifdef _WIN32 /* Windows */
# include <stdarg.h>
# include <winsock2.h>
#else /* Linux/Unix */
# include <err.h>
# include <sys/socket.h>
# include <sys/select.h>
# include <netinet/in.h>
# include <unistd.h>
# include <poll.h>
#endif

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/quic.h>

#include "internal/list.h"

#define POLL_FMT	"%s%s%s%s%s%s%s%s%s%s%s%s%s"
#define POLL_PRINTA(_revents_)	\
                (_revents_) & SSL_POLL_EVENT_F ? "SSL_POLL_EVENT_F " : "",	\
                (_revents_) & SSL_POLL_EVENT_EL ? "SSL_POLL_EVENT_EL" : "",	\
                (_revents_) & SSL_POLL_EVENT_EC ? "SSL_POLL_EVENT_EC " : "",	\
                (_revents_) & SSL_POLL_EVENT_ECD ? "SSL_POLL_EVENT_ECD " : "",	\
                (_revents_) & SSL_POLL_EVENT_ER? "SSL_POLL_EVENT_ER " : "",	\
                (_revents_) & SSL_POLL_EVENT_EW? "SSL_POLL_EVENT_EW " : "",	\
                (_revents_) & SSL_POLL_EVENT_R? "SSL_POLL_EVENT_R " : "",	\
                (_revents_) & SSL_POLL_EVENT_W? "SSL_POLL_EVENT_W " : "",	\
                (_revents_) & SSL_POLL_EVENT_IC? "SSL_POLL_EVENT_IC " : "",	\
                (_revents_) & SSL_POLL_EVENT_ISB? "SSL_POLL_EVENT_ISB " : "",	\
                (_revents_) & SSL_POLL_EVENT_ISU? "SSL_POLL_EVENT_ISU " : "",	\
                (_revents_) & SSL_POLL_EVENT_OSB? "SSL_POLL_EVENT_OSB " : "",	\
                (_revents_) & SSL_POLL_EVENT_OSU? "SSL_POLL_EVENT_OSU " : ""

#define poll_event_base	\
    SSL_POLL_ITEM				 pe_poll_item;   \
    OSSL_LIST_MEMBER(pe, struct poll_event);                     \
    uint64_t					 pe_want_events; \
    struct poll_manager				*pe_my_pm;       \
    unsigned char				 pe_type;        \
    struct poll_event				*pe_self;        \
    int(*pe_cb_in)(struct poll_event *);                         \
    int(*pe_cb_out)(struct poll_event *);                        \
    int(*pe_cb_error)(struct poll_event *)

struct poll_event {
    poll_event_base;
};

struct poll_event_listener {
    poll_event_base;
};

struct poll_event_connection {
    poll_event_base;
    uint64_t					 pec_want_stream;
    uint64_t					 pec_want_unistream;
};

DEFINE_LIST_OF(pe, struct poll_event);

#define POLL_GROW	20
#define	POLL_DOWNSIZ	20

struct poll_manager {
    OSSL_LIST(pe)	 pm_head;
    unsigned int	 pm_event_count;
    struct poll_event	*pm_poll_set;
    unsigned int	 pm_poll_set_sz;
    int			 pm_need_rebuild;
    int			 pm_continue;
    int(*pm_qconn_in)(struct poll_event *);
    int(*pm_qconn_out)(struct poll_event *);
    int(*pm_qstream_in)(struct poll_event *);
    int(*pm_qstream_out)(struct poll_event *);
    int(*pm_rready)(struct poll_event *);
    int(*pm_wready)(struct poll_event *);
};

#define POLL_ERROR	(SSL_POLL_EVENT_F | SSL_POLL_EVENT_EL | \
    SSL_POLL_EVENT_EC | SSL_POLL_EVENT_ECD | SSL_POLL_EVENT_ER | \
    SSL_POLL_EVENT_EW)

#define POLL_IN		(SSL_POLL_EVENT_R | SSL_POLL_EVENT_IC | \
    SSL_POLL_EVENT_ISB | SSL_POLL_EVENT_ISU)

#define POLL_OUT	(SSL_POLL_EVENT_W | SSL_POLL_EVENT_OSB | \
    SSL_POLL_EVENT_OSU)

static int pe_return_error(struct poll_event *);
static int pe_accept_qconn(struct poll_event *);
static int pe_accept_qstream(struct poll_event *);
static int pe_new_qstream(struct poll_event *);
static int pe_read_qstream(struct poll_event *);
static int pe_write_qstream(struct poll_event *);
static int pe_handle_listener_error(struct poll_event *);
static int pe_handle_qconn_error(struct poll_event *);
static int pe_handle_qstream_error(struct poll_event *);

#ifdef _WIN32
static const char *progname;

static void vwarnx(const char *fmt, va_list ap)
{
    if (progname != NULL)
        fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, fmt, ap);
    putc('\n', stderr);
}

static void errx(int status, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarnx(fmt, ap);
    va_end(ap);
    exit(status);
}

static void warnx(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarnx(fmt, ap);
    va_end(ap);
}
#endif

enum pe_types {
    PE_NONE,
    PE_LISTENER,
    PE_CONNECTION,
    PE_STREAM,
    PE_STREAM_UNI_IN,
    PE_STREAM_UNI_OUT,
    PE_INVALID
};

static const char *pe_type_to_name(const struct poll_event *pe)
{
    static const char *names[] = {
        "none",
        "listener",
        "connection",
        "stream (bidi)",
        "stream (in)",
        "stream (out)",
        "invalid"
    };

    if (pe->pe_type >= PE_INVALID)
        return (names[PE_INVALID]);

    return names[pe->pe_type];
}

static void init_pe(struct poll_event *pe, SSL *ssl)
{
    pe->pe_poll_item.desc = SSL_as_poll_descriptor(ssl);
    pe->pe_poll_item.events = 0;
    pe->pe_poll_item.revents = 0;
    pe->pe_my_pm = NULL;
    pe->pe_cb_in = pe_return_error;
    pe->pe_cb_out = pe_return_error;
    pe->pe_cb_error = pe_return_error;
    pe->pe_self = pe;
    pe->pe_type = PE_NONE;
}

static struct poll_event *new_pe(SSL *ssl)
{
    struct poll_event *pe;

    if (ssl == NULL)
        return NULL;

    pe = OPENSSL_zalloc(sizeof (struct poll_event));
    if (pe != NULL)
        init_pe(pe, ssl);

    return pe;
}

static struct poll_event *new_listener_pe(SSL *ssl_listener)
{
    struct poll_event *listener_pe = new_pe(ssl_listener);

    if (listener_pe != NULL) {
        listener_pe->pe_cb_in = pe_accept_qconn;
        listener_pe->pe_cb_out = pe_return_error;
        listener_pe->pe_cb_error = pe_handle_listener_error;
        listener_pe->pe_type = PE_LISTENER;
        listener_pe->pe_want_events = SSL_POLL_EVENT_IC;
    }

    return listener_pe;
}

static struct poll_event *new_qconn_pe(SSL *ssl_qconn)
{
    struct poll_event *qconn_pe;

    qconn_pe  = OPENSSL_zalloc(sizeof (struct poll_event_connection));

    if (qconn_pe != NULL) {
        init_pe(qconn_pe, ssl_qconn);
        qconn_pe->pe_cb_in = pe_accept_qstream;
        qconn_pe->pe_cb_out = pe_new_qstream;
        qconn_pe->pe_cb_error = pe_handle_qconn_error;
        qconn_pe->pe_type = PE_CONNECTION;
        qconn_pe->pe_want_events = SSL_POLL_EVENT_ISB | SSL_POLL_EVENT_ISU;
        /*
         * SSL_POLL_EVENT_OSB (or SSL_POLL_EVENT_OSU) must be monitored once
         * there is a request for outbound stream created by app.
         */
    }

    return qconn_pe;
}

static struct poll_event *new_qstream_pe(SSL *ssl_qconn, uint64_t qstream_f)
{
    struct poll_event *qstream_pe;
    SSL *qstream;

    qstream = SSL_new_stream(ssl_qconn, qstream_f);
    if (qstream == NULL)
        return NULL;

    qstream_pe = new_pe(qstream);
    if (qstream_pe == NULL) {
        SSL_free(qstream);
    } else {
        qstream_pe->pe_cb_in = pe_read_qstream;
        qstream_pe->pe_cb_out = pe_write_qstream;
        qstream_pe->pe_cb_error = pe_handle_qstream_error;
        qstream_pe->pe_type = PE_STREAM;
        qstream_pe->pe_want_events = SSL_POLL_EVENT_R | SSL_POLL_EVENT_W;
    }

    return qstream_pe;
}

static SSL *get_ssl_from_pe(struct poll_event *pe)
{
    SSL *ssl = NULL;

    if (pe != NULL)
        ssl = pe->pe_poll_item.desc.value.ssl;

    return ssl;
}

static void add_pe_to_pm(struct poll_manager *pm, struct poll_event *pe)
{
    if (pe->pe_my_pm == NULL) {
        ossl_list_pe_insert_head(&pm->pm_head, pe);
        pm->pm_need_rebuild = 1;
        pe->pe_my_pm = pm;
    }
}
 
static void remove_pe_from_pm(struct poll_manager *pm, struct poll_event *pe)
{
    if (pe->pe_my_pm == pm) {
        ossl_list_pe_remove(&pm->pm_head, pe);
        pm->pm_need_rebuild = 1;
        pe->pe_my_pm = NULL;
    }
}

static int pm_nop(struct poll_event *pe)
{
    return 0;
}

static struct poll_manager *create_poll_manager(void)
{
    struct poll_manager *pm = NULL;

    pm = OPENSSL_zalloc(sizeof (struct poll_manager));
    if (pm == NULL)
        return NULL;

    ossl_list_pe_init(&pm->pm_head);
    pm->pm_poll_set = OPENSSL_malloc(sizeof (struct poll_event) * POLL_GROW);
    if (pm->pm_poll_set != NULL) {
        pm->pm_poll_set_sz = POLL_GROW;
        pm->pm_event_count = 0;
        pm->pm_qconn_in = pm_nop;
        pm->pm_qconn_out = pm_nop;
        pm->pm_qstream_in = pm_nop;
        pm->pm_qstream_out = pm_nop;
        pm->pm_rready = pm_nop;
        pm->pm_wready = pm_nop;
    } else {
        OPENSSL_free(pm);
    }

    return pm;
}

static int add_listener_to_pm(struct poll_manager *pm, SSL *listener)
{
    struct poll_event *pe;

    if (pm == NULL || pm->pm_listner != NULL)
        return -1;

    pe = new_listener_pe(listener);
    if (pe == NULL)
        return -1;

    add_pe_to_pm(pm, pe);
    pm->pm_listner = listner;

    return 0;
}

static int rebuild_poll_set(struct poll_manager *pm)
{
    struct poll_event *new_poll_set;
    struct poll_event *pe;
    size_t new_sz;
    size_t pe_num;
    size_t i;

    if (pm->pm_need_rebuild == 0)
        return 0;

    pe_num = ossl_list_pe_num(&pm->pm_head);
    if (pe_num > pm->pm_poll_set_sz) {
        /*
         * grow poll set by POLL_GROW
         */
        new_sz = sizeof (struct poll_event) * (pm->pm_poll_set_sz + POLL_GROW);
        new_poll_set = (struct poll_event *)OPENSSL_realloc(pm->pm_poll_set,
                                                        new_sz);
        if (new_poll_set == NULL)
            return -1;
        pm->pm_poll_set = new_poll_set;
        pm->pm_poll_set_sz += POLL_GROW;

    } else if ((pe_num + POLL_DOWNSIZ) < pm->pm_poll_set_sz) {
        new_sz = sizeof (struct poll_event) * (pm->pm_poll_set_sz - POLL_DOWNSIZ);
        new_poll_set = (struct poll_event *)OPENSSL_realloc(pm->pm_poll_set,
                                                            new_sz);
        if (new_poll_set == NULL)
            return -1;
        pm->pm_poll_set = new_poll_set;
        pm->pm_poll_set_sz -= POLL_GROW;
    }

    i = 0;
    OSSL_LIST_FOREACH(pe, pe, &pm->pm_head) {
        pe->pe_poll_item.events = pe->pe_want_events;
        pm->pm_poll_set[i++] = *pe;
    }
    pm->pm_event_count = i;

    return 0;
}

static void destroy_poll_manager(struct poll_manager *pm)
{
    struct poll_event *pe, *pe_safe;
    if (pm == NULL)
        return;

    OSSL_LIST_FOREACH_DELSAFE(pe, pe_safe, pe, &pm->pm_head) {
        SSL_free(get_ssl_from_pe(pe));
	/* ?todo? custom destroy callback on pe */
        OPENSSL_free(pe);
    }

    OPENSSL_free(pm->pm_poll_set);
    OPENSSL_free(pm);
}

static int pe_accept_qconn(struct poll_event *listener_pe)
{
    SSL *listener;
    SSL *qconn;
    struct poll_event *qc_pe;

    listener = get_ssl_from_pe(listener_pe);
    qconn = SSL_accept_connection(listener, 0);
    if (qconn == NULL)
        return -1;

    qc_pe = new_qconn_pe(qconn);
    if (qc_pe != NULL) {
        if (pm->pm_qconn_in(qc_pe) == -1)
            destroy_pe(qc_pe);
        else
            add_pe_to_pm(listener_pe->pe_my_pm, qc_pe);

    } else {
        SSL_free(qconn);
        return -1;
    }

    return 0;
}

/*
 * accept stream from remote peer
 */
static int pe_accept_qstream(struct poll_event *qconn_pe)
{
    SSL *qconn;
    SSL *qs;
    struct poll_event *qs_pe;

    assert(qconn_pe->pe_poll_item.revents & SSL_POLL_EVENT_IS);

    qconn = get_ssl_from_pe(qconn_pe);
    qs = SSL_accept_stream(qconn, 0);
    if (qs == NULL)
        return -1;

    qs_pe = new_pe(qconn);
    if (qs_pe != NULL) {
        qs_pe->pe_my_pm = qconn_pe->pe_my_pm;
        qs_pe->pe_cb_error = pe_handle_qstream_error;
        qs_pe->pe_cb_in = pe_read_qstream;
        qs_pe->pe_want_events = SSL_POLL_EVENT_R;

        if (qconn_pe->pe_poll_item.revents & SSL_POLL_EVENT_ISU) {
            qs_pe->pe_cb_out = pe_return_error;
            qs_pe->pe_type = PE_STREAM_UNI_IN;
        } else if (qconn_pe->pe_poll_item.revents * SSL_POLL_EVENT_ISB) {
            qs_pe->pe_cb_out = pe_write_qstream;
            qs_pe->pe_cb_error = pe_handle_qstream_error;
            qs_pe->pe_type = PE_STREAM;
            qs_pe->pe_want_events |= SSL_POLL_EVENT_W;
        }

        add_pe_to_pm(qconn_pe->pe_my_pm, qs_pe);
    } else {
        SSL_free(qs);
        return -1;
    }

    return 0;
}

/*
 * Event fires when outbound stream can be created.  The number of outbound
 * streams connection can open is determined by flow-control. Application
 * asks for outbound stream by calling new_stream(). The new_stream() adds
 * SSL_POLL_EVENT_OS to event wantset poll descriptor of associated connection.
 * As soon as connection is able create stream the pe_new_qstream() callback
 * here fires.
 */
static int pe_new_qstream(struct poll_event *qconn_pe)
{
    SSL *qconn;
    SSL *qs;
    struct poll_event_connection *pec;
    struct poll_event *qs_pe;

    assert(qconn_pe->pe_poll_item.revents & SSL_POLL_EVENT_OS);
    assert(qconn_pe->pe_type == PE_CONNECTION);

    qconn = get_ssl_from_pe(qconn_pe);
    qs = SSL_accept_stream(qconn, 0);
    if (qs == NULL)
        return -1;

    pec = (struct poll_event_connection *)qconn_pe;

    qs_pe = new_pe(qconn);
    if (qs_pe != NULL) {
        qs_pe->pe_my_pm = qconn_pe->pe_my_pm;
        qs_pe->pe_cb_error = pe_handle_qstream_error;
        qs_pe->pe_cb_in = pe_read_qstream;
        qs_pe->pe_want_events = SSL_POLL_EVENT_R;
        if (qconn_pe->pe_poll_item.revents & SSL_POLL_EVENT_OSU) {
            pec->pec_want_unistream--;
            assert(pec->pec_want_unistream >= 0);
            qs_pe->pe_cb_out = pe_return_error;
            qs_pe->pe_type = PE_STREAM_UNI_IN;
        } else {
            pec->pec_want_stream--;
            qs_pe->pe_cb_out = pe_write_qstream;
            qs_pe->pe_cb_error = pe_handle_qstream_error;
            qs_pe->pe_type = PE_STREAM;
            qs_pe->pe_want_events |= SSL_POLL_EVENT_W;
        }

        add_pe_to_pm(qconn_pe->pe_my_pm, qs_pe);
    } else {
        SSL_free(qs);
        return -1;
    }

    /*
     * stop polling for outbound stream events if desired
     * streams got created.
     */
    if (pec->pec_want_stream == 0)
        qconn_pe->pe_want_events &= ~SSL_POLL_EVENT_OSB;
    if (pec->pec_want_unistream == 0)
        qconn_pe->pe_want_events &= ~SSL_POLL_EVENT_OSU;

    return 0;
}

static void destroy_pe(struct poll_event *pe)
{
    SSL *ssl;

    if (pe == NULL)
        return;

    ssl = get_ssl_from_pe(pe);
    if (pe->pe_my_pm) {
        remove_pe_from_pm(pe->pe_my_pm, pe);
    }
    OPENSSL_free(pe);

    (void) SSL_shutdown(ssl);
    SSL_free(ssl);
}


static int pe_return_error(struct poll_event *pe)
{
    return -1;
}

static int pe_handle_listener_error(struct poll_event *pe)
{
    /*
     * todo: determine the nature of error return 0 when recovery
     * is possible, -1 otherwise
     * see handle_io_failure() in non-blocking server for possible
     * error codes.
     */
    pe->pe_my_pm->pm_continue = 0;
    return -1;
}

static int pe_handle_qconn_error(struct poll_event *pe)
{
    /*
     * todo: determine the nature of error return 0 when recovery
     * is possible, -1 otherwise
     * see handle_io_failure() in non-blocking server for possible
     * error codes.
     */
    return -1;
}

static int pe_handle_qstream_error(struct poll_event *pe)
{
    /*
     * todo: determine the nature of error return 0 when recovery
     * is possible, -1 otherwise
     * see handle_io_failure() in non-blocking server for possible
     * error codes.
     */
    return -1;
}

static int pe_read_qstream(struct poll_event *pe)
{
    /*
     * todo there should be an application callback which
     * we will receive data from qstream.
     * see handle_io_failure() in non-blocking server for possible
     * error codes.
     */
    return -1;
}

static int pe_write_qstream(struct poll_event *pe)
{
    /*
     * todo there should be an application callback which
     * we will write data to qstream.
     * see handle_io_failure() in non-blocking server for possible
     * error codes.
     */
    return -1;
}

/*
 * non-blocking variant for new_stream(). Creating outbound stream
 * is two step process when using non-blocking I/O.
 *    application starts polling for SSL_POLL_EVENT_OS* to check
 *    if outbound streams are available.
 *
 *    as soon as SSL_POLL_EVENT_OS comes back from SSL_poll() application
 *    should call SSL-new_stream() to create a stream object and
 *    add its poll descriptor to SSL_poll() events. The stream object
 *    should be monitored for SSL_POLL_EVENT_{W,R}
 *
 * new_stream() function below is supposed to be called by application
 * which uses SSL_poll()  to manage I/O. We expect there might be more
 * than 1 stream request.
 */
void new_stream(struct poll_event *qconn_pe, uint64_t qsflag)
{
    struct poll_event_connection *pec;

    if (qconn_pe->pe_type != PE_CONNECTION)
        return;

    pec = (struct poll_event_connection *)qconn_pe;
    if (qsflag & SSL_STREAM_FLAG_UNI) {
        pec->pec_want_unistream++;
        qconn_pe->pe_want_events |= SSL_POLL_EVENT_OSU;
    } else {
        pec->pec_want_stream++;
        qconn_pe->pe_want_events |= SSL_POLL_EVENT_OSB;
    }

    /*
     * We are changing poll events so SSL_poll() array needs be rebuilt.
     */
    qconn_pe->pe_my_pm->pm_need_rebuild = 1;
}

/*
 * ALPN strings for TLS handshake. Only 'http/1.0' and 'hq-interop'
 * are accepted.
 */
static const unsigned char alpn_ossltest[] = {
    8,  'h', 't', 't', 'p', '/', '1', '.', '0',
    10, 'h', 'q', '-', 'i', 'n', 't', 'e', 'r', 'o', 'p',
};

/*
 * This callback validates and negotiates the desired ALPN on the server side.
 */
static int select_alpn(SSL *ssl, const unsigned char **out,
                       unsigned char *out_len, const unsigned char *in,
                       unsigned int in_len, void *arg)
{
    if (SSL_select_next_proto((unsigned char **)out, out_len, alpn_ossltest,
                              sizeof(alpn_ossltest), in,
                              in_len) == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/* Create SSL_CTX. */
static SSL_CTX *create_ctx(const char *cert_path, const char *key_path)
{
    SSL_CTX *ctx;

    /*
     * An SSL_CTX holds shared configuration information for multiple
     * subsequent per-client connections. We specifically load a QUIC
     * server method here.
     */
    ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (ctx == NULL)
        goto err;

    /*
     * Load the server's certificate *chain* file (PEM format), which includes
     * not only the leaf (end-entity) server certificate, but also any
     * intermediate issuer-CA certificates.  The leaf certificate must be the
     * first certificate in the file.
     *
     * In advanced use-cases this can be called multiple times, once per public
     * key algorithm for which the server has a corresponding certificate.
     * However, the corresponding private key (see below) must be loaded first,
     * *before* moving on to the next chain file.
     *
     * The requisite files "chain.pem" and "pkey.pem" can be generated by running
     * "make chain" in this directory.  If the server will be executed from some
     * other directory, move or copy the files there.
     */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0) {
        fprintf(stderr, "couldn't load certificate file: %s\n", cert_path);
        goto err;
    }

    /*
     * Load the corresponding private key, this also checks that the private
     * key matches the just loaded end-entity certificate.  It does not check
     * whether the certificate chain is valid, the certificates could be
     * expired, or may otherwise fail to form a chain that a client can validate.
     */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "couldn't load key file: %s\n", key_path);
        goto err;
    }

    /*
     * Clients rarely employ certificate-based authentication, and so we don't
     * require "mutual" TLS authentication (indeed there's no way to know
     * whether or how the client authenticated the server, so the term "mutual"
     * is potentially misleading).
     *
     * Since we're not soliciting or processing client certificates, we don't
     * need to configure a trusted-certificate store, so no call to
     * SSL_CTX_set_default_verify_paths() is needed.  The server's own
     * certificate chain is assumed valid.
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /* Setup ALPN negotiation callback to decide which ALPN is accepted. */
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);

    return ctx;

err:
    SSL_CTX_free(ctx);
    return NULL;
}

/* Create UDP socket on the given port. */
static int create_socket(uint16_t port)
{
    int fd;
    struct sockaddr_in sa = {0};

    /* Retrieve the file descriptor for a new UDP socket */
    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        fprintf(stderr, "cannot create socket");
        return -1;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    /* Bind to the new UDP socket on localhost */
    if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "cannot bind to %u\n", port);
        BIO_closesocket(fd);
        return -1;
    }

    /* Set port to nonblocking mode */
    if (BIO_socket_nbio(fd, 1) <= 0) {
        fprintf(stderr, "Unable to set port to nonblocking mode");
        BIO_closesocket(fd);
        return -1;
    }

    return fd;
}

/*
 * Main loop for server to accept QUIC connections.
 * Echo every request back to the client.
 */
static int run_quic_server(SSL_CTX *ctx, struct poll_manager *pm, int fd)
{
    int ok = -1;
    int e;
    unsigned int i;
    SSL *listener;
    struct poll_event *listener_pe;
    struct poll_event *pe;
    size_t poll_items;

    /* Create a new QUIC listener */
    if ((listener = SSL_new_listener(ctx, 0)) == NULL)
        goto err;

    if (!SSL_set_fd(listener, fd))
        goto err;

    /*
     * Set the listener mode to non-blocking, which is inherited by
     * child objects.
     */
    if (!SSL_set_blocking_mode(listener, 0))
        goto err;

    /*
     * Begin listening. Note that is not usually needed as SSL_accept_connection
     * will implicitly start listening. It is only needed if a server wishes to
     * ensure it has started to accept incoming connections but does not wish to
     * actually call SSL_accept_connection yet.
     */
    if (!SSL_listen(listener))
        goto err;

    if (add_listener_to_pm(pm, listener) == -1)
        goto err;
    listener = NULL; /* listener is owned by pm now */

    /*
     * Begin an infinite loop of listening for connections. We will only
     * exit this loop if we encounter an error.
     */
    pm->pm_continue = 1;
    while (pm->pm_continue) {
        rebuild_poll_set(pm);
        ok = SSL_poll((SSL_POLL_ITEM *)pm->pm_poll_set, pm->pm_event_count,
                      sizeof (struct poll_event), NULL, 0, &poll_items);

        if (ok == 0 && poll_items == 0)
            break;

        for (i = 0; i < pm->pm_event_count; i++) {
            pe = &pm->pm_poll_set[i];
            if (pe->pe_poll_item.revents == 0)
                continue;
            fprintf(stderr, "%s %s (%p) " POLL_FMT "\n", __func__,
                   pe_type_to_name(pe), pe,
                   POLL_PRINTA(pe->pe_poll_item.revents));
            if (pe->pe_poll_item.revents & POLL_ERROR)
                e = pe->pe_cb_error(pe);
            else if (pe->pe_poll_item.revents & POLL_IN)
                e = pe->pe_cb_in(pe);
            else if (pe->pe_poll_item.revents & POLL_OUT)
                e = pe->pe_cb_out(pe);

            if (e == -1) {
                pe = pm->pm_poll_set[i].pe_self;
                destroy_pe(pe);
            }
        }
    }

    ok = EXIT_SUCCESS;
err:
    SSL_free(listener);
    destroy_poll_manager(pm);
    return ok;
}

/* Minimal QUIC HTTP/1.0 server. */
int main(int argc, char *argv[])
{
    int res = EXIT_FAILURE;
    SSL_CTX *ctx = NULL;
    int fd;
    unsigned long port;
    struct poll_manager *pm;

#ifdef _WIN32
    progname = argv[0];
#endif

    if (argc != 4)
        errx(res, "usage: %s <port> <server.crt> <server.key>", argv[0]);

    /* Create SSL_CTX that supports QUIC. */
    if ((ctx = create_ctx(argv[2], argv[3])) == NULL) {
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to create context");
    }

    /* Parse port number from command line arguments. */
    port = strtoul(argv[1], NULL, 0);
    if (port == 0 || port > UINT16_MAX) {
        SSL_CTX_free(ctx);
        errx(res, "Failed to parse port number");
    }

    /* Create and bind a UDP socket. */
    if ((fd = create_socket((uint16_t)port)) < 0) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to create socket");
    }

    pm = create_poll_manager();
    if (pm == NULL) {
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to create socket");
    }

    /* QUIC server connection acceptance loop. */
    if (run_quic_server(ctx, pm, fd) < 0) {
        SSL_CTX_free(ctx);
        BIO_closesocket(fd);
        ERR_print_errors_fp(stderr);
        errx(res, "Error in QUIC server loop");
    }

    /* Free resources. */
    SSL_CTX_free(ctx);
    destroy_poll_manager(pm);
    BIO_closesocket(fd);
    res = EXIT_SUCCESS;
    return res;
}
