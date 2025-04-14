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

/*
 * This is a simple non-blocking QUIC echo server application.
 * Server accepts QUIC connections. It then accepts bi-directional
 * stream from client and reads data. It then echoes data back
 * to client using the same stream.
 */

#ifdef DEBUG
#define DPRINTF		fprintf
#else
#define DPRINTF(...)	(void)(0)
#endif


/*
 * format string so we can print SSL_poll() events in more informative
 * way. To print events one does this:
 *   int events = SSL_POLL_EVENT_F | SSL_POLL_EVENT_R;
 *   printf("%s We got events: " POLL_FMT "\n", __func__, POLL_PRINTA(events));
 */
#define POLL_FMT	"%s%s%s%s%s%s%s%s%s%s%s%s%s"
#define POLL_PRINTA(_revents_)	\
                (_revents_) & SSL_POLL_EVENT_F ? "SSL_POLL_EVENT_F " : "",	\
                (_revents_) & SSL_POLL_EVENT_EL ? "SSL_POLL_EVENT_EL" : "",	\
                (_revents_) & SSL_POLL_EVENT_EC ? "SSL_POLL_EVENT_EC " : "",	\
                (_revents_) & SSL_POLL_EVENT_ECD ? "SSL_POLL_EVENT_ECD " : "",	\
                (_revents_) & SSL_POLL_EVENT_ER ? "SSL_POLL_EVENT_ER " : "",	\
                (_revents_) & SSL_POLL_EVENT_EW ? "SSL_POLL_EVENT_EW " : "",	\
                (_revents_) & SSL_POLL_EVENT_R ? "SSL_POLL_EVENT_R " : "",	\
                (_revents_) & SSL_POLL_EVENT_W ? "SSL_POLL_EVENT_W " : "",	\
                (_revents_) & SSL_POLL_EVENT_IC ? "SSL_POLL_EVENT_IC " : "",	\
                (_revents_) & SSL_POLL_EVENT_ISB ? "SSL_POLL_EVENT_ISB " : "",	\
                (_revents_) & SSL_POLL_EVENT_ISU ? "SSL_POLL_EVENT_ISU " : "",	\
                (_revents_) & SSL_POLL_EVENT_OSB ? "SSL_POLL_EVENT_OSB " : "",	\
                (_revents_) & SSL_POLL_EVENT_OSU ? "SSL_POLL_EVENT_OSU " : ""

#define poll_event_base	\
    SSL_POLL_ITEM				 pe_poll_item;		\
    OSSL_LIST_MEMBER(pe, struct poll_event);				\
    uint64_t					 pe_want_events;	\
    uint64_t                                     pe_want_mask;          \
    struct poll_manager				*pe_my_pm;		\
    unsigned char				 pe_type;		\
    struct poll_event				*pe_self;		\
    void					*pe_appdata;		\
    int(*pe_cb_in)(struct poll_event *);				\
    int(*pe_cb_out)(struct poll_event *);				\
    int(*pe_cb_error)(struct poll_event *);				\
    void(*pe_cb_ondestroy)(void *)

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
    SSL			*pm_listner;
    unsigned int	 pm_event_count;
    struct poll_event	*pm_poll_set;
    unsigned int	 pm_poll_set_sz;
    int			 pm_need_rebuild;
    int			 pm_continue;
    int(*pm_qconn_in)(struct poll_event *);
    int(*pm_qconn_out)(struct poll_event *);
    int(*pm_qstream_in)(struct poll_event *);
    int(*pm_qstream_out)(struct poll_event *);
    int(*pm_do_read)(struct poll_event *);
    int(*pm_do_write)(struct poll_event *);
    int(*pm_qconn_done)(struct poll_event *);
    int(*pm_qstream_done)(struct poll_event *);
};

#define POLL_ERROR	(SSL_POLL_EVENT_F | SSL_POLL_EVENT_EL | \
    SSL_POLL_EVENT_EC | SSL_POLL_EVENT_ECD | SSL_POLL_EVENT_ER | \
    SSL_POLL_EVENT_EW)

#define POLL_IN		(SSL_POLL_EVENT_R | SSL_POLL_EVENT_IC | \
    SSL_POLL_EVENT_ISB | SSL_POLL_EVENT_ISU)

#define POLL_OUT	(SSL_POLL_EVENT_W | SSL_POLL_EVENT_OSB | \
    SSL_POLL_EVENT_OSU)

static void destroy_pe(struct poll_event *);
static int pe_return_error(struct poll_event *);
static void pe_return_void(void *);
static int pe_accept_qconn(struct poll_event *);
static int pe_accept_qstream(struct poll_event *);
static int pe_new_qstream(struct poll_event *);
static int pe_read_qstream(struct poll_event *);
static int pe_write_qstream(struct poll_event *);
static int pe_handle_listener_error(struct poll_event *);
static int pe_handle_qconn_error(struct poll_event *);
static int pe_handle_qstream_error(struct poll_event *);

static void pe_disable_read(struct poll_event *);
static void pe_disable_write(struct poll_event *);

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
    pe->pe_cb_in = pe_return_error;
    pe->pe_cb_out = pe_return_error;
    pe->pe_cb_error = pe_return_error;
    pe->pe_cb_ondestroy = pe_return_void;
    pe->pe_self = pe;
    pe->pe_type = PE_NONE;
    pe->pe_want_mask = ~0;
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
        listener_pe->pe_want_events = SSL_POLL_EVENT_IC | SSL_POLL_EVENT_EL;
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
        qconn_pe->pe_want_events |= SSL_POLL_EVENT_EC | SSL_POLL_EVENT_ECD;
        /*
         * SSL_POLL_EVENT_OSB (or SSL_POLL_EVENT_OSU) must be monitored once
         * there is a request for outbound stream created by app.
         */
    }

    return qconn_pe;
}

static SSL *get_ssl_from_pe(struct poll_event *pe)
{
    SSL *ssl = NULL;

    if (pe != NULL)
        ssl = pe->pe_poll_item.desc.value.ssl;

    return ssl;
}

/*
 * handle_ssl_error() diagnoses error from SSL/QUIC stack and
 * decides if it is temporal error (in that case it returns zero)
 * or error is permanent. In case of permanent error the
 * poll event pe should be removed from poll manager and destroyed.
 */
static const char *err_str_n(unsigned long e, char *buf, size_t buf_sz)
{
    ERR_error_string_n(e, buf, buf_sz);
    return buf;
}

static int handle_ssl_error(struct poll_event *pe, int rc, const char *caller)
{

    SSL *ssl = get_ssl_from_pe(pe);
    int ssl_error, rv;
    char err_str[120];

    /* may be we should use SSL_shutdown_ex() to signal peer what's going on */
    ssl_error = SSL_get_error(ssl, rc);
    if (rc < 0) {
        switch (ssl_error) {
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        case SSL_ERROR_ZERO_RETURN:
            DPRINTF(stderr, "%s permanent error on %p (%s) [ %s ]\n",
                    caller, pe, pe_type_to_name(pe),
                    err_str_n(ssl_error, err_str, sizeof (err_str)));
            rv = -1;
            break;
        default:
            DPRINTF(stderr, "%s temporal error on %p (%s) [ %s ]\n",
                    caller, pe, pe_type_to_name(pe),
                    err_str_n(ssl_error, err_str, sizeof (err_str)));
            rv = 0; /* may be return -1 here too */
        }
    } else if (rc == 0) {
        DPRINTF(stderr, "%s temporal error on  %p (%s) [ %s ]\n",
                caller, pe, pe_type_to_name(pe),
                err_str_n(ssl_error, err_str, sizeof (err_str)));
        rv = 0;
    } else if (rc == 1) {
        DPRINTF(stderr, "%s no error on %p (%s) [ ??? ]\n", caller, pe,
                pe_type_to_name(pe));
        rv = -1; /* complete, stop polling for event */
    } else {
        DPRINTF(stderr, "%s ?unexpected? error on %p (%s) [ %s ]\n",
                caller, pe, pe_type_to_name(pe),
                err_str_n(ssl_error, err_str, sizeof (err_str)));
        rv = -1; /* stop polling 8 */
    }

    return rv;
}

static const char *stream_state_str(int stream_state)
{
    const char *rv;

    switch (stream_state) {
    case SSL_STREAM_STATE_NONE:
        rv = "SSL_STREAM_STATE_NONE";
        break;
    case SSL_STREAM_STATE_OK:
        rv = "SSL_STREAM_STATE_OK";
        break;
    case SSL_STREAM_STATE_WRONG_DIR:
        rv = "SSL_STREAM_STATE_WRONG_DIR";
        break;
    case SSL_STREAM_STATE_FINISHED:
        rv = "SSL_STREAM_STATE_FINISHED";
        break;
    case SSL_STREAM_STATE_RESET_LOCAL:
        rv = "SSL_STREAM_STATE_RESET_LOCAL";
        break;
    case SSL_STREAM_STATE_RESET_REMOTE:
        rv = "SSL_STREAM_STATE_RESET_REMOTE";
        break;
    case SSL_STREAM_STATE_CONN_CLOSED:
        rv = "SSL_STREAM_STATE_CONN_CLOSED";
        break;
    default:
        rv = "???";
    }

    return rv;
}

static int handle_read_stream_state(struct poll_event *pe)
{
    int stream_state = SSL_get_stream_read_state(get_ssl_from_pe(pe));
    int rv;

    switch (stream_state) {
    case SSL_STREAM_STATE_FINISHED:
        DPRINTF(stderr, "%s remote peer concluded the stream\n", __func__);
        pe_disable_read(pe);
        /* FALLTHRU */
    case SSL_STREAM_STATE_OK:
        rv = 0;
        break;
    default:
        DPRINTF(stderr,
                "%s error %s on stream, the %p (%s) should be destroyed\n",
                __func__, stream_state_str(stream_state), pe,
                pe_type_to_name(pe));
        rv = -1;
    }

    return rv;
}

static int handle_write_stream_state(struct poll_event *pe)
{
    int state = SSL_get_stream_write_state(get_ssl_from_pe(pe));
    int rv;

    switch (state) {
    case SSL_STREAM_STATE_FINISHED:
        DPRINTF(stderr, "%s remote peer concluded the stream\n", __func__);
        /* FALLTHRU */
    case SSL_STREAM_STATE_OK:
        rv = 0;
        break;
    default:
        DPRINTF(stderr,
                "%s error %s on stream, the %p (%s) should be destroyed\n",
                __func__, stream_state_str(state), pe, pe_type_to_name(pe));
        rv = -1;
    }

    return rv;
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
        pm->pm_qconn_done = pm_nop;
        pm->pm_qstream_in = pm_nop;
        pm->pm_qstream_out = pm_nop;
        pm->pm_do_read = pe_return_error;
        pm->pm_do_write = pe_return_error;
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
    pm->pm_listner = listener;

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
        /*
         * shrink poll set by POLL_DOWNSIZ
         */
        new_sz = sizeof (struct poll_event) *
                 (pm->pm_poll_set_sz - POLL_DOWNSIZ);
        new_poll_set = (struct poll_event *)OPENSSL_realloc(pm->pm_poll_set,
                                                            new_sz);
        if (new_poll_set == NULL)
            return -1;
        pm->pm_poll_set = new_poll_set;
        pm->pm_poll_set_sz -= POLL_GROW;
    }

    i = 0;
    DPRINTF(stderr, "%s there %zu events to poll\n", __func__,
            ossl_list_pe_num(&pm->pm_head));
    OSSL_LIST_FOREACH(pe, pe, &pm->pm_head) {
        pe->pe_poll_item.events = pe->pe_want_events;
        pm->pm_poll_set[i++] = *pe;
        DPRINTF(stderr, "\t%p (%s) " POLL_FMT " (disabled: " POLL_FMT ")\n",
                pe, pe_type_to_name(pe),
                POLL_PRINTA(pe->pe_poll_item.events),
                POLL_PRINTA(~pe->pe_want_mask));
    }
    pm->pm_event_count = i;
    pm->pm_need_rebuild = 0;

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
        if (listener_pe->pe_my_pm->pm_qconn_in(qc_pe) == -1)
            destroy_pe(qc_pe); /* qc_pe owns qconn */
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

    qs_pe = new_pe(qs);
    if (qs_pe != NULL) {
        qs_pe->pe_cb_error = pe_handle_qstream_error;
        qs_pe->pe_cb_in = pe_read_qstream;
        qs_pe->pe_want_events = SSL_POLL_EVENT_ER;

        if (qconn_pe->pe_poll_item.revents & SSL_POLL_EVENT_ISU) {
            qs_pe->pe_cb_out = pe_return_error;
            qs_pe->pe_type = PE_STREAM_UNI_IN;
        } else if (qconn_pe->pe_poll_item.revents * SSL_POLL_EVENT_ISB) {
            qs_pe->pe_want_events |= SSL_POLL_EVENT_EW;
            qs_pe->pe_cb_out = pe_write_qstream;
            qs_pe->pe_type = PE_STREAM;
        }

        add_pe_to_pm(qconn_pe->pe_my_pm, qs_pe);
        if (qconn_pe->pe_my_pm->pm_qstream_in(qs_pe) == -1) {
            /* application hangs up. signal stream conclude to peer */
            SSL_stream_conclude(qs, 0);
        }
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
    if (qconn_pe->pe_poll_item.revents & SSL_POLL_EVENT_OSU)
        qs = SSL_new_stream(qconn, SSL_STREAM_FLAG_UNI);
    else
        qs = SSL_new_stream(qconn, 0);

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

    DPRINTF(stderr, "%s %p (%s)\n", __func__, pe, pe_type_to_name(pe));
    ssl = get_ssl_from_pe(pe);
    if (pe->pe_my_pm) {
        remove_pe_from_pm(pe->pe_my_pm, pe);
    }

    pe->pe_cb_ondestroy(pe->pe_appdata);

    OPENSSL_free(pe);

    SSL_free(ssl);
}

static int pe_return_error(struct poll_event *pe)
{
    return -1;
}

static void pe_return_void(void *ctx)
{
    return;
}

static int pe_handle_listener_error(struct poll_event *pe)
{
    pe->pe_my_pm->pm_continue = 0;
    if (pe->pe_poll_item.revents & SSL_POLL_EVENT_EL)
        return -1;

    DPRINTF(stderr, "%s unexpected error on %p (%s) " POLL_FMT "\n", __func__,
            pe, pe_type_to_name(pe), POLL_PRINTA(pe->pe_poll_item.revents));

    return -1;
}

static int pe_handle_qconn_error(struct poll_event *pe)
{
    int rv = -2;

    if (pe->pe_poll_item.revents & SSL_POLL_EVENT_EC) {
        DPRINTF(stderr,
                "%s connection shutdown started on %p (%s), keep polling\n",
                __func__, pe, pe_type_to_name(pe));
        /*
         * shutdown has started, Not sure what we should be doing here.
         * So the plan is to call SSL_shutdown() here and stop monitoring
         * _EVENT_EC here. We will keep _EVENT_ECD monitored.
         * Shall we call shutdown too?
         */
        SSL_shutdown(get_ssl_from_pe(pe));
        /*
         * adjust _want_events, don't forget to ask poll manager to rebuild
         * poll set so _want_events can take effect in next loop iteration
         */
        pe->pe_want_events &= ~SSL_POLL_EVENT_EC;
        pe->pe_my_pm->pm_need_rebuild = 1;
        rv = 0;
    }

    if (pe->pe_poll_item.revents & SSL_POLL_EVENT_ECD) {
        DPRINTF(stderr,
                "%s connection shutdown done on %p (%s), stop polling\n",
                __func__, pe, pe_type_to_name(pe));
        rv = -1; /* shutdown is complete stop polling let pe to be destroyed */
    }

    if (rv == -2) {
        DPRINTF(stderr, "%s unexpected event on %p (%s)" POLL_FMT "\n",
                __func__, pe, pe_type_to_name(pe),
                POLL_PRINTA(pe->pe_poll_item.revents));
        rv = -1;
    }

    if (rv == -1) {
        /* tell application connection is done */
        (void) pe->pe_my_pm->pm_qconn_done(pe);
    }

    return rv;
}

static int pe_handle_qstream_error(struct poll_event *pe)
{
    int rv;

    if (pe->pe_poll_item.revents & SSL_POLL_EVENT_ER) {

        if ((pe->pe_poll_item.events & SSL_POLL_EVENT_R) == 0) {
            DPRINTF(stderr, "%s unexpected failure on reader %p (%s) "
                    POLL_FMT "\n", __func__, pe, pe_type_to_name(pe),
                    POLL_PRINTA(pe->pe_poll_item.revents));
        }

        if (pe->pe_type == PE_STREAM) {
            SSL_shutdown(get_ssl_from_pe(pe));
            rv = 0; /* attempt to shutdown the stream */
        } else {
            rv = -1; /* stop polling immediately */
        }
    } else if (pe->pe_poll_item.revents & SSL_POLL_EVENT_EW) {

        if ((pe->pe_poll_item.events & SSL_POLL_EVENT_W) == 0) {
            DPRINTF(stderr, "%s unexpected failure on writer %p (%s) "
                    POLL_FMT "\n", __func__, pe, pe_type_to_name(pe),
                    POLL_PRINTA(pe->pe_poll_item.revents));
        }

        rv = -1; /* stop polling immediately */
    } else {
        DPRINTF(stderr, "%s unexpected failure on writer/reader %p (%s) "
                POLL_FMT "\n", __func__, pe, pe_type_to_name(pe),
                POLL_PRINTA(pe->pe_poll_item.revents));
        rv = -1;
    }

    if (rv == -1) {
        /* tell application stream is done */
        (void) pe->pe_my_pm->pm_qstream_done(pe);
    }

    return -1;
}

static int pe_read_qstream(struct poll_event *pe)
{
    return pe->pe_my_pm->pm_do_read(pe);
}

static int pe_write_qstream(struct poll_event *pe)
{
    return pe->pe_my_pm->pm_do_write(pe);
}

static void pe_pause_read(struct poll_event *pe)
{
    pe->pe_want_events &= ~SSL_POLL_EVENT_R;
    pe->pe_my_pm->pm_need_rebuild = 1;
}

static void pe_resume_read(struct poll_event *pe)
{
    pe->pe_want_events |= (SSL_POLL_EVENT_R & pe->pe_want_mask);
    pe->pe_my_pm->pm_need_rebuild = 1;
}

static void pe_pause_write(struct poll_event *pe)
{
    pe->pe_want_events &= ~SSL_POLL_EVENT_W;
    pe->pe_my_pm->pm_need_rebuild = 1;
}

static void pe_resume_write(struct poll_event *pe)
{
    pe->pe_want_events |= (SSL_POLL_EVENT_W & pe->pe_want_mask);
    pe->pe_my_pm->pm_need_rebuild = 1;
}

/*
 * like pause, but is permanent,
 */
static void pe_disable_read(struct poll_event *pe)
{
    pe_pause_read(pe);
    pe->pe_want_mask &= ~SSL_POLL_EVENT_R;
}

static void pe_disable_write(struct poll_event *pe)
{
    pe_pause_write(pe);
    pe->pe_want_mask &= ~SSL_POLL_EVENT_W;
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
        DPRINTF(stderr, "couldn't load certificate file: %s\n", cert_path);
        goto err;
    }

    /*
     * Load the corresponding private key, this also checks that the private
     * key matches the just loaded end-entity certificate.  It does not check
     * whether the certificate chain is valid, the certificates could be
     * expired, or may otherwise fail to form a chain that a client can validate.
     */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        DPRINTF(stderr, "couldn't load key file: %s\n", key_path);
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
        DPRINTF(stderr, "cannot create socket");
        return -1;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    /* Bind to the new UDP socket on localhost */
    if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) < 0) {
        DPRINTF(stderr, "cannot bind to %u\n", port);
        BIO_closesocket(fd);
        return -1;
    }

    /* Set port to nonblocking mode */
    if (BIO_socket_nbio(fd, 1) <= 0) {
        DPRINTF(stderr, "Unable to set port to nonblocking mode");
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
            DPRINTF(stderr, "%s %s (%p) " POLL_FMT "\n", __func__,
                   pe_type_to_name(pe), pe,
                   POLL_PRINTA(pe->pe_poll_item.revents));
            pe->pe_self->pe_poll_item.revents = pe->pe_poll_item.revents;
            if (pe->pe_poll_item.revents & POLL_ERROR)
                e = pe->pe_cb_error(pe->pe_self);
            else if (pe->pe_poll_item.revents & POLL_IN)
                e = pe->pe_cb_in(pe->pe_self);
            else if (pe->pe_poll_item.revents & POLL_OUT)
                e = pe->pe_cb_out(pe->pe_self);

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

/*
 * The application read handler allocates linked_buf, reads data
 * from SSL object and puts buffer to list of write buffers.
 */
struct linked_buf {
    OSSL_LIST_MEMBER(lb, struct linked_buf);
    char		 lb_data[1024];
    size_t		 lb_len;
    char		*lb_wpos;
};

DEFINE_LIST_OF(lb, struct linked_buf);

/*
 * app_ctx is our QUIC echo application context it holds list
 * of buffers to write. This is a per-stream context.
 */
struct app_ctx {
    OSSL_LIST(lb)	 ac_head;
};

/*
 * get_write_len() returns the amount of bytes we can write
 * from particular linked buffer instance. 
 */
static size_t get_write_len(struct linked_buf *lb)
{
    char *buf_end;
    size_t rv;

    if (lb->lb_len == 0)
        return 0;

    buf_end = &lb->lb_data[lb->lb_len - 1];
    rv = buf_end - lb->lb_wpos;

    return rv;
}

/*
 * It's not granted we write the whole buffer in one call to
 * SSL_write_ex(). Function ypdate_lb_wpos() allows us to
 * remember where next write operation should start writing from.
 */
static void update_lb_wpos(struct linked_buf *lb, size_t written)
{
    if (written > lb->lb_len)
        written = lb->lb_len;

    lb->lb_wpos += written;
    if (lb->lb_wpos > &lb->lb_data[sizeof (lb->lb_data) - 1])
        lb->lb_wpos = &lb->lb_data[sizeof (lb->lb_data) - 1];
}

/*
 * Whenever stream gets destroyed, the app_destroy_cb() fires,
 * we must destroy all linked buffers including the context itself.
 */
static void app_destroy_cb(void *ctx)
{
    struct app_ctx *ac = (struct app_ctx *)ctx;
    struct linked_buf *lb, *lb_safe;

    OSSL_LIST_FOREACH_DELSAFE(lb, lb_safe, lb, &ac->ac_head) {
        free(lb);
    }
    free(ac);
}

/*
 * app_accept_stream() callback fires when there is a new stream
 * from client. Callback initializes context. It also indicates
 * its readiness to start receiving data.
 */
static int app_accept_stream_cb(struct poll_event *pe)
{
    struct app_ctx *ac;

    /*
     * QUIC echo server application requires bi-directional
     * streams (PE_STREAM) to work. Dealing with uni-directional
     * stream needs more thought.
     */
    if (pe->pe_type != PE_STREAM)
        return -1;

    ac = (struct app_ctx *)OPENSSL_zalloc(sizeof (struct app_ctx));
    if (ac == NULL)
        return -1;

    ossl_list_lb_init(&ac->ac_head);
    pe->pe_appdata = ac;
    pe->pe_cb_ondestroy = app_destroy_cb;
    pe_resume_read(pe);

    return 0;
}

/*
 * request_write() inserts link buffer to write queue and
 * indicates to poll manager there are outbound data ready.
 */
static int request_write(struct poll_event *pe, struct linked_buf *lb)
{
    struct app_ctx *ac = (struct app_ctx *)pe->pe_appdata;
    int rv, stype;

    /*
     * handling of unidirectional streams is more tricky
     * in asynchronous I/O. We need to move/share app_ctx from
     * from read poll event (this pe), to new poll event which
     * is associated with outbound stream poll event (a.k.a. write side)
     *
     * and we already know creating stream is two stop process:
     *     - step one: ask for stream
     *     - step two: handle notification of newly created stream
     * we need to pass ac from here to step two. Perhaps we need
     * something like pipe: a pair of two streams.
     */
    stype = SSL_get_stream_type(get_ssl_from_pe(pe));
    if (stype == SSL_STREAM_TYPE_BIDI) {
        ossl_list_lb_insert_tail(&ac->ac_head, lb);
        if (ossl_list_lb_num(&ac->ac_head) == 1) {
            pe_resume_write(pe);
        }
        rv = 0;
    } else {
        rv = -1;
    }

    return rv;
}

/*
 * app_read_cb() callback notifies application there are data
 * waiting to be read from stream. The callback allocates
 * new linked buffer and reads data from stream to newly allocated
 * buffer. It then uses request_write() to put the buffer to write
 * queue so data can be echoed back to client.
 */
static int app_read_cb(struct poll_event *pe)
{
    struct linked_buf *lb;
    int rv;

    lb = (struct linked_buf *)OPENSSL_zalloc(sizeof (struct linked_buf));
    if (lb == NULL)
        return -1;

    rv = SSL_read_ex(get_ssl_from_pe(pe), lb->lb_data, sizeof (lb->lb_data),
                     &lb->lb_len);
    if (rv == 0) {
        free(lb);
        /*
	 * May be it's over cautious, we should just examine stream state and
	 * decide if we can continue with poll (rv == 0) or we should stop
	 * polling (rv == -1).
         */
        rv = handle_ssl_error(pe, rv, __func__);
        if (rv == 0)
            rv = handle_read_stream_state(pe);
        return rv;
    }
    lb->lb_wpos = lb->lb_data;

    rv = request_write(pe, lb);

    if (rv != 0)
        free(lb);

    return 0;
}

/*
 * app_write_cb() callback notifies application the QUIC stack
 * is ready to send data. The write callback attempts to process
 * all buffers in write queue.
 * if write queue becomes empty, stream is concluded.
 */
static int app_write_cb(struct poll_event *pe)
{
    struct app_ctx *ac = (struct app_ctx *)pe->pe_appdata;
    struct linked_buf *lb, *lb_safe;
    size_t written;
    int rv;

    lb = ossl_list_lb_head(&ac->ac_head);
    if (lb == NULL) {
        DPRINTF(stderr,
                "%s write queue is empty pausing write, resuming read\n",
                __func__);
        pe_pause_write(pe);
        pe_resume_write(pe);
        return 0;
    }

    OSSL_LIST_FOREACH_DELSAFE(lb, lb_safe, lb, &ac->ac_head) {
        rv = SSL_write_ex(get_ssl_from_pe(pe), lb->lb_wpos, get_write_len(lb),
                          &written);
        if (rv == 0) {
            /*
             * just return 0 to keep polling, we assume to get error notification
             */
            return 0;
        } 

        update_lb_wpos(lb, written);

        if (get_write_len(lb) == 0) {
            ossl_list_lb_remove(&ac->ac_head, lb);
            free(lb);
        } else {
            return 0;
        }
    }

    if (ossl_list_lb_head(&ac->ac_head) == NULL) {
        /*
	 * What happens now purely depends on application logic. In our case
	 * here the client application (quic-client-*block,c sends its data
         * and concludes stream.
         */
        SSL_stream_conclude(get_ssl_from_pe(pe), 0);
        /*
         * Notes: I still don't know what's the best course of action here.
         * Doing pe_resume_read() is not option because it makes reader
         * to wake up immediately, app_read_cb() attempts to read data
         * and finds there is nothing, it bails out with -1. This makes
         * poll manager to destroy poll event stream immediately which is
         * too soon to deliver the STREAM_CONCLUDE to peer. The stream
         * is torn down immediately causing client to see a RESET.
         */
        pe_disable_write(pe);
    }

    return 0;
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

    /*
     * This works for bi-directional streams
     */
    pm->pm_qstream_in = app_accept_stream_cb;
    pm->pm_do_read = app_read_cb;
    pm->pm_do_write = app_write_cb;

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
