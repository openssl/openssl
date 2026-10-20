/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/common.h"
#include "internal/quic_ssl.h"
#include "internal/quic_reactor_wait_ctx.h"
#include "internal/ssl_unwrap.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../ssl_local.h"
#include "poll_builder.h"

#ifdef OPENSSL_NO_QUIC
/* Stub type when QUIC is disabled so function signatures remain consistent */
typedef int QUIC_REACTOR_WAIT_CTX;
#endif

#if defined(_AIX)
/*
 * Some versions of AIX define macros for events and revents for use when
 * accessing pollfd structures (see Github issue #24236). That interferes
 * with our use of these names here. We simply undef them.
 */
#undef revents
#undef events
#endif

#define ITEM_N(items, stride, n) \
    (*(SSL_POLL_ITEM *)((char *)(items) + (n) * (stride)))

#define FAIL_FROM(n)                              \
    do {                                          \
        size_t j;                                 \
                                                  \
        for (j = (n); j < num_items; ++j)         \
            ITEM_N(items, stride, j).revents = 0; \
                                                  \
        ok = 0;                                   \
        goto out;                                 \
    } while (0)

#define FAIL_ITEM(idx)                                          \
    do {                                                        \
        size_t idx_ = (idx);                                    \
                                                                \
        ITEM_N(items, stride, idx_).revents = SSL_POLL_EVENT_F; \
        ++result_count;                                         \
        FAIL_FROM(idx_ + 1);                                    \
    } while (0)

#ifndef OPENSSL_NO_QUIC
/*
 * Test instrumentation only; see poll_builder.h. Always NULL in production
 * use.
 */
void (*ossl_quic_poll_translate_test_step_cb)(size_t idx, void *arg) = NULL;
void *ossl_quic_poll_translate_test_step_cb_arg = NULL;

static int poll_translate_ssl_quic(SSL *ssl,
    QUIC_REACTOR_WAIT_CTX *wctx,
    RIO_POLL_BUILDER *rpb,
    uint64_t events,
    int *abort_blocking)
{
    BIO_POLL_DESCRIPTOR rd, wd;
    int fd1 = -1, fd2 = -1, fd_nfy = -1;
    int fd1_r = 0, fd1_w = 0, fd2_w = 0;

    if (SSL_net_read_desired(ssl)) {
        if (!SSL_get_rpoll_descriptor(ssl, &rd)) {
            ERR_raise_data(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                "SSL_poll requires the network BIOs underlying "
                "a QUIC SSL object provide poll descriptors");
            return 0;
        }

        if (rd.type != BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD) {
            ERR_raise_data(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                "SSL_poll requires the poll descriptors of the "
                "network BIOs underlying a QUIC SSL object be "
                "of socket type");
            return 0;
        }

        fd1 = rd.value.fd;
        fd1_r = 1;
    }

    if (SSL_net_write_desired(ssl)) {
        if (!SSL_get_wpoll_descriptor(ssl, &wd)) {
            ERR_raise_data(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                "SSL_poll requires the network BIOs underlying "
                "a QUIC SSL object provide poll descriptors");
            return 0;
        }

        if (wd.type != BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD) {
            ERR_raise_data(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                "SSL_poll requires the poll descriptors of the "
                "network BIOs underlying a QUIC SSL object be "
                "of socket type");
            return 0;
        }

        fd2 = wd.value.fd;
        fd2_w = 1;
    }

    if (fd2 == fd1) {
        fd2 = -1;
        fd1_w = fd2_w;
    }

    if (fd1 != -1)
        if (!ossl_rio_poll_builder_add_fd(rpb, fd1, fd1_r, fd1_w))
            return 0;

    if (fd2 != -1 && fd2_w)
        if (!ossl_rio_poll_builder_add_fd(rpb, fd2, /*r = */ 0, fd2_w))
            return 0;

    /*
     * Add the notifier FD for the QUIC domain this SSL object is a part of (if
     * there is one). This ensures we get woken up if another thread calls into
     * that QUIC domain and some readiness event relevant to the SSL_poll call
     * on this thread arises without the underlying network socket ever becoming
     * readable.
     */
    fd_nfy = ossl_quic_get_notifier_fd(ssl);
    if (fd_nfy != -1) {
        uint64_t revents = 0;

        if (!ossl_rio_poll_builder_add_fd(rpb, fd_nfy, /*r = */ 1, /*w = */ 0))
            return 0;

        /* Tell QUIC domain we need to receive notifications. */
        ossl_quic_enter_blocking_section(ssl, wctx);

        /*
         * Only after the above call returns is it guaranteed that any readiness
         * events will cause the above notifier to become readable. Therefore,
         * it is possible the object became ready after our initial
         * poll_readout() call (before we determined that nothing was ready and
         * we needed to block). We now need to do another readout, in which case
         * blocking is to be aborted.
         */
        if (!ossl_quic_conn_poll_events(ssl, events, /*do_tick = */ 0, &revents)) {
            ossl_quic_leave_blocking_section(ssl, wctx);
            return 0;
        }

        if (revents != 0) {
            ossl_quic_leave_blocking_section(ssl, wctx);
            *abort_blocking = 1;
            return 1;
        }
    }

    return 1;
}

static void postpoll_translation_cleanup_ssl_quic(SSL *ssl,
    QUIC_REACTOR_WAIT_CTX *wctx)
{
    if (ossl_quic_get_notifier_fd(ssl) != -1)
        ossl_quic_leave_blocking_section(ssl, wctx);
}
#endif /* OPENSSL_NO_QUIC */

#ifndef OPENSSL_NO_DTLS
typedef struct {
    SSL **listeners;
    size_t num_listeners;
    size_t max_listeners;
} DTLS_POLL_WAIT_CTX;

/* Run callback-producing demux work before any item registers a waiter. */
static void poll_preflight_dtls(SSL_POLL_ITEM *items, size_t num_items,
    size_t stride)
{
    size_t i;
    SSL_POLL_ITEM *item;
    SSL *ssl;
    SSL_CONNECTION *sc;
    DTLS_LISTENER *dl;

    for (i = 0; i < num_items; ++i) {
        item = &ITEM_N(items, stride, i);
        if (item->desc.type != BIO_POLL_DESCRIPTOR_TYPE_SSL
            || (item->events & (SSL_POLL_EVENT_R | SSL_POLL_EVENT_EC)) == 0)
            continue;

        ssl = item->desc.value.ssl;
        if (ssl == NULL || ssl->type != SSL_TYPE_SSL_CONNECTION
            || !SSL_is_dtls(ssl) || SSL_get_rbio(ssl) != NULL)
            continue;

        sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
        if (sc == NULL || sc->d1 == NULL || sc->d1->listener == NULL)
            continue;

        dl = (DTLS_LISTENER *)sc->d1->listener;
        if (ossl_dtls_listener_get_error(dl, /*raise_error=*/0) == SSL_ERROR_NONE)
            ossl_dtls_tick(dl);
        /* Translation handles failure using the item's requested error mask. */
    }
}

/*
 * Register each listener only once, even when several items share it. Record
 * actual registrations rather than inferring them from mutable failure state.
 * The listener helpers acquire and release their own mutex.
 */
static int dtls_poll_enter_blocking_section(DTLS_POLL_WAIT_CTX *ctx,
    DTLS_LISTENER *dl, RIO_POLL_BUILDER *rpb)
{
    size_t i;
    int nfd;

    if (!dl->have_notifier
        || (nfd = ossl_rio_notifier_as_fd(&dl->notifier)) == -1)
        return 1;

    for (i = 0; i < ctx->num_listeners; ++i)
        if (ctx->listeners[i] == (SSL *)dl)
            return 1;

    if (ctx->listeners == NULL) {
        ctx->listeners = OPENSSL_malloc_array(ctx->max_listeners,
            sizeof(*ctx->listeners));
        if (ctx->listeners == NULL)
            return 0;
    }

    if (!ossl_rio_poll_builder_add_fd(rpb, nfd, /*r=*/1, /*w=*/0))
        return 0;

    ossl_dtls_listener_enter_blocking_section((SSL *)dl);
    /*
     * Leave barriers must be visited in a consistent order across threads.
     * Otherwise two waits covering the same listeners in opposite orders can
     * each wait for the other's registration at a different listener.
     */
    for (i = ctx->num_listeners; i > 0
        && (uintptr_t)ctx->listeners[i - 1] > (uintptr_t)dl;
        --i)
        ctx->listeners[i] = ctx->listeners[i - 1];
    ctx->listeners[i] = (SSL *)dl;
    ++ctx->num_listeners;
    return 1;
}

static int poll_translate_ssl_dtls_listener(SSL *ssl,
    DTLS_POLL_WAIT_CTX *ctx,
    RIO_POLL_BUILDER *rpb,
    uint64_t events,
    int *abort_blocking)
{
    BIO *rbio;
    BIO_POLL_DESCRIPTOR desc;
    DTLS_LISTENER *dl = (DTLS_LISTENER *)ssl;
    uint64_t revents = 0;

    /* A failed listener has no normal readiness or usable socket to wait on. */
    if (ossl_dtls_listener_get_error(dl, /*raise_error=*/0) != SSL_ERROR_NONE) {
        *abort_blocking = (events & SSL_POLL_EVENT_EL) != 0;
        return 1;
    }

    if (!dtls_poll_enter_blocking_section(ctx, dl, rpb))
        return 0;

    /* Re-check readiness after registering, closing the lost-wakeup window. */
    if (!ossl_dtls_listener_poll_events(ssl, events, /*do_tick=*/0, &revents))
        return 0;

    /*
     * On a newly observed failure, rebuild even if EL was not requested: the
     * notifier already added above may be signalled. The next translation
     * skips this listener entirely if there is no requested error to report.
     */
    if (revents != 0
        || ossl_dtls_listener_get_error(dl, /*raise_error=*/0) != SSL_ERROR_NONE) {
        *abort_blocking = 1;
        return 1;
    }

    rbio = SSL_get_rbio(ssl);
    if (rbio == NULL
        || !BIO_get_rpoll_descriptor(rbio, &desc)
        || desc.type != BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD) {
        if (ossl_dtls_listener_get_error(dl, /*raise_error=*/0) != SSL_ERROR_NONE) {
            *abort_blocking = 1;
            return 1;
        }
        if (rbio == NULL)
            return 0;
        ERR_raise_data(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
            "DTLS listener requires a socket BIO for blocking poll");
        return 0;
    }

    if (ossl_dtls_listener_get_error(dl, /*raise_error=*/0) != SSL_ERROR_NONE) {
        *abort_blocking = 1;
        return 1;
    }

    /*
     * Watch a healthy listener's socket for incoming datagrams. The notifier
     * also wakes us for readiness or failure produced by another thread.
     */
    if (!ossl_rio_poll_builder_add_fd(rpb, desc.value.fd, /*r=*/1, /*w=*/0))
        return 0;

    return 1;
}

static int poll_translate_ssl_dtls_conn(SSL *ssl,
    DTLS_POLL_WAIT_CTX *ctx,
    RIO_POLL_BUILDER *rpb,
    uint64_t events,
    int *abort_blocking,
    int bound_by_event_timeout,
    OSSL_TIME *earliest_wakeup_deadline)
{
    BIO *rbio, *wbio;
    BIO_POLL_DESCRIPTOR rdesc, wdesc;
    int rfd = -1, wfd = -1;
    SSL_CONNECTION *sc;
    DTLS_LISTENER *dl = NULL;
    int has_pending;
    struct timeval timeout;
    int is_infinite = 0;

    sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    if (sc != NULL && sc->d1 != NULL && sc->d1->listener != NULL)
        dl = (DTLS_LISTENER *)sc->d1->listener;

    if (dl != NULL) {
        if (ossl_dtls_listener_get_error(dl, /*raise_error=*/0) != SSL_ERROR_NONE) {
            *abort_blocking = (events & SSL_POLL_EVENT_EC) != 0;
            return 1;
        }

        /* Parent failure must wake writers and EC-only waiters too. */
        if ((events & (SSL_POLL_EVENT_R | SSL_POLL_EVENT_W | SSL_POLL_EVENT_EC)) != 0
            && !dtls_poll_enter_blocking_section(ctx, dl, rpb))
            return 0;

        if (ossl_dtls_listener_get_error(dl, /*raise_error=*/0) != SSL_ERROR_NONE) {
            *abort_blocking = 1;
            return 1;
        }

        if ((events & SSL_POLL_EVENT_EC) != 0
            && (ossl_statem_in_error(sc) || SSL_get_shutdown(ssl) != 0)) {
            *abort_blocking = 1;
            return 1;
        }

        /* Earlier callbacks may also have buffered connection data. */
        if ((events & SSL_POLL_EVENT_R) != 0
            && (SSL_has_pending(ssl) || SSL_pending(ssl) > 0)) {
            *abort_blocking = 1;
            return 1;
        }
    }

    if ((events & SSL_POLL_EVENT_R) != 0
        || (dl != NULL && (events & SSL_POLL_EVENT_EC) != 0)) {
        rbio = SSL_get_rbio(ssl);

        if (rbio == NULL && dl != NULL) {
            /*
             * Preflight pumped the listener's demux before any registrations.
             * Now check the URXE buffer. If data has been demuxed into
             * this connection's receive queue, abort blocking immediately -
             * there is no need to wait on the socket FD.
             * Registration above precedes this check, so later arrivals wake
             * the notifier. No listener mutex is held while accessing RX.
             */
            if ((events & SSL_POLL_EVENT_R) != 0 && sc->d1->rx != NULL) {
                ossl_crypto_mutex_lock(sc->d1->rx->mutex);
                has_pending = !ossl_list_urxe_is_empty(&sc->d1->rx->urxe_pending);
                ossl_crypto_mutex_unlock(sc->d1->rx->mutex);
                if (has_pending) {
                    *abort_blocking = 1;
                    return 1;
                }
            }

            /*
             * Monitor the listener's rbio for data or transport failure. An
             * EC-only waiter also needs to receive from the shared socket to
             * discover a permanent receive error.
             */
            rbio = SSL_get_rbio(sc->d1->listener);
        }

        if (rbio != NULL) {
            if (BIO_get_rpoll_descriptor(rbio, &rdesc)
                && rdesc.type == BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD)
                rfd = rdesc.value.fd;
        }
    }

    if ((events & SSL_POLL_EVENT_W) != 0) {
        wbio = SSL_get_wbio(ssl);
        if (wbio != NULL) {
            if (BIO_get_wpoll_descriptor(wbio, &wdesc)
                && wdesc.type == BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD)
                wfd = wdesc.value.fd;
        }
    }

    if (dl != NULL
        && ossl_dtls_listener_get_error(dl, /*raise_error=*/0) != SSL_ERROR_NONE) {
        *abort_blocking = 1;
        return 1;
    }

    /* If same FD for read and write, combine them */
    if (rfd != -1 && wfd == rfd) {
        if (!ossl_rio_poll_builder_add_fd(rpb, rfd, /*r=*/1, /*w=*/1))
            return 0;
    } else {
        if (rfd != -1)
            if (!ossl_rio_poll_builder_add_fd(rpb, rfd, /*r=*/1, /*w=*/0))
                return 0;
        if (wfd != -1)
            if (!ossl_rio_poll_builder_add_fd(rpb, wfd, /*r=*/0, /*w=*/1))
                return 0;
    }

    /*
     * Only healthy connections need retransmission wakeups. A waiter which
     * cannot service the timer must not be woken by it, or an expired timer
     * would make every subsequent wait return immediately.
     */
    if (bound_by_event_timeout) {
        if (!SSL_get_event_timeout(ssl, &timeout, &is_infinite))
            return 0;

        if (!is_infinite)
            *earliest_wakeup_deadline
                = ossl_time_min(*earliest_wakeup_deadline,
                    ossl_time_add(ossl_time_now(),
                        ossl_time_from_timeval(timeout)));
    }

    if (dl != NULL
        && ossl_dtls_listener_get_error(dl, /*raise_error=*/0) != SSL_ERROR_NONE)
        *abort_blocking = 1;

    return 1;
}
#else
typedef int DTLS_POLL_WAIT_CTX;
#endif /* OPENSSL_NO_DTLS */

#if !defined(OPENSSL_NO_QUIC) || !defined(OPENSSL_NO_DTLS)
static void postpoll_translation_cleanup(SSL_POLL_ITEM *items,
    size_t num_items,
    size_t stride,
    ossl_unused QUIC_REACTOR_WAIT_CTX *wctx)
{
    SSL_POLL_ITEM *item;
    SSL *ssl;
    size_t i;

    for (i = 0; i < num_items; ++i) {
        item = &ITEM_N(items, stride, i);

        switch (item->desc.type) {
        case BIO_POLL_DESCRIPTOR_TYPE_SSL:
            ssl = item->desc.value.ssl;
            if (ssl == NULL)
                break;

            switch (ssl->type) {
#ifndef OPENSSL_NO_QUIC
            case SSL_TYPE_QUIC_LISTENER:
            case SSL_TYPE_QUIC_CONNECTION:
            case SSL_TYPE_QUIC_XSO:
                postpoll_translation_cleanup_ssl_quic(ssl, wctx);
                break;
#endif

            default:
                break;
            }
            break;
        default:
            break;
        }
    }
}

static int poll_translate(SSL_POLL_ITEM *items,
    size_t num_items,
    size_t stride,
    ossl_unused QUIC_REACTOR_WAIT_CTX *wctx,
    ossl_unused DTLS_POLL_WAIT_CTX *dtls_wctx,
    RIO_POLL_BUILDER *rpb,
    OSSL_TIME *p_earliest_wakeup_deadline,
    int *abort_blocking,
    ossl_unused int bound_by_event_timeout,
    size_t *p_result_count)
{
    int ok = 1;
    SSL_POLL_ITEM *item;
    size_t result_count = 0;
    SSL *ssl;
    OSSL_TIME earliest_wakeup_deadline = ossl_time_infinite();
#ifndef OPENSSL_NO_QUIC
    struct timeval timeout;
    int is_infinite = 0;
#endif
    size_t i;
#ifndef OPENSSL_NO_DTLS
    size_t dtls_idx;
#endif

    for (i = 0; i < num_items; ++i) {
        item = &ITEM_N(items, stride, i);

#ifndef OPENSSL_NO_QUIC
        if (ossl_quic_poll_translate_test_step_cb != NULL)
            ossl_quic_poll_translate_test_step_cb(i,
                ossl_quic_poll_translate_test_step_cb_arg);
#endif

        switch (item->desc.type) {
        case BIO_POLL_DESCRIPTOR_TYPE_SSL:
            ssl = item->desc.value.ssl;
            if (ssl == NULL)
                /* NULL items are no-ops and have revents reported as 0 */
                break;

            switch (ssl->type) {
#ifndef OPENSSL_NO_QUIC
            case SSL_TYPE_QUIC_LISTENER:
            case SSL_TYPE_QUIC_CONNECTION:
            case SSL_TYPE_QUIC_XSO:
                if (!poll_translate_ssl_quic(ssl, wctx, rpb, item->events,
                        abort_blocking))
                    FAIL_ITEM(i);

                if (*abort_blocking)
                    goto out;

                if (!SSL_get_event_timeout(ssl, &timeout, &is_infinite))
                    FAIL_ITEM(i++); /* need to clean up this item too */

                if (!is_infinite)
                    earliest_wakeup_deadline
                        = ossl_time_min(earliest_wakeup_deadline,
                            ossl_time_add(ossl_time_now(),
                                ossl_time_from_timeval(timeout)));

                break;
#endif

#ifndef OPENSSL_NO_DTLS
            case SSL_TYPE_DTLS_LISTENER:
                /* DTLS registrations are deferred until after this pass. */
                break;
            case SSL_TYPE_SSL_CONNECTION:
                if (!SSL_is_dtls(ssl)) {
                    ERR_raise_data(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                        "SSL_poll currently only supports DTLS listeners for DTLS connections");
                }
                break;
#endif

            default:
                ERR_raise_data(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                    "SSL_poll currently only supports QUIC SSL "
                    "objects");
                FAIL_ITEM(i);
            }
            break;

        case BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD:
            ERR_raise_data(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                "SSL_poll currently does not support polling "
                "sockets");
            FAIL_ITEM(i);

        default:
            ERR_raise_data(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                "SSL_poll does not support unknown poll descriptor "
                "type %d",
                item->desc.type);
            FAIL_ITEM(i);
        }
    }

#ifndef OPENSSL_NO_DTLS
    /*
     * QUIC translation can invoke callbacks too. Only register DTLS waiters
     * after it has completed for every item, then recheck readiness in each
     * DTLS translator to close the lost-wakeup window. Keep i at num_items so
     * every translated QUIC item is cleaned up if this pass fails or aborts.
     */
    for (dtls_idx = 0; dtls_idx < num_items; ++dtls_idx) {
        item = &ITEM_N(items, stride, dtls_idx);
        if (item->desc.type != BIO_POLL_DESCRIPTOR_TYPE_SSL
            || (ssl = item->desc.value.ssl) == NULL)
            continue;

        if (ssl->type == SSL_TYPE_DTLS_LISTENER) {
            if (!poll_translate_ssl_dtls_listener(ssl, dtls_wctx, rpb,
                    item->events, abort_blocking))
                FAIL_ITEM(dtls_idx);
        } else if (ssl->type == SSL_TYPE_SSL_CONNECTION && SSL_is_dtls(ssl)) {
            if (!poll_translate_ssl_dtls_conn(ssl, dtls_wctx, rpb,
                    item->events, abort_blocking, bound_by_event_timeout,
                    &earliest_wakeup_deadline))
                FAIL_ITEM(dtls_idx);
        }

        if (*abort_blocking)
            goto out;
    }
#endif

out:
    /*
     * QUIC items balance their own registration on failure or abort; only
     * items 0..i-1 need cleanup here. DTLS registrations are tracked separately
     * and all released by poll_block(), including the current item's.
     */
    if (!ok || *abort_blocking)
        postpoll_translation_cleanup(items, i, stride, wctx);

    *p_earliest_wakeup_deadline = earliest_wakeup_deadline;
    *p_result_count = result_count;
    return ok;
}

static int poll_block(SSL_POLL_ITEM *items,
    size_t num_items,
    size_t stride,
    OSSL_TIME user_deadline,
    int bound_by_event_timeout,
    size_t *p_result_count)
{
    int ok = 0, abort_blocking = 0;
    RIO_POLL_BUILDER rpb;
    QUIC_REACTOR_WAIT_CTX wctx;
    DTLS_POLL_WAIT_CTX dtls_wctx;
    OSSL_TIME earliest_wakeup_deadline;

    /*
     * Blocking is somewhat involved and involves the following steps:
     *
     * - Translation, in which the various logical items (SSL objects, etc.) to
     *   be polled are translated into items an OS polling API understands.
     *
     * - Synchronisation bookkeeping. This ensures that we can be woken up
     *   not just by readiness of any underlying file descriptor distilled from
     *   the provided items but also by other threads, which might do work
     *   on a relevant QUIC object to cause the object to be ready without the
     *   underlying file descriptor ever becoming ready from our perspective.
     *
     * - The blocking call to the OS polling API.
     *
     * - Currently we do not do reverse translation but simply call
     *   poll_readout() again to read out all readiness state for all
     *   descriptors which the user passed.
     *
     *   TODO(QUIC POLLING): In the future we will do reverse translation here
     *   also to facilitate a more efficient readout.
     */
#ifndef OPENSSL_NO_QUIC
    ossl_quic_reactor_wait_ctx_init(&wctx);
#endif
#ifndef OPENSSL_NO_DTLS
    dtls_wctx.listeners = NULL;
    dtls_wctx.num_listeners = 0;
    dtls_wctx.max_listeners = num_items;
#endif
    ossl_rio_poll_builder_init(&rpb);

#ifndef OPENSSL_NO_DTLS
    poll_preflight_dtls(items, num_items, stride);
#endif

    if (!poll_translate(items, num_items, stride, &wctx, &dtls_wctx, &rpb,
            &earliest_wakeup_deadline,
            &abort_blocking,
            bound_by_event_timeout,
            p_result_count))
        goto out;

    if (abort_blocking) {
        /*
         * Nothing actually failed; we just shouldn't block because an item
         * may have become ready while we were setting up. The caller's
         * retry loop will call poll_readout() again to pick this up.
         */
        ok = 1;
        goto out;
    }

    earliest_wakeup_deadline = ossl_time_min(earliest_wakeup_deadline,
        user_deadline);

    ok = ossl_rio_poll_builder_poll(&rpb, earliest_wakeup_deadline);

    postpoll_translation_cleanup(items, num_items, stride, &wctx);

out:
#ifndef OPENSSL_NO_DTLS
{
    size_t i;

    for (i = 0; i < dtls_wctx.num_listeners; ++i)
        ossl_dtls_listener_leave_blocking_section(dtls_wctx.listeners[i]);
}
    OPENSSL_free(dtls_wctx.listeners);
#endif
    ossl_rio_poll_builder_cleanup(&rpb);
#ifndef OPENSSL_NO_QUIC
    ossl_quic_reactor_wait_ctx_cleanup(&wctx);
#endif
    return ok;
}

#ifndef OPENSSL_NO_DTLS
/*
 * Wait until the given DTLS listener or listener-based connection may have
 * become ready for one of the given events, or until the deadline expires.
 *
 * This is the wait that libssl itself performs when a DTLS object is used in
 * blocking mode. It is the same wait SSL_poll() performs, and reuses it, so a
 * blocking call is woken by the same means an application polling the object
 * would be: readiness of the listener's socket, or the listener's notifier if
 * another thread produces readiness without the socket becoming readable here.
 *
 * No readout is performed. A spurious wakeup is always possible - the socket
 * becoming readable says nothing about which connection the datagram is for -
 * so the caller must re-test its own condition and wait again if needed.
 *
 * bound_by_event_timeout says whether the connection's own event timeout, which
 * for DTLS is the retransmission timer, should shorten the wait. Pass 1 unless
 * the caller is unable to service that timer when it fires: waking for a
 * timeout nothing then handles leaves it expired, and an expired timeout reads
 * as a zero deadline, so every later wait returns at once.
 *
 * Returns 1 if the wait completed and 0 on error.
 */
int ossl_dtls_block_until_ready(SSL *ssl, uint64_t events, OSSL_TIME deadline,
    int bound_by_event_timeout)
{
    SSL_POLL_ITEM item;
    size_t result_count = 0;

    item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    item.desc.value.ssl = ssl;
    item.events = events;
    item.revents = 0;

    return poll_block(&item, 1, sizeof(item), deadline, bound_by_event_timeout,
        &result_count);
}
#endif /* OPENSSL_NO_DTLS */
#endif

static int poll_readout(SSL_POLL_ITEM *items,
    size_t num_items,
    size_t stride,
    int do_tick,
    size_t *p_result_count)
{
    int ok = 1;
    size_t i, result_count = 0;
    SSL_POLL_ITEM *item;
    SSL *ssl;
#if !defined(OPENSSL_NO_QUIC) || !defined(OPENSSL_NO_DTLS)
    uint64_t events;
#endif
    uint64_t revents;

    for (i = 0; i < num_items; ++i) {
        item = &ITEM_N(items, stride, i);
#if !defined(OPENSSL_NO_QUIC) || !defined(OPENSSL_NO_DTLS)
        events = item->events;
#endif
        revents = 0;

        switch (item->desc.type) {
        case BIO_POLL_DESCRIPTOR_TYPE_SSL:
            ssl = item->desc.value.ssl;
            if (ssl == NULL)
                /* NULL items are no-ops and have revents reported as 0 */
                break;

            switch (ssl->type) {
#ifndef OPENSSL_NO_QUIC
            case SSL_TYPE_QUIC_LISTENER:
            case SSL_TYPE_QUIC_CONNECTION:
            case SSL_TYPE_QUIC_XSO:
                if (!ossl_quic_conn_poll_events(ssl, events, do_tick, &revents))
                    /* above call raises ERR */
                    FAIL_ITEM(i);

                if (revents != 0)
                    ++result_count;

                break;
#endif

#ifndef OPENSSL_NO_DTLS
            case SSL_TYPE_DTLS_LISTENER:
                if (!ossl_dtls_listener_poll_events(ssl, events, do_tick, &revents))
                    /* above call raises ERR */
                    FAIL_ITEM(i);

                if (revents != 0)
                    ++result_count;
                break;
            case SSL_TYPE_SSL_CONNECTION:
                if (SSL_is_dtls(ssl)) {
                    if (!ossl_dtls_conn_poll_events(ssl, events, do_tick, &revents))
                        /* above call raises ERR */
                        FAIL_ITEM(i);

                    if (revents != 0)
                        ++result_count;
                } else {
                    /* TLS Connections not supported */
                    ERR_raise_data(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                        "SSL_poll currently only supports QUIC and DTLS SSL objects");
                    FAIL_ITEM(i);
                }
                break;
#endif

            default:
                ERR_raise_data(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                    "SSL_poll currently only supports QUIC and DTLS SSL objects");
                FAIL_ITEM(i);
            }
            break;
        case BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD:
            ERR_raise_data(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                "SSL_poll currently does not support polling "
                "sockets");
            FAIL_ITEM(i);
        default:
            ERR_raise_data(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                "SSL_poll does not support unknown poll descriptor "
                "type %d",
                item->desc.type);
            FAIL_ITEM(i);
        }

        item->revents = revents;
    }

out:
    if (p_result_count != NULL)
        *p_result_count = result_count;

    return ok;
}

int SSL_poll(SSL_POLL_ITEM *items,
    size_t num_items,
    size_t stride,
    const struct timeval *timeout,
    uint64_t flags,
    size_t *p_result_count)
{
    int ok = 1;
    size_t result_count = 0;
    ossl_unused int do_tick = ((flags & SSL_POLL_FLAG_NO_HANDLE_EVENTS) == 0);
    OSSL_TIME deadline;

    /* Trivial case. */
    if (num_items == 0) {
        if (timeout == NULL)
            goto out;
        OSSL_sleep(ossl_time2ms(ossl_time_from_timeval(*timeout)));
        goto out;
    }

    /* Convert timeout to deadline. */
    if (timeout == NULL)
        deadline = ossl_time_infinite();
    else if (timeout->tv_sec == 0 && timeout->tv_usec == 0)
        deadline = ossl_time_zero();
    else
        deadline = ossl_time_add(ossl_time_now(),
            ossl_time_from_timeval(*timeout));

    /* Loop until we have something to report. */
    for (;;) {
        /* Readout phase - poll current state of each item. */
        if (!poll_readout(items, num_items, stride, do_tick, &result_count)) {
            ok = 0;
            goto out;
        }

        /*
         * If we got anything, or we are in immediate mode (zero timeout), or
         * the deadline has expired, we're done.
         */
        if (result_count > 0
            || ossl_time_is_zero(deadline) /* (avoids now call) */
            || ossl_time_compare(ossl_time_now(), deadline) >= 0)
            goto out;

        /*
         * Block until something is ready. Ignore NO_HANDLE_EVENTS from this
         * point onwards.
         */
        do_tick = 1;
#if !defined(OPENSSL_NO_QUIC) || !defined(OPENSSL_NO_DTLS)
        if (!poll_block(items, num_items, stride, deadline,
                /*bound_by_event_timeout=*/1, &result_count)) {
            ok = 0;
            goto out;
        }
#endif
    }

    /* TODO(QUIC POLLING): Support for polling FDs */

out:
    if (p_result_count != NULL)
        *p_result_count = result_count;

    return ok;
}
