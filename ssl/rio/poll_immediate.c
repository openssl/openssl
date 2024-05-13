/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/common.h"
#include "internal/quic_ssl.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../ssl_local.h"
#include "poll_builder.h"

#define ITEM_N(items, stride, n) \
    (*(SSL_POLL_ITEM *)((char *)(items) + (n)*(stride)))

#define FAIL_FROM(n)                                                        \
    do {                                                                    \
        size_t j;                                                           \
                                                                            \
        for (j = (n); j < num_items; ++j)                                   \
            ITEM_N(items, stride, j).revents = 0;                           \
                                                                            \
        ok = 0;                                                             \
        goto out;                                                           \
    } while (0)

#define FAIL_ITEM(i)                                                        \
    do {                                                                    \
        ITEM_N(items, stride, i).revents = SSL_POLL_EVENT_F;                \
        ++result_count;                                                     \
        FAIL_FROM(i + 1);                                                   \
    } while (0)

static int poll_translate_ssl_quic(SSL *ssl, RIO_POLL_BUILDER *rpb)
{
    BIO_POLL_DESCRIPTOR rd, wd;
    int fd1 = -1, fd2 = -1;
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

        fd1   = rd.value.fd;
        fd1_r = 1;
    }

    if (SSL_net_write_desired(ssl)) {
        if (!SSL_get_wpoll_descriptor(ssl, &wd)) {
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

        fd2   = wd.value.fd;
        fd2_w = 1;
    }

    if (fd2 == fd1) {
        fd2 = -1;
        fd1_w = fd1_w || fd2_w;
    }

    if (fd1 != -1 && (fd1_r || fd1_w))
        if (!ossl_rio_poll_builder_add_fd(rpb, fd1, fd1_r, fd1_w))
            return 0;

    if (fd2 != -1 && fd2_w)
        if (!ossl_rio_poll_builder_add_fd(rpb, fd2, /*r=*/0, fd2_w))
            return 0;

    return 1;
}

static int poll_translate(SSL_POLL_ITEM *items,
                          size_t num_items,
                          size_t stride,
                          RIO_POLL_BUILDER *rpb,
                          OSSL_TIME *p_earliest_wakeup_deadline)
{
    int ok = 1;
    SSL_POLL_ITEM *item;
    size_t result_count = 0;
    SSL *ssl;
    OSSL_TIME earliest_wakeup_deadline = ossl_time_infinite();
    struct timeval timeout;
    int is_infinite = 0;
    size_t i;

    for (i = 0; i < num_items; ++i) {
        item = &ITEM_N(items, stride, i);

        switch (item->desc.type) {
        case BIO_POLL_DESCRIPTOR_TYPE_SSL:
            ssl = item->desc.value.ssl;
            if (ssl == NULL)
                /* NULL items are no-ops and have revents reported as 0 */
                break;

            switch (ssl->type) {
#ifndef OPENSSL_NO_QUIC
            case SSL_TYPE_QUIC_CONNECTION:
            case SSL_TYPE_QUIC_XSO:
                if (!poll_translate_ssl_quic(ssl, rpb))
                    FAIL_ITEM(i);

                if (!SSL_get_event_timeout(ssl, &timeout, &is_infinite))
                    FAIL_ITEM(i);

                if (!is_infinite)
                    earliest_wakeup_deadline
                        = ossl_time_min(earliest_wakeup_deadline,
                                        ossl_time_add(ossl_time_now(),
                                                      ossl_time_from_timeval(timeout)));

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
                           "type %d", item->desc.type);
            FAIL_ITEM(i);
        }
    }

out:
    *p_earliest_wakeup_deadline = earliest_wakeup_deadline;
    return ok;
}

static int poll_block(SSL_POLL_ITEM *items,
                      size_t num_items,
                      size_t stride,
                      OSSL_TIME user_deadline)
{
    int ok = 0;
    RIO_POLL_BUILDER rpb;
    OSSL_TIME earliest_wakeup_deadline;

    ossl_rio_poll_builder_init(&rpb);

    if (!poll_translate(items, num_items, stride, &rpb,
                        &earliest_wakeup_deadline))
        goto out;

    earliest_wakeup_deadline = ossl_time_min(earliest_wakeup_deadline,
                                             user_deadline);

    if (!ossl_rio_poll_builder_poll(&rpb, earliest_wakeup_deadline))
        goto out;

    ok = 1;
out:
    ossl_rio_poll_builder_cleanup(&rpb);
    return ok;
}

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
    uint64_t events, revents;

    for (i = 0; i < num_items; ++i) {
        item    = &ITEM_N(items, stride, i);
        events  = item->events;
        revents = 0;

        switch (item->desc.type) {
        case BIO_POLL_DESCRIPTOR_TYPE_SSL:
            ssl = item->desc.value.ssl;
            if (ssl == NULL)
                /* NULL items are no-ops and have revents reported as 0 */
                break;

            switch (ssl->type) {
#ifndef OPENSSL_NO_QUIC
            case SSL_TYPE_QUIC_CONNECTION:
            case SSL_TYPE_QUIC_XSO:
                if (!ossl_quic_conn_poll_events(ssl, events, do_tick, &revents))
                    /* above call raises ERR */
                    FAIL_ITEM(i);

                if (revents != 0)
                    ++result_count;

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
                           "type %d", item->desc.type);
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
    if (num_items == 0)
        goto out;

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
            result_count = 0;
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
        if (!poll_block(items, num_items, stride, deadline)) {
            ok = 0;
            goto out;
        }
    }

    /* TODO(QUIC POLLING): Support for polling listeners */
    /* TODO(QUIC POLLING): Support for polling FDs */

out:
    if (p_result_count != NULL)
        *p_result_count = result_count;

    return ok;
}
