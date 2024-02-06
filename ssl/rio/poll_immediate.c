/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/common.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../ssl_local.h"

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

int SSL_poll(SSL_POLL_ITEM *items,
             size_t num_items,
             size_t stride,
             const struct timeval *timeout,
             uint64_t flags,
             size_t *p_result_count)
{
    int ok = 1;
    size_t i, result_count = 0;
    SSL_POLL_ITEM *item;
    SSL *ssl;
    uint64_t revents;
    ossl_unused uint64_t events;
    ossl_unused int do_tick = ((flags & SSL_POLL_FLAG_NO_HANDLE_EVENTS) == 0);
    int is_immediate
        = (timeout != NULL
           && timeout->tv_sec == 0 && timeout->tv_usec == 0);

    /*
     * Prevent calls which use SSL_poll functionality which is not currently
     * supported.
     */
    if (!is_immediate) {
        ERR_raise_data(ERR_LIB_SSL, SSL_R_POLL_REQUEST_NOT_SUPPORTED,
                       "SSL_poll does not currently support blocking "
                       "operation");
        FAIL_FROM(0);
    }

    /* Trivial case. */
    if (num_items == 0)
        goto out;

    /* Poll current state of each item. */
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

    /* TODO(QUIC POLLING): Blocking mode */
    /* TODO(QUIC POLLING): Support for polling FDs */

out:
    if (p_result_count != NULL)
        *p_result_count = result_count;

    return ok;
}
