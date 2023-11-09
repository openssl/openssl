/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef OSSL_QUIC_PORT_H
# define OSSL_QUIC_PORT_H

# include <openssl/ssl.h>
# include "internal/quic_types.h"
# include "internal/quic_reactor.h"
# include "internal/quic_demux.h"
# include "internal/quic_predef.h"
# include "internal/thread_arch.h"

# ifndef OPENSSL_NO_QUIC

/*
 * QUIC Port
 * =========
 *
 * A QUIC Port (QUIC_PORT) represents a single UDP network socket and contains
 * zero or more subsidiary QUIC_CHANNEL instances, each of which represents a
 * single QUIC connection. All QUIC_CHANNEL instances must belong to a
 * QUIC_PORT.
 */
typedef struct quic_port_args_st {
    /* All channels in a QUIC event domain share the same (libctx, propq). */
    OSSL_LIB_CTX    *libctx;
    const char      *propq;

    /*
     * This must be a mutex the lifetime of which will exceed that of the port
     * and all channels. The instantiator of the port is responsible for
     * providing a mutex as this makes it easier to handle instantiation and
     * teardown of channels in situations potentially requiring locking.
     *
     * Note that this is a MUTEX not a RWLOCK as it needs to be an OS mutex for
     * compatibility with an OS's condition variable wait API, whereas RWLOCK
     * may, depending on the build configuration, be implemented using an OS's
     * mutex primitive or using its RW mutex primitive.
     */
    CRYPTO_MUTEX    *mutex;

    /*
     * Optional function pointer to use to retrieve the current time. If NULL,
     * ossl_time_now() is used.
     */
    OSSL_TIME       (*now_cb)(void *arg);
    void            *now_cb_arg;

    /*
     * This SSL_CTX will be used when constructing the handshake layer object
     * inside newly created channels.
     */
    SSL_CTX         *channel_ctx;
} QUIC_PORT_ARGS;

typedef struct quic_port_st QUIC_PORT;

QUIC_PORT *ossl_quic_port_new(const QUIC_PORT_ARGS *args);

void ossl_quic_port_free(QUIC_PORT *port);

/*
 * Queries and Accessors
 * =====================
 */

/* Gets/sets the underlying network read and write BIO. */
BIO *ossl_quic_port_get_net_rbio(QUIC_PORT *port);
BIO *ossl_quic_port_get_net_wbio(QUIC_PORT *port);
int ossl_quic_port_set_net_rbio(QUIC_PORT *port, BIO *net_rbio);
int ossl_quic_port_set_net_wbio(QUIC_PORT *port, BIO *net_wbio);

int ossl_quic_port_update_poll_descriptors(QUIC_PORT *port);

/* Gets the reactor which can be used to tick/poll on the port. */
QUIC_REACTOR *ossl_quic_port_get0_reactor(QUIC_PORT *port);

/* Gets the demuxer belonging to the port. */
QUIC_DEMUX *ossl_quic_port_get0_demux(QUIC_PORT *port);

/* Gets the mutex used by the port. */
CRYPTO_MUTEX *ossl_quic_port_get0_mutex(QUIC_PORT *port);

/* Gets the current time. */
OSSL_TIME ossl_quic_port_get_time(QUIC_PORT *port);

# endif

#endif
