/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef OSSL_QUIC_ENGINE_H
# define OSSL_QUIC_ENGINE_H

# include <openssl/ssl.h>

# include "internal/quic_predef.h"
# include "internal/quic_port.h"
# include "internal/thread_arch.h"

# ifndef OPENSSL_NO_QUIC

/*
 * QUIC Engine
 * ===========
 *
 * A QUIC Engine (QUIC_ENGINE) represents an event processing domain for the
 * purposes of QUIC and contains zero or more subsidiary QUIC_PORT instances
 * (each of which currently represents a UDP socket), each of which in turn
 * contains zero or more subsidiary QUIC_CHANNEL instances, each of which
 * represents a single QUIC connection. All QUIC_PORT instances must belong
 * to a QUIC_ENGINE.
 *
 * TODO(QUIC SERVER): Currently a QUIC_PORT belongs to a single QUIC_CHANNEL.
 * This will cease to be the case once connection migration and/or multipath is
 * implemented, so in future a channel might be associated with multiple ports.
 *
 * A QUIC engine is the root object in a QUIC event domain, and is responsible
 * for managing event processing for all QUIC ports and channels (e.g. timeouts,
 * clock management, the QUIC_REACTOR instance, etc.).
 */
typedef struct quic_engine_args_st {
    OSSL_LIB_CTX    *libctx;
    const char      *propq;

    /*
     * This must be a mutex the lifetime of which will exceed that of the engine
     * and all ports and channels. The instantiator of the engine is responsible
     * for providing a mutex as this makes it easier to handle instantiation and
     * teardown of channels in situations potentially requiring locking.
     *
     * Note that this is a MUTEX not a RWLOCK as it needs to be an OS mutex for
     * compatibility with an OS's condition variable wait API, whereas RWLOCK
     * may, depending on the build configuration, be implemented using an OS's
     * mutex primitive or using its RW mutex primitive.
     */
    CRYPTO_MUTEX    *mutex;

    OSSL_TIME       (*now_cb)(void *arg);
    void            *now_cb_arg;
} QUIC_ENGINE_ARGS;

QUIC_ENGINE *ossl_quic_engine_new(const QUIC_ENGINE_ARGS *args);

void ossl_quic_engine_free(QUIC_ENGINE *qeng);

/*
 * Create a port which is a child of the engine. args->engine shall be NULL.
 */
QUIC_PORT *ossl_quic_engine_create_port(QUIC_ENGINE *qeng,
                                        const QUIC_PORT_ARGS *args);

/* Gets the mutex used by the engine. */
CRYPTO_MUTEX *ossl_quic_engine_get0_mutex(QUIC_ENGINE *qeng);

/* Gets the current time. */
OSSL_TIME ossl_quic_engine_get_time(QUIC_ENGINE *qeng);

/* For testing use. While enabled, ticking is not performed. */
void ossl_quic_engine_set_inhibit_tick(QUIC_ENGINE *qeng, int inhibit);

/* Gets the reactor which can be used to tick/poll on the port. */
QUIC_REACTOR *ossl_quic_engine_get0_reactor(QUIC_ENGINE *qeng);

# endif

#endif
