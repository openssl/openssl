/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/quic_engine.h"
#include "internal/quic_port.h"
#include "quic_engine_local.h"
#include "quic_port_local.h"
#include "../ssl_local.h"

/*
 * QUIC Engine
 * ===========
 */
static int qeng_init(QUIC_ENGINE *qeng);
static void qeng_cleanup(QUIC_ENGINE *qeng);
static void qeng_tick(QUIC_TICK_RESULT *res, void *arg, uint32_t flags);

DEFINE_LIST_OF_IMPL(port, QUIC_PORT);

QUIC_ENGINE *ossl_quic_engine_new(const QUIC_ENGINE_ARGS *args)
{
    QUIC_ENGINE *qeng;

    if ((qeng = OPENSSL_zalloc(sizeof(QUIC_ENGINE))) == NULL)
        return NULL;

    qeng->libctx            = args->libctx;
    qeng->propq             = args->propq;
    qeng->mutex             = args->mutex;
    qeng->now_cb            = args->now_cb;
    qeng->now_cb_arg        = args->now_cb_arg;

    if (!qeng_init(qeng)) {
        OPENSSL_free(qeng);
        return NULL;
    }

    return qeng;
}

void ossl_quic_engine_free(QUIC_ENGINE *qeng)
{
    if (qeng == NULL)
        return;

    qeng_cleanup(qeng);
    OPENSSL_free(qeng);
}

static int qeng_init(QUIC_ENGINE *qeng)
{
    ossl_quic_reactor_init(&qeng->rtor, qeng_tick, qeng, ossl_time_zero());
    return 1;
}

static void qeng_cleanup(QUIC_ENGINE *qeng)
{
    assert(ossl_list_port_num(&qeng->port_list) == 0);
}

QUIC_REACTOR *ossl_quic_engine_get0_reactor(QUIC_ENGINE *qeng)
{
    return &qeng->rtor;
}

CRYPTO_MUTEX *ossl_quic_engine_get0_mutex(QUIC_ENGINE *qeng)
{
    return qeng->mutex;
}

OSSL_TIME ossl_quic_engine_get_time(QUIC_ENGINE *qeng)
{
    if (qeng->now_cb == NULL)
        return ossl_time_now();

    return qeng->now_cb(qeng->now_cb_arg);
}

void ossl_quic_engine_set_inhibit_tick(QUIC_ENGINE *qeng, int inhibit)
{
    qeng->inhibit_tick = (inhibit != 0);
}

/*
 * QUIC Engine: Child Object Lifecycle Management
 * ==============================================
 */

QUIC_PORT *ossl_quic_engine_create_port(QUIC_ENGINE *qeng,
                                        const QUIC_PORT_ARGS *args)
{
    QUIC_PORT_ARGS largs = *args;

    if (ossl_list_port_num(&qeng->port_list) > 0)
        /* TODO(QUIC MULTIPORT): We currently support only one port. */
        return NULL;

    if (largs.engine != NULL)
        return NULL;

    largs.engine = qeng;
    return ossl_quic_port_new(&largs);
}

/*
 * QUIC Engine: Ticker-Mutator
 * ==========================
 */

/*
 * The central ticker function called by the reactor. This does everything, or
 * at least everything network I/O related. Best effort - not allowed to fail
 * "loudly".
 */
static void qeng_tick(QUIC_TICK_RESULT *res, void *arg, uint32_t flags)
{
    QUIC_ENGINE *qeng = arg;
    QUIC_PORT *port;

    res->net_read_desired   = 0;
    res->net_write_desired  = 0;
    res->tick_deadline      = ossl_time_infinite();

    if (qeng->inhibit_tick)
        return;

    /* Iterate through all ports and service them. */
    OSSL_LIST_FOREACH(port, port, &qeng->port_list) {
        QUIC_TICK_RESULT subr = {0};

        ossl_quic_port_subtick(port, &subr, flags);
        ossl_quic_tick_result_merge_into(res, &subr);
    }
}
