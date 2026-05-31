/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "internal/quic_channel.h"
#include "internal/quic_port.h"
#include "internal/quic_ssl.h"
#include "internal/ssl_unwrap.h"
#include "../ssl/quic/quic_local.h"
#include "../ssl/quic/quic_port_local.h"

#include "testutil.h"

static int test_ossl_quic_port_create_incoming(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    QUIC_LISTENER *ql;
    QUIC_CHANNEL *ch = NULL;
    int ret = 0;
    OSSL_LIB_CTX *lctx;

    if (!TEST_ptr(lctx = OSSL_LIB_CTX_new()))
        goto err;
    ctx = SSL_CTX_new_ex(lctx, NULL, OSSL_QUIC_server_method());
    if (!TEST_ptr(ctx))
        goto err;

    if (!TEST_true(ossl_quic_set_diag_title(ctx, "QUIC port qlog leak test")))
        goto err;

    listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_NO_VALIDATE);
    if (!TEST_ptr(listener))
        goto err;

    ql = QUIC_LISTENER_FROM_SSL(listener);
    if (!TEST_true(ossl_quic_port_test_and_set_peeloff(ql->port, PEELOFF_ACCEPT)))
        goto err;

    MFAIL_start();
    ch = ossl_quic_port_create_incoming(ql->port, NULL);
    MFAIL_end();

    if (ch == NULL)
        goto err;

    ret = 1;

err:
    /*
     * On success, the channel and the inner TLS are owned by the user_ssl
     * created inside port_new_handshake_layer (we passed tls=NULL). Freeing
     * user_ssl cascades through qc_cleanup() to free both the inner TLS and
     * the channel. ossl_quic_channel_free() alone would leak both.
     *
     * On failure (ch == NULL), port_make_channel already cleaned everything up.
     */
    if (ch != NULL) {
        SSL *inner_tls = ossl_quic_channel_get0_tls(ch);
        SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(inner_tls);
        SSL *user_ssl = SSL_CONNECTION_GET_USER_SSL(sc);
        SSL_free(user_ssl);
    }

    SSL_free(listener);
    SSL_CTX_free(ctx);
    OSSL_LIB_CTX_free(lctx);
    return ret;
}

static int test_ch_cleanup_idempotent(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    QUIC_LISTENER *ql;
    QUIC_CHANNEL_ARGS args = { 0 };
    QUIC_CHANNEL *ch = NULL;
    int alloc_failed = 0;
    int ret = 0;
    OSSL_LIB_CTX *lctx = NULL;

    if (!TEST_ptr(lctx = OSSL_LIB_CTX_new()))
        goto err;
    ctx = SSL_CTX_new_ex(lctx, NULL, OSSL_QUIC_server_method());
    if (!TEST_ptr(ctx))
        goto err;

    listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_NO_VALIDATE);
    if (!TEST_ptr(listener))
        goto err;
    ql = QUIC_LISTENER_FROM_SSL(listener);

    args.port = ql->port;
    args.lcidm = ql->port->lcidm;
    args.srtm = ql->port->srtm;
    args.is_server = 1;
    args.is_tserver_ch = 1;
    args.use_qlog = 1;
    args.qlog_title = "qlog";

    MFAIL_start();
    ch = ossl_quic_channel_alloc(&args);
    if (ch == NULL) {
        alloc_failed = 1;
    } else {
        if (!ossl_quic_channel_init(ch))
            alloc_failed = 1;

        /*
         * Whether init succeeded or failed, ossl_quic_channel_free() runs
         * ch_cleanup(). On the failure path that's the second ch_cleanup()
         * for this channel and must not crash or double-free.
         */
        ossl_quic_channel_free(ch);
        ch = NULL;
    }
    MFAIL_end();

    ret = alloc_failed ? 0 : 1;

err:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    OSSL_LIB_CTX_free(lctx);
    return ret;
}

int setup_tests(void)
{
    ADD_MFAIL_TEST(test_ossl_quic_port_create_incoming);
    ADD_MFAIL_TEST(test_ch_cleanup_idempotent);

    return 1;
}
