/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/quic_stream_map.h"

#if defined(_AIX)
/*
 * Some versions of AIX define macros for events and revents for use when
 * accessing pollfd structures (see Github issue #24236). That interferes
 * with our use of these names here. We simply undef them.
 */
#undef revents
#undef events
#endif

/*
 * Test Scripts
 * ============================================================================
 */

DEF_FUNC(check_rejected)
{
    QUIC_CHANNEL *ch;
    SSL *ssl, *stream;
    QUIC_STREAM *qs;
    uint64_t stream_id;
    int ok = 0;

    REQUIRE_SSL_2(ssl, stream);
    ch = ossl_quic_conn_get_channel(ssl);
    if (!TEST_ptr(ch))
        goto err;

    stream_id = SSL_get_stream_id(stream);
    qs = ossl_quic_stream_map_get_by_id(ossl_quic_channel_get_qsm(ch), stream_id);
    if (!TEST_ptr(qs))
        goto err;

    if (qs->peer_stop_sending)
        ok = 1;
    else
        F_SPIN_AGAIN();

err:

    return ok;
}

/*
 * Multi-stream test
 */
DEF_SCRIPT(multi_stream, "multi stream test")
{
    OP_SIMPLE_PAIR_CONN();
    OP_WRITE_B(C, "apple");
    OP_ACCEPT_CONN_WAIT(L, S, 0);
    OP_SET_INCOMING_STREAM_POLICY(C, SSL_INCOMING_STREAM_POLICY_ACCEPT, 42 /* error code */);
    OP_SET_INCOMING_STREAM_POLICY(S, SSL_INCOMING_STREAM_POLICY_ACCEPT, 42 /* error code */);
    OP_READ_EXPECT_B(S, "apple");
    OP_WRITE_B(S, "orange");
    OP_READ_EXPECT_B(C, "orange");

    OP_NEW_STREAM(C, C0, 0 /* bidirectional stream */);
    OP_WRITE_B(C0, "flamingo");
    OP_ACCEPT_STREAM_WAIT(S, S0, 0 /* bidirectional stream */);
    OP_READ_EXPECT_B(S0, "flamingo");
    OP_CONCLUDE(C0);
    OP_EXPECT_FIN(S0);
    OP_WRITE_B(S0, "gargoyle");
    OP_READ_EXPECT_B(C0, "gargoyle");
    OP_CONCLUDE(S0);
    OP_EXPECT_FIN(C0);

    OP_NEW_STREAM(C, C1, SSL_STREAM_FLAG_UNI);
    OP_WRITE_B(C1, "elephant");
    OP_ACCEPT_STREAM_WAIT(S, S1, SSL_STREAM_FLAG_UNI);
    OP_READ_EXPECT_B(S1, "elephant");
    OP_CONCLUDE(C1);
    OP_EXPECT_FIN(S1);
    OP_READ_FAIL(S1);
    OP_WRITE_FAIL(S1);

    OP_ACCEPT_STREAM_NONE(C, SSL_STREAM_FLAG_UNI);

    OP_NEW_STREAM(S, S2, 0 /* bidirectional stream */);
    OP_WRITE_B(S2, "frog");
    OP_ACCEPT_STREAM_WAIT(C, C2, 0 /* bidirectional stream */);
    OP_READ_EXPECT_B(C2, "frog");
    OP_CONCLUDE(S2);
    OP_EXPECT_FIN(C2);

    OP_ACCEPT_STREAM_NONE(C, 0);

    OP_NEW_STREAM(S, S3, 0 /* bidirectional stream */);
    OP_WRITE_B(S3, "mixture");
    OP_CONCLUDE(S3);

    OP_ACCEPT_STREAM_WAIT(C, C3, 0 /* bidirectional stream */);
    OP_READ_EXPECT_B(C3, "mixture");
    OP_EXPECT_FIN(C3);
    OP_WRITE_B(C3, "ramble");
    OP_READ_EXPECT_B(S3, "ramble");
    OP_CONCLUDE(C3);
    OP_EXPECT_FIN(S3);

    OP_NEW_STREAM(S, S4, SSL_STREAM_FLAG_UNI);
    OP_WRITE_B(S4, "yonder");
    OP_CONCLUDE(S4);
    OP_ACCEPT_STREAM_WAIT(C, C4, SSL_STREAM_FLAG_UNI);
    OP_ACCEPT_STREAM_NONE(C, SSL_STREAM_FLAG_UNI);
    OP_READ_EXPECT_B(C4, "yonder");
    OP_EXPECT_FIN(C4);
    OP_WRITE_FAIL(C4);

    OP_SET_INCOMING_STREAM_POLICY(C, SSL_INCOMING_STREAM_POLICY_REJECT, 42 /* application error code */);
    OP_NEW_STREAM(S, S5, 0 /* bidirectional stream */);
    OP_WRITE_B(S5, "unseen");
    OP_ACCEPT_STREAM_NONE(C, 0);
    OP_SELECT_SSL(0, S);
    OP_SELECT_SSL(1, S5);
    /*
     * Stream S5 is rejected because of reject policy on client side.
     */
    OP_FUNC(check_rejected);

    OP_SET_INCOMING_STREAM_POLICY(C, SSL_INCOMING_STREAM_POLICY_AUTO, 0 /* app. error code */);
    OP_NEW_STREAM(S, S6, 0 /* bidirectional stream */);
    OP_WRITE_B(S6, "UNSEEN");
    OP_ACCEPT_STREAM_NONE(C, 0);
    OP_SELECT_SSL(0, S);
    OP_SELECT_SSL(1, S6);
    /*
     * Remember the client `C` and server `S` got created by
     * OP_SIMPLE_PAIR_CON() which creates QUIC connection objects switched to
     * default (implicit) stream mode (see SSL_set_default_stream_mode(3ossl)).
     * The stream policy on client `C` is AUTO now which in combination with
     * default stream mode makes `C` to reject incoming stream `S6`
     * (see SSL_set_incoming_stream_policy(3ossl) for details).
     */
    OP_FUNC(check_rejected);
}

/*
 * Simple single-stream test
 */
DEF_SCRIPT(simple_stream, "single stream test")
{
    OP_SIMPLE_PAIR_CONN();
    OP_WRITE_B(C, "apple");
    OP_ACCEPT_CONN_WAIT(L, S, 0);
    OP_CONCLUDE(C);
    OP_READ_EXPECT_B(S, "apple");
    OP_EXPECT_FIN(S);
    OP_WRITE_B(S, "orange");
    OP_READ_EXPECT_B(C, "orange");
    OP_CONCLUDE(S);
    OP_EXPECT_FIN(C);
}

/*
 * Test: simple_conn
 * -----------------
 */
DEF_SCRIPT(simple_conn, "simple connection to server")
{
    size_t i;

    for (i = 0; i < 2; ++i) {
        if (i == 0) {
            OP_SIMPLE_PAIR_CONN_D();
        } else {
            OP_CLEAR();
            OP_SIMPLE_PAIR_CONN();
        }

        OP_WRITE_B(C, "apple");

        OP_ACCEPT_CONN_WAIT(L, La, 0);
        OP_ACCEPT_CONN_NONE(L);

        OP_READ_EXPECT_B(La, "apple");
        OP_WRITE_B(La, "orange");
        OP_READ_EXPECT_B(C, "orange");
    }
}

DEF_SCRIPT(simple_thread_child,
    "test that RADIX multithreading is working (child)")
{
}

/*
 * Test: simple_thread
 * -------------------
 */
DEF_SCRIPT(simple_thread,
    "test that RADIX multithreading is working")
{
    size_t i;

    for (i = 0; i < 2; ++i)
        OP_SPAWN_THREAD(simple_thread_child);
}

/*
 * Test: ssl_poll
 * --------------
 */
DEF_SCRIPT(ssl_poll_child,
    "test that SSL_poll is working (child)")
{
    OP_SLEEP(100);
    OP_WRITE_B(C0, "extra");
}

DEF_FUNC(ssl_poll_check)
{
    int ok = 0;
    SSL *La, *Lax[4];
    SSL_POLL_ITEM items[6] = { 0 }, expected_items[6] = { 0 };
    size_t result_count = 0, i;
    const struct timeval z_timeout = { 0 }, *p_timeout = &z_timeout;
    struct timeval timeout = { 0 };
    uint64_t mode;
    size_t expected_result_count;
    OSSL_TIME time_before, time_after;

    F_POP(mode);
    REQUIRE_SSL_5(La, Lax[0], Lax[1], Lax[2], Lax[3]);

    items[0].desc = SSL_as_poll_descriptor(La);
    items[0].events = 0;
    items[0].revents = 0;

    for (i = 0; i < 4; ++i) {
        items[i + 1].desc = SSL_as_poll_descriptor(Lax[i]);
        items[i + 1].events = SSL_POLL_EVENT_R | SSL_POLL_EVENT_I;
        items[i + 1].revents = 0;
    }

    items[5].desc = SSL_as_poll_descriptor(SSL_get0_listener(La));

    switch (mode) {
    case 0: /* Nothing ready */
    case 2:
        expected_result_count = 0;
        break;
    case 1: /* Various events reported correctly */
        expected_result_count = 5;
        items[0].events = SSL_POLL_EVENT_OS;
        expected_items[0].revents = SSL_POLL_EVENT_OS;

        expected_items[1].revents = SSL_POLL_EVENT_R;

        for (i = 0; i < 4; ++i) {
            items[i + 1].events |= SSL_POLL_EVENT_W;
            expected_items[i + 1].revents |= SSL_POLL_EVENT_W;
        }

        break;
    case 3: /* Blocking test */
        expected_result_count = 1;
        expected_items[1].revents = SSL_POLL_EVENT_R;

        p_timeout = &timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        break;
    case 4: /* Listener test */
        expected_result_count = 1;
        items[5].events = SSL_POLL_EVENT_IC;
        expected_items[5].revents = SSL_POLL_EVENT_IC;
        break;
    default:
        goto err;
    }

    /* Zero-timeout call. */
    result_count = SIZE_MAX;
    time_before = ossl_time_now();
    if (!TEST_true(SSL_poll(items, OSSL_NELEM(items), sizeof(SSL_POLL_ITEM),
            p_timeout, 0, &result_count)))
        goto err;

    time_after = ossl_time_now();
    if (!TEST_size_t_eq(result_count, expected_result_count))
        goto err;

    for (i = 0; i < OSSL_NELEM(items); ++i)
        if (!TEST_uint64_t_eq(items[i].revents, expected_items[i].revents))
            goto err;

    /*
     * The SSL_poll call for the blocking test definitely shouldn't have
     * returned sooner than in 100ms.
     */
    if (i == 3 && !TEST_uint64_t_ge(ossl_time2ms(ossl_time_subtract(time_after, time_before)), 100))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_SCRIPT(ssl_poll,
    "test that SSL_poll is working")
{
    size_t i;

    OP_SIMPLE_PAIR_CONN_ND();

    /* Setup streams */
    OP_NEW_STREAM(C, C0, 0);
    OP_WRITE_B(C0, "apple");

    OP_NEW_STREAM(C, C1, 0);
    OP_WRITE_B(C1, "orange");

    OP_NEW_STREAM(C, C2, 0);
    OP_WRITE_B(C2, "Strawberry");

    OP_NEW_STREAM(C, C3, 0);
    OP_WRITE_B(C3, "sync");

    OP_ACCEPT_CONN_WAIT1_ND(L, La, 0);

    OP_ACCEPT_STREAM_WAIT(La, La0, 0);
    OP_READ_EXPECT_B(La0, "apple");

    OP_ACCEPT_STREAM_WAIT(La, La1, 0);
    OP_READ_EXPECT_B(La1, "orange");

    OP_ACCEPT_STREAM_WAIT(La, La2, 0);
    OP_READ_EXPECT_B(La2, "Strawberry");

    OP_ACCEPT_STREAM_WAIT(La, La3, 0);
    OP_READ_EXPECT_B(La3, "sync");

    for (i = 0; i <= 4; ++i) {
        /* 0: Check nothing ready */
        /* 1: Check that various events are reported correctly */
        /* 2: Check nothing ready */
        /* 3: Blocking call unblocked from child thread */
        /* 4: Listener test */

        if (i == 1) {
            OP_WRITE_B(C0, "orange");
            OP_WRITE_B(C3, "sync");
            OP_READ_EXPECT_B(La3, "sync");
        } else if (i == 2) {
            OP_READ_EXPECT_B(La0, "orange");
        } else if (i == 3) {
            OP_SPAWN_THREAD(ssl_poll_child);
        } else if (i == 4) {
            OP_NEW_SSL_C(Cb);
            OP_SET_PEER_ADDR_FROM(Cb, L);
            OP_CONNECT_WAIT(Cb);
        }

        OP_SELECT_SSL(0, La);
        OP_SELECT_SSL(1, La0);
        OP_SELECT_SSL(2, La1);
        OP_SELECT_SSL(3, La2);
        OP_SELECT_SSL(4, La3);
        OP_PUSH_U64(i);
        OP_FUNC(ssl_poll_check);

        if (i == 3)
            OP_READ_EXPECT_B(La0, "extra");

        if (i == 4) {
            OP_ACCEPT_CONN_WAIT1_ND(L, Lb, 0);
            OP_NEW_STREAM(Lb, Lb0, 0);
            OP_WRITE_B(Lb0, "foo");
            OP_READ_EXPECT_B(Cb, "foo");
        }
    }
}

DEF_FUNC(check_writeable)
{
    int ok = 0;
    SSL *ssl;
    SSL_POLL_ITEM item;
    size_t result_count = 0;
    uint64_t expect;
    const struct timeval z_timeout = { 0 }, *p_timeout = &z_timeout;

    F_POP(expect);
    REQUIRE_SSL(ssl);

    item.desc = SSL_as_poll_descriptor(ssl);
    item.events = SSL_POLL_EVENT_W;
    item.revents = 0;

    /* Zero-timeout call. */
    result_count = SIZE_MAX;
    if (!TEST_true(SSL_poll(&item, 1, sizeof(SSL_POLL_ITEM),
            p_timeout, 0, &result_count)))
        goto err;

    ok = (!!(item.revents & SSL_POLL_EVENT_W) == expect);

err:
    return ok;
}

DEF_SCRIPT(check_cwm, "check stream obeys cwm")
{
    OP_SIMPLE_PAIR_CONN();

    /* Create the initial stream by writing some data */
    OP_WRITE_RAND(C, 1024);

    /* We should be writeable at the start */
    OP_PUSH_U64(1);
    OP_SELECT_SSL(0, C);
    OP_FUNC(check_writeable);

    /* Default stream cwm is 512k (we already sent 1k). Consume all the rest */
    OP_WRITE_RAND(C, 511 * 1024);

    /* Confirm we are no longer writeable */
    OP_PUSH_U64(0);
    OP_SELECT_SSL(0, C);
    OP_FUNC(check_writeable);

    /* We now expect writes to fail */
    OP_WRITE_FAIL(C);
}

struct mutcbk_ctx {
    QUIC_PKT_HDR mutctx_qhdrin;
    OSSL_QTX_IOVEC mutctx_iov;
    const unsigned char *mutctx_inject;
    size_t mutctx_inject_sz;
    int mutctx_done;
};

static int mutcbk_inject_frames(const QUIC_PKT_HDR *hdrin,
    const OSSL_QTX_IOVEC *iovecin, size_t numin, QUIC_PKT_HDR **hdrout,
    const OSSL_QTX_IOVEC **iovecout, size_t *numout, void *arg)
{
    struct mutcbk_ctx *mutctx = (struct mutcbk_ctx *)arg;
    size_t i;
    size_t grow_allowance = 1200; /* QUIC_MIN_INITIAL_DGRAM_LEN */
    size_t bufsz = 0;
    char *buf;

    /*
     * make injection callback a one shot event,
     * callback is invoked for every packet we
     * want to modify only one packet here.
     */
    if (mutctx->mutctx_done)
        return 0;

    mutctx->mutctx_done = 1;

    for (i = 0; i < numin; i++)
        bufsz += iovecin[i].buf_len;

    mutctx->mutctx_iov.buf_len = bufsz; /* keeps old size */
    grow_allowance -= (bufsz < grow_allowance) ? bufsz : grow_allowance;
    /* AEAD tag (16 bytes) + long header (14 bytes) */
    grow_allowance -= (30 < grow_allowance) ? 30 : grow_allowance;

    grow_allowance -= (hdrin->dst_conn_id.id_len < grow_allowance) ? hdrin->dst_conn_id.id_len : grow_allowance;
    grow_allowance -= (hdrin->src_conn_id.id_len < grow_allowance) ? hdrin->src_conn_id.id_len : grow_allowance;

    if (grow_allowance == 0) {
        TEST_info("%s not enough space to inject", __func__);
        return 0;
    }
    bufsz += grow_allowance;

    /* discard const */
    OPENSSL_free((char *)mutctx->mutctx_iov.buf);
    mutctx->mutctx_iov.buf = OPENSSL_malloc(bufsz);
    /* discard const */
    buf = (char *)mutctx->mutctx_iov.buf;
    if (buf == NULL) {
        TEST_info("%s OPENSSL_malloc() failed", __func__);
        return 0;
    }

    for (i = 0; i < numin; i++) {
        memcpy(buf, iovecin[i].buf, iovecin[i].buf_len);
        buf += iovecin[i].buf_len;
    }

    /* discard const */
    buf = (char *)mutctx->mutctx_iov.buf;
    if (mutctx->mutctx_inject != NULL) {
        memmove(buf + mutctx->mutctx_inject_sz, buf,
            mutctx->mutctx_iov.buf_len);
        memcpy(buf, mutctx->mutctx_inject, mutctx->mutctx_inject_sz);
    }
    /*
     * perhaps needed to have not looked at yet
     */
    mutctx->mutctx_qhdrin = *hdrin;
    *hdrout = &mutctx->mutctx_qhdrin;
    mutctx->mutctx_iov.buf_len += mutctx->mutctx_inject_sz;
    *iovecout = &mutctx->mutctx_iov;
    *numout = 1;

    return 1;
}

static void mutcbk_finish_injecct_frames(void *arg)
{
    struct mutcbk_ctx *mutctx = (struct mutcbk_ctx *)arg;

    OPENSSL_free((char *)mutctx->mutctx_iov.buf);
    mutctx->mutctx_iov.buf = NULL;
}

/* 16 path challenge frames */
#define PATH_CHALLENGE_FRAMES \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"                \
    "\x1a"                    \
    "ABCDEFGH"

DEF_FUNC(mount_flood)
{
    int ok = 0;
    SSL *ssl;
    QUIC_CHANNEL *ch;
    static struct mutcbk_ctx mutctx = { 0 };
    static const unsigned char *inject_frames = (const unsigned char *)PATH_CHALLENGE_FRAMES;

    mutctx.mutctx_inject = inject_frames;
    mutctx.mutctx_inject_sz = sizeof(PATH_CHALLENGE_FRAMES) - 1;
    REQUIRE_SSL(ssl);
    ch = ossl_quic_conn_get_channel(ssl);
    if (!TEST_ptr(ch))
        goto err;

    if (!TEST_true(ossl_quic_channel_set_mutator(ch, mutcbk_inject_frames,
            mutcbk_finish_injecct_frames, &mutctx)))
        goto err;
    ok = 1;
err:
    return ok;
}

DEF_FUNC(check_flood_stats)
{
    int ok = 0;
    SSL *ssl;
    QUIC_CHANNEL *ch;
    uint64_t path_response_count;
    uint64_t path_challenge_count;

    REQUIRE_SSL(ssl);
    ch = ossl_quic_conn_get_channel(ssl);
    if (!TEST_ptr(ch))
        goto err;

    path_challenge_count = ossl_quic_channel_get_path_challenge_count(ch);
    path_response_count = ossl_quic_channel_get_path_response_count(ch);

    /*
     * The flood is delivered over a real socket and processed by the
     * connection's assist thread asynchronously, so give it a chance to
     * catch up rather than failing on the first observation.
     */
    if (path_challenge_count < 16 || path_response_count < 1)
        F_SPIN_AGAIN();

    if (!TEST_uint64_t_eq(path_challenge_count, 16))
        goto err;
    if (!TEST_uint64_t_eq(path_response_count, 1))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_SCRIPT(check_pc_flood, "check path challenge flood")
{
    OP_SIMPLE_PAIR_CONN();
    OP_SELECT_SSL(0, C);
    OP_FUNC(mount_flood);
    OP_ACCEPT_CONN_WAIT(L, S, 0);
    OP_WRITE_B(C, "attack");
    OP_SELECT_SSL(0, S);
    OP_FUNC(check_flood_stats);
}

/*
 * Test to make sure that SSL_accept_connection returns the same ssl object
 * that is used in the various TLS callbacks
 *
 * Unlike TCP, QUIC processes new connections independently from their
 * acceptance, and so we need to pre-allocate tls objects to return during
 * connection acceptance via the user_ssl.  This is just a quic test to validate
 * that:
 * 1) The new callback to inform the user of a new pending ssl acceptance works
 *    properly
 * 2) That the object returned from SSL_accept_connection matches the one passed
 *    to various callbacks
 *
 * It would be better as its own test, but currently the tserver used in the
 * other quic_tests doesn't actually accept connections (it pre-creates them
 * and fixes them up in place), so testing there is not feasible at the moment
 *
 * For details on this issue see:
 * https://github.com/openssl/project/issues/918
 */
static SSL *pending_ssl_obj = NULL;
static SSL *client_hello_ssl_obj = NULL;
static int check_pending_match = 0;
static int pending_cb_called = 0;
static int hello_cb_called = 0;

static int new_pending_cb(SSL_CTX *ctx, SSL *new_ssl, void *arg)
{
    pending_ssl_obj = new_ssl;
    pending_cb_called = 1;
    return 1;
}

static int client_hello_cb(SSL *s, int *al, void *arg)
{
    client_hello_ssl_obj = s;
    hello_cb_called = 1;
    return 1;
}

DEF_FUNC(init_pending_test)
{
    pending_ssl_obj = NULL;
    client_hello_ssl_obj = NULL;
    check_pending_match = 0;
    pending_cb_called = 0;
    hello_cb_called = 0;

    return 1;
}

DEF_FUNC(check_pending)
{
    int ok = 0;
    SSL *conn;

    REQUIRE_SSL(conn);

    if (check_pending_match) {
        if (!TEST_true(pending_cb_called))
            goto err;

        if (!TEST_true(hello_cb_called))
            goto err;

        if (!TEST_ptr_eq(pending_ssl_obj, client_hello_ssl_obj))
            goto err;

        if (!TEST_ptr_eq(pending_ssl_obj, conn))
            goto err;

        pending_ssl_obj = client_hello_ssl_obj = NULL;
        check_pending_match = 0;
        pending_cb_called = hello_cb_called = 0;
    }

    ok = 1;
err:
    return ok;
}

DEF_FUNC(new_listener)
{
    int ok = 0;
    SSL_CTX *ctx = NULL;
    SSL *listener;
    const char *name;

    F_POP(name);

    if (!TEST_ptr(ctx = SSL_CTX_new(OSSL_QUIC_server_method())))
        goto err;

#if defined(OPENSSL_THREADS)
    if (!TEST_true(SSL_CTX_set_domain_flags(ctx,
            SSL_DOMAIN_FLAG_MULTI_THREAD
                | SSL_DOMAIN_FLAG_BLOCKING)))
        goto err;
#endif

    if (!TEST_true(ssl_ctx_configure(ctx, 1)))
        goto err;

    SSL_CTX_set_new_pending_conn_cb(ctx, new_pending_cb, NULL);
    SSL_CTX_set_client_hello_cb(ctx, client_hello_cb, NULL);
    check_pending_match = 1;
    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;

    if (!TEST_true(ssl_attach_bio_dgram(listener, 0, NULL))) {
        SSL_free(listener);
        goto err;
    }

    if (!TEST_true(RADIX_PROCESS_set_ssl(RP(), name, listener))) {
        SSL_free(listener);
        goto err;
    }

    ok = 1;
err:
    /* SSL object will hold ref, we don't need it */
    SSL_CTX_free(ctx);
    return ok;
}

DEF_SCRIPT(check_ctx_cbks, "Check new_pending and client_hello callbacks")
{
    OP_FUNC(init_pending_test);
    OP_PUSH_PZ("L");
    OP_FUNC(new_listener);
    OP_LISTEN(L);
    OP_NEW_SSL_C(C);
    OP_SET_PEER_ADDR_FROM(C, L);
    OP_CONNECT_WAIT(C);
    OP_ACCEPT_CONN_WAIT(L, S, 0);
    OP_SELECT_SSL(0, S);
    OP_FUNC(check_pending);
}

DEF_FUNC(check_stream_reset_5)
{
    int ok = 0;
    SSL *ssl;
    uint64_t aec = 0;
    int state;

    REQUIRE_SSL(ssl);

    state = SSL_get_stream_read_state(ssl);
    if (state != SSL_STREAM_STATE_RESET_REMOTE)
        F_SPIN_AGAIN();

    if (!TEST_true(SSL_get_stream_read_error_code(ssl, &aec)))
        goto err;

    if (!TEST_uint64_t_eq(aec, 42))
        goto err;

    ok = 1;
err:
    return ok;
}

/*
 * script_5 - script_106 are place holders for tests we
 * currently keep in test/quic_multistream_test.c.
 * We need to move those here so we can get rid off
 * QUIC T-server mock-up.
 *
 * there should be one PR for each script being moved here,
 * to make reviewer's life easier. Once all scripts will be
 * moved we can find better names for script_5, ..., script_106.
 *
 * The scaffolding here hopes to avoid conflicts in 'scripts'
 * array below when more PRs will be in flight.
 */

/* 5. Test stream reset functionality */
DEF_SCRIPT(script_5, "Test stream reset functionality")
{
    OP_SIMPLE_PAIR_CONN_ND();

    OP_NEW_STREAM(C, Ca, 0 /* bidirectional */);
    OP_NEW_STREAM(C, Cb, 0 /* bidirectional */);

    OP_WRITE(Ca, "apple", 5);
    OP_STREAM_RESET(Ca, 42);

    OP_WRITE(Cb, "strawberry", 10);

    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0); /* first stream = Ca */
    OP_ACCEPT_STREAM_WAIT(S, Sb, 0); /* second stream = Cb */

    /* Reset disrupts read of already-sent data */
    OP_SELECT_SSL(0, Sa);
    OP_FUNC(check_stream_reset_5);

    OP_READ_EXPECT(Sb, "strawberry", 10);
}

DEF_FUNC(check_stream_stopped_6)
{
    int ok = 0;
    SSL *ssl;

    REQUIRE_SSL(ssl);

    if (SSL_get_stream_write_state(ssl) != SSL_STREAM_STATE_RESET_LOCAL)
        F_SPIN_AGAIN();

    ok = 1;
err:
    return ok;
}

/* 6. Test STOP_SENDING functionality */
DEF_SCRIPT(script_6, "Test STOP_SENDING functionality")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_NEW_STREAM(S, Sa, 0 /* bidirectional */);
    OP_WRITE(Sa, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(C, Ca, 0);
    OP_UNBIND(Ca);
    OP_ACCEPT_STREAM_NONE(C, 0);

    OP_SELECT_SSL(0, Sa);
    OP_FUNC(check_stream_stopped_6);
}

/* 7. Unidirectional default stream mode test (client sends first) */
DEF_SCRIPT(script_7, "Unidirectional default stream mode (client sends first)")
{
    OP_SIMPLE_PAIR_CONN();
    OP_SET_DEFAULT_STREAM_MODE(C, SSL_DEFAULT_STREAM_MODE_AUTO_UNI);
    OP_WRITE(C, "apple", 5);

    OP_ACCEPT_CONN_WAIT(L, S, 0);
    OP_READ_EXPECT(S, "apple", 5);
    OP_WRITE_FAIL(S);
}

/* 8. Unidirectional default stream mode test (server sends first) */
DEF_SCRIPT(script_8, "Unidirectional default stream mode (server sends first)")
{
    OP_SIMPLE_PAIR_CONN();
    OP_SET_DEFAULT_STREAM_MODE(C, SSL_DEFAULT_STREAM_MODE_AUTO_UNI);

    OP_ACCEPT_CONN_WAIT(L, S, 0);
    OP_NEW_STREAM(S, Sa, SSL_STREAM_FLAG_UNI);
    OP_WRITE(Sa, "apple", 5);

    OP_READ_EXPECT(C, "apple", 5);
    OP_WRITE_FAIL(C);
}

/* 9. Unidirectional default stream mode test (server sends first on bidi) */
DEF_SCRIPT(script_9, "Unidirectional default stream mode (server sends bidi first)")
{
    OP_SIMPLE_PAIR_CONN();
    OP_SET_DEFAULT_STREAM_MODE(C, SSL_DEFAULT_STREAM_MODE_AUTO_UNI);

    OP_ACCEPT_CONN_WAIT(L, S, 0);
    OP_NEW_STREAM(S, Sa, 0 /* bidirectional */);
    OP_WRITE(Sa, "apple", 5);

    OP_READ_EXPECT(C, "apple", 5);
    OP_WRITE(C, "orange", 6);
    OP_READ_EXPECT(Sa, "orange", 6);
}

/* 10. Shutdown */
DEF_SCRIPT(script_10, "Shutdown test")
{
    OP_SIMPLE_PAIR_CONN();

    OP_WRITE(C, "apple", 5);
    OP_ACCEPT_CONN_WAIT(L, S, 0);
    OP_READ_EXPECT(S, "apple", 5);

    OP_SHUTDOWN_WAIT(C, 0, 0, NULL);
    OP_EXPECT_CONN_CLOSE_INFO(C, 0, 1, 0);
    OP_EXPECT_CONN_CLOSE_INFO(S, 0, 1, 1);
}

/* 11. Many threads accepted on the same client connection */
DEF_SCRIPT(script_11_child_0,
    "child: accept stream from C, read, sleep, expect FIN")
{
    OP_ACCEPT_STREAM_WAIT(C, C0, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_READ_EXPECT_B(C0, "foo");
    OP_SLEEP(10);
    OP_EXPECT_FIN(C0);
}

DEF_SCRIPT(script_11_child_1,
    "child: accept stream from C, read, sleep, expect FIN")
{
    OP_ACCEPT_STREAM_WAIT(C, C1, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_READ_EXPECT_B(C1, "foo");
    OP_SLEEP(10);
    OP_EXPECT_FIN(C1);
}

DEF_SCRIPT(script_11_child_2,
    "child: accept stream from C, read, sleep, expect FIN")
{
    OP_ACCEPT_STREAM_WAIT(C, C2, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_READ_EXPECT_B(C2, "foo");
    OP_SLEEP(10);
    OP_EXPECT_FIN(C2);
}

DEF_SCRIPT(script_11_child_3,
    "child: accept stream from C, read, sleep, expect FIN")
{
    OP_ACCEPT_STREAM_WAIT(C, C3, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_READ_EXPECT_B(C3, "foo");
    OP_SLEEP(10);
    OP_EXPECT_FIN(C3);
}

DEF_SCRIPT(script_11_child_4,
    "child: accept stream from C, read, sleep, expect FIN")
{
    OP_ACCEPT_STREAM_WAIT(C, C4, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_READ_EXPECT_B(C4, "foo");
    OP_SLEEP(10);
    OP_EXPECT_FIN(C4);
}

DEF_SCRIPT(script_11, "Many threads accepted on the same client connection")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_BIND(C0);
    OP_BIND(C1);
    OP_BIND(C2);
    OP_BIND(C3);
    OP_BIND(C4);
    OP_BIND(Sa);
    OP_BIND(Sb);
    OP_BIND(Sc);
    OP_BIND(Sd);
    OP_BIND(Se);

    OP_SPAWN_THREAD(script_11_child_0);
    OP_SPAWN_THREAD(script_11_child_1);
    OP_SPAWN_THREAD(script_11_child_2);
    OP_SPAWN_THREAD(script_11_child_3);
    OP_SPAWN_THREAD(script_11_child_4);

    OP_NEW_STREAM(S, Sa, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_WRITE_B(Sa, "foo");
    OP_CONCLUDE(Sa);

    OP_NEW_STREAM(S, Sb, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_WRITE_B(Sb, "foo");
    OP_CONCLUDE(Sb);

    OP_NEW_STREAM(S, Sc, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_WRITE_B(Sc, "foo");
    OP_CONCLUDE(Sc);

    OP_NEW_STREAM(S, Sd, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_WRITE_B(Sd, "foo");
    OP_CONCLUDE(Sd);

    OP_NEW_STREAM(S, Se, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_WRITE_B(Se, "foo");
    OP_CONCLUDE(Se);
    OP_SLEEP(10);
}

/* 12. Many threads initiated on the same client connection */
DEF_SCRIPT(script_12_child_0,
    "child: create stream on C, write, conclude")
{
    OP_NEW_STREAM(C, C0, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_WRITE_B(C0, "foo");
    OP_CONCLUDE(C0);
}

DEF_SCRIPT(script_12_child_1,
    "child: create stream on C, write, conclude")
{
    OP_NEW_STREAM(C, C1, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_WRITE_B(C1, "foo");
    OP_CONCLUDE(C1);
}

DEF_SCRIPT(script_12_child_2,
    "child: create stream on C, write, conclude")
{
    OP_NEW_STREAM(C, C2, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_WRITE_B(C2, "foo");
    OP_CONCLUDE(C2);
}

DEF_SCRIPT(script_12_child_3,
    "child: create stream on C, write, conclude")
{
    OP_NEW_STREAM(C, C3, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_WRITE_B(C3, "foo");
    OP_CONCLUDE(C3);
}

DEF_SCRIPT(script_12_child_4,
    "child: create stream on C, write, conclude")
{
    OP_NEW_STREAM(C, C4, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_WRITE_B(C4, "foo");
    OP_CONCLUDE(C4);
}

DEF_SCRIPT(script_12, "Many threads initiated on the same client connection")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_BIND(C0);
    OP_BIND(C1);
    OP_BIND(C2);
    OP_BIND(C3);
    OP_BIND(C4);
    OP_BIND(Sa);
    OP_BIND(Sb);
    OP_BIND(Sc);
    OP_BIND(Sd);
    OP_BIND(Se);

    OP_SPAWN_THREAD(script_12_child_0);
    OP_SPAWN_THREAD(script_12_child_1);
    OP_SPAWN_THREAD(script_12_child_2);
    OP_SPAWN_THREAD(script_12_child_3);
    OP_SPAWN_THREAD(script_12_child_4);

    OP_ACCEPT_STREAM_WAIT(S, Sa, OP_F_REPLACE_STREAM);
    OP_READ_EXPECT_B(Sa, "foo");
    OP_EXPECT_FIN(Sa);
    OP_ACCEPT_STREAM_WAIT(S, Sb, OP_F_REPLACE_STREAM);
    OP_READ_EXPECT_B(Sb, "foo");
    OP_EXPECT_FIN(Sb);
    OP_ACCEPT_STREAM_WAIT(S, Sc, OP_F_REPLACE_STREAM);
    OP_READ_EXPECT_B(Sc, "foo");
    OP_EXPECT_FIN(Sc);
    OP_ACCEPT_STREAM_WAIT(S, Sd, OP_F_REPLACE_STREAM);
    OP_READ_EXPECT_B(Sd, "foo");
    OP_EXPECT_FIN(Sd);
    OP_ACCEPT_STREAM_WAIT(S, Se, OP_F_REPLACE_STREAM);
    OP_READ_EXPECT_B(Se, "foo");
    OP_EXPECT_FIN(Se);
    OP_SLEEP(10);
}

/* 13. Many threads accepted on the same client connection (stress test) */
DEF_SCRIPT(script_13_child_1,
    "child: 10x accept stream from C, read, expect FIN, free")
{
    size_t i;

    for (i = 0; i < 10; i++) {
        OP_ACCEPT_STREAM_WAIT(C, C1, OP_F_REPLACE_STREAM);
        OP_READ_EXPECT_B(C1, "foo");
        OP_EXPECT_FIN(C1);
    }
}

DEF_SCRIPT(script_13_child_2,
    "child: 10x accept stream from C, read, expect FIN, free")
{
    size_t i;

    for (i = 0; i < 10; i++) {
        OP_ACCEPT_STREAM_WAIT(C, C2, OP_F_REPLACE_STREAM);
        OP_READ_EXPECT_B(C2, "foo");
        OP_EXPECT_FIN(C2);
    }
}

DEF_SCRIPT(script_13_child_3,
    "child: 10x accept stream from C, read, expect FIN, free")
{
    size_t i;

    for (i = 0; i < 10; i++) {
        OP_ACCEPT_STREAM_WAIT(C, C3, OP_F_REPLACE_STREAM);
        OP_READ_EXPECT_B(C3, "foo");
        OP_EXPECT_FIN(C3);
    }
}

DEF_SCRIPT(script_13_child_4,
    "child: 10x accept stream from C, read, expect FIN, free")
{
    size_t i;

    for (i = 0; i < 10; i++) {
        OP_ACCEPT_STREAM_WAIT(C, C4, OP_F_REPLACE_STREAM);
        OP_READ_EXPECT_B(C4, "foo");
        OP_EXPECT_FIN(C4);
    }
}

DEF_SCRIPT(script_13_child_5,
    "child: 10x accept stream from C, read, expect FIN, free")
{
    size_t i;

    for (i = 0; i < 10; i++) {
        OP_ACCEPT_STREAM_WAIT(C, C5, OP_F_REPLACE_STREAM);
        OP_READ_EXPECT_B(C5, "foo");
        OP_EXPECT_FIN(C5);
    }
}

DEF_SCRIPT(script_13,
    "Many threads accepted on same client connection (stress test)")
{
    size_t i;

    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    /*
     * put empty objects to radix process cache.
     * objects C1 - C5 are going to be used for
     * SSL streams in _child_1 - _child_5 threads.
     */
    OP_BIND(C1);
    OP_BIND(C2);
    OP_BIND(C3);
    OP_BIND(C4);
    OP_BIND(C5);
    OP_BIND(Sa);

    OP_SPAWN_THREAD(script_13_child_1);
    OP_SPAWN_THREAD(script_13_child_2);
    OP_SPAWN_THREAD(script_13_child_3);
    OP_SPAWN_THREAD(script_13_child_4);
    OP_SPAWN_THREAD(script_13_child_5);

    for (i = 0; i < 50; ++i) {
        OP_NEW_STREAM(S, Sa, OP_F_REPLACE_STREAM);
        OP_WRITE_B(Sa, "foo");
        OP_CONCLUDE(Sa);
    }
}

/* 14. Many threads initiating on the same client connection (stress test) */
DEF_SCRIPT(script_14_child_1,
    "child: 10x create stream on C, write, conclude, free")
{
    size_t i;

    for (i = 0; i < 10; i++) {
        OP_NEW_STREAM(C, C1, OP_F_REPLACE_STREAM);
        OP_WRITE_B(C1, "foo");
        OP_CONCLUDE(C1);
    }
}

DEF_SCRIPT(script_14_child_2,
    "child: 10x create stream on C, write, conclude, free")
{
    size_t i;

    for (i = 0; i < 10; i++) {
        OP_NEW_STREAM(C, C2, OP_F_REPLACE_STREAM);
        OP_WRITE_B(C2, "foo");
        OP_CONCLUDE(C2);
    }
}

DEF_SCRIPT(script_14_child_3,
    "child: 10x create stream on C, write, conclude, free")
{
    size_t i;

    for (i = 0; i < 10; i++) {
        OP_NEW_STREAM(C, C3, OP_F_REPLACE_STREAM);
        OP_WRITE_B(C3, "foo");
        OP_CONCLUDE(C3);
    }
}

DEF_SCRIPT(script_14_child_4,
    "child: 10x create stream on C, write, conclude, free")
{
    size_t i;

    for (i = 0; i < 10; i++) {
        OP_NEW_STREAM(C, C4, OP_F_REPLACE_STREAM);
        OP_WRITE_B(C4, "foo");
        OP_CONCLUDE(C4);
    }
}

DEF_SCRIPT(script_14_child_5,
    "child: 10x create stream on C, write, conclude, free")
{
    size_t i;

    for (i = 0; i < 10; i++) {
        OP_NEW_STREAM(C, C5, OP_F_REPLACE_STREAM);
        OP_WRITE_B(C5, "foo");
        OP_CONCLUDE(C5);
    }
}

DEF_SCRIPT(script_14,
    "Many threads initiating on same client connection (stress test)")
{
    size_t i;

    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_BIND(C1);
    OP_BIND(C2);
    OP_BIND(C3);
    OP_BIND(C4);
    OP_BIND(C5);
    OP_BIND(Sa);

    OP_SPAWN_THREAD(script_14_child_1);
    OP_SPAWN_THREAD(script_14_child_2);
    OP_SPAWN_THREAD(script_14_child_3);
    OP_SPAWN_THREAD(script_14_child_4);
    OP_SPAWN_THREAD(script_14_child_5);

    for (i = 0; i < 50; ++i) {
        OP_ACCEPT_STREAM_WAIT(S, Sa, OP_F_REPLACE_STREAM);
        OP_READ_EXPECT_B(Sa, "foo");
        OP_EXPECT_FIN(Sa);
    }
}

/* 15. Client sending large number of streams, MAX_STREAMS test */
DEF_SCRIPT(script_15, "Client sending large number of streams, MAX_STREAMS test")
{
    size_t i;

    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    /*
     * This will cause a protocol violation to be raised by the server if we are
     * not handling the stream limit correctly on the TX side.
     */
    for (i = 0; i < 200; ++i) {
        OP_NEW_STREAM(C, Ca, SSL_STREAM_FLAG_ADVANCE);
        OP_WRITE(Ca, "foo", 3);
        OP_CONCLUDE(Ca);
        OP_UNBIND(Ca);
    }

    /* Prove the connection is still good. */
    OP_NEW_STREAM(S, Sa, 0);
    OP_WRITE(Sa, "bar", 3);
    OP_CONCLUDE(Sa);

    OP_ACCEPT_STREAM_WAIT(C, Ca, 0);
    OP_READ_EXPECT(Ca, "bar", 3);
    OP_EXPECT_FIN(Ca);

    /*
     * Drain the queue of incoming streams. We should be able to get all 200
     * even though only 100 can be initiated at a time.
     */
    for (i = 0; i < 200; ++i) {
        OP_ACCEPT_STREAM_WAIT(S, Sb, 0);
        OP_READ_EXPECT(Sb, "foo", 3);
        OP_EXPECT_FIN(Sb);
        OP_UNBIND(Sb);
    }
}

/* 16. Server sending large number of streams, MAX_STREAMS test */
DEF_SCRIPT(script_16, "Server sending large number of streams, MAX_STREAMS test")
{
    size_t i;

    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    /*
     * This will cause a protocol violation to be raised by the client if we are
     * not handling the stream limit correctly on the TX side.
     */
    for (i = 0; i < 200; ++i) {
        OP_NEW_STREAM(S, Sa, SSL_STREAM_FLAG_ADVANCE);
        OP_WRITE(Sa, "foo", 3);
        OP_CONCLUDE(Sa);
        OP_UNBIND(Sa);
    }

    /* Prove that the connection is still good. */
    OP_NEW_STREAM(C, Ca, 0);
    OP_WRITE(Ca, "bar", 3);
    OP_CONCLUDE(Ca);

    OP_ACCEPT_STREAM_WAIT(S, Sb, 0);
    OP_READ_EXPECT(Sb, "bar", 3);
    OP_EXPECT_FIN(Sb);

    /* Drain the queue of incoming streams. */
    for (i = 0; i < 200; ++i) {
        OP_ACCEPT_STREAM_WAIT(C, Cb, 0);
        OP_READ_EXPECT(Cb, "foo", 3);
        OP_EXPECT_FIN(Cb);
        OP_UNBIND(Cb);
    }
}

/* 17. Key update test - unlimited */
DEF_SCRIPT(script_17, "Key update test - unlimited")
{
    size_t i;

    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_WRITE(C, "apple", 5);
    OP_READ_EXPECT(S, "apple", 5);

    OP_OVERRIDE_KEY_UPDATE(C, 1);

    for (i = 0; i < 200; ++i) {
        OP_WRITE(C, "apple", 5);
        OP_READ_EXPECT(S, "apple", 5);
        /*
         * TXKU frequency is bounded by RTT because a previous TXKU needs to be
         * acknowledged by the peer first before another one can begin. By
         * waiting this long, we eliminate any such concern and ensure as many key
         * updates as possible can occur for the purposes of this test.
         */
        OP_SKIP_TIME(100);
    }

    /* At least 5 RXKUs detected */
    OP_CHECK_KEY_UPDATE_GE(C, 5);

    /*
     * Prove the connection is still healthy by sending something in both
     * directions.
     */
    OP_WRITE(C, "xyzzy", 5);
    OP_READ_EXPECT(S, "xyzzy", 5);

    OP_WRITE(S, "plugh", 5);
    OP_READ_EXPECT(C, "plugh", 5);
}

/* 18. Key update test - RTT-bounded */
DEF_SCRIPT(script_18, "Key update test - RTT-bounded")
{
    size_t i;

    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_WRITE(C, "apple", 5);
    OP_READ_EXPECT(S, "apple", 5);

    OP_OVERRIDE_KEY_UPDATE(C, 1);

    for (i = 0; i < 200; ++i) {
        OP_WRITE(C, "apple", 5);
        OP_READ_EXPECT(S, "apple", 5);
        OP_SKIP_TIME(8);
    }

    /*
     * This time we simulate far less time passing between writes, so there are
     * fewer opportunities to initiate TXKUs. Note that we ask for a TXKU every
     * 1 packet above, which is absurd; thus this ensures we only actually
     * generate TXKUs when we are allowed to.
     */
    OP_CHECK_KEY_UPDATE_LT(C, 240);

    /*
     * Prove the connection is still healthy by sending something in both
     * directions.
     */
    OP_WRITE(C, "xyzzy", 5);
    OP_READ_EXPECT(S, "xyzzy", 5);

    OP_WRITE(S, "plugh", 5);
    OP_READ_EXPECT(C, "plugh", 5);
}

/* 19. Key update test - artificially triggered */
DEF_SCRIPT(script_19, "Key update test - artificially triggered")
{
    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_WRITE(C, "apple", 5);
    OP_READ_EXPECT(S, "apple", 5);

    OP_WRITE(C, "orange", 6);
    OP_READ_EXPECT(S, "orange", 6);

    OP_WRITE(S, "strawberry", 10);
    OP_READ_EXPECT(C, "strawberry", 10);

    OP_CHECK_KEY_UPDATE_LT(C, 1);

    OP_TRIGGER_KEY_UPDATE(C, SSL_KEY_UPDATE_REQUESTED);

    OP_WRITE(C, "orange", 6);
    OP_READ_EXPECT(S, "orange", 6);
    OP_WRITE(S, "ok", 2);

    OP_READ_EXPECT(C, "ok", 2);
    OP_CHECK_KEY_UPDATE_GE(C, 1);
}

DEF_SCRIPT(script_20, "place holder for multistrem script_20")
{
}

DEF_SCRIPT(script_21, "place holder for multistrem script_21")
{
}

DEF_SCRIPT(script_22, "place holder for multistrem script_22")
{
}

DEF_SCRIPT(script_23, "place holder for multistrem script_23")
{
}

DEF_SCRIPT(script_24, "place holder for multistrem script_24")
{
}

DEF_SCRIPT(script_25, "place holder for multistrem script_25")
{
}

DEF_SCRIPT(script_26, "place holder for multistrem script_26")
{
}

DEF_SCRIPT(script_27, "place holder for multistrem script_27")
{
}

DEF_SCRIPT(script_28, "place holder for multistrem script_28")
{
}

DEF_SCRIPT(script_29, "place holder for multistrem script_29")
{
}

DEF_SCRIPT(script_30, "place holder for multistrem script_30")
{
}

DEF_SCRIPT(script_31, "place holder for multistrem script_31")
{
}

DEF_SCRIPT(script_32, "place holder for multistrem script_32")
{
}

DEF_SCRIPT(script_33, "place holder for multistrem script_33")
{
}

DEF_SCRIPT(script_34, "place holder for multistrem script_34")
{
}

DEF_SCRIPT(script_35, "place holder for multistrem script_35")
{
}

DEF_SCRIPT(script_36, "place holder for multistrem script_36")
{
}

DEF_SCRIPT(script_37, "place holder for multistrem script_37")
{
}

DEF_SCRIPT(script_38, "place holder for multistrem script_38")
{
}

DEF_SCRIPT(script_39, "place holder for multistrem script_39")
{
}

DEF_SCRIPT(script_40, "place holder for multistrem script_40")
{
}

DEF_SCRIPT(script_41, "place holder for multistrem script_41")
{
}

DEF_SCRIPT(script_42, "place holder for multistrem script_42")
{
}

DEF_SCRIPT(script_43, "place holder for multistrem script_43")
{
}

DEF_SCRIPT(script_44, "place holder for multistrem script_44")
{
}

DEF_SCRIPT(script_45, "place holder for multistrem script_45")
{
}

DEF_SCRIPT(script_46, "place holder for multistrem script_46")
{
}

DEF_SCRIPT(script_47, "place holder for multistrem script_47")
{
}

DEF_SCRIPT(script_48, "place holder for multistrem script_48")
{
}

DEF_SCRIPT(script_49, "place holder for multistrem script_49")
{
}

DEF_SCRIPT(script_50, "place holder for multistrem script_50")
{
}

DEF_SCRIPT(script_51, "place holder for multistrem script_51")
{
}

DEF_SCRIPT(script_52, "place holder for multistrem script_52")
{
}

DEF_SCRIPT(script_53, "place holder for multistrem script_53")
{
}

DEF_SCRIPT(script_54, "place holder for multistrem script_54")
{
}

DEF_SCRIPT(script_55, "place holder for multistrem script_55")
{
}

DEF_SCRIPT(script_56, "place holder for multistrem script_56")
{
}

DEF_SCRIPT(script_57, "place holder for multistrem script_57")
{
}

DEF_SCRIPT(script_58, "place holder for multistrem script_58")
{
}

DEF_SCRIPT(script_59, "place holder for multistrem script_59")
{
}

DEF_SCRIPT(script_60, "place holder for multistrem script_60")
{
}

DEF_SCRIPT(script_61, "place holder for multistrem script_61")
{
}

DEF_SCRIPT(script_62, "place holder for multistrem script_62")
{
}

DEF_SCRIPT(script_63, "place holder for multistrem script_63")
{
}

DEF_SCRIPT(script_64, "place holder for multistrem script_64")
{
}

DEF_SCRIPT(script_65, "place holder for multistrem script_65")
{
}

DEF_SCRIPT(script_66, "place holder for multistrem script_66")
{
}

DEF_SCRIPT(script_67, "place holder for multistrem script_67")
{
}

DEF_SCRIPT(script_68, "place holder for multistrem script_68")
{
}

DEF_SCRIPT(script_69, "place holder for multistrem script_69")
{
}

DEF_SCRIPT(script_70, "place holder for multistrem script_70")
{
}

DEF_SCRIPT(script_71, "place holder for multistrem script_71")
{
}

DEF_SCRIPT(script_72, "place holder for multistrem script_72")
{
}

DEF_SCRIPT(script_73, "place holder for multistrem script_73")
{
}

DEF_SCRIPT(script_74, "place holder for multistrem script_74")
{
}

DEF_SCRIPT(script_75, "place holder for multistrem script_75")
{
}

DEF_SCRIPT(script_76, "place holder for multistrem script_76")
{
}

DEF_SCRIPT(script_77, "place holder for multistrem script_77")
{
}

DEF_SCRIPT(script_78, "place holder for multistrem script_78")
{
}

DEF_SCRIPT(script_79, "place holder for multistrem script_79")
{
}

DEF_SCRIPT(script_80, "place holder for multistrem script_80")
{
}

DEF_SCRIPT(script_81, "place holder for multistrem script_81")
{
}

DEF_SCRIPT(script_82, "place holder for multistrem script_82")
{
}

DEF_SCRIPT(script_83, "place holder for multistrem script_83")
{
}

DEF_SCRIPT(script_84, "place holder for multistrem script_84")
{
}

DEF_SCRIPT(script_85, "place holder for multistrem script_85")
{
}

DEF_SCRIPT(script_86, "place holder for multistrem script_86")
{
}

DEF_SCRIPT(script_87, "place holder for multistrem script_87")
{
}

DEF_SCRIPT(script_88, "place holder for multistrem script_88")
{
}

DEF_SCRIPT(script_89, "place holder for multistrem script_89")
{
}

DEF_SCRIPT(script_90, "place holder for multistrem script_90")
{
}

DEF_SCRIPT(script_91, "place holder for multistrem script_91")
{
}

DEF_SCRIPT(script_92, "place holder for multistrem script_92")
{
}

DEF_SCRIPT(script_93, "place holder for multistrem script_93")
{
}

DEF_SCRIPT(script_94, "place holder for multistrem script_94")
{
}

DEF_SCRIPT(script_95, "place holder for multistrem script_95")
{
}

DEF_SCRIPT(script_96, "place holder for multistrem script_96")
{
}

DEF_SCRIPT(script_97, "place holder for multistrem script_97")
{
}

DEF_SCRIPT(script_98, "place holder for multistrem script_98")
{
}

DEF_SCRIPT(script_99, "place holder for multistrem script_99")
{
}

DEF_SCRIPT(script_100, "place holder for multistrem script_100")
{
}

DEF_SCRIPT(script_101, "place holder for multistrem script_101")
{
}

DEF_SCRIPT(script_102, "place holder for multistrem script_102")
{
}

DEF_SCRIPT(script_103, "place holder for multistrem script_103")
{
}

DEF_SCRIPT(script_104, "place holder for multistrem script_104")
{
}

DEF_SCRIPT(script_105, "place holder for multistrem script_105")
{
}

DEF_SCRIPT(script_106, "place holder for multistrem script_106")
{
}

/*
 * List of Test Scripts
 * ============================================================================
 */
static SCRIPT_INFO *const scripts[] = {
    USE(simple_stream),
    USE(multi_stream),
    USE(simple_conn),
    USE(simple_thread),
    USE(ssl_poll),
    USE(check_cwm),
    USE(check_pc_flood),
    USE(check_ctx_cbks),
    USE(script_5),
    USE(script_6),
    USE(script_7),
    USE(script_8),
    USE(script_9),
    USE(script_10),
    USE(script_11),
    USE(script_12),
    USE(script_13),
    USE(script_14),
    USE(script_15),
    USE(script_16),
    USE(script_17),
    USE(script_18),
    USE(script_19),
    USE(script_20),
    USE(script_21),
    USE(script_22),
    USE(script_23),
    USE(script_24),
    USE(script_25),
    USE(script_26),
    USE(script_27),
    USE(script_28),
    USE(script_29),
    USE(script_30),
    USE(script_31),
    USE(script_32),
    USE(script_33),
    USE(script_34),
    USE(script_35),
    USE(script_36),
    USE(script_37),
    USE(script_38),
    USE(script_39),
    USE(script_40),
    USE(script_41),
    USE(script_42),
    USE(script_43),
    USE(script_44),
    USE(script_45),
    USE(script_46),
    USE(script_47),
    USE(script_48),
    USE(script_49),
    USE(script_50),
    USE(script_51),
    USE(script_52),
    USE(script_53),
    USE(script_54),
    USE(script_55),
    USE(script_56),
    USE(script_57),
    USE(script_58),
    USE(script_59),
    USE(script_60),
    USE(script_61),
    USE(script_62),
    USE(script_63),
    USE(script_64),
    USE(script_65),
    USE(script_66),
    USE(script_67),
    USE(script_68),
    USE(script_69),
    USE(script_70),
    USE(script_71),
    USE(script_72),
    USE(script_73),
    USE(script_74),
    USE(script_75),
    USE(script_76),
    USE(script_77),
    USE(script_78),
    USE(script_79),
    USE(script_80),
    USE(script_81),
    USE(script_82),
    USE(script_83),
    USE(script_84),
    USE(script_85),
    USE(script_86),
    USE(script_87),
    USE(script_88),
    USE(script_89),
    USE(script_90),
    USE(script_91),
    USE(script_92),
    USE(script_93),
    USE(script_94),
    USE(script_95),
    USE(script_96),
    USE(script_97),
    USE(script_98),
    USE(script_99),
    USE(script_100),
    USE(script_101),
    USE(script_102),
    USE(script_103),
    USE(script_104),
    USE(script_105),
    USE(script_106),
};
