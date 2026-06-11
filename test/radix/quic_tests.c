/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

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

    if (TEST_uint64_t_ne(path_challenge_count, 16))
        goto err;
    if (TEST_uint64_t_ne(path_response_count, 1))
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
        if (TEST_false(pending_cb_called))
            goto err;

        if (TEST_false(hello_cb_called))
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

/*
 * List of Test Scripts
 * ============================================================================
 */
static SCRIPT_INFO *const scripts[] = {
    USE(simple_stream),
    USE(simple_conn),
    USE(simple_thread),
    USE(ssl_poll),
    USE(check_cwm),
    USE(check_pc_flood),
    USE(check_ctx_cbks),
};
