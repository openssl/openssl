/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/quic_stream_map.h"
#include "internal/quic_reactor.h"
#include "../../ssl/rio/poll_builder.h"

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

DEF_FUNC(check_want_read)
{
    int ok = 0;
    SSL *ssl;

    REQUIRE_SSL(ssl);
    if (!TEST_int_eq(SSL_get_error(ssl, 0), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(SSL_want(ssl), SSL_READING))
        goto err;

    ok = 1;
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
 * Reject an incoming stream before a default stream has been established.
 */
DEF_SCRIPT(reject_before_default_stream, "reject before default stream")
{
    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);
    OP_SET_INCOMING_STREAM_POLICY(C, SSL_INCOMING_STREAM_POLICY_REJECT, 42);
    OP_WRITE_B(S, "unseen");
    OP_SLEEP(100);
    OP_READ_FAIL(C);
    OP_FUNC(check_want_read);
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

/*
 * Test: poll_abort_blocking
 * -------------------------
 *
 * SSL_poll(), when it has to block, registers each item's QUIC connection
 * for cross-thread notification one item at a time (poll_translate() in
 * ssl/rio/poll_immediate.c). If an item turns out to already be ready right
 * as it is being registered, translation is aborted so the readout loop can
 * retry instead of actually blocking. This exercises that abort path and
 * checks that:
 *
 *   - SSL_poll() reports success rather than spuriously failing, and
 *   - any items already registered before the abort have their blocking
 *     section correctly left (i.e. no leak in the QUIC reactor's blocking
 *     waiter count).
 *
 * The race between an item being registered and becoming ready is normally
 * vanishingly narrow, so we use ossl_quic_poll_translate_test_step_cb (test
 * instrumentation only, see ssl/rio/poll_builder.h) to deterministically
 * make the second item ready immediately before poll_translate() processes
 * it, while the first item is still mid-registration.
 */
struct poll_abort_test_ctx {
    SSL *peer_writer; /* write here to make target ready */
    SSL *target;
    uint64_t target_events;
    size_t trigger_idx;
    int made_ready; /* set by poll_abort_test_step_cb() on success */
};

static void poll_abort_test_step_cb(size_t idx, void *arg)
{
    struct poll_abort_test_ctx *ctx = arg;
    uint64_t revents = 0;
    int i;

    if (idx != ctx->trigger_idx)
        return;

    if (SSL_write(ctx->peer_writer, "x", 1) != 1)
        return;

    /* Force the data through synchronously so target is ready by the time we return. */
    for (i = 0; i < 1000; ++i) {
        if (!ossl_quic_conn_poll_events(ctx->target, ctx->target_events,
                /* do_tick = */ 1, &revents))
            return;

        if (revents != 0) {
            ctx->made_ready = 1;
            return;
        }

        OSSL_sleep(1);
    }
}

DEF_FUNC(check_poll_abort_blocking)
{
    int ok = 0;
    SSL *C, *C0, *Cb0, *Lb0;
    QUIC_CHANNEL *ch0;
    QUIC_REACTOR *rtor0;
    SSL_POLL_ITEM items[2] = { 0 };
    size_t result_count = SIZE_MAX, waiters_before, waiters_after;
    struct poll_abort_test_ctx ctx;
    const struct timeval z_timeout = { 0 };

    /*
     * C0 and Cb0 are streams of two independent client connections, and so
     * belong to two independent QUIC_REACTORs. The bug being tested for does
     * not actually require this: it reproduces just as well if all items
     * share one reactor. What needs two reactors is poll_abort_test_step_cb()
     * below, which forces Cb0 ready by ticking its reactor directly, on this
     * thread, while C0's blocking section is still open. Doing that on C0's
     * own (shared) reactor would deadlock: ossl_quic_reactor_tick() would see
     * a nonzero cur_blocking_waiters left over from C0 and call
     * rtor_notify_other_threads(), which waits on a condvar for some *other*
     * thread to clear the notifier signal - a thread that doesn't exist here.
     * Using Cb0's own, still-untouched reactor keeps that tick a no-op.
     */
    REQUIRE_SSL_4(C, C0, Cb0, Lb0);

    items[0].desc = SSL_as_poll_descriptor(C0);
    items[0].events = SSL_POLL_EVENT_R;
    items[1].desc = SSL_as_poll_descriptor(Cb0);
    items[1].events = SSL_POLL_EVENT_R;

    /* Sanity check: nothing ready yet, so SSL_poll() will need to block. */
    if (!TEST_true(SSL_poll(items, OSSL_NELEM(items), sizeof(SSL_POLL_ITEM),
            &z_timeout, 0, &result_count))
        || !TEST_size_t_eq(result_count, 0))
        goto err;

    if (!TEST_ptr(ch0 = ossl_quic_conn_get_channel(C)))
        goto err;
    rtor0 = ossl_quic_channel_get_reactor(ch0);
    waiters_before = rtor0->cur_blocking_waiters;

    ctx.peer_writer = Lb0;
    ctx.target = Cb0;
    ctx.target_events = items[1].events;
    ctx.trigger_idx = 1;
    ctx.made_ready = 0;

    ossl_quic_poll_translate_test_step_cb_arg = &ctx;
    ossl_quic_poll_translate_test_step_cb = poll_abort_test_step_cb;

    result_count = SIZE_MAX;
    /*
     * No timeout: if the abort_blocking case were instead to actually block,
     * this call would hang forever rather than fail fast.
     */
    ok = TEST_true(SSL_poll(items, OSSL_NELEM(items), sizeof(SSL_POLL_ITEM),
        NULL, 0, &result_count));

    ossl_quic_poll_translate_test_step_cb = NULL;
    ossl_quic_poll_translate_test_step_cb_arg = NULL;

    if (!ok)
        goto err;

    ok = 0;
    if (!TEST_true(ctx.made_ready)
        || !TEST_size_t_ge(result_count, 1)
        || !TEST_true((items[1].revents & SSL_POLL_EVENT_R) != 0))
        goto err;

    /* The first item's blocking-section entry must have been balanced. */
    waiters_after = rtor0->cur_blocking_waiters;
    if (!TEST_size_t_eq(waiters_after, waiters_before))
        goto err;

    ok = 1;
err:
    ossl_quic_poll_translate_test_step_cb = NULL;
    ossl_quic_poll_translate_test_step_cb_arg = NULL;
    return ok;
}

DEF_SCRIPT(poll_abort_blocking,
    "test that SSL_poll() correctly handles an item becoming ready while blocking is being set up")
{
    OP_SIMPLE_PAIR_CONN_ND();

    OP_NEW_STREAM(C, C0, 0);
    OP_WRITE_B(C0, "probe0");

    OP_ACCEPT_CONN_WAIT1_ND(L, La, 0);
    OP_ACCEPT_STREAM_WAIT(La, La0, 0);
    OP_READ_EXPECT_B(La0, "probe0");

    /* A second, independent client connection to the same listener. */
    OP_NEW_SSL_C(Cb);
    OP_SET_PEER_ADDR_FROM(Cb, L);
    OP_CONNECT_WAIT(Cb);
    OP_SET_DEFAULT_STREAM_MODE(Cb, SSL_DEFAULT_STREAM_MODE_NONE);

    OP_NEW_STREAM(Cb, Cb0, 0);
    OP_WRITE_B(Cb0, "probe1");

    OP_ACCEPT_CONN_WAIT1_ND(L, Lb, 0);
    OP_ACCEPT_STREAM_WAIT(Lb, Lb0, 0);
    OP_READ_EXPECT_B(Lb0, "probe1");

    OP_SELECT_SSL(0, C);
    OP_SELECT_SSL(1, C0);
    OP_SELECT_SSL(2, Cb0);
    OP_SELECT_SSL(3, Lb0);
    OP_FUNC(check_poll_abort_blocking);
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
     * want to modify only one packet here. Returning 0 tells the QTX the
     * packet send itself failed (tearing down the connection), so once
     * we're done mutating we must pass subsequent packets through
     * unmodified instead.
     */
    if (mutctx->mutctx_done) {
        *hdrout = (QUIC_PKT_HDR *)hdrin;
        *iovecout = iovecin;
        *numout = numin;
        return 1;
    }

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
        TEST_info("%s not enough space to inject", OPENSSL_FUNC);
        return 0;
    }
    bufsz += grow_allowance;

    /* discard const */
    OPENSSL_free((char *)mutctx->mutctx_iov.buf);
    mutctx->mutctx_iov.buf = OPENSSL_malloc(bufsz);
    /* discard const */
    buf = (char *)mutctx->mutctx_iov.buf;
    if (buf == NULL) {
        TEST_info("%s OPENSSL_malloc() failed", OPENSSL_FUNC);
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

/*
 * With client ticking disabled only its assist thread can act, so skipping fake
 * time past the 30s idle timeout keeps the server up only if the assist thread
 * keeps sending keepalives.
 */
DEF_SCRIPT(check_thread_assisted_idle,
    "thread-assisted mode keeps an idle connection alive")
{
    size_t i;

    OP_NEW_SSL_L_MEM(L);
    OP_NEW_SSL_C_TA_MEM(C);
    OP_LINK_DGRAM_PAIR(C, L);
    OP_LISTEN(L);
    OP_CONNECT_WAIT(C);

    OP_ACCEPT_CONN_WAIT(L, Sa, 0);
    OP_ACCEPT_CONN_NONE(L);

    OP_WRITE_B(C, "apple");
    OP_READ_EXPECT_B(Sa, "apple");

    OP_TICK_DISABLE(C);

    /* Step well below the keepalive interval so due PINGs can be serviced. */
    for (i = 0; i < 40; ++i) {
        OP_SKIP_TIME_WAIT(C, 1000);
        OP_EXPECT_CONNECTED(Sa);
    }

    OP_TICK_ENABLE(C);
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

/* 20. Multiple threads accept stream with socket forcibly closed (error test) */
DEF_SCRIPT(script_20_child_0,
    "child: accept stream, read, signal ready, wait, expect read failure")
{
    OP_ACCEPT_STREAM_WAIT(C, Ca, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_READ_EXPECT_B(Ca, "foo");

    OP_TRIGGER_COUNTER(0);
    OP_WAIT_COUNTER(1, 1);

    OP_READ_FAIL_WAIT(Ca);
    OP_EXPECT_SSL_ERR(Ca, SSL_ERROR_SYSCALL);
}

DEF_SCRIPT(script_20_child_1,
    "child: accept stream, read, signal ready, wait, expect read failure")
{
    OP_ACCEPT_STREAM_WAIT(C, Cb, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_READ_EXPECT_B(Cb, "foo");

    OP_TRIGGER_COUNTER(0);
    OP_WAIT_COUNTER(1, 1);

    OP_READ_FAIL_WAIT(Cb);
    OP_EXPECT_SSL_ERR(Cb, SSL_ERROR_SYSCALL);
}

DEF_SCRIPT(script_20_child_2,
    "child: accept stream, read, signal ready, wait, expect read failure")
{
    OP_ACCEPT_STREAM_WAIT(C, Cc, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_READ_EXPECT_B(Cc, "foo");

    OP_TRIGGER_COUNTER(0);
    OP_WAIT_COUNTER(1, 1);

    OP_READ_FAIL_WAIT(Cc);
    OP_EXPECT_SSL_ERR(Cc, SSL_ERROR_SYSCALL);
}

DEF_SCRIPT(script_20_child_3,
    "child: accept stream, read, signal ready, wait, expect read failure")
{
    OP_ACCEPT_STREAM_WAIT(C, Cd, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_READ_EXPECT_B(Cd, "foo");

    OP_TRIGGER_COUNTER(0);
    OP_WAIT_COUNTER(1, 1);

    OP_READ_FAIL_WAIT(Cd);
    OP_EXPECT_SSL_ERR(Cd, SSL_ERROR_SYSCALL);
}

DEF_SCRIPT(script_20_child_4,
    "child: accept stream, read, signal ready, wait, expect read failure")
{
    OP_ACCEPT_STREAM_WAIT(C, Ce, OP_F_REPLACE_STREAM /* bidirectional */);
    OP_READ_EXPECT_B(Ce, "foo");

    OP_TRIGGER_COUNTER(0);
    OP_WAIT_COUNTER(1, 1);

    OP_READ_FAIL_WAIT(Ce);
    OP_EXPECT_SSL_ERR(Ce, SSL_ERROR_SYSCALL);
}

DEF_SCRIPT(script_20, "Multiple threads accept stream with socket forcibly closed (error test)")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_BIND(Ca);
    OP_BIND(Cb);
    OP_BIND(Cc);
    OP_BIND(Cd);
    OP_BIND(Ce);
    OP_BIND(Sa);
    OP_BIND(Sb);
    OP_BIND(Sc);
    OP_BIND(Sd);
    OP_BIND(Se);

    OP_SPAWN_THREAD(script_20_child_0);
    OP_SPAWN_THREAD(script_20_child_1);
    OP_SPAWN_THREAD(script_20_child_2);
    OP_SPAWN_THREAD(script_20_child_3);
    OP_SPAWN_THREAD(script_20_child_4);

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

    OP_WAIT_COUNTER(0, 5);

    OP_CLOSE_SOCKET(C);

    OP_TRIGGER_COUNTER(1);
}

/* 21. Fault injection - unknown frame in 1-RTT packet */
static int script_21_inject_plain(RADIX_FAULT *fault, QUIC_PKT_HDR *hdr,
    unsigned char *buf, size_t len)
{
    int ok = 0;
    WPACKET wpkt;
    unsigned char frame_buf[21];
    size_t written;

    if (fault->word0 == 0 || hdr->type != fault->word0)
        return 1;

    if (!TEST_true(WPACKET_init_static_len(&wpkt, frame_buf,
            sizeof(frame_buf), 0)))
        return 0;

    if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, fault->word1)))
        goto err;

    switch (fault->word1) {
    case OSSL_QUIC_FRAME_TYPE_PATH_CHALLENGE:
    case OSSL_QUIC_FRAME_TYPE_PATH_RESPONSE:
    case OSSL_QUIC_FRAME_TYPE_RETIRE_CONN_ID:
        if (!TEST_true(WPACKET_put_bytes_u64(&wpkt, (uint64_t)0)))
            goto err;
        break;
    case OSSL_QUIC_FRAME_TYPE_MAX_DATA:
    case OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_UNI:
    case OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_BIDI:
    case OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_BIDI:
    case OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_UNI:
    case OSSL_QUIC_FRAME_TYPE_DATA_BLOCKED:
        if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, (uint64_t)0)))
            goto err;
        break;
    case OSSL_QUIC_FRAME_TYPE_STOP_SENDING:
    case OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA:
    case OSSL_QUIC_FRAME_TYPE_STREAM_DATA_BLOCKED:
        if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, (uint64_t)0))
            || !TEST_true(WPACKET_quic_write_vlint(&wpkt, (uint64_t)0)))
            goto err;
        break;
    case OSSL_QUIC_FRAME_TYPE_STREAM:
    case OSSL_QUIC_FRAME_TYPE_RESET_STREAM:
    case OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_APP:
        if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, (uint64_t)0))
            || !TEST_true(WPACKET_quic_write_vlint(&wpkt, (uint64_t)0))
            || !TEST_true(WPACKET_quic_write_vlint(&wpkt, (uint64_t)0)))
            goto err;
        break;
    case OSSL_QUIC_FRAME_TYPE_NEW_TOKEN:
        if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, (uint64_t)1))
            || !TEST_true(WPACKET_put_bytes_u8(&wpkt, (uint8_t)0)))
            goto err;
        break;
    case OSSL_QUIC_FRAME_TYPE_NEW_CONN_ID:
        /* seq number */
        if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, (uint64_t)0))
            /* retire prior to */
            || !TEST_true(WPACKET_quic_write_vlint(&wpkt, (uint64_t)0))
            /* Connection id length, arbitrary at 1 bytes */
            || !TEST_true(WPACKET_put_bytes_u8(&wpkt, (uint8_t)1))
            /* The connection id */
            || !TEST_true(WPACKET_put_bytes_u8(&wpkt, (uint8_t)0))
            /* 16 bytes total for the stateless reset token */
            || !TEST_true(WPACKET_memset(&wpkt, 0, 16)))
            goto err;

        break;
    }

    if (!TEST_true(WPACKET_get_total_written(&wpkt, &written))
        || !radix_fault_prepend_frame(fault, frame_buf, written))
        goto err;

    ok = 1;
err:
    if (ok)
        WPACKET_finish(&wpkt);
    else
        WPACKET_cleanup(&wpkt);
    return ok;
}

DEF_SCRIPT(script_21, "Fault injection - unknown frame in 1-RTT packet")
{
    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_SET_INJECT_PLAIN(S, script_21_inject_plain);

    OP_WRITE(C, "apple", 5);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(QUIC_PKT_TYPE_1RTT, OSSL_QUIC_VLINT_MAX);

    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_FRAME_ENCODING_ERROR, 0, 0);
}

/* 22. Fault injection - non-zero packet header reserved bits */
static int script_22_inject_plain(RADIX_FAULT *fault, QUIC_PKT_HDR *hdr,
    unsigned char *buf, size_t len)
{
    if (fault->word0 == 0)
        return 1;

    hdr->reserved = 1;
    return 1;
}

DEF_SCRIPT(script_22, "Fault injection - non-zero packet header reserved bits")
{
    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_SET_INJECT_PLAIN(S, script_22_inject_plain);

    OP_WRITE(C, "apple", 5);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(1, 0);

    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_PROTOCOL_VIOLATION, 0, 0);
}

/* 23. Fault injection - empty NEW_TOKEN */
static int script_23_inject_plain(RADIX_FAULT *fault, QUIC_PKT_HDR *hdr,
    unsigned char *buf, size_t len)
{
    int ok = 0;
    WPACKET wpkt;
    unsigned char frame_buf[16];
    size_t written;

    if (fault->word0 == 0 || hdr->type != QUIC_PKT_TYPE_1RTT)
        return 1;

    if (!TEST_true(WPACKET_init_static_len(&wpkt, frame_buf, sizeof(frame_buf), 0)))
        return 0;

    if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, OSSL_QUIC_FRAME_TYPE_NEW_TOKEN))
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, 0))
        || !TEST_true(WPACKET_get_total_written(&wpkt, &written))
        || !radix_fault_prepend_frame(fault, frame_buf, written))
        goto err;

    ok = 1;
err:
    if (ok)
        WPACKET_finish(&wpkt);
    else
        WPACKET_cleanup(&wpkt);
    return ok;
}

DEF_SCRIPT(script_23, "Fault injection - empty NEW_TOKEN")
{
    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_SET_INJECT_PLAIN(S, script_23_inject_plain);

    OP_WRITE(C, "apple", 5);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(1, 0);

    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_FRAME_ENCODING_ERROR, 0, 0);
}

/* 24. Fault injection - excess value of MAX_STREAMS_BIDI */
static int script_24_inject_plain(RADIX_FAULT *fault, QUIC_PKT_HDR *hdr,
    unsigned char *buf, size_t len)
{
    int ok = 0;
    WPACKET wpkt;
    unsigned char frame_buf[16];
    size_t written;

    if (fault->word0 == 0 || hdr->type != QUIC_PKT_TYPE_1RTT)
        return 1;

    if (!TEST_true(WPACKET_init_static_len(&wpkt, frame_buf, sizeof(frame_buf), 0)))
        return 0;

    if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, fault->word1))
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, (((uint64_t)1) << 60) + 1))
        || !TEST_true(WPACKET_get_total_written(&wpkt, &written))
        || !radix_fault_prepend_frame(fault, frame_buf, written))
        goto err;

    ok = 1;
err:
    if (ok)
        WPACKET_finish(&wpkt);
    else
        WPACKET_cleanup(&wpkt);
    return ok;
}

DEF_SCRIPT(script_24, "Fault injection - excess value of MAX_STREAMS_BIDI")
{
    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_SET_INJECT_PLAIN(S, script_24_inject_plain);

    OP_WRITE(C, "apple", 5);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(1, OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_BIDI);

    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_FRAME_ENCODING_ERROR, 0, 0);
}

/* 25. Fault injection - excess value of MAX_STREAMS_UNI */
DEF_SCRIPT(script_25, "Fault injection - excess value of MAX_STREAMS_UNI")
{
    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_SET_INJECT_PLAIN(S, script_24_inject_plain);

    OP_WRITE(C, "apple", 5);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(1, OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_UNI);

    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_FRAME_ENCODING_ERROR, 0, 0);
}

/* 26. Fault injection - excess value of STREAMS_BLOCKED_BIDI */
DEF_SCRIPT(script_26, "Fault injection - excess value of STREAMS_BLOCKED_BIDI")
{
    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_SET_INJECT_PLAIN(S, script_24_inject_plain);

    OP_WRITE(C, "apple", 5);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(1, OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_BIDI);

    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_STREAM_LIMIT_ERROR, 0, 0);
}

/* 27. Fault injection - excess value of STREAMS_BLOCKED_UNI */
DEF_SCRIPT(script_27, "Fault injection - excess value of STREAMS_BLOCKED_UNI")
{
    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_SET_INJECT_PLAIN(S, script_24_inject_plain);

    OP_WRITE(C, "apple", 5);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(1, OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_UNI);

    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_STREAM_LIMIT_ERROR, 0, 0);
}

/* 28. Fault injection - received RESET_STREAM for send-only stream */
static int inject_stream_frame_plain(RADIX_FAULT *fault, QUIC_PKT_HDR *hdr,
    unsigned char *buf, size_t len)
{
    int ok = 0;
    WPACKET wpkt;
    unsigned char frame_buf[32];
    size_t written;

    if (fault->word0 == 0 || hdr->type != QUIC_PKT_TYPE_1RTT)
        return 1;

    if (!TEST_true(WPACKET_init_static_len(&wpkt, frame_buf,
            sizeof(frame_buf), 0)))
        return 0;

    if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, fault->word1))
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, /* stream ID */
            fault->word0 - 1))
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, 123))
        || (fault->word1 == OSSL_QUIC_FRAME_TYPE_RESET_STREAM
            && !TEST_true(WPACKET_quic_write_vlint(&wpkt, 5))) /* final size */
        || !TEST_true(WPACKET_get_total_written(&wpkt, &written))
        || !radix_fault_prepend_frame(fault, frame_buf, written))
        goto err;

    ok = 1;
err:
    if (ok)
        WPACKET_finish(&wpkt);
    else
        WPACKET_cleanup(&wpkt);
    return ok;
}

DEF_SCRIPT(script_28, "Fault injection - received RESET_STREAM for send-only stream")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_stream_frame_plain);

    OP_NEW_STREAM(C, Ca, 0 /* bidirectional */);
    OP_WRITE(Ca, "orange", 6);

    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "orange", 6);

    OP_NEW_STREAM(C, Cb, SSL_STREAM_FLAG_UNI);
    OP_WRITE(Cb, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(S, Sb, 0);
    OP_READ_EXPECT(Sb, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(C_UNI_ID(0) + 1, OSSL_QUIC_FRAME_TYPE_RESET_STREAM);
    OP_WRITE(Sa, "fruit", 5);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_STREAM_STATE_ERROR, 0, 0);
}

/* 29. Fault injection - received RESET_STREAM for nonexistent send-only stream */
DEF_SCRIPT(script_29, "Fault injection - received RESET_STREAM for nonexistent send-only stream")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_stream_frame_plain);

    OP_NEW_STREAM(C, Ca, 0 /* bidirectional */);
    OP_WRITE(Ca, "orange", 6);

    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "orange", 6);

    OP_NEW_STREAM(C, Cb, SSL_STREAM_FLAG_UNI);
    OP_WRITE(Cb, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(S, Sb, 0);
    OP_READ_EXPECT(Sb, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(C_UNI_ID(1) + 1, OSSL_QUIC_FRAME_TYPE_RESET_STREAM);
    OP_WRITE(Sa, "fruit", 5);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_STREAM_STATE_ERROR, 0, 0);
}

/* 30. Fault injection - received STOP_SENDING for receive-only stream */
DEF_SCRIPT(script_30, "Fault injection - received STOP_SENDING for receive-only stream")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_stream_frame_plain);

    OP_NEW_STREAM(S, Sa, SSL_STREAM_FLAG_UNI);
    OP_WRITE(Sa, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(C, Ca, 0);
    OP_READ_EXPECT(Ca, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(S_UNI_ID(0) + 1, OSSL_QUIC_FRAME_TYPE_STOP_SENDING);

    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_STREAM_STATE_ERROR, 0, 0);
}

/* 31. Fault injection - received STOP_SENDING for nonexistent receive-only stream */
DEF_SCRIPT(script_31, "Fault injection - received STOP_SENDING for nonexistent receive-only stream")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_stream_frame_plain);

    OP_NEW_STREAM(S, Sa, SSL_STREAM_FLAG_UNI);
    OP_WRITE(Sa, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(C, Ca, 0);
    OP_READ_EXPECT(Ca, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(C_UNI_ID(0) + 1, OSSL_QUIC_FRAME_TYPE_STOP_SENDING);
    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_STREAM_STATE_ERROR, 0, 0);
}

/* 32. Fault injection - STREAM frame for nonexistent stream */
static int inject_stream_data_frame_plain(RADIX_FAULT *fault, QUIC_PKT_HDR *hdr,
    unsigned char *buf, size_t len)
{
    int ok = 0;
    WPACKET wpkt;
    unsigned char frame_buf[64];
    size_t written;
    uint64_t type = OSSL_QUIC_FRAME_TYPE_STREAM_OFF_LEN, offset, flen, i;

    if (hdr->type != QUIC_PKT_TYPE_1RTT)
        return 1;

    switch (fault->word1) {
    default:
        return 0;
    case 0:
        return 1;
    case 1:
        offset = 0;
        flen = 0;
        break;
    case 2:
        offset = (((uint64_t)1) << 62) - 1;
        flen = 5;
        break;
    case 3:
        offset = 1 * 1024 * 1024 * 1024; /* 1G */
        flen = 5;
        break;
    case 4:
        offset = 0;
        flen = 1;
        break;
    }

    if (!TEST_true(WPACKET_init_static_len(&wpkt, frame_buf,
            sizeof(frame_buf), 0)))
        return 0;

    if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, type))
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, /* stream ID */
            fault->word0 - 1))
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, offset))
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, flen)))
        goto err;

    for (i = 0; i < flen; ++i)
        if (!TEST_true(WPACKET_put_bytes_u8(&wpkt, 0x42)))
            goto err;

    if (!TEST_true(WPACKET_get_total_written(&wpkt, &written))
        || !radix_fault_prepend_frame(fault, frame_buf, written))
        goto err;

    ok = 1;
err:
    if (ok)
        WPACKET_finish(&wpkt);
    else
        WPACKET_cleanup(&wpkt);
    return ok;
}

DEF_SCRIPT(script_32, "Fault injection - STREAM frame for nonexistent stream")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_stream_data_frame_plain);

    OP_NEW_STREAM(S, Sa, SSL_STREAM_FLAG_UNI);
    OP_WRITE(Sa, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(C, Ca, 0);
    OP_READ_EXPECT(Ca, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(C_UNI_ID(0) + 1, 1);
    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_STREAM_STATE_ERROR, 0, 0);
}

/* 33. Fault injection - STREAM frame with illegal offset */
DEF_SCRIPT(script_33, "Fault injection - STREAM frame with illegal offset")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_stream_data_frame_plain);

    OP_NEW_STREAM(C, Ca, 0 /* bidirectional */);
    OP_WRITE(Ca, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(C_BIDI_ID(0) + 1, 2);
    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_FRAME_ENCODING_ERROR, 0, 0);
}

DEF_SCRIPT(script_34, "Fault injection - STREAM frame which exceeds FC")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_stream_data_frame_plain);

    OP_NEW_STREAM(C, Ca, 0 /* bidirectional */);
    OP_WRITE(Ca, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(C_BIDI_ID(0) + 1, 3);
    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_FLOW_CONTROL_ERROR, 0, 0);
}

/* 35. Fault injection - MAX_STREAM_DATA for receive-only stream */
DEF_SCRIPT(script_35, "Fault injection - MAX_STREAM_DATA for receive-only stream")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_stream_frame_plain);

    OP_NEW_STREAM(S, Sa, SSL_STREAM_FLAG_UNI);
    OP_WRITE(Sa, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(C, Ca, 0);
    OP_READ_EXPECT(Ca, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(S_UNI_ID(0) + 1, OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA);

    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_STREAM_STATE_ERROR, 0, 0);
}

/* 36. Fault injection - MAX_STREAM_DATA for nonexistent stream */
DEF_SCRIPT(script_36, "Fault injection - MAX_STREAM_DATA for nonexistent stream")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_stream_frame_plain);

    OP_NEW_STREAM(S, Sa, SSL_STREAM_FLAG_UNI);
    OP_WRITE(Sa, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(C, Ca, 0);
    OP_READ_EXPECT(Ca, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(C_BIDI_ID(0) + 1, OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA);
    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_STREAM_STATE_ERROR, 0, 0);
}

/* 37. Fault injection - STREAM_DATA_BLOCKED for send-only stream */
DEF_SCRIPT(script_37, "Fault injection - STREAM_DATA_BLOCKED for send-only stream")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_stream_frame_plain);

    OP_NEW_STREAM(C, Ca, SSL_STREAM_FLAG_UNI);
    OP_WRITE(Ca, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_NEW_STREAM(S, Sb, SSL_STREAM_FLAG_UNI);
    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(C_UNI_ID(0) + 1, OSSL_QUIC_FRAME_TYPE_STREAM_DATA_BLOCKED);
    OP_WRITE(Sb, "orange", 5);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_STREAM_STATE_ERROR, 0, 0);
}

/* 38. Fault injection - STREAM_DATA_BLOCKED for non-existent stream */
DEF_SCRIPT(script_38, "Fault injection - STREAM_DATA_BLOCKED for non-existent stream")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_stream_frame_plain);

    OP_NEW_STREAM(C, Ca, SSL_STREAM_FLAG_UNI);
    OP_WRITE(Ca, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(C_BIDI_ID(0) + 1, OSSL_QUIC_FRAME_TYPE_STREAM_DATA_BLOCKED);

    OP_NEW_STREAM(S, Sb, SSL_STREAM_FLAG_UNI);
    OP_WRITE(Sb, "orange", 5);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_STREAM_STATE_ERROR, 0, 0);
}

/* 39. Fault injection - NEW_CONN_ID with zero-len CID */
static int inject_new_conn_id_plain(RADIX_FAULT *fault, QUIC_PKT_HDR *hdr,
    unsigned char *buf, size_t len)
{
    int ok = 0;
    WPACKET wpkt;
    unsigned char frame_buf[64];
    size_t i, written;
    uint64_t seq_no = 0, retire_prior_to = 0;
    QUIC_CONN_ID new_cid = { 0 };

    if (hdr->type != QUIC_PKT_TYPE_1RTT)
        return 1;

    switch (fault->word1) {
    case 0:
        return 1;
    case 1:
        new_cid.id_len = 0;
        break;
    case 2:
        new_cid.id_len = 21;
        break;
    case 3:
        new_cid.id_len = 1;
        new_cid.id[0] = 0x55;

        seq_no = 0;
        retire_prior_to = 1;
        break;
    case 4:
        /* Use our actual CID so we don't break connectivity. */
        ossl_quic_channel_get_diag_local_cid(fault->ch, &new_cid);

        seq_no = 2;
        retire_prior_to = 2;
        break;
    case 5:
        /*
         * Use a bogus CID which will need to be ignored if connectivity is to
         * be continued.
         */
        new_cid.id_len = 8;
        new_cid.id[0] = 0x55;

        seq_no = 1;
        retire_prior_to = 1;
        break;
    }

    if (!TEST_true(WPACKET_init_static_len(&wpkt, frame_buf,
            sizeof(frame_buf), 0)))
        return 0;

    if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, OSSL_QUIC_FRAME_TYPE_NEW_CONN_ID))
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, seq_no)) /* seq no */
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, retire_prior_to)) /* retire prior to */
        || !TEST_true(WPACKET_put_bytes_u8(&wpkt, new_cid.id_len))) /* len */
        goto err;

    for (i = 0; i < new_cid.id_len && i < OSSL_NELEM(new_cid.id); ++i)
        if (!TEST_true(WPACKET_put_bytes_u8(&wpkt, new_cid.id[i])))
            goto err;

    for (; i < new_cid.id_len; ++i)
        if (!TEST_true(WPACKET_put_bytes_u8(&wpkt, 0x55)))
            goto err;

    for (i = 0; i < QUIC_STATELESS_RESET_TOKEN_LEN; ++i)
        if (!TEST_true(WPACKET_put_bytes_u8(&wpkt, 0x42)))
            goto err;

    if (!TEST_true(WPACKET_get_total_written(&wpkt, &written))
        || !radix_fault_prepend_frame(fault, frame_buf, written))
        goto err;

    ok = 1;
err:
    if (ok)
        WPACKET_finish(&wpkt);
    else
        WPACKET_cleanup(&wpkt);
    return ok;
}

DEF_SCRIPT(script_39, "Fault injection - NEW_CONN_ID with zero-len CID")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_new_conn_id_plain);

    OP_NEW_STREAM(C, Ca, 0 /* bidirectional */);
    OP_WRITE(Ca, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(0, 1);
    OP_WRITE(Sa, "orange", 5);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_FRAME_ENCODING_ERROR, 0, 0);
}

/* 40. Shutdown flush test */
static unsigned char script_40_data[1024] = "strawberry";

DEF_SCRIPT(script_40, "Shutdown flush test")
{
    size_t i;

    OP_SIMPLE_PAIR_CONN_ND();

    OP_NEW_STREAM(C, Ca, 0 /* bidirectional */);
    OP_WRITE(Ca, "apple", 5);

    OP_INHIBIT_TICK(C, 1);
    OP_SET_WRITE_BUF_SIZE(Ca, 1024 * 100 * 3);

    for (i = 0; i < 100; ++i)
        OP_WRITE(Ca, script_40_data, sizeof(script_40_data));

    OP_CONCLUDE(Ca);
    OP_SHUTDOWN_WAIT(C, 0, 0, NULL); /* disengages tick inhibition */

    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    for (i = 0; i < 100; ++i)
        OP_READ_EXPECT(Sa, script_40_data, sizeof(script_40_data));

    OP_EXPECT_FIN(Sa);

    OP_EXPECT_CONN_CLOSE_INFO(C, 0, 1, 0);
    OP_EXPECT_CONN_CLOSE_INFO(S, 0, 1, 1);
}

/* 41. Fault injection - PATH_CHALLENGE yields PATH_RESPONSE */
static const uint64_t script_41_path_challenge = UINT64_C(0xbdeb9451169c83aa);
static uint64_t script_41_valid_responses;
static uint64_t script_41_bad_responses;

static int script_41_inject_plain(RADIX_FAULT *fault, QUIC_PKT_HDR *hdr,
    unsigned char *buf, size_t len)
{
    int ok = 0;
    WPACKET wpkt;
    unsigned char frame_buf[16];
    size_t written;

    if (fault->word0 == 0 || hdr->type != QUIC_PKT_TYPE_1RTT)
        return 1;

    if (!TEST_true(WPACKET_init_static_len(&wpkt, frame_buf,
            sizeof(frame_buf), 0)))
        return 0;

    if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, fault->word1))
        || !TEST_true(WPACKET_put_bytes_u64(&wpkt, script_41_path_challenge))
        || !TEST_true(WPACKET_get_total_written(&wpkt, &written))
        || !TEST_size_t_eq(written, 9)
        || !radix_fault_prepend_frame(fault, frame_buf, written))
        goto err;

    --fault->word0;
    ok = 1;
err:
    if (ok)
        WPACKET_finish(&wpkt);
    else
        WPACKET_cleanup(&wpkt);
    return ok;
}

static void script_41_trace(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    uint64_t frame_type, frame_data;
    int was_minimal;
    PACKET pkt;

    if (version != OSSL_QUIC1_VERSION
        || content_type != SSL3_RT_QUIC_FRAME_FULL
        || len < 1)
        return;

    if (!TEST_true(PACKET_buf_init(&pkt, buf, len))
        || !TEST_true(ossl_quic_wire_peek_frame_header(&pkt, &frame_type,
            &was_minimal))) {
        ++script_41_bad_responses;
        return;
    }

    if (frame_type != OSSL_QUIC_FRAME_TYPE_PATH_RESPONSE)
        return;

    if (!TEST_true(ossl_quic_wire_decode_frame_path_response(&pkt, &frame_data))
        || !TEST_uint64_t_eq(frame_data, script_41_path_challenge)) {
        ++script_41_bad_responses;
        return;
    }

    ++script_41_valid_responses;
}

DEF_FUNC(install_trace_41)
{
    int ok = 0;
    SSL *ssl;

    REQUIRE_SSL(ssl);
    SSL_set_msg_callback(ssl, script_41_trace);

    ok = 1;
err:
    return ok;
}

DEF_FUNC(check_path_response_41)
{
    int ok = 0;

    /* At least one valid challenge/response echo? */
    if (script_41_valid_responses == 0)
        F_SPIN_AGAIN();

    /* No failed tests? */
    if (!TEST_uint64_t_eq(script_41_bad_responses, 0))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_SCRIPT(script_41, "Fault injection - PATH_CHALLENGE yields PATH_RESPONSE")
{
    OP_SIMPLE_PAIR_CONN();

    OP_WRITE(C, "apple", 5);

    OP_ACCEPT_CONN_WAIT(L, S, 0);
    OP_SET_INJECT_PLAIN(S, script_41_inject_plain);
    OP_SELECT_SSL(0, S);
    OP_FUNC(install_trace_41);

    OP_READ_EXPECT(S, "apple", 5);

    OP_SET_INJECT_WORD(1, OSSL_QUIC_FRAME_TYPE_PATH_CHALLENGE);

    OP_WRITE(S, "orange", 6);
    OP_READ_EXPECT(C, "orange", 6);

    OP_WRITE(C, "strawberry", 10);
    OP_READ_EXPECT(S, "strawberry", 10);

    OP_FUNC(check_path_response_41);
}

/* 42. Fault injection - CRYPTO frame with illegal offset */
static int script_42_inject_plain(RADIX_FAULT *fault, QUIC_PKT_HDR *hdr,
    unsigned char *buf, size_t len)
{
    int ok = 0;
    unsigned char frame_buf[64];
    size_t written;
    WPACKET wpkt;

    if (fault->word0 == 0)
        return 1;

    --fault->word0;

    if (!TEST_true(WPACKET_init_static_len(&wpkt, frame_buf,
            sizeof(frame_buf), 0)))
        return 0;

    if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, OSSL_QUIC_FRAME_TYPE_CRYPTO))
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, fault->word1))
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, 1))
        || !TEST_true(WPACKET_put_bytes_u8(&wpkt, 0x42))
        || !TEST_true(WPACKET_get_total_written(&wpkt, &written))
        || !radix_fault_prepend_frame(fault, frame_buf, written))
        goto err;

    ok = 1;
err:
    if (ok)
        WPACKET_finish(&wpkt);
    else
        WPACKET_cleanup(&wpkt);
    return ok;
}

DEF_SCRIPT(script_42, "Fault injection - CRYPTO frame with illegal offset")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_SET_INJECT_PLAIN(S, script_42_inject_plain);

    OP_NEW_STREAM(C, Ca, 0);
    OP_WRITE(Ca, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(1, (((uint64_t)1) << 62) - 1);
    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_FRAME_ENCODING_ERROR, 0, 0);
}

/* 43. Fault injection - CRYPTO frame exceeding FC */
DEF_SCRIPT(script_43, "Fault injection - CRYPTO frame exceeding FC")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_ACCEPT_CONN_WAIT_ND(L, S, 0);

    OP_SET_INJECT_PLAIN(S, script_42_inject_plain);

    OP_NEW_STREAM(C, Ca, 0);
    OP_WRITE(Ca, "apple", 5);

    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(1, 0x100000 /* 1 MiB */);
    OP_WRITE(Sa, "orange", 6);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED, 0, 0);
}

/* 44. Fault injection - PADDING */
static int script_44_inject_plain(RADIX_FAULT *fault, QUIC_PKT_HDR *hdr,
    unsigned char *buf, size_t len)
{
    int ok = 0;
    WPACKET wpkt;
    unsigned char frame_buf[16];
    size_t written;

    if (fault->word0 == 0 || hdr->type != QUIC_PKT_TYPE_1RTT)
        return 1;

    if (!TEST_true(WPACKET_init_static_len(&wpkt, frame_buf,
            sizeof(frame_buf), 0)))
        return 0;

    if (!TEST_true(ossl_quic_wire_encode_padding(&wpkt, 1))
        || !TEST_true(WPACKET_get_total_written(&wpkt, &written))
        || !radix_fault_prepend_frame(fault, frame_buf, written))
        goto err;

    ok = 1;
err:
    if (ok)
        WPACKET_finish(&wpkt);
    else
        WPACKET_cleanup(&wpkt);
    return ok;
}

DEF_SCRIPT(script_44, "Fault injection - PADDING")
{
    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_SET_INJECT_PLAIN(S, script_44_inject_plain);

    OP_WRITE(C, "apple", 5);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_SET_INJECT_WORD(1, 0);

    OP_WRITE(Sa, "Strawberry", 10);
    OP_READ_EXPECT(C, "Strawberry", 10);
}

static uint16_t script_45_ack_count;

/* 45. PING must generate ACK */
DEF_FUNC(force_ping_45)
{
    int ok = 0;
    SSL *ssl;
    QUIC_CHANNEL *ch;

    REQUIRE_SSL(ssl);
    ch = ossl_quic_conn_get_channel(ssl);
    if (!TEST_ptr(ch))
        goto err;

    script_45_ack_count = ossl_quic_channel_get_diag_num_rx_ack(ch);

    if (!TEST_true(ossl_quic_channel_ping(ch)))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_FUNC(wait_incoming_acks_increased_45)
{
    int ok = 0;
    SSL *ssl;
    QUIC_CHANNEL *ch;
    uint16_t count;

    REQUIRE_SSL(ssl);
    ch = ossl_quic_conn_get_channel(ssl);
    if (!TEST_ptr(ch))
        goto err;

    count = ossl_quic_channel_get_diag_num_rx_ack(ch);

    if (count == script_45_ack_count)
        F_SPIN_AGAIN();

    ok = 1;
err:
    return ok;
}

DEF_SCRIPT(script_45, "PING must generate ACK")
{
    size_t i;

    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_WRITE(C, "apple", 5);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    for (i = 0; i < 2; ++i) {
        OP_SELECT_SSL(0, S);
        OP_FUNC(force_ping_45);
        OP_SELECT_SSL(0, S);
        OP_FUNC(wait_incoming_acks_increased_45);
    }

    OP_WRITE(Sa, "Strawberry", 10);
    OP_READ_EXPECT(C, "Strawberry", 10);
}

static int inject_malformed_ack_plain(RADIX_FAULT *fault, QUIC_PKT_HDR *hdr,
    unsigned char *buf, size_t len)
{
    int ok = 0;
    WPACKET wpkt;
    unsigned char frame_buf[16];
    size_t written;
    uint64_t type = 0, largest_acked = 0, first_range = 0, range_count = 0;
    uint64_t agap = 0, alen = 0;
    uint64_t ect0 = 0, ect1 = 0, ecnce = 0;

    if (fault->word0 == 0)
        return 1;

    if (!TEST_true(WPACKET_init_static_len(&wpkt, frame_buf,
            sizeof(frame_buf), 0)))
        return 0;

    type = OSSL_QUIC_FRAME_TYPE_ACK_WITHOUT_ECN;

    switch (fault->word0) {
    case 1:
        largest_acked = 100;
        first_range = 101;
        range_count = 0;
        break;
    case 2:
        largest_acked = 100;
        first_range = 80;
        /* [20..100]; [0..18]  */
        range_count = 1;
        agap = 0;
        alen = 19;
        break;
    case 3:
        largest_acked = 100;
        first_range = 80;
        range_count = 1;
        agap = 18;
        alen = 1;
        break;
    case 4:
        type = OSSL_QUIC_FRAME_TYPE_ACK_WITH_ECN;
        largest_acked = 100;
        first_range = 1;
        range_count = 0;
        break;
    case 5:
        type = OSSL_QUIC_FRAME_TYPE_ACK_WITH_ECN;
        largest_acked = 0;
        first_range = 0;
        range_count = 0;
        ect0 = 0;
        ect1 = 50;
        ecnce = 200;
        break;
    }

    fault->word0 = 0;

    if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, type))
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, largest_acked))
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, /*ack_delay=*/0))
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, /*ack_range_count=*/range_count))
        || !TEST_true(WPACKET_quic_write_vlint(&wpkt, /*first_ack_range=*/first_range)))
        goto err;

    if (range_count > 0)
        if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, /*range[0].gap=*/agap))
            || !TEST_true(WPACKET_quic_write_vlint(&wpkt, /*range[0].len=*/alen)))
            goto err;

    if (type == OSSL_QUIC_FRAME_TYPE_ACK_WITH_ECN)
        if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, ect0))
            || !TEST_true(WPACKET_quic_write_vlint(&wpkt, ect1))
            || !TEST_true(WPACKET_quic_write_vlint(&wpkt, ecnce)))
            goto err;

    if (!TEST_true(WPACKET_get_total_written(&wpkt, &written))
        || !radix_fault_prepend_frame(fault, frame_buf, written))
        goto err;

    ok = 1;
err:
    if (ok)
        WPACKET_finish(&wpkt);
    else
        WPACKET_cleanup(&wpkt);
    return ok;
}

/* 46. Fault injection - ACK - malformed initial range */
DEF_SCRIPT(script_46, "Fault injection - ACK - malformed initial range")
{
    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_malformed_ack_plain);

    OP_WRITE(C, "apple", 5);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(1, 0);
    OP_WRITE(Sa, "Strawberry", 10);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_FRAME_ENCODING_ERROR, 0, 0);
}

DEF_SCRIPT(script_47, "Fault injection - ACK - malformed subsequent range")
{
    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_malformed_ack_plain);

    OP_WRITE(C, "apple", 5);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(2, 0);
    OP_WRITE(Sa, "Strawberry", 10);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_FRAME_ENCODING_ERROR, 0, 0);
}

DEF_SCRIPT(script_48, "Fault injection - ACK - malformed subsequent range")
{
    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_malformed_ack_plain);

    OP_WRITE(C, "apple", 5);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_ENGINE_TICK_DISABLE(S);
    OP_SET_INJECT_WORD(3, 0);
    OP_WRITE(Sa, "Strawberry", 10);
    OP_ENGINE_TICK_ENABLE(S);

    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_FRAME_ENCODING_ERROR, 0, 0);
}

DEF_SCRIPT(script_49, "Fault injection - ACK - fictional PN")
{
    OP_SIMPLE_PAIR_CONN();
    OP_ACCEPT_CONN_WAIT(L, S, 0);

    OP_SET_INJECT_PLAIN(S, inject_malformed_ack_plain);

    OP_WRITE(C, "apple", 5);
    OP_ACCEPT_STREAM_WAIT(S, Sa, 0);
    OP_READ_EXPECT(Sa, "apple", 5);

    OP_SET_INJECT_WORD(4, 0);

    OP_WRITE(Sa, "Strawberry", 10);
    /*
     * The injected ACK acknowledges a packet number we have not sent, which the
     * peer is expected to treat as a PROTOCOL_VIOLATION, so the connection is
     * closed rather than the stream data being delivered.
     */
    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_PROTOCOL_VIOLATION, 0, 0);
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
    USE(reject_before_default_stream),
    USE(simple_conn),
    USE(simple_thread),
    USE(ssl_poll),
    USE(poll_abort_blocking),
    USE(check_cwm),
    USE(check_pc_flood),
    USE(check_ctx_cbks),
    USE(check_thread_assisted_idle),
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
