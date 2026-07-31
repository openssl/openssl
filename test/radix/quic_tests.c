/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/quic_reactor.h"
#include "internal/quic_reactor_wait_ctx.h"
#include "internal/quic_channel.h"
#include "internal/quic_ssl.h"
#include "internal/time.h"
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

/*
 * Test: poll_multi_reactor_cleanup
 * --------------------------------
 *
 * Exercise normal and translation-abort cleanup with two workers, each
 * polling two notifier-enabled reactors. Repeated items also check that
 * registrations are aggregated by reactor within each call.
 *
 * The fourth item's translation hook is a barrier. In the normal case it is
 * a NULL sentinel, reached after both reactors have been registered in
 * opposite orders. In the abort case only the first reactor is registered
 * at the barrier; the coordinator changes the fourth item's event mask to
 * writable so its registration on the other reactor takes the abort path.
 * Both variants must finish with no outstanding waiters or signals.
 */

#if defined(OPENSSL_THREADS)
struct poll_multi_reactor_ctx {
    CRYPTO_MUTEX *mu;
    CRYPTO_CONDVAR *cv;
    int arrived;
    int release;
    int done;
    int abort_blocking;
    int rc[2];
    size_t result_count[2];
};

struct poll_cleanup_thread_ctx {
    SSL *ssl0, *ssl1;
    SSL_POLL_ITEM items[4];
    size_t idx;
    struct poll_multi_reactor_ctx *ctx;
};

static int poll_cleanup_wait(struct poll_multi_reactor_ctx *ctx,
    int *counter, int expected)
{
    OSSL_TIME deadline = ossl_time_add(ossl_time_now(), ossl_seconds2time(10));
    int ok;

    ossl_crypto_mutex_lock(ctx->mu);
    while (*counter < expected
        && ossl_time_compare(ossl_time_now(), deadline) < 0)
        ossl_crypto_condvar_wait_timeout(ctx->cv, ctx->mu, deadline);
    ok = (*counter == expected);
    ossl_crypto_mutex_unlock(ctx->mu);
    return ok;
}

static void poll_cleanup_release(struct poll_multi_reactor_ctx *ctx, int stage)
{
    ossl_crypto_mutex_lock(ctx->mu);
    ctx->release = stage;
    ossl_crypto_condvar_broadcast(ctx->cv);
    ossl_crypto_mutex_unlock(ctx->mu);
}

static void poll_cleanup_join(struct poll_multi_reactor_ctx *ctx,
    CRYPTO_THREAD **threads, size_t num_threads)
{
    size_t i;

    /* Bound error-path cleanup as well as the normal worker completion. */
    if (!poll_cleanup_wait(ctx, &ctx->done, (int)num_threads))
        OPENSSL_die("SSL_poll cleanup workers are wedged", __FILE__, __LINE__);

    for (i = 0; i < num_threads; ++i) {
        ossl_crypto_thread_native_join(threads[i], NULL);
        ossl_crypto_thread_native_clean(threads[i]);
    }
}

/*
 * Arm the notifier exactly as rtor_notify_other_threads() does, but without
 * its condvar wait, so both reactors can be put into the required state
 * deterministically before the workers are released.
 */
static void poll_cleanup_signal_notifier(QUIC_REACTOR *rtor)
{
    ossl_crypto_mutex_lock(rtor->mutex);
    if (rtor->have_notifier && !rtor->signalled_notifier
        && rtor->cur_blocking_waiters > 0) {
        ossl_rio_notifier_signal(&rtor->notifier);
        rtor->signalled_notifier = 1;
    }
    ossl_crypto_mutex_unlock(rtor->mutex);
}

static void poll_cleanup_test_step_cb(size_t idx, void *arg)
{
    struct poll_multi_reactor_ctx *ctx = arg;

    if (idx != 3)
        return;

    ossl_crypto_mutex_lock(ctx->mu);
    if (!ctx->release) {
        ++ctx->arrived;
        ossl_crypto_condvar_broadcast(ctx->cv);
        while (!ctx->release)
            ossl_crypto_condvar_wait(ctx->cv, ctx->mu);
    }
    ossl_crypto_mutex_unlock(ctx->mu);
}

static CRYPTO_THREAD_RETVAL poll_cleanup_thread(void *arg)
{
    struct poll_cleanup_thread_ctx *d = arg;
    struct poll_multi_reactor_ctx *ctx = d->ctx;
    SSL_POLL_ITEM *items = d->items;
    const struct timeval timeout = { 1, 0 };
    size_t result_count = 0, i;
    int rc;

    items[0].desc = SSL_as_poll_descriptor(d->ssl0);
    items[1].desc = SSL_as_poll_descriptor(ctx->abort_blocking ? d->ssl0 : d->ssl1);
    items[2].desc = SSL_as_poll_descriptor(ctx->abort_blocking ? NULL : d->ssl0);
    items[3].desc = SSL_as_poll_descriptor(ctx->abort_blocking ? d->ssl1 : NULL);
    for (i = 0; i < OSSL_NELEM(d->items); ++i)
        items[i].events = SSL_POLL_EVENT_R;

    /* Do not tick while the other worker may be stopped at the test barrier. */
    rc = SSL_poll(items, OSSL_NELEM(d->items), sizeof(SSL_POLL_ITEM),
        &timeout, SSL_POLL_FLAG_NO_HANDLE_EVENTS, &result_count);

    ossl_crypto_mutex_lock(ctx->mu);
    ctx->rc[d->idx] = rc;
    ctx->result_count[d->idx] = result_count;
    ++ctx->done;
    ossl_crypto_condvar_broadcast(ctx->cv);
    ossl_crypto_mutex_unlock(ctx->mu);
    return 0;
}
#endif

DEF_FUNC(check_poll_multi_reactor_cleanup)
{
    int ok = 0;
    uint64_t abort_blocking;
#if !defined(OPENSSL_THREADS)
    F_POP(abort_blocking);
    TEST_skip("threading not supported, skipping");
    F_SKIP_REST();
err:
    return ok;
#else
    SSL *stream_a0, *stream_a1, *stream_b0, *stream_b1, *conn;
    QUIC_CHANNEL *ch;
    QUIC_REACTOR *rtor[2];
    CRYPTO_THREAD *thread[2] = { NULL, NULL };
    size_t i, started = 0;
    int state_ok;
    struct poll_multi_reactor_ctx ctx = { 0 };
    struct poll_cleanup_thread_ctx worker[2] = { 0 };

    F_POP(abort_blocking);
    REQUIRE_SSL_4(stream_a0, stream_a1, stream_b0, stream_b1);
    ctx.abort_blocking = (abort_blocking != 0);

    for (i = 0; i < 2; ++i)
        if (!TEST_ptr(conn = SSL_get0_connection(i == 0 ? stream_a0
                                                        : stream_b0))
            || !TEST_ptr(ch = ossl_quic_conn_get_channel(conn))
            || !TEST_ptr(rtor[i] = ossl_quic_channel_get_reactor(ch)))
            return 0;

    if (rtor[0] == rtor[1]
        || !rtor[0]->have_notifier
        || !rtor[1]->have_notifier) {
        TEST_skip("test requires two distinct notifier-enabled reactors");
        F_SKIP_REST();
    }

    if ((ctx.mu = ossl_crypto_mutex_new()) == NULL
        || (ctx.cv = ossl_crypto_condvar_new()) == NULL)
        goto err;

    worker[0].ssl0 = stream_a0;
    worker[0].ssl1 = stream_b0;
    worker[1].ssl0 = stream_b1;
    worker[1].ssl1 = stream_a1;
    for (i = 0; i < 2; ++i) {
        worker[i].idx = i;
        worker[i].ctx = &ctx;
    }

    ossl_quic_poll_translate_test_step_cb_arg = &ctx;
    ossl_quic_poll_translate_test_step_cb = poll_cleanup_test_step_cb;

    for (i = 0; i < 2; ++i) {
        if ((thread[i] = ossl_crypto_thread_native_start(poll_cleanup_thread,
                 &worker[i], 1))
            == NULL)
            goto err_join;
        ++started;
    }

    if (!TEST_true(poll_cleanup_wait(&ctx, &ctx.arrived, 2)))
        goto err_join;

    /* The barrier keeps the waiter counts stable until release. */
    state_ok = 1;
    for (i = 0; i < 2; ++i) {
        ossl_crypto_mutex_lock(rtor[i]->mutex);
        if (!TEST_size_t_eq(rtor[i]->cur_blocking_waiters,
                ctx.abort_blocking ? 1 : 2))
            state_ok = 0;
        ossl_crypto_mutex_unlock(rtor[i]->mutex);
    }
    if (!state_ok)
        goto err_join;

    for (i = 0; i < 2; ++i)
        poll_cleanup_signal_notifier(rtor[i]);

    /* The workers are at the barrier and cannot read these items yet. */
    if (ctx.abort_blocking)
        for (i = 0; i < 2; ++i)
            worker[i].items[3].events = SSL_POLL_EVENT_W;

    poll_cleanup_release(&ctx, 1);

    /* Do not let a cleanup regression hang the test process. */
    if (!TEST_true(poll_cleanup_wait(&ctx, &ctx.done, 2)))
        goto err_wedge;

    ossl_crypto_mutex_lock(ctx.mu);
    state_ok = 1;
    for (i = 0; i < 2; ++i)
        if (!TEST_int_eq(ctx.rc[i], 1)
            || !TEST_size_t_eq(ctx.result_count[i], ctx.abort_blocking ? 1 : 0))
            state_ok = 0;
    ossl_crypto_mutex_unlock(ctx.mu);
    if (!state_ok)
        goto err_join;

    state_ok = 1;
    for (i = 0; i < 2; ++i) {
        ossl_crypto_mutex_lock(rtor[i]->mutex);
        if (!TEST_size_t_eq(rtor[i]->cur_blocking_waiters, 0))
            state_ok = 0;
        if (!TEST_int_eq(rtor[i]->signalled_notifier, 0))
            state_ok = 0;
        ossl_crypto_mutex_unlock(rtor[i]->mutex);
    }
    if (!state_ok)
        goto err_join;

    ok = 1;

err_join:
    /* Release any worker stopped at the registration barrier. */
    poll_cleanup_release(&ctx, 1);
    poll_cleanup_join(&ctx, thread, started);
    goto err;

err_wedge:
    /* Normal cleanup would re-enter reactors held by the wedged workers. */
    OPENSSL_die("SSL_poll cleanup workers are wedged", __FILE__, __LINE__);

err:
    ossl_quic_poll_translate_test_step_cb = NULL;
    ossl_quic_poll_translate_test_step_cb_arg = NULL;
    ossl_crypto_condvar_free(&ctx.cv);
    ossl_crypto_mutex_free(&ctx.mu);
    return ok;
#endif
}

DEF_SCRIPT(poll_multi_reactor_cleanup,
    "verify SSL_poll() multi-reactor two-phase cleanup does not deadlock")
{
    size_t i;

    OP_SIMPLE_PAIR_CONN_ND();

    OP_NEW_STREAM(C, C0, 0);
    OP_NEW_STREAM(C, C1, 0);

    /* A second, independent client connection (its own reactor). */
    OP_NEW_SSL_C(Cb);
    OP_SET_PEER_ADDR_FROM(Cb, L);
    OP_CONNECT_WAIT(Cb);
    OP_SET_DEFAULT_STREAM_MODE(Cb, SSL_DEFAULT_STREAM_MODE_NONE);

    OP_NEW_STREAM(Cb, Cb0, 0);
    OP_NEW_STREAM(Cb, Cb1, 0);

    OP_SELECT_SSL(0, C0);
    OP_SELECT_SSL(1, C1);
    OP_SELECT_SSL(2, Cb0);
    OP_SELECT_SSL(3, Cb1);
    for (i = 0; i < 2; ++i) {
        OP_PUSH_U64(i);
        OP_FUNC(check_poll_multi_reactor_cleanup);
    }
}

/*
 * Test: poll_notification_generation
 * ---------------------------------
 *
 * Pause a worker after deregistration but before draining its wait context.
 * Complete that notification cycle and start another before letting it drain.
 * The worker must finish while the later cycle is still signalled.
 */
#if defined(OPENSSL_THREADS)
struct poll_generation_thread_ctx {
    QUIC_REACTOR *rtor;
    struct poll_multi_reactor_ctx *ctx;
};

static CRYPTO_THREAD_RETVAL poll_generation_thread(void *arg)
{
    struct poll_generation_thread_ctx *d = arg;
    struct poll_multi_reactor_ctx *ctx = d->ctx;
    QUIC_REACTOR_WAIT_CTX wctx;
    int ok;

    ossl_quic_reactor_wait_ctx_init(&wctx);
    ossl_crypto_mutex_lock(d->rtor->mutex);
    ok = ossl_quic_reactor_wait_ctx_enter(&wctx, d->rtor);
    ossl_crypto_mutex_unlock(d->rtor->mutex);
    if (!ok)
        goto end;

    ossl_crypto_mutex_lock(ctx->mu);
    ctx->arrived = 1;
    ossl_crypto_condvar_broadcast(ctx->cv);
    while (ctx->release < 1)
        ossl_crypto_condvar_wait(ctx->cv, ctx->mu);
    ossl_crypto_mutex_unlock(ctx->mu);

    ossl_crypto_mutex_lock(d->rtor->mutex);
    ossl_quic_reactor_wait_ctx_deregister(&wctx, d->rtor);
    ossl_crypto_mutex_unlock(d->rtor->mutex);

    ossl_crypto_mutex_lock(ctx->mu);
    ctx->arrived = 2;
    ossl_crypto_condvar_broadcast(ctx->cv);
    while (ctx->release < 2)
        ossl_crypto_condvar_wait(ctx->cv, ctx->mu);
    ossl_crypto_mutex_unlock(ctx->mu);

    ossl_quic_reactor_wait_ctx_drain(&wctx);

end:
    ossl_quic_reactor_wait_ctx_cleanup(&wctx);
    ossl_crypto_mutex_lock(ctx->mu);
    ctx->rc[0] = ok;
    ++ctx->done;
    ossl_crypto_condvar_broadcast(ctx->cv);
    ossl_crypto_mutex_unlock(ctx->mu);
    return 0;
}
#endif

DEF_FUNC(check_poll_notification_generation)
{
    int ok = 0;
#if !defined(OPENSSL_THREADS)
    TEST_skip("threading not supported, skipping");
    F_SKIP_REST();
err:
    return ok;
#else
    SSL *conn;
    QUIC_CHANNEL *ch;
    QUIC_REACTOR *rtor;
    CRYPTO_THREAD *thread[1] = { NULL };
    struct poll_multi_reactor_ctx ctx = { 0 };
    struct poll_generation_thread_ctx worker;
    uint64_t generation, cleanup_generation = 0;
    size_t started = 0;
    int registered = 0, need_wait = 0, state_ok;

    REQUIRE_SSL(conn);
    if (!TEST_ptr(ch = ossl_quic_conn_get_channel(conn))
        || !TEST_ptr(rtor = ossl_quic_channel_get_reactor(ch)))
        return 0;

    if (!rtor->have_notifier) {
        TEST_skip("test requires a notifier-enabled reactor");
        F_SKIP_REST();
    }

    if ((ctx.mu = ossl_crypto_mutex_new()) == NULL
        || (ctx.cv = ossl_crypto_condvar_new()) == NULL)
        goto err;

    ossl_crypto_mutex_lock(rtor->mutex);
    state_ok = TEST_size_t_eq(rtor->cur_blocking_waiters, 0)
        && TEST_int_eq(rtor->signalled_notifier, 0);
    generation = rtor->notify_generation;
    if (state_ok) {
        ossl_quic_reactor_enter_blocking_section(rtor);
        registered = 1;
    }
    ossl_crypto_mutex_unlock(rtor->mutex);
    if (!state_ok)
        goto err;

    worker.rtor = rtor;
    worker.ctx = &ctx;
    if (!TEST_ptr(thread[0] = ossl_crypto_thread_native_start(
                      poll_generation_thread, &worker, 1)))
        goto err_join;
    started = 1;

    if (!TEST_true(poll_cleanup_wait(&ctx, &ctx.arrived, 1)))
        goto err_join;

    poll_cleanup_signal_notifier(rtor);
    poll_cleanup_release(&ctx, 1);
    if (!TEST_true(poll_cleanup_wait(&ctx, &ctx.arrived, 2)))
        goto err_join;

    ossl_crypto_mutex_lock(rtor->mutex);
    state_ok = TEST_size_t_eq(rtor->cur_blocking_waiters, 1)
        && TEST_int_eq(rtor->signalled_notifier, 1)
        && TEST_uint64_t_eq(rtor->notify_generation, generation);
    if (state_ok) {
        /* The coordinator is the last registered waiter for this cycle. */
        ossl_quic_reactor_leave_blocking_section(rtor);
        registered = 0;
        state_ok = TEST_uint64_t_eq(rtor->notify_generation, generation + 1);
        if (state_ok) {
            ossl_quic_reactor_enter_blocking_section(rtor);
            registered = 1;
            ossl_rio_notifier_signal(&rtor->notifier);
            rtor->signalled_notifier = 1;
        }
    }
    ossl_crypto_mutex_unlock(rtor->mutex);
    if (!state_ok)
        goto err_join;

    poll_cleanup_release(&ctx, 2);
    if (!TEST_true(poll_cleanup_wait(&ctx, &ctx.done, 1))
        || !TEST_int_eq(ctx.rc[0], 1))
        goto err_join;

    /* Finishing the old wait must not consume the later notification. */
    ossl_crypto_mutex_lock(rtor->mutex);
    ok = TEST_size_t_eq(rtor->cur_blocking_waiters, 1)
        && TEST_int_eq(rtor->signalled_notifier, 1)
        && TEST_uint64_t_eq(rtor->notify_generation, generation + 1);
    ossl_crypto_mutex_unlock(rtor->mutex);

err_join:
    if (registered) {
        ossl_crypto_mutex_lock(rtor->mutex);
        need_wait = ossl_quic_reactor_deregister_blocking_section(rtor,
            &cleanup_generation);
        ossl_crypto_mutex_unlock(rtor->mutex);
    }
    poll_cleanup_release(&ctx, 2);
    poll_cleanup_join(&ctx, thread, started);
    if (need_wait)
        ossl_quic_reactor_wait_for_notifier_clear(rtor, cleanup_generation);

    ossl_crypto_mutex_lock(rtor->mutex);
    if (!TEST_size_t_eq(rtor->cur_blocking_waiters, 0)
        || !TEST_int_eq(rtor->signalled_notifier, 0))
        ok = 0;
    ossl_crypto_mutex_unlock(rtor->mutex);

err:
    ossl_crypto_condvar_free(&ctx.cv);
    ossl_crypto_mutex_free(&ctx.mu);
    return ok;
#endif
}

DEF_SCRIPT(poll_notification_generation,
    "verify a QUIC poll wait completes independently of later notification cycles")
{
    OP_SIMPLE_PAIR_CONN_ND();
    OP_SELECT_SSL(0, C);
    OP_FUNC(check_poll_notification_generation);
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
        TEST_info("mutcbk_inject_frames() not enough space to inject");
        return 0;
    }
    bufsz += grow_allowance;

    /* discard const */
    OPENSSL_free((char *)mutctx->mutctx_iov.buf);
    mutctx->mutctx_iov.buf = OPENSSL_malloc(bufsz);
    /* discard const */
    buf = (char *)mutctx->mutctx_iov.buf;
    if (buf == NULL) {
        TEST_info("mutcbk_inject_frames() OPENSSL_malloc() failed");
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

static int inject_new_cids(RADIX_FAULT *fault, QUIC_PKT_HDR *hdr,
    unsigned char *buf, size_t len)
{
    int ok = 0;
    WPACKET wpkt;
    unsigned char frame_buf[1000];
    size_t i, j, written;
    uint64_t seq_no = 2, retire_prior_to = seq_no - 1;
    QUIC_CONN_ID new_cid = { 0 };

    if (hdr->type != QUIC_PKT_TYPE_1RTT)
        return 1;

    if (!TEST_true(WPACKET_init_static_len(&wpkt, frame_buf,
            sizeof(frame_buf), 0)))
        return 0;

    ossl_quic_channel_get_diag_local_cid(fault->ch, &new_cid);

    for (i = 0; i < 20; i++) {
        if (!TEST_true(WPACKET_quic_write_vlint(&wpkt, OSSL_QUIC_FRAME_TYPE_NEW_CONN_ID))
            || !TEST_true(WPACKET_quic_write_vlint(&wpkt, seq_no)) /* seq no */
            || !TEST_true(WPACKET_quic_write_vlint(&wpkt, retire_prior_to)) /* retire prior to */
            || !TEST_true(WPACKET_put_bytes_u8(&wpkt, new_cid.id_len))) /* len */
            goto err;
        seq_no++;
        retire_prior_to++;

        for (j = 0; j < new_cid.id_len && i < OSSL_NELEM(new_cid.id); ++j)
            if (!TEST_true(WPACKET_put_bytes_u8(&wpkt, new_cid.id[j])))
                goto err;

        for (; j < new_cid.id_len; ++j)
            if (!TEST_true(WPACKET_put_bytes_u8(&wpkt, 0x55)))
                goto err;

        for (j = 0; j < QUIC_STATELESS_RESET_TOKEN_LEN; ++j)
            if (!TEST_true(WPACKET_put_bytes_u8(&wpkt, 0x42)))
                goto err;
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

DEF_SCRIPT(new_connid, "verify remote peer does not send excessive amount of NEW_CONNID frames")
{
    OP_SIMPLE_PAIR_CONN();
    OP_WRITE_B(C, "apple");
    OP_ACCEPT_CONN_WAIT(L, S, 0);
    OP_SET_INCOMING_STREAM_POLICY(C, SSL_INCOMING_STREAM_POLICY_ACCEPT, 42 /* error code */);
    OP_SET_INCOMING_STREAM_POLICY(S, SSL_INCOMING_STREAM_POLICY_ACCEPT, 42 /* error code */);
    OP_READ_EXPECT_B(S, "apple");

    OP_WRITE_B(S, "orange");
    OP_READ_EXPECT_B(C, "orange");

    OP_SET_INJECT_PLAIN(S, inject_new_cids);

    OP_WRITE_B(S, "banana");
    OP_EXPECT_CONN_CLOSE_INFO(C, OSSL_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR, 0, 0);
}
/*
 * List of Test Scripts
 * ============================================================================
 */
static SCRIPT_INFO *const scripts[] = {
    USE(simple_conn),
    USE(simple_thread),
    USE(ssl_poll),
    USE(poll_abort_blocking),
    USE(poll_multi_reactor_cleanup),
    USE(poll_notification_generation),
    USE(check_cwm),
    USE(check_pc_flood),
    USE(check_ctx_cbks),
    USE(new_connid),
};
