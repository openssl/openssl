/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "internal/sockets.h"
#include "internal/thread_arch.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"
#if !defined(OPENSSL_NO_DTLS1_2) || !defined(OPENSSL_NO_DTLS1_3)
#include "../ssl/ssl_local.h"
#endif

static char *cert = NULL;
static char *privkey = NULL;

#define NUM_CLIENTS 3
#define CLIENT_TO_SERVER_MSG "Hello from client"
#define SERVER_TO_CLIENT_MSG "Hello from server"
#define POLL_TIMEOUT_SEC 5
#define MAX_POLL_RETRIES 50

/*
 * Per-thread state for server connection handlers
 */
struct server_thread_args {
    SSL *conn; /* Server-side connection for this thread */
    int thread_idx;
    CRYPTO_THREAD *thread;
    int result; /* 1 = success, 0 = failure */
};

/*
 * Per-thread state for client connection handlers
 */
struct client_thread_args {
    SSL *conn; /* Client-side connection for this thread */
    int thread_idx;
    CRYPTO_THREAD *thread;
    int result; /* 1 = success, 0 = failure */
};

/*
 * Thread function: waits for data on a server connection using SSL_poll,
 * reads the message from client, and sends a response.
 *
 * Uses a retry loop because SSL_poll() returning SSL_POLL_EVENT_R doesn't
 * guarantee SSL_read_ex() will succeed - there may be encrypted records
 * but not yet a complete application data message.
 */
static unsigned int server_conn_thread(void *arg)
{
    struct server_thread_args *ta = (struct server_thread_args *)arg;
    SSL_POLL_ITEM item;
    struct timeval timeout;
    size_t result_count, readbytes, written;
    char buf[256] = { 0 };
    int ret, err, retries;

    ta->result = 0;
    readbytes = 0;

    item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    item.desc.value.ssl = ta->conn;
    item.events = SSL_POLL_EVENT_R;
    item.revents = 0;

    timeout.tv_sec = POLL_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    /* Poll and receive message from client */
    for (retries = 0; retries < MAX_POLL_RETRIES; retries++) {
        item.revents = 0;

        if (!TEST_true(SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count)))
            return 0;

        if (result_count == 0 || (item.revents & SSL_POLL_EVENT_R) == 0)
            continue;

        ret = SSL_read_ex(ta->conn, buf, sizeof(buf) - 1, &readbytes);
        if (ret == 1)
            break;

        err = SSL_get_error(ta->conn, ret);
        if (!TEST_int_eq(err, SSL_ERROR_WANT_READ))
            return 0;
    }

    if (!TEST_int_lt(retries, MAX_POLL_RETRIES))
        return 0;

    buf[readbytes] = '\0';
    if (!TEST_str_eq(buf, CLIENT_TO_SERVER_MSG))
        return 0;

    if (!TEST_true(SSL_write_ex(ta->conn, SERVER_TO_CLIENT_MSG,
            strlen(SERVER_TO_CLIENT_MSG), &written)))
        return 0;

    ta->result = 1;
    return 0;
}

/*
 * Thread function: sends a message to the server and waits for the response.
 *
 * Uses SSL_poll to wait for readable data from server, then verifies the response.
 */
static unsigned int client_conn_thread(void *arg)
{
    struct client_thread_args *ta = (struct client_thread_args *)arg;
    SSL_POLL_ITEM item;
    struct timeval timeout;
    size_t result_count, written;
    size_t readbytes = 0;
    char buf[256] = { 0 };
    int ret, err, retries;

    ta->result = 0;

    /* Send message to server */
    if (!TEST_true(SSL_write_ex(ta->conn, CLIENT_TO_SERVER_MSG,
            strlen(CLIENT_TO_SERVER_MSG), &written)))
        return 0;

    /* Wait for and receive response from server */
    item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    item.desc.value.ssl = ta->conn;
    item.events = SSL_POLL_EVENT_R;
    item.revents = 0;

    timeout.tv_sec = POLL_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    for (retries = 0; retries < MAX_POLL_RETRIES; retries++) {
        item.revents = 0;

        if (!TEST_true(SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count)))
            return 0;

        if (result_count == 0 || (item.revents & SSL_POLL_EVENT_R) == 0)
            continue;

        ret = SSL_read_ex(ta->conn, buf, sizeof(buf) - 1, &readbytes);
        if (ret == 1)
            break;

        err = SSL_get_error(ta->conn, ret);
        if (!TEST_int_eq(err, SSL_ERROR_WANT_READ))
            return 0;
    }

    if (!TEST_int_lt(retries, MAX_POLL_RETRIES))
        return 0;

    buf[readbytes] = '\0';
    if (!TEST_str_eq(buf, SERVER_TO_CLIENT_MSG))
        return 0;

    ta->result = 1;
    return 0;
}

/*
 * Helper: create DTLS listener with real UDP socket
 */
static int create_listener_ex(SSL_CTX *ctx, uint64_t flags, SSL **listener,
    BIO_ADDR **addr, int *fd)
{
    BIO *bio = NULL;
    struct in_addr ina;
    union BIO_sock_info_u info;
    int ret = 0;

    *listener = NULL;
    *addr = NULL;
    *fd = -1;

    ina.s_addr = htonl(INADDR_LOOPBACK);

    *fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(*fd, 0))
        goto err;

    if (!TEST_true(BIO_socket_nbio(*fd, 1)))
        goto err;

    if (!TEST_ptr(*addr = BIO_ADDR_new()))
        goto err;

    if (!TEST_true(BIO_ADDR_rawmake(*addr, AF_INET, &ina, sizeof(ina), 0)))
        goto err;

    if (!TEST_true(BIO_bind(*fd, *addr, 0)))
        goto err;

    info.addr = *addr;
    if (!TEST_true(BIO_sock_info(*fd, BIO_SOCK_INFO_ADDRESS, &info)))
        goto err;

    if (!TEST_ptr(bio = BIO_new_dgram(*fd, BIO_NOCLOSE)))
        goto err;

    if (!TEST_ptr(*listener = SSL_new_listener(ctx, flags)))
        goto err;

    SSL_set_bio(*listener, bio, bio);
    bio = NULL;

    if (!TEST_int_eq(SSL_listen(*listener), 1))
        goto err;

    ret = 1;

err:
    BIO_free(bio);
    if (ret == 0) {
        SSL_free(*listener);
        BIO_ADDR_free(*addr);
        if (*fd >= 0)
            BIO_closesocket(*fd);
        *listener = NULL;
        *addr = NULL;
        *fd = -1;
    }
    return ret;
}

static int create_listener(SSL_CTX *ctx, SSL **listener, BIO_ADDR **addr,
    int *fd)
{
    return create_listener_ex(ctx, 0, listener, addr, fd);
}

/*
 * Helper: create DTLS client connected to server address
 */
static int create_client(SSL_CTX *ctx, const BIO_ADDR *server_addr,
    SSL **client, int *fd)
{
    BIO *bio = NULL;
    int ret = 0;

    *client = NULL;
    *fd = -1;

    *fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(*fd, 0))
        goto err;

    if (!TEST_true(BIO_socket_nbio(*fd, 1)))
        goto err;

    if (!TEST_ptr(bio = BIO_new_dgram(*fd, BIO_NOCLOSE)))
        goto err;

    if (!TEST_true(BIO_dgram_set_peer(bio, server_addr)))
        goto err;

    if (!TEST_ptr(*client = SSL_new(ctx)))
        goto err;

    SSL_set_bio(*client, bio, bio);
    bio = NULL;

    ret = 1;

err:
    BIO_free(bio);
    if (ret == 0) {
        SSL_free(*client);
        if (*fd >= 0)
            BIO_closesocket(*fd);
        *client = NULL;
        *fd = -1;
    }
    return ret;
}

/*
 * Helper: drive handshake between client and listener, return accepted connection.
 */
static int do_handshake(SSL *client, SSL *listener, SSL **server_conn)
{
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int retc, err_code;
    int abortctr = 0;

    *server_conn = NULL;

    SSL_set_connect_state(client);

    while (*server_conn == NULL) {
        if (!TEST_int_le(++abortctr, 100))
            return 0;

        retc = SSL_connect(client);
        err_code = SSL_get_error(client, retc);
        if (retc <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE)
            return 0;

        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 100000;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item),
                &poll_timeout, 0, &poll_result)))
            return 0;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            *server_conn = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(*server_conn))
        return 0;

    if (!TEST_true(create_ssl_connection(*server_conn, client, SSL_ERROR_NONE)))
        return 0;

    return 1;
}

#if !defined(OPENSSL_NO_DTLS1_3) || !defined(OPENSSL_NO_DTLS1_2)
#define RECV_ERROR_POLL_TIMEOUT_SEC 5
#define RECV_ERROR_PROMPT_MAX_MS 2000
#define RECV_ERROR_WATCHDOG_SEC 10
#define RECV_ERROR_MAX_SEND_ATTEMPTS 8

struct recv_error_thread_args {
    SSL *conn;
    SSL *second_conn;
    SSL *idle_listener;
    SSL *accepted;
    DTLS_LISTENER *listener;
    CRYPTO_THREAD *thread;
    CRYPTO_MUTEX *mutex;
    CRYPTO_CONDVAR *cv;
    int armed;
    int transient_receives;
    int permanent_receives;
    int arrived;
    int release;
    int barrier_timeout;
    int done;
    int blocking_read;
    int blocking_accept;
    int blocking_write;
    int blocked_writer;
    int write_wait_fd;
    int send_attempts;
    int send_limit_hit;
    int ssl_error;
    unsigned long error;
    unsigned long first_error;
    size_t readbytes;
    size_t written;
    size_t waiters_at_barrier;
    int registered_descriptor_queries;
    int ret;
    size_t result_count;
    uint64_t revents;
    uint64_t second_revents;
    OSSL_TIME released;
    OSSL_TIME finished;
};

static int recv_error_wait(struct recv_error_thread_args *ta, int *predicate)
{
    OSSL_TIME deadline;
    int ready;

    deadline = ossl_time_add(ossl_time_now(),
        ossl_seconds2time(RECV_ERROR_WATCHDOG_SEC));

    ossl_crypto_mutex_lock(ta->mutex);
    while (!*predicate && ossl_time_compare(ossl_time_now(), deadline) < 0)
        ossl_crypto_condvar_wait_timeout(ta->cv, ta->mutex, deadline);
    ready = *predicate;
    ossl_crypto_mutex_unlock(ta->mutex);

    if (!ready)
        return 0;

    return 1;
}

/* Keep the peer open and unread so the write descriptor cannot become ready. */
static int recv_error_fill_write_socket(int fds[2])
{
#if !defined(OPENSSL_SYS_WINDOWS) && !defined(__DJGPP__) && defined(AF_UNIX)
    BIO *bio = NULL;
    char buf[4096] = { 0 };
    int i, ret, ok = 0;

    if (!TEST_int_eq(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0)
        || !TEST_true(BIO_socket_nbio(fds[0], 1))
        || !TEST_ptr(bio = BIO_new_socket(fds[0], BIO_NOCLOSE)))
        goto end;

    /* Bound setup even if the platform permits unusually large send buffers. */
    for (i = 0; i < 4096; i++) {
        ret = BIO_write(bio, buf, sizeof(buf));
        if (ret <= 0) {
            if (!TEST_true(BIO_should_retry(bio))
                || !TEST_int_eq(BIO_socket_ready(fds[0], 0), 0))
                goto end;
            ok = 1;
            break;
        }
    }
    if (!ok)
        TEST_error("Could not fill the write-wait socket within the setup bound");
end:
    BIO_free(bio);
    ERR_clear_error();
    return ok;
#else
    return 0;
#endif
}

static long recv_error_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    struct recv_error_thread_args *ta = BIO_get_data(bio);
    BIO_POLL_DESCRIPTOR *desc = ptr;
    OSSL_TIME deadline;
    size_t waiters;
    long ret;

    ret = BIO_ctrl(BIO_next(bio), cmd, num, ptr);
    if (ta->blocked_writer && cmd == BIO_CTRL_GET_WPOLL_DESCRIPTOR) {
        desc->type = BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD;
        desc->value.fd = ta->write_wait_fd;
        ret = 1;
    }
    /* Only park the descriptor query for the worker's internal wait. */
    if (ta->blocking_accept || ta->idle_listener != NULL
        || cmd != (ta->blocking_write ? BIO_CTRL_GET_WPOLL_DESCRIPTOR : BIO_CTRL_GET_RPOLL_DESCRIPTOR)
        || ret <= 0
        || desc->type != BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD
        || desc->value.fd < 0)
        return ret;

    /* Never acquire the listener mutex while holding the test mutex. */
    ossl_crypto_mutex_lock(ta->listener->mutex);
    waiters = ta->listener->cur_blocking_waiters;
    ossl_crypto_mutex_unlock(ta->listener->mutex);

    /* Blocking capability checks query the descriptor before registration. */
    if (!ta->blocking_write && waiters == 0)
        return ret;

    ossl_crypto_mutex_lock(ta->mutex);
    /* Both items share one registration; park at the second item's query. */
    if (ta->second_conn != NULL && !ta->arrived
        && ++ta->registered_descriptor_queries < 2) {
        ossl_crypto_mutex_unlock(ta->mutex);
        return ret;
    }
    if (!ta->arrived) {
        /*
         * Read translation reaches here after registration and its readiness
         * recheck. Write translation reaches here after a retryable send,
         * notifier registration and the shared-failure recheck. Neither path
         * holds the listener mutex here, so another connection can discover
         * the receive error while we are parked.
         */
        ta->waiters_at_barrier = waiters;
        ta->arrived = 1;
        ossl_crypto_condvar_broadcast(ta->cv);

        deadline = ossl_time_add(ossl_time_now(),
            ossl_seconds2time(RECV_ERROR_WATCHDOG_SEC));
        while (!ta->release && ossl_time_compare(ossl_time_now(), deadline) < 0)
            ossl_crypto_condvar_wait_timeout(ta->cv, ta->mutex, deadline);
        if (!ta->release)
            ta->barrier_timeout = 1;
    }
    ossl_crypto_mutex_unlock(ta->mutex);

    return ret;
}

/* The second, independent item is translated after the EC-only child. */
static long recv_error_idle_ctrl_cb(BIO *bio, int oper, const char *argp,
    size_t len, int cmd, long argl, int ret, size_t *processed)
{
    struct recv_error_thread_args *ta = (void *)BIO_get_callback_arg(bio);
    OSSL_TIME deadline;
    size_t waiters;

    if (oper != (BIO_CB_CTRL | BIO_CB_RETURN)
        || cmd != BIO_CTRL_GET_RPOLL_DESCRIPTOR || ret <= 0)
        return ret;

    ossl_crypto_mutex_lock(ta->listener->mutex);
    waiters = ta->listener->cur_blocking_waiters;
    ossl_crypto_mutex_unlock(ta->listener->mutex);

    ossl_crypto_mutex_lock(ta->mutex);
    if (!ta->arrived) {
        ta->waiters_at_barrier = waiters;
        ta->arrived = 1;
        ossl_crypto_condvar_broadcast(ta->cv);
        deadline = ossl_time_add(ossl_time_now(),
            ossl_seconds2time(RECV_ERROR_WATCHDOG_SEC));
        while (!ta->release && ossl_time_compare(ossl_time_now(), deadline) < 0)
            ossl_crypto_condvar_wait_timeout(ta->cv, ta->mutex, deadline);
        if (!ta->release)
            ta->barrier_timeout = 1;
    }
    ossl_crypto_mutex_unlock(ta->mutex);
    return ret;
}

static int recv_error_recvmmsg(BIO *bio, BIO_MSG *msg, size_t stride,
    size_t num_msg, uint64_t flags, size_t *msgs_processed)
{
    struct recv_error_thread_args *ta = BIO_get_data(bio);
    int armed;

    ossl_crypto_mutex_lock(ta->mutex);
    armed = ta->armed;
    if (armed)
        ta->permanent_receives++;
    else
        ta->transient_receives++;
    ossl_crypto_mutex_unlock(ta->mutex);

    /* Leave BIO configuration immutable while ctrl and receive can overlap. */
    *msgs_processed = 0;
    ERR_raise(ERR_LIB_BIO, armed ? BIO_R_TRANSFER_ERROR : BIO_R_NON_FATAL);
    return 0;
}

static int recv_error_sendmmsg(BIO *bio, BIO_MSG *msg, size_t stride,
    size_t num_msg, uint64_t flags, size_t *msgs_processed)
{
    struct recv_error_thread_args *ta = BIO_get_data(bio);

    /* Only the writer uses this BIO; no datagram is sent to the idle client. */
    *msgs_processed = 0;
    if (++ta->send_attempts > RECV_ERROR_MAX_SEND_ATTEMPTS) {
        /* Bound a broken retry loop, and make this escape fail the test. */
        ta->send_limit_hit = 1;
        ERR_raise(ERR_LIB_BIO, ERR_R_INTERNAL_ERROR);
    } else {
        ERR_raise(ERR_LIB_BIO, BIO_R_NON_FATAL);
    }
    return 0;
}

static unsigned int recv_error_conn_thread(void *arg)
{
    struct recv_error_thread_args *ta = arg;
    SSL_POLL_ITEM items[2];
    size_t num_items = ta->second_conn != NULL || ta->idle_listener != NULL ? 2 : 1;
    struct timeval timeout = { RECV_ERROR_POLL_TIMEOUT_SEC, 0 };
    OSSL_TIME finished;
    unsigned char buf;

    items[0].desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    items[0].desc.value.ssl = ta->conn;
    items[0].events = SSL_POLL_EVENT_R | SSL_POLL_EVENT_EC;
    items[0].revents = 0;
    items[1] = items[0];
    items[1].desc.value.ssl = ta->second_conn;
    if (ta->idle_listener != NULL) {
        items[0].events = SSL_POLL_EVENT_EC;
        items[1].desc.value.ssl = ta->idle_listener;
        items[1].events = SSL_POLL_EVENT_IC;
    }

    ERR_clear_error();
    if (ta->blocking_accept) {
        ta->accepted = SSL_accept_connection((SSL *)ta->listener, 0);
        ta->first_error = ERR_peek_error();
        ta->error = ERR_peek_last_error();
    } else if (ta->blocking_write) {
        ta->ret = SSL_write_ex(ta->conn, SERVER_TO_CLIENT_MSG,
            strlen(SERVER_TO_CLIENT_MSG), &ta->written);
        ta->ssl_error = SSL_get_error(ta->conn, ta->ret);
        ta->first_error = ERR_peek_error();
        ta->error = ERR_peek_last_error();
    } else if (ta->blocking_read) {
        /* Exercise libssl's internal wait rather than the public polling API. */
        ta->ret = SSL_read_ex(ta->conn, &buf, sizeof(buf), &ta->readbytes);
        ta->ssl_error = SSL_get_error(ta->conn, ta->ret);
        ta->error = ERR_peek_last_error();
    } else {
        ta->ret = SSL_poll(items, num_items, sizeof(items[0]), &timeout, 0,
            &ta->result_count);
    }
    finished = ossl_time_now();
    ta->revents = items[0].revents;
    ta->second_revents = items[1].revents;

    ossl_crypto_mutex_lock(ta->mutex);
    ta->finished = finished;
    ta->done = 1;
    ossl_crypto_condvar_broadcast(ta->cv);
    ossl_crypto_mutex_unlock(ta->mutex);
    return 0;
}

static void recv_error_release_join(struct recv_error_thread_args *ta)
{
    if (ta->thread == NULL)
        return;

    ossl_crypto_mutex_lock(ta->mutex);
    if (ossl_time_is_zero(ta->released))
        ta->released = ossl_time_now();
    ta->release = 1;
    ossl_crypto_condvar_broadcast(ta->cv);
    ossl_crypto_mutex_unlock(ta->mutex);

    /* Bound stuck blocking I/O/accepts and deadlocks during poll cleanup. */
    if (!recv_error_wait(ta, &ta->done))
        OPENSSL_die("DTLS receive error poll worker is wedged", __FILE__, __LINE__);

    if (!ossl_crypto_thread_native_join(ta->thread, NULL)
        || !ossl_crypto_thread_native_clean(ta->thread))
        OPENSSL_die("DTLS receive error poll worker join failed", __FILE__, __LINE__);

    ta->thread = NULL;
}

/*
 * For idx 0..4, a permanent listener receive error discovered by another thread
 * must wake a registered connection or listener waiter. The handshaken DTLS
 * client stays idle, the real socket stays live, and no timer or network data
 * can supply the wakeup. Only production error handling can signal the notifier.
 * idx 0/1 wait with SSL_poll; idx 2/3 wait with blocking SSL_read_ex.
 * Within idx 0..3, even indices discover failure through listener polling;
 * odd indices use a second accepted connection's read, which pumps the shared
 * demux directly. idx 4 blocks in SSL_accept_connection and uses the second
 * connection's read to discover failure without concurrent listener polling.
 * idx 5 forces SSL_write_ex into its internal write wait with a retryable send,
 * then discovers failure through the second connection at descriptor translation.
 * The UDP socket remains writable: this checks terminal failure across the write
 * wait, not notifier wakeup from an OS-blocked send. No send may be retried after
 * that failure, and the writer must receive the original transport diagnostic.
 * idx 6 polls two distinct children of one listener. Failure is discovered by
 * a third child after both poll items reach descriptor translation. They share
 * one listener registration, which cleanup must release before draining. The
 * worker watchdog bounds a deadlock; the finite poll timeout cannot bound
 * cleanup after the OS wait returns.
 * idx 7 uses the same retryable send as idx 5, but substitutes a full socketpair
 * endpoint for the write-poll descriptor. Its peer is never drained or closed
 * while the worker runs, so writability cannot end the wait. The descriptor
 * barrier orders failure injection; it does not prove an OS sleep has begun.
 * Production notification must allow prompt completion despite the nonwritable
 * descriptor. The watchdog aborts if the writer remains stuck.
 * idx 8 polls only EC on the child. An independent idle listener supplies a
 * descriptor barrier after that child's translation, without registering on
 * its behalf. Shared failure must wake the poll before its finite deadline;
 * the unrelated listener must report no event.
 */
static int test_dtls_listener_recv_error_notifier(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL, *client = NULL, *conn = NULL;
    SSL *detect_client = NULL, *detect_conn = NULL;
    SSL *second_client = NULL, *second_conn = NULL;
    BIO_ADDR *server_addr = NULL;
    BIO_ADDR *idle_addr = NULL;
    BIO *idle_bio = NULL;
    BIO_METHOD *method = NULL;
    BIO *filter = NULL, *wfilter = NULL, *rbio, *wbio;
    DTLS_LISTENER *dl;
    struct recv_error_thread_args ta = { 0 };
    SSL_POLL_ITEM item;
    struct timeval timeout = { 0, 0 }, timer_left;
    OSSL_TIME elapsed, deadline;
    size_t waiters;
    size_t result_count = 0;
    size_t readbytes = 0;
    unsigned char buf;
    unsigned long error;
    int server_fd = -1, client_fd = -1, nfd;
    int detect_client_fd = -1, read_error = SSL_ERROR_NONE;
    int second_client_fd = -1;
    int idle_fd = -1;
    int write_wait_fds[2] = { -1, -1 };
    int is_infinite = 0, ret, notifier_ready = 0, worker_done;
    int testresult = 0;
    int multi_item = idx == 6;
    int error_only = idx == 8;
    int direct_read = idx % 2 || idx == 4 || multi_item || error_only;
#ifndef OPENSSL_NO_DTLS1_3
    int version = DTLS1_3_VERSION;
#else
    int version = DTLS1_2_VERSION;
#endif

    ta.blocked_writer = idx == 7;
#if defined(OPENSSL_SYS_WINDOWS) || defined(__DJGPP__) || !defined(AF_UNIX)
    if (ta.blocked_writer) {
        TEST_skip("Nonwritable write descriptor requires a Unix socketpair");
        return 1;
    }
#endif

    /* Protect failure injection and the worker's completion notification. */
    if (!TEST_ptr(ta.mutex = ossl_crypto_mutex_new())
        || !TEST_ptr(ta.cv = ossl_crypto_condvar_new()))
        goto end;

    /* Complete the handshake without ticket traffic that could wake the poll. */
    ERR_clear_error();
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), version, version,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(create_listener_ex(sctx, SSL_LISTENER_FLAG_NO_VALIDATE,
            &listener, &server_addr, &server_fd))
        || !TEST_true(SSL_set_blocking_mode(listener, 0))
        || !TEST_true(create_client(cctx, server_addr, &client, &client_fd))
        || !TEST_true(do_handshake(client, listener, &conn)))
        goto end;

    if (direct_read) {
        /* Discover failure on a separate, already accepted connection. */
        if (!TEST_true(create_client(cctx, server_addr, &detect_client,
                &detect_client_fd))
            || !TEST_true(do_handshake(detect_client, listener, &detect_conn))
            || !TEST_true(SSL_set_blocking_mode(detect_conn, 0))
            || !TEST_true(SSL_is_init_finished(detect_conn))
            || !TEST_true(SSL_is_init_finished(detect_client))
            || !TEST_true(SSL_get_event_timeout(detect_conn, &timer_left,
                &is_infinite))
            || !TEST_true(is_infinite))
            goto end;
    }

    if (multi_item) {
        /* Both polled children must be idle before installing the fault filter. */
        if (!TEST_true(create_client(cctx, server_addr, &second_client,
                &second_client_fd))
            || !TEST_true(do_handshake(second_client, listener, &second_conn))
            || !TEST_true(SSL_set_blocking_mode(second_conn, 0))
            || !TEST_true(SSL_is_init_finished(second_conn))
            || !TEST_true(SSL_is_init_finished(second_client))
            || !TEST_true(SSL_get_event_timeout(second_conn, &timer_left,
                &is_infinite))
            || !TEST_true(is_infinite))
            goto end;

        item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        item.desc.value.ssl = second_conn;
        item.events = SSL_POLL_EVENT_R | SSL_POLL_EVENT_EC;
        item.revents = 0;

        ERR_clear_error();
        if (!TEST_int_eq(SSL_poll(&item, 1, sizeof(item), &timeout,
                             SSL_POLL_FLAG_NO_HANDLE_EVENTS, &result_count),
                1)
            || !TEST_size_t_eq(result_count, 0)
            || !TEST_uint64_t_eq(item.revents, 0))
            goto end;
    }

    /* Start with a finished connection and no existing notifier activity. */
    dl = (DTLS_LISTENER *)listener;
    ta.listener = dl;
    ta.conn = conn;
    ta.second_conn = second_conn;
    ta.blocking_read = idx == 2 || idx == 3;
    ta.blocking_accept = idx == 4;
    ta.blocking_write = idx == 5 || ta.blocked_writer;
    if (!TEST_true(SSL_is_init_finished(conn))
        || !TEST_true(SSL_is_init_finished(client))
        || !TEST_true(dl->have_notifier)
        || !TEST_size_t_eq(dl->cur_blocking_waiters, 0)
        || !TEST_int_eq(dl->signalled_notifier, 0))
        goto end;

    /* No readable socket may supply a receive-error wakeup. */
    nfd = ossl_rio_notifier_as_fd(&dl->notifier);
    if (!TEST_int_ge(nfd, 0)
        || !TEST_int_eq(BIO_socket_ready(nfd, 1), 0)
        || !TEST_int_eq(BIO_socket_ready(server_fd, 1), 0))
        goto end;

    /* Write readiness bounds the OS wait after the descriptor rendezvous. */
    if (ta.blocking_write && !TEST_int_eq(BIO_socket_ready(server_fd, 0), 1))
        goto end;

    if (ta.blocked_writer) {
        if (!TEST_true(recv_error_fill_write_socket(write_wait_fds)))
            goto end;
        ta.write_wait_fd = write_wait_fds[0];
    }

    ERR_clear_error();
    if (!TEST_true(SSL_get_event_timeout(conn, &timer_left, &is_infinite))
        || !TEST_true(is_infinite))
        goto end;

    /* Buffered SSL data must not let the worker return before it starts waiting. */
    item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    item.desc.value.ssl = conn;
    item.events = SSL_POLL_EVENT_R | SSL_POLL_EVENT_EC;
    item.revents = 0;

    ERR_clear_error();
    if (!TEST_int_eq(SSL_poll(&item, 1, sizeof(item), &timeout,
                         SSL_POLL_FLAG_NO_HANDLE_EVENTS, &result_count),
            1)
        || !TEST_size_t_eq(result_count, 0)
        || !TEST_uint64_t_eq(item.revents, 0))
        goto end;

    /* Set the worker's mode before installing the descriptor rendezvous. */
    if (!TEST_true(SSL_set_blocking_mode(conn,
            ta.blocking_read || ta.blocking_write))
        || !TEST_int_eq(SSL_get_blocking_mode(conn),
            ta.blocking_read || ta.blocking_write))
        goto end;

    if (ta.blocking_accept
        && (!TEST_true(SSL_set_blocking_mode(listener, 1))
            || !TEST_int_eq(SSL_get_blocking_mode(listener), 1)))
        goto end;

    /* Inject receive errors without closing or making the real socket readable. */
    if (!TEST_ptr(method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_FILTER,
                      "Cross-thread receive error filter"))
        || !TEST_true(BIO_meth_set_ctrl(method, recv_error_ctrl))
        || !TEST_true(BIO_meth_set_recvmmsg(method, recv_error_recvmmsg))
        || !TEST_true(BIO_meth_set_sendmmsg(method, recv_error_sendmmsg))
        || !TEST_ptr(filter = BIO_new(method)))
        goto end;

    BIO_set_data(filter, &ta);
    BIO_set_init(filter, 1);

    /* Keep a reference for the receive chain; the write BIO stays unchanged. */
    if (!TEST_ptr(rbio = SSL_get_rbio(listener))
        || !TEST_true(BIO_up_ref(rbio)))
        goto end;

    BIO_push(filter, rbio);
    ERR_clear_error();
    SSL_set0_rbio(listener, filter);
    filter = NULL;

    /* Install a separate send filter only on the connection used by the writer. */
    if (ta.blocking_write) {
        if (!TEST_ptr(wfilter = BIO_new(method)))
            goto end;

        BIO_set_data(wfilter, &ta);
        BIO_set_init(wfilter, 1);
        if (!TEST_ptr(wbio = SSL_get_wbio(conn))
            || !TEST_true(BIO_up_ref(wbio)))
            goto end;

        BIO_push(wfilter, wbio);
        SSL_set0_wbio(conn, wfilter);
        wfilter = NULL;
    }

    if (error_only) {
        if (!TEST_true(create_listener_ex(sctx,
                SSL_LISTENER_FLAG_NO_VALIDATE | SSL_LISTENER_FLAG_SINGLE_THREAD,
                &ta.idle_listener, &idle_addr, &idle_fd))
            || !TEST_true(SSL_set_blocking_mode(ta.idle_listener, 0))
            || !TEST_int_eq(BIO_socket_ready(idle_fd, 1), 0)
            || !TEST_ptr(idle_bio = SSL_get_rbio(ta.idle_listener)))
            goto end;

        BIO_set_callback_arg(idle_bio, (char *)&ta);
        BIO_set_callback_ex(idle_bio, recv_error_idle_ctrl_cb);
    }

    /* Connection workers park during descriptor translation of their wait. */
    ta.thread = ossl_crypto_thread_native_start(recv_error_conn_thread, &ta, 1);
    if (!TEST_ptr(ta.thread))
        goto end;

    if (ta.blocking_accept) {
        /*
         * Listener descriptor translation precedes registration, so observe
         * registration instead of using the ctrl rendezvous. This may precede
         * the final readiness recheck: it validates blocking accept's exit,
         * not exclusively a wakeup from an OS-level sleep.
         */
        deadline = ossl_time_add(ossl_time_now(),
            ossl_seconds2time(RECV_ERROR_WATCHDOG_SEC));
        for (;;) {
            ossl_crypto_mutex_lock(dl->mutex);
            waiters = dl->cur_blocking_waiters;
            ossl_crypto_mutex_unlock(dl->mutex);

            ossl_crypto_mutex_lock(ta.mutex);
            ta.waiters_at_barrier = waiters;
            worker_done = ta.done;
            ossl_crypto_mutex_unlock(ta.mutex);

            if (waiters > 0 || worker_done
                || ossl_time_compare(ossl_time_now(), deadline) >= 0)
                break;

            OSSL_sleep(1);
        }
        if (!TEST_false(worker_done) || !TEST_size_t_gt(waiters, 0))
            goto end;

    } else if (!TEST_true(recv_error_wait(&ta, &ta.arrived))) {
        goto end;
    }

    if (ta.blocked_writer
        && !TEST_int_eq(BIO_socket_ready(ta.write_wait_fd, 0), 0))
        goto end;

    if (multi_item) {
        /* Both translated items must share exactly one listener registration. */
        ossl_crypto_mutex_lock(dl->mutex);
        waiters = dl->cur_blocking_waiters;
        ossl_crypto_mutex_unlock(dl->mutex);
        if (!TEST_size_t_eq(waiters, 1))
            goto end;
    }

    /* Only the main thread's next receive should discover the permanent error. */
    ossl_crypto_mutex_lock(ta.mutex);
    /* Accept can finish before release_join; measure from failure injection. */
    if (ta.blocking_accept)
        ta.released = ossl_time_now();
    ta.armed = 1;
    ossl_crypto_mutex_unlock(ta.mutex);

    ERR_clear_error();
    if (!direct_read) {
        /* A zero-time normal poll ticks the listener and discovers the failure. */
        item.desc.value.ssl = listener;
        item.events = SSL_POLL_EVENT_IC | SSL_POLL_EVENT_EL;
        item.revents = 0;
        ret = SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count);
    } else {
        /* Do not tick the listener: the connection read must notify on its own. */
        ret = SSL_read_ex(detect_conn, &buf, sizeof(buf), &readbytes);
        read_error = SSL_get_error(detect_conn, ret);
    }
    error = ERR_peek_last_error();

    /* Parked registered workers keep the notification pending until release. */
    if (!ta.blocking_accept && (!ta.blocking_write || ta.blocked_writer))
        notifier_ready = BIO_socket_ready(nfd, 1);
    recv_error_release_join(&ta);

    /* Exclude setup/barrier time and the main thread's scheduling after done. */
    elapsed = ossl_time_subtract(ta.finished, ta.released);

    if (error_only
        && (!TEST_uint64_t_lt(ossl_time2ms(elapsed), RECV_ERROR_PROMPT_MAX_MS)
            || !TEST_uint64_t_eq(ta.second_revents, 0)
            || !TEST_int_eq(BIO_socket_ready(idle_fd, 1), 0)))
        goto end;

    /* Shared snapshots can be checked without locks now that the worker joined. */
    if (!TEST_false(ta.barrier_timeout)
        || (ta.blocked_writer
            && (!TEST_size_t_eq(ta.waiters_at_barrier, 1)
                || !TEST_int_eq(BIO_socket_ready(ta.write_wait_fd, 0), 0)))
        || (!ta.blocking_write
            && (!TEST_size_t_eq(ta.waiters_at_barrier, 1)
                || !TEST_int_gt(ta.transient_receives, 0)))
        || (multi_item && !TEST_int_eq(ta.registered_descriptor_queries, 2))
        || !TEST_int_eq(ta.permanent_receives, 1)
        || !TEST_int_eq(ERR_GET_LIB(error), ERR_LIB_BIO)
        || !TEST_int_eq(ERR_GET_REASON(error), BIO_R_TRANSFER_ERROR))
        goto end;

    if (!direct_read) {
        if (!TEST_int_eq(ret, 1)
            || !TEST_size_t_eq(result_count, 1)
            || !TEST_uint64_t_eq(item.revents, SSL_POLL_EVENT_EL))
            goto end;

    } else if (!TEST_int_eq(ret, 0)
        || !TEST_size_t_eq(readbytes, 0)
        || !TEST_int_eq(read_error, SSL_ERROR_SSL)) {
        goto end;
    }

    /* The last waiter must unregister and drain any production notification. */
    if (!TEST_size_t_eq(dl->cur_blocking_waiters, 0)
        || !TEST_int_eq(dl->signalled_notifier, 0)
        || !TEST_int_eq(BIO_socket_ready(nfd, 1), 0)
        || !TEST_int_eq(BIO_socket_ready(server_fd, 1), 0))
        goto end;

    if (ta.blocking_accept) {
        /* Retain the transport error without appending a generic SSL error. */
        if (!TEST_ptr_null(ta.accepted)
            || !TEST_int_eq(ERR_GET_LIB(ta.first_error), ERR_LIB_BIO)
            || !TEST_int_eq(ERR_GET_REASON(ta.first_error), BIO_R_TRANSFER_ERROR)
            || !TEST_int_eq(ERR_GET_LIB(ta.error), ERR_LIB_BIO)
            || !TEST_int_eq(ERR_GET_REASON(ta.error), BIO_R_TRANSFER_ERROR))
            goto end;

    } else if (ta.blocking_write) {
        /* A bounded escape or another send cannot substitute for failure. */
        if (!TEST_false(ta.send_limit_hit)
            || !TEST_int_eq(ta.send_attempts, 1)
            || !TEST_int_eq(ta.ret, 0)
            || !TEST_size_t_eq(ta.written, 0)
            || !TEST_int_eq(ta.ssl_error, SSL_ERROR_SSL)
            || !TEST_int_eq(ERR_GET_LIB(ta.first_error), ERR_LIB_BIO)
            || !TEST_int_eq(ERR_GET_REASON(ta.first_error), BIO_R_TRANSFER_ERROR)
            || !TEST_int_eq(ERR_GET_LIB(ta.error), ERR_LIB_BIO)
            || !TEST_int_eq(ERR_GET_REASON(ta.error), BIO_R_TRANSFER_ERROR))
            goto end;

    } else if (ta.blocking_read) {
        /* The worker must retain the original error on its own error queue. */
        if (!TEST_int_eq(ta.ret, 0)
            || !TEST_size_t_eq(ta.readbytes, 0)
            || !TEST_int_eq(ta.ssl_error, SSL_ERROR_SSL)
            || !TEST_int_eq(ERR_GET_LIB(ta.error), ERR_LIB_BIO)
            || !TEST_int_eq(ERR_GET_REASON(ta.error), BIO_R_TRANSFER_ERROR))
            goto end;

    } else if (!TEST_int_eq(ta.ret, 1)
        || !TEST_size_t_eq(ta.result_count, multi_item ? 2 : 1)
        || !TEST_uint64_t_eq(ta.revents, SSL_POLL_EVENT_EC)
        || (multi_item
            && !TEST_uint64_t_eq(ta.second_revents, SSL_POLL_EVENT_EC))) {
        goto end;
    }

    /* Accept may drain the notifier; idx 5 checks write failure, not notification. */
    if (!TEST_int_ge(ossl_time_compare(ta.finished, ta.released), 0)
        || !TEST_uint64_t_lt(ossl_time2ms(elapsed), RECV_ERROR_PROMPT_MAX_MS)
        || (!ta.blocking_accept && (!ta.blocking_write || ta.blocked_writer)
            && !TEST_int_eq(notifier_ready, 1)))
        goto end;

    testresult = 1;
end:
    if (ta.thread != NULL && ta.blocking_accept) {
        /*
         * An observer timeout must also release accept through production
         * error handling. Arming alone cannot wake an idle socket waiter.
         */
        ossl_crypto_mutex_lock(ta.mutex);
        ta.armed = 1;
        ossl_crypto_mutex_unlock(ta.mutex);
        ERR_clear_error();
        if (!TEST_int_eq(ret = SSL_read_ex(detect_conn, &buf, sizeof(buf),
                             &readbytes),
                0)
            || !TEST_int_eq(SSL_get_error(detect_conn, ret), SSL_ERROR_SSL))
            testresult = 0;
    }
    /* Release and join the worker before freeing anything it could still use. */
    recv_error_release_join(&ta);
    if (idle_bio != NULL) {
        BIO_set_callback_ex(idle_bio, NULL);
        BIO_set_callback_arg(idle_bio, NULL);
    }
    SSL_free(ta.idle_listener);
    BIO_ADDR_free(idle_addr);
    if (idle_fd >= 0)
        BIO_closesocket(idle_fd);
    SSL_free(ta.accepted);
    SSL_free(second_conn);
    SSL_free(second_client);
    SSL_free(detect_conn);
    SSL_free(detect_client);
    SSL_free(conn);
    SSL_free(client);
    SSL_free(listener);
    BIO_free_all(filter);
    BIO_free_all(wfilter);
    BIO_meth_free(method);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    if (client_fd >= 0)
        BIO_closesocket(client_fd);
    if (detect_client_fd >= 0)
        BIO_closesocket(detect_client_fd);
    if (second_client_fd >= 0)
        BIO_closesocket(second_client_fd);
    if (write_wait_fds[0] >= 0)
        BIO_closesocket(write_wait_fds[0]);
    if (write_wait_fds[1] >= 0)
        BIO_closesocket(write_wait_fds[1]);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ossl_crypto_condvar_free(&ta.cv);
    ossl_crypto_mutex_free(&ta.mutex);
    return testresult;
}
#endif

#define NUM_LISTENER_THREADS 2
#define LISTENER_RACE_ITERATIONS 1000
#define CLIENT_TRAFFIC_ITERATIONS 25
#define CLEAR_REPLACE_CYCLES 3

struct listener_thread_args {
    SSL *listener;
    CRYPTO_THREAD *thread;
    int result;
};

static unsigned int listener_thread(void *arg)
{
    struct listener_thread_args *ta = arg;
    SSL_POLL_ITEM item;
    struct timeval timeout;
    size_t result_count;
    int i;

    ta->result = 0;
    item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    item.desc.value.ssl = ta->listener;
    item.events = SSL_POLL_EVENT_IC;
    timeout.tv_sec = 0;
    timeout.tv_usec = 1000;

    for (i = 0; i < LISTENER_RACE_ITERATIONS; i++) {
        item.revents = 0;
        if (!SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count))
            return 0;
        OSSL_sleep(1);
    }

    ta->result = 1;
    return 0;
}

struct client_traffic_thread_args {
    SSL *client;
    CRYPTO_THREAD *thread;
    int result;
};

static unsigned int client_traffic_thread(void *arg)
{
    struct client_traffic_thread_args *ta = arg;
    size_t written;
    int i, ret, err;

    ta->result = 0;
    for (i = 0; i < CLIENT_TRAFFIC_ITERATIONS; i++) {
        ret = SSL_write_ex(ta->client, CLIENT_TO_SERVER_MSG,
            strlen(CLIENT_TO_SERVER_MSG), &written);
        if (ret <= 0) {
            err = SSL_get_error(ta->client, ret);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                return 0;
        }
        OSSL_sleep(1);
    }

    ta->result = 1;
    return 0;
}

/*
 * Exercise concurrent listener polling while pending connections enter their
 * first SSL_accept(), which calls SSL_clear(). This covers listener state that
 * must remain stable while d1 is reset or replaced. ThreadSanitizer verifies
 * that the listener threads do not race on that state.
 */
static int test_dtls_listener_clear_race(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clients[NUM_CLIENTS] = { NULL };
    SSL *server_conns[NUM_CLIENTS] = { NULL };
    struct listener_thread_args thread_args[NUM_LISTENER_THREADS];
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1;
    int client_fds[NUM_CLIENTS] = { -1, -1, -1 };
    int testresult = 0;
    int i;

    memset(thread_args, 0, sizeof(thread_args));

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), 0, 0, &sctx, &cctx, cert, privkey))
        || !TEST_true(create_listener_ex(sctx, SSL_LISTENER_FLAG_NO_VALIDATE,
            &listener, &server_addr, &server_fd))
        || !TEST_true(SSL_set_blocking_mode(listener, 0)))
        goto err;

    for (i = 0; i < NUM_CLIENTS; i++) {
        if (!TEST_true(create_client(cctx, server_addr, &clients[i],
                &client_fds[i])))
            goto err;
    }

    for (i = 0; i < NUM_LISTENER_THREADS; i++) {
        thread_args[i].listener = listener;
        thread_args[i].thread = ossl_crypto_thread_native_start(
            listener_thread, &thread_args[i], 1);
        if (!TEST_ptr(thread_args[i].thread))
            goto err;
    }

    for (i = 0; i < NUM_CLIENTS; i++)
        if (!TEST_true(do_handshake(clients[i], listener, &server_conns[i])))
            goto err;

    for (i = 0; i < NUM_LISTENER_THREADS; i++) {
        ossl_crypto_thread_native_join(thread_args[i].thread, NULL);
        ossl_crypto_thread_native_clean(thread_args[i].thread);
        thread_args[i].thread = NULL;
        if (!TEST_int_eq(thread_args[i].result, 1))
            goto err;
    }

    testresult = 1;
err:
    for (i = 0; i < NUM_LISTENER_THREADS; i++) {
        if (thread_args[i].thread != NULL) {
            ossl_crypto_thread_native_join(thread_args[i].thread, NULL);
            ossl_crypto_thread_native_clean(thread_args[i].thread);
        }
    }
    for (i = 0; i < NUM_CLIENTS; i++) {
        SSL_free(clients[i]);
        SSL_free(server_conns[i]);
        if (client_fds[i] >= 0)
            BIO_closesocket(client_fds[i]);
    }
    SSL_free(listener);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/* Exercise the SSL_clear() path which replaces d1 after a handshake. */
static int test_dtls_listener_clear_replace_race(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL, *client = NULL, *server_conn = NULL;
    struct listener_thread_args thread_args[NUM_LISTENER_THREADS];
    struct client_traffic_thread_args traffic_args;
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1, client_fd = -1;
    int testresult = 0;
    int i;

    memset(thread_args, 0, sizeof(thread_args));
    memset(&traffic_args, 0, sizeof(traffic_args));

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), 0, 0, &sctx, &cctx, cert, privkey))
        || !TEST_true(create_listener_ex(sctx, SSL_LISTENER_FLAG_NO_VALIDATE,
            &listener, &server_addr, &server_fd))
        || !TEST_true(SSL_set_blocking_mode(listener, 0))
        || !TEST_true(create_client(cctx, server_addr, &client, &client_fd))
        || !TEST_true(do_handshake(client, listener, &server_conn)))
        goto err;

    for (i = 0; i < NUM_LISTENER_THREADS; i++) {
        thread_args[i].listener = listener;
        thread_args[i].thread = ossl_crypto_thread_native_start(
            listener_thread, &thread_args[i], 1);
        if (!TEST_ptr(thread_args[i].thread))
            goto err;
    }

    for (i = 0; i < CLEAR_REPLACE_CYCLES; i++) {
        traffic_args.client = client;
        traffic_args.result = 0;
        traffic_args.thread = ossl_crypto_thread_native_start(
            client_traffic_thread, &traffic_args, 1);
        if (!TEST_ptr(traffic_args.thread))
            goto err;

        OSSL_sleep(2);
        if (!TEST_true(SSL_clear(server_conn)))
            goto err;

        /* Let the listener threads route client datagrams through the reset. */
        OSSL_sleep(5);

        ossl_crypto_thread_native_join(traffic_args.thread, NULL);
        ossl_crypto_thread_native_clean(traffic_args.thread);
        traffic_args.thread = NULL;
        if (!TEST_int_eq(traffic_args.result, 1)
            || !TEST_true(SSL_clear(client)))
            goto err;

        SSL_set_accept_state(server_conn);
        SSL_set_connect_state(client);
        if (!TEST_true(create_ssl_connection(server_conn, client,
                SSL_ERROR_NONE)))
            goto err;
    }

    for (i = 0; i < NUM_LISTENER_THREADS; i++) {
        ossl_crypto_thread_native_join(thread_args[i].thread, NULL);
        ossl_crypto_thread_native_clean(thread_args[i].thread);
        thread_args[i].thread = NULL;
        if (!TEST_int_eq(thread_args[i].result, 1))
            goto err;
    }

    testresult = 1;
err:
    if (traffic_args.thread != NULL) {
        ossl_crypto_thread_native_join(traffic_args.thread, NULL);
        ossl_crypto_thread_native_clean(traffic_args.thread);
    }
    for (i = 0; i < NUM_LISTENER_THREADS; i++) {
        if (thread_args[i].thread != NULL) {
            ossl_crypto_thread_native_join(thread_args[i].thread, NULL);
            ossl_crypto_thread_native_clean(thread_args[i].thread);
        }
    }
    SSL_free(client);
    SSL_free(server_conn);
    SSL_free(listener);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    if (client_fd >= 0)
        BIO_closesocket(client_fd);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Main test: multiple threads polling on different DTLS connections
 */
static int test_dtls_multithread(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clients[NUM_CLIENTS] = { NULL };
    SSL *server_conns[NUM_CLIENTS] = { NULL };
    int client_fds[NUM_CLIENTS] = { -1, -1, -1 };
    struct server_thread_args server_args[NUM_CLIENTS];
    struct client_thread_args client_args[NUM_CLIENTS];
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1;
    int testresult = 0;
    int i;

    memset(server_args, 0, sizeof(server_args));
    memset(client_args, 0, sizeof(client_args));

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            0, 0,
            &sctx, &cctx, cert, privkey)))
        goto err;

    if (!TEST_true(create_listener(sctx, &listener, &server_addr, &server_fd)))
        goto err;

    /*
     * do_handshake() below drives both ends from this thread, so the server
     * side must not block: a blocking read would wait for a client which only
     * this thread can advance. Connections accepted from the listener inherit
     * this. The worker threads which follow use SSL_poll() and expect
     * SSL_ERROR_WANT_READ, so they need it too.
     */
    if (!TEST_true(SSL_set_blocking_mode(listener, 0)))
        goto err;

    for (i = 0; i < NUM_CLIENTS; i++) {
        if (!TEST_true(create_client(cctx, server_addr, &clients[i], &client_fds[i])))
            goto err;

        if (!TEST_true(do_handshake(clients[i], listener, &server_conns[i])))
            goto err;
    }

    /* Start server threads - each will poll and wait for data */
    for (i = 0; i < NUM_CLIENTS; i++) {
        server_args[i].conn = server_conns[i];
        server_args[i].thread_idx = i;
        server_args[i].result = 0;

        server_args[i].thread = ossl_crypto_thread_native_start(
            server_conn_thread, &server_args[i], 1);
        if (!TEST_ptr(server_args[i].thread))
            goto err;
    }

    /* Start client threads - each will send data and wait for response */
    for (i = 0; i < NUM_CLIENTS; i++) {
        client_args[i].conn = clients[i];
        client_args[i].thread_idx = i;
        client_args[i].result = 0;

        client_args[i].thread = ossl_crypto_thread_native_start(
            client_conn_thread, &client_args[i], 1);
        if (!TEST_ptr(client_args[i].thread))
            goto err;
    }

    /* Wait for all server threads to complete */
    for (i = 0; i < NUM_CLIENTS; i++) {
        ossl_crypto_thread_native_join(server_args[i].thread, NULL);
        ossl_crypto_thread_native_clean(server_args[i].thread);
        server_args[i].thread = NULL;

        if (!TEST_int_eq(server_args[i].result, 1))
            goto err;
    }

    /* Wait for all client threads to complete */
    for (i = 0; i < NUM_CLIENTS; i++) {
        ossl_crypto_thread_native_join(client_args[i].thread, NULL);
        ossl_crypto_thread_native_clean(client_args[i].thread);
        client_args[i].thread = NULL;

        if (!TEST_int_eq(client_args[i].result, 1))
            goto err;
    }

    testresult = 1;

err:
    /* Clean up any remaining server threads */
    for (i = 0; i < NUM_CLIENTS; i++) {
        if (server_args[i].thread != NULL) {
            ossl_crypto_thread_native_join(server_args[i].thread, NULL);
            ossl_crypto_thread_native_clean(server_args[i].thread);
        }
    }

    /* Clean up any remaining client threads */
    for (i = 0; i < NUM_CLIENTS; i++) {
        if (client_args[i].thread != NULL) {
            ossl_crypto_thread_native_join(client_args[i].thread, NULL);
            ossl_crypto_thread_native_clean(client_args[i].thread);
        }
    }

    for (i = 0; i < NUM_CLIENTS; i++) {
        SSL_free(clients[i]);
        SSL_free(server_conns[i]);
        if (client_fds[i] >= 0)
            BIO_closesocket(client_fds[i]);
    }

    SSL_free(listener);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);

    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

/*
 * Per-thread state for the blocking accept
 */
struct accept_thread_args {
    SSL *listener;
    SSL *conn; /* connection the accept returned */
    CRYPTO_THREAD *thread;
    int result; /* 1 = success, 0 = failure */
};

/*
 * Thread function: block in SSL_accept_connection() until a connection turns
 * up. This is the accept path which ticks the listener itself, so no other
 * thread needs to drive it.
 */
static unsigned int blocking_accept_thread(void *arg)
{
    struct accept_thread_args *ta = (struct accept_thread_args *)arg;

    ta->conn = SSL_accept_connection(ta->listener, 0);
    ta->result = (ta->conn != NULL);
    return 1;
}

/*
 * Test that a blocking SSL_accept_connection() waits for a connection and
 * returns it.
 *
 * The listener demultiplexes one socket to many connections, so it cannot
 * block inside a read: doing so would stall every other connection, and the
 * demux lock is held across it. Blocking accept therefore has to wait for
 * readiness rather than for a datagram, which is what this exercises - a
 * client is only created once the accepting thread is already in the call.
 *
 * This cannot distinguish waiting from spinning: the accept returns the
 * connection either way, and the difference is not observable through the
 * API.
 */
static int test_dtls_blocking_accept(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL, *client = NULL;
    struct accept_thread_args accept_args;
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1, client_fd = -1;
    int testresult = 0;
    int i, ret, err;

    memset(&accept_args, 0, sizeof(accept_args));

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), 0, 0, &sctx, &cctx, cert, privkey)))
        goto err;

    if (!TEST_true(create_listener(sctx, &listener, &server_addr, &server_fd)))
        goto err;

    /* This test needs the blocking accept. */
    if (!TEST_true(SSL_set_blocking_mode(listener, 1)))
        goto err;

    /*
     * Create the client's socket first, but do not connect with it yet. There
     * is no way to cancel a blocking SSL_accept_connection(), so a thread
     * parked in one is released only by a connection arriving - which means
     * nothing between starting the thread and the exchange completing may bail
     * out, or the join below would wait for ever. Anything which can fail is
     * therefore done up front. The accept still has to wait, since no datagram
     * is sent until SSL_connect() below.
     */
    if (!TEST_true(create_client(cctx, server_addr, &client, &client_fd)))
        goto err;

    accept_args.listener = listener;
    accept_args.thread = ossl_crypto_thread_native_start(blocking_accept_thread,
        &accept_args, 1);
    if (!TEST_ptr(accept_args.thread))
        goto err;

    /*
     * Drive the client's side of the cookie exchange. The accepting thread
     * ticks the listener, so this only has to keep the client moving.
     */
    SSL_set_connect_state(client);
    for (i = 0; i < 200 && accept_args.result == 0; i++) {
        ret = SSL_connect(client);
        err = SSL_get_error(client, ret);
        if (ret <= 0 && err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect failed (err %d)", err);
            goto err;
        }
        OSSL_sleep(10);
    }

    ossl_crypto_thread_native_join(accept_args.thread, NULL);
    ossl_crypto_thread_native_clean(accept_args.thread);
    accept_args.thread = NULL;

    if (!TEST_int_eq(accept_args.result, 1) || !TEST_ptr(accept_args.conn))
        goto err;

    testresult = 1;
err:
    if (accept_args.thread != NULL) {
        ossl_crypto_thread_native_join(accept_args.thread, NULL);
        ossl_crypto_thread_native_clean(accept_args.thread);
    }
    SSL_free(accept_args.conn);
    SSL_free(client);
    SSL_free(listener);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    if (client_fd >= 0)
        BIO_closesocket(client_fd);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * How long the client waits, in milliseconds, after its handshake completes
 * before sending anything. The server thread has to still be inside its
 * blocking read when the write finally happens, or the test proves nothing.
 *
 * A machine slow enough to get there late does not make the test fail: the read
 * then finds the datagram already queued and returns it, which is a pass with
 * nothing demonstrated. Only the absence of blocking turns it into a failure.
 */
#define BLOCKING_READ_QUIET_MS 250

/*
 * Per-thread state for the blocking read
 */
struct read_thread_args {
    SSL *listener;
    SSL *conn; /* connection the accept returned */
    CRYPTO_THREAD *thread;
    char buf[256];
    size_t readbytes;
    int nonblocking_handshake; /* handshake without blocking mode */
    int result; /* 1 = success, 0 = failure */
};

/*
 * Helper: complete the handshake with the connection in non-blocking mode,
 * driving the listener by hand, so that the blocking read which follows is the
 * only thing relying on the emulation.
 */
static int nonblocking_handshake(struct read_thread_args *ta)
{
    int i, ret = -1, err;

    if (!TEST_true(SSL_set_blocking_mode(ta->conn, 0)))
        return 0;

    for (i = 0; i < 200; i++) {
        ret = SSL_accept(ta->conn);
        if (ret == 1)
            break;
        err = SSL_get_error(ta->conn, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_accept failed (err %d)", err);
            return 0;
        }
        /* Nothing else will service the listener while we are in here. */
        if (!TEST_true(SSL_handle_events(ta->listener)))
            return 0;
        OSSL_sleep(10);
    }

    if (!TEST_int_eq(ret, 1))
        return 0;

    return TEST_true(SSL_set_blocking_mode(ta->conn, 1));
}

/*
 * Thread function: accept a connection, complete its handshake and read from
 * it, so that the thread never has to handle WANT_READ.
 */
static unsigned int blocking_read_thread(void *arg)
{
    struct read_thread_args *ta = (struct read_thread_args *)arg;

    ta->conn = SSL_accept_connection(ta->listener, 0);
    if (!TEST_ptr(ta->conn))
        return 0;

    /*
     * A listener-created connection has no BIO of its own to block in - it
     * reads from a queue the listener demultiplexes into - so without the
     * emulation these calls return immediately with WANT_READ instead of
     * waiting.
     */
    if (ta->nonblocking_handshake) {
        if (!nonblocking_handshake(ta))
            return 0;
    } else if (!TEST_int_gt(SSL_accept(ta->conn), 0)) {
        return 0;
    }

    if (!TEST_true(SSL_read_ex(ta->conn, ta->buf, sizeof(ta->buf) - 1,
            &ta->readbytes)))
        return 0;

    ta->result = 1;
    return 0;
}

/*
 * Test that a blocking listener connection waits for a datagram rather than
 * reporting WANT_READ.
 *
 * The client stays silent for BLOCKING_READ_QUIET_MS after its own handshake
 * completes, so by the time it writes, the server thread is already parked in
 * SSL_read_ex() with nothing to return. A non-blocking connection reports
 * WANT_READ immediately, so the absence of the emulation shows up as a failed
 * assertion rather than as a hang.
 *
 * idx 0 blocks in the handshake as well as in the read. idx 1 handshakes in
 * non-blocking mode and only then switches the connection to blocking, so
 * the read is the only thing relying on the emulation.
 *
 * Only the client is driven from this thread: the accepting thread ticks the
 * listener itself, which is what lets a blocked connection make progress at
 * all.
 */
static int test_dtls_blocking_read(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL, *client = NULL;
    struct read_thread_args read_args;
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1, client_fd = -1;
    int testresult = 0;
    size_t written;
    int i, ret = -1, err;

    memset(&read_args, 0, sizeof(read_args));

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), 0, 0, &sctx, &cctx, cert, privkey)))
        goto err;

    if (!TEST_true(create_listener(sctx, &listener, &server_addr, &server_fd)))
        goto err;

    /* Blocking is the default, but this test depends on it, so be explicit. */
    if (!TEST_true(SSL_set_blocking_mode(listener, 1)))
        goto err;

    /*
     * As in test_dtls_blocking_accept, create the client's socket before the
     * thread which will park in the blocking accept, because nothing can
     * release that thread except a connection arriving. Nothing is sent until
     * SSL_connect() below, so the accept still waits.
     */
    if (!TEST_true(create_client(cctx, server_addr, &client, &client_fd)))
        goto err;

    read_args.listener = listener;
    read_args.nonblocking_handshake = idx;
    read_args.thread = ossl_crypto_thread_native_start(blocking_read_thread,
        &read_args, 1);
    if (!TEST_ptr(read_args.thread))
        goto err;

    /* Drive the client's handshake to completion. */
    SSL_set_connect_state(client);
    for (i = 0; i < 200; i++) {
        ret = SSL_connect(client);
        if (ret == 1)
            break;
        err = SSL_get_error(client, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect failed (err %d)", err);
            goto err;
        }
        OSSL_sleep(10);
    }
    if (!TEST_int_eq(ret, 1))
        goto err;

    /* Let the server thread reach its read and find nothing there. */
    OSSL_sleep(BLOCKING_READ_QUIET_MS);

    if (!TEST_true(SSL_write_ex(client, CLIENT_TO_SERVER_MSG,
            strlen(CLIENT_TO_SERVER_MSG), &written)))
        goto err;

    ossl_crypto_thread_native_join(read_args.thread, NULL);
    ossl_crypto_thread_native_clean(read_args.thread);
    read_args.thread = NULL;

    if (!TEST_int_eq(read_args.result, 1))
        goto err;

    read_args.buf[read_args.readbytes] = '\0';
    if (!TEST_str_eq(read_args.buf, CLIENT_TO_SERVER_MSG))
        goto err;

    testresult = 1;
err:
    if (read_args.thread != NULL) {
        ossl_crypto_thread_native_join(read_args.thread, NULL);
        ossl_crypto_thread_native_clean(read_args.thread);
    }
    SSL_free(read_args.conn);
    SSL_free(client);
    SSL_free(listener);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    if (client_fd >= 0)
        BIO_closesocket(client_fd);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

    ADD_TEST(test_dtls_multithread);
#if !defined(OPENSSL_NO_DTLS1_3) || !defined(OPENSSL_NO_DTLS1_2)
    ADD_ALL_TESTS(test_dtls_listener_recv_error_notifier, 9);
#endif
    ADD_TEST(test_dtls_listener_clear_race);
    ADD_TEST(test_dtls_listener_clear_replace_race);
    ADD_TEST(test_dtls_blocking_accept);
    ADD_ALL_TESTS(test_dtls_blocking_read, 2);
    return 1;
}
