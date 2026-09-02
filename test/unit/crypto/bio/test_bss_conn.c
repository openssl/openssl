/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/sockets.h"

#ifndef OPENSSL_NO_SOCK

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <cmocka.h>
#include "bio_local.h"

#define FAKE_SOCKET 42

/*
 * Fake addrinfo used across state machine tests.  g_addrinfo1.bai_next is
 * NULL by default.  Tests needing a second address temporarily set it to
 * &g_addrinfo2 and restore it afterwards.
 */
static struct sockaddr_in g_sin;
static BIO_ADDRINFO g_addrinfo1;
static BIO_ADDRINFO g_addrinfo2;

/* prototypes for __wrap_* (required by -Wmissing-prototypes) */
ssize_t __wrap_read(int fd, void *buf, size_t count);
ssize_t __wrap_write(int fd, const void *buf, size_t count);
int __wrap_BIO_lookup(const char *host, const char *service,
    enum BIO_lookup_type lookup_type,
    int family, int socktype, BIO_ADDRINFO **res);
int __wrap_BIO_socket(int domain, int socktype, int protocol, int options);
int __wrap_BIO_connect(int sock, const BIO_ADDR *addr, int options);
int __wrap_BIO_sock_should_retry(int i);
int __wrap_BIO_closesocket(int sock);
int __wrap_BIO_socket_wait(int fd, int for_write, time_t max_time);
int __wrap_BIO_sock_error(int sock);

/* wraps */

ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    function_called();
    check_expected(fd);
    check_expected_ptr(buf);
    check_expected(count);
    return mock_type(ssize_t);
}

ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
    function_called();
    check_expected(fd);
    check_expected_ptr(buf);
    check_expected(count);
    return mock_type(ssize_t);
}

int __wrap_BIO_lookup(const char *host, const char *service,
    enum BIO_lookup_type lookup_type,
    int family, int socktype, BIO_ADDRINFO **res)
{
    int rc;

    function_called();
    check_expected(host);
    check_expected(service);
    check_expected(lookup_type);
    check_expected(family);
    check_expected(socktype);
    rc = mock_type(int);
    if (rc == 1)
        *res = mock_ptr_type(BIO_ADDRINFO *);
    return rc;
}

int __wrap_BIO_socket(int domain, int socktype, int protocol, int options)
{
    function_called();
    check_expected(domain);
    check_expected(socktype);
    check_expected(protocol);
    check_expected(options);
    return mock_type(int);
}

int __wrap_BIO_connect(int sock, const BIO_ADDR *addr, int options)
{
    function_called();
    check_expected(sock);
    check_expected_ptr(addr);
    check_expected(options);
    return mock_type(int);
}

int __wrap_BIO_sock_should_retry(int i)
{
    function_called();
    check_expected(i);
    return mock_type(int);
}

int __wrap_BIO_closesocket(int sock)
{
    function_called();
    check_expected(sock);
    return mock_type(int);
}

int __wrap_BIO_socket_wait(int fd, int for_write, time_t max_time)
{
    function_called();
    check_expected(fd);
    check_expected(for_write);
    (void)max_time; /* derived from time(NULL): not checked */
    return mock_type(int);
}

int __wrap_BIO_sock_error(int sock)
{
    function_called();
    check_expected(sock);
    return mock_type(int);
}

/*
 * A minimal fake dgram BIO.  conn_read/conn_write/conn_sendmmsg/conn_recvmmsg
 * delegate to the public BIO_* calls on data->dgram_bio, so the leaf needs
 * read/write/sendmmsg/recvmmsg to dispatch.  Everything the connect layer
 * forwards (the buffer, message array, stride, count and flags) is verified.
 */

static int fake_dgram_read(BIO *b, char *buf, size_t size, size_t *readbytes);
static int fake_dgram_write(BIO *b, const char *buf, size_t size,
    size_t *written);
static long fake_dgram_ctrl(BIO *b, int cmd, long arg1, void *arg2);
static int fake_dgram_sendmmsg(BIO *b, BIO_MSG *m, size_t s, size_t n,
    uint64_t f, size_t *mp);
static int fake_dgram_recvmmsg(BIO *b, BIO_MSG *m, size_t s, size_t n,
    uint64_t f, size_t *mp);

static int fake_dgram_read(BIO *b, char *buf, size_t size, size_t *readbytes)
{
    int ret;

    (void)b;
    function_called();
    check_expected_ptr(buf);
    check_expected(size);
    ret = mock_type(int);
    if (ret > 0) {
        *readbytes = (size_t)ret;
        return 1;
    }
    *readbytes = 0;
    return ret;
}

static int fake_dgram_write(BIO *b, const char *buf, size_t size,
    size_t *written)
{
    int ret;

    (void)b;
    function_called();
    check_expected_ptr(buf);
    check_expected(size);
    ret = mock_type(int);
    if (ret > 0) {
        *written = (size_t)ret;
        return 1;
    }
    *written = 0;
    return ret;
}

static long fake_dgram_ctrl(BIO *b, int cmd, long arg1, void *arg2)
{
    (void)b;
    (void)arg1;
    (void)arg2;
    if (cmd == BIO_CTRL_FLUSH)
        return 1;
    return 0;
}

static int fake_dgram_sendmmsg(BIO *b, BIO_MSG *m, size_t s, size_t n,
    uint64_t f, size_t *mp)
{
    (void)b;
    function_called();
    check_expected_ptr(m);
    check_expected(s);
    check_expected(n);
    check_expected(f);
    *mp = mock_type(size_t);
    return mock_type(int);
}

static int fake_dgram_recvmmsg(BIO *b, BIO_MSG *m, size_t s, size_t n,
    uint64_t f, size_t *mp)
{
    (void)b;
    function_called();
    check_expected_ptr(m);
    check_expected(s);
    check_expected(n);
    check_expected(f);
    *mp = mock_type(size_t);
    return mock_type(int);
}

static BIO_METHOD *fake_dgram_method = NULL;

static BIO_METHOD *make_fake_dgram_method(void)
{
    BIO_METHOD *m = BIO_meth_new(BIO_TYPE_DGRAM | 0xff, "fake dgram");

    assert_non_null(m);
    assert_true(BIO_meth_set_read_ex(m, fake_dgram_read));
    assert_true(BIO_meth_set_write_ex(m, fake_dgram_write));
    assert_true(BIO_meth_set_ctrl(m, fake_dgram_ctrl));
    assert_true(BIO_meth_set_sendmmsg(m, fake_dgram_sendmmsg));
    assert_true(BIO_meth_set_recvmmsg(m, fake_dgram_recvmmsg));
    return m;
}

static BIO *make_fake_dgram(void)
{
    BIO *d = BIO_new(fake_dgram_method);

    assert_non_null(d);
    BIO_set_init(d, 1);
    return d;
}

/* expectations */

static void expect_read(int fd, const void *buf, size_t count, ssize_t rc)
{
    expect_function_call(__wrap_read);
    expect_value(__wrap_read, fd, fd);
    expect_value(__wrap_read, buf, buf);
    expect_value(__wrap_read, count, count);
    will_return(__wrap_read, rc);
}

static void expect_write(int fd, const void *buf, size_t count, ssize_t rc)
{
    expect_function_call(__wrap_write);
    expect_value(__wrap_write, fd, fd);
    expect_value(__wrap_write, buf, buf);
    expect_value(__wrap_write, count, count);
    will_return(__wrap_write, rc);
}

static void expect_BIO_lookup(BIO_ADDRINFO *res, int rc)
{
    expect_function_call(__wrap_BIO_lookup);
    expect_any(__wrap_BIO_lookup, host);
    expect_any(__wrap_BIO_lookup, service);
    expect_any(__wrap_BIO_lookup, lookup_type);
    expect_any(__wrap_BIO_lookup, family);
    expect_any(__wrap_BIO_lookup, socktype);
    will_return(__wrap_BIO_lookup, rc);
    if (rc == 1)
        will_return(__wrap_BIO_lookup, res);
}

/* options is the literal the state machine passes (always 0 here) */
static void expect_BIO_socket(int domain, int socktype, int protocol,
    int options, int rc)
{
    expect_function_call(__wrap_BIO_socket);
    expect_value(__wrap_BIO_socket, domain, domain);
    expect_value(__wrap_BIO_socket, socktype, socktype);
    expect_value(__wrap_BIO_socket, protocol, protocol);
    expect_value(__wrap_BIO_socket, options, options);
    will_return(__wrap_BIO_socket, rc);
}

static void expect_BIO_connect(int sock, const BIO_ADDR *addr, int options,
    int rc)
{
    expect_function_call(__wrap_BIO_connect);
    expect_value(__wrap_BIO_connect, sock, sock);
    expect_value(__wrap_BIO_connect, addr, addr);
    expect_value(__wrap_BIO_connect, options, options);
    will_return(__wrap_BIO_connect, rc);
}

static void expect_BIO_sock_should_retry(int i, int rc)
{
    expect_function_call(__wrap_BIO_sock_should_retry);
    expect_value(__wrap_BIO_sock_should_retry, i, i);
    will_return(__wrap_BIO_sock_should_retry, rc);
}

static void expect_BIO_closesocket(int sock, int rc)
{
    expect_function_call(__wrap_BIO_closesocket);
    expect_value(__wrap_BIO_closesocket, sock, sock);
    will_return(__wrap_BIO_closesocket, rc);
}

static void expect_BIO_socket_wait(int fd, int for_write, int rc)
{
    expect_function_call(__wrap_BIO_socket_wait);
    expect_value(__wrap_BIO_socket_wait, fd, fd);
    expect_value(__wrap_BIO_socket_wait, for_write, for_write);
    will_return(__wrap_BIO_socket_wait, rc);
}

static void expect_BIO_sock_error(int sock, int rc)
{
    expect_function_call(__wrap_BIO_sock_error);
    expect_value(__wrap_BIO_sock_error, sock, sock);
    will_return(__wrap_BIO_sock_error, rc);
}

static void expect_fake_dgram_read(const void *buf, size_t size, int rc)
{
    expect_function_call(fake_dgram_read);
    expect_value(fake_dgram_read, buf, buf);
    expect_value(fake_dgram_read, size, size);
    will_return(fake_dgram_read, rc);
}

static void expect_fake_dgram_write(const void *buf, size_t size, int rc)
{
    expect_function_call(fake_dgram_write);
    expect_value(fake_dgram_write, buf, buf);
    expect_value(fake_dgram_write, size, size);
    will_return(fake_dgram_write, rc);
}

static void expect_fake_dgram_sendmmsg(const BIO_MSG *m, size_t s, size_t n,
    uint64_t f, size_t processed, int rc)
{
    expect_function_call(fake_dgram_sendmmsg);
    expect_value(fake_dgram_sendmmsg, m, m);
    expect_value(fake_dgram_sendmmsg, s, s);
    expect_value(fake_dgram_sendmmsg, n, n);
    expect_value(fake_dgram_sendmmsg, f, f);
    will_return(fake_dgram_sendmmsg, processed);
    will_return(fake_dgram_sendmmsg, rc);
}

static void expect_fake_dgram_recvmmsg(const BIO_MSG *m, size_t s, size_t n,
    uint64_t f, size_t processed, int rc)
{
    expect_function_call(fake_dgram_recvmmsg);
    expect_value(fake_dgram_recvmmsg, m, m);
    expect_value(fake_dgram_recvmmsg, s, s);
    expect_value(fake_dgram_recvmmsg, n, n);
    expect_value(fake_dgram_recvmmsg, f, f);
    will_return(fake_dgram_recvmmsg, processed);
    will_return(fake_dgram_recvmmsg, rc);
}

/* helpers */

static BIO_CONNECT *get_data(BIO *bio)
{
    return (BIO_CONNECT *)bio->ptr;
}

/*
 * Call at the end of any test that sets bio->num or addr_first to prevent
 * unexpected BIO_closesocket or BIO_ADDRINFO_free invocations in teardown.
 */
static void reset_for_teardown(BIO *bio)
{
    BIO_CONNECT *data = get_data(bio);

    bio->num = (int)INVALID_SOCKET;
    data->addr_first = NULL;
    data->addr_iter = NULL;
    data->state = BIO_CONN_S_BEFORE;
}

/* setup / teardown */

static int setup(void **state)
{
    BIO *bio = BIO_new(BIO_s_connect());

    assert_non_null(bio);
    *state = bio;
    return 0;
}

static int teardown(void **state)
{
    if (*state != NULL)
        BIO_free(*state);
    return 0;
}

/* I/O tests pre-establish state=OK so the state machine is not entered. */
static int setup_io(void **state)
{
    BIO *bio;
    BIO_CONNECT *data;

    if (setup(state) != 0)
        return -1;
    bio = *state;
    data = get_data(bio);
    data->state = BIO_CONN_S_OK;
    bio->num = FAKE_SOCKET;
    bio->init = 1;
    return 0;
}

static int teardown_io(void **state)
{
    if (*state != NULL)
        reset_for_teardown(*state);
    return teardown(state);
}

static int group_setup(void **state)
{
    (void)state;

    fake_dgram_method = make_fake_dgram_method();

    memset(&g_sin, 0, sizeof(g_sin));
    g_sin.sin_family = AF_INET;
    g_sin.sin_port = htons(443);
    g_sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    memset(&g_addrinfo1, 0, sizeof(g_addrinfo1));
    g_addrinfo1.bai_family = AF_INET;
    g_addrinfo1.bai_socktype = SOCK_STREAM;
    g_addrinfo1.bai_protocol = IPPROTO_TCP;
    g_addrinfo1.bai_addrlen = sizeof(g_sin);
    g_addrinfo1.bai_addr = (struct sockaddr *)&g_sin;
    g_addrinfo1.bai_next = NULL;

    memcpy(&g_addrinfo2, &g_addrinfo1, sizeof(g_addrinfo1));
    g_addrinfo2.bai_next = NULL;

    return 0;
}

static int group_teardown(void **state)
{
    (void)state;
    BIO_meth_free(fake_dgram_method);
    fake_dgram_method = NULL;
    return 0;
}

/* conn_new */

static void test_conn_new(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    assert_non_null(data);
    assert_int_equal(data->state, BIO_CONN_S_BEFORE);
    assert_int_equal(data->connect_family, BIO_FAMILY_IPANY);
    assert_int_equal(data->connect_sock_type, SOCK_STREAM);
    assert_null(data->param_hostname);
    assert_null(data->param_service);
    assert_null(data->addr_first);
    assert_null(data->dgram_bio);
    assert_int_equal(bio->num, (int)INVALID_SOCKET);
    assert_int_equal(bio->init, 0);
}

/* conn_free */

static void test_conn_free_no_shutdown(void **state)
{
    /* shutdown=0: conn_close_socket and BIO_CONNECT_free are both skipped */
    BIO *bio = BIO_new(BIO_s_connect());

    assert_non_null(bio);
    bio->shutdown = BIO_NOCLOSE;
    BIO_free(bio);
    *state = NULL;
}

/* conn_close_socket (via BIO_CTRL_RESET) */

static void test_close_socket_none(void **state)
{
    /* bio->num == INVALID_SOCKET: no calls expected */
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_RESET, 0, NULL), 0);
}

static void test_close_socket_non_ok_state(void **state)
{
    /* Socket open but state != OK: BIO_closesocket called, no shutdown */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    bio->num = FAKE_SOCKET;
    data->state = BIO_CONN_S_BLOCKED_CONNECT;

    expect_BIO_closesocket(FAKE_SOCKET, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_RESET, 0, NULL), 0);
    assert_int_equal(bio->num, (int)INVALID_SOCKET);
    assert_int_equal(data->state, BIO_CONN_S_BEFORE);
}

static void test_close_socket_ok_state(void **state)
{
    /* Socket open and state=OK: shutdown first, then BIO_closesocket */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    bio->num = FAKE_SOCKET;
    data->state = BIO_CONN_S_OK;

    expect_BIO_closesocket(FAKE_SOCKET, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_RESET, 0, NULL), 0);
    assert_int_equal(bio->num, (int)INVALID_SOCKET);
    assert_int_equal(data->state, BIO_CONN_S_BEFORE);
}

/* conn_state (via BIO_C_DO_STATE_MACHINE) */

static void test_conn_state_no_hostname(void **state)
{
    /* BEFORE with no hostname and no service */
    assert_true(BIO_ctrl(*state, BIO_C_DO_STATE_MACHINE, 0, NULL) <= 0);
}

static void test_conn_state_unsupported_family(void **state)
{
    /* BEFORE -> GET_ADDR -> unrecognised connect_family -> error */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->param_hostname = OPENSSL_strdup("host");
    data->param_service = OPENSSL_strdup("443");
    data->connect_family = 9999;

    assert_true(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL) <= 0);
}

static void test_conn_state_lookup_fails(void **state)
{
    /* BEFORE -> GET_ADDR -> BIO_lookup returns 0 */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->param_hostname = OPENSSL_strdup("host");
    data->param_service = OPENSSL_strdup("443");

    expect_BIO_lookup(NULL, 0);
    assert_true(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL) <= 0);
}

static void test_conn_state_socket_fails(void **state)
{
    /* Pre-set CREATE_SOCKET: BIO_socket returns INVALID_SOCKET */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->state = BIO_CONN_S_CREATE_SOCKET;
    data->addr_iter = &g_addrinfo1;

    expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0,
        (int)INVALID_SOCKET);
    assert_true(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL) <= 0);

    data->addr_iter = NULL;
    data->state = BIO_CONN_S_BEFORE;
}

static void test_conn_state_connect_succeeds(void **state)
{
    /* Full happy path: BEFORE -> GET_ADDR -> CREATE_SOCKET -> CONNECT -> OK */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->param_hostname = OPENSSL_strdup("host");
    data->param_service = OPENSSL_strdup("443");

    expect_BIO_lookup(&g_addrinfo1, 1);
    expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, FAKE_SOCKET);
    /* STREAM addrinfo adds KEEPALIVE to the default (zero) connect_mode */
    expect_BIO_connect(FAKE_SOCKET, (BIO_ADDR *)&g_sin, BIO_SOCK_KEEPALIVE, 1);

    assert_int_equal(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL), 1);
    assert_int_equal(data->state, BIO_CONN_S_OK);

    reset_for_teardown(bio);
}

static void test_conn_state_already_ok(void **state)
{
    /* State already OK: returns 1 with no external calls */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->state = BIO_CONN_S_OK;
    assert_int_equal(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL), 1);
    data->state = BIO_CONN_S_BEFORE;
}

static void test_conn_state_connect_retry(void **state)
{
    /* Pre-set CONNECT: BIO_connect fails with retry -> BLOCKED_CONNECT */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->state = BIO_CONN_S_CONNECT;
    data->addr_iter = &g_addrinfo1;
    bio->num = FAKE_SOCKET;

    expect_BIO_connect(FAKE_SOCKET, (BIO_ADDR *)&g_sin, BIO_SOCK_KEEPALIVE, 0);
    expect_BIO_sock_should_retry(0, 1);

    assert_int_equal(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL), 0);
    assert_int_equal(data->state, BIO_CONN_S_BLOCKED_CONNECT);
    assert_int_equal(bio->retry_reason, BIO_RR_CONNECT);

    reset_for_teardown(bio);
}

static void test_conn_state_connect_error(void **state)
{
    /* Pre-set CONNECT: fails, no retry, no more addresses -> CONNECT_ERROR */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->state = BIO_CONN_S_CONNECT;
    data->addr_iter = &g_addrinfo1; /* bai_next == NULL */
    bio->num = FAKE_SOCKET;

    expect_BIO_connect(FAKE_SOCKET, (BIO_ADDR *)&g_sin, BIO_SOCK_KEEPALIVE, 0);
    expect_BIO_sock_should_retry(0, 0);
    /* loop continues to CONNECT_ERROR which exits immediately */

    assert_int_equal(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL), 0);

    reset_for_teardown(bio);
}

static void test_conn_state_connect_next_addr(void **state)
{
    /*
     * Pre-set CONNECT with two addresses: first connect fails, iterator
     * advances, second CREATE_SOCKET fails so we get a clean exit.
     */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    g_addrinfo1.bai_next = &g_addrinfo2;
    data->state = BIO_CONN_S_CONNECT;
    data->addr_iter = &g_addrinfo1;
    bio->num = FAKE_SOCKET;

    expect_BIO_connect(FAKE_SOCKET, (BIO_ADDR *)&g_sin, BIO_SOCK_KEEPALIVE, 0);
    expect_BIO_sock_should_retry(0, 0);
    expect_BIO_closesocket(FAKE_SOCKET, 0);
    /* CREATE_SOCKET for g_addrinfo2 */
    expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0,
        (int)INVALID_SOCKET);

    assert_true(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL) <= 0);

    g_addrinfo1.bai_next = NULL;
    reset_for_teardown(bio);
}

static void test_conn_state_blocked_ok(void **state)
{
    /* Pre-set BLOCKED_CONNECT: socket becomes writable, no error -> OK */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->state = BIO_CONN_S_BLOCKED_CONNECT;
    data->addr_iter = &g_addrinfo1;
    bio->num = FAKE_SOCKET;

    expect_BIO_socket_wait(FAKE_SOCKET, 0, 1);
    expect_BIO_sock_error(FAKE_SOCKET, 0);

    assert_int_equal(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL), 1);
    assert_int_equal(data->state, BIO_CONN_S_OK);

    reset_for_teardown(bio);
}

static void test_conn_state_blocked_error(void **state)
{
    /* Pre-set BLOCKED_CONNECT: socket error, no more addresses -> error */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->state = BIO_CONN_S_BLOCKED_CONNECT;
    data->addr_iter = &g_addrinfo1; /* bai_next == NULL */
    bio->num = FAKE_SOCKET;

    expect_BIO_socket_wait(FAKE_SOCKET, 0, 1);
    expect_BIO_sock_error(FAKE_SOCKET, ECONNREFUSED);

    assert_int_equal(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL), 0);

    reset_for_teardown(bio);
}

#ifndef OPENSSL_NO_DGRAM
static void test_conn_state_connect_dgram_ok(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->connect_sock_type = SOCK_DGRAM;
    data->state = BIO_CONN_S_CONNECT;
    data->addr_iter = &g_addrinfo1;
    bio->num = FAKE_SOCKET;

    /* DGRAM addrinfo means opts stays at the default connect_mode (0) */
    g_addrinfo1.bai_socktype = SOCK_DGRAM;

    expect_BIO_connect(FAKE_SOCKET, (BIO_ADDR *)&g_sin, 0, 1);

    assert_int_equal(BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL), 1);
    assert_int_equal(data->state, BIO_CONN_S_OK);
    assert_non_null(data->dgram_bio);

    g_addrinfo1.bai_socktype = SOCK_STREAM;

    assert_int_equal(BIO_set_close(data->dgram_bio, BIO_NOCLOSE), 1);
    BIO_free(data->dgram_bio);
    data->dgram_bio = NULL;
    reset_for_teardown(bio);
}
#endif

/* conn_read */

static void test_conn_read_success(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_SOCKET, buf, 8, 8);
    assert_int_equal(BIO_read(bio, buf, 8), 8);
    assert_false(BIO_should_retry(bio));
    assert_false(BIO_eof(bio));
}

static void test_conn_read_eof(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_SOCKET, buf, 8, 0);
    expect_BIO_sock_should_retry(0, 0);
    assert_true(BIO_read(bio, buf, 8) <= 0);
    assert_true(BIO_eof(bio));
}

static void test_conn_read_retry(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_SOCKET, buf, 8, -1);
    expect_BIO_sock_should_retry(-1, 1);
    assert_true(BIO_read(bio, buf, 8) <= 0);
    assert_true(BIO_should_read(bio));
}

static void test_conn_read_error(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_SOCKET, buf, 8, -1);
    expect_BIO_sock_should_retry(-1, 0);
    assert_true(BIO_read(bio, buf, 8) <= 0);
    assert_false(BIO_should_retry(bio));
    assert_false(BIO_eof(bio));
}

static void test_conn_read_enters_state_machine(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    char buf[8] = { 0 };

    data->param_hostname = OPENSSL_strdup("host");
    data->param_service = OPENSSL_strdup("443");
    bio->init = 1;

    expect_BIO_lookup(&g_addrinfo1, 1);
    expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, FAKE_SOCKET);
    expect_BIO_connect(FAKE_SOCKET, (BIO_ADDR *)&g_sin, BIO_SOCK_KEEPALIVE, 1);
    expect_read(FAKE_SOCKET, buf, 8, 8);

    assert_int_equal(BIO_read(bio, buf, 8), 8);
    assert_int_equal(data->state, BIO_CONN_S_OK);

    reset_for_teardown(bio);
}

static void test_conn_read_state_machine_fails(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    char buf[8] = { 0 };

    data->param_hostname = OPENSSL_strdup("host");
    data->param_service = OPENSSL_strdup("443");
    bio->init = 1;

    expect_BIO_lookup(NULL, 0); /* conn_state <= 0, no socket touched */

    assert_true(BIO_read(bio, buf, 8) <= 0);

    reset_for_teardown(bio);
}

static void test_conn_read_dgram_delegates(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO *dg = make_fake_dgram();
    char buf[8] = { 0 };

    data->dgram_bio = dg;

    expect_fake_dgram_read(buf, 8, 4);
    assert_int_equal(BIO_read(bio, buf, 8), 4);

    data->dgram_bio = NULL;
    BIO_free(dg);
}

/* conn_write */

static void test_conn_write_success(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_write(FAKE_SOCKET, buf, 5, 5);
    assert_int_equal(BIO_write(bio, buf, 5), 5);
    assert_false(BIO_should_retry(bio));
}

static void test_conn_write_retry(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_write(FAKE_SOCKET, buf, 5, -1);
    expect_BIO_sock_should_retry(-1, 1);
    assert_true(BIO_write(bio, buf, 5) <= 0);
    assert_true(BIO_should_write(bio));
}

static void test_conn_write_error(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_write(FAKE_SOCKET, buf, 5, -1);
    expect_BIO_sock_should_retry(-1, 0);
    assert_true(BIO_write(bio, buf, 5) <= 0);
    assert_false(BIO_should_retry(bio));
}

static void test_conn_write_dgram_delegates(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO *dg = make_fake_dgram();
    const char buf[] = "hello";

    data->dgram_bio = dg;

    expect_fake_dgram_write(buf, 5, 5);
    assert_int_equal(BIO_write(bio, buf, 5), 5);

    data->dgram_bio = NULL;
    BIO_free(dg);
}

/* conn_gets
 *
 * conn_gets is non-static (unlike the other method functions) so it is a
 * public symbol, but we exercise it via BIO_gets to stay in-interface.
 */

static void test_conn_gets_null_buf(void **state)
{
    assert_true(BIO_gets(*state, NULL, 8) <= 0);
}

static void test_conn_gets_zero_size(void **state)
{
    char buf[8] = { 0 };

    assert_true(BIO_gets(*state, buf, 0) <= 0);
}

static void test_conn_gets_null_ptr(void **state)
{
    /* bio->ptr == NULL is caught before any field access */
    BIO *bio = *state;
    char buf[8] = { 0 };
    void *saved = bio->ptr;

    bio->ptr = NULL;
    assert_true(BIO_gets(bio, buf, sizeof(buf)) <= 0);
    bio->ptr = saved;
}

static void test_conn_gets_dgram_bio_set(void **state)
{
    /* dgram_bio present is an error for gets */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    char buf[8] = { 0 };
    BIO fake_dgram;

    data->dgram_bio = &fake_dgram;
    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), -1);
    data->dgram_bio = NULL;
}

static void test_conn_gets_newline(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 'h', 'i', '\n' };

    expect_read(FAKE_SOCKET, buf, 1, 1);
    expect_read(FAKE_SOCKET, buf + 1, 1, 1);
    expect_read(FAKE_SOCKET, buf + 2, 1, 1);

    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), 3);
}

static void test_conn_gets_fills_buffer(void **state)
{
    /* size=4 allows at most 3 chars before the terminating NUL */
    BIO *bio = *state;
    char buf[4] = { 'a', 'b', 'c' };

    expect_read(FAKE_SOCKET, buf, 1, 1);
    expect_read(FAKE_SOCKET, buf + 1, 1, 1);
    expect_read(FAKE_SOCKET, buf + 2, 1, 1);

    assert_int_equal(BIO_gets(bio, buf, 4), 3);
}

static void test_conn_gets_eof_mid(void **state)
{
    /* One char read, then EOF: returns the char count */
    BIO *bio = *state;
    char buf[8] = { 'z' };

    expect_read(FAKE_SOCKET, buf, 1, 1);
    expect_read(FAKE_SOCKET, buf + 1, 1, 0);
    expect_BIO_sock_should_retry(0, 0);

    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), 1);
}

static void test_conn_gets_immediate_eof(void **state)
{
    /* First read returns 0: EOF flag set, returns 0 */
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_SOCKET, buf, 1, 0);
    expect_BIO_sock_should_retry(0, 0);

    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), 0);
    assert_int_equal(buf[0], '\0');
}

static void test_conn_gets_retry(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_SOCKET, buf, 1, -1);
    expect_BIO_sock_should_retry(-1, 1);

    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), -1);
    assert_true(BIO_should_retry(bio));
}

/* conn_puts */

static void test_conn_puts_success(void **state)
{
    BIO *bio = *state;
    const char *str = "hello";

    expect_write(FAKE_SOCKET, str, 5, 5);
    assert_int_equal(BIO_puts(bio, str), 5);
}

static void test_conn_puts_write_fails(void **state)
{
    BIO *bio = *state;
    const char *str = "hello";

    expect_write(FAKE_SOCKET, str, 5, -1);
    expect_BIO_sock_should_retry(-1, 0);
    assert_true(BIO_puts(bio, str) <= 0);
}

/* conn_ctrl */

static void test_conn_ctrl_reset_no_socket(void **state)
{
    /* INVALID_SOCKET -> conn_close_socket is a no-op */
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_RESET, 0, NULL), 0);
    assert_int_equal(get_data(*state)->state, BIO_CONN_S_BEFORE);
}

static void test_conn_ctrl_reset_clears_addrs(void **state)
{
    /* RESET also nulls the iterators and clears flags */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->addr_first = NULL; /* keep BIO_ADDRINFO_free a no-op */
    data->addr_iter = &g_addrinfo1;
    bio->flags = BIO_FLAGS_IN_EOF;
    bio->num = (int)INVALID_SOCKET;

    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_RESET, 0, NULL), 0);
    assert_null(data->addr_first);
    assert_null(data->addr_iter);
    assert_int_equal(bio->flags, 0);
    assert_int_equal(data->state, BIO_CONN_S_BEFORE);
}

static void test_conn_ctrl_get_connect(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    const char *out = NULL;

    /* NULL ptr always returns 0 regardless of num */
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_CONNECT, 0, NULL), 0);

    data->param_hostname = OPENSSL_strdup("host.example");
    data->param_service = OPENSSL_strdup("443");
    data->connect_mode = BIO_SOCK_KEEPALIVE;

    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_CONNECT, 0, &out), 1);
    assert_string_equal(out, "host.example");

    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_CONNECT, 1, &out), 1);
    assert_string_equal(out, "443");

    /* num==4: connect_mode; ptr just needs to be non-NULL */
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_CONNECT, 4, &out),
        BIO_SOCK_KEEPALIVE);

    /* unknown num with non-NULL ptr -> 0 */
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_CONNECT, 99, &out), 0);
}

static void test_conn_ctrl_get_connect_address(void **state)
{
    /* num==2: address pointer from addr_iter */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    const char *out = NULL;

    data->addr_iter = &g_addrinfo1;
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_CONNECT, 2, &out), 1);
    assert_non_null(out);
    data->addr_iter = NULL;
}

static void test_conn_ctrl_get_connect_family(void **state)
{
    /* num==3: AF_INET addr_iter maps to BIO_FAMILY_IPV4 */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    const char *out = NULL;

    data->addr_iter = &g_addrinfo1;
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_CONNECT, 3, &out),
        BIO_FAMILY_IPV4);
    data->addr_iter = NULL;
}

static void test_conn_ctrl_set_connect_null_ptr(void **state)
{
    /* ptr == NULL: no-op, init left untouched */
    BIO *bio = *state;

    assert_int_equal(bio->init, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_CONNECT, 0, NULL), 1);
    assert_int_equal(bio->init, 0);
}

static void test_conn_ctrl_set_connect_hostname(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_CONNECT, 0, "host.example:443"),
        1);
    assert_int_equal(bio->init, 1);
    assert_string_equal(data->param_hostname, "host.example");
    assert_string_equal(data->param_service, "443");
}

static void test_conn_ctrl_set_connect_port(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_CONNECT, 1, "8443"), 1);
    assert_string_equal(data->param_service, "8443");
}

static void test_conn_ctrl_set_connect_address(void **state)
{
    /* num==2: derive host/service from a BIO_ADDR */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO_ADDR *addr = BIO_ADDR_new();

    assert_non_null(addr);
    assert_true(BIO_ADDR_rawmake(addr, AF_INET, &g_sin.sin_addr,
        sizeof(g_sin.sin_addr), g_sin.sin_port));

    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_CONNECT, 2, addr), 1);
    assert_non_null(data->param_hostname);
    assert_non_null(data->param_service);
    assert_null(data->addr_first);

    BIO_ADDR_free(addr);
}

static void test_conn_ctrl_set_connect_family(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    int family = BIO_FAMILY_IPV4;

    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_CONNECT, 3, &family), 1);
    assert_int_equal(data->connect_family, BIO_FAMILY_IPV4);
}

static void test_conn_ctrl_set_sock_type(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_SOCK_TYPE, SOCK_DGRAM, NULL), 1);
    assert_int_equal(data->connect_sock_type, SOCK_DGRAM);

    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_SOCK_TYPE, SOCK_STREAM, NULL), 1);
    assert_int_equal(data->connect_sock_type, SOCK_STREAM);

    /* Invalid socktype */
    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_SOCK_TYPE, 9999, NULL), 0);

    /* Too late once past BEFORE */
    data->state = BIO_CONN_S_GET_ADDR;
    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_SOCK_TYPE, SOCK_DGRAM, NULL), 0);
    data->state = BIO_CONN_S_BEFORE;
}

static void test_conn_ctrl_get_sock_type(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    data->connect_sock_type = SOCK_DGRAM;
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_SOCK_TYPE, 0, NULL), SOCK_DGRAM);
    data->connect_sock_type = SOCK_STREAM;
}

static void test_conn_ctrl_get_dgram_bio(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO *out = NULL;
    BIO fake_dgram;

    /* dgram_bio NULL -> 0 */
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_DGRAM_BIO, 0, &out), 0);

    data->dgram_bio = &fake_dgram;
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_DGRAM_BIO, 0, &out), 1);
    assert_ptr_equal(out, &fake_dgram);
    data->dgram_bio = NULL;
}

static void test_conn_ctrl_nbio(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    BIO_ctrl(bio, BIO_C_SET_NBIO, 1, NULL);
    assert_true(data->connect_mode & BIO_SOCK_NONBLOCK);

    BIO_ctrl(bio, BIO_C_SET_NBIO, 0, NULL);
    assert_false(data->connect_mode & BIO_SOCK_NONBLOCK);
}

static void test_conn_ctrl_nbio_dgram(void **state)
{
    /* with a dgram_bio attached the mode flips and the call delegates */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO *dg = make_fake_dgram();

    data->dgram_bio = dg;
    BIO_ctrl(bio, BIO_C_SET_NBIO, 1, NULL);
    assert_true(data->connect_mode & BIO_SOCK_NONBLOCK);

    data->dgram_bio = NULL;
    BIO_free(dg);
}

static void test_conn_ctrl_connect_mode(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);

    BIO_ctrl(bio, BIO_C_SET_CONNECT_MODE, BIO_SOCK_KEEPALIVE, NULL);
    assert_int_equal(data->connect_mode, BIO_SOCK_KEEPALIVE);
    assert_int_equal(data->tfo_first, 0);
}

static void test_conn_ctrl_get_fd(void **state)
{
    BIO *bio = *state;
    int fd = -1;

    /* init==0 -> -1 */
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_FD, 0, &fd), -1);

    bio->init = 1;
    bio->num = FAKE_SOCKET;
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_FD, 0, &fd), FAKE_SOCKET);
    assert_int_equal(fd, FAKE_SOCKET);

    bio->init = 0;
    bio->num = (int)INVALID_SOCKET;
}

static void test_conn_ctrl_get_set_close(void **state)
{
    BIO *bio = *state;

    bio->shutdown = BIO_NOCLOSE;
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_GET_CLOSE, 0, NULL), BIO_NOCLOSE);

    BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, BIO_CLOSE, NULL);
    assert_int_equal(bio->shutdown, BIO_CLOSE);
}

static void test_conn_ctrl_pending_flush(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL), 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_WPENDING, 0, NULL), 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, NULL), 1);
}

static void test_conn_ctrl_eof(void **state)
{
    BIO *bio = *state;

    bio->flags &= ~BIO_FLAGS_IN_EOF;
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL), 0);

    bio->flags |= BIO_FLAGS_IN_EOF;
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL), 1);
    bio->flags &= ~BIO_FLAGS_IN_EOF;
}

static void test_conn_ctrl_set_callback_defers(void **state)
{
    /* BIO_CTRL_SET_CALLBACK via conn_ctrl returns 0 (use callback ctrl) */
    BIO *bio = *state;

    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_SET_CALLBACK, 0, NULL), 0);
}

static void test_conn_ctrl_default(void **state)
{
    assert_int_equal(BIO_ctrl(*state, 9999, 0, NULL), 0);
}

/* conn_callback_ctrl */

static int dummy_cb(BIO *b, int s, int res)
{
    (void)b;
    (void)s;
    return res;
}

static void test_conn_ctrl_get_callback(void **state)
{
    /* BIO_CTRL_GET_CALLBACK returns the stored info_callback */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO_info_cb *fp = NULL;

    data->info_callback = dummy_cb;
    BIO_ctrl(bio, BIO_CTRL_GET_CALLBACK, 0, &fp);
    assert_ptr_equal(fp, dummy_cb);
    data->info_callback = NULL;
}

static void test_conn_callback_ctrl_set(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO_info_cb *retrieved;

    assert_int_equal(BIO_set_info_callback(bio, dummy_cb), 1);
    assert_ptr_equal(data->info_callback, dummy_cb);

    assert_int_equal(BIO_get_info_callback(bio, &retrieved), 1);
    assert_ptr_equal(retrieved, dummy_cb);

    assert_int_equal(BIO_set_info_callback(bio, NULL), 1);
}

static void test_conn_callback_ctrl_default(void **state)
{
    assert_int_equal(BIO_callback_ctrl(*state, BIO_CTRL_SET_CALLBACK, dummy_cb), 1);
}

static void test_conn_callback_ctrl_invalid(void **state)
{
    /* If cmd different than BIO_CTRL_SET_CALLBACK, return -2. */
    assert_int_equal(BIO_callback_ctrl(*state, 9999, dummy_cb), -2);
}

/* conn_sendmmsg / conn_recvmmsg */

static void test_conn_sendmmsg_no_dgram(void **state)
{
    /* State OK, dgram_bio NULL -> error */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO_MSG msg = { 0 };
    size_t processed = 1;

    data->state = BIO_CONN_S_OK;
    bio->num = FAKE_SOCKET;

    assert_int_equal(
        BIO_sendmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 0);
    assert_int_equal(processed, 0);

    reset_for_teardown(bio);
}

static void test_conn_sendmmsg_state_fails(void **state)
{
    /* state != OK and conn_state fails -> 0, processed zeroed */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO_MSG msg = { 0 };
    size_t processed = 5;

    data->param_hostname = OPENSSL_strdup("host");
    data->param_service = OPENSSL_strdup("443");
    bio->init = 1; /* BIO_sendmmsg rejects !init before dispatch */

    expect_BIO_lookup(NULL, 0);

    assert_int_equal(
        BIO_sendmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 0);
    assert_int_equal(processed, 0);

    reset_for_teardown(bio);
}

static void test_conn_sendmmsg_dgram_delegates(void **state)
{
    /* state OK with dgram_bio -> delegates to BIO_sendmmsg on it */
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO *dg = make_fake_dgram();
    BIO_MSG msg = { 0 };
    size_t processed = 0;

    data->dgram_bio = dg;

    expect_fake_dgram_sendmmsg(&msg, sizeof(msg), 1, 0, 1, 1);

    assert_int_equal(
        BIO_sendmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 1);
    assert_int_equal(processed, 1);

    data->dgram_bio = NULL;
    BIO_free(dg);
    reset_for_teardown(bio);
}

static void test_conn_recvmmsg_no_dgram(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO_MSG msg = { 0 };
    size_t processed = 1;

    data->state = BIO_CONN_S_OK;
    bio->num = FAKE_SOCKET;

    assert_int_equal(
        BIO_recvmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 0);
    assert_int_equal(processed, 0);

    reset_for_teardown(bio);
}

static void test_conn_recvmmsg_state_fails(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO_MSG msg = { 0 };
    size_t processed = 5;

    data->param_hostname = OPENSSL_strdup("host");
    data->param_service = OPENSSL_strdup("443");
    bio->init = 1;

    expect_BIO_lookup(NULL, 0);

    assert_int_equal(
        BIO_recvmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 0);
    assert_int_equal(processed, 0);

    reset_for_teardown(bio);
}

static void test_conn_recvmmsg_dgram_delegates(void **state)
{
    BIO *bio = *state;
    BIO_CONNECT *data = get_data(bio);
    BIO *dg = make_fake_dgram();
    BIO_MSG msg = { 0 };
    size_t processed = 0;

    data->dgram_bio = dg;

    expect_fake_dgram_recvmmsg(&msg, sizeof(msg), 1, 0, 1, 1);

    assert_int_equal(
        BIO_recvmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 1);
    assert_int_equal(processed, 1);

    data->dgram_bio = NULL;
    BIO_free(dg);
    reset_for_teardown(bio);
}

/* main */

#define CONN_TEST(name) \
    cmocka_unit_test_setup_teardown(name, setup, teardown)

#define CONN_TEST_IO(name) \
    cmocka_unit_test_setup_teardown(name, setup_io, teardown_io)

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* conn_new */
        CONN_TEST(test_conn_new),
        /* conn_free */
        CONN_TEST(test_conn_free_no_shutdown),
        /* conn_close_socket */
        CONN_TEST(test_close_socket_none),
        CONN_TEST(test_close_socket_non_ok_state),
        CONN_TEST(test_close_socket_ok_state),
        /* conn_state */
        CONN_TEST(test_conn_state_no_hostname),
        CONN_TEST(test_conn_state_unsupported_family),
        CONN_TEST(test_conn_state_lookup_fails),
        CONN_TEST(test_conn_state_socket_fails),
        CONN_TEST(test_conn_state_connect_succeeds),
        CONN_TEST(test_conn_state_already_ok),
        CONN_TEST(test_conn_state_connect_retry),
        CONN_TEST(test_conn_state_connect_error),
        CONN_TEST(test_conn_state_connect_next_addr),
        CONN_TEST(test_conn_state_blocked_ok),
        CONN_TEST(test_conn_state_blocked_error),
#ifndef OPENSSL_NO_DGRAM
        CONN_TEST(test_conn_state_connect_dgram_ok),
#endif
        /* conn_read */
        CONN_TEST_IO(test_conn_read_success),
        CONN_TEST_IO(test_conn_read_eof),
        CONN_TEST_IO(test_conn_read_retry),
        CONN_TEST_IO(test_conn_read_error),
        CONN_TEST(test_conn_read_enters_state_machine),
        CONN_TEST(test_conn_read_state_machine_fails),
        CONN_TEST_IO(test_conn_read_dgram_delegates),
        /* conn_write */
        CONN_TEST_IO(test_conn_write_success),
        CONN_TEST_IO(test_conn_write_retry),
        CONN_TEST_IO(test_conn_write_error),
        CONN_TEST_IO(test_conn_write_dgram_delegates),
        /* conn_gets */
        CONN_TEST(test_conn_gets_null_buf),
        CONN_TEST(test_conn_gets_zero_size),
        CONN_TEST(test_conn_gets_null_ptr),
        CONN_TEST_IO(test_conn_gets_dgram_bio_set),
        CONN_TEST_IO(test_conn_gets_newline),
        CONN_TEST_IO(test_conn_gets_fills_buffer),
        CONN_TEST_IO(test_conn_gets_eof_mid),
        CONN_TEST_IO(test_conn_gets_immediate_eof),
        CONN_TEST_IO(test_conn_gets_retry),
        /* conn_puts */
        CONN_TEST_IO(test_conn_puts_success),
        CONN_TEST_IO(test_conn_puts_write_fails),
        /* conn_ctrl */
        CONN_TEST(test_conn_ctrl_reset_no_socket),
        CONN_TEST(test_conn_ctrl_reset_clears_addrs),
        CONN_TEST(test_conn_ctrl_get_connect),
        CONN_TEST(test_conn_ctrl_get_connect_address),
        CONN_TEST(test_conn_ctrl_get_connect_family),
        CONN_TEST(test_conn_ctrl_set_connect_null_ptr),
        CONN_TEST(test_conn_ctrl_set_connect_hostname),
        CONN_TEST(test_conn_ctrl_set_connect_port),
        CONN_TEST(test_conn_ctrl_set_connect_address),
        CONN_TEST(test_conn_ctrl_set_connect_family),
        CONN_TEST(test_conn_ctrl_set_sock_type),
        CONN_TEST(test_conn_ctrl_get_sock_type),
        CONN_TEST(test_conn_ctrl_get_dgram_bio),
        CONN_TEST(test_conn_ctrl_nbio),
        CONN_TEST_IO(test_conn_ctrl_nbio_dgram),
        CONN_TEST(test_conn_ctrl_connect_mode),
        CONN_TEST(test_conn_ctrl_get_fd),
        CONN_TEST(test_conn_ctrl_get_set_close),
        CONN_TEST(test_conn_ctrl_pending_flush),
        CONN_TEST(test_conn_ctrl_eof),
        CONN_TEST(test_conn_ctrl_set_callback_defers),
        CONN_TEST(test_conn_ctrl_default),
        /* conn_callback_ctrl */
        CONN_TEST(test_conn_ctrl_get_callback),
        CONN_TEST(test_conn_callback_ctrl_set),
        CONN_TEST(test_conn_callback_ctrl_default),
        CONN_TEST(test_conn_callback_ctrl_invalid),
        /* conn_sendmmsg / conn_recvmmsg */
        CONN_TEST(test_conn_sendmmsg_no_dgram),
        CONN_TEST(test_conn_sendmmsg_state_fails),
        CONN_TEST_IO(test_conn_sendmmsg_dgram_delegates),
        CONN_TEST(test_conn_recvmmsg_no_dgram),
        CONN_TEST(test_conn_recvmmsg_state_fails),
        CONN_TEST_IO(test_conn_recvmmsg_dgram_delegates),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

#else

int main(void)
{
    return 0;
}

#endif /* OPENSSL_NO_SOCK */
