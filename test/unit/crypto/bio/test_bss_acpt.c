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
int __wrap_BIO_lookup(const char *host, const char *service,
    enum BIO_lookup_type lookup_type,
    int family, int socktype, BIO_ADDRINFO **res);
int __wrap_BIO_socket(int domain, int socktype, int protocol, int options);
int __wrap_BIO_listen(int sock, const BIO_ADDR *addr, int options);
int __wrap_BIO_accept_ex(int accept_sock, BIO_ADDR *addr, int options);
int __wrap_BIO_sock_info(int sock, enum BIO_sock_info_type type,
    union BIO_sock_info_u *info);
int __wrap_BIO_sock_should_retry(int i);
int __wrap_BIO_closesocket(int sock);
char *__wrap_BIO_ADDR_hostname_string(const BIO_ADDR *ap, int numeric);
char *__wrap_BIO_ADDR_service_string(const BIO_ADDR *ap, int numeric);

/* wraps */

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

int __wrap_BIO_listen(int sock, const BIO_ADDR *addr, int options)
{
    function_called();
    check_expected(sock);
    check_expected_ptr(addr);
    check_expected(options);
    return mock_type(int);
}

int __wrap_BIO_accept_ex(int accept_sock, BIO_ADDR *addr, int options)
{
    function_called();
    check_expected(accept_sock);
    check_expected_ptr(addr);
    check_expected(options);
    return mock_type(int);
}

int __wrap_BIO_sock_info(int sock, enum BIO_sock_info_type type,
    union BIO_sock_info_u *info)
{
    function_called();
    check_expected(sock);
    check_expected(type);
    (void)info; /* addr field left untouched; cache addr is zeroed already */
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

/*
 * The cache_*_name / cache_*_serv pointers get OPENSSL_free()d in
 * BIO_ACCEPT_free and when a new bind starts, so these wraps must return
 * heap pointers (or NULL).
 */
char *__wrap_BIO_ADDR_hostname_string(const BIO_ADDR *ap, int numeric)
{
    function_called();
    (void)ap;
    (void)numeric;
    return mock_ptr_type(char *);
}

char *__wrap_BIO_ADDR_service_string(const BIO_ADDR *ap, int numeric)
{
    function_called();
    (void)ap;
    (void)numeric;
    return mock_ptr_type(char *);
}

/*
 * A minimal fake sink BIO.  The accept BIO forwards reads/writes to its
 * next_bio once a connection is established, so I/O tests push one of these
 * instead of a real socket BIO.  This keeps acpt_read/acpt_write under test
 * in isolation: no dependency on sock_read/sock_write, on the libc read/write
 * syscalls, or on BIO_sock_should_retry.
 *
 * The fake read/write return mock_type and, on a non-positive result, set
 * their own retry flag when asked, so acpt_read/acpt_write's
 * BIO_copy_next_retry has a real source-of-truth to propagate upward.
 */

static int fake_sink_read(BIO *b, char *buf, size_t size, size_t *readbytes);
static int fake_sink_write(BIO *b, const char *buf, size_t size,
    size_t *written);
static long fake_sink_ctrl(BIO *b, int cmd, long arg1, void *arg2);

static int fake_sink_read(BIO *b, char *buf, size_t size, size_t *readbytes)
{
    int ret;

    function_called();
    check_expected_ptr(buf);
    check_expected(size);
    BIO_clear_retry_flags(b);
    ret = mock_type(int);
    if (ret > 0) {
        *readbytes = (size_t)ret;
        return 1;
    }
    if (mock_type(int))
        BIO_set_retry_read(b);
    *readbytes = 0;
    return ret;
}

static int fake_sink_write(BIO *b, const char *buf, size_t size,
    size_t *written)
{
    int ret;

    function_called();
    check_expected_ptr(buf);
    check_expected(size);
    BIO_clear_retry_flags(b);
    ret = mock_type(int);
    if (ret > 0) {
        *written = (size_t)ret;
        return 1;
    }
    if (mock_type(int))
        BIO_set_retry_write(b);
    *written = 0;
    return ret;
}

static long fake_sink_ctrl(BIO *b, int cmd, long arg1, void *arg2)
{
    (void)b;
    (void)arg1;
    (void)arg2;
    if (cmd == BIO_CTRL_FLUSH)
        return 1;
    return 0;
}

static BIO_METHOD *fake_sink_method = NULL;

static BIO_METHOD *make_fake_sink_method(void)
{
    BIO_METHOD *m = BIO_meth_new(BIO_TYPE_SOURCE_SINK | 0xff, "fake sink");

    assert_non_null(m);
    assert_true(BIO_meth_set_read_ex(m, fake_sink_read));
    assert_true(BIO_meth_set_write_ex(m, fake_sink_write));
    assert_true(BIO_meth_set_ctrl(m, fake_sink_ctrl));
    return m;
}

static BIO *make_fake_sink(void)
{
    BIO *b = BIO_new(fake_sink_method);

    assert_non_null(b);
    BIO_set_init(b, 1);
    return b;
}

/* expectations */

static void expect_BIO_lookup(BIO_ADDRINFO *res, int rc)
{
    expect_function_call(__wrap_BIO_lookup);
    expect_any(__wrap_BIO_lookup, host);
    expect_any(__wrap_BIO_lookup, service);
    expect_value(__wrap_BIO_lookup, lookup_type, BIO_LOOKUP_SERVER);
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

static void expect_BIO_listen(int sock, const BIO_ADDR *addr, int options,
    int rc)
{
    expect_function_call(__wrap_BIO_listen);
    expect_value(__wrap_BIO_listen, sock, sock);
    expect_value(__wrap_BIO_listen, addr, addr);
    expect_value(__wrap_BIO_listen, options, options);
    will_return(__wrap_BIO_listen, rc);
}

static void expect_BIO_accept_ex(int sock, int options, int rc)
{
    expect_function_call(__wrap_BIO_accept_ex);
    expect_value(__wrap_BIO_accept_ex, accept_sock, sock);
    expect_any(__wrap_BIO_accept_ex, addr);
    expect_value(__wrap_BIO_accept_ex, options, options);
    will_return(__wrap_BIO_accept_ex, rc);
}

static void expect_BIO_sock_info(int sock, int rc)
{
    expect_function_call(__wrap_BIO_sock_info);
    expect_value(__wrap_BIO_sock_info, sock, sock);
    expect_value(__wrap_BIO_sock_info, type, BIO_SOCK_INFO_ADDRESS);
    will_return(__wrap_BIO_sock_info, rc);
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

/* The returned pointer is heap allocated; ownership passes to the BIO. */
static void expect_BIO_ADDR_hostname_string(const char *val)
{
    expect_function_call(__wrap_BIO_ADDR_hostname_string);
    will_return(__wrap_BIO_ADDR_hostname_string,
        val == NULL ? NULL : OPENSSL_strdup(val));
}

static void expect_BIO_ADDR_service_string(const char *val)
{
    expect_function_call(__wrap_BIO_ADDR_service_string);
    will_return(__wrap_BIO_ADDR_service_string,
        val == NULL ? NULL : OPENSSL_strdup(val));
}

/*
 * rc is the byte count (>0) or the non-positive result; retry tells the sink
 * whether to set its own retry flag when rc <= 0.
 */
static void expect_fake_sink_read(const void *buf, size_t size, int rc,
    int retry)
{
    expect_function_call(fake_sink_read);
    expect_value(fake_sink_read, buf, buf);
    expect_value(fake_sink_read, size, size);
    will_return(fake_sink_read, rc);
    if (rc <= 0)
        will_return(fake_sink_read, retry);
}

static void expect_fake_sink_write(const void *buf, size_t size, int rc,
    int retry)
{
    expect_function_call(fake_sink_write);
    expect_value(fake_sink_write, buf, buf);
    expect_value(fake_sink_write, size, size);
    will_return(fake_sink_write, rc);
    if (rc <= 0)
        will_return(fake_sink_write, retry);
}

/*
 * The LISTEN state always emits, in order: BIO_listen, BIO_sock_info, then a
 * hostname_string + service_string pair for the accepting address cache.
 */
static void expect_listen_sequence(int sock)
{
    expect_BIO_listen(sock, (const BIO_ADDR *)&g_sin, 0, 1);
    expect_BIO_sock_info(sock, 1);
    expect_BIO_ADDR_hostname_string("127.0.0.1");
    expect_BIO_ADDR_service_string("443");
}

/* helpers */

static BIO_ACCEPT *get_data(BIO *bio)
{
    return (BIO_ACCEPT *)bio->ptr;
}

/*
 * Reset socket bookkeeping so acpt_close_socket is a no-op during free, and
 * clear the address iterators that point at static storage.
 */
static void reset_for_teardown(BIO *bio)
{
    BIO_ACCEPT *data = get_data(bio);

    bio->num = (int)INVALID_SOCKET;
    data->accept_sock = (int)INVALID_SOCKET;
    data->addr_first = NULL;
    data->addr_iter = NULL;
    data->state = BIO_ACPT_S_BEFORE;
}

/* setup / teardown */

static int setup(void **state)
{
    BIO *bio = BIO_new(BIO_s_accept());

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

/*
 * I/O tests pre-establish state=OK and push a fake sink BIO so the state
 * machine exits immediately and reads/writes are forwarded to next_bio.
 */
static int setup_io(void **state)
{
    BIO *bio, *sink;
    BIO_ACCEPT *data;

    if (setup(state) != 0)
        return -1;
    bio = *state;
    data = get_data(bio);
    data->state = BIO_ACPT_S_OK;
    data->accept_sock = FAKE_SOCKET;
    bio->num = FAKE_SOCKET;
    bio->init = 1;

    sink = make_fake_sink();
    assert_non_null(BIO_push(bio, sink));
    return 0;
}

static int teardown_io(void **state)
{
    if (*state != NULL) {
        reset_for_teardown(*state);
        /* BIO_free_all to also release the pushed fake sink BIO. */
        BIO_free_all(*state);
        *state = NULL;
    }
    return 0;
}

static int group_setup(void **state)
{
    (void)state;

    fake_sink_method = make_fake_sink_method();

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
    BIO_meth_free(fake_sink_method);
    fake_sink_method = NULL;
    return 0;
}

/* acpt_new */

static void test_acpt_new(void **state)
{
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    assert_non_null(data);
    assert_int_equal(data->state, BIO_ACPT_S_BEFORE);
    assert_int_equal(data->accept_family, BIO_FAMILY_IPANY);
    assert_int_equal(data->accept_sock, (int)INVALID_SOCKET);
    assert_null(data->param_addr);
    assert_null(data->param_serv);
    assert_null(data->addr_first);
    assert_null(data->bio_chain);
    assert_int_equal(bio->num, (int)INVALID_SOCKET);
    assert_int_equal(bio->init, 0);
    assert_int_equal(bio->shutdown, 1);
}

/* acpt_free */

static void test_acpt_free_no_shutdown(void **state)
{
    /* shutdown=0: acpt_close_socket and BIO_ACCEPT_free are both skipped */
    BIO *bio = BIO_new(BIO_s_accept());

    assert_non_null(bio);
    bio->shutdown = BIO_NOCLOSE;
    BIO_free(bio);
    *state = NULL;
}

/* acpt_close_socket (via BIO_CTRL_RESET) */

static void test_close_socket_none(void **state)
{
    /* accept_sock == INVALID_SOCKET: no closesocket expected */
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_RESET, 0, NULL), 0);
    assert_int_equal(get_data(*state)->state, BIO_ACPT_S_BEFORE);
}

/* acpt_state via BIO_C_DO_STATE_MACHINE (BIO_do_accept) */

static void test_acpt_state_no_addr(void **state)
{
    /* BEFORE with no addr and no serv -> error */
    assert_true(BIO_do_accept(*state) <= 0);
}

static void test_acpt_state_unsupported_family(void **state)
{
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    data->param_serv = OPENSSL_strdup("443");
    data->accept_family = 9999;

    assert_true(BIO_do_accept(bio) <= 0);
}

static void test_acpt_state_lookup_fails(void **state)
{
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    data->param_serv = OPENSSL_strdup("443");

    expect_BIO_lookup(NULL, 0);
    assert_true(BIO_do_accept(bio) <= 0);
}

static void test_acpt_state_lookup_empty(void **state)
{
    /* BIO_lookup succeeds but returns no addresses */
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    data->param_serv = OPENSSL_strdup("443");

    expect_BIO_lookup(NULL, 1); /* rc==1 but res stays NULL */
    assert_true(BIO_do_accept(bio) <= 0);
}

static void test_acpt_state_socket_fails(void **state)
{
    /* Pre-set CREATE_SOCKET, single address: BIO_socket fails -> error */
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    data->state = BIO_ACPT_S_CREATE_SOCKET;
    data->addr_iter = &g_addrinfo1; /* bai_next == NULL */

    expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0,
        (int)INVALID_SOCKET);
    assert_true(BIO_do_accept(bio) <= 0);

    reset_for_teardown(bio);
}

static void test_acpt_state_socket_next_addr(void **state)
{
    /*
     * Two addresses: first BIO_socket fails, iterator advances, second
     * BIO_socket also fails -> clean error exit.
     */
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    g_addrinfo1.bai_next = &g_addrinfo2;
    data->state = BIO_ACPT_S_CREATE_SOCKET;
    data->addr_iter = &g_addrinfo1;

    expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0,
        (int)INVALID_SOCKET);
    expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0,
        (int)INVALID_SOCKET);
    assert_true(BIO_do_accept(bio) <= 0);

    g_addrinfo1.bai_next = NULL;
    reset_for_teardown(bio);
}

static void test_acpt_state_listen_fails(void **state)
{
    /* CREATE_SOCKET succeeds, BIO_listen fails -> closesocket, error */
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    data->state = BIO_ACPT_S_CREATE_SOCKET;
    data->addr_iter = &g_addrinfo1;

    expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, FAKE_SOCKET);
    expect_BIO_listen(FAKE_SOCKET, (const BIO_ADDR *)&g_sin, 0, 0);
    expect_BIO_closesocket(FAKE_SOCKET, 0);

    assert_true(BIO_do_accept(bio) <= 0);
    assert_int_equal(data->accept_sock, (int)INVALID_SOCKET);

    reset_for_teardown(bio);
}

static void test_acpt_state_sock_info_fails(void **state)
{
    /* listen ok, BIO_sock_info fails -> closesocket, error */
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    data->state = BIO_ACPT_S_CREATE_SOCKET;
    data->addr_iter = &g_addrinfo1;

    expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, FAKE_SOCKET);
    expect_BIO_listen(FAKE_SOCKET, (const BIO_ADDR *)&g_sin, 0, 1);
    expect_BIO_sock_info(FAKE_SOCKET, 0);
    expect_BIO_closesocket(FAKE_SOCKET, 0);

    assert_true(BIO_do_accept(bio) <= 0);
    assert_int_equal(data->accept_sock, (int)INVALID_SOCKET);

    reset_for_teardown(bio);
}

static void test_acpt_state_bind_ok(void **state)
{
    /*
     * Full bind path: BEFORE -> GET_ADDR -> CREATE_SOCKET -> LISTEN returns 1
     * and the machine stops at BIO_ACPT_S_ACCEPT (next_bio is NULL).
     */
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    data->param_serv = OPENSSL_strdup("443");

    expect_BIO_lookup(&g_addrinfo1, 1);
    expect_BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, FAKE_SOCKET);
    expect_listen_sequence(FAKE_SOCKET);

    assert_int_equal(BIO_do_accept(bio), 1);
    assert_int_equal(data->state, BIO_ACPT_S_ACCEPT);
    assert_int_equal(data->accept_sock, FAKE_SOCKET);
    assert_string_equal(data->cache_accepting_name, "127.0.0.1");
    assert_string_equal(data->cache_accepting_serv, "443");

    reset_for_teardown(bio);
}

static void test_acpt_state_accept_retry(void **state)
{
    /* Pre-set ACCEPT, no next_bio: BIO_accept_ex retryable -> special flag */
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    data->state = BIO_ACPT_S_ACCEPT;
    data->accept_sock = FAKE_SOCKET;
    bio->num = FAKE_SOCKET;

    expect_BIO_accept_ex(FAKE_SOCKET, 0, -1);
    expect_BIO_sock_should_retry(-1, 1);

    assert_true(BIO_do_accept(bio) <= 0);
    assert_true(BIO_should_io_special(bio));
    assert_int_equal(bio->retry_reason, BIO_RR_ACCEPT);

    reset_for_teardown(bio);
}

static void test_acpt_state_accept_error(void **state)
{
    /* Pre-set ACCEPT: BIO_accept_ex fails, not retryable -> error */
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    data->state = BIO_ACPT_S_ACCEPT;
    data->accept_sock = FAKE_SOCKET;
    bio->num = FAKE_SOCKET;

    expect_BIO_accept_ex(FAKE_SOCKET, 0, -1);
    expect_BIO_sock_should_retry(-1, 0);

    assert_true(BIO_do_accept(bio) <= 0);

    reset_for_teardown(bio);
}

static void test_acpt_state_already_ok_no_next(void **state)
{
    /*
     * State OK but next_bio NULL: machine drops back to ACCEPT and tries to
     * accept. We make that accept fail non-retryably for a clean exit.
     */
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    data->state = BIO_ACPT_S_OK;
    data->accept_sock = FAKE_SOCKET;
    bio->num = FAKE_SOCKET;

    expect_BIO_accept_ex(FAKE_SOCKET, 0, -1);
    expect_BIO_sock_should_retry(-1, 0);

    assert_true(BIO_do_accept(bio) <= 0);

    reset_for_teardown(bio);
}

/* acpt_read / acpt_write (state already OK with a pushed fake sink BIO) */

static void test_acpt_read_forwards(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_fake_sink_read(buf, 8, 8, 0);
    assert_int_equal(BIO_read(bio, buf, 8), 8);
    assert_false(BIO_should_retry(bio));
}

static void test_acpt_read_forwards_retry(void **state)
{
    /*
     * The fake sink returns a retryable read and sets its own retry-read
     * flag; acpt_read must propagate it onto the accept BIO via
     * BIO_copy_next_retry.
     */
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_fake_sink_read(buf, 8, -1, 1);
    assert_true(BIO_read(bio, buf, 8) <= 0);
    assert_true(BIO_should_read(bio));
    assert_true(BIO_should_retry(bio));
}

static void test_acpt_write_forwards(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_fake_sink_write(buf, 5, 5, 0);
    assert_int_equal(BIO_write(bio, buf, 5), 5);
    assert_false(BIO_should_retry(bio));
}

static void test_acpt_write_forwards_retry(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_fake_sink_write(buf, 5, -1, 1);
    assert_true(BIO_write(bio, buf, 5) <= 0);
    assert_true(BIO_should_write(bio));
    assert_true(BIO_should_retry(bio));
}

static void test_acpt_puts_forwards(void **state)
{
    BIO *bio = *state;
    const char *str = "hello";

    expect_fake_sink_write(str, 5, 5, 0);
    assert_int_equal(BIO_puts(bio, str), 5);
}

/* acpt_ctrl */

static void test_acpt_ctrl_reset_clears_addrs(void **state)
{
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    data->addr_first = NULL; /* keep BIO_ADDRINFO_free a no-op */
    data->addr_iter = &g_addrinfo1;
    bio->flags = BIO_FLAGS_SHOULD_RETRY;

    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_RESET, 0, NULL), 0);
    assert_null(data->addr_first);
    assert_null(data->addr_iter);
    assert_int_equal(bio->flags, 0);
    assert_int_equal(data->state, BIO_ACPT_S_BEFORE);
}

static void test_acpt_ctrl_set_accept_name(void **state)
{
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    assert_true(BIO_set_accept_name(bio, "host.example:443") > 0);
    assert_int_equal(bio->init, 1);
    assert_string_equal(data->param_addr, "host.example");
    assert_string_equal(data->param_serv, "443");
}

static void test_acpt_ctrl_set_accept_port(void **state)
{
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    assert_true(BIO_set_accept_port(bio, "8443") > 0);
    assert_int_equal(bio->init, 1);
    assert_string_equal(data->param_serv, "8443");
}

static void test_acpt_ctrl_set_nbio_accept(void **state)
{
    /* toggles BIO_SOCK_NONBLOCK in bind_mode */
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    BIO_set_nbio_accept(bio, 1);
    assert_true(data->bind_mode & BIO_SOCK_NONBLOCK);

    BIO_set_nbio_accept(bio, 0);
    assert_false(data->bind_mode & BIO_SOCK_NONBLOCK);
}

static void test_acpt_ctrl_set_accept_bios(void **state)
{
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);
    BIO *chain = BIO_new(BIO_s_mem());

    assert_non_null(chain);
    assert_true(BIO_set_accept_bios(bio, chain) > 0);
    assert_ptr_equal(data->bio_chain, chain);
    /* freed by BIO_ACCEPT_free in teardown */
}

static void test_acpt_ctrl_set_accept_ip_family(void **state)
{
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    assert_true(BIO_set_accept_ip_family(bio, BIO_FAMILY_IPV4) > 0);
    assert_int_equal(data->accept_family, BIO_FAMILY_IPV4);
}

static void test_acpt_ctrl_set_tfo_accept(void **state)
{
    /* toggles BIO_SOCK_TFO in bind_mode */
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    BIO_set_tfo_accept(bio, 1);
    assert_true(data->bind_mode & BIO_SOCK_TFO);

    BIO_set_tfo_accept(bio, 0);
    assert_false(data->bind_mode & BIO_SOCK_TFO);
}

static void test_acpt_ctrl_set_nbio(void **state)
{
    /* BIO_C_SET_NBIO: toggles BIO_SOCK_NONBLOCK in accepted_mode */
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    BIO_set_nbio(bio, 1);
    assert_true(data->accepted_mode & BIO_SOCK_NONBLOCK);

    BIO_set_nbio(bio, 0);
    assert_false(data->accepted_mode & BIO_SOCK_NONBLOCK);
}

static void test_acpt_ctrl_set_fd(void **state)
{
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    BIO_set_fd(bio, FAKE_SOCKET, BIO_NOCLOSE);
    assert_int_equal(bio->num, FAKE_SOCKET);
    assert_int_equal(data->accept_sock, FAKE_SOCKET);
    assert_int_equal(data->state, BIO_ACPT_S_ACCEPT);
    assert_int_equal(bio->init, 1);
    assert_int_equal(bio->shutdown, BIO_NOCLOSE);

    reset_for_teardown(bio);
}

static void test_acpt_ctrl_get_fd(void **state)
{
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);
    int fd = -1;

    /* init==0 -> -1 */
    assert_int_equal(BIO_get_fd(bio, &fd), -1);

    bio->init = 1;
    data->accept_sock = FAKE_SOCKET;
    assert_int_equal(BIO_get_fd(bio, &fd), FAKE_SOCKET);
    assert_int_equal(fd, FAKE_SOCKET);

    bio->init = 0;
    data->accept_sock = (int)INVALID_SOCKET;
}

static void test_acpt_ctrl_get_accept_names(void **state)
{
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);
    const char *out;

    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_ACCEPT, 0, &out), -1);

    bio->init = 1;
    data->cache_accepting_name = OPENSSL_strdup("accept.host");
    data->cache_accepting_serv = OPENSSL_strdup("443");
    data->cache_peer_name = OPENSSL_strdup("peer.host");
    data->cache_peer_serv = OPENSSL_strdup("55000");

    assert_string_equal(BIO_get_accept_name(bio), "accept.host");
    assert_string_equal(BIO_get_accept_port(bio), "443");
    assert_string_equal(BIO_get_peer_name(bio), "peer.host");
    assert_string_equal(BIO_get_peer_port(bio), "55000");

    bio->init = 0;
}

static void test_acpt_ctrl_get_accept_family(void **state)
{
    /* AF_INET addr_iter maps to BIO_FAMILY_IPV4 */
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    bio->init = 1;
    data->addr_iter = &g_addrinfo1;
    assert_int_equal(BIO_get_accept_ip_family(bio), BIO_FAMILY_IPV4);
    data->addr_iter = NULL;
    bio->init = 0;
}

static void test_acpt_ctrl_get_set_close(void **state)
{
    BIO *bio = *state;

    bio->shutdown = BIO_NOCLOSE;
    assert_int_equal(BIO_get_close(bio), BIO_NOCLOSE);

    assert_int_equal(BIO_set_close(bio, BIO_CLOSE), 1);
    assert_int_equal(bio->shutdown, BIO_CLOSE);
}

static void test_acpt_ctrl_bind_mode(void **state)
{
    BIO *bio = *state;
    BIO_ACCEPT *data = get_data(bio);

    BIO_set_bind_mode(bio, BIO_SOCK_REUSEADDR);
    assert_int_equal(data->bind_mode, BIO_SOCK_REUSEADDR);
    assert_int_equal(BIO_get_bind_mode(bio), BIO_SOCK_REUSEADDR);
}

static void test_acpt_ctrl_pending_flush(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL), 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_WPENDING, 0, NULL), 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, NULL), 1);
}

static void test_acpt_ctrl_eof_no_next(void **state)
{
    /* next_bio == NULL -> 0 */
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_EOF, 0, NULL), 0);
}

static void test_acpt_ctrl_default(void **state)
{
    assert_int_equal(BIO_ctrl(*state, 9999, 0, NULL), 0);
}

/* BIO_new_accept convenience constructor */

static void test_bio_new_accept(void **state)
{
    BIO *bio = BIO_new_accept("localhost:443");
    BIO_ACCEPT *data;

    assert_non_null(bio);
    data = (BIO_ACCEPT *)bio->ptr;
    assert_string_equal(data->param_addr, "localhost");
    assert_string_equal(data->param_serv, "443");
    BIO_free(bio);
    (void)state;
}

/* main */

#define ACPT_TEST(name) \
    cmocka_unit_test_setup_teardown(name, setup, teardown)

#define ACPT_TEST_IO(name) \
    cmocka_unit_test_setup_teardown(name, setup_io, teardown_io)

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* acpt_new */
        ACPT_TEST(test_acpt_new),
        /* acpt_free */
        ACPT_TEST(test_acpt_free_no_shutdown),
        /* acpt_close_socket */
        ACPT_TEST(test_close_socket_none),
        /* acpt_state */
        ACPT_TEST(test_acpt_state_no_addr),
        ACPT_TEST(test_acpt_state_unsupported_family),
        ACPT_TEST(test_acpt_state_lookup_fails),
        ACPT_TEST(test_acpt_state_lookup_empty),
        ACPT_TEST(test_acpt_state_socket_fails),
        ACPT_TEST(test_acpt_state_socket_next_addr),
        ACPT_TEST(test_acpt_state_listen_fails),
        ACPT_TEST(test_acpt_state_sock_info_fails),
        ACPT_TEST(test_acpt_state_bind_ok),
        ACPT_TEST(test_acpt_state_accept_retry),
        ACPT_TEST(test_acpt_state_accept_error),
        ACPT_TEST(test_acpt_state_already_ok_no_next),
        /* acpt_read / acpt_write / acpt_puts */
        ACPT_TEST_IO(test_acpt_read_forwards),
        ACPT_TEST_IO(test_acpt_read_forwards_retry),
        ACPT_TEST_IO(test_acpt_write_forwards),
        ACPT_TEST_IO(test_acpt_write_forwards_retry),
        ACPT_TEST_IO(test_acpt_puts_forwards),
        /* acpt_ctrl */
        ACPT_TEST(test_acpt_ctrl_reset_clears_addrs),
        ACPT_TEST(test_acpt_ctrl_set_accept_name),
        ACPT_TEST(test_acpt_ctrl_set_accept_port),
        ACPT_TEST(test_acpt_ctrl_set_nbio_accept),
        ACPT_TEST(test_acpt_ctrl_set_accept_bios),
        ACPT_TEST(test_acpt_ctrl_set_accept_ip_family),
        ACPT_TEST(test_acpt_ctrl_set_tfo_accept),
        ACPT_TEST(test_acpt_ctrl_set_nbio),
        ACPT_TEST(test_acpt_ctrl_set_fd),
        ACPT_TEST(test_acpt_ctrl_get_fd),
        ACPT_TEST(test_acpt_ctrl_get_accept_names),
        ACPT_TEST(test_acpt_ctrl_get_accept_family),
        ACPT_TEST(test_acpt_ctrl_get_set_close),
        ACPT_TEST(test_acpt_ctrl_bind_mode),
        ACPT_TEST(test_acpt_ctrl_pending_flush),
        ACPT_TEST(test_acpt_ctrl_eof_no_next),
        ACPT_TEST(test_acpt_ctrl_default),
        /* BIO_new_accept */
        ACPT_TEST(test_bio_new_accept),
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
