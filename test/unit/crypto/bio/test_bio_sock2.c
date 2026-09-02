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
#include <cmocka.h>

#include "bio_local.h"
#include "internal/bio_tfo.h"
#include <openssl/bio.h>

#define FAKE_SOCKET 42
#define ACCEPTED_SOCKET 7

/* prototypes for __wrap_* (required by -Wmissing-prototypes) */
int __wrap_socket(int domain, int type, int protocol);
int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t addrlen);
int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t addrlen);
int __wrap_listen(int fd, int backlog);
int __wrap_accept(int fd, struct sockaddr *addr, socklen_t *addrlen);
int __wrap_close(int fd);
int __wrap_getsockopt(int fd, int level, int optname, void *optval,
    socklen_t *optlen);
int __wrap_setsockopt(int fd, int level, int optname, const void *optval,
    socklen_t optlen);
int __wrap_BIO_socket_nbio(int fd, int mode);
int __wrap_BIO_sock_should_retry(int i);

/* wraps */

int __wrap_socket(int domain, int type, int protocol)
{
    function_called();
    check_expected(domain);
    check_expected(type);
    check_expected(protocol);
    return mock_type(int);
}

int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    function_called();
    check_expected(fd);
    (void)addr;
    (void)addrlen;
    return mock_type(int);
}

int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    function_called();
    check_expected(fd);
    (void)addr;
    (void)addrlen;
    return mock_type(int);
}

int __wrap_listen(int fd, int backlog)
{
    function_called();
    check_expected(fd);
    (void)backlog;
    return mock_type(int);
}

int __wrap_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    function_called();
    check_expected(fd);
    (void)addr;
    (void)addrlen;
    return mock_type(int);
}

int __wrap_close(int fd)
{
    function_called();
    check_expected(fd);
    return mock_type(int);
}

int __wrap_getsockopt(int fd, int level, int optname, void *optval,
    socklen_t *optlen)
{
    int rc;

    function_called();
    check_expected(fd);
    check_expected(level);
    check_expected(optname);
    rc = mock_type(int);
    if (rc == 0) {
        if (optval != NULL)
            *(int *)optval = mock_type(int);
        if (optlen != NULL)
            *optlen = (socklen_t)mock_type(int);
    }
    return rc;
}

int __wrap_setsockopt(int fd, int level, int optname, const void *optval,
    socklen_t optlen)
{
    int on = (optval != NULL) ? *(const int *)optval : 0;

    function_called();
    check_expected(fd);
    check_expected(level);
    check_expected(optname);
    check_expected(on);
    (void)optlen;
    return mock_type(int);
}

int __wrap_BIO_socket_nbio(int fd, int mode)
{
    function_called();
    check_expected(fd);
    check_expected(mode);
    return mock_type(int);
}

int __wrap_BIO_sock_should_retry(int i)
{
    function_called();
    check_expected(i);
    return mock_type(int);
}

/* expectations */

static void expect_socket(int domain, int type, int protocol, int rc)
{
    expect_function_call(__wrap_socket);
    expect_value(__wrap_socket, domain, domain);
    expect_value(__wrap_socket, type, type);
    expect_value(__wrap_socket, protocol, protocol);
    will_return(__wrap_socket, rc);
}

static void expect_connect(int fd, int rc)
{
    expect_function_call(__wrap_connect);
    expect_value(__wrap_connect, fd, fd);
    will_return(__wrap_connect, rc);
}

static void expect_bind(int fd, int rc)
{
    expect_function_call(__wrap_bind);
    expect_value(__wrap_bind, fd, fd);
    will_return(__wrap_bind, rc);
}

static void expect_listen(int fd, int rc)
{
    expect_function_call(__wrap_listen);
    expect_value(__wrap_listen, fd, fd);
    will_return(__wrap_listen, rc);
}

static void expect_accept(int fd, int rc)
{
    expect_function_call(__wrap_accept);
    expect_value(__wrap_accept, fd, fd);
    will_return(__wrap_accept, rc);
}

static void expect_close(int fd, int rc)
{
    expect_function_call(__wrap_close);
    expect_value(__wrap_close, fd, fd);
    will_return(__wrap_close, rc);
}

static void expect_getsockopt(int fd, int level, int optname, int rc,
    int value, socklen_t outlen)
{
    expect_function_call(__wrap_getsockopt);
    expect_value(__wrap_getsockopt, fd, fd);
    expect_value(__wrap_getsockopt, level, level);
    expect_value(__wrap_getsockopt, optname, optname);
    will_return(__wrap_getsockopt, rc);
    if (rc == 0) {
        will_return(__wrap_getsockopt, value);
        will_return(__wrap_getsockopt, (int)outlen);
    }
}

static void expect_setsockopt(int fd, int level, int optname, int on, int rc)
{
    expect_function_call(__wrap_setsockopt);
    expect_value(__wrap_setsockopt, fd, fd);
    expect_value(__wrap_setsockopt, level, level);
    expect_value(__wrap_setsockopt, optname, optname);
    expect_value(__wrap_setsockopt, on, on);
    will_return(__wrap_setsockopt, rc);
}

static void expect_nbio(int fd, int mode, int rc)
{
    expect_function_call(__wrap_BIO_socket_nbio);
    expect_value(__wrap_BIO_socket_nbio, fd, fd);
    expect_value(__wrap_BIO_socket_nbio, mode, mode);
    will_return(__wrap_BIO_socket_nbio, rc);
}

static void expect_should_retry(int i, int rc)
{
    expect_function_call(__wrap_BIO_sock_should_retry);
    expect_value(__wrap_BIO_sock_should_retry, i, i);
    will_return(__wrap_BIO_sock_should_retry, rc);
}

/* helpers */

static void make_addr(BIO_ADDR *a, int family)
{
    memset(a, 0, sizeof(*a));
    a->sa.sa_family = family;
}

/* BIO_socket */

static void test_socket_success(void **state)
{
    (void)state;
    expect_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, FAKE_SOCKET);
    assert_int_equal(
        BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0), FAKE_SOCKET);
}

static void test_socket_fails(void **state)
{
    (void)state;
    expect_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, -1);
    assert_int_equal(
        BIO_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0), (int)INVALID_SOCKET);
}

/* BIO_connect */

static void test_connect_invalid_sock(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    assert_int_equal(BIO_connect(-1, &a, 0), 0);
}

static void test_connect_nbio_fails(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_nbio(FAKE_SOCKET, 0, 0);
    assert_int_equal(BIO_connect(FAKE_SOCKET, &a, 0), 0);
}

static void test_connect_success(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_connect(FAKE_SOCKET, 0);
    assert_int_equal(BIO_connect(FAKE_SOCKET, &a, 0), 1);
}

static void test_connect_nonblock(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_nbio(FAKE_SOCKET, 1, 1);
    expect_connect(FAKE_SOCKET, 0);
    assert_int_equal(BIO_connect(FAKE_SOCKET, &a, BIO_SOCK_NONBLOCK), 1);
}

static void test_connect_keepalive(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_setsockopt(FAKE_SOCKET, SOL_SOCKET, SO_KEEPALIVE, 1, 0);
    expect_connect(FAKE_SOCKET, 0);
    assert_int_equal(BIO_connect(FAKE_SOCKET, &a, BIO_SOCK_KEEPALIVE), 1);
}

static void test_connect_keepalive_fails(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_setsockopt(FAKE_SOCKET, SOL_SOCKET, SO_KEEPALIVE, 1, -1);
    assert_int_equal(BIO_connect(FAKE_SOCKET, &a, BIO_SOCK_KEEPALIVE), 0);
}

static void test_connect_nodelay(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_setsockopt(FAKE_SOCKET, IPPROTO_TCP, TCP_NODELAY, 1, 0);
    expect_connect(FAKE_SOCKET, 0);
    assert_int_equal(BIO_connect(FAKE_SOCKET, &a, BIO_SOCK_NODELAY), 1);
}

static void test_connect_nodelay_fails(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_setsockopt(FAKE_SOCKET, IPPROTO_TCP, TCP_NODELAY, 1, -1);
    assert_int_equal(BIO_connect(FAKE_SOCKET, &a, BIO_SOCK_NODELAY), 0);
}

static void test_connect_fails_retry(void **state)
{
    /* connect() failing retryably returns 0 without raising a fatal error */
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_connect(FAKE_SOCKET, -1);
    expect_should_retry(-1, 1);
    assert_int_equal(BIO_connect(FAKE_SOCKET, &a, 0), 0);
}

static void test_connect_fails_error(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_connect(FAKE_SOCKET, -1);
    expect_should_retry(-1, 0);
    assert_int_equal(BIO_connect(FAKE_SOCKET, &a, 0), 0);
}

/* BIO_bind */

static void test_bind_invalid_sock(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    assert_int_equal(BIO_bind(-1, &a, 0), 0);
}

static void test_bind_success(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_bind(FAKE_SOCKET, 0);
    assert_int_equal(BIO_bind(FAKE_SOCKET, &a, 0), 1);
}

static void test_bind_reuseaddr(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_setsockopt(FAKE_SOCKET, SOL_SOCKET, SO_REUSEADDR, 1, 0);
    expect_bind(FAKE_SOCKET, 0);
    assert_int_equal(BIO_bind(FAKE_SOCKET, &a, BIO_SOCK_REUSEADDR), 1);
}

static void test_bind_reuseaddr_fails(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_setsockopt(FAKE_SOCKET, SOL_SOCKET, SO_REUSEADDR, 1, -1);
    assert_int_equal(BIO_bind(FAKE_SOCKET, &a, BIO_SOCK_REUSEADDR), 0);
}

static void test_bind_bind_fails(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_bind(FAKE_SOCKET, -1);
    assert_int_equal(BIO_bind(FAKE_SOCKET, &a, 0), 0);
}

/* BIO_listen */

static void test_listen_success(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, 0, SOCK_STREAM,
        sizeof(int));
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_bind(FAKE_SOCKET, 0);
    expect_listen(FAKE_SOCKET, 0);
    assert_int_equal(BIO_listen(FAKE_SOCKET, &a, 0), 1);
}

static void test_listen_invalid_sock(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    assert_int_equal(BIO_listen(-1, &a, 0), 0);
}

static void test_listen_getsockopt_fails(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, -1, 0, 0);
    assert_int_equal(BIO_listen(FAKE_SOCKET, &a, 0), 0);
}

static void test_listen_socktype_len_mismatch(void **state)
{
    /* a short socktype_len is rejected even when getsockopt succeeds */
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, 0, SOCK_STREAM,
        (socklen_t)(sizeof(int) - 1));
    assert_int_equal(BIO_listen(FAKE_SOCKET, &a, 0), 0);
}

static void test_listen_nbio_fails(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, 0, SOCK_STREAM,
        sizeof(int));
    expect_nbio(FAKE_SOCKET, 0, 0);
    assert_int_equal(BIO_listen(FAKE_SOCKET, &a, 0), 0);
}

static void test_listen_keepalive(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, 0, SOCK_STREAM,
        sizeof(int));
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_setsockopt(FAKE_SOCKET, SOL_SOCKET, SO_KEEPALIVE, 1, 0);
    expect_bind(FAKE_SOCKET, 0);
    expect_listen(FAKE_SOCKET, 0);
    assert_int_equal(BIO_listen(FAKE_SOCKET, &a, BIO_SOCK_KEEPALIVE), 1);
}

static void test_listen_keepalive_fails(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, 0, SOCK_STREAM,
        sizeof(int));
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_setsockopt(FAKE_SOCKET, SOL_SOCKET, SO_KEEPALIVE, 1, -1);
    assert_int_equal(BIO_listen(FAKE_SOCKET, &a, BIO_SOCK_KEEPALIVE), 0);
}

static void test_listen_nodelay(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, 0, SOCK_STREAM,
        sizeof(int));
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_setsockopt(FAKE_SOCKET, IPPROTO_TCP, TCP_NODELAY, 1, 0);
    expect_bind(FAKE_SOCKET, 0);
    expect_listen(FAKE_SOCKET, 0);
    assert_int_equal(BIO_listen(FAKE_SOCKET, &a, BIO_SOCK_NODELAY), 1);
}

static void test_listen_reuseaddr(void **state)
{
    /* REUSEADDR is honoured inside the real (unwrappable) BIO_bind */
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, 0, SOCK_STREAM,
        sizeof(int));
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_setsockopt(FAKE_SOCKET, SOL_SOCKET, SO_REUSEADDR, 1, 0);
    expect_bind(FAKE_SOCKET, 0);
    expect_listen(FAKE_SOCKET, 0);
    assert_int_equal(BIO_listen(FAKE_SOCKET, &a, BIO_SOCK_REUSEADDR), 1);
}

static void test_listen_bind_fails(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, 0, SOCK_STREAM,
        sizeof(int));
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_bind(FAKE_SOCKET, -1);
    assert_int_equal(BIO_listen(FAKE_SOCKET, &a, 0), 0);
}

static void test_listen_dgram(void **state)
{
    /* datagram sockets are bound but never put into listen() */
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, 0, SOCK_DGRAM,
        sizeof(int));
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_bind(FAKE_SOCKET, 0);
    assert_int_equal(BIO_listen(FAKE_SOCKET, &a, 0), 1);
}

static void test_listen_listen_fails(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET);
    expect_getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, 0, SOCK_STREAM,
        sizeof(int));
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_bind(FAKE_SOCKET, 0);
    expect_listen(FAKE_SOCKET, -1);
    assert_int_equal(BIO_listen(FAKE_SOCKET, &a, 0), 0);
}

#if defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
static void test_listen_v6only(void **state)
{
    /* an AF_INET6 socket always gets IPV6_V6ONLY set, here to 1 */
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET6);
    expect_getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, 0, SOCK_STREAM,
        sizeof(int));
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_setsockopt(FAKE_SOCKET, IPPROTO_IPV6, IPV6_V6ONLY, 1, 0);
    expect_bind(FAKE_SOCKET, 0);
    expect_listen(FAKE_SOCKET, 0);
    assert_int_equal(BIO_listen(FAKE_SOCKET, &a, BIO_SOCK_V6_ONLY), 1);
}

static void test_listen_v6only_off(void **state)
{
    /* without BIO_SOCK_V6_ONLY the option is still set, to 0 */
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET6);
    expect_getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, 0, SOCK_STREAM,
        sizeof(int));
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_setsockopt(FAKE_SOCKET, IPPROTO_IPV6, IPV6_V6ONLY, 0, 0);
    expect_bind(FAKE_SOCKET, 0);
    expect_listen(FAKE_SOCKET, 0);
    assert_int_equal(BIO_listen(FAKE_SOCKET, &a, 0), 1);
}

static void test_listen_v6only_fails(void **state)
{
    BIO_ADDR a;

    (void)state;
    make_addr(&a, AF_INET6);
    expect_getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, 0, SOCK_STREAM,
        sizeof(int));
    expect_nbio(FAKE_SOCKET, 0, 1);
    expect_setsockopt(FAKE_SOCKET, IPPROTO_IPV6, IPV6_V6ONLY, 1, -1);
    assert_int_equal(BIO_listen(FAKE_SOCKET, &a, BIO_SOCK_V6_ONLY), 0);
}
#endif

/* BIO_accept_ex */

static void test_accept_ex_success(void **state)
{
    BIO_ADDR a;

    (void)state;
    memset(&a, 0, sizeof(a));
    expect_accept(FAKE_SOCKET, ACCEPTED_SOCKET);
    expect_nbio(ACCEPTED_SOCKET, 0, 1);
    assert_int_equal(BIO_accept_ex(FAKE_SOCKET, &a, 0), ACCEPTED_SOCKET);
}

static void test_accept_ex_null_addr(void **state)
{
    /* a NULL addr is accepted into an internal local BIO_ADDR */
    (void)state;
    expect_accept(FAKE_SOCKET, ACCEPTED_SOCKET);
    expect_nbio(ACCEPTED_SOCKET, 0, 1);
    assert_int_equal(BIO_accept_ex(FAKE_SOCKET, NULL, 0), ACCEPTED_SOCKET);
}

static void test_accept_ex_nonblock(void **state)
{
    BIO_ADDR a;

    (void)state;
    memset(&a, 0, sizeof(a));
    expect_accept(FAKE_SOCKET, ACCEPTED_SOCKET);
    expect_nbio(ACCEPTED_SOCKET, 1, 1);
    assert_int_equal(
        BIO_accept_ex(FAKE_SOCKET, &a, BIO_SOCK_NONBLOCK), ACCEPTED_SOCKET);
}

static void test_accept_ex_retry(void **state)
{
    BIO_ADDR a;

    (void)state;
    memset(&a, 0, sizeof(a));
    expect_accept(FAKE_SOCKET, -1);
    expect_should_retry(-1, 1);
    assert_int_equal(BIO_accept_ex(FAKE_SOCKET, &a, 0), (int)INVALID_SOCKET);
}

static void test_accept_ex_error(void **state)
{
    BIO_ADDR a;

    (void)state;
    memset(&a, 0, sizeof(a));
    expect_accept(FAKE_SOCKET, -1);
    expect_should_retry(-1, 0);
    assert_int_equal(BIO_accept_ex(FAKE_SOCKET, &a, 0), (int)INVALID_SOCKET);
}

static void test_accept_ex_nbio_fails(void **state)
{
    /* a non-blocking failure on the accepted socket closes it again */
    BIO_ADDR a;

    (void)state;
    memset(&a, 0, sizeof(a));
    expect_accept(FAKE_SOCKET, ACCEPTED_SOCKET);
    expect_nbio(ACCEPTED_SOCKET, 0, 0);
    expect_close(ACCEPTED_SOCKET, 0);
    assert_int_equal(BIO_accept_ex(FAKE_SOCKET, &a, 0), (int)INVALID_SOCKET);
}

/* BIO_closesocket */

static void test_closesocket_success(void **state)
{
    (void)state;
    expect_close(FAKE_SOCKET, 0);
    assert_int_equal(BIO_closesocket(FAKE_SOCKET), 1);
}

static void test_closesocket_negative(void **state)
{
    /* a negative fd short-circuits before any close() */
    (void)state;
    assert_int_equal(BIO_closesocket(-1), 0);
}

static void test_closesocket_fails(void **state)
{
    (void)state;
    expect_close(FAKE_SOCKET, -1);
    assert_int_equal(BIO_closesocket(FAKE_SOCKET), 0);
}

/* main */

#define SOCK_TEST(name) cmocka_unit_test(name)

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* BIO_socket */
        SOCK_TEST(test_socket_success),
        SOCK_TEST(test_socket_fails),
        /* BIO_connect */
        SOCK_TEST(test_connect_invalid_sock),
        SOCK_TEST(test_connect_nbio_fails),
        SOCK_TEST(test_connect_success),
        SOCK_TEST(test_connect_nonblock),
        SOCK_TEST(test_connect_keepalive),
        SOCK_TEST(test_connect_keepalive_fails),
        SOCK_TEST(test_connect_nodelay),
        SOCK_TEST(test_connect_nodelay_fails),
        SOCK_TEST(test_connect_fails_retry),
        SOCK_TEST(test_connect_fails_error),
        /* BIO_bind */
        SOCK_TEST(test_bind_invalid_sock),
        SOCK_TEST(test_bind_success),
        SOCK_TEST(test_bind_reuseaddr),
        SOCK_TEST(test_bind_reuseaddr_fails),
        SOCK_TEST(test_bind_bind_fails),
        /* BIO_listen */
        SOCK_TEST(test_listen_success),
        SOCK_TEST(test_listen_invalid_sock),
        SOCK_TEST(test_listen_getsockopt_fails),
        SOCK_TEST(test_listen_socktype_len_mismatch),
        SOCK_TEST(test_listen_nbio_fails),
        SOCK_TEST(test_listen_keepalive),
        SOCK_TEST(test_listen_keepalive_fails),
        SOCK_TEST(test_listen_nodelay),
        SOCK_TEST(test_listen_reuseaddr),
        SOCK_TEST(test_listen_bind_fails),
        SOCK_TEST(test_listen_dgram),
        SOCK_TEST(test_listen_listen_fails),
#if defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
        SOCK_TEST(test_listen_v6only),
        SOCK_TEST(test_listen_v6only_off),
        SOCK_TEST(test_listen_v6only_fails),
#endif
        /* BIO_accept_ex */
        SOCK_TEST(test_accept_ex_success),
        SOCK_TEST(test_accept_ex_null_addr),
        SOCK_TEST(test_accept_ex_nonblock),
        SOCK_TEST(test_accept_ex_retry),
        SOCK_TEST(test_accept_ex_error),
        SOCK_TEST(test_accept_ex_nbio_fails),
        /* BIO_closesocket */
        SOCK_TEST(test_closesocket_success),
        SOCK_TEST(test_closesocket_negative),
        SOCK_TEST(test_closesocket_fails),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#else

int main(void)
{
    return 0;
}

#endif /* OPENSSL_NO_SOCK */
