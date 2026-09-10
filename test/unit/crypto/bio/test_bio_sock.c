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
#include <openssl/bio.h>

#define FAKE_SOCKET 42

#if defined(TCP_NODELAY) && (defined(IPPROTO_TCP) || defined(SOL_TCP))
#ifdef SOL_TCP
#define TEST_TCP_LEVEL SOL_TCP
#else
#define TEST_TCP_LEVEL IPPROTO_TCP
#endif
#endif

/* prototypes for __wrap_* (required by -Wmissing-prototypes) */
int __wrap_getsockopt(int fd, int level, int optname, void *optval,
    socklen_t *optlen);
int __wrap_setsockopt(int fd, int level, int optname, const void *optval,
    socklen_t optlen);
int __wrap_getsockname(int fd, struct sockaddr *addr, socklen_t *slen);
int __wrap_ioctl(int fd, unsigned long request, void *arg);
int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout);
struct hostent *__wrap_gethostbyname(const char *name);
int __wrap_BIO_lookup(const char *host, const char *service,
    enum BIO_lookup_type lookup_type, int family, int socktype,
    BIO_ADDRINFO **res);
int __wrap_BIO_socket(int domain, int socktype, int protocol, int options);
int __wrap_BIO_listen(int sock, const BIO_ADDR *ba, int options);
int __wrap_BIO_closesocket(int sock);
void __wrap_BIO_ADDRINFO_free(BIO_ADDRINFO *bai);
int __wrap_BIO_accept_ex(int accept_sock, BIO_ADDR *addr, int options);
int __wrap_BIO_sock_should_retry(int i);
char *__wrap_BIO_ADDR_hostname_string(const BIO_ADDR *ap, int numeric);
char *__wrap_BIO_ADDR_service_string(const BIO_ADDR *ap, int numeric);

/* wraps */

int __wrap_getsockopt(int fd, int level, int optname, void *optval,
    socklen_t *optlen)
{
    int rc;

    function_called();
    check_expected(fd);
    check_expected(level);
    check_expected(optname);
    (void)optlen;
    rc = mock_type(int);
    if (rc == 0) {
        if (optval != NULL)
            *(int *)optval = mock_type(int);
    } else {
        errno = mock_type(int);
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

int __wrap_getsockname(int fd, struct sockaddr *addr, socklen_t *slen)
{
    int rc;

    function_called();
    check_expected(fd);
    (void)addr;
    rc = mock_type(int);
    if (rc == 0 && slen != NULL)
        *slen = (socklen_t)mock_type(int);
    return rc;
}

int __wrap_ioctl(int fd, unsigned long request, void *arg)
{
    function_called();
    check_expected(fd);
    check_expected(request);
    (void)arg;
    return mock_type(int);
}

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    int pfd = fds[0].fd;
    int events = fds[0].events;

    function_called();
    check_expected(pfd);
    check_expected(events);
    (void)nfds;
    (void)timeout;
    return mock_type(int);
}

struct hostent *__wrap_gethostbyname(const char *name)
{
    function_called();
    check_expected_ptr(name);
    return mock_ptr_type(struct hostent *);
}

int __wrap_BIO_lookup(const char *host, const char *service,
    enum BIO_lookup_type lookup_type, int family, int socktype,
    BIO_ADDRINFO **res)
{
    int rc;

    function_called();
    check_expected(family);
    check_expected(socktype);
    check_expected(lookup_type);
    (void)host;
    (void)service;
    rc = mock_type(int);
    if (rc == 1) {
        BIO_ADDRINFO *r = mock_ptr_type(BIO_ADDRINFO *);

        if (res != NULL)
            *res = r;
    }
    return rc;
}

int __wrap_BIO_socket(int domain, int socktype, int protocol, int options)
{
    function_called();
    check_expected(domain);
    check_expected(socktype);
    check_expected(protocol);
    (void)options;
    return mock_type(int);
}

int __wrap_BIO_listen(int sock, const BIO_ADDR *ba, int options)
{
    function_called();
    check_expected(sock);
    check_expected(options);
    (void)ba;
    return mock_type(int);
}

int __wrap_BIO_closesocket(int sock)
{
    function_called();
    check_expected(sock);
    return mock_type(int);
}

/* the fake addrinfo handed back by BIO_lookup is static; nothing to release */
void __wrap_BIO_ADDRINFO_free(BIO_ADDRINFO *bai)
{
    (void)bai;
}

int __wrap_BIO_accept_ex(int accept_sock, BIO_ADDR *addr, int options)
{
    function_called();
    check_expected(accept_sock);
    check_expected(options);
    (void)addr;
    return mock_type(int);
}

int __wrap_BIO_sock_should_retry(int i)
{
    function_called();
    check_expected(i);
    return mock_type(int);
}

char *__wrap_BIO_ADDR_hostname_string(const BIO_ADDR *ap, int numeric)
{
    function_called();
    check_expected(numeric);
    (void)ap;
    return mock_ptr_type(char *);
}

char *__wrap_BIO_ADDR_service_string(const BIO_ADDR *ap, int numeric)
{
    function_called();
    check_expected(numeric);
    (void)ap;
    return mock_ptr_type(char *);
}

/* expectations */

static void expect_getsockopt(int fd, int rc, int value)
{
    expect_function_call(__wrap_getsockopt);
    expect_value(__wrap_getsockopt, fd, fd);
    expect_value(__wrap_getsockopt, level, SOL_SOCKET);
    expect_value(__wrap_getsockopt, optname, SO_ERROR);
    will_return(__wrap_getsockopt, rc);
    will_return(__wrap_getsockopt, value);
}

#if defined(TCP_NODELAY) && (defined(IPPROTO_TCP) || defined(SOL_TCP))
static void expect_setsockopt(int fd, int on, int rc)
{
    expect_function_call(__wrap_setsockopt);
    expect_value(__wrap_setsockopt, fd, fd);
    expect_value(__wrap_setsockopt, level, TEST_TCP_LEVEL);
    expect_value(__wrap_setsockopt, optname, TCP_NODELAY);
    expect_value(__wrap_setsockopt, on, on);
    will_return(__wrap_setsockopt, rc);
}
#endif

static void expect_getsockname(int fd, int rc, socklen_t outlen)
{
    expect_function_call(__wrap_getsockname);
    expect_value(__wrap_getsockname, fd, fd);
    will_return(__wrap_getsockname, rc);
    if (rc == 0)
        will_return(__wrap_getsockname, (int)outlen);
}

#ifdef FIONBIO
static void expect_ioctl(int fd, unsigned long request, int rc)
{
    expect_function_call(__wrap_ioctl);
    expect_value(__wrap_ioctl, fd, fd);
    expect_value(__wrap_ioctl, request, request);
    will_return(__wrap_ioctl, rc);
}
#endif

static void expect_poll(int fd, int events, int rc)
{
    expect_function_call(__wrap_poll);
    expect_value(__wrap_poll, pfd, fd);
    expect_value(__wrap_poll, events, events);
    will_return(__wrap_poll, rc);
}

/* setup */

/* BIO_sock_init / bio_sock_cleanup_int */

static void test_sock_init(void **state)
{
    (void)state;
    assert_int_equal(BIO_sock_init(), 1);
}

static void test_sock_cleanup(void **state)
{
    (void)state;
    /* no-op on non-Windows; exercised for coverage */
    bio_sock_cleanup_int();
}

/* BIO_sock_error */

static void test_sock_error_value(void **state)
{
    /* getsockopt succeeds: SO_ERROR value is returned verbatim */
    (void)state;
    expect_getsockopt(FAKE_SOCKET, 0, ECONNREFUSED);
    assert_int_equal(BIO_sock_error(FAKE_SOCKET), ECONNREFUSED);
}

static void test_sock_error_getsockopt_fails(void **state)
{
    /* getsockopt fails: the last socket error (errno) is returned */
    (void)state;
    expect_getsockopt(FAKE_SOCKET, -1, EBADF);
    assert_int_equal(BIO_sock_error(FAKE_SOCKET), EBADF);
}

/* BIO_socket_ioctl */

#ifdef FIONBIO
static void test_socket_ioctl_success(void **state)
{
    int arg = 1;

    (void)state;
    expect_ioctl(FAKE_SOCKET, FIONBIO, 0);
    assert_int_equal(BIO_socket_ioctl(FAKE_SOCKET, FIONBIO, &arg), 0);
}

static void test_socket_ioctl_error(void **state)
{
    int arg = 1;

    (void)state;
    expect_ioctl(FAKE_SOCKET, FIONBIO, -1);
    assert_int_equal(BIO_socket_ioctl(FAKE_SOCKET, FIONBIO, &arg), -1);
}
#endif

/* BIO_set_tcp_ndelay */

#if defined(TCP_NODELAY) && (defined(IPPROTO_TCP) || defined(SOL_TCP))
static void test_set_tcp_ndelay_on(void **state)
{
    (void)state;
    expect_setsockopt(FAKE_SOCKET, 1, 0);
    assert_int_equal(BIO_set_tcp_ndelay(FAKE_SOCKET, 1), 1);
}

static void test_set_tcp_ndelay_off(void **state)
{
    (void)state;
    expect_setsockopt(FAKE_SOCKET, 0, 0);
    assert_int_equal(BIO_set_tcp_ndelay(FAKE_SOCKET, 0), 1);
}

static void test_set_tcp_ndelay_fails(void **state)
{
    (void)state;
    expect_setsockopt(FAKE_SOCKET, 1, -1);
    assert_int_equal(BIO_set_tcp_ndelay(FAKE_SOCKET, 1), 0);
}
#endif

/* BIO_socket_nbio */

#ifdef FIONBIO
static void test_socket_nbio_enable(void **state)
{
    (void)state;
    expect_ioctl(FAKE_SOCKET, FIONBIO, 0);
    assert_int_equal(BIO_socket_nbio(FAKE_SOCKET, 1), 1);
}

static void test_socket_nbio_disable(void **state)
{
    (void)state;
    expect_ioctl(FAKE_SOCKET, FIONBIO, 0);
    assert_int_equal(BIO_socket_nbio(FAKE_SOCKET, 0), 1);
}

static void test_socket_nbio_fails(void **state)
{
    (void)state;
    expect_ioctl(FAKE_SOCKET, FIONBIO, -1);
    assert_int_equal(BIO_socket_nbio(FAKE_SOCKET, 1), 0);
}
#endif

/* BIO_sock_info */

static void test_sock_info_success(void **state)
{
    union BIO_sock_info_u info;
    BIO_ADDR addr;

    (void)state;
    memset(&addr, 0, sizeof(addr));
    info.addr = &addr;
    expect_getsockname(FAKE_SOCKET, 0, (socklen_t)sizeof(struct sockaddr_in));
    assert_int_equal(
        BIO_sock_info(FAKE_SOCKET, BIO_SOCK_INFO_ADDRESS, &info), 1);
}

static void test_sock_info_getsockname_fails(void **state)
{
    union BIO_sock_info_u info;
    BIO_ADDR addr;

    (void)state;
    memset(&addr, 0, sizeof(addr));
    info.addr = &addr;
    expect_getsockname(FAKE_SOCKET, -1, 0);
    assert_int_equal(
        BIO_sock_info(FAKE_SOCKET, BIO_SOCK_INFO_ADDRESS, &info), 0);
}

static void test_sock_info_truncated(void **state)
{
    /* getsockname reports an address larger than the BIO_ADDR storage */
    union BIO_sock_info_u info;
    BIO_ADDR addr;

    (void)state;
    memset(&addr, 0, sizeof(addr));
    info.addr = &addr;
    expect_getsockname(FAKE_SOCKET, 0, (socklen_t)(sizeof(BIO_ADDR) + 1));
    assert_int_equal(
        BIO_sock_info(FAKE_SOCKET, BIO_SOCK_INFO_ADDRESS, &info), 0);
}

static void test_sock_info_unknown_type(void **state)
{
    union BIO_sock_info_u info;
    BIO_ADDR addr;

    (void)state;
    memset(&addr, 0, sizeof(addr));
    info.addr = &addr;
    assert_int_equal(
        BIO_sock_info(FAKE_SOCKET, (enum BIO_sock_info_type)999, &info), 0);
}

/* BIO_socket_wait */

static void test_socket_wait_immediate(void **state)
{
    /* max_time == 0 returns immediately without polling */
    (void)state;
    assert_int_equal(BIO_socket_wait(FAKE_SOCKET, 1, 0), 1);
}

static void test_socket_wait_bad_fd(void **state)
{
    (void)state;
    assert_int_equal(BIO_socket_wait(-1, 1, time(NULL) + 100), -1);
}

static void test_socket_wait_past(void **state)
{
    /* deadline already elapsed: timeout without polling */
    (void)state;
    assert_int_equal(BIO_socket_wait(FAKE_SOCKET, 1, (time_t)1), 0);
}

static void test_socket_wait_read_ready(void **state)
{
    (void)state;
    expect_poll(FAKE_SOCKET, POLLIN, 1);
    assert_int_equal(BIO_socket_wait(FAKE_SOCKET, 1, time(NULL) + 100), 1);
}

static void test_socket_wait_write_ready(void **state)
{
    (void)state;
    expect_poll(FAKE_SOCKET, POLLOUT, 1);
    assert_int_equal(BIO_socket_wait(FAKE_SOCKET, 0, time(NULL) + 100), 1);
}

static void test_socket_wait_timeout(void **state)
{
    (void)state;
    expect_poll(FAKE_SOCKET, POLLIN, 0);
    assert_int_equal(BIO_socket_wait(FAKE_SOCKET, 1, time(NULL) + 100), 0);
}

static void test_socket_wait_error(void **state)
{
    (void)state;
    expect_poll(FAKE_SOCKET, POLLIN, -1);
    assert_int_equal(BIO_socket_wait(FAKE_SOCKET, 1, time(NULL) + 100), -1);
}

/* main */

#define SOCK_TEST(name) cmocka_unit_test(name)

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* BIO_sock_init / cleanup */
        SOCK_TEST(test_sock_init),
        SOCK_TEST(test_sock_cleanup),
        /* BIO_sock_error */
        SOCK_TEST(test_sock_error_value),
        SOCK_TEST(test_sock_error_getsockopt_fails),
#ifdef FIONBIO
        /* BIO_socket_ioctl */
        SOCK_TEST(test_socket_ioctl_success),
        SOCK_TEST(test_socket_ioctl_error),
#endif
    /* BIO_set_tcp_ndelay */
#if defined(TCP_NODELAY) && (defined(IPPROTO_TCP) || defined(SOL_TCP))
        SOCK_TEST(test_set_tcp_ndelay_on),
        SOCK_TEST(test_set_tcp_ndelay_off),
        SOCK_TEST(test_set_tcp_ndelay_fails),
#endif
    /* BIO_socket_nbio */
#ifdef FIONBIO
        SOCK_TEST(test_socket_nbio_enable),
        SOCK_TEST(test_socket_nbio_disable),
        SOCK_TEST(test_socket_nbio_fails),
#endif
        /* BIO_sock_info */
        SOCK_TEST(test_sock_info_success),
        SOCK_TEST(test_sock_info_getsockname_fails),
        SOCK_TEST(test_sock_info_truncated),
        SOCK_TEST(test_sock_info_unknown_type),
        /* BIO_socket_wait */
        SOCK_TEST(test_socket_wait_immediate),
        SOCK_TEST(test_socket_wait_bad_fd),
        SOCK_TEST(test_socket_wait_past),
        SOCK_TEST(test_socket_wait_read_ready),
        SOCK_TEST(test_socket_wait_write_ready),
        SOCK_TEST(test_socket_wait_timeout),
        SOCK_TEST(test_socket_wait_error),
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
