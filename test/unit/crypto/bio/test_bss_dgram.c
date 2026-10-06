/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if defined(OPENSSL_NO_SOCK) || defined(OPENSSL_NO_DGRAM)

int main(void)
{
    return 0;
}

#else

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <cmocka.h>
#include "bio_local.h"
#include <openssl/bio.h>

#define FAKE_SOCKET 42

/* prototypes for __wrap_* (required by -Wmissing-prototypes) */
ssize_t __wrap_recvfrom(int fd, void *buf, size_t len, int flags,
    struct sockaddr *src, socklen_t *slen);
ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags,
    const struct sockaddr *dst, socklen_t slen);
ssize_t __wrap_write(int fd, const void *buf, size_t count);
int __wrap_getsockname(int fd, struct sockaddr *addr, socklen_t *slen);
int __wrap_getpeername(int fd, struct sockaddr *addr, socklen_t *slen);
int __wrap_BIO_closesocket(int fd);
int __wrap_BIO_socket_nbio(int fd, int mode);

/*
 * Shared sockaddrs handed back by the address-returning mocks.  group_setup
 * fills g_sin (AF_INET loopback); g_sin6 is an AF_INET6 loopback and
 * g_sin6_v4m an IPv4-mapped IPv6 address (::ffff:127.0.0.1).
 */
static struct sockaddr_in g_sin;
static struct sockaddr_in6 g_sin6;
static struct sockaddr_in6 g_sin6_v4m;

/* wraps */

ssize_t __wrap_recvfrom(int fd, void *buf, size_t len, int flags,
    struct sockaddr *src, socklen_t *slen)
{
    ssize_t rc;

    function_called();
    check_expected(fd);
    check_expected_ptr(buf);
    check_expected(len);
    check_expected(flags);
    rc = mock_type(ssize_t);
    if (rc >= 0 && src != NULL && slen != NULL) {
        const struct sockaddr *sa = mock_ptr_type(const struct sockaddr *);

        if (sa != NULL && *slen >= sizeof(g_sin)) {
            memcpy(src, sa, sizeof(g_sin));
            *slen = sizeof(g_sin);
        }
    }
    if (rc < 0)
        errno = mock_type(int);
    return rc;
}

ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags,
    const struct sockaddr *dst, socklen_t slen)
{
    ssize_t rc;

    function_called();
    check_expected(fd);
    check_expected_ptr(buf);
    check_expected(len);
    check_expected(flags);
    check_expected(slen);
    (void)dst;
    rc = mock_type(ssize_t);
    if (rc < 0)
        errno = mock_type(int);
    return rc;
}

ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
    function_called();
    check_expected(fd);
    check_expected_ptr(buf);
    check_expected(count);
    return mock_type(ssize_t);
}

int __wrap_getsockname(int fd, struct sockaddr *addr, socklen_t *slen)
{
    int rc;

    function_called();
    check_expected(fd);
    rc = mock_type(int);
    if (rc == 0 && addr != NULL && slen != NULL) {
        const struct sockaddr *sa = mock_ptr_type(const struct sockaddr *);
        socklen_t sl = (socklen_t)mock_type(int);

        if (sa != NULL && *slen >= sl) {
            memcpy(addr, sa, sl);
            *slen = sl;
        }
    }
    return rc;
}

int __wrap_getpeername(int fd, struct sockaddr *addr, socklen_t *slen)
{
    int rc;

    function_called();
    check_expected(fd);
    rc = mock_type(int);
    if (rc == 0 && addr != NULL && slen != NULL && *slen >= sizeof(g_sin)) {
        memcpy(addr, &g_sin, sizeof(g_sin));
        *slen = sizeof(g_sin);
    }
    return rc;
}

int __wrap_BIO_closesocket(int fd)
{
    function_called();
    check_expected(fd);
    return mock_type(int);
}

int __wrap_BIO_socket_nbio(int fd, int mode)
{
    function_called();
    check_expected(fd);
    check_expected(mode);
    return mock_type(int);
}

/* expectations */

static void expect_recvfrom(int fd, const void *buf, size_t len, int flags,
    ssize_t rc, const struct sockaddr *src, int errnoval)
{
    expect_function_call(__wrap_recvfrom);
    expect_value(__wrap_recvfrom, fd, fd);
    expect_value(__wrap_recvfrom, buf, buf);
    expect_value(__wrap_recvfrom, len, len);
    expect_value(__wrap_recvfrom, flags, flags);
    will_return(__wrap_recvfrom, rc);
    if (rc >= 0)
        will_return(__wrap_recvfrom, src);
    else
        will_return(__wrap_recvfrom, errnoval);
}

static void expect_sendto(int fd, const void *buf, size_t len, int flags,
    socklen_t slen, ssize_t rc, int errnoval)
{
    expect_function_call(__wrap_sendto);
    expect_value(__wrap_sendto, fd, fd);
    expect_value(__wrap_sendto, buf, buf);
    expect_value(__wrap_sendto, len, len);
    expect_value(__wrap_sendto, flags, flags);
    expect_value(__wrap_sendto, slen, slen);
    will_return(__wrap_sendto, rc);
    if (rc < 0)
        will_return(__wrap_sendto, errnoval);
}

static void expect_write(int fd, const void *buf, size_t count, ssize_t rc)
{
    expect_function_call(__wrap_write);
    expect_value(__wrap_write, fd, fd);
    expect_value(__wrap_write, buf, buf);
    expect_value(__wrap_write, count, count);
    will_return(__wrap_write, rc);
}

static void expect_getsockname(int fd, int rc)
{
    expect_function_call(__wrap_getsockname);
    expect_value(__wrap_getsockname, fd, fd);
    will_return(__wrap_getsockname, rc);
    if (rc == 0) {
        will_return(__wrap_getsockname, (const struct sockaddr *)&g_sin);
        will_return(__wrap_getsockname, (int)sizeof(g_sin));
    }
}

static void expect_getpeername(int fd, int rc)
{
    expect_function_call(__wrap_getpeername);
    expect_value(__wrap_getpeername, fd, fd);
    will_return(__wrap_getpeername, rc);
}

static void expect_BIO_closesocket(int fd, int rc)
{
    expect_function_call(__wrap_BIO_closesocket);
    expect_value(__wrap_BIO_closesocket, fd, fd);
    will_return(__wrap_BIO_closesocket, rc);
}

static void expect_BIO_socket_nbio(int fd, int mode, int rc)
{
    expect_function_call(__wrap_BIO_socket_nbio);
    expect_value(__wrap_BIO_socket_nbio, fd, fd);
    expect_value(__wrap_BIO_socket_nbio, mode, mode);
    will_return(__wrap_BIO_socket_nbio, rc);
}

/* helpers */

static bio_dgram_data *get_data(BIO *bio)
{
    return (bio_dgram_data *)bio->ptr;
}

static void make_peer(BIO *bio, unsigned short port)
{
    struct sockaddr_in sa;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &sa);
}

/*
 * Detach the fake socket before teardown so BIO_free does not call a real
 * close: BIO_NOCLOSE already guards it, but resetting num keeps any stray
 * dgram_clear path inert.
 */
static void reset_for_teardown(BIO *bio)
{
    bio->num = (int)INVALID_SOCKET;
    bio->shutdown = BIO_NOCLOSE;
}

/* setup / teardown */

static int setup(void **state)
{
    BIO *bio = BIO_new(BIO_s_datagram());

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

/* I/O tests attach the fake socket up front so the BIO is init'ed. */
static int setup_io(void **state)
{
    BIO *bio;

    if (setup(state) != 0)
        return -1;
    bio = *state;
    expect_getsockname(FAKE_SOCKET, 0);
    expect_getpeername(FAKE_SOCKET, -1);
    BIO_set_fd(bio, FAKE_SOCKET, BIO_NOCLOSE);
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
    struct in6_addr loop6 = IN6ADDR_LOOPBACK_INIT;

    (void)state;
    memset(&g_sin, 0, sizeof(g_sin));
    g_sin.sin_family = AF_INET;
    g_sin.sin_port = htons(443);
    g_sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    memset(&g_sin6, 0, sizeof(g_sin6));
    g_sin6.sin6_family = AF_INET6;
    g_sin6.sin6_port = htons(443);
    g_sin6.sin6_addr = loop6;

    /* ::ffff:127.0.0.1 -> IPv4-mapped, exercises the v4mapped MTU branch */
    memset(&g_sin6_v4m, 0, sizeof(g_sin6_v4m));
    g_sin6_v4m.sin6_family = AF_INET6;
    g_sin6_v4m.sin6_port = htons(443);
    g_sin6_v4m.sin6_addr.s6_addr[10] = 0xff;
    g_sin6_v4m.sin6_addr.s6_addr[11] = 0xff;
    g_sin6_v4m.sin6_addr.s6_addr[12] = 127;
    g_sin6_v4m.sin6_addr.s6_addr[15] = 1;
    return 0;
}

/* BIO_new_dgram */
static void test_new_dgram(void **state)
{
    int out = -1;
    BIO *bio;

    (void)state;
    expect_getsockname(FAKE_SOCKET, 0);
    expect_getpeername(FAKE_SOCKET, -1);
    bio = BIO_new_dgram(FAKE_SOCKET, BIO_NOCLOSE);
    assert_non_null(bio);
    assert_int_equal(BIO_get_fd(bio, &out), FAKE_SOCKET);
    assert_int_equal(out, FAKE_SOCKET);
    reset_for_teardown(bio);
    BIO_free(bio);
}

static void test_dgram_new_defaults(void **state)
{
    BIO *bio = *state;

    assert_non_null(get_data(bio));
    assert_int_equal(bio->num, 0);
    assert_int_equal(bio->init, 0);
}

/* BIO_C_SET_FD / BIO_C_GET_FD */

static void test_set_fd_unconnected(void **state)
{
    BIO *bio = *state;
    bio_dgram_data *data;
    int out = -1;

    expect_getsockname(FAKE_SOCKET, 0);
    expect_getpeername(FAKE_SOCKET, -1);
    BIO_set_fd(bio, FAKE_SOCKET, BIO_NOCLOSE);

    data = get_data(bio);
    assert_int_equal(data->connected, 0);
    assert_int_equal(bio->init, 1);
    assert_int_equal(BIO_get_fd(bio, &out), FAKE_SOCKET);
    assert_int_equal(out, FAKE_SOCKET);
    reset_for_teardown(bio);
}

static void test_set_fd_connected(void **state)
{
    /* getpeername succeeds: peer is recorded and connected is set */
    BIO *bio = *state;
    bio_dgram_data *data;

    expect_getsockname(FAKE_SOCKET, 0);
    expect_getpeername(FAKE_SOCKET, 0);
    BIO_set_fd(bio, FAKE_SOCKET, BIO_NOCLOSE);

    data = get_data(bio);
    assert_int_equal(data->connected, 1);
    assert_int_equal(BIO_ADDR_family(&data->peer), AF_INET);
    reset_for_teardown(bio);
}

static void test_get_fd_uninit(void **state)
{
    assert_int_equal(BIO_ctrl(*state, BIO_C_GET_FD, 0, NULL), -1);
}

/* dgram_read */

static void test_dgram_read_noop(void **state)
{
    /* outl == 0: recvfrom is never reached */
    BIO *bio = *state;
    char buf[1];

    assert_int_equal(BIO_read(bio, buf, 0), 0);
}

static void test_dgram_read_success(void **state)
{
    BIO *bio = *state;
    char buf[16] = { 0 };

    expect_recvfrom(FAKE_SOCKET, buf, sizeof(buf), 0, 4, NULL, 0);
    assert_int_equal(BIO_read(bio, buf, sizeof(buf)), 4);
    assert_false(BIO_should_retry(bio));
}

static void test_dgram_read_sets_peer(void **state)
{
    /* unconnected receive records the source address as the peer */
    BIO *bio = *state;
    bio_dgram_data *data = get_data(bio);
    char buf[16] = { 0 };

    expect_recvfrom(FAKE_SOCKET, buf, sizeof(buf), 0, 4,
        (const struct sockaddr *)&g_sin, 0);
    assert_int_equal(BIO_read(bio, buf, sizeof(buf)), 4);
    assert_int_equal(BIO_ADDR_family(&data->peer), AF_INET);
}

static void test_dgram_read_peek(void **state)
{
    /* peekmode passes MSG_PEEK to recvfrom */
    BIO *bio = *state;
    char buf[16] = { 0 };

    get_data(bio)->peekmode = 1;
    expect_recvfrom(FAKE_SOCKET, buf, sizeof(buf), MSG_PEEK, 4, NULL, 0);
    assert_int_equal(BIO_read(bio, buf, sizeof(buf)), 4);
}

static void test_dgram_read_retry(void **state)
{
    BIO *bio = *state;
    char buf[16] = { 0 };

    expect_recvfrom(FAKE_SOCKET, buf, sizeof(buf), 0, -1, NULL, EAGAIN);
    assert_true(BIO_read(bio, buf, sizeof(buf)) <= 0);
    assert_true(BIO_should_read(bio));
}

static void test_dgram_read_error(void **state)
{
    BIO *bio = *state;
    char buf[16] = { 0 };

    expect_recvfrom(FAKE_SOCKET, buf, sizeof(buf), 0, -1, NULL, ECONNREFUSED);
    assert_true(BIO_read(bio, buf, sizeof(buf)) <= 0);
    assert_false(BIO_should_retry(bio));
}

/* dgram_write */

static void test_dgram_write_unconnected(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    make_peer(bio, 4433);
    expect_sendto(FAKE_SOCKET, buf, 5, 0,
        (socklen_t)sizeof(struct sockaddr_in), 5, 0);
    assert_int_equal(BIO_write(bio, buf, 5), 5);
    assert_false(BIO_should_retry(bio));
}

static void test_dgram_write_connected(void **state)
{
    BIO *bio = *state;
    bio_dgram_data *data = get_data(bio);
    const char buf[] = "hello";

    data->connected = 1;
    expect_write(FAKE_SOCKET, buf, 5, 5);
    assert_int_equal(BIO_write(bio, buf, 5), 5);
    data->connected = 0;
}

static void test_dgram_write_retry(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    make_peer(bio, 4433);
    expect_sendto(FAKE_SOCKET, buf, 5, 0,
        (socklen_t)sizeof(struct sockaddr_in), -1, EAGAIN);
    assert_true(BIO_write(bio, buf, 5) <= 0);
    assert_true(BIO_should_write(bio));
}

static void test_dgram_write_error(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    make_peer(bio, 4433);
    expect_sendto(FAKE_SOCKET, buf, 5, 0,
        (socklen_t)sizeof(struct sockaddr_in), -1, ECONNREFUSED);
    assert_true(BIO_write(bio, buf, 5) <= 0);
    assert_false(BIO_should_retry(bio));
}

/* dgram_ctrl */

static void test_ctrl_reset(void **state)
{
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_RESET, 0, NULL), 0);
}

static void test_ctrl_info(void **state)
{
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_INFO, 0, NULL), 0);
}

static void test_ctrl_pending_wpending(void **state)
{
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_PENDING, 0, NULL), 0);
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_WPENDING, 0, NULL), 0);
}

static void test_ctrl_dup_flush(void **state)
{
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_DUP, 0, NULL), 1);
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_FLUSH, 0, NULL), 1);
}

static void test_ctrl_get_set_close(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_GET_CLOSE, 0, NULL), BIO_NOCLOSE);
    BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, BIO_CLOSE, NULL);
    assert_int_equal(bio->shutdown, BIO_CLOSE);
    bio->shutdown = BIO_NOCLOSE;
}

static void test_ctrl_connect(void **state)
{
    BIO *bio = *state;
    bio_dgram_data *data = get_data(bio);
    struct sockaddr_in sa;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(4433);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    BIO_ctrl(bio, BIO_CTRL_DGRAM_CONNECT, 0, &sa);
    assert_int_equal(BIO_ADDR_family(&data->peer), AF_INET);
    assert_int_equal(data->peer.s_in.sin_port, htons(4433));
}

static void test_ctrl_set_get_peer(void **state)
{
    BIO *bio = *state;
    BIO_ADDR got;

    make_peer(bio, 4433);
    memset(&got, 0, sizeof(got));
    BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_PEER, sizeof(got), &got);
    assert_int_equal(got.s_in.sin_family, AF_INET);
    assert_int_equal(got.s_in.sin_port, htons(4433));
}

static void test_ctrl_set_connected(void **state)
{
    BIO *bio = *state;
    bio_dgram_data *data = get_data(bio);
    struct sockaddr_in sa;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(4433);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &sa);
    assert_int_equal(data->connected, 1);
    assert_int_equal(BIO_ADDR_family(&data->peer), AF_INET);

    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, NULL);
    assert_int_equal(data->connected, 0);
    assert_int_equal(BIO_ADDR_family(&data->peer), AF_UNSPEC);
}

static void test_ctrl_detect_peer_addr_from_data(void **state)
{
    /* peer already known: returned without touching getpeername */
    BIO *bio = *state;
    BIO_ADDR got;

    make_peer(bio, 4433);
    memset(&got, 0, sizeof(got));
    assert_true(
        BIO_ctrl(bio, BIO_CTRL_DGRAM_DETECT_PEER_ADDR, sizeof(got), &got) > 0);
    assert_int_equal(got.s_in.sin_family, AF_INET);
}

static void test_ctrl_detect_peer_addr_via_getpeername(void **state)
{
    /* peer unset: dgram_ctrl falls back to getpeername */
    BIO *bio = *state;
    BIO_ADDR got;

    memset(&got, 0, sizeof(got));
    expect_getpeername(FAKE_SOCKET, 0);
    assert_true(
        BIO_ctrl(bio, BIO_CTRL_DGRAM_DETECT_PEER_ADDR, sizeof(got), &got) > 0);
    assert_int_equal(got.s_in.sin_family, AF_INET);
}

static void test_ctrl_set_get_mtu(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_MTU, 1400, NULL), 1400);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_MTU, 0, NULL), 1400);
}

static void test_ctrl_fallback_mtu_ipv4(void **state)
{
    /* AF_INET peer: 576 payload minus 28 bytes IP+UDP overhead */
    BIO *bio = *state;

    make_peer(bio, 4433);
    assert_int_equal(
        BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0, NULL), 576 - 28);
}

#if OPENSSL_USE_IPV6
static void test_ctrl_fallback_mtu_ipv6(void **state)
{
    /* AF_INET6 non-mapped peer: 1280 minus 48 bytes overhead */
    BIO *bio = *state;

    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &g_sin6);
    assert_int_equal(
        BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0, NULL), 1280 - 48);
}

#ifdef IN6_IS_ADDR_V4MAPPED
static void test_ctrl_fallback_mtu_ipv6_v4mapped(void **state)
{
    /* v4-mapped AF_INET6 peer: treated as IPv4, 576 minus 28 overhead */
    BIO *bio = *state;

    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &g_sin6_v4m);
    assert_int_equal(
        BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0, NULL), 576 - 28);
}
#endif
#endif

#if defined(OPENSSL_SYS_LINUX) && defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
static void test_ctrl_mtu_discover_getsockname_fails(void **state)
{
    /* getsockname fails before any setsockopt: ret 0 */
    BIO *bio = *state;

    expect_getsockname(FAKE_SOCKET, -1);
    assert_int_equal(
        BIO_ctrl(bio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL), 0);
}
#endif

static void test_ctrl_nbio(void **state)
{
    BIO *bio = *state;

    expect_BIO_socket_nbio(FAKE_SOCKET, 1, 1);
    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_NBIO, 1, NULL), 1);
}

static void test_ctrl_set_next_timeout(void **state)
{
    BIO *bio = *state;
    struct timeval tv = { 1, 0 };

    assert_int_equal(
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, 0, &tv), 1);
}

/* dgram_clear / dgram_free */

static void test_free_closes_when_shutdown(void **state)
{
    BIO *bio = BIO_new(BIO_s_datagram());

    (void)state;
    assert_non_null(bio);
    expect_getsockname(FAKE_SOCKET, 0);
    expect_getpeername(FAKE_SOCKET, -1);
    BIO_set_fd(bio, FAKE_SOCKET, BIO_CLOSE);

    expect_BIO_closesocket(FAKE_SOCKET, 0);
    BIO_free(bio);
}

static void test_free_no_close_when_noclose(void **state)
{
    BIO *bio = BIO_new(BIO_s_datagram());

    (void)state;
    assert_non_null(bio);
    expect_getsockname(FAKE_SOCKET, 0);
    expect_getpeername(FAKE_SOCKET, -1);
    BIO_set_fd(bio, FAKE_SOCKET, BIO_NOCLOSE);
    BIO_free(bio);
}

/* main */

#define DG_TEST(name) \
    cmocka_unit_test_setup_teardown(name, setup, teardown)

#define DG_TEST_IO(name) \
    cmocka_unit_test_setup_teardown(name, setup_io, teardown_io)

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* BIO_new_dgram */
        DG_TEST(test_new_dgram),
        DG_TEST(test_dgram_new_defaults),
        /* SET_FD / GET_FD */
        DG_TEST(test_set_fd_unconnected),
        DG_TEST(test_set_fd_connected),
        DG_TEST(test_get_fd_uninit),
        /* dgram_read */
        DG_TEST_IO(test_dgram_read_noop),
        DG_TEST_IO(test_dgram_read_success),
        DG_TEST_IO(test_dgram_read_sets_peer),
        DG_TEST_IO(test_dgram_read_peek),
        DG_TEST_IO(test_dgram_read_retry),
        DG_TEST_IO(test_dgram_read_error),
        /* dgram_write */
        DG_TEST_IO(test_dgram_write_unconnected),
        DG_TEST_IO(test_dgram_write_connected),
        DG_TEST_IO(test_dgram_write_retry),
        DG_TEST_IO(test_dgram_write_error),
        /* dgram_ctrl */
        DG_TEST_IO(test_ctrl_reset),
        DG_TEST_IO(test_ctrl_info),
        DG_TEST_IO(test_ctrl_pending_wpending),
        DG_TEST_IO(test_ctrl_dup_flush),
        DG_TEST_IO(test_ctrl_get_set_close),
        DG_TEST_IO(test_ctrl_connect),
        DG_TEST_IO(test_ctrl_set_get_peer),
        DG_TEST_IO(test_ctrl_set_connected),
        DG_TEST_IO(test_ctrl_detect_peer_addr_from_data),
        DG_TEST_IO(test_ctrl_detect_peer_addr_via_getpeername),
        DG_TEST_IO(test_ctrl_set_get_mtu),
        DG_TEST_IO(test_ctrl_fallback_mtu_ipv4),
#if OPENSSL_USE_IPV6
        DG_TEST_IO(test_ctrl_fallback_mtu_ipv6),
#ifdef IN6_IS_ADDR_V4MAPPED
        DG_TEST_IO(test_ctrl_fallback_mtu_ipv6_v4mapped),
#endif
#endif
#if defined(OPENSSL_SYS_LINUX) && defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
        DG_TEST_IO(test_ctrl_mtu_discover_getsockname_fails),
#endif
        DG_TEST_IO(test_ctrl_nbio),
        DG_TEST_IO(test_ctrl_set_next_timeout),
        /* dgram_clear / dgram_free */
        DG_TEST(test_free_closes_when_shutdown),
        DG_TEST(test_free_no_close_when_noclose),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);

    return cmocka_run_group_tests(tests, group_setup, NULL);
}

#endif /* OPENSSL_NO_SOCK || OPENSSL_NO_DGRAM */
