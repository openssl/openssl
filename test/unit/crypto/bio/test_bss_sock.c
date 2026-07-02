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
#include <netinet/in.h>
#include <cmocka.h>
#include "bio_local.h"
#include "internal/bio_tfo.h"
#include <openssl/bio.h>

#define FAKE_SOCKET 42

/* prototypes for __wrap_* (required by -Wmissing-prototypes) */
ssize_t __wrap_read(int fd, void *buf, size_t count);
ssize_t __wrap_write(int fd, const void *buf, size_t count);
int __wrap_BIO_closesocket(int fd);

/* wraps */

ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    ssize_t rc;

    function_called();
    check_expected(fd);
    check_expected_ptr(buf);
    check_expected(count);
    rc = mock_type(ssize_t);
    if (rc < 0)
        errno = mock_type(int);
    return rc;
}

ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
    ssize_t rc;

    function_called();
    check_expected(fd);
    check_expected_ptr(buf);
    check_expected(count);
    rc = mock_type(ssize_t);
    if (rc < 0)
        errno = mock_type(int);
    return rc;
}

int __wrap_BIO_closesocket(int fd)
{
    function_called();
    check_expected(fd);
    return mock_type(int);
}

/* expectations */

static void expect_read(int fd, const void *buf, size_t count, ssize_t rc,
    int errnoval)
{
    expect_function_call(__wrap_read);
    expect_value(__wrap_read, fd, fd);
    expect_value(__wrap_read, buf, buf);
    expect_value(__wrap_read, count, count);
    will_return(__wrap_read, rc);
    if (rc < 0)
        will_return(__wrap_read, errnoval);
}

static void expect_write(int fd, const void *buf, size_t count, ssize_t rc,
    int errnoval)
{
    expect_function_call(__wrap_write);
    expect_value(__wrap_write, fd, fd);
    expect_value(__wrap_write, buf, buf);
    expect_value(__wrap_write, count, count);
    will_return(__wrap_write, rc);
    if (rc < 0)
        will_return(__wrap_write, errnoval);
}

static void expect_BIO_closesocket(int fd, int rc)
{
    expect_function_call(__wrap_BIO_closesocket);
    expect_value(__wrap_BIO_closesocket, fd, fd);
    will_return(__wrap_BIO_closesocket, rc);
}

/* setup / teardown */

static int setup(void **state)
{
    BIO *bio = BIO_new(BIO_s_socket());

    assert_non_null(bio);
    BIO_set_fd(bio, FAKE_SOCKET, BIO_NOCLOSE);
    *state = bio;
    return 0;
}

static int teardown(void **state)
{
    if (*state != NULL)
        BIO_free(*state);
    return 0;
}

/* sock_new defaults */

static void test_sock_new_defaults(void **state)
{
    /* fresh BIO before BIO_set_fd: init 0, num 0, ptr allocated */
    BIO *bio = BIO_new(BIO_s_socket());

    (void)state;
    assert_non_null(bio);
    assert_int_equal(bio->init, 0);
    assert_int_equal(bio->num, 0);
    assert_non_null(bio->ptr);
    BIO_free(bio);
}

/* BIO_new_socket */

static void test_new_socket(void **state)
{
    int out = -1;
    BIO *bio = BIO_new_socket(FAKE_SOCKET, BIO_NOCLOSE);

    (void)state;
    assert_non_null(bio);
    assert_int_equal(bio->init, 1);
    assert_int_equal(BIO_get_fd(bio, &out), FAKE_SOCKET);
    assert_int_equal(out, FAKE_SOCKET);
    BIO_free(bio);
}

/* sock_read */

static void test_sock_read_noop(void **state)
{
    /* outl == 0: readsocket is never reached */
    BIO *bio = *state;
    char buf[1];

    assert_int_equal(BIO_read(bio, buf, 0), 0);
}

static void test_sock_read_success(void **state)
{
    BIO *bio = *state;
    char buf[16] = { 0 };

    expect_read(FAKE_SOCKET, buf, 16, 4, 0);
    assert_int_equal(BIO_read(bio, buf, sizeof(buf)), 4);
    assert_false(BIO_should_retry(bio));
    assert_false(BIO_eof(bio));
}

static void test_sock_read_eof(void **state)
{
    BIO *bio = *state;
    char buf[16] = { 0 };

    expect_read(FAKE_SOCKET, buf, 16, 0, 0);
    assert_true(BIO_read(bio, buf, sizeof(buf)) <= 0);
    assert_true(BIO_eof(bio));
    assert_false(BIO_should_retry(bio));
}

static void test_sock_read_retry(void **state)
{
    BIO *bio = *state;
    char buf[16] = { 0 };

    expect_read(FAKE_SOCKET, buf, 16, -1, EAGAIN);
    assert_true(BIO_read(bio, buf, sizeof(buf)) <= 0);
    assert_true(BIO_should_read(bio));
    assert_false(BIO_eof(bio));
}

static void test_sock_read_error(void **state)
{
    BIO *bio = *state;
    char buf[16] = { 0 };

    expect_read(FAKE_SOCKET, buf, 16, -1, ECONNREFUSED);
    assert_true(BIO_read(bio, buf, sizeof(buf)) <= 0);
    assert_false(BIO_should_retry(bio));
    assert_false(BIO_eof(bio));
}

static void test_sock_read_clears_eof(void **state)
{
    /* BIO_FLAGS_IN_EOF is cleared at the start of each new read attempt */
    BIO *bio = *state;
    char buf[1] = { 0 };

    expect_read(FAKE_SOCKET, buf, 1, 0, 0);
    BIO_read(bio, buf, 1);
    assert_true(BIO_eof(bio));

    expect_read(FAKE_SOCKET, buf, 1, 1, 0);
    assert_int_equal(BIO_read(bio, buf, 1), 1);
    assert_false(BIO_eof(bio));
}

/* sock_write */

static void test_sock_write_success(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_write(FAKE_SOCKET, buf, 5, 5, 0);
    assert_int_equal(BIO_write(bio, buf, 5), 5);
    assert_false(BIO_should_retry(bio));
}

static void test_sock_write_retry(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_write(FAKE_SOCKET, buf, 5, -1, EAGAIN);
    assert_true(BIO_write(bio, buf, 5) <= 0);
    assert_true(BIO_should_write(bio));
}

static void test_sock_write_error(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_write(FAKE_SOCKET, buf, 5, -1, ECONNREFUSED);
    assert_true(BIO_write(bio, buf, 5) <= 0);
    assert_false(BIO_should_retry(bio));
}

/* sock_ctrl */

static void test_ctrl_get_fd(void **state)
{
    BIO *bio = *state;
    int out = -1;

    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_FD, 0, &out), FAKE_SOCKET);
    assert_int_equal(out, FAKE_SOCKET);
}

static void test_ctrl_get_fd_uninit(void **state)
{
    BIO *bio = *state;

    bio->init = 0;
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_FD, 0, NULL), -1);
    bio->init = 1;
}

static void test_ctrl_set_fd(void **state)
{
    BIO *bio = *state;
    int newfd = 99;

    /* existing shutdown=BIO_NOCLOSE so the old fd is not closed */
    BIO_ctrl(bio, BIO_C_SET_FD, BIO_NOCLOSE, &newfd);
    assert_int_equal(bio->num, 99);
    assert_int_equal(bio->shutdown, BIO_NOCLOSE);
    assert_int_equal(bio->init, 1);
}

static void test_ctrl_get_set_close(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_GET_CLOSE, 0, NULL), BIO_NOCLOSE);
    BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, BIO_CLOSE, NULL);
    assert_int_equal(bio->shutdown, BIO_CLOSE);
    bio->shutdown = BIO_NOCLOSE;
}

static void test_ctrl_dup_flush(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_DUP, 0, NULL), 1);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, NULL), 1);
}

static void test_ctrl_rpoll_descriptor(void **state)
{
    BIO *bio = *state;
    BIO_POLL_DESCRIPTOR pd;

    memset(&pd, 0, sizeof(pd));
    assert_int_equal(
        BIO_ctrl(bio, BIO_CTRL_GET_RPOLL_DESCRIPTOR, 0, &pd), 1);
    assert_int_equal(pd.type, BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD);
    assert_int_equal(pd.value.fd, FAKE_SOCKET);
}

static void test_ctrl_wpoll_descriptor(void **state)
{
    BIO *bio = *state;
    BIO_POLL_DESCRIPTOR pd;

    memset(&pd, 0, sizeof(pd));
    assert_int_equal(
        BIO_ctrl(bio, BIO_CTRL_GET_WPOLL_DESCRIPTOR, 0, &pd), 1);
    assert_int_equal(pd.type, BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD);
    assert_int_equal(pd.value.fd, FAKE_SOCKET);
}

static void test_ctrl_poll_descriptor_uninit(void **state)
{
    BIO *bio = *state;
    BIO_POLL_DESCRIPTOR pd;

    memset(&pd, 0, sizeof(pd));
    bio->init = 0;
    assert_int_equal(
        BIO_ctrl(bio, BIO_CTRL_GET_RPOLL_DESCRIPTOR, 0, &pd), 0);
    bio->init = 1;
}

static void test_ctrl_eof_clear(void **state)
{
    BIO *bio = *state;

    bio->flags &= ~BIO_FLAGS_IN_EOF;
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL), 0);
}

static void test_ctrl_eof_set(void **state)
{
    BIO *bio = *state;

    bio->flags |= BIO_FLAGS_IN_EOF;
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL), 1);
    bio->flags &= ~BIO_FLAGS_IN_EOF;
}

static void test_ctrl_get_connect(void **state)
{
    /* num==2: returns a pointer to the stored tfo_peer */
    BIO *bio = *state;
    const char *ptr = NULL;

    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_CONNECT, 2, &ptr), 1);
    assert_non_null(ptr);
}

static void test_ctrl_get_connect_bad_num(void **state)
{
    BIO *bio = *state;
    const char *ptr = NULL;

    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_CONNECT, 0, &ptr), 0);
}

static void test_ctrl_set_connect(void **state)
{
    BIO *bio = *state;
    struct sockaddr_in sa;
    BIO_ADDR addr;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(4433);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert_true(BIO_ADDR_make(&addr, (const struct sockaddr *)&sa));

    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_CONNECT, 2, &addr), 1);
}

static void test_ctrl_set_connect_bad_num(void **state)
{
    BIO *bio = *state;
    BIO_ADDR addr;

    memset(&addr, 0, sizeof(addr));
    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_CONNECT, 0, &addr), 0);
}

static void test_ctrl_set_send_flags(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_SEND_FLAGS, 0, NULL), 1);
}

static void test_ctrl_default(void **state)
{
    assert_int_equal(BIO_ctrl(*state, 9999, 0, NULL), 0);
}

/* sock_puts */

static void test_sock_puts_success(void **state)
{
    BIO *bio = *state;
    const char *str = "hello";

    expect_write(FAKE_SOCKET, str, 5, 5, 0);
    assert_int_equal(BIO_puts(bio, str), 5);
}

static void test_sock_puts_write_fails(void **state)
{
    BIO *bio = *state;
    const char *str = "hello";

    expect_write(FAKE_SOCKET, str, 5, -1, ECONNREFUSED);
    assert_true(BIO_puts(bio, str) <= 0);
}

/* sock_free (via BIO_free) - mostly just coverage for ASAN */

static void test_free_closes_when_shutdown(void **state)
{
    BIO *bio = BIO_new(BIO_s_socket());

    (void)state;
    assert_non_null(bio);
    BIO_set_fd(bio, FAKE_SOCKET, BIO_CLOSE);

    expect_BIO_closesocket(FAKE_SOCKET, 0);
    BIO_free(bio);
}

static void test_free_no_close_when_noclose(void **state)
{
    BIO *bio = BIO_new(BIO_s_socket());

    (void)state;
    assert_non_null(bio);
    BIO_set_fd(bio, FAKE_SOCKET, BIO_NOCLOSE);
    BIO_free(bio);
}

static void test_free_no_close_when_uninit(void **state)
{
    /* shutdown set but init==0: closesocket must NOT be called */
    BIO *bio = BIO_new(BIO_s_socket());

    (void)state;
    assert_non_null(bio);
    bio->num = FAKE_SOCKET;
    bio->shutdown = BIO_CLOSE;
    bio->init = 0;
    BIO_free(bio);
}

/* main */

#define SOCK_TEST(name) \
    cmocka_unit_test_setup_teardown(name, setup, teardown)

#define SOCK_TEST_PLAIN(name) \
    cmocka_unit_test(name)

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* sock_new / BIO_new_socket */
        SOCK_TEST_PLAIN(test_sock_new_defaults),
        SOCK_TEST_PLAIN(test_new_socket),
        /* sock_read */
        SOCK_TEST(test_sock_read_noop),
        SOCK_TEST(test_sock_read_success),
        SOCK_TEST(test_sock_read_eof),
        SOCK_TEST(test_sock_read_retry),
        SOCK_TEST(test_sock_read_error),
        SOCK_TEST(test_sock_read_clears_eof),
        /* sock_write */
        SOCK_TEST(test_sock_write_success),
        SOCK_TEST(test_sock_write_retry),
        SOCK_TEST(test_sock_write_error),
        /* sock_ctrl */
        SOCK_TEST(test_ctrl_get_fd),
        SOCK_TEST(test_ctrl_get_fd_uninit),
        SOCK_TEST(test_ctrl_set_fd),
        SOCK_TEST(test_ctrl_get_set_close),
        SOCK_TEST(test_ctrl_dup_flush),
        SOCK_TEST(test_ctrl_rpoll_descriptor),
        SOCK_TEST(test_ctrl_wpoll_descriptor),
        SOCK_TEST(test_ctrl_poll_descriptor_uninit),
        SOCK_TEST(test_ctrl_eof_clear),
        SOCK_TEST(test_ctrl_eof_set),
        SOCK_TEST(test_ctrl_get_connect),
        SOCK_TEST(test_ctrl_get_connect_bad_num),
        SOCK_TEST(test_ctrl_set_connect),
        SOCK_TEST(test_ctrl_set_connect_bad_num),
        SOCK_TEST(test_ctrl_set_send_flags),
        SOCK_TEST(test_ctrl_default),
        /* sock_puts */
        SOCK_TEST(test_sock_puts_success),
        SOCK_TEST(test_sock_puts_write_fails),
        /* sock_free */
        SOCK_TEST(test_free_closes_when_shutdown),
        SOCK_TEST(test_free_no_close_when_noclose),
        SOCK_TEST(test_free_no_close_when_uninit),
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
