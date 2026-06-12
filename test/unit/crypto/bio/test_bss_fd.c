/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifdef OPENSSL_NO_POSIX_IO

int main(void)
{
    return 0;
}

#else

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "bio_local.h"

#include <openssl/bio.h>

#define FAKE_FD 42

/* wraps */

ssize_t __wrap_read(int fd, void *buf, size_t count);
ssize_t __wrap_write(int fd, const void *buf, size_t count);
off_t __wrap_lseek(int fd, off_t offset, int whence);
int __wrap_close(int fd);

ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    ssize_t rc;

    function_called();
    check_expected(fd);
    check_expected_ptr(buf);
    check_expected(count);
    rc = mock_type(ssize_t);
    if (rc <= 0)
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
    if (rc <= 0)
        errno = mock_type(int);
    return rc;
}

off_t __wrap_lseek(int fd, off_t offset, int whence)
{
    function_called();
    check_expected(fd);
    check_expected(offset);
    check_expected(whence);

    return mock_type(off_t);
}

int __wrap_close(int fd)
{
    function_called();
    check_expected(fd);

    return mock_type(int);
}

/* expectations */

/*
 * errnoval is consumed by __wrap_read only when rc <= 0; pass 0 for success
 * calls where the value is irrelevant.
 */
static void expect_read(int fd, const void *buf, size_t count, ssize_t rc,
    int errnoval)
{
    expect_function_call(__wrap_read);
    expect_value(__wrap_read, fd, fd);
    expect_value(__wrap_read, buf, buf);
    expect_value(__wrap_read, count, count);
    will_return(__wrap_read, rc);
    if (rc <= 0)
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
    if (rc <= 0)
        will_return(__wrap_write, errnoval);
}

static void expect_lseek(int fd, off_t offset, int whence, off_t rc)
{
    expect_function_call(__wrap_lseek);
    expect_value(__wrap_lseek, fd, fd);
    expect_value(__wrap_lseek, offset, offset);
    expect_value(__wrap_lseek, whence, whence);
    will_return(__wrap_lseek, rc);
}

static void expect_close(int fd, int rc)
{
    expect_function_call(__wrap_close);
    expect_value(__wrap_close, fd, fd);
    will_return(__wrap_close, rc);
}

/* setup / teardown */

static int setup(void **state)
{
    BIO *bio = BIO_new(BIO_s_fd());

    assert_non_null(bio);
    BIO_set_fd(bio, FAKE_FD, BIO_NOCLOSE);
    *state = bio;
    return 0;
}

static int teardown(void **state)
{
    if (*state != NULL)
        BIO_free(*state);
    return 0;
}

/* BIO_fd_non_fatal_error */

static void test_non_fatal_error_retryable(void **state)
{
    static const int errs[] = {
#ifdef EAGAIN
        EAGAIN,
#endif
#ifdef EINTR
        EINTR,
#endif
#if defined(EWOULDBLOCK) && (!defined(EAGAIN) || EWOULDBLOCK != EAGAIN)
        EWOULDBLOCK,
#endif
#ifdef EINPROGRESS
        EINPROGRESS,
#endif
#ifdef EALREADY
        EALREADY,
#endif
#ifdef ENOTCONN
        ENOTCONN,
#endif
#ifdef EPROTO
        EPROTO,
#endif
    };
    size_t i;

    (void)state;
    for (i = 0; i < sizeof(errs) / sizeof(errs[0]); i++)
        assert_int_equal(BIO_fd_non_fatal_error(errs[i]), 1);
}

static void test_non_fatal_error_fatal(void **state)
{
    (void)state;
    assert_int_equal(BIO_fd_non_fatal_error(ENOENT), 0);
    assert_int_equal(BIO_fd_non_fatal_error(EBADF), 0);
    assert_int_equal(BIO_fd_non_fatal_error(0), 0);
}

/* BIO_fd_should_retry */

static void test_should_retry_positive_i(void **state)
{
    /* i > 0: always returns 0 regardless of errno */
    (void)state;
    errno = EAGAIN;
    assert_int_equal(BIO_fd_should_retry(1), 0);
    assert_int_equal(BIO_fd_should_retry(100), 0);
}

static void test_should_retry_fatal_errno(void **state)
{
    (void)state;
    errno = ENOENT;
    assert_int_equal(BIO_fd_should_retry(-1), 0);
    errno = ENOENT;
    assert_int_equal(BIO_fd_should_retry(0), 0);
}

static void test_should_retry_non_fatal_errno(void **state)
{
    (void)state;
    errno = EAGAIN;
    assert_int_equal(BIO_fd_should_retry(-1), 1);
    errno = EINTR;
    assert_int_equal(BIO_fd_should_retry(0), 1);
}

/* fd_read (via BIO_read) */

static void test_fd_read_success(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_FD, buf, 8, 8, 0);
    assert_int_equal(BIO_read(bio, buf, 8), 8);
    assert_false(BIO_should_retry(bio));
    assert_false(BIO_eof(bio));
}

static void test_fd_read_eof(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_FD, buf, 8, 0, 0);
    assert_true(BIO_read(bio, buf, 8) <= 0);
    assert_true(BIO_eof(bio));
    assert_false(BIO_should_retry(bio));
}

static void test_fd_read_retry(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_FD, buf, 8, -1, EAGAIN);
    assert_true(BIO_read(bio, buf, 8) <= 0);
    assert_true(BIO_should_retry(bio));
    assert_true(BIO_should_read(bio));
    assert_false(BIO_eof(bio));
}

static void test_fd_read_error(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_FD, buf, 8, -1, ENOENT);
    assert_true(BIO_read(bio, buf, 8) <= 0);
    assert_false(BIO_should_retry(bio));
    assert_false(BIO_eof(bio));
}

static void test_fd_read_clears_eof(void **state)
{
    /* BIO_FLAGS_IN_EOF is cleared at the start of each new read attempt. */
    BIO *bio = *state;
    char buf[1] = { 0 };

    expect_read(FAKE_FD, buf, 1, 0, 0);
    BIO_read(bio, buf, 1);
    assert_true(BIO_eof(bio));

    expect_read(FAKE_FD, buf, 1, 1, 0);
    assert_int_equal(BIO_read(bio, buf, 1), 1);
    assert_false(BIO_eof(bio));
}

/* fd_write (via BIO_write) */

static void test_fd_write_success(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_write(FAKE_FD, buf, 5, 5, 0);
    assert_int_equal(BIO_write(bio, buf, 5), 5);
    assert_false(BIO_should_retry(bio));
}

static void test_fd_write_retry(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_write(FAKE_FD, buf, 5, -1, EAGAIN);
    assert_true(BIO_write(bio, buf, 5) <= 0);
    assert_true(BIO_should_retry(bio));
    assert_true(BIO_should_write(bio));
}

static void test_fd_write_error(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_write(FAKE_FD, buf, 5, -1, ENOSPC);
    assert_true(BIO_write(bio, buf, 5) <= 0);
    assert_false(BIO_should_retry(bio));
}

/* fd_ctrl (via BIO_ctrl) */

static void test_fd_ctrl_reset(void **state)
{
    BIO *bio = *state;

    /* RESET sets num=0 then falls through to FILE_SEEK: lseek(fd, 0, 0) */
    expect_lseek(FAKE_FD, 0, 0, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_RESET, 0, NULL), 0);
}

static void test_fd_ctrl_seek(void **state)
{
    BIO *bio = *state;

    expect_lseek(FAKE_FD, 512, 0, 512);
    assert_int_equal(BIO_ctrl(bio, BIO_C_FILE_SEEK, 512, NULL), 512);
}

static void test_fd_ctrl_tell(void **state)
{
    BIO *bio = *state;

    expect_lseek(FAKE_FD, 0, 1, 256);
    assert_int_equal(BIO_ctrl(bio, BIO_C_FILE_TELL, 0, NULL), 256);
}

static void test_fd_ctrl_info(void **state)
{
    BIO *bio = *state;

    /* BIO_CTRL_INFO shares the lseek(fd, 0, 1) branch with FILE_TELL */
    expect_lseek(FAKE_FD, 0, 1, 128);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), 128);
}

static void test_fd_ctrl_set_fd(void **state)
{
    BIO *bio = *state;
    int newfd = 99;

    /* fd_free is called first; existing shutdown=BIO_NOCLOSE so no close */
    BIO_ctrl(bio, BIO_C_SET_FD, BIO_NOCLOSE, &newfd);
    assert_int_equal(bio->num, 99);
    assert_int_equal(bio->shutdown, BIO_NOCLOSE);
    assert_int_equal(bio->init, 1);
}

static void test_fd_ctrl_get_fd_init(void **state)
{
    BIO *bio = *state;
    int out = -1;

    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_FD, 0, &out), FAKE_FD);
    assert_int_equal(out, FAKE_FD);
}

static void test_fd_ctrl_get_fd_uninit(void **state)
{
    BIO *bio = *state;

    /* teardown is safe: shutdown=BIO_NOCLOSE guards the close call */
    bio->init = 0;
    assert_int_equal(BIO_ctrl(bio, BIO_C_GET_FD, 0, NULL), -1);
}

static void test_fd_ctrl_get_close(void **state)
{
    BIO *bio = *state;

    bio->shutdown = BIO_NOCLOSE;
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_GET_CLOSE, 0, NULL), BIO_NOCLOSE);
    bio->shutdown = BIO_CLOSE;
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_GET_CLOSE, 0, NULL), BIO_CLOSE);
    bio->shutdown = BIO_NOCLOSE;
}

static void test_fd_ctrl_set_close(void **state)
{
    BIO *bio = *state;

    BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, BIO_CLOSE, NULL);
    assert_int_equal(bio->shutdown, BIO_CLOSE);
    /* Restore before teardown to avoid an unexpected close call. */
    BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, BIO_NOCLOSE, NULL);
}

static void test_fd_ctrl_pending(void **state)
{
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_PENDING, 0, NULL), 0);
}

static void test_fd_ctrl_wpending(void **state)
{
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_WPENDING, 0, NULL), 0);
}

static void test_fd_ctrl_dup(void **state)
{
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_DUP, 0, NULL), 1);
}

static void test_fd_ctrl_flush(void **state)
{
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_FLUSH, 0, NULL), 1);
}

static void test_fd_ctrl_eof_clear(void **state)
{
    BIO *bio = *state;

    bio->flags &= ~BIO_FLAGS_IN_EOF;
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL), 0);
}

static void test_fd_ctrl_eof_set(void **state)
{
    BIO *bio = *state;

    bio->flags |= BIO_FLAGS_IN_EOF;
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL), 1);
    bio->flags &= ~BIO_FLAGS_IN_EOF;
}

static void test_fd_ctrl_default(void **state)
{
    assert_int_equal(BIO_ctrl(*state, 9999, 0, NULL), 0);
}

/* fd_free (via BIO_free) */

static void test_fd_free_shutdown_with_init(void **state)
{
    /* shutdown=1 and init=1: close must be called */
    BIO *bio = BIO_new(BIO_s_fd());

    assert_non_null(bio);
    bio->num = FAKE_FD;
    bio->shutdown = BIO_CLOSE;
    bio->init = 1;

    expect_close(FAKE_FD, 0);
    BIO_free(bio);
    *state = NULL;
}

static void test_fd_free_shutdown_no_init(void **state)
{
    /* shutdown=1 but init=0: close must NOT be called */
    BIO *bio = BIO_new(BIO_s_fd());

    assert_non_null(bio);
    bio->num = FAKE_FD;
    bio->shutdown = BIO_CLOSE;
    bio->init = 0;

    BIO_free(bio);
    *state = NULL;
}

static void test_fd_free_no_shutdown(void **state)
{
    /* shutdown=0: close must NOT be called regardless of init */
    BIO *bio = BIO_new(BIO_s_fd());

    assert_non_null(bio);
    bio->num = FAKE_FD;
    bio->shutdown = BIO_NOCLOSE;
    bio->init = 1;

    BIO_free(bio);
    *state = NULL;
}

/* fd_puts (via BIO_puts) */

static void test_fd_puts_success(void **state)
{
    BIO *bio = *state;
    const char *str = "hello";

    expect_write(FAKE_FD, str, 5, 5, 0);
    assert_int_equal(BIO_puts(bio, str), 5);
}

static void test_fd_puts_write_fails(void **state)
{
    BIO *bio = *state;
    const char *str = "hello";

    expect_write(FAKE_FD, str, 5, -1, ENOSPC);
    assert_true(BIO_puts(bio, str) <= 0);
}

/*
 * fd_gets (via BIO_gets)
 *
 * fd_gets calls fd_read one byte at a time, which in turn calls read.
 * The buffer is pre-filled with the data that each mocked read delivers,
 * since __wrap_read returns the count without writing into the buffer.
 */

static void test_fd_gets_size_one(void **state)
{
    /* end == buf when size=1, so the loop body never executes */
    BIO *bio = *state;
    char buf[4] = { 0 };

    assert_int_equal(BIO_gets(bio, buf, 1), 0);
    assert_int_equal(buf[0], '\0');
}

static void test_fd_gets_newline_terminates(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 'h', 'i', '\n' };

    expect_read(FAKE_FD, buf, 1, 1, 0);
    expect_read(FAKE_FD, buf + 1, 1, 1, 0);
    expect_read(FAKE_FD, buf + 2, 1, 1, 0);

    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), 3);
    assert_memory_equal(buf, "hi\n", 4);
}

static void test_fd_gets_fills_to_limit(void **state)
{
    /* size=4: reads at most 3 chars (buf+3 is the null slot) */
    BIO *bio = *state;
    char buf[4] = { 'a', 'b', 'c' };

    expect_read(FAKE_FD, buf, 1, 1, 0);
    expect_read(FAKE_FD, buf + 1, 1, 1, 0);
    expect_read(FAKE_FD, buf + 2, 1, 1, 0);

    assert_int_equal(BIO_gets(bio, buf, 4), 3);
    assert_memory_equal(buf, "abc", 4);
}

static void test_fd_gets_eof_mid_line(void **state)
{
    /* read returns 0 after the first byte: return what was read */
    BIO *bio = *state;
    char buf[8] = { 'z' };

    expect_read(FAKE_FD, buf, 1, 1, 0);
    expect_read(FAKE_FD, buf + 1, 1, 0, 0);

    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), 1);
    assert_memory_equal(buf, "z", 2);
}

static void test_fd_gets_immediate_eof(void **state)
{
    /* First read returns 0: returns 0 and buf[0] is '\0' */
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_read(FAKE_FD, buf, 1, 0, 0);

    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), 0);
    assert_int_equal(buf[0], '\0');
}

/* main */

#define FD_TEST(name) \
    cmocka_unit_test_setup_teardown(name, setup, teardown)

#define FD_TEST_PLAIN(name) \
    cmocka_unit_test(name)

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* BIO_fd_non_fatal_error */
        FD_TEST_PLAIN(test_non_fatal_error_retryable),
        FD_TEST_PLAIN(test_non_fatal_error_fatal),
        /* BIO_fd_should_retry */
        FD_TEST_PLAIN(test_should_retry_positive_i),
        FD_TEST_PLAIN(test_should_retry_fatal_errno),
        FD_TEST_PLAIN(test_should_retry_non_fatal_errno),
        /* fd_read */
        FD_TEST(test_fd_read_success),
        FD_TEST(test_fd_read_eof),
        FD_TEST(test_fd_read_retry),
        FD_TEST(test_fd_read_error),
        FD_TEST(test_fd_read_clears_eof),
        /* fd_write */
        FD_TEST(test_fd_write_success),
        FD_TEST(test_fd_write_retry),
        FD_TEST(test_fd_write_error),
        /* fd_ctrl */
        FD_TEST(test_fd_ctrl_reset),
        FD_TEST(test_fd_ctrl_seek),
        FD_TEST(test_fd_ctrl_tell),
        FD_TEST(test_fd_ctrl_info),
        FD_TEST(test_fd_ctrl_set_fd),
        FD_TEST(test_fd_ctrl_get_fd_init),
        FD_TEST(test_fd_ctrl_get_fd_uninit),
        FD_TEST(test_fd_ctrl_get_close),
        FD_TEST(test_fd_ctrl_set_close),
        FD_TEST(test_fd_ctrl_pending),
        FD_TEST(test_fd_ctrl_wpending),
        FD_TEST(test_fd_ctrl_dup),
        FD_TEST(test_fd_ctrl_flush),
        FD_TEST(test_fd_ctrl_eof_clear),
        FD_TEST(test_fd_ctrl_eof_set),
        FD_TEST(test_fd_ctrl_default),
        /* fd_free */
        FD_TEST(test_fd_free_shutdown_with_init),
        FD_TEST(test_fd_free_shutdown_no_init),
        FD_TEST(test_fd_free_no_shutdown),
        /* fd_puts */
        FD_TEST(test_fd_puts_success),
        FD_TEST(test_fd_puts_write_fails),
        /* fd_gets */
        FD_TEST(test_fd_gets_size_one),
        FD_TEST(test_fd_gets_newline_terminates),
        FD_TEST(test_fd_gets_fills_to_limit),
        FD_TEST(test_fd_gets_eof_mid_line),
        FD_TEST(test_fd_gets_immediate_eof),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif /* OPENSSL_NO_POSIX_IO */
