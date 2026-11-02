/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/sockets.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <limits.h>
#include <cmocka.h>
#ifndef OPENSSL_NO_SOCK
#include <netinet/in.h>
#endif
#include "bio_local.h"
#include <openssl/bio.h>

#define BUF_DEFAULT 4096

/* prototypes for the wraps and reals (required by -Wmissing-prototypes) */
#ifndef OPENSSL_NO_SOCK
BIO_ADDR *__wrap_BIO_ADDR_new(void);
BIO_ADDR *__real_BIO_ADDR_new(void);
int __wrap_BIO_ADDR_copy(BIO_ADDR *dst, const BIO_ADDR *src);
int __real_BIO_ADDR_copy(BIO_ADDR *dst, const BIO_ADDR *src);
#endif

/* wraps */

#ifndef OPENSSL_NO_SOCK

BIO_ADDR *__wrap_BIO_ADDR_new(void)
{
    function_called();
    return mock_type(int) ? __real_BIO_ADDR_new() : NULL;
}

int __wrap_BIO_ADDR_copy(BIO_ADDR *dst, const BIO_ADDR *src)
{
    function_called();
    check_expected_ptr(src);
    return mock_type(int) ? __real_BIO_ADDR_copy(dst, src) : 0;
}

#endif

/* expectations */

#ifndef OPENSSL_NO_SOCK

static void expect_BIO_ADDR_new(int ok)
{
    expect_function_call(__wrap_BIO_ADDR_new);
    will_return(__wrap_BIO_ADDR_new, ok);
}

static void expect_BIO_ADDR_copy(const BIO_ADDR *src, int rc)
{
    expect_function_call(__wrap_BIO_ADDR_copy);
    expect_value(__wrap_BIO_ADDR_copy, src, src);
    will_return(__wrap_BIO_ADDR_copy, rc);
}

#endif

/* fake next BIO whose callbacks are cmocka mocks */

static int fake_next_eof;

static int fake_next_write(BIO *b, const char *data, size_t datal,
    size_t *written)
{
    int rc;

    function_called();
    check_expected(datal);
    check_expected(data);
    BIO_clear_retry_flags(b);
    rc = mock_type(int);
    if (rc < 0 && mock_type(int))
        BIO_set_retry_write(b);
    if (rc <= 0) {
        *written = 0;
        return rc;
    }
    *written = (size_t)rc;
    return 1;
}

static int fake_next_read(BIO *b, char *data, size_t datal, size_t *readbytes)
{
    int rc;

    function_called();
    check_expected(datal);
    BIO_clear_retry_flags(b);
    *readbytes = 0;
    rc = mock_type(int);
    if (rc > 0) {
        memcpy(data, mock_ptr_type(const char *), (size_t)rc);
        *readbytes = (size_t)rc;
        return 1;
    }
    if (rc < 0 && mock_type(int))
        BIO_set_retry_read(b);
    return rc;
}

static long fake_next_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    (void)b;
    (void)num;
    (void)ptr;
    /* keep BIO_push()/BIO_pop() housekeeping out of the mock queues */
    if (cmd == BIO_CTRL_PUSH || cmd == BIO_CTRL_POP)
        return 0;
    if (cmd == BIO_CTRL_EOF)
        return fake_next_eof;
    function_called();
    check_expected(cmd);
    return mock_type(long);
}

static long fake_next_cb_ctrl(BIO *b, int cmd, BIO_info_cb *fp)
{
    (void)b;
    function_called();
    check_expected(cmd);
    check_expected_ptr(fp);
    return mock_type(long);
}

#ifndef OPENSSL_NO_SOCK
static int fake_next_sendmmsg(BIO *b, BIO_MSG *msg, size_t stride,
    size_t num_msg, uint64_t flags, size_t *msgs_processed)
{
    const void *data = msg->data;
    size_t data_len = msg->data_len;
    int peer_family = msg->peer != NULL ? BIO_ADDR_family(msg->peer) : -1;

    (void)b;
    (void)stride;
    (void)flags;
    function_called();
    check_expected(num_msg);
    check_expected(data_len);
    check_expected(data);
    check_expected(peer_family);
    *msgs_processed = mock_type(size_t);
    return mock_type(int);
}
#endif

static void expect_next_write(const void *content, size_t len, int rc,
    int retry)
{
    expect_function_call(fake_next_write);
    expect_value(fake_next_write, datal, len);
    if (content != NULL)
        expect_memory(fake_next_write, data, content, len);
    else
        expect_any(fake_next_write, data);
    will_return(fake_next_write, rc);
    if (rc < 0)
        will_return(fake_next_write, retry);
}

static void expect_next_read(size_t len, const void *payload, int rc,
    int retry)
{
    expect_function_call(fake_next_read);
    expect_value(fake_next_read, datal, len);
    will_return(fake_next_read, rc);
    if (rc > 0)
        will_return(fake_next_read, payload);
    if (rc < 0)
        will_return(fake_next_read, retry);
}

static void expect_next_ctrl(int cmd, long rc)
{
    expect_function_call(fake_next_ctrl);
    expect_value(fake_next_ctrl, cmd, cmd);
    will_return(fake_next_ctrl, rc);
}

static void expect_next_cb_ctrl(int cmd, BIO_info_cb *fp, long rc)
{
    expect_function_call(fake_next_cb_ctrl);
    expect_value(fake_next_cb_ctrl, cmd, cmd);
    expect_value(fake_next_cb_ctrl, fp, fp);
    will_return(fake_next_cb_ctrl, rc);
}

#ifndef OPENSSL_NO_SOCK
static void expect_next_sendmmsg(const void *content, size_t len, int family,
    size_t processed, int rc)
{
    expect_function_call(fake_next_sendmmsg);
    expect_value(fake_next_sendmmsg, num_msg, 1);
    expect_value(fake_next_sendmmsg, data_len, len);
    expect_memory(fake_next_sendmmsg, data, content, len);
    expect_value(fake_next_sendmmsg, peer_family, family);
    will_return(fake_next_sendmmsg, processed);
    will_return(fake_next_sendmmsg, rc);
}
#endif

/* helpers */

static BIO_METHOD *fake_meth;
static unsigned char pattern[16384];

static BIO_F_BUFFER_CTX *get_ctx(BIO *b)
{
    return (BIO_F_BUFFER_CTX *)b->ptr;
}

static int dummy_info_cb(BIO *b, int state, int res)
{
    (void)b;
    (void)state;
    (void)res;
    return 1;
}

#ifndef OPENSSL_NO_SOCK
static void make_peer(BIO_ADDR *addr)
{
    struct sockaddr_in sa;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(4433);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert_true(BIO_ADDR_make(addr, (const struct sockaddr *)&sa));
}
#endif

/* setup / teardown */

static int group_setup(void **state)
{
    size_t i;

    (void)state;
    for (i = 0; i < sizeof(pattern); i++)
        pattern[i] = (unsigned char)('A' + i % 26);

    fake_meth = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "fake next");
    assert_non_null(fake_meth);
    assert_true(BIO_meth_set_write_ex(fake_meth, fake_next_write));
    assert_true(BIO_meth_set_read_ex(fake_meth, fake_next_read));
    assert_true(BIO_meth_set_ctrl(fake_meth, fake_next_ctrl));
    assert_true(BIO_meth_set_callback_ctrl(fake_meth, fake_next_cb_ctrl));
#ifndef OPENSSL_NO_SOCK
    assert_true(BIO_meth_set_sendmmsg(fake_meth, fake_next_sendmmsg));
#endif
    return 0;
}

static int group_teardown(void **state)
{
    (void)state;
    BIO_meth_free(fake_meth);
    fake_meth = NULL;
    return 0;
}

static int setup(void **state)
{
    BIO *next = BIO_new(fake_meth);
    BIO *bio = BIO_new(BIO_f_buffer());

    assert_non_null(next);
    assert_non_null(bio);
    BIO_set_init(next, 1);
    fake_next_eof = 0;
    assert_ptr_equal(BIO_push(bio, next), bio);
    *state = bio;
    return 0;
}

static int setup_nonext(void **state)
{
    BIO *bio = BIO_new(BIO_f_buffer());

    assert_non_null(bio);
    fake_next_eof = 0;
    *state = bio;
    return 0;
}

static int teardown(void **state)
{
    if (*state != NULL)
        BIO_free_all(*state);
    return 0;
}

/* buffer_new */

static void test_new_defaults(void **state)
{
    BIO *bio = BIO_new(BIO_f_buffer());
    BIO_F_BUFFER_CTX *ctx;

    (void)state;
    assert_non_null(bio);
    assert_int_equal(bio->init, 1);
    ctx = get_ctx(bio);
    assert_int_equal(ctx->ibuf_size, BUF_DEFAULT);
    assert_int_equal(ctx->obuf_size, BUF_DEFAULT);
    assert_int_equal(ctx->ibuf_len, 0);
    assert_int_equal(ctx->obuf_len, 0);
    BIO_free(bio);
}

/* buffer_write */

static void test_write_small_buffered(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_write(bio, "hello", 5), 5);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), 5);
    assert_memory_equal(get_ctx(bio)->obuf, "hello", 5);
}

static void test_write_null_data(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_write(bio, NULL, 5), 0);
    assert_int_equal(BIO_write(bio, "x", 0), 0);
}

static void test_write_fill_and_flush(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_write(bio, pattern, 4090), 4090);
    /* 6 bytes top up the buffer, the full 4096 are flushed, 94 rebuffered */
    expect_next_write(pattern, BUF_DEFAULT, BUF_DEFAULT, 0);
    assert_int_equal(BIO_write(bio, pattern + 4090, 100), 100);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), 94);
}

static void test_write_flush_needs_two_writes(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_write(bio, pattern, BUF_DEFAULT), BUF_DEFAULT);
    expect_next_write(pattern, BUF_DEFAULT, 1000, 0);
    expect_next_write(pattern + 1000, 3096, 3096, 0);
    assert_int_equal(BIO_write(bio, pattern + BUF_DEFAULT, 10), 10);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), 10);
}

static void test_write_flush_retry(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_write(bio, pattern, BUF_DEFAULT), BUF_DEFAULT);
    expect_next_write(pattern, BUF_DEFAULT, -1, 1);
    assert_int_equal(BIO_write(bio, pattern + BUF_DEFAULT, 10), -1);
    assert_true(BIO_should_write(bio));
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), BUF_DEFAULT);
}

static void test_write_flush_retry_after_topup(void **state)
{
    BIO *bio = *state;

    /* 6 bytes are consumed into the buffer before the flush fails */
    assert_int_equal(BIO_write(bio, pattern, 4090), 4090);
    expect_next_write(pattern, BUF_DEFAULT, -1, 1);
    assert_int_equal(BIO_write(bio, pattern + 4090, 100), 6);
    assert_true(BIO_should_write(bio));
}

static void test_write_flush_error(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_write(bio, pattern, BUF_DEFAULT), BUF_DEFAULT);
    expect_next_write(pattern, BUF_DEFAULT, -1, 0);
    assert_int_equal(BIO_write(bio, pattern + BUF_DEFAULT, 10), -1);
    assert_false(BIO_should_retry(bio));
}

static void test_write_flush_zero(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_write(bio, pattern, BUF_DEFAULT), BUF_DEFAULT);
    expect_next_write(pattern, BUF_DEFAULT, 0, 0);
    assert_int_equal(BIO_write(bio, pattern + BUF_DEFAULT, 10), 0);
}

static void test_write_large_direct(void **state)
{
    BIO *bio = *state;

    /* 9000 bytes: one direct write of 5000, the 4000 left over rebuffered */
    expect_next_write(pattern, 9000, 5000, 0);
    assert_int_equal(BIO_write(bio, pattern, 9000), 9000);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), 4000);
    assert_memory_equal(get_ctx(bio)->obuf, pattern + 5000, 4000);
}

static void test_write_large_direct_error(void **state)
{
    BIO *bio = *state;

    expect_next_write(pattern, 10000, 5000, 0);
    expect_next_write(pattern + 5000, 5000, -1, 0);
    assert_int_equal(BIO_write(bio, pattern, 10000), 5000);
}

static void test_write_large_direct_zero(void **state)
{
    BIO *bio = *state;

    expect_next_write(pattern, 10000, 5000, 0);
    expect_next_write(pattern + 5000, 5000, 0, 0);
    assert_int_equal(BIO_write(bio, pattern, 10000), 5000);
}

static void test_write_large_exact_multiple(void **state)
{
    BIO *bio = *state;

    /* an exact multiple of the buffer size goes out without rebuffering */
    expect_next_write(pattern, 8192, 8192, 0);
    assert_int_equal(BIO_write(bio, pattern, 8192), 8192);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), 0);
}

/* buffer_read */

static void test_read_from_preset_data(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    assert_true(BIO_set_buffer_read_data(bio, "hello", 5));
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL), 5);
    assert_int_equal(BIO_read(bio, buf, 5), 5);
    assert_memory_equal(buf, "hello", 5);
}

static void test_read_refill_buffered(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_next_read(BUF_DEFAULT, "abcdefgh", 8, 0);
    assert_int_equal(BIO_read(bio, buf, 3), 3);
    assert_memory_equal(buf, "abc", 3);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL), 5);
    assert_int_equal(BIO_read(bio, buf, 5), 5);
    assert_memory_equal(buf, "defgh", 5);
}

static void test_read_partial_then_refill(void **state)
{
    BIO *bio = *state;
    char buf[16] = { 0 };

    assert_true(BIO_set_buffer_read_data(bio, "wxyz", 4));
    expect_next_read(BUF_DEFAULT, "123456", 6, 0);
    assert_int_equal(BIO_read(bio, buf, 10), 10);
    assert_memory_equal(buf, "wxyz123456", 10);
}

static void test_read_large_direct(void **state)
{
    BIO *bio = *state;
    static char buf[5000];

    expect_next_read(5000, pattern, 2000, 0);
    expect_next_read(3000, pattern + 2000, 3000, 0);
    assert_int_equal(BIO_read(bio, buf, 5000), 5000);
    assert_memory_equal(buf, pattern, 5000);
}

static void test_read_large_direct_partial_error(void **state)
{
    BIO *bio = *state;
    static char buf[5000];

    expect_next_read(5000, pattern, 2000, 0);
    expect_next_read(3000, NULL, -1, 1);
    assert_int_equal(BIO_read(bio, buf, 5000), 2000);
    assert_true(BIO_should_read(bio));
}

static void test_read_large_direct_eof(void **state)
{
    BIO *bio = *state;
    static char buf[5000];

    fake_next_eof = 1;
    expect_next_read(5000, pattern, 2000, 0);
    expect_next_read(3000, NULL, 0, 0);
    assert_int_equal(BIO_read(bio, buf, 5000), 2000);
}

static void test_read_null_buffer(void **state)
{
    BIO *bio = *state;

    assert_true(BIO_read(bio, NULL, 5) <= 0);
}

static void test_read_retry(void **state)
{
    BIO *bio = *state;
    char buf[8];

    expect_next_read(BUF_DEFAULT, NULL, -1, 1);
    assert_int_equal(BIO_read(bio, buf, 8), -1);
    assert_true(BIO_should_read(bio));
}

static void test_read_error(void **state)
{
    BIO *bio = *state;
    char buf[8];

    expect_next_read(BUF_DEFAULT, NULL, -1, 0);
    assert_int_equal(BIO_read(bio, buf, 8), -1);
    assert_false(BIO_should_retry(bio));
}

static void test_read_eof(void **state)
{
    BIO *bio = *state;
    char buf[8];

    fake_next_eof = 1;
    expect_next_read(BUF_DEFAULT, NULL, 0, 0);
    assert_int_equal(BIO_read(bio, buf, 8), 0);
    assert_true(BIO_eof(bio));
}

/* buffer_gets */

static void test_gets_line(void **state)
{
    BIO *bio = *state;
    char buf[16];

    assert_true(BIO_set_buffer_read_data(bio, "line1\nline2\n", 12));
    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), 6);
    assert_string_equal(buf, "line1\n");
    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), 6);
    assert_string_equal(buf, "line2\n");
}

static void test_gets_refill(void **state)
{
    BIO *bio = *state;
    char buf[16];

    assert_true(BIO_set_buffer_read_data(bio, "par", 3));
    expect_next_read(BUF_DEFAULT, "tial\n", 5, 0);
    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), 8);
    assert_string_equal(buf, "partial\n");
}

static void test_gets_truncated(void **state)
{
    BIO *bio = *state;
    char buf[4];

    assert_true(BIO_set_buffer_read_data(bio, "abcdef\n", 7));
    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), 3);
    assert_string_equal(buf, "abc");
}

static void test_gets_eof(void **state)
{
    BIO *bio = *state;
    char buf[16];

    assert_true(BIO_set_buffer_read_data(bio, "xy", 2));
    fake_next_eof = 1;
    expect_next_read(BUF_DEFAULT, NULL, 0, 0);
    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), 2);
    assert_string_equal(buf, "xy");
}

static void test_gets_error(void **state)
{
    BIO *bio = *state;
    char buf[16];

    expect_next_read(BUF_DEFAULT, NULL, -1, 1);
    assert_int_equal(BIO_gets(bio, buf, sizeof(buf)), -1);
    assert_string_equal(buf, "");
    assert_true(BIO_should_read(bio));
}

/* buffer_puts */

static void test_puts_buffered(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_puts(bio, "hello\n"), 6);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), 6);
}

/* buffer_ctrl */

static void test_ctrl_reset(void **state)
{
    BIO *bio = *state;
    BIO_F_BUFFER_CTX *ctx = get_ctx(bio);

    assert_int_equal(BIO_write(bio, "hello", 5), 5);
    assert_true(BIO_set_buffer_read_data(bio, "world", 5));
    expect_next_ctrl(BIO_CTRL_RESET, 1);
    assert_int_equal(BIO_reset(bio), 1);
    assert_int_equal(ctx->obuf_len, 0);
    assert_int_equal(ctx->ibuf_len, 0);
}

static void test_ctrl_eof_with_pending(void **state)
{
    BIO *bio = *state;

    assert_true(BIO_set_buffer_read_data(bio, "x", 1));
    fake_next_eof = 1;
    assert_int_equal(BIO_eof(bio), 0);
}

static void test_ctrl_eof_forwarded(void **state)
{
    BIO *bio = *state;

    fake_next_eof = 1;
    assert_int_equal(BIO_eof(bio), 1);
}

static void test_ctrl_num_lines(void **state)
{
    BIO *bio = *state;

    assert_true(BIO_set_buffer_read_data(bio, "a\nb\nc", 5));
    assert_int_equal(BIO_get_buffer_num_lines(bio), 2);
}

static void test_ctrl_wpending(void **state)
{
    BIO *bio = *state;

    expect_next_ctrl(BIO_CTRL_WPENDING, 42);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_WPENDING, 0, NULL), 42);
    assert_int_equal(BIO_write(bio, "hello", 5), 5);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_WPENDING, 0, NULL), 5);
}

static void test_ctrl_pending(void **state)
{
    BIO *bio = *state;

    expect_next_ctrl(BIO_CTRL_PENDING, 7);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL), 7);
    assert_true(BIO_set_buffer_read_data(bio, "abc", 3));
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL), 3);
}

static void test_ctrl_set_read_data_large(void **state)
{
    BIO *bio = *state;
    static char buf[10000];

    /* larger than ibuf_size: a bigger buffer is allocated */
    assert_true(BIO_set_buffer_read_data(bio, pattern, 10000));
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL), 10000);
    assert_int_equal(BIO_read(bio, buf, 10000), 10000);
    assert_memory_equal(buf, pattern, 10000);
}

static void test_ctrl_set_buffer_size(void **state)
{
    BIO *bio = *state;
    BIO_F_BUFFER_CTX *ctx = get_ctx(bio);

    assert_int_equal(BIO_set_buffer_size(bio, 8192), 1);
    assert_int_equal(ctx->ibuf_size, 8192);
    assert_int_equal(ctx->obuf_size, 8192);
}

static void test_ctrl_set_rw_buffer_sizes(void **state)
{
    BIO *bio = *state;
    BIO_F_BUFFER_CTX *ctx = get_ctx(bio);

    assert_int_equal(BIO_set_read_buffer_size(bio, 6000), 1);
    assert_int_equal(ctx->ibuf_size, 6000);
    assert_int_equal(ctx->obuf_size, BUF_DEFAULT);
    assert_int_equal(BIO_set_write_buffer_size(bio, 7000), 1);
    assert_int_equal(ctx->obuf_size, 7000);
}

static void test_ctrl_do_state_machine(void **state)
{
    BIO *bio = *state;

    expect_next_ctrl(BIO_C_DO_STATE_MACHINE, 1);
    assert_int_equal(BIO_do_handshake(bio), 1);
}

static void test_ctrl_flush_empty(void **state)
{
    BIO *bio = *state;

    expect_next_ctrl(BIO_CTRL_FLUSH, 1);
    assert_int_equal(BIO_flush(bio), 1);
}

static void test_ctrl_flush_data(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_write(bio, "hello", 5), 5);
    expect_next_write("hello", 5, 5, 0);
    expect_next_ctrl(BIO_CTRL_FLUSH, 1);
    assert_int_equal(BIO_flush(bio), 1);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), 0);
}

static void test_ctrl_flush_partial_writes(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_write(bio, pattern, 10), 10);
    expect_next_write(pattern, 10, 4, 0);
    expect_next_write(pattern + 4, 6, 6, 0);
    expect_next_ctrl(BIO_CTRL_FLUSH, 1);
    assert_int_equal(BIO_flush(bio), 1);
}

static void test_ctrl_flush_retry(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_write(bio, "hello", 5), 5);
    expect_next_write("hello", 5, -1, 1);
    assert_true(BIO_flush(bio) <= 0);
    assert_true(BIO_should_write(bio));
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), 5);
}

static void test_ctrl_dup(void **state)
{
    BIO *bio = *state;
    BIO *dbio = BIO_new(BIO_f_buffer());

    assert_non_null(dbio);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_DUP, 0, dbio), 1);
    BIO_free(dbio);
}

static void test_ctrl_dup_fails(void **state)
{
    BIO *bio = *state;
    BIO *dbio = BIO_new(BIO_s_null());

    /* a null BIO rejects the buffer-size ctrls the duplication forwards */
    assert_non_null(dbio);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_DUP, 0, dbio), 0);
    BIO_free(dbio);
}

static void test_ctrl_peek(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    assert_true(BIO_set_buffer_read_data(bio, "hello", 5));
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_PEEK, 3, buf), 3);
    assert_memory_equal(buf, "hel", 3);
    /* peeking must not consume the buffered data */
    assert_int_equal(BIO_read(bio, buf, 5), 5);
    assert_memory_equal(buf, "hello", 5);
}

static void test_ctrl_peek_more_than_buffered(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    assert_true(BIO_set_buffer_read_data(bio, "hello", 5));
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_PEEK, 8, buf), 5);
    assert_memory_equal(buf, "hello", 5);
}

static void test_ctrl_default_forwarded(void **state)
{
    BIO *bio = *state;

    expect_next_ctrl(1234, 5);
    assert_int_equal(BIO_ctrl(bio, 1234, 0, NULL), 5);
}

static void test_callback_ctrl_forwarded(void **state)
{
    BIO *bio = *state;

    expect_next_cb_ctrl(BIO_CTRL_SET_CALLBACK, dummy_info_cb, 1);
    assert_int_equal(
        BIO_callback_ctrl(bio, BIO_CTRL_SET_CALLBACK, dummy_info_cb), 1);
}

/* behaviour with no next BIO */

static void test_nonext_io(void **state)
{
    BIO *bio = *state;
    char buf[8];

    assert_int_equal(BIO_read(bio, buf, 8), 0);
    assert_int_equal(BIO_write(bio, "x", 1), 0);
    assert_int_equal(BIO_eof(bio), 1);
}

static void test_nonext_ctrl(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_reset(bio), 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_WPENDING, 0, NULL), 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL), 0);
    assert_int_equal(BIO_flush(bio), 0);
    assert_int_equal(BIO_do_handshake(bio), 0);
    assert_int_equal(BIO_ctrl(bio, 1234, 0, NULL), 0);
    assert_int_equal(
        BIO_callback_ctrl(bio, BIO_CTRL_SET_CALLBACK, dummy_info_cb), 0);
}

/* buffer_sendmmsg / datagram flush */

#ifndef OPENSSL_NO_SOCK

static void test_sendmmsg_records_peer_and_buffers(void **state)
{
    BIO *bio = *state;
    BIO_ADDR peer;
    BIO_MSG msg;
    size_t processed = 0;

    make_peer(&peer);
    memset(&msg, 0, sizeof(msg));
    msg.data = (void *)"dgram1";
    msg.data_len = 6;
    msg.peer = &peer;

    expect_BIO_ADDR_new(1);
    expect_BIO_ADDR_copy(&peer, 1);
    assert_int_equal(BIO_sendmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 1);
    assert_int_equal(processed, 1);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), 6);
    assert_non_null(get_ctx(bio)->peer);
}

static void test_sendmmsg_flush_datagram(void **state)
{
    BIO *bio = *state;
    BIO_ADDR peer;
    BIO_MSG msg;
    size_t processed = 0;

    make_peer(&peer);
    memset(&msg, 0, sizeof(msg));
    msg.data = (void *)"dgram1";
    msg.data_len = 6;
    msg.peer = &peer;

    expect_BIO_ADDR_new(1);
    expect_BIO_ADDR_copy(&peer, 1);
    assert_int_equal(BIO_sendmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 1);

    /* the flush must go out via BIO_sendmmsg() carrying the peer address */
    expect_next_sendmmsg("dgram1", 6, AF_INET, 1, 1);
    expect_next_ctrl(BIO_CTRL_FLUSH, 1);
    assert_int_equal(BIO_flush(bio), 1);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), 0);
    assert_null(get_ctx(bio)->peer);
}

static void test_sendmmsg_flush_send_fails(void **state)
{
    BIO *bio = *state;
    BIO_ADDR peer;
    BIO_MSG msg;
    size_t processed = 0;

    make_peer(&peer);
    memset(&msg, 0, sizeof(msg));
    msg.data = (void *)"dgram1";
    msg.data_len = 6;
    msg.peer = &peer;

    expect_BIO_ADDR_new(1);
    expect_BIO_ADDR_copy(&peer, 1);
    assert_int_equal(BIO_sendmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 1);

    expect_next_sendmmsg("dgram1", 6, AF_INET, 0, 0);
    assert_true(BIO_flush(bio) <= 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), 6);
    assert_non_null(get_ctx(bio)->peer);
}

static void test_sendmmsg_no_peer(void **state)
{
    BIO *bio = *state;
    BIO_MSG msg;
    size_t processed = 1;

    memset(&msg, 0, sizeof(msg));
    msg.data = (void *)"dgram1";
    msg.data_len = 6;

    assert_int_equal(BIO_sendmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 0);
    assert_int_equal(processed, 0);
}

static void test_sendmmsg_addr_new_fails(void **state)
{
    BIO *bio = *state;
    BIO_ADDR peer;
    BIO_MSG msg;
    size_t processed = 1;

    make_peer(&peer);
    memset(&msg, 0, sizeof(msg));
    msg.data = (void *)"dgram1";
    msg.data_len = 6;
    msg.peer = &peer;

    expect_BIO_ADDR_new(0);
    assert_int_equal(BIO_sendmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 0);
    assert_int_equal(processed, 0);
}

static void test_sendmmsg_addr_copy_fails(void **state)
{
    BIO *bio = *state;
    BIO_ADDR peer;
    BIO_MSG msg;
    size_t processed = 1;

    make_peer(&peer);
    memset(&msg, 0, sizeof(msg));
    msg.data = (void *)"dgram1";
    msg.data_len = 6;
    msg.peer = &peer;

    expect_BIO_ADDR_new(1);
    expect_BIO_ADDR_copy(&peer, 0);
    assert_int_equal(BIO_sendmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 0);
    assert_int_equal(processed, 0);
    assert_null(get_ctx(bio)->peer);
}

static void test_sendmmsg_multiple_msgs(void **state)
{
    BIO *bio = *state;
    BIO_ADDR peer;
    BIO_MSG msg[2];
    size_t processed = 0;

    make_peer(&peer);
    memset(msg, 0, sizeof(msg));
    msg[0].data = (void *)"first";
    msg[0].data_len = 5;
    msg[0].peer = &peer;
    msg[1].data = (void *)"second";
    msg[1].data_len = 6;
    msg[1].peer = &peer;

    /* the peer is recorded once, both payloads accumulate in the buffer */
    expect_BIO_ADDR_new(1);
    expect_BIO_ADDR_copy(&peer, 1);
    assert_int_equal(BIO_sendmmsg(bio, msg, sizeof(msg[0]), 2, 0, &processed),
        1);
    assert_int_equal(processed, 2);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), 11);
    assert_memory_equal(get_ctx(bio)->obuf, "firstsecond", 11);
}

static void test_sendmmsg_zero_msgs(void **state)
{
    BIO *bio = *state;
    BIO_MSG msg;
    size_t processed = 1;

    memset(&msg, 0, sizeof(msg));
    assert_int_equal(BIO_sendmmsg(bio, &msg, sizeof(msg), 0, 0, &processed), 0);
    assert_int_equal(processed, 0);
}

static void test_sendmmsg_oversized_msg(void **state)
{
    BIO *bio = *state;
    BIO_ADDR peer;
    BIO_MSG msg[2];
    size_t processed = 0;

    make_peer(&peer);
    memset(msg, 0, sizeof(msg));
    msg[0].data = (void *)"first";
    msg[0].data_len = 5;
    msg[0].peer = &peer;
    /* the data is never dereferenced: the length check rejects it first */
    msg[1].data = (void *)"x";
    msg[1].data_len = (size_t)INT_MAX + 1;
    msg[1].peer = &peer;

    expect_BIO_ADDR_new(1);
    expect_BIO_ADDR_copy(&peer, 1);
    assert_int_equal(BIO_sendmmsg(bio, msg, sizeof(msg[0]), 2, 0, &processed),
        1);
    assert_int_equal(processed, 1);
}

static void test_sendmmsg_second_msg_write_fails(void **state)
{
    BIO *bio = *state;
    BIO_ADDR peer;
    BIO_MSG msg[2];
    size_t processed = 0;

    make_peer(&peer);
    memset(msg, 0, sizeof(msg));
    msg[0].data = pattern;
    msg[0].data_len = BUF_DEFAULT;
    msg[0].peer = &peer;
    msg[1].data = (void *)"more";
    msg[1].data_len = 4;
    msg[1].peer = &peer;

    /* the second message forces a flush, which fails all-or-nothing */
    expect_BIO_ADDR_new(1);
    expect_BIO_ADDR_copy(&peer, 1);
    expect_next_sendmmsg(pattern, BUF_DEFAULT, AF_INET, 0, 0);
    assert_int_equal(BIO_sendmmsg(bio, msg, sizeof(msg[0]), 2, 0, &processed),
        1);
    assert_int_equal(processed, 1);
}

static void test_sendmmsg_no_next(void **state)
{
    BIO *bio = *state;
    BIO_MSG msg;
    size_t processed = 1;

    memset(&msg, 0, sizeof(msg));
    msg.data = (void *)"dgram1";
    msg.data_len = 6;

    assert_int_equal(BIO_sendmmsg(bio, &msg, sizeof(msg), 1, 0, &processed), 0);
    assert_int_equal(processed, 0);
}

#endif /* OPENSSL_NO_SOCK */

/* main */

#define BUFF_TEST(name) \
    cmocka_unit_test_setup_teardown(name, setup, teardown)

#define BUFF_TEST_NONEXT(name) \
    cmocka_unit_test_setup_teardown(name, setup_nonext, teardown)

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* buffer_new */
        cmocka_unit_test(test_new_defaults),
        /* buffer_write */
        BUFF_TEST(test_write_small_buffered),
        BUFF_TEST(test_write_null_data),
        BUFF_TEST(test_write_fill_and_flush),
        BUFF_TEST(test_write_flush_needs_two_writes),
        BUFF_TEST(test_write_flush_retry),
        BUFF_TEST(test_write_flush_retry_after_topup),
        BUFF_TEST(test_write_flush_error),
        BUFF_TEST(test_write_flush_zero),
        BUFF_TEST(test_write_large_direct),
        BUFF_TEST(test_write_large_direct_error),
        BUFF_TEST(test_write_large_direct_zero),
        BUFF_TEST(test_write_large_exact_multiple),
        /* buffer_read */
        BUFF_TEST(test_read_from_preset_data),
        BUFF_TEST(test_read_refill_buffered),
        BUFF_TEST(test_read_partial_then_refill),
        BUFF_TEST(test_read_large_direct),
        BUFF_TEST(test_read_large_direct_partial_error),
        BUFF_TEST(test_read_large_direct_eof),
        BUFF_TEST(test_read_null_buffer),
        BUFF_TEST(test_read_retry),
        BUFF_TEST(test_read_error),
        BUFF_TEST(test_read_eof),
        /* buffer_gets */
        BUFF_TEST(test_gets_line),
        BUFF_TEST(test_gets_refill),
        BUFF_TEST(test_gets_truncated),
        BUFF_TEST(test_gets_eof),
        BUFF_TEST(test_gets_error),
        /* buffer_puts */
        BUFF_TEST(test_puts_buffered),
        /* buffer_ctrl */
        BUFF_TEST(test_ctrl_reset),
        BUFF_TEST(test_ctrl_eof_with_pending),
        BUFF_TEST(test_ctrl_eof_forwarded),
        BUFF_TEST(test_ctrl_num_lines),
        BUFF_TEST(test_ctrl_wpending),
        BUFF_TEST(test_ctrl_pending),
        BUFF_TEST(test_ctrl_set_read_data_large),
        BUFF_TEST(test_ctrl_set_buffer_size),
        BUFF_TEST(test_ctrl_set_rw_buffer_sizes),
        BUFF_TEST(test_ctrl_do_state_machine),
        BUFF_TEST(test_ctrl_flush_empty),
        BUFF_TEST(test_ctrl_flush_data),
        BUFF_TEST(test_ctrl_flush_partial_writes),
        BUFF_TEST(test_ctrl_flush_retry),
        BUFF_TEST(test_ctrl_dup),
        BUFF_TEST(test_ctrl_dup_fails),
        BUFF_TEST(test_ctrl_peek),
        BUFF_TEST(test_ctrl_peek_more_than_buffered),
        BUFF_TEST(test_ctrl_default_forwarded),
        BUFF_TEST(test_callback_ctrl_forwarded),
        /* no next BIO */
        BUFF_TEST_NONEXT(test_nonext_io),
        BUFF_TEST_NONEXT(test_nonext_ctrl),
#ifndef OPENSSL_NO_SOCK
        /* buffer_sendmmsg */
        BUFF_TEST(test_sendmmsg_records_peer_and_buffers),
        BUFF_TEST(test_sendmmsg_flush_datagram),
        BUFF_TEST(test_sendmmsg_flush_send_fails),
        BUFF_TEST(test_sendmmsg_no_peer),
        BUFF_TEST(test_sendmmsg_addr_new_fails),
        BUFF_TEST(test_sendmmsg_addr_copy_fails),
        BUFF_TEST(test_sendmmsg_multiple_msgs),
        BUFF_TEST(test_sendmmsg_zero_msgs),
        BUFF_TEST(test_sendmmsg_oversized_msg),
        BUFF_TEST(test_sendmmsg_second_msg_write_fails),
        BUFF_TEST_NONEXT(test_sendmmsg_no_next),
#endif
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
