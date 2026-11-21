/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Tests that BIO_get_line() and BIO_gets() on a connect BIO do not lose the
 * start of a line when a nonblocking read needs to be retried after some
 * bytes of the line have already been read, and that hard errors are still
 * reported as errors.
 */

#include <string.h>
#include <time.h>
#include <openssl/bio.h>
#ifndef OPENSSL_NO_HTTP
#include <openssl/http.h>
#endif
#include "testutil.h"

#define PART1 "hello "
#define PART2 "world\n"
#define WHOLE PART1 PART2

/* A line split over two writes into a BIO pair must not lose its start */
static int test_get_line_pair_split(void)
{
    BIO *reader = NULL, *writer = NULL;
    char buf[64];
    int ret = 0;

    if (!TEST_true(BIO_new_bio_pair(&reader, 0, &writer, 0)))
        goto err;

    if (!TEST_int_eq(BIO_write(writer, PART1, strlen(PART1)), strlen(PART1)))
        goto err;
    /* All available bytes must be returned, not -1 */
    if (!TEST_int_eq(BIO_get_line(reader, buf, sizeof(buf)), strlen(PART1))
        || !TEST_str_eq(buf, PART1))
        goto err;

    /* Nothing more is available yet, so this must ask for a retry */
    if (!TEST_int_eq(BIO_get_line(reader, buf, sizeof(buf)), -1)
        || !TEST_true(BIO_should_retry(reader))
        || !TEST_str_eq(buf, ""))
        goto err;

    if (!TEST_int_eq(BIO_write(writer, PART2, strlen(PART2)), strlen(PART2)))
        goto err;
    if (!TEST_int_eq(BIO_get_line(reader, buf, sizeof(buf)), strlen(PART2))
        || !TEST_str_eq(buf, PART2))
        goto err;

    ret = 1;
err:
    BIO_free(reader);
    BIO_free(writer);
    return ret;
}

/* Existing behaviour that must be kept */
static int test_get_line_pair_unchanged(void)
{
    BIO *reader = NULL, *writer = NULL;
    char buf[64];
    int ret = 0;

    if (!TEST_true(BIO_new_bio_pair(&reader, 0, &writer, 0)))
        goto err;

    /* A retry before any data arrives still returns -1 */
    if (!TEST_int_eq(BIO_get_line(reader, buf, sizeof(buf)), -1)
        || !TEST_true(BIO_should_retry(reader)))
        goto err;

    /* A whole line is returned at once */
    if (!TEST_int_eq(BIO_write(writer, WHOLE, strlen(WHOLE)), strlen(WHOLE))
        || !TEST_int_eq(BIO_get_line(reader, buf, sizeof(buf)), strlen(WHOLE))
        || !TEST_str_eq(buf, WHOLE))
        goto err;

    /* A partial line followed by EOF is returned, then EOF gives 0 */
    if (!TEST_int_eq(BIO_write(writer, PART1, strlen(PART1)), strlen(PART1))
        || !TEST_int_eq(BIO_shutdown_wr(writer), 1)
        || !TEST_int_eq(BIO_get_line(reader, buf, sizeof(buf)), strlen(PART1))
        || !TEST_str_eq(buf, PART1)
        || !TEST_int_eq(BIO_get_line(reader, buf, sizeof(buf)), 0))
        goto err;

    ret = 1;
err:
    BIO_free(reader);
    BIO_free(writer);
    return ret;
}

/*
 * A source BIO that returns the bytes of PART1 one at a time, then fails
 * with an error that is not retriable.
 */
static int err_after_data_read(BIO *bio, char *buf, int len)
{
    size_t *pos = BIO_get_data(bio);

    BIO_clear_retry_flags(bio);
    if (len <= 0 || *pos >= strlen(PART1))
        return -1;
    *buf = PART1[(*pos)++];
    return 1;
}

static long err_after_data_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    return 0;
}

/* A hard error after some data must be reported as an error */
static int test_get_line_hard_error(void)
{
    BIO_METHOD *meth = NULL;
    BIO *bio = NULL;
    size_t pos = 0;
    char buf[64];
    int ret = 0;

    if (!TEST_ptr(meth = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "err after data"))
        || !TEST_true(BIO_meth_set_read(meth, err_after_data_read))
        || !TEST_true(BIO_meth_set_ctrl(meth, err_after_data_ctrl))
        || !TEST_ptr(bio = BIO_new(meth)))
        goto err;
    BIO_set_data(bio, &pos);
    BIO_set_init(bio, 1);

    if (!TEST_int_eq(BIO_get_line(bio, buf, sizeof(buf)), -1)
        || !TEST_false(BIO_should_retry(bio)))
        goto err;

    ret = 1;
err:
    BIO_free(bio);
    BIO_meth_free(meth);
    return ret;
}

#ifndef OPENSSL_NO_SOCK
/*
 * Reads from |b| with BIO_gets() until |want| has been collected, waiting
 * for |fd| to become readable before each attempt. Readability only means
 * that some data has arrived, so a single call may return fewer bytes.
 * With the bug, bytes read before a retry are lost and |want| is never
 * collected.
 */
static int gets_until(BIO *b, int fd, const char *want)
{
    size_t wantlen = strlen(want), gotlen = 0;
    char got[64], buf[64];
    int i, n;

    for (i = 0; i < 20 && gotlen < wantlen; i++) {
        if (!TEST_int_gt(BIO_socket_wait(fd, 1, time(NULL) + 5), 0))
            return 0;
        n = BIO_gets(b, buf, sizeof(buf));
        if (n > 0) {
            if (!TEST_size_t_le(gotlen + n, wantlen))
                return 0;
            memcpy(got + gotlen, buf, n);
            gotlen += n;
        } else if (n == 0 || !BIO_should_retry(b)) {
            TEST_error("BIO_gets() failed with %d", n);
            return 0;
        }
    }
    return TEST_mem_eq(got, gotlen, want, wantlen);
}

/* A line split over two sends on a nonblocking connect BIO */
static int test_conn_gets_split(void)
{
    BIO *abio = NULL, *cbio = NULL, *sbio = NULL, *cbio2 = NULL;
    const char *port;
    char buf[64];
    int fd = -1, ret = 0;

    /* Skip if IPv4 loopback is not available on this host */
    if ((abio = BIO_new_accept("127.0.0.1:0")) == NULL
        || BIO_do_accept(abio) <= 0 /* bind and listen */
        || (port = BIO_get_accept_port(abio)) == NULL) {
        BIO_free(abio);
        return TEST_skip("IPv4 loopback is not available");
    }

    if (!TEST_ptr(cbio = BIO_new_connect("127.0.0.1"))
        || !TEST_long_gt(BIO_set_conn_port(cbio, port), 0)
        || !TEST_int_gt(BIO_do_connect(cbio), 0)
        || !TEST_int_gt(BIO_do_accept(abio), 0)
        || !TEST_ptr(sbio = BIO_pop(abio))
        || !TEST_int_ge(BIO_get_fd(cbio, &fd), 0)
        || !TEST_true(BIO_socket_nbio(fd, 1)))
        goto err;

    /*
     * All of PART1 must be reported by successful BIO_gets() calls before
     * PART2 is sent, although the line is not complete yet.
     */
    if (!TEST_int_eq(BIO_write(sbio, PART1, strlen(PART1)), strlen(PART1))
        || !gets_until(cbio, fd, PART1)
        || !TEST_int_eq(BIO_write(sbio, PART2, strlen(PART2)), strlen(PART2))
        || !gets_until(cbio, fd, PART2))
        goto err;

    /*
     * Connecting is not reading: with room for no data at all, BIO_gets()
     * on a new connect BIO must connect and then report 0 bytes, not 1.
     */
    if (!TEST_ptr(cbio2 = BIO_new_connect("127.0.0.1"))
        || !TEST_long_gt(BIO_set_conn_port(cbio2, port), 0)
        || !TEST_int_eq(BIO_gets(cbio2, buf, 1), 0))
        goto err;

    ret = 1;
err:
    BIO_free(cbio2);
    BIO_free(sbio);
    BIO_free(cbio);
    BIO_free(abio);
    return ret;
}
#endif

#ifndef OPENSSL_NO_HTTP
/* An HTTP response whose status line is split over two writes */
static int test_http_split_status_line(void)
{
    static const char resp1[] = "HTTP/1.0 2";
    static const char resp2[] = "00 OK\r\nContent-Length: 6\r\n\r\nhello\n";
    BIO *client = NULL, *server = NULL;
    OSSL_HTTP_REQ_CTX *rctx = NULL;
    char buf[256];
    int i, rv = -1, sent2 = 0, ret = 0;

    if (!TEST_true(BIO_new_bio_pair(&client, 0, &server, 0))
        || !TEST_ptr(rctx = OSSL_HTTP_REQ_CTX_new(client, client, 0))
        || !TEST_true(OSSL_HTTP_REQ_CTX_set_request_line(rctx, 0, NULL, NULL,
            "/"))
        || !TEST_true(OSSL_HTTP_REQ_CTX_set_expected(rctx, NULL, 0, 0, 0)))
        goto err;

    if (!TEST_int_eq(BIO_write(server, resp1, strlen(resp1)), strlen(resp1)))
        goto err;

    for (i = 0; i < 10; i++) {
        /* Discard the request sent by the client */
        while (BIO_read(server, buf, sizeof(buf)) > 0)
            continue;
        if ((rv = OSSL_HTTP_REQ_CTX_nbio(rctx)) != -1)
            break;
        if (!sent2) {
            if (!TEST_int_eq(BIO_write(server, resp2, strlen(resp2)),
                    strlen(resp2)))
                goto err;
            sent2 = 1;
        }
    }

    /* The split must have caused a retry, and the response must succeed */
    if (!TEST_true(sent2)
        || !TEST_int_eq(rv, 1)
        || !TEST_int_eq(BIO_read(client, buf, sizeof(buf)), 6)
        || !TEST_mem_eq(buf, 6, "hello\n", 6))
        goto err;

    ret = 1;
err:
    OSSL_HTTP_REQ_CTX_free(rctx);
    BIO_free(client);
    BIO_free(server);
    return ret;
}
#endif

int setup_tests(void)
{
    ADD_TEST(test_get_line_pair_split);
    ADD_TEST(test_get_line_pair_unchanged);
    ADD_TEST(test_get_line_hard_error);
#ifndef OPENSSL_NO_SOCK
    ADD_TEST(test_conn_gets_split);
#endif
#ifndef OPENSSL_NO_HTTP
    ADD_TEST(test_http_split_status_line);
#endif
    return 1;
}
