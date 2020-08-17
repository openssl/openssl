/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "ssltestlib.h"
#include "testutil.h"

static char *cert = NULL;
static char *privkey = NULL;

static int async_new(BIO *bio);
static int async_free(BIO *bio);
static int async_read_ex(BIO *bio, char *out, size_t outl, size_t *readbytes);
static int async_write_ex(BIO *bio, const char *in, size_t inl, size_t *written);
static long async_ctrl(BIO *bio, int cmd, long num, void *ptr);

static BIO_METHOD *methods_async = NULL;

struct async_state {
    int test_error;
    int force_read_retry;
    const char *read_buffer;
    size_t read_size;
    int force_write_retry;
    const char *write_buffer;
    size_t write_size;
};

static const BIO_METHOD *bio_f_async_filter(void)
{
    if (methods_async == NULL) {
        methods_async = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_FILTER, "Async filter");
        if (   methods_async == NULL
            || !BIO_meth_set_write_ex(methods_async, async_write_ex)
            || !BIO_meth_set_read_ex(methods_async, async_read_ex)
            || !BIO_meth_set_ctrl(methods_async, async_ctrl)
            || !BIO_meth_set_create(methods_async, async_new)
            || !BIO_meth_set_destroy(methods_async, async_free))
            return NULL;
    }
    return methods_async;
}

static int async_new(BIO *bio)
{
    struct async_state *state;

    state = OPENSSL_zalloc(sizeof(struct async_state));
    if (state == NULL)
        return 0;

    state->force_read_retry = 1;
    state->force_write_retry = 1;

    BIO_set_data(bio, state);
    BIO_set_init(bio, 1);
    return 1;
}

static int async_free(BIO *bio)
{
    struct async_state *state;

    if (bio == NULL)
        return 0;
    state = BIO_get_data(bio);
    OPENSSL_free(state);
    BIO_set_data(bio, NULL);
    BIO_set_init(bio, 0);

    return 1;
}

static int async_read_ex(BIO *bio, char *out, size_t outl, size_t *readbytes)
{
    struct async_state *state;
    int ret = 0;
    BIO *next = BIO_next(bio);

    if (outl <= 0)
        return 0;
    if (next == NULL)
        return 0;

    state = BIO_get_data(bio);

    BIO_clear_retry_flags(bio);

    if (!state->force_read_retry) {
        if(!TEST_true(out == state->read_buffer)
                || !TEST_true(outl >= state->read_size))
            state->test_error = 1;

        ret = BIO_read_ex(next, out, outl, readbytes);
        if (ret <= 0 && BIO_should_read(next))
            BIO_set_retry_read(bio);
        else
            state->force_read_retry = 1;
    } else {
        state->force_read_retry = 0;
        state->read_buffer = out;
        state->read_size = outl;
        BIO_set_retry_read(bio);
    }

    return ret;
}

static int async_write_ex(BIO *bio, const char *in, size_t inl, size_t *written)
{
    struct async_state *state;
    int ret = 0;
    BIO *next = BIO_next(bio);

    if (inl <= 0)
        return 0;
    if (next == NULL)
        return 0;

    state = BIO_get_data(bio);

    BIO_clear_retry_flags(bio);

    if (!state->force_write_retry) {
        if(!TEST_true(in == state->write_buffer)
                || !TEST_true(inl >= state->write_size))
            state->test_error = 1;

        ret = BIO_write_ex(next, in, inl, written);
        if (ret <= 0 && BIO_should_write(next))
            BIO_set_retry_write(bio);
        else
            state->force_write_retry = 1;
    } else {
        state->force_write_retry = 0;
        state->write_buffer = in;
        state->write_size = inl;
        BIO_set_retry_write(bio);
    }

    return ret;
}

static long async_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    long ret;
    BIO *next = BIO_next(bio);

    if (next == NULL)
        return 0;

    switch (cmd) {
    case BIO_CTRL_DUP:
        ret = 0L;
        break;
    default:
        ret = BIO_ctrl(next, cmd, num, ptr);
        break;
    }
    return ret;
}

#define MAX_ATTEMPTS    100

static int test_asyncio_buffer(int test)
{
    SSL_CTX *serverctx = NULL, *clientctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO *s_to_c_fbio = NULL, *c_to_s_fbio = NULL;
    struct async_state *s_to_c_fbio_state = NULL, *c_to_s_fbio_state = NULL;
    int testresult = 0, ret;
    size_t i, j;
    const char testdata[] = "Test data";
    char buf[sizeof(testdata)];

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &serverctx, &clientctx, cert, privkey)))
        goto end;

    if (test == 1) {
        SSL_CTX_set_read_ahead(clientctx, 1);
        SSL_CTX_set_read_ahead(serverctx, 1);
    }

    s_to_c_fbio = BIO_new(bio_f_async_filter());
    c_to_s_fbio = BIO_new(bio_f_async_filter());
    if (!TEST_ptr(s_to_c_fbio)
            || !TEST_ptr(c_to_s_fbio)) {
        BIO_free(s_to_c_fbio);
        BIO_free(c_to_s_fbio);
        goto end;
    }

    s_to_c_fbio_state = BIO_get_data(s_to_c_fbio);
    c_to_s_fbio_state = BIO_get_data(s_to_c_fbio);
    if (!TEST_ptr(s_to_c_fbio_state)
            || !TEST_ptr(c_to_s_fbio_state)) {
        BIO_free(s_to_c_fbio);
        BIO_free(c_to_s_fbio);
        goto end;
    }

    /* BIOs get freed on error */
    if (!TEST_true(create_ssl_objects(serverctx, clientctx, &serverssl,
                                      &clientssl, s_to_c_fbio, c_to_s_fbio))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                          SSL_ERROR_NONE)))
        goto end;

    /*
     * Send and receive some test data. Do the whole thing twice to ensure
     * we hit at least one async event in both reading and writing
     */
    for (j = 0; j < 2; j++) {
        int len;

        /*
         * Write some test data. It should never take more than 2 attempts
         * (the first one might be a retryable fail).
         */
        for (ret = -1, i = 0, len = 0; len != sizeof(testdata) && i < 2;
            i++) {
            ret = SSL_write(clientssl, testdata + len,
                sizeof(testdata) - len);
            if (ret > 0) {
                len += ret;
            } else {
                int ssl_error = SSL_get_error(clientssl, ret);

                if (!TEST_false(ssl_error == SSL_ERROR_SYSCALL ||
                                ssl_error == SSL_ERROR_SSL))
                    goto end;
            }
        }
        if (!TEST_size_t_eq(len, sizeof(testdata)))
            goto end;

        /*
         * Now read the test data. It may take more attempts here because
         * it could fail once for each byte read, including all overhead
         * bytes from the record header/padding etc.
         */
        for (ret = -1, i = 0, len = 0; len != sizeof(testdata) &&
                i < MAX_ATTEMPTS; i++) {
            ret = SSL_read(serverssl, buf + len, sizeof(buf) - len);
            if (ret > 0) {
                len += ret;
            } else {
                int ssl_error = SSL_get_error(serverssl, ret);

                if (!TEST_false(ssl_error == SSL_ERROR_SYSCALL ||
                                ssl_error == SSL_ERROR_SSL))
                    goto end;
            }
        }
        if (!TEST_mem_eq(testdata, sizeof(testdata), buf, len))
            goto end;
    }

    do {
        ret = SSL_shutdown(clientssl);
    } while (ret < 0
                    && SSL_get_error(clientssl, ret) == SSL_ERROR_WANT_WRITE);
    if (!TEST_int_eq(ret, 0))
        goto end;

    do {
        ret = SSL_shutdown(serverssl);
    } while (ret < 0
                    && SSL_get_error(serverssl, ret) == SSL_ERROR_WANT_WRITE);
    if (!TEST_int_eq(ret, 0))
        goto end;

    if (!TEST_false(s_to_c_fbio_state->test_error)
            || !TEST_false(c_to_s_fbio_state->test_error))
        goto end;

    testresult = 1;

 end:
    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_CTX_free(clientctx);
    SSL_CTX_free(serverctx);

    return testresult;
}

OPT_TEST_DECLARE_USAGE("certname privkey\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert = test_get_argument(0))
            || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

    ADD_ALL_TESTS(test_asyncio_buffer, 2);
    return 1;
}

void cleanup_tests(void)
{
    BIO_meth_free(methods_async);
}
