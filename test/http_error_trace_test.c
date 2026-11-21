/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/http.h>
#include <openssl/httperr.h>
#include <openssl/trace.h>
#include "testutil.h"

/**
 * @def BODY(s)
 * @brief Initialize a fixture's body and byte length from string literal @p s.
 */
#define BODY(s) .body = s, .body_len = sizeof(s) - 1

/**
 * @struct error_fixture_st
 * @brief Input schedule, framing, and expected diagnostics for an error body.
 */
typedef struct error_fixture_st {
    const char *body; /**< Bytes available for the response body and any suffix */
    size_t body_len; /**< Number of bytes in body, including embedded NULs */
    int status_code; /**< HTTP response status */
    long declared_len; /**< Content-Length, or -1 to omit the header */
    size_t first; /**< Initial byte count, or SIZE_MAX for the whole body */
    size_t chunk; /**< Later byte count per call, or zero for all remaining bytes */
    int close; /**< Signal EOF when the last body bytes are supplied */
    int wait_eof; /**< Expect retry after all bytes arrive, before signalling EOF */
    size_t traced_len; /**< Expected body byte count in the trace */
    int extra_reason; /**< Additional HTTP error reason, or zero */
    unsigned long max_len; /**< Response length limit, or zero for the default */
    const char *masked_body; /**< Expected masked body of a non-text 399 response */
} ERROR_FIXTURE;

#ifndef OPENSSL_NO_TRACE
/**
 * @brief Set the test-owned HTTP trace channel.
 * @param trace Whether tracing is enabled.
 * @param capture Receives a retained BIO reference, freed by the caller.
 * @returns 1 on success, or 0 after a test assertion fails.
 */
static int set_capture(int trace, BIO **capture)
{
    *capture = NULL;
    if (trace && (!TEST_ptr(*capture = BIO_new(BIO_s_mem())) || !TEST_true(BIO_up_ref(*capture))))
        return 0;
    if (!TEST_true(OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_HTTP, *capture))) {
        BIO_free(*capture);
        return 0;
    }
    return 1;
}

/**
 * @brief Check the complete error-body trace, including its closing delimiter.
 * @param capture Trace channel containing the exchange output.
 * @param fixture Expected body, or NULL to require no error-body trace marker.
 * @returns 1 if the trace matches, or 0 otherwise.
 */
static int check_trace(BIO *capture, const ERROR_FIXTURE *fixture)
{
    static const char prefix[] = "Receiving error response content";
    char marker[80], *data;
    long len = BIO_get_mem_data(capture, &data);
    size_t offset, marker_len;
    const char *body;

    if (!TEST_long_ge(len, 0))
        return 0;
    for (offset = 0; offset + sizeof(prefix) - 1 <= (size_t)len; offset++)
        if (memcmp(data + offset, prefix, sizeof(prefix) - 1) == 0)
            break;
    if (fixture == NULL) {
        static const char header_marker[] = "Receiving response header: [\n";

        if (!TEST_size_t_gt(offset + sizeof(prefix) - 1, (size_t)len))
            return 0;
        for (offset = 0; offset + sizeof(header_marker) - 1 <= (size_t)len; offset++)
            if (memcmp(data + offset, header_marker, sizeof(header_marker) - 1) == 0)
                break;
        return TEST_size_t_le(offset + sizeof(header_marker) - 1, (size_t)len);
    }
    snprintf(marker, sizeof(marker), "%s (likely %s): [\n", prefix,
        fixture->masked_body != NULL ? "ASN.1" : "text");
    marker_len = strlen(marker);
    if (!TEST_size_t_le(offset + marker_len, (size_t)len)
        || !TEST_mem_eq(data + offset, marker_len, marker, marker_len))
        return 0;
    offset += marker_len;
    body = fixture->masked_body != NULL ? fixture->masked_body : fixture->body;
    return TEST_size_t_eq((size_t)len - offset, fixture->traced_len + 2)
        && TEST_mem_eq(data + offset, fixture->traced_len, body, fixture->traced_len)
        && TEST_mem_eq(data + offset + fixture->traced_len, 2, "]\n", 2);
}
#endif

static int put(BIO *writer, const char *data, size_t len)
{
    return TEST_size_t_le(len, INT_MAX)
        && (len == 0 || TEST_int_eq(BIO_write(writer, data, (int)len), (int)len));
}

static int expect_http_error(int reason)
{
    unsigned long error = ERR_get_error();

    return TEST_int_eq(ERR_GET_LIB(error), ERR_LIB_HTTP)
        && TEST_int_eq(ERR_GET_REASON(error), reason);
}

/**
 * @brief Prepare a GET request and supply complete response headers.
 * @param ctx Request context to reinitialize.
 * @param request BIO receiving the request.
 * @param writer Peer supplying the response.
 * @param status_code Response status. 304 uses an If-None-Match request header.
 * @param content_type Response Content-Type, or NULL to omit it.
 * @param declared_len Content-Length, or -1 to omit it.
 * @returns 1 on success, or 0 after a test assertion fails.
 */
static int prepare_response(OSSL_HTTP_REQ_CTX *ctx, BIO *request, BIO *writer,
    int status_code, const char *content_type, long declared_len)
{
    char header[256], type_header[80] = "", length_header[80] = "";
    int len;

    (void)BIO_reset(request);
    if (!TEST_true(OSSL_HTTP_REQ_CTX_set_request_line(ctx, 0, NULL, NULL, "/"))
        || (status_code == 304
            && !TEST_true(OSSL_HTTP_REQ_CTX_add1_header(ctx, "If-None-Match", "\"fixture\"")))
        || !TEST_true(OSSL_HTTP_REQ_CTX_set_expected(ctx, NULL, 1, 0, 0)))
        return 0;
    if (content_type != NULL)
        snprintf(type_header, sizeof(type_header), "Content-Type: %s\r\n", content_type);
    if (declared_len >= 0)
        snprintf(length_header, sizeof(length_header), "Content-Length: %ld\r\n", declared_len);
    len = snprintf(header, sizeof(header), "HTTP/1.1 %d Test response\r\n%s%s\r\n",
        status_code, type_header, length_header);
    return TEST_int_gt(len, 0)
        && TEST_size_t_lt((size_t)len, sizeof(header))
        && put(writer, header, (size_t)len);
}

/**
 * @brief Feed one error response and check each scheduled return and final result.
 * @param ctx Request context, reinitialized for this exchange.
 * @param request BIO receiving the request.
 * @param reader BIO supplying the response.
 * @param writer Peer used to supply response bytes and EOF.
 * @param fixture Input schedule and expected diagnostics.
 * @param trace Whether HTTP tracing is enabled.
 * @returns 1 if all checks pass, or 0 otherwise.
 */
static int exchange(OSSL_HTTP_REQ_CTX *ctx, BIO *request,
    BIO *reader, BIO *writer, const ERROR_FIXTURE *fixture, int trace)
{
    char remaining[16];
    size_t supplied = 0, amount, extra, resp_len;
    int ret = -1, expected, ok = 0;
    int read_error = fixture->extra_reason == HTTP_R_FAILED_READING_DATA;
    int original_reason = fixture->status_code < 400
        ? HTTP_R_STATUS_CODE_UNSUPPORTED
        : HTTP_R_CONTENT_TYPE_MISMATCH;
#ifndef OPENSSL_NO_TRACE
    BIO *capture = NULL;

    if (!set_capture(trace, &capture))
        goto end;
#endif
    if (!TEST_int_eq(OSSL_trace_enabled(OSSL_TRACE_CATEGORY_HTTP), trace))
        goto end;
    OSSL_HTTP_REQ_CTX_set_max_response_length(ctx, fixture->max_len);
    if (!prepare_response(ctx, request, writer, fixture->status_code,
            fixture->masked_body != NULL ? "application/octet-stream" : "text/plain",
            fixture->declared_len))
        goto end;
    ERR_clear_error();
    amount = fixture->first;
    for (;;) {
        if (amount > fixture->body_len - supplied)
            amount = fixture->body_len - supplied;
        if (!put(writer, fixture->body + supplied, amount))
            goto end;
        supplied += amount;
        if (fixture->close && supplied == fixture->body_len) {
            if (!TEST_true(BIO_shutdown_wr(writer)))
                goto end;
        }
        expected = 0;
        if (trace && !read_error
            && (supplied < fixture->body_len || fixture->wait_eof))
            expected = -1;
        ret = OSSL_HTTP_REQ_CTX_nbio(ctx);
        if (!TEST_int_eq(ret, expected))
            goto end;
        if (ret == 0)
            break;
        /* Empty polls must retain both the body prefix and the original error. */
        if (!TEST_true(BIO_should_retry(reader))
            || !TEST_false(BIO_eof(reader))
            || !TEST_int_eq(OSSL_HTTP_REQ_CTX_nbio(ctx), -1))
            goto end;
        if (supplied == fixture->body_len) {
            if (!TEST_true(BIO_shutdown_wr(writer))
                || !TEST_int_eq(OSSL_HTTP_REQ_CTX_nbio(ctx), 0))
                goto end;
            break;
        }
        amount = fixture->chunk != 0 ? fixture->chunk : SIZE_MAX;
    }
    if (!expect_http_error(original_reason)
        || (fixture->extra_reason != 0 && !expect_http_error(fixture->extra_reason))
        || !TEST_ulong_eq(ERR_peek_error(), 0)
        || (read_error && (!TEST_false(BIO_should_retry(reader)) || !TEST_false(BIO_eof(reader)))))
        goto end;
    resp_len = fixture->declared_len >= 0     ? (size_t)fixture->declared_len
        : trace && fixture->extra_reason == 0 ? supplied
                                              : 0;
    if (!TEST_size_t_eq(OSSL_HTTP_REQ_CTX_get_resp_len(ctx), resp_len)
        || (!trace && !TEST_false(BIO_eof(reader))))
        goto end;
#ifndef OPENSSL_NO_TRACE
    if (trace && !check_trace(capture, fixture))
        goto end;
#endif
    /* Bytes following a framed body belong to the following exchange. */
    if (trace && fixture->declared_len >= 0
        && supplied > (size_t)fixture->declared_len) {
        extra = supplied - (size_t)fixture->declared_len;
        if (!TEST_size_t_le(extra, sizeof(remaining))
            || !TEST_int_eq(BIO_read(reader, remaining, (int)extra), (int)extra)
            || !TEST_mem_eq(remaining, extra,
                fixture->body + fixture->declared_len, extra))
            goto end;
    }
    ok = 1;
end:
#ifndef OPENSSL_NO_TRACE
    if (!TEST_true(OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_HTTP, NULL)))
        ok = 0;
    BIO_free(capture);
#endif
    ERR_clear_error();
    return ok;
}

/* Fail the body's BIO_read() without retry or EOF. Header BIO_gets() calls pass. */
static long fail_read(BIO *bio, int oper, const char *argp, size_t len,
    int argi, long argl, int ret, size_t *processed)
{
    if (oper == BIO_CB_READ) {
        BIO_clear_retry_flags(bio);
        return -1;
    }
    return ret;
}

/**
 * @brief Create a request context and a BIO pair for supplying responses.
 * @param request Receives the request BIO, freed by the caller.
 * @param reader Receives the read chain, freed by the caller with BIO_free_all().
 * @param writer Receives the peer BIO, freed by the caller.
 * @param buffered Whether to add a buffering BIO supporting BIO_gets().
 * @returns A context freed by the caller, or NULL on failure.
 */
static OSSL_HTTP_REQ_CTX *new_context(BIO **request, BIO **reader,
    BIO **writer, int buffered)
{
    BIO *wire = NULL;

    if (!TEST_true(BIO_new_bio_pair(&wire, 0, writer, 0)))
        return NULL;
    *reader = wire;
    if (buffered) {
        BIO *buffer = BIO_new(BIO_f_buffer());

        if (!TEST_ptr(buffer))
            return NULL;
        *reader = BIO_push(buffer, wire);
    }
    if (!TEST_ptr(*request = BIO_new(BIO_s_mem())))
        return NULL;
    return OSSL_HTTP_REQ_CTX_new(*request, *reader, 1024);
}

/**
 * @brief Run fixtures in order on the same context and BIO pair.
 * @param fixtures Responses and expected results.
 * @param count Number of fixtures.
 * @param trace Whether HTTP tracing is enabled.
 * @param buffered Whether the response BIO supports BIO_gets().
 * @returns 1 if all fixtures pass, or 0 otherwise.
 */
static int run_fixtures(const ERROR_FIXTURE *fixtures, size_t count,
    int trace, int buffered)
{
    BIO *writer = NULL, *reader = NULL, *request = NULL;
    OSSL_HTTP_REQ_CTX *ctx = new_context(&request, &reader, &writer, buffered);
    size_t i;
    int ok = 0;

    if (!TEST_ptr(ctx))
        goto end;
    for (i = 0; i < count; i++) {
        BIO_set_callback_ex(reader, fixtures[i].extra_reason == HTTP_R_FAILED_READING_DATA ? fail_read : NULL);
        if (!exchange(ctx, request, reader, writer, &fixtures[i], trace))
            goto end;
    }
    ok = 1;
end:
    OSSL_HTTP_REQ_CTX_free(ctx);
    BIO_free(request);
    BIO_free_all(reader);
    BIO_free(writer);
    return ok;
}

static int test_no_trace(void)
{
    static const ERROR_FIXTURE fixture = {
        BODY("diagnostic"), .status_code = 500, .declared_len = 10
    };

    return run_fixtures(&fixture, 1, 0, 1);
}

/**
 * @struct bodyless_fixture_st
 * @brief A rejected response ending at its headers, with optional following data.
 */
typedef struct bodyless_fixture_st {
    int status_code; /**< HTTP response status */
    long declared_len; /**< Content-Length, or -1 to omit it */
    const char *suffix; /**< Following bytes that must remain available, or NULL */
    int close; /**< Signal EOF before receiving the response */
} BODYLESS_FIXTURE;

static const BODYLESS_FIXTURE bodyless_fixtures[] = {
    { .status_code = 204, .declared_len = -1 },
    { .status_code = 304, .declared_len = 10 },
    { .status_code = 304, .declared_len = 10, .close = 1 },
    { .status_code = 103, .declared_len = -1, .suffix = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnext" },
};

/**
 * @brief Check immediate rejection without tracing or consuming a nonexistent body.
 * @param idx Fixture index. The second group of fixtures enables HTTP tracing.
 * @returns 1 if the status error, trace, and unread bytes are correct.
 */
static int test_bodyless(int idx)
{
    const BODYLESS_FIXTURE *fixture = &bodyless_fixtures[idx % OSSL_NELEM(bodyless_fixtures)];
    int trace = idx >= (int)OSSL_NELEM(bodyless_fixtures), ok = 0;
    size_t suffix_len = fixture->suffix == NULL ? 0 : strlen(fixture->suffix);
    char remaining[128];
    BIO *writer = NULL, *reader = NULL, *request = NULL;
    OSSL_HTTP_REQ_CTX *ctx = NULL;
#ifndef OPENSSL_NO_TRACE
    BIO *capture = NULL;

    if (!set_capture(trace, &capture))
        goto end;
#endif
    if (!TEST_int_eq(OSSL_trace_enabled(OSSL_TRACE_CATEGORY_HTTP), trace)
        || !TEST_ptr(ctx = new_context(&request, &reader, &writer, 1))
        || !prepare_response(ctx, request, writer, fixture->status_code, NULL,
            fixture->declared_len)
        || !put(writer, fixture->suffix, suffix_len)
        || (fixture->close && !TEST_true(BIO_shutdown_wr(writer))))
        goto end;
    ERR_clear_error();
    if (!TEST_int_eq(OSSL_HTTP_REQ_CTX_nbio(ctx), 0)
        || !expect_http_error(HTTP_R_STATUS_CODE_UNSUPPORTED)
        || !TEST_ulong_eq(ERR_peek_error(), 0)
        || !TEST_int_eq(BIO_eof(reader), fixture->close))
        goto end;
#ifndef OPENSSL_NO_TRACE
    if (trace && !check_trace(capture, NULL))
        goto end;
#endif
    /* Buffer prefetch may move following bytes out of the underlying BIO pair. */
    if (!TEST_size_t_eq(BIO_ctrl_pending(reader), suffix_len)
        || !TEST_size_t_le(suffix_len, sizeof(remaining)))
        goto end;
    if (suffix_len != 0
        && (!TEST_int_eq(BIO_read(reader, remaining, (int)suffix_len), (int)suffix_len)
            || !TEST_mem_eq(remaining, suffix_len, fixture->suffix, suffix_len)))
        goto end;
    ok = 1;
end:
#ifndef OPENSSL_NO_TRACE
    if (!TEST_true(OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_HTTP, NULL)))
        ok = 0;
    BIO_free(capture);
#endif
    OSSL_HTTP_REQ_CTX_free(ctx);
    BIO_free(request);
    BIO_free_all(reader);
    BIO_free(writer);
    ERR_clear_error();
    return ok;
}

#ifndef OPENSSL_NO_TRACE
static char long_body[2050];
static char long_line[1026];

static const ERROR_FIXTURE fixtures[] = {
    { BODY("diagnostic\n"), .status_code = 500, .declared_len = 11, .first = SIZE_MAX,
        .close = 1, .traced_len = 11 },
    { BODY("diagnostic\n"), .status_code = 500, .declared_len = 11,
        .close = 1, .traced_len = 11 },
    { BODY("first\nsecond\n"), .status_code = 500, .declared_len = 13, .first = 6,
        .close = 1, .traced_len = 13 },
    { BODY("diagnostic"), .status_code = 500, .declared_len = 10, .first = SIZE_MAX,
        .close = 1, .traced_len = 10 },
    { BODY("first\ndiagnostic"), .status_code = 500, .declared_len = 16, .first = SIZE_MAX,
        .close = 1, .traced_len = 16 },
    /* Split within lines, with several retries and an empty poll between them. */
    { BODY("first\ndiagnostic\n"), .status_code = 500, .declared_len = 17, .first = 2,
        .chunk = 3, .close = 1, .traced_len = 17 },
    { BODY("first\ndiagnostic"), .status_code = 500, .declared_len = 16, .first = 2,
        .chunk = 3, .close = 1, .traced_len = 16 },
    { BODY("short\n"), .status_code = 500, .declared_len = 11, .first = SIZE_MAX,
        .close = 1, .traced_len = 6,
        .extra_reason = HTTP_R_INCONSISTENT_CONTENT_LENGTH },
    { BODY("short"), .status_code = 500, .declared_len = 11, .first = SIZE_MAX,
        .close = 1, .traced_len = 5,
        .extra_reason = HTTP_R_INCONSISTENT_CONTENT_LENGTH },
    /* A known length ends the body without closing the connection. */
    { BODY("diagnostic\n"), .status_code = 500, .declared_len = 11, .first = SIZE_MAX, .traced_len = 11 },
    { BODY("diagnostic"), .status_code = 500, .declared_len = 10, .first = SIZE_MAX, .traced_len = 10 },
    { BODY("diagnosticNEXT"), .status_code = 500, .declared_len = 10, .first = SIZE_MAX, .traced_len = 10 },
    { BODY(""), .status_code = 500, .declared_len = 0, .first = SIZE_MAX },
    { BODY("NEXT"), .status_code = 500, .declared_len = 0, .first = SIZE_MAX },
    /* Without Content-Length, only EOF terminates the error body. */
    { BODY("diagnostic"), .status_code = 500, .declared_len = -1, .first = SIZE_MAX,
        .close = 1, .traced_len = 10 },
    { BODY("diagnostic"), .status_code = 500, .declared_len = -1, .first = SIZE_MAX,
        .wait_eof = 1, .traced_len = 10 },
    { BODY(""), .status_code = 500, .declared_len = -1, .first = SIZE_MAX, .close = 1 },
    /* Body chunks are not restricted by the response header line size. */
    { .body = long_body, .body_len = 1023, .status_code = 500, .declared_len = 1023, .first = SIZE_MAX, .close = 1, .traced_len = 1023 },
    { .body = long_body, .body_len = 1024, .status_code = 500, .declared_len = 1024, .first = SIZE_MAX, .close = 1, .traced_len = 1024 },
    { .body = long_body, .body_len = 1025, .status_code = 500, .declared_len = 1025, .first = SIZE_MAX, .close = 1, .traced_len = 1025 },
    { .body = long_body, .body_len = 2049, .status_code = 500, .declared_len = 2049, .first = SIZE_MAX, .close = 1, .traced_len = 2049 },
    { .body = long_line, .body_len = 1025, .status_code = 500, .declared_len = 1025, .first = SIZE_MAX, .close = 1, .traced_len = 1025 },
    { .body = long_line, .body_len = 1025, .status_code = 500, .declared_len = 1025, .first = 1024, .chunk = 1, .traced_len = 1025 },
    /* Exercise the body-read length limit with no Content-Length header. */
    { .body = long_body, .body_len = 32, .status_code = 500, .declared_len = -1, .first = 16, .chunk = 16, .close = 1, .traced_len = 32, .max_len = 32 },
    { .body = long_body, .body_len = 33, .status_code = 500, .declared_len = -1, .first = 32, .chunk = 1, .close = 1, .traced_len = 32, .extra_reason = HTTP_R_MAX_RESP_LEN_EXCEEDED, .max_len = 32 },
    { BODY("a\0]\nb"), .status_code = 500, .declared_len = 5, .first = 2, .chunk = 1, .traced_len = 5 },
    { BODY("A\0\t\nB\r"), .status_code = 399, .declared_len = 6, .first = 2, .chunk = 2,
        .traced_len = 6, .masked_body = "A  \nB " },
};

static int test_error_trace(int idx)
{
    return run_fixtures(&fixtures[idx], 1, 1, 1);
}

static int test_no_gets(void)
{
    /* BIO pairs do not implement BIO_gets(). All headers arrive together. */
    static const ERROR_FIXTURE fixture = {
        BODY("first\ndiagnostic"), .status_code = 500, .declared_len = 16, .first = 2,
        .chunk = 3, .close = 1, .traced_len = 16
    };

    return run_fixtures(&fixture, 1, 1, 0);
}

static int test_read_error(void)
{
    /* BIO_gets() delivers the headers. The first body read fails without EOF. */
    static const ERROR_FIXTURE fixture = {
        BODY(""), .status_code = 500, .declared_len = 10, .first = SIZE_MAX,
        .extra_reason = HTTP_R_FAILED_READING_DATA
    };

    return run_fixtures(&fixture, 1, 1, 1);
}

static int test_reuse(void)
{
    /* Reinitializing a context must also reset whether Content-Length was seen. */
    static const ERROR_FIXTURE reuse[] = {
        { BODY("first"), .status_code = 500, .declared_len = 5, .first = SIZE_MAX, .traced_len = 5 },
        { BODY(""), .status_code = 500, .declared_len = 0, .first = SIZE_MAX },
        { BODY("diagnostic"), .status_code = 500, .declared_len = -1, .first = 2,
            .chunk = 3, .close = 1, .traced_len = 10 },
    };

    return run_fixtures(reuse, OSSL_NELEM(reuse), 1, 1);
}
#endif

int setup_tests(void)
{
    ADD_TEST(test_no_trace);
#ifndef OPENSSL_NO_TRACE
    memset(long_body, 'x', sizeof(long_body) - 1);
    memset(long_line, 'x', sizeof(long_line) - 2);
    long_line[sizeof(long_line) - 2] = '\n';
    ADD_ALL_TESTS(test_error_trace, OSSL_NELEM(fixtures));
    ADD_TEST(test_no_gets);
    ADD_TEST(test_read_error);
    ADD_TEST(test_reuse);
    ADD_ALL_TESTS(test_bodyless, 2 * OSSL_NELEM(bodyless_fixtures));
#else
    ADD_ALL_TESTS(test_bodyless, OSSL_NELEM(bodyless_fixtures));
#endif
    return 1;
}
