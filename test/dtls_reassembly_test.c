/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Tests for the aggregate receive-side DTLS handshake reassembly byte
 * budget (DTLS_MAX_REASSEMBLY_BUDGET_DEFAULT / dtls1_reassembly_budget).
 *
 * Crafted plaintext DTLS handshake records are fed to a server whose
 * receive BIO is a BIO_s_dgram_mem. Out-of-sequence messages are buffered
 * by the reassembly queue; the tests check that the per-connection byte
 * counter (d1->reassembly_bytes) tracks the allocated slots exactly and
 * that the aggregate budget rejects fragments once it would be exceeded.
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/dtls1.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>

#include "internal/nelem.h"
#include "internal/ssl_unwrap.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"
#include "../ssl/ssl_local.h"

static char *cert = NULL;
static char *privkey = NULL;

static unsigned int infinite_timer_cb(SSL *s, unsigned int timer_us)
{
    (void)s;

    if (timer_us == 0)
        return 999999999;
    return timer_us;
}

/*
 * Build a plaintext DTLS record carrying a single handshake fragment.
 * |ver| is the record-layer version, |rec_seq| the record-layer sequence
 * number, |hstype| the handshake message type, |hs_seq| the handshake
 * sequence number, |msg_len| the total handshake message length,
 * |frag_off|/|frag_len| the fragment, and |frag| the fragment body
 * (|frag_len| bytes; zero-filled if NULL). Returns the record length, or
 * 0 if it would not fit in |outsz|.
 */
static size_t build_hs_record(unsigned char *out, size_t outsz, int ver,
    unsigned long long rec_seq, unsigned char hstype,
    unsigned long msg_len, unsigned short hs_seq,
    unsigned long frag_off, unsigned long frag_len,
    const unsigned char *frag)
{
    unsigned char *p = out;
    size_t payload = DTLS1_HM_HEADER_LENGTH + frag_len;
    size_t i;

    if (outsz < DTLS1_RT_HEADER_LENGTH + payload
        || msg_len > 0xFFFFFFUL || frag_len > 0xFFFFFFUL
        || frag_off > 0xFFFFFFUL)
        return 0;

    *p++ = SSL3_RT_HANDSHAKE;
    *p++ = (unsigned char)(ver >> 8);
    *p++ = (unsigned char)ver;
    *p++ = 0; /* epoch 0 */
    *p++ = 0;
    for (i = 0; i < 6; i++) /* record-layer sequence number */
        *p++ = (unsigned char)(rec_seq >> (8 * (5 - i)));
    *p++ = (unsigned char)(payload >> 8);
    *p++ = (unsigned char)payload;

    /* handshake message header */
    *p++ = hstype;
    *p++ = (unsigned char)(msg_len >> 16);
    *p++ = (unsigned char)(msg_len >> 8);
    *p++ = (unsigned char)msg_len;
    *p++ = (unsigned char)(hs_seq >> 8);
    *p++ = (unsigned char)hs_seq;
    *p++ = (unsigned char)(frag_off >> 16);
    *p++ = (unsigned char)(frag_off >> 8);
    *p++ = (unsigned char)frag_off;
    *p++ = (unsigned char)(frag_len >> 16);
    *p++ = (unsigned char)(frag_len >> 8);
    *p++ = (unsigned char)frag_len;

    if (frag_len > 0) {
        if (frag != NULL)
            memcpy(p, frag, frag_len);
        else
            memset(p, 0, frag_len);
        p += frag_len;
    }

    return (size_t)(p - out);
}

/* Create an unconnected DTLS server whose read BIO is a BIO_s_dgram_mem. */
static int create_server(SSL_CTX **sctxp, SSL **sslp, BIO **rbio, int ver)
{
    SSL_CTX *sctx = NULL;
    SSL *ssl = NULL;
    BIO *rb = NULL, *wb = NULL;

    if (!TEST_ptr(sctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(sctx, ver))
        || !TEST_true(SSL_CTX_set_max_proto_version(sctx, ver)))
        goto err;

    if (ver == DTLS1_VERSION)
        SSL_CTX_set_security_level(sctx, 0);

    if (!TEST_true(SSL_CTX_use_certificate_file(sctx, cert,
            SSL_FILETYPE_PEM))
        || !TEST_true(SSL_CTX_use_PrivateKey_file(sctx, privkey,
            SSL_FILETYPE_PEM)))
        goto err;

    if (!TEST_ptr(rb = BIO_new(BIO_s_dgram_mem()))
        || !TEST_ptr(wb = BIO_new(BIO_s_mem())))
        goto err;

    if (!TEST_ptr(ssl = SSL_new(sctx)))
        goto err;

    SSL_set_bio(ssl, rb, wb);

    *sctxp = sctx;
    *sslp = ssl;
    *rbio = rb;
    return 1;

err:
    BIO_free(rb);
    BIO_free(wb);
    SSL_free(ssl);
    SSL_CTX_free(sctx);
    return 0;
}

static size_t reassembly_bytes(SSL *ssl)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    return sc->d1->reassembly_bytes;
}

/* Drive the server's read state machine; nbio (WANT_READ/WANT_WRITE) is OK. */
static int drive_server(SSL *ssl)
{
    int ret = SSL_accept(ssl);

    if (ret > 0)
        return 1;
    if (ret == 0 || SSL_get_error(ssl, ret) == SSL_ERROR_SYSCALL
        || SSL_get_error(ssl, ret) == SSL_ERROR_SSL)
        return 0;
    return 1;
}

/* Feed one crafted record to the server. */
static int feed_record(BIO *rbio, const unsigned char *rec, size_t len)
{
    return TEST_int_eq(BIO_write(rbio, rec, (int)len), (int)len);
}

static const int versions[] = {
#ifndef OPENSSL_NO_DTLS1_2
    DTLS1_2_VERSION,
#endif
#ifndef OPENSSL_NO_DTLS1
    DTLS1_VERSION,
#endif
};

/*
 * Buffer 3 full-size fragments (fits in the default ~400 KB budget), then
 * check that a 4th full-size fragment is discarded and that the connection
 * still accepts a small fragment afterwards. Exercises the partial-fragment
 * (reassembly) budget path and counter accounting.
 */
static int test_reassembly_aggregate(int idx)
{
    const size_t msg_len = 100000;
    const size_t slot = msg_len + ((msg_len + 7) / 8);
    unsigned char *rec;
    size_t rec_len;
    SSL_CTX *sctx = NULL;
    SSL *ssl = NULL;
    BIO *rbio = NULL;
    unsigned long long rseq = 1000;
    int i, testresult = 0, ver = versions[idx];

    if (!TEST_ptr(rec = OPENSSL_malloc(DTLS1_RT_HEADER_LENGTH
                      + DTLS1_HM_HEADER_LENGTH + msg_len))
        || !TEST_true(create_server(&sctx, &ssl, &rbio, ver)))
        goto end;

    for (i = 0; i < 3; i++) {
        rec_len = build_hs_record(rec, DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH + msg_len, ver, rseq++,
            SSL3_MT_CERTIFICATE, msg_len, i + 1, 0, 1, NULL);
        if (!TEST_size_t_gt(rec_len, 0)
            || !TEST_true(feed_record(rbio, rec, rec_len)))
            goto end;
    }
    if (!TEST_true(drive_server(ssl))
        || !TEST_size_t_eq(reassembly_bytes(ssl), 3 * slot))
        goto end;

    /* 4th full-size fragment would exceed the budget: must be discarded. */
    rec_len = build_hs_record(rec, DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH + msg_len, ver, rseq++,
        SSL3_MT_CERTIFICATE, msg_len, 4, 0, 1, NULL);
    if (!TEST_size_t_gt(rec_len, 0)
        || !TEST_true(feed_record(rbio, rec, rec_len))
        || !TEST_true(drive_server(ssl))
        || !TEST_size_t_eq(reassembly_bytes(ssl), 3 * slot))
        goto end;

    /* Connection still alive: a small fragment is accepted. */
    rec_len = build_hs_record(rec, DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH + msg_len, ver, rseq++,
        SSL3_MT_CERTIFICATE, 1000, 5, 0, 1, NULL);
    if (!TEST_size_t_gt(rec_len, 0)
        || !TEST_true(feed_record(rbio, rec, rec_len))
        || !TEST_true(drive_server(ssl))
        || !TEST_size_t_eq(reassembly_bytes(ssl),
            3 * slot + 1000 + ((1000 + 7) / 8)))
        goto end;

    testresult = 1;
end:
    OPENSSL_free(rec);
    SSL_free(ssl);
    SSL_CTX_free(sctx);
    return testresult;
}

/*
 * Complete (non-fragmented) out-of-sequence messages are accounted against
 * the budget too. They cannot exceed the maximum DTLS record size (~16 KB),
 * so a second scenario uses a small max_cert_list to make the aggregate
 * budget bind and prove the complete-message path enforces it.
 */
static int test_reassembly_complete_messages(int idx)
{
    const size_t msg_len = 10000;
    unsigned char *rec;
    size_t rec_len;
    SSL_CTX *sctx = NULL;
    SSL *ssl = NULL;
    BIO *rbio = NULL;
    unsigned long long rseq = 2000;
    int i, testresult = 0, ver = versions[idx];

    if (!TEST_ptr(rec = OPENSSL_malloc(DTLS1_RT_HEADER_LENGTH
                      + DTLS1_HM_HEADER_LENGTH + 20000))
        || !TEST_true(create_server(&sctx, &ssl, &rbio, ver)))
        goto end;

    /* complete messages are buffered and counted (window allows 5) */
    for (i = 0; i < 5; i++) {
        rec_len = build_hs_record(rec, DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH + 20000, ver, rseq++,
            SSL3_MT_CERTIFICATE, msg_len, i + 1, 0, msg_len, NULL);
        if (!TEST_size_t_gt(rec_len, 0)
            || !TEST_true(feed_record(rbio, rec, rec_len)))
            goto end;
    }
    if (!TEST_true(drive_server(ssl))
        || !TEST_size_t_eq(reassembly_bytes(ssl), 5 * msg_len))
        goto end;

    SSL_free(ssl);
    SSL_CTX_free(sctx);
    ssl = NULL;
    sctx = NULL;

    /* with max_cert_list = 20000, budget = 80000: 3 partial 20000-byte
     * fragments (slot 22500 each) leave 12500 bytes; a complete 15000-byte
     * message must be discarded */
    if (!TEST_true(create_server(&sctx, &ssl, &rbio, ver)))
        goto end;
    if (!TEST_true(SSL_set_max_cert_list(ssl, 20000)))
        goto end;

    for (i = 0; i < 3; i++) {
        rec_len = build_hs_record(rec, DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH + 20000, ver, rseq++,
            SSL3_MT_CERTIFICATE, 20000, i + 1, 0, 1, NULL);
        if (!TEST_size_t_gt(rec_len, 0)
            || !TEST_true(feed_record(rbio, rec, rec_len)))
            goto end;
    }
    rec_len = build_hs_record(rec, DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH + 20000, ver, rseq++,
        SSL3_MT_CERTIFICATE, 15000, 4, 0, 15000, NULL);
    if (!TEST_size_t_gt(rec_len, 0)
        || !TEST_true(feed_record(rbio, rec, rec_len))
        || !TEST_true(drive_server(ssl))
        || !TEST_size_t_eq(reassembly_bytes(ssl), 3 * (20000 + ((20000 + 7) / 8))))
        goto end;

    testresult = 1;
end:
    OPENSSL_free(rec);
    SSL_free(ssl);
    SSL_CTX_free(sctx);
    return testresult;
}

/*
 * The 11-slot sequence-number window still bounds the number of buffered
 * messages: sequence 11 is dropped even though the byte budget is not hit.
 */
static int test_reassembly_window(int idx)
{
    const size_t msg_len = 1000;
    const size_t slot = msg_len + ((msg_len + 7) / 8);
    unsigned char rec[DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH + 1];
    size_t rec_len;
    SSL_CTX *sctx = NULL;
    SSL *ssl = NULL;
    BIO *rbio = NULL;
    unsigned long long rseq = 3000;
    int i, testresult = 0, ver = versions[idx];

    if (!TEST_true(create_server(&sctx, &ssl, &rbio, ver)))
        goto end;

    for (i = 0; i < 11; i++) {
        rec_len = build_hs_record(rec, sizeof(rec), ver, rseq++,
            SSL3_MT_CERTIFICATE, msg_len, i + 1, 0, 1, NULL);
        if (!TEST_size_t_gt(rec_len, 0)
            || !TEST_true(feed_record(rbio, rec, rec_len)))
            goto end;
    }
    if (!TEST_true(drive_server(ssl))
        || !TEST_size_t_eq(reassembly_bytes(ssl), 10 * slot))
        goto end;

    testresult = 1;
end:
    SSL_free(ssl);
    SSL_CTX_free(sctx);
    return testresult;
}

/*
 * The budget scales with the configured maximum certificate list size: with
 * max_cert_list raised to 1 MiB, a single 500 KB message (which would exceed
 * the ~400 KB default budget) is accepted, because it is legal under the
 * per-message limit. Under a fixed default-derived constant this message
 * would be wrongly rejected.
 */
static int test_reassembly_scaled_budget(int idx)
{
    const size_t msg_len = 500000;
    const size_t slot = msg_len + ((msg_len + 7) / 8);
    unsigned char rec[DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH + 1];
    size_t rec_len;
    SSL_CTX *sctx = NULL;
    SSL *ssl = NULL;
    BIO *rbio = NULL;
    int testresult = 0, ver = versions[idx];

    if (!TEST_true(create_server(&sctx, &ssl, &rbio, ver)))
        goto end;

    if (!TEST_true(SSL_set_max_cert_list(ssl, 1024 * 1024)))
        goto end;

    rec_len = build_hs_record(rec, sizeof(rec), ver, 4000,
        SSL3_MT_CERTIFICATE, msg_len, 1, 0, 1, NULL);
    if (!TEST_size_t_gt(rec_len, 0)
        || !TEST_true(feed_record(rbio, rec, rec_len))
        || !TEST_true(drive_server(ssl))
        || !TEST_size_t_eq(reassembly_bytes(ssl), slot))
        goto end;

    testresult = 1;
end:
    SSL_free(ssl);
    SSL_CTX_free(sctx);
    return testresult;
}

/* A normal DTLS handshake still completes and transfers data. */
static int test_reassembly_positive_control(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    int max_ver = versions[idx];
    int testresult = 0, ret;
    char buf[64];

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), max_ver, max_ver,
            &sctx, &cctx, cert, privkey)))
        return 0;

    if (max_ver == DTLS1_VERSION) {
        SSL_CTX_set_security_level(sctx, 0);
        SSL_CTX_set_security_level(cctx, 0);
    }

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(sssl, infinite_timer_cb);
    DTLS_set_timer_cb(cssl, infinite_timer_cb);

    if (!TEST_int_le(SSL_connect(cssl), 0)
        || !TEST_int_le(SSL_accept(sssl), 0)
        || !TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    ret = SSL_accept(sssl);
    if (!TEST_int_gt(ret, 0))
        goto end;
    ret = SSL_connect(cssl);
    if (!TEST_int_gt(ret, 0))
        goto end;

    if (!TEST_int_eq(SSL_write(cssl, "hello", 5), 5)
        || !TEST_int_eq(SSL_read(sssl, buf, sizeof(buf)), 5)
        || !TEST_mem_eq(buf, 5, "hello", 5))
        goto end;

    /* reassembly accounting returned to zero after the handshake */
    if (!TEST_size_t_eq(reassembly_bytes(sssl), 0))
        goto end;

    testresult = 1;
end:
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

    ADD_ALL_TESTS(test_reassembly_aggregate, OSSL_NELEM(versions));
    ADD_ALL_TESTS(test_reassembly_complete_messages, OSSL_NELEM(versions));
    ADD_ALL_TESTS(test_reassembly_window, OSSL_NELEM(versions));
    ADD_ALL_TESTS(test_reassembly_scaled_budget, OSSL_NELEM(versions));
    ADD_ALL_TESTS(test_reassembly_positive_control, OSSL_NELEM(versions));

    return 1;
}
