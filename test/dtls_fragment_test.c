/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Regression test: a DTLS handshake fragment with frag_len == 0 and
 * msg_len > 0 must not be delivered to the state machine as a complete
 * message. Such a fragment carries no payload bytes at all; the reassembly
 * path already treats frag_len == 0 as DTLS1_HM_FRAGMENT_RETRY, and the
 * fast path in dtls_get_reassembled_message must do the same. Otherwise,
 * an empty body can reach the handshake parser with a header claiming the
 * full message length, after handshake_read_seq has already advanced.
 *
 * The test drives a DTLS 1.2 server over memory BIOs with crafted epoch-0
 * records and counts handshake messages handed to the state machine on
 * the read side via SSL_set_msg_callback().
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include "helpers/ssltestlib.h"
#include "testutil.h"

static int deliveries;
static char *cert = NULL;
static char *privkey = NULL;

/* write_p == 0 && content_type == SSL3_RT_HANDSHAKE means a handshake
 * message was handed to the state machine on read */
static void msg_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    (void)version;
    (void)buf;
    (void)len;
    (void)ssl;
    (void)arg;
    if (!write_p && content_type == SSL3_RT_HANDSHAKE)
        deliveries++;
}

/*
 * Feed one crafted epoch-0 DTLS 1.2 handshake record to a fresh server and
 * report (deliveries, SSL_get_error(SSL_accept())). Returns 1 on success.
 */
static int run_case(const unsigned char *rec, size_t reclen,
    int *pdeliveries, int *perr)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *rbio = NULL, *wbio = NULL;
    int r, ret = 0;

    deliveries = 0;
    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION))
        || !TEST_ptr(ssl = SSL_new(ctx)))
        goto err;
    SSL_set_msg_callback(ssl, msg_cb);
    if (!TEST_ptr(rbio = BIO_new(BIO_s_mem()))
        || !TEST_ptr(wbio = BIO_new(BIO_s_mem())))
        goto err;
    SSL_set_bio(ssl, rbio, wbio);
    rbio = wbio = NULL;
    if (!TEST_int_eq(BIO_write(SSL_get_rbio(ssl), rec, (int)reclen),
            (int)reclen))
        goto err;

    r = SSL_accept(ssl);
    *pdeliveries = deliveries;
    *perr = SSL_get_error(ssl, r);
    ret = 1;
err:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    BIO_free(rbio);
    BIO_free(wbio);
    return ret;
}

/* frag_len = 0, msg_len = 100: must be swallowed, server stays waiting */
static int test_zero_len_fragment(void)
{
    static const unsigned char rec[] = {
        0x16, 0xfe, 0xff, /* handshake, DTLS 1.2 */
        0x00, 0x00, /* epoch 0 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* sequence number 0 */
        0x00, 0x0c, /* length 12 = header only */
        0x01, /* msg_type ClientHello */
        0x00, 0x00, 0x64, /* msg_len = 100 */
        0x00, 0x00, /* msg_seq = 0 */
        0x00, 0x00, 0x00, /* frag_off = 0 */
        0x00, 0x00, 0x00 /* frag_len = 0 */
    };
    int d = -1, e = -1;

    if (!TEST_true(run_case(rec, sizeof(rec), &d, &e)))
        return 0;
    /* No phantom message may reach the state machine ... */
    if (!TEST_int_eq(d, 0))
        return 0;
    /* ... and the server must still be waiting for input */
    return TEST_int_eq(e, SSL_ERROR_WANT_READ);
}

/* Control: a genuine partial fragment is buffered, nothing is delivered */
static int test_partial_fragment(void)
{
    static const unsigned char rec[] = {
        0x16, 0xfe, 0xff,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x11, /* length 17 = header + 5 */
        0x01,
        0x00, 0x00, 0x64, /* msg_len = 100 */
        0x00, 0x00, /* msg_seq = 0 */
        0x00, 0x00, 0x00, /* frag_off = 0 */
        0x00, 0x00, 0x05, /* frag_len = 5 */
        0x01, 0x02, 0x03, 0x04, 0x05 /* 5 body bytes */
    };
    int d = -1, e = -1;

    if (!TEST_true(run_case(rec, sizeof(rec), &d, &e)))
        return 0;
    if (!TEST_int_eq(d, 0))
        return 0;
    return TEST_int_eq(e, SSL_ERROR_WANT_READ);
}

/* frag_len = 0, msg_len = 100, frag_off = 101: fragment extends past the
 * claimed message length, so the server must fail the handshake with
 * SSL_R_EXCESSIVE_MESSAGE_SIZE instead of a bare SSL_ERROR_SYSCALL */
static int test_bad_fragment_offset(void)
{
    static const unsigned char rec[] = {
        0x16, 0xfe, 0xff, /* handshake, DTLS 1.2 */
        0x00, 0x00, /* epoch 0 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* sequence number 0 */
        0x00, 0x0c, /* length 12 = header only */
        0x01, /* msg_type ClientHello */
        0x00, 0x00, 0x64, /* msg_len = 100 */
        0x00, 0x00, /* msg_seq = 0 */
        0x00, 0x00, 0x65, /* frag_off = 101 */
        0x00, 0x00, 0x00 /* frag_len = 0 */
    };
    int d = -1, e = -1;

    if (!TEST_true(run_case(rec, sizeof(rec), &d, &e)))
        return 0;
    if (!TEST_int_eq(d, 0)
        || !TEST_int_eq(e, SSL_ERROR_SSL)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()),
            SSL_R_EXCESSIVE_MESSAGE_SIZE)) {
        ERR_clear_error();
        return 0;
    }
    ERR_clear_error();
    return 1;
}

/* frag_len = 0, msg_len = 102401: claimed length above the 102400 default
 * maximum, so the server must fail the handshake with
 * SSL_R_EXCESSIVE_MESSAGE_SIZE */
static int test_excessive_message_length(void)
{
    static const unsigned char rec[] = {
        0x16, 0xfe, 0xff, /* handshake, DTLS 1.2 */
        0x00, 0x00, /* epoch 0 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* sequence number 0 */
        0x00, 0x0c, /* length 12 = header only */
        0x01, /* msg_type ClientHello */
        0x01, 0x90, 0x01, /* msg_len = 102401 */
        0x00, 0x00, /* msg_seq = 0 */
        0x00, 0x00, 0x00, /* frag_off = 0 */
        0x00, 0x00, 0x00 /* frag_len = 0 */
    };
    int d = -1, e = -1;

    if (!TEST_true(run_case(rec, sizeof(rec), &d, &e)))
        return 0;
    if (!TEST_int_eq(d, 0)
        || !TEST_int_eq(e, SSL_ERROR_SSL)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()),
            SSL_R_EXCESSIVE_MESSAGE_SIZE)) {
        ERR_clear_error();
        return 0;
    }
    ERR_clear_error();
    return 1;
}

#ifndef OPENSSL_NO_RSA
static unsigned int get_u24(const unsigned char *p)
{
    return ((unsigned int)p[0] << 16) | ((unsigned int)p[1] << 8) | p[2];
}

static void put_u24(unsigned char *p, unsigned int value)
{
    p[0] = (unsigned char)(value >> 16);
    p[1] = (unsigned char)(value >> 8);
    p[2] = (unsigned char)value;
}

/* The caller has checked that hello holds one complete ClientHello record. */
static int make_fragment(unsigned char *out, const unsigned char *hello,
    unsigned int offset, unsigned int len)
{
    unsigned int record_len = DTLS1_HM_HEADER_LENGTH + len;
    size_t header_len = DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH;

    memcpy(out, hello, header_len);
    out[11] = (unsigned char)(record_len >> 8);
    out[12] = (unsigned char)record_len;
    put_u24(out + DTLS1_RT_HEADER_LENGTH + 6, offset);
    put_u24(out + DTLS1_RT_HEADER_LENGTH + 9, len);
    memcpy(out + header_len, hello + header_len + offset, len);
    return (int)(header_len + len);
}

static int test_fragment_continuation(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO *capture = NULL, *saved_wbio = NULL, *transport;
    unsigned char hello[4096], fragment[4096];
    unsigned int msg_len, split;
    int ret, n, fraglen, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    /* Capture the original message without writing to the packet BIO yet. */
    transport = SSL_get_wbio(clientssl);
    if (!TEST_true(BIO_up_ref(transport)))
        goto end;
    saved_wbio = transport;
    if (!TEST_ptr(capture = BIO_new(BIO_s_mem())))
        goto end;
    SSL_set0_wbio(clientssl, capture);
    capture = NULL;
    SSL_set_options(clientssl, SSL_OP_NO_QUERY_MTU);
    if (!TEST_true(SSL_set_mtu(clientssl, 1500)))
        goto end;

    ret = SSL_connect(clientssl);
    if (!TEST_int_le(ret, 0)
        || !TEST_int_eq(SSL_get_error(clientssl, ret), SSL_ERROR_WANT_READ))
        goto end;

    n = BIO_read(SSL_get_wbio(clientssl), hello, sizeof(hello));
    if (!TEST_int_ge(n, DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH)
        || !TEST_size_t_eq(BIO_ctrl_pending(SSL_get_wbio(clientssl)), 0)
        || !TEST_int_eq(hello[0], SSL3_RT_HANDSHAKE)
        || !TEST_int_eq(hello[3] | hello[4], 0)
        || !TEST_int_eq((hello[11] << 8) | hello[12],
            n - DTLS1_RT_HEADER_LENGTH)
        || !TEST_int_eq(hello[13], SSL3_MT_CLIENT_HELLO)
        || !TEST_int_eq(hello[17] | hello[18], 0)
        || !TEST_uint_eq(get_u24(hello + 19), 0))
        goto end;
    msg_len = get_u24(hello + 14);
    if (!TEST_uint_ge(msg_len, 2)
        || !TEST_uint_eq(msg_len, get_u24(hello + 22))
        || !TEST_uint_eq(msg_len,
            (unsigned int)n - DTLS1_RT_HEADER_LENGTH - DTLS1_HM_HEADER_LENGTH))
        goto end;

    SSL_set0_wbio(clientssl, saved_wbio);
    saved_wbio = NULL;
    transport = SSL_get_rbio(serverssl);
    deliveries = 0;
    SSL_set_msg_callback(serverssl, msg_cb);
    split = msg_len / 2;

    /*
     * Injection enables record numbering in the packet BIO. It also adjusts
     * later records in epoch zero; the client's transcript stays unchanged.
     */
    fraglen = make_fragment(fragment, hello, 0, split);
    if (!TEST_int_eq(mempacket_test_inject(transport, (char *)fragment,
                         fraglen, 0, INJECT_PACKET),
            fraglen))
        goto end;

    /* Queue the empty fragment before reading, to advance packet numbering. */
    fraglen = make_fragment(fragment, hello, split, 0);
    if (!TEST_int_eq(BIO_write(transport, fragment, fraglen), fraglen))
        goto end;

    ret = SSL_accept(serverssl);
    if (!TEST_int_le(ret, 0)
        || !TEST_int_eq(SSL_get_error(serverssl, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(deliveries, 0))
        goto end;

    /* Completion requires the bytes buffered before the empty fragment. */
    fraglen = make_fragment(fragment, hello, split, msg_len - split);
    if (!TEST_int_eq(BIO_write(transport, fragment, fraglen), fraglen))
        goto end;

    /* Check delivery before the client can retransmit the complete message. */
    ret = SSL_accept(serverssl);
    if (!TEST_int_le(ret, 0)
        || !TEST_int_eq(SSL_get_error(serverssl, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(deliveries, 1)
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    BIO_free(capture);
    BIO_free(saved_wbio);
    return testresult;
}
#endif

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }
    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

    ADD_TEST(test_zero_len_fragment);
    ADD_TEST(test_partial_fragment);
    ADD_TEST(test_bad_fragment_offset);
    ADD_TEST(test_excessive_message_length);
#ifndef OPENSSL_NO_RSA
    ADD_TEST(test_fragment_continuation);
#endif
    return 1;
}

void cleanup_tests(void)
{
    bio_s_mempacket_test_free();
}
