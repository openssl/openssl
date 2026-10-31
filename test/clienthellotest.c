/*
 * Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

#include "internal/packet.h"

#include "testutil.h"

#define CLIENT_VERSION_LEN 2

#define TOTAL_NUM_TESTS 1

/*
 * Test that explicitly setting ticket data results in it appearing in the
 * ClientHello for a negotiated SSL/TLS version
 */
#define TEST_SET_SESSION_TICK_DATA_VER_NEG 0

static int test_client_hello(int currtest)
{
    SSL_CTX *ctx;
    SSL *con = NULL;
    BIO *rbio;
    BIO *wbio;
    long len;
    unsigned char *data;
    PACKET pkt, pkt2, pkt3;
    char *dummytick = "Hello World!";
    unsigned int type = 0;
    int testresult = 0;
    BIO *sessbio = NULL;
    SSL_SESSION *sess = NULL;

    memset(&pkt, 0, sizeof(pkt));
    memset(&pkt2, 0, sizeof(pkt2));
    memset(&pkt3, 0, sizeof(pkt3));

    /*
     * For each test set up an SSL_CTX and SSL and see what ClientHello gets
     * produced when we try to connect
     */
    ctx = SSL_CTX_new(TLS_method());
    if (!TEST_ptr(ctx))
        goto end;
    if (!TEST_true(SSL_CTX_set_max_proto_version(ctx, 0)))
        goto end;

    switch (currtest) {
    case TEST_SET_SESSION_TICK_DATA_VER_NEG:
#if !defined(OPENSSL_NO_TLS1_3) && defined(OPENSSL_NO_TLS1_2)
        /* TLSv1.3 is enabled and TLSv1.2 is disabled so can't do this test */
        SSL_CTX_free(ctx);
        return 1;
#else
        /* Testing for session tickets <= TLS1.2; not relevant for 1.3 */
        if (!TEST_true(SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION)))
            goto end;
#endif
        break;

    default:
        goto end;
    }

    con = SSL_new(ctx);
    if (!TEST_ptr(con))
        goto end;

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    if (!TEST_ptr(rbio) || !TEST_ptr(wbio)) {
        BIO_free(rbio);
        BIO_free(wbio);
        goto end;
    }

    SSL_set_bio(con, rbio, wbio);
    SSL_set_connect_state(con);

    if (currtest == TEST_SET_SESSION_TICK_DATA_VER_NEG) {
        if (!TEST_true(SSL_set_session_ticket_ext(con, dummytick,
                (int)strlen(dummytick))))
            goto end;
    }

    if (!TEST_int_le(SSL_connect(con), 0)) {
        /* This shouldn't succeed because we don't have a server! */
        goto end;
    }

    if (!TEST_long_ge(len = BIO_get_mem_data(wbio, (char **)&data), 0)
        || !TEST_true(PACKET_buf_init(&pkt, data, len))
        /* Skip the record header */
        || !PACKET_forward(&pkt, SSL3_RT_HEADER_LENGTH))
        goto end;

    /* Skip the handshake message header */
    if (!TEST_true(PACKET_forward(&pkt, SSL3_HM_HEADER_LENGTH))
        /* Skip client version and random */
        || !TEST_true(PACKET_forward(&pkt, CLIENT_VERSION_LEN + SSL3_RANDOM_SIZE))
        /* Skip session id */
        || !TEST_true(PACKET_get_length_prefixed_1(&pkt, &pkt2))
        /* Skip ciphers */
        || !TEST_true(PACKET_get_length_prefixed_2(&pkt, &pkt2))
        /* Skip compression */
        || !TEST_true(PACKET_get_length_prefixed_1(&pkt, &pkt2))
        /* Extensions len */
        || !TEST_true(PACKET_as_length_prefixed_2(&pkt, &pkt2)))
        goto end;

    /* Loop through all extensions */
    while (PACKET_remaining(&pkt2)) {

        if (!TEST_true(PACKET_get_net_2(&pkt2, &type))
            || !TEST_true(PACKET_get_length_prefixed_2(&pkt2, &pkt3)))
            goto end;

        if (type == TLSEXT_TYPE_session_ticket) {
            if (currtest == TEST_SET_SESSION_TICK_DATA_VER_NEG) {
                if (TEST_true(PACKET_equal(&pkt3, dummytick,
                        strlen(dummytick)))) {
                    /* Ticket data is as we expected */
                    testresult = 1;
                }
                goto end;
            }
        }
    }

end:
    SSL_free(con);
    SSL_CTX_free(ctx);
    SSL_SESSION_free(sess);
    BIO_free(sessbio);

    return testresult;
}

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    ADD_ALL_TESTS(test_client_hello, TOTAL_NUM_TESTS);
    return 1;
}
