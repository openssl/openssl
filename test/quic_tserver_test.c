/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/bio.h>
#include "internal/common.h"
#include "internal/sockets.h"
#include "internal/quic_tserver.h"
#include "internal/time.h"
#include "testutil.h"

static const char msg1[] = "The quick brown fox jumped over the lazy dogs.";
static char msg2[1024], msg3[1024];

static int is_want(SSL *s, int ret)
{
    int ec = SSL_get_error(s, ret);
    return ec == SSL_ERROR_WANT_READ || ec == SSL_ERROR_WANT_WRITE;
}

static int test_tserver(void)
{
    int testresult = 0, ret;
    int s_fd = -1, c_fd = -1;
    BIO *s_net_bio = NULL, *s_net_bio_own = NULL;
    BIO *c_net_bio = NULL, *c_net_bio_own = NULL;
    QUIC_TSERVER_ARGS tserver_args = {0};
    QUIC_TSERVER *tserver = NULL;
    BIO_ADDR *s_addr_ = NULL;
    struct in_addr ina = {0};
    union BIO_sock_info_u s_info = {0};
    SSL_CTX *c_ctx = NULL;
    SSL *c_ssl = NULL;
    short port = 8186;
    int c_connected = 0, c_write_done = 0, c_begin_read = 0;
    size_t l = 0, s_total_read = 0, s_total_written = 0, c_total_read = 0;
    int s_begin_write = 0;
    OSSL_TIME start_time;

    ina.s_addr = htonl(0x7f000001UL);

    /* Setup test server. */
    s_fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(s_fd, 0))
        goto err;

    if (!TEST_true(BIO_socket_nbio(s_fd, 1)))
        goto err;

    if (!TEST_ptr(s_addr_ = BIO_ADDR_new()))
        goto err;

    if (!TEST_true(BIO_ADDR_rawmake(s_addr_, AF_INET, &ina, sizeof(ina),
                                    htons(port))))
        goto err;

    if (!TEST_true(BIO_bind(s_fd, s_addr_, 0)))
        goto err;

    s_info.addr = s_addr_;
    if (!TEST_true(BIO_sock_info(s_fd, BIO_SOCK_INFO_ADDRESS, &s_info)))
        goto err;

    if (!TEST_int_gt(BIO_ADDR_rawport(s_addr_), 0))
        goto err;

    if (!TEST_ptr(s_net_bio = s_net_bio_own = BIO_new_dgram(s_fd, 0)))
        goto err;

    if (!BIO_up_ref(s_net_bio))
        goto err;

    tserver_args.net_rbio = s_net_bio;
    tserver_args.net_wbio = s_net_bio;

    if (!TEST_ptr(tserver = ossl_quic_tserver_new(&tserver_args))) {
        BIO_free(s_net_bio);
        goto err;
    }

    s_net_bio_own = NULL;

    /* Setup test client. */
    c_fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(c_fd, 0))
        goto err;

    if (!TEST_true(BIO_socket_nbio(c_fd, 1)))
        goto err;

    if (!TEST_ptr(c_net_bio = c_net_bio_own = BIO_new_dgram(c_fd, 0)))
        goto err;

    if (!BIO_dgram_set_peer(c_net_bio, s_addr_))
        goto err;

    if (!TEST_ptr(c_ctx = SSL_CTX_new(OSSL_QUIC_client_method())))
        goto err;

    if (!TEST_ptr(c_ssl = SSL_new(c_ctx)))
        goto err;

    /* Takes ownership of our reference to the BIO. */
    SSL_set0_rbio(c_ssl, c_net_bio);

    /* Get another reference to be transferred in the SSL_set0_wbio call. */
    if (!TEST_true(BIO_up_ref(c_net_bio))) {
        c_net_bio_own = NULL; /* SSL_free will free the first reference. */
        goto err;
    }

    SSL_set0_wbio(c_ssl, c_net_bio);
    c_net_bio_own = NULL;

    if (!TEST_true(SSL_set_blocking_mode(c_ssl, 0)))
        goto err;

    start_time = ossl_time_now();

    for (;;) {
        if (ossl_time_compare(ossl_time_subtract(ossl_time_now(), start_time),
                              ossl_ms2time(1000)) >= 0) {
            TEST_error("timeout while attempting QUIC server test");
            goto err;
        }

        ret = SSL_connect(c_ssl);
        if (!TEST_true(ret == 1 || is_want(c_ssl, ret)))
            goto err;

        if (ret == 1)
            c_connected = 1;

        if (c_connected && !c_write_done) {
            if (!TEST_int_eq(SSL_write(c_ssl, msg1, sizeof(msg1) - 1),
                             (int)sizeof(msg1) - 1))
                goto err;

            c_write_done = 1;
        }

        if (c_connected && c_write_done && s_total_read < sizeof(msg1) - 1) {
            if (!TEST_true(ossl_quic_tserver_read(tserver,
                                                  (unsigned char *)msg2 + s_total_read,
                                                  sizeof(msg2) - s_total_read, &l)))
                goto err;

            s_total_read += l;
            if (s_total_read == sizeof(msg1) - 1) {
                if (!TEST_mem_eq(msg1, sizeof(msg1) - 1,
                                 msg2, sizeof(msg1) - 1))
                    goto err;

                s_begin_write = 1;
            }
        }

        if (s_begin_write && s_total_written < sizeof(msg1) - 1) {
            if (!TEST_true(ossl_quic_tserver_write(tserver,
                                                   (unsigned char *)msg2 + s_total_written,
                                                   sizeof(msg1) - 1 - s_total_written, &l)))
                goto err;

            s_total_written += l;

            if (s_total_written == sizeof(msg1) - 1)
                c_begin_read = 1;
        }

        if (c_begin_read && c_total_read < sizeof(msg1) - 1) {
            ret = SSL_read_ex(c_ssl, msg3 + c_total_read,
                              sizeof(msg1) - 1 - c_total_read, &l);
            if (!TEST_true(ret == 1 || is_want(c_ssl, ret)))
                goto err;

            c_total_read += l;

            if (c_total_read == sizeof(msg1) - 1) {
                if (!TEST_mem_eq(msg1, sizeof(msg1) - 1,
                                 msg3, c_total_read))
                    goto err;

                /* MATCH */
                break;
            }
        }

        /*
         * This is inefficient because we spin until things work without
         * blocking but this is just a test.
         */
        SSL_tick(c_ssl);
        ossl_quic_tserver_tick(tserver);
    }

    testresult = 1;
err:
    SSL_free(c_ssl);
    SSL_CTX_free(c_ctx);
    ossl_quic_tserver_free(tserver);
    BIO_ADDR_free(s_addr_);
    BIO_free(s_net_bio_own);
    BIO_free(c_net_bio_own);
    if (s_fd >= 0)
        BIO_closesocket(s_fd);
    if (c_fd >= 0)
        BIO_closesocket(c_fd);
    return testresult;
}

int setup_tests(void)
{
    ADD_TEST(test_tserver);
    return 1;
}
