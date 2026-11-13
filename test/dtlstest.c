/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"

static char *cert = NULL;
static char *privkey = NULL;
static unsigned int timer_cb_count;

#define NUM_TESTS 2

#define DUMMY_CERT_STATUS_LEN 12

static unsigned char certstatus[] = {
    SSL3_RT_HANDSHAKE, /* Content type */
    0xfe, 0xfd, /* Record version */
    0, 1, /* Epoch */
    0, 0, 0, 0, 0, 0x0f, /* Record sequence number */
    0, DTLS1_HM_HEADER_LENGTH + DUMMY_CERT_STATUS_LEN - 2,
    SSL3_MT_CERTIFICATE_STATUS, /* Cert Status handshake message type */
    0, 0, DUMMY_CERT_STATUS_LEN, /* Message len */
    0, 5, /* Message sequence */
    0, 0, 0, /* Fragment offset */
    0, 0, DUMMY_CERT_STATUS_LEN - 2, /* Fragment len */
    0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80 /* Dummy data */
};

#define RECORD_SEQUENCE 10

static const char dummy_cookie[] = "0123456";

static int generate_cookie_cb(SSL *ssl, unsigned char *cookie,
    unsigned int *cookie_len)
{
    memcpy(cookie, dummy_cookie, sizeof(dummy_cookie));
    *cookie_len = sizeof(dummy_cookie);
    return 1;
}

static int verify_cookie_cb(SSL *ssl, const unsigned char *cookie,
    unsigned int cookie_len)
{
    return TEST_mem_eq(cookie, cookie_len, dummy_cookie, sizeof(dummy_cookie));
}

static unsigned int timer_cb(SSL *s, unsigned int timer_us)
{
    ++timer_cb_count;
    if (timer_us == 0)
        return 50000;
    else
        return 2 * timer_us;
}

static int test_dtls_unprocessed(int testidx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl1 = NULL, *clientssl1 = NULL;
    BIO *c_to_s_fbio, *c_to_s_mempacket;
    int testresult = 0;

    timer_cb_count = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifndef OPENSSL_NO_DTLS1_2
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA")))
        goto end;
#else
    /* Default sigalgs are SHA1 based in <DTLS1.2 which is in security level 0 */
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "AES128-SHA:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx,
            "AES128-SHA:@SECLEVEL=0")))
        goto end;
#endif

    c_to_s_fbio = BIO_new(bio_f_tls_dump_filter());
    if (!TEST_ptr(c_to_s_fbio))
        goto end;

    /* BIO is freed by create_ssl_connection on error */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl1, &clientssl1,
            NULL, c_to_s_fbio)))
        goto end;

    DTLS_set_timer_cb(clientssl1, timer_cb);

    if (testidx == 1)
        certstatus[RECORD_SEQUENCE] = 0xff;

    /*
     * Inject a dummy record from the next epoch. In test 0, this should never
     * get used because the message sequence number is too big. In test 1 we set
     * the record sequence number to be way off in the future.
     */
    c_to_s_mempacket = SSL_get_wbio(clientssl1);
    c_to_s_mempacket = BIO_next(c_to_s_mempacket);
    mempacket_test_inject(c_to_s_mempacket, (char *)certstatus,
        sizeof(certstatus), 1, INJECT_PACKET_IGNORE_REC_SEQ);

    /*
     * Create the connection. We use "create_bare_ssl_connection" here so that
     * we can force the connection to not do "SSL_read" once partly connected.
     * We don't want to accidentally read the dummy records we injected because
     * they will fail to decrypt.
     */
    if (!TEST_true(create_bare_ssl_connection(serverssl1, clientssl1,
            SSL_ERROR_NONE, 0, 0)))
        goto end;

    if (timer_cb_count == 0) {
        printf("timer_callback was not called.\n");
        goto end;
    }

    testresult = 1;
end:
    SSL_free(serverssl1);
    SSL_free(clientssl1);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

/* One record for the cookieless initial ClientHello */
#define CLI_TO_SRV_COOKIE_EXCH 1

/*
 * In a resumption handshake we use 2 records for the initial ClientHello in
 * this test because we are using a very small MTU and the ClientHello is
 * bigger than in the non resumption case.
 */
#define CLI_TO_SRV_RESUME_COOKIE_EXCH 2
#define SRV_TO_CLI_COOKIE_EXCH 1

#define CLI_TO_SRV_EPOCH_0_RECS 3
#define CLI_TO_SRV_EPOCH_1_RECS 1
#if !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_DH)
#define SRV_TO_CLI_EPOCH_0_RECS 10
#else
/*
 * In this case we have no ServerKeyExchange message, because we don't have
 * ECDHE or DHE. When it is present it gets fragmented into 3 records in this
 * test.
 */
#define SRV_TO_CLI_EPOCH_0_RECS 9
#endif
#define SRV_TO_CLI_EPOCH_1_RECS 1
#define TOTAL_FULL_HAND_RECORDS \
    (CLI_TO_SRV_COOKIE_EXCH + SRV_TO_CLI_COOKIE_EXCH + CLI_TO_SRV_EPOCH_0_RECS + CLI_TO_SRV_EPOCH_1_RECS + SRV_TO_CLI_EPOCH_0_RECS + SRV_TO_CLI_EPOCH_1_RECS)

#define CLI_TO_SRV_RESUME_EPOCH_0_RECS 3
#define CLI_TO_SRV_RESUME_EPOCH_1_RECS 1
#define SRV_TO_CLI_RESUME_EPOCH_0_RECS 2
#define SRV_TO_CLI_RESUME_EPOCH_1_RECS 1
#define TOTAL_RESUME_HAND_RECORDS \
    (CLI_TO_SRV_RESUME_COOKIE_EXCH + SRV_TO_CLI_COOKIE_EXCH + CLI_TO_SRV_RESUME_EPOCH_0_RECS + CLI_TO_SRV_RESUME_EPOCH_1_RECS + SRV_TO_CLI_RESUME_EPOCH_0_RECS + SRV_TO_CLI_RESUME_EPOCH_1_RECS)

#define TOTAL_RECORDS (TOTAL_FULL_HAND_RECORDS + TOTAL_RESUME_HAND_RECORDS)

/*
 * We are assuming a ServerKeyExchange message is sent in this test. If we don't
 * have either DH or EC, then it won't be
 */
#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_EC)
static int test_dtls_drop_records(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO *c_to_s_fbio, *mempackbio;
    int testresult = 0;
    int epoch = 0;
    SSL_SESSION *sess = NULL;
    int cli_to_srv_cookie, cli_to_srv_epoch0, cli_to_srv_epoch1;
    int srv_to_cli_epoch0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifdef OPENSSL_NO_DTLS1_2
    /* Default sigalgs are SHA1 based in <DTLS1.2 which is in security level 0 */
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "DEFAULT:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx,
            "DEFAULT:@SECLEVEL=0")))
        goto end;
#endif

    if (!TEST_true(SSL_CTX_set_dh_auto(sctx, 1)))
        goto end;

    SSL_CTX_set_options(sctx, SSL_OP_COOKIE_EXCHANGE);
    SSL_CTX_set_cookie_generate_cb(sctx, generate_cookie_cb);
    SSL_CTX_set_cookie_verify_cb(sctx, verify_cookie_cb);

    if (idx >= TOTAL_FULL_HAND_RECORDS) {
        /* We're going to do a resumption handshake. Get a session first. */
        if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                SSL_ERROR_NONE))
            || !TEST_ptr(sess = SSL_get1_session(clientssl)))
            goto end;

        SSL_shutdown(clientssl);
        SSL_shutdown(serverssl);
        SSL_free(serverssl);
        SSL_free(clientssl);
        serverssl = clientssl = NULL;

        cli_to_srv_epoch0 = CLI_TO_SRV_RESUME_EPOCH_0_RECS;
        cli_to_srv_epoch1 = CLI_TO_SRV_RESUME_EPOCH_1_RECS;
        srv_to_cli_epoch0 = SRV_TO_CLI_RESUME_EPOCH_0_RECS;
        cli_to_srv_cookie = CLI_TO_SRV_RESUME_COOKIE_EXCH;
        idx -= TOTAL_FULL_HAND_RECORDS;
    } else {
        cli_to_srv_epoch0 = CLI_TO_SRV_EPOCH_0_RECS;
        cli_to_srv_epoch1 = CLI_TO_SRV_EPOCH_1_RECS;
        srv_to_cli_epoch0 = SRV_TO_CLI_EPOCH_0_RECS;
        cli_to_srv_cookie = CLI_TO_SRV_COOKIE_EXCH;
    }

    c_to_s_fbio = BIO_new(bio_f_tls_dump_filter());
    if (!TEST_ptr(c_to_s_fbio))
        goto end;

    /* BIO is freed by create_ssl_connection on error */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, c_to_s_fbio)))
        goto end;

    if (sess != NULL) {
        if (!TEST_true(SSL_set_session(clientssl, sess)))
            goto end;
    }

    DTLS_set_timer_cb(clientssl, timer_cb);
    DTLS_set_timer_cb(serverssl, timer_cb);

    /* Work out which record to drop based on the test number */
    if (idx >= cli_to_srv_cookie + cli_to_srv_epoch0 + cli_to_srv_epoch1) {
        mempackbio = SSL_get_wbio(serverssl);
        idx -= cli_to_srv_cookie + cli_to_srv_epoch0 + cli_to_srv_epoch1;
        if (idx >= SRV_TO_CLI_COOKIE_EXCH + srv_to_cli_epoch0) {
            epoch = 1;
            idx -= SRV_TO_CLI_COOKIE_EXCH + srv_to_cli_epoch0;
        }
    } else {
        mempackbio = SSL_get_wbio(clientssl);
        if (idx >= cli_to_srv_cookie + cli_to_srv_epoch0) {
            epoch = 1;
            idx -= cli_to_srv_cookie + cli_to_srv_epoch0;
        }
        mempackbio = BIO_next(mempackbio);
    }
    BIO_ctrl(mempackbio, MEMPACKET_CTRL_SET_DROP_EPOCH, epoch, NULL);
    BIO_ctrl(mempackbio, MEMPACKET_CTRL_SET_DROP_REC, idx, NULL);

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    if (sess != NULL && !TEST_true(SSL_session_reused(clientssl)))
        goto end;

    /* If the test did what we planned then it should have dropped a record */
    if (!TEST_int_eq((int)BIO_ctrl(mempackbio, MEMPACKET_CTRL_GET_DROP_REC, 0,
                         NULL),
            -1))
        goto end;

    testresult = 1;
end:
    SSL_SESSION_free(sess);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
#endif /* !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_EC) */

static int test_cookie(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

    SSL_CTX_set_options(sctx, SSL_OP_COOKIE_EXCHANGE);
    SSL_CTX_set_cookie_generate_cb(sctx, generate_cookie_cb);
    SSL_CTX_set_cookie_verify_cb(sctx, verify_cookie_cb);

#ifdef OPENSSL_NO_DTLS1_2
    /* Default sigalgs are SHA1 based in <DTLS1.2 which is in security level 0 */
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "DEFAULT:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx,
            "DEFAULT:@SECLEVEL=0")))
        goto end;
#endif

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

static int test_dtls_duplicate_records(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifdef OPENSSL_NO_DTLS1_2
    /* Default sigalgs are SHA1 based in <DTLS1.2 which is in security level 0 */
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "DEFAULT:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx,
            "DEFAULT:@SECLEVEL=0")))
        goto end;
#endif

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(clientssl, timer_cb);
    DTLS_set_timer_cb(serverssl, timer_cb);

    BIO_ctrl(SSL_get_wbio(clientssl), MEMPACKET_CTRL_SET_DUPLICATE_REC, 1, NULL);
    BIO_ctrl(SSL_get_wbio(serverssl), MEMPACKET_CTRL_SET_DUPLICATE_REC, 1, NULL);

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

/*
 * Test just sending a Finished message as the first message. Should fail due
 * to an unexpected message.
 */
static int test_just_finished(void)
{
    int testresult = 0, ret;
    SSL_CTX *sctx = NULL;
    SSL *serverssl = NULL;
    BIO *rbio = NULL, *wbio = NULL, *sbio = NULL;
    unsigned char buf[] = {
        /* Record header */
        SSL3_RT_HANDSHAKE, /* content type */
        (DTLS1_2_VERSION >> 8) & 0xff, /* protocol version hi byte */
        DTLS1_2_VERSION & 0xff, /* protocol version lo byte */
        0, 0, /* epoch */
        0, 0, 0, 0, 0, 0, /* record sequence */
        0, DTLS1_HM_HEADER_LENGTH + SHA_DIGEST_LENGTH, /* record length */

        /* Message header */
        SSL3_MT_FINISHED, /* message type */
        0, 0, SHA_DIGEST_LENGTH, /* message length */
        0, 0, /* message sequence */
        0, 0, 0, /* fragment offset */
        0, 0, SHA_DIGEST_LENGTH, /* fragment length */

        /* Message body */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            NULL, 0, 0,
            &sctx, NULL, cert, privkey)))
        return 0;

#ifdef OPENSSL_NO_DTLS1_2
    /* DTLSv1 is not allowed at the default security level */
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "DEFAULT:@SECLEVEL=0")))
        goto end;
#endif

    serverssl = SSL_new(sctx);
    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());

    if (!TEST_ptr(serverssl) || !TEST_ptr(rbio) || !TEST_ptr(wbio))
        goto end;

    sbio = rbio;
    SSL_set0_rbio(serverssl, rbio);
    SSL_set0_wbio(serverssl, wbio);
    rbio = wbio = NULL;
    DTLS_set_timer_cb(serverssl, timer_cb);

    if (!TEST_int_eq(BIO_write(sbio, buf, sizeof(buf)), sizeof(buf)))
        goto end;

    /* We expect the attempt to process the message to fail */
    if (!TEST_int_le(ret = SSL_accept(serverssl), 0))
        goto end;

    /* Check that we got the error we were expecting */
    if (!TEST_int_eq(SSL_get_error(serverssl, ret), SSL_ERROR_SSL))
        goto end;

    if (!TEST_int_eq(ERR_GET_REASON(ERR_get_error()), SSL_R_UNEXPECTED_MESSAGE))
        goto end;

    testresult = 1;
end:
    BIO_free(rbio);
    BIO_free(wbio);
    SSL_free(serverssl);
    SSL_CTX_free(sctx);

    return testresult;
}

/*
 * Test that swapping later records before Finished or CCS still works
 * Test 0: Test receiving a handshake record early from next epoch on server side
 * Test 1: Test receiving a handshake record early from next epoch on client side
 * Test 2: Test receiving an app data record early from next epoch on client side
 * Test 3: Test receiving an app data before Finished on client side
 */
static int test_swap_records(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    int testresult = 0;
    BIO *bio;
    char msg[] = { 0x00, 0x01, 0x02, 0x03 };
    char buf[10];

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifndef OPENSSL_NO_DTLS1_2
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA")))
        goto end;
#else
    /* Default sigalgs are SHA1 based in <DTLS1.2 which is in security level 0 */
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "AES128-SHA:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx,
            "AES128-SHA:@SECLEVEL=0")))
        goto end;
#endif

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl,
            NULL, NULL)))
        goto end;

    /* Send flight 1: ClientHello */
    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    /* Recv flight 1, send flight 2: ServerHello, Certificate, ServerHelloDone */
    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    /* Recv flight 2, send flight 3: ClientKeyExchange, CCS, Finished */
    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (idx == 0) {
        /* Swap Finished and CCS within the datagram */
        bio = SSL_get_wbio(cssl);
        if (!TEST_ptr(bio)
            || !TEST_true(mempacket_swap_epoch(bio)))
            goto end;
    }

    /* Recv flight 3, send flight 4: datagram 0(NST, CCS) datagram 1(Finished) */
    if (!TEST_int_gt(SSL_accept(sssl), 0))
        goto end;

    /* Send flight 4 (cont'd): datagram 2(app data) */
    if (!TEST_int_eq(SSL_write(sssl, msg, sizeof(msg)), (int)sizeof(msg)))
        goto end;

    bio = SSL_get_wbio(sssl);
    if (!TEST_ptr(bio))
        goto end;
    if (idx == 1) {
        /* Finished comes before NST/CCS */
        if (!TEST_true(mempacket_move_packet(bio, 0, 1)))
            goto end;
    } else if (idx == 2) {
        /* App data comes before NST/CCS */
        if (!TEST_true(mempacket_move_packet(bio, 0, 2)))
            goto end;
    } else if (idx == 3) {
        /* App data comes before Finished */
        bio = SSL_get_wbio(sssl);
        if (!TEST_true(mempacket_move_packet(bio, 1, 2)))
            goto end;
    }

    /*
     * Recv flight 4 (datagram 1): NST, CCS, + flight 5: app data
     *      + flight 4 (datagram 2): Finished
     */
    if (!TEST_int_gt(SSL_connect(cssl), 0))
        goto end;

    if (idx == 0 || idx == 1) {
        /* App data was not received early, so it should not be pending */
        if (!TEST_int_eq(SSL_pending(cssl), 0)
            || !TEST_false(SSL_has_pending(cssl)))
            goto end;

    } else {
        /* We received the app data early so it should be buffered already */
        if (!TEST_int_eq(SSL_pending(cssl), (int)sizeof(msg))
            || !TEST_true(SSL_has_pending(cssl)))
            goto end;
    }

    /*
     * Recv flight 5 (app data)
     */
    if (!TEST_int_eq(SSL_read(cssl, buf, sizeof(buf)), (int)sizeof(msg)))
        goto end;

    testresult = 1;
end:
    SSL_free(cssl);
    SSL_free(sssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);

    return testresult;
}

static int test_duplicate_app_data(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    int testresult = 0;
    BIO *bio;
    char msg[] = { 0x00, 0x01, 0x02, 0x03 };
    char buf[10];
    int ret;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifndef OPENSSL_NO_DTLS1_2
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA")))
        goto end;
#else
    /* Default sigalgs are SHA1 based in <DTLS1.2 which is in security level 0 */
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "AES128-SHA:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx,
            "AES128-SHA:@SECLEVEL=0")))
        goto end;
#endif

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl,
            NULL, NULL)))
        goto end;

    /* Send flight 1: ClientHello */
    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    /* Recv flight 1, send flight 2: ServerHello, Certificate, ServerHelloDone */
    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    /* Recv flight 2, send flight 3: ClientKeyExchange, CCS, Finished */
    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    /* Recv flight 3, send flight 4: datagram 0(NST, CCS) datagram 1(Finished) */
    if (!TEST_int_gt(SSL_accept(sssl), 0))
        goto end;

    bio = SSL_get_wbio(sssl);
    if (!TEST_ptr(bio))
        goto end;

    /*
     * Send flight 4 (cont'd): datagram 2(app data)
     * + datagram 3 (app data duplicate)
     */
    if (!TEST_int_eq(SSL_write(sssl, msg, sizeof(msg)), (int)sizeof(msg)))
        goto end;

    if (!TEST_true(mempacket_dup_last_packet(bio)))
        goto end;

    /* App data comes before NST/CCS */
    if (!TEST_true(mempacket_move_packet(bio, 0, 2)))
        goto end;

    /*
     * Recv flight 4 (datagram 2): app data + flight 4 (datagram 0): NST, CCS, +
     *      + flight 4 (datagram 1): Finished
     */
    if (!TEST_int_gt(SSL_connect(cssl), 0))
        goto end;

    /*
     * Read flight 4 (app data)
     */
    if (!TEST_int_eq(SSL_read(cssl, buf, sizeof(buf)), (int)sizeof(msg)))
        goto end;

    if (!TEST_mem_eq(buf, sizeof(msg), msg, sizeof(msg)))
        goto end;

    /*
     * Read flight 4, datagram 3. We expect the duplicated app data to have been
     * dropped, with no more data available
     */
    if (!TEST_int_le(ret = SSL_read(cssl, buf, sizeof(buf)), 0)
        || !TEST_int_eq(SSL_get_error(cssl, ret), SSL_ERROR_WANT_READ))
        goto end;

    testresult = 1;
end:
    SSL_free(cssl);
    SSL_free(sssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);

    return testresult;
}

/*
 * frag_bio and the four retransmit tests below need DTLS1.2
 */
#ifndef OPENSSL_NO_DTLS1_2

/*
 * Number of times the retransmit timer is fired while a write is parked, in
 * each of the four tests below
 */
#define NUM_RETRANSMITS 3

typedef struct {
    BIO *bio;
    int allowed; /* number of fragment writes to let through before suspending */
    int write_calls; /* number of times frag_write() has been invoked at all */
} frag_bio;

/*
 * Each call to this function corresponds to exactly one DTLS fragment being
 * handed to the BIO by dtls1_do_write(). Once |allowed| fragments have been
 * let through, every further write suspends (WANT_WRITE) until the test
 * bumps |allowed| again.
 */
static int frag_write(BIO *bio, const char *buf, size_t len, size_t *written)
{
    frag_bio *f = BIO_get_data(bio);

    BIO_clear_retry_flags(bio);

    f->write_calls++;

    if (f->allowed <= 0) {
        BIO_set_retry_write(bio);
        *written = 0;
        return 0;
    }
    f->allowed--;

    if (!BIO_write_ex(f->bio, buf, len, written)) {
        fprintf(stderr, "Failed to send data via BIO_write_ex\n");
        return 0;
    }

    return 1;
}

static int frag_read(BIO *bio, char *buf, size_t buf_len, size_t *readbytes)
{
    frag_bio *f = BIO_get_data(bio);
    return BIO_read_ex(f->bio, buf, buf_len, readbytes);
}

static long frag_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    frag_bio *f = BIO_get_data(bio);
    return BIO_ctrl(f->bio, cmd, num, ptr);
}

static int frag_puts(BIO *bio, const char *str)
{
    size_t written;
    return frag_write(bio, str, strlen(str), &written) ? (int)written : -1;
}

static int frag_create(BIO *bio)
{
    frag_bio *f = OPENSSL_zalloc(sizeof(*f));
    if (f == NULL)
        return 0;
    BIO_set_data(bio, f);
    BIO_set_init(bio, 1);
    return 1;
}

static int frag_destroy(BIO *bio)
{
    frag_bio *f = BIO_get_data(bio);
    if (f == NULL)
        return 1;

    BIO_free(f->bio);
    OPENSSL_free(f);
    BIO_set_data(bio, NULL);
    BIO_set_init(bio, 0);
    return 1;
}

static BIO_METHOD *frag_method(void)
{
    static BIO_METHOD *m = NULL;
    if (m == NULL) {
        m = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_TYPE_FILTER, "fragment-limited dgram");
        BIO_meth_set_write_ex(m, frag_write);
        BIO_meth_set_read_ex(m, frag_read);
        BIO_meth_set_ctrl(m, frag_ctrl);
        BIO_meth_set_puts(m, frag_puts);
        BIO_meth_set_create(m, frag_create);
        BIO_meth_set_destroy(m, frag_destroy);
    }
    return m;
}

static BIO *frag_new(BIO *bio, int allowed)
{
    BIO *b = BIO_new(frag_method());
    frag_bio *f;
    if (b == NULL) {
        BIO_free(bio);
        return NULL;
    }
    f = BIO_get_data(b);
    f->bio = bio;
    f->allowed = allowed;
    return b;
}

/*
 * DTLS1.2 only. Exercises dtls1_handle_timeout()'s write_state guard (see
 * d1_lib.c): while a write is parked mid-flight (WANT_WRITE, suspended here
 * by a fragment-limiting BIO), a firing retransmit timer must not touch the
 * retransmit queue at all - dtls1_retransmit_sent_messages() should never be
 * entered, since retransmitting a message concurrently with the live write
 * reusing the very same s->init_off/s->init_num/s->d1->w_msg fields would
 * corrupt whichever write resumes second.
 *
 * Without the guard, letting that retransmit run ClientHello to completion
 * while its own live write is still parked resets s->init_off/s->init_num
 * to 0/0 out from under that write - so when the app resumes with
 * SSL_connect(), dtls1_do_write() re-enters believing s->init_off == 0 means
 * a brand new message is starting, when s->init_num no longer matches
 * ClientHello's real length the way a fresh message's would - hitting an
 * internal entry assertion and calling OPENSSL_die()/abort().
 *
 * The client never calls SSL_connect() again until the very end, so the
 * server is never driven far enough to respond - there's nothing to
 * retransmit ClientHello against except the timer, driven purely by
 * DTLSv1_get_timeout()/DTLSv1_handle_timeout().
 */
static int test_dtls_client_retransmit(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int testresult = 0;
    int ret, err, i;
    struct timeval tv;
    static unsigned char alpn[750];
    size_t j, used = 0;
    BIO *c_to_s_bio = NULL;
    BIO *frag_wbio;
    frag_bio *fb;
    int write_calls_before;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        return 0;

    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);

    /* Pad the ClientHello out via ALPN so it needs multiple fragments. */
    for (j = 0; j < 3; j++) {
        char name[250];
        int n = snprintf(name, sizeof(name),
            "proto-%04u-%s", (unsigned int)j,
            "padpadpadpadpadpadpadpadpadpadpadpadpadpadpad"
            "padpadpadpadpadpadpadpadpadpadpadpadpadpadpad"
            "padpadpadpadpadpadpadpadpadpadpadpadpadpadpad"
            "padpadpadpadpadpadpadpadpadpadpadpadpadpadpad"
            "padpadpadpadpadpadpadpadpadpadpadpadpadpad");

        if (!TEST_int_ge(n, 0) || !TEST_size_t_lt((size_t)n, sizeof(name)))
            goto end;
        if (!TEST_size_t_le(used + 1 + (size_t)n, sizeof(alpn)))
            goto end;

        alpn[used++] = (unsigned char)n;
        memcpy(alpn + used, name, (size_t)n);
        used += (size_t)n;
    }
    if (!TEST_false(SSL_CTX_set_alpn_protos(cctx, alpn, (unsigned int)used)))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    /*
     * Pin the MTU so fragmentation of the ClientHello (padded out via ALPN
     * above) is deterministic. SSL_OP_NO_QUERY_MTU stops dtls1_query_mtu()
     * from overriding this with a value queried from the BIO.
     */
    SSL_set_options(clientssl, SSL_OP_NO_QUERY_MTU);
    if (!TEST_true(SSL_set_mtu(clientssl, 256)))
        goto end;

    /*
     * Wrap the client's write BIO in our fragment-limiting filter, initially
     * allowing only the ClientHello's first fragment through. SSL_get_wbio()
     * is a borrowed reference, and SSL_set0_wbio() will free whatever the old
     * wbio pointer was as soon as we install the replacement - so we need our
     * own ref on the underlying bio before frag_new() stores it internally,
     * otherwise the wrapper is left holding a dangling pointer.
     */
    c_to_s_bio = SSL_get_wbio(clientssl);

    if (!TEST_ptr(c_to_s_bio) || !TEST_true(BIO_up_ref(c_to_s_bio)))
        goto end;

    frag_wbio = frag_new(c_to_s_bio, 1);
    if (!TEST_ptr(frag_wbio)) {
        BIO_free(c_to_s_bio);
        goto end;
    }
    fb = BIO_get_data(frag_wbio);

    SSL_set0_wbio(clientssl, frag_wbio);

    DTLS_set_timer_cb(clientssl, timer_cb);

    /*
     * Flight 1: frag_wbio's budget of 1 write buys exactly ClientHello's
     * first fragment - that's all that goes out. The next write (its
     * second fragment) is what actually suspends, leaving write_state
     * parked at WRITE_STATE_SEND, waiting to resume ClientHello.
     */
    ret = SSL_connect(clientssl);
    if (!TEST_int_le(ret, 0)
        || !TEST_int_eq(SSL_get_error(clientssl, ret), SSL_ERROR_WANT_WRITE))
        goto end;

    /*
     * Let the retransmit timer fire, NUM_RETRANSMITS times, while the write
     * above is still parked. fb->allowed = 100 so our custom BIO isn't what
     * would block a retransmit, if one were sent. frag_write()'s call
     * counter shouldn't move at all, round after round.
     */
    fb->allowed = 100;

    for (i = 0; i < NUM_RETRANSMITS; i++) {
        write_calls_before = fb->write_calls;

        if (!TEST_int_gt((int)DTLSv1_get_timeout(clientssl, &tv), 0))
            goto end;

        /* Wait for the retransmit timer to actually expire */
        OSSL_sleep((uint64_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000) + 10);

        if (!TEST_int_ge((int)DTLSv1_handle_timeout(clientssl), 0))
            goto end;

        if (!TEST_int_eq(fb->write_calls, write_calls_before))
            goto end;
    }

    /*
     * Resume the original suspended write. This is the call expected to
     * hit the entry assertion described above if the guard weren't there.
     */
    ret = SSL_connect(clientssl);
    err = SSL_get_error(clientssl, ret);

    /*
     * If we get here at all (i.e. we didn't just abort()), the resume
     * should look like an ordinary handshake continuation - WANT_READ or
     * WANT_WRITE, not an internal failure.
     */
    if (!TEST_false(err == SSL_ERROR_SSL || err == SSL_ERROR_SYSCALL))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

/*
 * DTLS1.2 only. Server-side counterpart to test_dtls_client_retransmit():
 * same write_state guard, but Certificate suspends mid-write during the
 * server's flight instead of ClientHello. The cipher is pinned to a
 * static-RSA suite so the flight is just ServerHello + Certificate +
 * ServerHelloDone (no ServerKeyExchange); with a 256 byte MTU, ServerHello
 * fits in a single fragment but Certificate does not.
 *
 * The client never calls SSL_accept() again until the very end, so the
 * server is driven purely by DTLSv1_get_timeout()/DTLSv1_handle_timeout().
 */
static int test_dtls_server_retransmit(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int testresult = 0;
    int ret, err, i;
    struct timeval tv;
    BIO *s_to_c_bio = NULL;
    BIO *frag_wbio;
    frag_bio *fb;
    int write_calls_before;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        return 0;

    /* Static RSA cipher: no ServerKeyExchange, keeps the flight simple. */
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA")))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    /*
     * Pin the server's MTU so its flight fragments deterministically. The
     * client is left alone - its ClientHello is small and unfragmented.
     */
    SSL_set_options(serverssl, SSL_OP_NO_QUERY_MTU);
    if (!TEST_true(SSL_set_mtu(serverssl, 256)))
        goto end;

    /* Wrap only the server's write BIO in our fragment-limiting filter. */
    s_to_c_bio = SSL_get_wbio(serverssl);

    if (!TEST_ptr(s_to_c_bio) || !TEST_true(BIO_up_ref(s_to_c_bio)))
        goto end;

    /* Only let ServerHello and Certificate's first fragment out initially. */
    frag_wbio = frag_new(s_to_c_bio, 2);
    if (!TEST_ptr(frag_wbio)) {
        BIO_free(s_to_c_bio);
        goto end;
    }
    fb = BIO_get_data(frag_wbio);

    SSL_set0_wbio(serverssl, frag_wbio);

    DTLS_set_timer_cb(serverssl, timer_cb);

    /* Flight 1: the client sends its ClientHello without any restriction. */
    if (!TEST_int_le(SSL_connect(clientssl), 0))
        goto end;

    /*
     * Flight 2: frag_wbio's budget of 2 writes buys exactly ServerHello in
     * full plus the first fragment of Certificate - that's all that goes
     * out. The next write (Certificate's second fragment) is what actually
     * suspends, leaving write_state parked at WRITE_STATE_SEND, waiting to
     * resume Certificate specifically.
     */
    ret = SSL_accept(serverssl);
    if (!TEST_int_le(ret, 0)
        || !TEST_int_eq(SSL_get_error(serverssl, ret), SSL_ERROR_WANT_WRITE))
        goto end;

    /*
     * Let the retransmit timer fire, NUM_RETRANSMITS times, while the write
     * above is still parked. fb->allowed = 100 so our custom BIO isn't what
     * would block a retransmit, if one were sent. frag_write()'s call
     * counter shouldn't move at all, round after round.
     */
    fb->allowed = 100;

    for (i = 0; i < NUM_RETRANSMITS; i++) {
        write_calls_before = fb->write_calls;

        if (!TEST_int_gt((int)DTLSv1_get_timeout(serverssl, &tv), 0))
            goto end;

        OSSL_sleep((uint64_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000) + 10);

        if (!TEST_int_ge((int)DTLSv1_handle_timeout(serverssl), 0))
            goto end;

        if (!TEST_int_eq(fb->write_calls, write_calls_before))
            goto end;
    }

    /*
     * Resume the original suspended write. This is the call expected to
     * hit the entry assertion described in test_dtls_client_retransmit() if
     * the guard weren't there.
     */
    ret = SSL_accept(serverssl);
    err = SSL_get_error(serverssl, ret);

    /*
     * If we get here at all (i.e. we didn't just abort()), the resume
     * should look like an ordinary handshake continuation - WANT_READ or
     * WANT_WRITE, not an internal failure.
     */
    if (!TEST_false(err == SSL_ERROR_SSL || err == SSL_ERROR_SYSCALL))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

#endif

/* Confirm that we can create a connections using DTLSv1_listen() */
static int test_listen(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifdef OPENSSL_NO_DTLS1_2
    /* Default sigalgs are SHA1 based in <DTLS1.2 which is in security level 0 */
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "DEFAULT:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx,
            "DEFAULT:@SECLEVEL=0")))
        goto end;
#endif

    SSL_CTX_set_cookie_generate_cb(sctx, generate_cookie_cb);
    SSL_CTX_set_cookie_verify_cb(sctx, verify_cookie_cb);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(clientssl, timer_cb);
    DTLS_set_timer_cb(serverssl, timer_cb);

    /*
     * The last parameter to create_bare_ssl_connection() requests that
     * DTLSv1_listen() is used.
     */
    if (!TEST_true(create_bare_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE, 1, 1)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

/*
 * Handshake message reassembly: memory held for incomplete messages.
 *
 * A peer chooses the length a handshake message claims, and the memory held for
 * a message must depend on the bytes received for it, not on that claim. These
 * tests inject hand-built handshake fragments into a server and check how much
 * memory is held, and that what is held is freed.
 *
 * Memory is measured with an allocator installed by global_init(), which wraps
 * whatever allocator the test framework has installed.
 */

#define MEMTRK_HDR 16

static CRYPTO_malloc_fn memtrk_base_malloc;
static CRYPTO_realloc_fn memtrk_base_realloc;
static CRYPTO_free_fn memtrk_base_free;
static size_t memtrk_live_bytes;
static int memtrk_enabled;

/* The next allocation of memtrk_fail_size bytes fails, once, if armed */
static size_t memtrk_fail_size;
static int memtrk_fail_armed;
static int memtrk_fail_hits;

static int memtrk_should_fail(size_t num)
{
    if (!memtrk_fail_armed || num != memtrk_fail_size)
        return 0;
    memtrk_fail_armed = 0;
    memtrk_fail_hits++;
    return 1;
}

static void *memtrk_malloc(size_t num, const char *file, int line)
{
    unsigned char *p;

    if (num == 0 || memtrk_should_fail(num))
        return NULL;
    p = memtrk_base_malloc(num + MEMTRK_HDR, file, line);
    if (p == NULL)
        return NULL;
    memcpy(p, &num, sizeof(num));
    memtrk_live_bytes += num;
    return p + MEMTRK_HDR;
}

static void memtrk_free(void *ptr, const char *file, int line)
{
    unsigned char *p;
    size_t num;

    if (ptr == NULL)
        return;
    p = (unsigned char *)ptr - MEMTRK_HDR;
    memcpy(&num, p, sizeof(num));
    memtrk_live_bytes -= num;
    memtrk_base_free(p, file, line);
}

static void *memtrk_realloc(void *ptr, size_t num, const char *file, int line)
{
    unsigned char *p;
    size_t oldnum;

    if (ptr == NULL)
        return memtrk_malloc(num, file, line);
    if (num == 0) {
        memtrk_free(ptr, file, line);
        return NULL;
    }
    if (memtrk_should_fail(num))
        return NULL;
    p = (unsigned char *)ptr - MEMTRK_HDR;
    memcpy(&oldnum, p, sizeof(oldnum));
    p = memtrk_base_realloc(p, num + MEMTRK_HDR, file, line);
    if (p == NULL)
        return NULL;
    memtrk_live_bytes = memtrk_live_bytes - oldnum + num;
    memcpy(p, &num, sizeof(num));
    return p + MEMTRK_HDR;
}

/*
 * The library's default allocator dispatches through the installed functions:
 * wrapping it would call itself. The libc functions stand in for it.
 */
static void *memtrk_libc_malloc(size_t num, const char *file, int line)
{
    return malloc(num);
}

static void *memtrk_libc_realloc(void *ptr, size_t num, const char *file,
    int line)
{
    return realloc(ptr, num);
}

static void memtrk_libc_free(void *ptr, const char *file, int line)
{
    free(ptr);
}

int global_init(void)
{
    CRYPTO_get_mem_functions(&memtrk_base_malloc, &memtrk_base_realloc,
        &memtrk_base_free);
    if (memtrk_base_malloc == CRYPTO_malloc
        || memtrk_base_realloc == CRYPTO_realloc
        || memtrk_base_free == CRYPTO_free) {
        memtrk_base_malloc = memtrk_libc_malloc;
        memtrk_base_realloc = memtrk_libc_realloc;
        memtrk_base_free = memtrk_libc_free;
    }
    /* Not fatal: the tests which need the counter are skipped without it. */
    memtrk_enabled = CRYPTO_set_mem_functions(memtrk_malloc, memtrk_realloc, memtrk_free);
    return 1;
}

#ifndef OPENSSL_NO_DTLS1_2

/* Largest fragment body a test record carries */
#define REASM_MAX_BODY 1024
/* Memory held for a few small fragments, whatever message length they claim */
#define REASM_SMALL (8 * 1024)

typedef struct {
    SSL_CTX *sctx;
    SSL *ssl;
    BIO *rbio; /* owned by ssl; fragments are written to it */
    uint64_t recseq;
    int err; /* SSL error after the last record was read */
    size_t base; /* live bytes once the server is set up */
    size_t bio_base; /* of which the memory BIO's buffer */
} REASM_TEST_FIXTURE;

static void reasm_fx_free(REASM_TEST_FIXTURE *fx)
{
    SSL_free(fx->ssl);
    SSL_CTX_free(fx->sctx);
    fx->ssl = NULL;
    fx->sctx = NULL;
    fx->rbio = NULL;
}

/* Size of the buffer behind the memory BIO the fragments are written to */
static size_t reasm_bio_alloc(const REASM_TEST_FIXTURE *fx)
{
    BUF_MEM *bm = NULL;

    BIO_get_mem_ptr(fx->rbio, &bm);
    return bm != NULL ? bm->max : 0;
}

/* A DTLS 1.2 server with nothing yet received, reading from a memory BIO */
static int reasm_fx_new(REASM_TEST_FIXTURE *fx)
{
    BIO *rbio = NULL, *wbio = NULL;

    memset(fx, 0, sizeof(*fx));

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(), NULL,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &fx->sctx, NULL, cert, privkey))
        || !TEST_ptr(fx->ssl = SSL_new(fx->sctx))
        || !TEST_ptr(rbio = BIO_new(BIO_s_mem()))
        || !TEST_ptr(wbio = BIO_new(BIO_s_mem()))) {
        BIO_free(rbio);
        BIO_free(wbio);
        reasm_fx_free(fx);
        return 0;
    }

    fx->rbio = rbio;
    SSL_set0_rbio(fx->ssl, rbio);
    SSL_set0_wbio(fx->ssl, wbio);
    DTLS_set_timer_cb(fx->ssl, timer_cb);

    /* Let the server allocate its own state before the baseline is taken. */
    if (!TEST_int_eq(SSL_get_error(fx->ssl, SSL_accept(fx->ssl)),
            SSL_ERROR_WANT_READ)) {
        reasm_fx_free(fx);
        return 0;
    }
    fx->err = SSL_ERROR_WANT_READ;
    fx->base = memtrk_live_bytes;
    fx->bio_base = reasm_bio_alloc(fx);
    return 1;
}

/*
 * Memory the server holds beyond its baseline. The memory BIO the test writes
 * to keeps its buffer after the server has read from it, so the growth of that
 * buffer is not the server's and is not counted.
 */
static size_t reasm_held(const REASM_TEST_FIXTURE *fx)
{
    size_t used = memtrk_live_bytes > fx->base ? memtrk_live_bytes - fx->base
                                               : 0;
    size_t bio = reasm_bio_alloc(fx);
    size_t bio_growth = bio > fx->bio_base ? bio - fx->bio_base : 0;

    return used > bio_growth ? used - bio_growth : 0;
}

/* The message the server holds for a sequence number, if any */
static pitem *reasm_find(SSL_CONNECTION *sc, unsigned int seq)
{
    unsigned char seq64be[8] = { 0 };

    seq64be[6] = (unsigned char)(seq >> 8);
    seq64be[7] = (unsigned char)seq;
    return pqueue_find(sc->d1->buffered_messages, seq64be);
}

/* Largest message length the server accepts a claim for */
static size_t reasm_max_len(const REASM_TEST_FIXTURE *fx)
{
    return (size_t)SSL_get_max_cert_list(fx->ssl);
}

/*
 * Write one epoch 0 handshake record carrying a fragment of frag_len bytes of
 * fill to the server. The message length and the offsets are claims, not
 * checked.
 */
static int reasm_inject(REASM_TEST_FIXTURE *fx, unsigned char type,
    size_t msg_len, unsigned int msg_seq, size_t frag_off, size_t frag_len,
    unsigned char fill)
{
    unsigned char buf[DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH
        + REASM_MAX_BODY];
    const size_t reclen = DTLS1_HM_HEADER_LENGTH + frag_len;
    unsigned char *p = buf;
    uint64_t seq = fx->recseq++;
    int i;

    if (!TEST_size_t_le(frag_len, REASM_MAX_BODY))
        return 0;

    *p++ = SSL3_RT_HANDSHAKE;
    *p++ = (DTLS1_2_VERSION >> 8) & 0xff;
    *p++ = DTLS1_2_VERSION & 0xff;
    *p++ = 0; /* epoch */
    *p++ = 0;
    for (i = 5; i >= 0; i--)
        *p++ = (unsigned char)(seq >> (8 * i));
    *p++ = (unsigned char)(reclen >> 8);
    *p++ = (unsigned char)reclen;

    *p++ = type;
    *p++ = (unsigned char)(msg_len >> 16);
    *p++ = (unsigned char)(msg_len >> 8);
    *p++ = (unsigned char)msg_len;
    *p++ = (unsigned char)(msg_seq >> 8);
    *p++ = (unsigned char)msg_seq;
    *p++ = (unsigned char)(frag_off >> 16);
    *p++ = (unsigned char)(frag_off >> 8);
    *p++ = (unsigned char)frag_off;
    *p++ = (unsigned char)(frag_len >> 16);
    *p++ = (unsigned char)(frag_len >> 8);
    *p++ = (unsigned char)frag_len;
    memset(p, fill, frag_len);
    p += frag_len;

    if (!TEST_int_eq(BIO_write(fx->rbio, buf, (int)(p - buf)),
            (int)(p - buf)))
        return 0;

    /*
     * The memory BIO is a byte stream: a read can end part way through a record
     * if several are queued, and DTLS discards the partial record. Let the
     * server read each record as it is written, so every one arrives whole.
     * Once it has failed it is not driven again; the error is kept for
     * reasm_step().
     */
    if (fx->err == SSL_ERROR_WANT_READ) {
        fx->err = SSL_get_error(fx->ssl, SSL_accept(fx->ssl));
        ERR_clear_error();
    }
    return 1;
}

/* Let the server read what has been written, and return its SSL error */
static int reasm_step(REASM_TEST_FIXTURE *fx)
{
    if (fx->err == SSL_ERROR_WANT_READ) {
        fx->err = SSL_get_error(fx->ssl, SSL_accept(fx->ssl));
        ERR_clear_error();
    }
    return fx->err;
}

/*
 * Whether the server holds the message with this sequence number complete, as
 * msg_len bytes in order, every one of them fill.
 */
static int reasm_message_is(const REASM_TEST_FIXTURE *fx, unsigned int seq,
    size_t msg_len, unsigned char fill)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL_ONLY(fx->ssl);
    pitem *item = reasm_find(sc, seq);
    hm_fragment *frag;
    size_t i;

    if (!TEST_ptr(item))
        return 0;
    frag = (hm_fragment *)item->data;
    if (!TEST_false(frag->incomplete) || !TEST_ptr(frag->buf))
        return 0;

    for (i = 0; i < msg_len; i++)
        if (!TEST_uchar_eq(frag->buf[i], fill))
            return 0;
    return 1;
}

/*
 * First fragments of the ten messages after the one expected, each claiming the
 * largest length the server permits. Held memory must not follow the claim.
 */
static int test_dtls_reassembly_future_messages_memory(void)
{
    REASM_TEST_FIXTURE fx;
    unsigned int seq;
    int testresult = 0;

    if (!memtrk_enabled)
        return TEST_skip("allocation tracking not available");
    if (!reasm_fx_new(&fx))
        return 0;

    for (seq = 1; seq <= 10; seq++)
        if (!reasm_inject(&fx, SSL3_MT_CERTIFICATE, reasm_max_len(&fx), seq, 0,
                1, 'a'))
            goto end;

    if (!TEST_int_eq(reasm_step(&fx), SSL_ERROR_WANT_READ)
        || !TEST_size_t_lt(reasm_held(&fx), REASM_SMALL))
        goto end;

    testresult = 1;
end:
    reasm_fx_free(&fx);
    return testresult;
}

/*
 * The same for the message the server is waiting for, which claims the largest
 * length the server permits.
 */
static int test_dtls_reassembly_current_message_memory(void)
{
    REASM_TEST_FIXTURE fx;
    int testresult = 0;

    if (!memtrk_enabled)
        return TEST_skip("allocation tracking not available");
    if (!reasm_fx_new(&fx))
        return 0;

    if (!reasm_inject(&fx, SSL3_MT_CLIENT_HELLO, reasm_max_len(&fx), 0, 0, 1,
            'a'))
        goto end;

    if (!TEST_int_eq(reasm_step(&fx), SSL_ERROR_WANT_READ)
        || !TEST_size_t_lt(reasm_held(&fx), REASM_SMALL))
        goto end;

    testresult = 1;
end:
    reasm_fx_free(&fx);
    return testresult;
}

/*
 * So many one byte fragments with gaps between them that what is saved for
 * them, with the offset and length saved with each, comes to the length the
 * message claims. The message is then held in a buffer, so what is held for it
 * stays near the length it claims however many fragments follow, and all of
 * them are kept.
 */
static int test_dtls_reassembly_tiny_fragments_buffer(void)
{
    REASM_TEST_FIXTURE fx;
    SSL_CONNECTION *sc;
    pitem *item;
    hm_fragment *frag;
    size_t count, i;
    int testresult = 0;

    if (!memtrk_enabled)
        return TEST_skip("allocation tracking not available");
    if (!reasm_fx_new(&fx))
        return 0;

    /* Each is saved as 7 bytes: 6 of offset and length, and the byte itself */
    count = reasm_max_len(&fx) / 7 + 100;

    for (i = 0; i < count; i++)
        if (!reasm_inject(&fx, SSL3_MT_CERTIFICATE, reasm_max_len(&fx), 1,
                i * 2, 1, 'a'))
            goto end;

    sc = SSL_CONNECTION_FROM_SSL_ONLY(fx.ssl);
    if (!TEST_int_eq(reasm_step(&fx), SSL_ERROR_WANT_READ)
        || !TEST_ptr(item = reasm_find(sc, 1)))
        goto end;

    frag = (hm_fragment *)item->data;
    if (!TEST_ptr(frag->buf)
        || !TEST_size_t_lt(reasm_held(&fx),
            reasm_max_len(&fx) + reasm_max_len(&fx) / 8 + REASM_SMALL))
        goto end;
    for (i = 0; i < count; i++)
        if (!TEST_int_ne(frag->covered[(i * 2) >> 3] & (1 << ((i * 2) & 7)), 0))
            goto end;

    testresult = 1;
end:
    reasm_fx_free(&fx);
    return testresult;
}

/* The same fragment over and over must not accumulate */
static int test_dtls_reassembly_duplicate_flood(void)
{
    REASM_TEST_FIXTURE fx;
    size_t i;
    int testresult = 0;

    if (!memtrk_enabled)
        return TEST_skip("allocation tracking not available");
    if (!reasm_fx_new(&fx))
        return 0;

    for (i = 0; i < 500; i++)
        if (!reasm_inject(&fx, SSL3_MT_CERTIFICATE, reasm_max_len(&fx), 1, 0,
                1, 'a'))
            goto end;

    if (!TEST_int_eq(reasm_step(&fx), SSL_ERROR_WANT_READ)
        || !TEST_size_t_lt(reasm_held(&fx), REASM_SMALL))
        goto end;

    testresult = 1;
end:
    reasm_fx_free(&fx);
    return testresult;
}

/* Whether the message with this sequence number is held in a buffer */
static int reasm_held_in_buffer(const REASM_TEST_FIXTURE *fx, unsigned int seq)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL_ONLY(fx->ssl);
    pitem *item = reasm_find(sc, seq);

    return item != NULL && ((hm_fragment *)item->data)->buf != NULL;
}

/*
 * A message with many small fragments saved, just short of what would make it
 * be held in a buffer, is then sent the same fragment over and over. A
 * duplicate adds no bytes, but what is saved for it counts, so they must not be
 * free: once enough of them have arrived the message is held in a buffer, which
 * a duplicate does not add to.
 */
static int test_dtls_reassembly_duplicate_fragments_buffer(void)
{
    REASM_TEST_FIXTURE fx;
    const size_t limit = 30000;
    size_t i, count;
    int testresult = 0;

    if (!memtrk_enabled)
        return TEST_skip("allocation tracking not available");

    /* How many one byte fragments, with gaps, are saved before the buffer */
    if (!reasm_fx_new(&fx))
        return 0;
    for (count = 0; count < limit; count++) {
        if (!reasm_inject(&fx, SSL3_MT_CERTIFICATE, reasm_max_len(&fx), 1,
                count * 2, 1, 'a'))
            goto end;
        if (reasm_held_in_buffer(&fx, 1))
            break;
    }
    reasm_fx_free(&fx);
    if (!TEST_size_t_gt(count, 1) || !TEST_size_t_lt(count, limit))
        return 0;

    /* One fewer, so that the fragments are still saved */
    if (!reasm_fx_new(&fx))
        return 0;
    for (i = 0; i < count; i++)
        if (!reasm_inject(&fx, SSL3_MT_CERTIFICATE, reasm_max_len(&fx), 1,
                i * 2, 1, 'a'))
            goto end;
    if (!TEST_int_eq(reasm_step(&fx), SSL_ERROR_WANT_READ)
        || !TEST_false(reasm_held_in_buffer(&fx, 1)))
        goto end;

    for (i = 0; i < 500; i++)
        if (!reasm_inject(&fx, SSL3_MT_CERTIFICATE, reasm_max_len(&fx), 1, 0,
                1, 'a'))
            goto end;

    if (!TEST_int_eq(reasm_step(&fx), SSL_ERROR_WANT_READ)
        || !TEST_true(reasm_held_in_buffer(&fx, 1))
        || !TEST_size_t_lt(reasm_held(&fx),
            reasm_max_len(&fx) + reasm_max_len(&fx) / 8 + REASM_SMALL))
        goto end;

    testresult = 1;
end:
    reasm_fx_free(&fx);
    return testresult;
}

/*
 * A message of the largest permitted length is sent in fragments of 128 bytes
 * at every other 128 bytes, the rest being lost, and then again in fragments of
 * 192 bytes, as a sender whose fragment size changed would. The message must
 * complete, however the fragments of the second pass fall across the gaps left
 * by the first: once what is saved for it could be all of it, it is held in a
 * buffer, whatever the fragments saved were.
 */
static int test_dtls_reassembly_refragmented_max_message(void)
{
    REASM_TEST_FIXTURE fx;
    SSL_CONNECTION *sc;
    pitem *item;
    size_t max, off, len;
    int testresult = 0;

    if (!memtrk_enabled)
        return TEST_skip("allocation tracking not available");
    if (!reasm_fx_new(&fx))
        return 0;
    max = reasm_max_len(&fx);

    for (off = 0; off < max; off += 256)
        if (!reasm_inject(&fx, SSL3_MT_CERTIFICATE, max, 1, off, 128, 'a'))
            goto end;
    for (off = 0; off < max; off += 192) {
        len = max - off < 192 ? max - off : 192;
        if (!reasm_inject(&fx, SSL3_MT_CERTIFICATE, max, 1, off, len, 'a'))
            goto end;
    }

    sc = SSL_CONNECTION_FROM_SSL_ONLY(fx.ssl);
    if (!TEST_int_eq(reasm_step(&fx), SSL_ERROR_WANT_READ)
        || !TEST_ptr(item = reasm_find(sc, 1))
        || !TEST_false(((hm_fragment *)item->data)->incomplete)
        || !TEST_size_t_lt(reasm_held(&fx), 2 * max))
        goto end;

    testresult = 1;
end:
    reasm_fx_free(&fx);
    return testresult;
}

/*
 * However little a message claims, what is received of it is saved, and not held
 * in a buffer of the length it claims, until what is saved with the next
 * fragment could be all of it. A fragment of one byte is saved with its 6 byte
 * offset and length, so 7 bytes.
 *
 *   0: 1024 bytes claimed, 1 byte received: saved
 *   1: 7 bytes claimed, 1 byte received: held in a buffer
 */
static int test_dtls_reassembly_small_message_saved(int idx)
{
    REASM_TEST_FIXTURE fx;
    SSL_CONNECTION *sc;
    pitem *item;
    hm_fragment *frag;
    int testresult = 0;

    if (!reasm_fx_new(&fx))
        return 0;

    if (!reasm_inject(&fx, SSL3_MT_CERTIFICATE, idx == 0 ? 1024 : 7, 1, 0, 1,
            'a'))
        goto end;

    sc = SSL_CONNECTION_FROM_SSL_ONLY(fx.ssl);
    if (!TEST_int_eq(reasm_step(&fx), SSL_ERROR_WANT_READ)
        || !TEST_ptr(item = reasm_find(sc, 1)))
        goto end;

    frag = (hm_fragment *)item->data;
    if (!TEST_true(frag->incomplete))
        goto end;
    if (idx == 0) {
        if (!TEST_ptr_null(frag->buf) || !TEST_size_t_eq(frag->saved_len, 7))
            goto end;
    } else if (!TEST_ptr(frag->buf) || !TEST_size_t_eq(frag->saved_len, 0)) {
        goto end;
    }

    testresult = 1;
end:
    reasm_fx_free(&fx);
    return testresult;
}

/*
 * A message made complete from fragments in different ways holds about what was
 * sent for it, not more.
 *
 *   0: in order
 *   1: last to first
 *   2: overlapping
 *   3: each fragment twice
 */
static int test_dtls_reassembly_complete_message_memory(int idx)
{
    REASM_TEST_FIXTURE fx;
    const size_t msg_len = 3000, step = 500;
    size_t off;
    int i, ok = 1, testresult = 0;

    if (!memtrk_enabled)
        return TEST_skip("allocation tracking not available");
    if (!reasm_fx_new(&fx))
        return 0;

    switch (idx) {
    case 0:
        for (off = 0; ok && off < msg_len; off += step)
            ok = reasm_inject(&fx, SSL3_MT_CERTIFICATE, msg_len, 1, off, step,
                'a');
        break;
    case 1:
        for (i = (int)(msg_len / step) - 1; ok && i >= 0; i--)
            ok = reasm_inject(&fx, SSL3_MT_CERTIFICATE, msg_len, 1, i * step,
                step, 'a');
        break;
    case 2:
        /* Each fragment starts 100 bytes before the end of the last one */
        for (off = 0; ok && off < msg_len; off += step - 100)
            ok = reasm_inject(&fx, SSL3_MT_CERTIFICATE, msg_len, 1, off,
                off + step > msg_len ? msg_len - off : step, 'a');
        break;
    case 3:
        for (off = 0; ok && off < msg_len; off += step)
            ok = reasm_inject(&fx, SSL3_MT_CERTIFICATE, msg_len, 1, off, step,
                     'a')
                && reasm_inject(&fx, SSL3_MT_CERTIFICATE, msg_len, 1, off,
                    step, 'a');
        break;
    }
    if (!TEST_true(ok))
        goto end;

    /* A complete message is not consumed until it is the one expected */
    if (!TEST_int_eq(reasm_step(&fx), SSL_ERROR_WANT_READ)
        || !TEST_true(reasm_message_is(&fx, 1, msg_len, 'a'))
        || !TEST_size_t_lt(reasm_held(&fx), msg_len + REASM_SMALL))
        goto end;

    testresult = 1;
end:
    reasm_fx_free(&fx);
    return testresult;
}

/*
 * Everything held for incomplete messages is released however the connection
 * ends. The allocator is exact, so unlike a leak checker this also fails in a
 * build without one. A cycle without fragments is run first, so that state which
 * outlives a connection (error queue, lazily created tables) is not counted.
 *
 *   0: SSL_free with fragments held
 *   1: SSL_clear with fragments held, then SSL_free
 *   2: a fatal error with fragments held, then SSL_free
 */
static int reasm_cleanup_cycle(int idx, int with_fragments)
{
    REASM_TEST_FIXTURE fx;
    unsigned int seq;
    int testresult = 0;

    if (!reasm_fx_new(&fx))
        return 0;

    if (with_fragments) {
        for (seq = 1; seq <= 10; seq++)
            if (!reasm_inject(&fx, SSL3_MT_CERTIFICATE, reasm_max_len(&fx), seq,
                    0, 1, 'a'))
                goto end;
        if (idx == 2
            /* A complete ClientHello which is not one: a fatal error */
            && !reasm_inject(&fx, SSL3_MT_CLIENT_HELLO, 1, 0, 0, 1, 'a'))
            goto end;
        (void)reasm_step(&fx);
        if (idx == 1 && !TEST_true(SSL_clear(fx.ssl)))
            goto end;
    }

    testresult = 1;
end:
    reasm_fx_free(&fx);
    return testresult;
}

static int test_dtls_reassembly_cleanup(int idx)
{
    size_t before;

    if (!memtrk_enabled)
        return TEST_skip("allocation tracking not available");

    if (!reasm_cleanup_cycle(idx, 0))
        return 0;
    before = memtrk_live_bytes;
    if (!reasm_cleanup_cycle(idx, 1))
        return 0;
    return TEST_size_t_le(memtrk_live_bytes, before);
}

/*
 * An allocation which fails while a fragment is being received must end the
 * handshake with a fatal error. The body of the fragment has not been read, so
 * a server which only reported the failure would take the body for a handshake
 * header when it was called again.
 *
 *   0: the buffer a message is switched to, which a third fragment needs
 *   1: the room for the fragments saved for a message, which a second needs
 *   2: the buffer of a message which arrives whole, out of sequence
 */
static int test_dtls_reassembly_alloc_failure(int idx)
{
    REASM_TEST_FIXTURE fx;
    SSL_CONNECTION *sc;
    const size_t msg_len = 1000, frag_len = 400, whole_len = 777;
    int testresult = 0;

    if (!memtrk_enabled)
        return TEST_skip("allocation tracking not available");
    if (!reasm_fx_new(&fx))
        return 0;
    sc = SSL_CONNECTION_FROM_SSL_ONLY(fx.ssl);

    switch (idx) {
    case 0:
        /* Two fragments are saved: with the third what is saved could be it */
        if (!reasm_inject(&fx, SSL3_MT_CERTIFICATE, msg_len, 1, 0, frag_len,
                'a')
            || !reasm_inject(&fx, SSL3_MT_CERTIFICATE, msg_len, 1, frag_len,
                frag_len, 'a'))
            goto end;
        memtrk_fail_size = msg_len + (msg_len + 7) / 8;
        break;
    case 1:
        if (!reasm_inject(&fx, SSL3_MT_CERTIFICATE, msg_len, 1, 0, frag_len,
                'a'))
            goto end;
        /* Room for two records, the first of which doubles */
        memtrk_fail_size = 2 * (6 + frag_len);
        break;
    case 2:
        memtrk_fail_size = whole_len;
        break;
    }

    memtrk_fail_hits = 0;
    memtrk_fail_armed = 1;
    switch (idx) {
    case 0:
        testresult = reasm_inject(&fx, SSL3_MT_CERTIFICATE, msg_len, 1,
            2 * frag_len, 200, 'a');
        break;
    case 1:
        testresult = reasm_inject(&fx, SSL3_MT_CERTIFICATE, msg_len, 1,
            frag_len, frag_len, 'a');
        break;
    case 2:
        testresult = reasm_inject(&fx, SSL3_MT_CERTIFICATE, whole_len, 1, 0,
            whole_len, 'a');
        break;
    }
    memtrk_fail_armed = 0;

    if (!TEST_true(testresult)) {
        testresult = 0;
        goto end;
    }
    testresult = TEST_int_eq(memtrk_fail_hits, 1)
        && TEST_int_eq(fx.err, SSL_ERROR_SSL)
        && TEST_true(ossl_statem_in_error(sc));
end:
    memtrk_fail_armed = 0;
    reasm_fx_free(&fx);
    return testresult;
}

/*
 * A real handshake whose server flight is fragmented by a small MTU still
 * completes when the flight arrives with the last packet first.
 */
static int test_dtls_reassembly_handshake(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO *wbio;
    int i, ret, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    SSL_set_options(serverssl, SSL_OP_NO_QUERY_MTU);
    if (!TEST_true(SSL_set_mtu(serverssl, 256)))
        goto end;

    wbio = SSL_get_wbio(serverssl);

    /* The server's flight is queued for the client, undelivered */
    ret = SSL_connect(clientssl);
    if (!TEST_int_le(ret, 0)
        || !TEST_int_eq(SSL_get_error(clientssl, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_accept(serverssl);
    if (!TEST_int_le(ret, 0)
        || !TEST_int_eq(SSL_get_error(serverssl, ret), SSL_ERROR_WANT_READ))
        goto end;

    for (i = 1; mempacket_move_packet(wbio, 0, i); i++)
        continue;
    if (!TEST_int_gt(i, 1))
        goto end;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}
#endif /* OPENSSL_NO_DTLS1_2 */

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

    ADD_ALL_TESTS(test_dtls_unprocessed, NUM_TESTS);
#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_EC)
    ADD_ALL_TESTS(test_dtls_drop_records, TOTAL_RECORDS);
#endif
    ADD_TEST(test_cookie);
    ADD_TEST(test_dtls_duplicate_records);
    ADD_TEST(test_just_finished);
    ADD_ALL_TESTS(test_swap_records, 4);
    ADD_TEST(test_listen);
    ADD_TEST(test_duplicate_app_data);
#ifndef OPENSSL_NO_DTLS1_2
    ADD_TEST(test_dtls_client_retransmit);
    ADD_TEST(test_dtls_server_retransmit);
    ADD_TEST(test_dtls_reassembly_future_messages_memory);
    ADD_TEST(test_dtls_reassembly_tiny_fragments_buffer);
    ADD_TEST(test_dtls_reassembly_duplicate_flood);
    ADD_TEST(test_dtls_reassembly_duplicate_fragments_buffer);
    ADD_TEST(test_dtls_reassembly_refragmented_max_message);
    ADD_ALL_TESTS(test_dtls_reassembly_small_message_saved, 2);
    ADD_ALL_TESTS(test_dtls_reassembly_complete_message_memory, 4);
    ADD_ALL_TESTS(test_dtls_reassembly_cleanup, 3);
    ADD_ALL_TESTS(test_dtls_reassembly_alloc_failure, 3);
    ADD_TEST(test_dtls_reassembly_handshake);
    ADD_TEST(test_dtls_reassembly_current_message_memory);
#endif
    return 1;
}

void cleanup_tests(void)
{
    bio_f_tls_dump_filter_free();
    bio_s_mempacket_test_free();
}
