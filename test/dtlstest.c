/*
 * Copyright 2016-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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
    if (!TEST_int_gt(mempacket_test_inject(c_to_s_mempacket, (char *)certstatus,
                         sizeof(certstatus), 1, INJECT_PACKET_IGNORE_REC_SEQ),
            0))
        goto end;

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

#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_EC)
#ifndef OPENSSL_NO_DTLS
static int test_dtls_drop_records(int serverwbio, int minversion, int maxversion,
    int doresumption, int epoch, int idx);
#endif
#ifndef OPENSSL_NO_DTLS1_2
static int test_dtls_drop_records_dtls1(int idx)
{
    int doresumption;
    int cli_to_srv_cookie, cli_to_srv_epoch0, cli_to_srv_epoch1;
    int srv_to_cli_epoch0;
    int serverwbio;
    int epoch = 0;

    if (idx >= TOTAL_FULL_HAND_RECORDS) {
        doresumption = 1;
        cli_to_srv_epoch0 = CLI_TO_SRV_RESUME_EPOCH_0_RECS;
        cli_to_srv_epoch1 = CLI_TO_SRV_RESUME_EPOCH_1_RECS;
        srv_to_cli_epoch0 = SRV_TO_CLI_RESUME_EPOCH_0_RECS;
        cli_to_srv_cookie = CLI_TO_SRV_RESUME_COOKIE_EXCH;
        idx -= TOTAL_FULL_HAND_RECORDS;
    } else {
        doresumption = 0;
        cli_to_srv_epoch0 = CLI_TO_SRV_EPOCH_0_RECS;
        cli_to_srv_epoch1 = CLI_TO_SRV_EPOCH_1_RECS;
        srv_to_cli_epoch0 = SRV_TO_CLI_EPOCH_0_RECS;
        cli_to_srv_cookie = CLI_TO_SRV_COOKIE_EXCH;
    }
    /* Work out which record to drop based on the test number */
    if (idx >= cli_to_srv_cookie + cli_to_srv_epoch0 + cli_to_srv_epoch1) {
        serverwbio = 1;
        idx -= cli_to_srv_cookie + cli_to_srv_epoch0 + cli_to_srv_epoch1;
        if (idx >= SRV_TO_CLI_COOKIE_EXCH + srv_to_cli_epoch0) {
            epoch = 1;
            idx -= SRV_TO_CLI_COOKIE_EXCH + srv_to_cli_epoch0;
        }
    } else {
        serverwbio = 0;
        if (idx >= cli_to_srv_cookie + cli_to_srv_epoch0) {
            epoch = 1;
            idx -= cli_to_srv_cookie + cli_to_srv_epoch0;
        }
    }

    return test_dtls_drop_records(serverwbio, DTLS1_VERSION, DTLS1_2_VERSION,
        doresumption, epoch, idx);
}
#endif /* OPENSSL_NO_DTLS1_2 */

/* ClientHello */
#define DTLS13_CLI_TO_SRV_EPOCH_0_RECS_FULL 1
/* ServerHello */
#define DTLS13_SRV_TO_CLI_EPOCH_0_RECS_FULL 1
/* Finish */
#define DTLS13_CLI_TO_SRV_EPOCH_2_RECS_FULL 1
/* EncryptedExtensions, Certificate, CertificateVerify, Finish */
#define DTLS13_SRV_TO_CLI_EPOCH_2_RECS_FULL 4

#define DTLS13_TOTAL_HAND_RECORDS_FULL                                         \
    (DTLS13_CLI_TO_SRV_EPOCH_0_RECS_FULL + DTLS13_SRV_TO_CLI_EPOCH_0_RECS_FULL \
        + DTLS13_CLI_TO_SRV_EPOCH_2_RECS_FULL + DTLS13_SRV_TO_CLI_EPOCH_2_RECS_FULL)

/* ClientHello */
#define DTLS13_CLI_TO_SRV_EPOCH_0_RECS_RESM 1
/* ServerHello */
#define DTLS13_SRV_TO_CLI_EPOCH_0_RECS_RESM 1
/* Finish */
#define DTLS13_CLI_TO_SRV_EPOCH_2_RECS_RESM 1
/* EncryptedExtensions, Finish */
#define DTLS13_SRV_TO_CLI_EPOCH_2_RECS_RESM 2

#define DTLS13_TOTAL_HAND_RECORDS_RESM                                         \
    (DTLS13_CLI_TO_SRV_EPOCH_0_RECS_RESM + DTLS13_SRV_TO_CLI_EPOCH_0_RECS_RESM \
        + DTLS13_CLI_TO_SRV_EPOCH_2_RECS_RESM + DTLS13_SRV_TO_CLI_EPOCH_2_RECS_RESM)

#define DTLS13_TOTAL_RECORDS \
    (DTLS13_TOTAL_HAND_RECORDS_FULL + DTLS13_TOTAL_HAND_RECORDS_RESM)

#if !defined(OPENSSL_NO_INTEGRITY_ONLY_CIPHERS) && !defined(OPENSSL_NO_DTLS1_3)
/**
 * test_dtls_drop_records_dtls13 tests DTLS 1.3 implementation robustness against
 * dropped records
 *
 * @param idx
 *
 * idx:
 *      0) Tests drop of ClientHello (Client)
 *      1) Tests drop of Finish (Client)
 *      2) Tests drop of ServerHello (Server)
 *      3) Tests drop of EncryptedExtensions (Server)
 *      4) Tests drop of Certificate (Server)
 *      5) Tests drop of CertificateVerify (Server)
 *      6) Tests drop of Finish (Server)
 *      7) Tests drop of ClientHello (Client) in resumption
 *      8) Tests drop of Finish (Client) in resumption
 *      9) Tests drop of ServerHello (Server) in resumption
 *      10) Tests drop of EncryptedExtensions (Server) in resumption
 *      11) Tests drop of Finish (Server) in resumption
 *
 * @return 1 on success, 0 on failure
 */

static int test_dtls_drop_records_dtls13(int idx)
{
    int doresumption;
    int srv_to_cli_epoch0, cli_to_srv_epoch0, cli_to_srv_epoch2;
    int serverwbio;
    int epoch = 0;

    if (idx >= DTLS13_TOTAL_HAND_RECORDS_FULL) {
        doresumption = 1;
        cli_to_srv_epoch0 = DTLS13_CLI_TO_SRV_EPOCH_0_RECS_RESM;
        cli_to_srv_epoch2 = DTLS13_CLI_TO_SRV_EPOCH_2_RECS_RESM;
        srv_to_cli_epoch0 = DTLS13_SRV_TO_CLI_EPOCH_0_RECS_RESM;
        idx -= DTLS13_TOTAL_HAND_RECORDS_FULL;
    } else {
        doresumption = 0;
        cli_to_srv_epoch0 = DTLS13_CLI_TO_SRV_EPOCH_0_RECS_FULL;
        cli_to_srv_epoch2 = DTLS13_CLI_TO_SRV_EPOCH_2_RECS_FULL;
        srv_to_cli_epoch0 = DTLS13_SRV_TO_CLI_EPOCH_0_RECS_FULL;
    }
    /* Work out which record to drop based on the test number */
    if (idx >= cli_to_srv_epoch0 + cli_to_srv_epoch2) {
        serverwbio = 1;
        idx -= cli_to_srv_epoch0 + cli_to_srv_epoch2;
        if (idx >= srv_to_cli_epoch0) {
            epoch = 2;
            idx -= srv_to_cli_epoch0;
        }
    } else {
        serverwbio = 0;
        if (idx >= cli_to_srv_epoch0) {
            epoch = 2;
            idx -= cli_to_srv_epoch0;
        }
    }

    return test_dtls_drop_records(serverwbio, DTLS1_3_VERSION, 0, doresumption, epoch, idx);
}
#endif /* !defined(OPENSSL_NO_INTEGRITY_ONLY_CIPHERS) */

#ifndef OPENSSL_NO_DTLS
static int test_dtls_drop_records(int serverwbio, int minversion, int maxversion,
    int doresumption, int epoch, int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO *c_to_s_fbio, *mempackbio;
    int testresult = 0;
    SSL_SESSION *sess = NULL;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            minversion, maxversion,
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

    if (minversion == DTLS1_3_VERSION) {
        /*
         * Use integrity only cipher see we can obtain the sequence number
         * in ssltestlib.c mempacket_test_read
         */
        SSL_CTX_set_security_level(sctx, 0);
        SSL_CTX_set_security_level(cctx, 0);
        if (!TEST_true(SSL_CTX_set_ciphersuites(sctx, "TLS_SHA256_SHA256"))
            || !TEST_true(SSL_CTX_set_ciphersuites(cctx, "TLS_SHA256_SHA256")))
            goto end;
    }

    if (doresumption) {
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

    /*
     * The MTU Size was changed to be something more reasonable
     * but for this test lets have a lot of records to be dropped.
     */
    SSL_set_options(serverssl, SSL_OP_NO_QUERY_MTU);
    SSL_set_options(clientssl, SSL_OP_NO_QUERY_MTU);
    SSL_set_mtu(serverssl, 256);
    SSL_set_mtu(clientssl, 256);

    /* Work out which record to drop based on the test number */
    if (serverwbio) {
        mempackbio = SSL_get_wbio(serverssl);
    } else {
        mempackbio = SSL_get_wbio(clientssl);

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
#endif /* OPENSSL_NO_DTLS */
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

#if defined(OPENSSL_NO_DTLS1_2) && defined(OPENSSL_NO_DTLS1_3)
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

#if defined(OPENSSL_NO_DTLS1_2) && defined(OPENSSL_NO_DTLS1_3)
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
#ifndef OPENSSL_NO_DTLS1_2
static int test_swap_records_dtls1(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    int testresult = 0;
    BIO *bio;
    char msg[] = { 0x00, 0x01, 0x02, 0x03 };
    char buf[10];

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, DTLS1_2_VERSION,
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

    /*
     * The MTU Size was changed to be something more reasonable
     * but for this test lets have a lot of records to be dropped.
     */
    SSL_set_options(sssl, SSL_OP_NO_QUERY_MTU);
    SSL_set_options(cssl, SSL_OP_NO_QUERY_MTU);
    SSL_set_mtu(sssl, 256);
    SSL_set_mtu(cssl, 256);

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
#endif /* OPENSSL_NO_DTLS1_2 */

/*
 * Test that swapping later records before Finished or CCS still works
 * Test 0: Test receiving a handshake record early from next epoch on client side
 * Test 1: Test receiving the first fragment of the New Session Ticket before ACK message on client side
 * Test 2: Test receiving the second fragment of the New Session Ticket before ACK message on client side
 * Test 3: Test receiving an app data before ACK and the New Session Ticket messages on client side
 */
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECX) && !defined(OPENSSL_NO_ML_KEM) \
    && !defined(OPENSSL_NO_DTLS1_3)
static int test_swap_records_dtls13(int idx)
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
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        return 0;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl,
            NULL, NULL)))
        goto end;

    /*
     * The MTU Size was changed to be something more reasonable
     * but for this test lets have a lot of records to be dropped.
     */
    SSL_set_options(sssl, SSL_OP_NO_QUERY_MTU);
    SSL_set_options(cssl, SSL_OP_NO_QUERY_MTU);
    SSL_set_mtu(sssl, 256);
    SSL_set_mtu(cssl, 256);

    /* Send flight 1: ClientHello */
    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    /* Recv flight 1, send flight 2: ServerHello, Certificate, ServerHelloDone */
    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    if (idx == 0) {
        /* Swap Server Hello and first Epoch 2 (Encrypted Extensions) */
        bio = SSL_get_wbio(sssl);
        if (!TEST_ptr(bio)
            || !TEST_true(mempacket_swap_epoch_dtls13(bio)))
            goto end;
    }

    /* Recv flight 2, send flight 3: Client Finished */
    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    /* Recv flight 3, send flight 4: ACK, New Session tickets*/
    if (!TEST_int_gt(SSL_accept(sssl), 0))
        goto end;

    /* Send flight 4 (cont'd): datagram 2(app data) */
    if (!TEST_int_eq(SSL_write(sssl, msg, sizeof(msg)), (int)sizeof(msg)))
        goto end;

    bio = SSL_get_wbio(sssl);
    if (!TEST_ptr(bio))
        goto end;
    if (idx == 1) {
        /* Move the first New Session Ticket fragment before the ACK */
        if (!TEST_true(mempacket_move_packet(bio, 0, 1)))
            goto end;
    } else if (idx == 2) {
        /* Move the second New Session Ticket fragment before the ACK */
        if (!TEST_true(mempacket_move_packet(bio, 0, 2)))
            goto end;
    } else if (idx == 3) {
        /* App data comes before ACK */
        bio = SSL_get_wbio(sssl);
        if (!TEST_true(mempacket_move_packet(bio, 0, 5)))
            goto end;
    }

    /*
     * Recv Server's ACK
     */
    if (!TEST_int_gt(SSL_connect(cssl), 0))
        goto end;

    if (idx != 3) {
        /* App data was not received early, so it should not be pending */
        if (!TEST_int_eq(SSL_pending(cssl), 0)
            || !TEST_false(SSL_has_pending(cssl)))
            goto end;
    }

    if (!TEST_int_eq(ret = SSL_read(cssl, buf, sizeof(buf)), (int)sizeof(msg)))
        goto end;

    if (!TEST_mem_eq(buf, sizeof(msg), msg, sizeof(msg)))
        goto end;

    if (!TEST_int_eq(SSL_write(sssl, msg, sizeof(msg)), (int)sizeof(msg)))
        goto end;

    if (!TEST_int_eq(SSL_read(cssl, buf, sizeof(buf)), (int)sizeof(msg)))
        goto end;

    if (!TEST_mem_eq(buf, sizeof(msg), msg, sizeof(msg)))
        goto end;

    testresult = 1;
end:
    SSL_free(cssl);
    SSL_free(sssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);

    return testresult;
}
#endif

#ifndef OPENSSL_NO_DTLS
static int test_duplicate_app_data(int minversion, int maxversion);
#endif
#ifndef OPENSSL_NO_DTLS1_2
static int test_duplicate_app_data_dtls1(void)
{
    return test_duplicate_app_data(DTLS1_VERSION, DTLS1_2_VERSION);
}
#endif /* OPENSSL_NO_DTLS1_2 */

#ifndef OPENSSL_NO_DTLS1_3
static int test_duplicate_app_data_dtls13(void)
{
    return test_duplicate_app_data(DTLS1_3_VERSION, DTLS1_3_VERSION);
}
#endif /* OPENSSL_NO_DTLS1_3 */

#ifndef OPENSSL_NO_DTLS
static int test_duplicate_app_data(int minversion, int maxversion)
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
            minversion, maxversion,
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
#endif /* OPENSSL_NO_DTLS */

#ifndef OPENSSL_NO_DTLS1_3
/*
 * Keyed DTLS 1.3 epochs must silently discard DTLSPlaintext records
 * (RFC 9147 sections 4 and 4.5.2).
 */

/*
 * RFC 9147 section 6.1 assigns epoch 2 to handshake traffic and epoch 3 to
 * the first application traffic keys.
 */
#define DTLS13_HANDSHAKE_EPOCH 2
#define DTLS13_APPLICATION_EPOCH 3

/*
 * Genuine sequence numbers are close to zero in these tests. A sequence
 * number of 100 is beyond the 64 record replay window, so accepting it would
 * make the next genuine record stale.
 */
#define DTLS13_FAR_AHEAD_SEQUENCE 100

/*
 * DTLSPlaintext has a 48 bit sequence number. Its maximum moves the replay
 * window as far forward as the record format permits. Sequence zero is the
 * first protected record in a newly installed epoch.
 */
#define DTLS13_MAX_PLAINTEXT_SEQUENCE ((((uint64_t)1) << 48) - 1)
#define DTLS13_FIRST_PROTECTED_SEQUENCE 0

static size_t make_forged_plaintext_record(unsigned char *out,
    unsigned int epoch, uint64_t seq,
    unsigned int type,
    const unsigned char *body,
    size_t bodylen)
{
    out[0] = (unsigned char)type;
    out[1] = 0xfe;
    out[2] = 0xfd;
    out[3] = (unsigned char)(epoch >> 8);
    out[4] = (unsigned char)epoch;
    out[5] = (unsigned char)(seq >> 40);
    out[6] = (unsigned char)(seq >> 32);
    out[7] = (unsigned char)(seq >> 24);
    out[8] = (unsigned char)(seq >> 16);
    out[9] = (unsigned char)(seq >> 8);
    out[10] = (unsigned char)seq;
    out[11] = (unsigned char)(bodylen >> 8);
    out[12] = (unsigned char)bodylen;
    memcpy(out + 13, body, bodylen);
    return 13 + bodylen;
}

static size_t make_forged_alert(unsigned char *out, unsigned int epoch,
    uint64_t seq, unsigned int level,
    unsigned int descr)
{
    unsigned char body[2];

    body[0] = (unsigned char)level;
    body[1] = (unsigned char)descr;
    return make_forged_plaintext_record(out, epoch, seq, SSL3_RT_ALERT,
        body, sizeof(body));
}

static int do_dtls13_handshake(SSL *sssl, SSL *cssl)
{
    int i;

    /*
     * An in memory DTLS 1.3 handshake completes in far fewer than 64 calls,
     * even when its flights are fragmented. This isn't a protocol limit: it
     * leaves ample room while making a stalled handshake fail promptly.
     */
    for (i = 0; i < 64; i++) {
        int rc = SSL_connect(cssl);
        int rs = SSL_accept(sssl);

        if (SSL_is_init_finished(cssl) && SSL_is_init_finished(sssl))
            return 1;
        if (rc <= 0) {
            int e = SSL_get_error(cssl, rc);

            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
                return 0;
        }
        if (rs <= 0) {
            int e = SSL_get_error(sssl, rs);

            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
                return 0;
        }
    }
    return 0;
}

/* Drain pending ACK and NewSessionTicket records. */
static int drain_ssl(SSL *ssl)
{
    unsigned char buf[256];
    int ret;

    do {
        ret = SSL_read(ssl, buf, sizeof(buf));
    } while (ret > 0);

    if (!TEST_int_eq(SSL_get_error(ssl, ret), SSL_ERROR_WANT_READ))
        return 0;
    ERR_clear_error();
    return 1;
}

static int inject_client_datagram(SSL *cssl, const unsigned char *pkt,
    size_t pktlen)
{
    BIO *bio = SSL_get_wbio(cssl);

    if (!TEST_ptr(bio))
        return 0;
    return TEST_int_eq(mempacket_test_inject(bio, (const char *)pkt,
                           (int)pktlen, -1,
                           INJECT_PACKET_IGNORE_REC_SEQ),
        (int)pktlen);
}

/* Rejected plaintext must not change state or disrupt application data. */
static int test_dtls13_forged_plaintext_alert(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    unsigned char pkt[5 * 15];
    size_t pktlen = 0;
    char msg[] = { 0x00, 0x01, 0x02, 0x03 };
    char buf[16];
    int ret, i, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        return 0;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    if (!TEST_true(do_dtls13_handshake(sssl, cssl)))
        goto end;

    /* Consume any post-handshake ACKs and NewSessionTickets */
    if (!TEST_true(drain_ssl(cssl)) || !TEST_true(drain_ssl(sssl)))
        goto end;

    switch (idx) {
    case 0:
        /* Spoofed close_notify */
        pktlen = make_forged_alert(pkt, DTLS13_APPLICATION_EPOCH,
            DTLS13_FAR_AHEAD_SEQUENCE, SSL3_AL_WARNING,
            SSL3_AD_CLOSE_NOTIFY);
        break;
    case 1:
        /* Spoofed fatal alert (handshake_failure) */
        pktlen = make_forged_alert(pkt, DTLS13_APPLICATION_EPOCH,
            DTLS13_FAR_AHEAD_SEQUENCE, SSL3_AL_FATAL,
            SSL3_AD_HANDSHAKE_FAILURE);
        break;
    case 2:
        /* user_cancelled with seq 2^48-1 (replay-window poison) */
        pktlen = make_forged_alert(pkt, DTLS13_APPLICATION_EPOCH,
            DTLS13_MAX_PLAINTEXT_SEQUENCE, SSL3_AL_WARNING,
            SSL_AD_USER_CANCELLED);
        break;
    case 3:
        /* Trip the warning limit while preserving record framing. */
        for (i = 0; i < 5; i++)
            pktlen += make_forged_alert(pkt + pktlen,
                DTLS13_APPLICATION_EPOCH, 10 + i, SSL3_AL_WARNING,
                SSL_AD_USER_CANCELLED);
        break;
    case 4:
        /* Malformed alert body (fragment length 3) */
        pktlen = make_forged_alert(pkt, DTLS13_APPLICATION_EPOCH,
            DTLS13_FAR_AHEAD_SEQUENCE, SSL3_AL_FATAL,
            SSL3_AD_HANDSHAKE_FAILURE);
        pkt[12] = 3;
        pkt[15] = 0xff;
        pktlen = 16;
        break;
    case 5:
        /* Alert with an overlong body (longer than content + tag) */
        pktlen = make_forged_alert(pkt, DTLS13_APPLICATION_EPOCH,
            DTLS13_FAR_AHEAD_SEQUENCE, SSL3_AL_WARNING,
            SSL3_AD_CLOSE_NOTIFY);
        pkt[11] = 0;
        pkt[12] = 40;
        memset(pkt + 15, 0xaa, 40 - 2);
        pktlen = 13 + 40;
        break;
    case 6:
        /* Type 22 used to reach AAD setup with an uninitialised WPACKET. */
        {
            unsigned char body[40];

            memset(body, 0xbb, sizeof(body));
            pktlen = make_forged_plaintext_record(pkt,
                DTLS13_APPLICATION_EPOCH, DTLS13_FAR_AHEAD_SEQUENCE,
                SSL3_RT_HANDSHAKE, body, sizeof(body));
        }
        break;
    case 7:
        /* Same as case 6 with outer type ack(26) */
        {
            unsigned char body[40];

            memset(body, 0xcc, sizeof(body));
            pktlen = make_forged_plaintext_record(pkt,
                DTLS13_APPLICATION_EPOCH, DTLS13_FAR_AHEAD_SEQUENCE,
                SSL3_RT_ACK, body, sizeof(body));
        }
        break;
    default:
        goto end;
    }

    if (!inject_client_datagram(cssl, pkt, pktlen))
        goto end;

    /* It must be silently discarded without changing shutdown state. */
    ret = SSL_read(sssl, buf, sizeof(buf));
    if (!TEST_int_le(ret, 0)
        || !TEST_int_eq(SSL_get_error(sssl, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(SSL_get_shutdown(sssl), 0))
        goto end;
    ERR_clear_error();

    /* The association must still work: application data keeps flowing */
    if (!TEST_int_eq(SSL_write(cssl, msg, sizeof(msg)), (int)sizeof(msg))
        || !TEST_int_eq(ret = SSL_read(sssl, buf, sizeof(buf)),
            (int)sizeof(msg))
        || !TEST_mem_eq(buf, sizeof(msg), msg, sizeof(msg)))
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
 * Plant epoch 2 plaintext after ClientHello and verify that it is discarded
 * when reparsed under epoch 2.
 *
 * idx 0: far ahead sequence makes Finished stale
 * idx 1: fatal alert aborts the handshake
 * idx 2: sequence 0 makes the first protected record look replayed
 */
static int test_dtls13_forged_plaintext_alert_plant(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    unsigned char pkt[15];
    size_t pktlen = 0;
    char msg[] = { 0x00, 0x01, 0x02, 0x03 };
    char buf[16];
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        return 0;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    /* Send flight 1: ClientHello */
    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    switch (idx) {
    case 0:
        pktlen = make_forged_alert(pkt, DTLS13_HANDSHAKE_EPOCH,
            DTLS13_MAX_PLAINTEXT_SEQUENCE, SSL3_AL_WARNING,
            SSL_AD_USER_CANCELLED);
        break;
    case 1:
        pktlen = make_forged_alert(pkt, DTLS13_HANDSHAKE_EPOCH,
            DTLS13_FIRST_PROTECTED_SEQUENCE, SSL3_AL_FATAL,
            SSL3_AD_HANDSHAKE_FAILURE);
        break;
    case 2:
        pktlen = make_forged_alert(pkt, DTLS13_HANDSHAKE_EPOCH,
            DTLS13_FIRST_PROTECTED_SEQUENCE, SSL3_AL_WARNING,
            SSL_AD_USER_CANCELLED);
        break;
    default:
        goto end;
    }

    if (!inject_client_datagram(cssl, pkt, pktlen))
        goto end;

    /* The handshake must complete despite the plant */
    if (!TEST_true(do_dtls13_handshake(sssl, cssl)))
        goto end;

    /* Application data must flow in both directions */
    if (!TEST_int_eq(SSL_write(cssl, msg, sizeof(msg)), (int)sizeof(msg))
        || !TEST_int_eq(SSL_read(sssl, buf, sizeof(buf)), (int)sizeof(msg))
        || !TEST_mem_eq(buf, sizeof(msg), msg, sizeof(msg))
        || !TEST_int_eq(SSL_write(sssl, msg, sizeof(msg)), (int)sizeof(msg))
        || !TEST_int_eq(SSL_read(cssl, buf, sizeof(buf)), (int)sizeof(msg))
        || !TEST_mem_eq(buf, sizeof(msg), msg, sizeof(msg)))
        goto end;

    testresult = 1;
end:
    SSL_free(cssl);
    SSL_free(sssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);

    return testresult;
}

/* Epoch 0 plaintext alerts must still reach the handshake. */
static int test_dtls13_epoch0_plaintext_alert(void)
{
#ifdef OPENSSL_NO_EC
    const char *group = "ffdhe3072";
#else
    const char *group = "P-256";
#endif
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    unsigned char pkt[15];
    size_t pktlen;
    int ret, i, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        return 0;

    /* Keep ClientHello in one record so sequence number 1 remains unused. */
    if (!TEST_true(SSL_CTX_set1_groups_list(sctx, group))
        || !TEST_true(SSL_CTX_set1_groups_list(cctx, group)))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    /* Send flight 1: ClientHello */
    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    /* ClientHello used sequence 0, so inject the alert with sequence 1. */
    pktlen = make_forged_alert(pkt, 0, 1, SSL3_AL_FATAL,
        SSL3_AD_HANDSHAKE_FAILURE);
    if (!inject_client_datagram(cssl, pkt, pktlen))
        goto end;

    /* The epoch 0 alert must fail the handshake. */
    ret = SSL_accept(sssl);
    for (i = 0; i < 3 && ret <= 0
        && SSL_get_error(sssl, ret) == SSL_ERROR_WANT_READ;
        i++)
        ret = SSL_accept(sssl);
    if (!TEST_int_le(ret, 0)
        || !TEST_int_eq(SSL_get_error(sssl, ret), SSL_ERROR_SSL)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()),
            SSL_AD_REASON_OFFSET + SSL3_AD_HANDSHAKE_FAILURE)
        || !TEST_true((SSL_get_shutdown(sssl) & SSL_RECEIVED_SHUTDOWN) != 0))
        goto end;
    ERR_clear_error();

    testresult = 1;
end:
    SSL_free(cssl);
    SSL_free(sssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);

    return testresult;
}
#endif /* OPENSSL_NO_DTLS1_3 */

/* Confirm that we can create a connections using DTLSv1_listen() */
#ifndef OPENSSL_NO_DTLS1_2
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
#ifndef OPENSSL_NO_DTLS1_2
    ADD_ALL_TESTS(test_dtls_drop_records_dtls1, TOTAL_RECORDS);
#endif
#if !defined(OPENSSL_NO_INTEGRITY_ONLY_CIPHERS) && !defined(OPENSSL_NO_DTLS1_3)
    ADD_ALL_TESTS(test_dtls_drop_records_dtls13, DTLS13_TOTAL_RECORDS);
#endif
#endif
    ADD_TEST(test_cookie);
    ADD_TEST(test_dtls_duplicate_records);
    ADD_TEST(test_just_finished);
#ifndef OPENSSL_NO_DTLS1_2
    ADD_ALL_TESTS(test_swap_records_dtls1, 4);
#endif
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECX) && !defined(OPENSSL_NO_ML_KEM) \
    && !defined(OPENSSL_NO_DTLS1_3)
    ADD_ALL_TESTS(test_swap_records_dtls13, 4);
#endif
#ifndef OPENSSL_NO_DTLS1_2
    ADD_TEST(test_listen);
    ADD_TEST(test_duplicate_app_data_dtls1);
#endif
#ifndef OPENSSL_NO_DTLS1_3
    ADD_TEST(test_duplicate_app_data_dtls13);
    ADD_ALL_TESTS(test_dtls13_forged_plaintext_alert, 8);
    ADD_ALL_TESTS(test_dtls13_forged_plaintext_alert_plant, 3);
    ADD_TEST(test_dtls13_epoch0_plaintext_alert);
#endif

    return 1;
}

void cleanup_tests(void)
{
    bio_f_tls_dump_filter_free();
    bio_s_mempacket_test_free();
}
