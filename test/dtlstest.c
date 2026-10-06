/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
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

#include "internal/nelem.h"
#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "../ssl/record/methods/recmethod_local.h"
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

#ifndef OPENSSL_NO_DTLS1_3
static int generate_stateless_cookie_cb(SSL *ssl, unsigned char *cookie,
    size_t *cookie_len)
{
    memcpy(cookie, dummy_cookie, sizeof(dummy_cookie));
    *cookie_len = sizeof(dummy_cookie);
    return 1;
}

static int verify_stateless_cookie_cb(SSL *ssl, const unsigned char *cookie,
    size_t cookie_len)
{
    return TEST_mem_eq(cookie, cookie_len, dummy_cookie, sizeof(dummy_cookie));
}

static int client_hello_count, client_hello_cookie_count;

static int count_client_hello_cb(SSL *s, int *al, void *arg)
{
    const unsigned char *ext;
    size_t extlen;

    client_hello_count++;
    if (SSL_client_hello_get0_ext(s, TLSEXT_TYPE_cookie, &ext, &extlen))
        client_hello_cookie_count++;

    return SSL_CLIENT_HELLO_SUCCESS;
}

/*
 * Test SSL_OP_COOKIE_EXCHANGE without DTLSv1_listen():
 * 0: DTLS 1.2 client answered with a HelloVerifyRequest
 * 1: DTLS 1.3 client answered with a HelloRetryRequest cookie
 * 2: as 1 with only the HelloVerifyRequest callbacks set
 * 3: DTLS 1.3 client with no callbacks set fails
 * 4: as 1 for a PSK-only resumption, where the HelloRetryRequest has no key_share
 */
static int test_cookie_exchange(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_SESSION *sess = NULL;
    int testresult = 0;

#ifdef OPENSSL_NO_DTLS1_2
    if (idx == 0)
        return TEST_skip("DTLS 1.2 is disabled");
#endif

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), 0, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

    SSL_CTX_set_options(sctx, SSL_OP_COOKIE_EXCHANGE);
    if (idx != 3) {
        SSL_CTX_set_cookie_generate_cb(sctx, generate_cookie_cb);
        SSL_CTX_set_cookie_verify_cb(sctx, verify_cookie_cb);
    }
    if (idx != 2 && idx != 3) {
        SSL_CTX_set_stateless_cookie_generate_cb(sctx,
            generate_stateless_cookie_cb);
        SSL_CTX_set_stateless_cookie_verify_cb(sctx,
            verify_stateless_cookie_cb);
    }
    if (idx == 4) {
        SSL_CTX_set_options(sctx, SSL_OP_ALLOW_NO_DHE_KEX | SSL_OP_PREFER_NO_DHE_KEX);
        SSL_CTX_set_options(cctx, SSL_OP_ALLOW_NO_DHE_KEX);
    }
    SSL_CTX_set_client_hello_cb(sctx, count_client_hello_cb, NULL);

    if (idx == 0
        && !TEST_true(SSL_CTX_set_max_proto_version(cctx, DTLS1_2_VERSION)))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    if (idx == 3) {
        if (!TEST_false(create_ssl_connection(serverssl, clientssl,
                SSL_ERROR_SSL))
            || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()),
                SSL_R_NO_COOKIE_CALLBACK_SET))
            goto end;
        testresult = 1;
        goto end;
    }

    if (idx == 4) {
        if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                SSL_ERROR_NONE))
            || !TEST_ptr(sess = SSL_get1_session(clientssl)))
            goto end;
        shutdown_ssl_connection(serverssl, clientssl);
        serverssl = clientssl = NULL;
        if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                NULL, NULL))
            || !TEST_true(SSL_set_session(clientssl, sess)))
            goto end;
    }
    client_hello_count = client_hello_cookie_count = 0;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_int_eq(SSL_version(clientssl),
            idx == 0 ? DTLS1_2_VERSION : DTLS1_3_VERSION)
        || !TEST_int_eq(SSL_session_reused(clientssl), idx == 4)
        /* The second ClientHello carries the cookie */
        || !TEST_int_eq(client_hello_count, 2)
        || !TEST_int_eq(client_hello_cookie_count, idx == 0 ? 0 : 1))
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
#endif /* OPENSSL_NO_DTLS1_3 */

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
/* Place record state near boundaries instead of sending 65536 records. */
typedef struct seqnum_test_st {
    uint64_t start;
    /* Keep the initial window for first-period cases; otherwise align it. */
    int move_reader;
    int num;
} SEQNUM_TEST;

static const SEQNUM_TEST seqnum_tests[] = {
    { 0x100, 1, 2 }, /* ordinary forward progression */
    { 0xfffe, 0, 2 }, /* end of the first period, reader at the epoch start */
    { 40000, 0, 2 }, /* more than half a period past the reader's window */
    { 0xffff, 1, 4 }, /* the 16 bit sequence number field wraps */
    { 0x1ffff, 1, 4 }, /* ... and wraps again */
    { 0xfffffffe, 1, 4 }, /* ... and past the 32 bit boundary */
};

static int test_seq_num_wrap(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    SSL_CONNECTION *ssc, *csc;
    const SEQNUM_TEST *t = &seqnum_tests[idx];
    unsigned char wrbuf[16], rdbuf[16];
    int testresult = 0;
    int i, j;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        return 0;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    if (!TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE)))
        goto end;

    if (!TEST_ptr(ssc = SSL_CONNECTION_FROM_SSL_ONLY(sssl))
        || !TEST_ptr(csc = SSL_CONNECTION_FROM_SSL_ONLY(cssl)))
        goto end;

    /* Application data must use a unified header. */
    if (!TEST_uint64_t_gt(csc->rlayer.wrl->epoch, 0)
        || !TEST_uint64_t_gt(ssc->rlayer.wrl->epoch, 0))
        goto end;

    /* Drain post-handshake ACKs before manipulating the record state. */
    while (SSL_read(sssl, rdbuf, sizeof(rdbuf)) > 0)
        continue;
    while (SSL_read(cssl, rdbuf, sizeof(rdbuf)) > 0)
        continue;
    ERR_clear_error();

    for (j = 0; j < 2; j++) {
        SSL *wssl = j == 0 ? cssl : sssl;
        SSL *rssl = j == 0 ? sssl : cssl;
        SSL_CONNECTION *wsc = j == 0 ? csc : ssc;
        SSL_CONNECTION *rsc = j == 0 ? ssc : csc;

        /* The writer must not go backwards: that would reuse a nonce */
        if (!TEST_uint64_t_ge(t->start, wsc->rlayer.wrl->sequence))
            goto end;

        wsc->rlayer.wrl->sequence = t->start;

        if (t->move_reader) {
            rsc->rlayer.rrl->bitmap.max_seq_num = t->start - 1;
            rsc->rlayer.rrl->bitmap.map = 1;
        }

        for (i = 0; i < t->num; i++) {
            memset(wrbuf, 0, sizeof(wrbuf));
            wrbuf[0] = (unsigned char)(i + 1);

            if (!TEST_int_eq(SSL_write(wssl, wrbuf, sizeof(wrbuf)),
                    (int)sizeof(wrbuf)))
                goto end;

            /* The full sequence number keeps increasing across the wrap */
            if (!TEST_uint64_t_eq(wsc->rlayer.wrl->sequence,
                    t->start + i + 1))
                goto end;

            memset(rdbuf, 0, sizeof(rdbuf));
            if (!TEST_int_eq(SSL_read(rssl, rdbuf, sizeof(rdbuf)),
                    (int)sizeof(rdbuf))
                || !TEST_mem_eq(rdbuf, sizeof(rdbuf), wrbuf,
                    sizeof(wrbuf)))
                goto end;

            /* ... and the peer has to have reconstructed the same value */
            if (!TEST_uint64_t_eq(rsc->rlayer.rrl->bitmap.max_seq_num,
                    t->start + i))
                goto end;
        }
    }

    testresult = 1;
end:
    SSL_free(cssl);
    SSL_free(sssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);

    return testresult;
}

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

/*
 * RFC 9147 (DTLS 1.3): TLS_AES_128_CCM_8_SHA256 MUST NOT be used in DTLS
 * without additional safeguards against forgery, due to its short
 * authentication tag. OpenSSL does not implement such safeguards, so a
 * DTLS1.3 connection offering only this ciphersuite must fail to find a
 * usable cipher rather than falling back to negotiating it anyway.
 */
static int test_dtls13_ccm8_not_offered(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int testresult = 0;
    int ret;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        return 0;

    /* CCM8 ciphers are considered low security due to their short tag */
    SSL_CTX_set_security_level(sctx, 0);
    SSL_CTX_set_security_level(cctx, 0);

    if (!TEST_true(SSL_CTX_set_ciphersuites(sctx, TLS1_3_RFC_AES_128_CCM_8_SHA256))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS1_3_RFC_AES_128_CCM_8_SHA256)))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    /*
     * The client must fail before it can even construct a ClientHello: it
     * has no cipher left that is permitted under DTLS to offer.
     */
    if (!TEST_int_le(ret = SSL_connect(clientssl), 0)
        || !TEST_int_eq(SSL_get_error(clientssl, ret), SSL_ERROR_SSL)
        || !TEST_int_eq(ERR_GET_REASON(ERR_get_error()),
            SSL_R_NO_CIPHERS_AVAILABLE))
        goto end;
    ERR_clear_error();

    /* The server independently has nothing usable configured either */
    if (!TEST_int_le(ret = SSL_accept(serverssl), 0)
        || !TEST_int_eq(SSL_get_error(serverssl, ret), SSL_ERROR_SSL)
        || !TEST_int_eq(ERR_GET_REASON(ERR_get_error()),
            SSL_R_NO_CIPHERS_AVAILABLE))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
#endif /* OPENSSL_NO_DTLS1_3 */

/*
 * frag_bio and the four retransmit tests below need only one of DTLS1.2 or
 * DTLS1.3 to be available - the frag_bio helpers are shared by both, so
 * they can't be scoped to either protocol's guard alone.
 */
#if !defined(OPENSSL_NO_DTLS1_2)                            \
    || (!defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECX) \
        && !defined(OPENSSL_NO_ML_KEM) && !defined(OPENSSL_NO_DTLS1_3))

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

#ifndef OPENSSL_NO_DTLS1_2
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
            "proto-%04zu-%s", j,
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

#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECX) && !defined(OPENSSL_NO_ML_KEM) \
    && !defined(OPENSSL_NO_DTLS1_3)
/*
 * DTLS1.3 counterpart to test_dtls_client_retransmit(): same write_state
 * guard, exercised with ClientHello fragmented under DTLS1.3 instead of
 * DTLS1.2.
 *
 * Pinning groups to X25519MLKEM768 alone is what forces fragmentation here:
 * its key share is large enough on its own that ClientHello can't fit in a
 * single 256-byte MTU fragment.
 */
static int test_dtls_client_retransmit_dtls13(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int testresult = 0;
    int ret, err, i;
    struct timeval tv;
    BIO *c_to_s_bio = NULL;
    BIO *frag_wbio;
    frag_bio *fb;
    int write_calls_before;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        return 0;

    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);

    if (!TEST_true(SSL_CTX_set1_groups_list(cctx, "X25519MLKEM768")))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    /*
     * Pin the MTU so fragmentation of the ClientHello is deterministic.
     * SSL_OP_NO_QUERY_MTU stops dtls1_query_mtu() from overriding this with
     * a value queried from the BIO.
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
     * hit dtls1_do_write()'s entry assertion (see
     * test_dtls_client_retransmit()) if the guard weren't there.
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
 * DTLS1.3 counterpart to test_dtls_server_retransmit(): same write_state
 * guard, exercised with the server's encrypted flight (Certificate, in
 * practice) fragmented under DTLS1.3 instead of DTLS1.2.
 */
static int test_dtls_server_retransmit_dtls13(void)
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
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        return 0;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    /*
     * Pin the server's MTU so its flight fragments deterministically. The
     * client is left alone - it sends its ClientHello without restriction.
     */
    SSL_set_options(serverssl, SSL_OP_NO_QUERY_MTU);
    if (!TEST_true(SSL_set_mtu(serverssl, 256)))
        goto end;

    /* Wrap only the server's write BIO in our fragment-limiting filter. */
    s_to_c_bio = SSL_get_wbio(serverssl);

    if (!TEST_ptr(s_to_c_bio) || !TEST_true(BIO_up_ref(s_to_c_bio)))
        goto end;

    /*
     * Only let ServerHello and the first fragment of the encrypted flight
     * (Certificate, in practice) out initially.
     */
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
     * Flight 2: the server sends ServerHello in full but only gets the
     * first fragment of the encrypted flight out before our BIO suspends
     * it, leaving write_state parked at WRITE_STATE_SEND.
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
     * hit dtls1_do_write()'s entry assertion (see
     * test_dtls_client_retransmit()) if the guard weren't there.
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
#endif /* !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECX) && ... */
#endif /* !defined(OPENSSL_NO_DTLS1_2) || (DTLS1.3-capable) */

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

#ifndef OPENSSL_NO_DTLS1_3
/* Expire the retransmission timer as the queued ACK is read from the BIO. */
static long ack_read_timeout_cb(BIO *b, int oper, const char *argp,
    size_t len, int argi, long argl, int ret, size_t *processed)
{
    SSL_CONNECTION *sc = (SSL_CONNECTION *)BIO_get_callback_arg(b);

    if (sc != NULL && oper == (BIO_CB_READ | BIO_CB_RETURN)
        && ret > 0 && processed != NULL && *processed > 0) {
        /* A nonzero deadline in the past makes the next timeout check fire. */
        sc->d1->next_timeout = ossl_ticks2time(1);
        BIO_set_callback_arg(b, NULL);
    }
    return ret;
}

/*
 * Drive a DTLS 1.3 handshake until the server has completed. At that point
 * the client has sent its Finished flight with the retransmission timer
 * armed, and the server's ACK is queued for the client, unread.
 */
static int drive_until_server_finished(SSL *sssl, SSL *cssl)
{
    int i, rc, rs, e;

    for (i = 0; i < 64 && !SSL_is_init_finished(sssl); i++) {
        if (!SSL_is_init_finished(cssl)) {
            rc = SSL_connect(cssl);
            if (rc <= 0) {
                e = SSL_get_error(cssl, rc);
                if (!TEST_true(e == SSL_ERROR_WANT_READ
                        || e == SSL_ERROR_WANT_WRITE))
                    return 0;
            }
        }
        rs = SSL_accept(sssl);
        if (rs <= 0) {
            e = SSL_get_error(sssl, rs);
            if (!TEST_true(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE))
                return 0;
        }
    }
    return SSL_is_init_finished(sssl);
}

/*
 * Expire the timer after the initial timeout check, while receiving the ACK.
 * Reading the rest of the ACK must not retransmit and overwrite its prefix.
 */
static int test_dtls13_ack_read_timeout(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    SSL_CONNECTION *sc;
    BIO *rbio = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        return 0;

    /* Leave only the ACK queued for the client. */
    if (!TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL))
        || !TEST_true(drive_until_server_finished(sssl, cssl)))
        goto end;

    if (!TEST_ptr(sc = SSL_CONNECTION_FROM_SSL_ONLY(cssl))
        || !TEST_false(SSL_is_init_finished(cssl))
        || !TEST_false(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;

    /* Prevent expiry before the BIO callback, independently of elapsed time. */
    sc->d1->next_timeout = ossl_time_infinite();
    rbio = SSL_get_rbio(cssl);
    BIO_set_callback_arg(rbio, (char *)sc);
    BIO_set_callback_ex(rbio, ack_read_timeout_cb);

    if (!TEST_int_eq(SSL_connect(cssl), 1)
        || !TEST_ptr_null(BIO_get_callback_arg(rbio))
        || !TEST_true(SSL_is_init_finished(cssl))
        || !TEST_true(SSL_is_init_finished(sssl)))
        goto end;

    testresult = 1;
end:
    if (rbio != NULL) {
        BIO_set_callback_ex(rbio, NULL);
        BIO_set_callback_arg(rbio, NULL);
    }
    SSL_free(cssl);
    SSL_free(sssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return testresult;
}

/*
 * Check that a DTLS 1.3 client that sends early data still retransmits its
 * ClientHello if the first flight is lost.
 */
static int test_dtls13_early_data_retransmit(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    SSL_SESSION *sess = NULL;
    BIO *s_rbio;
    struct timeval tv;
    unsigned char buf[2048];
    static const char msg[] = "early data";
    size_t written;
    int dropped = 0, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_max_early_data(sctx,
            SSL3_RT_MAX_PLAIN_LENGTH)))
        goto end;

    /* Do a full handshake to get a session that allows early data */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL))
        || !TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE))
        || !TEST_ptr(sess = SSL_get1_session(cssl))
        || !TEST_uint_gt(SSL_SESSION_get_max_early_data(sess), 0))
        goto end;
    shutdown_ssl_connection(sssl, cssl);
    sssl = cssl = NULL;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL))
        || !TEST_true(SSL_set_session(cssl, sess)))
        goto end;

    DTLS_set_timer_cb(cssl, timer_cb);

    /* Sends the ClientHello followed by the early data */
    if (!TEST_true(SSL_write_early_data(cssl, msg, sizeof(msg), &written))
        || !TEST_size_t_eq(written, sizeof(msg)))
        goto end;

    /* Lose everything the client has sent so far */
    s_rbio = SSL_get_rbio(sssl);
    while (BIO_ctrl_pending(s_rbio) > 0) {
        if (!TEST_int_gt(BIO_read(s_rbio, buf, sizeof(buf)), 0))
            goto end;
        dropped++;
    }
    if (!TEST_int_gt(dropped, 0))
        goto end;

    /* The ClientHello retransmission timer must be running */
    if (!TEST_int_gt((int)DTLSv1_get_timeout(cssl, &tv), 0))
        goto end;
    OSSL_sleep((uint64_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000) + 10);
    if (!TEST_int_gt((int)DTLSv1_handle_timeout(cssl), 0)
        || !TEST_size_t_gt(BIO_ctrl_pending(s_rbio), 0))
        goto end;

    /* The handshake should now complete using the retransmitted ClientHello */
    if (!TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE)))
        goto end;

    testresult = 1;
end:
    SSL_SESSION_free(sess);
    SSL_free(cssl);
    SSL_free(sssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return testresult;
}
#endif /* OPENSSL_NO_DTLS1_3 */

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
#ifndef OPENSSL_NO_DTLS1_3
    ADD_ALL_TESTS(test_cookie_exchange, 5);
#endif
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
    ADD_ALL_TESTS(test_seq_num_wrap, OSSL_NELEM(seqnum_tests));
    ADD_ALL_TESTS(test_dtls13_forged_plaintext_alert, 8);
    ADD_ALL_TESTS(test_dtls13_forged_plaintext_alert_plant, 3);
    ADD_TEST(test_dtls13_epoch0_plaintext_alert);
    ADD_TEST(test_dtls13_ccm8_not_offered);
    ADD_TEST(test_dtls13_ack_read_timeout);
    ADD_TEST(test_dtls13_early_data_retransmit);
#endif
#ifndef OPENSSL_NO_DTLS1_2
    ADD_TEST(test_dtls_client_retransmit);
    ADD_TEST(test_dtls_server_retransmit);
#endif
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECX) && !defined(OPENSSL_NO_ML_KEM) \
    && !defined(OPENSSL_NO_DTLS1_3)
    ADD_TEST(test_dtls_client_retransmit_dtls13);
    ADD_TEST(test_dtls_server_retransmit_dtls13);
#endif

    return 1;
}

void cleanup_tests(void)
{
    bio_f_tls_dump_filter_free();
    bio_s_mempacket_test_free();
}
