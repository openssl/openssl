/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/evp.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"

static char *cert = NULL;
static char *privkey = NULL;

#define TEST_PLAINTEXT_OVERFLOW_OK 0
#define TEST_PLAINTEXT_OVERFLOW_NOT_OK 1
#define TEST_ENCRYPTED_OVERFLOW_TLS1_3_OK 2
#define TEST_ENCRYPTED_OVERFLOW_TLS1_3_NOT_OK 3
#define TEST_ENCRYPTED_OVERFLOW_TLS1_2_OK 4
#define TEST_ENCRYPTED_OVERFLOW_TLS1_2_NOT_OK 5

#define TOTAL_RECORD_OVERFLOW_TESTS 6

static int write_record(BIO *b, size_t len, uint8_t rectype, int recversion)
{
    unsigned char header[SSL3_RT_HEADER_LENGTH];
    size_t written;
    unsigned char buf[256];

    memset(buf, 0, sizeof(buf));

    header[0] = rectype;
    header[1] = (recversion >> 8) & 0xff;
    header[2] = recversion & 0xff;
    header[3] = (len >> 8) & 0xff;
    header[4] = len & 0xff;

    if (!BIO_write_ex(b, header, SSL3_RT_HEADER_LENGTH, &written)
        || written != SSL3_RT_HEADER_LENGTH)
        return 0;

    while (len > 0) {
        size_t outlen;

        if (len > sizeof(buf))
            outlen = sizeof(buf);
        else
            outlen = len;

        if (!BIO_write_ex(b, buf, outlen, &written)
            || written != outlen)
            return 0;

        len -= outlen;
    }

    return 1;
}

#if !defined(OPENSSL_NO_DTLS1_2)
static int write_dtls_record(BIO *b, size_t len, uint8_t rectype,
    int recversion, uint16_t epoch, uint64_t seq)
{
    unsigned char record[DTLS1_RT_HEADER_LENGTH + 256] = { 0 };
    size_t written, i;

    if (len > sizeof(record) - DTLS1_RT_HEADER_LENGTH)
        return 0;

    record[0] = rectype;
    record[1] = (recversion >> 8) & 0xff;
    record[2] = recversion & 0xff;
    record[3] = (epoch >> 8) & 0xff;
    record[4] = epoch & 0xff;
    for (i = 0; i < 6; i++)
        record[10 - i] = (seq >> (8 * i)) & 0xff;
    record[11] = (len >> 8) & 0xff;
    record[12] = len & 0xff;

    return BIO_write_ex(b, record, DTLS1_RT_HEADER_LENGTH + len, &written)
        && written == DTLS1_RT_HEADER_LENGTH + len;
}
#endif

static int fail_due_to_record_overflow(int enc)
{
    long err = ERR_peek_error();
    int reason;

    if (enc)
        reason = SSL_R_ENCRYPTED_LENGTH_TOO_LONG;
    else
        reason = SSL_R_DATA_LENGTH_TOO_LONG;

    if (ERR_GET_LIB(err) == ERR_LIB_SSL
        && ERR_GET_REASON(err) == reason)
        return 1;

    return 0;
}

static int test_record_overflow(int idx)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    size_t len = 0;
    size_t written;
    int overf_expected;
    unsigned char buf;
    BIO *serverbio;
    int recversion;

#ifdef OPENSSL_NO_TLS1_2
    if (idx == TEST_ENCRYPTED_OVERFLOW_TLS1_2_OK
        || idx == TEST_ENCRYPTED_OVERFLOW_TLS1_2_NOT_OK)
        return 1;
#endif
#if defined(OPENSSL_NO_TLS1_3) \
    || (defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH))
    if (idx == TEST_ENCRYPTED_OVERFLOW_TLS1_3_OK
        || idx == TEST_ENCRYPTED_OVERFLOW_TLS1_3_NOT_OK)
        return 1;
#endif

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
            TLS_client_method(),
            TLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (idx == TEST_ENCRYPTED_OVERFLOW_TLS1_2_OK
        || idx == TEST_ENCRYPTED_OVERFLOW_TLS1_2_NOT_OK) {
        len = SSL3_RT_MAX_ENCRYPTED_LENGTH;
#ifndef OPENSSL_NO_COMP
        len -= SSL3_RT_MAX_COMPRESSED_OVERHEAD;
#endif
        SSL_CTX_set_max_proto_version(sctx, TLS1_2_VERSION);
    } else if (idx == TEST_ENCRYPTED_OVERFLOW_TLS1_3_OK
        || idx == TEST_ENCRYPTED_OVERFLOW_TLS1_3_NOT_OK) {
        len = SSL3_RT_MAX_TLS13_ENCRYPTED_LENGTH;
    }

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    serverbio = SSL_get_rbio(serverssl);

    if (idx == TEST_PLAINTEXT_OVERFLOW_OK
        || idx == TEST_PLAINTEXT_OVERFLOW_NOT_OK) {
        len = SSL3_RT_MAX_PLAIN_LENGTH;

        if (idx == TEST_PLAINTEXT_OVERFLOW_NOT_OK)
            len++;

        if (!TEST_true(write_record(serverbio, len,
                SSL3_RT_HANDSHAKE, TLS1_VERSION)))
            goto end;

        if (!TEST_int_le(SSL_accept(serverssl), 0))
            goto end;

        overf_expected = (idx == TEST_PLAINTEXT_OVERFLOW_OK) ? 0 : 1;
        if (!TEST_int_eq(fail_due_to_record_overflow(0), overf_expected))
            goto end;

        goto success;
    }

    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE)))
        goto end;

    if (idx == TEST_ENCRYPTED_OVERFLOW_TLS1_2_NOT_OK
        || idx == TEST_ENCRYPTED_OVERFLOW_TLS1_3_NOT_OK) {
        overf_expected = 1;
        len++;
    } else {
        overf_expected = 0;
    }

    recversion = TLS1_2_VERSION;

    if (!TEST_true(write_record(serverbio, len, SSL3_RT_APPLICATION_DATA,
            recversion)))
        goto end;

    if (!TEST_false(SSL_read_ex(serverssl, &buf, sizeof(buf), &written)))
        goto end;

    if (!TEST_int_eq(fail_due_to_record_overflow(1), overf_expected))
        goto end;

success:
    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int write_and_read_app_data(SSL *serverssl, SSL *clientssl)
{
    static const unsigned char msg = 0xa5;
    unsigned char buf = 0;
    size_t readbytes = 0, written = 0;

    return TEST_true(SSL_write_ex(clientssl, &msg, sizeof(msg), &written))
        && TEST_size_t_eq(written, sizeof(msg))
        && TEST_true(SSL_read_ex(serverssl, &buf, sizeof(buf),
            &readbytes))
        && TEST_size_t_eq(readbytes, sizeof(msg))
        && TEST_uchar_eq(buf, msg);
}

typedef enum {
    SHORT_AEAD_RECORD_AES,
    SHORT_AEAD_RECORD_ARIA,
    SHORT_AEAD_RECORD_CHACHA
} SHORT_AEAD_RECORD_CIPHER;

typedef struct {
    const char *cipher;
    size_t record_len;
    SHORT_AEAD_RECORD_CIPHER cipher_type;
} SHORT_AEAD_RECORD_TEST;

#if !defined(OPENSSL_NO_TLS1_2)
static const SHORT_AEAD_RECORD_TEST short_aead_record_tests[] = {
    { TLS1_TXT_RSA_WITH_AES_128_CCM, 0, SHORT_AEAD_RECORD_AES },
    { TLS1_TXT_RSA_WITH_AES_128_CCM,
        EVP_CCM_TLS_EXPLICIT_IV_LEN + EVP_CCM_TLS_TAG_LEN - 1,
        SHORT_AEAD_RECORD_AES },
    { TLS1_TXT_RSA_WITH_AES_128_CCM_8,
        EVP_CCM_TLS_EXPLICIT_IV_LEN + EVP_CCM8_TLS_TAG_LEN - 1,
        SHORT_AEAD_RECORD_AES },
    { TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256,
        EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN - 1,
        SHORT_AEAD_RECORD_AES },
    { TLS1_TXT_RSA_WITH_ARIA_128_GCM_SHA256,
        EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN - 1,
        SHORT_AEAD_RECORD_ARIA },
    { TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305,
        EVP_CHACHAPOLY_TLS_TAG_LEN - 1, SHORT_AEAD_RECORD_CHACHA },
};
#endif

static void alert_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    unsigned char *alert = arg;
    const unsigned char *alert_data = buf;

    if (write_p && content_type == SSL3_RT_ALERT && len == 2) {
        alert[0] = alert_data[0];
        alert[1] = alert_data[1];
    }
}

#ifndef OPENSSL_NO_TLS1_2
static int test_tls12_short_aead_record(int idx)
{
    const SHORT_AEAD_RECORD_TEST *test = &short_aead_record_tests[idx];
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    size_t readbytes;
    unsigned char buf, alert[2] = { 0 };

#ifdef OPENSSL_NO_AES
    if (test->cipher_type == SHORT_AEAD_RECORD_AES)
        return TEST_skip("AES is disabled");
#endif
#ifdef OPENSSL_NO_ARIA
    if (test->cipher_type == SHORT_AEAD_RECORD_ARIA)
        return TEST_skip("ARIA is disabled");
#endif
#if defined(OPENSSL_NO_CHACHA) || defined(OPENSSL_NO_POLY1305) \
    || defined(OPENSSL_NO_EC)
    if (test->cipher_type == SHORT_AEAD_RECORD_CHACHA)
        return TEST_skip("ChaCha20-Poly1305 or EC is disabled");
#endif

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
            TLS_client_method(), TLS1_2_VERSION, TLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /* CCM-8 is not available at the default security level. */
    SSL_CTX_set_security_level(sctx, 0);
    SSL_CTX_set_security_level(cctx, 0);

    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, test->cipher))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx, test->cipher))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    SSL_set_msg_callback(serverssl, alert_cb);
    SSL_set_msg_callback_arg(serverssl, &alert);

    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_true(write_and_read_app_data(serverssl, clientssl))
        || !TEST_true(write_record(SSL_get_rbio(serverssl), test->record_len,
            SSL3_RT_APPLICATION_DATA, TLS1_2_VERSION))
        || !TEST_false(SSL_read_ex(serverssl, &buf, sizeof(buf), &readbytes))
        || !TEST_uchar_eq(alert[0], SSL3_AL_FATAL)
        || !TEST_uchar_eq(alert[1], SSL_AD_BAD_RECORD_MAC))
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

#ifndef OPENSSL_NO_DTLS1_2
static int test_dtls12_short_aead_record(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0, ret;
    size_t readbytes = 0;
    unsigned char buf = 0, alert[2] = { 0 };

#ifdef OPENSSL_NO_AES
    return TEST_skip("AES is disabled");
#endif

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    SSL_CTX_set_security_level(sctx, 0);
    SSL_CTX_set_security_level(cctx, 0);

    if (!TEST_true(SSL_CTX_set_cipher_list(sctx,
            TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx,
            TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    SSL_set_msg_callback(serverssl, alert_cb);
    SSL_set_msg_callback_arg(serverssl, &alert);

    /*
     * The forged record uses the first application-data sequence number. A
     * valid client write after this must still be accepted.
     */
    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_true(write_dtls_record(SSL_get_rbio(serverssl),
            EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN - 1,
            SSL3_RT_APPLICATION_DATA, DTLS1_2_VERSION, 1, 1)))
        goto end;

    ERR_clear_error();
    ret = SSL_read_ex(serverssl, &buf, sizeof(buf), &readbytes);
    if (!TEST_false(ret)
        || !TEST_int_eq(SSL_get_error(serverssl, ret), SSL_ERROR_WANT_READ)
        || !TEST_uchar_eq(alert[0], 0)
        || !TEST_uchar_eq(alert[1], 0)
        || !TEST_true(write_and_read_app_data(serverssl, clientssl)))
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

    ADD_ALL_TESTS(test_record_overflow, TOTAL_RECORD_OVERFLOW_TESTS);
#ifndef OPENSSL_NO_TLS1_2
    ADD_ALL_TESTS(test_tls12_short_aead_record,
        OSSL_NELEM(short_aead_record_tests));
#endif
#ifndef OPENSSL_NO_DTLS1_2
    ADD_TEST(test_dtls12_short_aead_record);
#endif
    return 1;
}

void cleanup_tests(void)
{
    bio_s_mempacket_test_free();
}
