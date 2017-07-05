/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>

#include "ssltestlib.h"
#include "testutil.h"
#include "e_os.h"
#include "../ssl/ssl_locl.h"

static char *cert = NULL;
static char *privkey = NULL;

#define LOG_BUFFER_SIZE 1024
static char server_log_buffer[LOG_BUFFER_SIZE + 1] = {0};
static size_t server_log_buffer_index = 0;
static char client_log_buffer[LOG_BUFFER_SIZE + 1] = {0};
static size_t client_log_buffer_index = 0;
static int error_writing_log = 0;

#ifndef OPENSSL_NO_OCSP
static const unsigned char orespder[] = "Dummy OCSP Response";
static int ocsp_server_called = 0;
static int ocsp_client_called = 0;

static int cdummyarg = 1;
static X509 *ocspcert = NULL;
#endif

#define NUM_EXTRA_CERTS 40

/*
 * This structure is used to validate that the correct number of log messages
 * of various types are emitted when emitting secret logs.
 */
struct sslapitest_log_counts {
    unsigned int rsa_key_exchange_count;
    unsigned int master_secret_count;
    unsigned int client_handshake_secret_count;
    unsigned int server_handshake_secret_count;
    unsigned int client_application_secret_count;
    unsigned int server_application_secret_count;
};


static unsigned char serverinfov1[] = {
    0xff, 0xff, /* Dummy extension type */
    0x00, 0x01, /* Extension length is 1 byte */
    0xff        /* Dummy extension data */
};

static unsigned char serverinfov2[] = {
    0x00, 0x00, 0x00,
    (unsigned char)(SSL_EXT_CLIENT_HELLO & 0xff), /* Dummy context - 4 bytes */
    0xff, 0xff, /* Dummy extension type */
    0x00, 0x01, /* Extension length is 1 byte */
    0xff        /* Dummy extension data */
};

static void client_keylog_callback(const SSL *ssl, const char *line)
{
    int line_length = strlen(line);

    /* If the log doesn't fit, error out. */
    if (client_log_buffer_index + line_length > sizeof(client_log_buffer) - 1) {
        TEST_info("Client log too full");
        error_writing_log = 1;
        return;
    }

    strcat(client_log_buffer, line);
    client_log_buffer_index += line_length;
    client_log_buffer[client_log_buffer_index++] = '\n';
}

static void server_keylog_callback(const SSL *ssl, const char *line)
{
    int line_length = strlen(line);

    /* If the log doesn't fit, error out. */
    if (server_log_buffer_index + line_length > sizeof(server_log_buffer) - 1) {
        TEST_info("Server og too full");
        error_writing_log = 1;
        return;
    }

    strcat(server_log_buffer, line);
    server_log_buffer_index += line_length;
    server_log_buffer[server_log_buffer_index++] = '\n';
}

static int compare_hex_encoded_buffer(const char *hex_encoded,
                                      size_t hex_length,
                                      const uint8_t *raw,
                                      size_t raw_length)
{
    size_t i, j;
    char hexed[3];

    if (!TEST_size_t_eq(raw_length * 2, hex_length))
        return 1;

    for (i = j = 0; i < raw_length && j + 1 < hex_length; i++, j += 2) {
        sprintf(hexed, "%02x", raw[i]);
        if (!TEST_int_eq(hexed[0], hex_encoded[j])
                || !TEST_int_eq(hexed[1], hex_encoded[j + 1]))
            return 1;
    }

    return 0;
}

static int test_keylog_output(char *buffer, const SSL *ssl,
                              const SSL_SESSION *session,
                              struct sslapitest_log_counts *expected)
{
    char *token = NULL;
    unsigned char actual_client_random[SSL3_RANDOM_SIZE] = {0};
    size_t client_random_size = SSL3_RANDOM_SIZE;
    unsigned char actual_master_key[SSL_MAX_MASTER_KEY_LENGTH] = {0};
    size_t master_key_size = SSL_MAX_MASTER_KEY_LENGTH;
    unsigned int rsa_key_exchange_count = 0;
    unsigned int master_secret_count = 0;
    unsigned int client_handshake_secret_count = 0;
    unsigned int server_handshake_secret_count = 0;
    unsigned int client_application_secret_count = 0;
    unsigned int server_application_secret_count = 0;

    for (token = strtok(buffer, " \n"); token != NULL;
         token = strtok(NULL, " \n")) {
        if (strcmp(token, "RSA") == 0) {
            /*
             * Premaster secret. Tokens should be: 16 ASCII bytes of
             * hex-encoded encrypted secret, then the hex-encoded pre-master
             * secret.
             */
            if (!TEST_ptr(token = strtok(NULL, " \n")))
                return 0;
            if (!TEST_size_t_eq(strlen(token), 16))
                return 0;
            if (!TEST_ptr(token = strtok(NULL, " \n")))
                return 0;
            /*
             * We can't sensibly check the log because the premaster secret is
             * transient, and OpenSSL doesn't keep hold of it once the master
             * secret is generated.
             */
            rsa_key_exchange_count++;
        } else if (strcmp(token, "CLIENT_RANDOM") == 0) {
            /*
             * Master secret. Tokens should be: 64 ASCII bytes of hex-encoded
             * client random, then the hex-encoded master secret.
             */
            client_random_size = SSL_get_client_random(ssl,
                                                       actual_client_random,
                                                       SSL3_RANDOM_SIZE);
            if (!TEST_size_t_eq(client_random_size, SSL3_RANDOM_SIZE))
                return 0;

            if (!TEST_ptr(token = strtok(NULL, " \n")))
                return 0;
            if (!TEST_size_t_eq(strlen(token), 64))
                return 0;
            if (!TEST_false(compare_hex_encoded_buffer(token, 64,
                                                       actual_client_random,
                                                       client_random_size)))
                return 0;

            if (!TEST_ptr(token = strtok(NULL, " \n")))
                return 0;
            master_key_size = SSL_SESSION_get_master_key(session,
                                                         actual_master_key,
                                                         master_key_size);
            if (!TEST_size_t_ne(master_key_size, 0))
                return 0;
            if (!TEST_false(compare_hex_encoded_buffer(token, strlen(token),
                                                       actual_master_key,
                                                       master_key_size)))
                return 0;
            master_secret_count++;
        } else if (strcmp(token, "CLIENT_HANDSHAKE_TRAFFIC_SECRET") == 0
                    || strcmp(token, "SERVER_HANDSHAKE_TRAFFIC_SECRET") == 0
                    || strcmp(token, "CLIENT_TRAFFIC_SECRET_0") == 0
                    || strcmp(token, "SERVER_TRAFFIC_SECRET_0") == 0) {
            /*
             * TLSv1.3 secret. Tokens should be: 64 ASCII bytes of hex-encoded
             * client random, and then the hex-encoded secret. In this case,
             * we treat all of these secrets identically and then just
             * distinguish between them when counting what we saw.
             */
            if (strcmp(token, "CLIENT_HANDSHAKE_TRAFFIC_SECRET") == 0)
                client_handshake_secret_count++;
            else if (strcmp(token, "SERVER_HANDSHAKE_TRAFFIC_SECRET") == 0)
                server_handshake_secret_count++;
            else if (strcmp(token, "CLIENT_TRAFFIC_SECRET_0") == 0)
                client_application_secret_count++;
            else if (strcmp(token, "SERVER_TRAFFIC_SECRET_0") == 0)
                server_application_secret_count++;

            client_random_size = SSL_get_client_random(ssl,
                                                       actual_client_random,
                                                       SSL3_RANDOM_SIZE);
            if (!TEST_size_t_eq(client_random_size, SSL3_RANDOM_SIZE))
                return 0;

            if (!TEST_ptr(token = strtok(NULL, " \n")))
                return 0;
            if (!TEST_size_t_eq(strlen(token), 64))
                return 0;
            if (!TEST_false(compare_hex_encoded_buffer(token, 64,
                                                       actual_client_random,
                                                       client_random_size)))
                return 0;

            if (!TEST_ptr(token = strtok(NULL, " \n")))
                return 0;

            /*
             * TODO(TLS1.3): test that application traffic secrets are what
             * we expect */
        } else {
            TEST_info("Unexpected token %s\n", token);
            return 0;
        }
    }

    /* Got what we expected? */
    if (!TEST_size_t_eq(rsa_key_exchange_count,
                        expected->rsa_key_exchange_count)
            || !TEST_size_t_eq(master_secret_count,
                               expected->master_secret_count)
            || !TEST_size_t_eq(client_handshake_secret_count,
                               expected->client_handshake_secret_count)
            || !TEST_size_t_eq(server_handshake_secret_count,
                               expected->server_handshake_secret_count)
            || !TEST_size_t_eq(client_application_secret_count,
                               expected->client_application_secret_count)
            || !TEST_size_t_eq(server_application_secret_count,
                               expected->server_application_secret_count))
        return 0;
    return 1;
}

static int test_keylog(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    struct sslapitest_log_counts expected = {0};

    /* Clean up logging space */
    memset(client_log_buffer, 0, sizeof(client_log_buffer));
    memset(server_log_buffer, 0, sizeof(server_log_buffer));
    client_log_buffer_index = 0;
    server_log_buffer_index = 0;
    error_writing_log = 0;

    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(),
                                       TLS_client_method(),
                                       &sctx, &cctx, cert, privkey)))
        return 0;

    /* We cannot log the master secret for TLSv1.3, so we should forbid it. */
    SSL_CTX_set_options(cctx, SSL_OP_NO_TLSv1_3);
    SSL_CTX_set_options(sctx, SSL_OP_NO_TLSv1_3);

    /* We also want to ensure that we use RSA-based key exchange. */
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "RSA")))
        goto end;

    if (!TEST_true(SSL_CTX_get_keylog_callback(cctx) == NULL)
            || !TEST_true(SSL_CTX_get_keylog_callback(sctx) == NULL))
        goto end;
    SSL_CTX_set_keylog_callback(cctx, client_keylog_callback);
    if (!TEST_true(SSL_CTX_get_keylog_callback(cctx)
                   == client_keylog_callback))
        goto end;
    SSL_CTX_set_keylog_callback(sctx, server_keylog_callback);
    if (!TEST_true(SSL_CTX_get_keylog_callback(sctx)
                   == server_keylog_callback))
        goto end;

    /* Now do a handshake and check that the logs have been written to. */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE))
            || !TEST_false(error_writing_log)
            || !TEST_int_gt(client_log_buffer_index, 0)
            || !TEST_int_gt(server_log_buffer_index, 0))
        goto end;

    /*
     * Now we want to test that our output data was vaguely sensible. We
     * do that by using strtok and confirming that we have more or less the
     * data we expect. For both client and server, we expect to see one master
     * secret. The client should also see a RSA key exchange.
     */
    expected.rsa_key_exchange_count = 1;
    expected.master_secret_count = 1;
    if (!TEST_true(test_keylog_output(client_log_buffer, clientssl,
                                      SSL_get_session(clientssl), &expected)))
        goto end;

    expected.rsa_key_exchange_count = 0;
    if (!TEST_true(test_keylog_output(server_log_buffer, serverssl,
                                      SSL_get_session(serverssl), &expected)))
        goto end;

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

#ifndef OPENSSL_NO_TLS1_3
static int test_keylog_no_master_key(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    struct sslapitest_log_counts expected = {0};

    /* Clean up logging space */
    memset(client_log_buffer, 0, sizeof(client_log_buffer));
    memset(server_log_buffer, 0, sizeof(server_log_buffer));
    client_log_buffer_index = 0;
    server_log_buffer_index = 0;
    error_writing_log = 0;

    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(),
                             TLS_client_method(), &sctx,
                             &cctx, cert, privkey)))
        return 0;

    if (!TEST_true(SSL_CTX_get_keylog_callback(cctx) == NULL)
            || !TEST_true(SSL_CTX_get_keylog_callback(sctx) == NULL))
        goto end;

    SSL_CTX_set_keylog_callback(cctx, client_keylog_callback);
    if (!TEST_true(SSL_CTX_get_keylog_callback(cctx)
                   == client_keylog_callback))
        goto end;

    SSL_CTX_set_keylog_callback(sctx, server_keylog_callback);
    if (!TEST_true(SSL_CTX_get_keylog_callback(sctx)
                   == server_keylog_callback))
        goto end;

    /* Now do a handshake and check that the logs have been written to. */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE))
            || !TEST_false(error_writing_log))
        goto end;

    /*
     * Now we want to test that our output data was vaguely sensible. For this
     * test, we expect no CLIENT_RANDOM entry because it doesn't make sense for
     * TLSv1.3, but we do expect both client and server to emit keys.
     */
    expected.client_handshake_secret_count = 1;
    expected.server_handshake_secret_count = 1;
    expected.client_application_secret_count = 1;
    expected.server_application_secret_count = 1;
    if (!TEST_true(test_keylog_output(client_log_buffer, clientssl,
                                      SSL_get_session(clientssl), &expected))
            || !TEST_true(test_keylog_output(server_log_buffer, serverssl,
                                             SSL_get_session(serverssl),
                                             &expected)))
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

#ifndef OPENSSL_NO_TLS1_2
static int full_early_callback(SSL *s, int *al, void *arg)
{
    int *ctr = arg;
    const unsigned char *p;
    int *exts;
    /* We only configure two ciphers, but the SCSV is added automatically. */
#ifdef OPENSSL_NO_EC
    const unsigned char expected_ciphers[] = {0x00, 0x9d, 0x00, 0xff};
#else
    const unsigned char expected_ciphers[] = {0x00, 0x9d, 0xc0,
                                              0x2c, 0x00, 0xff};
#endif
    const int expected_extensions[] = {
#ifndef OPENSSL_NO_EC
                                       11, 10,
#endif
                                       35, 13, 22, 23};
    size_t len;

    /* Make sure we can defer processing and get called back. */
    if ((*ctr)++ == 0)
        return -1;

    len = SSL_early_get0_ciphers(s, &p);
    if (!TEST_mem_eq(p, len, expected_ciphers, sizeof(expected_ciphers))
            || !TEST_size_t_eq(SSL_early_get0_compression_methods(s, &p), 1)
            || !TEST_int_eq(*p, 0))
        return 0;
    if (!SSL_early_get1_extensions_present(s, &exts, &len))
        return 0;
    if (len != OSSL_NELEM(expected_extensions) ||
        memcmp(exts, expected_extensions, len * sizeof(*exts)) != 0) {
        printf("Early callback expected ClientHello extensions mismatch\n");
        OPENSSL_free(exts);
        return 0;
    }
    OPENSSL_free(exts);
    return 1;
}

static int test_early_cb(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testctr = 0, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(),
                                       TLS_client_method(), &sctx,
                                       &cctx, cert, privkey)))
        goto end;
    SSL_CTX_set_early_cb(sctx, full_early_callback, &testctr);

    /* The gimpy cipher list we configure can't do TLS 1.3. */
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);

    if (!TEST_true(SSL_CTX_set_cipher_list(cctx,
                        "AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384"))
            || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                             &clientssl, NULL, NULL))
            || !TEST_false(create_ssl_connection(serverssl, clientssl,
                                                 SSL_ERROR_WANT_EARLY))
                /*
                 * Passing a -1 literal is a hack since
                 * the real value was lost.
                 * */
            || !TEST_int_eq(SSL_get_error(serverssl, -1), SSL_ERROR_WANT_EARLY)
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
#endif

static int execute_test_large_message(const SSL_METHOD *smeth,
                                      const SSL_METHOD *cmeth, int read_ahead)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    int i;
    BIO *certbio = NULL;
    X509 *chaincert = NULL;
    int certlen;

    if (!TEST_ptr(certbio = BIO_new_file(cert, "r")))
        goto end;
    chaincert = PEM_read_bio_X509(certbio, NULL, NULL, NULL);
    BIO_free(certbio);
    certbio = NULL;
    if (!TEST_ptr(chaincert))
        goto end;

    if (!TEST_true(create_ssl_ctx_pair(smeth, cmeth, &sctx,
                                       &cctx, cert, privkey)))
        goto end;

    if (read_ahead) {
        /*
         * Test that read_ahead works correctly when dealing with large
         * records
         */
        SSL_CTX_set_read_ahead(cctx, 1);
    }

    /*
     * We assume the supplied certificate is big enough so that if we add
     * NUM_EXTRA_CERTS it will make the overall message large enough. The
     * default buffer size is requested to be 16k, but due to the way BUF_MEM
     * works, it ends up allocating a little over 21k (16 * 4/3). So, in this
     * test we need to have a message larger than that.
     */
    certlen = i2d_X509(chaincert, NULL);
    OPENSSL_assert(certlen * NUM_EXTRA_CERTS >
                   (SSL3_RT_MAX_PLAIN_LENGTH * 4) / 3);
    for (i = 0; i < NUM_EXTRA_CERTS; i++) {
        if (!X509_up_ref(chaincert))
            goto end;
        if (!SSL_CTX_add_extra_chain_cert(sctx, chaincert)) {
            X509_free(chaincert);
            goto end;
        }
    }

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    /*
     * Calling SSL_clear() first is not required but this tests that SSL_clear()
     * doesn't leak (when using enable-crypto-mdebug).
     */
    if (!TEST_true(SSL_clear(serverssl)))
        goto end;

    testresult = 1;
 end:
    X509_free(chaincert);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

static int test_large_message_tls(void)
{
    return execute_test_large_message(TLS_server_method(), TLS_client_method(),
                                      0);
}

static int test_large_message_tls_read_ahead(void)
{
    return execute_test_large_message(TLS_server_method(), TLS_client_method(),
                                      1);
}

#ifndef OPENSSL_NO_DTLS
static int test_large_message_dtls(void)
{
    /*
     * read_ahead is not relevant to DTLS because DTLS always acts as if
     * read_ahead is set.
     */
    return execute_test_large_message(DTLS_server_method(),
                                      DTLS_client_method(), 0);
}
#endif

#ifndef OPENSSL_NO_OCSP
static int ocsp_server_cb(SSL *s, void *arg)
{
    int *argi = (int *)arg;
    unsigned char *copy = NULL;
    STACK_OF(OCSP_RESPID) *ids = NULL;
    OCSP_RESPID *id = NULL;

    if (*argi == 2) {
        /* In this test we are expecting exactly 1 OCSP_RESPID */
        SSL_get_tlsext_status_ids(s, &ids);
        if (ids == NULL || sk_OCSP_RESPID_num(ids) != 1)
            return SSL_TLSEXT_ERR_ALERT_FATAL;

        id = sk_OCSP_RESPID_value(ids, 0);
        if (id == NULL || !OCSP_RESPID_match(id, ocspcert))
            return SSL_TLSEXT_ERR_ALERT_FATAL;
    } else if (*argi != 1) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (!TEST_ptr(copy = OPENSSL_memdup(orespder, sizeof(orespder))))
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    SSL_set_tlsext_status_ocsp_resp(s, copy, sizeof(orespder));
    ocsp_server_called = 1;
    return SSL_TLSEXT_ERR_OK;
}

static int ocsp_client_cb(SSL *s, void *arg)
{
    int *argi = (int *)arg;
    const unsigned char *respderin;
    size_t len;

    if (*argi != 1 && *argi != 2)
        return 0;

    len = SSL_get_tlsext_status_ocsp_resp(s, &respderin);
    if (!TEST_mem_eq(orespder, len, respderin, len))
        return 0;

    ocsp_client_called = 1;
    return 1;
}

static int test_tlsext_status_type(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    STACK_OF(OCSP_RESPID) *ids = NULL;
    OCSP_RESPID *id = NULL;
    BIO *certbio = NULL;

    if (!create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(), &sctx,
                             &cctx, cert, privkey))
        return 0;

    if (SSL_CTX_get_tlsext_status_type(cctx) != -1)
        goto end;

    /* First just do various checks getting and setting tlsext_status_type */

    clientssl = SSL_new(cctx);
    if (!TEST_int_eq(SSL_get_tlsext_status_type(clientssl), -1)
            || !TEST_true(SSL_set_tlsext_status_type(clientssl,
                                                      TLSEXT_STATUSTYPE_ocsp))
            || !TEST_int_eq(SSL_get_tlsext_status_type(clientssl),
                            TLSEXT_STATUSTYPE_ocsp))
        goto end;

    SSL_free(clientssl);
    clientssl = NULL;

    if (!SSL_CTX_set_tlsext_status_type(cctx, TLSEXT_STATUSTYPE_ocsp)
     || SSL_CTX_get_tlsext_status_type(cctx) != TLSEXT_STATUSTYPE_ocsp)
        goto end;

    clientssl = SSL_new(cctx);
    if (SSL_get_tlsext_status_type(clientssl) != TLSEXT_STATUSTYPE_ocsp)
        goto end;
    SSL_free(clientssl);
    clientssl = NULL;

    /*
     * Now actually do a handshake and check OCSP information is exchanged and
     * the callbacks get called
     */
    SSL_CTX_set_tlsext_status_cb(cctx, ocsp_client_cb);
    SSL_CTX_set_tlsext_status_arg(cctx, &cdummyarg);
    SSL_CTX_set_tlsext_status_cb(sctx, ocsp_server_cb);
    SSL_CTX_set_tlsext_status_arg(sctx, &cdummyarg);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE))
            || !TEST_true(ocsp_client_called)
            || !TEST_true(ocsp_server_called))
        goto end;
    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = NULL;
    clientssl = NULL;

    /* Try again but this time force the server side callback to fail */
    ocsp_client_called = 0;
    ocsp_server_called = 0;
    cdummyarg = 0;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL))
                /* This should fail because the callback will fail */
            || !TEST_false(create_ssl_connection(serverssl, clientssl,
                                                 SSL_ERROR_NONE))
            || !TEST_false(ocsp_client_called)
            || !TEST_false(ocsp_server_called))
        goto end;
    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = NULL;
    clientssl = NULL;

    /*
     * This time we'll get the client to send an OCSP_RESPID that it will
     * accept.
     */
    ocsp_client_called = 0;
    ocsp_server_called = 0;
    cdummyarg = 2;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;

    /*
     * We'll just use any old cert for this test - it doesn't have to be an OCSP
     * specific one. We'll use the server cert.
     */
    if (!TEST_ptr(certbio = BIO_new_file(cert, "r"))
            || !TEST_ptr(id = OCSP_RESPID_new())
            || !TEST_ptr(ids = sk_OCSP_RESPID_new_null())
            || !TEST_ptr(ocspcert = PEM_read_bio_X509(certbio,
                                                      NULL, NULL, NULL))
            || !TEST_true(OCSP_RESPID_set_by_key(id, ocspcert))
            || !TEST_true(sk_OCSP_RESPID_push(ids, id)))
        goto end;
    id = NULL;
    SSL_set_tlsext_status_ids(clientssl, ids);
    /* Control has been transferred */
    ids = NULL;

    BIO_free(certbio);
    certbio = NULL;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                                         SSL_ERROR_NONE))
            || !TEST_true(ocsp_client_called)
            || !TEST_true(ocsp_server_called))
        goto end;

    testresult = 1;

 end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    sk_OCSP_RESPID_pop_free(ids, OCSP_RESPID_free);
    OCSP_RESPID_free(id);
    BIO_free(certbio);
    X509_free(ocspcert);
    ocspcert = NULL;

    return testresult;
}
#endif

typedef struct ssl_session_test_fixture {
    const char *test_case_name;
    int use_ext_cache;
    int use_int_cache;
} SSL_SESSION_TEST_FIXTURE;

static int new_called = 0, remove_called = 0;

static SSL_SESSION_TEST_FIXTURE
ssl_session_set_up(const char *const test_case_name)
{
    SSL_SESSION_TEST_FIXTURE fixture;

    fixture.test_case_name = test_case_name;
    fixture.use_ext_cache = 1;
    fixture.use_int_cache = 1;

    new_called = remove_called = 0;

    return fixture;
}

static void ssl_session_tear_down(SSL_SESSION_TEST_FIXTURE fixture)
{
}

static int new_session_cb(SSL *ssl, SSL_SESSION *sess)
{
    new_called++;
    return 1;
}

static void remove_session_cb(SSL_CTX *ctx, SSL_SESSION *sess)
{
    remove_called++;
}

static int execute_test_session(SSL_SESSION_TEST_FIXTURE fix)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl1 = NULL, *clientssl1 = NULL;
    SSL *serverssl2 = NULL, *clientssl2 = NULL;
#ifndef OPENSSL_NO_TLS1_1
    SSL *serverssl3 = NULL, *clientssl3 = NULL;
#endif
    SSL_SESSION *sess1 = NULL, *sess2 = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(),
                                       TLS_client_method(), &sctx,
                                       &cctx, cert, privkey)))
        return 0;

#ifndef OPENSSL_NO_TLS1_2
    /* Only allow TLS1.2 so we can force a connection failure later */
    SSL_CTX_set_min_proto_version(cctx, TLS1_2_VERSION);
#endif

    /* Set up session cache */
    if (fix.use_ext_cache) {
        SSL_CTX_sess_set_new_cb(cctx, new_session_cb);
        SSL_CTX_sess_set_remove_cb(cctx, remove_session_cb);
    }
    if (fix.use_int_cache) {
        /* Also covers instance where both are set */
        SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    } else {
        SSL_CTX_set_session_cache_mode(cctx,
                                       SSL_SESS_CACHE_CLIENT
                                       | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    }

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl1, &clientssl1,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl1, clientssl1,
                                                SSL_ERROR_NONE))
            || !TEST_ptr(sess1 = SSL_get1_session(clientssl1)))
        goto end;

    /* Should fail because it should already be in the cache */
    if (fix.use_int_cache && !TEST_false(SSL_CTX_add_session(cctx, sess1)))
        goto end;
    if (fix.use_ext_cache && (new_called != 1 || remove_called != 0))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl2,
                                      &clientssl2, NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl2, clientssl2,
                                                SSL_ERROR_NONE)))
        goto end;

    if (!TEST_ptr(sess2 = SSL_get1_session(clientssl2)))
        goto end;

    if (fix.use_ext_cache && (new_called != 2 || remove_called != 0))
        goto end;

    /*
     * This should clear sess2 from the cache because it is a "bad" session.
     * See SSL_set_session() documentation.
     */
    if (!TEST_true(SSL_set_session(clientssl2, sess1)))
        goto end;
    if (fix.use_ext_cache && (new_called != 2 || remove_called != 1))
        goto end;
    if (!TEST_ptr_eq(SSL_get_session(clientssl2), sess1))
        goto end;

    if (fix.use_int_cache) {
        /* Should succeeded because it should not already be in the cache */
        if (!TEST_true(SSL_CTX_add_session(cctx, sess2))
                || !TEST_true(SSL_CTX_remove_session(cctx, sess2)))
            goto end;

        /*
         * This is for the purposes of internal cache testing...ignore the
         * counter for external cache
         */
        if (fix.use_ext_cache)
            remove_called--;
    }

    /* This shouldn't be in the cache so should fail */
    if (!TEST_false(SSL_CTX_remove_session(cctx, sess2)))
        goto end;

    if (fix.use_ext_cache && (new_called != 2 || remove_called != 2))
        goto end;

#if !defined(OPENSSL_NO_TLS1_1) && !defined(OPENSSL_NO_TLS1_2)
    /* Force a connection failure */
    SSL_CTX_set_max_proto_version(sctx, TLS1_1_VERSION);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl3,
                                      &clientssl3, NULL, NULL))
            || !TEST_true(SSL_set_session(clientssl3, sess1))
        /* This should fail because of the mismatched protocol versions */
            || !TEST_false(create_ssl_connection(serverssl3, clientssl3,
                                                 SSL_ERROR_NONE)))
        goto end;

    /* We should have automatically removed the session from the cache */
    if (fix.use_ext_cache && (new_called != 2 || remove_called != 3))
        goto end;

    /* Should succeed because it should not already be in the cache */
    if (fix.use_int_cache && !SSL_CTX_add_session(cctx, sess2))
        goto end;
#endif

    testresult = 1;

 end:
    SSL_free(serverssl1);
    SSL_free(clientssl1);
    SSL_free(serverssl2);
    SSL_free(clientssl2);
#ifndef OPENSSL_NO_TLS1_1
    SSL_free(serverssl3);
    SSL_free(clientssl3);
#endif
    SSL_SESSION_free(sess1);
    SSL_SESSION_free(sess2);

    /*
     * Check if we need to remove any sessions up-refed for the external cache
     */
    if (new_called >= 1)
        SSL_SESSION_free(sess1);
    if (new_called >= 2)
        SSL_SESSION_free(sess2);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

static int test_session_with_only_int_cache(void)
{
    SETUP_TEST_FIXTURE(SSL_SESSION_TEST_FIXTURE, ssl_session_set_up);
    fixture.use_ext_cache = 0;
    EXECUTE_TEST(execute_test_session, ssl_session_tear_down);
}

static int test_session_with_only_ext_cache(void)
{
    SETUP_TEST_FIXTURE(SSL_SESSION_TEST_FIXTURE, ssl_session_set_up);
    fixture.use_int_cache = 0;
    EXECUTE_TEST(execute_test_session, ssl_session_tear_down);
}

static int test_session_with_both_cache(void)
{
    SETUP_TEST_FIXTURE(SSL_SESSION_TEST_FIXTURE, ssl_session_set_up);
    EXECUTE_TEST(execute_test_session, ssl_session_tear_down);
}

#define USE_NULL    0
#define USE_BIO_1   1
#define USE_BIO_2   2

#define TOTAL_SSL_SET_BIO_TESTS (3 * 3 * 3 * 3)

static void setupbio(BIO **res, BIO *bio1, BIO *bio2, int type)
{
    switch (type) {
    case USE_NULL:
        *res = NULL;
        break;
    case USE_BIO_1:
        *res = bio1;
        break;
    case USE_BIO_2:
        *res = bio2;
        break;
    }
}

static int test_ssl_set_bio(int idx)
{
    SSL_CTX *ctx;
    BIO *bio1 = NULL;
    BIO *bio2 = NULL;
    BIO *irbio = NULL, *iwbio = NULL, *nrbio = NULL, *nwbio = NULL;
    SSL *ssl = NULL;
    int initrbio, initwbio, newrbio, newwbio;
    int testresult = 0;

    initrbio = idx % 3;
    idx /= 3;
    initwbio = idx % 3;
    idx /= 3;
    newrbio = idx % 3;
    idx /= 3;
    newwbio = idx;
    if (!TEST_int_le(newwbio, 2))
        return 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_method()))
                || !TEST_ptr(ssl = SSL_new(ctx)))
        goto end;

    if (initrbio == USE_BIO_1
            || initwbio == USE_BIO_1
            || newrbio == USE_BIO_1
            || newwbio == USE_BIO_1) {
        if (!TEST_ptr(bio1 = BIO_new(BIO_s_mem())))
            goto end;
    }

    if (initrbio == USE_BIO_2
            || initwbio == USE_BIO_2
            || newrbio == USE_BIO_2
            || newwbio == USE_BIO_2) {
        if (!TEST_ptr(bio2 = BIO_new(BIO_s_mem())))
            goto end;
    }

    setupbio(&irbio, bio1, bio2, initrbio);
    setupbio(&iwbio, bio1, bio2, initwbio);

    /*
     * We want to maintain our own refs to these BIO, so do an up ref for each
     * BIO that will have ownership transferred in the SSL_set_bio() call
     */
    if (irbio != NULL)
        BIO_up_ref(irbio);
    if (iwbio != NULL && iwbio != irbio)
        BIO_up_ref(iwbio);

    SSL_set_bio(ssl, irbio, iwbio);

    setupbio(&nrbio, bio1, bio2, newrbio);
    setupbio(&nwbio, bio1, bio2, newwbio);

    /*
     * We will (maybe) transfer ownership again so do more up refs.
     * SSL_set_bio() has some really complicated ownership rules where BIOs have
     * already been set!
     */
    if (nrbio != NULL
            && nrbio != irbio
            && (nwbio != iwbio || nrbio != nwbio))
        BIO_up_ref(nrbio);
    if (nwbio != NULL
            && nwbio != nrbio
            && (nwbio != iwbio || (nwbio == iwbio && irbio == iwbio)))
        BIO_up_ref(nwbio);

    SSL_set_bio(ssl, nrbio, nwbio);

    testresult = 1;

 end:
    SSL_free(ssl);
    BIO_free(bio1);
    BIO_free(bio2);

    /*
     * This test is checking that the ref counting for SSL_set_bio is correct.
     * If we get here and we did too many frees then we will fail in the above
     * functions. If we haven't done enough then this will only be detected in
     * a crypto-mdebug build
     */
    SSL_CTX_free(ctx);
    return testresult;
}

typedef struct ssl_bio_test_fixture {
    const char *test_case_name;
    int pop_ssl;
    enum { NO_BIO_CHANGE, CHANGE_RBIO, CHANGE_WBIO } change_bio;
} SSL_BIO_TEST_FIXTURE;

static SSL_BIO_TEST_FIXTURE ssl_bio_set_up(const char *const test_case_name)
{
    SSL_BIO_TEST_FIXTURE fixture;

    fixture.test_case_name = test_case_name;
    fixture.pop_ssl = 0;
    fixture.change_bio = NO_BIO_CHANGE;
    return fixture;
}

static void ssl_bio_tear_down(SSL_BIO_TEST_FIXTURE fixture)
{
}

static int execute_test_ssl_bio(SSL_BIO_TEST_FIXTURE fix)
{
    BIO *sslbio = NULL, *membio1 = NULL, *membio2 = NULL;
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    int testresult = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_method()))
            || !TEST_ptr(ssl = SSL_new(ctx))
            || !TEST_ptr(sslbio = BIO_new(BIO_f_ssl()))
            || !TEST_ptr(membio1 = BIO_new(BIO_s_mem())))
        goto end;

    BIO_set_ssl(sslbio, ssl, BIO_CLOSE);

    /*
     * If anything goes wrong here then we could leak memory, so this will
     * be caught in a crypto-mdebug build
     */
    BIO_push(sslbio, membio1);

    /* Verify changing the rbio/wbio directly does not cause leaks */
    if (fix.change_bio != NO_BIO_CHANGE) {
        if (!TEST_ptr(membio2 = BIO_new(BIO_s_mem())))
            goto end;
        if (fix.change_bio == CHANGE_RBIO)
            SSL_set0_rbio(ssl, membio2);
        else
            SSL_set0_wbio(ssl, membio2);
    }
    ssl = NULL;

    if (fix.pop_ssl)
        BIO_pop(sslbio);
    else
        BIO_pop(membio1);

    testresult = 1;
 end:
    BIO_free(membio1);
    BIO_free(sslbio);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return testresult;
}

static int test_ssl_bio_pop_next_bio(void)
{
    SETUP_TEST_FIXTURE(SSL_BIO_TEST_FIXTURE, ssl_bio_set_up);
    EXECUTE_TEST(execute_test_ssl_bio, ssl_bio_tear_down);
}

static int test_ssl_bio_pop_ssl_bio(void)
{
    SETUP_TEST_FIXTURE(SSL_BIO_TEST_FIXTURE, ssl_bio_set_up);
    fixture.pop_ssl = 1;
    EXECUTE_TEST(execute_test_ssl_bio, ssl_bio_tear_down);
}

static int test_ssl_bio_change_rbio(void)
{
    SETUP_TEST_FIXTURE(SSL_BIO_TEST_FIXTURE, ssl_bio_set_up);
    fixture.change_bio = CHANGE_RBIO;
    EXECUTE_TEST(execute_test_ssl_bio, ssl_bio_tear_down);
}

static int test_ssl_bio_change_wbio(void)
{
    SETUP_TEST_FIXTURE(SSL_BIO_TEST_FIXTURE, ssl_bio_set_up);
    fixture.change_bio = CHANGE_WBIO;
    EXECUTE_TEST(execute_test_ssl_bio, ssl_bio_tear_down);
}

typedef struct {
    /* The list of sig algs */
    const int *list;
    /* The length of the list */
    size_t listlen;
    /* A sigalgs list in string format */
    const char *liststr;
    /* Whether setting the list should succeed */
    int valid;
    /* Whether creating a connection with the list should succeed */
    int connsuccess;
} sigalgs_list;

static const int validlist1[] = {NID_sha256, EVP_PKEY_RSA};
#ifndef OPENSSL_NO_EC
static const int validlist2[] = {NID_sha256, EVP_PKEY_RSA, NID_sha512, EVP_PKEY_EC};
static const int validlist3[] = {NID_sha512, EVP_PKEY_EC};
#endif
static const int invalidlist1[] = {NID_undef, EVP_PKEY_RSA};
static const int invalidlist2[] = {NID_sha256, NID_undef};
static const int invalidlist3[] = {NID_sha256, EVP_PKEY_RSA, NID_sha256};
static const int invalidlist4[] = {NID_sha256};
static const sigalgs_list testsigalgs[] = {
    {validlist1, OSSL_NELEM(validlist1), NULL, 1, 1},
#ifndef OPENSSL_NO_EC
    {validlist2, OSSL_NELEM(validlist2), NULL, 1, 1},
    {validlist3, OSSL_NELEM(validlist3), NULL, 1, 0},
#endif
    {NULL, 0, "RSA+SHA256", 1, 1},
#ifndef OPENSSL_NO_EC
    {NULL, 0, "RSA+SHA256:ECDSA+SHA512", 1, 1},
    {NULL, 0, "ECDSA+SHA512", 1, 0},
#endif
    {invalidlist1, OSSL_NELEM(invalidlist1), NULL, 0, 0},
    {invalidlist2, OSSL_NELEM(invalidlist2), NULL, 0, 0},
    {invalidlist3, OSSL_NELEM(invalidlist3), NULL, 0, 0},
    {invalidlist4, OSSL_NELEM(invalidlist4), NULL, 0, 0},
    {NULL, 0, "RSA", 0, 0},
    {NULL, 0, "SHA256", 0, 0},
    {NULL, 0, "RSA+SHA256:SHA256", 0, 0},
    {NULL, 0, "Invalid", 0, 0}
};

static int test_set_sigalgs(int idx)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    const sigalgs_list *curr;
    int testctx;

    /* Should never happen */
    if (!TEST_size_t_le((size_t)idx, OSSL_NELEM(testsigalgs) * 2))
        return 0;

    testctx = ((size_t)idx < OSSL_NELEM(testsigalgs));
    curr = testctx ? &testsigalgs[idx]
                   : &testsigalgs[idx - OSSL_NELEM(testsigalgs)];

    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(),
                                       TLS_client_method(), &sctx,
                                       &cctx, cert, privkey)))
        return 0;

    /*
     * TODO(TLS1.3): These APIs cannot set TLSv1.3 sig algs so we just test it
     * for TLSv1.2 for now until we add a new API.
     */
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);

    if (testctx) {
        int ret;

        if (curr->list != NULL)
            ret = SSL_CTX_set1_sigalgs(cctx, curr->list, curr->listlen);
        else
            ret = SSL_CTX_set1_sigalgs_list(cctx, curr->liststr);

        if (!ret) {
            if (curr->valid)
                TEST_info("Failure setting sigalgs in SSL_CTX (%d)\n", idx);
            else
                testresult = 1;
            goto end;
        }
        if (!curr->valid) {
            TEST_info("Not-failed setting sigalgs in SSL_CTX (%d)\n", idx);
            goto end;
        }
    }

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;

    if (!testctx) {
        int ret;

        if (curr->list != NULL)
            ret = SSL_set1_sigalgs(clientssl, curr->list, curr->listlen);
        else
            ret = SSL_set1_sigalgs_list(clientssl, curr->liststr);
        if (!ret) {
            if (curr->valid)
                TEST_info("Failure setting sigalgs in SSL (%d)\n", idx);
            else
                testresult = 1;
            goto end;
        }
        if (!curr->valid)
            goto end;
    }

    if (!TEST_int_eq(create_ssl_connection(serverssl, clientssl,
                                           SSL_ERROR_NONE),
                curr->connsuccess))
        goto end;

    testresult = 1;

 end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

#ifndef OPENSSL_NO_TLS1_3

#define MSG1    "Hello"
#define MSG2    "World."
#define MSG3    "This"
#define MSG4    "is"
#define MSG5    "a"
#define MSG6    "test"
#define MSG7    "message."

/*
 * Helper method to setup objects for early data test. Caller frees objects on
 * error.
 */
static int setupearly_data_test(SSL_CTX **cctx, SSL_CTX **sctx, SSL **clientssl,
                                SSL **serverssl, SSL_SESSION **sess, int idx)
{
    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(),
                                       TLS_client_method(), sctx,
                                       cctx, cert, privkey)))
        return 0;

    /* When idx == 1 we repeat the tests with read_ahead set */
    if (idx > 0) {
        SSL_CTX_set_read_ahead(*cctx, 1);
        SSL_CTX_set_read_ahead(*sctx, 1);
    }

    if (!TEST_true(create_ssl_objects(*sctx, *cctx, serverssl, clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(*serverssl, *clientssl,
                                                SSL_ERROR_NONE)))
        return 0;

    *sess = SSL_get1_session(*clientssl);
    SSL_shutdown(*clientssl);
    SSL_shutdown(*serverssl);
    SSL_free(*serverssl);
    SSL_free(*clientssl);
    *serverssl = *clientssl = NULL;

    if (!TEST_true(create_ssl_objects(*sctx, *cctx, serverssl,
                                      clientssl, NULL, NULL))
            || !TEST_true(SSL_set_session(*clientssl, *sess)))
        return 0;

    return 1;
}

static int test_early_data_read_write(int idx)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    SSL_SESSION *sess = NULL;
    unsigned char buf[20], data[1024];
    size_t readbytes, written, eoedlen, rawread, rawwritten;
    BIO *rbio;

    if (!TEST_true(setupearly_data_test(&cctx, &sctx, &clientssl,
                                        &serverssl, &sess, idx)))
        goto end;

    /* Write and read some early data */
    if (!TEST_true(SSL_write_early_data(clientssl, MSG1, strlen(MSG1),
                                        &written))
            || !TEST_size_t_eq(written, strlen(MSG1))
            || !TEST_int_eq(SSL_read_early_data(serverssl, buf,
                                                sizeof(buf), &readbytes),
                            SSL_READ_EARLY_DATA_SUCCESS)
            || !TEST_mem_eq(MSG1, readbytes, buf, strlen(MSG1))
            || !TEST_int_eq(SSL_get_early_data_status(serverssl),
                            SSL_EARLY_DATA_ACCEPTED))
        goto end;

    /*
     * Server should be able to write data, and client should be able to
     * read it.
     */
    if (!TEST_true(SSL_write_early_data(serverssl, MSG2, strlen(MSG2),
                                        &written))
            || !TEST_size_t_eq(written, strlen(MSG2))
            || !TEST_true(SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes))
            || !TEST_mem_eq(buf, readbytes, MSG2, strlen(MSG2)))
        goto end;

    /* Even after reading normal data, client should be able write early data */
    if (!TEST_true(SSL_write_early_data(clientssl, MSG3, strlen(MSG3),
                                        &written))
            || !TEST_size_t_eq(written, strlen(MSG3)))
        goto end;

    /* Server should still be able read early data after writing data */
    if (!TEST_int_eq(SSL_read_early_data(serverssl, buf, sizeof(buf),
                                         &readbytes),
                     SSL_READ_EARLY_DATA_SUCCESS)
            || !TEST_mem_eq(buf, readbytes, MSG3, strlen(MSG3)))
        goto end;

    /* Write more data from server and read it from client */
    if (!TEST_true(SSL_write_early_data(serverssl, MSG4, strlen(MSG4),
                                        &written))
            || !TEST_size_t_eq(written, strlen(MSG4))
            || !TEST_true(SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes))
            || !TEST_mem_eq(buf, readbytes, MSG4, strlen(MSG4)))
        goto end;

    /*
     * If client writes normal data it should mean writing early data is no
     * longer possible.
     */
    if (!TEST_true(SSL_write_ex(clientssl, MSG5, strlen(MSG5), &written))
            || !TEST_size_t_eq(written, strlen(MSG5))
            || !TEST_int_eq(SSL_get_early_data_status(clientssl),
                            SSL_EARLY_DATA_ACCEPTED))
        goto end;

    /*
     * At this point the client has written EndOfEarlyData, ClientFinished and
     * normal (fully protected) data. We are going to cause a delay between the
     * arrival of EndOfEarlyData and ClientFinished. We read out all the data
     * in the read BIO, and then just put back the EndOfEarlyData message.
     */
    rbio = SSL_get_rbio(serverssl);
    if (!TEST_true(BIO_read_ex(rbio, data, sizeof(data), &rawread))
            || !TEST_size_t_lt(rawread, sizeof(data))
            || !TEST_size_t_gt(rawread, SSL3_RT_HEADER_LENGTH))
        goto end;

    /* Record length is in the 4th and 5th bytes of the record header */
    eoedlen = SSL3_RT_HEADER_LENGTH + (data[3] << 8 | data[4]);
    if (!TEST_true(BIO_write_ex(rbio, data, eoedlen, &rawwritten))
            || !TEST_size_t_eq(rawwritten, eoedlen))
        goto end;

    /* Server should be told that there is no more early data */
    if (!TEST_int_eq(SSL_read_early_data(serverssl, buf, sizeof(buf),
                                         &readbytes),
                     SSL_READ_EARLY_DATA_FINISH)
            || !TEST_size_t_eq(readbytes, 0))
        goto end;

    /*
     * Server has not finished init yet, so should still be able to write early
     * data.
     */
    if (!TEST_true(SSL_write_early_data(serverssl, MSG6, strlen(MSG6),
                                        &written))
            || !TEST_size_t_eq(written, strlen(MSG6)))
        goto end;

    /* Push the ClientFinished and the normal data back into the server rbio */
    if (!TEST_true(BIO_write_ex(rbio, data + eoedlen, rawread - eoedlen,
                                &rawwritten))
            || !TEST_size_t_eq(rawwritten, rawread - eoedlen))
        goto end;

    /* Server should be able to read normal data */
    if (!TEST_true(SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes))
            || !TEST_size_t_eq(readbytes, strlen(MSG5)))
        goto end;

    /* Client and server should not be able to write/read early data now */
    if (!TEST_false(SSL_write_early_data(clientssl, MSG6, strlen(MSG6),
                                         &written)))
        goto end;
    ERR_clear_error();
    if (!TEST_int_eq(SSL_read_early_data(serverssl, buf, sizeof(buf),
                                         &readbytes),
                     SSL_READ_EARLY_DATA_ERROR))
        goto end;
    ERR_clear_error();

    /* Client should be able to read the data sent by the server */
    if (!TEST_true(SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes))
            || !TEST_mem_eq(buf, readbytes, MSG6, strlen(MSG6)))
        goto end;

    /*
     * Make sure we process the NewSessionTicket. This arrives post-handshake.
     * We attempt a read which we do not expect to return any data.
     */
    if (!TEST_false(SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes)))
        goto end;

    /* Server should be able to write normal data */
    if (!TEST_true(SSL_write_ex(serverssl, MSG7, strlen(MSG7), &written))
            || !TEST_size_t_eq(written, strlen(MSG7))
            || !TEST_true(SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes))
            || !TEST_mem_eq(buf, readbytes, MSG7, strlen(MSG7)))
        goto end;

    SSL_SESSION_free(sess);
    sess = SSL_get1_session(clientssl);

    SSL_shutdown(clientssl);
    SSL_shutdown(serverssl);
    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = clientssl = NULL;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL))
            || !TEST_true(SSL_set_session(clientssl, sess)))
        goto end;

    /* Write and read some early data */
    if (!TEST_true(SSL_write_early_data(clientssl, MSG1, strlen(MSG1),
                                        &written))
            || !TEST_size_t_eq(written, strlen(MSG1))
            || !TEST_int_eq(SSL_read_early_data(serverssl, buf, sizeof(buf),
                                                &readbytes),
                            SSL_READ_EARLY_DATA_SUCCESS)
            || !TEST_mem_eq(buf, readbytes, MSG1, strlen(MSG1)))
        goto end;

    if (!TEST_int_gt(SSL_connect(clientssl), 0)
            || !TEST_int_gt(SSL_accept(serverssl), 0))
        goto end;

    /* Client and server should not be able to write/read early data now */
    if (!TEST_false(SSL_write_early_data(clientssl, MSG6, strlen(MSG6),
                                         &written)))
        goto end;
    ERR_clear_error();
    if (!TEST_int_eq(SSL_read_early_data(serverssl, buf, sizeof(buf),
                                         &readbytes),
                     SSL_READ_EARLY_DATA_ERROR))
        goto end;
    ERR_clear_error();

    /* Client and server should be able to write/read normal data */
    if (!TEST_true(SSL_write_ex(clientssl, MSG5, strlen(MSG5), &written))
            || !TEST_size_t_eq(written, strlen(MSG5))
            || !TEST_true(SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes))
            || !TEST_size_t_eq(readbytes, strlen(MSG5)))
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

/*
 * Test that a server attempting to read early data can handle a connection
 * from a client where the early data is not acceptable.
 */
static int test_early_data_skip(int idx)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    SSL_SESSION *sess = NULL;
    unsigned char buf[20];
    size_t readbytes, written;

    if (!TEST_true(setupearly_data_test(&cctx, &sctx, &clientssl,
                                        &serverssl, &sess, idx)))
        goto end;

    /*
     * Deliberately corrupt the creation time. We take 20 seconds off the time.
     * It could be any value as long as it is not within tolerance. This should
     * mean the ticket is rejected.
     */
    if (!TEST_true(SSL_SESSION_set_time(sess, time(NULL) - 20)))
        goto end;

    /* Write some early data */
    if (!TEST_true(SSL_write_early_data(clientssl, MSG1, strlen(MSG1),
                                        &written))
            || !TEST_size_t_eq(written, strlen(MSG1)))
        goto end;

    /* Server should reject the early data and skip over it */
    if (!TEST_int_eq(SSL_read_early_data(serverssl, buf, sizeof(buf),
                                         &readbytes),
                     SSL_READ_EARLY_DATA_FINISH)
            || !TEST_size_t_eq(readbytes, 0)
            || !TEST_int_eq(SSL_get_early_data_status(serverssl),
                            SSL_EARLY_DATA_REJECTED))
        goto end;

    /* Should be able to send normal data despite rejection of early data */
    if (!TEST_true(SSL_write_ex(clientssl, MSG2, strlen(MSG2), &written))
            || !TEST_size_t_eq(written, strlen(MSG2))
            || !TEST_int_eq(SSL_get_early_data_status(clientssl),
                            SSL_EARLY_DATA_REJECTED)
            || !TEST_true(SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes))
            || !TEST_mem_eq(buf, readbytes, MSG2, strlen(MSG2)))
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

/*
 * Test that a server attempting to read early data can handle a connection
 * from a client that doesn't send any.
 */
static int test_early_data_not_sent(int idx)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    SSL_SESSION *sess = NULL;
    unsigned char buf[20];
    size_t readbytes, written;

    if (!TEST_true(setupearly_data_test(&cctx, &sctx, &clientssl,
                                        &serverssl, &sess, idx)))
        goto end;

    /* Write some data - should block due to handshake with server */
    SSL_set_connect_state(clientssl);
    if (!TEST_false(SSL_write_ex(clientssl, MSG1, strlen(MSG1), &written)))
        goto end;

    /* Server should detect that early data has not been sent */
    if (!TEST_int_eq(SSL_read_early_data(serverssl, buf, sizeof(buf),
                                         &readbytes),
                     SSL_READ_EARLY_DATA_FINISH)
            || !TEST_size_t_eq(readbytes, 0)
            || !TEST_int_eq(SSL_get_early_data_status(serverssl),
                            SSL_EARLY_DATA_NOT_SENT)
            || !TEST_int_eq(SSL_get_early_data_status(clientssl),
                            SSL_EARLY_DATA_NOT_SENT))
        goto end;

    /* Continue writing the message we started earlier */
    if (!TEST_true(SSL_write_ex(clientssl, MSG1, strlen(MSG1), &written))
            || !TEST_size_t_eq(written, strlen(MSG1))
            || !TEST_true(SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes))
            || !TEST_mem_eq(buf, readbytes, MSG1, strlen(MSG1))
            || !SSL_write_ex(serverssl, MSG2, strlen(MSG2), &written)
            || !TEST_size_t_eq(written, strlen(MSG2)))
        goto end;

    /*
     * Should block due to the NewSessionTicket arrival unless we're using
     * read_ahead
     */
    if (idx == 0) {
        if (!TEST_false(SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes)))
            goto end;
    }

    if (!TEST_true(SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes))
            || !TEST_mem_eq(buf, readbytes, MSG2, strlen(MSG2)))
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

/*
 * Test that a server that doesn't try to read early data can handle a
 * client sending some.
 */
static int test_early_data_not_expected(int idx)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    SSL_SESSION *sess = NULL;
    unsigned char buf[20];
    size_t readbytes, written;


    if (!TEST_true(setupearly_data_test(&cctx, &sctx, &clientssl,
                                        &serverssl, &sess, idx)))
        goto end;

    /* Write some early data */
    if (!TEST_true(SSL_write_early_data(clientssl, MSG1, strlen(MSG1),
                                        &written)))
        goto end;

    /*
     * Server should skip over early data and then block waiting for client to
     * continue handshake
     */
    if (!TEST_int_le(SSL_accept(serverssl), 0)
     || !TEST_int_gt(SSL_connect(clientssl), 0)
     || !TEST_int_eq(SSL_get_early_data_status(serverssl),
                     SSL_EARLY_DATA_REJECTED)
     || !TEST_int_gt(SSL_accept(serverssl), 0)
     || !TEST_int_eq(SSL_get_early_data_status(clientssl),
                     SSL_EARLY_DATA_REJECTED))
        goto end;

    /* Send some normal data from client to server */
    if (!TEST_true(SSL_write_ex(clientssl, MSG2, strlen(MSG2), &written))
            || !TEST_size_t_eq(written, strlen(MSG2)))
        goto end;

    if (!TEST_true(SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes))
            || !TEST_mem_eq(buf, readbytes, MSG2, strlen(MSG2)))
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


# ifndef OPENSSL_NO_TLS1_2
/*
 * Test that a server attempting to read early data can handle a connection
 * from a TLSv1.2 client.
 */
static int test_early_data_tls1_2(int idx)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    unsigned char buf[20];
    size_t readbytes, written;

    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(),
                                       TLS_client_method(), &sctx,
                                       &cctx, cert, privkey)))
        goto end;

    /* When idx == 1 we repeat the tests with read_ahead set */
    if (idx > 0) {
        SSL_CTX_set_read_ahead(cctx, 1);
        SSL_CTX_set_read_ahead(sctx, 1);
    }

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;

    /* Write some data - should block due to handshake with server */
    SSL_set_max_proto_version(clientssl, TLS1_2_VERSION);
    SSL_set_connect_state(clientssl);
    if (!TEST_false(SSL_write_ex(clientssl, MSG1, strlen(MSG1), &written)))
        goto end;

    /*
     * Server should do TLSv1.2 handshake. First it will block waiting for more
     * messages from client after ServerDone. Then SSL_read_early_data should
     * finish and detect that early data has not been sent
     */
    if (!TEST_int_eq(SSL_read_early_data(serverssl, buf, sizeof(buf),
                                         &readbytes),
                     SSL_READ_EARLY_DATA_ERROR))
        goto end;

    /*
     * Continue writing the message we started earlier. Will still block waiting
     * for the CCS/Finished from server
     */
    if (!TEST_false(SSL_write_ex(clientssl, MSG1, strlen(MSG1), &written))
            || !TEST_int_eq(SSL_read_early_data(serverssl, buf, sizeof(buf),
                                                &readbytes),
                            SSL_READ_EARLY_DATA_FINISH)
            || !TEST_size_t_eq(readbytes, 0)
            || !TEST_int_eq(SSL_get_early_data_status(serverssl),
                            SSL_EARLY_DATA_NOT_SENT))
        goto end;

    /* Continue writing the message we started earlier */
    if (!TEST_true(SSL_write_ex(clientssl, MSG1, strlen(MSG1), &written))
            || !TEST_size_t_eq(written, strlen(MSG1))
            || !TEST_int_eq(SSL_get_early_data_status(clientssl),
                            SSL_EARLY_DATA_NOT_SENT)
            || !TEST_true(SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes))
            || !TEST_mem_eq(buf, readbytes, MSG1, strlen(MSG1))
            || !TEST_true(SSL_write_ex(serverssl, MSG2, strlen(MSG2), &written))
            || !TEST_size_t_eq(written, strlen(MSG2))
            || !SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes)
            || !TEST_mem_eq(buf, readbytes, MSG2, strlen(MSG2)))
        goto end;

    testresult = 1;

 end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
# endif /* OPENSSL_NO_TLS1_2 */

static int test_ciphersuite_change(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    SSL_SESSION *clntsess = NULL;
    int testresult = 0;
    const SSL_CIPHER *aes_128_gcm_sha256 = NULL;

    /* Create a session based on SHA-256 */
    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(),
                                       TLS_client_method(), &sctx,
                                       &cctx, cert, privkey))
            || !TEST_true(SSL_CTX_set_cipher_list(cctx,
                                                  "TLS13-AES-128-GCM-SHA256"))
            || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                          &clientssl, NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    clntsess = SSL_get1_session(clientssl);
    /* Save for later */
    aes_128_gcm_sha256 = SSL_SESSION_get0_cipher(clntsess);
    SSL_shutdown(clientssl);
    SSL_shutdown(serverssl);
    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = clientssl = NULL;

    /* Check we can resume a session with a different SHA-256 ciphersuite */
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx,
                                           "TLS13-CHACHA20-POLY1305-SHA256"))
            || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                             NULL, NULL))
            || !TEST_true(SSL_set_session(clientssl, clntsess))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE))
            || !TEST_true(SSL_session_reused(clientssl)))
        goto end;

    SSL_SESSION_free(clntsess);
    clntsess = SSL_get1_session(clientssl);
    SSL_shutdown(clientssl);
    SSL_shutdown(serverssl);
    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = clientssl = NULL;

    /*
     * Check attempting to resume a SHA-256 session with no SHA-256 ciphersuites
     * succeeds but does not resume.
     */
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "TLS13-AES-256-GCM-SHA384"))
            || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                             NULL, NULL))
            || !TEST_true(SSL_set_session(clientssl, clntsess))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_SSL))
            || !TEST_false(SSL_session_reused(clientssl)))
        goto end;

    SSL_SESSION_free(clntsess);
    clntsess = NULL;
    SSL_shutdown(clientssl);
    SSL_shutdown(serverssl);
    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = clientssl = NULL;

    /* Create a session based on SHA384 */
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "TLS13-AES-256-GCM-SHA384"))
            || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                          &clientssl, NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    clntsess = SSL_get1_session(clientssl);
    SSL_shutdown(clientssl);
    SSL_shutdown(serverssl);
    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = clientssl = NULL;

    if (!TEST_true(SSL_CTX_set_cipher_list(cctx,
                   "TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384"))
            || !TEST_true(SSL_CTX_set_cipher_list(sctx,
                                                  "TLS13-AES-256-GCM-SHA384"))
            || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                             NULL, NULL))
            || !TEST_true(SSL_set_session(clientssl, clntsess))
               /*
                * We use SSL_ERROR_WANT_READ below so that we can pause the
                * connection after the initial ClientHello has been sent to
                * enable us to make some session changes.
                */
            || !TEST_false(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_WANT_READ)))
        goto end;

    /* Trick the client into thinking this session is for a different digest */
    clntsess->cipher = aes_128_gcm_sha256;
    clntsess->cipher_id = clntsess->cipher->id;

    /*
     * Continue the previously started connection. Server has selected a SHA-384
     * ciphersuite, but client thinks the session is for SHA-256, so it should
     * bail out.
     */
    if (!TEST_false(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_SSL))
            || !TEST_int_eq(ERR_GET_REASON(ERR_get_error()),
                            SSL_R_CIPHERSUITE_DIGEST_HAS_CHANGED))
        goto end;

    testresult = 1;

 end:
    SSL_SESSION_free(clntsess);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}


static SSL_SESSION *psk = NULL;
static const char *pskid = "Identity";
static const char *srvid;

static int use_session_cb_cnt = 0;
static int find_session_cb_cnt = 0;

static int use_session_cb(SSL *ssl, const EVP_MD *md, const unsigned char **id,
                          size_t *idlen, SSL_SESSION **sess)
{
    switch (++use_session_cb_cnt) {
    case 1:
        /* The first call should always have a NULL md */
        if (md != NULL)
            return 0;
        break;

    case 2:
        /* The second call should always have an md */
        if (md == NULL)
            return 0;
        break;

    default:
        /* We should only be called a maximum of twice */
        return 0;
    }

    if (psk != NULL)
        SSL_SESSION_up_ref(psk);

    *sess = psk;
    *id = (const unsigned char *)pskid;
    *idlen = strlen(pskid);

    return 1;
}

static int find_session_cb(SSL *ssl, const unsigned char *identity,
                           size_t identity_len, SSL_SESSION **sess)
{
    find_session_cb_cnt++;

    /* We should only ever be called a maximum of twice per connection */
    if (find_session_cb_cnt > 2)
        return 0;

    if (psk == NULL)
        return 0;

    /* Identity should match that set by the client */
    if (strlen(srvid) != identity_len
            || strncmp(srvid, (const char *)identity, identity_len) != 0) {
        /* No PSK found, continue but without a PSK */
        *sess = NULL;
        return 1;
    }

    SSL_SESSION_up_ref(psk);
    *sess = psk;

    return 1;
}

#define TLS13_AES_256_GCM_SHA384_BYTES  ((const unsigned char *)"\x13\x02")

static int test_tls13_psk(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const SSL_CIPHER *cipher = NULL;
    const unsigned char key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(),
                                       TLS_client_method(), &sctx,
                                       &cctx, cert, privkey)))
        goto end;

    SSL_CTX_set_psk_use_session_callback(cctx, use_session_cb);
    SSL_CTX_set_psk_find_session_callback(sctx, find_session_cb);
    srvid = pskid;

    /* Check we can create a connection if callback decides not to send a PSK */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                             NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE))
            || !TEST_false(SSL_session_reused(clientssl))
            || !TEST_false(SSL_session_reused(serverssl))
            || !TEST_true(use_session_cb_cnt == 1)
            || !TEST_true(find_session_cb_cnt == 0))
        goto end;

    shutdown_ssl_connection(serverssl, clientssl);
    serverssl = clientssl = NULL;
    use_session_cb_cnt = 0;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                             NULL, NULL)))
        goto end;

    /* Create the PSK */
    cipher = SSL_CIPHER_find(clientssl, TLS13_AES_256_GCM_SHA384_BYTES);
    psk = SSL_SESSION_new();
    if (!TEST_ptr(psk)
            || !TEST_ptr(cipher)
            || !TEST_true(SSL_SESSION_set1_master_key(psk, key, sizeof(key)))
            || !TEST_true(SSL_SESSION_set_cipher(psk, cipher))
            || !TEST_true(SSL_SESSION_set_protocol_version(psk,
                                                           TLS1_3_VERSION)))
        goto end;

    /* Check we can create a connection and the PSK is used */
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
            || !TEST_true(SSL_session_reused(clientssl))
            || !TEST_true(SSL_session_reused(serverssl))
            || !TEST_true(use_session_cb_cnt == 1)
            || !TEST_true(find_session_cb_cnt == 1))
        goto end;

    shutdown_ssl_connection(serverssl, clientssl);
    serverssl = clientssl = NULL;
    use_session_cb_cnt = find_session_cb_cnt = 0;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                             NULL, NULL)))
        goto end;

    /* Force an HRR */
    if (!TEST_true(SSL_set1_groups_list(serverssl, "P-256")))
        goto end;

    /*
     * Check we can create a connection, the PSK is used and the callbacks are
     * called twice.
     */
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
            || !TEST_true(SSL_session_reused(clientssl))
            || !TEST_true(SSL_session_reused(serverssl))
            || !TEST_true(use_session_cb_cnt == 2)
            || !TEST_true(find_session_cb_cnt == 2))
        goto end;

    shutdown_ssl_connection(serverssl, clientssl);
    serverssl = clientssl = NULL;
    use_session_cb_cnt = find_session_cb_cnt = 0;

    /*
     * Check that if the server rejects the PSK we can still connect, but with
     * a full handshake
     */
    srvid = "Dummy Identity";
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                             NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE))
            || !TEST_false(SSL_session_reused(clientssl))
            || !TEST_false(SSL_session_reused(serverssl))
            || !TEST_true(use_session_cb_cnt == 1)
            || !TEST_true(find_session_cb_cnt == 1))
        goto end;

    shutdown_ssl_connection(serverssl, clientssl);
    serverssl = clientssl = NULL;
    testresult = 1;

 end:
    SSL_SESSION_free(psk);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

#endif /* OPENSSL_NO_TLS1_3 */

static int clntaddoldcb = 0;
static int clntparseoldcb = 0;
static int srvaddoldcb = 0;
static int srvparseoldcb = 0;
static int clntaddnewcb = 0;
static int clntparsenewcb = 0;
static int srvaddnewcb = 0;
static int srvparsenewcb = 0;
static int snicb = 0;

#define TEST_EXT_TYPE1  0xff00

static int old_add_cb(SSL *s, unsigned int ext_type, const unsigned char **out,
                      size_t *outlen, int *al, void *add_arg)
{
    int *server = (int *)add_arg;
    unsigned char *data;

    if (SSL_is_server(s))
        srvaddoldcb++;
    else
        clntaddoldcb++;

    if (*server != SSL_is_server(s)
            || (data = OPENSSL_malloc(sizeof(*data))) == NULL)
        return -1;

    *data = 1;
    *out = data;
    *outlen = sizeof(char);
    return 1;
}

static void old_free_cb(SSL *s, unsigned int ext_type, const unsigned char *out,
                        void *add_arg)
{
    OPENSSL_free((unsigned char *)out);
}

static int old_parse_cb(SSL *s, unsigned int ext_type, const unsigned char *in,
                        size_t inlen, int *al, void *parse_arg)
{
    int *server = (int *)parse_arg;

    if (SSL_is_server(s))
        srvparseoldcb++;
    else
        clntparseoldcb++;

    if (*server != SSL_is_server(s)
            || inlen != sizeof(char)
            || *in != 1)
        return -1;

    return 1;
}

static int new_add_cb(SSL *s, unsigned int ext_type, unsigned int context,
                      const unsigned char **out, size_t *outlen, X509 *x,
                      size_t chainidx, int *al, void *add_arg)
{
    int *server = (int *)add_arg;
    unsigned char *data;

    if (SSL_is_server(s))
        srvaddnewcb++;
    else
        clntaddnewcb++;

    if (*server != SSL_is_server(s)
            || (data = OPENSSL_malloc(sizeof(*data))) == NULL)
        return -1;

    *data = 1;
    *out = data;
    *outlen = sizeof(*data);
    return 1;
}

static void new_free_cb(SSL *s, unsigned int ext_type, unsigned int context,
                        const unsigned char *out, void *add_arg)
{
    OPENSSL_free((unsigned char *)out);
}

static int new_parse_cb(SSL *s, unsigned int ext_type, unsigned int context,
                        const unsigned char *in, size_t inlen, X509 *x,
                        size_t chainidx, int *al, void *parse_arg)
{
    int *server = (int *)parse_arg;

    if (SSL_is_server(s))
        srvparsenewcb++;
    else
        clntparsenewcb++;

    if (*server != SSL_is_server(s)
            || inlen != sizeof(char) || *in != 1)
        return -1;

    return 1;
}

static int sni_cb(SSL *s, int *al, void *arg)
{
    SSL_CTX *ctx = (SSL_CTX *)arg;

    if (SSL_set_SSL_CTX(s, ctx) == NULL) {
        *al = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    snicb++;
    return SSL_TLSEXT_ERR_OK;
}

/*
 * Custom call back tests.
 * Test 0: Old style callbacks in TLSv1.2
 * Test 1: New style callbacks in TLSv1.2
 * Test 2: New style callbacks in TLSv1.2 with SNI
 * Test 3: New style callbacks in TLSv1.3. Extensions in CH and EE
 * Test 4: New style callbacks in TLSv1.3. Extensions in CH, SH, EE, Cert + NST
 */
static int test_custom_exts(int tst)
{
    SSL_CTX *cctx = NULL, *sctx = NULL, *sctx2 = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    static int server = 1;
    static int client = 0;
    SSL_SESSION *sess = NULL;
    unsigned int context;

    /* Reset callback counters */
    clntaddoldcb = clntparseoldcb = srvaddoldcb = srvparseoldcb = 0;
    clntaddnewcb = clntparsenewcb = srvaddnewcb = srvparsenewcb = 0;
    snicb = 0;

    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(),
                                       TLS_client_method(), &sctx,
                                       &cctx, cert, privkey)))
        goto end;

    if (tst == 2
            && !TEST_true(create_ssl_ctx_pair(TLS_server_method(), NULL, &sctx2,
                                              NULL, cert, privkey)))
        goto end;


    if (tst < 3) {
        SSL_CTX_set_options(cctx, SSL_OP_NO_TLSv1_3);
        SSL_CTX_set_options(sctx, SSL_OP_NO_TLSv1_3);
        if (sctx2 != NULL)
            SSL_CTX_set_options(sctx2, SSL_OP_NO_TLSv1_3);
    }

    if (tst == 4) {
        context = SSL_EXT_CLIENT_HELLO
                  | SSL_EXT_TLS1_2_SERVER_HELLO
                  | SSL_EXT_TLS1_3_SERVER_HELLO
                  | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS
                  | SSL_EXT_TLS1_3_CERTIFICATE
                  | SSL_EXT_TLS1_3_NEW_SESSION_TICKET;
    } else {
        context = SSL_EXT_CLIENT_HELLO
                  | SSL_EXT_TLS1_2_SERVER_HELLO
                  | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS;
    }

    /* Create a client side custom extension */
    if (tst == 0) {
        if (!TEST_true(SSL_CTX_add_client_custom_ext(cctx, TEST_EXT_TYPE1,
                                                     old_add_cb, old_free_cb,
                                                     &client, old_parse_cb,
                                                     &client)))
            goto end;
    } else {
        if (!TEST_true(SSL_CTX_add_custom_ext(cctx, TEST_EXT_TYPE1, context,
                                              new_add_cb, new_free_cb,
                                              &client, new_parse_cb, &client)))
            goto end;
    }

    /* Should not be able to add duplicates */
    if (!TEST_false(SSL_CTX_add_client_custom_ext(cctx, TEST_EXT_TYPE1,
                                                  old_add_cb, old_free_cb,
                                                  &client, old_parse_cb,
                                                  &client))
            || !TEST_false(SSL_CTX_add_custom_ext(cctx, TEST_EXT_TYPE1,
                                                  context, new_add_cb,
                                                  new_free_cb, &client,
                                                  new_parse_cb, &client)))
        goto end;

    /* Create a server side custom extension */
    if (tst == 0) {
        if (!TEST_true(SSL_CTX_add_server_custom_ext(sctx, TEST_EXT_TYPE1,
                                                     old_add_cb, old_free_cb,
                                                     &server, old_parse_cb,
                                                     &server)))
            goto end;
    } else {
        if (!TEST_true(SSL_CTX_add_custom_ext(sctx, TEST_EXT_TYPE1, context,
                                              new_add_cb, new_free_cb,
                                              &server, new_parse_cb, &server)))
            goto end;
        if (sctx2 != NULL
                && !TEST_true(SSL_CTX_add_custom_ext(sctx2, TEST_EXT_TYPE1,
                                                     context, new_add_cb,
                                                     new_free_cb, &server,
                                                     new_parse_cb, &server)))
            goto end;
    }

    /* Should not be able to add duplicates */
    if (!TEST_false(SSL_CTX_add_server_custom_ext(sctx, TEST_EXT_TYPE1,
                                                  old_add_cb, old_free_cb,
                                                  &server, old_parse_cb,
                                                  &server))
            || !TEST_false(SSL_CTX_add_custom_ext(sctx, TEST_EXT_TYPE1,
                                                  context, new_add_cb,
                                                  new_free_cb, &server,
                                                  new_parse_cb, &server)))
        goto end;

    if (tst == 2) {
        /* Set up SNI */
        if (!TEST_true(SSL_CTX_set_tlsext_servername_callback(sctx, sni_cb))
                || !TEST_true(SSL_CTX_set_tlsext_servername_arg(sctx, sctx2)))
            goto end;
    }

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    if (tst == 0) {
        if (clntaddoldcb != 1
                || clntparseoldcb != 1
                || srvaddoldcb != 1
                || srvparseoldcb != 1)
            goto end;
    } else if (tst == 1 || tst == 2 || tst == 3) {
        if (clntaddnewcb != 1
                || clntparsenewcb != 1
                || srvaddnewcb != 1
                || srvparsenewcb != 1
                || (tst != 2 && snicb != 0)
                || (tst == 2 && snicb != 1))
            goto end;
    } else {
        if (clntaddnewcb != 1
                || clntparsenewcb != 4
                || srvaddnewcb != 4
                || srvparsenewcb != 1)
            goto end;
    }

    sess = SSL_get1_session(clientssl);
    SSL_shutdown(clientssl);
    SSL_shutdown(serverssl);
    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = clientssl = NULL;

    if (tst == 3) {
        /* We don't bother with the resumption aspects for this test */
        testresult = 1;
        goto end;
    }

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(SSL_set_session(clientssl, sess))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                               SSL_ERROR_NONE)))
        goto end;

    /*
     * For a resumed session we expect to add the ClientHello extension. For the
     * old style callbacks we ignore it on the server side because they set
     * SSL_EXT_IGNORE_ON_RESUMPTION. The new style callbacks do not ignore
     * them.
     */
    if (tst == 0) {
        if (clntaddoldcb != 2
                || clntparseoldcb != 1
                || srvaddoldcb != 1
                || srvparseoldcb != 1)
            goto end;
    } else if (tst == 1 || tst == 2 || tst == 3) {
        if (clntaddnewcb != 2
                || clntparsenewcb != 2
                || srvaddnewcb != 2
                || srvparsenewcb != 2)
            goto end;
    } else {
        /* No Certificate message extensions in the resumption handshake */
        if (clntaddnewcb != 2
                || clntparsenewcb != 7
                || srvaddnewcb != 7
                || srvparsenewcb != 2)
            goto end;
    }

    testresult = 1;

end:
    SSL_SESSION_free(sess);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx2);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test loading of serverinfo data in various formats. test_sslmessages actually
 * tests to make sure the extensions appear in the handshake
 */
static int test_serverinfo(int tst)
{
    unsigned int version;
    unsigned char *sibuf;
    size_t sibuflen;
    int ret, expected, testresult = 0;
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_method());
    if (!TEST_ptr(ctx))
        goto end;

    if ((tst & 0x01) == 0x01)
        version = SSL_SERVERINFOV2;
    else
        version = SSL_SERVERINFOV1;

    if ((tst & 0x02) == 0x02) {
        sibuf = serverinfov2;
        sibuflen = sizeof(serverinfov2);
        expected = (version == SSL_SERVERINFOV2);
    } else {
        sibuf = serverinfov1;
        sibuflen = sizeof(serverinfov1);
        expected = (version == SSL_SERVERINFOV1);
    }

    if ((tst & 0x04) == 0x04) {
        ret = SSL_CTX_use_serverinfo_ex(ctx, version, sibuf, sibuflen);
    } else {
        ret = SSL_CTX_use_serverinfo(ctx, sibuf, sibuflen);

        /*
         * The version variable is irrelevant in this case - it's what is in the
         * buffer that matters
         */
        if ((tst & 0x02) == 0x02)
            expected = 0;
        else
            expected = 1;
    }

    if (!TEST_true(ret == expected))
        goto end;

    testresult = 1;

 end:
    SSL_CTX_free(ctx);

    return testresult;
}

/*
 * Test that SSL_export_keying_material() produces expected results. There are
 * no test vectors so all we do is test that both sides of the communication
 * produce the same results for different protocol versions.
 */
static int test_export_key_mat(int tst)
{
    int testresult = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL, *sctx2 = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    const char label[] = "test label";
    const unsigned char context[] = "context";
    const unsigned char *emptycontext = NULL;
    unsigned char ckeymat1[80], ckeymat2[80], ckeymat3[80];
    unsigned char skeymat1[80], skeymat2[80], skeymat3[80];
    const int protocols[] = {
        TLS1_VERSION,
        TLS1_1_VERSION,
        TLS1_2_VERSION,
        TLS1_3_VERSION
    };

#ifdef OPENSSL_NO_TLS1
    if (tst == 0)
        return 1;
#endif
#ifdef OPENSSL_NO_TLS1_1
    if (tst == 1)
        return 1;
#endif
#ifdef OPENSSL_NO_TLS1_2
    if (tst == 2)
        return 1;
#endif
#ifdef OPENSSL_NO_TLS1_3
    if (tst == 3)
        return 1;
#endif
    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(),
                                       TLS_client_method(), &sctx,
                                       &cctx, cert, privkey)))
        goto end;

    OPENSSL_assert(tst >= 0 && (size_t)tst < OSSL_NELEM(protocols));
    SSL_CTX_set_max_proto_version(cctx, protocols[tst]);
    SSL_CTX_set_min_proto_version(cctx, protocols[tst]);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL,
                                      NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_export_keying_material(clientssl, ckeymat1,
                                                sizeof(ckeymat1), label,
                                                sizeof(label) - 1, context,
                                                sizeof(context) - 1, 1), 1)
            || !TEST_int_eq(SSL_export_keying_material(clientssl, ckeymat2,
                                                       sizeof(ckeymat2), label,
                                                       sizeof(label) - 1,
                                                       emptycontext,
                                                       0, 1), 1)
            || !TEST_int_eq(SSL_export_keying_material(clientssl, ckeymat3,
                                                       sizeof(ckeymat3), label,
                                                       sizeof(label) - 1,
                                                       NULL, 0, 0), 1)
            || !TEST_int_eq(SSL_export_keying_material(serverssl, skeymat1,
                                                       sizeof(skeymat1), label,
                                                       sizeof(label) - 1,
                                                       context,
                                                       sizeof(context) -1, 1),
                            1)
            || !TEST_int_eq(SSL_export_keying_material(serverssl, skeymat2,
                                                       sizeof(skeymat2), label,
                                                       sizeof(label) - 1,
                                                       emptycontext,
                                                       0, 1), 1)
            || !TEST_int_eq(SSL_export_keying_material(serverssl, skeymat3,
                                                       sizeof(skeymat3), label,
                                                       sizeof(label) - 1,
                                                       NULL, 0, 0), 1)
               /*
                * Check that both sides created the same key material with the
                * same context.
                */
            || !TEST_mem_eq(ckeymat1, sizeof(ckeymat1), skeymat1,
                            sizeof(skeymat1))
               /*
                * Check that both sides created the same key material with an
                * empty context.
                */
            || !TEST_mem_eq(ckeymat2, sizeof(ckeymat2), skeymat2,
                            sizeof(skeymat2))
               /*
                * Check that both sides created the same key material without a
                * context.
                */
            || !TEST_mem_eq(ckeymat3, sizeof(ckeymat3), skeymat3,
                            sizeof(skeymat3))
               /* Different contexts should produce different results */
            || !TEST_mem_ne(ckeymat1, sizeof(ckeymat1), ckeymat2,
                            sizeof(ckeymat2)))
        goto end;

    /*
     * Check that an empty context and no context produce different results in
     * protocols less than TLSv1.3. In TLSv1.3 they should be the same.
     */
    if ((tst != 3 && !TEST_mem_ne(ckeymat2, sizeof(ckeymat2), ckeymat3,
                                  sizeof(ckeymat3)))
            || (tst ==3 && !TEST_mem_eq(ckeymat2, sizeof(ckeymat2), ckeymat3,
                                        sizeof(ckeymat3))))
        goto end;

    testresult = 1;

 end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx2);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

int test_main(int argc, char *argv[])
{
    int testresult = 1;

    if (argc != 3) {
        TEST_error("Wrong argument count");
        return 0;
    }

    cert = argv[1];
    privkey = argv[2];

    ADD_TEST(test_large_message_tls);
    ADD_TEST(test_large_message_tls_read_ahead);
#ifndef OPENSSL_NO_DTLS
    ADD_TEST(test_large_message_dtls);
#endif
#ifndef OPENSSL_NO_OCSP
    ADD_TEST(test_tlsext_status_type);
#endif
    ADD_TEST(test_session_with_only_int_cache);
    ADD_TEST(test_session_with_only_ext_cache);
    ADD_TEST(test_session_with_both_cache);
    ADD_ALL_TESTS(test_ssl_set_bio, TOTAL_SSL_SET_BIO_TESTS);
    ADD_TEST(test_ssl_bio_pop_next_bio);
    ADD_TEST(test_ssl_bio_pop_ssl_bio);
    ADD_TEST(test_ssl_bio_change_rbio);
    ADD_TEST(test_ssl_bio_change_wbio);
    ADD_ALL_TESTS(test_set_sigalgs, OSSL_NELEM(testsigalgs) * 2);
    ADD_TEST(test_keylog);
#ifndef OPENSSL_NO_TLS1_3
    ADD_TEST(test_keylog_no_master_key);
#endif
#ifndef OPENSSL_NO_TLS1_2
    ADD_TEST(test_early_cb);
#endif
#ifndef OPENSSL_NO_TLS1_3
    ADD_ALL_TESTS(test_early_data_read_write, 2);
    ADD_ALL_TESTS(test_early_data_skip, 2);
    ADD_ALL_TESTS(test_early_data_not_sent, 2);
    ADD_ALL_TESTS(test_early_data_not_expected, 2);
# ifndef OPENSSL_NO_TLS1_2
    ADD_ALL_TESTS(test_early_data_tls1_2, 2);
# endif
#endif
#ifndef OPENSSL_NO_TLS1_3
    ADD_TEST(test_ciphersuite_change);
    ADD_TEST(test_tls13_psk);
    ADD_ALL_TESTS(test_custom_exts, 5);
#else
    ADD_ALL_TESTS(test_custom_exts, 3);
#endif
    ADD_ALL_TESTS(test_serverinfo, 8);
    ADD_ALL_TESTS(test_export_key_mat, 4);

    testresult = run_tests(argv[0]);

    bio_s_mempacket_test_free();

    return testresult;
}
