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
#include "test_main_custom.h"
#include "e_os.h"

static char *cert = NULL;
static char *privkey = NULL;

#define LOG_BUFFER_SIZE 1024
static char server_log_buffer[LOG_BUFFER_SIZE + 1] = {0};
static int server_log_buffer_index = 0;
static char client_log_buffer[LOG_BUFFER_SIZE + 1] = {0};
static int client_log_buffer_index = 0;
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

static void client_keylog_callback(const SSL *ssl, const char *line) {
    int line_length = strlen(line);

    /* If the log doesn't fit, error out. */
    if ((client_log_buffer_index + line_length) > LOG_BUFFER_SIZE) {
        printf("No room in client log\n");
        error_writing_log = 1;
        return;
    }

    strcat(client_log_buffer, line);
    client_log_buffer_index += line_length;
    client_log_buffer[client_log_buffer_index] = '\n';
    client_log_buffer_index += 1;

    return;
}

static void server_keylog_callback(const SSL *ssl, const char *line) {
    int line_length = strlen(line);

    /* If the log doesn't fit, error out. */
    if ((server_log_buffer_index + line_length) > LOG_BUFFER_SIZE) {
        printf("No room in server log\n");
        error_writing_log = 1;
        return;
    }

    strcat(server_log_buffer, line);
    server_log_buffer_index += line_length;
    server_log_buffer[server_log_buffer_index] = '\n';
    server_log_buffer_index += 1;

    return;
}

static int compare_hex_encoded_buffer(const char *hex_encoded,
                                      size_t hex_length,
                                      const uint8_t *raw,
                                      size_t raw_length) {
    size_t i;
    size_t j;

    /* One byte too big, just to be safe. */
    char hexed[3] = {0};

    if ((raw_length * 2) != hex_length) {
        printf("Inconsistent hex encoded lengths.\n");
        return 1;
    }

    for (i = j = 0; (i < raw_length) && ((j + 1) < hex_length); i++) {
        sprintf(hexed, "%02x", raw[i]);
        if ((hexed[0] != hex_encoded[j]) || (hexed[1] != hex_encoded[j + 1])) {
            printf("Hex output does not match.\n");
            return 1;
        }
        j += 2;
    }

    return 0;
}

static int test_keylog_output(char *buffer, const SSL *ssl,
                              const SSL_SESSION *session,
                              struct sslapitest_log_counts *expected) {
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

    token = strtok(buffer, " \n");
    while (token) {
        if (strcmp(token, "RSA") == 0) {
            /*
             * Premaster secret. Tokens should be: 16 ASCII bytes of
             * hex-encoded encrypted secret, then the hex-encoded pre-master
             * secret.
             */
            token = strtok(NULL, " \n");
            if (!token) {
                printf("Unexpectedly short premaster secret log.\n");
                return 0;
            }
            if (strlen(token) != 16) {
                printf("Bad value for encrypted secret: %s\n", token);
                return 0;
            }
            token = strtok(NULL, " \n");
            if (!token) {
                printf("Unexpectedly short premaster secret log.\n");
                return 0;
            }
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
            if (client_random_size != SSL3_RANDOM_SIZE) {
                printf("Unexpected short client random.\n");
                return 0;
            }

            token = strtok(NULL, " \n");
            if (!token) {
                printf("Unexpected short master secret log.\n");
                return 0;
            }
            if (strlen(token) != 64) {
                printf("Bad value for client random: %s\n", token);
                return 0;
            }
            if (compare_hex_encoded_buffer(token, 64, actual_client_random,
                                           client_random_size)) {
                printf("Bad value for client random: %s\n", token);
                return 0;
            }

            token = strtok(NULL, " \n");
            if (!token) {
                printf("Unexpectedly short master secret log.\n");
                return 0;
            }

            master_key_size = SSL_SESSION_get_master_key(session,
                                                         actual_master_key,
                                                         master_key_size);
            if (!master_key_size) {
                printf("Error getting master key to compare.\n");
                return 0;
            }
            if (compare_hex_encoded_buffer(token, strlen(token),
                                           actual_master_key,
                                           master_key_size)) {
                printf("Bad value for master key: %s\n", token);
                return 0;
            }

            master_secret_count++;
        } else if ((strcmp(token, "CLIENT_HANDSHAKE_TRAFFIC_SECRET") == 0) ||
                   (strcmp(token, "SERVER_HANDSHAKE_TRAFFIC_SECRET") == 0) ||
                   (strcmp(token, "CLIENT_TRAFFIC_SECRET_0") == 0) ||
                   (strcmp(token, "SERVER_TRAFFIC_SECRET_0") == 0)) {
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
            if (client_random_size != SSL3_RANDOM_SIZE) {
                printf("Unexpected short client random.\n");
                return 0;
            }

            token = strtok(NULL, " \n");
            if (!token) {
                printf("Unexpected short client handshake secret log.\n");
                return 0;
            }
            if (strlen(token) != 64) {
                printf("Bad value for client random: %s\n", token);
                return 0;
            }
            if (compare_hex_encoded_buffer(token, 64, actual_client_random,
                                           client_random_size)) {
                printf("Bad value for client random: %s\n", token);
                return 0;
            }

            token = strtok(NULL, " \n");
            if (!token) {
                printf("Unexpectedly short master secret log.\n");
                return 0;
            }

            /*
             * TODO(TLS1.3): test that application traffic secrets are what
             * we expect */
        } else {
            printf("Unexpected token in buffer: %s\n", token);
            return 0;
        }

        token = strtok(NULL, " \n");
    }

    /* Return whether we got what we expected. */
    return ((rsa_key_exchange_count == expected->rsa_key_exchange_count) &&
            (master_secret_count == expected->master_secret_count) &&
            (client_handshake_secret_count == expected->client_handshake_secret_count) &&
            (server_handshake_secret_count == expected->server_handshake_secret_count) &&
            (client_application_secret_count == expected->client_application_secret_count) &&
            (server_application_secret_count == expected->server_application_secret_count));
}

static int test_keylog(void) {
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    int rc;
    struct sslapitest_log_counts expected = {0};

    /* Clean up logging space */
    memset(client_log_buffer, 0, LOG_BUFFER_SIZE + 1);
    memset(server_log_buffer, 0, LOG_BUFFER_SIZE + 1);
    client_log_buffer_index = 0;
    server_log_buffer_index = 0;
    error_writing_log = 0;

    if (!create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(), &sctx,
                             &cctx, cert, privkey)) {
        printf("Unable to create SSL_CTX pair\n");
        return 0;
    }

    /* We cannot log the master secret for TLSv1.3, so we should forbid it. */
    SSL_CTX_set_options(cctx, SSL_OP_NO_TLSv1_3);
    SSL_CTX_set_options(sctx, SSL_OP_NO_TLSv1_3);

    /* We also want to ensure that we use RSA-based key exchange. */
    rc = SSL_CTX_set_cipher_list(cctx, "RSA");
    if (rc == 0) {
        printf("Unable to restrict to RSA key exchange.\n");
        goto end;
    }

    if (SSL_CTX_get_keylog_callback(cctx)) {
        printf("Unexpected initial value for client "
               "SSL_CTX_get_keylog_callback()\n");
        goto end;
    }
    if (SSL_CTX_get_keylog_callback(sctx)) {
        printf("Unexpected initial value for server "
               "SSL_CTX_get_keylog_callback()\n");
        goto end;
    }

    SSL_CTX_set_keylog_callback(cctx, client_keylog_callback);
    SSL_CTX_set_keylog_callback(sctx, server_keylog_callback);

    if (SSL_CTX_get_keylog_callback(cctx) != client_keylog_callback) {
        printf("Unexpected set value for client "
               "SSL_CTX_get_keylog_callback()\n");
    }

    if (SSL_CTX_get_keylog_callback(sctx) != server_keylog_callback) {
        printf("Unexpected set value for server "
               "SSL_CTX_get_keylog_callback()\n");
    }

    /* Now do a handshake and check that the logs have been written to. */
    if (!create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)) {
        printf("Unable to create SSL objects\n");
        goto end;
    }

    if (!create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)) {
        printf("Unable to create SSL connection\n");
        goto end;
    }

    if (error_writing_log) {
        printf("Error encountered while logging\n");
        goto end;
    }

    if ((client_log_buffer_index == 0) || (server_log_buffer_index == 0)) {
        printf("No logs written\n");
        goto end;
    }

    /*
     * Now we want to test that our output data was vaguely sensible. We
     * do that by using strtok and confirming that we have more or less the
     * data we expect. For both client and server, we expect to see one master
     * secret. The client should also see a RSA key exchange.
     */
    expected.rsa_key_exchange_count = 1;
    expected.master_secret_count = 1;
    if (!test_keylog_output(client_log_buffer, clientssl,
                            SSL_get_session(clientssl), &expected)) {
        printf("Error encountered in client log buffer\n");
        goto end;
    }

    expected.rsa_key_exchange_count = 0;
    if (!test_keylog_output(server_log_buffer, serverssl,
                            SSL_get_session(serverssl), &expected)) {
        printf("Error encountered in server log buffer\n");
        goto end;
    }

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

#ifndef OPENSSL_NO_TLS1_3
static int test_keylog_no_master_key(void) {
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    struct sslapitest_log_counts expected = {0};

    /* Clean up logging space */
    memset(client_log_buffer, 0, LOG_BUFFER_SIZE + 1);
    memset(server_log_buffer, 0, LOG_BUFFER_SIZE + 1);
    client_log_buffer_index = 0;
    server_log_buffer_index = 0;
    error_writing_log = 0;

    if (!create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(), &sctx,
                             &cctx, cert, privkey)) {
        printf("Unable to create SSL_CTX pair\n");
        return 0;
    }

    if (SSL_CTX_get_keylog_callback(cctx)) {
        printf("Unexpected initial value for client "
               "SSL_CTX_get_keylog_callback()\n");
        goto end;
    }
    if (SSL_CTX_get_keylog_callback(sctx)) {
        printf("Unexpected initial value for server "
               "SSL_CTX_get_keylog_callback()\n");
        goto end;
    }

    SSL_CTX_set_keylog_callback(cctx, client_keylog_callback);
    SSL_CTX_set_keylog_callback(sctx, server_keylog_callback);

    if (SSL_CTX_get_keylog_callback(cctx) != client_keylog_callback) {
        printf("Unexpected set value for client "
               "SSL_CTX_get_keylog_callback()\n");
    }

    if (SSL_CTX_get_keylog_callback(sctx) != server_keylog_callback) {
        printf("Unexpected set value for server "
               "SSL_CTX_get_keylog_callback()\n");
    }

    /* Now do a handshake and check that the logs have been written to. */
    if (!create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)) {
        printf("Unable to create SSL objects\n");
        goto end;
    }

    if (!create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)) {
        printf("Unable to create SSL connection\n");
        goto end;
    }

    if (error_writing_log) {
        printf("Error encountered while logging\n");
        goto end;
    }

    /*
     * Now we want to test that our output data was vaguely sensible. For this
     * test, we expect no CLIENT_RANDOM entry becuase it doesn't make sense for
     * TLSv1.3, but we do expect both client and server to emit keys.
     */
    expected.client_handshake_secret_count = 1;
    expected.server_handshake_secret_count = 1;
    expected.client_application_secret_count = 1;
    expected.server_application_secret_count = 1;
    if (!test_keylog_output(client_log_buffer, clientssl,
                            SSL_get_session(clientssl), &expected)) {
        printf("Error encountered in client log buffer\n");
        goto end;
    }
    if (!test_keylog_output(server_log_buffer, serverssl,
                            SSL_get_session(serverssl), &expected)) {
        printf("Error encountered in server log buffer\n");
        goto end;
    }

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
    /* We only configure two ciphers, but the SCSV is added automatically. */
#ifdef OPENSSL_NO_EC
    const unsigned char expected_ciphers[] = {0x00, 0x9d, 0x00, 0xff};
#else
    const unsigned char expected_ciphers[] = {0x00, 0x9d, 0xc0,
                                              0x2c, 0x00, 0xff};
#endif
    size_t len;

    /* Make sure we can defer processing and get called back. */
    if ((*ctr)++ == 0)
        return -1;

    len = SSL_early_get0_ciphers(s, &p);
    if (len != sizeof(expected_ciphers) ||
        memcmp(p, expected_ciphers, len) != 0) {
        printf("Early callback expected ciphers mismatch\n");
        return 0;
    }
    len = SSL_early_get0_compression_methods(s, &p);
    if (len != 1 || *p != 0) {
        printf("Early callback expected comperssion methods mismatch\n");
        return 0;
    }
    return 1;
}

static int test_early_cb(void) {
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testctr = 0, testresult = 0;

    if (!create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(), &sctx,
                             &cctx, cert, privkey)) {
        printf("Unable to create SSL_CTX pair\n");
        goto end;
    }

    SSL_CTX_set_early_cb(sctx, full_early_callback, &testctr);
    /* The gimpy cipher list we configure can't do TLS 1.3. */
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
    if (!SSL_CTX_set_cipher_list(cctx,
            "AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384")) {
        printf("Failed to set cipher list\n");
        goto end;
    }

    if (!create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)) {
        printf("Unable to create SSL objects\n");
        goto end;
    }

    if (create_ssl_connection(serverssl, clientssl, SSL_ERROR_WANT_EARLY)) {
        printf("Creating SSL connection succeeded with async early return\n");
        goto end;
    }

    /* Passing a -1 literal is a hack since the real value was lost. */
    if (SSL_get_error(serverssl, -1) != SSL_ERROR_WANT_EARLY) {
        printf("Early callback failed to make state SSL_ERROR_WANT_EARLY\n");
        goto end;
    }

    if (!create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)) {
        printf("Restarting SSL connection failed\n");
        goto end;
    }

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
    BIO *certbio = BIO_new_file(cert, "r");
    X509 *chaincert = NULL;
    int certlen;

    if (certbio == NULL) {
        printf("Can't load the certficate file\n");
        goto end;
    }
    chaincert = PEM_read_bio_X509(certbio, NULL, NULL, NULL);
    BIO_free(certbio);
    certbio = NULL;
    if (chaincert == NULL) {
        printf("Unable to load certificate for chain\n");
        goto end;
    }

    if (!create_ssl_ctx_pair(smeth, cmeth, &sctx,
                             &cctx, cert, privkey)) {
        printf("Unable to create SSL_CTX pair\n");
        goto end;
    }

    if(read_ahead) {
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
     * works, it ends up allocing a little over 21k (16 * 4/3). So, in this test
     * we need to have a message larger than that.
     */
    certlen = i2d_X509(chaincert, NULL);
    OPENSSL_assert((certlen * NUM_EXTRA_CERTS)
                   > ((SSL3_RT_MAX_PLAIN_LENGTH * 4) / 3));
    for (i = 0; i < NUM_EXTRA_CERTS; i++) {
        if (!X509_up_ref(chaincert)) {
            printf("Unable to up ref cert\n");
            goto end;
        }
        if (!SSL_CTX_add_extra_chain_cert(sctx, chaincert)) {
            printf("Unable to add extra chain cert %d\n", i);
            X509_free(chaincert);
            goto end;
        }
    }

    if (!create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)) {
        printf("Unable to create SSL objects\n");
        goto end;
    }

    if (!create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)) {
        printf("Unable to create SSL connection\n");
        goto end;
    }

    /*
     * Calling SSL_clear() first is not required but this tests that SSL_clear()
     * doesn't leak (when using enable-crypto-mdebug).
     */
    if (!SSL_clear(serverssl)) {
        printf("Unexpected failure from SSL_clear()\n");
        goto end;
    }

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
    unsigned char *orespdercopy = NULL;
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


    orespdercopy = OPENSSL_memdup(orespder, sizeof(orespder));
    if (orespdercopy == NULL)
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    SSL_set_tlsext_status_ocsp_resp(s, orespdercopy, sizeof(orespder));

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

    if (memcmp(orespder, respderin, len) != 0)
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
                             &cctx, cert, privkey)) {
        printf("Unable to create SSL_CTX pair\n");
        return 0;
    }

    if (SSL_CTX_get_tlsext_status_type(cctx) != -1) {
        printf("Unexpected initial value for "
               "SSL_CTX_get_tlsext_status_type()\n");
        goto end;
    }

    /* First just do various checks getting and setting tlsext_status_type */

    clientssl = SSL_new(cctx);
    if (SSL_get_tlsext_status_type(clientssl) != -1) {
        printf("Unexpected initial value for SSL_get_tlsext_status_type()\n");
        goto end;
    }

    if (!SSL_set_tlsext_status_type(clientssl, TLSEXT_STATUSTYPE_ocsp)) {
        printf("Unexpected fail for SSL_set_tlsext_status_type()\n");
        goto end;
    }

    if (SSL_get_tlsext_status_type(clientssl) != TLSEXT_STATUSTYPE_ocsp) {
        printf("Unexpected result for SSL_get_tlsext_status_type()\n");
        goto end;
    }

    SSL_free(clientssl);
    clientssl = NULL;

    if (!SSL_CTX_set_tlsext_status_type(cctx, TLSEXT_STATUSTYPE_ocsp)) {
        printf("Unexpected fail for SSL_CTX_set_tlsext_status_type()\n");
        goto end;
    }

    if (SSL_CTX_get_tlsext_status_type(cctx) != TLSEXT_STATUSTYPE_ocsp) {
        printf("Unexpected result for SSL_CTX_get_tlsext_status_type()\n");
        goto end;
    }

    clientssl = SSL_new(cctx);

    if (SSL_get_tlsext_status_type(clientssl) != TLSEXT_STATUSTYPE_ocsp) {
        printf("Unexpected result for SSL_get_tlsext_status_type() (test 2)\n");
        goto end;
    }

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

    if (!create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)) {
        printf("Unable to create SSL objects\n");
        goto end;
    }

    if (!create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)) {
        printf("Unable to create SSL connection\n");
        goto end;
    }

    if (!ocsp_client_called || !ocsp_server_called) {
        printf("OCSP callbacks not called\n");
        goto end;
    }

    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = NULL;
    clientssl = NULL;

    /* Try again but this time force the server side callback to fail */
    ocsp_client_called = 0;
    ocsp_server_called = 0;
    cdummyarg = 0;

    if (!create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)) {
        printf("Unable to create SSL objects\n");
        goto end;
    }

    /* This should fail because the callback will fail */
    if (create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)) {
        printf("Unexpected success creating the connection\n");
        goto end;
    }

    if (ocsp_client_called || ocsp_server_called) {
        printf("OCSP callbacks successfully called unexpectedly\n");
        goto end;
    }

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

    if (!create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)) {
        printf("Unable to create SSL objects\n");
        goto end;
    }

    /*
     * We'll just use any old cert for this test - it doesn't have to be an OCSP
     * specifc one. We'll use the server cert.
     */
    certbio = BIO_new_file(cert, "r");
    if (certbio == NULL) {
        printf("Can't load the certficate file\n");
        goto end;
    }
    id = OCSP_RESPID_new();
    ids = sk_OCSP_RESPID_new_null();
    ocspcert = PEM_read_bio_X509(certbio, NULL, NULL, NULL);
    if (id == NULL || ids == NULL || ocspcert == NULL
            || !OCSP_RESPID_set_by_key(id, ocspcert)
            || !sk_OCSP_RESPID_push(ids, id)) {
        printf("Unable to set OCSP_RESPIDs\n");
        goto end;
    }
    id = NULL;
    SSL_set_tlsext_status_ids(clientssl, ids);
    /* Control has been transferred */
    ids = NULL;

    BIO_free(certbio);
    certbio = NULL;

    if (!create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)) {
        printf("Unable to create SSL connection\n");
        goto end;
    }

    if (!ocsp_client_called || !ocsp_server_called) {
        printf("OCSP callbacks not called\n");
        goto end;
    }

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

    if (!create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(), &sctx,
                             &cctx, cert, privkey)) {
        printf("Unable to create SSL_CTX pair\n");
        return 0;
    }

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

    if (!create_ssl_objects(sctx, cctx, &serverssl1, &clientssl1, NULL,
                               NULL)) {
        printf("Unable to create SSL objects\n");
        goto end;
    }

    if (!create_ssl_connection(serverssl1, clientssl1, SSL_ERROR_NONE)) {
        printf("Unable to create SSL connection\n");
        goto end;
    }
    sess1 = SSL_get1_session(clientssl1);
    if (sess1 == NULL) {
        printf("Unexpected NULL session\n");
        goto end;
    }

    if (fix.use_int_cache && SSL_CTX_add_session(cctx, sess1)) {
        /* Should have failed because it should already be in the cache */
        printf("Unexpected success adding session to cache\n");
        goto end;
    }

    if (fix.use_ext_cache && (new_called != 1 || remove_called != 0)) {
        printf("Session not added to cache\n");
        goto end;
    }

    if (!create_ssl_objects(sctx, cctx, &serverssl2, &clientssl2, NULL, NULL)) {
        printf("Unable to create second SSL objects\n");
        goto end;
    }

    if (!create_ssl_connection(serverssl2, clientssl2, SSL_ERROR_NONE)) {
        printf("Unable to create second SSL connection\n");
        goto end;
    }

    sess2 = SSL_get1_session(clientssl2);
    if (sess2 == NULL) {
        printf("Unexpected NULL session from clientssl2\n");
        goto end;
    }

    if (fix.use_ext_cache && (new_called != 2 || remove_called != 0)) {
        printf("Remove session callback unexpectedly called\n");
        goto end;
    }

    /*
     * This should clear sess2 from the cache because it is a "bad" session. See
     * SSL_set_session() documentation.
     */
    if (!SSL_set_session(clientssl2, sess1)) {
        printf("Unexpected failure setting session\n");
        goto end;
    }

    if (fix.use_ext_cache && (new_called != 2 || remove_called != 1)) {
        printf("Failed to call callback to remove session\n");
        goto end;
    }


    if (SSL_get_session(clientssl2) != sess1) {
        printf("Unexpected session found\n");
        goto end;
    }

    if (fix.use_int_cache) {
        if (!SSL_CTX_add_session(cctx, sess2)) {
            /*
             * Should have succeeded because it should not already be in the cache
             */
            printf("Unexpected failure adding session to cache\n");
            goto end;
        }

        if (!SSL_CTX_remove_session(cctx, sess2)) {
            printf("Unexpected failure removing session from cache\n");
            goto end;
        }

        /* This is for the purposes of internal cache testing...ignore the
         * counter for external cache
         */
        if (fix.use_ext_cache)
            remove_called--;
    }

    /* This shouldn't be in the cache so should fail */
    if (SSL_CTX_remove_session(cctx, sess2)) {
        printf("Unexpected success removing session from cache\n");
        goto end;
    }

    if (fix.use_ext_cache && (new_called != 2 || remove_called != 2)) {
        printf("Failed to call callback to remove session #2\n");
        goto end;
    }

#if !defined(OPENSSL_NO_TLS1_1) && !defined(OPENSSL_NO_TLS1_2)
    /* Force a connection failure */
    SSL_CTX_set_max_proto_version(sctx, TLS1_1_VERSION);

    if (!create_ssl_objects(sctx, cctx, &serverssl3, &clientssl3, NULL, NULL)) {
        printf("Unable to create third SSL objects\n");
        goto end;
    }

    if (!SSL_set_session(clientssl3, sess1)) {
        printf("Unable to set session for third connection\n");
        goto end;
    }

    /* This should fail because of the mismatched protocol versions */
    if (create_ssl_connection(serverssl3, clientssl3, SSL_ERROR_NONE)) {
        printf("Unable to create third SSL connection\n");
        goto end;
    }


    /* We should have automatically removed the session from the cache */
    if (fix.use_ext_cache && (new_called != 2 || remove_called != 3)) {
        printf("Failed to call callback to remove session #2\n");
        goto end;
    }

    if (fix.use_int_cache && !SSL_CTX_add_session(cctx, sess2)) {
        /*
         * Should have succeeded because it should not already be in the cache
         */
        printf("Unexpected failure adding session to cache #2\n");
        goto end;
    }
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
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    BIO *bio1 = NULL;
    BIO *bio2 = NULL;
    BIO *irbio = NULL, *iwbio = NULL, *nrbio = NULL, *nwbio = NULL;
    SSL *ssl = NULL;
    int initrbio, initwbio, newrbio, newwbio;
    int testresult = 0;

    if (ctx == NULL) {
        printf("Failed to allocate SSL_CTX\n");
        goto end;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("Failed to allocate SSL object\n");
        goto end;
    }

    initrbio = idx % 3;
    idx /= 3;
    initwbio = idx % 3;
    idx /= 3;
    newrbio = idx % 3;
    idx /= 3;
    newwbio = idx;
    OPENSSL_assert(newwbio <= 2);

    if (initrbio == USE_BIO_1 || initwbio == USE_BIO_1 || newrbio == USE_BIO_1
            || newwbio == USE_BIO_1) {
        bio1 = BIO_new(BIO_s_mem());
        if (bio1 == NULL) {
            printf("Failed to allocate bio1\n");
            goto end;
        }
    }

    if (initrbio == USE_BIO_2 || initwbio == USE_BIO_2 || newrbio == USE_BIO_2
            || newwbio == USE_BIO_2) {
        bio2 = BIO_new(BIO_s_mem());
        if (bio2 == NULL) {
            printf("Failed to allocate bio2\n");
            goto end;
        }
    }

    setupbio(&irbio, bio1, bio2, initrbio);
    setupbio(&iwbio, bio1, bio2, initwbio);

    /*
     * We want to maintain our own refs to these BIO, so do an up ref for each
     * BIO that will have ownersip transferred in the SSL_set_bio() call
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
    if (nrbio != NULL && nrbio != irbio && (nwbio != iwbio || nrbio != nwbio))
        BIO_up_ref(nrbio);
    if (nwbio != NULL && nwbio != nrbio && (nwbio != iwbio || (nwbio == iwbio && irbio == iwbio)))
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
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *ssl = NULL;
    int testresult = 0;

    if (ctx == NULL) {
        printf("Failed to allocate SSL_CTX\n");
        return 0;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("Failed to allocate SSL object\n");
        goto end;
    }

    sslbio = BIO_new(BIO_f_ssl());
    membio1 = BIO_new(BIO_s_mem());

    if (sslbio == NULL || membio1 == NULL) {
        printf("Malloc failure creating BIOs\n");
        goto end;
    }

    BIO_set_ssl(sslbio, ssl, BIO_CLOSE);

    /*
     * If anything goes wrong here then we could leak memory, so this will
     * be caught in a crypto-mdebug build
     */
    BIO_push(sslbio, membio1);

    /* Verify chaning the rbio/wbio directly does not cause leaks */
    if (fix.change_bio != NO_BIO_CHANGE) {
        membio2 = BIO_new(BIO_s_mem());
        if (membio2 == NULL) {
            printf("Malloc failure creating membio2\n");
            goto end;
        }
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
    {NULL, 0, "Invalid", 0, 0}};

static int test_set_sigalgs(int idx)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    const sigalgs_list *curr;
    int testctx;

    /* Should never happen */
    if ((size_t)idx >= OSSL_NELEM(testsigalgs) * 2)
        return 0;

    testctx = ((size_t)idx < OSSL_NELEM(testsigalgs));
    curr = testctx ? &testsigalgs[idx]
                   : &testsigalgs[idx - OSSL_NELEM(testsigalgs)];

    if (!create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(), &sctx,
                             &cctx, cert, privkey)) {
        printf("Unable to create SSL_CTX pair\n");
        return 0;
    }

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
                printf("Unexpected failure setting sigalgs in SSL_CTX (%d)\n",
                       idx);
            else
                testresult = 1;
            goto end;
        }
        if (!curr->valid) {
            printf("Unexpected success setting sigalgs in SSL_CTX (%d)\n", idx);
            goto end;
        }
    }

    if (!create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)) {
        printf("Unable to create SSL objects\n");
        goto end;
    }

    if (!testctx) {
        int ret;

        if (curr->list != NULL)
            ret = SSL_set1_sigalgs(clientssl, curr->list, curr->listlen);
        else
            ret = SSL_set1_sigalgs_list(clientssl, curr->liststr);
        if (!ret) {
            if (curr->valid)
                printf("Unexpected failure setting sigalgs in SSL (%d)\n", idx);
            else
                testresult = 1;
            goto end;
        }
        if (!curr->valid) {
            printf("Unexpected success setting sigalgs in SSL (%d)\n", idx);
            goto end;
        }
    }

    if (curr->connsuccess != create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)) {
        printf("Unexpected return value creating SSL connection (%d)\n", idx);
        goto end;
    }

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
#define MSG6    "test."

/*
 * Helper method to setup objects for early data test. Caller frees objects on
 * error.
 */
static int setupearly_data_test(SSL_CTX **cctx, SSL_CTX **sctx, SSL **clientssl,
                                SSL **serverssl, SSL_SESSION **sess)
{
    if (!create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(), sctx,
                             cctx, cert, privkey)) {
        printf("Unable to create SSL_CTX pair\n");
        return 0;
    }

    if (!create_ssl_objects(*sctx, *cctx, serverssl, clientssl, NULL, NULL)) {
        printf("Unable to create SSL objects\n");
        return 0;
    }

    if (!create_ssl_connection(*serverssl, *clientssl, SSL_ERROR_NONE)) {
        printf("Unable to create SSL connection\n");
        return 0;
    }

    *sess = SSL_get1_session(*clientssl);

    SSL_shutdown(*clientssl);
    SSL_shutdown(*serverssl);

    SSL_free(*serverssl);
    SSL_free(*clientssl);
    *serverssl = *clientssl = NULL;

    if (!create_ssl_objects(*sctx, *cctx, serverssl, clientssl, NULL, NULL)) {
        printf("Unable to create SSL objects (2)\n");
        return 0;
    }

    if (!SSL_set_session(*clientssl, *sess)) {
        printf("Failed setting session\n");
        return 0;
    }

    return 1;
}

static int test_early_data_read_write(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    SSL_SESSION *sess = NULL;
    unsigned char buf[20];
    size_t readbytes, written;

    if (!setupearly_data_test(&cctx, &sctx, &clientssl, &serverssl, &sess))
        goto end;

    /* Write and read some early data */
    if (!SSL_write_early_data(clientssl, MSG1, strlen(MSG1), &written)
            || written != strlen(MSG1)) {
        printf("Failed writing early data message 1\n");
        goto end;
    }

    if (SSL_read_early_data(serverssl, buf, sizeof(buf), &readbytes)
                != SSL_READ_EARLY_DATA_SUCCESS
            || readbytes != strlen(MSG1)
            || memcmp(MSG1, buf, strlen(MSG1))) {
        printf("Failed reading early data message 1\n");
        goto end;
    }

    if (SSL_get_early_data_status(serverssl) != SSL_EARLY_DATA_ACCEPTED) {
        printf("Unexpected early data status\n");
        goto end;
    }

    /*
     * Server should be able to write data, and client should be able to
     * read it.
     */
    if (!SSL_write_early_data(serverssl, MSG2, strlen(MSG2), &written)
            || written != strlen(MSG2)) {
        printf("Failed writing message 2\n");
        goto end;
    }

    if (!SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes)
            || readbytes != strlen(MSG2)
            || memcmp(MSG2, buf, strlen(MSG2))) {
        printf("Failed reading message 2\n");
        goto end;
    }

    /* Even after reading normal data, client should be able write early data */
    if (!SSL_write_early_data(clientssl, MSG3, strlen(MSG3), &written)
            || written != strlen(MSG3)) {
        printf("Failed writing early data message 3\n");
        goto end;
    }

    /* Server should still be able read early data after writing data */
    if (SSL_read_early_data(serverssl, buf, sizeof(buf), &readbytes)
                != SSL_READ_EARLY_DATA_SUCCESS
            || readbytes != strlen(MSG3)
            || memcmp(MSG3, buf, strlen(MSG3))) {
        printf("Failed reading early data message 3\n");
        goto end;
    }

    /* Write more data from server and read it from client */
    if (!SSL_write_early_data(serverssl, MSG4, strlen(MSG4), &written)
            || written != strlen(MSG4)) {
        printf("Failed writing message 4\n");
        goto end;
    }

    if (!SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes)
            || readbytes != strlen(MSG4)
            || memcmp(MSG4, buf, strlen(MSG4))) {
        printf("Failed reading message 4\n");
        goto end;
    }

    /*
     * If client writes normal data it should mean writing early data is no
     * longer possible.
     */
    if (!SSL_write_ex(clientssl, MSG5, strlen(MSG5), &written)
            || written != strlen(MSG5)) {
        printf("Failed writing message 5\n");
        goto end;
    }

    if (SSL_get_early_data_status(clientssl) != SSL_EARLY_DATA_ACCEPTED) {
        printf("Unexpected early data status(2)\n");
        goto end;
    }

    /* Server should be told that there is no more early data */
    if (SSL_read_early_data(serverssl, buf, sizeof(buf), &readbytes)
                != SSL_READ_EARLY_DATA_FINISH
            || readbytes != 0) {
        printf("Failed finishing read of early data\n");
        goto end;
    }

    /* Server should be able to read normal data */
    if (!SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes)
            || readbytes != strlen(MSG5)) {
        printf("Failed reading message 5\n");
        goto end;
    }

    /* Client and server should not be able to write/read early data now */
    if (SSL_write_early_data(clientssl, MSG6, strlen(MSG6), &written)) {
        printf("Unexpected success writing early data\n");
        goto end;
    }
    ERR_clear_error();

    if (SSL_read_early_data(serverssl, buf, sizeof(buf), &readbytes)
                != SSL_READ_EARLY_DATA_ERROR) {
        printf("Unexpected success reading early data\n");
        goto end;
    }
    ERR_clear_error();

    /*
     * Make sure we process the NewSessionTicket. This arrives post-handshake
     * so we must make sure we attempt a read - even though we don't expect to
     * actually get any application data.
     */
    if (SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes)) {
        printf("Unexpected success doing final client read\n");
        goto end;
    }

    SSL_SESSION_free(sess);
    sess = SSL_get1_session(clientssl);

    SSL_shutdown(clientssl);
    SSL_shutdown(serverssl);

    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = clientssl = NULL;

    if (!create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)) {
        printf("Unable to create SSL objects (3)\n");
        goto end;
    }

    if (!SSL_set_session(clientssl, sess)) {
        printf("Failed setting session (2)\n");
        goto end;
    }

    /* Write and read some early data */
    if (!SSL_write_early_data(clientssl, MSG1, strlen(MSG1), &written)
            || written != strlen(MSG1)) {
        printf("Failed writing early data message 1\n");
        goto end;
    }

    if (SSL_read_early_data(serverssl, buf, sizeof(buf), &readbytes)
                != SSL_READ_EARLY_DATA_SUCCESS
            || readbytes != strlen(MSG1)
            || memcmp(MSG1, buf, strlen(MSG1))) {
        printf("Failed reading early data message 1\n");
        goto end;
    }

    if (SSL_connect(clientssl) <= 0) {
        printf("Unable to complete client handshake\n");
        goto end;
    }

    if (SSL_accept(serverssl) <= 0) {
        printf("Unable to complete server handshake\n");
        goto end;
    }

    /* Client and server should not be able to write/read early data now */
    if (SSL_write_early_data(clientssl, MSG6, strlen(MSG6), &written)) {
        printf("Unexpected success writing early data (2)\n");
        goto end;
    }
    ERR_clear_error();

    if (SSL_read_early_data(serverssl, buf, sizeof(buf), &readbytes)
                != SSL_READ_EARLY_DATA_ERROR) {
        printf("Unexpected success reading early data (2)\n");
        goto end;
    }
    ERR_clear_error();

    /* Client and server should be able to write/read normal data */
    if (!SSL_write_ex(clientssl, MSG5, strlen(MSG5), &written)
            || written != strlen(MSG5)) {
        printf("Failed writing message 5 (2)\n");
        goto end;
    }

    if (!SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes)
            || readbytes != strlen(MSG5)) {
        printf("Failed reading message 5 (2)\n");
        goto end;
    }

    testresult = 1;

 end:
    if(!testresult)
        ERR_print_errors_fp(stdout);
    SSL_SESSION_free(sess);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

static int test_early_data_skip(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    SSL_SESSION *sess;
    unsigned char buf[20];
    size_t readbytes, written;

    /*
     * Test that a server attempting to read early data can handle a connection
     * from a client where the early data is not acceptable.
     */

    if (!setupearly_data_test(&cctx, &sctx, &clientssl, &serverssl, &sess))
        goto end;

    /*
     * Deliberately corrupt the creation time. We take 20 seconds off the time.
     * It could be any value as long as it is not within tolerance. This should
     * mean the ticket is rejected.
     */
    if (!SSL_SESSION_set_time(sess, time(NULL) - 20)) {
        printf("Unexpected failure setting session creation time\n");
        goto end;
    }

    /* Write some early data */
    if (!SSL_write_early_data(clientssl, MSG1, strlen(MSG1), &written)
            || written != strlen(MSG1)) {
        printf("Failed writing early data message 1\n");
        goto end;
    }

    /* Server should reject the early data and skip over it */
    if (SSL_read_early_data(serverssl, buf, sizeof(buf), &readbytes)
                != SSL_READ_EARLY_DATA_FINISH
            || readbytes != 0) {
        printf("Failed reading early data\n");
        goto end;
    }

    if (SSL_get_early_data_status(serverssl) != SSL_EARLY_DATA_REJECTED) {
        printf("Unexpected early data status\n");
        goto end;
    }

    /*
     * We should be able to send normal data despite rejection of early data
     */
    if (!SSL_write_ex(clientssl, MSG2, strlen(MSG2), &written)
            || written != strlen(MSG2)) {
        printf("Failed writing message 2\n");
        goto end;
    }

    if (SSL_get_early_data_status(clientssl) != SSL_EARLY_DATA_REJECTED) {
        printf("Unexpected early data status (2)\n");
        goto end;
    }

    if (!SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes)
            || readbytes != strlen(MSG2)
            || memcmp(MSG2, buf, strlen(MSG2))) {
        printf("Failed reading message 2\n");
        goto end;
    }

    testresult = 1;

 end:
    if(!testresult)
        ERR_print_errors_fp(stdout);
    SSL_SESSION_free(sess);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

static int test_early_data_not_sent(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    SSL_SESSION *sess;
    unsigned char buf[20];
    size_t readbytes, written;

    /*
     * Test that a server attempting to read early data can handle a connection
     * from a client that doesn't send any.
     */

    if (!setupearly_data_test(&cctx, &sctx, &clientssl, &serverssl, &sess))
        goto end;

    /* Write some data - should block due to handshake with server */
    SSL_set_connect_state(clientssl);
    if (SSL_write_ex(clientssl, MSG1, strlen(MSG1), &written)) {
        printf("Unexpected success writing message 1\n");
        goto end;
    }

    /* Server should detect that early data has not been sent */
    if (SSL_read_early_data(serverssl, buf, sizeof(buf), &readbytes)
                != SSL_READ_EARLY_DATA_FINISH
            || readbytes != 0) {
        printf("Failed reading early data\n");
        goto end;
    }

    if (SSL_get_early_data_status(serverssl) != SSL_EARLY_DATA_NOT_SENT) {
        printf("Unexpected early data status\n");
        goto end;
    }

    if (SSL_get_early_data_status(clientssl) != SSL_EARLY_DATA_NOT_SENT) {
        printf("Unexpected early data status (2)\n");
        goto end;
    }

    /* Continue writing the message we started earlier */
    if (!SSL_write_ex(clientssl, MSG1, strlen(MSG1), &written)
            || written != strlen(MSG1)) {
        printf("Failed writing message 1\n");
        goto end;
    }

    if (!SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes)
            || readbytes != strlen(MSG1)
            || memcmp(MSG1, buf, strlen(MSG1))) {
        printf("Failed reading message 1\n");
        goto end;
    }

    if (!SSL_write_ex(serverssl, MSG2, strlen(MSG2), &written)
            || written != strlen(MSG2)) {
        printf("Failed writing message 2\n");
        goto end;
    }

    /* Should block due to the NewSessionTicket arrival */
    if (SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes)) {
        printf("Unexpected success reading message 2\n");
        goto end;
    }

    if (!SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes)
            || readbytes != strlen(MSG2)
            || memcmp(MSG2, buf, strlen(MSG2))) {
        printf("Failed reading message 2\n");
        goto end;
    }

    testresult = 1;

 end:
    if(!testresult)
        ERR_print_errors_fp(stdout);
    SSL_SESSION_free(sess);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

static int test_early_data_not_expected(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    SSL_SESSION *sess;
    unsigned char buf[20];
    size_t readbytes, written;

    /*
     * Test that a server that doesn't try to read early data can handle a
     * client sending some.
     */

    if (!setupearly_data_test(&cctx, &sctx, &clientssl, &serverssl, &sess))
        goto end;

    /* Write some early data */
    if (!SSL_write_early_data(clientssl, MSG1, strlen(MSG1), &written)) {
        printf("Unexpected failure writing message 1\n");
        goto end;
    }

    /*
     * Server should skip over early data and then block waiting for client to
     * continue handshake
     */
    if (SSL_accept(serverssl) > 0) {
        printf("Unexpected success setting up server connection\n");
        goto end;
    }

    if (SSL_connect(clientssl) <= 0) {
        printf("Failed setting up client connection\n");
        goto end;
    }

    if (SSL_get_early_data_status(serverssl) != SSL_EARLY_DATA_REJECTED) {
        printf("Unexpected early data status\n");
        goto end;
    }

    if (SSL_accept(serverssl) <= 0) {
        printf("Failed setting up server connection\n");
        goto end;
    }

    if (SSL_get_early_data_status(clientssl) != SSL_EARLY_DATA_REJECTED) {
        printf("Unexpected early data status (2)\n");
        goto end;
    }

    /* Send some normal data from client to server */
    if (!SSL_write_ex(clientssl, MSG2, strlen(MSG2), &written)
            || written != strlen(MSG2)) {
        printf("Failed writing message 2\n");
        goto end;
    }

    if (!SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes)
            || readbytes != strlen(MSG2)
            || memcmp(MSG2, buf, strlen(MSG2))) {
        printf("Failed reading message 2\n");
        goto end;
    }

    testresult = 1;

 end:
    if(!testresult)
        ERR_print_errors_fp(stdout);
    SSL_SESSION_free(sess);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}


# ifndef OPENSSL_NO_TLS1_2
static int test_early_data_tls1_2(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    unsigned char buf[20];
    size_t readbytes, written;

    /*
     * Test that a server attempting to read early data can handle a connection
     * from a TLSv1.2 client.
     */

    if (!create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(), &sctx,
                             &cctx, cert, privkey)) {
        printf("Unable to create SSL_CTX pair\n");
        goto end;
    }

    if (!create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL)) {
        printf("Unable to create SSL objects\n");
        goto end;
    }

    /* Write some data - should block due to handshake with server */
    SSL_set_max_proto_version(clientssl, TLS1_2_VERSION);
    SSL_set_connect_state(clientssl);
    if (SSL_write_ex(clientssl, MSG1, strlen(MSG1), &written)) {
        printf("Unexpected success writing message 1\n");
        goto end;
    }

    /*
     * Server should do TLSv1.2 handshake. First it will block waiting for more
     * messages from client after ServerDone. Then SSL_read_early_data should
     * finish and detect that early data has not been sent
     */
    if (SSL_read_early_data(serverssl, buf, sizeof(buf), &readbytes)
                != SSL_READ_EARLY_DATA_ERROR) {
        printf("Unexpected success reading early data\n");
        goto end;
    }

    /*
     * Continue writing the message we started earlier. Will still block waiting
     * for the CCS/Finished from server
     */
    if (SSL_write_ex(clientssl, MSG1, strlen(MSG1), &written)) {
        printf("Unexpected success writing message 1\n");
        goto end;
    }

    if (SSL_read_early_data(serverssl, buf, sizeof(buf), &readbytes)
                != SSL_READ_EARLY_DATA_FINISH
            || readbytes != 0) {
        printf("Failed reading early data\n");
        goto end;
    }

    if (SSL_get_early_data_status(serverssl) != SSL_EARLY_DATA_NOT_SENT) {
        printf("Unexpected early data status\n");
        goto end;
    }

    /* Continue writing the message we started earlier */
    if (!SSL_write_ex(clientssl, MSG1, strlen(MSG1), &written)
            || written != strlen(MSG1)) {
        printf("Failed writing message 1\n");
        goto end;
    }

    if (SSL_get_early_data_status(clientssl) != SSL_EARLY_DATA_NOT_SENT) {
        printf("Unexpected early data status (2)\n");
        goto end;
    }

    if (!SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes)
            || readbytes != strlen(MSG1)
            || memcmp(MSG1, buf, strlen(MSG1))) {
        printf("Failed reading message 1\n");
        goto end;
    }

    if (!SSL_write_ex(serverssl, MSG2, strlen(MSG2), &written)
            || written != strlen(MSG2)) {
        printf("Failed writing message 2\n");
        goto end;
    }

    if (!SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes)
            || readbytes != strlen(MSG2)
            || memcmp(MSG2, buf, strlen(MSG2))) {
        printf("Failed reading message 2\n");
        goto end;
    }

    testresult = 1;

 end:
    if(!testresult)
        ERR_print_errors_fp(stdout);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
# endif
#endif

int test_main(int argc, char *argv[])
{
    int testresult = 1;

    if (argc != 3) {
        printf("Invalid argument count\n");
        return 1;
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
    ADD_TEST(test_early_data_read_write);
    ADD_TEST(test_early_data_skip);
    ADD_TEST(test_early_data_not_sent);
    ADD_TEST(test_early_data_not_expected);
# ifndef OPENSSL_NO_TLS1_2
    ADD_TEST(test_early_data_tls1_2);
# endif
#endif

    testresult = run_tests(argv[0]);

    bio_s_mempacket_test_free();

    return testresult;
}
