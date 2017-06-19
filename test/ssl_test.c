/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "handshake_helper.h"
#include "ssl_test_ctx.h"
#include "testutil.h"

static CONF *conf = NULL;

/* Currently the section names are of the form test-<number>, e.g. test-15. */
#define MAX_TESTCASE_NAME_LENGTH 100

static const char *print_alert(int alert)
{
    return alert ? SSL_alert_desc_string_long(alert) : "no alert";
}

static int check_result(HANDSHAKE_RESULT *result, SSL_TEST_CTX *test_ctx)
{
    if (!TEST_int_eq(result->result, test_ctx->expected_result)) {
        TEST_info("ExpectedResult mismatch: expected %s, got %s.",
                  ssl_test_result_name(test_ctx->expected_result),
                  ssl_test_result_name(result->result));
        return 0;
    }
    return 1;
}

static int check_alerts(HANDSHAKE_RESULT *result, SSL_TEST_CTX *test_ctx)
{
    if (!TEST_int_eq(result->client_alert_sent,
                     result->client_alert_received)) {
        TEST_info("Client sent alert %s but server received %s.",
                  print_alert(result->client_alert_sent),
                  print_alert(result->client_alert_received));
        /*
         * We can't bail here because the peer doesn't always get far enough
         * to process a received alert. Specifically, in protocol version
         * negotiation tests, we have the following scenario.
         * Client supports TLS v1.2 only; Server supports TLS v1.1.
         * Client proposes TLS v1.2; server responds with 1.1;
         * Client now sends a protocol alert, using TLS v1.2 in the header.
         * The server, however, rejects the alert because of version mismatch
         * in the record layer; therefore, the server appears to never
         * receive the alert.
         */
        /* return 0; */
    }

    if (!TEST_int_eq(result->server_alert_sent,
                     result->server_alert_received)) {
        TEST_info("Server sent alert %s but client received %s.",
                  print_alert(result->server_alert_sent),
                  print_alert(result->server_alert_received));
        /* return 0; */
    }

    /* Tolerate an alert if one wasn't explicitly specified in the test. */
    if (test_ctx->expected_client_alert
        /*
         * The info callback alert value is computed as
         * (s->s3->send_alert[0] << 8) | s->s3->send_alert[1]
         * where the low byte is the alert code and the high byte is other stuff.
         */
        && (result->client_alert_sent & 0xff) != test_ctx->expected_client_alert) {
        TEST_error("ClientAlert mismatch: expected %s, got %s.",
                   print_alert(test_ctx->expected_client_alert),
                   print_alert(result->client_alert_sent));
        return 0;
    }

    if (test_ctx->expected_server_alert
        && (result->server_alert_sent & 0xff) != test_ctx->expected_server_alert) {
        TEST_error("ServerAlert mismatch: expected %s, got %s.",
                   print_alert(test_ctx->expected_server_alert),
                   print_alert(result->server_alert_sent));
        return 0;
    }

    if (!TEST_int_le(result->client_num_fatal_alerts_sent, 1))
        return 0;
    if (!TEST_int_le(result->server_num_fatal_alerts_sent, 1))
        return 0;
    return 1;
}

static int check_protocol(HANDSHAKE_RESULT *result, SSL_TEST_CTX *test_ctx)
{
    if (!TEST_int_eq(result->client_protocol, result->server_protocol)) {
        TEST_info("Client has protocol %s but server has %s.",
                  ssl_protocol_name(result->client_protocol),
                  ssl_protocol_name(result->server_protocol));
        return 0;
    }

    if (test_ctx->expected_protocol) {
        if (!TEST_int_eq(result->client_protocol,
                         test_ctx->expected_protocol)) {
            TEST_info("Protocol mismatch: expected %s, got %s.\n",
                      ssl_protocol_name(test_ctx->expected_protocol),
                      ssl_protocol_name(result->client_protocol));
            return 0;
        }
    }
    return 1;
}

static int check_servername(HANDSHAKE_RESULT *result, SSL_TEST_CTX *test_ctx)
{
    if (!TEST_int_eq(result->servername, test_ctx->expected_servername)) {
      TEST_info("Client ServerName mismatch, expected %s, got %s.",
                ssl_servername_name(test_ctx->expected_servername),
                ssl_servername_name(result->servername));
      return 0;
    }
  return 1;
}

static int check_session_ticket(HANDSHAKE_RESULT *result, SSL_TEST_CTX *test_ctx)
{
    if (test_ctx->session_ticket_expected == SSL_TEST_SESSION_TICKET_IGNORE)
        return 1;
    if (!TEST_int_eq(result->session_ticket,
                     test_ctx->session_ticket_expected)) {
        TEST_info("Client SessionTicketExpected mismatch, expected %s, got %s.",
                  ssl_session_ticket_name(test_ctx->session_ticket_expected),
                  ssl_session_ticket_name(result->session_ticket));
        return 0;
    }
    return 1;
}

static int check_compression(HANDSHAKE_RESULT *result, SSL_TEST_CTX *test_ctx)
{
    if (!TEST_int_eq(result->compression, test_ctx->compression_expected))
        return 0;
    return 1;
}
#ifndef OPENSSL_NO_NEXTPROTONEG
static int check_npn(HANDSHAKE_RESULT *result, SSL_TEST_CTX *test_ctx)
{
    int ret = 1;
    if (!TEST_str_eq(result->client_npn_negotiated,
                     result->server_npn_negotiated))
        ret = 0;
    if (!TEST_str_eq(test_ctx->expected_npn_protocol,
                     result->client_npn_negotiated))
        ret = 0;
    return ret;
}
#endif

static int check_alpn(HANDSHAKE_RESULT *result, SSL_TEST_CTX *test_ctx)
{
    int ret = 1;
    if (!TEST_str_eq(result->client_alpn_negotiated,
                     result->server_alpn_negotiated))
        ret = 0;
    if (!TEST_str_eq(test_ctx->expected_alpn_protocol,
                     result->client_alpn_negotiated))
        ret = 0;
    return ret;
}

static int check_resumption(HANDSHAKE_RESULT *result, SSL_TEST_CTX *test_ctx)
{
    if (!TEST_int_eq(result->client_resumed, result->server_resumed))
        return 0;
    if (!TEST_int_eq(result->client_resumed, test_ctx->resumption_expected))
        return 0;
    return 1;
}

static int check_nid(const char *name, int expected_nid, int nid)
{
    if (expected_nid == 0 || expected_nid == nid)
        return 1;
    TEST_error("%s type mismatch, %s vs %s\n",
               name, OBJ_nid2ln(expected_nid),
               nid == NID_undef ? "absent" : OBJ_nid2ln(nid));
    return 0;
}

static void print_ca_names(STACK_OF(X509_NAME) *names)
{
    int i;

    if (names == NULL || sk_X509_NAME_num(names) == 0) {
        TEST_note("    <empty>");
        return;
    }
    for (i = 0; i < sk_X509_NAME_num(names); i++) {
        X509_NAME_print_ex(bio_err, sk_X509_NAME_value(names, i), 4,
                           XN_FLAG_ONELINE);
        BIO_puts(bio_err, "\n");
    }
}

static int check_ca_names(const char *name,
                          STACK_OF(X509_NAME) *expected_names,
                          STACK_OF(X509_NAME) *names)
{
    int i;

    if (expected_names == NULL)
        return 1;
    if (names == NULL || sk_X509_NAME_num(names) == 0) {
        if (TEST_int_eq(sk_X509_NAME_num(expected_names), 0))
            return 1;
        goto err;
    }
    if (sk_X509_NAME_num(names) != sk_X509_NAME_num(expected_names))
        goto err;
    for (i = 0; i < sk_X509_NAME_num(names); i++) {
        if (!TEST_int_eq(X509_NAME_cmp(sk_X509_NAME_value(names, i),
                                       sk_X509_NAME_value(expected_names, i)),
                         0)) {
            goto err;
        }
    }
    return 1;
err:
    TEST_info("%s: list mismatch", name);
    TEST_note("Expected Names:");
    print_ca_names(expected_names);
    TEST_note("Received Names:");
    print_ca_names(names);
    return 0;
}

static int check_tmp_key(HANDSHAKE_RESULT *result, SSL_TEST_CTX *test_ctx)
{
    return check_nid("Tmp key", test_ctx->expected_tmp_key_type,
                     result->tmp_key_type);
}

static int check_server_cert_type(HANDSHAKE_RESULT *result,
                                  SSL_TEST_CTX *test_ctx)
{
    return check_nid("Server certificate", test_ctx->expected_server_cert_type,
                     result->server_cert_type);
}

static int check_server_sign_hash(HANDSHAKE_RESULT *result,
                                  SSL_TEST_CTX *test_ctx)
{
    return check_nid("Server signing hash", test_ctx->expected_server_sign_hash,
                     result->server_sign_hash);
}

static int check_server_sign_type(HANDSHAKE_RESULT *result,
                                  SSL_TEST_CTX *test_ctx)
{
    return check_nid("Server signing", test_ctx->expected_server_sign_type,
                     result->server_sign_type);
}

static int check_server_ca_names(HANDSHAKE_RESULT *result,
                                 SSL_TEST_CTX *test_ctx)
{
    return check_ca_names("Server CA names",
                          test_ctx->expected_server_ca_names,
                          result->server_ca_names);
}

static int check_client_cert_type(HANDSHAKE_RESULT *result,
                                  SSL_TEST_CTX *test_ctx)
{
    return check_nid("Client certificate", test_ctx->expected_client_cert_type,
                     result->client_cert_type);
}

static int check_client_sign_hash(HANDSHAKE_RESULT *result,
                                  SSL_TEST_CTX *test_ctx)
{
    return check_nid("Client signing hash", test_ctx->expected_client_sign_hash,
                     result->client_sign_hash);
}

static int check_client_sign_type(HANDSHAKE_RESULT *result,
                                  SSL_TEST_CTX *test_ctx)
{
    return check_nid("Client signing", test_ctx->expected_client_sign_type,
                     result->client_sign_type);
}

static int check_client_ca_names(HANDSHAKE_RESULT *result,
                                 SSL_TEST_CTX *test_ctx)
{
    return check_ca_names("Client CA names",
                          test_ctx->expected_client_ca_names,
                          result->client_ca_names);
}

/*
 * This could be further simplified by constructing an expected
 * HANDSHAKE_RESULT, and implementing comparison methods for
 * its fields.
 */
static int check_test(HANDSHAKE_RESULT *result, SSL_TEST_CTX *test_ctx)
{
    int ret = 1;
    ret &= check_result(result, test_ctx);
    ret &= check_alerts(result, test_ctx);
    if (result->result == SSL_TEST_SUCCESS) {
        ret &= check_protocol(result, test_ctx);
        ret &= check_servername(result, test_ctx);
        ret &= check_session_ticket(result, test_ctx);
        ret &= check_compression(result, test_ctx);
        ret &= (result->session_ticket_do_not_call == 0);
#ifndef OPENSSL_NO_NEXTPROTONEG
        ret &= check_npn(result, test_ctx);
#endif
        ret &= check_alpn(result, test_ctx);
        ret &= check_resumption(result, test_ctx);
        ret &= check_tmp_key(result, test_ctx);
        ret &= check_server_cert_type(result, test_ctx);
        ret &= check_server_sign_hash(result, test_ctx);
        ret &= check_server_sign_type(result, test_ctx);
        ret &= check_server_ca_names(result, test_ctx);
        ret &= check_client_cert_type(result, test_ctx);
        ret &= check_client_sign_hash(result, test_ctx);
        ret &= check_client_sign_type(result, test_ctx);
        ret &= check_client_ca_names(result, test_ctx);
    }
    return ret;
}

static int test_handshake(int idx)
{
    int ret = 0;
    SSL_CTX *server_ctx = NULL, *server2_ctx = NULL, *client_ctx = NULL,
        *resume_server_ctx = NULL, *resume_client_ctx = NULL;
    SSL_TEST_CTX *test_ctx = NULL;
    HANDSHAKE_RESULT *result = NULL;
    char test_app[MAX_TESTCASE_NAME_LENGTH];

    BIO_snprintf(test_app, sizeof(test_app), "test-%d", idx);

    test_ctx = SSL_TEST_CTX_create(conf, test_app);
    if (!TEST_ptr(test_ctx))
        goto err;

#ifndef OPENSSL_NO_DTLS
    if (test_ctx->method == SSL_TEST_METHOD_DTLS) {
        server_ctx = SSL_CTX_new(DTLS_server_method());
        if (test_ctx->extra.server.servername_callback !=
            SSL_TEST_SERVERNAME_CB_NONE) {
            server2_ctx = SSL_CTX_new(DTLS_server_method());
            TEST_check(server2_ctx != NULL);
        }
        client_ctx = SSL_CTX_new(DTLS_client_method());
        if (test_ctx->handshake_mode == SSL_TEST_HANDSHAKE_RESUME) {
            resume_server_ctx = SSL_CTX_new(DTLS_server_method());
            resume_client_ctx = SSL_CTX_new(DTLS_client_method());
            TEST_check(resume_server_ctx != NULL);
            TEST_check(resume_client_ctx != NULL);
        }
    }
#endif
    if (test_ctx->method == SSL_TEST_METHOD_TLS) {
        server_ctx = SSL_CTX_new(TLS_server_method());
        /* SNI on resumption isn't supported/tested yet. */
        if (test_ctx->extra.server.servername_callback !=
            SSL_TEST_SERVERNAME_CB_NONE) {
            server2_ctx = SSL_CTX_new(TLS_server_method());
            TEST_check(server2_ctx != NULL);
        }
        client_ctx = SSL_CTX_new(TLS_client_method());

        if (test_ctx->handshake_mode == SSL_TEST_HANDSHAKE_RESUME) {
            resume_server_ctx = SSL_CTX_new(TLS_server_method());
            resume_client_ctx = SSL_CTX_new(TLS_client_method());
            TEST_check(resume_server_ctx != NULL);
            TEST_check(resume_client_ctx != NULL);
        }
    }

    TEST_check(server_ctx != NULL);
    TEST_check(client_ctx != NULL);

    TEST_check(CONF_modules_load(conf, test_app, 0) > 0);

    if (!SSL_CTX_config(server_ctx, "server")
        || !SSL_CTX_config(client_ctx, "client")) {
        goto err;
    }

    if (server2_ctx != NULL && !SSL_CTX_config(server2_ctx, "server2"))
        goto err;
    if (resume_server_ctx != NULL
        && !SSL_CTX_config(resume_server_ctx, "resume-server"))
        goto err;
    if (resume_client_ctx != NULL
        && !SSL_CTX_config(resume_client_ctx, "resume-client"))
        goto err;

    result = do_handshake(server_ctx, server2_ctx, client_ctx,
                          resume_server_ctx, resume_client_ctx, test_ctx);

    ret = check_test(result, test_ctx);

err:
    CONF_modules_unload(0);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(server2_ctx);
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(resume_server_ctx);
    SSL_CTX_free(resume_client_ctx);
    SSL_TEST_CTX_free(test_ctx);
    HANDSHAKE_RESULT_free(result);
    return ret;
}

int test_main(int argc, char **argv)
{
    int result = 0;
    long num_tests;

    if (argc != 2)
        return 1;

    conf = NCONF_new(NULL);
    TEST_check(conf != NULL);

    /* argv[1] should point to the test conf file */
    TEST_check(NCONF_load(conf, argv[1], NULL) > 0);

    TEST_check(NCONF_get_number_e(conf, NULL, "num_tests", &num_tests));

    ADD_ALL_TESTS(test_handshake, (int)(num_tests));
    result = run_tests(argv[0]);

    NCONF_free(conf);
    return result;
}
