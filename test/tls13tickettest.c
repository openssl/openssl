/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include "helpers/ssltestlib.h"
#include "testutil.h"

struct stats {
    unsigned int tickets;
};

static char *cert = NULL;
static char *pkey = NULL;
static int stats_idx = -1;

static int stats_init(struct stats *stats)
{
    memset(stats, 0, sizeof(*stats));
    return 1;
}

static int sess_new_cb(SSL *ssl, SSL_SESSION *session)
{
    struct stats *stats = SSL_get_ex_data(ssl, stats_idx);
    if (stats == NULL)
        return 0;
    if (SSL_is_init_finished(ssl) == 0)
        stats->tickets++;
    return 0;
}

static void handshake_finished(const SSL *ssl)
{
    const char *endpoint = SSL_is_server(ssl) ? "server" : "client";
    if (SSL_session_reused(ssl))
        TEST_info("%s: Abbreviated handshake finished", endpoint);
    else
        TEST_info("%s: Full handshake finished", endpoint);
}

static void info_cb(const SSL *ssl, int type, int val)
{
    const char *endpoint = SSL_is_server(ssl) ? "server" : "client";

    if (type & SSL_CB_ALERT) {
        const char *dir = (type & SSL_CB_READ) ? "read" : "write";

        TEST_info("%s: alert %s: %s : %s", endpoint, dir,
            SSL_alert_type_string_long(val),
            SSL_alert_desc_string_long(val));
    }
    if (type & SSL_CB_HANDSHAKE_DONE)
        handshake_finished(ssl);
}

static int set_callbacks(SSL *ssl)
{
    SSL_set_info_callback(ssl, info_cb);
    return 1;
}

static int tlsv13_ctx_pair(SSL_CTX **s, SSL_CTX **c, char *crt, char *key)
{
    const SSL_METHOD *cm = TLS_client_method();
    const SSL_METHOD *sm = TLS_server_method();
    int test, v = TLS1_VERSION;

    test = TEST_true(create_ssl_ctx_pair(NULL, sm, cm, v, 0, s, c, crt, key))
        && TEST_true(SSL_CTX_set_min_proto_version(*s, TLS1_3_VERSION))
        && TEST_true(SSL_CTX_set_max_proto_version(*s, TLS1_3_VERSION))
        && TEST_true(SSL_CTX_set_min_proto_version(*c, TLS1_3_VERSION))
        && TEST_true(SSL_CTX_set_max_proto_version(*c, TLS1_3_VERSION));

    return test;
}

static int set_shutdown(SSL *c, SSL *s)
{
    SSL_set_shutdown(c, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_set_shutdown(s, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    return 1;
}

static int enable_tickets(SSL_CTX *s, SSL_CTX *c)
{
    unsigned int cf = SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE;
    unsigned int sf = SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL_STORE;

    SSL_CTX_set_session_cache_mode(s, sf);
    SSL_CTX_set_session_cache_mode(c, cf);
    SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);

    SSL_CTX_sess_set_new_cb(s, sess_new_cb);
    SSL_CTX_sess_set_new_cb(c, sess_new_cb);

    return 1;
}

/*
 * Verify ticket regeneration after fallback to a full handshake. If session
 * resumption fails due to a ciphersuite mismatch, it falls back to a full
 * handshake. In that case, ensure a new session ticket is issued reflecting the
 * negotiated ciphersuite.
 */
static int test_tls13_ticket_ciphersuite_mismatch(void)
{
    struct stats stats1, stats2;
    SSL_CTX *s_ctx = NULL, *c_ctx = NULL;
    SSL *s_ssl = NULL, *c_ssl = NULL, *s = NULL, *c = NULL;
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(tlsv13_ctx_pair(&s_ctx, &c_ctx, cert, pkey))
        && TEST_true(SSL_CTX_set_ciphersuites(s_ctx, "TLS_AES_128_GCM_SHA256"))
        && TEST_true(SSL_CTX_set_ciphersuites(c_ctx, "TLS_AES_128_GCM_SHA256"))
        && TEST_true(enable_tickets(s_ctx, c_ctx))
        && TEST_true(create_ssl_objects(s_ctx, c_ctx, &s, &c, NULL, NULL))
        && TEST_true(set_callbacks(c))
        && TEST_true(set_callbacks(s))
        && TEST_true(stats_init(&stats1))
        && TEST_true(SSL_set_ex_data(c, stats_idx, &stats1))
        && TEST_true(create_ssl_connection(s, c, SSL_ERROR_NONE))
        && TEST_uint_eq(stats1.tickets, 2)
        && TEST_true(set_shutdown(c, s))
        && TEST_ptr(sess = SSL_get1_session(c))
        && TEST_true(SSL_CTX_set_ciphersuites(s_ctx, "TLS_AES_256_GCM_SHA384"))
        && TEST_true(SSL_CTX_set_ciphersuites(c_ctx, "TLS_AES_256_GCM_SHA384"))
        && TEST_true(create_ssl_objects(s_ctx, c_ctx, &s_ssl, &c_ssl, NULL, NULL))
        && TEST_true(SSL_set_session(c_ssl, sess))
        && TEST_true(set_callbacks(c_ssl))
        && TEST_true(set_callbacks(s_ssl))
        && TEST_true(stats_init(&stats2))
        && TEST_true(SSL_set_ex_data(c_ssl, stats_idx, &stats2))
        && TEST_true(create_ssl_connection(s_ssl, c_ssl, SSL_ERROR_NONE))
        && TEST_false(SSL_session_reused(c_ssl))
        && TEST_uint_eq(stats2.tickets, 2);

    SSL_SESSION_free(sess);
    SSL_free(s_ssl);
    SSL_free(c_ssl);
    SSL_free(s);
    SSL_free(c);
    SSL_CTX_free(s_ctx);
    SSL_CTX_free(c_ctx);
    return test;
}

OPT_TEST_DECLARE_USAGE("\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(pkey = test_get_argument(1)))
        return 0;

    stats_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    ADD_TEST(test_tls13_ticket_ciphersuite_mismatch);

    return 1;
}
