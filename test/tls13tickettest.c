/*
 * Copyright 2017-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/tls1.h>
#include "helpers/ssltestlib.h"
#include "testutil.h"

struct stats {
    unsigned int tickets;
    unsigned int nst_msgs;
    unsigned int ch_has_psk;
    unsigned int ch_has_psk_kex_modes;
    unsigned int ch_has_session_ticket;
    unsigned int sh_has_psk;
    unsigned int sh_has_supported_versions;
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

static int has_extension(const unsigned char *ex, size_t len, unsigned int type)
{
    while (len >= 4) {
        size_t elen = (ex[2] << 8) | ex[3];

        if (len < 4 + elen)
            break;
        if (((ex[0] << 8) | ex[1]) == type)
            return 1;
        ex += 4 + elen;
        len -= 4 + elen;
    }
    return 0;
}

static void parse_server_hello_exts(const unsigned char *buf, size_t len,
    struct stats *stats)
{
    size_t off = 4, sid_len, ext_len;

    if (len < off + 2 + 32 + 1)
        return;
    off += 2 + 32;
    sid_len = buf[off];
    off += 1 + sid_len;
    if (len < off + 2 + 1)
        return;
    off += 2 + 1;
    if (len < off + 2)
        return;
    ext_len = (buf[off] << 8) | buf[off + 1];
    off += 2;
    if (len < off + ext_len)
        return;

    stats->sh_has_psk = has_extension(buf + off, ext_len, TLSEXT_TYPE_psk);
    stats->sh_has_supported_versions = has_extension(buf + off, ext_len,
        TLSEXT_TYPE_supported_versions);

    TEST_info("ServerHello extensions: psk=%d supported_versions=%d",
        stats->sh_has_psk, stats->sh_has_supported_versions);
}

static void msg_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    const char *endpoint = SSL_is_server(ssl) ? "server" : "client";
    const char *dir = write_p ? "sent" : "received";
    struct stats *stats = SSL_get_ex_data(ssl, stats_idx);

    if (content_type == SSL3_RT_HANDSHAKE && len > 0) {
        unsigned char mt = ((const unsigned char *)buf)[0];

        if (mt == SSL3_MT_NEWSESSION_TICKET) {
            TEST_info("%s: %s NewSessionTicket", endpoint, dir);
            if (stats != NULL)
                stats->nst_msgs++;
        }
        if (mt == SSL3_MT_SERVER_HELLO && stats != NULL)
            parse_server_hello_exts(buf, len, stats);
    }
}

static int client_hello_cb(SSL *ssl, int *al, void *arg)
{
    struct stats *stats = (struct stats *)arg;
    const unsigned char *data;
    size_t len;

    stats->ch_has_psk = SSL_client_hello_get0_ext(
        ssl, TLSEXT_TYPE_psk, &data, &len);
    stats->ch_has_psk_kex_modes = SSL_client_hello_get0_ext(
        ssl, TLSEXT_TYPE_psk_kex_modes, &data, &len);
    stats->ch_has_session_ticket = SSL_client_hello_get0_ext(
        ssl, TLSEXT_TYPE_session_ticket, &data, &len);

    TEST_info("CH extensions: psk=%d psk_kex_modes=%d session_ticket=%d",
        stats->ch_has_psk, stats->ch_has_psk_kex_modes,
        stats->ch_has_session_ticket);

    return SSL_CLIENT_HELLO_SUCCESS;
}

static int set_callbacks(SSL *ssl)
{
    SSL_set_info_callback(ssl, info_cb);
    SSL_set_msg_callback(ssl, msg_cb);
    return 1;
}

static int enforce_tls13(SSL_CTX *s, SSL_CTX *c)
{
    int test;
    test = TEST_true(SSL_CTX_set_min_proto_version(s, TLS1_3_VERSION))
        && TEST_true(SSL_CTX_set_max_proto_version(s, TLS1_3_VERSION))
        && TEST_true(SSL_CTX_set_min_proto_version(c, TLS1_3_VERSION))
        && TEST_true(SSL_CTX_set_max_proto_version(c, TLS1_3_VERSION));

    return test;
}

static int set_shutdown(SSL *c, SSL *s)
{
    SSL_set_shutdown(c, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_set_shutdown(s, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    return 1;
}

int tlsv13_ctx_pair(SSL_CTX **sctx, SSL_CTX **cctx, char *cert, char *pkey)
{
    int test;
    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
              TLS1_VERSION, 0, sctx, cctx, cert, pkey));

    return test;
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

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
               TLS_client_method(), TLS1_VERSION, 0, &s_ctx, &c_ctx, cert, pkey))
        && TEST_true(enforce_tls13(s_ctx, c_ctx))
        && TEST_true(SSL_CTX_set_ciphersuites(s_ctx, "TLS_AES_128_GCM_SHA256"))
        && TEST_true(SSL_CTX_set_ciphersuites(c_ctx, "TLS_AES_128_GCM_SHA256"))
        && TEST_true(enable_tickets(s_ctx, c_ctx))
        && TEST_true(create_ssl_objects(s_ctx, c_ctx, &s, &c, NULL, NULL))
        && TEST_true(set_callbacks(c))
        && TEST_true(set_callbacks(s))
        && TEST_true(stats_init(&stats1))
        && TEST_true(SSL_set_ex_data(c, stats_idx, &stats1))
        && TEST_true(create_ssl_connection(s, c, SSL_ERROR_NONE))
        && TEST_uint_ge(stats1.tickets, 1)
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
        && TEST_uint_ge(stats2.tickets, 1);

    SSL_SESSION_free(sess);
    SSL_free(s_ssl);
    SSL_free(c_ssl);
    SSL_free(s);
    SSL_free(c);
    SSL_CTX_free(s_ctx);
    SSL_CTX_free(c_ctx);
    return test;
}

static int server_disable_tickets(SSL_CTX *s)
{
    SSL_CTX_set_options(s, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(s, SSL_SESS_CACHE_OFF);
    return 1;
}

static int client_enable_tickets(SSL_CTX *c)
{
    SSL_CTX_set_session_cache_mode(c,
        SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(c, sess_new_cb);
    return 1;
}

static int client_disable_tickets(SSL_CTX *c)
{
    SSL_CTX_set_options(c, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(c, SSL_SESS_CACHE_OFF);
    return 1;
}

/*
 * Do not issue TLSv1.3 session tickets if the server has explicitly disabled
 * them via SSL_OP_NO_TICKET and also turned off the session cache with
 * SSL_SESS_CACHE_OFF. Both conditions together indicate a clear intent to
 * suppress resumption, so sending NewSessionTicket messages would be
 * wasteful and misleading.
 */
static int test_tls13_ticket_disable_server(void)
{
    struct stats c_stats, s_stats;
    SSL_CTX *s_ctx = NULL, *c_ctx = NULL;
    SSL *s = NULL, *c = NULL;
    int test;

    stats_init(&c_stats);
    stats_init(&s_stats);

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
               TLS_client_method(), TLS1_VERSION, 0, &s_ctx, &c_ctx, cert, pkey))
        && TEST_true(enforce_tls13(s_ctx, c_ctx))
        && TEST_true(server_disable_tickets(s_ctx))
        && TEST_true(client_enable_tickets(c_ctx));

    if (test)
        SSL_CTX_set_client_hello_cb(s_ctx, client_hello_cb, &s_stats);

    test = test
        && TEST_true(create_ssl_objects(s_ctx, c_ctx, &s, &c, NULL, NULL))
        && TEST_true(set_callbacks(c))
        && TEST_true(set_callbacks(s))
        && TEST_true(SSL_set_ex_data(c, stats_idx, &c_stats))
        && TEST_true(SSL_set_ex_data(s, stats_idx, &s_stats))
        && TEST_true(create_ssl_connection(s, c, SSL_ERROR_NONE))
        && TEST_true(set_shutdown(c, s))
        && TEST_int_eq(s_stats.nst_msgs, 0)
        && TEST_int_eq(c_stats.nst_msgs, 0);

    SSL_free(s);
    SSL_free(c);
    SSL_CTX_free(s_ctx);
    SSL_CTX_free(c_ctx);

    return test;
}

/*
 * Do not request or accept TLSv1.3 session tickets if the client has set
 * both SSL_OP_NO_TICKET and SSL_SESS_CACHE_OFF. When both are set, the
 * client has no session cache to store tickets in and no intention to
 * resume.
 *
 * Signal zero ticket desire to the server using the ticket_request extension
 * [RFC-9149] if supported.
 */
static int test_tls13_ticket_disable_client(void)
{
    struct stats c_stats, s_stats;
    SSL_CTX *s_ctx = NULL, *c_ctx = NULL;
    SSL *s = NULL, *c = NULL;
    int test;

    stats_init(&c_stats);
    stats_init(&s_stats);

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
               TLS_client_method(), TLS1_VERSION, 0, &s_ctx, &c_ctx, cert, pkey))
        && TEST_true(enforce_tls13(s_ctx, c_ctx))
        && TEST_true(client_disable_tickets(c_ctx));

    if (test)
        SSL_CTX_set_client_hello_cb(s_ctx, client_hello_cb, &s_stats);

    test = test
        && TEST_true(create_ssl_objects(s_ctx, c_ctx, &s, &c, NULL, NULL))
        && TEST_true(set_callbacks(c))
        && TEST_true(set_callbacks(s))
        && TEST_true(SSL_set_ex_data(c, stats_idx, &c_stats))
        && TEST_true(SSL_set_ex_data(s, stats_idx, &s_stats))
        && TEST_true(create_ssl_connection(s, c, SSL_ERROR_NONE))
        && TEST_true(set_shutdown(c, s))
        /* Server still sends tickets, no client-side suppression yet */
        && TEST_int_ge(s_stats.nst_msgs, 1)
        && TEST_int_ge(c_stats.nst_msgs, 1);

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
    ADD_TEST(test_tls13_ticket_disable_server);
    ADD_TEST(test_tls13_ticket_disable_client);

    return 1;
}

void cleanup_tests(void)
{
}
