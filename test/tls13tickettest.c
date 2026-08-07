/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/tls1.h>
#include "ssl/ssl_local.h"
#include "internal/packet.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"

/*
 * Do not issue TLS 1.3 session tickets if the server has explicitly disabled
 * them via SSL_OP_NO_TICKET and also disabled the session cache with
 * SSL_SESS_CACHE_OFF. Together, these settings clearly indicate an intent to
 * suppress session resumption; sending NewSessionTicket messages in this case
 * would be wasteful and misleading.
 *
 * From the server’s perspective, a client that does not advertise
 * psk_key_exchange_modes in TLS 1.3, or that sends it with RFC 9149 parameters
 * such as new_session_count = 0 or resumption_count = 0, is effectively
 * signaling no interest in session tickets or resumption.
 *
 * RFC 8446 section 4.2.9: Servers MUST NOT select a key exchange mode that is
 * not listed by the client. This extension also restricts the modes for use
 * with PSK resumption. Servers SHOULD NOT send NewSessionTicket with tickets
 * that are not compatible with the advertised modes; however, if a server does
 * so, the impact will just be that the client's attempts at resumption fail.
 *
 * In other words, if psk_key_exchange_modes is missing or the server doesn't
 * recognize any of the client's advertised modes, this effectively disables
 * both resumption and ticket issuance, since the server has no valid mode the
 * client understands. In TLS 1.3 terms, omitting this extension is essentially
 * a signal that the client has no interest in tickets and resumption.
 */

#ifndef CLIENT_VERSION_LEN
/*
 * This is the legacy version length, i.e. len(0x0303). The same
 * label is used in e.g. test/sslapitest.c and elsewhere but not
 * defined in a header file I could find.
 */
#define CLIENT_VERSION_LEN 2
#endif

#define TICKET_KEYS_LENGTH (TLSEXT_KEYNAME_LENGTH + (2 * TLSEXT_TICK_KEY_LENGTH))

struct stats {
    unsigned int tickets;
    unsigned int nst_msgs;
    unsigned int ch_has_psk;
    unsigned int ch_has_psk_kex_modes;
    unsigned int ch_has_session_ticket;
    unsigned int sh_has_psk;
    unsigned int sh_has_supported_versions;
};

struct tls13_endpoint {
    SSL *ssl;
    struct stats stats;
};

struct tls13_channel {
    struct tls13_endpoint c, s;
};

static char *cert = NULL;
static char *pkey = NULL;
static int stats_idx = -1;

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

static void parse_ch_exts(const unsigned char *buf, size_t len, struct stats *x)
{
    PACKET pkt, e, ex;
    unsigned int v;

    if (!PACKET_buf_init(&pkt, buf, len)
        || !PACKET_forward(&pkt, 4 + 2 + 32)
        || !PACKET_get_1(&pkt, &v)
        || !PACKET_forward(&pkt, v)
        || !PACKET_get_net_2(&pkt, &v)
        || !PACKET_forward(&pkt, v)
        || !PACKET_get_1(&pkt, &v)
        || !PACKET_forward(&pkt, v)
        || !PACKET_as_length_prefixed_2(&pkt, &e))
        return;

    while (PACKET_remaining(&e) > 0) {
        if (!PACKET_get_net_2(&e, &v) || !PACKET_get_length_prefixed_2(&e, &ex))
            return;
        switch (v) {
        case TLSEXT_TYPE_psk:
            x->ch_has_psk = 1;
            break;
        case TLSEXT_TYPE_psk_kex_modes:
            x->ch_has_psk_kex_modes = 1;
            break;
        case TLSEXT_TYPE_session_ticket:
            x->ch_has_session_ticket = 1;
            break;
        }
    }
    TEST_info("ch extensions: psk=%d psk_kex_modes=%d session_ticket=%d",
        x->ch_has_psk, x->ch_has_psk_kex_modes, x->ch_has_session_ticket);
}

static void parse_sh_exts(const unsigned char *buf, size_t len, struct stats *x)
{
    PACKET pkt, e, ex;
    unsigned int v;

    if (!PACKET_buf_init(&pkt, buf, len)
        || !PACKET_forward(&pkt, 4 + 2 + 32)
        || !PACKET_get_1(&pkt, &v)
        || !PACKET_forward(&pkt, v + 2 + 1)
        || !PACKET_as_length_prefixed_2(&pkt, &e))
        return;

    while (PACKET_remaining(&e) > 0) {
        if (!PACKET_get_net_2(&e, &v) || !PACKET_get_length_prefixed_2(&e, &ex))
            return;
        switch (v) {
        case TLSEXT_TYPE_psk:
            x->sh_has_psk = 1;
            break;
        case TLSEXT_TYPE_supported_versions:
            x->sh_has_supported_versions = 1;
            break;
        }
    }
    TEST_info("sh extensions: psk=%d supported_versions=%d",
        x->sh_has_psk, x->sh_has_supported_versions);
}

static void msg_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    struct stats *stats = SSL_get_ex_data(ssl, stats_idx);

    if (content_type == SSL3_RT_HANDSHAKE && len > 0) {
        unsigned char mt = ((const unsigned char *)buf)[0];

        if (mt == SSL3_MT_NEWSESSION_TICKET && stats != NULL)
            stats->nst_msgs++;
        if (mt == SSL3_MT_CLIENT_HELLO && stats != NULL)
            parse_ch_exts(buf, len, stats);
        if (mt == SSL3_MT_SERVER_HELLO && stats != NULL)
            parse_sh_exts(buf, len, stats);
    }
}

static int set_ctx_callbacks(SSL_CTX *c, SSL_CTX *s)
{
    SSL_CTX_sess_set_new_cb(s, sess_new_cb);
    SSL_CTX_sess_set_new_cb(c, sess_new_cb);
    SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);
    return 1;
}

static int tls_channel_init(SSL_CTX *c_ctx, SSL_CTX *s_ctx, struct tls13_channel *ch)
{
    SSL *c = NULL, *s = NULL;
    int test;

    memset(ch, 0, sizeof(*ch));

    test = TEST_true(create_ssl_objects(s_ctx, c_ctx, &s, &c, NULL, NULL))
        && TEST_true(SSL_set_ex_data(c, stats_idx, &ch->c.stats))
        && TEST_true(SSL_set_ex_data(s, stats_idx, &ch->s.stats));

    if (test != 0) {
        SSL_set_info_callback(c, info_cb);
        SSL_set_msg_callback(c, msg_cb);
        SSL_set_info_callback(s, info_cb);
        SSL_set_msg_callback(s, msg_cb);
        ch->c.ssl = c;
        ch->s.ssl = s;
    }
    return test;
}

static void tls_channel_fini(struct tls13_channel *ch)
{
    SSL_free(ch->c.ssl);
    SSL_free(ch->s.ssl);
}

static int tls_shutdown(struct tls13_channel *ch)
{
    SSL_set_shutdown(ch->c.ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_set_shutdown(ch->s.ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    return 1;
}

static int ticket_enable(SSL_CTX *ctx)
{
    unsigned flags = SSL_SESS_CACHE_NO_INTERNAL_STORE;
    if (SSL_CTX_is_server(ctx))
        flags |= SSL_SESS_CACHE_SERVER;
    else
        flags |= SSL_SESS_CACHE_CLIENT;

    SSL_CTX_set_session_cache_mode(ctx, flags);
    return 1;
}

static int ticket_disable(SSL_CTX *ctx)
{
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    return 1;
}

/*
 * RFC 5077 3.1: The server sends an empty SessionTicket extension to indicate
 * that it will send a new session ticket using the NewSessionTicket handshake
 * message.
 */

static int test_tls12_ticket_enable(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_2_VERSION, TLS1_2_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 1)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 1)
        && TEST_uint_eq(initial.c.stats.tickets, 1)
        && TEST_uint_eq(initial.s.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.sh_has_supported_versions, 0)
        && TEST_uint_eq(initial.s.stats.sh_has_supported_versions, 0)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_true(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(resumed.c.stats.sh_has_supported_versions, 0)
        && TEST_uint_eq(resumed.s.stats.sh_has_supported_versions, 0);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

static int test_tls12_ticket_disable_server(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_2_VERSION, TLS1_2_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_disable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(initial.c.stats.sh_has_supported_versions, 0)
        && TEST_uint_eq(initial.s.stats.sh_has_supported_versions, 0);

    tls_channel_fini(&initial);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * Verify ticket regeneration after fallback to a full handshake. If session
 * resumption fails due to a ciphersuite mismatch, it falls back to a full
 * handshake. In that case, ensure a new session ticket is issued reflecting the
 * negotiated ciphersuite.
 */
static int test_tls13_ticket_ciphersuite_mismatch(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(SSL_CTX_set_ciphersuites(s, "TLS_AES_128_GCM_SHA256"))
        && TEST_true(SSL_CTX_set_ciphersuites(c, "TLS_AES_128_GCM_SHA256"))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_uint_ge(initial.c.stats.tickets, 1)
        && TEST_true(tls_shutdown(&initial))
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(SSL_CTX_set_ciphersuites(s, "TLS_AES_256_GCM_SHA384"))
        && TEST_true(SSL_CTX_set_ciphersuites(c, "TLS_AES_256_GCM_SHA384"))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_false(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.s.stats.tickets, 2)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * The session_ticket extension (#35) is still present in the ClientHello for
 * channels where both min and max protocol version are TLS 1.3. This is
 * unexpected given that session_ticket (#35) is defined as
 * TLS1_2_AND_BELOW_ONLY in OpenSSL, and therefore should not appear in a
 * strictly TLS 1.3 handshake.
 */

static int test_tls13_ticket_enable(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.c.stats.tickets, 2)
        && TEST_uint_eq(initial.s.stats.tickets, 2)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_true(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 1)
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 1)
        && TEST_uint_eq(resumed.c.stats.tickets, 1)
        && TEST_uint_eq(resumed.s.stats.tickets, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(resumed.s.stats.sh_has_supported_versions, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * If num_tickets is set to 0, then no tickets will be issued for either
 * a full (initial) connection or a resumed session.
 */
static int test_tls13_ticket_initial_set_num_tickets_zero(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(SSL_CTX_set_num_tickets(s, 0))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_false(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(resumed.s.stats.sh_has_supported_versions, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

static int test_tls13_ticket_resumed_set_num_tickets_zero(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.c.stats.tickets, 2)
        && TEST_uint_eq(initial.s.stats.tickets, 2)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(SSL_CTX_set_num_tickets(s, 0))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_true(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(resumed.s.stats.sh_has_supported_versions, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
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
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_disable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(initial.s.stats.sh_has_supported_versions, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_false(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(resumed.s.stats.sh_has_supported_versions, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * Exercise the SSL_TICKET_NO_DECRYPT path in tls_parse_ctos_psk().
 *
 * Rotate ticket keys so that the previously issued ticket can no longer be
 * decrypted. If session resumption fails due to a NO_DECRYPT, it falls back to
 * a full handshake. In that case, ensure a new session ticket is issued.
 */
static int test_tls13_ticket_no_decrypt(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    unsigned char k1[TICKET_KEYS_LENGTH];
    unsigned char k2[TICKET_KEYS_LENGTH];
    int test;

    memset(k1, 0xaa, sizeof(k1));
    memset(k2, 0xbb, sizeof(k2));

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_int_eq(SSL_CTX_set_tlsext_ticket_keys(s, k1, sizeof(k1)), 1)
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.c.stats.tickets, 2)
        && TEST_uint_eq(initial.s.stats.tickets, 2)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(initial.s.stats.sh_has_supported_versions, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_int_eq(SSL_CTX_set_tlsext_ticket_keys(s, k2, sizeof(k2)), 1)
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_false(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 2)
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 2)
        && TEST_uint_eq(resumed.c.stats.tickets, 2)
        && TEST_uint_eq(resumed.s.stats.tickets, 2)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(resumed.s.stats.sh_has_supported_versions, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/* Encode a session with i2d_SSL_SESSION and decode it again */
static SSL_SESSION *session_roundtrip(SSL_SESSION *in)
{
    unsigned char *der = NULL, *p;
    const unsigned char *q;
    SSL_SESSION *out = NULL;
    int len = i2d_SSL_SESSION(in, NULL);

    if (len <= 0 || (der = OPENSSL_malloc(len)) == NULL)
        return NULL;
    p = der;
    if (i2d_SSL_SESSION(in, &p) == len) {
        q = der;
        out = d2i_SSL_SESSION(NULL, &q, len);
    }
    OPENSSL_free(der);
    return out;
}

/*
 * Verify that a ticket issued for a resumed TLSv1.3 session does not extend
 * the session lifetime beyond the bound established by the initial full
 * handshake. The NewSessionTicket lifetime hint mirrors the (possibly capped)
 * session timeout computed by the server, so it is used to observe the cap:
 * the initial handshake advertises the full configured timeout, a resumed
 * handshake advertises at most the remaining lifetime, and once the original
 * lifetime has elapsed the client no longer offers the ticket, forcing a full
 * handshake that restarts the lifetime in full.
 */
#define BOUND_TIMEOUT 5 /* seconds */
#define DEFAULT_TIMEOUT (2 * 60 * 60) /* tls1_default_timeout() */

static int test_tls13_ticket_lifetime_bound(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel expired = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL, *sess2 = NULL, *sess3 = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_long_eq(SSL_CTX_set_timeout(s, BOUND_TIMEOUT), DEFAULT_TIMEOUT)
        && TEST_long_eq(SSL_CTX_get_timeout(s), BOUND_TIMEOUT)
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_ulong_eq(SSL_SESSION_get_ticket_lifetime_hint(sess), BOUND_TIMEOUT);

    if (test) {
        /* Consume a noticeable part of the session lifetime */
        OSSL_sleep(3000);

        test = TEST_true(tls_channel_init(c, s, &resumed))
            && TEST_true(SSL_set_session(resumed.c.ssl, sess))
            && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
            && TEST_true(SSL_session_reused(resumed.c.ssl))
            && TEST_uint_eq(resumed.s.stats.ch_has_psk, 1)
            && TEST_true(tls_shutdown(&resumed))
            && TEST_ptr(sess2 = SSL_get1_session(resumed.c.ssl))
            /* The new ticket only carries what was left of the lifetime */
            && TEST_ulong_le(SSL_SESSION_get_ticket_lifetime_hint(sess2),
                BOUND_TIMEOUT - 3);
    }

    if (test) {
        /* Let the originally established lifetime elapse completely */
        OSSL_sleep(4000);

        test = TEST_true(tls_channel_init(c, s, &expired))
            && TEST_true(SSL_set_session(expired.c.ssl, sess2))
            && TEST_true(create_ssl_connection(expired.s.ssl, expired.c.ssl, SSL_ERROR_NONE))
            /* The ticket has expired: no PSK offered, full handshake */
            && TEST_false(SSL_session_reused(expired.c.ssl))
            && TEST_uint_eq(expired.s.stats.ch_has_psk, 0)
            && TEST_true(tls_shutdown(&expired))
            && TEST_ptr(sess3 = SSL_get1_session(expired.c.ssl))
            /* The full handshake re-establishes the lifetime in full */
            && TEST_ulong_eq(SSL_SESSION_get_ticket_lifetime_hint(sess3),
                BOUND_TIMEOUT);
    }

    SSL_SESSION_free(sess);
    SSL_SESSION_free(sess2);
    SSL_SESSION_free(sess3);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    tls_channel_fini(&expired);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * An unlimited session timeout, selected with a negative value, is advertised
 * in the ticket lifetime hint as the RFC8446 1 week maximum and, unlike a
 * finite timeout, is restarted in full on each resumption rather than being
 * capped by the remaining lifetime.
 */
#define ONE_WEEK_SECS (7 * 24 * 60 * 60)

static int test_tls13_ticket_lifetime_unlimited(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL, *sess2 = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_long_eq(SSL_CTX_set_timeout(s, -1), DEFAULT_TIMEOUT)
        && TEST_long_eq(SSL_CTX_get_timeout(s), -1)
        /* The setter reports a previously unlimited timeout as -1 */
        && TEST_long_eq(SSL_CTX_set_timeout(s, 300), -1)
        && TEST_long_eq(SSL_CTX_set_timeout(s, -1), 300)
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_ulong_eq(SSL_SESSION_get_ticket_lifetime_hint(sess), ONE_WEEK_SECS);

    if (test) {
        /*
         * Let some time pass so that a finite timeout would be capped to the
         * remaining lifetime and thus advertise less than the full week.
         */
        OSSL_sleep(2000);

        test = TEST_true(tls_channel_init(c, s, &resumed))
            && TEST_true(SSL_set_session(resumed.c.ssl, sess))
            && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
            && TEST_true(SSL_session_reused(resumed.c.ssl))
            && TEST_true(tls_shutdown(&resumed))
            && TEST_ptr(sess2 = SSL_get1_session(resumed.c.ssl))
            /* Unlimited lifetime is restarted in full, not capped */
            && TEST_ulong_eq(SSL_SESSION_get_ticket_lifetime_hint(sess2),
                ONE_WEEK_SECS);
    }

    SSL_SESSION_free(sess);
    SSL_SESSION_free(sess2);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * An unlimited session timeout survives i2d_SSL_SESSION/d2i_SSL_SESSION,
 * which is the same encoding used inside stateless session tickets, so a
 * session re-created from such a ticket retains its unlimited timeout.
 */
static int test_tls13_ticket_timeout_encoding(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL, *rt1 = NULL, *rt2 = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_long_eq(SSL_SESSION_set_timeout(sess, -1), 1)
        && TEST_long_eq(SSL_SESSION_get_timeout(sess), -1)
        && TEST_ptr(rt1 = session_roundtrip(sess))
        && TEST_long_eq(SSL_SESSION_get_timeout(rt1), -1)
        && TEST_long_eq(SSL_SESSION_set_timeout(sess, 12345), 1)
        && TEST_ptr(rt2 = session_roundtrip(sess))
        && TEST_long_eq(SSL_SESSION_get_timeout(rt2), 12345);

    SSL_SESSION_free(sess);
    SSL_SESSION_free(rt1);
    SSL_SESSION_free(rt2);
    tls_channel_fini(&initial);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * The server must not resume an expired session even if the client offers the
 * ticket. The ticket lifetime communicated in NewSessionTicket is only a
 * hint: a non-conforming client can ignore it and keep offering the ticket,
 * so the lifetime bound established by the initial full handshake has to be
 * enforced server side from the state embedded in the ticket itself. The
 * enforcement lives in ssl_get_prev_session(), which rejects a timed out
 * session for TLSv1.3 tickets as well.
 *
 * Simulate such a client by overwriting the lifetime hint stored in the
 * client's session with a large value, so that the client offers a PSK whose
 * server-side lifetime has already expired.
 */
#define EXPIRE_TIMEOUT 1 /* seconds */

static int test_tls13_ticket_expired_no_resume(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel expired = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL, *sess2 = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_long_eq(SSL_CTX_set_timeout(s, EXPIRE_TIMEOUT), DEFAULT_TIMEOUT)
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_ulong_eq(SSL_SESSION_get_ticket_lifetime_hint(sess), EXPIRE_TIMEOUT);

    if (test) {
        /*
         * Let the session lifetime expire, with ample margin for the second
         * granularity of the serialised session time inside the ticket.
         */
        OSSL_sleep(3000);

        /* Pretend the client did not honour the ticket lifetime hint */
        sess->ext.tick_lifetime_hint = ONE_WEEK_SECS;

        test = TEST_true(tls_channel_init(c, s, &expired))
            && TEST_true(SSL_set_session(expired.c.ssl, sess))
            && TEST_true(create_ssl_connection(expired.s.ssl, expired.c.ssl, SSL_ERROR_NONE))
            /* The client offered the expired ticket ... */
            && TEST_uint_eq(expired.s.stats.ch_has_psk, 1)
            /* ... but the server must refuse it and do a full handshake */
            && TEST_false(SSL_session_reused(expired.c.ssl))
            && TEST_uint_eq(expired.s.stats.sh_has_psk, 0)
            && TEST_true(tls_shutdown(&expired))
            /* The fallback full handshake issues fresh full-lifetime tickets */
            && TEST_uint_eq(expired.s.stats.nst_msgs, 2)
            && TEST_ptr(sess2 = SSL_get1_session(expired.c.ssl))
            && TEST_ulong_eq(SSL_SESSION_get_ticket_lifetime_hint(sess2),
                EXPIRE_TIMEOUT);
    }

    SSL_SESSION_free(sess);
    SSL_SESSION_free(sess2);
    tls_channel_fini(&initial);
    tls_channel_fini(&expired);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * Coverage for the SessionTimeout (-session_timeout) configuration command:
 * plain seconds, "infinite" (case-insensitive) and negative values are
 * accepted, malformed values are rejected, and the command is only available
 * to servers.
 */
static int test_tls13_ticket_session_timeout_conf(void)
{
    SSL_CTX *s = NULL;
    SSL_CONF_CTX *cctx = NULL;
    int test;

    test = TEST_ptr(s = SSL_CTX_new(TLS_server_method()))
        && TEST_ptr(cctx = SSL_CONF_CTX_new());

    if (test) {
        SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_SERVER);
        SSL_CONF_CTX_set_ssl_ctx(cctx, s);

        test = TEST_int_eq(SSL_CONF_cmd(cctx, "SessionTimeout", "1234"), 2)
            && TEST_long_eq(SSL_CTX_get_timeout(s), 1234)
            && TEST_int_eq(SSL_CONF_cmd(cctx, "SessionTimeout", "Infinite"), 2)
            && TEST_long_eq(SSL_CTX_get_timeout(s), -1)
            && TEST_int_eq(SSL_CONF_cmd(cctx, "SessionTimeout", "-30"), 2)
            && TEST_long_eq(SSL_CTX_get_timeout(s), -1)
            && TEST_int_eq(SSL_CONF_cmd(cctx, "SessionTimeout", "12abc"), 0)
            && TEST_int_eq(SSL_CONF_cmd(cctx, "SessionTimeout", ""), 0)
            && TEST_true(SSL_CONF_CTX_finish(cctx));
    }

    if (test) {
        /* The command must not be recognised in a client-only context */
        test = TEST_uint_eq(SSL_CONF_CTX_clear_flags(cctx, SSL_CONF_FLAG_SERVER)
                & SSL_CONF_FLAG_SERVER,
            0);
        SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
        test = test
            && TEST_int_eq(SSL_CONF_cmd(cctx, "SessionTimeout", "10"), -2);
    }

    SSL_CONF_CTX_free(cctx);
    SSL_CTX_free(s);
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
    ADD_TEST(test_tls12_ticket_enable);
    ADD_TEST(test_tls12_ticket_disable_server);
    ADD_TEST(test_tls13_ticket_ciphersuite_mismatch);
    ADD_TEST(test_tls13_ticket_enable);
    ADD_TEST(test_tls13_ticket_initial_set_num_tickets_zero);
    ADD_TEST(test_tls13_ticket_resumed_set_num_tickets_zero);
    ADD_TEST(test_tls13_ticket_disable_server);
    ADD_TEST(test_tls13_ticket_no_decrypt);
    ADD_TEST(test_tls13_ticket_lifetime_bound);
    ADD_TEST(test_tls13_ticket_lifetime_unlimited);
    ADD_TEST(test_tls13_ticket_timeout_encoding);
    ADD_TEST(test_tls13_ticket_expired_no_resume);
    ADD_TEST(test_tls13_ticket_session_timeout_conf);

    return 1;
}
