/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
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
 * RFC 9846 section 4.3.9: Servers MUST NOT select a key exchange mode that is
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
    unsigned int ch_has_early_data;
    unsigned int sh_has_psk;
    unsigned int sh_has_supported_versions;
    unsigned int ee_has_early_data;
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
        case TLSEXT_TYPE_early_data:
            x->ch_has_early_data = 1;
            break;
        }
    }
    TEST_info("ch extensions: psk=%d psk_kex_modes=%d session_ticket=%d"
              " early_data=%d",
        x->ch_has_psk, x->ch_has_psk_kex_modes, x->ch_has_session_ticket,
        x->ch_has_early_data);
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

static void parse_ee_exts(const unsigned char *buf, size_t len, struct stats *x)
{
    PACKET pkt, e, ex;
    unsigned int v;

    if (!PACKET_buf_init(&pkt, buf, len)
        || !PACKET_forward(&pkt, 4)
        || !PACKET_as_length_prefixed_2(&pkt, &e))
        return;

    while (PACKET_remaining(&e) > 0) {
        if (!PACKET_get_net_2(&e, &v) || !PACKET_get_length_prefixed_2(&e, &ex))
            return;
        switch (v) {
        case TLSEXT_TYPE_early_data:
            x->ee_has_early_data = 1;
            break;
        }
    }
    TEST_info("ee extensions: early_data=%d", x->ee_has_early_data);
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
        if (mt == SSL3_MT_ENCRYPTED_EXTENSIONS && stats != NULL)
            parse_ee_exts(buf, len, stats);
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
 * TLSv1.3 stateful tickets for a server: the NewSessionTicket then only
 * carries a session id resolved through the server's internal session cache,
 * so the server-side session object (and thus its time and timeout) is
 * directly reachable for a test via SSL_get1_session() on the server SSL.
 * This lets lifetime tests age a session deterministically with
 * SSL_SESSION_set_time_ex() instead of sleeping through real time.
 */
static int ticket_enable_stateful(SSL_CTX *ctx)
{
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    return 1;
}

/*
 * A fixed, 0-RTT-capable external PSK (RFC 9846), offered via the
 * psk_use_session (client) and psk_find_session (server) callbacks. Used to
 * exercise 0-RTT keyed off an external PSK while a retired resumption ticket is
 * also present: the external PSK is the first offered identity (slot 0).
 */
static const unsigned char ext_psk_id[] = {
    'e', 'x', 't', '-', 'p', 's', 'k'
};
static const unsigned char ext_psk_key[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

static SSL_SESSION *ext_psk_session(SSL *ssl)
{
    static const unsigned char tls13_aes128gcmsha256_id[] = { 0x13, 0x01 };
    SSL_SESSION *sess = SSL_SESSION_new();
    const SSL_CIPHER *cipher = SSL_CIPHER_find(ssl, tls13_aes128gcmsha256_id);

    if (sess == NULL
        || cipher == NULL
        || !SSL_SESSION_set1_master_key(sess, ext_psk_key, sizeof(ext_psk_key))
        || !SSL_SESSION_set_cipher(sess, cipher)
        || !SSL_SESSION_set_protocol_version(sess, TLS1_3_VERSION)
        || !SSL_SESSION_set_max_early_data(sess, SSL3_RT_MAX_PLAIN_LENGTH)) {
        SSL_SESSION_free(sess);
        return NULL;
    }
    return sess;
}

static int ext_psk_use_cb(SSL *ssl, const EVP_MD *md, const unsigned char **id,
    size_t *idlen, SSL_SESSION **sess)
{
    (void)md;
    if ((*sess = ext_psk_session(ssl)) == NULL)
        return 0;
    *id = ext_psk_id;
    *idlen = sizeof(ext_psk_id);
    return 1;
}

static int ext_psk_find_cb(SSL *ssl, const unsigned char *id, size_t idlen,
    SSL_SESSION **sess)
{
    if (idlen != sizeof(ext_psk_id) || memcmp(id, ext_psk_id, idlen) != 0) {
        *sess = NULL;
        return 1;
    }
    return (*sess = ext_psk_session(ssl)) != NULL;
}

static int enable_external_psk(SSL *cssl, SSL *sssl)
{
    SSL_set_psk_use_session_callback(cssl, ext_psk_use_cb);
    SSL_set_psk_find_session_callback(sssl, ext_psk_find_cb);
    return 1;
}

/*
 * A client psk_use_session callback that hands back a single shared
 * SSL_SESSION on every call (up-ref'd, as the API permits) so we can check
 * that connection-local sid_ctx provenance is not written into it.
 */
static SSL_SESSION *shared_psk_sess = NULL;

static int shared_psk_use_cb(SSL *ssl, const EVP_MD *md, const unsigned char **id,
    size_t *idlen, SSL_SESSION **sess)
{
    (void)ssl;
    (void)md;
    if (shared_psk_sess == NULL || !SSL_SESSION_up_ref(shared_psk_sess))
        return 0;
    *sess = shared_psk_sess;
    *id = ext_psk_id;
    *idlen = sizeof(ext_psk_id);
    return 1;
}

static int enable_shared_psk(SSL *cssl, SSL *sssl)
{
    SSL_set_psk_use_session_callback(cssl, shared_psk_use_cb);
    SSL_set_psk_find_session_callback(sssl, ext_psk_find_cb);
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

/*
 * TLS 1.3 0-RTT early_data accepted
 *
 * Complements the suppression/rejection tests above: with a fresh resumption
 * ticket the client advertises both pre_shared_key and early_data, the server
 * accepts 0-RTT.
 */
static int test_tls13_ticket_early_data_accepted(void)
{
    const unsigned char m[] = "message";
    unsigned char buf[256];
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    size_t w = 0, r = 0;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(SSL_CTX_set_max_early_data(s, SSL3_RT_MAX_PLAIN_LENGTH))
        && TEST_true(SSL_CTX_set_options(s, SSL_OP_NO_ANTI_REPLAY) != 0)
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, 0))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.c.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.s.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.c.stats.tickets, 2)
        && TEST_uint_eq(initial.s.stats.tickets, 2)
        && TEST_uint_eq(initial.c.stats.ch_has_psk, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_psk, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_early_data, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_early_data, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(SSL_write_early_data(resumed.c.ssl, m, sizeof(m), &w))
        && TEST_size_t_eq(w, sizeof(m))
        && TEST_int_eq(SSL_read_early_data(resumed.s.ssl, buf, sizeof(buf), &r),
            SSL_READ_EARLY_DATA_SUCCESS)
        && TEST_mem_eq(buf, r, m, sizeof(m))
        && TEST_int_gt(SSL_connect(resumed.c.ssl), 0)
        && TEST_int_eq(SSL_read_early_data(resumed.s.ssl, buf, sizeof(buf), &r),
            SSL_READ_EARLY_DATA_FINISH)
        && TEST_size_t_eq(r, 0)
        && TEST_int_eq(SSL_get_early_data_status(resumed.s.ssl), SSL_EARLY_DATA_ACCEPTED)
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, 0))
        && TEST_int_eq(SSL_get_early_data_status(resumed.c.ssl), SSL_EARLY_DATA_ACCEPTED)
        && TEST_true(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 1)
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 1)
        && TEST_uint_eq(resumed.c.stats.tickets, 1)
        && TEST_uint_eq(resumed.s.stats.tickets, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_early_data, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_early_data, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.s.stats.ee_has_early_data, 1)
        && TEST_uint_eq(resumed.c.stats.ee_has_early_data, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

enum endpoint_state {
    ENDPOINT_WRITE_EARLY_DATA,
    ENDPOINT_READ_EARLY_DATA,
    ENDPOINT_HANDSHAKE,
    ENDPOINT_READ_APP_DATA,
    ENDPOINT_DONE,
    ENDPOINT_ERROR
};

/* Retry logic switch extracted from s_client. */
static int is_retryable(SSL *ssl, int ret)
{
    switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_ASYNC:
    case SSL_ERROR_WANT_READ:
        return 1;
    default:
        return 0;
    }
}

/*
 * The client follows the s_client retry loop; the server skips early data and
 * completes the handshake.
 *
 * SSL_write_early_data() states the call behaves like SSL_write_ex(): if it
 * fails, the caller must consult SSL_get_error() and, while it reports a
 * retryable WANT_READ/WANT_WRITE condition, keep calling SSL_write_early_data()
 * with the same arguments until it succeeds. This helper encodes that decision.
 */
static int tls_early_data_retry(struct tls13_channel *x)
{
    const unsigned char m[] = "message";
    unsigned char buf[256];
    enum endpoint_state c = ENDPOINT_WRITE_EARLY_DATA;
    enum endpoint_state s = ENDPOINT_READ_EARLY_DATA;
    size_t w = SIZE_MAX, r = SIZE_MAX;

    for (int i = 0; i < 100 && (c != ENDPOINT_DONE || s != ENDPOINT_DONE); i++) {
        if (c == ENDPOINT_WRITE_EARLY_DATA) {
            if (SSL_write_early_data(x->c.ssl, m, sizeof(m), &w) > 0)
                c = ENDPOINT_DONE;
            else if (!is_retryable(x->c.ssl, 0))
                c = ENDPOINT_ERROR;
        }
        if (s == ENDPOINT_READ_EARLY_DATA) {
            switch (SSL_read_early_data(x->s.ssl, buf, sizeof(buf), &r)) {
            case SSL_READ_EARLY_DATA_FINISH:
                s = ENDPOINT_HANDSHAKE;
                break;
            default:
                s = ENDPOINT_ERROR;
            }
        }
        if (s == ENDPOINT_HANDSHAKE) {
            if (SSL_is_init_finished(x->s.ssl))
                s = ENDPOINT_DONE;
            else if (SSL_accept(x->s.ssl) <= 0 && !is_retryable(x->s.ssl, 0))
                s = ENDPOINT_ERROR;
        }
        if (c == ENDPOINT_ERROR || s == ENDPOINT_ERROR)
            break;
    }

    return TEST_int_eq(c, ENDPOINT_DONE)
        && TEST_int_eq(s, ENDPOINT_DONE)
        && TEST_size_t_eq(w, sizeof(m))
        && TEST_size_t_eq(r, 0);
}

/*
 * TLS 1.3 Client-side Ticket Age Mismatch 0-RTT Rejection (API retry test)
 *
 * This test exercises the case where the client does not send a PSK due to a
 * ticket age mismatch, and verifies that the client suppresses the early_data
 * as a result.
 *
 * RFC 9846 4.3.10: When a PSK is used and early data is allowed for that PSK,
 * the client can send Application Data in its first flight of messages. If the
 * client opts to do so, it MUST supply both the "pre_shared_key" and
 * "early_data" extensions. The PSK used to encrypt the early data MUST be the
 * first PSK listed in the client's "pre_shared_key" extension.
 *
 * RFC 9846 4.3.11.1: Clients MUST NOT attempt to use tickets which have ages
 * greater than the "ticket_lifetime" value which was provided with the ticket.
 */
static int test_tls13_ticket_client_age_mismatch_reject_early_data_retry(void)
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
        && TEST_true(SSL_CTX_set_max_early_data(s, SSL3_RT_MAX_PLAIN_LENGTH))
        && TEST_true(SSL_CTX_set_timeout(s, 1) > 0)
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, 0))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.c.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.s.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.c.stats.tickets, 2)
        && TEST_uint_eq(initial.s.stats.tickets, 2)
        && TEST_uint_eq(initial.c.stats.ch_has_psk, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_psk, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_early_data, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_early_data, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_time_t_gt(SSL_SESSION_set_time_ex(sess, time(NULL) - 10), 0)
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(tls_early_data_retry(&resumed))
        && TEST_int_eq(SSL_get_early_data_status(resumed.c.ssl), SSL_EARLY_DATA_REJECTED)
        && TEST_false(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 2)
        && TEST_uint_eq(resumed.c.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.tickets, 2)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk, 0)
        && TEST_uint_eq(resumed.c.stats.ch_has_early_data, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_early_data, 0)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.s.stats.ee_has_early_data, 0)
        && TEST_uint_eq(resumed.c.stats.ee_has_early_data, 0);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * TLS 1.3 Server-side Ticket Age Mismatch 0-RTT Rejection
 *
 * Exercises the server-side ticket age validation. The client considers the
 * ticket fresh and proceeds with PSK + 0-RTT, but the transmitted
 * obfuscated_ticket_age indicates a ticket roughly 10s old. Since the apparent
 * ticket age exceeds TICKET_AGE_ALLOWANCE, the server rejects early data.
 *
 * RFC 9846 4.3.10: For PSKs provisioned via NewSessionTicket, a server MUST
 * validate that the ticket age for the selected PSK identity is within a small
 * tolerance of the time since the ticket was issued. If it is not, the server
 * SHOULD proceed with the handshake but reject 0-RTT.
 */
static int test_tls13_ticket_server_age_mismatch_reject_early_data(void)
{
    const unsigned char m[] = "message";
    unsigned char buf[256];
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    size_t w = 0, r = 0;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(SSL_CTX_set_max_early_data(s, SSL3_RT_MAX_PLAIN_LENGTH))
        && TEST_true(SSL_CTX_set_options(s, SSL_OP_NO_ANTI_REPLAY) != 0)
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, 0))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.c.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.s.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.c.stats.tickets, 2)
        && TEST_uint_eq(initial.s.stats.tickets, 2)
        && TEST_uint_eq(initial.c.stats.ch_has_psk, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_psk, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_early_data, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_early_data, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_time_t_gt(SSL_SESSION_set_time_ex(sess, time(NULL) - 10), 0)
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(SSL_write_early_data(resumed.c.ssl, m, sizeof(m), &w))
        && TEST_size_t_eq(w, sizeof(m))
        && TEST_int_eq(SSL_read_early_data(resumed.s.ssl, buf, sizeof(buf), &r),
            SSL_READ_EARLY_DATA_FINISH)
        && TEST_size_t_eq(r, 0)
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, 0))
        && TEST_int_eq(SSL_get_early_data_status(resumed.c.ssl), SSL_EARLY_DATA_REJECTED)
        && TEST_true(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 1)
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 1)
        && TEST_uint_eq(resumed.c.stats.tickets, 1)
        && TEST_uint_eq(resumed.s.stats.tickets, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_early_data, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_early_data, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.s.stats.ee_has_early_data, 0)
        && TEST_uint_eq(resumed.c.stats.ee_has_early_data, 0);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * TLS 1.3 Client-side Ticket Age Mismatch 0-RTT Rejection (outer test)
 */
static int test_tls13_ticket_client_age_mismatch_reject_early_data_outer(void)
{
    const unsigned char m[] = "message";
    unsigned char buf[256];
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    size_t r = 0, w = 0;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(SSL_CTX_set_max_early_data(s, SSL3_RT_MAX_PLAIN_LENGTH))
        && TEST_true(SSL_CTX_set_timeout(s, 1) > 0)
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, 0))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.c.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.s.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.c.stats.tickets, 2)
        && TEST_uint_eq(initial.s.stats.tickets, 2)
        && TEST_uint_eq(initial.c.stats.ch_has_psk, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_psk, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_early_data, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_early_data, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_time_t_gt(SSL_SESSION_set_time_ex(sess, time(NULL) - 10), 0)
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(tls_early_data_retry(&resumed))
        && TEST_int_eq(SSL_get_early_data_status(resumed.c.ssl), SSL_EARLY_DATA_REJECTED)
        && TEST_false(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 2)
        && TEST_uint_eq(resumed.c.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.tickets, 2)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk, 0)
        && TEST_uint_eq(resumed.c.stats.ch_has_early_data, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_early_data, 0)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.s.stats.ee_has_early_data, 0)
        && TEST_uint_eq(resumed.c.stats.ee_has_early_data, 0)
        /*
         * While the application is still in the early data write sequence,
         * further suppressed SSL_write_early_data() calls keep succeeding.
         */
        && TEST_size_t_eq((w = SIZE_MAX), SIZE_MAX)
        && TEST_true(SSL_write_early_data(resumed.c.ssl, m, sizeof(m), &w))
        && TEST_size_t_eq(w, sizeof(m))
        /* Ordinary application I/O ends that sequence. */
        && TEST_size_t_eq((w = SIZE_MAX), SIZE_MAX)
        && TEST_int_gt(SSL_write_ex(resumed.c.ssl, m, sizeof(m), &w), 0)
        && TEST_size_t_eq(w, sizeof(m))
        && TEST_size_t_eq((r = SIZE_MAX), SIZE_MAX)
        && TEST_int_gt(SSL_read_ex(resumed.s.ssl, buf, sizeof(buf), &r), 0)
        && TEST_size_t_eq(r, sizeof(m))
        && TEST_mem_eq(buf, r, m, sizeof(m))
        && TEST_size_t_eq((w = SIZE_MAX), SIZE_MAX)
        && TEST_int_gt(SSL_write_ex(resumed.s.ssl, m, sizeof(m), &w), 0)
        && TEST_size_t_eq(w, sizeof(m))
        && TEST_size_t_eq((r = SIZE_MAX), SIZE_MAX)
        && TEST_int_gt(SSL_read_ex(resumed.c.ssl, buf, sizeof(buf), &r), 0)
        && TEST_size_t_eq(r, sizeof(m))
        && TEST_mem_eq(buf, r, m, sizeof(m))
        /*
         * Having left the early data write sequence, a further
         * SSL_write_early_data() reports the normal error rather than masking
         * the application's state-machine mistake as success.
         */
        && TEST_size_t_eq((w = SIZE_MAX), SIZE_MAX)
        && TEST_false(SSL_write_early_data(resumed.c.ssl, m, sizeof(m), &w))
        && TEST_int_eq(SSL_get_error(resumed.c.ssl, 0), SSL_ERROR_SSL)
        && TEST_int_eq(ERR_GET_REASON(ERR_get_error()),
            ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED)
        && TEST_size_t_eq(w, SIZE_MAX);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

OPT_TEST_DECLARE_USAGE("\n")

/*
 * TLS 1.3 0-RTT keyed off an external PSK past a retired resumption ticket.
 *
 * The client holds a 0-RTT-capable resumption ticket that has aged past its
 * lifetime, so tls_construct_ctos_psk() does not offer it; an external PSK
 * from the psk_use_session callback therefore occupies identity 0 and keys the
 * early data. The keying sites must follow that slot-0 PSK, not the retired
 * ticket (whose max_early_data is still non-zero) -- otherwise client and
 * server derive different CLIENT_EARLY_TRAFFIC_SECRET values and the server
 * fails with a bad record MAC. Regression test for the mixed aged-ticket +
 * external-PSK 0-RTT keying bug.
 */
static int test_tls13_aged_ticket_external_psk_early_data(void)
{
    const unsigned char m[] = "message";
    unsigned char buf[256];
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    size_t w = 0, r = 0;
    unsigned char ceed[32], seed[32];
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        /*
         * Pin the ciphersuite to the external PSK's committed cipher so the
         * negotiated cipher matches it; 0-RTT on an external PSK requires that
         * (RFC 9846 4.3.10). Orthogonal to the bug under test, which is about
         * which PSK's secret keys the early data, not the cipher.
         */
        && TEST_true(SSL_CTX_set_ciphersuites(s, "TLS_AES_128_GCM_SHA256"))
        && TEST_true(SSL_CTX_set_ciphersuites(c, "TLS_AES_128_GCM_SHA256"))
        && TEST_true(SSL_CTX_set_max_early_data(s, SSL3_RT_MAX_PLAIN_LENGTH))
        && TEST_true(SSL_CTX_set_options(s, SSL_OP_NO_ANTI_REPLAY) != 0)
        /* Short ticket lifetime so the backdated ticket ages out client-side
         * and is not offered, leaving the external PSK at slot 0. */
        && TEST_true(SSL_CTX_set_timeout(s, 1) > 0)
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, 0))
        && TEST_true(tls_shutdown(&initial))
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        /* Retire the (0-RTT-capable) ticket so it is not offered at slot 0. */
        && TEST_time_t_gt(SSL_SESSION_set_time_ex(sess, time(NULL) - 10), 0)
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(enable_external_psk(resumed.c.ssl, resumed.s.ssl))
        && TEST_true(SSL_write_early_data(resumed.c.ssl, m, sizeof(m), &w))
        && TEST_size_t_eq(w, sizeof(m))
        && TEST_int_eq(SSL_read_early_data(resumed.s.ssl, buf, sizeof(buf), &r),
            SSL_READ_EARLY_DATA_SUCCESS)
        && TEST_mem_eq(buf, r, m, sizeof(m))
        && TEST_int_gt(SSL_connect(resumed.c.ssl), 0)
        && TEST_int_eq(SSL_read_early_data(resumed.s.ssl, buf, sizeof(buf), &r),
            SSL_READ_EARLY_DATA_FINISH)
        && TEST_size_t_eq(r, 0)
        && TEST_int_eq(SSL_get_early_data_status(resumed.s.ssl),
            SSL_EARLY_DATA_ACCEPTED)
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, 0))
        && TEST_int_eq(SSL_get_early_data_status(resumed.c.ssl),
            SSL_EARLY_DATA_ACCEPTED)
        /*
         * The early exporter secret must match on both ends -- an independent
         * check (separate from the decrypted early data) that both sides keyed
         * 0-RTT from the same slot-0 PSK.
         */
        && TEST_int_eq(SSL_export_keying_material_early(resumed.c.ssl, ceed,
                           sizeof(ceed), "label", 5, (const unsigned char *)"ctx", 3),
            1)
        && TEST_int_eq(SSL_export_keying_material_early(resumed.s.ssl, seed,
                           sizeof(seed), "label", 5, (const unsigned char *)"ctx", 3),
            1)
        && TEST_mem_eq(ceed, sizeof(ceed), seed, sizeof(seed))
        /* The external PSK (slot 0) keyed 0-RTT, not the retired ticket. */
        && TEST_uint_eq(resumed.c.stats.ch_has_psk, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_early_data, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_early_data, 1)
        && TEST_uint_eq(resumed.s.stats.ee_has_early_data, 1)
        && TEST_uint_eq(resumed.c.stats.ee_has_early_data, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * TLS 1.3 external-PSK sid_ctx must not mutate a callback-shared session.
 *
 * The psk_use_session callback is entitled to return the same SSL_SESSION on
 * every call (up-ref'd). When the client resumes via that PSK it stamps its
 * connection-local sid_ctx onto the session; it must do so on a private
 * duplicate, never on the shared object, or the sid_ctx bleeds across
 * connections (and races under concurrency). After a handshake with a
 * non-empty client sid_ctx, the shared session's sid_ctx must be untouched.
 */
static int test_tls13_external_psk_sid_ctx_not_shared(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel conn = { .c.ssl = NULL, .s.ssl = NULL };
    static const unsigned char sidctx[] = { 'S', 'I', 'D' };
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(SSL_CTX_set_ciphersuites(s, "TLS_AES_128_GCM_SHA256"))
        && TEST_true(SSL_CTX_set_ciphersuites(c, "TLS_AES_128_GCM_SHA256"))
        && TEST_true(tls_channel_init(c, s, &conn))
        && TEST_ptr(shared_psk_sess = ext_psk_session(conn.c.ssl))
        && TEST_true(SSL_set_session_id_context(conn.c.ssl, sidctx, sizeof(sidctx)))
        && TEST_true(enable_shared_psk(conn.c.ssl, conn.s.ssl))
        && TEST_true(create_ssl_connection(conn.s.ssl, conn.c.ssl, 0))
        && TEST_true(SSL_session_reused(conn.c.ssl))
        /* Our sid_ctx must not have been written into the shared session. */
        && TEST_size_t_eq(shared_psk_sess->sid_ctx_length, 0);

    SSL_SESSION_free(shared_psk_sess);
    shared_psk_sess = NULL;
    tls_channel_fini(&conn);
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
 *
 * Stateful tickets are used so that the passing of time can be simulated by
 * backdating the server's cached session instead of sleeping through real
 * lifetime; the cap itself is shared with the stateless ticket path.
 */
#define BOUND_TIMEOUT 5 /* seconds */
#define BOUND_ELAPSED 3 /* how far the server-side session is backdated */
#define DEFAULT_TIMEOUT (2 * 60 * 60) /* tls1_default_timeout() */

static int test_tls13_ticket_lifetime_bound(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel expired = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL, *sess2 = NULL, *sess3 = NULL, *srvsess = NULL;
    unsigned long hint;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable_stateful(s))
        && TEST_true(ticket_enable(c))
        && TEST_long_eq(SSL_CTX_set_timeout(s, BOUND_TIMEOUT), DEFAULT_TIMEOUT)
        && TEST_long_eq(SSL_CTX_get_timeout(s), BOUND_TIMEOUT)
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_ulong_eq(SSL_SESSION_get_ticket_lifetime_hint(sess), BOUND_TIMEOUT)
        /* Consume a noticeable part of the server-side session lifetime */
        && TEST_ptr(srvsess = SSL_get1_session(initial.s.ssl))
        && TEST_time_t_gt(SSL_SESSION_set_time_ex(srvsess,
                              time(NULL) - BOUND_ELAPSED),
            0);

    if (test) {
        test = TEST_true(tls_channel_init(c, s, &resumed))
            && TEST_true(SSL_set_session(resumed.c.ssl, sess))
            && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
            && TEST_true(SSL_session_reused(resumed.c.ssl))
            && TEST_uint_eq(resumed.s.stats.ch_has_psk, 1)
            && TEST_true(tls_shutdown(&resumed))
            && TEST_ptr(sess2 = SSL_get1_session(resumed.c.ssl));
    }

    if (test) {
        /*
         * The new ticket only carries what was left of the lifetime,
         * plus/minus one second for the whole-second granularity of both
         * the backdating above and the encoded lifetime.
         */
        hint = SSL_SESSION_get_ticket_lifetime_hint(sess2);
        test = TEST_ulong_ge(hint, BOUND_TIMEOUT - BOUND_ELAPSED - 1)
            && TEST_ulong_le(hint, BOUND_TIMEOUT - BOUND_ELAPSED);
    }

    if (test) {
        /* Let the capped lifetime elapse completely, client side */
        test = TEST_time_t_gt(SSL_SESSION_set_time_ex(sess2,
                                  time(NULL) - BOUND_TIMEOUT),
                   0)
            && TEST_true(tls_channel_init(c, s, &expired))
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
    SSL_SESSION_free(srvsess);
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
    SSL_SESSION *sess = NULL, *sess2 = NULL, *srvsess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable_stateful(s))
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
        && TEST_ulong_eq(SSL_SESSION_get_ticket_lifetime_hint(sess), ONE_WEEK_SECS)
        /*
         * Age the server-side session so that a finite timeout would be
         * capped to the remaining lifetime and thus advertise less than the
         * full week.
         */
        && TEST_ptr(srvsess = SSL_get1_session(initial.s.ssl))
        && TEST_time_t_gt(SSL_SESSION_set_time_ex(srvsess, time(NULL) - 2), 0);

    if (test) {
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
    SSL_SESSION_free(srvsess);
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
    SSL_SESSION *sess = NULL, *rt1 = NULL, *rt2 = NULL, *rt3 = NULL;
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

    if (test && sizeof(long) > 4) {
        /*
         * A finite value too large to represent as an OSSL_TIME saturates
         * to unlimited on the way in, matching the treatment of oversized
         * encoded timeouts in d2i_SSL_SESSION_ex(), rather than silently
         * wrapping to a near-zero timeout.
         */
        long big = (long)(((uint64_t)1) << 62);

        test = TEST_long_eq(SSL_SESSION_set_timeout(sess, big), 1)
            && TEST_long_eq(SSL_SESSION_get_timeout(sess), -1)
            && TEST_ptr(rt3 = session_roundtrip(sess))
            && TEST_long_eq(SSL_SESSION_get_timeout(rt3), -1);
    }

    SSL_SESSION_free(sess);
    SSL_SESSION_free(rt1);
    SSL_SESSION_free(rt2);
    SSL_SESSION_free(rt3);
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
 * Simulate such a client by backdating the client's session past the
 * lifetime and overwriting the lifetime hint stored in it with a large
 * value, so that the client offers a PSK whose server-side lifetime (aged
 * by backdating the server's cached session) has already expired.
 */
#define EXPIRE_TIMEOUT 1 /* seconds */

static int test_tls13_ticket_expired_no_resume(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel expired = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL, *sess2 = NULL, *srvsess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable_stateful(s))
        && TEST_true(ticket_enable(c))
        && TEST_long_eq(SSL_CTX_set_timeout(s, EXPIRE_TIMEOUT), DEFAULT_TIMEOUT)
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_ulong_eq(SSL_SESSION_get_ticket_lifetime_hint(sess), EXPIRE_TIMEOUT)
        /* Let the session lifetime expire, with ample margin */
        && TEST_ptr(srvsess = SSL_get1_session(initial.s.ssl))
        && TEST_time_t_gt(SSL_SESSION_set_time_ex(srvsess,
                              time(NULL) - (EXPIRE_TIMEOUT + 2)),
            0)
        && TEST_time_t_gt(SSL_SESSION_set_time_ex(sess,
                              time(NULL) - (EXPIRE_TIMEOUT + 2)),
            0);

    if (test) {
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
    SSL_SESSION_free(srvsess);
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
            /* A previous timeout of 0 must not read as a command failure */
            && TEST_int_eq(SSL_CONF_cmd(cctx, "SessionTimeout", "0"), 2)
            && TEST_int_eq(SSL_CONF_cmd(cctx, "SessionTimeout", "300"), 2)
            && TEST_long_eq(SSL_CTX_get_timeout(s), 300)
            /* Values that overflow the parser are rejected, not wrapped */
            && TEST_int_eq(SSL_CONF_cmd(cctx, "SessionTimeout",
                               "99999999999999999999"),
                0)
            && TEST_long_eq(SSL_CTX_get_timeout(s), 300)
            && TEST_int_eq(SSL_CONF_cmd(cctx, "SessionTimeout", "12abc"), 0)
            && TEST_int_eq(SSL_CONF_cmd(cctx, "SessionTimeout", ""), 0);

        if (test && sizeof(long) > 4) {
            /*
             * Parseable values too large to represent as an OSSL_TIME (here
             * 2^62 seconds) saturate to an unlimited timeout instead of
             * wrapping to a near-zero one.
             */
            test = TEST_int_eq(SSL_CONF_cmd(cctx, "SessionTimeout",
                                   "4611686018427387904"),
                       2)
                && TEST_long_eq(SSL_CTX_get_timeout(s), -1);
        }

        test = test && TEST_true(SSL_CONF_CTX_finish(cctx));
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

/*
 * The resumed-session lifetime cap keys off the server having accepted a
 * PSK, but a handshake authenticated by an external PSK is a fresh
 * authentication, not a resumption: the lifetime of tickets issued for it
 * must not be capped by the age of the application-provided PSK session.
 * The server-side find callback hands back a session created a while ago
 * (backdated), whose remaining lifetime is well below its timeout; the
 * issued ticket must still carry the full timeout.
 */
#define EXT_PSK_TIMEOUT 300 /* seconds */
#define EXT_PSK_AGE 100 /* seconds */

static int ext_psk_find_aged_cb(SSL *ssl, const unsigned char *id, size_t idlen,
    SSL_SESSION **sess)
{
    if (!ext_psk_find_cb(ssl, id, idlen, sess))
        return 0;
    if (*sess != NULL
        && (SSL_SESSION_set_timeout(*sess, EXT_PSK_TIMEOUT) != 1
            || SSL_SESSION_set_time_ex(*sess, time(NULL) - EXT_PSK_AGE) == 0)) {
        SSL_SESSION_free(*sess);
        *sess = NULL;
        return 0;
    }
    return 1;
}

static int test_tls13_external_psk_lifetime_uncapped(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel psk = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        /* Pin the ciphersuite to the external PSK's committed cipher */
        && TEST_true(SSL_CTX_set_ciphersuites(s, "TLS_AES_128_GCM_SHA256"))
        && TEST_true(SSL_CTX_set_ciphersuites(c, "TLS_AES_128_GCM_SHA256"))
        && TEST_true(tls_channel_init(c, s, &psk));

    if (test) {
        SSL_set_psk_use_session_callback(psk.c.ssl, ext_psk_use_cb);
        SSL_set_psk_find_session_callback(psk.s.ssl, ext_psk_find_aged_cb);

        test = TEST_true(create_ssl_connection(psk.s.ssl, psk.c.ssl, SSL_ERROR_NONE))
            && TEST_true(SSL_session_reused(psk.c.ssl))
            && TEST_uint_eq(psk.s.stats.ch_has_psk, 1)
            && TEST_uint_eq(psk.s.stats.sh_has_psk, 1)
            && TEST_true(tls_shutdown(&psk))
            && TEST_ptr(sess = SSL_get1_session(psk.c.ssl))
            /* The full timeout, not EXT_PSK_TIMEOUT - EXT_PSK_AGE */
            && TEST_ulong_eq(SSL_SESSION_get_ticket_lifetime_hint(sess),
                EXT_PSK_TIMEOUT);
    }

    SSL_SESSION_free(sess);
    tls_channel_fini(&psk);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * TLSv1.2 ticket lifetime hint (RFC 5077): an initial handshake advertises
 * the configured timeout; an unlimited timeout has no finite representation
 * in the 32 bit field, so it is sent as 0 ("unspecified"), not as a
 * truncation artefact.
 */
#define TLS12_TIMEOUT 7777 /* seconds */

static int test_tls12_ticket_lifetime_hint(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel finite = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel unlimited = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL, *sess2 = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_2_VERSION, TLS1_2_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_long_eq(SSL_CTX_set_timeout(s, TLS12_TIMEOUT), DEFAULT_TIMEOUT)
        && TEST_true(tls_channel_init(c, s, &finite))
        && TEST_true(create_ssl_connection(finite.s.ssl, finite.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&finite))
        && TEST_ptr(sess = SSL_get1_session(finite.c.ssl))
        && TEST_ulong_eq(SSL_SESSION_get_ticket_lifetime_hint(sess),
            TLS12_TIMEOUT);

    if (test) {
        test = TEST_long_eq(SSL_CTX_set_timeout(s, -1), TLS12_TIMEOUT)
            && TEST_true(tls_channel_init(c, s, &unlimited))
            && TEST_true(create_ssl_connection(unlimited.s.ssl, unlimited.c.ssl,
                SSL_ERROR_NONE))
            && TEST_true(tls_shutdown(&unlimited))
            && TEST_ptr(sess2 = SSL_get1_session(unlimited.c.ssl))
            && TEST_ulong_eq(SSL_SESSION_get_ticket_lifetime_hint(sess2), 0);
    }

    SSL_SESSION_free(sess);
    SSL_SESSION_free(sess2);
    tls_channel_fini(&finite);
    tls_channel_fini(&unlimited);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

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
    ADD_TEST(test_tls13_ticket_early_data_accepted);
    ADD_TEST(test_tls13_ticket_client_age_mismatch_reject_early_data_retry);
    ADD_TEST(test_tls13_ticket_client_age_mismatch_reject_early_data_outer);
    ADD_TEST(test_tls13_ticket_server_age_mismatch_reject_early_data);
    ADD_TEST(test_tls13_aged_ticket_external_psk_early_data);
    ADD_TEST(test_tls13_external_psk_sid_ctx_not_shared);
    ADD_TEST(test_tls13_ticket_lifetime_bound);
    ADD_TEST(test_tls13_ticket_lifetime_unlimited);
    ADD_TEST(test_tls13_ticket_timeout_encoding);
    ADD_TEST(test_tls13_ticket_expired_no_resume);
    ADD_TEST(test_tls13_ticket_session_timeout_conf);
    ADD_TEST(test_tls13_external_psk_lifetime_uncapped);
    ADD_TEST(test_tls12_ticket_lifetime_hint);

    return 1;
}
