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
    unsigned int ch_has_early_data;
    unsigned int sh_has_psk;
    unsigned int sh_has_supported_versions;
    unsigned int ee_has_early_data;
    unsigned int ee_has_alpn;
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
        case TLSEXT_TYPE_application_layer_protocol_negotiation:
            x->ee_has_alpn = 1;
            break;
        }
    }
    TEST_info("ee extensions: early_data=%d alpn=%d",
        x->ee_has_early_data, x->ee_has_alpn);
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
 * A fixed, 0-RTT-capable external PSK (RFC 8446), offered via the
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
 * The server offers a single protocol via server_alpn and selects it when the
 * client advertises it. The client advertises a protocol using the
 * length-prefixed wire form expected by SSL_set_alpn_protos().
 */
static const char *server_alpn = NULL;

static int alpn_select_cb(SSL *ssl, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in,
    unsigned int inlen, void *arg)
{
    unsigned int protlen = 0;
    const unsigned char *prot;

    if (server_alpn == NULL)
        return SSL_TLSEXT_ERR_NOACK;

    for (prot = in; prot < in + inlen; prot += protlen) {
        protlen = *prot++;
        if (in + inlen < prot + protlen)
            return SSL_TLSEXT_ERR_NOACK;
        if (protlen == strlen(server_alpn)
            && memcmp(prot, server_alpn, protlen) == 0) {
            *out = prot;
            *outlen = protlen;
            return SSL_TLSEXT_ERR_OK;
        }
    }
    return SSL_TLSEXT_ERR_NOACK;
}

static int alpn_server_enable(SSL_CTX *ctx, const char *proto)
{
    server_alpn = proto;
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
    return 1;
}

/* Change which protocol the server selects for the next handshake. */
static int alpn_server_select(const char *proto)
{
    server_alpn = proto;
    return 1;
}

/* Append protocol proto (length-prefixed) to the wire buffer at *n. */
static int alpn_wire_add(unsigned char *wire, size_t cap, unsigned int *n,
    const char *proto)
{
    unsigned int plen = (unsigned int)strlen(proto);

    if (plen == 0 || plen > 255 || *n + 1 + plen > cap)
        return 0;
    wire[(*n)++] = (unsigned char)plen;
    memcpy(wire + *n, proto, plen);
    *n += plen;
    return 1;
}

static int alpn_client_offer(SSL *ssl, const char *proto)
{
    unsigned char wire[256];
    unsigned int n = 0;

    if (!alpn_wire_add(wire, sizeof(wire), &n, proto))
        return 0;
    /* SSL_set_alpn_protos() returns 0 on success. */
    return SSL_set_alpn_protos(ssl, wire, n) == 0;
}

static int alpn_client_offer2(SSL *ssl, const char *p1, const char *p2)
{
    unsigned char wire[256];
    unsigned int n = 0;

    if (!alpn_wire_add(wire, sizeof(wire), &n, p1)
        || !alpn_wire_add(wire, sizeof(wire), &n, p2))
        return 0;
    /* SSL_set_alpn_protos() returns 0 on success. */
    return SSL_set_alpn_protos(ssl, wire, n) == 0;
}

/* Returns 1 if the connection negotiated exactly the given ALPN protocol. */
static int alpn_conn_selected_is(SSL *ssl, const char *proto)
{
    const unsigned char *alpn = NULL;
    unsigned int alpnlen = 0;

    SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
    return alpn != NULL
        && alpnlen == strlen(proto)
        && memcmp(alpn, proto, alpnlen) == 0;
}

/* Returns 1 if the connection negotiated no ALPN protocol. */
static int alpn_conn_selected_none(SSL *ssl)
{
    const unsigned char *alpn = NULL;
    unsigned int alpnlen = 0;

    SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
    return alpn == NULL && alpnlen == 0;
}

/* Returns 1 if the session stores no ALPN protocol. */
static int alpn_sess_selected_none(SSL *ssl)
{
    const unsigned char *alpn = NULL;
    size_t alpnlen = 0;

    SSL_SESSION_get0_alpn_selected(SSL_get_session(ssl), &alpn, &alpnlen);
    return alpn == NULL && alpnlen == 0;
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

/*
 * TLS 1.3 stale ALPN cleared from a resumption ticket
 *
 * A session that negotiated ALPN is resumed on a connection that negotiates no
 * ALPN at all (the client advertises none). The NewSessionTicket issued for the
 * resumed session must not retain the ALPN protocol from the original session;
 * otherwise a later 0-RTT attempt using that ticket would incorrectly assume
 * that protocol had been negotiated.
 *
 * Regression test for GitHub issue #11197: tls_construct_new_session_ticket()
 * copied s->s3.alpn_selected into the session only when an ALPN protocol was
 * negotiated, but failed to clear s->session->ext.alpn_selected when it wasn't.
 *
 * A third connection then resumes the now-ALPN-cleared ticket and negotiates
 * "goodalpn" again -- the same, non-empty protocol as the original session,
 * coincidentally. Since the ticket being resumed carries no ALPN, 0-RTT must
 * still be rejected: the client's SSL_write_early_data() appears to succeed
 * (the data is sent before the server's response is known), but a post hoc
 * SSL_get_early_data_status() check confirms the server never accepted it.
 *
 * A fourth connection resumes that same ALPN-cleared ticket a second time --
 * anti-replay is disabled for this test, so reusing it twice is not itself a
 * reason for rejection -- but this time advertises no ALPN, consistent with
 * what the ticket actually recorded. 0-RTT must now be accepted. Without this
 * case, the rejection asserted for connection 3 would be unfalsifiable: it
 * would look identical if early data were simply never being accepted here
 * for any reason at all.
 *
 * The fourth connection resumes from an independent SSL_SESSION_dup() copy
 * of the ticket (taken before connection 3 uses the original), rather than
 * the original SSL_SESSION object itself: completing a handshake from a
 * resumed session marks that SSL_SESSION object not-resumable on the client
 * side as a single-use safeguard, independent of (and in addition to) the
 * server's SSL_OP_NO_ANTI_REPLAY setting. Resuming the literal object a
 * second time would therefore quietly fall back to a full, non-PSK
 * handshake instead of testing the intended 0-RTT path.
 */
static int test_tls13_ticket_alpn_cleared(void)
{
    const unsigned char m[] = "message";
    unsigned char buf[256];
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed2 = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed3 = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL, *sess2 = NULL, *sess2b = NULL;
    size_t w = 0, r = 0;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(SSL_CTX_set_max_early_data(s, SSL3_RT_MAX_PLAIN_LENGTH))
        && TEST_true(SSL_CTX_set_options(s, SSL_OP_NO_ANTI_REPLAY) != 0)
        && TEST_true(alpn_server_enable(s, "goodalpn"))
        /*
         * Connection 1: the client advertises "goodalpn", the server selects
         * it, and the negotiated protocol is stored in the session.
         */
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(alpn_client_offer(initial.c.ssl, "goodalpn"))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(alpn_conn_selected_is(initial.s.ssl, "goodalpn"))
        && TEST_true(alpn_conn_selected_is(initial.c.ssl, "goodalpn"))
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
        && TEST_uint_eq(initial.s.stats.ee_has_alpn, 1)
        && TEST_uint_eq(initial.c.stats.ee_has_alpn, 1)
        && TEST_true(tls_shutdown(&initial))
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        /*
         * Connection 2: resume the session, but the client advertises no ALPN
         * this time so nothing is negotiated. The server issues a fresh
         * NewSessionTicket for the resumed session; its stored ALPN must be
         * cleared rather than inheriting "goodalpn" from the original session.
         */
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_true(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 1)
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 1)
        && TEST_uint_eq(resumed.c.stats.tickets, 1)
        && TEST_uint_eq(resumed.s.stats.tickets, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_early_data, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_early_data, 0)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.s.stats.ee_has_early_data, 0)
        && TEST_uint_eq(resumed.c.stats.ee_has_early_data, 0)
        && TEST_uint_eq(resumed.s.stats.ee_has_alpn, 0)
        && TEST_uint_eq(resumed.c.stats.ee_has_alpn, 0)
        /* No ALPN was negotiated on the resumption handshake ... */
        && TEST_true(alpn_conn_selected_none(resumed.s.ssl))
        && TEST_true(alpn_conn_selected_none(resumed.c.ssl))
        /* ... so the session written into the new ticket must carry none. */
        && TEST_true(alpn_sess_selected_none(resumed.s.ssl))
        && TEST_true(tls_shutdown(&resumed))
        && TEST_ptr(sess2 = SSL_get1_session(resumed.c.ssl))
        /*
         * Connection 3 is about to resume sess2 and, since 0-RTT is attempted
         * on it, the client will mark sess2 not-resumable once that attempt
         * completes (this happens on any full handshake completed from a
         * resumed session, independent of the server's anti-replay setting --
         * it is a client-side single-use restriction on the SSL_SESSION
         * object itself). Take an independent copy now, while sess2 is still
         * untouched, so connection 4 below has its own unconsumed ticket to
         * resume from.
         */
        && TEST_ptr(sess2b = SSL_SESSION_dup(sess2))
        /*
         * Connection 3: resume the ALPN-cleared ticket from connection 2, but
         * this time negotiate "goodalpn" again -- the same protocol as the
         * original session, purely by coincidence. The ticket being resumed
         * has no ALPN of its own, so 0-RTT must be rejected regardless of
         * this match.
         */
        && TEST_true(tls_channel_init(c, s, &resumed2))
        && TEST_true(alpn_client_offer(resumed2.c.ssl, "goodalpn"))
        && TEST_true(SSL_set_session(resumed2.c.ssl, sess2))
        && TEST_true(SSL_write_early_data(resumed2.c.ssl, m, sizeof(m), &w))
        && TEST_size_t_eq(w, sizeof(m))
        /* The server skips the early data: nothing is delivered to the app. */
        && TEST_int_eq(SSL_read_early_data(resumed2.s.ssl, buf, sizeof(buf), &r),
            SSL_READ_EARLY_DATA_FINISH)
        && TEST_size_t_eq(r, 0)
        && TEST_true(create_ssl_connection(resumed2.s.ssl, resumed2.c.ssl, 0))
        && TEST_true(SSL_session_reused(resumed2.c.ssl))
        && TEST_true(alpn_conn_selected_is(resumed2.s.ssl, "goodalpn"))
        && TEST_true(alpn_conn_selected_is(resumed2.c.ssl, "goodalpn"))
        && TEST_uint_eq(resumed2.s.stats.ee_has_alpn, 1)
        && TEST_uint_eq(resumed2.c.stats.ee_has_alpn, 1)
        && TEST_uint_eq(resumed2.s.stats.ee_has_early_data, 0)
        && TEST_uint_eq(resumed2.c.stats.ee_has_early_data, 0)
        /* Post hoc: the write appeared to succeed, but nothing was accepted. */
        && TEST_int_eq(SSL_get_early_data_status(resumed2.c.ssl),
            SSL_EARLY_DATA_REJECTED)
        && TEST_true(tls_shutdown(&resumed2))
        /*
         * Connection 4: resume the same ticket from connection 2 again, via
         * the untouched copy (sess2b) taken before connection 3 consumed
         * sess2 -- anti-replay is off, so a second use of that ticket is not
         * itself rejected -- but this time advertise no ALPN, matching what
         * the ticket recorded. 0-RTT must be accepted, proving connection 3
         * was rejected for the ALPN mismatch specifically, not because early
         * data never works.
         */
        && TEST_true(tls_channel_init(c, s, &resumed3))
        && TEST_true(SSL_set_session(resumed3.c.ssl, sess2b))
        && TEST_true(SSL_write_early_data(resumed3.c.ssl, m, sizeof(m), &w))
        && TEST_size_t_eq(w, sizeof(m))
        && TEST_int_eq(SSL_read_early_data(resumed3.s.ssl, buf, sizeof(buf), &r),
            SSL_READ_EARLY_DATA_SUCCESS)
        && TEST_mem_eq(buf, r, m, sizeof(m))
        && TEST_int_gt(SSL_connect(resumed3.c.ssl), 0)
        && TEST_int_eq(SSL_read_early_data(resumed3.s.ssl, buf, sizeof(buf), &r),
            SSL_READ_EARLY_DATA_FINISH)
        && TEST_size_t_eq(r, 0)
        && TEST_int_eq(SSL_get_early_data_status(resumed3.s.ssl), SSL_EARLY_DATA_ACCEPTED)
        && TEST_true(create_ssl_connection(resumed3.s.ssl, resumed3.c.ssl, 0))
        && TEST_int_eq(SSL_get_early_data_status(resumed3.c.ssl), SSL_EARLY_DATA_ACCEPTED)
        && TEST_true(SSL_session_reused(resumed3.c.ssl))
        && TEST_true(alpn_conn_selected_none(resumed3.s.ssl))
        && TEST_true(alpn_conn_selected_none(resumed3.c.ssl))
        && TEST_uint_eq(resumed3.s.stats.ee_has_alpn, 0)
        && TEST_uint_eq(resumed3.c.stats.ee_has_alpn, 0);

    SSL_SESSION_free(sess);
    SSL_SESSION_free(sess2);
    SSL_SESSION_free(sess2b);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    tls_channel_fini(&resumed2);
    tls_channel_fini(&resumed3);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    server_alpn = NULL;
    return test;
}

/*
 * TLS 1.3 ALPN mismatch 0-RTT rejection
 *
 * The session negotiated ALPN "goodalpn". On resumption the client still offers
 * "goodalpn" (so it is willing to send early data) alongside "otheralpn", and
 * the server selects "otheralpn" instead. Because the ALPN selected for the
 * resumption handshake differs from the one associated with the ticket, the
 * server must reject 0-RTT while still completing the (resumed) handshake.
 *
 * RFC 8446 4.2.10: In order to accept early data, the server MUST have accepted
 * a PSK cipher suite and selected the first key offered in the client's
 * "pre_shared_key" extension. In addition, it MUST verify that the following
 * values are the same as those associated with the selected PSK: TLS version
 * number, selected cipher suite, and selected ALPN (RFC 7301) protocol, if any.
 */
static int test_tls13_ticket_alpn_mismatch_reject_early_data(void)
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
        && TEST_true(alpn_server_enable(s, "goodalpn"))
        /* Connection 1: negotiate ALPN "goodalpn" and store it in the ticket. */
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(alpn_client_offer(initial.c.ssl, "goodalpn"))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, 0))
        && TEST_true(alpn_conn_selected_is(initial.s.ssl, "goodalpn"))
        && TEST_true(alpn_conn_selected_is(initial.c.ssl, "goodalpn"))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.c.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.s.stats.nst_msgs, 2)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        /*
         * Connection 2: attempt 0-RTT. The client offers "goodalpn" (matching
         * the ticket, so it is willing to send early data) plus "otheralpn";
         * the server selects "otheralpn", which mismatches the ticket's ALPN.
         */
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(alpn_client_offer2(resumed.c.ssl, "goodalpn", "otheralpn"))
        && TEST_true(alpn_server_select("otheralpn"))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(SSL_write_early_data(resumed.c.ssl, m, sizeof(m), &w))
        && TEST_size_t_eq(w, sizeof(m))
        /* The server skips the early data: nothing is delivered to the app. */
        && TEST_int_eq(SSL_read_early_data(resumed.s.ssl, buf, sizeof(buf), &r),
            SSL_READ_EARLY_DATA_FINISH)
        && TEST_size_t_eq(r, 0)
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, 0))
        && TEST_int_eq(SSL_get_early_data_status(resumed.c.ssl),
            SSL_EARLY_DATA_REJECTED)
        /* PSK resumption still succeeds, only 0-RTT is refused. */
        && TEST_true(SSL_session_reused(resumed.c.ssl))
        && TEST_true(alpn_conn_selected_is(resumed.s.ssl, "otheralpn"))
        && TEST_true(alpn_conn_selected_is(resumed.c.ssl, "otheralpn"))
        /* ALPN was negotiated, but the server did not accept early_data. */
        && TEST_uint_eq(resumed.s.stats.ee_has_alpn, 1)
        && TEST_uint_eq(resumed.c.stats.ee_has_alpn, 1)
        && TEST_uint_eq(resumed.s.stats.ee_has_early_data, 0)
        && TEST_uint_eq(resumed.c.stats.ee_has_early_data, 0);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    server_alpn = NULL;
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
 * RFC 8446 4.2.10: When a PSK is used and early data is allowed for that PSK,
 * the client can send Application Data in its first flight of messages. If the
 * client opts to do so, it MUST supply both the "pre_shared_key" and
 * "early_data" extensions. The PSK used to encrypt the early data MUST be the
 * first PSK listed in the client's "pre_shared_key" extension.
 *
 * RFC 8446 4.2.11.1: Clients MUST NOT attempt to use tickets which have ages
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
        && TEST_int_gt((int)SSL_SESSION_set_time_ex(sess, time(NULL) - 10), 0)
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
 * RFC 8446 4.2.10: For PSKs provisioned via NewSessionTicket, a server MUST
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
        && TEST_int_gt((int)SSL_SESSION_set_time_ex(sess, time(NULL) - 10), 0)
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
        && TEST_int_gt((int)SSL_SESSION_set_time_ex(sess, time(NULL) - 10), 0)
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
         * (RFC 8446 4.2.10). Orthogonal to the bug under test, which is about
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
        && TEST_int_gt((int)SSL_SESSION_set_time_ex(sess, time(NULL) - 10), 0)
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
    ADD_TEST(test_tls13_ticket_alpn_cleared);
    ADD_TEST(test_tls13_ticket_alpn_mismatch_reject_early_data);
    ADD_TEST(test_tls13_ticket_early_data_accepted);
    ADD_TEST(test_tls13_ticket_client_age_mismatch_reject_early_data_retry);
    ADD_TEST(test_tls13_ticket_client_age_mismatch_reject_early_data_outer);
    ADD_TEST(test_tls13_ticket_server_age_mismatch_reject_early_data);
    ADD_TEST(test_tls13_aged_ticket_external_psk_early_data);
    ADD_TEST(test_tls13_external_psk_sid_ctx_not_shared);

    return 1;
}
