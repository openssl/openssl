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
#include <openssl/rand.h>
#include <openssl/ssl3.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"

#ifndef OPENSSL_NO_PSK

static const char psk_secret[] = "shared-secret";
static const char psk_identity[] = "identity";

static const unsigned char sid_req[] = {
    0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
};

static const unsigned char sid_res[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04
};

static const struct ciphersuites {
    char *name;
} css[] = {
    { "PSK-AES128-CBC-SHA256" },
    { "PSK-AES256-CBC-SHA384" },
    { "PSK-AES128-GCM-SHA256" },
    { "PSK-AES256-GCM-SHA384" }
};

#define HELLO_RANDOM_OFF 6
#define HELLO_RANDOM_LEN 32
#define HELLO_SID_LEN_OFF (HELLO_RANDOM_OFF + HELLO_RANDOM_LEN)
#define HELLO_SID_OFF (HELLO_SID_LEN_OFF + 1)
#define HELLO_MIN_LEN (HELLO_SID_LEN_OFF + 1)

static void hello_session_id(const unsigned char *p, size_t len)
{
    char *str;
    size_t sid_len;

    if (len < HELLO_MIN_LEN)
        return;

    sid_len = p[HELLO_SID_LEN_OFF];
    if (sid_len == 0 || len < HELLO_SID_OFF + sid_len)
        return;

    str = OPENSSL_buf2hexstr(p + HELLO_SID_OFF, (long)sid_len);
    TEST_info("session_id(%u): <%s>", (unsigned int)sid_len, str);
    OPENSSL_free(str);
}

static void msg_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    const unsigned char *p = buf;

    if (content_type != SSL3_RT_HANDSHAKE || len < 1)
        return;

    switch (p[0]) {
    case SSL3_MT_CLIENT_HELLO:
        TEST_info("%p client_hello", (void *)ssl);
        hello_session_id(p, len);
        break;

    case SSL3_MT_SERVER_HELLO:
        TEST_info("%p server_hello", (void *)ssl);
        hello_session_id(p, len);
        break;
    }
}

static void handshake_finished(const SSL *ssl)
{
    const char *endpoint = SSL_is_server(ssl) ? "server" : "client";
    unsigned int has_ticket = SSL_SESSION_has_ticket(SSL_get_session(ssl));

    if (SSL_session_reused(ssl))
        TEST_info("%s: Abbreviated handshake finished", endpoint);
    else
        TEST_info("%s: Full handshake finished", endpoint);

    TEST_info("%s: has_ticket: %u", endpoint, has_ticket);
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

static unsigned int server_psk_cb(SSL *ssl, const char *identity,
    unsigned char *psk, unsigned int max)
{
    if (max < (sizeof(psk_secret) - 1))
        return 0;
    memcpy(psk, psk_secret, (sizeof(psk_secret) - 1));
    return (unsigned int)(sizeof(psk_secret) - 1);
}

static unsigned int client_psk_cb(SSL *ssl, const char *hint,
    char *identity, unsigned int max_id,
    unsigned char *psk, unsigned int max)
{
    if (max < (sizeof(psk_secret) - 1) || max_id < sizeof(psk_identity))
        return 0;
    strncpy(identity, psk_identity, max_id);
    memcpy(psk, psk_secret, (sizeof(psk_secret) - 1));
    return (unsigned int)(sizeof(psk_secret) - 1);
}

static SSL_SESSION *dup_session_with_id(SSL_SESSION *src,
    const unsigned char *new_id,
    unsigned int new_id_len)
{
    SSL_SESSION *dst = NULL;
    unsigned char *data = NULL;
    const unsigned char *p;
    long data_len;

    data_len = i2d_SSL_SESSION(src, &data);
    if (!TEST_long_gt(data_len, 0))
        return NULL;
    p = data;
    dst = d2i_SSL_SESSION(NULL, &p, data_len);
    OPENSSL_free(data);
    if (!TEST_ptr(dst))
        return NULL;
    if (!TEST_true(SSL_SESSION_set1_id(dst, new_id, new_id_len))) {
        SSL_SESSION_free(dst);
        return NULL;
    }
    return dst;
}

static SSL_SESSION *sess_cache;
static SSL_SESSION *get_sess_cb(SSL *ssl, const unsigned char *id, int len, int *copy)
{
    *copy = 1;

    if (sess_cache != NULL) {
        char *str;
        const unsigned char *sid;
        unsigned int sid_len;

        sid = SSL_SESSION_get_id(sess_cache, &sid_len);
        str = OPENSSL_buf2hexstr(sid, sid_len);
        TEST_info("(cached) session_id: <%s>", str);
        OPENSSL_free(str);
    }
    return sess_cache;
}

static int ctx_set_cache(SSL_CTX *s_ctx, SSL_CTX *c_ctx)
{
    SSL_CTX_set_psk_server_callback(s_ctx, server_psk_cb);
    SSL_CTX_set_psk_client_callback(c_ctx, client_psk_cb);
    SSL_CTX_set_session_cache_mode(s_ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_session_cache_mode(c_ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_set_options(s_ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_verify(c_ctx, SSL_VERIFY_NONE, NULL);
    return 1;
}

static int ctx_set_ticket(SSL_CTX *s_ctx, SSL_CTX *c_ctx)
{
    SSL_CTX_set_psk_server_callback(s_ctx, server_psk_cb);
    SSL_CTX_set_psk_client_callback(c_ctx, client_psk_cb);
    SSL_CTX_set_session_cache_mode(s_ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_session_cache_mode(c_ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_set_verify(c_ctx, SSL_VERIFY_NONE, NULL);
    return 1;
}

static int set_shutdown(SSL *c, SSL *s)
{
    SSL_set_shutdown(c, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_set_shutdown(s, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    return 1;
}

static int set_server_cache(SSL_CTX *s_ctx)
{
    unsigned int v = SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL_STORE;
    SSL_CTX_sess_set_get_cb(s_ctx, get_sess_cb);
    SSL_CTX_set_session_cache_mode(s_ctx, v);
    return 1;
}

static int set_callbacks(SSL *c, SSL *s)
{
    SSL_set_msg_callback(c, msg_cb);
    SSL_set_info_callback(c, info_cb);
    SSL_set_msg_callback(s, msg_cb);
    SSL_set_info_callback(s, info_cb);
    return 1;
}

static int ctx_enforce_tls12(SSL_CTX *s_ctx, SSL_CTX *c_ctx)
{
    int test;
    test = TEST_true(SSL_CTX_set_min_proto_version(s_ctx, TLS1_2_VERSION))
        && TEST_true(SSL_CTX_set_max_proto_version(s_ctx, TLS1_2_VERSION))
        && TEST_true(SSL_CTX_set_min_proto_version(c_ctx, TLS1_2_VERSION))
        && TEST_true(SSL_CTX_set_max_proto_version(c_ctx, TLS1_2_VERSION));

    return test;
}

static int sessid_matches(SSL *c, SSL *s)
{
    const unsigned char *c_sid, *s_sid;
    unsigned int c_len, s_len;
    int test;

    test = TEST_ptr(c_sid = SSL_SESSION_get_id(SSL_get0_session(c), &c_len))
        && TEST_ptr(s_sid = SSL_SESSION_get_id(SSL_get0_session(s), &s_len))
        && TEST_uint_eq(c_len, s_len) && TEST_mem_eq(c_sid, c_len, s_sid, s_len);

    return test;
}

/*
 * The session ID stored in an SSL_SESSION is assigned by the server at the
 * end of the original full handshake and never modified afterwards. The
 * client-supplied session ID in ClientHello is copied verbatim from the
 * session the client cached after that same handshake. If both sides behaved
 * correctly, the two values are guaranteed to be identical.
 *
 * This Explicit comparison inside ssl_get_prev_session() between the session ID
 * the client offered in ClientHello and the session ID embedded in the
 * SSL_SESSION returned by the external cache. If they do not match, the cached
 * session is released and ssl_get_prev_session() returns a cache miss, forcing
 * a full handshake. Catching the mismatch here ensures the server never
 * sends a ServerHello that claims resumption of a session ID it cannot
 * legitimately echo.
 *
 * A mismatch unambiguously indicates one of:
 *   - a corrupt cache entry
 *   - an external cache implementation that returned the wrong session
 *   - an active tampering attempt
 *
 * In all three cases, refusing resumption and falling back to a full
 * handshake is the correct response.
 */

static int test_tls12_psk_resume_sessid_mismatch(int idx)
{
    const struct ciphersuites *cs = &css[idx];
    SSL_CTX *s_ctx = NULL, *c_ctx = NULL;
    SSL *s_ssl = NULL, *c_ssl = NULL, *s = NULL, *c = NULL;
    SSL_SESSION *sess = NULL, *r_sess = NULL;
    const unsigned char *sid;
    unsigned int sid_len;
    int test;

    sess_cache = NULL;

    test = TEST_ptr(s_ctx = SSL_CTX_new(TLS_server_method()))
        && TEST_ptr(c_ctx = SSL_CTX_new(TLS_client_method()))
        && TEST_true(ctx_enforce_tls12(s_ctx, c_ctx))
        && TEST_true(SSL_CTX_set_cipher_list(s_ctx, cs->name))
        && TEST_true(SSL_CTX_set_cipher_list(c_ctx, cs->name))
        && TEST_true(ctx_set_cache(s_ctx, c_ctx))
        && TEST_true(create_ssl_objects(s_ctx, c_ctx, &s, &c, NULL, NULL))
        && TEST_true(set_callbacks(c, s))
        && TEST_true(create_ssl_connection(s, c, SSL_ERROR_NONE))
        && TEST_ptr(sess = SSL_get1_session(c))
        && TEST_true(set_shutdown(c, s))
        && TEST_ptr(sid = SSL_SESSION_get_id(sess, &sid_len))
        && TEST_uint_eq(sid_len, 32)
        && TEST_ptr(r_sess = dup_session_with_id(sess, sid_req, sizeof(sid_req)))
        && TEST_ptr(sess_cache = sess)
        && TEST_true(set_server_cache(s_ctx))
        && TEST_true(create_ssl_objects(s_ctx, c_ctx, &s_ssl, &c_ssl, NULL, NULL))
        && TEST_true(set_callbacks(c_ssl, s_ssl))
        && TEST_true(SSL_set_session(c_ssl, r_sess))
        && TEST_true(create_ssl_connection(s_ssl, c_ssl, SSL_ERROR_NONE))
        && TEST_false(SSL_session_reused(s_ssl));

    sess_cache = NULL;
    SSL_free(s_ssl);
    SSL_free(c_ssl);
    SSL_SESSION_free(r_sess);
    SSL_SESSION_free(sess);
    SSL_CTX_free(s_ctx);
    SSL_CTX_free(c_ctx);
    SSL_free(s);
    SSL_free(c);
    return test;
}

/*
 * RFC 5077 3.4 requires the server to echo the session ID from ClientHello
 * in the ServerHello when accepting a session ticket. Some clients rely on
 * this echo to confirm that resumption succeeded. The ticket decryption path
 * in tls_decrypt_ticket() guarantees the restored SSL_SESSION carries the
 * correct session ID, so tls_construct_server_hello() will echo it correctly.
 * If the session ID is empty, its length is set to zero as required by the
 * RFC.
 */
static int test_tls12_psk_resume_ticket_mismatch(int idx)
{
    const struct ciphersuites *cs = &css[idx];
    SSL_CTX *s_ctx = NULL, *c_ctx = NULL;
    SSL *s_ssl = NULL, *c_ssl = NULL, *s = NULL, *c = NULL;
    SSL_SESSION *c_sess = NULL, *r_sess = NULL, *q_sess = NULL, *s_sess = NULL;
    int test;

    test = TEST_ptr(s_ctx = SSL_CTX_new(TLS_server_method()))
        && TEST_ptr(c_ctx = SSL_CTX_new(TLS_client_method()))
        && TEST_true(ctx_enforce_tls12(s_ctx, c_ctx))
        && TEST_true(SSL_CTX_set_cipher_list(s_ctx, cs->name))
        && TEST_true(SSL_CTX_set_cipher_list(c_ctx, cs->name))
        && TEST_true(ctx_set_ticket(s_ctx, c_ctx))
        && TEST_true(create_ssl_objects(s_ctx, c_ctx, &s, &c, NULL, NULL))
        && TEST_true(set_callbacks(c, s))
        && TEST_true(create_ssl_connection(s, c, SSL_ERROR_NONE))
        && TEST_ptr(c_sess = SSL_get1_session(c))
        && TEST_ptr(s_sess = SSL_get1_session(s))
        && TEST_true(SSL_SESSION_has_ticket(c_sess))
        && TEST_int_eq(set_shutdown(c, s), 1)
        && TEST_ptr(r_sess = dup_session_with_id(c_sess, sid_req, sizeof(sid_req)))
        && TEST_ptr(q_sess = dup_session_with_id(s_sess, sid_res, sizeof(sid_res)))
        && TEST_true(create_ssl_objects(s_ctx, c_ctx, &s_ssl, &c_ssl, NULL, NULL))
        && TEST_true(set_callbacks(c_ssl, s_ssl))
        && TEST_true(SSL_set_session(c_ssl, r_sess))
        && TEST_true(SSL_set_session(s_ssl, q_sess))
        && TEST_true(create_ssl_connection(s_ssl, c_ssl, SSL_ERROR_NONE))
        && TEST_true(SSL_session_reused(s_ssl))
        && TEST_true(sessid_matches(c_ssl, s_ssl));

    SSL_free(s_ssl);
    SSL_free(c_ssl);
    SSL_SESSION_free(r_sess);
    SSL_SESSION_free(q_sess);
    SSL_SESSION_free(c_sess);
    SSL_SESSION_free(s_sess);
    SSL_CTX_free(s_ctx);
    SSL_CTX_free(c_ctx);
    SSL_free(s);
    SSL_free(c);
    return test;
}

#endif

OPT_TEST_DECLARE_USAGE("\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

#ifndef OPENSSL_NO_PSK
    ADD_ALL_TESTS(test_tls12_psk_resume_sessid_mismatch, OSSL_NELEM(css));
    ADD_ALL_TESTS(test_tls12_psk_resume_ticket_mismatch, OSSL_NELEM(css));
#endif
    return 1;
}
