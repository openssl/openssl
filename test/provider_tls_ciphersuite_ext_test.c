/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "../ssl/statem/statem_local.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"
#include "threadstest.h"

#include "helpers/tls_provider.h"

#define PROV_SHA256_NAME "TLS_TEST_PROVIDER_AES_128_GCM_SHA256"
#define PROV_SHA384_NAME "TLS_TEST_PROVIDER_AES_256_GCM_SHA384"
#define BUILTIN_SHA256_NAME "TLS_AES_128_GCM_SHA256"
#define BUILTIN_SHA384_NAME "TLS_AES_256_GCM_SHA384"
#define PROV_SHA256_CP 0xffa0U
#define PROV_SHA384_CP 0xffa2U

static OSSL_LIB_CTX *libctx;
static OSSL_PROVIDER *defprov, *tlsprov;
static char *cert, *privkey;

typedef struct {
    const char *provname;
    const char *builtinname;
    unsigned int codepoint;
    size_t mdsize;
} SUITE_VARIANT;

static const SUITE_VARIANT variants[] = {
    { PROV_SHA256_NAME, BUILTIN_SHA256_NAME, PROV_SHA256_CP,
        SHA256_DIGEST_LENGTH },
    { PROV_SHA384_NAME, BUILTIN_SHA384_NAME, PROV_SHA384_CP,
        SHA384_DIGEST_LENGTH }
};

static int nst_written, server_hellos;

static void wire_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    const unsigned char *m = buf;

    if (content_type != SSL3_RT_HANDSHAKE || len == 0)
        return;
    if (m[0] == SSL3_MT_NEWSESSION_TICKET && write_p)
        nst_written++;
    if (m[0] == SSL3_MT_SERVER_HELLO && !write_p)
        server_hellos++;
}

static void reset_counters(void)
{
    nst_written = server_hellos = 0;
}

static SSL_SESSION *captured_session;
static SSL_SESSION *captured_server_session;
static SSL_SESSION *external_cache_session;
static int session_dup_index, client_session_dups, server_session_dups;

static int count_session_dup(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
    void **from_data, int idx, long argl, void *argp)
{
    if (*from_data != NULL)
        ++*(int *)*from_data;
    return 1;
}

static int capture_session_cb(SSL *ssl, SSL_SESSION *sess)
{
    SSL_SESSION_free(captured_session);
    captured_session = sess;
    return 1;
}

static int capture_server_session_cb(SSL *ssl, SSL_SESSION *sess)
{
    SSL_SESSION_free(captured_server_session);
    captured_server_session = sess;
    return 1;
}

static SSL_SESSION *external_cache_cb(ossl_unused SSL *ssl,
    ossl_unused const unsigned char *id, ossl_unused int idlen, int *copy)
{
    *copy = 1;
    return external_cache_session;
}

static int make_pair(const char *sciph, const char *cciph, char *scert,
    char *skey, SSL_CTX **sctx, SSL_CTX **cctx)
{
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            sctx, cctx, scert, skey)))
        return 0;
    return TEST_true(SSL_CTX_set_ciphersuites(*sctx, sciph))
        && TEST_true(SSL_CTX_set_ciphersuites(*cctx, cciph));
}

static int exchange_data(SSL *a, SSL *b, const unsigned char *msg, size_t len)
{
    unsigned char *buf = OPENSSL_malloc(len);
    size_t written = 0, readbytes = 0, total = 0;
    int ret = 0;

    if (!TEST_ptr(buf))
        return 0;
    if (!TEST_true(SSL_write_ex(a, msg, len, &written))
        || !TEST_size_t_eq(written, len))
        goto end;
    while (total < len) {
        if (!TEST_true(SSL_read_ex(b, buf + total, len - total, &readbytes))
            || !TEST_size_t_gt(readbytes, 0))
            goto end;
        total += readbytes;
    }
    ret = TEST_mem_eq(buf, total, msg, len);
end:
    OPENSSL_free(buf);
    return ret;
}

static int check_negotiated(SSL *serverssl, SSL *clientssl, unsigned int cp,
    int expect_origin)
{
    const SSL_CIPHER *sc = SSL_get_current_cipher(serverssl);
    const SSL_CIPHER *cc = SSL_get_current_cipher(clientssl);
    static const unsigned char msg[] = "provider ciphersuite ext";

    return TEST_ptr(sc) && TEST_ptr(cc)
        && TEST_uint_eq(SSL_CIPHER_get_protocol_id(sc), cp)
        && TEST_uint_eq(SSL_CIPHER_get_protocol_id(cc), cp)
        && TEST_int_eq(sc->origin, expect_origin)
        && TEST_int_eq(cc->origin, expect_origin)
        && exchange_data(clientssl, serverssl, msg, sizeof(msg))
        && exchange_data(serverssl, clientssl, msg, sizeof(msg));
}

/* Built-in resumption must not acquire the provider-transition session copies. */
static int test_builtin_resumption_copies(int stateful)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_SESSION *sess = NULL, *cached = NULL;
    static const unsigned char msg[] = "resumed";
    int ret = 0;

    if (!make_pair(BUILTIN_SHA256_NAME, BUILTIN_SHA256_NAME, cert, privkey,
            &sctx, &cctx)
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 1)))
        goto end;
    if (stateful)
        SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    SSL_CTX_sess_set_new_cb(sctx, capture_server_session_cb);
    SSL_CTX_set_session_cache_mode(cctx,
        SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(cctx, capture_session_cb);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_false(SSL_session_reused(clientssl))
        || !TEST_ptr(captured_session)
        || !TEST_true(SSL_SESSION_is_resumable(captured_session)))
        goto end;
    sess = captured_session;
    captured_session = NULL;
    cached = captured_server_session;
    captured_server_session = NULL;
    shutdown_ssl_connection(serverssl, clientssl);
    serverssl = clientssl = NULL;

    if (!TEST_true(SSL_SESSION_set_ex_data(sess, session_dup_index,
            &client_session_dups))
        || (stateful
            && (!TEST_ptr(cached)
                || !TEST_true(SSL_SESSION_set_ex_data(cached, session_dup_index,
                    &server_session_dups)))))
        goto end;
    client_session_dups = server_session_dups = 0;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(SSL_set_session(clientssl, sess))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_true(SSL_session_reused(serverssl))
        || !TEST_true(SSL_session_reused(clientssl))
        || !exchange_data(serverssl, clientssl, msg, sizeof(msg)))
        goto end;

    /* Upstream copies once per peer when issuing/receiving the new ticket. */
    ret = TEST_int_eq(client_session_dups, 1);
    if (stateful)
        ret &= TEST_int_eq(server_session_dups, 1);
end:
    SSL_SESSION_free(sess);
    SSL_SESSION_free(cached);
    SSL_SESSION_free(captured_session);
    captured_session = NULL;
    SSL_SESSION_free(captured_server_session);
    captured_server_session = NULL;
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ret;
}

static int test_resume_into_provider_suite(int idx)
{
    const SUITE_VARIANT *v = &variants[idx & 1];
    int with_hrr = (idx & 2) != 0;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_SESSION *sess = NULL, *after = NULL;
    char both[128];
    int ret = 0;

#if defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH)
    if (with_hrr)
        return TEST_skip("EC and DH are disabled");
#endif /* defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH) */

    snprintf(both, sizeof(both), "%s:%s", v->provname, v->builtinname);

    /* First handshake: built-in suite only, obtain a ticket. */
    if (!make_pair(v->builtinname, v->builtinname, cert, privkey,
            &sctx, &cctx))
        goto end;
    SSL_CTX_set_session_cache_mode(cctx,
        SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(cctx, capture_session_cb);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(captured_session)
        || !TEST_true(SSL_SESSION_is_resumable(captured_session)))
        goto end;
    sess = captured_session;
    captured_session = NULL;
    /* A clean shutdown; SSL_free() without it marks the session unusable. */
    shutdown_ssl_connection(serverssl, clientssl);
    serverssl = clientssl = NULL;

    /*
     * Second handshake: server prefers the provider suite (same transcript
     * hash), client offers the PSK from the built-in session. RFC 8446
     * section 4.2.11 permits the switch.
     */
    if (!TEST_true(SSL_CTX_set_ciphersuites(sctx, both))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, both)))
        goto end;
    SSL_CTX_set_options(sctx, SSL_OP_SERVER_PREFERENCE);
    if (with_hrr
#if !defined(OPENSSL_NO_EC)
        && (!TEST_true(SSL_CTX_set1_groups_list(cctx,
                "secp521r1:secp384r1:prime256v1"))
            || !TEST_true(SSL_CTX_set1_groups_list(sctx,
                "prime256v1:secp384r1"))))
#else
        && (!TEST_true(SSL_CTX_set1_groups_list(cctx,
                "ffdhe2048:ffdhe3072"))
            || !TEST_true(SSL_CTX_set1_groups_list(sctx, "ffdhe3072"))))
#endif /* !defined(OPENSSL_NO_EC) */
        goto end;
    reset_counters();
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(SSL_set_session(clientssl, sess)))
        goto end;
    SSL_set_msg_callback(clientssl, wire_cb);
    SSL_set_msg_callback(serverssl, wire_cb);
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_int_eq(server_hellos, with_hrr ? 2 : 1)
        || !TEST_true(SSL_session_reused(serverssl))
        || !TEST_true(SSL_session_reused(clientssl))
        || !check_negotiated(serverssl, clientssl, v->codepoint,
            SSL_CIPHER_ORIGIN_PROVIDER)
        /* No NewSessionTicket may be issued on a provider-suite connection */
        || !TEST_int_eq(nst_written, 0)
        || !TEST_ptr(after = SSL_get1_session(clientssl))
        || !TEST_false(SSL_SESSION_is_resumable(after))
        || !TEST_int_eq(SSL_SESSION_get0_cipher(after)->origin,
            SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_int_eq(SSL_SESSION_get0_cipher(sess)->origin,
            SSL_CIPHER_ORIGIN_STATIC)
        || !TEST_false(sess->provider_cipher_seen)
        || !TEST_true(SSL_SESSION_is_resumable(sess)))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(after);
    SSL_SESSION_free(sess);
    SSL_SESSION_free(captured_session);
    captured_session = NULL;
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
}

static int test_stateful_cache_provider_transition(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_SESSION *sess = NULL, *replay = NULL, *cached = NULL, *after = NULL;
    char both[128];
    int ret = 0;

    snprintf(both, sizeof(both), "%s:%s", PROV_SHA256_NAME,
        BUILTIN_SHA256_NAME);
    if (!make_pair(BUILTIN_SHA256_NAME, BUILTIN_SHA256_NAME,
            cert, privkey, &sctx, &cctx))
        goto end;
    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    SSL_CTX_sess_set_new_cb(sctx, capture_server_session_cb);
    SSL_CTX_set_session_cache_mode(cctx,
        SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(cctx, capture_session_cb);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(captured_session)
        || !TEST_ptr(captured_server_session)
        || !TEST_ptr(replay = SSL_SESSION_dup(captured_session)))
        goto end;
    sess = captured_session;
    captured_session = NULL;
    cached = captured_server_session;
    captured_server_session = NULL;
    if (!TEST_int_eq(cached->cipher->origin, SSL_CIPHER_ORIGIN_STATIC)
        || !TEST_false(cached->provider_cipher_seen))
        goto end;
    shutdown_ssl_connection(serverssl, clientssl);
    serverssl = clientssl = NULL;

    if (!TEST_true(SSL_CTX_set_ciphersuites(sctx, both))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, both)))
        goto end;
    SSL_CTX_set_options(sctx, SSL_OP_SERVER_PREFERENCE);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(SSL_set_session(clientssl, sess))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_true(SSL_session_reused(serverssl))
        || !TEST_true(SSL_session_reused(clientssl))
        || !TEST_ptr(after = SSL_get1_session(clientssl))
        || !TEST_false(SSL_SESSION_is_resumable(after))
        || !TEST_int_eq(SSL_SESSION_get0_cipher(after)->origin,
            SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_int_eq(SSL_get_current_cipher(serverssl)->origin,
            SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_int_eq(cached->cipher->origin, SSL_CIPHER_ORIGIN_STATIC)
        || !TEST_false(cached->provider_cipher_seen))
        goto end;
    shutdown_ssl_connection(serverssl, clientssl);
    serverssl = clientssl = NULL;
    SSL_SESSION_free(after);
    after = NULL;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(SSL_set_session(clientssl, replay))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_true(SSL_session_reused(serverssl))
        || !TEST_true(SSL_session_reused(clientssl))
        || !TEST_ptr(after = SSL_get1_session(clientssl))
        || !TEST_false(SSL_SESSION_is_resumable(after))
        || !TEST_int_eq(SSL_SESSION_get0_cipher(after)->origin,
            SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_int_eq(SSL_get_current_cipher(serverssl)->origin,
            SSL_CIPHER_ORIGIN_PROVIDER))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(after);
    SSL_SESSION_free(cached);
    SSL_SESSION_free(replay);
    SSL_SESSION_free(sess);
    SSL_SESSION_free(captured_session);
    captured_session = NULL;
    SSL_SESSION_free(captured_server_session);
    captured_server_session = NULL;
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
}

static int test_external_cache_rejects_provider_session(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_SESSION *marked = NULL, *dup = NULL, *found;
    const SSL_CIPHER *suite;
    static const unsigned char id[] = { 1 };
    int ret = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_ptr(suite = ossl_ssl_get0_provider_cipher_by_name(ctx,
                         PROV_SHA256_NAME))
        || !TEST_ptr(marked = SSL_SESSION_new())
        || !TEST_true(ossl_ssl_session_set1_cipher(marked, suite))
        || !TEST_ptr(dup = ssl_session_dup(marked, 0))
        || !TEST_true(dup->provider_cipher_seen)
        || !TEST_false(dup->not_resumable)
        || !TEST_ptr(ssl = SSL_new(ctx)))
        goto end;
    external_cache_session = dup;
    SSL_CTX_set_session_cache_mode(ctx,
        SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL_LOOKUP);
    SSL_CTX_sess_set_get_cb(ctx, external_cache_cb);
    found = lookup_sess_in_cache(SSL_CONNECTION_FROM_SSL(ssl), id,
        sizeof(id));
    if (!TEST_ptr_null(found)) {
        SSL_SESSION_free(found);
        goto end;
    }

    ret = 1;
end:
    external_cache_session = NULL;
    SSL_SESSION_free(dup);
    SSL_SESSION_free(marked);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return ret;
}

static int test_public_provider_cipher_assignment_rejected(void)
{
    static const unsigned char builtin_id[] = { 0x13, 0x01 };
    static const unsigned char session_id[] = { 0x51 };
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_SESSION *session = NULL;
    const SSL_CIPHER *suite, *builtin;
    unsigned long err;
    int ret = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_ptr(ssl = SSL_new(ctx))
        || !TEST_ptr(suite = ossl_ssl_get0_provider_cipher_by_name(ctx,
                         PROV_SHA256_NAME))
        || !TEST_ptr(builtin = SSL_CIPHER_find(ssl, builtin_id))
        || !TEST_ptr(session = SSL_SESSION_new())
        || !TEST_true(SSL_SESSION_set_cipher(session, builtin))
        || !TEST_true(SSL_SESSION_set_protocol_version(session,
            TLS1_3_VERSION))
        || !TEST_true(SSL_SESSION_set1_id(session, session_id,
            sizeof(session_id)))
        || !TEST_true(SSL_CTX_add_session(ctx, session))
        || !TEST_long_eq(SSL_CTX_sess_number(ctx), 1)
        || !TEST_true(SSL_SESSION_is_resumable(session)))
        goto end;

    ERR_clear_error();
    if (!TEST_false(SSL_SESSION_set_cipher(session, suite)))
        goto end;
    err = ERR_peek_last_error();
    if (!TEST_int_eq(ERR_GET_LIB(err), ERR_LIB_SSL)
        || !TEST_int_eq(ERR_GET_REASON(err),
            SSL_R_PROVIDER_CIPHERSUITE_SESSION_UNSUPPORTED)
        || !TEST_ptr_eq(SSL_SESSION_get0_cipher(session), builtin)
        || !TEST_false(session->provider_cipher_seen)
        || !TEST_true(SSL_SESSION_is_resumable(session))
        || !TEST_long_eq(SSL_CTX_sess_number(ctx), 1))
        goto end;

    ret = 1;
end:
    if (ctx != NULL && session != NULL)
        SSL_CTX_remove_session(ctx, session);
    SSL_SESSION_free(session);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return ret;
}

static SSL_SESSION *clientpsk, *serverpsk;
static const char pskid[] = "provider-psk-identity";

static int use_session_cb(SSL *ssl, const EVP_MD *md, const unsigned char **id,
    size_t *idlen, SSL_SESSION **sess)
{
    if (clientpsk == NULL || !SSL_SESSION_up_ref(clientpsk))
        return 0;
    *sess = clientpsk;
    *id = (const unsigned char *)pskid;
    *idlen = strlen(pskid);
    return 1;
}

static int find_session_cb(SSL *ssl, const unsigned char *identity,
    size_t identity_len, SSL_SESSION **sess)
{
    *sess = NULL;
    if (identity_len != strlen(pskid)
        || memcmp(identity, pskid, identity_len) != 0)
        return 1;
    if (serverpsk == NULL || !SSL_SESSION_up_ref(serverpsk))
        return 0;
    *sess = serverpsk;
    return 1;
}

static SSL_SESSION *make_psk(SSL *ssl, unsigned int codepoint, size_t mdsize,
    int origin, uint32_t max_early)
{
    static const unsigned char key[SHA384_DIGEST_LENGTH] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f
    };
    unsigned char wire[2] = { (unsigned char)(codepoint >> 8),
        (unsigned char)codepoint };
    const SSL_CIPHER *cipher = SSL_CIPHER_find(ssl, wire);
    SSL_SESSION *sess = SSL_SESSION_new();
    int cipher_set;

    if (!TEST_ptr(cipher) || !TEST_ptr(sess)) {
        SSL_SESSION_free(sess);
        return NULL;
    }
    cipher_set = origin == SSL_CIPHER_ORIGIN_PROVIDER
        ? ossl_ssl_session_set1_cipher(sess, cipher)
        : SSL_SESSION_set_cipher(sess, cipher);

    if (!TEST_int_eq(cipher->origin, origin)
        || !TEST_true(SSL_SESSION_set1_master_key(sess, key, mdsize))
        || !TEST_true(cipher_set)
        || !TEST_true(SSL_SESSION_set_protocol_version(sess, TLS1_3_VERSION))
        || !TEST_true(SSL_SESSION_set_max_early_data(sess, max_early))) {
        SSL_SESSION_free(sess);
        return NULL;
    }
    return sess;
}

static SSL_SESSION *make_provider_psk(SSL *ssl, const SUITE_VARIANT *v,
    uint32_t max_early)
{
    return make_psk(ssl, v->codepoint, v->mdsize,
        SSL_CIPHER_ORIGIN_PROVIDER, max_early);
}

static SSL_SESSION *make_builtin_psk(SSL *ssl, const SUITE_VARIANT *v)
{
    unsigned int codepoint = v->mdsize == SHA256_DIGEST_LENGTH ? 0x1301U
                                                               : 0x1302U;

    return make_psk(ssl, codepoint, v->mdsize, SSL_CIPHER_ORIGIN_STATIC, 0);
}

static int test_builtin_external_psk_into_provider_suite(void)
{
    const SUITE_VARIANT *v = &variants[0];
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_SESSION *after = NULL;
    int ret = 0;

    if (!make_pair(v->provname, v->provname, cert, privkey,
            &sctx, &cctx))
        goto end;
    SSL_CTX_set_psk_use_session_callback(cctx, use_session_cb);
    SSL_CTX_set_psk_find_session_callback(sctx, find_session_cb);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_ptr(clientpsk = make_builtin_psk(clientssl, v))
        || !TEST_ptr(serverpsk = make_builtin_psk(serverssl, v))
        || !TEST_true(SSL_SESSION_set_ex_data(clientpsk, session_dup_index,
            &client_session_dups))
        || !TEST_true(SSL_SESSION_set_ex_data(serverpsk, session_dup_index,
            &server_session_dups)))
        goto end;

    client_session_dups = server_session_dups = 0;
    reset_counters();
    SSL_set_msg_callback(clientssl, wire_cb);
    SSL_set_msg_callback(serverssl, wire_cb);
    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_true(SSL_session_reused(serverssl))
        || !TEST_true(SSL_session_reused(clientssl))
        || !TEST_ptr_null(SSL_get0_peer_certificate(clientssl))
        || !check_negotiated(serverssl, clientssl, v->codepoint,
            SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_int_eq(nst_written, 0)
        || !TEST_ptr(after = SSL_get1_session(clientssl))
        || !TEST_false(SSL_SESSION_is_resumable(after))
        || !TEST_int_eq(SSL_SESSION_get0_cipher(after)->origin,
            SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_int_eq(SSL_SESSION_get0_cipher(clientpsk)->origin,
            SSL_CIPHER_ORIGIN_STATIC)
        || !TEST_int_eq(SSL_SESSION_get0_cipher(serverpsk)->origin,
            SSL_CIPHER_ORIGIN_STATIC)
        || !TEST_false(clientpsk->provider_cipher_seen)
        || !TEST_false(serverpsk->provider_cipher_seen)
        /* The client also copies to record the newly negotiated key-share group. */
        || !TEST_int_eq(client_session_dups, 2)
        || !TEST_int_eq(server_session_dups, 1))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(after);
    SSL_SESSION_free(clientpsk);
    SSL_SESSION_free(serverpsk);
    clientpsk = serverpsk = NULL;
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
}

static int test_provider_external_psk_rejected(int idx)
{
    const SUITE_VARIANT *v = &variants[idx];
    SSL_CTX *ctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    SSL_CONNECTION *sc;
    WPACKET wpkt = { 0 };
    PACKET packet = { 0 };
    unsigned char early_data_ext[16];
    unsigned char psk_ext[2 + 2 + sizeof(pskid) - 1 + 4];
    size_t idlen = sizeof(pskid) - 1;
    int ret = 0, wpkt_init = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_true(SSL_CTX_set_ciphersuites(ctx, v->provname)))
        goto end;
    SSL_CTX_set_psk_use_session_callback(ctx, use_session_cb);
    SSL_CTX_set_psk_find_session_callback(ctx, find_session_cb);
    if (!TEST_ptr(clientssl = SSL_new(ctx))
        || !TEST_ptr(serverssl = SSL_new(ctx))
        || !TEST_ptr(clientpsk = make_provider_psk(clientssl, v, 0)))
        goto end;

    SSL_set_connect_state(clientssl);
    sc = SSL_CONNECTION_FROM_SSL(clientssl);
    if (!TEST_true(WPACKET_init_static_len(&wpkt, early_data_ext,
            sizeof(early_data_ext), 0)))
        goto end;
    wpkt_init = 1;
    ERR_clear_error();
    if (!TEST_int_eq(tls_construct_ctos_early_data(sc, &wpkt,
                         SSL_EXT_CLIENT_HELLO, NULL, 0),
            EXT_RETURN_FAIL)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()), SSL_R_BAD_PSK))
        goto end;
    WPACKET_cleanup(&wpkt);
    wpkt_init = 0;

    SSL_SESSION_free(clientpsk);
    clientpsk = make_builtin_psk(clientssl, v);
    if (!TEST_ptr(clientpsk)
        || !TEST_ptr(serverpsk = make_provider_psk(serverssl, v, 0))
        || !TEST_true(SSL_SESSION_set_cipher(serverpsk,
            SSL_SESSION_get0_cipher(clientpsk)))
        || !TEST_true(serverpsk->provider_cipher_seen))
        goto end;

    if (!TEST_true(WPACKET_init_static_len(&wpkt, early_data_ext,
            sizeof(early_data_ext), 0)))
        goto end;
    wpkt_init = 1;
    if (!TEST_int_eq(tls_construct_ctos_early_data(sc, &wpkt,
                         SSL_EXT_CLIENT_HELLO, NULL, 0),
            EXT_RETURN_NOT_SENT))
        goto end;
    WPACKET_cleanup(&wpkt);
    wpkt_init = 0;

    psk_ext[0] = 0;
    psk_ext[1] = (unsigned char)(sizeof(psk_ext) - 2);
    psk_ext[2] = 0;
    psk_ext[3] = (unsigned char)idlen;
    memcpy(psk_ext + 4, pskid, idlen);
    memset(psk_ext + 4 + idlen, 0, 4);
    SSL_set_accept_state(serverssl);
    sc = SSL_CONNECTION_FROM_SSL(serverssl);
    sc->ext.psk_kex_mode = TLSEXT_KEX_MODE_FLAG_KE_DHE;
    if (!TEST_true(PACKET_buf_init(&packet, psk_ext, sizeof(psk_ext))))
        goto end;
    ERR_clear_error();
    if (!TEST_false(tls_parse_ctos_psk(sc, &packet,
            SSL_EXT_CLIENT_HELLO, NULL, 0))
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()), SSL_R_BAD_PSK))
        goto end;

    ret = 1;
end:
    if (wpkt_init)
        WPACKET_cleanup(&wpkt);
    SSL_SESSION_free(clientpsk);
    SSL_SESSION_free(serverpsk);
    clientpsk = serverpsk = NULL;
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return ret;
}

static int sec_min_bits, sec_seen_bits, sec_seen_provider;

static int sec_cb(const SSL *s, const SSL_CTX *ctx, int op, int bits, int nid,
    void *other, void *ex)
{
    const SSL_CIPHER *c = other;

    if (op == SSL_SECOP_CIPHER_SUPPORTED || op == SSL_SECOP_CIPHER_SHARED
        || op == SSL_SECOP_CIPHER_CHECK) {
        if (c != NULL && c->origin == SSL_CIPHER_ORIGIN_PROVIDER) {
            sec_seen_provider++;
            sec_seen_bits = bits;
            if (bits < sec_min_bits)
                return 0;
        }
    }
    return 1;
}

static int test_security_callback(int idx)
{
    const SUITE_VARIANT *v = &variants[idx & 1];
    int veto = (idx & 2) != 0;
    int expect_bits = v->mdsize == SHA384_DIGEST_LENGTH ? 256 : 128;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int ret = 0;

    sec_min_bits = veto ? expect_bits + 1 : expect_bits;
    sec_seen_bits = sec_seen_provider = 0;
    if (!make_pair(v->provname, v->provname, cert, privkey,
            &sctx, &cctx))
        goto end;
    SSL_CTX_set_security_callback(sctx, sec_cb);
    SSL_CTX_set_security_callback(cctx, sec_cb);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;
    if (veto) {
        if (!TEST_false(create_ssl_connection(serverssl, clientssl,
                SSL_ERROR_NONE)))
            goto end;
    } else if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                   SSL_ERROR_NONE))
        || !check_negotiated(serverssl, clientssl, v->codepoint,
            SSL_CIPHER_ORIGIN_PROVIDER)) {
        goto end;
    }
    if (!TEST_int_gt(sec_seen_provider, 0)
        || !TEST_int_eq(sec_seen_bits, expect_bits))
        goto end;

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
}

#define TEST_AEAD_ENCRYPTION_LIMIT 4

static int test_provider_aead_limit_failure(void)
{
    static const unsigned char msg[] = "limit";
    OSSL_LIB_CTX *localctx = NULL;
    OSSL_PROVIDER *localdef = NULL, *localtls = NULL;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    size_t written = 0;
    int i, write_ret, ret = 0;

    if (!TEST_true(tls_provider_libctx_new(&localctx, &localdef, &localtls,
            "tls-provider-limit", "valid-limit", "?provider=tls-provider"))
        || !TEST_true(create_ssl_ctx_pair(localctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, PROV_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, PROV_SHA256_NAME))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE)))
        goto end;

    for (i = 0; i < TEST_AEAD_ENCRYPTION_LIMIT / 2; i++) {
        if (!exchange_data(clientssl, serverssl, msg, sizeof(msg)))
            goto end;
    }

    if (!TEST_true(SSL_key_update(clientssl, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;

    for (i = 0; i < TEST_AEAD_ENCRYPTION_LIMIT; i++) {
        if (!exchange_data(clientssl, serverssl, msg, sizeof(msg)))
            goto end;
    }

    write_ret = SSL_write_ex(clientssl, msg, sizeof(msg), &written);
    if (!TEST_false(write_ret)
        || !TEST_int_eq(SSL_get_error(clientssl, write_ret), SSL_ERROR_SSL))
        goto end;

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    tls_provider_libctx_free(localctx, localdef, localtls);
    ERR_clear_error();
    return ret;
}

static int test_session_outlives_ctx(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_SESSION *sess = NULL, *dup = NULL;
    const SSL_CIPHER *c;
    int ret = 0;

    if (!make_pair(PROV_SHA256_NAME, PROV_SHA256_NAME, cert, privkey,
            &sctx, &cctx)
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(sess = SSL_get1_session(serverssl)))
        goto end;
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    serverssl = clientssl = NULL;
    sctx = cctx = NULL;

    /* The descriptor and its EVP objects must still be alive. */
    if (!TEST_ptr(c = SSL_SESSION_get0_cipher(sess))
        || !TEST_str_eq(SSL_CIPHER_get_name(c), PROV_SHA256_NAME)
        || !TEST_ptr(SSL_CIPHER_get_handshake_digest(c))
        || !TEST_int_gt(EVP_MD_get_size(SSL_CIPHER_get_handshake_digest(c)),
            0)
        || !TEST_ptr(dup = SSL_SESSION_dup(sess))
        || !TEST_ptr_eq(SSL_SESSION_get0_cipher(dup), c)
        || !TEST_false(SSL_SESSION_is_resumable(dup)))
        goto end;
    SSL_SESSION_free(sess);
    sess = NULL;
    if (!TEST_str_eq(SSL_CIPHER_get_name(SSL_SESSION_get0_cipher(dup)),
            PROV_SHA256_NAME))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(dup);
    SSL_SESSION_free(sess);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
}

/*
 * d2i_SSL_SESSION() into an existing session that holds a provider suite
 * must release that reference without clearing unrelated non-resumable state.
 */
static int test_d2i_into_provider_session(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_SESSION *prov = NULL, *builtin = NULL, *reuse = NULL;
    const unsigned char tick[] = { 0x01 };
    unsigned char *der = NULL;
    const unsigned char *p;
    int derlen, ret = 0;

    /* A serialisable built-in session. */
    if (!make_pair(BUILTIN_SHA256_NAME, BUILTIN_SHA256_NAME, cert,
            privkey, &sctx, &cctx)
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(builtin = SSL_get1_session(serverssl))
        || !TEST_int_gt(derlen = i2d_SSL_SESSION(builtin, &der), 0))
        goto end;
    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = clientssl = NULL;

    /* A session holding a provider suite as the d2i target. */
    if (!TEST_true(SSL_CTX_set_ciphersuites(sctx, PROV_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, PROV_SHA256_NAME))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(prov = SSL_get1_session(serverssl))
        || !TEST_int_eq(SSL_SESSION_get0_cipher(prov)->origin,
            SSL_CIPHER_ORIGIN_PROVIDER))
        goto end;
    prov->psk_external = 1;
    OPENSSL_free(prov->ext.tick);
    prov->ext.tick = OPENSSL_memdup(tick, sizeof(tick));
    prov->ext.ticklen = sizeof(tick);
    if (!TEST_ptr(prov->ext.tick))
        goto end;
    p = der;
    if (!TEST_ptr_eq(d2i_SSL_SESSION_ex(&prov, &p, derlen, libctx, NULL), prov)
        || !TEST_int_eq(SSL_SESSION_get0_cipher(prov)->origin,
            SSL_CIPHER_ORIGIN_STATIC)
        || !TEST_false(prov->provider_cipher_seen)
        || !TEST_false(prov->psk_external)
        || !TEST_ptr_null(prov->ext.tick)
        || !TEST_size_t_eq(prov->ext.ticklen, 0)
        || !TEST_true(prov->not_resumable)
        || !TEST_false(SSL_SESSION_is_resumable(prov))
        || !TEST_ptr(reuse = SSL_SESSION_dup(builtin)))
        goto end;

    reuse->not_resumable = 1;
    reuse->psk_external = 1;
    p = der;
    if (!TEST_ptr_eq(d2i_SSL_SESSION_ex(&reuse, &p, derlen, libctx, NULL),
            reuse)
        || !TEST_false(reuse->provider_cipher_seen)
        || !TEST_false(reuse->psk_external)
        || !TEST_true(reuse->not_resumable)
        || !TEST_false(SSL_SESSION_is_resumable(reuse)))
        goto end;

    ret = 1;
end:
    OPENSSL_free(der);
    SSL_SESSION_free(prov);
    SSL_SESSION_free(builtin);
    SSL_SESSION_free(reuse);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
}

static int test_d2i_provider_rollback_mfail(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_SESSION *prov = NULL, *builtin = NULL, *decoded;
    const SSL_CIPHER *provider_cipher = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    int derlen, ret = -1;

    if (!make_pair(BUILTIN_SHA256_NAME, BUILTIN_SHA256_NAME, cert,
            privkey, &sctx, &cctx)
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(builtin = SSL_get1_session(serverssl)))
        goto end;
    OPENSSL_free(builtin->ext.hostname);
    builtin->ext.hostname = OPENSSL_strdup("late-allocation.example");
    if (!TEST_ptr(builtin->ext.hostname)
        || !TEST_int_gt(derlen = i2d_SSL_SESSION(builtin, &der), 0))
        goto end;
    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = clientssl = NULL;

    if (!TEST_true(SSL_CTX_set_ciphersuites(sctx, PROV_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, PROV_SHA256_NAME))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(prov = SSL_get1_session(serverssl))
        || !TEST_ptr(provider_cipher = SSL_SESSION_get0_cipher(prov))
        || !TEST_int_eq(provider_cipher->origin,
            SSL_CIPHER_ORIGIN_PROVIDER))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    serverssl = clientssl = NULL;
    sctx = cctx = NULL;

    p = der;
    MFAIL_start();
    decoded = d2i_SSL_SESSION_ex(&prov, &p, derlen, libctx, NULL);
    MFAIL_end();
    if (decoded == NULL) {
        if (!TEST_ptr_eq(SSL_SESSION_get0_cipher(prov), provider_cipher)
            || !TEST_true(prov->provider_cipher_seen)
            || !TEST_str_eq(SSL_CIPHER_get_name(provider_cipher),
                PROV_SHA256_NAME))
            goto end;
    } else if (!TEST_ptr_eq(decoded, prov)
        || !TEST_int_eq(SSL_SESSION_get0_cipher(prov)->origin,
            SSL_CIPHER_ORIGIN_STATIC)
        || !TEST_false(prov->provider_cipher_seen)) {
        goto end;
    }

    ret = 1;
end:
    OPENSSL_free(der);
    SSL_SESSION_free(prov);
    SSL_SESSION_free(builtin);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
}

static int test_multiple_providers_collide(void)
{
    OSSL_LIB_CTX *localctx = NULL;
    OSSL_PROVIDER *localdef = NULL, *second = NULL, *third = NULL;
    SSL_CTX *ctx = NULL;
    int ret = 0;

    if (!TEST_ptr(localctx = OSSL_LIB_CTX_new())
        || !TEST_true(OSSL_PROVIDER_add_builtin(localctx, "tls-provider-b",
            tls_provider_init))
        || !TEST_true(OSSL_PROVIDER_add_builtin(localctx, "tls-provider-c",
            tls_provider_init))
        || !TEST_ptr(localdef = OSSL_PROVIDER_load(localctx, "default"))
        || !TEST_ptr(second = tls_provider_load(localctx, "tls-provider-b",
                         "valid"))
        || !TEST_ptr(third = tls_provider_load(localctx, "tls-provider-c",
                         "valid")))
        goto end;

    /* Same code point and name from two providers: context creation fails */
    ctx = SSL_CTX_new_ex(localctx, NULL, TLS_method());
    if (!TEST_ptr_null(ctx)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()), SSL_R_BAD_CIPHER))
        goto end;

    ret = 1;
end:
    SSL_CTX_free(ctx);
    if (third != NULL)
        OSSL_PROVIDER_unload(third);
    if (second != NULL)
        OSSL_PROVIDER_unload(second);
    OSSL_PROVIDER_unload(localdef);
    OSSL_LIB_CTX_free(localctx);
    ERR_clear_error();
    return ret;
}

#define THREAD_COUNT 8
#define HANDSHAKES_PER_THREAD 6

static SSL_CTX *th_sctx, *th_cctx;
static CRYPTO_RWLOCK *th_lock;
static int th_failures;

static void thread_worker(void)
{
    static const unsigned char msg[] = "threaded";
    SSL *serverssl = NULL, *clientssl = NULL;
    int i, ok = 1, tmp;

    for (i = 0; ok && i < HANDSHAKES_PER_THREAD; i++) {
        ok = create_ssl_objects(th_sctx, th_cctx, &serverssl, &clientssl,
                 NULL, NULL)
            && create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)
            && SSL_get_current_cipher(serverssl)->origin
                == SSL_CIPHER_ORIGIN_PROVIDER
            && exchange_data(clientssl, serverssl, msg, sizeof(msg))
            && SSL_key_update(serverssl, SSL_KEY_UPDATE_REQUESTED)
            && exchange_data(serverssl, clientssl, msg, sizeof(msg));
        SSL_free(serverssl);
        SSL_free(clientssl);
        serverssl = clientssl = NULL;
    }
    if (!ok)
        CRYPTO_atomic_add(&th_failures, 1, &tmp, th_lock);
}

static int test_concurrent_handshakes_prebuilt_contexts(void)
{
    thread_t threads[THREAD_COUNT];
    int i, started = 0, ret = 0;

    th_failures = 0;
    if (!TEST_ptr(th_lock = CRYPTO_THREAD_lock_new())
        || !make_pair(PROV_SHA256_NAME, PROV_SHA256_NAME, cert,
            privkey, &th_sctx, &th_cctx))
        goto end;
    for (i = 0; i < THREAD_COUNT; i++) {
        if (!TEST_true(run_thread(&threads[i], thread_worker)))
            break;
        started++;
    }
    for (i = 0; i < started; i++)
        (void)wait_for_thread(threads[i]);
    if (!TEST_int_eq(started, THREAD_COUNT) || !TEST_int_eq(th_failures, 0))
        goto end;

    ret = 1;
end:
    SSL_CTX_free(th_sctx);
    SSL_CTX_free(th_cctx);
    th_sctx = th_cctx = NULL;
    CRYPTO_THREAD_lock_free(th_lock);
    th_lock = NULL;
    ERR_clear_error();
    return ret;
}

static int test_provider_discovery_reload_lifecycle(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *local_default = NULL, *provider = NULL;
    SSL_CTX *sslctx = NULL;
    int i, ret = 0;

    for (i = 0; i < 64; i++) {
        if (!TEST_true(tls_provider_libctx_new(&ctx, &local_default, &provider,
                "tls-provider-reload", "valid", NULL))
            || !TEST_ptr(sslctx = SSL_CTX_new_ex(ctx, NULL, TLS_method()))
            || !TEST_int_eq(sk_SSL_CIPHER_num(
                                sslctx->provider_ciphersuites),
                1))
            goto end;
        OSSL_PROVIDER_unload(provider);
        provider = NULL;
        if (!TEST_true(SSL_CTX_set_ciphersuites(sslctx, PROV_SHA256_NAME)))
            goto end;
        SSL_CTX_free(sslctx);
        sslctx = NULL;
        OSSL_PROVIDER_unload(local_default);
        local_default = NULL;
        OSSL_LIB_CTX_free(ctx);
        ctx = NULL;
    }
    ret = 1;
end:
    SSL_CTX_free(sslctx);
    tls_provider_libctx_free(ctx, local_default, provider);
    ERR_clear_error();
    return ret;
}

#define RELOADS_PER_THREAD 32

static CRYPTO_RWLOCK *reload_lock;
static int reload_failures;

static void provider_discovery_reload_worker(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *local_default = NULL, *provider = NULL;
    SSL_CTX *sslctx = NULL;
    int i, ok = 1, tmp;

    for (i = 0; ok && i < RELOADS_PER_THREAD; i++) {
        ok = tls_provider_libctx_new(&ctx, &local_default, &provider,
                 "tls-provider-reload-thread", "valid", NULL)
            && (sslctx = SSL_CTX_new_ex(ctx, NULL, TLS_method())) != NULL
            && sk_SSL_CIPHER_num(sslctx->provider_ciphersuites) == 1;
        OSSL_PROVIDER_unload(provider);
        provider = NULL;
        if (ok)
            ok = SSL_CTX_set_ciphersuites(sslctx, PROV_SHA256_NAME);
        SSL_CTX_free(sslctx);
        sslctx = NULL;
        OSSL_PROVIDER_unload(local_default);
        local_default = NULL;
        OSSL_LIB_CTX_free(ctx);
        ctx = NULL;
    }
    SSL_CTX_free(sslctx);
    tls_provider_libctx_free(ctx, local_default, provider);
    if (!ok)
        CRYPTO_atomic_add(&reload_failures, 1, &tmp, reload_lock);
}

static int test_concurrent_provider_discovery_reload(void)
{
    thread_t threads[THREAD_COUNT];
    int i, started = 0, ret = 0;

    reload_failures = 0;
    if (!TEST_ptr(reload_lock = CRYPTO_THREAD_lock_new()))
        goto end;
    for (i = 0; i < THREAD_COUNT; i++) {
        if (!TEST_true(run_thread(&threads[i],
                provider_discovery_reload_worker)))
            break;
        started++;
    }
    for (i = 0; i < started; i++)
        (void)wait_for_thread(threads[i]);
    if (!TEST_int_eq(started, THREAD_COUNT)
        || !TEST_int_eq(reload_failures, 0))
        goto end;

    ret = 1;
end:
    CRYPTO_THREAD_lock_free(reload_lock);
    reload_lock = NULL;
    ERR_clear_error();
    return ret;
}

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    if (!test_skip_common_options()
        || !TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1))
        || !TEST_true(tls_provider_libctx_new(&libctx, &defprov, &tlsprov,
            "tls-provider", "valid-both", "?provider=tls-provider")))
        return 0;

    if (!TEST_int_ge(session_dup_index = SSL_SESSION_get_ex_new_index(0, NULL,
                         NULL, count_session_dup, NULL),
            0))
        return 0;

    ADD_ALL_TESTS(test_builtin_resumption_copies, 2);
    ADD_ALL_TESTS(test_resume_into_provider_suite, 4);
    ADD_TEST(test_stateful_cache_provider_transition);
    ADD_TEST(test_external_cache_rejects_provider_session);
    ADD_TEST(test_public_provider_cipher_assignment_rejected);
    ADD_TEST(test_builtin_external_psk_into_provider_suite);
    ADD_ALL_TESTS(test_provider_external_psk_rejected, 2);
    ADD_ALL_TESTS(test_security_callback, 4);
    ADD_TEST(test_provider_aead_limit_failure);
    ADD_TEST(test_session_outlives_ctx);
    ADD_TEST(test_d2i_into_provider_session);
    ADD_MFAIL_SAMPLED_NO_CHECK_TEST(test_d2i_provider_rollback_mfail, 64);
    ADD_TEST(test_provider_discovery_reload_lifecycle);
    ADD_TEST(test_multiple_providers_collide);
    ADD_TEST(test_concurrent_handshakes_prebuilt_contexts);
    ADD_TEST(test_concurrent_provider_discovery_reload);
    return 1;
}

void cleanup_tests(void)
{
    tls_provider_libctx_free(libctx, defprov, tlsprov);
}
