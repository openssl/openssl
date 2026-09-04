/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include "internal/packet.h"
#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "../ssl/statem/statem_local.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"

#include "helpers/tls_provider.h"

#define TLS_TEST_CIPHERSUITE "TLS_TEST_PROVIDER_AES_128_GCM_SHA256"

static OSSL_LIB_CTX *libctx;
static OSSL_PROVIDER *defprov, *tlsprov;
static char *cert, *privkey;
static int nst_written, nst_read, new_session_calls;

static const unsigned char builtin_ciphersuite_id[] = { 0x13, 0x01 };
static const unsigned char test_session_id[] = { 0x01 };

struct nst_extension_case {
    const char *name;
    const unsigned char *extensions;
    size_t extensions_len;
    MSG_PROCESS_RETURN expected;
};

static const unsigned char truncated_header[] = { 0xff };
static const unsigned char truncated_payload[] = { 0xff, 0xfe, 0x00, 0x01 };
static const unsigned char duplicate_early_data[] = {
    0x00, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01
};
static const unsigned char malformed_early_data[] = {
    0x00, 0x2a, 0x00, 0x03, 0x00, 0x00, 0x01
};
static const unsigned char valid_early_data[] = {
    0x00, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x2a
};
static const unsigned char unknown_extension[] = {
    0xff, 0xfe, 0x00, 0x00
};

static const struct nst_extension_case nst_extension_cases[] = {
    { "truncated header", truncated_header, sizeof(truncated_header),
        MSG_PROCESS_ERROR },
    { "truncated payload", truncated_payload, sizeof(truncated_payload),
        MSG_PROCESS_ERROR },
    { "duplicate early data", duplicate_early_data,
        sizeof(duplicate_early_data), MSG_PROCESS_ERROR },
    { "malformed early data", malformed_early_data,
        sizeof(malformed_early_data), MSG_PROCESS_ERROR },
    { "valid early data", valid_early_data, sizeof(valid_early_data),
        MSG_PROCESS_FINISHED_READING },
    { "unknown extension", unknown_extension, sizeof(unknown_extension),
        MSG_PROCESS_FINISHED_READING },
    { "empty extension list", NULL, 0, MSG_PROCESS_FINISHED_READING }
};

static void ticket_msg_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    const unsigned char *msg = buf;

    if (content_type != SSL3_RT_HANDSHAKE || len == 0
        || msg[0] != SSL3_MT_NEWSESSION_TICKET)
        return;
    if (write_p)
        nst_written++;
    else
        nst_read++;
}

static int new_session_cb(SSL *ssl, SSL_SESSION *session)
{
    new_session_calls++;
    return 0;
}

static int check_provider_session_error(int result)
{
    unsigned long err = ERR_peek_last_error();
    int ret = TEST_false(result)
        && TEST_int_eq(ERR_GET_LIB(err), ERR_LIB_SSL)
        && TEST_int_eq(ERR_GET_REASON(err),
            SSL_R_PROVIDER_CIPHERSUITE_SESSION_UNSUPPORTED);

    ERR_clear_error();
    return ret;
}

static int make_ctx_pair(const char *ciphersuite, int tickets,
    SSL_CTX **sctx, SSL_CTX **cctx)
{
    return create_ssl_ctx_pair(libctx, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, sctx, cctx, cert, privkey)
        && SSL_CTX_set_num_tickets(*sctx, tickets)
        && SSL_CTX_set_ciphersuites(*sctx, ciphersuite)
        && SSL_CTX_set_ciphersuites(*cctx, ciphersuite);
}

static MSG_PROCESS_RETURN process_nst_extensions(SSL_CTX *ctx,
    const SSL_CIPHER *cipher, const unsigned char *extensions,
    size_t extensions_len, uint32_t *max_early_data)
{
    unsigned char nst[64] = { 0 };
    SSL *ssl = NULL;
    SSL_CONNECTION *sc = NULL;
    SSL_SESSION *session = NULL;
    PACKET packet;
    WPACKET builder;
    size_t nst_len;
    MSG_PROCESS_RETURN result = MSG_PROCESS_ERROR;

    if (!WPACKET_init_static_len(&builder, nst, sizeof(nst), 0))
        return MSG_PROCESS_ERROR;
    if (!WPACKET_put_bytes_u32(&builder, 1) /* ticket_lifetime */
        || !WPACKET_put_bytes_u32(&builder, 0) /* ticket_age_add */
        || !WPACKET_put_bytes_u8(&builder, 0) /* empty ticket_nonce */
        || !WPACKET_start_sub_packet_u16(&builder)
        || !WPACKET_put_bytes_u8(&builder, 0x42) /* ticket */
        || !WPACKET_close(&builder)
        || !WPACKET_sub_memcpy_u16(&builder, extensions, extensions_len)
        || !WPACKET_finish(&builder)
        || !WPACKET_get_total_written(&builder, &nst_len))
        goto end;

    ssl = SSL_new(ctx);
    session = SSL_SESSION_new();
    if (ssl == NULL || session == NULL
        || !ossl_ssl_session_set1_cipher(session, cipher)
        || !SSL_SESSION_set_protocol_version(session, TLS1_3_VERSION)
        || !PACKET_buf_init(&packet, nst, nst_len))
        goto end;

    sc = SSL_CONNECTION_FROM_SSL(ssl);
    SSL_SESSION_free(sc->session);
    sc->session = session;
    session = NULL;
    result = tls_process_new_session_ticket(sc, &packet);

end:
    if (max_early_data != NULL && sc != NULL && sc->session != NULL)
        *max_early_data = sc->session->ext.max_early_data;
    WPACKET_cleanup(&builder);
    SSL_SESSION_free(session);
    SSL_free(ssl);
    return result;
}

static int test_provider_nst_extension_parser(void)
{
    SSL_CTX *ctx = NULL;
    SSL *probe = NULL;
    const SSL_CIPHER *provider_cipher = NULL, *builtin_cipher = NULL;
    size_t i;
    int ret = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL,
                      tlsv1_3_client_method()))
        || !TEST_true(SSL_CTX_set_ciphersuites(ctx, TLS_TEST_CIPHERSUITE))
        || !TEST_ptr(provider_cipher = ossl_ssl_get0_provider_cipher_by_name(ctx,
                         TLS_TEST_CIPHERSUITE))
        || !TEST_ptr(probe = SSL_new(ctx))
        || !TEST_ptr(builtin_cipher = SSL_CIPHER_find(probe,
                         builtin_ciphersuite_id)))
        goto end;

    for (i = 0; i < OSSL_NELEM(nst_extension_cases); i++) {
        const struct nst_extension_case *test = &nst_extension_cases[i];
        MSG_PROCESS_RETURN result;
        uint32_t max_early_data = UINT32_MAX;

        TEST_info("NST extension case: %s", test->name);
        result = process_nst_extensions(ctx, provider_cipher,
            test->extensions, test->extensions_len, &max_early_data);
        if (!TEST_int_eq(result, test->expected)
            || !TEST_uint_eq(max_early_data, 0))
            goto end;
        ERR_clear_error();
        if (test->expected == MSG_PROCESS_ERROR
            && !TEST_int_eq(process_nst_extensions(ctx, builtin_cipher,
                                test->extensions, test->extensions_len, NULL),
                test->expected))
            goto end;
        ERR_clear_error();
    }

    ret = 1;
end:
    SSL_free(probe);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return ret;
}

static int test_builtin_nonresumable_serialises(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_SESSION *session = NULL;
    int ret = 0;

    nst_written = nst_read = 0;
    if (!TEST_true(make_ctx_pair("TLS_AES_128_GCM_SHA256", 1,
            &sctx, &cctx))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;
    SSL_set_msg_callback(serverssl, ticket_msg_cb);
    SSL_set_msg_callback(clientssl, ticket_msg_cb);
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_int_gt(nst_written, 0)
        || !TEST_int_gt(nst_read, 0)
        || !TEST_ptr(session = SSL_get1_session(clientssl))
        || !TEST_false(session->provider_cipher_seen))
        goto end;

    session->not_resumable = 1;
    if (!TEST_int_gt(i2d_SSL_SESSION(session, NULL), 0))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(session);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
}

static int test_provider_nonresumption_gates(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL, *probe = NULL;
    SSL_SESSION *server_session = NULL, *client_session = NULL;
    SSL_SESSION *public_dup = NULL, *internal_dup = NULL;
    const SSL_CIPHER *builtin = NULL;
    int ret = 0;

    nst_written = nst_read = new_session_calls = 0;
    if (!TEST_true(make_ctx_pair(TLS_TEST_CIPHERSUITE, 2,
            &sctx, &cctx)))
        goto end;
    SSL_CTX_set_session_cache_mode(sctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    if (!TEST_long_eq(SSL_CTX_get_session_cache_mode(sctx),
            SSL_SESS_CACHE_SERVER)
        || !TEST_long_eq(SSL_CTX_get_session_cache_mode(cctx),
            SSL_SESS_CACHE_CLIENT)
        || !TEST_true(SSL_CTX_set_max_early_data(sctx, 1024))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;
    SSL_CTX_sess_set_new_cb(sctx, new_session_cb);
    SSL_CTX_sess_set_new_cb(cctx, new_session_cb);
    SSL_set_msg_callback(serverssl, ticket_msg_cb);
    SSL_set_msg_callback(clientssl, ticket_msg_cb);
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_int_eq(nst_written, 0)
        || !TEST_int_eq(nst_read, 0)
        || !TEST_int_eq(new_session_calls, 0)
        || !TEST_long_eq(SSL_CTX_sess_number(sctx), 0)
        || !TEST_long_eq(SSL_CTX_sess_number(cctx), 0)
        || !TEST_ptr(server_session = SSL_get1_session(serverssl))
        || !TEST_ptr(client_session = SSL_get1_session(clientssl))
        || !TEST_true(server_session->provider_cipher_seen)
        || !TEST_true(client_session->provider_cipher_seen)
        || !TEST_false(SSL_SESSION_is_resumable(client_session))
        || !TEST_true(check_provider_session_error(
            SSL_new_session_ticket(serverssl)))
        || !TEST_true(check_provider_session_error(
            i2d_SSL_SESSION(client_session, NULL)))
        || !TEST_true(check_provider_session_error(
            SSL_CTX_add_session(cctx, client_session)))
        || !TEST_ptr(probe = SSL_new(cctx))
        || !TEST_true(check_provider_session_error(
            SSL_set_session(probe, client_session)))
        || !TEST_ptr_null(SSL_get_session(probe))
        || !TEST_ptr(public_dup = SSL_SESSION_dup(client_session))
        || !TEST_true(public_dup->provider_cipher_seen)
        || !TEST_ptr(internal_dup = ssl_session_dup(client_session, 1))
        || !TEST_true(internal_dup->provider_cipher_seen)
        || !TEST_false(internal_dup->not_resumable)
        || !TEST_true(SSL_SESSION_set1_id(internal_dup, test_session_id,
            sizeof(test_session_id)))
        || !TEST_false(SSL_SESSION_is_resumable(internal_dup))
        || !TEST_ptr(builtin = SSL_CIPHER_find(probe, builtin_ciphersuite_id))
        || !TEST_true(SSL_SESSION_set_cipher(internal_dup, builtin))
        || !TEST_true(internal_dup->provider_cipher_seen)
        || !TEST_false(SSL_SESSION_is_resumable(internal_dup))
        || !TEST_true(check_provider_session_error(
            i2d_SSL_SESSION(internal_dup, NULL)))
        || !TEST_true(check_provider_session_error(
            SSL_set_session(probe, internal_dup)))
        || !TEST_true(check_provider_session_error(
            SSL_CTX_add_session(cctx, internal_dup)))
        || !TEST_long_eq(SSL_CTX_sess_number(cctx), 0))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(server_session);
    SSL_SESSION_free(client_session);
    SSL_SESSION_free(public_dup);
    SSL_SESSION_free(internal_dup);
    SSL_free(probe);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
}

static int test_injected_ticket_preserves_marker(void)
{
    static const unsigned char message[] = { 0x42 };
    unsigned char received[sizeof(message)];
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL, *probe = NULL;
    SSL_CONNECTION *serverconn;
    SSL_SESSION *client_session = NULL;
    const SSL_CIPHER *builtin;
    size_t written = 0, readbytes = 0;
    int ret = 0;

    nst_written = nst_read = new_session_calls = 0;
    if (!TEST_true(make_ctx_pair(TLS_TEST_CIPHERSUITE, 0,
            &sctx, &cctx)))
        goto end;
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    if (!TEST_long_eq(SSL_CTX_get_session_cache_mode(cctx),
            SSL_SESS_CACHE_CLIENT)
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_ptr(serverconn = SSL_CONNECTION_FROM_SSL_ONLY(serverssl)))
        goto end;
    SSL_CTX_sess_set_new_cb(cctx, new_session_cb);
    SSL_set_msg_callback(serverssl, ticket_msg_cb);
    SSL_set_msg_callback(clientssl, ticket_msg_cb);
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_int_eq(nst_written, 0)
        || !TEST_int_eq(nst_read, 0)
        || !TEST_ptr(builtin = SSL_CIPHER_find(serverssl,
                         builtin_ciphersuite_id))
        || !TEST_true(ossl_ssl_session_set1_cipher(serverconn->session, builtin)))
        goto end;

    /* Inject a ticket from a non-conforming peer. */
    serverconn->session->provider_cipher_seen = 0;
    serverconn->session->not_resumable = 0;
    nst_written = nst_read = new_session_calls = 0;
    if (!TEST_true(SSL_new_session_ticket(serverssl))
        || !TEST_true(SSL_write_ex(serverssl, message, sizeof(message),
            &written))
        || !TEST_size_t_eq(written, sizeof(message)))
        goto end;
    if (!TEST_true(SSL_read_ex(clientssl, received, sizeof(received),
            &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(received))
        || !TEST_mem_eq(received, readbytes, message, sizeof(message))
        || !TEST_int_eq(nst_written, 1)
        || !TEST_int_eq(nst_read, 1)
        || !TEST_ptr(client_session = SSL_get1_session(clientssl))
        || !TEST_true(client_session->provider_cipher_seen)
        || !TEST_true(client_session->not_resumable)
        || !TEST_size_t_eq(client_session->ext.ticklen, 0)
        || !TEST_false(SSL_SESSION_is_resumable(client_session))
        || !TEST_int_eq(new_session_calls, 0)
        || !TEST_long_eq(SSL_CTX_sess_number(cctx), 0)
        || !TEST_true(check_provider_session_error(
            i2d_SSL_SESSION(client_session, NULL)))
        || !TEST_true(check_provider_session_error(
            SSL_CTX_add_session(cctx, client_session)))
        || !TEST_ptr(probe = SSL_new(cctx))
        || !TEST_true(check_provider_session_error(
            SSL_set_session(probe, client_session)))
        || !TEST_int_ge(SSL_shutdown(clientssl), 0)
        || !TEST_int_ge(SSL_shutdown(serverssl), 0)
        || !TEST_int_ge(SSL_shutdown(clientssl), 0)
        || !TEST_true(SSL_clear(clientssl))
        || !TEST_ptr_null(SSL_get_session(clientssl)))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(client_session);
    SSL_free(probe);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
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
            "tls-provider", "valid", "?provider=tls-provider")))
        return 0;

    ADD_TEST(test_builtin_nonresumable_serialises);
    ADD_TEST(test_provider_nonresumption_gates);
    ADD_TEST(test_injected_ticket_preserves_marker);
    ADD_TEST(test_provider_nst_extension_parser);
    return 1;
}

void cleanup_tests(void)
{
    tls_provider_libctx_free(libctx, defprov, tlsprov);
}
