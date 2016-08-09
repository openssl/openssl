/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/x509_vfy.h>
#include <openssl/ssl.h>

#include "handshake_helper.h"
#include "testutil.h"

HANDSHAKE_RESULT *HANDSHAKE_RESULT_new()
{
    HANDSHAKE_RESULT *ret = OPENSSL_zalloc(sizeof(*ret));
    TEST_check(ret != NULL);
    return ret;
}

void HANDSHAKE_RESULT_free(HANDSHAKE_RESULT *result)
{
    if (result == NULL)
        return;
    OPENSSL_free(result->client_npn_negotiated);
    OPENSSL_free(result->server_npn_negotiated);
    OPENSSL_free(result->client_alpn_negotiated);
    OPENSSL_free(result->server_alpn_negotiated);
    OPENSSL_free(result);
}

/*
 * Since there appears to be no way to extract the sent/received alert
 * from the SSL object directly, we use the info callback and stash
 * the result in ex_data.
 */
typedef struct handshake_ex_data {
    int alert_sent;
    int alert_received;
    int session_ticket_do_not_call;
    ssl_servername_t servername;
} HANDSHAKE_EX_DATA;

typedef struct ctx_data {
    unsigned char *npn_protocols;
    size_t npn_protocols_len;
    unsigned char *alpn_protocols;
    size_t alpn_protocols_len;
} CTX_DATA;

/* |ctx_data| itself is stack-allocated. */
static void ctx_data_free_data(CTX_DATA *ctx_data)
{
    OPENSSL_free(ctx_data->npn_protocols);
    ctx_data->npn_protocols = NULL;
    OPENSSL_free(ctx_data->alpn_protocols);
    ctx_data->alpn_protocols = NULL;
}

static int ex_data_idx;

static void info_cb(const SSL *s, int where, int ret)
{
    if (where & SSL_CB_ALERT) {
        HANDSHAKE_EX_DATA *ex_data =
            (HANDSHAKE_EX_DATA*)(SSL_get_ex_data(s, ex_data_idx));
        if (where & SSL_CB_WRITE) {
            ex_data->alert_sent = ret;
        } else {
            ex_data->alert_received = ret;
        }
    }
}

/* Select the appropriate server CTX.
 * Returns SSL_TLSEXT_ERR_OK if a match was found.
 * If |ignore| is 1, returns SSL_TLSEXT_ERR_NOACK on mismatch.
 * Otherwise, returns SSL_TLSEXT_ERR_ALERT_FATAL on mismatch.
 * An empty SNI extension also returns SSL_TSLEXT_ERR_NOACK.
 */
static int select_server_ctx(SSL *s, void *arg, int ignore)
{
    const char *servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    HANDSHAKE_EX_DATA *ex_data =
        (HANDSHAKE_EX_DATA*)(SSL_get_ex_data(s, ex_data_idx));

    if (servername == NULL) {
        ex_data->servername = SSL_TEST_SERVERNAME_SERVER1;
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (strcmp(servername, "server2") == 0) {
        SSL_CTX *new_ctx = (SSL_CTX*)arg;
        SSL_set_SSL_CTX(s, new_ctx);
        /*
         * Copy over all the SSL_CTX options - reasonable behavior
         * allows testing of cases where the options between two
         * contexts differ/conflict
         */
        SSL_clear_options(s, 0xFFFFFFFFL);
        SSL_set_options(s, SSL_CTX_get_options(new_ctx));

        ex_data->servername = SSL_TEST_SERVERNAME_SERVER2;
        return SSL_TLSEXT_ERR_OK;
    } else if (strcmp(servername, "server1") == 0) {
        ex_data->servername = SSL_TEST_SERVERNAME_SERVER1;
        return SSL_TLSEXT_ERR_OK;
    } else if (ignore) {
        ex_data->servername = SSL_TEST_SERVERNAME_SERVER1;
        return SSL_TLSEXT_ERR_NOACK;
    } else {
        /* Don't set an explicit alert, to test library defaults. */
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
}

/*
 * (RFC 6066):
 *  If the server understood the ClientHello extension but
 *  does not recognize the server name, the server SHOULD take one of two
 *  actions: either abort the handshake by sending a fatal-level
 *  unrecognized_name(112) alert or continue the handshake.
 *
 * This behaviour is up to the application to configure; we test both
 * configurations to ensure the state machine propagates the result
 * correctly.
 */
static int servername_ignore_cb(SSL *s, int *ad, void *arg)
{
    return select_server_ctx(s, arg, 1);
}

static int servername_reject_cb(SSL *s, int *ad, void *arg)
{
    return select_server_ctx(s, arg, 0);
}

static int verify_reject_cb(X509_STORE_CTX *ctx, void *arg) {
    X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;
}

static int verify_accept_cb(X509_STORE_CTX *ctx, void *arg) {
    return 1;
}

static int broken_session_ticket_cb(SSL *s, unsigned char *key_name, unsigned char *iv,
                                    EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc)
{
    return 0;
}

static int do_not_call_session_ticket_cb(SSL *s, unsigned char *key_name,
                                         unsigned char *iv,
                                         EVP_CIPHER_CTX *ctx,
                                         HMAC_CTX *hctx, int enc)
{
    HANDSHAKE_EX_DATA *ex_data =
        (HANDSHAKE_EX_DATA*)(SSL_get_ex_data(s, ex_data_idx));
    ex_data->session_ticket_do_not_call = 1;
    return 0;
}

/* Parse the comma-separated list into TLS format. */
static void parse_protos(const char *protos, unsigned char **out, size_t *outlen)
{
    size_t len, i, prefix;

    len = strlen(protos);

    /* Should never have reuse. */
    TEST_check(*out == NULL);

    /* Test values are small, so we omit length limit checks. */
    *out = OPENSSL_malloc(len + 1);
    TEST_check(*out != NULL);
    *outlen = len + 1;

    /*
     * foo => '3', 'f', 'o', 'o'
     * foo,bar => '3', 'f', 'o', 'o', '3', 'b', 'a', 'r'
     */
    memcpy(*out + 1, protos, len);

    prefix = 0;
    i = prefix + 1;
    while (i <= len) {
        if ((*out)[i] == ',') {
            TEST_check(i - 1 - prefix > 0);
            (*out)[prefix] = i - 1 - prefix;
            prefix = i;
        }
        i++;
    }
    TEST_check(len - prefix > 0);
    (*out)[prefix] = len - prefix;
}

#ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * The client SHOULD select the first protocol advertised by the server that it
 * also supports.  In the event that the client doesn't support any of server's
 * protocols, or the server doesn't advertise any, it SHOULD select the first
 * protocol that it supports.
 */
static int client_npn_cb(SSL *s, unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
    CTX_DATA *ctx_data = (CTX_DATA*)(arg);
    int ret;

    ret = SSL_select_next_proto(out, outlen, in, inlen,
                                ctx_data->npn_protocols,
                                ctx_data->npn_protocols_len);
    /* Accept both OPENSSL_NPN_NEGOTIATED and OPENSSL_NPN_NO_OVERLAP. */
    TEST_check(ret == OPENSSL_NPN_NEGOTIATED || ret == OPENSSL_NPN_NO_OVERLAP);
    return SSL_TLSEXT_ERR_OK;
}

static int server_npn_cb(SSL *s, const unsigned char **data,
                         unsigned int *len, void *arg)
{
    CTX_DATA *ctx_data = (CTX_DATA*)(arg);
    *data = ctx_data->npn_protocols;
    *len = ctx_data->npn_protocols_len;
    return SSL_TLSEXT_ERR_OK;
}
#endif

/*
 * The server SHOULD select the most highly preferred protocol that it supports
 * and that is also advertised by the client.  In the event that the server
 * supports no protocols that the client advertises, then the server SHALL
 * respond with a fatal "no_application_protocol" alert.
 */
static int server_alpn_cb(SSL *s, const unsigned char **out,
                          unsigned char *outlen, const unsigned char *in,
                          unsigned int inlen, void *arg)
{
    CTX_DATA *ctx_data = (CTX_DATA*)(arg);
    int ret;

    /* SSL_select_next_proto isn't const-correct... */
    unsigned char *tmp_out;

    /*
     * The result points either to |in| or to |ctx_data->alpn_protocols|.
     * The callback is allowed to point to |in| or to a long-lived buffer,
     * so we can return directly without storing a copy.
     */
    ret = SSL_select_next_proto(&tmp_out, outlen,
                                ctx_data->alpn_protocols,
                                ctx_data->alpn_protocols_len, in, inlen);

    *out = tmp_out;
    /* Unlike NPN, we don't tolerate a mismatch. */
    return ret == OPENSSL_NPN_NEGOTIATED ? SSL_TLSEXT_ERR_OK
        : SSL_TLSEXT_ERR_NOACK;
}

/*
 * Configure callbacks and other properties that can't be set directly
 * in the server/client CONF.
 */
static void configure_handshake_ctx(SSL_CTX *server_ctx, SSL_CTX *server2_ctx,
                                    SSL_CTX *client_ctx,
                                    const SSL_TEST_EXTRA_CONF *extra,
                                    CTX_DATA *server_ctx_data,
                                    CTX_DATA *server2_ctx_data,
                                    CTX_DATA *client_ctx_data)
{
    unsigned char *ticket_keys;
    size_t ticket_key_len;

    switch (extra->client.verify_callback) {
    case SSL_TEST_VERIFY_ACCEPT_ALL:
        SSL_CTX_set_cert_verify_callback(client_ctx, &verify_accept_cb,
                                         NULL);
        break;
    case SSL_TEST_VERIFY_REJECT_ALL:
        SSL_CTX_set_cert_verify_callback(client_ctx, &verify_reject_cb,
                                         NULL);
        break;
    default:
        break;
    }

    /* link the two contexts for SNI purposes */
    switch (extra->server.servername_callback) {
    case SSL_TEST_SERVERNAME_IGNORE_MISMATCH:
        SSL_CTX_set_tlsext_servername_callback(server_ctx, servername_ignore_cb);
        SSL_CTX_set_tlsext_servername_arg(server_ctx, server2_ctx);
        break;
    case SSL_TEST_SERVERNAME_REJECT_MISMATCH:
        SSL_CTX_set_tlsext_servername_callback(server_ctx, servername_reject_cb);
        SSL_CTX_set_tlsext_servername_arg(server_ctx, server2_ctx);
        break;
    default:
        break;
    }

    /*
     * The initial_ctx/session_ctx always handles the encrypt/decrypt of the
     * session ticket. This ticket_key callback is assigned to the second
     * session (assigned via SNI), and should never be invoked
     */
    if (server2_ctx != NULL)
        SSL_CTX_set_tlsext_ticket_key_cb(server2_ctx,
                                         do_not_call_session_ticket_cb);

    if (extra->server.broken_session_ticket) {
        SSL_CTX_set_tlsext_ticket_key_cb(server_ctx, broken_session_ticket_cb);
    }
#ifndef OPENSSL_NO_NEXTPROTONEG
    if (extra->server.npn_protocols != NULL) {
        parse_protos(extra->server.npn_protocols,
                     &server_ctx_data->npn_protocols,
                     &server_ctx_data->npn_protocols_len);
        SSL_CTX_set_next_protos_advertised_cb(server_ctx, server_npn_cb,
                                              server_ctx_data);
    }
    if (extra->server2.npn_protocols != NULL) {
        parse_protos(extra->server2.npn_protocols,
                     &server2_ctx_data->npn_protocols,
                     &server2_ctx_data->npn_protocols_len);
        TEST_check(server2_ctx != NULL);
        SSL_CTX_set_next_protos_advertised_cb(server2_ctx, server_npn_cb,
                                              server2_ctx_data);
    }
    if (extra->client.npn_protocols != NULL) {
        parse_protos(extra->client.npn_protocols,
                     &client_ctx_data->npn_protocols,
                     &client_ctx_data->npn_protocols_len);
        SSL_CTX_set_next_proto_select_cb(client_ctx, client_npn_cb,
                                         client_ctx_data);
    }
#endif
    if (extra->server.alpn_protocols != NULL) {
        parse_protos(extra->server.alpn_protocols,
                     &server_ctx_data->alpn_protocols,
                     &server_ctx_data->alpn_protocols_len);
        SSL_CTX_set_alpn_select_cb(server_ctx, server_alpn_cb, server_ctx_data);
    }
    if (extra->server2.alpn_protocols != NULL) {
        TEST_check(server2_ctx != NULL);
        parse_protos(extra->server2.alpn_protocols,
                     &server2_ctx_data->alpn_protocols,
                     &server2_ctx_data->alpn_protocols_len);
        SSL_CTX_set_alpn_select_cb(server2_ctx, server_alpn_cb, server2_ctx_data);
    }
    if (extra->client.alpn_protocols != NULL) {
        unsigned char *alpn_protos = NULL;
        size_t alpn_protos_len;
        parse_protos(extra->client.alpn_protocols,
                     &alpn_protos, &alpn_protos_len);
        /* Reversed return value convention... */
        TEST_check(SSL_CTX_set_alpn_protos(client_ctx, alpn_protos,
                                           alpn_protos_len) == 0);
        OPENSSL_free(alpn_protos);
    }

    /*
     * Use fixed session ticket keys so that we can decrypt a ticket created with
     * one CTX in another CTX. Don't address server2 for the moment.
     */
    ticket_key_len = SSL_CTX_set_tlsext_ticket_keys(server_ctx, NULL, 0);
    ticket_keys = OPENSSL_zalloc(ticket_key_len);
    TEST_check(ticket_keys != NULL);
    TEST_check(SSL_CTX_set_tlsext_ticket_keys(server_ctx, ticket_keys,
                                              ticket_key_len) == 1);
    OPENSSL_free(ticket_keys);

#ifndef OPENSSL_NO_CT
    TEST_check(SSL_CTX_set_default_ctlog_list_file(client_ctx));
    switch (extra->client.ct_validation) {
    case SSL_TEST_CT_VALIDATION_PERMISSIVE:
        TEST_check(SSL_CTX_enable_ct(client_ctx, SSL_CT_VALIDATION_PERMISSIVE));
        break;
    case SSL_TEST_CT_VALIDATION_STRICT:
        TEST_check(SSL_CTX_enable_ct(client_ctx, SSL_CT_VALIDATION_STRICT));
        break;
    case SSL_TEST_CT_VALIDATION_NONE:
        break;
    }
#endif
}

/* Configure per-SSL callbacks and other properties. */
static void configure_handshake_ssl(SSL *server, SSL *client,
                                    const SSL_TEST_EXTRA_CONF *extra)
{
    if (extra->client.servername != SSL_TEST_SERVERNAME_NONE)
        SSL_set_tlsext_host_name(client,
                                 ssl_servername_name(extra->client.servername));
}


typedef enum {
    PEER_SUCCESS,
    PEER_RETRY,
    PEER_ERROR
} peer_status_t;

/*
 * RFC 5246 says:
 *
 * Note that as of TLS 1.1,
 *     failure to properly close a connection no longer requires that a
 *     session not be resumed.  This is a change from TLS 1.0 to conform
 *     with widespread implementation practice.
 *
 * However,
 * (a) OpenSSL requires that a connection be shutdown for all protocol versions.
 * (b) We test lower versions, too.
 * So we just implement shutdown. We do a full bidirectional shutdown so that we
 * can compare sent and received close_notify alerts and get some test coverage
 * for SSL_shutdown as a bonus.
 */
static peer_status_t do_handshake_step(SSL *ssl, int shutdown)
{
    int ret;

    ret = shutdown ? SSL_shutdown(ssl) : SSL_do_handshake(ssl);

    if (ret == 1) {
        return PEER_SUCCESS;
    } else if (ret == 0) {
        return shutdown ? PEER_RETRY : PEER_ERROR;
    } else {
        int error = SSL_get_error(ssl, ret);
        /* Memory bios should never block with SSL_ERROR_WANT_WRITE. */
        if (error == SSL_ERROR_WANT_READ)
            return PEER_RETRY;
        else
            return PEER_ERROR;
    }
}

typedef enum {
    /* Both parties succeeded. */
    HANDSHAKE_SUCCESS,
    /* Client errored. */
    CLIENT_ERROR,
    /* Server errored. */
    SERVER_ERROR,
    /* Peers are in inconsistent state. */
    INTERNAL_ERROR,
    /* One or both peers not done. */
    HANDSHAKE_RETRY
} handshake_status_t;

/*
 * Determine the handshake outcome.
 * last_status: the status of the peer to have acted last.
 * previous_status: the status of the peer that didn't act last.
 * client_spoke_last: 1 if the client went last.
 */
static handshake_status_t handshake_status(peer_status_t last_status,
                                           peer_status_t previous_status,
                                           int client_spoke_last)
{
    switch (last_status) {
    case PEER_SUCCESS:
        switch (previous_status) {
        case PEER_SUCCESS:
            /* Both succeeded. */
            return HANDSHAKE_SUCCESS;
        case PEER_RETRY:
            /* Let the first peer finish. */
            return HANDSHAKE_RETRY;
        case PEER_ERROR:
            /*
             * Second peer succeeded despite the fact that the first peer
             * already errored. This shouldn't happen.
             */
            return INTERNAL_ERROR;
        }

    case PEER_RETRY:
        if (previous_status == PEER_RETRY) {
            /* Neither peer is done. */
            return HANDSHAKE_RETRY;
        } else {
            /*
             * Deadlock: second peer is waiting for more input while first
             * peer thinks they're done (no more input is coming).
             */
            return INTERNAL_ERROR;
        }
    case PEER_ERROR:
        switch (previous_status) {
        case PEER_SUCCESS:
            /*
             * First peer succeeded but second peer errored.
             * TODO(emilia): we should be able to continue here (with some
             * application data?) to ensure the first peer receives the
             * alert / close_notify.
             */
            return client_spoke_last ? CLIENT_ERROR : SERVER_ERROR;
        case PEER_RETRY:
            /* We errored; let the peer finish. */
            return HANDSHAKE_RETRY;
        case PEER_ERROR:
            /* Both peers errored. Return the one that errored first. */
            return client_spoke_last ? SERVER_ERROR : CLIENT_ERROR;
        }
    }
    /* Control should never reach here. */
    return INTERNAL_ERROR;
}

/* Convert unsigned char buf's that shouldn't contain any NUL-bytes to char. */
static char *dup_str(const unsigned char *in, size_t len)
{
    char *ret;

    if(len == 0)
        return NULL;

    /* Assert that the string does not contain NUL-bytes. */
    TEST_check(OPENSSL_strnlen((const char*)(in), len) == len);
    ret = OPENSSL_strndup((const char*)(in), len);
    TEST_check(ret != NULL);
    return ret;
}

static HANDSHAKE_RESULT *do_handshake_internal(
    SSL_CTX *server_ctx, SSL_CTX *server2_ctx, SSL_CTX *client_ctx,
    const SSL_TEST_EXTRA_CONF *extra, SSL_SESSION *session_in,
    SSL_SESSION **session_out)
{
    SSL *server, *client;
    BIO *client_to_server, *server_to_client;
    HANDSHAKE_EX_DATA server_ex_data, client_ex_data;
    CTX_DATA client_ctx_data, server_ctx_data, server2_ctx_data;
    HANDSHAKE_RESULT *ret = HANDSHAKE_RESULT_new();
    int client_turn = 1, shutdown = 0;
    peer_status_t client_status = PEER_RETRY, server_status = PEER_RETRY;
    handshake_status_t status = HANDSHAKE_RETRY;
    unsigned char* tick = NULL;
    size_t tick_len = 0;
    SSL_SESSION* sess = NULL;
    const unsigned char *proto = NULL;
    /* API dictates unsigned int rather than size_t. */
    unsigned int proto_len = 0;

    memset(&server_ctx_data, 0, sizeof(server_ctx_data));
    memset(&server2_ctx_data, 0, sizeof(server2_ctx_data));
    memset(&client_ctx_data, 0, sizeof(client_ctx_data));

    configure_handshake_ctx(server_ctx, server2_ctx, client_ctx, extra,
                            &server_ctx_data, &server2_ctx_data, &client_ctx_data);

    server = SSL_new(server_ctx);
    client = SSL_new(client_ctx);
    TEST_check(server != NULL);
    TEST_check(client != NULL);

    configure_handshake_ssl(server, client, extra);
    if (session_in != NULL) {
        /* In case we're testing resumption without tickets. */
        TEST_check(SSL_CTX_add_session(server_ctx, session_in));
        TEST_check(SSL_set_session(client, session_in));
    }

    memset(&server_ex_data, 0, sizeof(server_ex_data));
    memset(&client_ex_data, 0, sizeof(client_ex_data));

    ret->result = SSL_TEST_INTERNAL_ERROR;

    client_to_server = BIO_new(BIO_s_mem());
    server_to_client = BIO_new(BIO_s_mem());

    TEST_check(client_to_server != NULL && server_to_client != NULL);

    /* Non-blocking bio. */
    BIO_set_nbio(client_to_server, 1);
    BIO_set_nbio(server_to_client, 1);

    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    /* The bios are now owned by the SSL object. */
    SSL_set_bio(client, server_to_client, client_to_server);
    TEST_check(BIO_up_ref(server_to_client) > 0);
    TEST_check(BIO_up_ref(client_to_server) > 0);
    SSL_set_bio(server, client_to_server, server_to_client);

    ex_data_idx = SSL_get_ex_new_index(0, "ex data", NULL, NULL, NULL);
    TEST_check(ex_data_idx >= 0);

    TEST_check(SSL_set_ex_data(server, ex_data_idx,
                                   &server_ex_data) == 1);
    TEST_check(SSL_set_ex_data(client, ex_data_idx,
                                   &client_ex_data) == 1);

    SSL_set_info_callback(server, &info_cb);
    SSL_set_info_callback(client, &info_cb);

    /*
     * Half-duplex handshake loop.
     * Client and server speak to each other synchronously in the same process.
     * We use non-blocking BIOs, so whenever one peer blocks for read, it
     * returns PEER_RETRY to indicate that it's the other peer's turn to write.
     * The handshake succeeds once both peers have succeeded. If one peer
     * errors out, we also let the other peer retry (and presumably fail).
     */
    for(;;) {
        if (client_turn) {
            client_status = do_handshake_step(client, shutdown);
            status = handshake_status(client_status, server_status,
                                      1 /* client went last */);
        } else {
            server_status = do_handshake_step(server, shutdown);
            status = handshake_status(server_status, client_status,
                                      0 /* server went last */);
        }

        switch (status) {
        case HANDSHAKE_SUCCESS:
            if (shutdown) {
                ret->result = SSL_TEST_SUCCESS;
                goto err;
            } else {
                client_status = server_status = PEER_RETRY;
                shutdown = 1;
                client_turn = 1;
                break;
            }
        case CLIENT_ERROR:
            ret->result = SSL_TEST_CLIENT_FAIL;
            goto err;
        case SERVER_ERROR:
            ret->result = SSL_TEST_SERVER_FAIL;
            goto err;
        case INTERNAL_ERROR:
            ret->result = SSL_TEST_INTERNAL_ERROR;
            goto err;
        case HANDSHAKE_RETRY:
            /* Continue. */
            client_turn ^= 1;
            break;
        }
    }
 err:
    ret->server_alert_sent = server_ex_data.alert_sent;
    ret->server_alert_received = client_ex_data.alert_received;
    ret->client_alert_sent = client_ex_data.alert_sent;
    ret->client_alert_received = server_ex_data.alert_received;
    ret->server_protocol = SSL_version(server);
    ret->client_protocol = SSL_version(client);
    ret->servername = server_ex_data.servername;
    if ((sess = SSL_get0_session(client)) != NULL)
        SSL_SESSION_get0_ticket(sess, &tick, &tick_len);
    if (tick == NULL || tick_len == 0)
        ret->session_ticket = SSL_TEST_SESSION_TICKET_NO;
    else
        ret->session_ticket = SSL_TEST_SESSION_TICKET_YES;
    ret->session_ticket_do_not_call = server_ex_data.session_ticket_do_not_call;

#ifndef OPENSSL_NO_NEXTPROTONEG
    SSL_get0_next_proto_negotiated(client, &proto, &proto_len);
    ret->client_npn_negotiated = dup_str(proto, proto_len);

    SSL_get0_next_proto_negotiated(server, &proto, &proto_len);
    ret->server_npn_negotiated = dup_str(proto, proto_len);
#endif

    SSL_get0_alpn_selected(client, &proto, &proto_len);
    ret->client_alpn_negotiated = dup_str(proto, proto_len);

    SSL_get0_alpn_selected(server, &proto, &proto_len);
    ret->server_alpn_negotiated = dup_str(proto, proto_len);

    ret->client_resumed = SSL_session_reused(client);
    ret->server_resumed = SSL_session_reused(server);

    if (session_out != NULL)
        *session_out = SSL_get1_session(client);

    ctx_data_free_data(&server_ctx_data);
    ctx_data_free_data(&server2_ctx_data);
    ctx_data_free_data(&client_ctx_data);

    SSL_free(server);
    SSL_free(client);
    return ret;
}

HANDSHAKE_RESULT *do_handshake(SSL_CTX *server_ctx, SSL_CTX *server2_ctx,
                               SSL_CTX *client_ctx, SSL_CTX *resume_server_ctx,
                               SSL_CTX *resume_client_ctx,
                               const SSL_TEST_CTX *test_ctx)
{
    HANDSHAKE_RESULT *result;
    SSL_SESSION *session = NULL;

    result = do_handshake_internal(server_ctx, server2_ctx, client_ctx,
                                   &test_ctx->extra, NULL, &session);
    if (test_ctx->handshake_mode == SSL_TEST_HANDSHAKE_SIMPLE)
        goto end;

    TEST_check(test_ctx->handshake_mode == SSL_TEST_HANDSHAKE_RESUME);

    if (result->result != SSL_TEST_SUCCESS) {
        result->result = SSL_TEST_FIRST_HANDSHAKE_FAILED;
        return result;
    }

    HANDSHAKE_RESULT_free(result);
    /* We don't support SNI on second handshake yet, so server2_ctx is NULL. */
    result = do_handshake_internal(resume_server_ctx, NULL, resume_client_ctx,
                                   &test_ctx->resume_extra, session, NULL);
 end:
    SSL_SESSION_free(session);
    return result;
}
