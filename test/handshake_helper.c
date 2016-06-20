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

/*
 * Select the appropriate server CTX.
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

static int broken_session_ticket_cb(SSL* s, unsigned char* key_name, unsigned char *iv,
                                    EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc)
{
    return 0;
}

static int do_not_call_session_ticket_cb(SSL* s, unsigned char* key_name,
                                         unsigned char *iv,
                                         EVP_CIPHER_CTX *ctx,
                                         HMAC_CTX *hctx, int enc)
{
    HANDSHAKE_EX_DATA *ex_data =
        (HANDSHAKE_EX_DATA*)(SSL_get_ex_data(s, ex_data_idx));
    ex_data->session_ticket_do_not_call = 1;
    return 0;
}

/*
 * Configure callbacks and other properties that can't be set directly
 * in the server/client CONF.
 */
static void configure_handshake_ctx(SSL_CTX *server_ctx, SSL_CTX *server2_ctx,
                                    SSL_CTX *client_ctx,
                                    const SSL_TEST_CTX *test_ctx)
{
    switch (test_ctx->client_verify_callback) {
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
    switch (test_ctx->servername_callback) {
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

    if (test_ctx->session_ticket_expected == SSL_TEST_SESSION_TICKET_BROKEN) {
        SSL_CTX_set_tlsext_ticket_key_cb(server_ctx, broken_session_ticket_cb);
    }
}

/*
 * Configure callbacks and other properties that can't be set directly
 * in the server/client CONF.
 */
static void configure_handshake_ssl(SSL *server, SSL *client,
                                    const SSL_TEST_CTX *test_ctx)
{
    if (test_ctx->servername != SSL_TEST_SERVERNAME_NONE)
        SSL_set_tlsext_host_name(client,
                                 ssl_servername_name(test_ctx->servername));
}


typedef enum {
    PEER_SUCCESS,
    PEER_RETRY,
    PEER_ERROR
} peer_status_t;

static peer_status_t do_handshake_step(SSL *ssl)
{
    int ret;

    ret = SSL_do_handshake(ssl);

    if (ret == 1) {
        return PEER_SUCCESS;
    } else if (ret == 0) {
        return PEER_ERROR;
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

HANDSHAKE_RESULT do_handshake(SSL_CTX *server_ctx, SSL_CTX *server2_ctx,
                              SSL_CTX *client_ctx, const SSL_TEST_CTX *test_ctx)
{
    SSL *server, *client;
    BIO *client_to_server, *server_to_client;
    HANDSHAKE_EX_DATA server_ex_data, client_ex_data;
    HANDSHAKE_RESULT ret;
    int client_turn = 1;
    peer_status_t client_status = PEER_RETRY, server_status = PEER_RETRY;
    handshake_status_t status = HANDSHAKE_RETRY;
    unsigned char* tick = NULL;
    size_t len = 0;
    SSL_SESSION* sess = NULL;

    configure_handshake_ctx(server_ctx, server2_ctx, client_ctx, test_ctx);

    server = SSL_new(server_ctx);
    client = SSL_new(client_ctx);
    OPENSSL_assert(server != NULL && client != NULL);

    configure_handshake_ssl(server, client, test_ctx);

    memset(&server_ex_data, 0, sizeof(server_ex_data));
    memset(&client_ex_data, 0, sizeof(client_ex_data));
    memset(&ret, 0, sizeof(ret));
    ret.result = SSL_TEST_INTERNAL_ERROR;

    client_to_server = BIO_new(BIO_s_mem());
    server_to_client = BIO_new(BIO_s_mem());

    OPENSSL_assert(client_to_server != NULL && server_to_client != NULL);

    /* Non-blocking bio. */
    BIO_set_nbio(client_to_server, 1);
    BIO_set_nbio(server_to_client, 1);

    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    /* The bios are now owned by the SSL object. */
    SSL_set_bio(client, server_to_client, client_to_server);
    OPENSSL_assert(BIO_up_ref(server_to_client) > 0);
    OPENSSL_assert(BIO_up_ref(client_to_server) > 0);
    SSL_set_bio(server, client_to_server, server_to_client);

    ex_data_idx = SSL_get_ex_new_index(0, "ex data", NULL, NULL, NULL);
    OPENSSL_assert(ex_data_idx >= 0);

    OPENSSL_assert(SSL_set_ex_data(server, ex_data_idx,
                                   &server_ex_data) == 1);
    OPENSSL_assert(SSL_set_ex_data(client, ex_data_idx,
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
            client_status = do_handshake_step(client);
            status = handshake_status(client_status, server_status,
                                      1 /* client went last */);
        } else {
            server_status = do_handshake_step(server);
            status = handshake_status(server_status, client_status,
                                      0 /* server went last */);
        }

        switch (status) {
        case HANDSHAKE_SUCCESS:
            ret.result = SSL_TEST_SUCCESS;
            goto err;
        case CLIENT_ERROR:
            ret.result = SSL_TEST_CLIENT_FAIL;
            goto err;
        case SERVER_ERROR:
            ret.result = SSL_TEST_SERVER_FAIL;
            goto err;
        case INTERNAL_ERROR:
            ret.result = SSL_TEST_INTERNAL_ERROR;
            goto err;
        case HANDSHAKE_RETRY:
            /* Continue. */
            client_turn ^= 1;
            break;
        }
    }
 err:
    ret.server_alert_sent = server_ex_data.alert_sent;
    ret.server_alert_received = client_ex_data.alert_received;
    ret.client_alert_sent = client_ex_data.alert_sent;
    ret.client_alert_received = server_ex_data.alert_received;
    ret.server_protocol = SSL_version(server);
    ret.client_protocol = SSL_version(client);
    ret.servername = server_ex_data.servername;
    if ((sess = SSL_get0_session(client)) != NULL)
        SSL_SESSION_get0_ticket(sess, &tick, &len);
    if (tick == NULL || len == 0)
        ret.session_ticket = SSL_TEST_SESSION_TICKET_NO;
    else
        ret.session_ticket = SSL_TEST_SESSION_TICKET_YES;
    ret.session_ticket_do_not_call = server_ex_data.session_ticket_do_not_call;

    SSL_free(server);
    SSL_free(client);
    return ret;
}
