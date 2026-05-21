/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Tests for SSL_new_listener() API for DTLS.
 *
 * This test file covers the new DTLS SSL Listener API:
 *   - SSL_new_listener()
 *   - SSL_is_listener()
 *   - SSL_get0_listener()
 *   - SSL_listen()
 *   - SSL_accept_connection()
 *   - SSL_get_accept_connection_queue_len()
 *   - SSL_poll()
 */

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include "internal/time.h"
#include "internal/sockets.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"
#include "../ssl/ssl_local.h"

static char *cert = NULL;
static char *privkey = NULL;

#if !defined(OPENSSL_NO_SOCK) && !defined(OPENSSL_NO_DTLS)

/*
 * Helper function to read data from a listener-based DTLS server connection.
 * Uses SSL_poll() to wait for data since server connections from a listener
 * don't have their own socket fd.
 */
#define DTLS_READ_TIMEOUT_MS 20000 /* 20 second timeout */

static int dtls_read_with_retry(SSL *ssl, void *buf, size_t bufsize,
    size_t *readbytes)
{
    SSL_POLL_ITEM item;
    struct timeval timeout;
    size_t result_count;

    item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    item.desc.value.ssl = ssl;
    item.events = SSL_POLL_EVENT_R;
    item.revents = 0;

    timeout.tv_sec = DTLS_READ_TIMEOUT_MS / 1000;
    timeout.tv_usec = (DTLS_READ_TIMEOUT_MS % 1000) * 1000;

    if (!SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count)) {
        TEST_error("SSL_poll failed");
        return 0;
    }

    if (result_count == 0) {
        TEST_error("SSL_poll timed out after %d ms", DTLS_READ_TIMEOUT_MS);
        return 0;
    }

    if ((item.revents & SSL_POLL_EVENT_R) == 0) {
        TEST_error("SSL_poll returned unexpected events: 0x%lx",
            (unsigned long)item.revents);
        return 0;
    }

    if (!TEST_true(SSL_read_ex(ssl, buf, bufsize, readbytes)))
        return 0;

    return 1;
}

/*
 * Helper to create a DTLS listener with real UDP sockets.
 *
 * This sets up:
 *   - Server UDP socket bound to loopback with ephemeral port
 *   - DTLS listener attached to that socket (with SSL_listen() called)
 *
 * Returns 1 on success, 0 on failure.
 * On success, caller is responsible for cleanup using the returned pointers/fds.
 */
static int create_dtls_listener(SSL_CTX *sctx, uint64_t listener_flags,
    SSL **listener, BIO_ADDR **server_addr, int *server_fd)
{
    BIO *listener_bio = NULL;
    struct in_addr ina;
    union BIO_sock_info_u info;
    int ret = 0;

    *listener = NULL;
    *server_addr = NULL;
    *server_fd = -1;

    ina.s_addr = htonl(INADDR_LOOPBACK);

    /* Create and bind server UDP socket */
    *server_fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(*server_fd, 0))
        goto err;

    if (!TEST_true(BIO_socket_nbio(*server_fd, 1)))
        goto err;

    *server_addr = BIO_ADDR_new();
    if (!TEST_ptr(*server_addr))
        goto err;

    if (!TEST_true(BIO_ADDR_rawmake(*server_addr, AF_INET, &ina, sizeof(ina), 0)))
        goto err;

    if (!TEST_true(BIO_bind(*server_fd, *server_addr, 0)))
        goto err;

    /* Get the actual bound address (with assigned port) */
    info.addr = *server_addr;
    if (!TEST_true(BIO_sock_info(*server_fd, BIO_SOCK_INFO_ADDRESS, &info)))
        goto err;

    /* Create listener BIO and attach to listener */
    listener_bio = BIO_new_dgram(*server_fd, BIO_NOCLOSE);
    if (!TEST_ptr(listener_bio))
        goto err;

    if (!TEST_ptr(*listener = SSL_new_listener(sctx, listener_flags)))
        goto err;

    SSL_set_bio(*listener, listener_bio, listener_bio);
    listener_bio = NULL; /* ownership transferred */

    /* Start listening */
    if (!TEST_int_eq(SSL_listen(*listener), 1))
        goto err;

    ret = 1;

err:
    BIO_free(listener_bio);
    if (ret == 0) {
        SSL_free(*listener);
        BIO_ADDR_free(*server_addr);
        if (*server_fd >= 0)
            BIO_closesocket(*server_fd);
        *listener = NULL;
        *server_addr = NULL;
        *server_fd = -1;
    }
    return ret;
}

/*
 * Helper to create a DTLS client connected to a server address.
 *
 * This sets up:
 *   - Client UDP socket
 *   - Client SSL connected to the server address
 *
 * Returns 1 on success, 0 on failure.
 * On success, caller is responsible for cleanup using the returned pointers/fds.
 */
static int create_dtls_client_for_addr(SSL_CTX *cctx, const BIO_ADDR *server_addr,
    SSL **clientssl, int *client_fd)
{
    BIO *c_bio = NULL;
    int ret = 0;

    *clientssl = NULL;
    *client_fd = -1;

    /* Create client UDP socket */
    *client_fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(*client_fd, 0))
        goto err;

    if (!TEST_true(BIO_socket_nbio(*client_fd, 1)))
        goto err;

    c_bio = BIO_new_dgram(*client_fd, BIO_NOCLOSE);
    if (!TEST_ptr(c_bio))
        goto err;

    if (!TEST_true(BIO_dgram_set_peer(c_bio, server_addr)))
        goto err;

    /* Create client SSL and attach BIO */
    if (!TEST_ptr(*clientssl = SSL_new(cctx)))
        goto err;

    SSL_set_bio(*clientssl, c_bio, c_bio);
    c_bio = NULL; /* ownership transferred */

    ret = 1;

err:
    BIO_free(c_bio);
    if (ret == 0) {
        SSL_free(*clientssl);
        if (*client_fd >= 0)
            BIO_closesocket(*client_fd);
        *clientssl = NULL;
        *client_fd = -1;
    }
    return ret;
}

/*
 * Helper to create a DTLS listener with real UDP sockets and a connected client.
 *
 * This sets up:
 *   - Server UDP socket bound to loopback with ephemeral port
 *   - DTLS listener attached to that socket (with SSL_listen() called)
 *   - Client UDP socket
 *   - Client SSL connected to the server address
 *
 * Returns 1 on success, 0 on failure.
 * On success, caller is responsible for cleanup using the returned pointers/fds.
 */
static int create_dtls_listener_and_client(SSL_CTX *sctx, SSL_CTX *cctx,
    uint64_t listener_flags,
    SSL **listener, SSL **clientssl,
    BIO_ADDR **server_addr,
    int *server_fd, int *client_fd)
{
    *clientssl = NULL;
    *client_fd = -1;

    /* Create the listener */
    if (!create_dtls_listener(sctx, listener_flags, listener, server_addr, server_fd))
        return 0;

    /* Create the client */
    if (!create_dtls_client_for_addr(cctx, *server_addr, clientssl, client_fd)) {
        SSL_free(*listener);
        BIO_ADDR_free(*server_addr);
        if (*server_fd >= 0)
            BIO_closesocket(*server_fd);
        *listener = NULL;
        *server_addr = NULL;
        *server_fd = -1;
        return 0;
    }

    return 1;
}

/*
 * Test SSL_new_listener for DTLS.
 * Verifies that a DTLS listener can be created from a DTLS context.
 */
static int test_dtls_new_listener(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    int success = 0;
    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)))
        goto err;
    /* Create a DTLS listener */
    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;
    /* Verify the listener is valid */
    if (!TEST_true(SSL_is_dtls(listener)))
        goto err;
    success = 1;
err:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test BIO management for DTLS listener.
 * Tests SSL_set0_rbio, SSL_set0_wbio, SSL_get_rbio, SSL_get_wbio, and SSL_set_bio.
 */
static int test_dtls_listener_bio(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    BIO *bio = NULL;
    BIO *bio2 = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)))
        goto err;

    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;

    /* Initially, there should be no BIO */
    if (!TEST_ptr_null(SSL_get_rbio(listener))
        || !TEST_ptr_null(SSL_get_wbio(listener)))
        goto err;

    /* Test SSL_set0_rbio/SSL_get_rbio */
    if (!TEST_ptr(bio = BIO_new(BIO_s_mem())))
        goto err;
    SSL_set0_rbio(listener, bio);
    if (!TEST_ptr_eq(SSL_get_rbio(listener), bio))
        goto err;
    /* bio is now owned by listener, will be freed by SSL_free */

    /* Test SSL_set0_wbio/SSL_get_wbio */
    if (!TEST_ptr(bio2 = BIO_new(BIO_s_mem())))
        goto err;
    SSL_set0_wbio(listener, bio2);
    if (!TEST_ptr_eq(SSL_get_wbio(listener), bio2))
        goto err;
    /* bio2 is now owned by listener, will be freed by SSL_free */

    /* Clear pointers since ownership transferred - SSL_free will clean up */
    bio = NULL;
    bio2 = NULL;

    success = 1;
err:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    BIO_free(bio);
    BIO_free(bio2);
    return success;
}

/*
 * Test SSL_new_listener with DTLS 1.2 only context.
 * Verifies that listeners work with DTLS 1.2.
 */
static int test_dtls_new_listener_dtls12(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION)))
        goto err;

    /* Create a DTLS listener */
    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;

    /* Verify the listener is valid */
    if (!TEST_true(SSL_is_dtls(listener)))
        goto err;

    if (!TEST_true(SSL_is_listener(listener)))
        goto err;

    success = 1;
err:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test SSL_get0_listener and SSL_is_listener on a non-listener DTLS SSL object.
 */
static int test_dtls_get0_listener_non_dtls_listener(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)))
        goto err;
    /* Create a DTLS connection object */
    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;
    /* A normal DTLS connection has no associated listener */
    if (!TEST_ptr_null(SSL_get0_listener(ssl)))
        goto err;
    /* And it is not itself a listener */
    if (!TEST_int_eq(SSL_is_listener(ssl), 0))
        goto err;
    success = 1;
err:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test SSL_get0_listener and SSL_is_listener on a DTLS_LISTENER object.
 */
static int test_dtls_get0_listener_listener(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)))
        goto err;
    /* Create a DTLS listener */
    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;
    /* The listener should identify itself as the listener */
    if (!TEST_ptr_eq(SSL_get0_listener(listener), listener))
        goto err;
    /* And SSL_is_listener should confirm it */
    if (!TEST_int_eq(SSL_is_listener(listener), 1))
        goto err;
    success = 1;
err:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test SSL_listen on a DTLS_LISTENER object.
 * The first call should set listening=1 and return 1.
 */
static int test_dtls_listen_basic(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)))
        goto err;
    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;
    /* SSL_listen on a fresh listener must succeed */
    if (!TEST_int_eq(SSL_listen(listener), 1))
        goto err;
    success = 1;
err:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test that SSL_listen returns 0 when given a normal DTLS Connection
 */
static int test_dtls_listen_wrong_type(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)))
        goto err;
    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;

    if (!TEST_int_eq(SSL_listen(ssl), 0))
        goto err;
    success = 1;
err:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test SSL_accept_connection with a non-listener DTLS SSL object.
 */
static int test_dtls_accept_connection_wrong_type(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)))
        goto err;
    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;
    /* IS_DTLS routes to ossl_dtls_accept_connection, which must reject this */
    if (!TEST_ptr_null(SSL_accept_connection(ssl, SSL_ACCEPT_CONNECTION_NO_BLOCK)))
        goto err;
    success = 1;
err:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test SSL_accept_connection on an empty queue with NO_BLOCK.
 * No connections have been queued, so NULL must be returned immediately.
 */
static int test_dtls_accept_connection_empty_no_block(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)))
        goto err;
    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;
    /* Empty queue + NO_BLOCK -> NULL, no error */
    if (!TEST_ptr_null(SSL_accept_connection(listener,
            SSL_ACCEPT_CONNECTION_NO_BLOCK)))
        goto err;
    success = 1;
err:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test SSL_get_accept_connection_queue_len with a non-listener DTLS object.
 * A plain SSL_CONNECTION must return 0.
 */
static int test_dtls_queue_len_wrong_type(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)))
        goto err;
    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;
    if (!TEST_size_t_eq(SSL_get_accept_connection_queue_len(ssl), 0))
        goto err;
    success = 1;
err:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test SSL_get_accept_connection_queue_len on an empty listener.
 * A freshly created listener with no queued connections must return 0.
 */
static int test_dtls_queue_len_empty(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)))
        goto err;
    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;
    if (!TEST_size_t_eq(SSL_get_accept_connection_queue_len(listener), 0))
        goto err;
    success = 1;
err:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test SSL_accept_connection with no net_bio and NO_BLOCK flag.
 * When there is no BIO set and the caller requests non-blocking behaviour,
 * the function must return NULL immediately without raising an error.
 */
static int test_dtls_accept_connection_no_bio_no_block(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    SSL *conn = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)))
        goto err;
    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;

    /* No BIO has been set on the listener */

    ERR_clear_error();
    conn = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);

    /* Must return NULL - no connection available, no blocking */
    if (!TEST_ptr_null(conn))
        goto err;

    if (!TEST_int_eq((int)ERR_peek_error(), 0))
        goto err;

    success = 1;
err:
    SSL_free(conn);
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test SSL_accept_connection with no net_bio and blocking mode (no NO_BLOCK).
 * When there is no BIO and the caller wants to block, the function must return
 * NULL and raise SSL_R_BIO_NOT_SET.
 */
static int test_dtls_accept_connection_no_bio_block(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    SSL *conn = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)))
        goto err;
    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;

    /* No BIO has been set on the listener */

    ERR_clear_error();
    conn = SSL_accept_connection(listener, 0); /* blocking */

    /* Must return NULL */
    if (!TEST_ptr_null(conn))
        goto err;

    /* Must have raised SSL_R_BIO_NOT_SET */
    if (!TEST_int_eq((int)ERR_GET_REASON(ERR_peek_error()), SSL_R_BIO_NOT_SET))
        goto err;

    success = 1;
err:
    ERR_clear_error();
    SSL_free(conn);
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return success;
}

#ifndef OPENSSL_NO_DTLS1_3
/*
 * Test DTLS 1.3 connection WITH HelloRetryRequest (HRR).
 *
 * This test uses SSL_new_listener API to create a DTLS 1.3 server that
 * performs a HelloRetryRequest cookie exchange before the handshake completes.
 * The server is configured to always request a cookie via HRR using the
 * stateless cookie callbacks.
 *
 * Flow:
 *   1. Create SSL contexts for DTLS 1.3 only
 *   2. Create listener (with REQUIRE_HRR flag) and client using helper
 *   3. Drive connection loop: client SSL_connect() + poll listener for IC event
 *   4. SSL_accept_connection() returns server SSL after HRR cookie validation
 *   5. Complete handshake with create_ssl_connection()
 *   6. Verify DTLS 1.3 is negotiated
 *   7. Exchange bidirectional application data
 */
static int test_dtls13_connection_with_hrr(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1, client_fd = -1;
    const char msg[] = "Hello DTLS 1.3 with HRR";
    const char reply[] = "Reply from server";
    char buf[64];
    size_t written, readbytes;
    int testresult = 0;
    int retc = -1, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr = 0;

    /* Both server and client restricted to DTLS 1.3 only */
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /* Create listener and client using helper */
    if (!TEST_true(create_dtls_listener_and_client(sctx, cctx,
            SSL_LISTENER_FLAG_REQUIRE_HRR,
            &listener, &clientssl, &server_addr,
            &server_fd, &client_fd)))
        goto end;

    /*
     * Drive the connection until SSL_accept_connection returns a server SSL.
     * We need to interleave client SSL_connect() calls with polling the listener
     * since both sides need to make progress for the HRR exchange to complete.
     */
    SSL_set_connect_state(clientssl);
    while (serverssl == NULL) {
        if (++abortctr > 100) {
            TEST_error("HRR cookie exchange loop did not converge");
            goto end;
        }

        /* Advance the client state machine */
        retc = SSL_connect(clientssl);
        err_code = SSL_get_error(clientssl, retc);
        if (retc <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect failed (err %d)", err_code);
            goto end;
        }

        /* Poll the listener for incoming connection with short timeout */
        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 100000; /* 100ms */

        if (!SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result))
            goto end;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            serverssl = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(serverssl))
        goto end;

    /*
     * SSL_accept_connection() returns after cookie validation but before the
     * handshake is complete. We need to finish the handshake ourselves.
     */
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    /* Confirm DTLS 1.3 was negotiated */
    if (!TEST_int_eq(SSL_version(serverssl), DTLS1_3_VERSION)
        || !TEST_int_eq(SSL_version(clientssl), DTLS1_3_VERSION))
        goto end;

    /* Exchange application data to verify the connection works */
    if (!TEST_true(SSL_write_ex(clientssl, msg, sizeof(msg), &written))
        || !TEST_size_t_eq(written, sizeof(msg)))
        goto end;

    if (!TEST_true(dtls_read_with_retry(serverssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg))
        || !TEST_mem_eq(buf, readbytes, msg, sizeof(msg)))
        goto end;

    /* Verify bidirectional: server sends, client receives */
    if (!TEST_true(SSL_write_ex(serverssl, reply, sizeof(reply), &written))
        || !TEST_size_t_eq(written, sizeof(reply)))
        goto end;

    if (!TEST_true(dtls_read_with_retry(clientssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(reply))
        || !TEST_mem_eq(buf, readbytes, reply, sizeof(reply)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    if (client_fd >= 0)
        BIO_closesocket(client_fd);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test DTLS 1.3 connection WITHOUT HelloRetryRequest (no HRR).
 *
 * This test uses SSL_new_listener API with the SSL_LISTENER_FLAG_NO_VALIDATE
 * flag to skip the HRR cookie exchange. The connection is added to the accept
 * queue immediately after receiving the first ClientHello.
 *
 * Flow:
 *   1. Create SSL contexts for DTLS 1.3 only
 *   2. Create listener (with NO_VALIDATE flag) and client using helper
 *   3. Drive connection loop: client SSL_connect() + poll listener for IC event
 *   4. SSL_accept_connection() returns server SSL immediately after ClientHello
 *   5. Complete handshake with create_ssl_connection()
 *   6. Verify DTLS 1.3 is negotiated
 *   7. Exchange bidirectional application data
 */
static int test_dtls13_connection_without_hrr(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1, client_fd = -1;
    const char msg[] = "Hello DTLS 1.3 without HRR";
    const char reply[] = "Reply from server";
    char buf[64];
    size_t written, readbytes;
    int testresult = 0;
    int retc = -1, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr = 0;

    /* Both server and client restricted to DTLS 1.3 only */
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /*
     * Create listener and client using helper.
     * Use NO_VALIDATE flag to skip HRR - server won't send HelloRetryRequest.
     */
    if (!TEST_true(create_dtls_listener_and_client(sctx, cctx,
            SSL_LISTENER_FLAG_NO_VALIDATE,
            &listener, &clientssl, &server_addr,
            &server_fd, &client_fd)))
        goto end;

    /*
     * Drive the connection until SSL_accept_connection returns a server SSL.
     * Without HRR (using SSL_LISTENER_FLAG_NO_VALIDATE), SSL_accept_connection
     * returns immediately after receiving the first ClientHello, but BEFORE the
     * handshake is complete. The application must finish the handshake.
     */
    SSL_set_connect_state(clientssl);
    while (serverssl == NULL) {
        if (++abortctr > 100) {
            TEST_error("Connection loop did not converge");
            goto end;
        }

        /* Advance the client state machine */
        retc = SSL_connect(clientssl);
        err_code = SSL_get_error(clientssl, retc);
        if (retc <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect failed (err %d)", err_code);
            goto end;
        }

        /* Poll the listener for incoming connection with short timeout */
        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 100000; /* 100ms */

        if (!SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result))
            goto end;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            serverssl = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(serverssl))
        goto end;

    /*
     * SSL_accept_connection() returns after receiving ClientHello but before the
     * handshake is complete. We need to finish the handshake ourselves.
     */
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    /* Confirm DTLS 1.3 was negotiated */
    if (!TEST_int_eq(SSL_version(serverssl), DTLS1_3_VERSION)
        || !TEST_int_eq(SSL_version(clientssl), DTLS1_3_VERSION))
        goto end;

    /* Exchange application data to verify the connection works */
    if (!TEST_true(SSL_write_ex(clientssl, msg, sizeof(msg), &written))
        || !TEST_size_t_eq(written, sizeof(msg)))
        goto end;

    if (!TEST_true(dtls_read_with_retry(serverssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg))
        || !TEST_mem_eq(buf, readbytes, msg, sizeof(msg)))
        goto end;

    /* Verify bidirectional: server sends, client receives */
    if (!TEST_true(SSL_write_ex(serverssl, reply, sizeof(reply), &written))
        || !TEST_size_t_eq(written, sizeof(reply)))
        goto end;

    if (!TEST_true(dtls_read_with_retry(clientssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(reply))
        || !TEST_mem_eq(buf, readbytes, reply, sizeof(reply)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    if (client_fd >= 0)
        BIO_closesocket(client_fd);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test mixed DTLS versions: DTLS 1.2 with HVR and DTLS 1.3 with HRR.
 *
 * This test demonstrates that a single listener can handle both DTLS 1.2
 * and DTLS 1.3 clients, each using their appropriate cookie exchange mechanism:
 * - DTLS 1.2 clients use HelloVerifyRequest (HVR)
 * - DTLS 1.3 clients use HelloRetryRequest (HRR)
 *
 * The test:
 *   1. Creates a listener that supports both DTLS 1.2 and DTLS 1.3
 *   2. Connects a DTLS 1.2-only client with HVR exchange
 *   3. Connects a DTLS 1.3-only client with HRR exchange
 *   4. Verifies both connections negotiate the expected version
 *   5. Verifies data can be exchanged on both connections
 */
static int test_dtls_mixed_12_hvr_and_13_hrr(void)
{
    SSL_CTX *sctx = NULL;
    SSL_CTX *cctx_12 = NULL, *cctx_13 = NULL;
    SSL *listener = NULL;
    SSL *server_12 = NULL, *client_12 = NULL;
    SSL *server_13 = NULL, *client_13 = NULL;
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1;
    int client_12_fd = -1, client_13_fd = -1;
    const char msg_12[] = "Hello DTLS 1.2";
    const char msg_13[] = "Hello DTLS 1.3";
    char buf[32];
    size_t written, readbytes;
    int testresult = 0;
    int retc, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr;

    /*
     * Create server context that supports both DTLS 1.2 and DTLS 1.3.
     * Note: We need to create separate client contexts for version pinning.
     */
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx_12, cert, privkey)))
        goto end;

    /* Pin the first client context to DTLS 1.2 only */
    if (!TEST_true(SSL_CTX_set_max_proto_version(cctx_12, DTLS1_2_VERSION)))
        goto end;

    /* Create a second client context for DTLS 1.3 only */
    cctx_13 = SSL_CTX_new(DTLS_client_method());
    if (!TEST_ptr(cctx_13))
        goto end;
    if (!TEST_true(SSL_CTX_set_min_proto_version(cctx_13, DTLS1_3_VERSION))
        || !TEST_true(SSL_CTX_set_max_proto_version(cctx_13, DTLS1_3_VERSION)))
        goto end;

    /*
     * Create a DTLS listener with both HVR and HRR requirements.
     * This ensures DTLS 1.2 clients go through HVR and DTLS 1.3 clients
     * go through HRR cookie validation.
     */
    if (!TEST_true(create_dtls_listener(sctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_REQUIRE_HRR,
            &listener, &server_addr, &server_fd)))
        goto end;

    /*
     * --- Phase 1: Connect DTLS 1.2 client with HVR ---
     */

    /* Create DTLS 1.2 client */
    if (!TEST_true(create_dtls_client_for_addr(cctx_12, server_addr,
            &client_12, &client_12_fd)))
        goto end;

    /* Drive the DTLS 1.2 connection with HVR exchange */
    retc = -1;
    abortctr = 0;
    SSL_set_connect_state(client_12);
    while (server_12 == NULL) {
        if (++abortctr > 100) {
            TEST_error("DTLS 1.2 HVR exchange loop did not converge");
            goto end;
        }

        retc = SSL_connect(client_12);
        err_code = SSL_get_error(client_12, retc);
        if (retc <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect (DTLS 1.2) failed (err %d)", err_code);
            goto end;
        }

        /* Poll the listener for incoming connection with short timeout */
        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 100000; /* 100ms */

        if (!SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result))
            goto end;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            server_12 = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(server_12))
        goto end;

    /*
     * SSL_accept_connection() returns after cookie validation but before the
     * handshake is complete. We need to finish the handshake ourselves.
     */
    if (!TEST_true(create_ssl_connection(server_12, client_12, SSL_ERROR_NONE)))
        goto end;

    /* Verify DTLS 1.2 was negotiated */
    if (!TEST_int_eq(SSL_version(server_12), DTLS1_2_VERSION)
        || !TEST_int_eq(SSL_version(client_12), DTLS1_2_VERSION))
        goto end;

    /*
     * --- Phase 2: Connect DTLS 1.3 client with HRR ---
     */

    /* Create DTLS 1.3 client */
    if (!TEST_true(create_dtls_client_for_addr(cctx_13, server_addr,
            &client_13, &client_13_fd)))
        goto end;

    /* Drive the DTLS 1.3 connection with HRR exchange */
    retc = -1;
    abortctr = 0;
    SSL_set_connect_state(client_13);
    while (server_13 == NULL) {
        if (++abortctr > 100) {
            TEST_error("DTLS 1.3 HRR exchange loop did not converge");
            goto end;
        }

        retc = SSL_connect(client_13);
        err_code = SSL_get_error(client_13, retc);
        if (retc <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect (DTLS 1.3) failed (err %d)", err_code);
            goto end;
        }

        /* Poll the listener for incoming connection with short timeout */
        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 100000; /* 100ms */

        if (!SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result))
            goto end;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            server_13 = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(server_13))
        goto end;

    /*
     * SSL_accept_connection() returns after cookie validation but before the
     * handshake is complete. We need to finish the handshake ourselves.
     */
    if (!TEST_true(create_ssl_connection(server_13, client_13, SSL_ERROR_NONE)))
        goto end;

    /* Verify DTLS 1.3 was negotiated */
    if (!TEST_int_eq(SSL_version(server_13), DTLS1_3_VERSION)
        || !TEST_int_eq(SSL_version(client_13), DTLS1_3_VERSION))
        goto end;

    /*
     * --- Phase 3: Verify both connections can exchange data ---
     */

    /* Exchange data on DTLS 1.2 connection */
    if (!TEST_true(SSL_write_ex(client_12, msg_12, sizeof(msg_12), &written))
        || !TEST_size_t_eq(written, sizeof(msg_12)))
        goto end;
    memset(buf, 0, sizeof(buf));
    if (!TEST_true(dtls_read_with_retry(server_12, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg_12))
        || !TEST_mem_eq(buf, readbytes, msg_12, sizeof(msg_12)))
        goto end;

    /* Exchange data on DTLS 1.3 connection */
    if (!TEST_true(SSL_write_ex(client_13, msg_13, sizeof(msg_13), &written))
        || !TEST_size_t_eq(written, sizeof(msg_13)))
        goto end;
    memset(buf, 0, sizeof(buf));
    if (!TEST_true(dtls_read_with_retry(server_13, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg_13))
        || !TEST_mem_eq(buf, readbytes, msg_13, sizeof(msg_13)))
        goto end;

    testresult = 1;
end:
    SSL_free(server_12);
    SSL_free(client_12);
    SSL_free(server_13);
    SSL_free(client_13);
    SSL_free(listener);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    if (client_12_fd >= 0)
        BIO_closesocket(client_12_fd);
    if (client_13_fd >= 0)
        BIO_closesocket(client_13_fd);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx_12);
    SSL_CTX_free(cctx_13);
    return testresult;
}

/*
 * Test true concurrent multi-client with real UDP sockets.
 *
 * This test verifies that:
 *   1. A DTLS listener can accept multiple concurrent clients using real sockets
 *   2. Each connection gets its own connected UDP socket after handshake
 *   3. All connections can exchange data simultaneously
 *   4. The listener continues to accept new connections while others are active
 */
static int test_dtls_concurrent_clients_real_sockets(void)
{
    SSL_CTX *sctx = NULL;
    SSL_CTX *cctx = NULL;
    SSL *listener = NULL;
    SSL *server1 = NULL, *client1 = NULL;
    SSL *server2 = NULL, *client2 = NULL;
    SSL *accepted1 = NULL, *accepted2 = NULL;
    BIO *c1_bio = NULL, *c2_bio = NULL;
    BIO_ADDR *server_addr = NULL;
    BIO_ADDR *client1_local_addr = NULL;
    BIO_ADDR *client2_local_addr = NULL;
    BIO_ADDR *server_peer_addr = NULL;
    int server_fd = -1;
    int client1_fd = -1, client2_fd = -1;
    struct in_addr ina;
    union BIO_sock_info_u info;
    const char msg1[] = "Hello from client 1";
    const char msg2[] = "Hello from client 2";
    const char reply1[] = "Reply to client 1";
    const char reply2[] = "Reply to client 2";
    char buf[64];
    size_t written, readbytes;
    int testresult = 0;
    int ret, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr;

    ina.s_addr = htonl(INADDR_LOOPBACK);

    /* Create server and client contexts */
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /*
     * Create DTLS listener with both HVR and HRR requirements.
     * This ensures address validation for both DTLS 1.2 and 1.3 clients.
     */
    if (!TEST_true(create_dtls_listener(sctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_REQUIRE_HRR,
            &listener, &server_addr, &server_fd)))
        goto end;

    if (!TEST_int_gt(BIO_ADDR_rawport(server_addr), 0))
        goto end;

    /*
     * Allocate BIO_ADDRs for tracking client local addresses
     */
    client1_local_addr = BIO_ADDR_new();
    client2_local_addr = BIO_ADDR_new();
    server_peer_addr = BIO_ADDR_new();
    if (!TEST_ptr(client1_local_addr) || !TEST_ptr(client2_local_addr)
        || !TEST_ptr(server_peer_addr))
        goto end;

    /*
     * --- Create Client 1 ---
     */
    client1_fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(client1_fd, 0))
        goto end;

    if (!TEST_true(BIO_socket_nbio(client1_fd, 1)))
        goto end;

    /* Bind client1 to ephemeral port so we can identify it later */
    if (!TEST_true(BIO_ADDR_rawmake(client1_local_addr, AF_INET, &ina, sizeof(ina), 0)))
        goto end;
    if (!TEST_true(BIO_bind(client1_fd, client1_local_addr, 0)))
        goto end;
    /* Get assigned port */
    info.addr = client1_local_addr;
    if (!TEST_true(BIO_sock_info(client1_fd, BIO_SOCK_INFO_ADDRESS, &info)))
        goto end;

    c1_bio = BIO_new_dgram(client1_fd, BIO_NOCLOSE);
    if (!TEST_ptr(c1_bio))
        goto end;

    if (!TEST_true(BIO_dgram_set_peer(c1_bio, server_addr)))
        goto end;

    client1 = SSL_new(cctx);
    if (!TEST_ptr(client1))
        goto end;

    SSL_set_bio(client1, c1_bio, c1_bio);
    c1_bio = NULL; /* ownership transferred */

    /*
     * --- Create Client 2 ---
     */
    client2_fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(client2_fd, 0))
        goto end;

    if (!TEST_true(BIO_socket_nbio(client2_fd, 1)))
        goto end;

    /* Bind client2 to ephemeral port so we can identify it later */
    if (!TEST_true(BIO_ADDR_rawmake(client2_local_addr, AF_INET, &ina, sizeof(ina), 0)))
        goto end;
    if (!TEST_true(BIO_bind(client2_fd, client2_local_addr, 0)))
        goto end;
    /* Get assigned port */
    info.addr = client2_local_addr;
    if (!TEST_true(BIO_sock_info(client2_fd, BIO_SOCK_INFO_ADDRESS, &info)))
        goto end;

    c2_bio = BIO_new_dgram(client2_fd, BIO_NOCLOSE);
    if (!TEST_ptr(c2_bio))
        goto end;

    if (!TEST_true(BIO_dgram_set_peer(c2_bio, server_addr)))
        goto end;

    client2 = SSL_new(cctx);
    if (!TEST_ptr(client2))
        goto end;

    SSL_set_bio(client2, c2_bio, c2_bio);
    c2_bio = NULL; /* ownership transferred */

    /*
     * --- Drive both clients concurrently through handshake ---
     *
     * We alternate between driving client1 and client2, while also
     * accepting connections on the listener. This simulates true
     * concurrent operation.
     */
    SSL_set_connect_state(client1);
    SSL_set_connect_state(client2);
    abortctr = 0;
    while (accepted1 == NULL || accepted2 == NULL) {
        if (++abortctr > 500) {
            TEST_error("Concurrent handshake loop did not converge");
            goto end;
        }

        /* Drive client 1 if not yet connected */
        if (accepted1 == NULL || accepted2 == NULL) {
            ret = SSL_connect(client1);
            err_code = SSL_get_error(client1, ret);
            if (ret <= 0
                && err_code != SSL_ERROR_WANT_READ
                && err_code != SSL_ERROR_WANT_WRITE) {
                TEST_error("SSL_connect (client1) failed: err=%d", err_code);
                goto end;
            }
        }

        /* Drive client 2 if not yet connected */
        if (accepted1 == NULL || accepted2 == NULL) {
            ret = SSL_connect(client2);
            err_code = SSL_get_error(client2, ret);
            if (ret <= 0
                && err_code != SSL_ERROR_WANT_READ
                && err_code != SSL_ERROR_WANT_WRITE) {
                TEST_error("SSL_connect (client2) failed: err=%d", err_code);
                goto end;
            }
        }

        /* Poll the listener for incoming connection with short timeout */
        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 100000; /* 100ms */

        if (!SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result))
            goto end;

        /* Accept connections from listener if poll indicates availability */
        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0) {
            if (accepted1 == NULL)
                accepted1 = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
            else if (accepted2 == NULL)
                accepted2 = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
        }
    }

    if (!TEST_ptr(accepted1) || !TEST_ptr(accepted2))
        goto end;

    /*
     * Match accepted connections to clients based on peer address.
     * The server's peer address should match the client's local address.
     */
    if (!TEST_true(SSL_get_peer_addr(accepted1, server_peer_addr))) {
        TEST_error("Could not get peer addr from accepted1");
        goto end;
    }

    /* Check if accepted1's peer matches client1's local address */
    if (BIO_ADDR_rawport(server_peer_addr) == BIO_ADDR_rawport(client1_local_addr)) {
        server1 = accepted1;
        server2 = accepted2;
    } else {
        /* accepted1's peer should match client2 */
        server1 = accepted2;
        server2 = accepted1;
    }

    /* Finish the handshakes for both connections */
    if (!TEST_true(create_ssl_connection(server1, client1, SSL_ERROR_NONE))) {
        TEST_error("server1/client1 handshake failed");
        goto end;
    }

    if (!TEST_true(create_ssl_connection(server2, client2, SSL_ERROR_NONE))) {
        TEST_error("server2/client2 handshake failed");
        goto end;
    }

    /* Client 1 sends to server 1 */
    if (!TEST_true(SSL_write_ex(client1, msg1, sizeof(msg1), &written))
        || !TEST_size_t_eq(written, sizeof(msg1))) {
        TEST_error("client1 write failed");
        goto end;
    }

    /* Client 2 sends to server 2 */
    if (!TEST_true(SSL_write_ex(client2, msg2, sizeof(msg2), &written))
        || !TEST_size_t_eq(written, sizeof(msg2))) {
        TEST_error("client2 write failed");
        goto end;
    }

    /* Server 1 reads from client 1 */
    memset(buf, 0, sizeof(buf));
    if (!TEST_true(dtls_read_with_retry(server1, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg1))
        || !TEST_mem_eq(buf, readbytes, msg1, sizeof(msg1))) {
        TEST_error("server1 read failed or data mismatch");
        goto end;
    }

    /* Server 2 reads from client 2 */
    memset(buf, 0, sizeof(buf));
    if (!TEST_true(dtls_read_with_retry(server2, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg2))
        || !TEST_mem_eq(buf, readbytes, msg2, sizeof(msg2))) {
        TEST_error("server2 read failed or data mismatch");
        goto end;
    }

    /* Server 1 replies to client 1 */
    if (!TEST_true(SSL_write_ex(server1, reply1, sizeof(reply1), &written))
        || !TEST_size_t_eq(written, sizeof(reply1))) {
        TEST_error("server1 reply failed");
        goto end;
    }

    /* Server 2 replies to client 2 */
    if (!TEST_true(SSL_write_ex(server2, reply2, sizeof(reply2), &written))
        || !TEST_size_t_eq(written, sizeof(reply2))) {
        TEST_error("server2 reply failed");
        goto end;
    }

    /* Client 1 receives reply using dtls_read_with_retry */
    memset(buf, 0, sizeof(buf));
    if (!TEST_true(dtls_read_with_retry(client1, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(reply1))
        || !TEST_mem_eq(buf, readbytes, reply1, sizeof(reply1))) {
        TEST_error("client1 read reply failed or data mismatch");
        goto end;
    }

    /* Client 2 receives reply using dtls_read_with_retry */
    memset(buf, 0, sizeof(buf));
    if (!TEST_true(dtls_read_with_retry(client2, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(reply2))
        || !TEST_mem_eq(buf, readbytes, reply2, sizeof(reply2))) {
        TEST_error("client2 read reply failed or data mismatch");
        goto end;
    }

    testresult = 1;

end:
    /*
     * Note: server1/server2 are aliases to accepted1/accepted2 (just reordered),
     * so only free accepted1/accepted2 to avoid double-free.
     */
    SSL_free(accepted1);
    SSL_free(accepted2);
    SSL_free(client1);
    SSL_free(client2);
    SSL_free(listener);
    BIO_free(c1_bio);
    BIO_free(c2_bio);
    BIO_ADDR_free(server_addr);
    BIO_ADDR_free(client1_local_addr);
    BIO_ADDR_free(client2_local_addr);
    BIO_ADDR_free(server_peer_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    if (client1_fd >= 0)
        BIO_closesocket(client1_fd);
    if (client2_fd >= 0)
        BIO_closesocket(client2_fd);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}
#endif /* OPENSSL_NO_DTLS1_3 */

/*
 * Test DTLS 1.2 connection WITH HelloVerifyRequest (HVR).
 *
 * This test uses SSL_new_listener API to create a DTLS 1.2 server that
 * performs a HelloVerifyRequest cookie exchange. The connection is added
 * to the accept queue after cookie validation but before handshake completion.
 *
 * Flow:
 *   1. Create SSL contexts for DTLS 1.2 only
 *   2. Create listener (with REQUIRE_HVR flag) and client using helper
 *   3. Drive connection loop: client SSL_connect() + poll listener for IC event
 *   4. SSL_accept_connection() returns server SSL after HVR cookie validation
 *   5. Complete handshake with create_ssl_connection()
 *   6. Verify DTLS 1.2 is negotiated
 *   7. Exchange bidirectional application data (client->server, server->client)
 */
static int test_dtls12_connection_with_hvr(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1, client_fd = -1;
    const char msg[] = "Hello DTLS 1.2 with HVR";
    const char reply[] = "Reply from server";
    char buf[64];
    size_t written, readbytes;
    int testresult = 0;
    int retc = -1, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr = 0;

    /* Both server and client restricted to DTLS 1.2 only */
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /* Create listener and client using helper */
    if (!TEST_true(create_dtls_listener_and_client(sctx, cctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR,
            &listener, &clientssl, &server_addr,
            &server_fd, &client_fd)))
        goto end;

    /*
     * Drive the connection until SSL_accept_connection returns a server SSL.
     * For DTLS 1.2 with HVR, SSL_accept_connection returns AFTER cookie validation
     * (i.e., after receiving the second ClientHello with valid cookie), but BEFORE
     * the handshake is complete. The application must finish the handshake.
     */
    SSL_set_connect_state(clientssl);
    while (serverssl == NULL) {
        if (++abortctr > 100) {
            TEST_error("HVR cookie exchange loop did not converge");
            goto end;
        }

        /* Advance the client state machine */
        retc = SSL_connect(clientssl);
        err_code = SSL_get_error(clientssl, retc);
        if (retc <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect failed (err %d)", err_code);
            goto end;
        }

        /* Poll the listener for incoming connection with short timeout */
        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 100000; /* 100ms */

        if (!SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result))
            goto end;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            serverssl = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(serverssl))
        goto end;

    /*
     * SSL_accept_connection() returns after cookie validation but before the
     * handshake is complete. We need to finish the handshake ourselves.
     */
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    /* Confirm DTLS 1.2 was negotiated */
    if (!TEST_int_eq(SSL_version(serverssl), DTLS1_2_VERSION)
        || !TEST_int_eq(SSL_version(clientssl), DTLS1_2_VERSION))
        goto end;

    /* Exchange application data to verify the connection works */
    if (!TEST_true(SSL_write_ex(clientssl, msg, sizeof(msg), &written))
        || !TEST_size_t_eq(written, sizeof(msg)))
        goto end;

    if (!TEST_true(dtls_read_with_retry(serverssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg))
        || !TEST_mem_eq(buf, readbytes, msg, sizeof(msg)))
        goto end;

    /* Verify bidirectional: server sends, client receives */
    if (!TEST_true(SSL_write_ex(serverssl, reply, sizeof(reply), &written))
        || !TEST_size_t_eq(written, sizeof(reply)))
        goto end;

    if (!TEST_true(dtls_read_with_retry(clientssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(reply))
        || !TEST_mem_eq(buf, readbytes, reply, sizeof(reply)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    if (client_fd >= 0)
        BIO_closesocket(client_fd);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test DTLS 1.2 connection WITHOUT HelloVerifyRequest (no HVR).
 *
 * This test uses SSL_new_listener API with the SSL_LISTENER_FLAG_NO_VALIDATE
 * flag to skip the cookie validation/HVR exchange. The connection is added
 * to the accept queue immediately after receiving the first ClientHello.
 *
 * Flow:
 *   1. Create SSL contexts for DTLS 1.2 only
 *   2. Create listener (with NO_VALIDATE flag) and client using helper
 *   3. Drive connection loop: client SSL_connect() + poll listener for IC event
 *   4. SSL_accept_connection() returns server SSL immediately after ClientHello
 *   5. Complete handshake with create_ssl_connection()
 *   6. Verify DTLS 1.2 is negotiated
 *   7. Exchange bidirectional application data (client->server, server->client)
 */
static int test_dtls12_connection_without_hvr(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1, client_fd = -1;
    const char msg[] = "Hello DTLS 1.2 without HVR";
    const char reply[] = "Reply from server";
    char buf[64];
    size_t written, readbytes;
    int testresult = 0;
    int retc = -1, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr = 0;

    /* Both server and client restricted to DTLS 1.2 only */
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /*
     * Create listener and client using helper.
     * Use NO_VALIDATE flag to skip HVR - server won't send HelloVerifyRequest.
     */
    if (!TEST_true(create_dtls_listener_and_client(sctx, cctx,
            SSL_LISTENER_FLAG_NO_VALIDATE,
            &listener, &clientssl, &server_addr,
            &server_fd, &client_fd)))
        goto end;

    /*
     * Drive the connection until SSL_accept_connection returns a server SSL.
     * Without HVR (using SSL_LISTENER_FLAG_NO_VALIDATE), SSL_accept_connection
     * returns immediately after receiving the first ClientHello, but BEFORE the
     * handshake is complete. The application must finish the handshake.
     */
    SSL_set_connect_state(clientssl);
    while (serverssl == NULL) {
        if (++abortctr > 100) {
            TEST_error("Connection loop did not converge");
            goto end;
        }

        /* Advance the client state machine */
        retc = SSL_connect(clientssl);
        err_code = SSL_get_error(clientssl, retc);
        if (retc <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect failed (err %d)", err_code);
            goto end;
        }

        /* Poll the listener for incoming connection with short timeout */
        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 100000; /* 100ms */

        if (!SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result))
            goto end;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            serverssl = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(serverssl))
        goto end;

    /*
     * SSL_accept_connection() returns after receiving ClientHello but before the
     * handshake is complete. We need to finish the handshake ourselves.
     */
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    /* Confirm DTLS 1.2 was negotiated */
    if (!TEST_int_eq(SSL_version(serverssl), DTLS1_2_VERSION)
        || !TEST_int_eq(SSL_version(clientssl), DTLS1_2_VERSION))
        goto end;

    /* Exchange application data to verify the connection works */
    if (!TEST_true(SSL_write_ex(clientssl, msg, sizeof(msg), &written))
        || !TEST_size_t_eq(written, sizeof(msg)))
        goto end;

    if (!TEST_true(dtls_read_with_retry(serverssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg))
        || !TEST_mem_eq(buf, readbytes, msg, sizeof(msg)))
        goto end;

    /* Verify bidirectional: server sends, client receives */
    if (!TEST_true(SSL_write_ex(serverssl, reply, sizeof(reply), &written))
        || !TEST_size_t_eq(written, sizeof(reply)))
        goto end;

    if (!TEST_true(dtls_read_with_retry(clientssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(reply))
        || !TEST_mem_eq(buf, readbytes, reply, sizeof(reply)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    if (client_fd >= 0)
        BIO_closesocket(client_fd);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test SSL_get_peer_addr on a fresh SSL object with no peer.
 * A connection that has not completed handshake should return 0.
 */
static int test_dtls_get_peer_addr_no_peer(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO_ADDR *peer_addr = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method())))
        goto err;

    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;

    peer_addr = BIO_ADDR_new();
    if (!TEST_ptr(peer_addr))
        goto err;

    /* Fresh SSL has no peer, should return 0 */
    if (!TEST_int_eq(SSL_get_peer_addr(ssl, peer_addr), 0))
        goto err;

    success = 1;
err:
    BIO_ADDR_free(peer_addr);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test SSL_get_peer_addr on a listener object.
 * A listener doesn't have a peer address, should return 0.
 */
static int test_dtls_get_peer_addr_listener(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    BIO_ADDR *peer_addr = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method())))
        goto err;

    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;

    peer_addr = BIO_ADDR_new();
    if (!TEST_ptr(peer_addr))
        goto err;

    /* Listener has no peer, should return 0 */
    if (!TEST_int_eq(SSL_get_peer_addr(listener, peer_addr), 0))
        goto err;

    success = 1;
err:
    BIO_ADDR_free(peer_addr);
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test SSL_new_listener with NULL context.
 * Should return NULL and not crash.
 */
static int test_dtls_new_listener_null_ctx(void)
{
    SSL *listener = NULL;
    int success = 0;

    ERR_clear_error();

    /* SSL_new_listener with NULL ctx should return NULL */
    listener = SSL_new_listener(NULL, 0);
    if (!TEST_ptr_null(listener))
        goto err;

    success = 1;
err:
    SSL_free(listener);
    ERR_clear_error();
    return success;
}

/*
 * Test SSL_new_listener with a TLS (non-DTLS) context.
 * Should return NULL because listeners are only for DTLS/QUIC.
 */
static int test_tls_new_listener_fails(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    int success = 0;

    /* Create a TLS context (not DTLS) */
    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_server_method())))
        goto err;

    ERR_clear_error();

    /* SSL_new_listener should fail for TLS contexts */
    listener = SSL_new_listener(ctx, 0);
    if (!TEST_ptr_null(listener))
        goto err;

    success = 1;
err:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return success;
}

/*
 * Test SSL_new_listener_from for DTLS.
 * Currently SSL_new_listener_from is QUIC-only, so it should return NULL for DTLS.
 */
static int test_dtls_new_listener_from_returns_null(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL *listener = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method())))
        goto err;

    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;

    ERR_clear_error();

    /* SSL_new_listener_from should return NULL for DTLS */
    listener = SSL_new_listener_from(ssl, 0);
    if (!TEST_ptr_null(listener))
        goto err;

    success = 1;
err:
    SSL_free(listener);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return success;
}

/*
 * Test SSL_listen_ex for DTLS.
 * Currently SSL_listen_ex is QUIC-only, so it should return 0 for DTLS.
 */
static int test_dtls_listen_ex_returns_error(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    SSL *new_conn = NULL;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method())))
        goto err;

    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;

    if (!TEST_ptr(new_conn = SSL_new(ctx)))
        goto err;

    ERR_clear_error();

    /* SSL_listen_ex should return 0 for DTLS */
    if (!TEST_int_eq(SSL_listen_ex(listener, new_conn), 0))
        goto err;

    success = 1;
err:
    SSL_free(new_conn);
    SSL_free(listener);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return success;
}

/*
 * Counter to track how many times the test time callback is invoked.
 */
static int test_now_cb_call_count = 0;

/*
 * Test time callback that returns a fixed time and tracks invocation count.
 */
static OSSL_TIME test_fake_now_cb(void *arg)
{
    uint64_t *fake_time_secs = (uint64_t *)arg;

    test_now_cb_call_count++;
    return ossl_seconds2time(*fake_time_secs);
}

/*
 * Test ossl_dtls_listener_set_override_now_cb basic functionality.
 *
 * This test verifies that:
 * 1. The time callback can be set on a DTLS listener
 * 2. Setting a NULL callback is allowed (resets to default behavior)
 * 3. The function returns success/failure appropriately
 */
static int test_dtls_listener_time_callback_basic(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    uint64_t fake_time = 1700000000; /* A fixed timestamp */
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method())))
        goto err;

    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;

    /* Setting the time callback should succeed */
    if (!TEST_true(ossl_dtls_listener_set_override_now_cb(listener,
            test_fake_now_cb,
            &fake_time)))
        goto err;

    /* Setting callback to NULL should also succeed (resets to default) */
    if (!TEST_true(ossl_dtls_listener_set_override_now_cb(listener, NULL, NULL)))
        goto err;

    success = 1;
err:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test ossl_dtls_listener_set_override_now_cb with invalid arguments.
 *
 * This test verifies that the function handles invalid arguments gracefully:
 * 1. NULL SSL pointer should return 0
 * 2. Non-listener SSL should return 0
 */
static int test_dtls_listener_time_callback_invalid(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL *listener = NULL;
    uint64_t fake_time = 1700000000;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method())))
        goto err;

    /* Create a regular SSL connection (not a listener) */
    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;

    /* Setting time callback on NULL should fail */
    if (!TEST_false(ossl_dtls_listener_set_override_now_cb(NULL,
            test_fake_now_cb,
            &fake_time)))
        goto err;

    /* Setting time callback on a non-listener SSL should fail */
    if (!TEST_false(ossl_dtls_listener_set_override_now_cb(ssl,
            test_fake_now_cb,
            &fake_time)))
        goto err;

    /* Verify that a listener succeeds for contrast */
    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;

    if (!TEST_true(ossl_dtls_listener_set_override_now_cb(listener,
            test_fake_now_cb,
            &fake_time)))
        goto err;

    success = 1;
err:
    SSL_free(listener);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test SSL_listener_set_pending_timeout basic functionality.
 *
 * This test verifies that:
 * 1. The pending timeout can be set and retrieved on a DTLS listener
 * 2. Different timeout values can be set
 * 3. UINT64_MAX can be used to disable timeout
 */
static int test_dtls_listener_pending_timeout_basic(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    uint64_t timeout, retrieved;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method())))
        goto err;

    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;

    /* Default timeout should be 30 seconds (30000 ms) */
    retrieved = SSL_listener_get_pending_timeout(listener);
    if (!TEST_uint64_t_eq(retrieved, 30000))
        goto err;

    /* Set a custom timeout of 60 seconds (60000 ms) */
    timeout = 60000;
    if (!TEST_true(SSL_listener_set_pending_timeout(listener, timeout)))
        goto err;

    /* Verify the timeout was set */
    retrieved = SSL_listener_get_pending_timeout(listener);
    if (!TEST_uint64_t_eq(retrieved, timeout))
        goto err;

    /* Set timeout to UINT64_MAX (disable) */
    if (!TEST_true(SSL_listener_set_pending_timeout(listener, UINT64_MAX)))
        goto err;

    /* Verify infinite timeout */
    retrieved = SSL_listener_get_pending_timeout(listener);
    if (!TEST_uint64_t_eq(retrieved, UINT64_MAX))
        goto err;

    /* Set a very short timeout (1 second = 1000 ms) */
    timeout = 1000;
    if (!TEST_true(SSL_listener_set_pending_timeout(listener, timeout)))
        goto err;

    retrieved = SSL_listener_get_pending_timeout(listener);
    if (!TEST_uint64_t_eq(retrieved, timeout))
        goto err;

    success = 1;
err:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test SSL_listener_set_pending_timeout with invalid arguments.
 *
 * This test verifies that the function handles invalid arguments gracefully:
 * 1. NULL SSL pointer should return 0
 * 2. Non-listener SSL should return 0
 * 3. Get on NULL/non-listener should return 0
 */
static int test_dtls_listener_pending_timeout_invalid(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL *listener = NULL;
    uint64_t timeout;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method())))
        goto err;

    /* Create a regular SSL connection (not a listener) */
    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;

    timeout = 60000; /* 60 seconds in ms */

    /* Setting timeout on NULL should fail */
    if (!TEST_false(SSL_listener_set_pending_timeout(NULL, timeout)))
        goto err;

    /* Setting timeout on a non-listener SSL should fail */
    if (!TEST_false(SSL_listener_set_pending_timeout(ssl, timeout)))
        goto err;

    /* Get on NULL should return zero */
    if (!TEST_uint64_t_eq(SSL_listener_get_pending_timeout(NULL), 0))
        goto err;

    /* Get on non-listener should return zero */
    if (!TEST_uint64_t_eq(SSL_listener_get_pending_timeout(ssl), 0))
        goto err;

    /* Verify that a listener succeeds for contrast */
    if (!TEST_ptr(listener = SSL_new_listener(ctx, 0)))
        goto err;

    if (!TEST_true(SSL_listener_set_pending_timeout(listener, timeout)))
        goto err;

    success = 1;
err:
    SSL_free(listener);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return success;
}

#endif /* !OPENSSL_NO_SOCK && !OPENSSL_NO_DTLS */

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

#if !defined(OPENSSL_NO_SOCK) && !defined(OPENSSL_NO_DTLS)
    /* Basic listener creation and configuration tests */
    ADD_TEST(test_dtls_new_listener);
    ADD_TEST(test_dtls_new_listener_dtls12);

    /* BIO management tests */
    ADD_TEST(test_dtls_listener_bio);

    /* Listener API tests */
    ADD_TEST(test_dtls_get0_listener_non_dtls_listener);
    ADD_TEST(test_dtls_get0_listener_listener);
    ADD_TEST(test_dtls_listen_basic);
    ADD_TEST(test_dtls_listen_wrong_type);

    /* Accept connection tests */
    ADD_TEST(test_dtls_accept_connection_wrong_type);
    ADD_TEST(test_dtls_accept_connection_empty_no_block);
    ADD_TEST(test_dtls_accept_connection_no_bio_no_block);
    ADD_TEST(test_dtls_accept_connection_no_bio_block);

    /* Queue length tests */
    ADD_TEST(test_dtls_queue_len_wrong_type);
    ADD_TEST(test_dtls_queue_len_empty);

    /* Peer address tests */
    ADD_TEST(test_dtls_get_peer_addr_no_peer);
    ADD_TEST(test_dtls_get_peer_addr_listener);

    /* Error handling and edge case tests */
    ADD_TEST(test_dtls_new_listener_null_ctx);
    ADD_TEST(test_tls_new_listener_fails);
    ADD_TEST(test_dtls_new_listener_from_returns_null);
    ADD_TEST(test_dtls_listen_ex_returns_error);

    /* DTLS 1.2 connection tests */
    ADD_TEST(test_dtls12_connection_with_hvr);
    ADD_TEST(test_dtls12_connection_without_hvr);

#ifndef OPENSSL_NO_DTLS1_3
    /* DTLS 1.3 connection tests */
    ADD_TEST(test_dtls13_connection_with_hrr);
    ADD_TEST(test_dtls13_connection_without_hrr);

    /* Mixed version tests */
    ADD_TEST(test_dtls_mixed_12_hvr_and_13_hrr);

    /* Concurrent client tests */
    ADD_TEST(test_dtls_concurrent_clients_real_sockets);
#endif /* OPENSSL_NO_DTLS1_3 */

    /* Time callback tests (internal API) */
    ADD_TEST(test_dtls_listener_time_callback_basic);
    ADD_TEST(test_dtls_listener_time_callback_invalid);

    /* Pending timeout tests (internal API) */
    ADD_TEST(test_dtls_listener_pending_timeout_basic);
    ADD_TEST(test_dtls_listener_pending_timeout_invalid);
#endif /* !OPENSSL_NO_SOCK && !OPENSSL_NO_DTLS */

    return 1;
}
