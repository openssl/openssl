/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
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

/*
 * Helper function that waits for data using SSL_poll and then reads.
 * Uses SSL_poll() to wait for data since server connections from a listener
 * don't have their own socket fd.
 *
 * This function retries in a loop because SSL_poll() may report data is
 * available (based on the URXE queue having encrypted records) but SSL_read_ex()
 * may return SSL_ERROR_WANT_READ if those records don't yet constitute a
 * complete application data message. The retry loop allows the
 * demux to pump additional packets and complete the message.
 */
#define DTLS_READ_TIMEOUT_SEC 2
#define DTLS_READ_MAX_RETRIES 10

static int dtls_read_with_retry(SSL *ssl, void *buf, size_t bufsize,
    size_t *readbytes)
{
    SSL_POLL_ITEM item;
    struct timeval timeout;
    size_t result_count;
    int ret, err, retries;

    item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    item.desc.value.ssl = ssl;
    item.events = SSL_POLL_EVENT_R;
    item.revents = 0;

    timeout.tv_sec = DTLS_READ_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    for (retries = 0; retries < DTLS_READ_MAX_RETRIES; retries++) {
        item.revents = 0;
        if (!SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count)) {
            TEST_error("SSL_poll failed");
            return 0;
        }

        /* No data yet or not read-ready, continue polling */
        if (result_count == 0 || (item.revents & SSL_POLL_EVENT_R) == 0)
            continue;

        ret = SSL_read_ex(ssl, buf, bufsize, readbytes);
        if (ret == 1)
            return 1;

        err = SSL_get_error(ssl, ret);
        if (err != SSL_ERROR_WANT_READ) {
            TEST_error("SSL_read_ex failed with error %d", err);
            return 0;
        }
        /* SSL_ERROR_WANT_READ: retry the poll/read cycle */
    }

    TEST_error("dtls_read_with_retry exhausted retries");
    return 0;
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
    listener_bio = NULL;

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
    c_bio = NULL;

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
 * Helper to create a DTLS listener and client using memory BIOs.
 *
 * This uses BIO_new_bio_dgram_pair() to create a connected pair of dgram BIOs
 * for in-memory testing without real sockets.
 */
static int create_dtls_listener_and_client_mem(SSL_CTX *sctx, SSL_CTX *cctx,
    uint64_t listener_flags,
    SSL **listener, SSL **clientssl,
    BIO_ADDR **client_addr)
{
    BIO *server_bio = NULL, *client_bio = NULL;
    BIO_ADDR *server_addr = NULL;
    BIO_ADDR *client_local_addr = NULL;
    struct in_addr ina;
    int ret = 0;
    int bio_caps = BIO_DGRAM_CAP_HANDLES_DST_ADDR | BIO_DGRAM_CAP_HANDLES_SRC_ADDR;

    *listener = NULL;
    *clientssl = NULL;
    *client_addr = NULL;

    /* Create dgram BIO pair for in-memory communication */
    if (!TEST_int_eq(BIO_new_bio_dgram_pair(&server_bio, 0, &client_bio, 0), 1))
        goto err;

    /* Set capabilities on both BIOs to support addressed mode */
    if (!TEST_true(BIO_dgram_set_caps(server_bio, bio_caps))
        || !TEST_true(BIO_dgram_set_caps(client_bio, bio_caps)))
        goto err;

    ina.s_addr = htonl(INADDR_LOOPBACK);

    /* Create and set server's local address (127.0.0.1:54321) */
    if (!TEST_ptr(server_addr = BIO_ADDR_new()))
        goto err;
    if (!TEST_true(BIO_ADDR_rawmake(server_addr, AF_INET, &ina,
            sizeof(ina), htons(54321))))
        goto err;
    if (!TEST_int_eq(BIO_dgram_set0_local_addr(server_bio, server_addr), 1))
        goto err;
    server_addr = NULL; /* ownership transferred */

    /* Create and set client's local address (127.0.0.1:12345) */
    if (!TEST_ptr(client_local_addr = BIO_ADDR_new()))
        goto err;
    if (!TEST_true(BIO_ADDR_rawmake(client_local_addr, AF_INET, &ina,
            sizeof(ina), htons(12345))))
        goto err;
    if (!TEST_int_eq(BIO_dgram_set0_local_addr(client_bio, client_local_addr), 1))
        goto err;
    client_local_addr = NULL; /* ownership transferred */

    /* Create the listener and attach the server BIO */
    if (!TEST_ptr(*listener = SSL_new_listener(sctx, listener_flags)))
        goto err;

    SSL_set_bio(*listener, server_bio, server_bio);
    server_bio = NULL; /* ownership transferred */

    /* Start listening */
    if (!TEST_int_eq(SSL_listen(*listener), 1))
        goto err;

    /* Create client SSL */
    if (!TEST_ptr(*clientssl = SSL_new(cctx)))
        goto err;

    /*
     * NOTE: For regular DTLS clients with dgram pair BIOs, we do NOT call
     * SSL_set1_initial_peer_addr(). That function is for listener-created
     * connections. For dgram pairs, the BIOs are already connected and
     * BIO_write() will work without an explicit peer address.
     */

    /* Attach the client BIO */
    SSL_set_bio(*clientssl, client_bio, client_bio);
    client_bio = NULL; /* ownership transferred */

    /* Create the returned client_addr for the caller */
    if (!TEST_ptr(*client_addr = BIO_ADDR_new()))
        goto err;
    if (!TEST_true(BIO_ADDR_rawmake(*client_addr, AF_INET, &ina,
            sizeof(ina), htons(12345))))
        goto err;

    ret = 1;

err:
    BIO_free(server_bio);
    BIO_free(client_bio);
    BIO_ADDR_free(server_addr);
    BIO_ADDR_free(client_local_addr);
    if (ret == 0) {
        SSL_free(*listener);
        SSL_free(*clientssl);
        BIO_ADDR_free(*client_addr);
        *listener = NULL;
        *clientssl = NULL;
        *client_addr = NULL;
    }
    return ret;
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
    conn = SSL_accept_connection(listener, 0);

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
    BIO_ADDR *client_addr = NULL;
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

    /* Create listener and client using memory BIO helper */
    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_REQUIRE_HRR,
            &listener, &clientssl, &client_addr)))
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

        /* Poll the listener for incoming connection */
        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
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
    BIO_ADDR_free(client_addr);
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
    BIO_ADDR *client_addr = NULL;
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
     * Create listener and client using memory BIO helper.
     * Use NO_VALIDATE flag to skip HRR - server won't send HelloRetryRequest.
     */
    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_NO_VALIDATE,
            &listener, &clientssl, &client_addr)))
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

        /* Poll the listener for incoming connection */
        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
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
    BIO_ADDR_free(client_addr);
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
        poll_timeout.tv_usec = 100000;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
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
        poll_timeout.tv_usec = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
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
    c1_bio = NULL;

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
    c2_bio = NULL;

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
        poll_timeout.tv_usec = 100000;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
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
    BIO_ADDR *client_addr = NULL;
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

    /* Create listener and client using memory BIO helper */
    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR,
            &listener, &clientssl, &client_addr)))
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

        /* Poll the listener for incoming connection */
        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
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
    BIO_ADDR_free(client_addr);
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
    BIO_ADDR *client_addr = NULL;
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
     * Create listener and client using memory BIO helper.
     * Use NO_VALIDATE flag to skip HVR - server won't send HelloVerifyRequest.
     */
    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_NO_VALIDATE,
            &listener, &clientssl, &client_addr)))
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

        /* Poll the listener for incoming connection */
        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
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
    BIO_ADDR_free(client_addr);
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
    uint64_t fake_time = 1700000000;
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

    timeout = 60000;

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

/*
 * Test: Free listener with connection in pending_conns only.
 *
 * This test creates a listener and starts a client handshake but does NOT
 * complete it. The connection will be in pending_conns when the listener
 * is freed. The listener should properly free the SSL object.
 */
static int test_ssl_ownership_pending_conn_leak(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clientssl = NULL;
    BIO_ADDR *client_addr = NULL;
    int testresult = 0;
    int ret, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR,
            &listener, &clientssl, &client_addr)))
        goto end;

    SSL_set_connect_state(clientssl);
    ret = SSL_connect(clientssl);
    err_code = SSL_get_error(clientssl, ret);
    if (!TEST_int_le(ret, 0)
        || !TEST_true(err_code == SSL_ERROR_WANT_READ
            || err_code == SSL_ERROR_WANT_WRITE))
        goto end;

    /*
     * Listener processes the ClientHello.
     * This creates a pending connection in pending_conns and sends HVR.
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = listener;
    poll_item.events = SSL_POLL_EVENT_IC;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
        goto end;

    /*
     * Now the pending connection is in pending_conns and if we have a
     * leak the ASAN tests will detect it
     */
    testresult = 1;

end:
    /* Clean up - listener should free pending_conns SSL objects */
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_ADDR_free(client_addr);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test: Free listener with connection in incoming_connections.
 *
 * This test creates a listener, completes a handshake so the connection
 * moves to incoming_connections, but does NOT call SSL_accept_connection().
 * This means the connection will be in the incoming_connections queue.
 * The listener should properly free the SSL object when destroyed.
 */
static int test_ssl_ownership_incoming_conn_leak(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clientssl = NULL;
    BIO_ADDR *client_addr = NULL;
    int testresult = 0;
    int ret, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr = 0;
    int conn_ready = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR,
            &listener, &clientssl, &client_addr)))
        goto end;

    SSL_set_connect_state(clientssl);
    while (!conn_ready) {
        if (++abortctr > 100) {
            TEST_error("Handshake did not converge");
            goto end;
        }

        /* Drive the client side */
        ret = SSL_connect(clientssl);
        err_code = SSL_get_error(clientssl, ret);
        if (ret <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            /* Only fail if we haven't seen the connection ready yet */
            if (!conn_ready) {
                TEST_error("SSL_connect failed (err %d)", err_code);
                goto end;
            }
        }

        /* Poll the listener to drive server-side handshake */
        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
            goto end;

        /*
         * Check if a connection is ready (in incoming_connections).
         * Do NOT call SSL_accept_connection() - we want to leave it there.
         */
        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            conn_ready = 1;
    }

    /*
     * When we free the listener, it should free the SSL in incoming_connections.
     * If there's a leak, ASAN will detect it.
     */
    testresult = 1;

end:
    /*
     * We do NOT free any serverssl here because we never called accept.
     * The listener owns the connection and should free it.
     */
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_ADDR_free(client_addr);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test: Three connections with different ownership states.
 *
 * This test creates three connections:
 *   1. One accepted by user (user owns)
 *   2. One in incoming_connections (complete, not accepted, listener owns)
 *   3. One in pending_conns (handshake in progress, listener owns)
 *
 * When the listener is freed:
 *   - Connection 1 should NOT be freed by listener (user frees it)
 *   - Connection 2 should be freed by listener
 *   - Connection 3 should be freed by listener
 */
static int test_ssl_ownership_three_conn_states(void)
{
    SSL_CTX *sctx = NULL;
    SSL_CTX *cctx = NULL;
    SSL *listener = NULL;
    SSL *client1 = NULL, *client2 = NULL, *client3 = NULL;
    SSL *accepted1 = NULL;
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1;
    int client1_fd = -1, client2_fd = -1, client3_fd = -1;
    int testresult = 0;
    int ret, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr;
    int conn2_ready = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener(sctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR,
            &listener, &server_addr, &server_fd)))
        goto end;

    /*
     * --- Connection 1: Complete handshake AND accept (user owns) ---
     */
    if (!TEST_true(create_dtls_client_for_addr(cctx, server_addr,
            &client1, &client1_fd)))
        goto end;

    SSL_set_connect_state(client1);
    abortctr = 0;
    while (accepted1 == NULL) {
        if (++abortctr > 100) {
            TEST_error("Connection 1 handshake did not converge");
            goto end;
        }

        ret = SSL_connect(client1);
        err_code = SSL_get_error(client1, ret);
        if (ret <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE)
            break;

        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 100000;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
            goto end;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            accepted1 = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(accepted1))
        goto end;

    if (!TEST_true(create_ssl_connection(accepted1, client1, SSL_ERROR_NONE)))
        goto end;

    /*
     * --- Connection 2: Complete handshake but don't accept (listener owns) ---
     *
     * Drive handshake to completion via listener tick, but do NOT call
     * SSL_accept_connection(). The connection will be in incoming_connections.
     */
    if (!TEST_true(create_dtls_client_for_addr(cctx, server_addr,
            &client2, &client2_fd)))
        goto end;

    SSL_set_connect_state(client2);
    abortctr = 0;
    while (!conn2_ready) {
        if (++abortctr > 100) {
            TEST_error("Connection 2 handshake did not converge");
            goto end;
        }

        ret = SSL_connect(client2);
        err_code = SSL_get_error(client2, ret);
        if (ret <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE
            && !conn2_ready) {
            TEST_error("Connection 2 handshake failed unexpectedly");
            goto end;
        }

        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 100000;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
            goto end;

        /*
         * Check if connection is ready. Do NOT call SSL_accept_connection()
         * - we want it to stay in incoming_connections.
         */
        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            conn2_ready = 1;
    }

    /*
     * --- Connection 3: Start handshake but don't complete (listener owns) ---
     */
    if (!TEST_true(create_dtls_client_for_addr(cctx, server_addr,
            &client3, &client3_fd)))
        goto end;

    SSL_set_connect_state(client3);
    ret = SSL_connect(client3);
    err_code = SSL_get_error(client3, ret);
    if (!TEST_int_le(ret, 0)
        || !TEST_true(err_code == SSL_ERROR_WANT_READ
            || err_code == SSL_ERROR_WANT_WRITE))
        goto end;

    /* Listener processes the ClientHello - creates SSL in pending_conns */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = listener;
    poll_item.events = SSL_POLL_EVENT_R;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 100000;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
        goto end;

    /*
     * Now we have:
     *   - Connection 1 (accepted1): accepted by user (user owns)
     *   - Connection 2: in incoming_connections (listener owns)
     *   - Connection 3: in pending_conns (listener owns)
     *
     * When we free the listener, it should:
     *   - NOT double-free accepted1 (we free it ourselves)
     *   - Free the incoming connection for client2
     *   - Free the pending connection for client3
     */
    testresult = 1;

end:
    /* User-owned connection - we free it */
    SSL_free(accepted1);

    /* Client SSLs - we always own these */
    SSL_free(client1);
    SSL_free(client2);
    SSL_free(client3);

    /* Listener frees pending_conns and incoming_connections */
    SSL_free(listener);

    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    if (client1_fd >= 0)
        BIO_closesocket(client1_fd);
    if (client2_fd >= 0)
        BIO_closesocket(client2_fd);
    if (client3_fd >= 0)
        BIO_closesocket(client3_fd);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test: SSL_set0_rbio with pending connections causes leak.
 *
 * This test verifies that when SSL_set0_rbio is called on a listener
 * with connections in pending_conns, those connections are properly freed.
 */
static int test_ssl_ownership_set_rbio_pending_leak(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clientssl = NULL;
    BIO_ADDR *client_addr = NULL;
    BIO *new_server_bio = NULL;
    int testresult = 0;
    int ret, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR,
            &listener, &clientssl, &client_addr)))
        goto end;

    /*
     * Client sends initial ClientHello.
     */
    SSL_set_connect_state(clientssl);
    ret = SSL_connect(clientssl);
    err_code = SSL_get_error(clientssl, ret);
    if (!TEST_int_le(ret, 0)
        || !TEST_true(err_code == SSL_ERROR_WANT_READ
            || err_code == SSL_ERROR_WANT_WRITE))
        goto end;

    /*
     * Listener processes the ClientHello.
     * This creates a pending connection in pending_conns and sends HVR.
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = listener;
    poll_item.events = SSL_POLL_EVENT_IC;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
        goto end;

    /*
     * The pending connection is still in pending_conns, NOT in incoming_connections.
     * Now we call SSL_set0_rbio which should free the pending connections.
     * If there's a leak, ASAN will detect it.
     */

    /* Create a new mem BIO for the replacement */
    if (!TEST_ptr(new_server_bio = BIO_new(BIO_s_mem())))
        goto end;

    /*
     * Replace the BIO - this should trigger cleanup of pending_conns.
     * If there's a leak, ASAN will detect it.
     */
    SSL_set0_rbio(listener, new_server_bio);
    new_server_bio = NULL;

    testresult = 1;

end:
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_free(new_server_bio);
    BIO_ADDR_free(client_addr);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test: SSL_set0_rbio with completed connection in incoming_connections.
 *
 * This test verifies that when SSL_set0_rbio is called on a listener
 * with connections in incoming_connections (completed but not accepted),
 * those connections are properly freed.
 */
static int test_ssl_ownership_set_rbio_incoming_leak(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clientssl = NULL;
    BIO_ADDR *client_addr = NULL;
    BIO *new_server_bio = NULL;
    int testresult = 0;
    int ret, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr = 0;
    int conn_ready = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR,
            &listener, &clientssl, &client_addr)))
        goto end;

    SSL_set_connect_state(clientssl);
    while (!conn_ready) {
        if (++abortctr > 100) {
            TEST_error("Handshake did not converge");
            goto end;
        }

        /* Drive the client side */
        ret = SSL_connect(clientssl);
        err_code = SSL_get_error(clientssl, ret);
        if (ret <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            /* Only fail if we haven't seen the connection ready yet */
            if (!conn_ready) {
                TEST_error("SSL_connect failed with error %d", err_code);
                goto end;
            }
        }

        /* Poll the listener to drive server-side handshake */
        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
            goto end;

        /*
         * Check if a connection is ready (in incoming_connections).
         * Do NOT call SSL_accept_connection() - we want to leave it there.
         */
        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            conn_ready = 1;
    }

    /*
     * Now call SSL_set0_rbio which should free the incoming connections.
     * If there's a leak, ASAN will detect it.
     */

    /* Create a new mem BIO for the replacement */
    if (!TEST_ptr(new_server_bio = BIO_new(BIO_s_mem())))
        goto end;

    SSL_set0_rbio(listener, new_server_bio);
    new_server_bio = NULL;

    testresult = 1;

end:
    /* Do NOT free serverssl - we never called SSL_accept_connection() */
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_free(new_server_bio);
    BIO_ADDR_free(client_addr);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test: User accepts connection and frees it - no double-free.
 *
 * This test verifies that when a user accepts a connection and frees it,
 * the listener does not double-free when it is destroyed.
 */
static int test_ssl_ownership_accept_free_no_double_free(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clientssl = NULL;
    SSL *serverssl = NULL;
    BIO_ADDR *client_addr = NULL;
    int testresult = 0;
    int ret, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR,
            &listener, &clientssl, &client_addr)))
        goto end;

    SSL_set_connect_state(clientssl);
    while (serverssl == NULL) {
        if (++abortctr > 100) {
            TEST_error("Handshake did not converge");
            goto end;
        }

        ret = SSL_connect(clientssl);
        err_code = SSL_get_error(clientssl, ret);

        if (ret <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect failed with error %d", err_code);
            goto end;
        }

        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
            goto end;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            serverssl = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(serverssl))
        goto end;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    /*
     * User owns serverssl now. Free it before freeing the listener.
     * The listener should NOT try to free it again.
     */
    SSL_free(serverssl);
    serverssl = NULL;

    /*
     * Now free the listener. If there's a double-free bug, ASAN will catch it.
     */
    SSL_free(listener);
    listener = NULL;

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_ADDR_free(client_addr);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test: Multiple pending connections, free listener mid-handshake.
 *
 * This test creates multiple clients that start handshakes but don't
 * complete them. All pending connections should be freed when the
 * listener is destroyed.
 */
static int test_ssl_ownership_multiple_pending_leak(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clients[3] = { NULL, NULL, NULL };
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1;
    int client_fds[3] = { -1, -1, -1 };
    int testresult = 0;
    int ret, err_code;
    int i;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener(sctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR,
            &listener, &server_addr, &server_fd)))
        goto end;

    for (i = 0; i < 3; i++) {
        /* Create client */
        if (!TEST_true(create_dtls_client_for_addr(cctx, server_addr,
                &clients[i], &client_fds[i])))
            goto end;

        /* Client sends initial ClientHello */
        SSL_set_connect_state(clients[i]);
        ret = SSL_connect(clients[i]);
        err_code = SSL_get_error(clients[i], ret);
        if (!TEST_int_le(ret, 0)
            || !TEST_true(err_code == SSL_ERROR_WANT_READ
                || err_code == SSL_ERROR_WANT_WRITE))
            goto end;

        /* Listener processes the ClientHello - creates SSL in pending_conns */
        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
            goto end;
    }

    /*
     * Now we have 3 connections in pending_conns.
     * Free the listener - it should free all pending SSL objects.
     * If there's a leak, ASAN will detect it.
     */
    testresult = 1;

end:
    for (i = 0; i < 3; i++) {
        SSL_free(clients[i]);
        if (client_fds[i] >= 0)
            BIO_closesocket(client_fds[i]);
    }
    SSL_free(listener);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/* Helper for timeout test - fake time value */
static OSSL_TIME timeout_test_fake_time;

/* Helper callback that returns our fake time */
static OSSL_TIME timeout_test_now_cb(void *arg)
{
    return timeout_test_fake_time;
}

static int test_ssl_ownership_pending_timeout_cleanup(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clientssl = NULL;
    BIO_ADDR *client_addr = NULL;
    int testresult = 0;
    int ret, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR,
            &listener, &clientssl, &client_addr)))
        goto end;

    if (!TEST_true(SSL_listener_set_pending_timeout(listener, 1000)))
        goto end;

    /* Set our fake time callback */
    timeout_test_fake_time = ossl_time_from_time_t(1700000000);
    if (!TEST_true(ossl_dtls_listener_set_override_now_cb(listener,
            timeout_test_now_cb, NULL)))
        goto end;

    /*
     * Client sends initial ClientHello.
     */
    SSL_set_connect_state(clientssl);
    ret = SSL_connect(clientssl);
    err_code = SSL_get_error(clientssl, ret);
    if (!TEST_int_le(ret, 0)
        || !TEST_true(err_code == SSL_ERROR_WANT_READ
            || err_code == SSL_ERROR_WANT_WRITE))
        goto end;

    /*
     * Listener processes the ClientHello.
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = listener;
    poll_item.events = SSL_POLL_EVENT_IC;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
        goto end;

    /*
     * Advance the fake time past the timeout (more than 1 second).
     * The next tick should detect the timeout and free the pending connection.
     */
    timeout_test_fake_time = ossl_time_add(timeout_test_fake_time,
        ossl_seconds2time(5));

    /* Trigger a tick to process the timeout */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = listener;
    poll_item.events = SSL_POLL_EVENT_IC;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
        goto end;

    /*
     * The pending connection should have been timed out and freed by the listener.
     * If there's a leak (timeout didn't free the SSL), ASAN will detect it.
     *
     * Now free the listener - it should have nothing left in pending_conns
     * since the timeout already cleaned it up.
     */
    testresult = 1;

end:
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_ADDR_free(client_addr);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test: SSL_poll() with SSL_POLL_EVENT_W on established connection.
 *
 * This test verifies that SSL_POLL_EVENT_W (writable) always returns
 * true on an established DTLS connection, since DTLS connections are
 * always ready for writing.
 */
static int test_dtls_poll_conn_event_w(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO_ADDR *client_addr = NULL;
    int testresult = 0;
    int retc, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx, 0,
            &listener, &clientssl, &client_addr)))
        goto end;

    SSL_set_connect_state(clientssl);
    while (serverssl == NULL) {
        if (++abortctr > 100) {
            TEST_error("Connection loop did not converge");
            goto end;
        }

        retc = SSL_connect(clientssl);
        err_code = SSL_get_error(clientssl, retc);
        if (retc <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect failed (err %d)", err_code);
            goto end;
        }

        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
            goto end;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            serverssl = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(serverssl))
        goto end;

    /* Complete the handshake */
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    /*
     * Now poll the established server connection for SSL_POLL_EVENT_W.
     * This should always return true since DTLS connections are always writable.
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = serverssl;
    poll_item.events = SSL_POLL_EVENT_W;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
        goto end;

    /* Verify SSL_POLL_EVENT_W is returned */
    if (!TEST_size_t_gt(poll_result, 0))
        goto end;
    if (!TEST_true((poll_item.revents & SSL_POLL_EVENT_W) != 0))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_ADDR_free(client_addr);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test: SSL_poll() with SSL_POLL_EVENT_R on dgram pair BIO connection.
 *
 * This test validates the fix to ossl_dtls_conn_poll_events() that allows
 * polling for readable data on connections using dgram pair BIOs.
 */
static int test_dtls_poll_conn_dgram_pair_readable(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO_ADDR *client_addr = NULL;
    const char msg[] = "Test data for poll readable";
    char buf[64];
    size_t written, readbytes;
    int testresult = 0;
    int retc, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx, 0,
            &listener, &clientssl, &client_addr)))
        goto end;

    SSL_set_connect_state(clientssl);
    while (serverssl == NULL) {
        if (++abortctr > 100) {
            TEST_error("Connection loop did not converge");
            goto end;
        }

        retc = SSL_connect(clientssl);
        err_code = SSL_get_error(clientssl, retc);
        if (retc <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect failed (err %d)", err_code);
            goto end;
        }

        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
            goto end;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            serverssl = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(serverssl))
        goto end;

    /* Complete the handshake */
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    /*
     * Poll server connection for SSL_POLL_EVENT_R BEFORE any data is sent.
     * This should return revents=0 since no data is pending.
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = serverssl;
    poll_item.events = SSL_POLL_EVENT_R;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
        goto end;

    /* No data pending, so revents should be 0 */
    if (!TEST_true((poll_item.revents & SSL_POLL_EVENT_R) == 0))
        goto end;

    /* Now have the client send data */
    if (!TEST_true(SSL_write_ex(clientssl, msg, sizeof(msg), &written))
        || !TEST_size_t_eq(written, sizeof(msg)))
        goto end;

    /*
     * Poll server connection for SSL_POLL_EVENT_R AFTER data is sent.
     * This should return SSL_POLL_EVENT_R since data is now pending.
     * This is the key test for the dgram pair BIO fix - it uses BIO_pending()
     * instead of BIO_get_fd() + BIO_socket_ready().
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = serverssl;
    poll_item.events = SSL_POLL_EVENT_R;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
        goto end;

    /* Data is pending, so SSL_POLL_EVENT_R should be set */
    if (!TEST_size_t_gt(poll_result, 0))
        goto end;
    if (!TEST_true((poll_item.revents & SSL_POLL_EVENT_R) != 0))
        goto end;

    /* Verify we can actually read the data */
    if (!TEST_true(SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg))
        || !TEST_mem_eq(buf, readbytes, msg, sizeof(msg)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_ADDR_free(client_addr);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test: SSL_poll() returns no events when no data is pending.
 *
 * This test verifies that polling a connection for SSL_POLL_EVENT_R
 * returns revents=0 and result_count=0 when no data is available.
 */
static int test_dtls_poll_conn_no_events_before_data(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO_ADDR *client_addr = NULL;
    int testresult = 0;
    int retc, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx, 0,
            &listener, &clientssl, &client_addr)))
        goto end;

    SSL_set_connect_state(clientssl);
    while (serverssl == NULL) {
        if (++abortctr > 100) {
            TEST_error("Connection loop did not converge");
            goto end;
        }

        retc = SSL_connect(clientssl);
        err_code = SSL_get_error(clientssl, retc);
        if (retc <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect failed (err %d)", err_code);
            goto end;
        }

        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
            goto end;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            serverssl = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(serverssl))
        goto end;

    /* Complete the handshake */
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    /*
     * Poll server connection for SSL_POLL_EVENT_R with no data pending.
     * Use zero timeout for non-blocking behavior.
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = serverssl;
    poll_item.events = SSL_POLL_EVENT_R;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
        goto end;

    /* No data pending - verify revents has no SSL_POLL_EVENT_R */
    if (!TEST_true((poll_item.revents & SSL_POLL_EVENT_R) == 0))
        goto end;

    /* poll_result should be 0 since no events fired */
    if (!TEST_size_t_eq(poll_result, 0))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_ADDR_free(client_addr);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test: SSL_poll() on listener with multiple event types.
 *
 * This test verifies that polling a listener with both SSL_POLL_EVENT_IC
 * and SSL_POLL_EVENT_R works correctly.
 */
static int test_dtls_poll_listener_multiple_events(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clientssl = NULL;
    BIO_ADDR *client_addr = NULL;
    int testresult = 0;
    int retc, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx, 0,
            &listener, &clientssl, &client_addr)))
        goto end;

    /*
     * Poll listener with multiple events BEFORE client sends anything.
     * Should return revents=0 since no incoming connection yet.
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = listener;
    poll_item.events = SSL_POLL_EVENT_IC | SSL_POLL_EVENT_R;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
        goto end;

    /* No incoming connection yet */
    if (!TEST_true((poll_item.revents & SSL_POLL_EVENT_IC) == 0))
        goto end;

    /* Have client initiate the handshake (send ClientHello) */
    SSL_set_connect_state(clientssl);
    retc = SSL_connect(clientssl);
    err_code = SSL_get_error(clientssl, retc);
    if (!TEST_int_le(retc, 0)
        || !TEST_true(err_code == SSL_ERROR_WANT_READ
            || err_code == SSL_ERROR_WANT_WRITE))
        goto end;

    /*
     * Poll listener with multiple events AFTER client sends ClientHello.
     * Should return SSL_POLL_EVENT_R since data is available on the BIO.
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = listener;
    poll_item.events = SSL_POLL_EVENT_IC | SSL_POLL_EVENT_R;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
        goto end;

    /* Should have at least one event */
    if (!TEST_size_t_gt(poll_result, 0))
        goto end;

    /*
     * The listener should report SSL_POLL_EVENT_R since there's data
     * on the underlying BIO (the ClientHello).
     */
    if (!TEST_true((poll_item.revents & SSL_POLL_EVENT_IC) != 0))
        goto end;

    testresult = 1;
end:
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_ADDR_free(client_addr);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test: SSL_poll() with SSL_POLL_EVENT_EC after shutdown.
 *
 * This test verifies that SSL_POLL_EVENT_EC (exception condition) is
 * returned after SSL_shutdown() is called on the connection.
 */
static int test_dtls_poll_conn_event_ec(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO_ADDR *client_addr = NULL;
    int testresult = 0;
    int retc, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx, 0,
            &listener, &clientssl, &client_addr)))
        goto end;

    SSL_set_connect_state(clientssl);
    while (serverssl == NULL) {
        if (++abortctr > 100) {
            TEST_error("Connection loop did not converge");
            goto end;
        }

        retc = SSL_connect(clientssl);
        err_code = SSL_get_error(clientssl, retc);
        if (retc <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect failed (err %d)", err_code);
            goto end;
        }

        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
            goto end;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            serverssl = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(serverssl))
        goto end;

    /* Complete the handshake */
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    /*
     * Poll server connection for SSL_POLL_EVENT_EC before shutdown.
     * Should return revents=0 since no error/shutdown condition.
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = serverssl;
    poll_item.events = SSL_POLL_EVENT_EC;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
        goto end;

    /* No error condition yet */
    if (!TEST_true((poll_item.revents & SSL_POLL_EVENT_EC) == 0))
        goto end;

    /* Initiate shutdown on the server connection */
    SSL_shutdown(serverssl);

    /*
     * Poll server connection for SSL_POLL_EVENT_EC after shutdown.
     * Should return SSL_POLL_EVENT_EC since shutdown is in progress.
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = serverssl;
    poll_item.events = SSL_POLL_EVENT_EC;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)))
        goto end;

    /* Shutdown is in progress, so SSL_POLL_EVENT_EC should be set */
    if (!TEST_size_t_gt(poll_result, 0))
        goto end;
    if (!TEST_true((poll_item.revents & SSL_POLL_EVENT_EC) != 0))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_ADDR_free(client_addr);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test: SSL_poll() with NULL SSL in descriptor.
 *
 * This test verifies that SSL_poll() handles a NULL SSL pointer in the
 * poll descriptor gracefully.
 */
static int test_dtls_poll_null_item(void)
{
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int testresult = 0;

    /* Create a poll item with NULL SSL */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = NULL;
    poll_item.events = SSL_POLL_EVENT_R | SSL_POLL_EVENT_W;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    /*
     * Call SSL_poll with a NULL SSL descriptor.
     * Expected behavior: Should either return success with revents=0 (no-op),
     * or return failure. Either way, it should not crash.
     */
    if (SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0, &poll_result)) {
        /* If it succeeds, revents should be 0 (no events for NULL) */
        if (!TEST_true(poll_item.revents == 0))
            goto end;
    }
    /* If SSL_poll returns 0 (failure), that's also acceptable behavior */

    testresult = 1;
end:
    return testresult;
}

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

    /* SSL_poll() specific tests */
    ADD_TEST(test_dtls_poll_conn_event_w);
    ADD_TEST(test_dtls_poll_conn_dgram_pair_readable);
    ADD_TEST(test_dtls_poll_conn_no_events_before_data);
    ADD_TEST(test_dtls_poll_listener_multiple_events);
    ADD_TEST(test_dtls_poll_conn_event_ec);
    ADD_TEST(test_dtls_poll_null_item);
#endif /* OPENSSL_NO_DTLS1_3 */

    /* Time callback tests */
    ADD_TEST(test_dtls_listener_time_callback_basic);
    ADD_TEST(test_dtls_listener_time_callback_invalid);

    /* Pending timeout tests */
    ADD_TEST(test_dtls_listener_pending_timeout_basic);
    ADD_TEST(test_dtls_listener_pending_timeout_invalid);

    /* SSL object ownership tests (run with ASAN to detect leaks/double-frees) */
    ADD_TEST(test_ssl_ownership_pending_conn_leak);
    ADD_TEST(test_ssl_ownership_incoming_conn_leak);
    ADD_TEST(test_ssl_ownership_three_conn_states);
    ADD_TEST(test_ssl_ownership_set_rbio_pending_leak);
    ADD_TEST(test_ssl_ownership_accept_free_no_double_free);
    ADD_TEST(test_ssl_ownership_set_rbio_incoming_leak);
    ADD_TEST(test_ssl_ownership_multiple_pending_leak);
    ADD_TEST(test_ssl_ownership_pending_timeout_cleanup);

    return 1;
}
