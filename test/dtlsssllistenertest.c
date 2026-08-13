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
#include "internal/dgram_demux.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"
#include "../ssl/ssl_local.h"

static char *cert = NULL;
static char *privkey = NULL;

/*
 * Fake time support for timeout testing.
 * timeout_test_fake_time holds the simulated current time, and
 * timeout_test_now_cb is passed to the listener to override its time source.
 */
static OSSL_TIME timeout_test_fake_time;

static OSSL_TIME timeout_test_now_cb(void *arg)
{
    return timeout_test_fake_time;
}

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
static int create_dtls_listener_unconfigured(SSL_CTX *sctx, uint64_t listener_flags,
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
 * As create_dtls_listener_unconfigured(), but also opts out of blocking mode.
 *
 * These tests drive both ends of a handshake from a single thread, so the server
 * side must not block: a blocking read would wait for a client which only this
 * thread can advance. A listener is blocking by default, so opt out here rather
 * than in each test, and note that connections accepted from it inherit this.
 *
 * A test which needs to observe the default, or to exercise blocking mode, should
 * use create_dtls_listener_unconfigured() and configure what it needs.
 */
static int create_dtls_listener(SSL_CTX *sctx, uint64_t listener_flags,
    SSL **listener, BIO_ADDR **server_addr, int *server_fd)
{
    if (!create_dtls_listener_unconfigured(sctx, listener_flags, listener,
            server_addr, server_fd))
        return 0;

    if (!TEST_true(SSL_set_blocking_mode(*listener, 0))) {
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
 * Helper to create a DTLS client with a bound local address.
 *
 * Similar to create_dtls_client_for_addr but also binds to an ephemeral
 * local port so the client can be identified by its source address.
 * This is useful for tests that need to match accepted server connections
 * back to their corresponding clients.
 *
 * Returns 1 on success, 0 on failure.
 * On success, caller is responsible for cleanup using the returned pointers/fds.
 * The local_addr will be filled with the actual bound address (including port).
 */
static int create_dtls_client_bound(SSL_CTX *cctx, const BIO_ADDR *server_addr,
    SSL **clientssl, int *client_fd, BIO_ADDR *local_addr)
{
    BIO *c_bio = NULL;
    struct in_addr ina;
    union BIO_sock_info_u info;
    int ret = 0;

    *clientssl = NULL;
    *client_fd = -1;

    ina.s_addr = htonl(INADDR_LOOPBACK);

    /* Create client UDP socket */
    *client_fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(*client_fd, 0))
        goto err;

    if (!TEST_true(BIO_socket_nbio(*client_fd, 1)))
        goto err;

    /* Bind to ephemeral port so we can identify this client later */
    if (!TEST_true(BIO_ADDR_rawmake(local_addr, AF_INET, &ina, sizeof(ina), 0)))
        goto err;

    if (!TEST_true(BIO_bind(*client_fd, local_addr, 0)))
        goto err;

    /* Get the actual assigned port */
    info.addr = local_addr;
    if (!TEST_true(BIO_sock_info(*client_fd, BIO_SOCK_INFO_ADDRESS, &info)))
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
    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
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

    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
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
    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
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
    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
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
    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
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
    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
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
    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
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
 * Test SSL_accept_connection with no net_bio and the
 * SSL_ACCEPT_CONNECTION_NO_BLOCK flag, so that the caller is not asking to
 * wait. The function must return NULL immediately without raising an error,
 * the absence of a BIO being indistinguishable from having nothing queued.
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
    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
        goto err;

    /* No BIO has been set on the listener */

    ERR_clear_error();
    conn = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);

    /* Must return NULL - no connection available, no blocking */
    if (!TEST_ptr_null(conn))
        goto err;

    /*
     * With NO_BLOCK, returning NULL without an error is correct behavior.
     * it means "no connection available, try again later".
     * This is not an error condition, just an indication to poll/retry.
     */
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
 * Test SSL_accept_connection with no net_bio and without the
 * SSL_ACCEPT_CONNECTION_NO_BLOCK flag, so that the caller is asking to wait.
 * When there is no BIO the function must return NULL and raise
 * SSL_R_BIO_NOT_SET rather than waiting, since nothing could ever arrive.
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
    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
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
            SSL_LISTENER_FLAG_REQUIRE_HRR | SSL_LISTENER_FLAG_SINGLE_THREAD,
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
            SSL_LISTENER_FLAG_NO_VALIDATE | SSL_LISTENER_FLAG_SINGLE_THREAD,
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
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_REQUIRE_HRR | SSL_LISTENER_FLAG_SINGLE_THREAD,
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
        poll_timeout.tv_usec = 100000;

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
 * Test true concurrent multi-client with real UDP sockets (shared socket).
 *
 * This test verifies that:
 *   1. A DTLS listener can accept multiple concurrent clients using real sockets
 *   2. All connections share the listener's socket via the demux
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
    BIO_ADDR *server_addr = NULL;
    BIO_ADDR *client1_local_addr = NULL;
    BIO_ADDR *client2_local_addr = NULL;
    BIO_ADDR *server_peer_addr = NULL;
    int server_fd = -1;
    int client1_fd = -1, client2_fd = -1;
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
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_REQUIRE_HRR | SSL_LISTENER_FLAG_SINGLE_THREAD,
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
    if (!TEST_true(create_dtls_client_bound(cctx, server_addr,
            &client1, &client1_fd, client1_local_addr)))
        goto end;

    /*
     * --- Create Client 2 ---
     */
    if (!TEST_true(create_dtls_client_bound(cctx, server_addr,
            &client2, &client2_fd, client2_local_addr)))
        goto end;

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
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_SINGLE_THREAD,
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
            SSL_LISTENER_FLAG_NO_VALIDATE | SSL_LISTENER_FLAG_SINGLE_THREAD,
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

    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
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

    /* SSL_new_listener with NULL ctx should return NULL */
    listener = SSL_new_listener(NULL, 0);
    if (!TEST_ptr_null(listener))
        goto err;

    success = 1;
err:
    SSL_free(listener);
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

    /* SSL_new_listener should fail for TLS contexts */
    listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD);
    if (!TEST_ptr_null(listener))
        goto err;

    success = 1;
err:
    SSL_free(listener);
    SSL_CTX_free(ctx);
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

    /* SSL_new_listener_from should return NULL for DTLS */
    listener = SSL_new_listener_from(ssl, 0);
    if (!TEST_ptr_null(listener))
        goto err;

    success = 1;
err:
    SSL_free(listener);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
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

    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
        goto err;

    if (!TEST_ptr(new_conn = SSL_new(ctx)))
        goto err;

    /* SSL_listen_ex should return 0 for DTLS */
    if (!TEST_int_eq(SSL_listen_ex(listener, new_conn), 0))
        goto err;

    success = 1;
err:
    SSL_free(new_conn);
    SSL_free(listener);
    SSL_CTX_free(ctx);
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

    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
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
    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
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
 * Test SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT basic functionality.
 *
 * This test verifies that:
 * 1. The pending timeout can be set and retrieved on a DTLS listener via
 *    SSL_set_value_uint() / SSL_get_value_uint()
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

    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
        goto err;

    /* Default timeout should be 30 seconds (30000 ms) */
    if (!TEST_true(SSL_get_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT, &retrieved)))
        goto err;
    if (!TEST_uint64_t_eq(retrieved, 30000))
        goto err;

    /* Set a custom timeout of 60 seconds (60000 ms) */
    timeout = 60000;
    if (!TEST_true(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT, timeout)))
        goto err;

    /* Verify the timeout was set */
    if (!TEST_true(SSL_get_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT, &retrieved)))
        goto err;
    if (!TEST_uint64_t_eq(retrieved, timeout))
        goto err;

    /* Set timeout to UINT64_MAX (disable) */
    if (!TEST_true(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT, UINT64_MAX)))
        goto err;

    /* Verify infinite timeout */
    if (!TEST_true(SSL_get_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT, &retrieved)))
        goto err;
    if (!TEST_uint64_t_eq(retrieved, UINT64_MAX))
        goto err;

    /* Set a very short timeout (1 second = 1000 ms) */
    timeout = 1000;
    if (!TEST_true(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT, timeout)))
        goto err;

    if (!TEST_true(SSL_get_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT, &retrieved)))
        goto err;
    if (!TEST_uint64_t_eq(retrieved, timeout))
        goto err;

    success = 1;
err:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return success;
}

/*
 * Test SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT with invalid arguments.
 *
 * This test verifies that the underlying dispatch handles invalid arguments
 * gracefully:
 * 1. Non-listener SSL should fail
 * 2. Get on non-listener should fail
 */
static int test_dtls_listener_pending_timeout_invalid(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL *listener = NULL;
    uint64_t timeout;
    uint64_t retrieved;
    int success = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method())))
        goto err;

    /* Create a regular SSL connection (not a listener) */
    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;

    timeout = 60000;

    /* Setting timeout on a non-listener SSL should fail */
    if (!TEST_false(SSL_set_generic_value_uint(ssl,
            SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT, timeout)))
        goto err;

    /* Get on non-listener should fail */
    if (!TEST_false(SSL_get_generic_value_uint(ssl,
            SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT, &retrieved)))
        goto err;

    /* Verify that a listener succeeds for contrast */
    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
        goto err;

    if (!TEST_true(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT, timeout)))
        goto err;

    if (!TEST_false(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT, 0)))
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
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_SINGLE_THREAD,
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
     * The connection is pending so it is not yet queued in
     * incoming_connections: no readiness event should be reported.
     */
    if (!TEST_size_t_eq(poll_result, 0)
        || !TEST_true((poll_item.revents & SSL_POLL_EVENT_IC) == 0))
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
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_SINGLE_THREAD,
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
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener(sctx,
            SSL_LISTENER_FLAG_REQUIRE_HRR | SSL_LISTENER_FLAG_SINGLE_THREAD,
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
     * The tick consumed the ClientHello and the connection is now pending in
     * pending_conns; no data remains buffered on the listener's read BIO, so
     * no readable event should be reported.
     */
    if (!TEST_size_t_eq(poll_result, 0)
        || !TEST_true((poll_item.revents & SSL_POLL_EVENT_R) == 0))
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
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_SINGLE_THREAD,
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
     * The connection is pending so it is not yet queued in
     * incoming_connections: no readiness event should be reported.
     */
    if (!TEST_size_t_eq(poll_result, 0)
        || !TEST_true((poll_item.revents & SSL_POLL_EVENT_IC) == 0))
        goto end;

    /*
     * The pending connection is still in pending_conns, NOT in incoming_connections.
     * Now we call SSL_set0_rbio which should free the pending connections.
     * If there's a leak, ASAN will detect it.
     */

    /* Create a new dgram mem BIO for the replacement */
    if (!TEST_ptr(new_server_bio = BIO_new(BIO_s_dgram_mem())))
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
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_SINGLE_THREAD,
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

    /* Create a new dgram mem BIO for the replacement */
    if (!TEST_ptr(new_server_bio = BIO_new(BIO_s_dgram_mem())))
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
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_SINGLE_THREAD,
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
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_SINGLE_THREAD,
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

        /*
         * The connection is pending (HVR in flight), so it is not yet queued
         * in incoming_connections: no readiness event should be reported.
         */
        if (!TEST_size_t_eq(poll_result, 0)
            || !TEST_true((poll_item.revents & SSL_POLL_EVENT_IC) == 0))
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

static int test_ssl_ownership_pending_timeout_cleanup(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clientssl = NULL;
    BIO_ADDR *client_addr = NULL;
    int testresult = 0;
    int ret, err_code;
    int count_after_hello;
    uint64_t fake_now_secs = 1700000000;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_SINGLE_THREAD,
            &listener, &clientssl, &client_addr)))
        goto end;

    if (!TEST_true(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT, 1000)))
        goto end;

    /*
     * Setting test_now_cb_call_count to 0 before the test.
     */
    test_now_cb_call_count = 0;
    if (!TEST_true(ossl_dtls_listener_set_override_now_cb(listener,
            test_fake_now_cb, &fake_now_secs)))
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
     * The connection is pending (HVR in flight), so it is not yet queued in
     * incoming_connections: no readiness event should be reported.
     */
    if (!TEST_size_t_eq(poll_result, 0)
        || !TEST_true((poll_item.revents & SSL_POLL_EVENT_IC) == 0))
        goto end;

    /*
     * Processing the ClientHello (creating the pending connection and
     * generating the HelloVerifyRequest cookie) must have consulted the
     * listener's time override, so the callback should have been invoked at
     * least once by now.
     */
    if (!TEST_int_gt(test_now_cb_call_count, 0))
        goto end;
    count_after_hello = test_now_cb_call_count;

    /*
     * Advance the fake time past the timeout (more than 1 second).
     * The next tick should detect the timeout and free the pending connection.
     */
    fake_now_secs += 5;

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
     * The timed-out pending connection was cleaned up, so nothing is queued in
     * incoming_connections: no readiness event should be reported.
     */
    if (!TEST_size_t_eq(poll_result, 0)
        || !TEST_true((poll_item.revents & SSL_POLL_EVENT_IC) == 0))
        goto end;

    /*
     * The timeout check during the tick reads the (now advanced) time through
     * the override as well, so the callback must have been invoked again.
     */
    if (!TEST_int_gt(test_now_cb_call_count, count_after_hello))
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

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_SINGLE_THREAD,
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

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_SINGLE_THREAD,
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

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_SINGLE_THREAD,
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

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_SINGLE_THREAD,
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

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_SINGLE_THREAD,
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

/*
 * Test DTLS 1.3 SSL Listener handshake message buffering.
 *
 * This test verifies that when a DTLS 1.3 SSL Listener sends handshake
 * messages, multiple records are buffered into a single datagram
 * rather than being sent as separate datagrams.
 *
 * Expected behavior with buffering:
 *   - At least one datagram contains multiple DTLS records
 *
 * Without buffering (the bug this tests for):
 *   - Each record would be in its own datagram
 */
static int test_dtls13_listener_msg_buffering(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO_ADDR *client_addr = NULL;
    int testresult = 0;
    int retc, rets, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr = 0;
    unsigned char buf[16384];
    size_t datagram_len;
    BIO_MSG msg;
    size_t msgs_processed;
    int record_count, max_records_in_datagram = 0;
    BIO *client_rbio;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /*
     * Set NO_QUERY_MTU on the context so connections inherit it.
     * This prevents the MTU from being queried before we can set it.
     */
    SSL_CTX_set_options(sctx, SSL_OP_NO_QUERY_MTU);

    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_NO_VALIDATE | SSL_LISTENER_FLAG_SINGLE_THREAD,
            &listener, &clientssl, &client_addr)))
        goto end;

    SSL_set_connect_state(clientssl);

    retc = SSL_connect(clientssl);
    err_code = SSL_get_error(clientssl, retc);
    if (!TEST_true(retc <= 0
            && (err_code == SSL_ERROR_WANT_READ
                || err_code == SSL_ERROR_WANT_WRITE)))
        goto end;

    while (serverssl == NULL) {
        if (!TEST_int_le(++abortctr, 100))
            goto end;

        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item),
                &poll_timeout, 0, &poll_result)))
            goto end;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            serverssl = SSL_accept_connection(listener,
                SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(serverssl))
        goto end;

    /* Set a large MTU to prevent message fragmentation */
    SSL_set_mtu(serverssl, 1500);

    abortctr = 0;
    while (1) {
        if (!TEST_int_le(++abortctr, 100))
            goto end;

        rets = SSL_do_handshake(serverssl);
        err_code = SSL_get_error(serverssl, rets);

        if (rets > 0)
            break;

        if (err_code == SSL_ERROR_WANT_READ)
            break;

        if (!TEST_int_eq(err_code, SSL_ERROR_WANT_WRITE))
            goto end;
    }

    /*
     * The server has sent its flight, which should be buffered into one or
     * more datagrams. We read each datagram and count the DTLS records
     * within it. With proper buffering, at least one datagram should
     * contain multiple records.
     */
    client_rbio = SSL_get_rbio(clientssl);
    if (!TEST_ptr(client_rbio))
        goto end;

    /* Read all available datagrams */
    while (1) {
        memset(&msg, 0, sizeof(msg));
        msg.data = buf;
        msg.data_len = sizeof(buf);

        if (!BIO_recvmmsg(client_rbio, &msg, sizeof(msg), 1, 0, &msgs_processed)
            || msgs_processed == 0)
            break;

        datagram_len = msg.data_len;

        /* Count DTLS records in this datagram */
        record_count = 0;
        {
            size_t offset = 0;

            while (offset < datagram_len) {
                unsigned char hdr = buf[offset];
                size_t rec_len, hdr_len;

                /*
                 * Check that the first three bits are set to 001 to verify
                 * that the DTLS 1.3 Unified Header is present. Otherwise,
                 * assume DTLS 1.2 record format.
                 */
                if ((hdr & 0xE0) == 0x20) {
                    /* DTLS 1.3 unified header */
                    if (offset + 4 > datagram_len)
                        break;

                    if (hdr & 0x04) {
                        /* Length field present */
                        hdr_len = 1 + ((hdr & 0x08) ? 2 : 1);
                        if (offset + hdr_len + 2 > datagram_len)
                            break;
                        rec_len = (buf[offset + hdr_len] << 8)
                            | buf[offset + hdr_len + 1];
                        hdr_len += 2;
                    } else {
                        /* No length field - record extends to end of datagram */
                        rec_len = datagram_len - offset - 1
                            - ((hdr & 0x08) ? 2 : 1);
                        hdr_len = 1 + ((hdr & 0x08) ? 2 : 1);
                    }

                    offset += hdr_len + rec_len;
                } else if (hdr >= 20 && hdr <= 25) {
                    /* DTLS 1.2 style record header (13 bytes) */
                    if (offset + 13 > datagram_len)
                        break;
                    rec_len = (buf[offset + 11] << 8) | buf[offset + 12];
                    offset += 13 + rec_len;
                } else {
                    break;
                }

                record_count++;
            }
        }

        if (record_count > max_records_in_datagram)
            max_records_in_datagram = record_count;
    }

    /*
     * The key assertion: with buffering enabled, at least one datagram should
     * contain multiple records.
     */
    if (!TEST_int_gt(max_records_in_datagram, 1))
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

static int test_dtls_listener_max_pending_conns_api(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    uint64_t max_conns, retrieved_max_conns;
    int testresult = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method())))
        goto end;

    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
        goto end;

    /* Retrieve default maximum pending connections (256) */
    if (!TEST_true(SSL_get_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, &retrieved_max_conns)))
        goto end;

    if (!TEST_uint64_t_eq(retrieved_max_conns, 256))
        goto end;

    max_conns = 10;
    if (!TEST_true(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, max_conns)))
        goto end;

    if (!TEST_true(SSL_get_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, &retrieved_max_conns)))
        goto end;
    if (!TEST_uint64_t_eq(retrieved_max_conns, max_conns))
        goto end;

    if (!TEST_false(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, 0)))
        goto end;

    if (!TEST_true(SSL_get_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, &retrieved_max_conns)))
        goto end;
    if (!TEST_uint64_t_eq(retrieved_max_conns, max_conns))
        goto end;

    testresult = 1;

end:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return testresult;
}

static int test_dtls_listener_max_dgram_size_api(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    uint64_t size, retrieved_size;
    int testresult = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method())))
        goto end;

    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
        goto end;

    /* Retrieve default maximum datagram size (2000) */
    if (!TEST_true(SSL_get_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_DGRAM_SIZE, &retrieved_size)))
        goto end;
    if (!TEST_uint64_t_eq(retrieved_size, 2000))
        goto end;

    /* Set and read back a larger value */
    size = 9000;
    if (!TEST_true(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_DGRAM_SIZE, size)))
        goto end;
    if (!TEST_true(SSL_get_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_DGRAM_SIZE, &retrieved_size)))
        goto end;
    if (!TEST_uint64_t_eq(retrieved_size, size))
        goto end;

    /* Values above the maximum UDP payload are clamped to 65535 */
    if (!TEST_true(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_DGRAM_SIZE, 100000)))
        goto end;
    if (!TEST_true(SSL_get_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_DGRAM_SIZE, &retrieved_size)))
        goto end;
    if (!TEST_uint64_t_eq(retrieved_size, 65535))
        goto end;

    /* Values below the minimum receive size are rejected... */
    if (!TEST_false(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_DGRAM_SIZE, 100)))
        goto end;
    /* ...and leave the previous value unchanged. */
    if (!TEST_true(SSL_get_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_DGRAM_SIZE, &retrieved_size)))
        goto end;
    if (!TEST_uint64_t_eq(retrieved_size, 65535))
        goto end;

    testresult = 1;

end:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return testresult;
}

/*
 * A large dummy ClientHello extension used to inflate the ClientHello beyond
 * the default receive-buffer size, so the functional test below only succeeds
 * once SSL_VALUE_DTLS_LISTENER_MAX_DGRAM_SIZE has been raised. The server has no
 * callback registered for this extension type, so per TLS 1.3 rules it simply
 * ignores it.
 */
#define BIG_CH_EXT_TYPE 65280 /* IANA "Reserved for Private Use" range */
#define BIG_CH_EXT_LEN 2500 /* pushes the ClientHello over the 2000 default */

static int big_ch_ext_add_cb(SSL *s, unsigned int ext_type,
    unsigned int context, const unsigned char **out, size_t *outlen,
    X509 *x, size_t chainidx, int *al, void *add_arg)
{
    static const unsigned char padding[BIG_CH_EXT_LEN]; /* zero-filled */

    *out = padding;
    *outlen = sizeof(padding);
    return 1;
}

/*
 * Helper to create a DTLS client on a *connected* UDP socket. Unlike the
 * BIO_dgram_set_peer() helpers above (which use an unconnected socket and so
 * cause DTLS to fragment the ClientHello into sub-MTU datagrams), a connected
 * socket lets DTLS discover the large loopback path MTU and send the whole
 * ClientHello in a single datagram - which is what exercises the listener demux
 * receive-buffer sizing.
 */
static int create_dtls_client_connected(SSL_CTX *cctx,
    const BIO_ADDR *server_addr, SSL **clientssl, int *client_fd)
{
    BIO *c_bio = NULL;
    int ret = 0;

    *clientssl = NULL;
    *client_fd = -1;

    *client_fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(*client_fd, 0))
        goto err;

    if (!TEST_true(BIO_connect(*client_fd, server_addr, 0)))
        goto err;

    if (!TEST_true(BIO_socket_nbio(*client_fd, 1)))
        goto err;

    c_bio = BIO_new_dgram(*client_fd, BIO_NOCLOSE);
    if (!TEST_ptr(c_bio))
        goto err;

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
 * Functional test for SSL_VALUE_DTLS_LISTENER_MAX_DGRAM_SIZE.
 *
 * A connected client sends a ClientHello inflated (via a large custom
 * extension) past the default 2000-byte receive buffer, as a single datagram.
 * With the listener's max datagram size raised above the ClientHello size, the
 * demux receives it whole and the HRR handshake completes. With the default
 * size the oversized ClientHello would be truncated and the handshake would
 * stall - so this test passing demonstrates the tunable takes effect. (The
 * other listener tests avoid the issue only because they use unconnected
 * clients that fragment the ClientHello.)
 */
static int test_dtls_listener_max_dgram_size_functional(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1, client_fd = -1;
    const char msg[] = "Hello large ClientHello";
    char buf[64];
    size_t written, readbytes;
    int testresult = 0;
    int retc, err_code;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int abortctr = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /* Inflate the ClientHello past the 2000-byte default receive buffer. */
    if (!TEST_true(SSL_CTX_add_custom_ext(cctx, BIG_CH_EXT_TYPE,
            SSL_EXT_CLIENT_HELLO, big_ch_ext_add_cb, NULL, NULL, NULL, NULL)))
        goto end;

    if (!TEST_true(create_dtls_listener(sctx,
            SSL_LISTENER_FLAG_REQUIRE_HRR | SSL_LISTENER_FLAG_SINGLE_THREAD,
            &listener, &server_addr, &server_fd)))
        goto end;

    /* Raise the receive size above the inflated ClientHello. */
    if (!TEST_true(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_DGRAM_SIZE, 9000)))
        goto end;

    if (!TEST_true(create_dtls_client_connected(cctx, server_addr,
            &clientssl, &client_fd)))
        goto end;

    SSL_set_connect_state(clientssl);
    while (serverssl == NULL) {
        if (++abortctr > 100) {
            TEST_error("connection did not converge (oversized ClientHello)");
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

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item),
                &poll_timeout, 0, &poll_result)))
            goto end;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            serverssl = SSL_accept_connection(listener,
                SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(serverssl))
        goto end;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_version(serverssl), DTLS1_3_VERSION))
        goto end;

    if (!TEST_true(SSL_write_ex(clientssl, msg, sizeof(msg), &written))
        || !TEST_size_t_eq(written, sizeof(msg)))
        goto end;

    if (!TEST_true(dtls_read_with_retry(serverssl, buf, sizeof(buf), &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(msg))
        || !TEST_mem_eq(buf, readbytes, msg, sizeof(msg)))
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

static int test_dtls_listener_max_pending_conns_invalid(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL *listener = NULL;
    uint64_t retrieved_max_conns;
    int testresult = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_server_method())))
        goto end;

    if (!TEST_ptr(listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_SINGLE_THREAD)))
        goto end;

    /* Retrieve default maximum pending connections (256) */
    if (!TEST_true(SSL_get_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, &retrieved_max_conns)))
        goto end;

    if (!TEST_uint64_t_eq(retrieved_max_conns, 256))
        goto end;

    /* Setting the cap to 0 must fail - the cap cannot be disabled */
    if (!TEST_false(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, 0)))
        goto end;

    if (!TEST_true(SSL_get_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, &retrieved_max_conns)))
        goto end;
    if (!TEST_uint64_t_eq(retrieved_max_conns, 256))
        goto end;

    /* Setting on a non-listener SSL should fail */
    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto end;
    if (!TEST_false(SSL_set_generic_value_uint(ssl,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, 100)))
        goto end;

    /* Get on non-listener should fail */
    if (!TEST_false(SSL_get_generic_value_uint(ssl,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, &retrieved_max_conns)))
        goto end;

    /* Get with a NULL out-value must fail */
    if (!TEST_false(SSL_get_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, NULL)))
        goto end;

    /*
     * A non-GENERIC value class must be rejected: these tunables are local
     * configuration and do not participate in feature negotiation.
     */
    if (!TEST_false(SSL_set_value_uint(listener, SSL_VALUE_CLASS_FEATURE_REQUEST,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, 100)))
        goto end;
    if (!TEST_false(SSL_get_value_uint(listener, SSL_VALUE_CLASS_FEATURE_REQUEST,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, &retrieved_max_conns)))
        goto end;

    testresult = 1;

end:
    SSL_free(ssl);
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return testresult;
}

#define PENDING_CAP_TEST_LIMIT 3
#define PENDING_CAP_TEST_CLIENTS 5

/*
 * Helper for the pending-connection cap tests.
 *
 * Creates a single DTLS client, sends its initial ClientHello
 * then drives the listener once via SSL_poll() so it processes the ClientHello
 * - either admitting a pending connection (and sending an HVR/HRR) or rejecting
 * it once the cap has been reached.
 *
 * On success the new client SSL and its socket fd are returned via *client and
 * *client_fd for the caller to clean up.
 *
 * Returns 1 on success, 0 on failure.
 */
static int cap_test_send_clienthello(SSL_CTX *cctx, const BIO_ADDR *server_addr,
    SSL *listener, SSL **client, int *client_fd)
{
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int ret, err_code;

    if (!TEST_true(create_dtls_client_for_addr(cctx, server_addr, client, client_fd)))
        return 0;

    /* Client sends initial ClientHello */
    SSL_set_connect_state(*client);
    ret = SSL_connect(*client);
    err_code = SSL_get_error(*client, ret);

    /* The ClientHello should be sent but the handshake should not complete */
    if (!TEST_int_le(ret, 0))
        return 0;
    if (!TEST_true(err_code == SSL_ERROR_WANT_READ || err_code == SSL_ERROR_WANT_WRITE))
        return 0;

    /*
     * Drive the listener so it processes the ClientHello. Depending on the
     * current pending count it either creates a pending connection and sends
     * an HRR/HVR, or rejects the connection and releases the packet once the
     * cap has been reached.
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = listener;
    poll_item.events = SSL_POLL_EVENT_R;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 100000;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item),
            &poll_timeout, 0, &poll_result)))
        return 0;

    return 1;
}

/*
 * Test that pending connection cap is enforced.
 *
 * This test:
 *   1. Creates a listener with max_pending_conns = 3
 *   2. Starts 5 clients that send ClientHello but don't complete handshake
 *   3. Verifies only 3 pending connections are created
 *   4. The 4th and 5th clients should be rejected (their packets released)
 */
static int test_pending_conn_cap_enforcement(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clients[PENDING_CAP_TEST_CLIENTS] = { NULL };
    int client_fds[PENDING_CAP_TEST_CLIENTS] = { -1, -1, -1, -1, -1 };
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1;
    int testresult = 0;
    int i;

    /* Create SSL contexts */
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto err;

    /* Create listener with HVR required (so connections stay pending) */
    if (!TEST_true(create_dtls_listener(sctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_REQUIRE_HRR | SSL_LISTENER_FLAG_SINGLE_THREAD,
            &listener, &server_addr, &server_fd)))
        goto err;

    /* Set the pending connection cap to 3 */
    if (!TEST_true(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, PENDING_CAP_TEST_LIMIT)))
        goto err;

    /* Verify the cap was set */
    {
        uint64_t v;
        if (!TEST_true(SSL_get_generic_value_uint(listener,
                SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, &v)))
            goto err;
        if (!TEST_uint64_t_eq(v, PENDING_CAP_TEST_LIMIT))
            goto err;
    }

    /*
     * Create 5 clients and have each send their ClientHello.
     * The first three should end up in the pending connections.
     * The 4th and 5th clients should be rejected due to the cap.
     */
    for (i = 0; i < PENDING_CAP_TEST_CLIENTS; i++)
        if (!TEST_true(cap_test_send_clienthello(cctx, server_addr, listener,
                &clients[i], &client_fds[i])))
            goto err;

    /*
     * Only PENDING_CAP_TEST_LIMIT connections should have been admitted to
     * pending_conns; the remaining clients were rejected once the cap was
     * reached. Read the count directly from the listener's pending lookup
     * table (there is no public accessor by design - the cap is silent).
     */
    if (!TEST_size_t_eq(ossl_dgram_conn_lookup_num_items(
                            ((DTLS_LISTENER *)listener)->pending_conns),
            PENDING_CAP_TEST_LIMIT))
        goto err;

    testresult = 1;

err:
    for (i = 0; i < PENDING_CAP_TEST_CLIENTS; i++) {
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

/*
 * Test that pending connection cap and timeout interaction.
 *
 * This test:
 *   1. Creates a listener with max_pending_conns = 3
 *   2. Starts 5 clients that send ClientHello but don't complete handshake
 *   3. Verifies there are 3 pending connections
 *   4. Waits for the pending connections to timeout and be released
 *   5. Add the last two clients
 *   6. Verifies there are 2 pending connections
 */
static int test_pending_cap_with_timeout(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clients[PENDING_CAP_TEST_CLIENTS] = { NULL };
    int client_fds[PENDING_CAP_TEST_CLIENTS] = { -1, -1, -1, -1, -1 };
    BIO_ADDR *server_addr = NULL;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int server_fd = -1;
    int testresult = 0;
    int i;

    /* Create SSL contexts */
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto err;

    /* Create listener with HVR required (so connections stay pending) */
    if (!TEST_true(create_dtls_listener(sctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_REQUIRE_HRR | SSL_LISTENER_FLAG_SINGLE_THREAD,
            &listener, &server_addr, &server_fd)))
        goto err;

    /* Set the pending connection cap to 3 */
    if (!TEST_true(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, PENDING_CAP_TEST_LIMIT)))
        goto err;

    /* Verify the cap was set */
    {
        uint64_t v;
        if (!TEST_true(SSL_get_generic_value_uint(listener,
                SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, &v)))
            goto err;
        if (!TEST_uint64_t_eq(v, PENDING_CAP_TEST_LIMIT))
            goto err;
    }

    if (!TEST_true(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_PENDING_TIMEOUT, 1000)))
        goto err;

    timeout_test_fake_time = ossl_time_from_time_t(1700000000);
    if (!TEST_true(ossl_dtls_listener_set_override_now_cb(listener,
            /* Use a callback that returns timeout_test_fake_time */
            timeout_test_now_cb, NULL)))
        goto err;

    /*
     * Create 5 clients and have each send their ClientHello.
     * The first three should end up in the pending connections.
     * The 4th and 5th clients should be rejected due to the cap.
     */
    for (i = 0; i < PENDING_CAP_TEST_LIMIT; i++)
        if (!TEST_true(cap_test_send_clienthello(cctx, server_addr, listener,
                &clients[i], &client_fds[i])))
            goto err;

    if (!TEST_size_t_eq(ossl_dgram_conn_lookup_num_items(
                            ((DTLS_LISTENER *)listener)->pending_conns),
            PENDING_CAP_TEST_LIMIT))
        goto err;

    /* Advance time past timeout (5 seconds > 1 second timeout) */
    timeout_test_fake_time = ossl_time_add(timeout_test_fake_time,
        ossl_seconds2time(5));

    /* Trigger a tick to process timeouts */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = listener;
    poll_item.events = SSL_POLL_EVENT_R;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item),
            &poll_timeout, 0, &poll_result)))
        goto err;

    for (i = PENDING_CAP_TEST_LIMIT; i < PENDING_CAP_TEST_CLIENTS; i++)
        if (!TEST_true(cap_test_send_clienthello(cctx, server_addr, listener,
                &clients[i], &client_fds[i])))
            goto err;

    if (!TEST_size_t_eq(ossl_dgram_conn_lookup_num_items(
                            ((DTLS_LISTENER *)listener)->pending_conns),
            PENDING_CAP_TEST_CLIENTS - PENDING_CAP_TEST_LIMIT))
        goto err;

    testresult = 1;

err:
    for (i = 0; i < PENDING_CAP_TEST_CLIENTS; i++) {
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

/*
 * ============================================================================
 * new_pending_conn_cb tests
 * ============================================================================
 *
 * These tests exercise SSL_CTX_set_new_pending_conn_cb() on the DTLS listener
 * path. The callback fires from dtls_listener_packet_handler() after the
 * max_pending_conns cap check but before the new pending connection is
 * registered in the listener's pending_conns table. A callback return of 0
 * causes the listener to discard the newly-allocated conn_ssl; a non-zero
 * return admits it as a normal pending connection.
 *
 * Scenarios covered:
 *   1. Callback allows every connection (small workload, cap not a factor).
 *   2. Callback rejects every connection (small workload, cap not a factor).
 *   3. Cap set to LIMIT; callback always allows; more than LIMIT clients
 *      attempt to connect. The cap must win: exactly LIMIT connections are
 *      admitted, and the callback is invoked at most LIMIT times (because
 *      the cap is checked first and short-circuits before the callback).
 *   4. Cap set well above the client count; callback rejects everything.
 *      No pending connections are admitted; the cap is not the reason.
 */

/* --- Callback helpers ---------------------------------------------------- */

static int new_pending_cb_call_count;
static int new_pending_cb_allow_remaining;
static SSL_CTX *new_pending_cb_expected_ctx;
static void *new_pending_cb_expected_arg;
static int new_pending_cb_ctx_matched;
static int new_pending_cb_arg_matched;
static SSL *new_pending_cb_last_ssl;

/*
 * Reset the file-scope callback state before registering the callback for
 * a new scenario. These globals persist across tests, so leftover values
 * from a previous run would corrupt this run's assertions (e.g. an
 * inflated call_count or a sticky ctx_matched == 0).
 *
 * ctx             - SSL_CTX the caller is about to register the callback
 *                   on; stored so the callback can verify it is passed
 *                   back unchanged.
 * arg             - opaque cookie the caller will pass to
 *                   SSL_CTX_set_new_pending_conn_cb(); same round-trip
 *                   check.
 * allow_remaining - number of admissions the callback should grant before
 *                   it starts denying. 0 means "always deny". Pass a
 *                   value comfortably larger than the number of clients
 *                   to mean "always allow". Each admission decrements
 *                   this counter until it reaches 0.
 */
static void new_pending_cb_reset(SSL_CTX *ctx, void *arg, int allow_remaining)
{
    new_pending_cb_call_count = 0;
    new_pending_cb_allow_remaining = allow_remaining;
    new_pending_cb_expected_ctx = ctx;
    new_pending_cb_expected_arg = arg;
    new_pending_cb_ctx_matched = 1;
    new_pending_cb_arg_matched = 1;
    new_pending_cb_last_ssl = NULL;
}

static int new_pending_cb_fn(SSL_CTX *ctx, SSL *new_ssl, void *arg)
{
    new_pending_cb_call_count++;
    new_pending_cb_last_ssl = new_ssl;
    if (ctx != new_pending_cb_expected_ctx)
        new_pending_cb_ctx_matched = 0;
    if (arg != new_pending_cb_expected_arg)
        new_pending_cb_arg_matched = 0;
    if (new_pending_cb_allow_remaining > 0) {
        new_pending_cb_allow_remaining--;
        return 1;
    }
    return 0;
}

/*
 * Common test body for the new_pending_conn_cb DTLS listener tests.
 *
 * Sets up a DTLS 1.3 listener, applies the given max_pending_conns cap,
 * registers new_pending_cb_fn on the SSL_CTX, drives ClientHellos through
 * the listener from num_clients distinct peers, then asserts that the
 * listener's pending_conns table and the callback invocation counter
 * match the caller's expectations.
 *
 * Parameters:
 *   max_pending
 *       Value written to SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS on the
 *       listener before any traffic is driven. Governs when the cap
 *       check short-circuits ahead of the callback.
 *
 *   allow_remaining
 *       Initial admission budget for the callback. Each callback
 *       invocation that returns 1 decrements this counter; once it
 *       reaches 0, subsequent invocations return 0. Pass a value
 *       comfortably larger than num_clients (e.g. 100) for "always
 *       allow"; pass 0 for "always deny"; pass 1..num_clients-1 for
 *       "admit the first N then deny the rest".
 *
 *   num_clients
 *       Number of distinct DTLS clients the helper creates and drives
 *       through cap_test_send_clienthello(). Must not exceed
 *       PENDING_CAP_TEST_CLIENTS (the compile-time size of the internal
 *       clients[] / client_fds[] arrays); the helper asserts this at
 *       runtime.
 *
 *   expected_pending
 *       Number of entries expected in the listener's pending_conns
 *       after all ClientHellos have been driven.
 *
 *   expected_calls
 *       Expected number of new_pending_cb_fn invocations. Interpretation
 *       depends on strict_cb_count.
 *
 *   strict_cb_count
 *       0 -> assert (call_count >= expected_calls); use this whenever
 *            the callback ever denies, because denied peers do not
 *            receive an HVR and their DTLS retransmit timer can produce
 *            extra callback invocations during the drain window.
 *       Non-zero -> assert (call_count == expected_calls); safe only
 *            when either (a) every callback invocation admits (HVR
 *            quiets the peer, no retransmits), or (b) the cap
 *            short-circuits ahead of the callback for excess peers.
 *
 * Returns 1 on success, 0 on any assertion failure. All resources
 * (clients, sockets, listener, contexts) are freed on both paths.
 */
static int run_new_pending_cb_scenario(uint64_t max_pending, int allow_remaining,
    int num_clients, int expected_pending,
    int expected_calls, int strict_cb_count)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clients[PENDING_CAP_TEST_CLIENTS] = { NULL };
    int client_fds[PENDING_CAP_TEST_CLIENTS] = { -1, -1, -1, -1, -1 };
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1;
    int testresult = 0;
    int cb_arg_marker = 0;
    int i;

    if (!TEST_int_le(num_clients, PENDING_CAP_TEST_CLIENTS))
        return 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto err;

    if (!TEST_true(create_dtls_listener(sctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_REQUIRE_HRR
                | SSL_LISTENER_FLAG_SINGLE_THREAD,
            &listener, &server_addr, &server_fd)))
        goto err;

    if (!TEST_true(SSL_set_generic_value_uint(listener,
            SSL_VALUE_DTLS_LISTENER_MAX_PENDING_CONNS, max_pending)))
        goto err;

    new_pending_cb_reset(sctx, &cb_arg_marker, allow_remaining);
    SSL_CTX_set_new_pending_conn_cb(sctx, new_pending_cb_fn, &cb_arg_marker);

    for (i = 0; i < num_clients; i++)
        if (!TEST_true(cap_test_send_clienthello(cctx, server_addr, listener,
                &clients[i], &client_fds[i])))
            goto err;

    /* Verify the number of pending connections matches expectation. */
    if (!TEST_size_t_eq(ossl_dgram_conn_lookup_num_items(
                            ((DTLS_LISTENER *)listener)->pending_conns),
            (size_t)expected_pending))
        goto err;

    /*
     * Verify the callback was invoked as expected.
     *
     * Strict counts are only meaningful when we know retransmits cannot
     * reach the callback (either because we sent an HVR to quiet the
     * client, or because the cap short-circuits ahead of the callback).
     * Otherwise assert only the lower bound.
     */
    if (strict_cb_count) {
        if (!TEST_int_eq(new_pending_cb_call_count, expected_calls))
            goto err;
    } else {
        if (!TEST_int_ge(new_pending_cb_call_count, expected_calls))
            goto err;
    }

    /* Verify ctx and arg were passed through correctly on every call. */
    if (!TEST_true(new_pending_cb_ctx_matched))
        goto err;
    if (!TEST_true(new_pending_cb_arg_matched))
        goto err;

    testresult = 1;

err:
    /* Clear callback so nothing else re-enters new_pending_cb_fn. */
    if (sctx != NULL)
        SSL_CTX_set_new_pending_conn_cb(sctx, NULL, NULL);

    for (i = 0; i < num_clients; i++) {
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

/*
 * Scenario 1: Callback allows every connection; cap is high enough that it
 * never fires.
 *
 * Sends 3 ClientHellos, expects 3 pending connections registered, expects
 * the callback to have been invoked exactly 3 times (once per novel peer;
 * HVR keeps clients from retransmitting during the drain window).
 */
static int test_new_pending_cb_allow_all(void)
{
    return run_new_pending_cb_scenario(100, 100, 3, 3, 3, 1);
}

/*
 * Scenario 2: Callback rejects every connection; cap is high enough that it
 * never fires.
 *
 * Sends 3 ClientHellos, expects 0 pending connections registered, expects
 * the callback to have been invoked at least 3 times. On rejection no HVR
 * is sent, so the client's DTLS retransmit timer may re-fire the callback
 * during the drain window - we can only assert a lower bound.
 */
static int test_new_pending_cb_reject_all(void)
{
    return run_new_pending_cb_scenario(100, 0, 3, 0, 3, 0);
}

/*
 * Scenario 3: Cap set to LIMIT (3); callback always allows; 5 clients try to
 * connect.
 *
 * The cap is checked before the callback, so after the LIMIT-th pending
 * connection is registered the cap short-circuits subsequent packets and
 * the callback is not invoked for them (this holds even under retransmits).
 *
 * Expected:
 *   - exactly PENDING_CAP_TEST_LIMIT (3) pending connections registered
 *   - callback invoked exactly PENDING_CAP_TEST_LIMIT (3) times
 */
static int test_new_pending_cb_blocked_by_cap(void)
{
    return run_new_pending_cb_scenario(PENDING_CAP_TEST_LIMIT, 100,
        PENDING_CAP_TEST_CLIENTS,
        PENDING_CAP_TEST_LIMIT,
        PENDING_CAP_TEST_LIMIT, 1);
}

/*
 * Scenario 4: Cap set well above the client count; callback rejects every
 * connection.
 *
 * Verifies that callback-side rejection alone is sufficient to keep
 * pending_conns empty, even when the cap is not a factor. Sends 5
 * ClientHellos, expects 0 pending connections registered, expects the
 * callback to have been invoked at least 5 times (retransmits may inflate
 * the count - see scenario 2 for the rationale on the lower bound).
 */
static int test_new_pending_cb_all_denied_under_cap(void)
{
    return run_new_pending_cb_scenario(100, 0, PENDING_CAP_TEST_CLIENTS,
        0, PENDING_CAP_TEST_CLIENTS, 0);
}

/*
 * Scenario 5: Callback allows the first invocation and denies the rest.
 *
 * Verifies that the callback's return value is honored per-invocation
 * rather than cached from the first call. Sends 2 ClientHellos with a
 * high cap so the callback is always reached:
 *   - client 1: callback returns 1, pending connection is registered,
 *     an HVR is sent (so this client does not retransmit and re-enter
 *     the callback).
 *   - client 2: callback returns 0, connection is discarded silently;
 *     retransmits from client 2 may re-invoke the callback (all
 *     subsequent returns are also 0).
 *
 * Expected:
 *   - exactly 1 pending connection registered
 *   - callback invoked at least 2 times (lower-bound: retransmits from
 *     the denied client can inflate this)
 */
static int test_new_pending_cb_alternate(void)
{
    return run_new_pending_cb_scenario(100, 1, 2, 1, 2, 0);
}

/*
 * The two tests below need a listener with a notifier, which only exists
 * when the listener is created without SSL_LISTENER_FLAG_SINGLE_THREAD. In a
 * no-threads build that listener cannot be created at all, because the
 * condition variable it needs is unavailable.
 */
#if defined(OPENSSL_THREADS)
/*
 * Test that queueing a connection for accept signals the listener's notifier.
 *
 * A thread waiting in SSL_poll() for SSL_POLL_EVENT_IC is blocked on the
 * listener's network socket and on its notifier. Where another thread does the
 * demuxing, that socket does not necessarily become readable on the waiter's
 * behalf, so the notifier is what has to wake it.
 *
 * Most of the time the bug this covers is masked. Every connection reaching
 * the accept queue got there because a datagram was demuxed into its receive
 * queue, and the packet handler has always signalled on that injection, so the
 * waiter is woken, ticks the listener itself during its readout, and finds the
 * connection. What is not covered by that is the window in which the injection
 * and the queue push straddle a waiter registering, because signalling is
 * conditional on there being a waiter at the time.
 *
 * The numbered steps below are that window - the interleaving of two threads
 * which the fix exists to handle. They are not what this test does, and are
 * given only so that what it does assert makes sense; see the end of this
 * comment for how it is actually checked.
 *
 *   1. Accept thread A polls the listener for SSL_POLL_EVENT_IC. Its readout
 *      ticks the listener, finds nothing, and it decides to block. It is not
 *      a registered waiter yet.
 *   2. Worker thread B polls one of its own connections, which also ticks the
 *      listener. The pump reads a client's final ClientHello and injects it
 *      into that pending connection's queue. There are no waiters, so nothing
 *      is signalled.
 *   3. A enters the blocking section. Its re-check runs without ticking, so it
 *      sees only the accept queue, which is still empty, and it blocks.
 *   4. B's tick reaches dtls_listener_drive_pending(), which completes the
 *      connection against the buffered ClientHello and pushes it onto the
 *      accept queue.
 *
 * Without a signal at step 4, A sleeps on with a validated connection sitting
 * ready, until some unrelated datagram makes the socket readable again. B
 * consumed the only one in flight, and the client is now waiting on the
 * server, so on a quiet listener that is until the client retransmits.
 *
 * That interleaving cannot be forced from outside the library, so rather than
 * reproducing the steps above, this drives their essential part by hand and on
 * one thread: pumping the demux directly performs step 2, the signal it raises
 * is then cleared, and the tick which follows can only signal by way of step 4.
 * Asserting that it did is therefore asserting that a queue push signals.
 *
 * signalled_notifier is protected by the listener mutex in the library, which
 * has to assume concurrent access. This test is single threaded throughout, so
 * it reads the field directly without holding the mutex.
 */
static int test_dtls_notifier_signalled_on_accept_queue_push(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL, *clientssl = NULL;
    BIO_ADDR *server_addr = NULL;
    DTLS_LISTENER *dl;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result = 0;
    int server_fd = -1, client_fd = -1;
    int in_blocking_section = 0;
    int abortctr, retc, err_code;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_VERSION, 0, &sctx, &cctx, cert,
            privkey)))
        goto end;

    /*
     * Multi-threaded mode (no SSL_LISTENER_FLAG_SINGLE_THREAD) so that the
     * listener has a notifier at all.
     */
    if (!TEST_true(create_dtls_listener(sctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_REQUIRE_HRR,
            &listener, &server_addr, &server_fd)))
        goto end;

    dl = (DTLS_LISTENER *)listener;
    if (!TEST_true(dl->have_notifier))
        goto end;

    if (!TEST_true(create_dtls_client_for_addr(cctx, server_addr, &clientssl,
            &client_fd)))
        goto end;

    /* Pose as a thread waiting for readiness, so signalling is enabled. */
    ossl_dtls_listener_enter_blocking_section(listener);
    in_blocking_section = 1;

    /*
     * Drive the cookie exchange, splitting each round into its two halves so
     * that the two signalling opportunities can be told apart:
     *
     *   - demuxing a datagram to a connection's receive queue, which the
     *     packet handler has always signalled, and
     *   - completing a connection and pushing it onto the accept queue.
     *
     * Pumping the demux directly performs only the first. The signal it
     * raises is then cleared, so when the listener is next ticked the pump
     * finds nothing new and only the accept queue push can signal.
     *
     * There is no public API for that split: SSL_poll() and
     * SSL_accept_connection() both tick the listener, which does the two
     * together.
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = listener;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    SSL_set_connect_state(clientssl);
    for (abortctr = 0; abortctr < 100; abortctr++) {
        retc = SSL_connect(clientssl);
        err_code = SSL_get_error(clientssl, retc);
        if (retc <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect failed (err %d)", err_code);
            goto end;
        }

        ossl_dgram_demux_pump(dl->demux);

        ossl_dtls_listener_leave_blocking_section(listener);
        in_blocking_section = 0;
        if (!TEST_int_eq(dl->signalled_notifier, 0))
            goto end;
        ossl_dtls_listener_enter_blocking_section(listener);
        in_blocking_section = 1;

        /*
         * A zero timeout, so this ticks the listener and reads out the result
         * without ever blocking, and therefore without itself entering a
         * blocking section and clearing the signal we are watching for.
         */
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout,
                0, &poll_result)))
            goto end;

        if ((poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            break;
    }

    if (!TEST_size_t_gt(SSL_get_accept_connection_queue_len(listener), 0))
        goto end;

    /* The accept queue push must have woken any waiter. */
    if (!TEST_int_eq(dl->signalled_notifier, 1))
        goto end;

    testresult = 1;
end:
    if (in_blocking_section)
        ossl_dtls_listener_leave_blocking_section(listener);
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
 * Test that a blocking SSL_poll() on a listener enters a blocking section.
 *
 * Unless it does, three things follow: the notifier is not in the poll set, so
 * it cannot wake this thread; cur_blocking_waiters is never incremented, and
 * since signalling is conditional on there being a waiter, no other thread
 * even attempts to signal; and there is no re-check after registering, so
 * readiness arising between the readout and the wait is lost.
 *
 * Polling the socket alone is not enough, though not because a wakeup can be
 * missed outright. poll() reports whatever is currently sitting in the socket
 * buffer and returns immediately if there is any, so a thread cannot miss a
 * datagram just by being outside poll() when it arrives. What it can miss is a
 * datagram another thread has already taken. With several threads polling the
 * one shared socket that happens constantly: an arriving datagram wakes all of
 * them, only one gets it, and the rest find nothing. Any of them can be the
 * one that takes it, because SSL_read() on a connection pumps the demux and
 * SSL_poll() on a connection ticks the whole listener.
 *
 *   1. Accept thread A polls the listener for SSL_POLL_EVENT_IC. Its readout
 *      ticks the listener, finds nothing, and it decides to block.
 *   2. A client's final ClientHello lands on the shared socket.
 *   3. Worker thread B, polling one of its own connections, ticks the listener
 *      and is the one that takes the datagram. Its tick completes the pending
 *      connection and pushes it onto the accept queue. Signalling is attempted,
 *      but A never registered as a waiter, so nothing is signalled.
 *   4. A reaches its poll, watching the socket alone. B drained it, so it is
 *      empty, and A sleeps with a validated connection sitting on the accept
 *      queue.
 *
 * A's readout, back at step 1, would have found that connection had it run
 * after step 3 rather than before it. Registering as a waiter and re-checking
 * is what removes the dependency on that ordering.
 *
 * Note that the signal added for the step 3 queue push is itself conditional on
 * a registered waiter, so it does nothing for a thread polling the listener
 * until that thread registers. The two fixes are complementary.
 *
 * None of that has a public observable, and this deliberately does not time
 * the wait. Instead it relies on the last waiter out of a blocking section
 * draining a raised notifier signal: raise one beforehand, poll briefly with
 * nothing ready, and check afterwards. Drained means a blocking section was
 * entered and left, since only a leave drains it and only an enter can be left;
 * still standing means neither happened.
 *
 * signalled_notifier is protected by the listener mutex in the library, which
 * has to assume concurrent access. This test is single threaded throughout, so
 * it reads and writes the field directly without holding the mutex.
 *
 * Note what this does not cover. That the notifier is in the poll set, and so
 * can actually deliver a wakeup, is not checked: with a signal raised the poll
 * returns at once if the notifier is being watched and sleeps out its timeout
 * if it is not, and only timing separates those. A longer timeout would not
 * help, because the first iteration's leave drains the notifier and the next
 * one sleeps out the remainder either way. The re-check after registering is
 * not covered either, since readiness arriving between the readout and the
 * registration cannot be produced from a single thread.
 */
static int test_dtls_poll_listener_enters_blocking_section(void)
{
    SSL_CTX *sctx = NULL;
    SSL *listener = NULL;
    BIO_ADDR *server_addr = NULL;
    DTLS_LISTENER *dl;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result = 0;
    int server_fd = -1, nfd = -1;
    int testresult = 0;

    if (!TEST_ptr(sctx = SSL_CTX_new(DTLS_server_method())))
        goto end;

    if (!TEST_true(create_dtls_listener(sctx, 0, &listener, &server_addr,
            &server_fd)))
        goto end;

    dl = (DTLS_LISTENER *)listener;
    if (!TEST_true(dl->have_notifier))
        goto end;

    /*
     * Raise the notifier as another thread reporting readiness would, which
     * means both writing to the notifier and recording that it is raised, as
     * dtls_listener_signal_notifier() does.
     */
    if (!TEST_true(ossl_rio_notifier_signal(&dl->notifier)))
        goto end;
    dl->signalled_notifier = 1;

    nfd = ossl_rio_notifier_as_fd(&dl->notifier);
    if (!TEST_int_ge(nfd, 0)
        || !TEST_int_gt(BIO_socket_ready(nfd, /*for_read=*/1), 0))
        goto end;

    /*
     * Poll with a short timeout. No client exists, so nothing is ever ready
     * and SSL_poll() must block, which is what drives the translation that
     * enters the blocking section.
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = listener;
    poll_item.events = SSL_POLL_EVENT_IC;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 100000;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0,
            &poll_result)))
        goto end;

    if (!TEST_size_t_eq(poll_result, 0))
        goto end;

    /*
     * Leaving the blocking section must have drained the notifier. Check the
     * notifier itself and not only the flag recording its state, since it is
     * the notifier being readable that would spuriously wake a later waiter.
     */
    if (!TEST_int_eq(BIO_socket_ready(nfd, /*for_read=*/1), 0))
        goto end;

    if (!TEST_int_eq(dl->signalled_notifier, 0))
        goto end;

    if (!TEST_size_t_eq(dl->cur_blocking_waiters, 0))
        goto end;

    testresult = 1;
end:
    SSL_free(listener);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    SSL_CTX_free(sctx);
    return testresult;
}

#endif /* OPENSSL_THREADS */

static unsigned int short_timer_cb_count;

/* Force a short retransmission timeout and count how often it is consulted. */
static unsigned int short_timer_cb(SSL *s, unsigned int timer_us)
{
    ++short_timer_cb_count;
    return 50000; /* 50ms */
}

/*
 * Force a retransmission timeout short enough that it is always already
 * expired, so the timeout can be driven repeatedly without waiting. Anything
 * at or below 15ms is treated as expired by dtls1_get_timeout().
 */
static unsigned int tiny_timer_cb(SSL *s, unsigned int timer_us)
{
    return 1000; /* 1ms */
}

/*
 * Test that the DTLS retransmission timer is stopped once the connection gives
 * up retransmitting.
 *
 * dtls1_handle_timeout() fails the connection after DTLS1_TMO_ALERT_COUNT
 * unanswered retransmissions. It must not leave the timer armed in the past
 * when it does: nothing will re-arm or clear it afterwards, so every later
 * query reports the timeout as due immediately, and any caller which waits on
 * it spins instead of sleeping - whether that is an application using
 * DTLSv1_get_timeout() with select(), or SSL_poll() bounding its own wait.
 */
static int test_dtls_timer_stopped_when_retransmits_exhausted(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    struct timeval timer_left;
    int is_infinite = 0;
    int retc, rets;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_VERSION, 0, &sctx, &cctx, cert,
            privkey)))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(serverssl, tiny_timer_cb);

    retc = SSL_connect(clientssl);
    if (!TEST_int_le(retc, 0)
        || !TEST_int_eq(SSL_get_error(clientssl, retc), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * With a timeout this short the server's timer is expired on every read
     * attempt, so the accept retransmits until the budget runs out and fails
     * the connection by itself. The client is never fed, so nothing is ever
     * acknowledged.
     *
     * The retransmissions happen in dtls1_read_bytes(), which calls
     * dtls1_handle_timeout() and, when it reports that it retransmitted, goes
     * back to its start label to try the read again.
     */
    rets = SSL_accept(serverssl);
    if (!TEST_int_le(rets, 0)
        || !TEST_int_eq(SSL_get_error(serverssl, rets), SSL_ERROR_SSL))
        goto end;

    /* The timer must not have been left armed in the past. */
    if (!TEST_true(SSL_get_event_timeout(serverssl, &timer_left, &is_infinite))
        || !TEST_true(is_infinite))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test that a blocking SSL_poll() on a DTLS connection honours the
 * retransmission timer.
 *
 * SSL_poll() bounds its wait by the per-object event timeout so that timer
 * driven work is not delayed. For a DTLS connection that timeout is the
 * handshake retransmission timer: if it is ignored, a poll with a long user
 * timeout sleeps straight through the point at which the flight should have
 * been resent, and if the peer had lost that flight neither side progresses.
 *
 * This does not time the wait. The retransmission timeout is forced down to
 * 50ms and the poll is given much longer, so a correct implementation must
 * wake and retransmit at least once before the poll deadline; an
 * implementation which ignores the timer retransmits not at all.
 */
static int test_dtls_poll_conn_honours_retransmit_timer(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout, timer_left;
    size_t poll_result = 0;
    int is_infinite = 0;
    int retc, rets, err_code;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_VERSION, 0, &sctx, &cctx, cert,
            privkey)))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    /*
     * Install the short timeout before the server sends anything, so that it
     * is picked up when the retransmission timer is first started rather than
     * only on a later expiry.
     */
    DTLS_set_timer_cb(serverssl, short_timer_cb);

    /*
     * Drive just far enough for the server to send its first flight and start
     * its retransmission timer. The client is then left alone, so the flight
     * stays unacknowledged for the duration of the poll.
     */
    retc = SSL_connect(clientssl);
    if (!TEST_int_le(retc, 0)
        || !TEST_int_eq(SSL_get_error(clientssl, retc), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The server consumes the ClientHello, sends its flight and then waits for
     * the client, so this does not complete the handshake.
     */
    rets = SSL_accept(serverssl);
    if (!TEST_int_le(rets, 0))
        goto end;

    err_code = SSL_get_error(serverssl, rets);
    if (!TEST_true(err_code == SSL_ERROR_WANT_READ
            || err_code == SSL_ERROR_WANT_WRITE))
        goto end;

    /*
     * Assert the precondition through the same call SSL_poll() uses to compute
     * its deadline: a running timer is reported as a finite timeout.
     */
    if (!TEST_true(SSL_get_event_timeout(serverssl, &timer_left, &is_infinite))
        || !TEST_false(is_infinite))
        goto end;

    short_timer_cb_count = 0;

    /*
     * Nothing will arrive for this connection during the poll, so it runs to
     * its deadline. Along the way the retransmission timer must expire and be
     * serviced, which re-arms the timer via the callback.
     */
    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = serverssl;
    poll_item.events = SSL_POLL_EVENT_R;
    poll_item.revents = 0;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 500000;

    if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout, 0,
            &poll_result)))
        goto end;

    if (!TEST_size_t_gt(short_timer_cb_count, 0))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Drive a client's ClientHello, and any cookie exchange, at the listener until
 * a connection is sitting on its accept queue, without accepting it.
 *
 * Returns 1 on success, 0 on failure.
 */
static int drive_until_connection_queued(SSL *listener, SSL *clientssl)
{
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result = 0;
    int abortctr, retc, err_code;

    poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    poll_item.desc.value.ssl = listener;
    poll_timeout.tv_sec = 0;
    poll_timeout.tv_usec = 0;

    SSL_set_connect_state(clientssl);

    for (abortctr = 0; abortctr < 100; abortctr++) {
        retc = SSL_connect(clientssl);
        err_code = SSL_get_error(clientssl, retc);
        if (retc <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE) {
            TEST_error("SSL_connect failed (err %d)", err_code);
            return 0;
        }

        /* A zero timeout, so this ticks the listener without ever waiting. */
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item), &poll_timeout,
                0, &poll_result)))
            return 0;

        if ((poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            return 1;
    }

    TEST_error("cookie exchange loop did not converge");
    return 0;
}

/*
 * Test the blocking mode of a DTLS listener and of the connections it creates.
 *
 * Blocking is the default, as it is for QUIC: a listener which was never
 * configured is blocking, and a connection follows its listener unless it was
 * given a setting of its own.
 *
 * Blocking is emulated by waiting for readiness of the listener's socket, so it
 * needs a BIO which can supply a poll descriptor to wait on. Where there is
 * none the object is non-blocking whatever was asked for, and asking for
 * blocking fails rather than claiming something which cannot be delivered.
 */
static int test_dtls_blocking_mode(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL, *clientssl = NULL, *serverssl = NULL;
    SSL *memlistener = NULL, *memclient = NULL, *plainssl = NULL;
    BIO_ADDR *server_addr = NULL, *client_addr = NULL;
    int server_fd = -1, client_fd = -1;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_VERSION, 0, &sctx, &cctx, cert,
            privkey)))
        goto end;

    /*
     * create_dtls_listener() turns blocking mode off on behalf of the single
     * threaded tests, so it cannot be used here: this test has to see the mode
     * a listener has when the application has never set it. Hence the
     * unconfigured variant.
     *
     * A socket BIO supplies a poll descriptor, so blocking is available.
     */
    if (!TEST_true(create_dtls_listener_unconfigured(sctx,
            SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_REQUIRE_HRR
                | SSL_LISTENER_FLAG_SINGLE_THREAD,
            &listener, &server_addr, &server_fd)))
        goto end;

    /* Blocking by default, having never been configured. */
    if (!TEST_int_eq(SSL_get_blocking_mode(listener), 1))
        goto end;

    /* Get a connection object accepted from the listener to examine. */
    if (!TEST_true(create_dtls_client_for_addr(cctx, server_addr, &clientssl,
            &client_fd)))
        goto end;

    if (!drive_until_connection_queued(listener, clientssl)
        || !TEST_ptr(serverssl = SSL_accept_connection(listener,
                         SSL_ACCEPT_CONNECTION_NO_BLOCK)))
        goto end;

    /* It inherits the listener's mode. */

    if (!TEST_int_eq(SSL_get_blocking_mode(serverssl), 1))
        goto end;

    /* Setting the listener non-blocking is inherited by the connection. */
    if (!TEST_true(SSL_set_blocking_mode(listener, 0))
        || !TEST_int_eq(SSL_get_blocking_mode(listener), 0)
        || !TEST_int_eq(SSL_get_blocking_mode(serverssl), 0))
        goto end;

    /* A setting on the connection overrides what it would inherit. */
    if (!TEST_true(SSL_set_blocking_mode(serverssl, 1))
        || !TEST_int_eq(SSL_get_blocking_mode(serverssl), 1)
        || !TEST_int_eq(SSL_get_blocking_mode(listener), 0))
        goto end;

    /*
     * A connection's own setting survives SSL_clear(). The mode is a property
     * of the connection as the application configured it, not of the handshake,
     * and dtls1_clear() memsets d1 and restores only selected fields.
     *
     * The listener and the connection must disagree for this to prove anything:
     * were the connection's setting lost it would fall back to inheriting, and
     * that is only visible if the listener says something different.
     */
    if (!TEST_true(SSL_set_blocking_mode(listener, 1))
        || !TEST_true(SSL_set_blocking_mode(serverssl, 0))
        || !TEST_int_eq(SSL_get_blocking_mode(listener), 1)
        || !TEST_int_eq(SSL_get_blocking_mode(serverssl), 0))
        goto end;

    if (!TEST_true(SSL_clear(serverssl))
        || !TEST_int_eq(SSL_get_blocking_mode(serverssl), 0))
        goto end;

    /*
     * Clear again. SSL_clear() resets the method to the default one, so the
     * first call above went through the ssl_deinit/ssl_init path that
     * reallocates d1 while this one goes through dtls1_clear(). Both discard
     * d1, so both have to be covered.
     */
    if (!TEST_true(SSL_clear(serverssl))
        || !TEST_int_eq(SSL_get_blocking_mode(serverssl), 0))
        goto end;

    /* And back the other way round. */
    if (!TEST_true(SSL_set_blocking_mode(listener, 1))
        || !TEST_true(SSL_set_blocking_mode(serverssl, 0))
        || !TEST_int_eq(SSL_get_blocking_mode(listener), 1)
        || !TEST_int_eq(SSL_get_blocking_mode(serverssl), 0))
        goto end;

    /*
     * A listener on BIOs which cannot supply a poll descriptor reports
     * non-blocking however it was configured, and asking for blocking fails.
     */
    if (!TEST_true(create_dtls_listener_and_client_mem(sctx, cctx,
            SSL_LISTENER_FLAG_SINGLE_THREAD, &memlistener, &memclient,
            &client_addr)))
        goto end;

    if (!TEST_int_eq(SSL_get_blocking_mode(memlistener), 0))
        goto end;

    ERR_clear_error();
    if (!TEST_false(SSL_set_blocking_mode(memlistener, 1))
        || !TEST_int_eq((int)ERR_GET_REASON(ERR_peek_error()), ERR_R_UNSUPPORTED))
        goto end;
    ERR_clear_error();

    /* Asking for non-blocking is fine, that being what it already is. */
    if (!TEST_true(SSL_set_blocking_mode(memlistener, 0))
        || !TEST_int_eq(SSL_get_blocking_mode(memlistener), 0))
        goto end;

    /*
     * A DTLS object which did not come from a listener has no blocking mode:
     * it takes its behaviour from its own BIO in the traditional way.
     */
    if (!TEST_ptr(plainssl = SSL_new(cctx)))
        goto end;

    if (!TEST_int_eq(SSL_get_blocking_mode(plainssl), -1)
        || !TEST_false(SSL_set_blocking_mode(plainssl, 1))
        || !TEST_false(SSL_set_blocking_mode(plainssl, 0)))
        goto end;

    testresult = 1;
end:
    ERR_clear_error();
    SSL_free(plainssl);
    SSL_free(memclient);
    SSL_free(memlistener);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_free(listener);
    BIO_ADDR_free(client_addr);
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
 * Test when SSL_accept_connection() waits and when it does not.
 *
 * It waits only if the caller did not pass SSL_ACCEPT_CONNECTION_NO_BLOCK and
 * the listener is in blocking mode, which is the same rule QUIC applies. So
 * either of the two saying not to wait is enough, and this checks both of those
 * cases: no client exists, so anything which did wait would never return.
 */
static int test_dtls_accept_wait_requires_mode_and_flag(void)
{
    SSL_CTX *sctx = NULL;
    SSL *listener = NULL;
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1;
    int testresult = 0;

    if (!TEST_ptr(sctx = SSL_CTX_new(DTLS_server_method())))
        goto end;

    if (!TEST_true(create_dtls_listener(sctx, SSL_LISTENER_FLAG_SINGLE_THREAD,
            &listener, &server_addr, &server_fd)))
        goto end;

    /* Non-blocking mode, and no flag: the mode alone stops it waiting. */
    if (!TEST_true(SSL_set_blocking_mode(listener, 0))
        || !TEST_ptr_null(SSL_accept_connection(listener, 0)))
        goto end;

    /* Blocking mode, but the flag overrides it. */
    if (!TEST_true(SSL_set_blocking_mode(listener, 1))
        || !TEST_int_eq(SSL_get_blocking_mode(listener), 1)
        || !TEST_ptr_null(SSL_accept_connection(listener,
            SSL_ACCEPT_CONNECTION_NO_BLOCK)))
        goto end;

    testresult = 1;
end:
    SSL_free(listener);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    SSL_CTX_free(sctx);
    return testresult;
}

/*
 * Test that a rejected SSL_set_blocking_mode() leaves the mode alone.
 *
 * Whether blocking can be supported depends on the listener's BIO, so a
 * request can be refused now and be perfectly deliverable later. The refusal
 * must therefore not record the mode it refused to set: the effect only becomes
 * visible once a BIO which can supply a poll descriptor is in place, at which
 * point the listener would be found blocking on the strength of a call which
 * failed.
 */
static int test_dtls_blocking_mode_failed_set_is_inert(void)
{
    SSL_CTX *sctx = NULL;
    SSL *listener = NULL;
    BIO_ADDR *server_addr = NULL;
    BIO *rbio = NULL;
    int server_fd = -1;
    int testresult = 0;

    if (!TEST_ptr(sctx = SSL_CTX_new(DTLS_server_method())))
        goto end;

    if (!TEST_true(create_dtls_listener(sctx, SSL_LISTENER_FLAG_SINGLE_THREAD,
            &listener, &server_addr, &server_fd)))
        goto end;

    /* Ask for non-blocking explicitly, so the default cannot mask a change. */
    if (!TEST_true(SSL_set_blocking_mode(listener, 0))
        || !TEST_int_eq(SSL_get_blocking_mode(listener), 0))
        goto end;

    /* Keep the BIO, then take it away so blocking cannot be supported. */
    if (!TEST_ptr(rbio = SSL_get_rbio(listener))
        || !TEST_true(BIO_up_ref(rbio)))
        goto end;

    SSL_set0_rbio(listener, NULL);

    ERR_clear_error();
    if (!TEST_false(SSL_set_blocking_mode(listener, 1))
        || !TEST_int_eq((int)ERR_GET_REASON(ERR_peek_error()),
            ERR_R_UNSUPPORTED)) {
        BIO_free(rbio);
        goto end;
    }
    ERR_clear_error();

    /* Give the BIO back, which makes blocking supportable once more. */
    SSL_set0_rbio(listener, rbio);

    /* The refused request must not have taken effect. */
    if (!TEST_int_eq(SSL_get_blocking_mode(listener), 0))
        goto end;

    testresult = 1;
end:
    SSL_free(listener);
    BIO_ADDR_free(server_addr);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
    SSL_CTX_free(sctx);
    return testresult;
}

/*
 * State for the filter BIO below.
 */
struct failing_send_data {
    int fails_remaining; /* sends still to be rejected */
    int sends; /* sends attempted through the filter */
};

static long failing_send_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    BIO *next = BIO_next(bio);

    if (next == NULL)
        return 0;

    if (cmd == BIO_CTRL_DUP)
        return 0L;

    /*
     * Everything else, the poll descriptors in particular, has to reach the
     * socket underneath: the blocking write waits on the descriptor this
     * returns.
     */
    return BIO_ctrl(next, cmd, num, ptr);
}

static int failing_send_sendmmsg(BIO *bio, BIO_MSG *msg, size_t stride,
    size_t num_msg, uint64_t flags, size_t *msgs_processed)
{
    struct failing_send_data *data = BIO_get_data(bio);
    BIO *next = BIO_next(bio);

    if (data == NULL || next == NULL)
        return 0;

    data->sends++;

    if (data->fails_remaining > 0) {
        data->fails_remaining--;
        *msgs_processed = 0;
        /*
         * BIO_err_is_non_fatal() accepts this, so the record layer treats the
         * send as one to be attempted again rather than as an error.
         */
        ERR_raise(ERR_LIB_BIO, BIO_R_NON_FATAL);
        return 0;
    }

    return BIO_sendmmsg(next, msg, stride, num_msg, flags, msgs_processed);
}

/* Choose a sufficiently large type likely to be unused for this custom BIO */
#define BIO_TYPE_FAILING_SEND_FILTER (0x83 | BIO_TYPE_FILTER)

static BIO_METHOD *method_failing_send = NULL;

/* Note: Not thread safe! */
static const BIO_METHOD *bio_f_failing_send_filter(void)
{
    if (method_failing_send == NULL) {
        method_failing_send = BIO_meth_new(BIO_TYPE_FAILING_SEND_FILTER,
            "Failing datagram send filter");
        if (method_failing_send == NULL
            || !BIO_meth_set_ctrl(method_failing_send, failing_send_ctrl)
            || !BIO_meth_set_sendmmsg(method_failing_send,
                failing_send_sendmmsg))
            return NULL;
    }
    return method_failing_send;
}

/*
 * Test that a write on a blocking listener connection waits for the socket and
 * sends again, rather than reporting that it needs to be retried.
 *
 * A datagram which cannot be sent is normally dropped, which is reasonable for
 * an unreliable transport but is not what an application asking for blocking
 * writes expects: it gets no data sent and a WANT_WRITE it did not ask to have
 * to handle. The listener's socket is shared and always non-blocking, so there
 * is nothing for such a write to block in by itself.
 *
 * A loopback socket's send buffer does not fill, so a filter BIO supplies the
 * transient failure instead. Only one send is rejected: the retry then goes
 * through, and the client is read to confirm the datagram was really sent
 * rather than merely reported as sent.
 *
 * The handshake runs with the listener non-blocking, so this test drives both
 * ends from the one thread as the others here do, and only the connection is
 * switched to blocking, for the write.
 */
static int test_dtls_blocking_write(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL, *clientssl = NULL, *serverssl = NULL;
    BIO_ADDR *server_addr = NULL;
    BIO *sockbio = NULL, *filter = NULL;
    struct failing_send_data data;
    int server_fd = -1, client_fd = -1;
    int testresult = 0;
    char buf[256];
    size_t written = 0, readbytes = 0;
    int i, ret = -1;

    memset(&data, 0, sizeof(data));

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_VERSION, 0, &sctx, &cctx, cert,
            privkey)))
        goto end;

    if (!TEST_true(create_dtls_listener(sctx, SSL_LISTENER_FLAG_SINGLE_THREAD,
            &listener, &server_addr, &server_fd)))
        goto end;

    /*
     * Insert the filter in front of the listener's socket for writes only,
     * leaving reads to reach the socket directly. The listener holds a
     * reference for each direction, so the filter chain needs one of its own.
     */
    if (!TEST_ptr(sockbio = SSL_get_wbio(listener))
        || !TEST_ptr(filter = BIO_new(bio_f_failing_send_filter())))
        goto end;

    BIO_set_data(filter, &data);
    BIO_set_init(filter, 1);

    if (!TEST_true(BIO_up_ref(sockbio))) {
        BIO_free(filter);
        goto end;
    }

    BIO_push(filter, sockbio);
    SSL_set0_wbio(listener, filter); /* the listener owns the chain now */
    filter = NULL;

    if (!TEST_true(create_dtls_client_for_addr(cctx, server_addr, &clientssl,
            &client_fd)))
        goto end;

    if (!drive_until_connection_queued(listener, clientssl)
        || !TEST_ptr(serverssl = SSL_accept_connection(listener,
                         SSL_ACCEPT_CONNECTION_NO_BLOCK)))
        goto end;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    /*
     * Everything up to here, including any post-handshake traffic, has gone
     * through the filter untouched. Reject the next send only.
     */
    if (!TEST_true(SSL_set_blocking_mode(serverssl, 1))
        || !TEST_int_eq(SSL_get_blocking_mode(serverssl), 1))
        goto end;

    data.sends = 0;
    data.fails_remaining = 1;

    if (!TEST_true(SSL_write_ex(serverssl, "msg", 3, &written))
        || !TEST_size_t_eq(written, 3))
        goto end;

    /*
     * The send really was rejected, and was retried rather than reported: the
     * count proves a second attempt was made, which is the whole behaviour
     * under test. Without it, a write which never reached the filter at all
     * would look the same as one which was retried.
     */
    if (!TEST_int_eq(data.fails_remaining, 0)
        || !TEST_int_ge(data.sends, 2))
        goto end;

    /* The datagram reached the client, so nothing was dropped on the way. */
    for (i = 0; i < 20; i++) {
        ret = SSL_read_ex(clientssl, buf, sizeof(buf), &readbytes);
        if (ret == 1)
            break;
        if (!TEST_int_eq(SSL_get_error(clientssl, ret), SSL_ERROR_WANT_READ))
            goto end;
        OSSL_sleep(10);
    }

    if (!TEST_int_eq(ret, 1)
        || !TEST_mem_eq(buf, readbytes, "msg", 3))
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
    BIO_meth_free(method_failing_send);
    method_failing_send = NULL;
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

    /* Message buffering test */
    ADD_TEST(test_dtls13_listener_msg_buffering);
#endif /* OPENSSL_NO_DTLS1_3 */

    /* Time callback tests */
    ADD_TEST(test_dtls_listener_time_callback_basic);
    ADD_TEST(test_dtls_listener_time_callback_invalid);

    /* Pending timeout tests */
    ADD_TEST(test_dtls_listener_pending_timeout_basic);
    ADD_TEST(test_dtls_listener_pending_timeout_invalid);

    /* Blocking mode tests */
    ADD_TEST(test_dtls_blocking_mode);
    ADD_TEST(test_dtls_blocking_mode_failed_set_is_inert);
    ADD_TEST(test_dtls_accept_wait_requires_mode_and_flag);
    ADD_TEST(test_dtls_blocking_write);

    /* SSL object ownership tests (run with ASAN to detect leaks/double-frees) */
    ADD_TEST(test_ssl_ownership_pending_conn_leak);
    ADD_TEST(test_ssl_ownership_incoming_conn_leak);
    ADD_TEST(test_ssl_ownership_three_conn_states);
    ADD_TEST(test_ssl_ownership_set_rbio_pending_leak);
    ADD_TEST(test_ssl_ownership_accept_free_no_double_free);
    ADD_TEST(test_ssl_ownership_set_rbio_incoming_leak);
    ADD_TEST(test_ssl_ownership_multiple_pending_leak);
    ADD_TEST(test_ssl_ownership_pending_timeout_cleanup);

    /* Max number of pending connections tests */
    ADD_TEST(test_dtls_listener_max_pending_conns_api);
    ADD_TEST(test_dtls_listener_max_pending_conns_invalid);
    ADD_TEST(test_dtls_listener_max_dgram_size_api);
    ADD_TEST(test_dtls_listener_max_dgram_size_functional);
    ADD_TEST(test_pending_conn_cap_enforcement);
    ADD_TEST(test_pending_cap_with_timeout);

    /* new_pending_conn_cb tests (DTLS listener) */
    ADD_TEST(test_new_pending_cb_allow_all);
    ADD_TEST(test_new_pending_cb_reject_all);
    ADD_TEST(test_new_pending_cb_blocked_by_cap);
    ADD_TEST(test_new_pending_cb_all_denied_under_cap);
    ADD_TEST(test_new_pending_cb_alternate);
    /* Blocking SSL_poll() wakeup tests */
#if defined(OPENSSL_THREADS)
    ADD_TEST(test_dtls_notifier_signalled_on_accept_queue_push);
    ADD_TEST(test_dtls_poll_listener_enters_blocking_section);
#endif
    ADD_TEST(test_dtls_poll_conn_honours_retransmit_timer);
    ADD_TEST(test_dtls_timer_stopped_when_retransmits_exhausted);

    return 1;
}
