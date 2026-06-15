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
#include <openssl/bio.h>
#include <openssl/err.h>
#include "internal/sockets.h"
#include "internal/thread_arch.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"

static char *cert = NULL;
static char *privkey = NULL;

#define NUM_CLIENTS 3
#define CLIENT_TO_SERVER_MSG "Hello from client"
#define SERVER_TO_CLIENT_MSG "Hello from server"
#define POLL_TIMEOUT_SEC 5
#define MAX_POLL_RETRIES 50

/*
 * Per-thread state for server connection handlers
 */
struct server_thread_args {
    SSL *conn; /* Server-side connection for this thread */
    int thread_idx;
    CRYPTO_THREAD *thread;
    int result; /* 1 = success, 0 = failure */
};

/*
 * Per-thread state for client connection handlers
 */
struct client_thread_args {
    SSL *conn; /* Client-side connection for this thread */
    int thread_idx;
    CRYPTO_THREAD *thread;
    int result; /* 1 = success, 0 = failure */
};

/*
 * Thread function: waits for data on a server connection using SSL_poll,
 * reads the message from client, and sends a response.
 *
 * Uses a retry loop because SSL_poll() returning SSL_POLL_EVENT_R doesn't
 * guarantee SSL_read_ex() will succeed - there may be encrypted records
 * but not yet a complete application data message.
 */
static unsigned int server_conn_thread(void *arg)
{
    struct server_thread_args *ta = (struct server_thread_args *)arg;
    SSL_POLL_ITEM item;
    struct timeval timeout;
    size_t result_count, readbytes, written;
    char buf[256] = { 0 };
    int ret, err, retries;

    ta->result = 0;
    readbytes = 0;

    item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    item.desc.value.ssl = ta->conn;
    item.events = SSL_POLL_EVENT_R;
    item.revents = 0;

    timeout.tv_sec = POLL_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    /* Poll and receive message from client */
    for (retries = 0; retries < MAX_POLL_RETRIES; retries++) {
        item.revents = 0;

        if (!TEST_true(SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count)))
            return 0;

        if (result_count == 0 || (item.revents & SSL_POLL_EVENT_R) == 0)
            continue;

        ret = SSL_read_ex(ta->conn, buf, sizeof(buf) - 1, &readbytes);
        if (ret == 1)
            break;

        err = SSL_get_error(ta->conn, ret);
        if (!TEST_int_eq(err, SSL_ERROR_WANT_READ))
            return 0;
    }

    if (!TEST_int_lt(retries, MAX_POLL_RETRIES))
        return 0;

    buf[readbytes] = '\0';
    if (!TEST_str_eq(buf, CLIENT_TO_SERVER_MSG))
        return 0;

    if (!TEST_true(SSL_write_ex(ta->conn, SERVER_TO_CLIENT_MSG,
            strlen(SERVER_TO_CLIENT_MSG), &written)))
        return 0;

    ta->result = 1;
    return 0;
}

/*
 * Thread function: sends a message to the server and waits for the response.
 *
 * Uses SSL_poll to wait for readable data from server, then verifies the response.
 */
static unsigned int client_conn_thread(void *arg)
{
    struct client_thread_args *ta = (struct client_thread_args *)arg;
    SSL_POLL_ITEM item;
    struct timeval timeout;
    size_t result_count, readbytes, written;
    char buf[256] = { 0 };
    int ret, err, retries;

    ta->result = 0;

    /* Send message to server */
    if (!TEST_true(SSL_write_ex(ta->conn, CLIENT_TO_SERVER_MSG,
            strlen(CLIENT_TO_SERVER_MSG), &written)))
        return 0;

    /* Wait for and receive response from server */
    item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
    item.desc.value.ssl = ta->conn;
    item.events = SSL_POLL_EVENT_R;
    item.revents = 0;

    timeout.tv_sec = POLL_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    for (retries = 0; retries < MAX_POLL_RETRIES; retries++) {
        item.revents = 0;

        if (!TEST_true(SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count)))
            return 0;

        if (result_count == 0 || (item.revents & SSL_POLL_EVENT_R) == 0)
            continue;

        ret = SSL_read_ex(ta->conn, buf, sizeof(buf) - 1, &readbytes);
        if (ret == 1)
            break;

        err = SSL_get_error(ta->conn, ret);
        if (!TEST_int_eq(err, SSL_ERROR_WANT_READ))
            return 0;
    }

    if (!TEST_int_lt(retries, MAX_POLL_RETRIES))
        return 0;

    buf[readbytes] = '\0';
    if (!TEST_str_eq(buf, SERVER_TO_CLIENT_MSG))
        return 0;

    ta->result = 1;
    return 0;
}

/*
 * Helper: create DTLS listener with real UDP socket
 */
static int create_listener(SSL_CTX *ctx, SSL **listener, BIO_ADDR **addr, int *fd)
{
    BIO *bio = NULL;
    struct in_addr ina;
    union BIO_sock_info_u info;
    int ret = 0;

    *listener = NULL;
    *addr = NULL;
    *fd = -1;

    ina.s_addr = htonl(INADDR_LOOPBACK);

    *fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(*fd, 0))
        goto err;

    if (!TEST_true(BIO_socket_nbio(*fd, 1)))
        goto err;

    if (!TEST_ptr(*addr = BIO_ADDR_new()))
        goto err;

    if (!TEST_true(BIO_ADDR_rawmake(*addr, AF_INET, &ina, sizeof(ina), 0)))
        goto err;

    if (!TEST_true(BIO_bind(*fd, *addr, 0)))
        goto err;

    info.addr = *addr;
    if (!TEST_true(BIO_sock_info(*fd, BIO_SOCK_INFO_ADDRESS, &info)))
        goto err;

    if (!TEST_ptr(bio = BIO_new_dgram(*fd, BIO_NOCLOSE)))
        goto err;

    if (!TEST_ptr(*listener = SSL_new_listener(ctx, 0)))
        goto err;

    SSL_set_bio(*listener, bio, bio);
    bio = NULL;

    if (!TEST_int_eq(SSL_listen(*listener), 1))
        goto err;

    ret = 1;

err:
    BIO_free(bio);
    if (ret == 0) {
        SSL_free(*listener);
        BIO_ADDR_free(*addr);
        if (*fd >= 0)
            BIO_closesocket(*fd);
        *listener = NULL;
        *addr = NULL;
        *fd = -1;
    }
    return ret;
}

/*
 * Helper: create DTLS client connected to server address
 */
static int create_client(SSL_CTX *ctx, const BIO_ADDR *server_addr,
    SSL **client, int *fd)
{
    BIO *bio = NULL;
    int ret = 0;

    *client = NULL;
    *fd = -1;

    *fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(*fd, 0))
        goto err;

    if (!TEST_true(BIO_socket_nbio(*fd, 1)))
        goto err;

    if (!TEST_ptr(bio = BIO_new_dgram(*fd, BIO_NOCLOSE)))
        goto err;

    if (!TEST_true(BIO_dgram_set_peer(bio, server_addr)))
        goto err;

    if (!TEST_ptr(*client = SSL_new(ctx)))
        goto err;

    SSL_set_bio(*client, bio, bio);
    bio = NULL;

    ret = 1;

err:
    BIO_free(bio);
    if (ret == 0) {
        SSL_free(*client);
        if (*fd >= 0)
            BIO_closesocket(*fd);
        *client = NULL;
        *fd = -1;
    }
    return ret;
}

/*
 * Helper: drive handshake between client and listener, return accepted connection.
 */
static int do_handshake(SSL *client, SSL *listener, SSL **server_conn)
{
    SSL_POLL_ITEM poll_item;
    struct timeval poll_timeout;
    size_t poll_result;
    int retc, err_code;
    int abortctr = 0;

    *server_conn = NULL;

    SSL_set_connect_state(client);

    while (*server_conn == NULL) {
        if (!TEST_int_le(++abortctr, 100))
            return 0;

        retc = SSL_connect(client);
        err_code = SSL_get_error(client, retc);
        if (retc <= 0
            && err_code != SSL_ERROR_WANT_READ
            && err_code != SSL_ERROR_WANT_WRITE)
            return 0;

        poll_item.desc.type = BIO_POLL_DESCRIPTOR_TYPE_SSL;
        poll_item.desc.value.ssl = listener;
        poll_item.events = SSL_POLL_EVENT_IC;
        poll_item.revents = 0;
        poll_timeout.tv_sec = 0;
        poll_timeout.tv_usec = 100000;

        if (!TEST_true(SSL_poll(&poll_item, 1, sizeof(poll_item),
                &poll_timeout, 0, &poll_result)))
            return 0;

        if (poll_result > 0 && (poll_item.revents & SSL_POLL_EVENT_IC) != 0)
            *server_conn = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    }

    if (!TEST_ptr(*server_conn))
        return 0;

    if (!TEST_true(create_ssl_connection(*server_conn, client, SSL_ERROR_NONE)))
        return 0;

    return 1;
}

/*
 * Main test: multiple threads polling on different DTLS connections
 */
static int test_dtls_multithread(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *listener = NULL;
    SSL *clients[NUM_CLIENTS] = { NULL };
    SSL *server_conns[NUM_CLIENTS] = { NULL };
    int client_fds[NUM_CLIENTS] = { -1, -1, -1 };
    struct server_thread_args server_args[NUM_CLIENTS];
    struct client_thread_args client_args[NUM_CLIENTS];
    BIO_ADDR *server_addr = NULL;
    int server_fd = -1;
    int testresult = 0;
    int i;

    memset(server_args, 0, sizeof(server_args));
    memset(client_args, 0, sizeof(client_args));

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            0, 0,
            &sctx, &cctx, cert, privkey)))
        goto err;

    if (!TEST_true(create_listener(sctx, &listener, &server_addr, &server_fd)))
        goto err;

    for (i = 0; i < NUM_CLIENTS; i++) {
        if (!TEST_true(create_client(cctx, server_addr, &clients[i], &client_fds[i])))
            goto err;

        if (!TEST_true(do_handshake(clients[i], listener, &server_conns[i])))
            goto err;
    }

    /* Start server threads - each will poll and wait for data */
    for (i = 0; i < NUM_CLIENTS; i++) {
        server_args[i].conn = server_conns[i];
        server_args[i].thread_idx = i;
        server_args[i].result = 0;

        server_args[i].thread = ossl_crypto_thread_native_start(
            server_conn_thread, &server_args[i], 1);
        if (!TEST_ptr(server_args[i].thread))
            goto err;
    }

    /* Start client threads - each will send data and wait for response */
    for (i = 0; i < NUM_CLIENTS; i++) {
        client_args[i].conn = clients[i];
        client_args[i].thread_idx = i;
        client_args[i].result = 0;

        client_args[i].thread = ossl_crypto_thread_native_start(
            client_conn_thread, &client_args[i], 1);
        if (!TEST_ptr(client_args[i].thread))
            goto err;
    }

    /* Wait for all server threads to complete */
    for (i = 0; i < NUM_CLIENTS; i++) {
        ossl_crypto_thread_native_join(server_args[i].thread, NULL);
        ossl_crypto_thread_native_clean(server_args[i].thread);
        server_args[i].thread = NULL;

        if (!TEST_int_eq(server_args[i].result, 1))
            goto err;
    }

    /* Wait for all client threads to complete */
    for (i = 0; i < NUM_CLIENTS; i++) {
        ossl_crypto_thread_native_join(client_args[i].thread, NULL);
        ossl_crypto_thread_native_clean(client_args[i].thread);
        client_args[i].thread = NULL;

        if (!TEST_int_eq(client_args[i].result, 1))
            goto err;
    }

    testresult = 1;

err:
    /* Clean up any remaining server threads */
    for (i = 0; i < NUM_CLIENTS; i++) {
        if (server_args[i].thread != NULL) {
            ossl_crypto_thread_native_join(server_args[i].thread, NULL);
            ossl_crypto_thread_native_clean(server_args[i].thread);
        }
    }

    /* Clean up any remaining client threads */
    for (i = 0; i < NUM_CLIENTS; i++) {
        if (client_args[i].thread != NULL) {
            ossl_crypto_thread_native_join(client_args[i].thread, NULL);
            ossl_crypto_thread_native_clean(client_args[i].thread);
        }
    }

    for (i = 0; i < NUM_CLIENTS; i++) {
        SSL_free(clients[i]);
        SSL_free(server_conns[i]);
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

int setup_tests(void)
{
    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

    ADD_TEST(test_dtls_multithread);
    return 1;
}
