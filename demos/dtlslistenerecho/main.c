/*
 *  Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "internal/thread_arch.h"

#if !defined(OPENSSL_SYS_WINDOWS)
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>

#define SOCKET int
#define INVALID_SOCKET (-1)
#define closesocket(s) close(s)

#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <conio.h>
#include <io.h>
#endif

static const int server_port = 4433;

#define MAX_CONNECTIONS 10
#define POLL_TIMEOUT_SEC 5

/*
 * Per-thread state for connection handlers
 */
struct connection_thread_args {
    SSL *conn;
    int thread_idx;
    CRYPTO_THREAD *thread;
    int result;
    int shutdown_requested;
    int finished;
    int *server_shutdown;
};

typedef unsigned char flag;
#define true 1
#define false 0

static SSL_CTX *create_context(flag isServer)
{
    SSL_CTX *ctx;

    if (isServer) {
        ctx = SSL_CTX_new(DTLS_server_method());
    } else {
        ctx = SSL_CTX_new(DTLS_client_method());
    }

    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

static int create_dtls_listener(SSL_CTX *ssl_ctx, int port,
    SSL **listener, SOCKET *server_fd)
{
    BIO *listener_bio = NULL;
    BIO_ADDR *server_addr = NULL;
    struct in_addr ina;
    union BIO_sock_info_u info;
    int ret = 0;

    *listener = NULL;
    *server_fd = INVALID_SOCKET;

    /* Create and bind server UDP socket */
    *server_fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (*server_fd == INVALID_SOCKET) {
        perror("Unable to create UDP socket");
        goto err;
    }

    /* Set socket to non-blocking mode */
    if (!BIO_socket_nbio(*server_fd, 1)) {
        perror("Unable to set socket to non-blocking");
        goto err;
    }

    /* Create address for binding - use INADDR_ANY to listen on all interfaces */
    server_addr = BIO_ADDR_new();
    if (server_addr == NULL) {
        perror("Unable to allocate BIO_ADDR");
        goto err;
    }

    ina.s_addr = htonl(INADDR_ANY);
    if (!BIO_ADDR_rawmake(server_addr, AF_INET, &ina, sizeof(ina), htons(port))) {
        perror("Unable to create server address");
        goto err;
    }

    /* Bind the socket to the address */
    if (!BIO_bind(*server_fd, server_addr, 0)) {
        perror("Unable to bind socket");
        goto err;
    }

    /* Get the actual bound address (useful if port was 0 for ephemeral) */
    info.addr = server_addr;
    if (!BIO_sock_info(*server_fd, BIO_SOCK_INFO_ADDRESS, &info)) {
        perror("Unable to get socket info");
        goto err;
    }

    printf("Server bound to port %d\n", ntohs(BIO_ADDR_rawport(server_addr)));

    /* Create a datagram BIO and attach the socket */
    listener_bio = BIO_new_dgram(*server_fd, BIO_NOCLOSE);
    if (listener_bio == NULL) {
        perror("Unable to create datagram BIO");
        goto err;
    }

    /* Create the DTLS listener with HVR (DTLS 1.2) and HRR (DTLS 1.3) cookie validation */
    *listener = SSL_new_listener(ssl_ctx, SSL_LISTENER_FLAG_REQUIRE_HVR | SSL_LISTENER_FLAG_REQUIRE_HRR);
    if (*listener == NULL) {
        perror("Unable to create DTLS listener");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    /* Attach the BIO to the listener - ownership of listener_bio is transferred */
    SSL_set_bio(*listener, listener_bio, listener_bio);
    listener_bio = NULL; /* Ownership transferred to listener */

    /* Start listening for incoming connections */
    if (SSL_listen(*listener) != 1) {
        perror("SSL_listen failed");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    ret = 1;

err:
    BIO_free(listener_bio);
    BIO_ADDR_free(server_addr);
    if (ret == 0) {
        SSL_free(*listener);
        *listener = NULL;
        if (*server_fd != INVALID_SOCKET)
            BIO_closesocket(*server_fd);
        *server_fd = INVALID_SOCKET;
    }
    return ret;
}

/*
 * Thread function: handles a single DTLS connection.
 * Completes the handshake, then reads data and echoes it back.
 * Returns 1 if "killall" command was received, 0 otherwise.
 */
static unsigned int server_connection_thread(void *arg)
{
    struct connection_thread_args *conn_args = arg;
    SSL_POLL_ITEM item;
    struct timeval timeout;
    size_t result_count, readbytes, written;
    char buf[1500];
    int ret, err;

    conn_args->result = 0;
    conn_args->finished = 0;

    printf("Thread %d: Starting connection handler\n", conn_args->thread_idx);

    /* Complete the handshake */
    while ((ret = SSL_accept(conn_args->conn)) != 1) {
        if (conn_args->shutdown_requested) {
            printf("Thread %d: Shutdown requested during handshake\n", conn_args->thread_idx);
            goto done;
        }
        err = SSL_get_error(conn_args->conn, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            printf("Thread %d: Handshake failed\n", conn_args->thread_idx);
            ERR_print_errors_fp(stderr);
            goto done;
        }
    }

    printf("Thread %d: Handshake completed\n", conn_args->thread_idx);

    /* Setup poll item for reading */
    item.desc = SSL_as_poll_descriptor(conn_args->conn);
    item.events = SSL_POLL_EVENT_R;

    /* Main read/echo loop */
    while (!conn_args->shutdown_requested) {
        item.revents = 0;
        timeout.tv_sec = POLL_TIMEOUT_SEC;
        timeout.tv_usec = 0;

        if (!SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count)) {
            printf("Thread %d: SSL_poll failed\n", conn_args->thread_idx);
            ERR_print_errors_fp(stderr);
            break;
        }

        /* Check shutdown after poll returns */
        if (conn_args->shutdown_requested) {
            printf("Thread %d: Shutdown requested\n", conn_args->thread_idx);
            break;
        }

        /* Timeout - no data, loop again */
        if (result_count == 0 || (item.revents & SSL_POLL_EVENT_R) == 0)
            continue;

        ret = SSL_read_ex(conn_args->conn, buf, sizeof(buf) - 1, &readbytes);
        if (ret != 1) {
            err = SSL_get_error(conn_args->conn, ret);
            if (err == SSL_ERROR_WANT_READ)
                continue;
            if (err == SSL_ERROR_ZERO_RETURN)
                printf("Thread %d: Client closed connection\n", conn_args->thread_idx);
            else
                printf("Thread %d: Read error\n", conn_args->thread_idx);
            break;
        }

        buf[readbytes] = '\0';

        /* Check for kill command - exits this thread only */
        if (strcmp(buf, "kill\n") == 0) {
            printf("Thread %d: Kill command received, disconnecting\n", conn_args->thread_idx);
            break;
        }

        /* Check for killall command - signals server-wide shutdown */
        if (strcmp(buf, "killall\n") == 0) {
            printf("Thread %d: Killall command received, initiating server shutdown\n", conn_args->thread_idx);
            if (conn_args->server_shutdown != NULL)
                *conn_args->server_shutdown = 1;
            break;
        }

        printf("Thread %d: Received: %s", conn_args->thread_idx, buf);

        /* Echo back */
        if (!SSL_write_ex(conn_args->conn, buf, readbytes, &written)) {
            printf("Thread %d: Write failed\n", conn_args->thread_idx);
            ERR_print_errors_fp(stderr);
            break;
        }
    }

    conn_args->result = 1;

done:
    /* Send graceful shutdown to client */
    printf("Thread %d: Sending shutdown to client\n", conn_args->thread_idx);
    SSL_shutdown(conn_args->conn);

    printf("Thread %d: Exiting\n", conn_args->thread_idx);
    conn_args->finished = 1;
    return 0;
}

/*
 * Find a free slot in the thread array.
 * Returns the index of a free slot, or -1 if all slots are in use.
 */
static int find_free_thread_slot(struct connection_thread_args *threads)
{
    int i;

    for (i = 0; i < MAX_CONNECTIONS; i++) {
        if (threads[i].thread == NULL)
            return i;
    }
    return -1;
}

/*
 * Clean up finished threads.
 * Called from main thread after each poll to reclaim resources from
 * threads that have set their finished flag.
 */
static void cleanup_finished_threads(struct connection_thread_args *threads)
{
    int i;

    for (i = 0; i < MAX_CONNECTIONS; i++) {
        if (threads[i].thread != NULL && threads[i].finished) {
            ossl_crypto_thread_native_join(threads[i].thread, NULL);
            ossl_crypto_thread_native_clean(threads[i].thread);
            SSL_free(threads[i].conn);
            threads[i].thread = NULL;
            threads[i].conn = NULL;
            threads[i].finished = 0;
            printf("Main: Cleaned up thread %d\n", i);
        }
    }
}

/*
 * Signal all threads to shut down and wait for them to finish.
 * Called when the server is exiting.
 */
static void shutdown_all_threads(struct connection_thread_args *threads)
{
    int i;

    /* Signal all threads to terminate */
    for (i = 0; i < MAX_CONNECTIONS; i++) {
        if (threads[i].thread != NULL)
            threads[i].shutdown_requested = 1;
    }

    /* Join and clean up all threads */
    for (i = 0; i < MAX_CONNECTIONS; i++) {
        if (threads[i].thread != NULL) {
            ossl_crypto_thread_native_join(threads[i].thread, NULL);
            ossl_crypto_thread_native_clean(threads[i].thread);
            SSL_free(threads[i].conn);
            threads[i].thread = NULL;
            threads[i].conn = NULL;
            printf("Main: Shut down thread %d\n", i);
        }
    }
}

static void run_server(void)
{
    SSL_CTX *ssl_ctx = NULL;
    SSL *listener = NULL;
    SSL *new_conn = NULL;
    SOCKET server_fd = INVALID_SOCKET;
    int server_shutdown = 0;
    struct connection_thread_args conn_threads[MAX_CONNECTIONS];
    SSL_POLL_ITEM listener_item;
    struct timeval timeout;
    size_t result_count;
    int slot;

    /* Initialize thread array */
    memset(conn_threads, 0, sizeof(conn_threads));

    ssl_ctx = create_context(true);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, "cert.pem") <= 0) {
        ERR_print_errors_fp(stderr);
        goto err;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        goto err;
    }

    /* Create the DTLS listener with socket and BIO */
    if (!create_dtls_listener(ssl_ctx, server_port, &listener, &server_fd)) {
        goto err;
    }

    printf("DTLS listener started on port %d (max %d connections)\n",
        server_port, MAX_CONNECTIONS);

    /* Setup poll item for listener */
    listener_item.desc = SSL_as_poll_descriptor(listener);
    listener_item.events = SSL_POLL_EVENT_IC;

    while (!server_shutdown) {
        /* Clean up any finished threads first */
        cleanup_finished_threads(conn_threads);

        /* Poll listener for incoming connections */
        listener_item.revents = 0;
        timeout.tv_sec = POLL_TIMEOUT_SEC;
        timeout.tv_usec = 0;

        if (!SSL_poll(&listener_item, 1, sizeof(listener_item),
                &timeout, 0, &result_count)) {
            ERR_print_errors_fp(stderr);
            break;
        }

        /* Check if shutdown was requested by a connection thread */
        if (server_shutdown) {
            printf("Main: Server shutdown requested\n");
            break;
        }

        /* Timeout - no incoming connection, loop again */
        if (result_count == 0 || (listener_item.revents & SSL_POLL_EVENT_IC) == 0)
            continue;

        /* Accept new connection */
        new_conn = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
        if (new_conn == NULL) {
            fprintf(stderr, "SSL_accept_connection failed\n");
            ERR_print_errors_fp(stderr);
            continue;
        }

        /* Find free slot */
        slot = find_free_thread_slot(conn_threads);
        if (slot < 0) {
            fprintf(stderr, "Connection limit reached (%d), dropping new connection\n",
                MAX_CONNECTIONS);
            SSL_free(new_conn);
            continue;
        }

        /* Initialize thread args and spawn thread */
        conn_threads[slot].conn = new_conn;
        conn_threads[slot].thread_idx = slot;
        conn_threads[slot].result = 0;
        conn_threads[slot].shutdown_requested = 0;
        conn_threads[slot].finished = 0;
        conn_threads[slot].server_shutdown = &server_shutdown;

        conn_threads[slot].thread = ossl_crypto_thread_native_start(
            server_connection_thread, &conn_threads[slot], 1);

        if (conn_threads[slot].thread == NULL) {
            fprintf(stderr, "Failed to start thread for slot %d\n", slot);
            SSL_free(new_conn);
            conn_threads[slot].conn = NULL;
            continue;
        }

        printf("Main: Spawned thread %d for new connection\n", slot);
    }

    printf("Server exiting...\n");

err:
    /* Signal all threads to shut down and clean up */
    shutdown_all_threads(conn_threads);

    SSL_free(listener);
    SSL_CTX_free(ssl_ctx);
    if (server_fd >= 0)
        BIO_closesocket(server_fd);
}

/*
 * Create a DTLS client connection to the server.
 */
static int create_dtls_client(SSL_CTX *ssl_ctx, const char *server_name, int port,
    SSL **client, SOCKET *client_fd)
{
    BIO *client_bio = NULL;
    BIO_ADDR *server_addr = NULL;
    BIO_ADDRINFO *res = NULL;
    char port_str[6];
    int ret = 0;

    *client = NULL;
    *client_fd = INVALID_SOCKET;

    /* Create UDP socket */
    *client_fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (*client_fd == INVALID_SOCKET) {
        perror("Unable to create UDP socket");
        goto err;
    }

    /* Set socket to non-blocking mode */
    if (!BIO_socket_nbio(*client_fd, 1)) {
        perror("Unable to set socket to non-blocking");
        goto err;
    }

    /* Resolve server hostname or IP address */
    BIO_snprintf(port_str, sizeof(port_str), "%d", port);
    if (!BIO_lookup(server_name, port_str, BIO_LOOKUP_CLIENT, AF_INET, SOCK_DGRAM, &res)) {
        fprintf(stderr, "Unable to resolve server: %s\n", server_name);
        goto err;
    }
    server_addr = BIO_ADDR_dup(BIO_ADDRINFO_address(res));
    BIO_ADDRINFO_free(res);
    if (server_addr == NULL) {
        perror("Unable to allocate BIO_ADDR");
        goto err;
    }

    /* Create a datagram BIO and attach the socket */
    client_bio = BIO_new_dgram(*client_fd, BIO_NOCLOSE);
    if (client_bio == NULL) {
        perror("Unable to create datagram BIO");
        goto err;
    }

    /* Set the peer address */
    if (!BIO_dgram_set_peer(client_bio, server_addr)) {
        perror("Unable to set peer address");
        goto err;
    }

    /* Create the SSL client */
    *client = SSL_new(ssl_ctx);
    if (*client == NULL) {
        perror("Unable to create SSL client");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    /* Attach the BIO to the SSL - ownership is transferred */
    SSL_set_bio(*client, client_bio, client_bio);
    client_bio = NULL;

    if (!SSL_set1_dnsname(*client, server_name)) {
        ERR_print_errors_fp(stderr);
        goto err;
    }

    ret = 1;

err:
    BIO_free(client_bio);
    BIO_ADDR_free(server_addr);
    if (ret == 0) {
        SSL_free(*client);
        *client = NULL;
        if (*client_fd != INVALID_SOCKET)
            BIO_closesocket(*client_fd);
        *client_fd = INVALID_SOCKET;
    }
    return ret;
}

/*
 * Perform the DTLS handshake with the server.
 * Uses SSL_poll to wait for the connection to be ready.
 */
static int do_client_handshake(SSL *client)
{
    SSL_POLL_ITEM item;
    struct timeval timeout;
    size_t result_count;
    int ret, err;

    SSL_set_connect_state(client);

    while ((ret = SSL_connect(client)) != 1) {
        err = SSL_get_error(client, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            fprintf(stderr, "Handshake failed with err=%d\n", err);
            ERR_print_errors_fp(stderr);
            return 0;
        }

        /* Poll for the socket to be ready */
        item.desc = SSL_as_poll_descriptor(client);
        item.events = (err == SSL_ERROR_WANT_READ) ? SSL_POLL_EVENT_R : SSL_POLL_EVENT_W;
        item.revents = 0;

        timeout.tv_sec = POLL_TIMEOUT_SEC;
        timeout.tv_usec = 0;

        if (!SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count)) {
            fprintf(stderr, "SSL_poll failed during handshake\n");
            ERR_print_errors_fp(stderr);
            return 0;
        }

        if (result_count == 0) {
            fprintf(stderr, "Handshake timed out\n");
            return 0;
        }
    }

    return 1;
}

static void run_client(char *rem_server_name, int dtls_version)
{
    SSL_CTX *ssl_ctx = NULL;
    SSL *client = NULL;
    SOCKET client_fd = INVALID_SOCKET;
    char input_buf[1500];
    char recv_buf[1500];
    size_t written, readbytes;
    int ret, err;
#if !defined(OPENSSL_SYS_WINDOWS)
    struct pollfd pfds[2];
    BIO *rbio;
    BIO_POLL_DESCRIPTOR rdesc;
#else
    fd_set read_fds;
#endif
    SSL_POLL_ITEM item;
    struct timeval timeout;
    size_t result_count;

    ssl_ctx = create_context(false);

    /* Apply DTLS version constraint if specified */
    if (dtls_version != 0) {
        SSL_CTX_set_min_proto_version(ssl_ctx, dtls_version);
        SSL_CTX_set_max_proto_version(ssl_ctx, dtls_version);
        printf("Forcing %s\n",
            dtls_version == DTLS1_2_VERSION ? "DTLS 1.2" : "DTLS 1.3");
    }

    /* Create DTLS client connection */
    if (!create_dtls_client(ssl_ctx, rem_server_name, server_port, &client, &client_fd)) {
        goto err;
    }

    printf("Connecting to %s:%d...\n", rem_server_name, server_port);

    /* Perform handshake */
    if (!do_client_handshake(client)) {
        goto err;
    }

    printf("Connected! Type messages to send (or 'kill' to disconnect, 'killall' to shutdown server):\n");

#if !defined(OPENSSL_SYS_WINDOWS)
    int ssl_fd;

    /* Get the SSL socket fd for polling */
    rbio = SSL_get_rbio(client);
    if (rbio == NULL || !BIO_get_rpoll_descriptor(rbio, &rdesc)
        || rdesc.type != BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD) {
        fprintf(stderr, "Failed to get SSL socket fd\n");
        goto err;
    }
    ssl_fd = rdesc.value.fd;

    /* Setup poll fds: [0] = stdin, [1] = SSL socket */
    pfds[0].fd = STDIN_FILENO;
    pfds[0].events = POLLIN;
    pfds[1].fd = ssl_fd;
    pfds[1].events = POLLIN;

    /* Main loop: poll on both stdin and SSL connection */
    while (1) {
        pfds[0].revents = 0;
        pfds[1].revents = 0;

        ret = poll(pfds, 2, POLL_TIMEOUT_SEC * 1000);
        if (ret < 0) {
            perror("poll failed");
            break;
        }

        /* Check for server data/shutdown first */
        if (pfds[1].revents & POLLIN) {
            ret = SSL_read_ex(client, recv_buf, sizeof(recv_buf) - 1, &readbytes);
            if (ret != 1) {
                err = SSL_get_error(client, ret);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    printf("Server closed connection\n");
                    break;
                } else if (err == SSL_ERROR_WANT_READ) {
                    /* No actual data ready, continue polling */
                    continue;
                } else {
                    fprintf(stderr, "Read error from server\n");
                    ERR_print_errors_fp(stderr);
                    break;
                }
            }
            recv_buf[readbytes] = '\0';
            printf("Server: %s", recv_buf);
        }

        /* Check for user input */
        if (pfds[0].revents & POLLIN) {
            if (fgets(input_buf, sizeof(input_buf), stdin) == NULL) {
                printf("EOF received, exiting\n");
                break;
            }

            /* Send to server */
            if (!SSL_write_ex(client, input_buf, strlen(input_buf), &written)) {
                fprintf(stderr, "Failed to send data\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            /* Check if we sent the kill command */
            if (strcmp(input_buf, "kill\n") == 0) {
                printf("Sent kill command, disconnecting\n");
                break;
            }

            /* Check if we sent the killall command */
            if (strcmp(input_buf, "killall\n") == 0) {
                printf("Sent killall command, server will shutdown\n");
                break;
            }

            /* Wait for echo response using SSL_poll */
            item.desc = SSL_as_poll_descriptor(client);
            item.events = SSL_POLL_EVENT_R;
            item.revents = 0;

            timeout.tv_sec = POLL_TIMEOUT_SEC;
            timeout.tv_usec = 0;

            if (!SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count)) {
                fprintf(stderr, "SSL_poll failed waiting for echo\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            if (result_count == 0 || (item.revents & SSL_POLL_EVENT_R) == 0) {
                fprintf(stderr, "Timeout waiting for echo from server\n");
                continue;
            }

            /* Read the echo response */
            ret = SSL_read_ex(client, recv_buf, sizeof(recv_buf) - 1, &readbytes);
            if (ret != 1) {
                err = SSL_get_error(client, ret);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    printf("Server closed connection\n");
                } else if (err != SSL_ERROR_WANT_READ) {
                    fprintf(stderr, "Failed to read echo response\n");
                    ERR_print_errors_fp(stderr);
                }
                break;
            }

            recv_buf[readbytes] = '\0';
            printf("Echo: %s", recv_buf);
        }
    }
#else
    /*
     * Windows version: use select() for socket and _kbhit() for console input.
     * We can't easily poll stdin and a socket together on Windows, so we use
     * a short timeout on select() and check for keyboard input with _kbhit().
     */
    while (1) {
        int has_input = 0;

        /* Check for pending server data using select with short timeout */
        FD_ZERO(&read_fds);
        FD_SET(client_fd, &read_fds);
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; /* 100ms */

        ret = select(0, &read_fds, NULL, NULL, &timeout);
        if (ret < 0) {
            fprintf(stderr, "select failed\n");
            break;
        }

        /* Check for server data */
        if (ret > 0 && FD_ISSET(client_fd, &read_fds)) {
            ret = SSL_read_ex(client, recv_buf, sizeof(recv_buf) - 1, &readbytes);
            if (ret != 1) {
                err = SSL_get_error(client, ret);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    printf("Server closed connection\n");
                    break;
                } else if (err == SSL_ERROR_WANT_READ) {
                    /* No actual data ready, continue */
                } else {
                    fprintf(stderr, "Read error from server\n");
                    ERR_print_errors_fp(stderr);
                    break;
                }
            } else {
                recv_buf[readbytes] = '\0';
                printf("Server: %s", recv_buf);
            }
        }

        /* Check for user input using _kbhit() */
        if (_kbhit()) {
            if (fgets(input_buf, sizeof(input_buf), stdin) == NULL) {
                printf("EOF received, exiting\n");
                break;
            }
            has_input = 1;
        }

        if (has_input) {
            /* Send to server */
            if (!SSL_write_ex(client, input_buf, strlen(input_buf), &written)) {
                fprintf(stderr, "Failed to send data\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            /* Check if we sent the kill command */
            if (strcmp(input_buf, "kill\n") == 0
                || strcmp(input_buf, "kill\r\n") == 0) {
                printf("Sent kill command, disconnecting\n");
                break;
            }

            /* Check if we sent the killall command */
            if (strcmp(input_buf, "killall\n") == 0
                || strcmp(input_buf, "killall\r\n") == 0) {
                printf("Sent killall command, server will shutdown\n");
                break;
            }

            /* Wait for echo response using SSL_poll */
            item.desc = SSL_as_poll_descriptor(client);
            item.events = SSL_POLL_EVENT_R;
            item.revents = 0;

            timeout.tv_sec = POLL_TIMEOUT_SEC;
            timeout.tv_usec = 0;

            if (!SSL_poll(&item, 1, sizeof(item), &timeout, 0, &result_count)) {
                fprintf(stderr, "SSL_poll failed waiting for echo\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            if (result_count == 0 || (item.revents & SSL_POLL_EVENT_R) == 0) {
                fprintf(stderr, "Timeout waiting for echo from server\n");
                continue;
            }

            /* Read the echo response */
            ret = SSL_read_ex(client, recv_buf, sizeof(recv_buf) - 1, &readbytes);
            if (ret != 1) {
                err = SSL_get_error(client, ret);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    printf("Server closed connection\n");
                } else if (err != SSL_ERROR_WANT_READ) {
                    fprintf(stderr, "Failed to read echo response\n");
                    ERR_print_errors_fp(stderr);
                }
                break;
            }

            recv_buf[readbytes] = '\0';
            printf("Echo: %s", recv_buf);
        }
    }
#endif

err:
    SSL_free(client);
    SSL_CTX_free(ssl_ctx);
    if (client_fd != INVALID_SOCKET)
        BIO_closesocket(client_fd);
}

static void usage(void)
{
    printf("Usage: dtlslistenerecho s\n");
    printf("       --or--\n");
    printf("       dtlslistenerecho c hostname [dtls12|dtls13]\n");
    printf("       c=client, s=server, hostname=hostname of server\n");
    printf("       dtls12=force DTLS 1.2, dtls13=force DTLS 1.3 (optional)\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    flag isServer;
    char *rem_server_name = NULL;
    int dtls_version = 0;

    /* Need to know if client or server */
    if (argc < 2) {
        usage();
        /* NOTREACHED */
    }

    isServer = (argv[1][0] == 's') ? true : false;

    /* If client get remote server address */
    if (!isServer) {
        if (argc < 3) {
            usage();
            /* NOTREACHED */
        }
        rem_server_name = argv[2];

        /* Check for optional DTLS version argument */
        if (argc >= 4) {
            if (strcmp(argv[3], "dtls12") == 0) {
                dtls_version = DTLS1_2_VERSION;
            } else if (strcmp(argv[3], "dtls13") == 0) {
                dtls_version = DTLS1_3_VERSION;
            } else {
                fprintf(stderr, "Unknown protocol version: %s\n", argv[3]);
                usage();
                /* NOTREACHED */
            }
        }
    }

    if (isServer) {
        run_server();
    } else {
        run_client(rem_server_name, dtls_version);
    }

    return EXIT_SUCCESS;
}
