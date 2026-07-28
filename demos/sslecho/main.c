/*
 *  Copyright 2022-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#if !defined(OPENSSL_SYS_WINDOWS)
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define SOCKET int
#define INVALID_SOCKET -1
#define closesocket(s) close(s)

#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

static const int server_port = 4433;

typedef unsigned char flag;
#define true 1
#define false 0

/*
 * This flag won't be useful until both accept/read (TCP & SSL) methods
 * can be called with a timeout. TBD.
 */
static volatile flag server_running = true;

static SOCKET create_socket(flag isServer)
{
    SOCKET s = INVALID_SOCKET;
    BIO_ADDRINFO *res = NULL;
    const BIO_ADDR *addr;
    char port_str[6];

    /*
     * Resolve the wildcard address for our port. Requesting AF_INET6
     * gives a single socket and BIO_listen will allow that both IPv6
     * and IPv4 (v4-mapped) clients.
     */
    BIO_snprintf(port_str, sizeof(port_str), "%d", server_port);
    if (!BIO_lookup_ex(NULL, port_str, BIO_LOOKUP_SERVER, AF_INET6,
            SOCK_STREAM, 0, &res)) {
        fprintf(stderr, "Unable to resolve local address\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    addr = BIO_ADDRINFO_address(res);

    s = BIO_socket(BIO_ADDRINFO_family(res), SOCK_STREAM, 0, 0);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "Unable to create socket\n");
        ERR_print_errors_fp(stderr);
        BIO_ADDRINFO_free(res);
        exit(EXIT_FAILURE);
    }

    if (isServer) {
        /*
         * BIO_listen sets SO_REUSEADDR (BIO_SOCK_REUSEADDR) and, because we do
         * NOT pass BIO_SOCK_V6_ONLY, clears IPV6_V6ONLY to give us a dual-stack
         * listener, portably handling the platform default differences.
         */
        if (!BIO_listen((int)s, addr, BIO_SOCK_REUSEADDR)) {
            fprintf(stderr, "Unable to bind/listen\n");
            ERR_print_errors_fp(stderr);
            BIO_closesocket((int)s);
            BIO_ADDRINFO_free(res);
            exit(EXIT_FAILURE);
        }
    }

    BIO_ADDRINFO_free(res);
    return s;
}

static SSL_CTX *create_context(flag isServer)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    if (isServer)
        method = TLS_server_method();
    else
        method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

static void configure_server_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ctx, "cert.pem") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

static void configure_client_context(SSL_CTX *ctx)
{
    /*
     * Configure the client to abort the handshake if certificate verification
     * fails
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    /*
     * In a real application you would probably just use the default system certificate trust store and call:
     *     SSL_CTX_set_default_verify_paths(ctx);
     * In this demo though we are using a self-signed certificate, so the client must trust it directly.
     */
    if (!SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

static void usage(void)
{
    printf("Usage: sslecho s\n");
    printf("       --or--\n");
    printf("       sslecho c server\n");
    printf("       c=client, s=server, server=hostname of server\n");
    exit(EXIT_FAILURE);
}

#define BUFFERSIZE 1024
int main(int argc, char **argv)
{
    flag isServer;
    int result;

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    SOCKET server_skt = INVALID_SOCKET;
    SOCKET client_skt = INVALID_SOCKET;

    /* used by fgets */
    char buffer[BUFFERSIZE];
    char *txbuf;

    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    char *rem_server_name = NULL;

    struct sockaddr_storage addr;
#if defined(OPENSSL_SYS_CYGWIN) || defined(OPENSSL_SYS_WINDOWS)
    int addr_len = sizeof(addr);
#else
    unsigned int addr_len = sizeof(addr);
#endif

#if !defined(OPENSSL_SYS_WINDOWS)
    /* ignore SIGPIPE so that server can continue running when client pipe closes abruptly */
    signal(SIGPIPE, SIG_IGN);
#endif

    /* Splash */
    printf("\nsslecho : Simple Echo Client/Server : %s : %s\n\n", __DATE__,
        __TIME__);

    /* Need to know if client or server */
    if (argc < 2) {
        usage();
        /* NOTREACHED */
    }
    isServer = (argv[1][0] == 's') ? true : false;
    /* If client get remote server address (could be 127.0.0.1) */
    if (!isServer) {
        if (argc != 3) {
            usage();
            /* NOTREACHED */
        }
        rem_server_name = argv[2];
    }

    /* Create context used by both client and server */
    ssl_ctx = create_context(isServer);

    /* If server */
    if (isServer) {

        printf("We are the server on port: %d\n\n", server_port);

        /* Configure server context with appropriate key files */
        configure_server_context(ssl_ctx);

        /* Create server socket; will bind with server port and listen */
        server_skt = create_socket(true);

        /*
         * Loop to accept clients.
         * Need to implement timeouts on TCP & SSL connect/read functions
         * before we can catch a CTRL-C and kill the server.
         */
        while (server_running) {
            /* Wait for TCP connection from client */
            client_skt = accept(server_skt, (struct sockaddr *)&addr,
                &addr_len);
            if (client_skt == INVALID_SOCKET) {
                perror("Unable to accept");
                exit(EXIT_FAILURE);
            }

            printf("Client TCP connection accepted\n");

            /* Create server SSL structure using newly accepted client socket */
            ssl = SSL_new(ssl_ctx);
            if (!SSL_set_fd(ssl, (int)client_skt)) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }

            /* Wait for SSL connection from the client */
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                server_running = false;
            } else {

                printf("Client SSL connection accepted\n\n");

                /* Echo loop */
                while (true) {
                    /* Get message from client; will fail if client closes connection */
                    if ((rxlen = SSL_read(ssl, rxbuf, (int)rxcap)) <= 0) {
                        if (rxlen == 0) {
                            printf("Client closed connection\n");
                        } else {
                            printf("SSL_read returned %d\n", rxlen);
                        }
                        ERR_print_errors_fp(stderr);
                        break;
                    }
                    /* Insure null terminated input */
                    rxbuf[rxlen] = 0;
                    /* Look for kill switch */
                    if (strcmp(rxbuf, "kill\n") == 0) {
                        /* Terminate...with extreme prejudice */
                        printf("Server received 'kill' command\n");
                        server_running = false;
                        break;
                    }
                    /* Show received message */
                    printf("Received: %s", rxbuf);
                    /* Echo it back */
                    if (SSL_write(ssl, rxbuf, rxlen) <= 0) {
                        ERR_print_errors_fp(stderr);
                    }
                }
            }
            if (server_running) {
                /* Cleanup for next client */
                SSL_shutdown(ssl);
                SSL_free(ssl);
                closesocket(client_skt);
                /*
                 * Set client_skt to INVALID_SOCKET to avoid double close when
                 * server_running become false before next accept
                 */
                client_skt = INVALID_SOCKET;
            }
        }
        printf("Server exiting...\n");
    }
    /* Else client */
    else {
        BIO_ADDRINFO *res = NULL;
        const BIO_ADDRINFO *ai = NULL;
        char port_str[6];

        printf("We are the client\n\n");

        /* Configure client context so we verify the server correctly */
        configure_client_context(ssl_ctx);

        /* Resolve server hostname or IP address (IPv4 or IPv6) */
        BIO_snprintf(port_str, sizeof(port_str), "%d", server_port);
        if (!BIO_lookup(rem_server_name, port_str, BIO_LOOKUP_CLIENT,
                AF_UNSPEC, SOCK_STREAM, &res)) {
            fprintf(stderr, "Unable to resolve server: %s\n", rem_server_name);
            ERR_print_errors_fp(stderr);
            goto exit;
        }

        /*
         * Iterate over the resolved addresses and connect to the first one
         * that works.
         */
        for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
            client_skt = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_STREAM, 0, 0);
            if (client_skt == INVALID_SOCKET)
                continue;
            if (BIO_connect((int)client_skt, BIO_ADDRINFO_address(ai),
                    BIO_SOCK_NODELAY))
                break;
            BIO_closesocket((int)client_skt);
            client_skt = INVALID_SOCKET;
        }
        BIO_ADDRINFO_free(res);

        if (client_skt == INVALID_SOCKET) {
            fprintf(stderr, "Unable to TCP connect to server: %s\n",
                rem_server_name);
            ERR_print_errors_fp(stderr);
            goto exit;
        }
        printf("TCP connection to server successful\n");

        /* Create client SSL structure using dedicated client socket */
        ssl = SSL_new(ssl_ctx);
        if (!SSL_set_fd(ssl, (int)client_skt)) {
            ERR_print_errors_fp(stderr);
            goto exit;
        }
        /* Set hostname for SNI */
        SSL_set_tlsext_host_name(ssl, rem_server_name);
        /* Configure server hostname check */
        if (!SSL_set1_dnsname(ssl, rem_server_name)) {
            ERR_print_errors_fp(stderr);
            goto exit;
        }

        /* Now do SSL connect with server */
        if (SSL_connect(ssl) == 1) {

            printf("SSL connection to server successful\n\n");

            /* Loop to send input from keyboard */
            while (true) {
                /* Get a line of input */
                memset(buffer, 0, BUFFERSIZE);
                txbuf = fgets(buffer, BUFFERSIZE, stdin);

                /* Exit loop on error */
                if (txbuf == NULL) {
                    break;
                }
                /* Exit loop if just a carriage return */
                if (txbuf[0] == '\n') {
                    break;
                }
                /* Send it to the server */
                if ((result = SSL_write(ssl, txbuf, (int)strlen(txbuf))) <= 0) {
                    printf("Server closed connection\n");
                    ERR_print_errors_fp(stderr);
                    break;
                }

                /* Wait for the echo */
                rxlen = SSL_read(ssl, rxbuf, (int)rxcap);
                if (rxlen <= 0) {
                    printf("Server closed connection\n");
                    ERR_print_errors_fp(stderr);
                    break;
                } else {
                    /* Show it */
                    rxbuf[rxlen] = 0;
                    printf("Received: %s", rxbuf);
                }
            }
            printf("Client exiting...\n");
        } else {

            printf("SSL connection to server failed\n\n");

            ERR_print_errors_fp(stderr);
        }
    }
exit:
    /* Close up */
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);

    if (client_skt != INVALID_SOCKET)
        closesocket(client_skt);
    if (server_skt != INVALID_SOCKET)
        closesocket(server_skt);

    printf("sslecho exiting\n");

    return EXIT_SUCCESS;
}
