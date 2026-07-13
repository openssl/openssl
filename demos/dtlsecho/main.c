/*
 *  Copyright 2022-2025 The OpenSSL Project Authors. All Rights Reserved.
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
#include <openssl/bio.h>
#include <openssl/dtls1.h>
#if !defined(OPENSSL_SYS_WINDOWS)
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define SOCKET int
#define INVALID_SOCKET -1
#define closesocket(s) close(s)

#else
#include <winsock.h>
#include <ws2tcpip.h>
#endif

static const int server_port = 4433;

typedef unsigned char flag;
#define true 1
#define false 0

/*
 * This flag won't be useful until both accept/read (UDP & DTLS) methods
 * can be called with a timeout. TBD.
 */
static volatile flag server_running = true;

static SOCKET create_socket(flag isServer)
{
    SOCKET s;
    int optval = 1;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (isServer) {
        addr.sin_family = AF_INET;
        addr.sin_port = htons(server_port);
        addr.sin_addr.s_addr = INADDR_ANY;

        /* Reuse the address; good for quick restarts */
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&optval,
                sizeof(optval))
            < 0) {
            perror("setsockopt(SO_REUSEADDR) failed");
            exit(EXIT_FAILURE);
        }

        if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("Unable to bind");
            exit(EXIT_FAILURE);
        }
    }

    return s;
}

static SSL_CTX *create_context(flag isServer)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    if (isServer)
        method = DTLS_server_method();
    else
        method = DTLS_client_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Restrict to DTLSv1.3 only */
    if (!SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
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
     * In a real application you would probably just use the default system
     * certificate trust store and call:
     *     SSL_CTX_set_default_verify_paths(ctx);
     * In this demo though we are using a self-signed certificate, so the
     * client must trust it directly.
     */
    if (!SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

static void usage(void)
{
    printf("Usage: dtlsecho s\n");
    printf("       --or--\n");
    printf("       dtlsecho c hostname\n");
    printf("       c=client, s=server, hostname=hostname of server\n");
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

    struct sockaddr_in addr;
    int received_new_session_ack = 0;

#if !defined(OPENSSL_SYS_WINDOWS)
    /* Ignore SIGPIPE so that server can continue running when client pipe closes abruptly */
    signal(SIGPIPE, SIG_IGN);
#endif

    /* Splash */
    printf("\ndtlsecho : Simple Echo Client/Server : %s : %s\n\n", __DATE__,
        __TIME__);

    /* Need to know if client or server */
    if (argc < 2) {
        usage();
        /* NOTREACHED */
    }
    isServer = (argv[1][0] == 's') ? true : false;
    /* If client get remote server hostname */
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
        BIO *bio = NULL;

        printf("We are the server on port: %d\n\n", server_port);

        /* Configure server context with appropriate key files */
        configure_server_context(ssl_ctx);

        /* Create server socket; will bind to server port */
        server_skt = create_socket(true);
        if (server_skt == INVALID_SOCKET) {
            perror("Unable to create server socket");
            exit(EXIT_FAILURE);
        }

        printf("Waiting for DTLS connection...\n");

        ssl = SSL_new(ssl_ctx);
        if (ssl == NULL) {
            ERR_print_errors_fp(stderr);
            goto exit;
        }

        /* Wrap the bound server socket in a datagram BIO for OpenSSL */
        bio = BIO_new_dgram((int)server_skt, BIO_NOCLOSE);
        if (bio == NULL) {
            ERR_print_errors_fp(stderr);
            goto exit;
        }
        SSL_set_bio(ssl, bio, bio);
        DTLS_set_link_mtu(ssl, 1500);

        /* Complete the DTLS handshake */
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            goto exit;
        }

        printf("Client DTLS connection accepted\n\n");

        /* Echo loop */
        while (server_running) {
            /* Get message from client; will fail if client closes connection */
            if ((rxlen = SSL_read(ssl, rxbuf, (int)rxcap)) <= 0) {
                if (rxlen == 0) {
                    printf("Client closed connection\n");
                } else {
                    /*
                     * When the application starts the server is waiting for
                     * ACKs to the new session tickets it sent out. Therefore
                     * it will return -1 on the SSL_read until it receives
                     * those acks. For that scenario, let's keep us in the loop.
                     */
                    if (received_new_session_ack)
                        printf("SSL_read returned %d\n", rxlen);
                    continue;
                }
                ERR_print_errors_fp(stderr);
                break;
            }
            received_new_session_ack = 1;
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

        printf("Server exiting...\n");
    }
    /* Else client */
    else {
        BIO *bio;

        printf("We are the client\n\n");

        /* Configure client context so we verify the server correctly */
        configure_client_context(ssl_ctx);

        /* Create "bare" UDP socket */
        client_skt = create_socket(false);
        if (client_skt == INVALID_SOCKET) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        /* Set up server address */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, rem_server_name, &addr.sin_addr.s_addr);
        addr.sin_port = htons(server_port);

        /* Connect the UDP socket to the server (sets default peer address) */
        if (connect(client_skt, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            perror("Unable to UDP connect to server");
            goto exit;
        } else {
            printf("UDP connection to server successful\n");
        }

        /* Create a datagram BIO for the connected socket */
        bio = BIO_new_dgram((int)client_skt, BIO_NOCLOSE);
        if (bio == NULL) {
            ERR_print_errors_fp(stderr);
            goto exit;
        }

        /* Create client SSL structure and attach the BIO */
        ssl = SSL_new(ssl_ctx);
        if (ssl == NULL) {
            ERR_print_errors_fp(stderr);
            BIO_free(bio);
            goto exit;
        }
        SSL_set_bio(ssl, bio, bio);

        /* Configure server hostname check */
        if (!SSL_set1_dnsname(ssl, rem_server_name)) {
            ERR_print_errors_fp(stderr);
            goto exit;
        }

        /* Now do DTLS connect with server */
        if (SSL_connect(ssl) == 1) {

            printf("DTLS connection to server successful\n\n");

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

            printf("DTLS connection to server failed\n\n");

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

    printf("dtlsecho exiting\n");

    return EXIT_SUCCESS;
}
