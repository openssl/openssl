/*
 *  Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static const int server_port = 4433;

static const char echconfig[] = "AD7+DQA65wAgACA8wVN2BtscOl3vQheUzHeIkVmKIiydUhDCliA4iyQRCwAEAAEAAQALZXhhbXBsZS5jb20AAA==";
static const char echprivbuf[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VuBCIEICjd4yGRdsoP9gU7YT7My8DHx1Tjme8GYDXrOMCi8v1V\n"
    "-----END PRIVATE KEY-----\n"
    "-----BEGIN ECHCONFIG-----\n"
    "AD7+DQA65wAgACA8wVN2BtscOl3vQheUzHeIkVmKIiydUhDCliA4iyQRCwAEAAEAAQALZXhhbXBsZS5jb20AAA==\n"
    "-----END ECHCONFIG-----\n";

typedef unsigned char   bool;
#define true            1
#define false           0

/*
 * This flag won't be useful until both accept/read (TCP & SSL) methods
 * can be called with a timeout. TBD.
 */
static volatile bool    server_running = true;

int create_socket(bool isServer)
{
    int s;
    int optval = 1;
    struct sockaddr_in addr = { 0 };

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (isServer) {
        addr.sin_family = AF_INET;
        addr.sin_port = htons(server_port);
        addr.sin_addr.s_addr = INADDR_ANY;

        /* Reuse the address; good for quick restarts */
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))
                < 0) {
            perror("setsockopt(SO_REUSEADDR) failed");
            exit(EXIT_FAILURE);
        }

        if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
            perror("Unable to bind");
            exit(EXIT_FAILURE);
        }

        if (listen(s, 1) < 0) {
            perror("Unable to listen");
            exit(EXIT_FAILURE);
        }
    }

    return s;
}

SSL_CTX* create_context(bool isServer)
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

static int configure_ech(SSL_CTX *ctx, int server,
                         unsigned char *buf, size_t len)
{
    OSSL_ECHSTORE *es = NULL;
    BIO *es_in = BIO_new_mem_buf(buf, len);

    if (es_in == NULL || (es = OSSL_ECHSTORE_new(NULL, NULL)) == NULL)
        goto err;
    if (server && OSSL_ECHSTORE_read_pem(es, es_in, 1) != 1)
        goto err;
    if (!server && OSSL_ECHSTORE_read_echconfiglist(es, es_in) != 1)
        goto err;
    if (SSL_CTX_set1_echstore(ctx, es) != 1)
        goto err;
    BIO_free_all(es_in);
    return 1;
err:
    OSSL_ECHSTORE_free(es);
    BIO_free_all(es_in);
    return 0;
}

void configure_server_context(SSL_CTX *ctx)
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

    if (configure_ech(ctx, 1, (unsigned char*)echprivbuf,
                      sizeof(echprivbuf) - 1) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void configure_client_context(SSL_CTX *ctx)
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
    if (configure_ech(ctx, 0, (unsigned char*)echconfig,
                      sizeof(echconfig) - 1) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void usage()
{
    printf("Usage: echecho s\n");
    printf("       --or--\n");
    printf("       echecho c ip\n");
    printf("       c=client, s=server, ip=dotted ip of server\n");
    exit(1);
}

int main(int argc, char **argv)
{
    bool isServer;
    int result;

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int server_skt = -1;
    int client_skt = -1;

    /* used by getline relying on realloc, can't be statically allocated */
    char *txbuf = NULL;
    size_t txcap = 0;
    int txlen;

    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    char *rem_server_ip = NULL;

    struct sockaddr_in addr = { 0 };
    unsigned int addr_len = sizeof(addr);

    char *outer_sni = NULL, *inner_sni = NULL;
    int ech_status;

    /* Splash */
    printf("\nechecho : Simple Echo Client/Server: %s : %s\n\n", __DATE__,
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
        rem_server_ip = argv[2];
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
            client_skt = accept(server_skt, (struct sockaddr*) &addr,
                                &addr_len);
            if (client_skt < 0) {
                perror("Unable to accept");
                exit(EXIT_FAILURE);
            }

            printf("Client TCP connection accepted\n");

            /* Create server SSL structure using newly accepted client socket */
            ssl = SSL_new(ssl_ctx);
            SSL_set_fd(ssl, client_skt);

            /* Wait for SSL connection from the client */
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                server_running = false;
            } else {

                printf("Client SSL connection accepted\n\n");

                ech_status = SSL_ech_get1_status(ssl, &inner_sni, &outer_sni);
                printf("ECH %s (status: %d, inner: %s, outer: %s)\n",
                        (ech_status == 1 ? "worked" : "failed/not-tried"),
                        ech_status, inner_sni, outer_sni);
                OPENSSL_free(inner_sni);
                OPENSSL_free(outer_sni);
                inner_sni = outer_sni = NULL;

                /* Echo loop */
                while (true) {
                    /* Get message from client; will fail if client closes connection */
                    if ((rxlen = SSL_read(ssl, rxbuf, rxcap)) <= 0) {
                        if (rxlen == 0) {
                            printf("Client closed connection\n");
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
                close(client_skt);
            }
        }
        printf("Server exiting...\n");
    }
    /* Else client */
    else {

        printf("We are the client\n\n");

        /* Configure client context so we verify the server correctly */
        configure_client_context(ssl_ctx);

        /* Create "bare" socket */
        client_skt = create_socket(false);
        /* Set up connect address */
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, rem_server_ip, &addr.sin_addr.s_addr);
        addr.sin_port = htons(server_port);
        /* Do TCP connect with server */
        if (connect(client_skt, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
            perror("Unable to TCP connect to server");
            goto exit;
        } else {
            printf("TCP connection to server successful\n");
        }

        /* Create client SSL structure using dedicated client socket */
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_skt);
        /* Set hostname for SNI */
        SSL_set_tlsext_host_name(ssl, rem_server_ip);
        /* Configure server hostname check */
        SSL_set1_host(ssl, rem_server_ip);

        /* Now do SSL connect with server */
        if (SSL_connect(ssl) == 1) {

            printf("SSL connection to server successful\n\n");

            ech_status = SSL_ech_get1_status(ssl, &inner_sni, &outer_sni);
            printf("ECH %s (status: %d, inner: %s, outer: %s)\n",
                    (ech_status == 1 ? "worked" : "failed/not-tried"),
                    ech_status, inner_sni, outer_sni);
            OPENSSL_free(inner_sni);
            OPENSSL_free(outer_sni);
            inner_sni = outer_sni = NULL;

            /* Loop to send input from keyboard */
            while (true) {
                /* Get a line of input */
                txlen = getline(&txbuf, &txcap, stdin);
                /* Exit loop on error */
                if (txlen < 0 || txbuf == NULL) {
                    break;
                }
                /* Exit loop if just a carriage return */
                if (txbuf[0] == '\n') {
                    break;
                }
                /* Send it to the server */
                if ((result = SSL_write(ssl, txbuf, txlen)) <= 0) {
                    printf("Server closed connection\n");
                    ERR_print_errors_fp(stderr);
                    break;
                }

                /* Wait for the echo */
                rxlen = SSL_read(ssl, rxbuf, rxcap);
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

    if (client_skt != -1)
        close(client_skt);
    if (server_skt != -1)
        close(server_skt);

    if (txbuf != NULL && txcap > 0)
        free(txbuf);

    printf("echecho exiting\n");

    return 0;
}
