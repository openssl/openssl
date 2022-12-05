/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/provider.h>

#ifdef OPENSSL_NO_QUIC
#error Please enable QUIC
#endif
#include <openssl/quic.h>

static const int MAX_FAILURES = 16;

static OSSL_LIB_CTX *libctx = NULL;

static struct {
    const char *server_ip;
    int server_port;
    int is_server;
} params;

static char *error(const char *msg)
{
    size_t len;
    char *buf;
    const char *errno_str = strerror(errno);

    len = snprintf(NULL, 0, "%s : %s", msg, errno_str);
    buf = OPENSSL_malloc(len + 1);
    if (buf == NULL)
        abort();
    snprintf(buf, len + 1, "%s : %s", msg, errno_str);

    return buf;
}

static char *create_socket(int *p_socket)
{
    int s = -1;
    char *err = NULL;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        return error("Unable to create socket");
    }

    *p_socket = s;
    return NULL;
}

static char *create_server_socket(int *p_socket) {
    int s = -1;
    int optval = 1;
    struct sockaddr_in addr;
    char *e = NULL;

    if ((e = create_socket(&s)) != NULL)
        goto err;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(params.server_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* Reuse the address; good for quick restarts */
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        e = error("setsockopt(SO_REUSEADDR) failed");
        goto err;
    }

    if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        e = error("Unable to bind");
        goto err;
    }
    if (listen(s, 1) < 0) {
        e = error("Unable to listen");
        goto err;
    }

    *p_socket = s;
    return NULL;
err:
    close(s);
    return e;
}

static char *create_client_socket(int *p_socket) {
    int s = -1;
    int optval = 1;
    struct sockaddr_in addr;
    char *e = NULL;

    if ((e = create_socket(&s)) != NULL)
        goto err;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(params.server_port);
    if (!inet_pton(AF_INET, params.server_ip, &addr.sin_addr.s_addr)) {
        e = error("Cannot parse address");
        goto err;
    }

    /* Reuse the address; good for quick restarts */
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        e = error("setsockopt(SO_REUSEADDR) failed");
        goto err;
    }

    if (connect(s, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
        e = error("Cannot connect");
        goto err;
    }

    *p_socket = s;
    return NULL;
err:
    close(s);
    return e;
}

static int configure_server_context(SSL_CTX *server_ctx)
{
    int status = 0;

    if (!SSL_CTX_set_options(server_ctx,
                             SSL_OP_ALLOW_CLIENT_RENEGOTIATION))
        goto end;
    if (!SSL_CTX_set_max_proto_version(server_ctx, 0))
        goto end;

    /* Set the key and cert */
    /*Daniel:  */
    if (SSL_CTX_use_certificate_chain_file(server_ctx, "cert.pem") <= 0)
        goto end;

    if (SSL_CTX_use_PrivateKey_file(server_ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
        goto end;

    status = 1;
end:
    return status;
}

static int configure_client_context(SSL_CTX *client_ctx)
{
    int status = 0;

    /*
     * Configure the client to abort the handshake if certificate verification
     * fails
     */
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, NULL);

    /*
     * In a real application you would probably just use the default system certificate trust store and call:
     *     SSL_CTX_set_default_verify_paths(ctx);
     * In this demo though we are using a self-signed certificate, so the client must trust it directly.
     */
    if (!SSL_CTX_load_verify_locations(client_ctx, "cert.pem", NULL))
        goto end;

    status = 1;
end:
    return status;
}

static int server()
{
    int status = 0;
    const char *e = NULL;

    int server_socket = -1;
    SSL_CTX *server_ctx = NULL;

    int failures_num = 0;

    //server_ctx = SSL_CTX_new_ex(libctx, NULL, OSSL_QUIC_server_method());
    server_ctx = SSL_CTX_new_ex(libctx, NULL, TLS_server_method());
    if (server_ctx == NULL)
        goto end;
    if (!configure_server_context(server_ctx))
        goto end;

    if ((e = create_server_socket(&server_socket)) != NULL)
        goto end;

    for (;;) {
        int client_socket = -1;
        SSL *ssl = NULL;
        struct sockaddr_in addr;
        int addr_len = (int)sizeof(addr);

        client_socket = accept(server_socket,
                               (struct sockaddr*)&addr,
                               &addr_len);
        if (client_socket < 0) {
            e = error("Unable to accept");
            goto server_end;
        }

        /* Create server SSL structure using newly accepted client socket */
        ssl = SSL_new(server_ctx);
        if (ssl == NULL)
            goto server_end;

        if (!SSL_set_fd(ssl, client_socket))
            goto server_end;

        /* Wait for SSL connection from the client */
        if (SSL_accept(ssl) <= 0)
            goto server_end;

        printf("Connection accepted\n");
        // Client SSL connection accepted
        for (;;) {
            char rxbuf[128];
            size_t rxcap = sizeof(rxbuf);
            /* Get message from client; will fail if client closes connection */
            ssize_t rxlen = SSL_read(ssl, rxbuf, rxcap);
            if (rxlen == 0) {
                printf("Client closed connection\n");
                break;
            } else if (rxlen < 0) {
                goto end;
            }
        }

        /* ... */
server_end:
        if (e != NULL || status == 0)
            ++failures_num;
        if (e != NULL) {
            fprintf(stderr, "%s\n", e);
        } else if (status == 0) {
            ERR_print_errors_fp(stderr);
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_socket);
        OPENSSL_free(e);
        e = NULL;
        if (failures_num >= MAX_FAILURES) {
            e = error("Too many failures");
            goto end;
        }
    }

    status = 1;
end:
    if (e != NULL) {
        fprintf(stderr, "%s\n", e);
    } else if (status == 0) {
        ERR_print_errors_fp(stderr);
    }
    close(server_socket);
    SSL_CTX_free(server_ctx);
    OPENSSL_free(e);

    return status;
}

static int client()
{
    int status = 0;
    char *e = NULL;
    int rets = 0, err = 0;

    int client_socket = -1;
    SSL *client_ssl = NULL;
    SSL_CTX *client_ctx = NULL;

    //client_ctx = SSL_CTX_new_ex(libctx, NULL, OSSL_QUIC_client_method());
    client_ctx = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    if (client_ctx == NULL)
        goto end;
    if (!configure_client_context(client_ctx))
        goto end;

    if ((e = create_client_socket(&client_socket)) != NULL)
        goto end;

    /* Create client SSL structure using dedicated client socket */
    client_ssl = SSL_new(client_ctx);
    if (client_ssl == NULL)
        goto end;

    if (!SSL_set_fd(client_ssl, client_socket))
        goto end;

    // Daniel: Finish
    // Client SSL connection accepted
    /* Set hostname for SNI */
    if (!SSL_set_tlsext_host_name(client_ssl, params.server_ip))
        goto end;
    /* Configure server hostname check */
    if (!SSL_set1_host(client_ssl, params.server_ip))
        goto end;

    /* Now do SSL connect with server */
    for (;;) {
        rets = SSL_connect(client_ssl);
        if (rets == 1)
            break;
        // if (rets <= 0)
        err = SSL_get_error(client_ssl, rets);
        if (err == SSL_ERROR_WANT_ACCEPT)
            continue;
        /* Daniel: Maybe handle other cases? */
        goto end;
    }

    status = 1;
end:
    if (e != NULL) {
        fprintf(stderr, "%s\n", e);
    } else if (status == 0) {
        ERR_print_errors_fp(stderr);
    }
    close(client_socket);
    SSL_free(client_ssl);
    SSL_CTX_free(client_ctx);
    OPENSSL_free(e);

    return status;
}

int main(int argc, const char *argv[])
{
    int status = 0;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL)
        goto end;

    /* Daniel: Better params parsing */
    params.is_server = OPENSSL_strcasecmp(argv[1], "server") == 0;
    params.server_ip = argv[2];
    params.server_port = atoi(argv[3]);

    if (params.is_server) {
        server();
    } else {
        client();
    }

    status = 1;
end:
    OSSL_LIB_CTX_free(libctx);
    return status ? 0 : 1;
}