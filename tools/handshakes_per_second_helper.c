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

#ifdef DANIEL_IMPLEMENTED_QUIC
#ifdef OPENSSL_NO_QUIC
#error Please enable QUIC
#endif
#include <openssl/quic.h>
#endif

static const int MAX_FAILURES = 16;

static OSSL_LIB_CTX *libctx = NULL;

static struct {
    const char *server_ip;
    const char *server_host;
    const char *key;
    const char *cert;
    int server_port;
    int requests_num;
    int8_t is_server;
    int8_t is_client;
} params;

static void usage()
{
    printf("Usage: ...\n"
           "       This is an internal tool.\n"
           "       It should not be called directly.\n");
}

static char *error(const char *msg)
{
    size_t len;
    char *buf;
    const char *errno_str;
    
    if (errno == 0) {
        if ((buf = OPENSSL_strdup(msg)) == NULL)
            abort();
        return buf;
    }

    errno_str = strerror(errno);

    len = snprintf(NULL, 0, "%s : %s", msg, errno_str);
    if ((buf = OPENSSL_malloc(len + 1)) == NULL)
        abort();
    snprintf(buf, len + 1, "%s : %s", msg, errno_str);

    return buf;
}

static char *create_socket(int *p_socket)
{
    int s = -1;

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
    struct sockaddr_in addr;
    char *e = NULL;
    const int MAX_CONNECT_ATTEMPTS = 32;
    const int RECONNECT_SLEEP=500;
    int connect_attempts = 0;


    if ((e = create_socket(&s)) != NULL)
        goto err;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(params.server_port);
    if (!inet_pton(AF_INET, params.server_ip, &addr.sin_addr.s_addr)) {
        e = error("Cannot parse address");
        goto err;
    }

    for (;; connect_attempts++) {
        if (connect(s, (struct sockaddr*) &addr, sizeof(addr)) == 0)
            break;
        // Daniel: This connect attempts should be done only the first time
        if (connect_attempts >= MAX_CONNECT_ATTEMPTS) {
            e = error("Cannot connect");
            goto err;
        }
        fprintf(stderr, "Client: Cannot connect: %s\n", strerror(errno));
        OSSL_sleep(RECONNECT_SLEEP);
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

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(server_ctx, params.cert) <= 0)
        goto end;

    if (SSL_CTX_use_PrivateKey_file(server_ctx, params.key, SSL_FILETYPE_PEM) <= 0)
        goto end;

    status = 1;
end:
    return status;
}

static int configure_client_context(SSL_CTX *client_ctx)
{
    int status = 0;

    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER /*SSL_VERIFY_NONE*/, NULL);

    if (!SSL_CTX_load_verify_locations(client_ctx, params.cert, NULL))
        goto end;

    status = 1;
end:
    return status;
}

static int server()
{
    int status = 0;
    char *e = NULL;

    int server_socket = -1;
    SSL_CTX *server_ctx = NULL;

    int failures_num = 0;
    int request_id = 0;
    long start_time = -1;
    long end_time = -1;
    long accepted = 0;

    /* server_ctx = SSL_CTX_new_ex(libctx, NULL, OSSL_QUIC_server_method()); */
    server_ctx = SSL_CTX_new_ex(libctx, NULL, TLS_server_method());
    if (server_ctx == NULL)
        goto end;
    if (!configure_server_context(server_ctx))
        goto end;

    if ((e = create_server_socket(&server_socket)) != NULL)
        goto end;

    for (; request_id < params.requests_num; ++request_id) {
        int client_socket = -1;
        SSL *ssl = NULL;
        struct sockaddr_in addr;
        socklen_t addr_len = (socklen_t)sizeof(addr);

        client_socket = accept(server_socket,
                               (struct sockaddr*)&addr,
                               &addr_len);
        if (client_socket < 0) {
            e = error("Unable to accept");
            goto server_end;
        }
        if (start_time == -1)
            start_time = (long)time(NULL);

        /* Create server SSL structure using newly accepted client socket */
        ssl = SSL_new(server_ctx);
        if (ssl == NULL)
            goto server_end;

        if (!SSL_set_fd(ssl, client_socket))
            goto server_end;

        /* Wait for SSL connection from the client */
        if (SSL_accept(ssl) <= 0)
            goto server_end;

        end_time = (long)time(NULL);
        ++accepted;
        // Client SSL connection accepted

        status = 1;
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

    if (start_time > 0 && end_time >= start_time && accepted > 0) {
        printf("Server:\n"
               "  Accepted: %ld in %ld seconds\n"
               "  %.3f accepts/sec\n",
                accepted, end_time - start_time,
                (double)accepted/(end_time - start_time));
    }

    return status;
}

static int client_one_connect(SSL_CTX *client_ctx, char **p_e)
{
    int status = 0;
    char *e = NULL;
    int rets = 0, err = 0;
    int client_socket = -1;
    SSL *client_ssl = NULL;

    if ((e = create_client_socket(&client_socket)) != NULL)
        goto end;

    /* Create client SSL structure using dedicated client socket */
    client_ssl = SSL_new(client_ctx);
    if (client_ssl == NULL)
        goto end;

    if (!SSL_set_fd(client_ssl, client_socket))
        goto end;

    /* Set hostname for SNI */
    if (!SSL_set_tlsext_host_name(client_ssl, params.server_ip))
        goto end;
    /* Configure server hostname check */
    if (!SSL_set1_host(client_ssl, params.server_host))
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
        /* Maybe handle other cases? */
        goto end;
    }

    /*
     * It is necessary to attempt to read something
     * to prevent "broken pipe" on server side
     */
    for (;;) {
        char rxbuf[128];
        size_t rxcap = sizeof(rxbuf);
        ssize_t rxlen = SSL_read(client_ssl, rxbuf, rxcap);
        if (rxlen == 0) {
            break;
        } else if (rxlen < 0) {
            goto end;
        }
    }

    status = 1;
end:
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    close(client_socket);

    if (e != NULL)
        *p_e = e;
    
    return status;
}

static int client()
{
    int status = 0;
    int request_id = 0;
    char *e = NULL;
    SSL_CTX *client_ctx = NULL;

    //client_ctx = SSL_CTX_new_ex(libctx, NULL, OSSL_QUIC_client_method());
    client_ctx = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    if (client_ctx == NULL)
        goto end;
    if (!configure_client_context(client_ctx))
        goto end;

    for (; request_id < params.requests_num; ++request_id) {
        if (!client_one_connect(client_ctx, &e))
            goto end;
    }

    status = 1;
end:
    if (e != NULL) {
        fprintf(stderr, "%s\n", e);
    } else if (status == 0) {
        ERR_print_errors_fp(stderr);
    }
    SSL_CTX_free(client_ctx);
    OPENSSL_free(e);

    return status;
}

int main(int argc, const char *argv[])
{
    int status = 0;

    fprintf(stderr, "handshakes_per_second: ");
    for (int i = 0; i < argc; i++) {
        if (i > 0) {
            fprintf(stderr, " ");
        }
        fprintf(stderr, "'%s'", argv[i]);
    }
    fprintf(stderr, "\n");

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL)
        goto end;

    if (argc >= 8) {
        params.is_server = OPENSSL_strcasecmp(argv[1], "server") == 0;
        params.is_client = OPENSSL_strcasecmp(argv[1], "client") == 0;
        params.server_ip = argv[2];
        params.server_port = atoi(argv[3]);
        params.server_host = argv[4];
        params.key = argv[5];
        params.cert = argv[6];
        params.requests_num = atoi(argv[7]);
    }
    if (params.is_server) {
        if (!server())
            goto end;
    } else if (params.is_client) {
        if (!client())
            goto end;
    } else {
        usage();
        goto end;
    }

    status = 1;
end:
    OSSL_LIB_CTX_free(libctx);
    return status ? 0 : 1;
}