/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * A QUIC server for recipes that drive s_client, since s_server cannot speak
 * QUIC.  It listens on an ephemeral UDP port on 127.0.0.1 and announces it
 * the way s_server does, as "ACCEPT 127.0.0.1:<port>".  It selects the ALPN
 * protocol "ossltest" and rejects a client that does not offer it, which
 * fails that client's handshake.  Each connection is closed once its
 * handshake is over, and the server exits after NACCEPT of them.
 *
 * Usage: quic_alpn_server CERT KEY NACCEPT
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "internal/sockets.h"

static const unsigned char alpn_ossltest[] = "\x08ossltest";

static int select_alpn(SSL *ssl, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in,
    unsigned int inlen, void *arg)
{
    if (SSL_select_next_proto((unsigned char **)out, outlen, alpn_ossltest,
            sizeof(alpn_ossltest) - 1, in, inlen)
        == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;

    printf("ALPN REJECTED\n");
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

int main(int argc, char *argv[])
{
    static const unsigned char loopback[] = { 127, 0, 0, 1 };
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL, *conn;
    BIO_ADDR *addr = NULL;
    union BIO_sock_info_u info;
    char *port = NULL;
    int fd = -1, naccept, i, ret = 1;

    if (argc != 4 || (naccept = atoi(argv[3])) <= 0) {
        fprintf(stderr, "usage: %s cert key naccept\n", argv[0]);
        return 1;
    }

    /* The caller waits for the ACCEPT line, so don't let it sit in a buffer */
    setvbuf(stdout, NULL, _IONBF, 0);

    if ((ctx = SSL_CTX_new(OSSL_QUIC_server_method())) == NULL
        || SSL_CTX_use_certificate_chain_file(ctx, argv[1]) <= 0
        || SSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_PEM) <= 0)
        goto end;
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);

    if (!BIO_sock_init()
        || (addr = BIO_ADDR_new()) == NULL
        || !BIO_ADDR_rawmake(addr, AF_INET, loopback, sizeof(loopback), 0))
        goto end;
    fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (fd < 0 || !BIO_bind(fd, addr, 0))
        goto end;

    /* Find out which port the system picked */
    info.addr = addr;
    if (!BIO_sock_info(fd, BIO_SOCK_INFO_ADDRESS, &info)
        || (port = BIO_ADDR_service_string(addr, 1)) == NULL)
        goto end;

    if ((listener = SSL_new_listener(ctx, 0)) == NULL
        || !SSL_set_fd(listener, fd)
        || !SSL_listen(listener))
        goto end;
    printf("ACCEPT 127.0.0.1:%s\n", port);

    for (i = 0; i < naccept; i++) {
        if ((conn = SSL_accept_connection(listener, 0)) == NULL)
            goto end;
        if (SSL_accept(conn) == 1) {
            printf("HANDSHAKE COMPLETE\n");
        } else {
            printf("HANDSHAKE FAILED\n");
            ERR_print_errors_fp(stdout);
        }
        SSL_free(conn);
    }
    ret = 0;

end:
    if (ret != 0)
        ERR_print_errors_fp(stderr);
    SSL_free(listener);
    if (fd >= 0)
        BIO_closesocket(fd);
    OPENSSL_free(port);
    BIO_ADDR_free(addr);
    SSL_CTX_free(ctx);
    return ret;
}
