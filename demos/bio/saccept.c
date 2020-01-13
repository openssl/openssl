/*
 * Copyright 1998-2017 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*-
 * A minimal program to serve an tls connection.
 * It uses blocking.
 * saccept host:port
 * host is the interface IP to use.  If any interface, use *:port
 * The default it *:4433
 *
 * cc -I../../include saccept.c -L../.. -ltls -lcrypto -ldl
 */

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <opentls/err.h>
#include <opentls/tls.h>

#define CERT_FILE       "server.pem"

static volatile int done = 0;

void interrupt(int sig)
{
    done = 1;
}

void sigsetup(void)
{
    struct sigaction sa;

    /*
     * Catch at most once, and don't restart the accept system call.
     */
    sa.sa_flags = SA_RESETHAND;
    sa.sa_handler = interrupt;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
}

int main(int argc, char *argv[])
{
    char *port = NULL;
    BIO *in = NULL;
    BIO *tls_bio, *tmp;
    tls_CTX *ctx;
    char buf[512];
    int ret = EXIT_FAILURE, i;

    if (argc <= 1)
        port = "*:4433";
    else
        port = argv[1];

    ctx = tls_CTX_new(TLS_server_method());
    if (!tls_CTX_use_certificate_chain_file(ctx, CERT_FILE))
        goto err;
    if (!tls_CTX_use_PrivateKey_file(ctx, CERT_FILE, tls_FILETYPE_PEM))
        goto err;
    if (!tls_CTX_check_private_key(ctx))
        goto err;

    /* Setup server side tls bio */
    tls_bio = BIO_new_tls(ctx, 0);

    if ((in = BIO_new_accept(port)) == NULL)
        goto err;

    /*
     * This means that when a new connection is accepted on 'in', The tls_bio
     * will be 'duplicated' and have the new socket BIO push into it.
     * Basically it means the tls BIO will be automatically setup
     */
    BIO_set_accept_bios(in, tls_bio);

    /* Arrange to leave server loop on interrupt */
    sigsetup();

 again:
    /*
     * The first call will setup the accept socket, and the second will get a
     * socket.  In this loop, the first actual accept will occur in the
     * BIO_read() function.
     */

    if (BIO_do_accept(in) <= 0)
        goto err;

    while (!done) {
        i = BIO_read(in, buf, 512);
        if (i == 0) {
            /*
             * If we have finished, remove the underlying BIO stack so the
             * next time we call any function for this BIO, it will attempt
             * to do an accept
             */
            printf("Done\n");
            tmp = BIO_pop(in);
            BIO_free_all(tmp);
            goto again;
        }
        if (i < 0)
            goto err;
        fwrite(buf, 1, i, stdout);
        fflush(stdout);
    }

    ret = EXIT_SUCCESS;
 err:
    if (ret != EXIT_SUCCESS)
        ERR_print_errors_fp(stderr);
    BIO_free(in);
    return ret;
}
