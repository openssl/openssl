/*
 * Copyright 1998-2017 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*-
 * A minimal program to do tls to a passed host and port.
 * It is actually using non-blocking IO but in a very simple manner
 * sconnect host:port - it does a 'GET / HTTP/1.0'
 *
 * cc -I../../include sconnect.c -L../.. -ltls -lcrypto
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <opentls/err.h>
#include <opentls/tls.h>

#define HOSTPORT "localhost:4433"
#define CAFILE "root.pem"

int main(int argc, char *argv[])
{
    const char *hostport = HOSTPORT;
    const char *CAfile = CAFILE;
    char *hostname;
    char *cp;
    BIO *out = NULL;
    char buf[1024 * 10], *p;
    tls_CTX *tls_ctx = NULL;
    tls *tls;
    BIO *tls_bio;
    int i, len, off, ret = EXIT_FAILURE;

    if (argc > 1)
        hostport = argv[1];
    if (argc > 2)
        CAfile = argv[2];

    hostname = OPENtls_strdup(hostport);
    if ((cp = strchr(hostname, ':')) != NULL)
        *cp = 0;

#ifdef WATT32
    dbug_init();
    sock_init();
#endif

    tls_ctx = tls_CTX_new(TLS_client_method());

    /* Enable trust chain verification */
    tls_CTX_set_verify(tls_ctx, tls_VERIFY_PEER, NULL);
    tls_CTX_load_verify_locations(tls_ctx, CAfile, NULL);

    /* Lets make a tls structure */
    tls = tls_new(tls_ctx);
    tls_set_connect_state(tls);

    /* Enable peername verification */
    if (tls_set1_host(tls, hostname) <= 0)
        goto err;

    /* Use it inside an tls BIO */
    tls_bio = BIO_new(BIO_f_tls());
    BIO_set_tls(tls_bio, tls, BIO_CLOSE);

    /* Lets use a connect BIO under the tls BIO */
    out = BIO_new(BIO_s_connect());
    BIO_set_conn_hostname(out, hostport);
    BIO_set_nbio(out, 1);
    out = BIO_push(tls_bio, out);

    p = "GET / HTTP/1.0\r\n\r\n";
    len = strlen(p);

    off = 0;
    for (;;) {
        i = BIO_write(out, &(p[off]), len);
        if (i <= 0) {
            if (BIO_should_retry(out)) {
                fprintf(stderr, "write DELAY\n");
                sleep(1);
                continue;
            } else {
                goto err;
            }
        }
        off += i;
        len -= i;
        if (len <= 0)
            break;
    }

    for (;;) {
        i = BIO_read(out, buf, sizeof(buf));
        if (i == 0)
            break;
        if (i < 0) {
            if (BIO_should_retry(out)) {
                fprintf(stderr, "read DELAY\n");
                sleep(1);
                continue;
            }
            goto err;
        }
        fwrite(buf, 1, i, stdout);
    }

    ret = EXIT_SUCCESS;
    goto done;

 err:
    if (ERR_peek_error() == 0) { /* system call error */
        fprintf(stderr, "errno=%d ", errno);
        perror("error");
    } else {
        ERR_print_errors_fp(stderr);
    }
 done:
    BIO_free_all(out);
    tls_CTX_free(tls_ctx);
    return ret;
}
