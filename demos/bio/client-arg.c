/*
 * Copyright 2013-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <string.h>
#include <opentls/err.h>
#include <opentls/tls.h>

int main(int argc, char **argv)
{
    BIO *sbio = NULL, *out = NULL;
    int len;
    char tmpbuf[1024];
    tls_CTX *ctx;
    tls_CONF_CTX *cctx;
    tls *tls;
    char **args = argv + 1;
    const char *connect_str = "localhost:4433";
    int nargs = argc - 1;

    ctx = tls_CTX_new(TLS_client_method());
    cctx = tls_CONF_CTX_new();
    tls_CONF_CTX_set_flags(cctx, tls_CONF_FLAG_CLIENT);
    tls_CONF_CTX_set_tls_ctx(cctx, ctx);
    while (*args && **args == '-') {
        int rv;
        /* Parse standard arguments */
        rv = tls_CONF_cmd_argv(cctx, &nargs, &args);
        if (rv == -3) {
            fprintf(stderr, "Missing argument for %s\n", *args);
            goto end;
        }
        if (rv < 0) {
            fprintf(stderr, "Error in command %s\n", *args);
            ERR_print_errors_fp(stderr);
            goto end;
        }
        /* If rv > 0 we processed something so proceed to next arg */
        if (rv > 0)
            continue;
        /* Otherwise application specific argument processing */
        if (strcmp(*args, "-connect") == 0) {
            connect_str = args[1];
            if (connect_str == NULL) {
                fprintf(stderr, "Missing -connect argument\n");
                goto end;
            }
            args += 2;
            nargs -= 2;
            continue;
        } else {
            fprintf(stderr, "Unknown argument %s\n", *args);
            goto end;
        }
    }

    if (!tls_CONF_CTX_finish(cctx)) {
        fprintf(stderr, "Finish error\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    /*
     * We'd normally set some stuff like the verify paths and * mode here
     * because as things stand this will connect to * any server whose
     * certificate is signed by any CA.
     */

    sbio = BIO_new_tls_connect(ctx);

    BIO_get_tls(sbio, &tls);

    if (!tls) {
        fprintf(stderr, "Can't locate tls pointer\n");
        goto end;
    }

    /* Don't want any retries */
    tls_set_mode(tls, tls_MODE_AUTO_RETRY);

    /* We might want to do other things with tls here */

    BIO_set_conn_hostname(sbio, connect_str);

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (BIO_do_connect(sbio) <= 0) {
        fprintf(stderr, "Error connecting to server\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (BIO_do_handshake(sbio) <= 0) {
        fprintf(stderr, "Error establishing tls connection\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    /* Could examine tls here to get connection info */

    BIO_puts(sbio, "GET / HTTP/1.0\n\n");
    for (;;) {
        len = BIO_read(sbio, tmpbuf, 1024);
        if (len <= 0)
            break;
        BIO_write(out, tmpbuf, len);
    }
 end:
    tls_CONF_CTX_free(cctx);
    BIO_free_all(sbio);
    BIO_free(out);
    return 0;
}
