/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include "x509_lcl.h"

static int by_file_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc,
                        long argl, char **ret);
static X509_LOOKUP_METHOD x509_file_lookup = {
    "Load file into cache",
    NULL,                       /* new_item */
    NULL,                       /* free */
    NULL,                       /* init */
    NULL,                       /* shutdown */
    by_file_ctrl,               /* ctrl */
    NULL,                       /* get_by_subject */
    NULL,                       /* get_by_issuer_serial */
    NULL,                       /* get_by_fingerprint */
    NULL,                       /* get_by_alias */
};

X509_LOOKUP_METHOD *X509_LOOKUP_file(void)
{
    return &x509_file_lookup;
}

static int by_file_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp,
                        long argl, char **ret)
{
    int ok = 0;
    const char *file;

    switch (cmd) {
    case X509_L_FILE_LOAD:
        if (argl == X509_FILETYPE_DEFAULT) {
            file = getenv(X509_get_default_cert_file_env());
            if (file)
                ok = (X509_load_cert_crl_file(ctx, file,
                                              X509_FILETYPE_PEM) != 0);

            else
                ok = (X509_load_cert_crl_file
                      (ctx, X509_get_default_cert_file(),
                       X509_FILETYPE_PEM) != 0);

            if (!ok) {
                X509err(X509_F_BY_FILE_CTRL, X509_R_LOADING_DEFAULTS);
            }
        } else {
            if (argl == X509_FILETYPE_PEM)
                ok = (X509_load_cert_crl_file(ctx, argp,
                                              X509_FILETYPE_PEM) != 0);
            else
                ok = (X509_load_cert_file(ctx, argp, (int)argl) != 0);
        }
        break;
    }
    return ok;
}

int x509_load_cert_crl_file_int(X509_LOOKUP *ctx, const char *file,
                                int expected_result)
{
    OSSL_STORE_CTX *storectx = OSSL_STORE_open(file, NULL, NULL, NULL, NULL);
    OSSL_STORE_INFO *info = NULL;
    int ok = 0;

    if (storectx == NULL) {
        X509err(X509_F_X509_LOAD_CERT_CRL_FILE_INT, ERR_R_OSSL_STORE_LIB);
        return ok;
    }

    if (!OSSL_STORE_expect(storectx, expected_result)) {
        X509err(X509_F_X509_LOAD_CERT_CRL_FILE_INT, ERR_R_OSSL_STORE_LIB);
        return ok;
    }

    while ((info = OSSL_STORE_load(storectx)) != NULL) {
        switch (OSSL_STORE_INFO_get_type(info)) {
        case OSSL_STORE_INFO_CERT:
            X509_STORE_add_cert(ctx->store_ctx,
                                OSSL_STORE_INFO_get0_CERT(info));
            break;
        case OSSL_STORE_INFO_CRL:
            X509_STORE_add_crl(ctx->store_ctx,
                               OSSL_STORE_INFO_get0_CRL(info));
            break;
        default:
            /* Everything else is ignored */
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    if (OSSL_STORE_error(storectx)) {
        X509err(X509_F_X509_LOAD_CERT_CRL_FILE_INT, ERR_R_OSSL_STORE_LIB);
        goto err;
    }

    fprintf(stderr, "FOO[by_file]!\n");
    ok = 1;
 err:
    OSSL_STORE_close(storectx);
    return ok;
}

int X509_load_cert_file(X509_LOOKUP *ctx, const char *file, int type)
{
    return x509_load_cert_crl_file_int(ctx, file, OSSL_STORE_INFO_CERT);
}

int X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type)
{
    return x509_load_cert_crl_file_int(ctx, file, OSSL_STORE_INFO_CRL);
}

int X509_load_cert_crl_file(X509_LOOKUP *ctx, const char *file, int type)
{
    /* In this case, 0 means certs and CRLs */
    return x509_load_cert_crl_file_int(ctx, file, 0);
}
