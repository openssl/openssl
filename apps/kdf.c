/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_KDFOPT, OPT_BIN, OPT_KEYLEN, OPT_OUT
} OPTION_CHOICE;

const OPTIONS kdf_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] kdf_name\n"},
    {OPT_HELP_STR, 1, '-', "kdf_name\t KDF algorithm.\n"},

    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"kdfopt", OPT_KDFOPT, 's', "KDF algorithm control parameters in n:v form."},
    {OPT_HELP_STR, 1, '-', "See 'Supported Controls' in the EVP_KDF_ docs"},
    {"keylen", OPT_KEYLEN, 's', "The size of the output derived key"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output to filename rather than stdout"},
    {"binary", OPT_BIN, '-', "Output in binary format (Default is hexadecimal "
                             "output)"},
    {NULL}
};

int kdf_main(int argc, char **argv)
{
    int ret = 1, out_bin = 0;
    OPTION_CHOICE o;
    STACK_OF(OPENSSL_STRING) *opts = NULL;
    char *prog, *hexout = NULL;
    const char *outfile = NULL;
    unsigned char *dkm_bytes = NULL;
    size_t dkm_len = 0;
    BIO *out = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;

    prog = opt_init(argc, argv, kdf_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        default:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto err;
        case OPT_HELP:
            opt_help(kdf_options);
            ret = 0;
            goto err;
        case OPT_BIN:
            out_bin = 1;
            break;
        case OPT_KEYLEN:
            dkm_len = (size_t)atoi(opt_arg());
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_KDFOPT:
            if (opts == NULL)
                opts = sk_OPENSSL_STRING_new_null();
            if (opts == NULL || !sk_OPENSSL_STRING_push(opts, opt_arg()))
                goto opthelp;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (argc != 1) {
        BIO_printf(bio_err, "Invalid number of extra arguments\n");
        goto opthelp;
    }

    if ((kdf = EVP_KDF_fetch(NULL, argv[0], NULL)) == NULL) {
        BIO_printf(bio_err, "Invalid KDF name %s\n", argv[0]);
        goto opthelp;
    }

    ctx = EVP_KDF_CTX_new(kdf);
    if (ctx == NULL)
        goto err;

    if (opts != NULL) {
        int ok = 1;
        OSSL_PARAM *params =
            app_params_new_from_opts(opts, EVP_KDF_settable_ctx_params(kdf));

        if (params == NULL)
            goto err;

        if (!EVP_KDF_CTX_set_params(ctx, params)) {
            BIO_printf(bio_err, "KDF parameter error\n");
            ERR_print_errors(bio_err);
            ok = 0;
        }
        app_params_free(params);
        if (!ok)
            goto err;
    }

    out = bio_open_default(outfile, 'w', out_bin ? FORMAT_BINARY : FORMAT_TEXT);
    if (out == NULL)
        goto err;

    if (dkm_len <= 0) {
        BIO_printf(bio_err, "Invalid derived key length.\n");
        goto err;
    }
    dkm_bytes = app_malloc(dkm_len, "out buffer");
    if (dkm_bytes == NULL)
        goto err;

    if (!EVP_KDF_derive(ctx, dkm_bytes, dkm_len)) {
        BIO_printf(bio_err, "EVP_KDF_derive failed\n");
        goto err;
    }

    if (out_bin) {
        BIO_write(out, dkm_bytes, dkm_len);
    } else {
        hexout = OPENSSL_buf2hexstr(dkm_bytes, dkm_len);
        BIO_printf(out, "%s\n\n", hexout);
    }

    ret = 0;
err:
    if (ret != 0)
        ERR_print_errors(bio_err);
    OPENSSL_clear_free(dkm_bytes, dkm_len);
    sk_OPENSSL_STRING_free(opts);
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(ctx);
    BIO_free(out);
    OPENSSL_free(hexout);
    return ret;
}
