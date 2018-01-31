/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#include "apps.h"
#include "progs.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/store.h>

static int process(const char *uri, const UI_METHOD *uimeth, PW_CB_DATA *uidata,
                   int text, int noout, int recursive, int indent, BIO *out);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP, OPT_ENGINE, OPT_OUT, OPT_PASSIN,
    OPT_NOOUT, OPT_TEXT, OPT_RECURSIVE
} OPTION_CHOICE;

const OPTIONS storeutl_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] uri\nValid options are:\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"out", OPT_OUT, '>', "Output file - default stdout"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"text", OPT_TEXT, '-', "Print a text form of the objects"},
    {"noout", OPT_NOOUT, '-', "No PEM output, just status"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {"r", OPT_RECURSIVE, '-', "Recurse through names"},
    {NULL}
};

int storeutl_main(int argc, char *argv[])
{
    int ret = 1, noout = 0, text = 0, recursive = 0;
    char *outfile = NULL, *passin = NULL, *passinarg = NULL;
    BIO *out = NULL;
    ENGINE *e = NULL;
    OPTION_CHOICE o;
    char *prog = opt_init(argc, argv, storeutl_options);
    PW_CB_DATA pw_cb_data;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(storeutl_options);
            ret = 0;
            goto end;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_RECURSIVE:
            recursive = 1;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (argc == 0) {
        BIO_printf(bio_err, "%s: No URI given, nothing to do...\n", prog);
        goto opthelp;
    }
    if (argc > 1) {
        BIO_printf(bio_err, "%s: Unknown extra parameters after URI\n", prog);
        goto opthelp;
    }

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }
    pw_cb_data.password = passin;
    pw_cb_data.prompt_info = argv[0];

    out = bio_open_default(outfile, 'w', FORMAT_TEXT);
    if (out == NULL)
        goto end;

    ret = process(argv[0], get_ui_method(), &pw_cb_data, text, noout, recursive,
                  0, out);

 end:
    BIO_free_all(out);
    OPENSSL_free(passin);
    release_engine(e);
    return ret;
}

static int indent_printf(int indent, BIO *bio, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);

    ret = BIO_printf(bio, "%*s", indent, "") + BIO_vprintf(bio, format, args);

    va_end(args);
    return ret;
}

static int process(const char *uri, const UI_METHOD *uimeth, PW_CB_DATA *uidata,
                   int text, int noout, int recursive, int indent, BIO *out)
{
    OSSL_STORE_CTX *store_ctx = NULL;
    int ret = 1, items = 0;

    if ((store_ctx = OSSL_STORE_open(uri, uimeth, uidata, NULL, NULL))
        == NULL) {
        BIO_printf(bio_err, "Couldn't open file or uri %s\n", uri);
        ERR_print_errors(bio_err);
        return ret;
    }

    /* From here on, we count errors, and we'll return the count at the end */
    ret = 0;

    for (;;) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(store_ctx);
        int type = info == NULL ? 0 : OSSL_STORE_INFO_get_type(info);
        const char *infostr =
            info == NULL ? NULL : OSSL_STORE_INFO_type_string(type);

        if (info == NULL) {
            if (OSSL_STORE_eof(store_ctx))
                break;

            if (OSSL_STORE_error(store_ctx)) {
                if (recursive)
                    ERR_clear_error();
                else
                    ERR_print_errors(bio_err);
                ret++;
                continue;
            }

            BIO_printf(bio_err,
                       "ERROR: OSSL_STORE_load() returned NULL without "
                       "eof or error indications\n");
            BIO_printf(bio_err, "       This is an error in the loader\n");
            ERR_print_errors(bio_err);
            ret++;
            break;
        }

        if (type == OSSL_STORE_INFO_NAME) {
            const char *name = OSSL_STORE_INFO_get0_NAME(info);
            const char *desc = OSSL_STORE_INFO_get0_NAME_description(info);
            indent_printf(indent, bio_out, "%d: %s: %s\n", items, infostr,
                          name);
            if (desc != NULL)
                indent_printf(indent, bio_out, "%s\n", desc);
        } else {
            indent_printf(indent, bio_out, "%d: %s\n", items, infostr);
        }

        /*
         * Unfortunately, PEM_X509_INFO_write_bio() is sorely lacking in
         * functionality, so we must figure out how exactly to write things
         * ourselves...
         */
        switch (type) {
        case OSSL_STORE_INFO_NAME:
            if (recursive) {
                const char *suburi = OSSL_STORE_INFO_get0_NAME(info);
                ret += process(suburi, uimeth, uidata, text, noout, recursive,
                               indent + 2, out);
            }
            break;
        case OSSL_STORE_INFO_PARAMS:
            if (text)
                EVP_PKEY_print_params(out, OSSL_STORE_INFO_get0_PARAMS(info),
                                      0, NULL);
            if (!noout)
                PEM_write_bio_Parameters(out,
                                         OSSL_STORE_INFO_get0_PARAMS(info));
            break;
        case OSSL_STORE_INFO_PKEY:
            if (text)
                EVP_PKEY_print_private(out, OSSL_STORE_INFO_get0_PKEY(info),
                                       0, NULL);
            if (!noout)
                PEM_write_bio_PrivateKey(out, OSSL_STORE_INFO_get0_PKEY(info),
                                         NULL, NULL, 0, NULL, NULL);
            break;
        case OSSL_STORE_INFO_CERT:
            if (text)
                X509_print(out, OSSL_STORE_INFO_get0_CERT(info));
            if (!noout)
                PEM_write_bio_X509(out, OSSL_STORE_INFO_get0_CERT(info));
            break;
        case OSSL_STORE_INFO_CRL:
            if (text)
                X509_CRL_print(out, OSSL_STORE_INFO_get0_CRL(info));
            if (!noout)
                PEM_write_bio_X509_CRL(out, OSSL_STORE_INFO_get0_CRL(info));
            break;
        default:
            BIO_printf(bio_err, "!!! Unknown code\n");
            ret++;
            break;
        }
        items++;
        OSSL_STORE_INFO_free(info);
    }
    indent_printf(indent, out, "Total found: %d\n", items);

    if (!OSSL_STORE_close(store_ctx)) {
        ERR_print_errors(bio_err);
        ret++;
    }

    return ret;
}
