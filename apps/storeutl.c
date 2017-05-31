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
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/store.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP, OPT_ENGINE, OPT_OUT, OPT_PASSIN,
    OPT_NOOUT, OPT_TEXT
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
    {NULL}
};

int storeutl_main(int argc, char *argv[])
{
    STORE_CTX *store_ctx = NULL;
    int ret = 1, noout = 0, text = 0, items = 0;
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

    if ((store_ctx = STORE_open(argv[0], get_ui_method(), &pw_cb_data, NULL,
                                   NULL)) == NULL) {
        BIO_printf(bio_err, "Couldn't open file or uri %s\n", argv[0]);
        ERR_print_errors(bio_err);
        goto end;
    }

    /* From here on, we count errors, and we'll return the count at the end */
    ret = 0;

    while (!STORE_eof(store_ctx)) {
        STORE_INFO *info = STORE_load(store_ctx);

        if (info == NULL) {
            ERR_print_errors(bio_err);
            ret++;
            break;
        }

        if (STORE_INFO_get_type(info) == STORE_INFO_UNSPECIFIED) {
            goto cont;
        } else if (STORE_INFO_get_type(info) == STORE_INFO_NAME) {
            BIO_printf(bio_out, "%d: %s: %s\n", items,
                       STORE_INFO_type_string(STORE_INFO_get_type(info)),
                       STORE_INFO_get0_NAME(info));
            if (STORE_INFO_get0_NAME_description(info) != NULL)
                BIO_printf(bio_out, "%s\n",
                           STORE_INFO_get0_NAME_description(info));
        } else {
            BIO_printf(bio_out, "%d: %s\n", items,
                       STORE_INFO_type_string(STORE_INFO_get_type(info)));
        }

        /*
         * Unfortunately, PEM_X509_INFO_write_bio() is sorely lacking in
         * functionality, so we must figure out how exactly to write things
         * ourselves...
         */
        switch (STORE_INFO_get_type(info)) {
        case STORE_INFO_NAME:
            break;
        case STORE_INFO_PARAMS:
            if (text)
                EVP_PKEY_print_params(out, STORE_INFO_get0_PARAMS(info),
                                      0, NULL);
            if (!noout)
                PEM_write_bio_Parameters(out, STORE_INFO_get0_PARAMS(info));
            break;
        case STORE_INFO_PKEY:
            if (text)
                EVP_PKEY_print_private(out, STORE_INFO_get0_PKEY(info),
                                       0, NULL);
            if (!noout)
                PEM_write_bio_PrivateKey(out, STORE_INFO_get0_PKEY(info),
                                         NULL, NULL, 0, NULL, NULL);
            break;
        case STORE_INFO_CERT:
            if (text)
                X509_print(out, STORE_INFO_get0_CERT(info));
            if (!noout)
                PEM_write_bio_X509(out, STORE_INFO_get0_CERT(info));
            break;
        case STORE_INFO_CRL:
            if (text)
                X509_CRL_print(out, STORE_INFO_get0_CRL(info));
            if (!noout)
                PEM_write_bio_X509_CRL(out, STORE_INFO_get0_CRL(info));
            break;
        }
        items++;
     cont:
        STORE_INFO_free(info);
    }
    BIO_printf(out, "Total found: %d\n", items);

    if (!STORE_close(store_ctx)) {
        ERR_print_errors(bio_err);
        ret++;
        goto end;
    }

 end:
    BIO_free_all(out);
    OPENSSL_free(passin);
    release_engine(e);
    return ret;
}
