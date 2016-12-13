/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
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
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP, OPT_ENGINE, OPT_OUT, OPT_OUTFORM,
    OPT_NOOUT
} OPTION_CHOICE;

const OPTIONS storeutl_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] uri\nValid options are:\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"outform", OPT_OUTFORM, 'f',
     "Output format - default PEM (one of DER, NET or PEM)"},
    {"out", OPT_OUT, '>', "Output file - default stdout"},
    {"noout", OPT_NOOUT, '-', "No output, just status"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int storeutl_main(int argc, char *argv[])
{
    STACK_OF(STORE_INFO) *infos = NULL;
    int ret = 1, noout = 0, i = 0, num = 0;
    char *outfile = NULL;
    int outformat = FORMAT_PEM;
    BIO *out = NULL;
#ifndef OPENSSL_NO_ENGINE
    ENGINE *e = NULL;
#endif
    OPTION_CHOICE o;
    char *prog = opt_init(argc, argv, storeutl_options);

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
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &outformat))
                goto opthelp;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_NOOUT:
            noout = ++num;
            break;
#ifndef OPENSSL_NO_ENGINE
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
#endif
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

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

    infos = STORE_load(argv[0], (pem_password_cb *)password_callback, NULL);
    if (infos == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    for (i = 0; i < sk_STORE_INFO_num(infos); i++) {
        STORE_INFO *info = sk_STORE_INFO_value(infos, i);

        if (info == NULL)
            BIO_printf(bio_err, "STORE_INFO %d is NULL!\n", i);
        else if (STORE_INFO_get_type(info) == STORE_INFO_NAME)
            BIO_printf(bio_out, "%d: %s: %s\n", i,
                       STORE_INFO_type_string(STORE_INFO_get_type(info)),
                       STORE_INFO_get0_NAME(info));
        else
            BIO_printf(bio_out, "%d: %s\n", i,
                       STORE_INFO_type_string(STORE_INFO_get_type(info)));

        if (!noout) {
            X509_INFO xinfo = { 0 };
            X509_PKEY xpkey = { 0 };
            switch (STORE_INFO_get_type(info)) {
            case STORE_INFO_PKEY:
                xpkey.dec_pkey = (EVP_PKEY *)STORE_INFO_get0_PKEY(info);
                xinfo.x_pkey = &xpkey;
                break;
            case STORE_INFO_CERT:
                xinfo.x509 = (X509 *)STORE_INFO_get0_CERT(info);
                break;
            case STORE_INFO_CRL:
                xinfo.crl = (X509_CRL *)STORE_INFO_get0_CRL(info);
                break;
            }
            PEM_X509_INFO_write_bio(out, &xinfo, NULL, NULL, 0,
                                    (pem_password_cb *)password_callback, NULL);
        }
    }

    sk_STORE_INFO_pop_free(infos, STORE_INFO_free);

    ret = 0;
 end:
    BIO_free_all(out);
    release_engine(e);
    return ret;
}
