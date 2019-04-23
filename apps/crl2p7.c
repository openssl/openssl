/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "apps.h"
#include "progs.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/objects.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT, OPT_NOCRL, OPT_CERTFILE
} OPTION_CHOICE;

const OPTIONS crl2pkcs7_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'F', "DEPRECATED AND IGNORED"},
    {"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
    {"in", OPT_IN, '<', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"nocrl", OPT_NOCRL, '-', "No crl to load, just certs from '-certfile'"},
    {"certfile", OPT_CERTFILE, '<',
     "File of chain of certs to a trusted CA; can be repeated"},
    {NULL}
};

int crl2pkcs7_main(int argc, char **argv)
{
    BIO *out = NULL;
    PKCS7 *p7 = NULL;
    PKCS7_SIGNED *p7s = NULL;
    STACK_OF(OPENSSL_STRING) *certflst = NULL;
    STACK_OF(X509) *cert_stack = NULL;
    STACK_OF(X509_CRL) *crl_stack = NULL;
    X509_CRL *crl = NULL;
    char *infile = NULL, *outfile = NULL, *prog, *certfile;
    int i = 0, informat = FORMAT_PEM, outformat = FORMAT_PEM, ret = 1, nocrl =
        0;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, crl2pkcs7_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(crl2pkcs7_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
                goto opthelp;
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_NOCRL:
            nocrl = 1;
            break;
        case OPT_CERTFILE:
            if ((certflst == NULL)
                && (certflst = sk_OPENSSL_STRING_new_null()) == NULL)
                goto end;
            if (!sk_OPENSSL_STRING_push(certflst, opt_arg()))
                goto end;
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (!nocrl) {
        crl = load_crl(infile);
        if (crl == NULL)
            goto end;
    }

    if ((p7 = PKCS7_new()) == NULL)
        goto end;
    if ((p7s = PKCS7_SIGNED_new()) == NULL)
        goto end;
    p7->type = OBJ_nid2obj(NID_pkcs7_signed);
    p7->d.sign = p7s;
    p7s->contents->type = OBJ_nid2obj(NID_pkcs7_data);

    if (!ASN1_INTEGER_set(p7s->version, 1))
        goto end;
    if ((crl_stack = sk_X509_CRL_new_null()) == NULL)
        goto end;
    p7s->crl = crl_stack;
    if (crl != NULL) {
        sk_X509_CRL_push(crl_stack, crl);
        crl = NULL;             /* now part of p7 for OPENSSL_freeing */
    }

    if ((cert_stack = sk_X509_new_null()) == NULL)
        goto end;
    p7s->cert = cert_stack;

    if (certflst != NULL)
        for (i = 0; i < sk_OPENSSL_STRING_num(certflst); i++) {
            certfile = sk_OPENSSL_STRING_value(certflst, i);
            if (!load_certs(certfile, &cert_stack, NULL, "certificates")) {
                BIO_printf(bio_err, "error loading certificates\n");
                ERR_print_errors(bio_err);
                goto end;
            }
        }

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

    if (outformat == FORMAT_ASN1)
        i = i2d_PKCS7_bio(out, p7);
    else if (outformat == FORMAT_PEM)
        i = PEM_write_bio_PKCS7(out, p7);
    if (!i) {
        BIO_printf(bio_err, "unable to write pkcs7 object\n");
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
 end:
    sk_OPENSSL_STRING_free(certflst);
    BIO_free_all(out);
    PKCS7_free(p7);
    X509_CRL_free(crl);

    return ret;
}
