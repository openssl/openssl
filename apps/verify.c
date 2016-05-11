/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

static int cb(int ok, X509_STORE_CTX *ctx);
static int check(X509_STORE *ctx, char *file,
                 STACK_OF(X509) *uchain, STACK_OF(X509) *tchain,
                 STACK_OF(X509_CRL) *crls, int show_chain);
static int v_verbose = 0, vflags = 0;

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE, OPT_CAPATH, OPT_CAFILE, OPT_NOCAPATH, OPT_NOCAFILE,
    OPT_UNTRUSTED, OPT_TRUSTED, OPT_CRLFILE, OPT_CRL_DOWNLOAD, OPT_SHOW_CHAIN,
    OPT_V_ENUM,
    OPT_VERBOSE
} OPTION_CHOICE;

OPTIONS verify_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] cert.pem...\n"},
    {OPT_HELP_STR, 1, '-', "Valid options are:\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"verbose", OPT_VERBOSE, '-',
        "Print extra information about the operations being performed."},
    {"CApath", OPT_CAPATH, '/', "A directory of trusted certificates"},
    {"CAfile", OPT_CAFILE, '<', "A file of trusted certificates"},
    {"no-CAfile", OPT_NOCAFILE, '-',
     "Do not load the default certificates file"},
    {"no-CApath", OPT_NOCAPATH, '-',
     "Do not load certificates from the default certificates directory"},
    {"untrusted", OPT_UNTRUSTED, '<', "A file of untrusted certificates"},
    {"trusted", OPT_TRUSTED, '<', "A file of trusted certificates"},
    {"CRLfile", OPT_CRLFILE, '<',
        "File containing one or more CRL's (in PEM format) to load"},
    {"crl_download", OPT_CRL_DOWNLOAD, '-',
        "Attempt to download CRL information for this certificate"},
    {"show_chain", OPT_SHOW_CHAIN, '-',
        "Display information about the certificate chain"},
    OPT_V_OPTIONS,
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int verify_main(int argc, char **argv)
{
    STACK_OF(X509) *untrusted = NULL, *trusted = NULL;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    char *prog, *CApath = NULL, *CAfile = NULL;
    int noCApath = 0, noCAfile = 0;
    int vpmtouched = 0, crl_download = 0, show_chain = 0, i = 0, ret = 1;
    OPTION_CHOICE o;

    if ((vpm = X509_VERIFY_PARAM_new()) == NULL)
        goto end;

    prog = opt_init(argc, argv, verify_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(verify_options);
            BIO_printf(bio_err, "Recognized usages:\n");
            for (i = 0; i < X509_PURPOSE_get_count(); i++) {
                X509_PURPOSE *ptmp;
                ptmp = X509_PURPOSE_get0(i);
                BIO_printf(bio_err, "\t%-10s\t%s\n",
                        X509_PURPOSE_get0_sname(ptmp),
                        X509_PURPOSE_get0_name(ptmp));
            }

            BIO_printf(bio_err, "Recognized verify names:\n");
            for (i = 0; i < X509_VERIFY_PARAM_get_count(); i++) {
                const X509_VERIFY_PARAM *vptmp;
                vptmp = X509_VERIFY_PARAM_get0(i);
                BIO_printf(bio_err, "\t%-10s\n",
                        X509_VERIFY_PARAM_get0_name(vptmp));
            }
            ret = 0;
            goto end;
        case OPT_V_CASES:
            if (!opt_verify(o, vpm))
                goto end;
            vpmtouched++;
            break;
        case OPT_CAPATH:
            CApath = opt_arg();
            break;
        case OPT_CAFILE:
            CAfile = opt_arg();
            break;
        case OPT_NOCAPATH:
            noCApath = 1;
            break;
        case OPT_NOCAFILE:
            noCAfile = 1;
            break;
        case OPT_UNTRUSTED:
            /* Zero or more times */
            if (!load_certs(opt_arg(), &untrusted, FORMAT_PEM, NULL,
                            "untrusted certificates"))
                goto end;
            break;
        case OPT_TRUSTED:
            /* Zero or more times */
            noCAfile = 1;
            noCApath = 1;
            if (!load_certs(opt_arg(), &trusted, FORMAT_PEM, NULL,
                            "trusted certificates"))
                goto end;
            break;
        case OPT_CRLFILE:
            /* Zero or more times */
            if (!load_crls(opt_arg(), &crls, FORMAT_PEM, NULL,
                           "other CRLs"))
                goto end;
            break;
        case OPT_CRL_DOWNLOAD:
            crl_download = 1;
            break;
        case OPT_ENGINE:
            if (setup_engine(opt_arg(), 0) == NULL) {
                /* Failure message already displayed */
                goto end;
            }
            break;
        case OPT_SHOW_CHAIN:
            show_chain = 1;
            break;
        case OPT_VERBOSE:
            v_verbose = 1;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();
    if (trusted != NULL && (CAfile || CApath)) {
        BIO_printf(bio_err,
                   "%s: Cannot use -trusted with -CAfile or -CApath\n",
                   prog);
        goto end;
    }

    if ((store = setup_verify(CAfile, CApath, noCAfile, noCApath)) == NULL)
        goto end;
    X509_STORE_set_verify_cb(store, cb);

    if (vpmtouched)
        X509_STORE_set1_param(store, vpm);

    ERR_clear_error();

    if (crl_download)
        store_setup_crl_download(store);

    ret = 0;
    if (argc < 1) {
        if (check(store, NULL, untrusted, trusted, crls, show_chain) != 1)
            ret = -1;
    } else {
        for (i = 0; i < argc; i++)
            if (check(store, argv[i], untrusted, trusted, crls,
                      show_chain) != 1)
                ret = -1;
    }

 end:
    X509_VERIFY_PARAM_free(vpm);
    X509_STORE_free(store);
    sk_X509_pop_free(untrusted, X509_free);
    sk_X509_pop_free(trusted, X509_free);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    return (ret < 0 ? 2 : ret);
}

static int check(X509_STORE *ctx, char *file,
                 STACK_OF(X509) *uchain, STACK_OF(X509) *tchain,
                 STACK_OF(X509_CRL) *crls, int show_chain)
{
    X509 *x = NULL;
    int i = 0, ret = 0;
    X509_STORE_CTX *csc;
    STACK_OF(X509) *chain = NULL;
    int num_untrusted;

    x = load_cert(file, FORMAT_PEM, "certificate file");
    if (x == NULL)
        goto end;

    csc = X509_STORE_CTX_new();
    if (csc == NULL) {
        printf("error %s: X.509 store context allocation failed\n",
               (file == NULL) ? "stdin" : file);
        goto end;
    }
    X509_STORE_set_flags(ctx, vflags);
    if (!X509_STORE_CTX_init(csc, ctx, x, uchain)) {
        printf("error %s: X.509 store context initialization failed\n",
               (file == NULL) ? "stdin" : file);
        goto end;
    }
    if (tchain)
        X509_STORE_CTX_set0_trusted_stack(csc, tchain);
    if (crls)
        X509_STORE_CTX_set0_crls(csc, crls);
    i = X509_verify_cert(csc);
    if (i > 0 && X509_STORE_CTX_get_error(csc) == X509_V_OK) {
        printf("%s: OK\n", (file == NULL) ? "stdin" : file);
        ret = 1;
        if (show_chain) {
            int j;

            chain = X509_STORE_CTX_get1_chain(csc);
            num_untrusted = X509_STORE_CTX_get_num_untrusted(csc);
            printf("Chain:\n");
            for (j = 0; j < sk_X509_num(chain); j++) {
                X509 *cert = sk_X509_value(chain, j);
                printf("depth=%d: ", j);
                X509_NAME_print_ex_fp(stdout,
                                      X509_get_subject_name(cert),
                                      0, XN_FLAG_ONELINE);
                if (j < num_untrusted)
                    printf(" (untrusted)");
                printf("\n");
            }
            sk_X509_pop_free(chain, X509_free);
        }
    } else {
        printf("error %s: verification failed\n", (file == NULL) ? "stdin" : file);
    }
    X509_STORE_CTX_free(csc);

 end:
    if (i <= 0)
        ERR_print_errors(bio_err);
    X509_free(x);

    return ret;
}

static int cb(int ok, X509_STORE_CTX *ctx)
{
    int cert_error = X509_STORE_CTX_get_error(ctx);
    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);

    if (!ok) {
        if (current_cert) {
            X509_NAME_print_ex(bio_err,
                            X509_get_subject_name(current_cert),
                            0, XN_FLAG_ONELINE);
            BIO_printf(bio_err, "\n");
        }
        BIO_printf(bio_err, "%serror %d at %d depth lookup: %s\n",
               X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path] " : "",
               cert_error,
               X509_STORE_CTX_get_error_depth(ctx),
               X509_verify_cert_error_string(cert_error));
        switch (cert_error) {
        case X509_V_ERR_NO_EXPLICIT_POLICY:
            policies_print(ctx);
        case X509_V_ERR_CERT_HAS_EXPIRED:

            /*
             * since we are just checking the certificates, it is ok if they
             * are self signed. But we should still warn the user.
             */
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            /* Continue after extension errors too */
        case X509_V_ERR_INVALID_CA:
        case X509_V_ERR_INVALID_NON_CA:
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        case X509_V_ERR_INVALID_PURPOSE:
        case X509_V_ERR_CRL_HAS_EXPIRED:
        case X509_V_ERR_CRL_NOT_YET_VALID:
        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
            ok = 1;
        }

        return ok;

    }
    if (cert_error == X509_V_OK && ok == 2)
        policies_print(ctx);
    if (!v_verbose)
        ERR_clear_error();
    return (ok);
}
