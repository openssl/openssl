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
#include <openssl/pem.h>
#include <openssl/ssl.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT,
    OPT_TEXT, OPT_CERT, OPT_NOOUT, OPT_CONTEXT
} OPTION_CHOICE;

OPTIONS sess_id_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'F', "Input format - default PEM (DER or PEM)"},
    {"outform", OPT_OUTFORM, 'F',
     "Output format - default PEM (PEM, DER or NSS)"},
    {"in", OPT_IN, 's', "Input file - default stdin"},
    {"out", OPT_OUT, 's', "Output file - default stdout"},
    {"text", OPT_TEXT, '-', "Print ssl session id details"},
    {"cert", OPT_CERT, '-', "Output certificate "},
    {"noout", OPT_NOOUT, '-', "Don't output the encoded session info"},
    {"context", OPT_CONTEXT, 's', "Set the session ID context"},
    {NULL}
};

static SSL_SESSION *load_sess_id(char *file, int format);

int sess_id_main(int argc, char **argv)
{
    SSL_SESSION *x = NULL;
    X509 *peer = NULL;
    BIO *out = NULL;
    char *infile = NULL, *outfile = NULL, *context = NULL, *prog;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM;
    int cert = 0, noout = 0, text = 0, ret = 1, i, num = 0;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, sess_id_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(sess_id_options);
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
        case OPT_TEXT:
            text = ++num;
            break;
        case OPT_CERT:
            cert = ++num;
            break;
        case OPT_NOOUT:
            noout = ++num;
            break;
        case OPT_CONTEXT:
            context = opt_arg();
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    x = load_sess_id(infile, informat);
    if (x == NULL) {
        goto end;
    }
    peer = SSL_SESSION_get0_peer(x);

    if (context) {
        size_t ctx_len = strlen(context);
        if (ctx_len > SSL_MAX_SID_CTX_LENGTH) {
            BIO_printf(bio_err, "Context too long\n");
            goto end;
        }
        if (!SSL_SESSION_set1_id_context(x, (unsigned char *)context,
                    ctx_len)) {
            BIO_printf(bio_err, "Error setting id context\n");
            goto end;
        }
    }

    if (!noout || text) {
        out = bio_open_default(outfile, 'w', outformat);
        if (out == NULL)
            goto end;
    }

    if (text) {
        SSL_SESSION_print(out, x);

        if (cert) {
            if (peer == NULL)
                BIO_puts(out, "No certificate present\n");
            else
                X509_print(out, peer);
        }
    }

    if (!noout && !cert) {
        if (outformat == FORMAT_ASN1)
            i = i2d_SSL_SESSION_bio(out, x);
        else if (outformat == FORMAT_PEM)
            i = PEM_write_bio_SSL_SESSION(out, x);
        else if (outformat == FORMAT_NSS)
            i = SSL_SESSION_print_keylog(out, x);
        else {
            BIO_printf(bio_err, "bad output format specified for outfile\n");
            goto end;
        }
        if (!i) {
            BIO_printf(bio_err, "unable to write SSL_SESSION\n");
            goto end;
        }
    } else if (!noout && (peer != NULL)) { /* just print the certificate */
        if (outformat == FORMAT_ASN1)
            i = (int)i2d_X509_bio(out, peer);
        else if (outformat == FORMAT_PEM)
            i = PEM_write_bio_X509(out, peer);
        else {
            BIO_printf(bio_err, "bad output format specified for outfile\n");
            goto end;
        }
        if (!i) {
            BIO_printf(bio_err, "unable to write X509\n");
            goto end;
        }
    }
    ret = 0;
 end:
    BIO_free_all(out);
    SSL_SESSION_free(x);
    return (ret);
}

static SSL_SESSION *load_sess_id(char *infile, int format)
{
    SSL_SESSION *x = NULL;
    BIO *in = NULL;

    in = bio_open_default(infile, 'r', format);
    if (in == NULL)
        goto end;
    if (format == FORMAT_ASN1)
        x = d2i_SSL_SESSION_bio(in, NULL);
    else
        x = PEM_read_bio_SSL_SESSION(in, NULL, NULL, NULL);
    if (x == NULL) {
        BIO_printf(bio_err, "unable to load SSL_SESSION\n");
        ERR_print_errors(bio_err);
        goto end;
    }

 end:
    BIO_free(in);
    return (x);
}
