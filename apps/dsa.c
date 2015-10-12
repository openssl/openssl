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

#include <openssl/opensslconf.h> /* for OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_DSA
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <time.h>
# include "apps.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/dsa.h>
# include <openssl/evp.h>
# include <openssl/x509.h>
# include <openssl/pem.h>
# include <openssl/bn.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT,
    OPT_ENGINE, OPT_PVK_STRONG, OPT_PVK_WEAK,
    OPT_PVK_NONE, OPT_NOOUT, OPT_TEXT, OPT_MODULUS, OPT_PUBIN,
    OPT_PUBOUT, OPT_CIPHER, OPT_PASSIN, OPT_PASSOUT
} OPTION_CHOICE;

OPTIONS dsa_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'F', "Input format, DER PEM PVK"},
    {"outform", OPT_OUTFORM, 'F', "Output format, DER PEM PVK"},
    {"in", OPT_IN, '<', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"noout", OPT_NOOUT, '-', "Don't print key out"},
    {"text", OPT_TEXT, '-', "Print the key in text"},
    {"modulus", OPT_MODULUS, '-', "Print the DSA public value"},
    {"pubin", OPT_PUBIN, '-'},
    {"pubout", OPT_PUBOUT, '-'},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"", OPT_CIPHER, '-', "Any supported cipher"},
# ifndef OPENSSL_NO_RC4
    {"pvk-strong", OPT_PVK_STRONG, '-'},
    {"pvk-weak", OPT_PVK_WEAK, '-'},
    {"pvk-none", OPT_PVK_NONE, '-'},
# endif
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine e, possibly a hardware device"},
# endif
    {NULL}
};

int dsa_main(int argc, char **argv)
{
    BIO *out = NULL;
    DSA *dsa = NULL;
    ENGINE *e = NULL;
    const EVP_CIPHER *enc = NULL;
    char *infile = NULL, *outfile = NULL, *prog;
    char *passin = NULL, *passout = NULL, *passinarg = NULL, *passoutarg = NULL;
    OPTION_CHOICE o;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, text = 0, noout = 0;
    int i, modulus = 0, pubin = 0, pubout = 0, pvk_encr = 2, ret = 1;
    int private = 0;

    prog = opt_init(argc, argv, dsa_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            ret = 0;
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(dsa_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format
                (opt_arg(), OPT_FMT_PEMDER | OPT_FMT_PVK, &informat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUTFORM:
            if (!opt_format
                (opt_arg(), OPT_FMT_PEMDER | OPT_FMT_PVK, &outformat))
                goto opthelp;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_PASSOUT:
            passoutarg = opt_arg();
            break;
#ifndef OPENSSL_NO_RC4
        case OPT_PVK_STRONG:
            pvk_encr = 2;
            break;
        case OPT_PVK_WEAK:
            pvk_encr = 1;
            break;
        case OPT_PVK_NONE:
            pvk_encr = 0;
            break;
#else
        case OPT_PVK_STRONG:
        case OPT_PVK_WEAK:
        case OPT_PVK_NONE:
            break;
#endif
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_MODULUS:
            modulus = 1;
            break;
        case OPT_PUBIN:
            pubin = 1;
            break;
        case OPT_PUBOUT:
            pubout = 1;
            break;
        case OPT_CIPHER:
            if (!opt_cipher(opt_unknown(), &enc))
                goto end;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();
    private = pubin || pubout ? 0 : 1;
    if (text)
        private = 1;

    if (!app_passwd(passinarg, passoutarg, &passin, &passout)) {
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }

    BIO_printf(bio_err, "read DSA key\n");
    {
        EVP_PKEY *pkey;

        if (pubin)
            pkey = load_pubkey(infile, informat, 1, passin, e, "Public Key");
        else
            pkey = load_key(infile, informat, 1, passin, e, "Private Key");

        if (pkey) {
            dsa = EVP_PKEY_get1_DSA(pkey);
            EVP_PKEY_free(pkey);
        }
    }
    if (dsa == NULL) {
        BIO_printf(bio_err, "unable to load Key\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL)
        goto end;

    if (text) {
        assert(private);
        if (!DSA_print(out, dsa, 0)) {
            perror(outfile);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (modulus) {
        BIO_printf(out, "Public Key=");
        BN_print(out, dsa->pub_key);
        BIO_printf(out, "\n");
    }

    if (noout) {
        ret = 0;
        goto end;
    }
    BIO_printf(bio_err, "writing DSA key\n");
    if (outformat == FORMAT_ASN1) {
        if (pubin || pubout)
            i = i2d_DSA_PUBKEY_bio(out, dsa);
        else {
            assert(private);
            i = i2d_DSAPrivateKey_bio(out, dsa);
        }
    } else if (outformat == FORMAT_PEM) {
        if (pubin || pubout)
            i = PEM_write_bio_DSA_PUBKEY(out, dsa);
        else {
            assert(private);
            i = PEM_write_bio_DSAPrivateKey(out, dsa, enc,
                                            NULL, 0, NULL, passout);
        }
# if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_RC4)
    } else if (outformat == FORMAT_MSBLOB || outformat == FORMAT_PVK) {
        EVP_PKEY *pk;
        pk = EVP_PKEY_new();
        EVP_PKEY_set1_DSA(pk, dsa);
        if (outformat == FORMAT_PVK) {
            assert(private);
            i = i2b_PVK_bio(out, pk, pvk_encr, 0, passout);
        }
        else if (pubin || pubout)
            i = i2b_PublicKey_bio(out, pk);
        else {
            assert(private);
            i = i2b_PrivateKey_bio(out, pk);
        }
        EVP_PKEY_free(pk);
# endif
    } else {
        BIO_printf(bio_err, "bad output format specified for outfile\n");
        goto end;
    }
    if (i <= 0) {
        BIO_printf(bio_err, "unable to write private key\n");
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
 end:
    BIO_free_all(out);
    DSA_free(dsa);
    OPENSSL_free(passin);
    OPENSSL_free(passout);
    return (ret);
}
#else                           /* !OPENSSL_NO_DSA */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
