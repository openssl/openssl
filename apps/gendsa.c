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
# include <string.h>
# include <sys/types.h>
# include <sys/stat.h>
# include "apps.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/bn.h>
# include <openssl/dsa.h>
# include <openssl/x509.h>
# include <openssl/pem.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_OUT, OPT_PASSOUT, OPT_ENGINE, OPT_RAND, OPT_CIPHER
} OPTION_CHOICE;

OPTIONS gendsa_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [args] dsaparam-file\n"},
    {OPT_HELP_STR, 1, '-', "Valid options are:\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"out", OPT_OUT, '>', "Output the key to the specified file"},
    {"passout", OPT_PASSOUT, 's'},
    {"rand", OPT_RAND, 's',
     "Load the file(s) into the random number generator"},
    {"", OPT_CIPHER, '-', "Encrypt the output with any supported cipher"},
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
# endif
    {NULL}
};

int gendsa_main(int argc, char **argv)
{
    BIO *out = NULL, *in = NULL;
    DSA *dsa = NULL;
    const EVP_CIPHER *enc = NULL;
    char *inrand = NULL, *dsaparams = NULL;
    char *outfile = NULL, *passoutarg = NULL, *passout = NULL, *prog;
    OPTION_CHOICE o;
    int ret = 1, private = 0;

    prog = opt_init(argc, argv, gendsa_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(gendsa_options);
            goto end;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PASSOUT:
            passoutarg = opt_arg();
            break;
        case OPT_ENGINE:
            (void)setup_engine(opt_arg(), 0);
            break;
        case OPT_RAND:
            inrand = opt_arg();
            break;
        case OPT_CIPHER:
            if (!opt_cipher(opt_unknown(), &enc))
                goto end;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();
    private = 1;

    if (argc != 1)
        goto opthelp;
    dsaparams = *argv;

    if (!app_passwd(NULL, passoutarg, NULL, &passout)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    in = bio_open_default(dsaparams, 'r', FORMAT_PEM);
    if (in == NULL)
        goto end2;

    if ((dsa = PEM_read_bio_DSAparams(in, NULL, NULL, NULL)) == NULL) {
        BIO_printf(bio_err, "unable to load DSA parameter file\n");
        goto end;
    }
    BIO_free(in);
    in = NULL;

    out = bio_open_owner(outfile, FORMAT_PEM, private);
    if (out == NULL)
        goto end2;

    if (!app_RAND_load_file(NULL, 1) && inrand == NULL) {
        BIO_printf(bio_err,
                   "warning, not much extra random data, consider using the -rand option\n");
    }
    if (inrand != NULL)
        BIO_printf(bio_err, "%ld semi-random bytes loaded\n",
                   app_RAND_load_files(inrand));

    BIO_printf(bio_err, "Generating DSA key, %d bits\n", BN_num_bits(dsa->p));
    if (!DSA_generate_key(dsa))
        goto end;

    app_RAND_write_file(NULL);

    assert(private);
    if (!PEM_write_bio_DSAPrivateKey(out, dsa, enc, NULL, 0, NULL, passout))
        goto end;
    ret = 0;
 end:
    if (ret != 0)
        ERR_print_errors(bio_err);
 end2:
    BIO_free(in);
    BIO_free_all(out);
    DSA_free(dsa);
    OPENSSL_free(passout);
    return (ret);
}
#else                           /* !OPENSSL_NO_DSA */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
