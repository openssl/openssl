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

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_RSA
# include <stdio.h>
# include <string.h>
# include <sys/types.h>
# include <sys/stat.h>
# include "apps.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/bn.h>
# include <openssl/rsa.h>
# include <openssl/evp.h>
# include <openssl/x509.h>
# include <openssl/pem.h>
# include <openssl/rand.h>

# define DEFBITS 2048

static int genrsa_cb(int p, int n, BN_GENCB *cb);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_3, OPT_F4, OPT_NON_FIPS_ALLOW, OPT_ENGINE,
    OPT_OUT, OPT_RAND, OPT_PASSOUT, OPT_CIPHER
} OPTION_CHOICE;

OPTIONS genrsa_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"3", OPT_3, '-', "Use 3 for the E value"},
    {"F4", OPT_F4, '-', "Use F4 (0x10001) for the E value"},
    {"f4", OPT_F4, '-', "Use F4 (0x10001) for the E value"},
    {"non-fips-allow", OPT_NON_FIPS_ALLOW, '-'},
    {"out", OPT_OUT, 's', "Output the key to specified file"},
    {"rand", OPT_RAND, 's',
     "Load the file(s) into the random number generator"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"", OPT_CIPHER, '-', "Encrypt the output with any supported cipher"},
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
# endif
    {NULL}
};

int genrsa_main(int argc, char **argv)
{
    BN_GENCB *cb = BN_GENCB_new();
    PW_CB_DATA cb_data;
    ENGINE *e = NULL;
    BIGNUM *bn = BN_new();
    BIO *out = NULL;
    RSA *rsa = NULL;
    const EVP_CIPHER *enc = NULL;
    int ret = 1, non_fips_allow = 0, num = DEFBITS, private = 0;
    unsigned long f4 = RSA_F4;
    char *outfile = NULL, *passoutarg = NULL, *passout = NULL;
    char *inrand = NULL, *prog, *hexe, *dece;
    OPTION_CHOICE o;

    if (bn == NULL || cb == NULL)
        goto end;

    BN_GENCB_set(cb, genrsa_cb, bio_err);

    prog = opt_init(argc, argv, genrsa_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(genrsa_options);
            goto end;
        case OPT_3:
            f4 = 3;
            break;
        case OPT_F4:
            f4 = RSA_F4;
            break;
        case OPT_NON_FIPS_ALLOW:
            non_fips_allow = 1;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_RAND:
            inrand = opt_arg();
            break;
        case OPT_PASSOUT:
            passoutarg = opt_arg();
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

    if (argv[0] && (!opt_int(argv[0], &num) || num <= 0))
        goto end;

    if (!app_passwd(NULL, passoutarg, NULL, &passout)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    out = bio_open_owner(outfile, FORMAT_PEM, private);
    if (out == NULL)
        goto end;

    if (!app_RAND_load_file(NULL, 1) && inrand == NULL
        && !RAND_status()) {
        BIO_printf(bio_err,
                   "warning, not much extra random data, consider using the -rand option\n");
    }
    if (inrand != NULL)
        BIO_printf(bio_err, "%ld semi-random bytes loaded\n",
                   app_RAND_load_files(inrand));

    BIO_printf(bio_err, "Generating RSA private key, %d bit long modulus\n",
               num);
    rsa = e ? RSA_new_method(e) : RSA_new();
    if (rsa == NULL)
        goto end;

    if (non_fips_allow)
        rsa->flags |= RSA_FLAG_NON_FIPS_ALLOW;

    if (!BN_set_word(bn, f4) || !RSA_generate_key_ex(rsa, num, bn, cb))
        goto end;

    app_RAND_write_file(NULL);

    hexe = BN_bn2hex(rsa->e);
    dece = BN_bn2dec(rsa->e);
    if (hexe && dece) {
        BIO_printf(bio_err, "e is %s (0x%s)\n", dece, hexe);
    }
    OPENSSL_free(hexe);
    OPENSSL_free(dece);
    cb_data.password = passout;
    cb_data.prompt_info = outfile;
    assert(private);
    if (!PEM_write_bio_RSAPrivateKey(out, rsa, enc, NULL, 0,
                                     (pem_password_cb *)password_callback,
                                     &cb_data))
        goto end;

    ret = 0;
 end:
    BN_free(bn);
    BN_GENCB_free(cb);
    RSA_free(rsa);
    BIO_free_all(out);
    OPENSSL_free(passout);
    if (ret != 0)
        ERR_print_errors(bio_err);
    return (ret);
}

static int genrsa_cb(int p, int n, BN_GENCB *cb)
{
    char c = '*';

    if (p == 0)
        c = '.';
    if (p == 1)
        c = '+';
    if (p == 2)
        c = '*';
    if (p == 3)
        c = '\n';
    BIO_write(BN_GENCB_get_arg(cb), &c, 1);
    (void)BIO_flush(BN_GENCB_get_arg(cb));
    return 1;
}
#else                           /* !OPENSSL_NO_RSA */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
