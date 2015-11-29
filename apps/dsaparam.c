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
# include <time.h>
# include <string.h>
# include "apps.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/bn.h>
# include <openssl/dsa.h>
# include <openssl/x509.h>
# include <openssl/pem.h>

# ifdef GENCB_TEST

static int stop_keygen_flag = 0;

static void timebomb_sigalarm(int foo)
{
    stop_keygen_flag = 1;
}

# endif

static int dsa_cb(int p, int n, BN_GENCB *cb);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT, OPT_TEXT, OPT_C,
    OPT_NOOUT, OPT_GENKEY, OPT_RAND, OPT_NON_FIPS_ALLOW, OPT_ENGINE,
    OPT_TIMEBOMB
} OPTION_CHOICE;

OPTIONS dsaparam_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'F', "Input format - DER or PEM"},
    {"in", OPT_IN, '<', "Input file"},
    {"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
    {"out", OPT_OUT, '>', "Output file"},
    {"text", OPT_TEXT, '-', "Print as text"},
    {"C", OPT_C, '-', "Output C code"},
    {"noout", OPT_NOOUT, '-', "No output"},
    {"genkey", OPT_GENKEY, '-', "Generate a DSA key"},
    {"rand", OPT_RAND, 's', "Files to use for random number input"},
    {"non-fips-allow", OPT_NON_FIPS_ALLOW, '-'},
# ifdef GENCB_TEST
    {"timebomb", OPT_TIMEBOMB, 'p', "Interrupt keygen after 'pnum' seconds"},
# endif
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine e, possibly a hardware device"},
# endif
    {NULL}
};

int dsaparam_main(int argc, char **argv)
{
    DSA *dsa = NULL;
    BIO *in = NULL, *out = NULL;
    BN_GENCB *cb = NULL;
    int numbits = -1, num = 0, genkey = 0, need_rand = 0, non_fips_allow = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, noout = 0, C = 0;
    int ret = 1, i, text = 0, private = 0;
# ifdef GENCB_TEST
    int timebomb = 0;
# endif
    char *infile = NULL, *outfile = NULL, *prog, *inrand = NULL;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, dsaparam_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(dsaparam_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_ENGINE:
            (void)setup_engine(opt_arg(), 0);
            break;
        case OPT_TIMEBOMB:
# ifdef GENCB_TEST
            timebomb = atoi(opt_arg());
            break;
# endif
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_C:
            C = 1;
            break;
        case OPT_GENKEY:
            genkey = need_rand = 1;
            break;
        case OPT_RAND:
            inrand = opt_arg();
            need_rand = 1;
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_NON_FIPS_ALLOW:
            non_fips_allow = 1;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (argc == 1) {
        if (!opt_int(argv[0], &num))
            goto end;
        /* generate a key */
        numbits = num;
        need_rand = 1;
    }
    private = genkey ? 1 : 0;

    in = bio_open_default(infile, 'r', informat);
    if (in == NULL)
        goto end;
    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL)
        goto end;

    if (need_rand) {
        app_RAND_load_file(NULL, (inrand != NULL));
        if (inrand != NULL)
            BIO_printf(bio_err, "%ld semi-random bytes loaded\n",
                       app_RAND_load_files(inrand));
    }

    if (numbits > 0) {
        cb = BN_GENCB_new();
        if (cb == NULL) {
            BIO_printf(bio_err, "Error allocating BN_GENCB object\n");
            goto end;
        }
        BN_GENCB_set(cb, dsa_cb, bio_err);
        assert(need_rand);
        dsa = DSA_new();
        if (dsa == NULL) {
            BIO_printf(bio_err, "Error allocating DSA object\n");
            goto end;
        }
        if (non_fips_allow)
            dsa->flags |= DSA_FLAG_NON_FIPS_ALLOW;
        BIO_printf(bio_err, "Generating DSA parameters, %d bit long prime\n",
                   num);
        BIO_printf(bio_err, "This could take some time\n");
# ifdef GENCB_TEST
        if (timebomb > 0) {
            struct sigaction act;
            act.sa_handler = timebomb_sigalarm;
            act.sa_flags = 0;
            BIO_printf(bio_err,
                       "(though I'll stop it if not done within %d secs)\n",
                       timebomb);
            if (sigaction(SIGALRM, &act, NULL) != 0) {
                BIO_printf(bio_err, "Error, couldn't set SIGALRM handler\n");
                goto end;
            }
            alarm(timebomb);
        }
# endif
        if (!DSA_generate_parameters_ex(dsa, num, NULL, 0, NULL, NULL, cb)) {
# ifdef GENCB_TEST
            if (stop_keygen_flag) {
                BIO_printf(bio_err, "DSA key generation time-stopped\n");
                /* This is an asked-for behaviour! */
                ret = 0;
                goto end;
            }
# endif
            ERR_print_errors(bio_err);
            BIO_printf(bio_err, "Error, DSA key generation failed\n");
            goto end;
        }
    } else if (informat == FORMAT_ASN1)
        dsa = d2i_DSAparams_bio(in, NULL);
    else
        dsa = PEM_read_bio_DSAparams(in, NULL, NULL, NULL);
    if (dsa == NULL) {
        BIO_printf(bio_err, "unable to load DSA parameters\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    if (text) {
        DSAparams_print(out, dsa);
    }

    if (C) {
        int len = BN_num_bytes(dsa->p);
        int bits_p = BN_num_bits(dsa->p);
        unsigned char *data = app_malloc(len + 20, "BN space");

        BIO_printf(bio_out, "DSA *get_dsa%d()\n{\n", bits_p);
        print_bignum_var(bio_out, dsa->p, "dsap", len, data);
        print_bignum_var(bio_out, dsa->q, "dsaq", len, data);
        print_bignum_var(bio_out, dsa->g, "dsag", len, data);
        BIO_printf(bio_out, "    DSA *dsa = DSA_new();\n"
                            "\n");
        BIO_printf(bio_out, "    if (dsa == NULL)\n"
                            "        return NULL;\n");
        BIO_printf(bio_out, "    dsa->p = BN_bin2bn(dsap_%d, sizeof (dsap_%d), NULL);\n",
               bits_p, bits_p);
        BIO_printf(bio_out, "    dsa->q = BN_bin2bn(dsaq_%d, sizeof (dsaq_%d), NULL);\n",
               bits_p, bits_p);
        BIO_printf(bio_out, "    dsa->g = BN_bin2bn(dsag_%d, sizeof (dsag_%d), NULL);\n",
               bits_p, bits_p);
        BIO_printf(bio_out, "    if (!dsa->p || !dsa->q || !dsa->g) {\n"
                            "        DSA_free(dsa);\n"
                            "        return NULL;\n"
                            "    }\n"
                            "    return(dsa);\n}\n");
    }

    if (!noout) {
        if (outformat == FORMAT_ASN1)
            i = i2d_DSAparams_bio(out, dsa);
        else
            i = PEM_write_bio_DSAparams(out, dsa);
        if (!i) {
            BIO_printf(bio_err, "unable to write DSA parameters\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    if (genkey) {
        DSA *dsakey;

        assert(need_rand);
        if ((dsakey = DSAparams_dup(dsa)) == NULL)
            goto end;
        if (non_fips_allow)
            dsakey->flags |= DSA_FLAG_NON_FIPS_ALLOW;
        if (!DSA_generate_key(dsakey)) {
            ERR_print_errors(bio_err);
            DSA_free(dsakey);
            goto end;
        }
        assert(private);
        if (outformat == FORMAT_ASN1)
            i = i2d_DSAPrivateKey_bio(out, dsakey);
        else
            i = PEM_write_bio_DSAPrivateKey(out, dsakey, NULL, NULL, 0, NULL,
                                            NULL);
        DSA_free(dsakey);
    }
    if (need_rand)
        app_RAND_write_file(NULL);
    ret = 0;
 end:
    BN_GENCB_free(cb);
    BIO_free(in);
    BIO_free_all(out);
    DSA_free(dsa);
    return (ret);
}

static int dsa_cb(int p, int n, BN_GENCB *cb)
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
# ifdef GENCB_TEST
    if (stop_keygen_flag)
        return 0;
# endif
    return 1;
}
#else                           /* !OPENSSL_NO_DSA */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
