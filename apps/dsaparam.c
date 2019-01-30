/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_DSA
NON_EMPTY_TRANSLATION_UNIT
#else

# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# include <string.h>
# include "apps.h"
# include "progs.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/bn.h>
# include <openssl/dsa.h>
# include <openssl/x509.h>
# include <openssl/pem.h>

static int dsa_cb(int p, int n, BN_GENCB *cb);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT, OPT_TEXT, OPT_C,
    OPT_NOOUT, OPT_GENKEY, OPT_ENGINE, OPT_R_ENUM
} OPTION_CHOICE;

const OPTIONS dsaparam_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [flags] [numbits [qbits [gindex]]]\n"},
    {OPT_HELP_STR, 1, '-', "The following options are used for parameter generation\n"},
    {OPT_HELP_STR, 1, '-', " numbits\tBit size of prime P\n"},
    {OPT_HELP_STR, 1, '-', " qbits\t\tBit size of subgroup order Q\n"},
    {OPT_HELP_STR, 1, '-', " gindex\t\tIndex used for canonical generation of g\n"},
    {OPT_HELP_STR, 1, '-', "Valid options are:\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'F', "Input format - DER or PEM"},
    {"in", OPT_IN, '<', "Input file"},
    {"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
    {"out", OPT_OUT, '>', "Output file"},
    {"text", OPT_TEXT, '-', "Print as text"},
    {"C", OPT_C, '-', "Output C code"},
    {"noout", OPT_NOOUT, '-', "No output"},
    {"genkey", OPT_GENKEY, '-', "Generate a DSA key"},
    OPT_R_OPTIONS,
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine e, possibly a hardware device"},
# endif
    {NULL}
};

int dsaparam_main(int argc, char **argv)
{
    ENGINE *e = NULL;
    DSA *dsa = NULL;
    BIO *in = NULL, *out = NULL;
    BN_GENCB *cb = NULL;
    int numbits = -1, num = 0, genkey = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, noout = 0, C = 0;
    int ret = 1, i, text = 0, private = 0;
    int qbits = -1, gindex = -1, counter = 0;
    size_t seedlen = 0;
    char *infile = NULL, *outfile = NULL, *prog;
    OPTION_CHOICE o;
    unsigned char *seed = NULL;

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
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_C:
            C = 1;
            break;
        case OPT_GENKEY:
            genkey = 1;
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (argc > 0) {
        if (!opt_int(argv[0], &num) || num < 0)
            goto end;
        /* generate a key */
        numbits = num;

        if (argc > 1) {
            if (!opt_int(argv[1], &num) || num < 0)
                goto end;
            /* The size of q */
            qbits = num;
        }
        if (argc == 3) {
            if (!opt_int(argv[2], &num) || num < 0)
                goto end;
            /* generate a ffc key with a canonical g */
            gindex = num;
        }
    }
    private = genkey ? 1 : 0;

    in = bio_open_default(infile, 'r', informat);
    if (in == NULL)
        goto end;
    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL)
        goto end;

    if (numbits > 0) {
        if (numbits > OPENSSL_DSA_MAX_MODULUS_BITS)
            BIO_printf(bio_err,
                       "Warning: It is not recommended to use more than %d bit for DSA keys.\n"
                       "         Your key size is %d! Larger key size may behave not as expected.\n",
                       OPENSSL_DSA_MAX_MODULUS_BITS, numbits);

        cb = BN_GENCB_new();
        if (cb == NULL) {
            BIO_printf(bio_err, "Error allocating BN_GENCB object\n");
            goto end;
        }
        BN_GENCB_set(cb, dsa_cb, bio_err);
        dsa = DSA_new();
        if (dsa == NULL) {
            BIO_printf(bio_err, "Error allocating DSA object\n");
            goto end;
        }
        BIO_printf(bio_err, "Generating DSA parameters, %d bit long prime\n",
                   numbits);
        BIO_printf(bio_err, "This could take some time\n");
        if (!DSA_generate_ffc_parameters(dsa, 2, numbits, qbits, gindex, cb)) {
            ERR_print_errors(bio_err);
            BIO_printf(bio_err, "Error, DSA key generation failed\n");
            goto end;
        }
        DSA_get0_validate_params(dsa, &seed, &seedlen, &counter, &gindex, NULL);
    } else if (informat == FORMAT_ASN1) {
        dsa = d2i_DSAparams_bio(in, NULL);
    } else {
        dsa = PEM_read_bio_DSAparams(in, NULL, NULL, NULL);
    }
    if (dsa == NULL) {
        BIO_printf(bio_err, "unable to load DSA parameters\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    if (text)
        DSAparams_print(bio_out, dsa);

    if (C) {
        const BIGNUM *p = NULL, *q = NULL, *g = NULL;
        BIGNUM *s = NULL;
        unsigned char *data;
        int len, bits_p, bits_q;

        DSA_get0_pqg(dsa, &p, &q, &g);
        len = BN_num_bytes(p);
        bits_p = BN_num_bits(p);
        bits_q = BN_num_bits(q);

        data = app_malloc(len + 20, "BN space");

        BIO_printf(bio_out, "static DSA *get_dsa%d_%d(void)\n{\n", bits_p,
                   bits_q);
        print_bignum_var(bio_out, p, "dsap", bits_p, data);
        print_bignum_var(bio_out, q, "dsaq", bits_q, data);
        print_bignum_var(bio_out, g, "dsag", bits_p, data);
        if (seed != NULL) {
            s = BN_bin2bn(seed, seedlen, NULL);
            print_bignum_var(bio_out, s, "seed", (int)seedlen * 8, data);
            BIO_printf(bio_out, "    size_t seedlen = %d;\n", (int)seedlen);
            BIO_printf(bio_out, "    int counter = %d;\n", counter);
            BIO_printf(bio_out, "    int gindex = %d;\n", gindex);
        }
        BIO_printf(bio_out, "    BIGNUM *p, *q, *g;\n"
                            "    DSA *dsa = DSA_new();\n\n");
        BIO_printf(bio_out, "    if (dsa == NULL)\n"
                            "        return NULL;\n");
        BIO_printf(bio_out, "    if (!DSA_set0_pqg(dsa, p = "
                            "BN_bin2bn(dsap_%d, sizeof(dsap_%d), NULL),\n",
                   bits_p, bits_p);
        BIO_printf(bio_out, "                           q = BN_bin2bn(dsaq_%d, "
                            "sizeof(dsaq_%d), NULL),\n",
                   bits_q, bits_q);
        BIO_printf(bio_out, "                           g = BN_bin2bn(dsag_%d, "
                            "sizeof(dsag_%d), NULL)))\n",
                   bits_p, bits_p);
        BIO_printf(bio_out, "        goto end;\n");
        if (seed != NULL)
            BIO_printf(bio_out, "    if (!DSA_set0_validate_params(dsa, seed"
                                ", seedlen, counter, gindex))\n"
                                "        goto end;\n");
        BIO_printf(bio_out, "    return dsa;\n");
        BIO_printf(bio_out, "end:\n");
        BIO_printf(bio_out, "    DSA_free(dsa);\n"
                            "    BN_free(p);\n"
                            "    BN_free(q);\n"
                            "    BN_free(g);\n"
                            "    return NULL;\n}\n\n");
        BN_clear_free(s);
        OPENSSL_free(data);
    }

    if (outformat == FORMAT_ASN1 && genkey)
        noout = 1;

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
    if (!text && !C) {
        BIO_printf(bio_out, "\n\n*******************************************************************\n");
        BIO_printf(bio_out, "For validation of p, q & g: the following parameters are required\n");
        BIO_printf(bio_out, "to be saved externally as they are not saved as part of the ASN1 data\n");
        print_array(bio_out, "seed", seedlen, seed);
        BIO_printf(bio_out, "counter = %d\n", counter);
        if (gindex != -1)
            BIO_printf(bio_out, "gindex = %d\n\n", gindex);
    }

    if (genkey) {
        DSA *dsakey;

        if ((dsakey = DSAparams_dup(dsa)) == NULL)
            goto end;
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
    ret = 0;
 end:
    BN_GENCB_free(cb);
    BIO_free(in);
    BIO_free_all(out);
    DSA_free(dsa);
    release_engine(e);
    return ret;
}

static int dsa_cb(int p, int n, BN_GENCB *cb)
{
    static const char symbols[] = ".+*\n";
    char c = (p >= 0 && (size_t)p < sizeof(symbols) - 1) ? symbols[p] : '?';

    BIO_write(BN_GENCB_get_arg(cb), &c, 1);
    (void)BIO_flush(BN_GENCB_get_arg(cb));
    return 1;
}
#endif
