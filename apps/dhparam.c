/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_NO_DEPRECATED_3_0
/* We need to use some deprecated APIs */
# define OPENSSL_SUPPRESS_DEPRECATED
#endif
#include <openssl/opensslconf.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#if !defined(OPENSSL_NO_DSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)
# include <openssl/dsa.h>
#endif

#define DEFBITS 2048

static int gendh_cb(EVP_PKEY_CTX *ctx);
static EVP_PKEY *do_gendh_params(EVP_PKEY_CTX *ctx, int numbits, int g,
                                 int verbose);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT,
    OPT_ENGINE, OPT_CHECK, OPT_TEXT, OPT_NOOUT,
    OPT_DSAPARAM, OPT_C, OPT_2, OPT_3, OPT_5,
    OPT_R_ENUM, OPT_PROV_ENUM
} OPTION_CHOICE;

const OPTIONS dhparam_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] [numbits]\n"},

    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"check", OPT_CHECK, '-', "Check the DH parameters"},
#ifndef OPENSSL_NO_DSA
    {"dsaparam", OPT_DSAPARAM, '-',
     "Read or generate DSA parameters, convert to DH"},
#endif
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine e, possibly a hardware device"},
#endif

    OPT_SECTION("Input"),
    {"in", OPT_IN, '<', "Input file"},
    {"inform", OPT_INFORM, 'F', "Input format, DER or PEM"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output file"},
    {"outform", OPT_OUTFORM, 'F', "Output format, DER or PEM"},
    {"text", OPT_TEXT, '-', "Print a text form of the DH parameters"},
    {"noout", OPT_NOOUT, '-', "Don't output any DH parameters"},
    {"C", OPT_C, '-', "Print C code"},
    {"2", OPT_2, '-', "Generate parameters using 2 as the generator value"},
    {"3", OPT_3, '-', "Generate parameters using 3 as the generator value"},
    {"5", OPT_5, '-', "Generate parameters using 5 as the generator value"},

    OPT_R_OPTIONS,
    OPT_PROV_OPTIONS,

    OPT_PARAMETERS(),
    {"numbits", 0, 0, "Number of bits if generating parameters (optional)"},
    {NULL}
};

int dhparam_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    char *infile = NULL, *outfile = NULL, *prog;
    ENGINE *e = NULL;
#if !defined(OPENSSL_NO_DSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)
    int dsaparam = 0;
#endif
    int i, text = 0, C = 0, ret = 1, num = 0, g = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, check = 0, noout = 0;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, dhparam_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(dhparam_options);
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
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_CHECK:
            check = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_DSAPARAM:
#ifndef OPENSSL_NO_DSA
# ifdef OPENSSL_NO_DEPRECATED_3_0
            BIO_printf(bio_err, "The dsaparam option is deprecated.\n");
# else
            dsaparam = 1;
# endif
#endif
            break;
        case OPT_C:
            C = 1;
            break;
        case OPT_2:
            g = 2;
            break;
        case OPT_3:
            g = 3;
            break;
        case OPT_5:
            g = 5;
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        case OPT_PROV_CASES:
            if (!opt_provider(o))
                goto end;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (argv[0] != NULL && (!opt_int(argv[0], &num) || num <= 0))
        goto end;

    if (g && !num)
        num = DEFBITS;

#if !defined(OPENSSL_NO_DSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)
    if (dsaparam && g) {
        BIO_printf(bio_err,
                   "Error, generator may not be chosen for DSA parameters\n");
        goto end;
    }
#endif

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

    /* DH parameters */
    if (num && !g)
        g = 2;

    if (num) {


#if !defined(OPENSSL_NO_DSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)
        if (dsaparam) {
            ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
            if (ctx == NULL) {
                BIO_printf(bio_err,
                           "Error, DSA parameter generation context allocation failed\n");
                goto end;
            }
            params = do_gendsa_params(ctx, num, 1);
            if (params == NULL)
                goto end;
        } else
#endif
        {
            ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
            if (ctx == NULL) {
                BIO_printf(bio_err,
                           "Error, DH parameter generation context allocation failed\n");
                goto end;
            }
            params = do_gendh_params(ctx, num, g, 1);
            if (params == NULL)
                goto end;
        }
    } else {
        in = bio_open_default(infile, 'r', informat);
        if (in == NULL)
            goto end;

#if !defined(OPENSSL_NO_DSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)
        if (dsaparam) {
            if (informat == FORMAT_ASN1)
                params = d2i_KeyParams_bio(EVP_PKEY_DSA, NULL, in);
            else                /* informat == FORMAT_PEM */
                params = PEM_read_bio_Parameters(in, NULL);

            if (params == NULL
                || EVP_PKEY_base_id(params) != EVP_PKEY_DSA) {
                EVP_PKEY_free(params);
                BIO_printf(bio_err, "Error, unable to load DSA parameters\n");
                goto end;
            }
        } else
#endif
        {
            if (informat == FORMAT_ASN1) {
                /*
                 * We have no PEM header to determine what type of DH params it
                 * is. We'll just try both.
                 */
                params = d2i_KeyParams_bio(EVP_PKEY_DH, NULL, in);
                /* BIO_reset() returns 0 for success for file BIOs only!!! */
                if (params == NULL && BIO_reset(in) == 0)
                    params = d2i_KeyParams_bio(EVP_PKEY_DHX, NULL, in);
            } else {
                /* informat == FORMAT_PEM */
                params = PEM_read_bio_Parameters(in, NULL);
            }

            if (params == NULL
                || (EVP_PKEY_base_id(params) != EVP_PKEY_DH
                    && EVP_PKEY_base_id(params) != EVP_PKEY_DHX)) {
                EVP_PKEY_free(params);
                BIO_printf(bio_err, "Error, unable to load DH parameters\n");
                goto end;
            }
        }
    }

#if !defined(OPENSSL_NO_DSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)
    if (dsaparam) {
        DSA *dsa;
        DH *dh;

        dsa = EVP_PKEY_get0_DSA(params);
        if (dsa == NULL)
            goto end;
        dh = DSA_dup_DH(dsa);
        EVP_PKEY_free(params);
        if ((params = EVP_PKEY_new()) == NULL
            || !EVP_PKEY_assign_DH(params, dh)) {
            DH_free(dh);
            EVP_PKEY_free(params);
            params = NULL;
        }
    }
#endif

    if (text)
        EVP_PKEY_print_params(out, params, 4, NULL);

    if (check) {
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new(params, NULL);
        if (ctx == NULL) {
            BIO_printf(bio_err,
                       "Error, DH key check context allocation failed\n");
            goto end;
        }
        if (!EVP_PKEY_param_check(ctx)) {
            BIO_printf(bio_err, "Error, invalid parameters generated\n");
            goto end;
        }
        BIO_printf(bio_err, "DH parameters appear to be ok.\n");
    }
    if (C) {
        unsigned char *data;
        DH *dh;
        int len, bits;
        const BIGNUM *pbn, *gbn;

        dh = EVP_PKEY_get0_DH(params);
        len = EVP_PKEY_size(params);
        bits = EVP_PKEY_size(params);
        DH_get0_pqg(dh, &pbn, NULL, &gbn);
        data = app_malloc(len, "print a BN");

        BIO_printf(out, "static DH *get_dh%d(void)\n{\n", bits);
        print_bignum_var(out, pbn, "dhp", bits, data);
        print_bignum_var(out, gbn, "dhg", bits, data);
        BIO_printf(out, "    DH *dh = DH_new();\n"
                        "    BIGNUM *p, *g;\n"
                        "\n"
                        "    if (dh == NULL)\n"
                        "        return NULL;\n");
        BIO_printf(out, "    p = BN_bin2bn(dhp_%d, sizeof(dhp_%d), NULL);\n",
                   bits, bits);
        BIO_printf(out, "    g = BN_bin2bn(dhg_%d, sizeof(dhg_%d), NULL);\n",
                   bits, bits);
        BIO_printf(out, "    if (p == NULL || g == NULL\n"
                        "            || !DH_set0_pqg(dh, p, NULL, g)) {\n"
                        "        DH_free(dh);\n"
                        "        BN_free(p);\n"
                        "        BN_free(g);\n"
                        "        return NULL;\n"
                        "    }\n");
        if (DH_get_length(dh) > 0)
            BIO_printf(out,
                        "    if (!DH_set_length(dh, %ld)) {\n"
                        "        DH_free(dh);\n"
                        "        return NULL;\n"
                        "    }\n", DH_get_length(dh));
        BIO_printf(out, "    return dh;\n}\n");
        OPENSSL_free(data);
    }

    if (!noout) {
        if (outformat == FORMAT_ASN1)
            i = i2d_KeyParams_bio(out, params);
        else
            i = PEM_write_bio_Parameters(out, params);
        if (!i) {
            BIO_printf(bio_err, "Error, unable to write DH parameters\n");
            goto end;
        }
    }
    ret = 0;
 end:
    if (ret != 0)
        ERR_print_errors(bio_err);
    BIO_free(in);
    BIO_free_all(out);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);
    release_engine(e);
    return ret;
}

static int gendh_cb(EVP_PKEY_CTX *ctx)
{
    static const char symbols[] = ".+*\n";
    BIO *b = EVP_PKEY_CTX_get_app_data(ctx);
    int p = EVP_PKEY_CTX_get_keygen_info(ctx, 0);
    char c = (p >= 0 && (size_t)p < sizeof(symbols) - 1) ? symbols[p] : '?';

    BIO_write(b, &c, 1);
    (void)BIO_flush(b);
    return 1;
}

static EVP_PKEY *do_gendh_params(EVP_PKEY_CTX *ctx, int numbits, int g, int v)
{
    EVP_PKEY *pkey = NULL;

    if (v) {
        BIO_printf(bio_err,
                   "Generating DH parameters, %d bit long safe prime, generator %d\n"
                   "This is going to take a long time\n",
                   numbits, g);
    }
    if (EVP_PKEY_paramgen_init(ctx) <= 0) {
        BIO_printf(bio_err,
                   "Error, unable to initialise DH param generation\n");
        goto err;
    }
    EVP_PKEY_CTX_set_cb(ctx, gendh_cb);
    EVP_PKEY_CTX_set_app_data(ctx, bio_err);
    if (!EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, numbits)) {
        BIO_printf(bio_err, "Error, unable to set DH prime length\n");
        goto err;
    }
    if (!EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, g)) {
        BIO_printf(bio_err, "Error, unable to set DH generator\n");
        goto err;
    }
    if (EVP_PKEY_paramgen(ctx, &pkey) <= 0) {
        BIO_printf(bio_err, "Error, DH params generation failed\n");
        goto err;
    }
    return pkey;
 err:
    EVP_PKEY_free(pkey);
    return NULL;
}
