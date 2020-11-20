/*
 * Copyright 2006-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include "apps.h"
#include "progs.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#ifndef OPENSSL_NO_EC
# include <openssl/ec.h>

static OPT_PAIR ec_conv_forms[] = {
    {"compressed", POINT_CONVERSION_COMPRESSED},
    {"uncompressed", POINT_CONVERSION_UNCOMPRESSED},
    {"hybrid", POINT_CONVERSION_HYBRID},
    {NULL}
};

static OPT_PAIR ec_param_enc[] = {
    {"named_curve", OPENSSL_EC_NAMED_CURVE},
    {"explicit", 0},
    {NULL}
};
#endif

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_PASSIN, OPT_PASSOUT, OPT_ENGINE,
    OPT_IN, OPT_OUT, OPT_PUBIN, OPT_PUBOUT, OPT_TEXT_PUB,
    OPT_TEXT, OPT_NOOUT, OPT_MD, OPT_TRADITIONAL, OPT_CHECK, OPT_PUB_CHECK,
    OPT_EC_PARAM_ENC, OPT_EC_CONV_FORM,
    OPT_PROV_ENUM
} OPTION_CHOICE;

const OPTIONS pkey_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {"check", OPT_CHECK, '-', "Check key consistency"},
    {"pubcheck", OPT_PUB_CHECK, '-', "Check public key consistency"},
    {"", OPT_MD, '-', "Any supported cipher"},
    {"ec_param_enc", OPT_EC_PARAM_ENC, 's',
     "Specifies the way the ec parameters are encoded"},
    {"ec_conv_form", OPT_EC_CONV_FORM, 's',
     "Specifies the point conversion form "},

    OPT_SECTION("Input"),
    {"in", OPT_IN, 's', "Input key"},
    {"inform", OPT_INFORM, 'f', "Input format (DER/PEM/P12/ENGINE)"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"pubin", OPT_PUBIN, '-',
     "Read public key from input (default is private key)"},
    {"traditional", OPT_TRADITIONAL, '-',
     "Use traditional format for private keys"},

    OPT_SECTION("Output"),
    {"outform", OPT_OUTFORM, 'F', "Output format (DER or PEM)"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"out", OPT_OUT, '>', "Output file"},
    {"pubout", OPT_PUBOUT, '-', "Output public key, not private"},
    {"text_pub", OPT_TEXT_PUB, '-', "Only output public key components"},
    {"text", OPT_TEXT, '-', "Output in plaintext as well"},
    {"noout", OPT_NOOUT, '-', "Don't output the key"},

    OPT_PROV_OPTIONS,
    {NULL}
};

int pkey_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EVP_PKEY *pkey = NULL;
    const EVP_CIPHER *cipher = NULL;
    char *infile = NULL, *outfile = NULL, *passin = NULL, *passout = NULL;
    char *passinarg = NULL, *passoutarg = NULL, *prog;
    OPTION_CHOICE o;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM;
    int pubin = 0, pubout = 0, pubtext = 0, text = 0, noout = 0, ret = 1;
    int private = 0, traditional = 0, check = 0, pub_check = 0;
#ifndef OPENSSL_NO_EC
    EC_KEY *eckey;
    int ec_asn1_flag = OPENSSL_EC_NAMED_CURVE, new_ec_asn1_flag = 0;
    int i, new_ec_form = 0;
    point_conversion_form_t ec_form = POINT_CONVERSION_UNCOMPRESSED;
#endif

    prog = opt_init(argc, argv, pkey_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(pkey_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat))
                goto opthelp;
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_PASSOUT:
            passoutarg = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PUBIN:
            pubin = pubout = pubtext = 1;
            break;
        case OPT_PUBOUT:
            pubout = 1;
            break;
        case OPT_TEXT_PUB:
            pubtext = text = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TRADITIONAL:
            traditional = 1;
            break;
        case OPT_CHECK:
            check = 1;
            break;
        case OPT_PUB_CHECK:
            pub_check = 1;
            break;
        case OPT_MD:
            if (!opt_cipher(opt_unknown(), &cipher))
                goto opthelp;
            break;
        case OPT_EC_CONV_FORM:
#ifdef OPENSSL_NO_EC
            goto opthelp;
#else
            if (!opt_pair(opt_arg(), ec_conv_forms, &i))
                goto opthelp;
            new_ec_form = 1;
            ec_form = i;
            break;
#endif
        case OPT_EC_PARAM_ENC:
#ifdef OPENSSL_NO_EC
            goto opthelp;
#else
            if (!opt_pair(opt_arg(), ec_param_enc, &i))
                goto opthelp;
            new_ec_asn1_flag = 1;
            ec_asn1_flag = i;
            break;
#endif
        case OPT_PROV_CASES:
            if (!opt_provider(o))
                goto end;
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    private = !noout && !pubout ? 1 : 0;
    if (text && !pubtext)
        private = 1;

    if (!app_passwd(passinarg, passoutarg, &passin, &passout)) {
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }

    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL)
        goto end;

    if (pubin)
        pkey = load_pubkey(infile, informat, 1, passin, e, "Public Key");
    else
        pkey = load_key(infile, informat, 1, passin, e, "key");
    if (pkey == NULL)
        goto end;

#ifndef OPENSSL_NO_EC
    /*
     * TODO: remove this and use a set params call with a 'pkeyopt' command
     * line option instead.
     */
    if (new_ec_form || new_ec_asn1_flag) {
        if ((eckey = EVP_PKEY_get0_EC_KEY(pkey)) == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }
        if (new_ec_form)
            EC_KEY_set_conv_form(eckey, ec_form);

        if (new_ec_asn1_flag)
            EC_KEY_set_asn1_flag(eckey, ec_asn1_flag);
    }
#endif

    if (check || pub_check) {
        int r;
        EVP_PKEY_CTX *ctx;

        ctx = EVP_PKEY_CTX_new(pkey, e);
        if (ctx == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }

        if (check)
            r = EVP_PKEY_check(ctx);
        else
            r = EVP_PKEY_public_check(ctx);

        if (r == 1) {
            BIO_printf(out, "Key is valid\n");
        } else {
            /*
             * Note: at least for RSA keys if this function returns
             * -1, there will be no error reasons.
             */
            unsigned long err;

            BIO_printf(out, "Key is invalid\n");

            while ((err = ERR_peek_error()) != 0) {
                BIO_printf(out, "Detailed error: %s\n",
                           ERR_reason_error_string(err));
                ERR_get_error(); /* remove err from error stack */
            }
        }
        EVP_PKEY_CTX_free(ctx);
    }

    if (!noout) {
        if (outformat == FORMAT_PEM) {
            if (pubout) {
                if (!PEM_write_bio_PUBKEY(out, pkey))
                    goto end;
            } else {
                assert(private);
                if (traditional) {
                    if (!PEM_write_bio_PrivateKey_traditional(out, pkey, cipher,
                                                              NULL, 0, NULL,
                                                              passout))
                        goto end;
                } else {
                    if (!PEM_write_bio_PrivateKey(out, pkey, cipher,
                                                  NULL, 0, NULL, passout))
                        goto end;
                }
            }
        } else if (outformat == FORMAT_ASN1) {
            if (pubout) {
                if (!i2d_PUBKEY_bio(out, pkey))
                    goto end;
            } else {
                assert(private);
                if (!i2d_PrivateKey_bio(out, pkey))
                    goto end;
            }
        } else {
            BIO_printf(bio_err, "Bad format specified for key\n");
            goto end;
        }
    }

    if (text) {
        if (pubtext) {
            if (EVP_PKEY_print_public(out, pkey, 0, NULL) <= 0)
                goto end;
        } else {
            assert(private);
            if (EVP_PKEY_print_private(out, pkey, 0, NULL) <= 0)
                goto end;
        }
    }

    ret = 0;

 end:
    if (ret != 0)
        ERR_print_errors(bio_err);
    EVP_PKEY_free(pkey);
    release_engine(e);
    BIO_free_all(out);
    BIO_free(in);
    OPENSSL_free(passin);
    OPENSSL_free(passout);

    return ret;
}
