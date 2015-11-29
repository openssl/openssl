/*
 * Written by Nils Larsch for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_EC
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include "apps.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/pem.h>

static OPT_PAIR conv_forms[] = {
    {"compressed", POINT_CONVERSION_COMPRESSED},
    {"uncompressed", POINT_CONVERSION_UNCOMPRESSED},
    {"hybrid", POINT_CONVERSION_HYBRID},
    {NULL}
};

static OPT_PAIR param_enc[] = {
    {"named_curve", OPENSSL_EC_NAMED_CURVE},
    {"explicit", 0},
    {NULL}
};

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_ENGINE, OPT_IN, OPT_OUT,
    OPT_NOOUT, OPT_TEXT, OPT_PARAM_OUT, OPT_PUBIN, OPT_PUBOUT,
    OPT_PASSIN, OPT_PASSOUT, OPT_PARAM_ENC, OPT_CONV_FORM, OPT_CIPHER
} OPTION_CHOICE;

OPTIONS ec_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, '<', "Input file"},
    {"inform", OPT_INFORM, 'F', "Input format - DER or PEM"},
    {"out", OPT_OUT, '>', "Output file"},
    {"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
    {"noout", OPT_NOOUT, '-', "Don't print key out"},
    {"text", OPT_TEXT, '-', "Print the key"},
    {"param_out", OPT_PARAM_OUT, '-', "Print the elliptic curve parameters"},
    {"pubin", OPT_PUBIN, '-'},
    {"pubout", OPT_PUBOUT, '-'},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"passout", OPT_PASSOUT, 's', "Output file pass phrase source"},
    {"param_enc", OPT_PARAM_ENC, 's',
     "Specifies the way the ec parameters are encoded"},
    {"conv_form", OPT_CONV_FORM, 's', "Specifies the point conversion form "},
    {"", OPT_CIPHER, '-', "Any supported cipher"},
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
# endif
    {NULL}
};

int ec_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    EC_KEY *eckey = NULL;
    const EC_GROUP *group;
    const EVP_CIPHER *enc = NULL;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    char *infile = NULL, *outfile = NULL, *prog;
    char *passin = NULL, *passout = NULL, *passinarg = NULL, *passoutarg = NULL;
    OPTION_CHOICE o;
    int asn1_flag = OPENSSL_EC_NAMED_CURVE, new_form = 0, new_asn1_flag = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, text = 0, noout = 0;
    int pubin = 0, pubout = 0, param_out = 0, i, ret = 1, private = 0;

    prog = opt_init(argc, argv, ec_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(ec_options);
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
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_PARAM_OUT:
            param_out = 1;
            break;
        case OPT_PUBIN:
            pubin = 1;
            break;
        case OPT_PUBOUT:
            pubout = 1;
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_PASSOUT:
            passoutarg = opt_arg();
            break;
        case OPT_ENGINE:
            (void)setup_engine(opt_arg(), 0);
            break;
        case OPT_CIPHER:
            if (!opt_cipher(opt_unknown(), &enc))
                goto opthelp;
            break;
        case OPT_CONV_FORM:
            if (!opt_pair(opt_arg(), conv_forms, &i))
                goto opthelp;
            new_form = 1;
            form = i;
            break;
        case OPT_PARAM_ENC:
            if (!opt_pair(opt_arg(), param_enc, &i))
                goto opthelp;
            new_asn1_flag = 1;
            asn1_flag = i;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();
    private = param_out || pubin || pubout ? 0 : 1;
    if (text)
        private = 1;

    if (!app_passwd(passinarg, passoutarg, &passin, &passout)) {
        BIO_printf(bio_err, "Error getting passwords\n");
        goto end;
    }

    in = bio_open_default(infile, 'r', informat);
    if (in == NULL)
        goto end;

    BIO_printf(bio_err, "read EC key\n");
    if (informat == FORMAT_ASN1) {
        if (pubin)
            eckey = d2i_EC_PUBKEY_bio(in, NULL);
        else
            eckey = d2i_ECPrivateKey_bio(in, NULL);
    } else {
        if (pubin)
            eckey = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, NULL);
        else
            eckey = PEM_read_bio_ECPrivateKey(in, NULL, NULL, passin);
    }
    if (eckey == NULL) {
        BIO_printf(bio_err, "unable to load Key\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL)
        goto end;

    group = EC_KEY_get0_group(eckey);

    if (new_form)
        EC_KEY_set_conv_form(eckey, form);

    if (new_asn1_flag)
        EC_KEY_set_asn1_flag(eckey, asn1_flag);

    if (text) {
        assert(private);
        if (!EC_KEY_print(out, eckey, 0)) {
            perror(outfile);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (noout) {
        ret = 0;
        goto end;
    }

    BIO_printf(bio_err, "writing EC key\n");
    if (outformat == FORMAT_ASN1) {
        if (param_out)
            i = i2d_ECPKParameters_bio(out, group);
        else if (pubin || pubout)
            i = i2d_EC_PUBKEY_bio(out, eckey);
        else {
            assert(private);
            i = i2d_ECPrivateKey_bio(out, eckey);
        }
    } else {
        if (param_out)
            i = PEM_write_bio_ECPKParameters(out, group);
        else if (pubin || pubout)
            i = PEM_write_bio_EC_PUBKEY(out, eckey);
        else {
            assert(private);
            i = PEM_write_bio_ECPrivateKey(out, eckey, enc,
                                           NULL, 0, NULL, passout);
        }
    }

    if (!i) {
        BIO_printf(bio_err, "unable to write private key\n");
        ERR_print_errors(bio_err);
    } else
        ret = 0;
 end:
    BIO_free(in);
    BIO_free_all(out);
    EC_KEY_free(eckey);
    OPENSSL_free(passin);
    OPENSSL_free(passout);
    return (ret);
}
#else                           /* !OPENSSL_NO_EC */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
