/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
#ifndef OPENSSL_NO_RSA

# include "apps.h"
# include <string.h>
# include <openssl/err.h>
# include <openssl/pem.h>
# include <openssl/rsa.h>

# define RSA_SIGN        1
# define RSA_VERIFY      2
# define RSA_ENCRYPT     3
# define RSA_DECRYPT     4

# define KEY_PRIVKEY     1
# define KEY_PUBKEY      2
# define KEY_CERT        3

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE, OPT_IN, OPT_OUT, OPT_ASN1PARSE, OPT_HEXDUMP,
    OPT_RAW, OPT_OAEP, OPT_SSL, OPT_PKCS, OPT_X931,
    OPT_SIGN, OPT_VERIFY, OPT_REV, OPT_ENCRYPT, OPT_DECRYPT,
    OPT_PUBIN, OPT_CERTIN, OPT_INKEY, OPT_PASSIN, OPT_KEYFORM
} OPTION_CHOICE;

OPTIONS rsautl_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, '<', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"inkey", OPT_INKEY, '<', "Input key"},
    {"keyform", OPT_KEYFORM, 'F', "Private key format - default PEM"},
    {"pubin", OPT_PUBIN, '-', "Input is an RSA public"},
    {"certin", OPT_CERTIN, '-', "Input is a cert carrying an RSA public key"},
    {"ssl", OPT_SSL, '-', "Use SSL v2 padding"},
    {"raw", OPT_RAW, '-', "Use no padding"},
    {"pkcs", OPT_PKCS, '-', "Use PKCS#1 v1.5 padding (default)"},
    {"oaep", OPT_OAEP, '-', "Use PKCS#1 OAEP"},
    {"sign", OPT_SIGN, '-', "Sign with private key"},
    {"verify", OPT_VERIFY, '-', "Verify with public key"},
    {"asn1parse", OPT_ASN1PARSE, '-'},
    {"hexdump", OPT_HEXDUMP, '-', "Hex dump output"},
    {"x931", OPT_X931, '-', "Use ANSI X9.31 padding"},
    {"rev", OPT_REV, '-'},
    {"encrypt", OPT_ENCRYPT, '-', "Encrypt with public key"},
    {"decrypt", OPT_DECRYPT, '-', "Decrypt with private key"},
    {"passin", OPT_PASSIN, 's', "Pass phrase source"},
# ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
# endif
    {NULL}
};

int rsautl_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    X509 *x;
    char *infile = NULL, *outfile = NULL, *keyfile = NULL;
    char *passinarg = NULL, *passin = NULL, *prog;
    char rsa_mode = RSA_VERIFY, key_type = KEY_PRIVKEY;
    unsigned char *rsa_in = NULL, *rsa_out = NULL, pad = RSA_PKCS1_PADDING;
    int rsa_inlen, keyformat = FORMAT_PEM, keysize, ret = 1;
    int rsa_outlen = 0, hexdump = 0, asn1parse = 0, need_priv = 0, rev = 0;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, rsautl_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(rsautl_options);
            ret = 0;
            goto end;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &keyformat))
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
        case OPT_ASN1PARSE:
            asn1parse = 1;
            break;
        case OPT_HEXDUMP:
            hexdump = 1;
            break;
        case OPT_RAW:
            pad = RSA_NO_PADDING;
            break;
        case OPT_OAEP:
            pad = RSA_PKCS1_OAEP_PADDING;
            break;
        case OPT_SSL:
            pad = RSA_SSLV23_PADDING;
            break;
        case OPT_PKCS:
            pad = RSA_PKCS1_PADDING;
            break;
        case OPT_X931:
            pad = RSA_X931_PADDING;
            break;
        case OPT_SIGN:
            rsa_mode = RSA_SIGN;
            need_priv = 1;
            break;
        case OPT_VERIFY:
            rsa_mode = RSA_VERIFY;
            break;
        case OPT_REV:
            rev = 1;
            break;
        case OPT_ENCRYPT:
            rsa_mode = RSA_ENCRYPT;
            break;
        case OPT_DECRYPT:
            rsa_mode = RSA_DECRYPT;
            need_priv = 1;
            break;
        case OPT_PUBIN:
            key_type = KEY_PUBKEY;
            break;
        case OPT_CERTIN:
            key_type = KEY_CERT;
            break;
        case OPT_INKEY:
            keyfile = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (need_priv && (key_type != KEY_PRIVKEY)) {
        BIO_printf(bio_err, "A private key is needed for this operation\n");
        goto end;
    }

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

/* FIXME: seed PRNG only if needed */
    app_RAND_load_file(NULL, 0);

    switch (key_type) {
    case KEY_PRIVKEY:
        pkey = load_key(keyfile, keyformat, 0, passin, e, "Private Key");
        break;

    case KEY_PUBKEY:
        pkey = load_pubkey(keyfile, keyformat, 0, NULL, e, "Public Key");
        break;

    case KEY_CERT:
        x = load_cert(keyfile, keyformat, NULL, e, "Certificate");
        if (x) {
            pkey = X509_get_pubkey(x);
            X509_free(x);
        }
        break;
    }

    if (!pkey) {
        return 1;
    }

    rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);

    if (!rsa) {
        BIO_printf(bio_err, "Error getting RSA key\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    in = bio_open_default(infile, 'r', FORMAT_BINARY);
    if (in == NULL)
        goto end;
    out = bio_open_default(outfile, 'w', FORMAT_BINARY);
    if (out == NULL)
        goto end;

    keysize = RSA_size(rsa);

    rsa_in = app_malloc(keysize * 2, "hold rsa key");
    rsa_out = app_malloc(keysize, "output rsa key");

    /* Read the input data */
    rsa_inlen = BIO_read(in, rsa_in, keysize * 2);
    if (rsa_inlen <= 0) {
        BIO_printf(bio_err, "Error reading input Data\n");
        goto end;
    }
    if (rev) {
        int i;
        unsigned char ctmp;
        for (i = 0; i < rsa_inlen / 2; i++) {
            ctmp = rsa_in[i];
            rsa_in[i] = rsa_in[rsa_inlen - 1 - i];
            rsa_in[rsa_inlen - 1 - i] = ctmp;
        }
    }
    switch (rsa_mode) {

    case RSA_VERIFY:
        rsa_outlen = RSA_public_decrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;

    case RSA_SIGN:
        rsa_outlen =
            RSA_private_encrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;

    case RSA_ENCRYPT:
        rsa_outlen = RSA_public_encrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;

    case RSA_DECRYPT:
        rsa_outlen =
            RSA_private_decrypt(rsa_inlen, rsa_in, rsa_out, rsa, pad);
        break;

    }

    if (rsa_outlen <= 0) {
        BIO_printf(bio_err, "RSA operation error\n");
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
    if (asn1parse) {
        if (!ASN1_parse_dump(out, rsa_out, rsa_outlen, 1, -1)) {
            ERR_print_errors(bio_err);
        }
    } else if (hexdump)
        BIO_dump(out, (char *)rsa_out, rsa_outlen);
    else
        BIO_write(out, rsa_out, rsa_outlen);
 end:
    RSA_free(rsa);
    BIO_free(in);
    BIO_free_all(out);
    OPENSSL_free(rsa_in);
    OPENSSL_free(rsa_out);
    OPENSSL_free(passin);
    return ret;
}

#else                           /* !OPENSSL_NO_RSA */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif
