/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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

#include "apps.h"
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define KEY_PRIVKEY     1
#define KEY_PUBKEY      2
#define KEY_CERT        3

static EVP_PKEY_CTX *init_ctx(int *pkeysize,
                              char *keyfile, int keyform, int key_type,
                              char *passinarg, int pkey_op, ENGINE *e);

static int setup_peer(EVP_PKEY_CTX *ctx, int peerform, const char *file);

static int do_keyop(EVP_PKEY_CTX *ctx, int pkey_op,
                    unsigned char *out, size_t *poutlen,
                    unsigned char *in, size_t inlen);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE, OPT_IN, OPT_OUT,
    OPT_PUBIN, OPT_CERTIN, OPT_ASN1PARSE, OPT_HEXDUMP, OPT_SIGN,
    OPT_VERIFY, OPT_VERIFYRECOVER, OPT_REV, OPT_ENCRYPT, OPT_DECRYPT,
    OPT_DERIVE, OPT_SIGFILE, OPT_INKEY, OPT_PEERKEY, OPT_PASSIN,
    OPT_PEERFORM, OPT_KEYFORM, OPT_PKEYOPT
} OPTION_CHOICE;

OPTIONS pkeyutl_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, '<', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"pubin", OPT_PUBIN, '-', "Input is a public key"},
    {"certin", OPT_CERTIN, '-', "Input is a cert with a public key"},
    {"asn1parse", OPT_ASN1PARSE, '-'},
    {"hexdump", OPT_HEXDUMP, '-', "Hex dump output"},
    {"sign", OPT_SIGN, '-', "Sign with private key"},
    {"verify", OPT_VERIFY, '-', "Verify with public key"},
    {"verifyrecover", OPT_VERIFYRECOVER, '-',
     "Verify with public key, recover original data"},
    {"rev", OPT_REV, '-'},
    {"encrypt", OPT_ENCRYPT, '-', "Encrypt with public key"},
    {"decrypt", OPT_DECRYPT, '-', "Decrypt with private key"},
    {"derive", OPT_DERIVE, '-', "Derive shared secret"},
    {"sigfile", OPT_SIGFILE, '<', "Signature file (verify operation only)"},
    {"inkey", OPT_INKEY, 's', "Input key"},
    {"peerkey", OPT_PEERKEY, 's'},
    {"passin", OPT_PASSIN, 's', "Pass phrase source"},
    {"peerform", OPT_PEERFORM, 'F'},
    {"keyform", OPT_KEYFORM, 'F', "Private key format - default PEM"},
    {"pkeyopt", OPT_PKEYOPT, 's', "Public key options as opt:value"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int pkeyutl_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    ENGINE *e = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    char *infile = NULL, *outfile = NULL, *sigfile = NULL, *passinarg = NULL;
    char hexdump = 0, asn1parse = 0, rev = 0, *prog;
    unsigned char *buf_in = NULL, *buf_out = NULL, *sig = NULL;
    OPTION_CHOICE o;
    int buf_inlen = 0, siglen = -1, keyform = FORMAT_PEM, peerform =
        FORMAT_PEM;
    int keysize = -1, pkey_op = EVP_PKEY_OP_SIGN, key_type = KEY_PRIVKEY;
    int ret = 1, rv = -1;
    size_t buf_outlen;

    prog = opt_init(argc, argv, pkeyutl_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(pkeyutl_options);
            ret = 0;
            goto end;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_SIGFILE:
            sigfile = opt_arg();
            break;
        case OPT_INKEY:
            ctx = init_ctx(&keysize, opt_arg(), keyform, key_type,
                           passinarg, pkey_op, e);
            if (ctx == NULL) {
                BIO_puts(bio_err, "%s: Error initializing context\n");
                ERR_print_errors(bio_err);
                goto opthelp;
            }
            break;
        case OPT_PEERKEY:
            if (!setup_peer(ctx, peerform, opt_arg()))
                goto opthelp;
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_PEERFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &peerform))
                goto opthelp;
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &keyform))
                goto opthelp;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_PUBIN:
            key_type = KEY_PUBKEY;
            break;
        case OPT_CERTIN:
            key_type = KEY_CERT;
            break;
        case OPT_ASN1PARSE:
            asn1parse = 1;
            break;
        case OPT_HEXDUMP:
            hexdump = 1;
            break;
        case OPT_SIGN:
            pkey_op = EVP_PKEY_OP_SIGN;
            break;
        case OPT_VERIFY:
            pkey_op = EVP_PKEY_OP_VERIFY;
            break;
        case OPT_VERIFYRECOVER:
            pkey_op = EVP_PKEY_OP_VERIFYRECOVER;
            break;
        case OPT_REV:
            rev = 1;
            break;
        case OPT_ENCRYPT:
            pkey_op = EVP_PKEY_OP_ENCRYPT;
            break;
        case OPT_DECRYPT:
            pkey_op = EVP_PKEY_OP_DECRYPT;
            break;
        case OPT_DERIVE:
            pkey_op = EVP_PKEY_OP_DERIVE;
            break;
        case OPT_PKEYOPT:
            if (ctx == NULL) {
                BIO_printf(bio_err,
                           "%s: Must have -inkey before -pkeyopt\n", prog);
                goto opthelp;
            }
            if (pkey_ctrl_string(ctx, opt_arg()) <= 0) {
                BIO_printf(bio_err, "%s: Can't set parameter:\n", prog);
                ERR_print_errors(bio_err);
                goto end;
            }
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (ctx == NULL)
        goto opthelp;

    if (sigfile && (pkey_op != EVP_PKEY_OP_VERIFY)) {
        BIO_printf(bio_err,
                   "%s: Signature file specified for non verify\n", prog);
        goto end;
    }

    if (!sigfile && (pkey_op == EVP_PKEY_OP_VERIFY)) {
        BIO_printf(bio_err,
                   "%s: No signature file specified for verify\n", prog);
        goto end;
    }

/* FIXME: seed PRNG only if needed */
    app_RAND_load_file(NULL, 0);

    if (pkey_op != EVP_PKEY_OP_DERIVE) {
        in = bio_open_default(infile, 'r', FORMAT_BINARY);
        if (in == NULL)
            goto end;
    }
    out = bio_open_default(outfile, 'w', FORMAT_BINARY);
    if (out == NULL)
        goto end;

    if (sigfile) {
        BIO *sigbio = BIO_new_file(sigfile, "rb");
        if (!sigbio) {
            BIO_printf(bio_err, "Can't open signature file %s\n", sigfile);
            goto end;
        }
        siglen = bio_to_mem(&sig, keysize * 10, sigbio);
        BIO_free(sigbio);
        if (siglen <= 0) {
            BIO_printf(bio_err, "Error reading signature data\n");
            goto end;
        }
    }

    if (in) {
        /* Read the input data */
        buf_inlen = bio_to_mem(&buf_in, keysize * 10, in);
        if (buf_inlen <= 0) {
            BIO_printf(bio_err, "Error reading input Data\n");
            exit(1);
        }
        if (rev) {
            size_t i;
            unsigned char ctmp;
            size_t l = (size_t)buf_inlen;
            for (i = 0; i < l / 2; i++) {
                ctmp = buf_in[i];
                buf_in[i] = buf_in[l - 1 - i];
                buf_in[l - 1 - i] = ctmp;
            }
        }
    }

    if (pkey_op == EVP_PKEY_OP_VERIFY) {
        rv = EVP_PKEY_verify(ctx, sig, (size_t)siglen,
                             buf_in, (size_t)buf_inlen);
        if (rv == 1) {
            BIO_puts(out, "Signature Verified Successfully\n");
            ret = 0;
        } else
            BIO_puts(out, "Signature Verification Failure\n");
        goto end;
    }
    rv = do_keyop(ctx, pkey_op, NULL, (size_t *)&buf_outlen,
                  buf_in, (size_t)buf_inlen);
    if (rv > 0) {
        buf_out = app_malloc(buf_outlen, "buffer output");
        rv = do_keyop(ctx, pkey_op,
                      buf_out, (size_t *)&buf_outlen,
                      buf_in, (size_t)buf_inlen);
    }
    if (rv <= 0) {
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;

    if (asn1parse) {
        if (!ASN1_parse_dump(out, buf_out, buf_outlen, 1, -1))
            ERR_print_errors(bio_err);
    } else if (hexdump)
        BIO_dump(out, (char *)buf_out, buf_outlen);
    else
        BIO_write(out, buf_out, buf_outlen);

 end:
    EVP_PKEY_CTX_free(ctx);
    BIO_free(in);
    BIO_free_all(out);
    OPENSSL_free(buf_in);
    OPENSSL_free(buf_out);
    OPENSSL_free(sig);
    return ret;
}

static EVP_PKEY_CTX *init_ctx(int *pkeysize,
                              char *keyfile, int keyform, int key_type,
                              char *passinarg, int pkey_op, ENGINE *e)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    char *passin = NULL;
    int rv = -1;
    X509 *x;
    if (((pkey_op == EVP_PKEY_OP_SIGN) || (pkey_op == EVP_PKEY_OP_DECRYPT)
         || (pkey_op == EVP_PKEY_OP_DERIVE))
        && (key_type != KEY_PRIVKEY)) {
        BIO_printf(bio_err, "A private key is needed for this operation\n");
        goto end;
    }
    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }
    switch (key_type) {
    case KEY_PRIVKEY:
        pkey = load_key(keyfile, keyform, 0, passin, e, "Private Key");
        break;

    case KEY_PUBKEY:
        pkey = load_pubkey(keyfile, keyform, 0, NULL, e, "Public Key");
        break;

    case KEY_CERT:
        x = load_cert(keyfile, keyform, NULL, e, "Certificate");
        if (x) {
            pkey = X509_get_pubkey(x);
            X509_free(x);
        }
        break;

    }

    *pkeysize = EVP_PKEY_size(pkey);

    if (!pkey)
        goto end;

    ctx = EVP_PKEY_CTX_new(pkey, e);

    EVP_PKEY_free(pkey);

    if (ctx == NULL)
        goto end;

    switch (pkey_op) {
    case EVP_PKEY_OP_SIGN:
        rv = EVP_PKEY_sign_init(ctx);
        break;

    case EVP_PKEY_OP_VERIFY:
        rv = EVP_PKEY_verify_init(ctx);
        break;

    case EVP_PKEY_OP_VERIFYRECOVER:
        rv = EVP_PKEY_verify_recover_init(ctx);
        break;

    case EVP_PKEY_OP_ENCRYPT:
        rv = EVP_PKEY_encrypt_init(ctx);
        break;

    case EVP_PKEY_OP_DECRYPT:
        rv = EVP_PKEY_decrypt_init(ctx);
        break;

    case EVP_PKEY_OP_DERIVE:
        rv = EVP_PKEY_derive_init(ctx);
        break;
    }

    if (rv <= 0) {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    }

 end:
    OPENSSL_free(passin);
    return ctx;

}

static int setup_peer(EVP_PKEY_CTX *ctx, int peerform, const char *file)
{
    EVP_PKEY *peer = NULL;
    int ret;
    if (!ctx) {
        BIO_puts(bio_err, "-peerkey command before -inkey\n");
        return 0;
    }

    peer = load_pubkey(file, peerform, 0, NULL, NULL, "Peer Key");

    if (!peer) {
        BIO_printf(bio_err, "Error reading peer key %s\n", file);
        ERR_print_errors(bio_err);
        return 0;
    }

    ret = EVP_PKEY_derive_set_peer(ctx, peer);

    EVP_PKEY_free(peer);
    if (ret <= 0)
        ERR_print_errors(bio_err);
    return ret;
}

static int do_keyop(EVP_PKEY_CTX *ctx, int pkey_op,
                    unsigned char *out, size_t *poutlen,
                    unsigned char *in, size_t inlen)
{
    int rv = 0;
    switch (pkey_op) {
    case EVP_PKEY_OP_VERIFYRECOVER:
        rv = EVP_PKEY_verify_recover(ctx, out, poutlen, in, inlen);
        break;

    case EVP_PKEY_OP_SIGN:
        rv = EVP_PKEY_sign(ctx, out, poutlen, in, inlen);
        break;

    case EVP_PKEY_OP_ENCRYPT:
        rv = EVP_PKEY_encrypt(ctx, out, poutlen, in, inlen);
        break;

    case EVP_PKEY_OP_DECRYPT:
        rv = EVP_PKEY_decrypt(ctx, out, poutlen, in, inlen);
        break;

    case EVP_PKEY_OP_DERIVE:
        rv = EVP_PKEY_derive(ctx, out, poutlen);
        break;

    }
    return rv;
}
