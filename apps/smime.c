/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 1999-2004 The OpenSSL Project.  All rights reserved.
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

/* S/MIME utility function */

#include <stdio.h>
#include <string.h>
#include "apps.h"
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

static int save_certs(char *signerfile, STACK_OF(X509) *signers);
static int smime_cb(int ok, X509_STORE_CTX *ctx);

#define SMIME_OP        0x10
#define SMIME_IP        0x20
#define SMIME_SIGNERS   0x40
#define SMIME_ENCRYPT   (1 | SMIME_OP)
#define SMIME_DECRYPT   (2 | SMIME_IP)
#define SMIME_SIGN      (3 | SMIME_OP | SMIME_SIGNERS)
#define SMIME_VERIFY    (4 | SMIME_IP)
#define SMIME_PK7OUT    (5 | SMIME_IP | SMIME_OP)
#define SMIME_RESIGN    (6 | SMIME_IP | SMIME_OP | SMIME_SIGNERS)

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENCRYPT, OPT_DECRYPT, OPT_SIGN, OPT_RESIGN, OPT_VERIFY,
    OPT_PK7OUT, OPT_TEXT, OPT_NOINTERN, OPT_NOVERIFY, OPT_NOCHAIN,
    OPT_NOCERTS, OPT_NOATTR, OPT_NODETACH, OPT_NOSMIMECAP,
    OPT_BINARY, OPT_NOSIGS, OPT_STREAM, OPT_INDEF, OPT_NOINDEF,
    OPT_NOOLDMIME, OPT_CRLFEOL, OPT_RAND, OPT_ENGINE, OPT_PASSIN,
    OPT_TO, OPT_FROM, OPT_SUBJECT, OPT_SIGNER, OPT_RECIP, OPT_MD,
    OPT_CIPHER, OPT_INKEY, OPT_KEYFORM, OPT_CERTFILE, OPT_CAFILE,
    OPT_V_ENUM,
    OPT_CAPATH, OPT_NOCAFILE, OPT_NOCAPATH, OPT_IN, OPT_INFORM, OPT_OUT,
    OPT_OUTFORM, OPT_CONTENT
} OPTION_CHOICE;

OPTIONS smime_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] cert.pem...\n"},
    {OPT_HELP_STR, 1, '-',
        "  cert.pem... recipient certs for encryption\n"},
    {OPT_HELP_STR, 1, '-', "Valid options are:\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"encrypt", OPT_ENCRYPT, '-', "Encrypt message"},
    {"decrypt", OPT_DECRYPT, '-', "Decrypt encrypted message"},
    {"sign", OPT_SIGN, '-', "Sign message"},
    {"verify", OPT_VERIFY, '-', "Verify signed message"},
    {"pk7out", OPT_PK7OUT, '-', "Output PKCS#7 structure"},
    {"nointern", OPT_NOINTERN, '-',
     "Don't search certificates in message for signer"},
    {"nosigs", OPT_NOSIGS, '-', "Don't verify message signature"},
    {"noverify", OPT_NOVERIFY, '-', "Don't verify signers certificate"},
    {"nocerts", OPT_NOCERTS, '-',
     "Don't include signers certificate when signing"},
    {"nodetach", OPT_NODETACH, '-', "Use opaque signing"},
    {"noattr", OPT_NOATTR, '-', "Don't include any signed attributes"},
    {"binary", OPT_BINARY, '-', "Don't translate message to text"},
    {"certfile", OPT_CERTFILE, '<', "Other certificates file"},
    {"signer", OPT_SIGNER, '<', "Signer certificate file"},
    {"recip", OPT_RECIP, '<', "Recipient certificate file for decryption"},
    {"in", OPT_IN, '<', "Input file"},
    {"inform", OPT_INFORM, 'F', "Input format SMIME (default), PEM or DER"},
    {"inkey", OPT_INKEY, '<',
     "Input private key (if not signer or recipient)"},
    {"keyform", OPT_KEYFORM, 'f', "Input private key format (PEM or ENGINE)"},
    {"out", OPT_OUT, '>', "Output file"},
    {"outform", OPT_OUTFORM, 'F',
     "Output format SMIME (default), PEM or DER"},
    {"content", OPT_CONTENT, '<',
     "Supply or override content for detached signature"},
    {"to", OPT_TO, 's', "To address"},
    {"from", OPT_FROM, 's', "From address"},
    {"subject", OPT_SUBJECT, 's', "Subject"},
    {"text", OPT_TEXT, '-', "Include or delete text MIME headers"},
    {"CApath", OPT_CAPATH, '/', "Trusted certificates directory"},
    {"CAfile", OPT_CAFILE, '<', "Trusted certificates file"},
    {"no-CAfile", OPT_NOCAFILE, '-',
     "Do not load the default certificates file"},
    {"no-CApath", OPT_NOCAPATH, '-',
     "Do not load certificates from the default certificates directory"},
    {"resign", OPT_RESIGN, '-'},
    {"nochain", OPT_NOCHAIN, '-'},
    {"nosmimecap", OPT_NOSMIMECAP, '-'},
    {"stream", OPT_STREAM, '-'},
    {"indef", OPT_INDEF, '-'},
    {"noindef", OPT_NOINDEF, '-'},
    {"nooldmime", OPT_NOOLDMIME, '-'},
    {"crlfeol", OPT_CRLFEOL, '-'},
    {"rand", OPT_RAND, 's',
     "Load the file(s) into the random number generator"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"md", OPT_MD, 's'},
    {"", OPT_CIPHER, '-', "Any supported cipher"},
    OPT_V_OPTIONS,
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int smime_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *indata = NULL;
    EVP_PKEY *key = NULL;
    PKCS7 *p7 = NULL;
    STACK_OF(OPENSSL_STRING) *sksigners = NULL, *skkeys = NULL;
    STACK_OF(X509) *encerts = NULL, *other = NULL;
    X509 *cert = NULL, *recip = NULL, *signer = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    const EVP_CIPHER *cipher = NULL;
    const EVP_MD *sign_md = NULL;
    char *CAfile = NULL, *CApath = NULL, *inrand = NULL;
    char *certfile = NULL, *keyfile = NULL, *contfile = NULL, *prog;
    char *infile = NULL, *outfile = NULL, *signerfile = NULL, *recipfile =
        NULL;
    char *passinarg = NULL, *passin = NULL, *to = NULL, *from =
        NULL, *subject = NULL;
    OPTION_CHOICE o;
    int noCApath = 0, noCAfile = 0;
    int flags = PKCS7_DETACHED, operation = 0, ret = 0, need_rand = 0, indef =
        0;
    int informat = FORMAT_SMIME, outformat = FORMAT_SMIME, keyform =
        FORMAT_PEM;
    int vpmtouched = 0, rv = 0;
    ENGINE *e = NULL;

    if ((vpm = X509_VERIFY_PARAM_new()) == NULL)
        return 1;

    prog = opt_init(argc, argv, smime_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(smime_options);
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
        case OPT_ENCRYPT:
            operation = SMIME_ENCRYPT;
            break;
        case OPT_DECRYPT:
            operation = SMIME_DECRYPT;
            break;
        case OPT_SIGN:
            operation = SMIME_SIGN;
            break;
        case OPT_RESIGN:
            operation = SMIME_RESIGN;
            break;
        case OPT_VERIFY:
            operation = SMIME_VERIFY;
            break;
        case OPT_PK7OUT:
            operation = SMIME_PK7OUT;
            break;
        case OPT_TEXT:
            flags |= PKCS7_TEXT;
            break;
        case OPT_NOINTERN:
            flags |= PKCS7_NOINTERN;
            break;
        case OPT_NOVERIFY:
            flags |= PKCS7_NOVERIFY;
            break;
        case OPT_NOCHAIN:
            flags |= PKCS7_NOCHAIN;
            break;
        case OPT_NOCERTS:
            flags |= PKCS7_NOCERTS;
            break;
        case OPT_NOATTR:
            flags |= PKCS7_NOATTR;
            break;
        case OPT_NODETACH:
            flags &= ~PKCS7_DETACHED;
            break;
        case OPT_NOSMIMECAP:
            flags |= PKCS7_NOSMIMECAP;
            break;
        case OPT_BINARY:
            flags |= PKCS7_BINARY;
            break;
        case OPT_NOSIGS:
            flags |= PKCS7_NOSIGS;
            break;
        case OPT_STREAM:
        case OPT_INDEF:
            indef = 1;
            break;
        case OPT_NOINDEF:
            indef = 0;
            break;
        case OPT_NOOLDMIME:
            flags |= PKCS7_NOOLDMIMETYPE;
            break;
        case OPT_CRLFEOL:
            flags |= PKCS7_CRLFEOL;
            break;
        case OPT_RAND:
            inrand = opt_arg();
            need_rand = 1;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_TO:
            to = opt_arg();
            break;
        case OPT_FROM:
            from = opt_arg();
            break;
        case OPT_SUBJECT:
            subject = opt_arg();
            break;
        case OPT_SIGNER:
            /* If previous -signer argument add signer to list */
            if (signerfile) {
                if (sksigners == NULL
                    && (sksigners = sk_OPENSSL_STRING_new_null()) == NULL)
                    goto end;
                sk_OPENSSL_STRING_push(sksigners, signerfile);
                if (keyfile == NULL)
                    keyfile = signerfile;
                if (skkeys == NULL
                    && (skkeys = sk_OPENSSL_STRING_new_null()) == NULL)
                    goto end;
                sk_OPENSSL_STRING_push(skkeys, keyfile);
                keyfile = NULL;
            }
            signerfile = opt_arg();
            break;
        case OPT_RECIP:
            recipfile = opt_arg();
            break;
        case OPT_MD:
            if (!opt_md(opt_arg(), &sign_md))
                goto opthelp;
            break;
        case OPT_CIPHER:
            if (!opt_cipher(opt_unknown(), &cipher))
                goto opthelp;
            break;
        case OPT_INKEY:
            /* If previous -inkey arument add signer to list */
            if (keyfile) {
                if (signerfile == NULL) {
                    BIO_printf(bio_err,
                               "%s: Must have -signer before -inkey\n", prog);
                    goto opthelp;
                }
                if (sksigners == NULL
                    && (sksigners = sk_OPENSSL_STRING_new_null()) == NULL)
                    goto end;
                sk_OPENSSL_STRING_push(sksigners, signerfile);
                signerfile = NULL;
                if (skkeys == NULL
                    && (skkeys = sk_OPENSSL_STRING_new_null()) == NULL)
                    goto end;
                sk_OPENSSL_STRING_push(skkeys, keyfile);
            }
            keyfile = opt_arg();
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyform))
                goto opthelp;
            break;
        case OPT_CERTFILE:
            certfile = opt_arg();
            break;
        case OPT_CAFILE:
            CAfile = opt_arg();
            break;
        case OPT_CAPATH:
            CApath = opt_arg();
            break;
        case OPT_NOCAFILE:
            noCAfile = 1;
            break;
        case OPT_NOCAPATH:
            noCApath = 1;
            break;
        case OPT_CONTENT:
            contfile = opt_arg();
            break;
        case OPT_V_CASES:
            if (!opt_verify(o, vpm))
                goto opthelp;
            vpmtouched++;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (!(operation & SMIME_SIGNERS) && (skkeys || sksigners)) {
        BIO_puts(bio_err, "Multiple signers or keys not allowed\n");
        goto opthelp;
    }

    if (operation & SMIME_SIGNERS) {
        /* Check to see if any final signer needs to be appended */
        if (keyfile && !signerfile) {
            BIO_puts(bio_err, "Illegal -inkey without -signer\n");
            goto opthelp;
        }
        if (signerfile) {
            if (!sksigners
                && (sksigners = sk_OPENSSL_STRING_new_null()) == NULL)
                goto end;
            sk_OPENSSL_STRING_push(sksigners, signerfile);
            if (!skkeys && (skkeys = sk_OPENSSL_STRING_new_null()) == NULL)
                goto end;
            if (!keyfile)
                keyfile = signerfile;
            sk_OPENSSL_STRING_push(skkeys, keyfile);
        }
        if (!sksigners) {
            BIO_printf(bio_err, "No signer certificate specified\n");
            goto opthelp;
        }
        signerfile = NULL;
        keyfile = NULL;
        need_rand = 1;
    } else if (operation == SMIME_DECRYPT) {
        if (!recipfile && !keyfile) {
            BIO_printf(bio_err,
                       "No recipient certificate or key specified\n");
            goto opthelp;
        }
    } else if (operation == SMIME_ENCRYPT) {
        if (argc == 0) {
            BIO_printf(bio_err, "No recipient(s) certificate(s) specified\n");
            goto opthelp;
        }
        need_rand = 1;
    } else if (!operation)
        goto opthelp;

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    if (need_rand) {
        app_RAND_load_file(NULL, (inrand != NULL));
        if (inrand != NULL)
            BIO_printf(bio_err, "%ld semi-random bytes loaded\n",
                       app_RAND_load_files(inrand));
    }

    ret = 2;

    if (!(operation & SMIME_SIGNERS))
        flags &= ~PKCS7_DETACHED;

    if (!(operation & SMIME_OP)) {
        if (flags & PKCS7_BINARY)
            outformat = FORMAT_BINARY;
    }

    if (!(operation & SMIME_IP)) {
        if (flags & PKCS7_BINARY)
            informat = FORMAT_BINARY;
    }

    if (operation == SMIME_ENCRYPT) {
        if (!cipher) {
#ifndef OPENSSL_NO_DES
            cipher = EVP_des_ede3_cbc();
#else
            BIO_printf(bio_err, "No cipher selected\n");
            goto end;
#endif
        }
        encerts = sk_X509_new_null();
        if (!encerts)
            goto end;
        while (*argv) {
            cert = load_cert(*argv, FORMAT_PEM,
                             NULL, e, "recipient certificate file");
            if (cert == NULL)
                goto end;
            sk_X509_push(encerts, cert);
            cert = NULL;
            argv++;
        }
    }

    if (certfile) {
        if ((other = load_certs(certfile, FORMAT_PEM, NULL,
                                 e, "certificate file")) == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (recipfile && (operation == SMIME_DECRYPT)) {
        if ((recip = load_cert(recipfile, FORMAT_PEM, NULL,
                                e, "recipient certificate file")) == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (operation == SMIME_DECRYPT) {
        if (!keyfile)
            keyfile = recipfile;
    } else if (operation == SMIME_SIGN) {
        if (!keyfile)
            keyfile = signerfile;
    } else
        keyfile = NULL;

    if (keyfile) {
        key = load_key(keyfile, keyform, 0, passin, e, "signing key file");
        if (!key)
            goto end;
    }

    in = bio_open_default(infile, 'r', informat);
    if (in == NULL)
        goto end;

    if (operation & SMIME_IP) {
        if (informat == FORMAT_SMIME)
            p7 = SMIME_read_PKCS7(in, &indata);
        else if (informat == FORMAT_PEM)
            p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
        else if (informat == FORMAT_ASN1)
            p7 = d2i_PKCS7_bio(in, NULL);
        else {
            BIO_printf(bio_err, "Bad input format for PKCS#7 file\n");
            goto end;
        }

        if (!p7) {
            BIO_printf(bio_err, "Error reading S/MIME message\n");
            goto end;
        }
        if (contfile) {
            BIO_free(indata);
            if ((indata = BIO_new_file(contfile, "rb")) == NULL) {
                BIO_printf(bio_err, "Can't read content file %s\n", contfile);
                goto end;
            }
        }
    }

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

    if (operation == SMIME_VERIFY) {
        if ((store = setup_verify(CAfile, CApath, noCAfile, noCApath)) == NULL)
            goto end;
        X509_STORE_set_verify_cb(store, smime_cb);
        if (vpmtouched)
            X509_STORE_set1_param(store, vpm);
    }

    ret = 3;

    if (operation == SMIME_ENCRYPT) {
        if (indef)
            flags |= PKCS7_STREAM;
        p7 = PKCS7_encrypt(encerts, in, cipher, flags);
    } else if (operation & SMIME_SIGNERS) {
        int i;
        /*
         * If detached data content we only enable streaming if S/MIME output
         * format.
         */
        if (operation == SMIME_SIGN) {
            if (flags & PKCS7_DETACHED) {
                if (outformat == FORMAT_SMIME)
                    flags |= PKCS7_STREAM;
            } else if (indef)
                flags |= PKCS7_STREAM;
            flags |= PKCS7_PARTIAL;
            p7 = PKCS7_sign(NULL, NULL, other, in, flags);
            if (!p7)
                goto end;
            if (flags & PKCS7_NOCERTS) {
                for (i = 0; i < sk_X509_num(other); i++) {
                    X509 *x = sk_X509_value(other, i);
                    PKCS7_add_certificate(p7, x);
                }
            }
        } else
            flags |= PKCS7_REUSE_DIGEST;
        for (i = 0; i < sk_OPENSSL_STRING_num(sksigners); i++) {
            signerfile = sk_OPENSSL_STRING_value(sksigners, i);
            keyfile = sk_OPENSSL_STRING_value(skkeys, i);
            signer = load_cert(signerfile, FORMAT_PEM, NULL,
                               e, "signer certificate");
            if (!signer)
                goto end;
            key = load_key(keyfile, keyform, 0, passin, e, "signing key file");
            if (!key)
                goto end;
            if (!PKCS7_sign_add_signer(p7, signer, key, sign_md, flags))
                goto end;
            X509_free(signer);
            signer = NULL;
            EVP_PKEY_free(key);
            key = NULL;
        }
        /* If not streaming or resigning finalize structure */
        if ((operation == SMIME_SIGN) && !(flags & PKCS7_STREAM)) {
            if (!PKCS7_final(p7, in, flags))
                goto end;
        }
    }

    if (!p7) {
        BIO_printf(bio_err, "Error creating PKCS#7 structure\n");
        goto end;
    }

    ret = 4;
    if (operation == SMIME_DECRYPT) {
        if (!PKCS7_decrypt(p7, key, recip, out, flags)) {
            BIO_printf(bio_err, "Error decrypting PKCS#7 structure\n");
            goto end;
        }
    } else if (operation == SMIME_VERIFY) {
        STACK_OF(X509) *signers;
        if (PKCS7_verify(p7, other, store, indata, out, flags))
            BIO_printf(bio_err, "Verification successful\n");
        else {
            BIO_printf(bio_err, "Verification failure\n");
            goto end;
        }
        signers = PKCS7_get0_signers(p7, other, flags);
        if (!save_certs(signerfile, signers)) {
            BIO_printf(bio_err, "Error writing signers to %s\n", signerfile);
            ret = 5;
            goto end;
        }
        sk_X509_free(signers);
    } else if (operation == SMIME_PK7OUT)
        PEM_write_bio_PKCS7(out, p7);
    else {
        if (to)
            BIO_printf(out, "To: %s\n", to);
        if (from)
            BIO_printf(out, "From: %s\n", from);
        if (subject)
            BIO_printf(out, "Subject: %s\n", subject);
        if (outformat == FORMAT_SMIME) {
            if (operation == SMIME_RESIGN)
                rv = SMIME_write_PKCS7(out, p7, indata, flags);
            else
                rv = SMIME_write_PKCS7(out, p7, in, flags);
        } else if (outformat == FORMAT_PEM)
            rv = PEM_write_bio_PKCS7_stream(out, p7, in, flags);
        else if (outformat == FORMAT_ASN1)
            rv = i2d_PKCS7_bio_stream(out, p7, in, flags);
        else {
            BIO_printf(bio_err, "Bad output format for PKCS#7 file\n");
            goto end;
        }
        if (rv == 0) {
            BIO_printf(bio_err, "Error writing output\n");
            ret = 3;
            goto end;
        }
    }
    ret = 0;
 end:
    if (need_rand)
        app_RAND_write_file(NULL);
    if (ret)
        ERR_print_errors(bio_err);
    sk_X509_pop_free(encerts, X509_free);
    sk_X509_pop_free(other, X509_free);
    X509_VERIFY_PARAM_free(vpm);
    sk_OPENSSL_STRING_free(sksigners);
    sk_OPENSSL_STRING_free(skkeys);
    X509_STORE_free(store);
    X509_free(cert);
    X509_free(recip);
    X509_free(signer);
    EVP_PKEY_free(key);
    PKCS7_free(p7);
    BIO_free(in);
    BIO_free(indata);
    BIO_free_all(out);
    OPENSSL_free(passin);
    return (ret);
}

static int save_certs(char *signerfile, STACK_OF(X509) *signers)
{
    int i;
    BIO *tmp;
    if (!signerfile)
        return 1;
    tmp = BIO_new_file(signerfile, "w");
    if (!tmp)
        return 0;
    for (i = 0; i < sk_X509_num(signers); i++)
        PEM_write_bio_X509(tmp, sk_X509_value(signers, i));
    BIO_free(tmp);
    return 1;
}

/* Minimal callback just to output policy info (if any) */

static int smime_cb(int ok, X509_STORE_CTX *ctx)
{
    int error;

    error = X509_STORE_CTX_get_error(ctx);

    if ((error != X509_V_ERR_NO_EXPLICIT_POLICY)
        && ((error != X509_V_OK) || (ok != 2)))
        return ok;

    policies_print(ctx);

    return ok;

}
