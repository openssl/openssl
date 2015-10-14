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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

#undef BUFSIZE
#define BUFSIZE 1024*8

int do_fp(BIO *out, unsigned char *buf, BIO *bp, int sep, int binout,
          EVP_PKEY *key, unsigned char *sigin, int siglen,
          const char *sig_name, const char *md_name,
          const char *file, BIO *bmd);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_C, OPT_R, OPT_RAND, OPT_OUT, OPT_SIGN, OPT_PASSIN, OPT_VERIFY,
    OPT_PRVERIFY, OPT_SIGNATURE, OPT_KEYFORM, OPT_ENGINE, OPT_ENGINE_IMPL,
    OPT_HEX, OPT_BINARY, OPT_DEBUG, OPT_FIPS_FINGERPRINT,
    OPT_NON_FIPS_ALLOW, OPT_HMAC, OPT_MAC, OPT_SIGOPT, OPT_MACOPT,
    OPT_DIGEST
} OPTION_CHOICE;

OPTIONS dgst_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] [file...]\n"},
    {OPT_HELP_STR, 1, '-',
        "  file... files to digest (default is stdin)\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"c", OPT_C, '-', "Print the digest with separating colons"},
    {"r", OPT_R, '-', "Print the digest in coreutils format"},
    {"rand", OPT_RAND, 's'},
    {"out", OPT_OUT, '>', "Output to filename rather than stdout"},
    {"passin", OPT_PASSIN, 's'},
    {"sign", OPT_SIGN, '<', "Sign digest using private key in file"},
    {"verify", OPT_VERIFY, '<',
     "Verify a signature using public key in file"},
    {"prverify", OPT_PRVERIFY, '<',
     "Verify a signature using private key in file"},
    {"signature", OPT_SIGNATURE, '<', "File with signature to verify"},
    {"keyform", OPT_KEYFORM, 'f', "Key file format (PEM or ENGINE)"},
    {"hex", OPT_HEX, '-', "Print as hex dump"},
    {"binary", OPT_BINARY, '-', "Print in binary form"},
    {"d", OPT_DEBUG, '-', "Print debug info"},
    {"debug", OPT_DEBUG, '-'},
    {"fips-fingerprint", OPT_FIPS_FINGERPRINT, '-'},
    {"non-fips-allow", OPT_NON_FIPS_ALLOW, '-'},
    {"hmac", OPT_HMAC, 's', "Create hashed MAC with key"},
    {"mac", OPT_MAC, 's', "Create MAC (not neccessarily HMAC)"},
    {"sigopt", OPT_SIGOPT, 's', "Signature parameter in n:v form"},
    {"macopt", OPT_MACOPT, 's', "MAC algorithm parameters in n:v form or key"},
    {"", OPT_DIGEST, '-', "Any supported digest"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine e, possibly a hardware device"},
    {"engine_impl", OPT_ENGINE_IMPL, '-'},
#endif
    {NULL}
};

int dgst_main(int argc, char **argv)
{
    BIO *in = NULL, *inp, *bmd = NULL, *out = NULL;
    ENGINE *e = NULL, *impl = NULL;
    EVP_PKEY *sigkey = NULL;
    STACK_OF(OPENSSL_STRING) *sigopts = NULL, *macopts = NULL;
    char *hmac_key = NULL;
    char *mac_name = NULL;
    char *passinarg = NULL, *passin = NULL;
    const EVP_MD *md = NULL, *m;
    const char *outfile = NULL, *keyfile = NULL, *prog = NULL;
    const char *sigfile = NULL, *randfile = NULL;
    OPTION_CHOICE o;
    int separator = 0, debug = 0, keyform = FORMAT_PEM, siglen = 0;
    int i, ret = 1, out_bin = -1, want_pub = 0, do_verify =
        0, non_fips_allow = 0;
    unsigned char *buf = NULL, *sigbuf = NULL;
    int engine_impl = 0;

    prog = opt_progname(argv[0]);
    buf = app_malloc(BUFSIZE, "I/O buffer");
    md = EVP_get_digestbyname(prog);

    prog = opt_init(argc, argv, dgst_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(dgst_options);
            ret = 0;
            goto end;
        case OPT_C:
            separator = 1;
            break;
        case OPT_R:
            separator = 2;
            break;
        case OPT_RAND:
            randfile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_SIGN:
            keyfile = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_VERIFY:
            keyfile = opt_arg();
            want_pub = do_verify = 1;
            break;
        case OPT_PRVERIFY:
            keyfile = opt_arg();
            do_verify = 1;
            break;
        case OPT_SIGNATURE:
            sigfile = opt_arg();
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyform))
                goto opthelp;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_ENGINE_IMPL:
            engine_impl = 1;
            break;
        case OPT_HEX:
            out_bin = 0;
            break;
        case OPT_BINARY:
            out_bin = 1;
            break;
        case OPT_DEBUG:
            debug = 1;
            break;
        case OPT_FIPS_FINGERPRINT:
            hmac_key = "etaonrishdlcupfm";
            break;
        case OPT_NON_FIPS_ALLOW:
            non_fips_allow = 1;
            break;
        case OPT_HMAC:
            hmac_key = opt_arg();
            break;
        case OPT_MAC:
            mac_name = opt_arg();
            break;
        case OPT_SIGOPT:
            if (!sigopts)
                sigopts = sk_OPENSSL_STRING_new_null();
            if (!sigopts || !sk_OPENSSL_STRING_push(sigopts, opt_arg()))
                goto opthelp;
            break;
        case OPT_MACOPT:
            if (!macopts)
                macopts = sk_OPENSSL_STRING_new_null();
            if (!macopts || !sk_OPENSSL_STRING_push(macopts, opt_arg()))
                goto opthelp;
            break;
        case OPT_DIGEST:
            if (!opt_md(opt_unknown(), &m))
                goto opthelp;
            md = m;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (do_verify && !sigfile) {
        BIO_printf(bio_err,
                   "No signature to verify: use the -signature option\n");
        goto end;
    }
    if (engine_impl)
        impl = e;

    in = BIO_new(BIO_s_file());
    bmd = BIO_new(BIO_f_md());
    if ((in == NULL) || (bmd == NULL)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (debug) {
        BIO_set_callback(in, BIO_debug_callback);
        /* needed for windows 3.1 */
        BIO_set_callback_arg(in, (char *)bio_err);
    }

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    if (out_bin == -1) {
        if (keyfile)
            out_bin = 1;
        else
            out_bin = 0;
    }

    if (randfile)
        app_RAND_load_file(randfile, 0);

    out = bio_open_default(outfile, 'w', out_bin ? FORMAT_BINARY : FORMAT_TEXT);
    if (out == NULL)
        goto end;

    if ((! !mac_name + ! !keyfile + ! !hmac_key) > 1) {
        BIO_printf(bio_err, "MAC and Signing key cannot both be specified\n");
        goto end;
    }

    if (keyfile) {
        if (want_pub)
            sigkey = load_pubkey(keyfile, keyform, 0, NULL, e, "key file");
        else
            sigkey = load_key(keyfile, keyform, 0, passin, e, "key file");
        if (!sigkey) {
            /*
             * load_[pub]key() has already printed an appropriate message
             */
            goto end;
        }
    }

    if (mac_name) {
        EVP_PKEY_CTX *mac_ctx = NULL;
        int r = 0;
        if (!init_gen_str(&mac_ctx, mac_name, impl, 0))
            goto mac_end;
        if (macopts) {
            char *macopt;
            for (i = 0; i < sk_OPENSSL_STRING_num(macopts); i++) {
                macopt = sk_OPENSSL_STRING_value(macopts, i);
                if (pkey_ctrl_string(mac_ctx, macopt) <= 0) {
                    BIO_printf(bio_err,
                               "MAC parameter error \"%s\"\n", macopt);
                    ERR_print_errors(bio_err);
                    goto mac_end;
                }
            }
        }
        if (EVP_PKEY_keygen(mac_ctx, &sigkey) <= 0) {
            BIO_puts(bio_err, "Error generating key\n");
            ERR_print_errors(bio_err);
            goto mac_end;
        }
        r = 1;
 mac_end:
        EVP_PKEY_CTX_free(mac_ctx);
        if (r == 0)
            goto end;
    }

    if (non_fips_allow) {
        EVP_MD_CTX *md_ctx;
        BIO_get_md_ctx(bmd, &md_ctx);
        EVP_MD_CTX_set_flags(md_ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    }

    if (hmac_key) {
        sigkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, impl,
                                      (unsigned char *)hmac_key, -1);
        if (!sigkey)
            goto end;
    }

    if (sigkey) {
        EVP_MD_CTX *mctx = NULL;
        EVP_PKEY_CTX *pctx = NULL;
        int r;
        if (!BIO_get_md_ctx(bmd, &mctx)) {
            BIO_printf(bio_err, "Error getting context\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (do_verify)
            r = EVP_DigestVerifyInit(mctx, &pctx, md, impl, sigkey);
        else
            r = EVP_DigestSignInit(mctx, &pctx, md, impl, sigkey);
        if (!r) {
            BIO_printf(bio_err, "Error setting context\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (sigopts) {
            char *sigopt;
            for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++) {
                sigopt = sk_OPENSSL_STRING_value(sigopts, i);
                if (pkey_ctrl_string(pctx, sigopt) <= 0) {
                    BIO_printf(bio_err, "parameter error \"%s\"\n", sigopt);
                    ERR_print_errors(bio_err);
                    goto end;
                }
            }
        }
    }
    /* we use md as a filter, reading from 'in' */
    else {
        EVP_MD_CTX *mctx = NULL;
        if (!BIO_get_md_ctx(bmd, &mctx)) {
            BIO_printf(bio_err, "Error getting context\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (md == NULL)
            md = EVP_md5();
        if (!EVP_DigestInit_ex(mctx, md, impl)) {
            BIO_printf(bio_err, "Error setting digest\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (sigfile && sigkey) {
        BIO *sigbio = BIO_new_file(sigfile, "rb");
        if (!sigbio) {
            BIO_printf(bio_err, "Error opening signature file %s\n", sigfile);
            ERR_print_errors(bio_err);
            goto end;
        }
        siglen = EVP_PKEY_size(sigkey);
        sigbuf = app_malloc(siglen, "signature buffer");
        siglen = BIO_read(sigbio, sigbuf, siglen);
        BIO_free(sigbio);
        if (siglen <= 0) {
            BIO_printf(bio_err, "Error reading signature file %s\n", sigfile);
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    inp = BIO_push(bmd, in);

    if (md == NULL) {
        EVP_MD_CTX *tctx;
        BIO_get_md_ctx(bmd, &tctx);
        md = EVP_MD_CTX_md(tctx);
    }

    if (argc == 0) {
        BIO_set_fp(in, stdin, BIO_NOCLOSE);
        ret = do_fp(out, buf, inp, separator, out_bin, sigkey, sigbuf,
                    siglen, NULL, NULL, "stdin", bmd);
    } else {
        const char *md_name = NULL, *sig_name = NULL;
        if (!out_bin) {
            if (sigkey) {
                const EVP_PKEY_ASN1_METHOD *ameth;
                ameth = EVP_PKEY_get0_asn1(sigkey);
                if (ameth)
                    EVP_PKEY_asn1_get0_info(NULL, NULL,
                                            NULL, NULL, &sig_name, ameth);
            }
            if (md)
                md_name = EVP_MD_name(md);
        }
        ret = 0;
        for (i = 0; i < argc; i++) {
            int r;
            if (BIO_read_filename(in, argv[i]) <= 0) {
                perror(argv[i]);
                ret++;
                continue;
            } else
                r = do_fp(out, buf, inp, separator, out_bin, sigkey, sigbuf,
                          siglen, sig_name, md_name, argv[i], bmd);
            if (r)
                ret = r;
            (void)BIO_reset(bmd);
        }
    }
 end:
    OPENSSL_clear_free(buf, BUFSIZE);
    BIO_free(in);
    OPENSSL_free(passin);
    BIO_free_all(out);
    EVP_PKEY_free(sigkey);
    sk_OPENSSL_STRING_free(sigopts);
    sk_OPENSSL_STRING_free(macopts);
    OPENSSL_free(sigbuf);
    BIO_free(bmd);
    return (ret);
}

int do_fp(BIO *out, unsigned char *buf, BIO *bp, int sep, int binout,
          EVP_PKEY *key, unsigned char *sigin, int siglen,
          const char *sig_name, const char *md_name,
          const char *file, BIO *bmd)
{
    size_t len;
    int i;

    for (;;) {
        i = BIO_read(bp, (char *)buf, BUFSIZE);
        if (i < 0) {
            BIO_printf(bio_err, "Read Error in %s\n", file);
            ERR_print_errors(bio_err);
            return 1;
        }
        if (i == 0)
            break;
    }
    if (sigin) {
        EVP_MD_CTX *ctx;
        BIO_get_md_ctx(bp, &ctx);
        i = EVP_DigestVerifyFinal(ctx, sigin, (unsigned int)siglen);
        if (i > 0)
            BIO_printf(out, "Verified OK\n");
        else if (i == 0) {
            BIO_printf(out, "Verification Failure\n");
            return 1;
        } else {
            BIO_printf(bio_err, "Error Verifying Data\n");
            ERR_print_errors(bio_err);
            return 1;
        }
        return 0;
    }
    if (key) {
        EVP_MD_CTX *ctx;
        BIO_get_md_ctx(bp, &ctx);
        len = BUFSIZE;
        if (!EVP_DigestSignFinal(ctx, buf, &len)) {
            BIO_printf(bio_err, "Error Signing Data\n");
            ERR_print_errors(bio_err);
            return 1;
        }
    } else {
        len = BIO_gets(bp, (char *)buf, BUFSIZE);
        if ((int)len < 0) {
            ERR_print_errors(bio_err);
            return 1;
        }
    }

    if (binout)
        BIO_write(out, buf, len);
    else if (sep == 2) {
        for (i = 0; i < (int)len; i++)
            BIO_printf(out, "%02x", buf[i]);
        BIO_printf(out, " *%s\n", file);
    } else {
        if (sig_name) {
            BIO_puts(out, sig_name);
            if (md_name)
                BIO_printf(out, "-%s", md_name);
            BIO_printf(out, "(%s)= ", file);
        } else if (md_name)
            BIO_printf(out, "%s(%s)= ", md_name, file);
        else
            BIO_printf(out, "(%s)= ", file);
        for (i = 0; i < (int)len; i++) {
            if (sep && (i != 0))
                BIO_printf(out, ":");
            BIO_printf(out, "%02x", buf[i]);
        }
        BIO_printf(out, "\n");
    }
    return 0;
}
