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
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#ifndef OPENSSL_NO_COMP
# include <openssl/comp.h>
#endif
#include <ctype.h>

#undef SIZE
#undef BSIZE
#define SIZE    (512)
#define BSIZE   (8*1024)

static int set_hex(char *in, unsigned char *out, int size);
static void show_ciphers(const OBJ_NAME *name, void *bio_);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_E, OPT_IN, OPT_OUT, OPT_PASS, OPT_ENGINE, OPT_D, OPT_P, OPT_V,
    OPT_NOPAD, OPT_SALT, OPT_NOSALT, OPT_DEBUG, OPT_UPPER_P, OPT_UPPER_A,
    OPT_A, OPT_Z, OPT_BUFSIZE, OPT_K, OPT_KFILE, OPT_UPPER_K, OPT_NONE,
    OPT_UPPER_S, OPT_IV, OPT_MD, OPT_NON_FIPS_ALLOW, OPT_CIPHER
} OPTION_CHOICE;

OPTIONS enc_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, '<', "Input file"},
    {"out", OPT_OUT, '>', "Output file"},
    {"pass", OPT_PASS, 's', "Passphrase source"},
    {"e", OPT_E, '-', "Encrypt"},
    {"d", OPT_D, '-', "Decrypt"},
    {"p", OPT_P, '-', "Print the iv/key"},
    {"P", OPT_UPPER_P, '-', "Print the iv/key and exit"},
    {"v", OPT_V, '-'},
    {"nopad", OPT_NOPAD, '-', "Disable standard block padding"},
    {"salt", OPT_SALT, '-'},
    {"nosalt", OPT_NOSALT, '-'},
    {"debug", OPT_DEBUG, '-'},
    {"A", OPT_UPPER_A, '-'},
    {"a", OPT_A, '-', "base64 encode/decode, depending on encryption flag"},
    {"base64", OPT_A, '-', "Base64 output as a single line"},
    {"bufsize", OPT_BUFSIZE, 's', "Buffer size"},
    {"k", OPT_K, 's', "Passphrase"},
    {"kfile", OPT_KFILE, '<', "Fead passphrase from file"},
    {"K", OPT_UPPER_K, 's', "Raw key, in hex"},
    {"S", OPT_UPPER_S, 's', "Salt, in hex"},
    {"iv", OPT_IV, 's', "IV in hex"},
    {"md", OPT_MD, 's', "Use specified digest to create key from passphrase"},
    {"non-fips-allow", OPT_NON_FIPS_ALLOW, '-'},
    {"none", OPT_NONE, '-', "Don't encrypt"},
    {"", OPT_CIPHER, '-', "Any supported cipher"},
#ifdef ZLIB
    {"z", OPT_Z, '-', "Use zlib as the 'encryption'"},
#endif
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int enc_main(int argc, char **argv)
{
    static char buf[128];
    static const char magic[] = "Salted__";
    BIO *in = NULL, *out = NULL, *b64 = NULL, *benc = NULL, *rbio =
        NULL, *wbio = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL, *c;
    const EVP_MD *dgst = NULL;
    char *hkey = NULL, *hiv = NULL, *hsalt = NULL, *p;
    char *infile = NULL, *outfile = NULL, *prog;
    char *str = NULL, *passarg = NULL, *pass = NULL, *strbuf = NULL;
    char mbuf[sizeof magic - 1];
    OPTION_CHOICE o;
    int bsize = BSIZE, verbose = 0, debug = 0, olb64 = 0, nosalt = 0;
    int enc = 1, printkey = 0, i, k;
    int base64 = 0, informat = FORMAT_BINARY, outformat = FORMAT_BINARY;
    int ret = 1, inl, nopad = 0, non_fips_allow = 0;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    unsigned char *buff = NULL, salt[PKCS5_SALT_LEN];
    unsigned long n;
#ifdef ZLIB
    int do_zlib = 0;
    BIO *bzl = NULL;
#endif

    /* first check the program name */
    prog = opt_progname(argv[0]);
    if (strcmp(prog, "base64") == 0)
        base64 = 1;
#ifdef ZLIB
    else if (strcmp(prog, "zlib") == 0)
        do_zlib = 1;
#endif
    else {
        cipher = EVP_get_cipherbyname(prog);
        if (cipher == NULL && strcmp(prog, "enc") != 0) {
            BIO_printf(bio_err, "%s is not a known cipher\n", prog);
            goto end;
        }
    }

    prog = opt_init(argc, argv, enc_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(enc_options);
            ret = 0;
            BIO_printf(bio_err, "Cipher Types\n");
            OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH,
                                   show_ciphers, bio_err);
            BIO_printf(bio_err, "\n");
            goto end;
        case OPT_E:
            enc = 1;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PASS:
            passarg = opt_arg();
            break;
        case OPT_ENGINE:
            (void)setup_engine(opt_arg(), 0);
            break;
        case OPT_D:
            enc = 0;
            break;
        case OPT_P:
            printkey = 1;
            break;
        case OPT_V:
            verbose = 1;
            break;
        case OPT_NOPAD:
            nopad = 1;
            break;
        case OPT_SALT:
            nosalt = 0;
            break;
        case OPT_NOSALT:
            nosalt = 1;
            break;
        case OPT_DEBUG:
            debug = 1;
            break;
        case OPT_UPPER_P:
            printkey = 2;
            break;
        case OPT_UPPER_A:
            olb64 = 1;
            break;
        case OPT_A:
            base64 = 1;
            break;
        case OPT_Z:
#ifdef ZLIB
            do_zlib = 1;
#endif
            break;
        case OPT_BUFSIZE:
            p = opt_arg();
            i = (int)strlen(p) - 1;
            k = i >= 1 && p[i] == 'k';
            if (k)
                p[i] = '\0';
            if (!opt_ulong(opt_arg(), &n))
                goto opthelp;
            if (k)
                n *= 1024;
            bsize = (int)n;
            break;
        case OPT_K:
            str = opt_arg();
            break;
        case OPT_KFILE:
            in = bio_open_default(opt_arg(), 'r', FORMAT_TEXT);
            if (in == NULL)
                goto opthelp;
            i = BIO_gets(in, buf, sizeof buf);
            BIO_free(in);
            in = NULL;
            if (i <= 0) {
                BIO_printf(bio_err,
                           "%s Can't read key from %s\n", prog, opt_arg());
                goto opthelp;
            }
            while (--i > 0 && (buf[i] == '\r' || buf[i] == '\n'))
                buf[i] = '\0';
            if (i <= 0) {
                BIO_printf(bio_err, "%s: zero length password\n", prog);
                goto opthelp;
            }
            str = buf;
            break;
        case OPT_UPPER_K:
            hkey = opt_arg();
            break;
        case OPT_UPPER_S:
            hsalt = opt_arg();
            break;
        case OPT_IV:
            hiv = opt_arg();
            break;
        case OPT_MD:
            if (!opt_md(opt_arg(), &dgst))
                goto opthelp;
            break;
        case OPT_NON_FIPS_ALLOW:
            non_fips_allow = 1;
            break;
        case OPT_CIPHER:
            if (!opt_cipher(opt_unknown(), &c))
                goto opthelp;
            cipher = c;
            break;
        case OPT_NONE:
            cipher = NULL;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (cipher && EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
        BIO_printf(bio_err, "%s: AEAD ciphers not supported\n", prog);
        goto end;
    }

    if (cipher && (EVP_CIPHER_mode(cipher) == EVP_CIPH_XTS_MODE)) {
        BIO_printf(bio_err, "%s XTS ciphers not supported\n", prog);
        goto end;
    }

    if (dgst == NULL)
        dgst = EVP_md5();

    /* It must be large enough for a base64 encoded line */
    if (base64 && bsize < 80)
        bsize = 80;
    if (verbose)
        BIO_printf(bio_err, "bufsize=%d\n", bsize);

    if (base64) {
        if (enc)
            outformat = FORMAT_BASE64;
        else
            informat = FORMAT_BASE64;
    }

    strbuf = app_malloc(SIZE, "strbuf");
    buff = app_malloc(EVP_ENCODE_LENGTH(bsize), "evp buffer");

    if (debug) {
        BIO_set_callback(in, BIO_debug_callback);
        BIO_set_callback(out, BIO_debug_callback);
        BIO_set_callback_arg(in, (char *)bio_err);
        BIO_set_callback_arg(out, (char *)bio_err);
    }

    if (infile == NULL) {
        unbuffer(stdin);
        in = dup_bio_in(informat);
    } else
        in = bio_open_default(infile, 'r', informat);
    if (in == NULL)
        goto end;

    if (!str && passarg) {
        if (!app_passwd(passarg, NULL, &pass, NULL)) {
            BIO_printf(bio_err, "Error getting password\n");
            goto end;
        }
        str = pass;
    }

    if ((str == NULL) && (cipher != NULL) && (hkey == NULL)) {
        for (;;) {
            char prompt[200];

            BIO_snprintf(prompt, sizeof prompt, "enter %s %s password:",
                         OBJ_nid2ln(EVP_CIPHER_nid(cipher)),
                         (enc) ? "encryption" : "decryption");
            strbuf[0] = '\0';
            i = EVP_read_pw_string((char *)strbuf, SIZE, prompt, enc);
            if (i == 0) {
                if (strbuf[0] == '\0') {
                    ret = 1;
                    goto end;
                }
                str = strbuf;
                break;
            }
            if (i < 0) {
                BIO_printf(bio_err, "bad password read\n");
                goto end;
            }
        }
    }

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

    rbio = in;
    wbio = out;

#ifdef ZLIB
    if (do_zlib) {
        if ((bzl = BIO_new(BIO_f_zlib())) == NULL)
            goto end;
        if (enc)
            wbio = BIO_push(bzl, wbio);
        else
            rbio = BIO_push(bzl, rbio);
    }
#endif

    if (base64) {
        if ((b64 = BIO_new(BIO_f_base64())) == NULL)
            goto end;
        if (debug) {
            BIO_set_callback(b64, BIO_debug_callback);
            BIO_set_callback_arg(b64, (char *)bio_err);
        }
        if (olb64)
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        if (enc)
            wbio = BIO_push(b64, wbio);
        else
            rbio = BIO_push(b64, rbio);
    }

    if (cipher != NULL) {
        /*
         * Note that str is NULL if a key was passed on the command line, so
         * we get no salt in that case. Is this a bug?
         */
        if (str != NULL) {
            /*
             * Salt handling: if encrypting generate a salt and write to
             * output BIO. If decrypting read salt from input BIO.
             */
            unsigned char *sptr;
            if (nosalt)
                sptr = NULL;
            else {
                if (enc) {
                    if (hsalt) {
                        if (!set_hex(hsalt, salt, sizeof salt)) {
                            BIO_printf(bio_err, "invalid hex salt value\n");
                            goto end;
                        }
                    } else if (RAND_bytes(salt, sizeof salt) <= 0)
                        goto end;
                    /*
                     * If -P option then don't bother writing
                     */
                    if ((printkey != 2)
                        && (BIO_write(wbio, magic,
                                      sizeof magic - 1) != sizeof magic - 1
                            || BIO_write(wbio,
                                         (char *)salt,
                                         sizeof salt) != sizeof salt)) {
                        BIO_printf(bio_err, "error writing output file\n");
                        goto end;
                    }
                } else if (BIO_read(rbio, mbuf, sizeof mbuf) != sizeof mbuf
                           || BIO_read(rbio,
                                       (unsigned char *)salt,
                                       sizeof salt) != sizeof salt) {
                    BIO_printf(bio_err, "error reading input file\n");
                    goto end;
                } else if (memcmp(mbuf, magic, sizeof magic - 1)) {
                    BIO_printf(bio_err, "bad magic number\n");
                    goto end;
                }

                sptr = salt;
            }

            if (!EVP_BytesToKey(cipher, dgst, sptr,
                                (unsigned char *)str,
                                strlen(str), 1, key, iv)) {
                BIO_printf(bio_err, "EVP_BytesToKey failed\n");
                goto end;
            }
            /*
             * zero the complete buffer or the string passed from the command
             * line bug picked up by Larry J. Hughes Jr. <hughes@indiana.edu>
             */
            if (str == strbuf)
                OPENSSL_cleanse(str, SIZE);
            else
                OPENSSL_cleanse(str, strlen(str));
        }
        if (hiv != NULL) {
            int siz = EVP_CIPHER_iv_length(cipher);
            if (siz == 0) {
                BIO_printf(bio_err, "warning: iv not use by this cipher\n");
            } else if (!set_hex(hiv, iv, sizeof iv)) {
                BIO_printf(bio_err, "invalid hex iv value\n");
                goto end;
            }
        }
        if ((hiv == NULL) && (str == NULL)
            && EVP_CIPHER_iv_length(cipher) != 0) {
            /*
             * No IV was explicitly set and no IV was generated during
             * EVP_BytesToKey. Hence the IV is undefined, making correct
             * decryption impossible.
             */
            BIO_printf(bio_err, "iv undefined\n");
            goto end;
        }
        if ((hkey != NULL) && !set_hex(hkey, key, EVP_CIPHER_key_length(cipher))) {
            BIO_printf(bio_err, "invalid hex key value\n");
            goto end;
        }

        if ((benc = BIO_new(BIO_f_cipher())) == NULL)
            goto end;

        /*
         * Since we may be changing parameters work on the encryption context
         * rather than calling BIO_set_cipher().
         */

        BIO_get_cipher_ctx(benc, &ctx);

        if (non_fips_allow)
            EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_FLAG_NON_FIPS_ALLOW);

        if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc)) {
            BIO_printf(bio_err, "Error setting cipher %s\n",
                       EVP_CIPHER_name(cipher));
            ERR_print_errors(bio_err);
            goto end;
        }

        if (nopad)
            EVP_CIPHER_CTX_set_padding(ctx, 0);

        if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, enc)) {
            BIO_printf(bio_err, "Error setting cipher %s\n",
                       EVP_CIPHER_name(cipher));
            ERR_print_errors(bio_err);
            goto end;
        }

        if (debug) {
            BIO_set_callback(benc, BIO_debug_callback);
            BIO_set_callback_arg(benc, (char *)bio_err);
        }

        if (printkey) {
            if (!nosalt) {
                printf("salt=");
                for (i = 0; i < (int)sizeof(salt); i++)
                    printf("%02X", salt[i]);
                printf("\n");
            }
            if (cipher->key_len > 0) {
                printf("key=");
                for (i = 0; i < cipher->key_len; i++)
                    printf("%02X", key[i]);
                printf("\n");
            }
            if (cipher->iv_len > 0) {
                printf("iv =");
                for (i = 0; i < cipher->iv_len; i++)
                    printf("%02X", iv[i]);
                printf("\n");
            }
            if (printkey == 2) {
                ret = 0;
                goto end;
            }
        }
    }

    /* Only encrypt/decrypt as we write the file */
    if (benc != NULL)
        wbio = BIO_push(benc, wbio);

    for (;;) {
        inl = BIO_read(rbio, (char *)buff, bsize);
        if (inl <= 0)
            break;
        if (BIO_write(wbio, (char *)buff, inl) != inl) {
            BIO_printf(bio_err, "error writing output file\n");
            goto end;
        }
    }
    if (!BIO_flush(wbio)) {
        BIO_printf(bio_err, "bad decrypt\n");
        goto end;
    }

    ret = 0;
    if (verbose) {
        BIO_printf(bio_err, "bytes read   :%8"PRIu64"\n", BIO_number_read(in));
        BIO_printf(bio_err, "bytes written:%8"PRIu64"\n", BIO_number_written(out));
    }
 end:
    ERR_print_errors(bio_err);
    OPENSSL_free(strbuf);
    OPENSSL_free(buff);
    BIO_free(in);
    BIO_free_all(out);
    BIO_free(benc);
    BIO_free(b64);
#ifdef ZLIB
    BIO_free(bzl);
#endif
    OPENSSL_free(pass);
    return (ret);
}

static void show_ciphers(const OBJ_NAME *name, void *bio_)
{
    BIO *bio = bio_;
    static int n;

    if (!islower((unsigned char)*name->name))
        return;

    BIO_printf(bio, "-%-25s", name->name);
    if (++n == 3) {
        BIO_printf(bio, "\n");
        n = 0;
    } else
        BIO_printf(bio, " ");
}

static int set_hex(char *in, unsigned char *out, int size)
{
    int i, n;
    unsigned char j;

    n = strlen(in);
    if (n > (size * 2)) {
        BIO_printf(bio_err, "hex string is too long\n");
        return (0);
    }
    memset(out, 0, size);
    for (i = 0; i < n; i++) {
        j = (unsigned char)*in;
        *(in++) = '\0';
        if (j == 0)
            break;
        if (!isxdigit(j)) {
            BIO_printf(bio_err, "non-hex digit\n");
            return (0);
        }
        j = (unsigned char)app_hex(j);
        if (i & 1)
            out[i / 2] |= j;
        else
            out[i / 2] = (j << 4);
    }
    return (1);
}
