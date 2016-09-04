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
#include <ctype.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

typedef enum pbe_kdf {
    PBE_KDF_INVALID,
    PBE_KDF_PBKDF2,
    PBE_KDF_SCRYPT
} PBE_KDF;

#define PASSWORD_BUFSIZE        (8 * 1024)
static OPT_PAIR pbe_kdfs[] = {
    {"pbkdf2", PBE_KDF_PBKDF2},
#ifndef OPENSSL_NO_SCRYPT
    {"scrypt", PBE_KDF_SCRYPT},
#endif
    {NULL}
};

static int hex_parse(char *hexbuffer);
#ifndef OPENSSL_NO_SCRYPT
static int is_power_of_two(unsigned int value);
#endif

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_HEXSALT,
    OPT_KDF, OPT_SALT,
    OPT_ITERCNT,
#ifndef OPENSSL_NO_SCRYPT
    OPT_PARAM_N, OPT_PARAM_R, OPT_PARAM_P,
    OPT_MEMSIZE,
#endif
    OPT_DKLEN, OPT_DIGEST
} OPTION_CHOICE;

OPTIONS pbe_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options]\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"kdf", OPT_KDF, 's', "Specify the key derivation function"},
    {"salt", OPT_SALT, 's', "Salt for key derivation"},
    {"hexsalt", OPT_HEXSALT, '-', "Interpret the given salt as hex string"},
    {"itercnt", OPT_ITERCNT, 'p', "Iteration count for key derivation with PBKDF2"},
#ifndef OPENSSL_NO_SCRYPT
    {"N", OPT_PARAM_N, 'p', "CPU/memory cost parameter for scrypt"},
    {"r", OPT_PARAM_R, 'p', "Block size parameter for scrypt"},
    {"p", OPT_PARAM_P, 'p', "Parallelization parameter for scrypt"},
    {"memsize", OPT_MEMSIZE, 'p', "Maximum memory allocation in MiB (default is 128 MiB)"},
#endif
    {"dklen", OPT_DKLEN, 'p', "Key derivation output key length"},
    {"", OPT_DIGEST, '-', "Any supported digest"},
    {NULL}
};

int pbe_main(int argc, char **argv)
{
    BIO *in = NULL;
    int kdf = PBE_KDF_INVALID;
    const EVP_MD *md = NULL, *m = NULL;
    char *salt = NULL, *password = NULL;
    int saltlen = 0, passlen = 0;
    OPTION_CHOICE o;
    unsigned int i = 0;
    int result = 0;
    const char *prog = NULL;
    int hexsalt = 0;
    unsigned int itercnt = 0, dklen = 0;
#ifndef OPENSSL_NO_SCRYPT
    unsigned int par_n = 0, par_r = 0, par_p = 0;
    unsigned int memsize_mib = 128;
#endif
    unsigned char *dkey = NULL;

    prog = opt_init(argc, argv, pbe_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(pbe_options);
            goto end;
        case OPT_HEXSALT:
            hexsalt = 1;
            break;
        case OPT_KDF:
            if (!opt_pair(opt_arg(), pbe_kdfs, &kdf)) {
                opt_help(pbe_options);
                goto end;
            }
            break;
        case OPT_SALT:
            salt = opt_arg();
            break;
        case OPT_ITERCNT:
            itercnt = atoi(opt_arg());
            break;
#ifndef OPENSSL_NO_SCRYPT
        case OPT_PARAM_N:
            par_n = atoi(opt_arg());
            break;
        case OPT_PARAM_R:
            par_r = atoi(opt_arg());
            break;
        case OPT_PARAM_P:
            par_p = atoi(opt_arg());
            break;
#endif
        case OPT_DKLEN:
            dklen = atoi(opt_arg());
            break;
        case OPT_DIGEST:
            if (!opt_md(opt_unknown(), &m))
                goto opthelp;
            md = m;
            break;
#ifndef OPENSSL_NO_SCRYPT
        case OPT_MEMSIZE:
            memsize_mib = atoi(opt_arg());
            break;
#endif
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (kdf == PBE_KDF_INVALID) {
        OPT_PAIR *next_kdf = pbe_kdfs;
        BIO_puts(bio_err,
                 "No key derivation function given: use the -kdf option\n");
        BIO_puts(bio_err, "Known KDF: ");
        while (next_kdf->name) {
            BIO_puts(bio_err, next_kdf->name);
            BIO_puts(bio_err, " ");
            next_kdf++;
        }
        BIO_puts(bio_err, "\n");
        goto end;
    }

    if (!salt) {
        BIO_puts(bio_err,
                 "No salt given: use the -salt option\n");
        goto end;
    }

    if (!dklen) {
        BIO_puts(bio_err,
                 "No derivative key length given: use the -dklen option\n");
        goto end;
    }

    if (!app_load_modules(NULL))
        goto end;

    dkey = app_malloc(dklen, "derived key buffer");
    password = app_malloc(PASSWORD_BUFSIZE, "password buffer");

    /* perform KDF-specific sanity checks before reading in the password */
    if (kdf == PBE_KDF_PBKDF2) {
#ifndef OPENSSL_NO_SCRYPT
        if (par_n || par_r || par_p) {
            BIO_puts(bio_err,
                     "For PBKDF2, the N, r and p parameters do not make sense. Omit them.\n");
            goto end;
        }
#endif
        if (!itercnt) {
            BIO_puts(bio_err,
                     "No iteration count given: use the -itercnt option\n");
            goto end;
        }
#ifndef OPENSSL_NO_SCRYPT
    } else if (kdf == PBE_KDF_SCRYPT) {
        if (itercnt || md) {
            BIO_puts(bio_err,
                     "For scrypt, the itercnt and digest parameters do not make sense. Omit them.\n");
            goto end;
        }
        if (!par_n || !par_r || !par_p) {
            BIO_puts(bio_err,
                     "Either N, r or p parameter missing: use the -N, -r or -p option\n");
            goto end;
        }
        if (par_n < 2) {
            BIO_puts(bio_err,
                     "Parameter \"N\" must be at least 2\n");
            goto end;
        }
        if (!is_power_of_two(par_n)) {
            BIO_puts(bio_err,
                     "Parameter \"N\" must be a power of two\n");
            goto end;
        }
#endif
    }

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }
    BIO_set_fp(in, stdin, BIO_NOCLOSE);

    passlen = BIO_read(in, password, PASSWORD_BUFSIZE);
    if (passlen == PASSWORD_BUFSIZE) {
        /* password was probably incompletely read, do not do any derivation on
         * truncated passwords */
        BIO_printf(bio_err,
                 "Given password exceeds allocated buffer of %d bytes.\n", PASSWORD_BUFSIZE);
        goto end;
    }

    saltlen = strlen(salt);
    if (hexsalt) {
        saltlen = hex_parse(salt);
        if (saltlen == 0) {
            BIO_puts(bio_err, "Could not parse salt as hex value\n");
            goto end;
        }
    }

    result = 0;
    if (kdf == PBE_KDF_PBKDF2) {
        if (!md)
            md = EVP_sha1();
        result = PKCS5_PBKDF2_HMAC(password, passlen, (unsigned char*)salt, saltlen, itercnt, md, dklen, dkey);
#ifndef OPENSSL_NO_SCRYPT
    } else if (kdf == PBE_KDF_SCRYPT) {
        result = EVP_PBE_scrypt(password, passlen, (unsigned char*)salt, saltlen, par_n, par_r, par_p, memsize_mib * 1024 * 1024, dkey, dklen);
#endif
    }

    if (result != 1) {
        BIO_printf(bio_err, "Key derivation failed: result %d\n", result);
        ERR_print_errors(bio_err);
        goto end;
    }

    for (i = 0; i < dklen; i++) {
        BIO_printf(bio_out, "%02x", dkey[i] & 0xff);
    }
    BIO_printf(bio_out, "\n");

end:
    OPENSSL_clear_free(password, PASSWORD_BUFSIZE);
    OPENSSL_free(dkey);
    BIO_free(in);
    return 0;
}

static int hex_parse(char *hexbuffer) {
    int i, l;
    l = strlen(hexbuffer);
    if ((l % 2) != 0) {
        BIO_puts(bio_err, "Hex string is not of even length\n");
        return 0;
    }
    for (i = 0; i < l; i += 2) {
        if ((!isxdigit(hexbuffer[i])) || (!isxdigit(hexbuffer[i + 1]))) {
            BIO_printf(bio_err, "Invalid hex character at position %d\n", i / 2);
            return 0;
        }
        hexbuffer[i / 2] = (OPENSSL_hexchar2int(hexbuffer[i + 0]) << 4) | (OPENSSL_hexchar2int(hexbuffer[i + 1]));
    }
    return l / 2;
}

#ifndef OPENSSL_NO_SCRYPT
static int is_power_of_two(unsigned int value) {
    int bits_set = 0;
    while (value) {
        if (value & 1) bits_set++;
        value >>= 1;
    }
    return bits_set == 1;
}
#endif
