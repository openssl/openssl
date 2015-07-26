/*
 * Copyright (c) 2015 Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

static
BIO *dup_bio_in(void)
{
    return BIO_new_fp(stdin, BIO_NOCLOSE | BIO_FP_TEXT);
}

static
BIO *dup_bio_out(void)
{
    BIO *b = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    return b;
}

static BIO *bio_open_default_(const char *filename, const char *mode, int quiet)
{
    BIO *ret;

    if (filename == NULL || strcmp(filename, "-") == 0) {
        ret = *mode == 'r' ? dup_bio_in() : dup_bio_out();
        if (quiet) {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
        fprintf(stderr,
                   "Can't open %s, %s\n",
                   *mode == 'r' ? "stdin" : "stdout", strerror(errno));
    } else {
        ret = BIO_new_file(filename, mode);
        if (quiet) {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
        fprintf(stderr,
                   "Can't open %s for %s, %s\n",
                   filename,
                   *mode == 'r' ? "reading" : "writing", strerror(errno));
    }
    return NULL;
}

int
main()
{
    CONF *conf;
    BIO *in;
    long errline;
    int ret;
    unsigned ciphers_num, high_ciphers_num;
    SSL_CTX *ctx = NULL;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    in = bio_open_default_("profiles-openssl.cnf", "r", 1);
    if (in == NULL) {
        fprintf(stderr, "unable to open configuration file\n");
        exit(1);
    }

    conf = NCONF_new(NULL);
    if (conf == NULL) {
        fprintf(stderr, "unable to init configuration\n");
        exit(1);
    }

    ret = NCONF_load_bio(conf, in, &errline);
    if (ret <= 0) {
    	fprintf(stderr, "cannot load file: %ld\n", errline);
    	exit(1);
    }

    if (CONF_modules_load(conf, NULL, 0) <= 0) {
    	fprintf(stderr, "failed in CONF_modules_load\n");
    	exit(1);
    }

    ctx = SSL_CTX_new(TLSv1_client_method());
    if (ctx == NULL) {
    	fprintf(stderr, "failed in SSL_CTX_new\n");
    	exit(1);
    }

#define CHECK_CIPHERS(x, num) \
    if (SSL_CTX_set_cipher_list(ctx, x) <= 0) { \
    	fprintf(stderr, "error checking %s\n", x); \
    	exit(1); \
    } \
    { \
    SSL *ssl = NULL; \
    STACK_OF(SSL_CIPHER) *sk = NULL; \
    ssl = SSL_new(ctx); \
    if (ssl == NULL) exit(1); \
    sk = SSL_get_ciphers(ssl); \
    ciphers_num = sk_SSL_CIPHER_num(sk); \
    if (num != -1 && ciphers_num != num) { \
    	fprintf(stderr, "unexpected number of ciphers (%d) for profile %s\n", ciphers_num, x); \
    	exit(1); \
    } \
    SSL_free(ssl); \
    }

    CHECK_CIPHERS("HIGH", -1);
    high_ciphers_num = ciphers_num;
    CHECK_CIPHERS("PROFILE=PROFILE1", 2);
    CHECK_CIPHERS("PROFILE=PROFILE2", 1);
    CHECK_CIPHERS("PROFILE=PROFILE-HIGH", high_ciphers_num);

    /* verify the cipher in profile2 */
    

    if (SSL_CTX_set_cipher_list(ctx, "PROFILE3") > 0) {
    	fprintf(stderr, "error checking inexistant profile\n");
    	exit(1);
    }
    SSL_CTX_free(ctx);
    BIO_free(in);
    CONF_modules_unload(1);

    return 0;
}
