/*
 * Copyright (c) 2016 Red Hat, Inc.
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
#include <string.h>

#ifdef _WIN32
# include <direct.h>
# define __func__ __FUNCTION__
# define DIRSEP '\\'
# define CHDIR _chdir
#else
# include <unistd.h>
# define DIRSEP '/'
# define CHDIR chdir
#endif

/* changes path to that of the filename */
static void change_path(const char *file)
{
    char *s = strdup(file);
    char *p;

    if (s == NULL)
        return;

    p = strrchr(s, DIRSEP);
    if (p == NULL)
        return;
    *p = 0;

    fprintf(stderr, "changing path to %s\n", s);
    chdir(s);
}

/* This test program checks the operation of the .include directive.
 */

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
main(int argc, char **argv)
{
    CONF *conf;
    BIO *in;
    long errline;
    int ret;
    long val;
    char *str, *conf_file;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if (argc < 2)
        exit(1);

    conf_file = argv[1];

    in = bio_open_default_(conf_file, "r", 1);
    if (in == NULL) {
        fprintf(stderr, "unable to open configuration file\n");
        exit(1);
    }

    /* for this test we need to chdir as we use relative
     * path names in config files */
    change_path(conf_file);

    conf = NCONF_new(NULL);
    if (conf == NULL) {
        fprintf(stderr, "unable to init configuration\n");
        exit(1);
    }

    ret = NCONF_load_bio(conf, in, &errline);
    if (ret <= 0) {
    	fprintf(stderr, "cannot load %s file; error in line %ld\n", conf_file, errline);
    	exit(2);
    }

    if (CONF_modules_load(conf, NULL, 0) <= 0) {
    	fprintf(stderr, "failed in CONF_modules_load\n");
    	exit(1);
    }

    /* verify whether RANDFILE is set correctly */
    str = NCONF_get_string(conf, "", "RANDFILE");
    if (str == NULL || strcmp(str, "./.rnd") != 0) {
        fprintf(stderr, "failed in %s: %d\n", __func__, __LINE__);
        exit(1);
    }

    /* verify whether CA_default/default_days is set
     */
    val = 0;
    if (NCONF_get_number(conf, "CA_default", "default_days", &val) == 0 || val != 365) {
        fprintf(stderr, "failed in %s: %d\n", __func__, __LINE__);
        exit(1);
    }

    /* verify whether req/default_bits is set */
    val = 0;
    if (NCONF_get_number(conf, "req", "default_bits", &val) == 0 || val != 2048) {
        fprintf(stderr, "failed in %s: %d\n", __func__, __LINE__);
        exit(1);
    }

    /* verify whether countryName_default is set correctly */
    str = NCONF_get_string(conf, "req_distinguished_name", "countryName_default");
    if (str == NULL || strcmp(str, "AU") != 0) {
        fprintf(stderr, "failed in %s: %d\n", __func__, __LINE__);
        exit(1);
    }

    BIO_free(in);
    NCONF_free(conf);
    CONF_modules_unload(1);

    return 0;
}
