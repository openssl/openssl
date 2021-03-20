/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "apps_globals.h"
#include "apps_config.h"
#include "apps_libctx.h"
#include "opt.h"
#include <openssl/err.h>
#include <openssl/conf.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * Centralized handling of input and output files with format specification
 * The format is meant to show what the input and output is supposed to be,
 * and is therefore a show of intent more than anything else.  However, it
 * does impact behavior on some platforms, such as differentiating between
 * text and binary input/output on non-Unix platforms
 */
BIO *dup_bio_in(int format)
{
    return BIO_new_fp(stdin,
                      BIO_NOCLOSE | (FMT_istext(format) ? BIO_FP_TEXT : 0));
}

BIO *dup_bio_out(int format)
{
    BIO *b = BIO_new_fp(stdout,
                        BIO_NOCLOSE | (FMT_istext(format) ? BIO_FP_TEXT : 0));
    void *prefix = NULL;

#ifdef OPENSSL_SYS_VMS
    if (FMT_istext(format))
        b = BIO_push(BIO_new(BIO_f_linebuffer()), b);
#endif

    if (FMT_istext(format)
        && (prefix = getenv("HARNESS_OSSL_PREFIX")) != NULL) {
        b = BIO_push(BIO_new(BIO_f_prefix()), b);
        BIO_set_prefix(b, prefix);
    }

    return b;
}

BIO *dup_bio_err(int format)
{
    BIO *b = BIO_new_fp(stderr,
                        BIO_NOCLOSE | (FMT_istext(format) ? BIO_FP_TEXT : 0));
#ifdef OPENSSL_SYS_VMS
    if (FMT_istext(format))
        b = BIO_push(BIO_new(BIO_f_linebuffer()), b);
#endif
    return b;
}

/*
 * Open a file for writing, owner-read-only.
 */
BIO *bio_open_owner(const char *filename, int format, int private)
{
    FILE *fp = NULL;
    BIO *b = NULL;
    int fd = -1, bflags, mode, textmode;

    if (!private || filename == NULL || strcmp(filename, "-") == 0)
        return bio_open_default(filename, 'w', format);

    mode = O_WRONLY;
#ifdef O_CREAT
    mode |= O_CREAT;
#endif
#ifdef O_TRUNC
    mode |= O_TRUNC;
#endif
    textmode = FMT_istext(format);
    if (!textmode) {
#ifdef O_BINARY
        mode |= O_BINARY;
#elif defined(_O_BINARY)
        mode |= _O_BINARY;
#endif
    }

#ifdef OPENSSL_SYS_VMS
    /* VMS doesn't have O_BINARY, it just doesn't make sense.  But,
     * it still needs to know that we're going binary, or fdopen()
     * will fail with "invalid argument"...  so we tell VMS what the
     * context is.
     */
    if (!textmode)
        fd = open(filename, mode, 0600, "ctx=bin");
    else
#endif
        fd = open(filename, mode, 0600);
    if (fd < 0)
        goto err;
    fp = fdopen(fd, modestr('w', format));
    if (fp == NULL)
        goto err;
    bflags = BIO_CLOSE;
    if (textmode)
        bflags |= BIO_FP_TEXT;
    b = BIO_new_fp(fp, bflags);
    if (b)
        return b;

 err:
    BIO_printf(bio_err, "%s: Can't open \"%s\" for writing, %s\n",
               opt_getprog(), filename, strerror(errno));
    ERR_print_errors(bio_err);
    /* If we have fp, then fdopen took over fd, so don't close both. */
    if (fp)
        fclose(fp);
    else if (fd >= 0)
        close(fd);
    return NULL;
}

static BIO *bio_open_default_(const char *filename, char mode, int format,
                              int quiet)
{
    BIO *ret;

    if (filename == NULL || strcmp(filename, "-") == 0) {
        ret = mode == 'r' ? dup_bio_in(format) : dup_bio_out(format);
        if (quiet) {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
        BIO_printf(bio_err,
                   "Can't open %s, %s\n",
                   mode == 'r' ? "stdin" : "stdout", strerror(errno));
    } else {
        ret = BIO_new_file(filename, modestr(mode, format));
        if (quiet) {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
        BIO_printf(bio_err,
                   "Can't open \"%s\" for %s, %s\n",
                   filename, modeverb(mode), strerror(errno));
    }
    ERR_print_errors(bio_err);
    return NULL;
}

CONF *app_load_config_bio(BIO *in, const char *filename)
{
    long errorline = -1;
    CONF *conf;
    int i;
    OSSL_LIB_CTX *app_libctx = app_get0_libctx();

    conf = NCONF_new_ex(app_libctx, NULL);
    i = NCONF_load_bio(conf, in, &errorline);
    if (i > 0)
        return conf;

    if (errorline <= 0) {
        BIO_printf(bio_err, "%s: Can't load ", opt_getprog());
    } else {
        BIO_printf(bio_err, "%s: Error on line %ld of ", opt_getprog(),
                   errorline);
    }
    if (filename != NULL)
        BIO_printf(bio_err, "config file \"%s\"\n", filename);
    else
        BIO_printf(bio_err, "config input");

    NCONF_free(conf);
    return NULL;
}

CONF *app_load_config_verbose(const char *filename, int verbose)
{
    if (verbose) {
        if (*filename == '\0')
            BIO_printf(bio_err, "No configuration used\n");
        else
            BIO_printf(bio_err, "Using configuration from %s\n", filename);
    }
    return app_load_config_internal(filename, 0);
}

CONF *app_load_config_internal(const char *filename, int quiet)
{
    BIO *in = NULL; /* leads to empty config in case filename == "" */
    CONF *conf;

    if (*filename != '\0'
        && (in = bio_open_default_(filename, 'r', FORMAT_TEXT, quiet)) == NULL)
        return NULL;
    conf = app_load_config_bio(in, filename);
    BIO_free(in);
    return conf;
}

BIO *bio_open_default(const char *filename, char mode, int format)
{
    return bio_open_default_(filename, mode, format, 0);
}

BIO *bio_open_default_quiet(const char *filename, char mode, int format)
{
    return bio_open_default_(filename, mode, format, 1);
}

