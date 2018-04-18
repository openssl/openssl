/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2018 BaishanCloud. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "apps.h"

#define BIO_TYPE_TEMP_FILE      (25|BIO_TYPE_FILTER)
static BIO_METHOD *methods_tempfile = NULL;

typedef struct {
    char *filename;
    char *tmp_filename;
} TEMPFILE_CTX;

static void apps_bf_tempfile_cleanup(void);
static int tempfile_new(BIO *b);
static int tempfile_free(BIO *b);
static int tempfile_read(BIO *b, char *out, int outl);
static int tempfile_write(BIO *b, const char *in, int inl);
static long tempfile_ctrl(BIO *b, int cmd, long num, void *ptr);
static int tempfile_gets(BIO *b, char *buf, int size);
static int tempfile_puts(BIO *b, const char *str);
static void make_temp_filename(const char *orig, char *filename);

BIO_METHOD *apps_bf_tempfile(void)
{
    if (methods_tempfile == NULL) {
        methods_tempfile = BIO_meth_new(BIO_TYPE_TEMP_FILE,
                                        "Temporary file filter");
        if (methods_tempfile == NULL
            || !BIO_meth_set_write(methods_tempfile, tempfile_write)
            || !BIO_meth_set_read(methods_tempfile, tempfile_read)
            || !BIO_meth_set_puts(methods_tempfile, tempfile_puts)
            || !BIO_meth_set_gets(methods_tempfile, tempfile_gets)
            || !BIO_meth_set_ctrl(methods_tempfile, tempfile_ctrl)
            || !BIO_meth_set_create(methods_tempfile, tempfile_new)
            || !BIO_meth_set_destroy(methods_tempfile, tempfile_free))
            return NULL;
    }
    OPENSSL_atexit(apps_bf_tempfile_cleanup);
    return methods_tempfile;
}

static void apps_bf_tempfile_cleanup(void)
{
    BIO_meth_free(methods_tempfile);
    methods_tempfile = NULL;
}

static int tempfile_new(BIO *b)
{
    TEMPFILE_CTX *temp;

    temp = app_malloc(sizeof(*temp), "temp file");
    temp->filename = NULL;
    temp->tmp_filename = NULL;
    BIO_set_data(b, temp);
    BIO_set_init(b, 1);

    return 1;
}

static int tempfile_free(BIO *b)
{
    TEMPFILE_CTX *temp;

    if (b == NULL)
        return 0;

    temp = BIO_get_data(b);
    if (temp->filename != NULL && temp->tmp_filename != NULL) {
        rename(temp->tmp_filename, temp->filename);
    }
    OPENSSL_free(temp->filename);
    OPENSSL_free(temp->tmp_filename);
    OPENSSL_free(temp);
    BIO_set_data(b, NULL);
    BIO_set_init(b, 0);

    return 1;
}

static int tempfile_read(BIO *b, char *out, int outl)
{
    int ret = 0;
    BIO *next = BIO_next(b);

    if (out == NULL || outl == 0)
        return 0;
    if (next == NULL)
        return 0;

    ret = BIO_read(next, out, outl);
    return ret;
}

static int tempfile_write(BIO *b, const char *in, int inl)
{
    BIO *next = BIO_next(b);

    if ((in == NULL) || (inl <= 0))
        return 0;
    if (next == NULL)
        return 0;

    return BIO_write(next, in, inl);
}

#define RND_SIZE 16

static void make_temp_filename(const char *orig, char *filename)
{
    int i, size = RND_SIZE;
    char *p;
    char set[] = "0123456789abcdefghijklmnopqrstuvwxyz"
                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    strcpy(filename, orig);
    p = filename + strlen(orig);
    *p++ = '.';

    srand(time(NULL));
    while (size--) {
        i = rand() % (sizeof(set) - 1);
        *p++ = set[i];
    }

    *p = '\0';

    return;
}

static FILE *make_temp_file_ptr(const char *filename, int format, int *bflags,
                                char **ret_tmp_filename)
{
    FILE *fp = NULL;
    int fd = -1, mode, textmode;
    char *tmp_filename = NULL;

    /* create tmp file name */
    tmp_filename = OPENSSL_malloc(strlen(filename) + RND_SIZE + 2);
    if (tmp_filename == NULL)
        goto err;
    make_temp_filename(filename, tmp_filename);

    /* create a tmp file sink BIO */
    mode = O_WRONLY;
#ifdef O_CREAT
    mode |= O_CREAT;
#endif
    textmode = istext(format);
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
        fd = open(tmp_filename, mode, 0600, "ctx=bin");
    else
#endif
        fd = open(tmp_filename, mode, 0600);
    if (fd < 0)
        goto err;
    fp = fdopen(fd, modestr('w', format));
    if (fp == NULL)
        goto err;
    *bflags = BIO_CLOSE;
    if (textmode)
        *bflags |= BIO_FP_TEXT;

    *ret_tmp_filename = tmp_filename;

    return fp;

 err:
    BIO_printf(bio_err, "%s: Can't open \"%s\" for writing, %s\n",
               opt_getprog(), filename, strerror(errno));
    ERR_print_errors(bio_err);
    /* If we have fp, then fdopen took over fd, so don't close both. */
    if (fp)
        fclose(fp);
    else if (fd >= 0)
        close(fd);
    OPENSSL_free(tmp_filename);
    return NULL;
}

static long tempfile_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    BIO *next = BIO_next(b);
    TEMPFILE_CTX *temp;
    char *tmp_filename;
    FILE *fp = NULL;
    int flags = 0;

    if (next == NULL)
        return 0;

    switch (cmd) {
    case BIO_C_SET_FILENAME:
        fp = make_temp_file_ptr((char *)ptr, num, &flags, &tmp_filename);
        if (fp == NULL || tmp_filename == NULL)
            return 0;
        temp = BIO_get_data(b);
        temp->tmp_filename = tmp_filename;
        temp->filename = OPENSSL_strdup((char *)ptr);
        if (temp->filename == NULL)
            return 0;
        /* set new FILE ptr to sink BIO */
        BIO_set_fp(next, fp, flags);
        break;
    default:
        ret = BIO_ctrl(next, cmd, num, ptr);
        break;
    }

    return ret;
}

static int tempfile_gets(BIO *b, char *buf, int size)
{
    BIO *next = BIO_next(b);

    if (next == NULL)
        return 0;

    return BIO_gets(next, buf, size);
}

static int tempfile_puts(BIO *b, const char *str)
{
    BIO *next = BIO_next(b);

    if (next == NULL)
        return 0;

    return BIO_puts(next, str);
}
