/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <string.h>
#include <openssl/bio.h>
#include "fmt.h"
// needed for dup_bio_in
#include "apps_extracted.h"
#include "apps_passwd.h"
#include "apps_globals.h"

static char *app_get_pass(const char *arg, int keepbio)
{
    static BIO *pwdbio = NULL;
    char *tmp, tpass[APP_PASS_LEN];
    int i;

    /* PASS_SOURCE_SIZE_MAX = max number of chars before ':' in below strings */
    if (strncmp(arg, "pass:", 5) == 0)
        return OPENSSL_strdup(arg + 5);
    if (strncmp(arg, "env:", 4) == 0) {
        tmp = getenv(arg + 4);
        if (tmp == NULL) {
            BIO_printf(bio_err, "No environment variable %s\n", arg + 4);
            return NULL;
        }
        return OPENSSL_strdup(tmp);
    }
    if (!keepbio || pwdbio == NULL) {
        if (strncmp(arg, "file:", 5) == 0) {
            pwdbio = BIO_new_file(arg + 5, "r");
            if (pwdbio == NULL) {
                BIO_printf(bio_err, "Can't open file %s\n", arg + 5);
                return NULL;
            }
#if !defined(_WIN32)
            /*
             * Under _WIN32, which covers even Win64 and CE, file
             * descriptors referenced by BIO_s_fd are not inherited
             * by child process and therefore below is not an option.
             * It could have been an option if bss_fd.c was operating
             * on real Windows descriptors, such as those obtained
             * with CreateFile.
             */
        } else if (strncmp(arg, "fd:", 3) == 0) {
            BIO *btmp;
            i = atoi(arg + 3);
            if (i >= 0)
                pwdbio = BIO_new_fd(i, BIO_NOCLOSE);
            if ((i < 0) || !pwdbio) {
                BIO_printf(bio_err, "Can't access file descriptor %s\n", arg + 3);
                return NULL;
            }
            /*
             * Can't do BIO_gets on an fd BIO so add a buffering BIO
             */
            btmp = BIO_new(BIO_f_buffer());
            pwdbio = BIO_push(btmp, pwdbio);
#endif
        } else if (strcmp(arg, "stdin") == 0) {
            pwdbio = dup_bio_in(FORMAT_TEXT);
            if (pwdbio == NULL) {
                BIO_printf(bio_err, "Can't open BIO for stdin\n");
                return NULL;
            }
        } else {
            /* argument syntax error; do not reveal too much about arg */
            tmp = strchr(arg, ':');
            if (tmp == NULL || tmp - arg > PASS_SOURCE_SIZE_MAX)
                BIO_printf(bio_err,
                           "Invalid password argument, missing ':' within the first %d chars\n",
                           PASS_SOURCE_SIZE_MAX + 1);
            else
                BIO_printf(bio_err,
                           "Invalid password argument, starting with \"%.*s\"\n",
                           (int)(tmp - arg + 1), arg);
            return NULL;
        }
    }
    i = BIO_gets(pwdbio, tpass, APP_PASS_LEN);
    if (keepbio != 1) {
        BIO_free_all(pwdbio);
        pwdbio = NULL;
    }
    if (i <= 0) {
        BIO_printf(bio_err, "Error reading password from BIO\n");
        return NULL;
    }
    tmp = strchr(tpass, '\n');
    if (tmp != NULL)
        *tmp = 0;
    return OPENSSL_strdup(tpass);
}

int app_passwd(const char *arg1, const char *arg2, char **pass1, char **pass2)
{
    int same = arg1 != NULL && arg2 != NULL && strcmp(arg1, arg2) == 0;

    if (arg1 != NULL) {
        *pass1 = app_get_pass(arg1, same);
        if (*pass1 == NULL)
            return 0;
    } else if (pass1 != NULL) {
        *pass1 = NULL;
    }
    if (arg2 != NULL) {
        *pass2 = app_get_pass(arg2, same ? 2 : 0);
        if (*pass2 == NULL)
            return 0;
    } else if (pass2 != NULL) {
        *pass2 = NULL;
    }
    return 1;
}

char *get_passwd(const char *pass, const char *desc)
{
    char *result = NULL;

    if (desc == NULL)
        desc = "<unknown>";
    if (!app_passwd(pass, NULL, &result, NULL))
        BIO_printf(bio_err, "Error getting password for %s\n", desc);
    if (pass != NULL && result == NULL) {
        BIO_printf(bio_err,
                   "Trying plain input string (better precede with 'pass:')\n");
        result = OPENSSL_strdup(pass);
        if (result == NULL)
            BIO_printf(bio_err, "Out of memory getting password for %s\n", desc);
    }
    return result;
}


