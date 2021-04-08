/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APPS_GLOBALS_H
# define OSSL_APPS_GLOBALS_H

#include <openssl/bio.h>

extern BIO *bio_in;
extern BIO *bio_out;
extern BIO *bio_err;

# define EXT_COPY_NONE   0
# define EXT_COPY_ADD    1
# define EXT_COPY_ALL    2

#define APP_PASS_LEN    1024
#define PASS_SOURCE_SIZE_MAX 4

void cleanse(char *str);
int set_ext_copy(int *copy_type, const char *arg);
int parse_yesno(const char *str, int def);
void make_uppercase(char *string);
const char *modestr(char mode, int format);
const char *modeverb(char mode);
int app_isdir(const char *);
void app_bail_out(char *fmt, ...);
void *app_malloc(size_t sz, const char *what);

#endif
