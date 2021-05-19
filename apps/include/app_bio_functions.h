/*
 * Copyright 2015-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APP_BIO_FUNCTIONS_H
# define OSSL_APP_BIO_FUNCTIONS_H

# include <openssl/bio.h>

/*
 * These are used by the macros bio_in, bio_out and bio_err, defined in
 * app_bio_macros.h.  They are intended for use as lvalues just as much
 * as rvalues.
 */
BIO **app_bio_in_location(void);
BIO **app_bio_out_location(void);
BIO **app_bio_err_location(void);

int app_bio_init(void);

BIO *app_bio_dup_in(int format);
BIO *app_bio_dup_out(int format);
BIO *app_bio_dup_err(int format);
BIO *app_bio_open(const char *filename, char mode, int format, int quiet);
BIO *app_bio_open_owner(const char *filename, int format, int private);
BIO *app_bio_open_default(const char *filename, char mode, int format);
BIO *app_bio_open_default_quiet(const char *filename, char mode, int format);

#endif
