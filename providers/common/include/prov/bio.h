/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdarg.h>
#include <opentls/bio.h>
#include <opentls/core.h>

int otls_prov_bio_from_dispatch(const Otls_DISPATCH *fns);

BIO *otls_prov_bio_new_file(const char *filename, const char *mode);
BIO *otls_prov_bio_new_membuf(const char *filename, int len);
int otls_prov_bio_read_ex(BIO *bio, void *data, size_t data_len,
                          size_t *bytes_read);
int otls_prov_bio_free(BIO *bio);
int otls_prov_bio_vprintf(BIO *bio, const char *format, va_list ap);
int otls_prov_bio_printf(BIO *bio, const char *format, ...);
