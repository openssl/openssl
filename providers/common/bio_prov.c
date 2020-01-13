/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/core_numbers.h>
#include "prov/bio.h"

static Otls_BIO_new_file_fn *c_bio_new_file = NULL;
static Otls_BIO_new_membuf_fn *c_bio_new_membuf = NULL;
static Otls_BIO_read_ex_fn *c_bio_read_ex = NULL;
static Otls_BIO_free_fn *c_bio_free = NULL;
static Otls_BIO_vprintf_fn *c_bio_vprintf = NULL;

int otls_prov_bio_from_dispatch(const Otls_DISPATCH *fns)
{
    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case Otls_FUNC_BIO_NEW_FILE:
            if (c_bio_new_file == NULL)
                c_bio_new_file = Otls_get_BIO_new_file(fns);
            break;
        case Otls_FUNC_BIO_NEW_MEMBUF:
            if (c_bio_new_membuf == NULL)
                c_bio_new_membuf = Otls_get_BIO_new_membuf(fns);
            break;
        case Otls_FUNC_BIO_READ_EX:
            if (c_bio_read_ex == NULL)
                c_bio_read_ex = Otls_get_BIO_read_ex(fns);
            break;
        case Otls_FUNC_BIO_FREE:
            if (c_bio_free == NULL)
                c_bio_free = Otls_get_BIO_free(fns);
            break;
        case Otls_FUNC_BIO_VPRINTF:
            if (c_bio_vprintf == NULL)
                c_bio_vprintf = Otls_get_BIO_vprintf(fns);
            break;
        }
    }

    return 1;
}

BIO *otls_prov_bio_new_file(const char *filename, const char *mode)
{
    if (c_bio_new_file == NULL)
        return NULL;
    return c_bio_new_file(filename, mode);
}

BIO *otls_prov_bio_new_membuf(const char *filename, int len)
{
    if (c_bio_new_membuf == NULL)
        return NULL;
    return c_bio_new_membuf(filename, len);
}

int otls_prov_bio_read_ex(BIO *bio, void *data, size_t data_len,
                          size_t *bytes_read)
{
    if (c_bio_read_ex == NULL)
        return 0;
    return c_bio_read_ex(bio, data, data_len, bytes_read);
}

int otls_prov_bio_free(BIO *bio)
{
    if (c_bio_free == NULL)
        return 0;
    return c_bio_free(bio);
}

int otls_prov_bio_vprintf(BIO *bio, const char *format, va_list ap)
{
    if (c_bio_vprintf == NULL)
        return -1;
    return c_bio_vprintf(bio, format, ap);
}

int otls_prov_bio_printf(BIO *bio, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = otls_prov_bio_vprintf(bio, format, ap);
    va_end(ap);

    return ret;
}

