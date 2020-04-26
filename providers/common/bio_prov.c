/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_numbers.h>
#include "prov/bio.h"

static OSSL_BIO_new_file_fn *c_bio_new_file = NULL;
static OSSL_BIO_new_membuf_fn *c_bio_new_membuf = NULL;
static OSSL_BIO_read_ex_fn *c_bio_read_ex = NULL;
static OSSL_BIO_free_fn *c_bio_free = NULL;
static OSSL_BIO_vprintf_fn *c_bio_vprintf = NULL;

int ossl_prov_bio_from_dispatch(const OSSL_DISPATCH *fns)
{
    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_BIO_NEW_FILE:
            if (c_bio_new_file == NULL)
                c_bio_new_file = OSSL_get_BIO_new_file(fns);
            break;
        case OSSL_FUNC_BIO_NEW_MEMBUF:
            if (c_bio_new_membuf == NULL)
                c_bio_new_membuf = OSSL_get_BIO_new_membuf(fns);
            break;
        case OSSL_FUNC_BIO_READ_EX:
            if (c_bio_read_ex == NULL)
                c_bio_read_ex = OSSL_get_BIO_read_ex(fns);
            break;
        case OSSL_FUNC_BIO_FREE:
            if (c_bio_free == NULL)
                c_bio_free = OSSL_get_BIO_free(fns);
            break;
        case OSSL_FUNC_BIO_VPRINTF:
            if (c_bio_vprintf == NULL)
                c_bio_vprintf = OSSL_get_BIO_vprintf(fns);
            break;
        }
    }

    return 1;
}

BIO *ossl_prov_bio_new_file(const char *filename, const char *mode)
{
    if (c_bio_new_file == NULL)
        return NULL;
    return c_bio_new_file(filename, mode);
}

BIO *ossl_prov_bio_new_membuf(const char *filename, int len)
{
    if (c_bio_new_membuf == NULL)
        return NULL;
    return c_bio_new_membuf(filename, len);
}

int ossl_prov_bio_read_ex(BIO *bio, void *data, size_t data_len,
                          size_t *bytes_read)
{
    if (c_bio_read_ex == NULL)
        return 0;
    return c_bio_read_ex(bio, data, data_len, bytes_read);
}

int ossl_prov_bio_free(BIO *bio)
{
    if (c_bio_free == NULL)
        return 0;
    return c_bio_free(bio);
}

int ossl_prov_bio_vprintf(BIO *bio, const char *format, va_list ap)
{
    if (c_bio_vprintf == NULL)
        return -1;
    return c_bio_vprintf(bio, format, ap);
}

int ossl_prov_bio_printf(BIO *bio, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = ossl_prov_bio_vprintf(bio, format, ap);
    va_end(ap);

    return ret;
}

