/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <openssl/core_numbers.h>
#include "internal/cryptlib.h"
#include "prov/bio.h"

static OSSL_BIO_new_file_fn *c_bio_new_file = NULL;
static OSSL_BIO_new_membuf_fn *c_bio_new_membuf = NULL;
static OSSL_BIO_read_ex_fn *c_bio_read_ex = NULL;
static OSSL_BIO_write_ex_fn *c_bio_write_ex = NULL;
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
        case OSSL_FUNC_BIO_WRITE_EX:
            if (c_bio_write_ex == NULL)
                c_bio_write_ex = OSSL_get_BIO_write_ex(fns);
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

OSSL_CORE_BIO *ossl_prov_bio_new_file(const char *filename, const char *mode)
{
    if (c_bio_new_file == NULL)
        return NULL;
    return c_bio_new_file(filename, mode);
}

OSSL_CORE_BIO *ossl_prov_bio_new_membuf(const char *filename, int len)
{
    if (c_bio_new_membuf == NULL)
        return NULL;
    return c_bio_new_membuf(filename, len);
}

int ossl_prov_bio_read_ex(OSSL_CORE_BIO *bio, void *data, size_t data_len,
                          size_t *bytes_read)
{
    if (c_bio_read_ex == NULL)
        return 0;
    return c_bio_read_ex(bio, data, data_len, bytes_read);
}

int ossl_prov_bio_write_ex(OSSL_CORE_BIO *bio, const void *data, size_t data_len,
                           size_t *written)
{
    if (c_bio_write_ex == NULL)
        return 0;
    return c_bio_write_ex(bio, data, data_len, written);
}

int ossl_prov_bio_free(OSSL_CORE_BIO *bio)
{
    if (c_bio_free == NULL)
        return 0;
    return c_bio_free(bio);
}

int ossl_prov_bio_vprintf(OSSL_CORE_BIO *bio, const char *format, va_list ap)
{
    if (c_bio_vprintf == NULL)
        return -1;
    return c_bio_vprintf(bio, format, ap);
}

int ossl_prov_bio_printf(OSSL_CORE_BIO *bio, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = ossl_prov_bio_vprintf(bio, format, ap);
    va_end(ap);

    return ret;
}

#ifndef FIPS_MODULE

/* No direct BIO support in the FIPS module */

static int bio_core_read_ex(BIO *bio, char *data, size_t data_len,
                            size_t *bytes_read)
{
    return ossl_prov_bio_read_ex(BIO_get_data(bio), data, data_len, bytes_read);
}

static int bio_core_write_ex(BIO *bio, const char *data, size_t data_len,
                             size_t *written)
{
    return ossl_prov_bio_write_ex(BIO_get_data(bio), data, data_len, written);
}

static long bio_core_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    /* We don't support this */
    assert(0);
    return 0;
}

static int bio_core_gets(BIO *bio, char *buf, int size)
{
    /* We don't support this */
    assert(0);
    return -1;
}

static int bio_core_puts(BIO *bio, const char *str)
{
    /* We don't support this */
    assert(0);
    return -1;
}

static int bio_core_new(BIO *bio)
{
    BIO_set_init(bio, 1);

    return 1;
}

static int bio_core_free(BIO *bio)
{
    BIO_set_init(bio, 0);

    return 1;
}

typedef struct bio_prov_global_st {
    BIO_METHOD *biocoremeth;
} BIO_PROV_GLOBAL;

static void *bio_prov_ossl_ctx_new(OPENSSL_CTX *libctx)
{
    BIO_PROV_GLOBAL *bpgbl = OPENSSL_zalloc(sizeof(*bpgbl));
    BIO_METHOD *biocoremeth = NULL;

    biocoremeth = BIO_meth_new(BIO_TYPE_CORE_TO_PROV, "BIO to Core filter");
    if (biocoremeth == NULL
            || !BIO_meth_set_write_ex(biocoremeth, bio_core_write_ex)
            || !BIO_meth_set_read_ex(biocoremeth, bio_core_read_ex)
            || !BIO_meth_set_puts(biocoremeth, bio_core_puts)
            || !BIO_meth_set_gets(biocoremeth, bio_core_gets)
            || !BIO_meth_set_ctrl(biocoremeth, bio_core_ctrl)
            || !BIO_meth_set_create(biocoremeth, bio_core_new)
            || !BIO_meth_set_destroy(biocoremeth, bio_core_free)) {
        OPENSSL_free(bpgbl);
        BIO_meth_free(biocoremeth);
        return NULL;
    }

    bpgbl->biocoremeth = biocoremeth;

    return bpgbl;
}

static void bio_prov_ossl_ctx_free(void *vbpgbl)
{
    BIO_PROV_GLOBAL *bpgbl = vbpgbl;

    BIO_meth_free(bpgbl->biocoremeth);
    OPENSSL_free(bpgbl);
}

static const OPENSSL_CTX_METHOD bio_prov_ossl_ctx_method = {
    bio_prov_ossl_ctx_new,
    bio_prov_ossl_ctx_free,
};

BIO *BIO_new_from_core_bio(OPENSSL_CTX *libctx, OSSL_CORE_BIO *corebio)
{
    BIO_PROV_GLOBAL *bpgbl = openssl_ctx_get_data(libctx,
                                                  OPENSSL_CTX_BIO_PROV_INDEX,
                                                  &bio_prov_ossl_ctx_method);

    BIO *outbio = BIO_new(bpgbl->biocoremeth);

    if (outbio != NULL)
        BIO_set_data(outbio, corebio);

    return outbio;
}

#endif
