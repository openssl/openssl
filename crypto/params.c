/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/bn.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/cryptoerr.h>

static const OSSL_PARAM *OSSL_PARAM_locate(const OSSL_PARAM *p, const char *key)
{
    for (; p->key != NULL; p++)
        if (strcmp(key, p->key) == 0)
            return p;
    CRYPTOerr(CRYPTO_F_OSSL_PARAM_LOCATE, CRYPTO_R_PARAM_NOT_FOUND);
    ERR_add_error_data(2, "param name=", key);
    return NULL;
}


static size_t OSSL_PARAM_get_width(int type)
{
    switch (type) {
    case OSSL_PARAM_INT:        return sizeof(int);
    case OSSL_PARAM_UINT:       return sizeof(unsigned int);
    case OSSL_PARAM_INT64:      return sizeof(int64_t);
    case OSSL_PARAM_UINT64:     return sizeof(uint64_t);
    case OSSL_PARAM_LONG:       return sizeof(long);
    case OSSL_PARAM_ULONG:      return sizeof(unsigned long);
    case OSSL_PARAM_SIZET:      return sizeof(size_t);
    case OSSL_PARAM_DOUBLE:     return sizeof(double);
    }
    return -1;
}

static int OSSL_PARAM_get_int_common(const OSSL_PARAM *p, const char *key,
                                     void *val, unsigned long type)
{
    size_t width;

    if ((p = OSSL_PARAM_locate(p, key)) == NULL)
        /* Not found. */
        return 0;

    /* Type safety. */
    width = OSSL_PARAM_get_width(type);
    if (p->data_type != type || p->buffer_size != width) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_GET_INT_COMMON, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    memcpy(val, p->buffer, width);
    return 1;
}

static int OSSL_PARAM_set_int_common(const OSSL_PARAM *p, const char *key,
                                     const void *val, unsigned long type)
{
    size_t width;

    if ((p = OSSL_PARAM_locate(p, key)) == NULL)
        return 0;

    /* Type safety. */
    width = OSSL_PARAM_get_width(type);
    if (p->data_type != type || p->buffer_size != width) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_SET_INT_COMMON, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    memcpy(p->buffer, val, width);
    if (p->return_size != NULL)
        *p->return_size = width;
    return 1;
}

#define PARAM_INT(name, type, PARAM) \
    int OSSL_PARAM_get_##name(const OSSL_PARAM *p, const char *key, type *val) \
    { \
        return OSSL_PARAM_get_int_common(p, key, val, PARAM); \
    } \
    int OSSL_PARAM_set_##name(const OSSL_PARAM *p, const char *key, type val) \
    { \
        return OSSL_PARAM_set_int_common(p, key, &val, PARAM); \
    }

PARAM_INT(int, int, OSSL_PARAM_INT)
PARAM_INT(uint, unsigned int, OSSL_PARAM_UINT)
PARAM_INT(int64, int64_t, OSSL_PARAM_INT64)
PARAM_INT(uint64, uint64_t, OSSL_PARAM_UINT64)
PARAM_INT(long, long int, OSSL_PARAM_LONG)
PARAM_INT(ulong, unsigned long int, OSSL_PARAM_ULONG)
PARAM_INT(size_t, size_t, OSSL_PARAM_SIZET)

/*
 * In the get/set double functions, "width" is always sizeof(double) but
 * having parallel construction with the integer functions above seems
 * worthwhile.
 */

int OSSL_PARAM_get_double(const OSSL_PARAM *p, const char *key, double *val)
{
    size_t width;
    double *dp;

    if ((p = OSSL_PARAM_locate(p, key)) == NULL)
        return 0;

    /* Type safety. */
    width = OSSL_PARAM_get_width(OSSL_PARAM_DOUBLE);
    if (p->data_type != OSSL_PARAM_DOUBLE || p->buffer_size != width) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_GET_DOUBLE, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    dp = (double *)p->buffer;
    *val = *dp;
    return 1;
}

int OSSL_PARAM_set_double(const OSSL_PARAM *p, const char *key, double val)
{
    size_t width;
    double *dp;

    if ((p = OSSL_PARAM_locate(p, key)) == NULL)
        return 0;

    /* Type safety. */
    width = OSSL_PARAM_get_width(OSSL_PARAM_DOUBLE);
    if (p->data_type != OSSL_PARAM_DOUBLE || p->buffer_size != width) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_SET_DOUBLE, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }
    dp = (double *)p->buffer;
    *dp = val;
    if (p->return_size != NULL)
        *p->return_size = width;
    return 1;
}

int OSSL_PARAM_get_BN(const OSSL_PARAM *p, const char *key, BIGNUM **val)
{
    BIGNUM *b;

    if ((p = OSSL_PARAM_locate(p, key)) == NULL)
        return 0;

    /* Type safety. */
    if (p->data_type != OSSL_PARAM_BIGNUM) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_GET_BN, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    if ((b = BN_native2bn(p->buffer, (int)p->buffer_size, *val)) == NULL)
        return 0;
    *val = b;
    if (p->return_size != NULL)
        *p->return_size = BN_num_bytes(b);
    return 1;
}

int OSSL_PARAM_set_BN(const OSSL_PARAM *p, const char *key, const BIGNUM *val)
{
    const size_t bytes = (size_t)BN_num_bytes(val);
    int r;

    if ((p = OSSL_PARAM_locate(p, key)) == NULL)
        return 0;

    /* Type safety. */
    if (p->data_type != OSSL_PARAM_BIGNUM || p->buffer_size < bytes) {
        CRYPTOerr(CRYPTO_F_OSSL_PARAM_SET_BN, CRYPTO_R_TYPE_MISMATCH);
        return 0;
    }

    if (p->buffer_size < bytes
            || (r = BN_bn2nativepad(val, p->buffer, bytes)) < 0)
        return 0;
    if (p->return_size != NULL)
        *p->return_size = r;
    return 1;
}
