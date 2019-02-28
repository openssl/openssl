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
#include <openssl/params.h>

static const OSSL_PARAM *OSSL_PARAM_locate(const OSSL_PARAM *p, const char *key)
{
    if (p != NULL && key != NULL)
        for (; p->key != NULL; p++)
            if (strcmp(key, p->key) == 0)
                return p;
    return NULL;
}

static int OSSL_PARAM_get_int_common(const OSSL_PARAM *p, const char *key,
                                     void *val, size_t sz)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    int neg, sign;

    if ((p = OSSL_PARAM_locate(p, key)) == NULL)
        return 0;

    sign = p->data_type == OSSL_PARAM_INTEGER;
    if (!sign && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)
        return 0;
    if (p->buffer_size == sz) {         /* Fast path */
        memcpy(val, p->buffer, sz);
    } else if (p->buffer_size < sz) {   /* Widening */
        const size_t eb = sz - p->buffer_size;

        if (is_endian.little) {
            neg = sign && (((unsigned char *)p->buffer)[p->buffer_size - 1]
                           & 0x80);
            memcpy(val, p->buffer, p->buffer_size);
            memset(((unsigned char *)val) + p->buffer_size, neg ? 0xff : 0, eb);
        } else {
            neg = sign && (*(unsigned char *)p->buffer & 0x80);
            memset(val, neg ? 0xff : 0, eb);
            memcpy(((unsigned char *)val) + eb, p->buffer, p->buffer_size);
        }
    } else {                            /* Narrowing */
        if (is_endian.little)
            memcpy(val, p->buffer, sz);
        else
            memcpy(val, ((unsigned char *)p->buffer) + (p->buffer_size - sz),
                   sz);
    }
    return 1;
}

static int OSSL_PARAM_set_int_common(const OSSL_PARAM *p, const char *key,
                                     const void *val, size_t sz)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    int neg, sign;

    if ((p = OSSL_PARAM_locate(p, key)) == NULL)
        return 0;

    sign = p->data_type == OSSL_PARAM_INTEGER;
    if (!sign && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)
        return 0;
    if (p->buffer_size == sz) {         /* Fast path */
        memcpy(p->buffer, val, sz);
    } else if (p->buffer_size > sz) {   /* Widening */
        const size_t eb = p->buffer_size - sz;

        if (is_endian.little) {
            neg = sign && (((unsigned char *)val)[p->buffer_size - 1]
                           & 0x80);
            memcpy(p->buffer, val, sz);
            memset(((unsigned char *)p->buffer) + sz, neg ? 0xff : 0, eb);
        } else {
            neg = sign && (*(unsigned char *)val & 0x80);
            memset(p->buffer, neg ? 0xff : 0, eb);
            memcpy(((unsigned char *)p->buffer) + eb, val, sz);
        }
    } else {                            /* Narrowing */
        if (is_endian.little)
            memcpy(p->buffer, val, p->buffer_size);
        else
            memcpy(p->buffer, ((unsigned char *)val) + (sz - p->buffer_size),
                   p->buffer_size);
    }
    if (p->return_size != NULL)
        *p->return_size = sz;
    return 1;
}

#define PARAM_INT(name, type) \
    int OSSL_PARAM_get_##name(const OSSL_PARAM *p, const char *key, type *val) \
    { \
        return OSSL_PARAM_get_int_common(p, key, val, sizeof(*val)); \
    } \
    int OSSL_PARAM_set_##name(const OSSL_PARAM *p, const char *key, type val) \
    { \
        return OSSL_PARAM_set_int_common(p, key, &val, sizeof(val)); \
    }

PARAM_INT(int, int)
PARAM_INT(uint, unsigned int)
PARAM_INT(int64, int64_t)
PARAM_INT(uint64, uint64_t)
PARAM_INT(long, long int)
PARAM_INT(ulong, unsigned long int)
PARAM_INT(size_t, size_t)

int OSSL_PARAM_get_BN(const OSSL_PARAM *p, const char *key, BIGNUM **val)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    BIGNUM *b;

    if ((p = OSSL_PARAM_locate(p, key)) == NULL)
        return 0;

    if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        if (is_endian.little)
            b = BN_lebin2bn(p->buffer, (int)p->buffer_size, *val);
        else
            b = BN_bin2bn(p->buffer, (int)p->buffer_size, *val);
        if (b != NULL) {
            *val = b;
            if (p->return_size != NULL)
                *p->return_size = BN_num_bytes(b);
            return 1;
        }
    }
    return 0;
}

int OSSL_PARAM_set_BN(const OSSL_PARAM *p, const char *key, const BIGNUM *val)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    int r;
    const size_t bytes = (size_t)BN_num_bytes(val);

    if ((p = OSSL_PARAM_locate(p, key)) == NULL)
        return 0;

    if (p->buffer_size < bytes)
        return 0;

    if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        if (is_endian.little)
            r = BN_bn2lebinpad(val, p->buffer, bytes);
        else
            r = BN_bn2binpad(val, p->buffer, bytes);
        if (r < 0)
            return 0;
        if (p->return_size != NULL)
            *p->return_size = r;
    }
    return 0;
}
