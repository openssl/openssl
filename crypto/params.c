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
    int sign;

    if ((p = OSSL_PARAM_locate(p, key)) == NULL)
        return 0;

    sign = p->data_type == OSSL_PARAM_INTEGER;
    if (!sign && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)
        return 0;
    if (p->buffer_size != sz)
        return 0;
    memcpy(val, p->buffer, sz);
    return 1;
}

static int OSSL_PARAM_set_int_common(const OSSL_PARAM *p, const char *key,
                                     const void *val, size_t sz)
{
    if ((p = OSSL_PARAM_locate(p, key)) == NULL)
        return 0;

    if (p->buffer_size != sz)
        return 0;
    memcpy(p->buffer, val, sz);
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
    BIGNUM *b;

    if ((p = OSSL_PARAM_locate(p, key)) == NULL
            || p->data_type != OSSL_PARAM_UNSIGNED_INTEGER
            || (b = BN_native2bn(p->buffer, (int)p->buffer_size, *val)) == NULL)
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

    if ((p = OSSL_PARAM_locate(p, key)) == NULL
            || p->buffer_size < bytes
            || p->data_type == OSSL_PARAM_UNSIGNED_INTEGER
            || (r = BN_bn2nativepad(val, p->buffer, bytes)) < 0)
        return 0;

    if (p->return_size != NULL)
        *p->return_size = r;
    return 1;
}
