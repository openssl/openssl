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
#include "internal/thread_once.h"

#define SET_RETURN_SIZE(p, sz) \
    if (p->return_size != NULL) \
        *p->return_size = (sz)

const OSSL_PARAM *OSSL_PARAM_locate(const OSSL_PARAM *p, const char *key)
{
    if (p != NULL && key != NULL)
        for (; p->key != NULL; p++)
            if (strcmp(key, p->key) == 0)
                return p;
    return NULL;
}

static OSSL_PARAM ossl_param_construct(const char *key, unsigned int data_type,
                                       void *buffer, size_t buffer_size,
                                       size_t *return_size)
{
    OSSL_PARAM res;

    res.key = key;
    res.data_type = data_type;
    res.buffer = buffer;
    res.buffer_size = buffer_size;
    res.return_size = return_size;
    return res;
}

#define PARAM_INT_GET(to, from) \
    case sizeof(from): \
        if (sizeof(to) >= sizeof(from)) { \
            *val = (to)*(const from *)p->buffer; \
            return 1; \
        } \
        break

#define PARAM_INT_SET(to, from) \
    case sizeof(to): \
        SET_RETURN_SIZE(p, sizeof(to)); \
        if (sizeof(to) >= sizeof(from)) { \
            *(to *)p->buffer = (to)val; \
            return 1; \
        } \
        break

#define PARAM_INT(name, type, pre) \
    int OSSL_PARAM_get_##name(const OSSL_PARAM *p, type *val) \
    { \
        if (val == NULL \
            || p == NULL \
            || (p->data_type != OSSL_PARAM_INTEGER \
                && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)) \
            return 0; \
        switch (p->buffer_size) { \
        PARAM_INT_GET(type, pre ## 32_t); \
        PARAM_INT_GET(type, pre ## 64_t); \
        } \
        return 0; \
    } \
    int OSSL_PARAM_set_##name(const OSSL_PARAM *p, type val) \
    { \
        if (p == NULL) \
            return 0; \
        SET_RETURN_SIZE(p, 0); \
        if (p->data_type == OSSL_PARAM_INTEGER \
            || p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) \
            switch (p->buffer_size) { \
            PARAM_INT_SET(pre ## 32_t, type); \
            PARAM_INT_SET(pre ## 64_t, type); \
            } \
        return 0; \
    } \
    OSSL_PARAM OSSL_PARAM_construct_##name(const char *key, type *buf, \
                                           size_t *rsize) \
    { \
        return ossl_param_construct(key, #pre[0] == 'u' \
                                         ? OSSL_PARAM_UNSIGNED_INTEGER \
                                         : OSSL_PARAM_INTEGER, \
                                    buf, sizeof(type), rsize); \
    }

PARAM_INT(int, int, int)
PARAM_INT(uint, unsigned int, uint)
PARAM_INT(long, long int, int)
PARAM_INT(ulong, unsigned long int, uint)
PARAM_INT(int32, int32_t, int)
PARAM_INT(uint32, uint32_t, uint)
PARAM_INT(int64, int64_t, int)
PARAM_INT(uint64, uint64_t, uint)
PARAM_INT(size_t, size_t, uint)

OSSL_PARAM OSSL_PARAM_construct_BN(const char *key, unsigned char *buf,
                                   size_t bsize, size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER,
                                buf, bsize, rsize);
}

int OSSL_PARAM_get_BN(const OSSL_PARAM *p, BIGNUM **val)
{
    BIGNUM *b;

    if (val == NULL || p == NULL)
        return 0;

    if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        b = BN_native2bn(p->buffer, (int)p->buffer_size, *val);
        if (b != NULL) {
            *val = b;
            return 1;
        }
    }
    return 0;
}

int OSSL_PARAM_set_BN(const OSSL_PARAM *p, const BIGNUM *val)
{
    size_t bytes;

    if (p == NULL)
        return 0;

    if (val != NULL && p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        bytes = (size_t)BN_num_bytes(val);
        SET_RETURN_SIZE(p, bytes);
        return p->buffer_size >= bytes
               && BN_bn2nativepad(val, p->buffer, bytes) >= 0;
    }
    SET_RETURN_SIZE(p, 0);
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_double(const char *key, double *buf,
                                       size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_REAL, buf, sizeof(double),
                                rsize);
}

int OSSL_PARAM_get_double(const OSSL_PARAM *p, double *val)
{
#define CASE(type) \
    case sizeof(type): \
        *val = (double)(*(type *)p->buffer); \
        return 1

    if (val == NULL || p == NULL)
        return 0;

    switch (p->data_type) {
    case OSSL_PARAM_REAL:
        switch (p->buffer_size) {
        CASE(double);
        }
        break;
    case OSSL_PARAM_INTEGER:
        switch (p->buffer_size) {
        CASE(int32_t);
        CASE(int64_t);
        }
        break;
    case OSSL_PARAM_UNSIGNED_INTEGER:
        switch (p->buffer_size) {
        CASE(uint32_t);
        CASE(uint64_t);
        }
    }
    return 0;
#undef CASE
}

int OSSL_PARAM_set_double(const OSSL_PARAM *p, double val)
{
#define CASE(type) \
    case sizeof(type): \
        *(type *)p->buffer = (type)val; \
        SET_RETURN_SIZE(p, sizeof(type)); \
        return 1

    if (p == NULL)
        return 0;

    SET_RETURN_SIZE(p, sizeof(double));
    switch (p->data_type) {
    case OSSL_PARAM_REAL:
        switch (p->buffer_size) {
        CASE(double);
        }
        break;
    case OSSL_PARAM_INTEGER:
        switch (p->buffer_size) {
        CASE(int32_t);
        CASE(int64_t);
        }
        break;
    case OSSL_PARAM_UNSIGNED_INTEGER:
        switch (p->buffer_size) {
        CASE(uint32_t);
        CASE(uint64_t);
        }
        break;
    }
    return 0;    
#undef CASE
}

OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf,
                                            size_t bsize, size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UTF8_STRING, buf, bsize,
                                rsize);
}

OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf,
                                             size_t bsize, size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_OCTET_STRING, buf, bsize,
                                rsize);
}

static int get_string_internal(const OSSL_PARAM *p, void **val, size_t max_len,
                               size_t *used_len, unsigned int type)
{
    size_t sz;

    if (val == NULL || p == NULL || p->data_type != type)
        return 0;

    sz = p->buffer_size;

    if (used_len != NULL)
        *used_len = sz;

    if (*val == NULL) {
        char *const q = OPENSSL_malloc(sz);

        if (q == NULL)
            return 0;
        *val = q;
        memcpy(q, p->buffer, sz);
        return 1;
    }
    if (max_len < sz)
        return 0;
    memcpy(*val, p->buffer, sz);
    return 1;
}

int OSSL_PARAM_get_utf8_string(const OSSL_PARAM *p, char **val, size_t max_len)
{
    return get_string_internal(p, (void **)val, max_len, NULL,
                               OSSL_PARAM_UTF8_STRING);
}

int OSSL_PARAM_get_octet_string(const OSSL_PARAM *p, void **val, size_t max_len,
                                size_t *used_len)
{
    return get_string_internal(p, val, max_len, used_len,
                               OSSL_PARAM_OCTET_STRING);
}

static int set_string_internal(const OSSL_PARAM *p, const void *val, size_t len,
                               unsigned int type)
{
    SET_RETURN_SIZE(p, len);
    if (p->data_type == type && p->buffer_size >= len) {
        memcpy(p->buffer, val, len);
        return 1;
    }
    return 0;
}

int OSSL_PARAM_set_utf8_string(const OSSL_PARAM *p, const char *val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (val == NULL)
            return 0;
    return set_string_internal(p, val, strlen(val) + 1, OSSL_PARAM_UTF8_STRING);

}
int OSSL_PARAM_set_octet_string(const OSSL_PARAM *p, const void *val,
                                size_t len)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (val == NULL)
            return 0;
    return set_string_internal(p, val, len, OSSL_PARAM_OCTET_STRING);
}

OSSL_PARAM OSSL_PARAM_construct_utf8_ptr(const char *key, char **buf,
                                         size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UTF8_PTR, buf, 0, rsize);
}

OSSL_PARAM OSSL_PARAM_construct_octet_ptr(const char *key, void **buf,
                                          size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_OCTET_PTR, buf, 0, rsize);
}

static int get_ptr_internal(const OSSL_PARAM *p, void **val, size_t *used_len,
                            unsigned int type)
{
    if (val == NULL || p == NULL || p->data_type != type)
        return 0;
    if (used_len != NULL)
        *used_len = p->buffer_size;
    *val = *(void **)p->buffer;
    return 1;
}

int OSSL_PARAM_get_utf8_ptr(const OSSL_PARAM *p, char **val)
{
    return get_ptr_internal(p, (void **)val, NULL, OSSL_PARAM_UTF8_PTR);
}

int OSSL_PARAM_get_octet_ptr(const OSSL_PARAM *p, void **val, size_t *used_len)
{
    return get_ptr_internal(p, val, used_len, OSSL_PARAM_OCTET_PTR);
}

static int set_ptr_internal(const OSSL_PARAM *p, void *val, unsigned int type,
                            size_t len)
{
    SET_RETURN_SIZE(p, len);
    if (p->data_type == type) {
        *(void **)p->buffer = val;
        return 1;
    }
    return 0;
}

int OSSL_PARAM_set_utf8_ptr(const OSSL_PARAM *p, char *val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (val == NULL)
        return 0;
    return set_ptr_internal(p, val, OSSL_PARAM_UTF8_PTR, strlen(val) + 1);
}

int OSSL_PARAM_set_octet_ptr(const OSSL_PARAM *p, void *val, size_t used_len)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (val == NULL)
        return 0;
    return set_ptr_internal(p, val, OSSL_PARAM_OCTET_PTR, used_len);
}
