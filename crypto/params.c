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
    if ((p)->return_size != NULL) \
        *(p)->return_size = (sz)

const OSSL_PARAM *OSSL_PARAM_locate(const OSSL_PARAM *p, const char *key)
{
    if (p != NULL && key != NULL)
        for (; p->key != NULL; p++)
            if (strcmp(key, p->key) == 0)
                return p;
    return NULL;
}

static OSSL_PARAM ossl_param_construct(const char *key, unsigned int data_type,
                                       void *data, size_t data_size,
                                       size_t *return_size)
{
    OSSL_PARAM res;

    res.key = key;
    res.data_type = data_type;
    res.data = data;
    res.data_size = data_size;
    res.return_size = return_size;
    return res;
}

int OSSL_PARAM_get_int(const OSSL_PARAM *p, int *val)
{
    if (val == NULL || p == NULL || p->data_type != OSSL_PARAM_INTEGER)
        return 0;

    switch (p->data_size) {
    case sizeof(int32_t):
        if (sizeof(int) >= sizeof(int32_t)) {
            *val = (int)*(const int32_t *)p->data;
            return 1;
        }
        break;
    case sizeof(int64_t):
        if (sizeof(int) >= sizeof(int64_t)) {
            *val = (int)*(const int64_t *)p->data;
            return 1;
        }
        break;
    }
    return 0;
}

int OSSL_PARAM_set_int(const OSSL_PARAM *p, int val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type != OSSL_PARAM_INTEGER)
        return 0;

    SET_RETURN_SIZE(p, sizeof(int)); /* Minimum expected size */
    switch (p->data_size) {
    case sizeof(int32_t):
        if (sizeof(int32_t) >= sizeof(int)) {
            SET_RETURN_SIZE(p, sizeof(int32_t));
            *(int32_t *)p->data = (int32_t)val;
            return 1;
        }
        break;
    case sizeof(int64_t):
        if (sizeof(int64_t) >= sizeof(int)) {
            SET_RETURN_SIZE(p, sizeof(int64_t));
            *(int64_t *)p->data = (int64_t)val;
            return 1;
        }
        break;
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_int(const char *key, int *buf, size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_INTEGER, buf, sizeof(int),
                                rsize);
}

int OSSL_PARAM_get_uint(const OSSL_PARAM *p, unsigned int *val)
{
    if (val == NULL
        || p == NULL
        || (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER))
        return 0;

    switch (p->data_size) {
    case sizeof(uint32_t):
        if (sizeof(unsigned int) >= sizeof(uint32_t)) {
            *val = (unsigned int)*(const uint32_t *)p->data;
            return 1;
        }
        break;
    case sizeof(uint64_t):
        if (sizeof(unsigned int) >= sizeof(uint64_t)) {
            *val = (unsigned int)*(const uint64_t *)p->data;
            return 1;
        }
        break;
    }
    return 0;
}

int OSSL_PARAM_set_uint(const OSSL_PARAM *p, unsigned int val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)
        return 0;

    SET_RETURN_SIZE(p, sizeof(unsigned int)); /* Minimum expected size */
    switch (p->data_size) {
    case sizeof(uint32_t):
        if (sizeof(uint32_t) >= sizeof(unsigned int)) {
            SET_RETURN_SIZE(p, sizeof(uint32_t));
            *(uint32_t *)p->data = (uint32_t)val;
            return 1;
        }
        break;
    case sizeof(uint64_t):
        if (sizeof(uint64_t) >= sizeof(unsigned int)) {
            SET_RETURN_SIZE(p, sizeof(uint64_t));
            *(uint64_t *)p->data = (uint64_t)val;
            return 1;
        }
        break;
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_uint(const char *key, unsigned int *buf,
                                     size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(unsigned int), rsize);
}

int OSSL_PARAM_get_long(const OSSL_PARAM *p, long int *val)
{
    if (val == NULL || p == NULL || (p->data_type != OSSL_PARAM_INTEGER))
        return 0;

    switch (p->data_size) {
    case sizeof(int32_t):
        if (sizeof(long int) >= sizeof(int32_t)) {
            *val = (long int)*(const int32_t *)p->data;
            return 1;
        } break;
    case sizeof(int64_t):
        if (sizeof(long int) >= sizeof(int64_t)) {
            *val = (long int)*(const int64_t *)p->data;
            return 1;
        }
        break;
    }
    return 0;
}

int OSSL_PARAM_set_long(const OSSL_PARAM *p, long int val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type != OSSL_PARAM_INTEGER)
        return 0;

    SET_RETURN_SIZE(p, sizeof(long int)); /* Minimum expected size */
    switch (p->data_size) {
    case sizeof(int32_t):
        if (sizeof(int32_t) >= sizeof(long int)) {
            SET_RETURN_SIZE(p, sizeof(int32_t));
            *(int32_t *)p->data = (int32_t)val;
            return 1;
        }
        break;
    case sizeof(int64_t):
        if (sizeof(int64_t) >= sizeof(long int)) {
            SET_RETURN_SIZE(p, sizeof(int64_t));
            *(int64_t *)p->data = (int64_t)val;
            return 1;
        }
        break;
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_long(const char *key, long int *buf,
                                     size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_INTEGER, buf, sizeof(long int),
                                rsize);
}

int OSSL_PARAM_get_ulong(const OSSL_PARAM *p, unsigned long int *val)
{
    if (val == NULL
        || p == NULL
        || (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER))
        return 0;

    switch (p->data_size) {
    case sizeof(uint32_t):
        if (sizeof(unsigned long int) >= sizeof(uint32_t)) {
            *val = (unsigned long int)*(const uint32_t *)p->data;
            return 1;
        }
        break;
    case sizeof(uint64_t):
        if (sizeof(unsigned long int) >= sizeof(uint64_t)) {
            *val = (unsigned long int)*(const uint64_t *)p->data;
            return 1;
        }
        break;
    }
    return 0;
}

int OSSL_PARAM_set_ulong(const OSSL_PARAM *p, unsigned long int val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)
        return 0;

    SET_RETURN_SIZE(p, sizeof(unsigned long int)); /* Minimum exp size */
    switch (p->data_size) {
    case sizeof(uint32_t):
        if (sizeof(uint32_t) >= sizeof(unsigned long int)) {
            SET_RETURN_SIZE(p, sizeof(uint32_t));
            *(uint32_t *)p->data = (uint32_t)val;
            return 1;
        }
        break;
    case sizeof(uint64_t):
        if (sizeof(uint64_t) >= sizeof(unsigned long int)) {
            SET_RETURN_SIZE(p, sizeof(uint64_t));
            *(uint64_t *)p->data = (uint64_t)val;
            return 1;
        }
        break;
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_ulong(const char *key, unsigned long int *buf,
                                      size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(unsigned long int), rsize);
}

int OSSL_PARAM_get_int32(const OSSL_PARAM *p, int32_t *val)
{
    if (val == NULL || p == NULL || (p->data_type != OSSL_PARAM_INTEGER))
        return 0;

    if (p->data_size == sizeof(int32_t)) {
        *val = *(const int32_t *)p->data;
        return 1;
    }
    return 0;
}

int OSSL_PARAM_set_int32(const OSSL_PARAM *p, int32_t val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type != OSSL_PARAM_INTEGER)
        return 0;

    SET_RETURN_SIZE(p, sizeof(int32_t)); /* Minimum expected size */
    switch (p->data_size) {
    case sizeof(int32_t):
        SET_RETURN_SIZE(p, sizeof(int32_t));
        *(int32_t *)p->data = val;
        return 1;
    case sizeof(int64_t):
        SET_RETURN_SIZE(p, sizeof(int64_t));
        *(int64_t *)p->data = (int64_t)val;
        return 1;
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_int32(const char *key, int32_t *buf,
                                      size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_INTEGER, buf,
                                sizeof(int32_t), rsize);
}

int OSSL_PARAM_get_uint32(const OSSL_PARAM *p, uint32_t *val)
{
    if (val == NULL
        || p == NULL
        || (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER))
        return 0;

    if (p->data_size == sizeof(uint32_t)) {
        *val = *(const uint32_t *)p->data;
        return 1;
    }
    return 0;
}

int OSSL_PARAM_set_uint32(const OSSL_PARAM *p, uint32_t val)
{
    if (p == NULL) return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)
        return 0;

    SET_RETURN_SIZE(p, sizeof(uint32_t)); /* Minimum expected size */
    switch (p->data_size) {
    case sizeof(uint32_t):
        SET_RETURN_SIZE(p, sizeof(uint32_t));
        *(uint32_t *)p->data = val;
        return 1;
    case sizeof(uint64_t):
        SET_RETURN_SIZE(p, sizeof(uint64_t));
        *(uint64_t *)p->data = (uint64_t)val;
        return 1;
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_uint32(const char *key, uint32_t *buf,
                                       size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(uint32_t), rsize);
}

int OSSL_PARAM_get_int64(const OSSL_PARAM *p, int64_t *val)
{
    if (val == NULL || p == NULL || (p->data_type != OSSL_PARAM_INTEGER))
        return 0;

    switch (p->data_size) {
    case sizeof(int32_t):
        *val = (int64_t)*(const int32_t *)p->data;
        return 1;
    case sizeof(int64_t):
        *val = *(const int64_t *)p->data;
        return 1;
    }
    return 0;
}

int OSSL_PARAM_set_int64(const OSSL_PARAM *p, int64_t val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type != OSSL_PARAM_INTEGER)
        return 0;

    SET_RETURN_SIZE(p, sizeof(int64_t)); /* Minimum expected size */
    switch (p->data_size) {
    case sizeof(int64_t):
        SET_RETURN_SIZE(p, sizeof(int64_t));
        *(int64_t *)p->data = val;
        return 1;
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_int64(const char *key, int64_t *buf,
                                      size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_INTEGER, buf, sizeof(int64_t),
                                rsize);
}

int OSSL_PARAM_get_uint64(const OSSL_PARAM *p, uint64_t *val)
{
    if (val == NULL
        || p == NULL
        || (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER))
        return 0;

    switch (p->data_size) {
    case sizeof(uint32_t):
        *val = (uint64_t)*(const uint32_t *)p->data;
        return 1;
    case sizeof(uint64_t):
        *val = *(const uint64_t *)p->data;
        return 1;
    }
    return 0;
}

int OSSL_PARAM_set_uint64(const OSSL_PARAM *p, uint64_t val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)
        return 0;

    SET_RETURN_SIZE(p, sizeof(uint64_t)); /* Minimum expected size */
    switch (p->data_size) {
    case sizeof(uint64_t):
        SET_RETURN_SIZE(p, sizeof(uint64_t));
        *(uint64_t *)p->data = val;
        return 1;
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_uint64(const char *key, uint64_t *buf,
                                       size_t *rsize) {
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(uint64_t), rsize);
}

int OSSL_PARAM_get_size_t(const OSSL_PARAM *p, size_t *val)
{
    if (val == NULL
        || p == NULL
        || p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)
        return 0;

    switch (p->data_size) {
    case sizeof(uint32_t):
        if (sizeof(size_t) >= sizeof(uint32_t)) {
            *val = (size_t)*(const uint32_t *)p->data;
            return 1;
        }
        break;
    case sizeof(uint64_t):
        if (sizeof(size_t) >= sizeof(uint64_t)) {
            *val = (size_t)*(const uint64_t *)p->data;
            return 1;
        }
        break;
    }
    return 0;
}

int OSSL_PARAM_set_size_t(const OSSL_PARAM *p, size_t val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)
        return 0;

    SET_RETURN_SIZE(p, sizeof(size_t)); /* Minimum expected size */
    switch (p->data_size) {
    case sizeof(uint32_t):
        if (sizeof(uint32_t) >= sizeof(size_t)) {
            SET_RETURN_SIZE(p, sizeof(uint32_t));
            *(uint32_t *)p->data = (uint32_t)val;
            return 1;
        }
        break;
    case sizeof(uint64_t):
        SET_RETURN_SIZE(p, sizeof(uint64_t));
        if (sizeof(uint64_t) >= sizeof(size_t)) {
            *(uint64_t *)p->data = (uint64_t)val;
            return 1;
        }
        break;
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_size_t(const char *key, size_t *buf,
                                       size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(size_t), rsize); }

int OSSL_PARAM_get_BN(const OSSL_PARAM *p, BIGNUM **val)
{
    BIGNUM *b;

    if (val == NULL
        || p == NULL
        || p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)
        return 0;

    b = BN_native2bn(p->data, (int)p->data_size, *val);
    if (b != NULL) {
        *val = b;
        return 1;
    }
    return 0;
}

int OSSL_PARAM_set_BN(const OSSL_PARAM *p, const BIGNUM *val)
{
    size_t bytes;

    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (val == NULL || p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)
        return 0;

    bytes = (size_t)BN_num_bytes(val);
    SET_RETURN_SIZE(p, bytes);
    return p->data_size >= bytes
        && BN_bn2nativepad(val, p->data, bytes) >= 0;
}

OSSL_PARAM OSSL_PARAM_construct_BN(const char *key, unsigned char *buf,
                                   size_t bsize, size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER,
                                buf, bsize, rsize);
}

int OSSL_PARAM_get_double(const OSSL_PARAM *p, double *val)
{
    if (val == NULL || p == NULL || p->data_type != OSSL_PARAM_REAL)
        return 0;

    switch (p->data_size) {
    case sizeof(double):
        *val = *(const double *)p->data;
        return 1;
    }
    return 0;
}

int OSSL_PARAM_set_double(const OSSL_PARAM *p, double val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (p->data_type != OSSL_PARAM_REAL)
        return 0;

    switch (p->data_size) {
    case sizeof(double):
        SET_RETURN_SIZE(p, sizeof(double));
        *(double *)p->data = val;
        return 1;
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_double(const char *key, double *buf,
                                       size_t *rsize)
{
    return ossl_param_construct(key, OSSL_PARAM_REAL, buf, sizeof(double),
                                rsize);
}

static int get_string_internal(const OSSL_PARAM *p, void **val, size_t max_len,
                               size_t *used_len, unsigned int type)
{
    size_t sz;

    if (val == NULL || p == NULL || p->data_type != type)
        return 0;

    sz = p->data_size;

    if (used_len != NULL)
        *used_len = sz;

    if (*val == NULL) {
        char *const q = OPENSSL_malloc(sz);

        if (q == NULL)
            return 0;
        *val = q;
        memcpy(q, p->data, sz);
        return 1;
    }
    if (max_len < sz)
        return 0;
    memcpy(*val, p->data, sz);
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
    if (p->data_type != type || p->data_size < len)
        return 0;

    memcpy(p->data, val, len);
    return 1;
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

static int get_ptr_internal(const OSSL_PARAM *p, const void **val,
                            size_t *used_len, unsigned int type)
{
    if (val == NULL || p == NULL || p->data_type != type)
        return 0;
    if (used_len != NULL)
        *used_len = p->data_size;
    *val = *(const void **)p->data;
    return 1;
}

int OSSL_PARAM_get_utf8_ptr(const OSSL_PARAM *p, const char **val)
{
    return get_ptr_internal(p, (const void **)val, NULL, OSSL_PARAM_UTF8_PTR);
}

int OSSL_PARAM_get_octet_ptr(const OSSL_PARAM *p, const void **val,
                             size_t *used_len)
{
    return get_ptr_internal(p, val, used_len, OSSL_PARAM_OCTET_PTR);
}

static int set_ptr_internal(const OSSL_PARAM *p, const void *val,
                            unsigned int type, size_t len)
{
    SET_RETURN_SIZE(p, len);
    if (p->data_type != type)
        return 0;
    *(const void **)p->data = val;
    return 1;
}

int OSSL_PARAM_set_utf8_ptr(const OSSL_PARAM *p, const char *val)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (val == NULL)
        return 0;
    return set_ptr_internal(p, val, OSSL_PARAM_UTF8_PTR, strlen(val) + 1);
}

int OSSL_PARAM_set_octet_ptr(const OSSL_PARAM *p, const void *val,
                             size_t used_len)
{
    if (p == NULL)
        return 0;
    SET_RETURN_SIZE(p, 0);
    if (val == NULL)
        return 0;
    return set_ptr_internal(p, val, OSSL_PARAM_OCTET_PTR, used_len);
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

int OSSL_PARAM_locate_get_int(const OSSL_PARAM *p, const char *key, int *val)
{
    return OSSL_PARAM_get_int(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_get_uint(const OSSL_PARAM *p, const char *key,
                               unsigned int *val)
{
    return OSSL_PARAM_get_uint(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_get_long(const OSSL_PARAM *p, const char *key,
                               long int *val)
{
    return OSSL_PARAM_get_long(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_get_ulong(const OSSL_PARAM *p, const char *key,
                                unsigned long int *val)
{
    return OSSL_PARAM_get_ulong(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_get_int32(const OSSL_PARAM *p, const char *key,
                                int32_t *val)
{
    return OSSL_PARAM_get_int32(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_get_uint32(const OSSL_PARAM *p, const char *key,
                                 uint32_t *val)
{
    return OSSL_PARAM_get_uint32(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_get_int64(const OSSL_PARAM *p, const char *key,
                                int64_t *val)
{
    return OSSL_PARAM_get_int64(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_get_uint64(const OSSL_PARAM *p, const char *key,
                                 uint64_t *val)
{
    return OSSL_PARAM_get_uint64(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_get_size_t(const OSSL_PARAM *p, const char *key,
                                 size_t *val)
{
    return OSSL_PARAM_get_size_t(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_set_int(const OSSL_PARAM *p, const char *key, int val)
{
    return OSSL_PARAM_set_int(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_set_uint(const OSSL_PARAM *p, const char *key,
                               unsigned int val)
{
    return OSSL_PARAM_set_uint(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_set_long(const OSSL_PARAM *p, const char *key,
                               long int val)
{
    return OSSL_PARAM_set_long(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_set_ulong(const OSSL_PARAM *p, const char *key,
                                unsigned long int val)
{
    return OSSL_PARAM_set_ulong(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_set_int32(const OSSL_PARAM *p, const char *key,
                                int32_t val)
{
    return OSSL_PARAM_set_int32(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_set_uint32(const OSSL_PARAM *p, const char *key,
                                 uint32_t val)
{
    return OSSL_PARAM_set_uint32(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_set_int64(const OSSL_PARAM *p, const char *key,
                                int64_t val)
{
    return OSSL_PARAM_set_int64(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_set_uint64(const OSSL_PARAM *p, const char *key,
                                 uint64_t val)
{
    return OSSL_PARAM_set_uint64(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_set_size_t(const OSSL_PARAM *p, const char *key,
                                 size_t val)
{
    return OSSL_PARAM_set_size_t(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_get_double(const OSSL_PARAM *p, const char *key,
                                 double *val)
{
    return OSSL_PARAM_get_double(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_set_double(const OSSL_PARAM *p, const char *key,
                                 double val)
{
    return OSSL_PARAM_set_double(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_get_BN(const OSSL_PARAM *p, const char *key,
                             BIGNUM **val)
{
    return OSSL_PARAM_get_BN(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_set_BN(const OSSL_PARAM *p, const char *key,
                             const BIGNUM *val)
{
    return OSSL_PARAM_set_BN(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_get_utf8_string(const OSSL_PARAM *p, const char *key,
                                      char **val, size_t max_len)
{
    return OSSL_PARAM_get_utf8_string(OSSL_PARAM_locate(p, key), val, max_len);
}

int OSSL_PARAM_locate_set_utf8_string(const OSSL_PARAM *p, const char *key,
                                      const char *val)
{
    return OSSL_PARAM_set_utf8_string(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_get_octet_string(const OSSL_PARAM *p, const char *key,
                                       void **val, size_t max_len,
                                       size_t *used_len)
{
    return OSSL_PARAM_get_octet_string(OSSL_PARAM_locate(p, key), val, max_len,
                                       used_len);
}

int OSSL_PARAM_locate_set_octet_string(const OSSL_PARAM *p, const char *key,
                                       const void *val, size_t len)
{
    return OSSL_PARAM_set_octet_string(OSSL_PARAM_locate(p, key), val, len);
}

int OSSL_PARAM_locate_get_utf8_ptr(const OSSL_PARAM *p, const char *key,
                                   const char **val)
{
    return OSSL_PARAM_get_utf8_ptr(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_set_utf8_ptr(const OSSL_PARAM *p, const char *key,
                                   const char *val)
{
    return OSSL_PARAM_set_utf8_ptr(OSSL_PARAM_locate(p, key), val);
}

int OSSL_PARAM_locate_get_octet_ptr(const OSSL_PARAM *p, const char *key,
                                    const void **val, size_t *used_len)
{
    return OSSL_PARAM_get_octet_ptr(OSSL_PARAM_locate(p, key), val, used_len);
}

int OSSL_PARAM_locate_set_octet_ptr(const OSSL_PARAM *p, const char *key,
                                    const void *val, size_t used_len)
{
    return OSSL_PARAM_set_octet_ptr(OSSL_PARAM_locate(p, key), val, used_len);
}

int OSSL_PARAM_optional_get_int(const OSSL_PARAM *p, const char *key, int *val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_int(p, val);
}

int OSSL_PARAM_optional_get_uint(const OSSL_PARAM *p, const char *key,
                                 unsigned int *val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_uint(p, val);
}

int OSSL_PARAM_optional_get_long(const OSSL_PARAM *p, const char *key,
                                 long int *val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_long(p, val);
}

int OSSL_PARAM_optional_get_ulong(const OSSL_PARAM *p, const char *key,
                                  unsigned long int *val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_ulong(p, val);
}

int OSSL_PARAM_optional_get_int32(const OSSL_PARAM *p, const char *key,
                                  int32_t *val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_int32(p, val);
}

int OSSL_PARAM_optional_get_uint32(const OSSL_PARAM *p, const char *key,
                                   uint32_t *val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_uint32(p, val);
}

int OSSL_PARAM_optional_get_int64(const OSSL_PARAM *p, const char *key,
                                  int64_t *val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_int64(p, val);
}

int OSSL_PARAM_optional_get_uint64(const OSSL_PARAM *p, const char *key,
                                   uint64_t *val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_uint64(p, val);
}

int OSSL_PARAM_optional_get_size_t(const OSSL_PARAM *p, const char *key,
                                   size_t *val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_size_t(p, val);
}

int OSSL_PARAM_optional_set_int(const OSSL_PARAM *p, const char *key, int val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_int(p, val);
}

int OSSL_PARAM_optional_set_uint(const OSSL_PARAM *p, const char *key,
                                 unsigned int val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_uint(p, val);
}

int OSSL_PARAM_optional_set_long(const OSSL_PARAM *p, const char *key,
                                 long int val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_long(p, val);
}

int OSSL_PARAM_optional_set_ulong(const OSSL_PARAM *p, const char *key,
                                  unsigned long int val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_ulong(p, val);
}

int OSSL_PARAM_optional_set_int32(const OSSL_PARAM *p, const char *key,
                                  int32_t val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_int32(p, val);
}

int OSSL_PARAM_optional_set_uint32(const OSSL_PARAM *p, const char *key,
                                   uint32_t val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_uint32(p, val);
}

int OSSL_PARAM_optional_set_int64(const OSSL_PARAM *p, const char *key,
                                  int64_t val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_int64(p, val);
}

int OSSL_PARAM_optional_set_uint64(const OSSL_PARAM *p, const char *key,
                                   uint64_t val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_uint64(p, val);
}

int OSSL_PARAM_optional_set_size_t(const OSSL_PARAM *p, const char *key,
                                   size_t val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_size_t(p, val);
}

int OSSL_PARAM_optional_get_double(const OSSL_PARAM *p, const char *key,
                                   double *val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_double(p, val);
}

int OSSL_PARAM_optional_set_double(const OSSL_PARAM *p, const char *key,
                                   double val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_double(p, val);
}

int OSSL_PARAM_optional_get_BN(const OSSL_PARAM *p, const char *key,
                               BIGNUM **val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_BN(p, val);
}

int OSSL_PARAM_optional_set_BN(const OSSL_PARAM *p, const char *key,
                               const BIGNUM *val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_BN(p, val);
}

int OSSL_PARAM_optional_get_utf8_string(const OSSL_PARAM *p, const char *key,
                                        char **val, size_t max_len)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_utf8_string(p, val, max_len);
}

int OSSL_PARAM_optional_set_utf8_string(const OSSL_PARAM *p, const char *key,
                                        const char *val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_utf8_string(p, val);
}

int OSSL_PARAM_optional_get_octet_string(const OSSL_PARAM *p, const char *key,
                                         void **val, size_t max_len,
                                         size_t *used_len)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_octet_string(p, val, max_len, used_len);
}

int OSSL_PARAM_optional_set_octet_string(const OSSL_PARAM *p, const char *key,
                                         const void *val, size_t len)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_octet_string(p, val, len);
}

int OSSL_PARAM_optional_get_utf8_ptr(const OSSL_PARAM *p, const char *key,
                                     const char **val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_utf8_ptr(p, val);
}

int OSSL_PARAM_optional_set_utf8_ptr(const OSSL_PARAM *p, const char *key,
                                     const char *val)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_utf8_ptr(p, val);
}

int OSSL_PARAM_optional_get_octet_ptr(const OSSL_PARAM *p, const char *key,
                                      const void **val, size_t *used_len)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_get_octet_ptr(p, val, used_len);
}

int OSSL_PARAM_optional_set_octet_ptr(const OSSL_PARAM *p, const char *key,
                                      const void *val, size_t used_len)
{
    return (p = OSSL_PARAM_locate(p, key)) == NULL
        || OSSL_PARAM_set_octet_ptr(p, val, used_len);
}
