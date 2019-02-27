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

static const OSSL_PARAM *param_locate(const OSSL_PARAM *p, const char *key)
{
    if (p != NULL && key != NULL)
        for (; p->key != NULL; p++)
            if (strcmp(key, p->key) == 0)
                return p;
    return NULL;
}

static int get_int_common(const OSSL_PARAM *p, const char *key,
                                     void *val, size_t sz)
{
    int neg, sign;

    sign = p->data_type == OSSL_PARAM_INTEGER;
    if (p->buffer_size < sz) {      /* Widening */
        const size_t eb = sz - p->buffer_size;

#ifdef L_ENDIAN
        neg = sign && (((unsigned char *)p->buffer)[p->buffer_size - 1] & 0x80);
        memcpy(val, p->buffer, p->buffer_size);
        memset(((unsigned char *)val) + p->buffer_size, neg ? 0xff : 0, eb);
#else
        neg = sign && (*(unsigned char *)p->buffer & 0x80);
        memset(val, neg ? 0xff : 0, eb);
        memcpy(((unsigned char *)val) + eb, p->buffer, p->buffer_size);
#endif
    } else {                        /* Narrowing */
#ifdef L_ENDIAN
        memcpy(val, p->buffer, sz);
#else
        memcpy(val, ((unsigned char *)p->buffer) + (p->buffer_size - sz), sz);
#endif
    }
    return 1;
}

static int set_int_common(const OSSL_PARAM *p, const char *key,
                                     const void *val, size_t sz)
{
    int neg, sign;

    sign = p->data_type == OSSL_PARAM_INTEGER;
    if (p->buffer_size > sz) {      /* Widening */
        const size_t eb = p->buffer_size - sz;

#ifdef L_ENDIAN
        neg = sign && (((unsigned char *)val)[p->buffer_size - 1] & 0x80);
        memcpy(p->buffer, val, sz);
        memset(((unsigned char *)p->buffer) + sz, neg ? 0xff : 0, eb);
#else
        neg = sign && (*(unsigned char *)val & 0x80);
        memset(p->buffer, neg ? 0xff : 0, eb);
        memcpy(((unsigned char *)p->buffer) + eb, val, sz);
#endif
    } else {                        /* Narrowing */
#ifdef L_ENDIAN
        memcpy(p->buffer, val, p->buffer_size);
#else
        memcpy(p->buffer, ((unsigned char *)val) + (sz - p->buffer_size),
               p->buffer_size);
#endif
    }
    if (p->return_size != NULL)
        *p->return_size = sz;
    return 1;
}

#define PARAM_INT(name, type) \
    int OSSL_PARAM_get_##name(const OSSL_PARAM *p, const char *key, type *val) \
    { \
        if ((p = param_locate(p, key)) == NULL \
            || (p->data_type != OSSL_PARAM_INTEGER \
                && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)) \
            return 0; \
        if (p->buffer_size == sizeof(type)) { \
            *val = *(type *)p->buffer; \
            return 1; \
        } \
        return get_int_common(p, key, val, sizeof(*val)); \
    } \
    int OSSL_PARAM_set_##name(const OSSL_PARAM *p, const char *key, type val) \
    { \
        if ((p = param_locate(p, key)) == NULL \
            || (p->data_type != OSSL_PARAM_INTEGER \
                && p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)) \
            return 0; \
        if (p->buffer_size == sizeof(type)) { \
            *(type *)p->buffer = val; \
            if (p->return_size != NULL) \
                *p->return_size = sizeof(type); \
            return 1; \
        } \
        return set_int_common(p, key, &val, sizeof(val)); \
    }

PARAM_INT(int, int)
PARAM_INT(long, long int)
PARAM_INT(int8, int8_t)
PARAM_INT(int16, int16_t)
PARAM_INT(int32, int32_t)
PARAM_INT(int64, int64_t)
PARAM_INT(intmax, intmax_t)

PARAM_INT(uint, unsigned int)
PARAM_INT(ulong, unsigned long int)
PARAM_INT(uint8, uint8_t)
PARAM_INT(uint16, uint16_t)
PARAM_INT(uint32, uint32_t)
PARAM_INT(uint64, uint64_t)
PARAM_INT(uintmax, uintmax_t)
PARAM_INT(size_t, size_t)

int OSSL_PARAM_get_BN(const OSSL_PARAM *p, const char *key, BIGNUM **val)
{
    BIGNUM *b;

    if ((p = param_locate(p, key)) == NULL)
        return 0;

    if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        b = BN_native2bn(p->buffer, (int)p->buffer_size, *val);
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
    int r;
    const size_t bytes = (size_t)BN_num_bytes(val);

    if ((p = param_locate(p, key)) == NULL)
        return 0;

    if (p->buffer_size < bytes)
        return 0;

    if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        r = BN_bn2nativepad(val, p->buffer, bytes);
        if (r < 0)
            return 0;
        if (p->return_size != NULL)
            *p->return_size = r;
    }
    return 0;
}

static int get_real_common(const OSSL_PARAM *p, const char *key,
                                      float *valf, double *vald)
{
#define CASE(type) \
    case sizeof(type): \
        if (vald != NULL) \
            *vald = (double)(*(type *)p->buffer); \
        else if (valf != NULL) \
            *valf = (float)(*(type *)p->buffer); \
        return 1
    if ((p = param_locate(p, key)) == NULL)
        return 0;

    if (p->data_type == OSSL_PARAM_REAL) {
        switch (p->buffer_size) {
        CASE(float);
        CASE(double);
        }
    } else if (p->data_type == OSSL_PARAM_INTEGER) {
        switch (p->buffer_size) {
        CASE(int8_t);
        CASE(int16_t);
        CASE(int32_t);
        CASE(int64_t);
        }
    } else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        switch (p->buffer_size) {
        CASE(uint8_t);
        CASE(uint16_t);
        CASE(uint32_t);
        CASE(uint64_t);
        }
    }
    return 0;
#undef CASE
}

static int set_real_common(const OSSL_PARAM *p, const char *key,
                                      const float *valf, const double *vald)
{
#define CASE(type) \
    case sizeof(type): \
        if (vald != NULL) \
            *(type *)p->buffer = (type)*vald; \
        else if (valf != NULL) \
            *(type *)p->buffer = (type)*valf; \
        return 1
    if ((p = param_locate(p, key)) == NULL)
        return 0;
    if (p->return_size != NULL)
        *p->return_size = p->buffer_size;

    if (p->data_type == OSSL_PARAM_REAL) {
        switch (p->buffer_size) {
        CASE(float);
        CASE(double);
        }
    } else if (p->data_type == OSSL_PARAM_INTEGER) {
        switch (p->buffer_size) {
        CASE(int8_t);
        CASE(int16_t);
        CASE(int32_t);
        CASE(int64_t);
        }
    } else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        switch (p->buffer_size) {
        CASE(uint8_t);
        CASE(uint16_t);
        CASE(uint32_t);
        CASE(uint64_t);
        }
    }
    return 0;    
#undef CASE
}

int OSSL_PARAM_get_float(const OSSL_PARAM *p, const char *key, float *val)
{
    return get_real_common(p, key, val, NULL);
}

int OSSL_PARAM_set_float(const OSSL_PARAM *p, const char *key, float val)
{
    return set_real_common(p, key, &val, NULL);
}

int OSSL_PARAM_get_double(const OSSL_PARAM *p, const char *key, double *val)
{
    return get_real_common(p, key, NULL, val);
}

int OSSL_PARAM_set_double(const OSSL_PARAM *p, const char *key, double val)
{
    return set_real_common(p, key, NULL, &val);
}

