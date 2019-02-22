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
    const size_t bytes = (size_t)BN_num_bytes(val);

    if (p == NULL)
        return 0;

    if (val != NULL && p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        SET_RETURN_SIZE(p, bytes);
        return p->buffer_size >= bytes
               && BN_bn2nativepad(val, p->buffer, bytes) >= 0;
    }
    SET_RETURN_SIZE(p, 0);
    return 0;
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
