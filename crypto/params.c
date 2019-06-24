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
#include <stdarg.h>
#include <openssl/params.h>
#include "internal/thread_once.h"
#include "internal/cryptlib.h"

OSSL_PARAM *OSSL_PARAM_locate(OSSL_PARAM *p, const char *key)
{
    if (p != NULL && key != NULL)
        for (; p->key != NULL; p++)
            if (strcmp(key, p->key) == 0)
                return p;
    return NULL;
}

const OSSL_PARAM *OSSL_PARAM_locate_const(const OSSL_PARAM *p, const char *key)
{
    return OSSL_PARAM_locate((OSSL_PARAM *)p, key);
}

static OSSL_PARAM ossl_param_construct(const char *key, unsigned int data_type,
                                       void *data, size_t data_size)
{
    OSSL_PARAM res;

    res.key = key;
    res.data_type = data_type;
    res.data = data;
    res.data_size = data_size;
    res.return_size = 0;
    return res;
}

int OSSL_PARAM_get_int(const OSSL_PARAM *p, int *val)
{
    switch (sizeof(int)) {
    case sizeof(int32_t):
        return OSSL_PARAM_get_int32(p, (int32_t *)val);
    case sizeof(int64_t):
        return OSSL_PARAM_get_int64(p, (int64_t *)val);
    }
    return 0;
}

int OSSL_PARAM_set_int(OSSL_PARAM *p, int val)
{
    switch (sizeof(int)) {
    case sizeof(int32_t):
        return OSSL_PARAM_set_int32(p, (int32_t)val);
    case sizeof(int64_t):
        return OSSL_PARAM_set_int64(p, (int64_t)val);
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_int(const char *key, int *buf)
{
    return ossl_param_construct(key, OSSL_PARAM_INTEGER, buf, sizeof(int));
}

int OSSL_PARAM_get_uint(const OSSL_PARAM *p, unsigned int *val)
{
    switch (sizeof(unsigned int)) {
    case sizeof(uint32_t):
        return OSSL_PARAM_get_uint32(p, (uint32_t *)val);
    case sizeof(uint64_t):
        return OSSL_PARAM_get_uint64(p, (uint64_t *)val);
    }
    return 0;
}

int OSSL_PARAM_set_uint(OSSL_PARAM *p, unsigned int val)
{
    switch (sizeof(unsigned int)) {
    case sizeof(uint32_t):
        return OSSL_PARAM_set_uint32(p, (uint32_t)val);
    case sizeof(uint64_t):
        return OSSL_PARAM_set_uint64(p, (uint64_t)val);
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_uint(const char *key, unsigned int *buf)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(unsigned int));
}

int OSSL_PARAM_get_long(const OSSL_PARAM *p, long int *val)
{
    switch (sizeof(long int)) {
    case sizeof(int32_t):
        return OSSL_PARAM_get_int32(p, (int32_t *)val);
    case sizeof(int64_t):
        return OSSL_PARAM_get_int64(p, (int64_t *)val);
    }
    return 0;
}

int OSSL_PARAM_set_long(OSSL_PARAM *p, long int val)
{
    switch (sizeof(long int)) {
    case sizeof(int32_t):
        return OSSL_PARAM_set_int32(p, (int32_t)val);
    case sizeof(int64_t):
        return OSSL_PARAM_set_int64(p, (int64_t)val);
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_long(const char *key, long int *buf)
{
    return ossl_param_construct(key, OSSL_PARAM_INTEGER, buf, sizeof(long int));
}

int OSSL_PARAM_get_ulong(const OSSL_PARAM *p, unsigned long int *val)
{
    switch (sizeof(unsigned long int)) {
    case sizeof(uint32_t):
        return OSSL_PARAM_get_uint32(p, (uint32_t *)val);
    case sizeof(uint64_t):
        return OSSL_PARAM_get_uint64(p, (uint64_t *)val);
    }
    return 0;
}

int OSSL_PARAM_set_ulong(OSSL_PARAM *p, unsigned long int val)
{
    switch (sizeof(unsigned long int)) {
    case sizeof(uint32_t):
        return OSSL_PARAM_set_uint32(p, (uint32_t)val);
    case sizeof(uint64_t):
        return OSSL_PARAM_set_uint64(p, (uint64_t)val);
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_ulong(const char *key, unsigned long int *buf)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(unsigned long int));
}

int OSSL_PARAM_get_int32(const OSSL_PARAM *p, int32_t *val)
{
    int64_t i64;
    uint32_t u32;
    uint64_t u64;
    double d;

    if (val == NULL || p == NULL )
        return 0;

    if (p->data_type == OSSL_PARAM_INTEGER) {
        switch (p->data_size) {
        case sizeof(int32_t):
            *val = *(const int32_t *)p->data;
            return 1;
        case sizeof(int64_t):
            i64 = *(const int64_t *)p->data;
            if (i64 >= INT32_MIN && i64 <= INT32_MAX) {
                *val = (int32_t)i64;
                return 1;
            }
            break;
        }
    } else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        switch (p->data_size) {
        case sizeof(uint32_t):
            u32 = *(const uint32_t *)p->data;
            if (u32 <= INT32_MAX) {
                *val = (int32_t)u32;
                return 1;
            }
            break;
        case sizeof(uint64_t):
            u64 = *(const uint64_t *)p->data;
            if (u64 <= INT32_MAX) {
                *val = (int32_t)u64;
                return 1;
            }
            break;
        }
    } else if (p->data_type == OSSL_PARAM_REAL) {
        switch (p->data_size) {
        case sizeof(double):
            d = *(const double *)p->data;
            if (d >= INT32_MIN && d <= INT32_MAX && d == (int32_t)d) {
                *val = (int32_t)d;
                return 1;
            }
            break;
        }
    }
    return 0;
}

int OSSL_PARAM_set_int32(OSSL_PARAM *p, int32_t val)
{
    if (p == NULL)
        return 0;
    p->return_size = 0;
    if (p->data_type == OSSL_PARAM_INTEGER) {
        p->return_size = sizeof(int32_t); /* Minimum expected size */
        switch (p->data_size) {
        case sizeof(int32_t):
            *(int32_t *)p->data = val;
            return 1;
        case sizeof(int64_t):
            p->return_size = sizeof(int64_t);
            *(int64_t *)p->data = (int64_t)val;
            return 1;
        }
    } else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER && val >= 0) {
        p->return_size = sizeof(uint32_t); /* Minimum expected size */
        switch (p->data_size) {
        case sizeof(uint32_t):
            *(uint32_t *)p->data = (uint32_t)val;
            return 1;
        case sizeof(uint64_t):
            p->return_size = sizeof(uint64_t);
            *(uint64_t *)p->data = (uint64_t)val;
            return 1;
        }
    } else if (p->data_type == OSSL_PARAM_REAL) {
        p->return_size = sizeof(double);
        switch (p->data_size) {
        case sizeof(double):
            *(double *)p->data = (double)val;
            return 1;
        }
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_int32(const char *key, int32_t *buf)
{
    return ossl_param_construct(key, OSSL_PARAM_INTEGER, buf,
                                sizeof(int32_t));
}

int OSSL_PARAM_get_uint32(const OSSL_PARAM *p, uint32_t *val)
{
    int32_t i32;
    int64_t i64;
    uint64_t u64;
    double d;

    if (val == NULL || p == NULL)
        return 0;

    if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        switch (p->data_size) {
        case sizeof(uint32_t):
            *val = *(const uint32_t *)p->data;
            return 1;
        case sizeof(uint64_t):
            u64 = *(const uint64_t *)p->data;
            if (u64 <= UINT32_MAX) {
                *val = (uint32_t)u64;
                return 1;
            }
            break;
        }
    } else if (p->data_type == OSSL_PARAM_INTEGER) {
        switch (p->data_size) {
        case sizeof(int32_t):
            i32 = *(const int32_t *)p->data;
            if (i32 >= 0) {
                *val = i32;
                return 1;
            }
            break;
        case sizeof(int64_t):
            i64 = *(const int64_t *)p->data;
            if (i64 >= 0 && i64 <= UINT32_MAX) {
                *val = (uint32_t)i64;
                return 1;
            }
            break;
        }
    } else if (p->data_type == OSSL_PARAM_REAL) {
        switch (p->data_size) {
        case sizeof(double):
            d = *(const double *)p->data;
            if (d >= 0 && d <= UINT32_MAX && d == (uint32_t)d) {
                *val = (uint32_t)d;
                return 1;
            }
            break;
        }
    }
    return 0;
}

int OSSL_PARAM_set_uint32(OSSL_PARAM *p, uint32_t val)
{
    if (p == NULL)
        return 0;
    p->return_size = 0;

    if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        p->return_size = sizeof(uint32_t); /* Minimum expected size */
        switch (p->data_size) {
        case sizeof(uint32_t):
            *(uint32_t *)p->data = val;
            return 1;
        case sizeof(uint64_t):
            p->return_size = sizeof(uint64_t);
            *(uint64_t *)p->data = val;
            return 1;
        }
    } else if (p->data_type == OSSL_PARAM_INTEGER) {
        p->return_size = sizeof(int32_t); /* Minimum expected size */
        switch (p->data_size) {
        case sizeof(int32_t):
            if (val <= INT32_MAX) {
                *(int32_t *)p->data = (int32_t)val;
                return 1;
            }
            break;
        case sizeof(int64_t):
            p->return_size = sizeof(int64_t);
            *(int64_t *)p->data = (int64_t)val;
            return 1;
        }
    } else if (p->data_type == OSSL_PARAM_REAL) {
        p->return_size = sizeof(double);
        switch (p->data_size) {
        case sizeof(double):
            *(double *)p->data = (double)val;
            return 1;
        }
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_uint32(const char *key, uint32_t *buf)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(uint32_t));
}

int OSSL_PARAM_get_int64(const OSSL_PARAM *p, int64_t *val)
{
    uint64_t u64;
    double d;

    if (val == NULL || p == NULL )
        return 0;

    if (p->data_type == OSSL_PARAM_INTEGER) {
        switch (p->data_size) {
        case sizeof(int32_t):
            *val = *(const int32_t *)p->data;
            return 1;
        case sizeof(int64_t):
            *val = *(const int64_t *)p->data;
            return 1;
        }
    } else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        switch (p->data_size) {
        case sizeof(uint32_t):
            *val = *(const uint32_t *)p->data;
            return 1;
        case sizeof(uint64_t):
            u64 = *(const uint64_t *)p->data;
            if (u64 <= INT64_MAX) {
                *val = (int64_t)u64;
                return 1;
            }
            break;
        }
    } else if (p->data_type == OSSL_PARAM_REAL) {
        switch (p->data_size) {
        case sizeof(double):
            d = *(const double *)p->data;
            if (d >= INT64_MIN && d <= INT64_MAX && d == (int64_t)d) {
                *val = (int64_t)d;
                return 1;
            }
            break;
        }
    }
    return 0;
}

int OSSL_PARAM_set_int64(OSSL_PARAM *p, int64_t val)
{
    uint64_t u64;

    if (p == NULL)
        return 0;
    p->return_size = 0;
    if (p->data_type == OSSL_PARAM_INTEGER) {
        p->return_size = sizeof(int64_t); /* Expected size */
        switch (p->data_size) {
        case sizeof(int32_t):
            if (val >= INT32_MIN && val <= INT32_MAX) {
                p->return_size = sizeof(int32_t);
                *(int32_t *)p->data = (int32_t)val;
                return 1;
            }
            break;
        case sizeof(int64_t):
            *(int64_t *)p->data = val;
            return 1;
        }
    } else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER && val >= 0) {
        p->return_size = sizeof(uint64_t); /* Expected size */
        switch (p->data_size) {
        case sizeof(uint32_t):
            if (val <= UINT32_MAX) {
                p->return_size = sizeof(uint32_t);
                *(uint32_t *)p->data = (uint32_t)val;
                return 1;
            }
            break;
        case sizeof(uint64_t):
            *(uint64_t *)p->data = (uint64_t)val;
            return 1;
        }
    } else if (p->data_type == OSSL_PARAM_REAL) {
        p->return_size = sizeof(double);
        switch (p->data_size) {
        case sizeof(double):
            u64 = val < 0 ? -val : val;
            if ((u64 >> 53) == 0) { /* 53 significant bits in the mantissa */
                *(double *)p->data = (double)val;
                return 1;
            }
            break;
        }
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_int64(const char *key, int64_t *buf)
{
    return ossl_param_construct(key, OSSL_PARAM_INTEGER, buf, sizeof(int64_t));
}

int OSSL_PARAM_get_uint64(const OSSL_PARAM *p, uint64_t *val)
{
    int32_t i32;
    int64_t i64;
    double d;

    if (val == NULL || p == NULL)
        return 0;

    if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        switch (p->data_size) {
        case sizeof(uint32_t):
            *val = *(const uint32_t *)p->data;
            return 1;
        case sizeof(uint64_t):
            *val = *(const uint64_t *)p->data;
            return 1;
        }
    } else if (p->data_type == OSSL_PARAM_INTEGER) {
        switch (p->data_size) {
        case sizeof(int32_t):
            i32 = *(const int32_t *)p->data;
            if (i32 >= 0) {
                *val = (uint64_t)i32;
                return 1;
            }
            break;
        case sizeof(int64_t):
            i64 = *(const int64_t *)p->data;
            if (i64 >= 0) {
                *val = (uint64_t)i64;
                return 1;
            }
            break;
        }
    } else if (p->data_type == OSSL_PARAM_REAL) {
        switch (p->data_size) {
        case sizeof(double):
            d = *(const double *)p->data;
            if (d >= 0 && d <= INT64_MAX && d == (uint64_t)d) {
                *val = (uint64_t)d;
                return 1;
            }
            break;
        }
    }
    return 0;
}

int OSSL_PARAM_set_uint64(OSSL_PARAM *p, uint64_t val)
{
    if (p == NULL)
        return 0;
    p->return_size = 0;

    if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        p->return_size = sizeof(uint64_t); /* Expected size */
        switch (p->data_size) {
        case sizeof(uint32_t):
            if (val <= UINT32_MAX) {
                p->return_size = sizeof(uint32_t);
                *(uint32_t *)p->data = (uint32_t)val;
                return 1;
            }
            break;
        case sizeof(uint64_t):
            *(uint64_t *)p->data = val;
            return 1;
        }
    } else if (p->data_type == OSSL_PARAM_INTEGER) {
        p->return_size = sizeof(int64_t); /* Expected size */
        switch (p->data_size) {
        case sizeof(int32_t):
            if (val <= INT32_MAX) {
                p->return_size = sizeof(int32_t);
                *(int32_t *)p->data = (int32_t)val;
                return 1;
            }
            break;
        case sizeof(int64_t):
            if (val <= INT64_MAX) {
                *(int64_t *)p->data = (int64_t)val;
                return 1;
            }
            break;
        }
    } else if (p->data_type == OSSL_PARAM_REAL) {
        p->return_size = sizeof(double);
        switch (p->data_size) {
        case sizeof(double):
            if ((val >> 53) == 0) { /* 53 significant bits in the mantissa */
                *(double *)p->data = (double)val;
                return 1;
            }
            break;
        }
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_uint64(const char *key, uint64_t *buf)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(uint64_t));
}

int OSSL_PARAM_get_size_t(const OSSL_PARAM *p, size_t *val)
{
    switch (sizeof(size_t)) {
    case sizeof(uint32_t):
        return OSSL_PARAM_get_uint32(p, (uint32_t *)val);
    case sizeof(uint64_t):
        return OSSL_PARAM_get_uint64(p, (uint64_t *)val);
    }
    return 0;
}

int OSSL_PARAM_set_size_t(OSSL_PARAM *p, size_t val)
{
    switch (sizeof(size_t)) {
    case sizeof(uint32_t):
        return OSSL_PARAM_set_uint32(p, (uint32_t)val);
    case sizeof(uint64_t):
        return OSSL_PARAM_set_uint64(p, (uint64_t)val);
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_size_t(const char *key, size_t *buf)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(size_t));
}

#ifndef FIPS_MODE
/*
 * TODO(3.0): Make this available in FIPS mode.
 *
 * Temporarily we don't include these functions in FIPS mode to avoid pulling
 * in the entire BN sub-library into the module at this point.
 */
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

int OSSL_PARAM_set_BN(OSSL_PARAM *p, const BIGNUM *val)
{
    size_t bytes;

    if (p == NULL)
        return 0;
    p->return_size = 0;
    if (val == NULL || p->data_type != OSSL_PARAM_UNSIGNED_INTEGER)
        return 0;

    /* For the moment, only positive values are permitted */
    if (BN_is_negative(val))
        return 0;

    bytes = (size_t)BN_num_bytes(val);
    p->return_size = bytes;
    return p->data_size >= bytes
        && BN_bn2nativepad(val, p->data, bytes) >= 0;
}

OSSL_PARAM OSSL_PARAM_construct_BN(const char *key, unsigned char *buf,
                                   size_t bsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER,
                                buf, bsize);
}
#endif

int OSSL_PARAM_get_double(const OSSL_PARAM *p, double *val)
{
    int64_t i64;
    uint64_t u64;

    if (val == NULL || p == NULL)
        return 0;

    if (p->data_type == OSSL_PARAM_REAL) {
        switch (p->data_size) {
        case sizeof(double):
            *val = *(const double *)p->data;
            return 1;
        }
    } else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        switch (p->data_size) {
        case sizeof(uint32_t):
            *val = *(const uint32_t *)p->data;
            return 1;
        case sizeof(uint64_t):
            u64 = *(const uint64_t *)p->data;
            if ((u64 >> 53) == 0) { /* 53 significant bits in the mantissa */
                *val = (double)u64;
                return 1;
            }
            break;
        }
    } else if (p->data_type == OSSL_PARAM_INTEGER) {
        switch (p->data_size) {
        case sizeof(int32_t):
            *val = *(const int32_t *)p->data;
            return 1;
        case sizeof(int64_t):
            i64 = *(const int64_t *)p->data;
            u64 = i64 < 0 ? -i64 : i64;
            if ((u64 >> 53) == 0) { /* 53 significant bits in the mantissa */
                *val = 0.0 + i64;
                return 1;
            }
            break;
        }
    }
    return 0;
}

int OSSL_PARAM_set_double(OSSL_PARAM *p, double val)
{
    if (p == NULL)
        return 0;
    p->return_size = 0;

    if (p->data_type == OSSL_PARAM_REAL) {
        p->return_size = sizeof(double);
        switch (p->data_size) {
        case sizeof(double):
            *(double *)p->data = val;
            return 1;
        }
    } else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER
               && val == (uintmax_t)val) {
        p->return_size = sizeof(double);
        switch (p->data_size) {
        case sizeof(uint32_t):
            if (val >= 0 && val <= UINT32_MAX) {
                p->return_size = sizeof(uint32_t);
                *(uint32_t *)p->data = (uint32_t)val;
                return 1;
            }
            break;
        case sizeof(uint64_t):
            if (val >= 0 && val <= UINT64_MAX) {
                p->return_size = sizeof(uint64_t);
                *(uint64_t *)p->data = (uint64_t)val;
                return 1;
            }
            break;            }
    } else if (p->data_type == OSSL_PARAM_INTEGER && val == (intmax_t)val) {
        p->return_size = sizeof(double);
        switch (p->data_size) {
        case sizeof(int32_t):
            if (val >= INT32_MIN && val <= INT32_MAX) {
                p->return_size = sizeof(int32_t);
                *(int32_t *)p->data = (int32_t)val;
                return 1;
            }
            break;
        case sizeof(int64_t):
            if (val >= INT64_MIN && val <= INT64_MAX) {
                p->return_size = sizeof(int64_t);
                *(int64_t *)p->data = (int64_t)val;
                return 1;
            }
            break;
        }
    }
    return 0;
}

OSSL_PARAM OSSL_PARAM_construct_double(const char *key, double *buf)
{
    return ossl_param_construct(key, OSSL_PARAM_REAL, buf, sizeof(double));
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

static int set_string_internal(OSSL_PARAM *p, const void *val, size_t len,
                               unsigned int type)
{
    p->return_size = len;
    if (p->data_type != type || p->data_size < len)
        return 0;

    memcpy(p->data, val, len);
    return 1;
}

int OSSL_PARAM_set_utf8_string(OSSL_PARAM *p, const char *val)
{
    if (p == NULL)
        return 0;

    p->return_size = 0;
    if (val == NULL)
        return 0;
    return set_string_internal(p, val, strlen(val) + 1, OSSL_PARAM_UTF8_STRING);
}

int OSSL_PARAM_set_octet_string(OSSL_PARAM *p, const void *val,
                                size_t len)
{
    if (p == NULL)
        return 0;

    p->return_size = 0;
    if (val == NULL)
        return 0;
    return set_string_internal(p, val, len, OSSL_PARAM_OCTET_STRING);
}

OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf,
                                            size_t bsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UTF8_STRING, buf, bsize);
}

OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf,
                                             size_t bsize)
{
    return ossl_param_construct(key, OSSL_PARAM_OCTET_STRING, buf, bsize);
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

static int set_ptr_internal(OSSL_PARAM *p, const void *val,
                            unsigned int type, size_t len)
{
    p->return_size = len;
    if (p->data_type != type)
        return 0;
    *(const void **)p->data = val;
    return 1;
}

int OSSL_PARAM_set_utf8_ptr(OSSL_PARAM *p, const char *val)
{
    if (p == NULL)
        return 0;
    p->return_size = 0;
    if (val == NULL)
        return 0;
    return set_ptr_internal(p, val, OSSL_PARAM_UTF8_PTR, strlen(val) + 1);
}

int OSSL_PARAM_set_octet_ptr(OSSL_PARAM *p, const void *val,
                             size_t used_len)
{
    if (p == NULL)
        return 0;
    p->return_size = 0;
    if (val == NULL)
        return 0;
    return set_ptr_internal(p, val, OSSL_PARAM_OCTET_PTR, used_len);
}

OSSL_PARAM OSSL_PARAM_construct_utf8_ptr(const char *key, char **buf,
                                         size_t bsize)
{
    return ossl_param_construct(key, OSSL_PARAM_UTF8_PTR, buf, bsize);
}

OSSL_PARAM OSSL_PARAM_construct_octet_ptr(const char *key, void **buf,
                                          size_t bsize)
{
    return ossl_param_construct(key, OSSL_PARAM_OCTET_PTR, buf, bsize);
}

OSSL_PARAM OSSL_PARAM_construct_end(void)
{
    OSSL_PARAM end = OSSL_PARAM_END;

    return end;
}

static void param_process(va_list ap, const char *name,
                          void (*f)(const char *name, int type, size_t len,
                                    const void *value, void *arg, int bignum),
                          void *arg)
{
    int type;

    for (; name != NULL; name = va_arg(ap, const char *)) {
        type = va_arg(ap, int);
#define T(type, type_name, param_type) \
    case OSSL_PARAM_TYPE_ ## type_name: { \
            type val = va_arg(ap, type); \
            \
            f(name, OSSL_PARAM_ ## param_type, sizeof(val), &val, arg, 0); \
            break; \
        }
        switch (type) {
        T(int, int, INTEGER);
        T(unsigned int, uint, UNSIGNED_INTEGER);
        T(long, long, INTEGER);
        T(unsigned long, ulong, UNSIGNED_INTEGER);
        T(int32_t, int32, INTEGER);
        T(uint32_t, uint32, UNSIGNED_INTEGER);
        T(int64_t, int64, INTEGER);
        T(uint64_t, uint64, UNSIGNED_INTEGER);
        T(size_t, size_t, UNSIGNED_INTEGER);
        T(double, double, REAL);
#undef T
        case OSSL_PARAM_TYPE_BN: {
            size_t len = va_arg(ap, size_t);
            BIGNUM *bn = va_arg(ap, BIGNUM *);

            if (len == 0)
                len = BN_num_bytes(bn);
            f(name, OSSL_PARAM_UNSIGNED_INTEGER, len, bn, arg, 1);
            break;           
        }
        case OSSL_PARAM_TYPE_utf8: {
            size_t len = va_arg(ap, size_t);
            char *s = va_arg(ap, char *);

            if (len == 0)
                len = strlen(s);
            f(name, OSSL_PARAM_UTF8_STRING, len, s, arg, 0);
            break;
        }
        case OSSL_PARAM_TYPE_octet: {
            size_t len = va_arg(ap, size_t);
            unsigned char *s = va_arg(ap, unsigned char *);

            f(name, OSSL_PARAM_OCTET_STRING, len, s, arg, 0);
            break;
        }
        }
    }
}

union param_value_un {
    OSSL_UNION_ALIGN;
};

#define ALIGN_SIZE sizeof(union param_value_un)

struct param_size_st {
    size_t n;
    size_t names;
    size_t blocks;
};

static void param_size(const char *name, int type, size_t len,
                       const void *value, void *arg, int bignum)
{
    struct param_size_st *s = (struct param_size_st *)arg;

    s->n++;
    s->names += strlen(name) + 1;
    s->blocks += (len + ALIGN_SIZE - 1) / ALIGN_SIZE;
}

struct param_build_st {
    OSSL_PARAM *param;
    union param_value_un *values;
    char *names;
};

static void param_build(const char *name, int type, size_t len,
                        const void *value, void *arg, int bignum)
{
    struct param_build_st *s = (struct param_build_st *)arg;
    OSSL_PARAM *p = s->param++;
    size_t l;

    p->key = s->names;
    p->data_type = type;
    p->data = s->values;
    p->data_size = len;

    l = strlen(name) + 1;
    memcpy(s->names, name, l);
    s->names += l;

    if (value == NULL)
        memset(s->values, 0, len);
    else if (bignum)
        BN_bn2nativepad((const BIGNUM *)value, (unsigned char *)s->values, len);
    else
        memcpy(s->values, value, len);
    s->values += (len + ALIGN_SIZE - 1) / ALIGN_SIZE;
}

OSSL_PARAM *OSSL_PARAM_build(const char *name, ...)
{
    va_list ap;
    struct param_size_st size;
    struct param_build_st build;
    OSSL_PARAM *res;
    size_t s;

    memset(&size, 0, sizeof(size));
    size.n = 1; /* For the end */

    va_start(ap, name);
    param_process(ap, name, &param_size, &size);
    va_end(ap);

    s = size.n * sizeof(OSSL_PARAM);
    s = ((s + ALIGN_SIZE - 1) / ALIGN_SIZE) * ALIGN_SIZE;
    res = OPENSSL_malloc(s
                         + size.blocks * ALIGN_SIZE
                         + size.names);
    if (res != NULL) {
        memset(&build, 0, sizeof(build));
        build.param = res;
        build.values = (union param_value_un *)(((unsigned char *)res) + s);
        build.names = (char *)(build.values + size.blocks);

        va_start(ap, name);
        param_process(ap, name, &param_build, &build);
        va_end(ap);
        *build.param = OSSL_PARAM_construct_end();
    }
    return res;
}

void OSSL_PARAM_build_free(OSSL_PARAM *params)
{
    OPENSSL_free(params);
}
