/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_PARAMS_H
# define HEADER_PARAMS_H

# include <openssl/core.h>

# ifdef  __cplusplus
extern "C" {
# endif

OSSL_PARAM *OSSL_PARAM_locate(OSSL_PARAM *p, const char *key);

# define OSSL_PARAM_DEF(key, type, size) \
        { (key), (type), NULL, (size), 0 }

# define OSSL_PARAM_int(key) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_INT, sizeof(int))
int OSSL_PARAM_set_int(OSSL_PARAM *p, const char *key, int *val);
int OSSL_PARAM_reserve_int(OSSL_PARAM *p, const char *key, int *val);
int OSSL_PARAM_get_int(OSSL_PARAM *p, const char *key, int *val);
int OSSL_PARAM_return_int(OSSL_PARAM *p, const char *key, int val);

# define OSSL_PARAM_uint(key) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_UINT, sizeof(unsigned int))
int OSSL_PARAM_set_uint(OSSL_PARAM *p, const char *key, unsigned int *val);
int OSSL_PARAM_reserve_uint(OSSL_PARAM *p, const char *key, unsigned int *val);
int OSSL_PARAM_get_uint(OSSL_PARAM *p, const char *key, unsigned int *val);
int OSSL_PARAM_return_uint(OSSL_PARAM *p, const char *key, unsigned int val);

# define OSSL_PARAM_int64(key) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_INT64, sizeof(int64_t))
int OSSL_PARAM_set_int64(OSSL_PARAM *p, const char *key, int64_t *val);
int OSSL_PARAM_reserve_int64(OSSL_PARAM *p, const char *key, int64_t *val);
int OSSL_PARAM_get_int64(OSSL_PARAM *p, const char *key, int64_t *val);
int OSSL_PARAM_return_int64(OSSL_PARAM *p, const char *key, int64_t val);

# define OSSL_PARAM_uint64(key) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_UINT64, sizeof(uint64_t))
int OSSL_PARAM_set_uint64(OSSL_PARAM *p, const char *key, uint64_t *val);
int OSSL_PARAM_reserve_uint64(OSSL_PARAM *p, const char *key, uint64_t *val);
int OSSL_PARAM_get_uint64(OSSL_PARAM *p, const char *key, uint64_t *val);
int OSSL_PARAM_return_uint64(OSSL_PARAM *p, const char *key, uint64_t val);

# define OSSL_PARAM_long(key) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_LONG, sizeof(long))
int OSSL_PARAM_set_long(OSSL_PARAM *p, const char *key, long *val);
int OSSL_PARAM_reserve_long(OSSL_PARAM *p, const char *key, long *val);
int OSSL_PARAM_get_long(OSSL_PARAM *p, const char *key, long *val);
int OSSL_PARAM_return_long(OSSL_PARAM *p, const char *key, long val);

# define OSSL_PARAM_ulong(key) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_ULONG, sizeof(unsigned long))
int OSSL_PARAM_set_ulong(OSSL_PARAM *p, const char *key, unsigned long *val);
int OSSL_PARAM_reserve_ulong(OSSL_PARAM *p, const char *key, unsigned long *val);
int OSSL_PARAM_get_ulong(OSSL_PARAM *p, const char *key, unsigned long *val);
int OSSL_PARAM_return_ulong(OSSL_PARAM *p, const char *key, unsigned long val);

# define OSSL_PARAM_size_t(key) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_SIZET, sizeof(size_t))
int OSSL_PARAM_set_size_t(OSSL_PARAM *p, const char *key, size_t *val);
int OSSL_PARAM_reserve_size_t(OSSL_PARAM *p, const char *key, size_t *val);
int OSSL_PARAM_get_size_t(OSSL_PARAM *p, const char *key, size_t *val);
int OSSL_PARAM_return_size_t(OSSL_PARAM *p, const char *key, size_t val);

# define OSSL_PARAM_double(key) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_DOUBLE, sizeof(double))
int OSSL_PARAM_set_double(OSSL_PARAM *p, const char *key, double *val);
int OSSL_PARAM_reserve_double(OSSL_PARAM *p, const char *key, double *val);
int OSSL_PARAM_get_double(OSSL_PARAM *p, const char *key, double *val);
int OSSL_PARAM_return_double(OSSL_PARAM *p, const char *key, double val);

# define OSSL_PARAM_pointer(key) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_POINTER, sizeof(void *))
int OSSL_PARAM_set_pointer(OSSL_PARAM *p, const char *key, void **val);
int OSSL_PARAM_reserve_pointer(OSSL_PARAM *p, const char *key, void **val);
int OSSL_PARAM_get_pointer(OSSL_PARAM *p, const char *key, void **val);
int OSSL_PARAM_return_pointer(OSSL_PARAM *p, const char *key, void *val);

# define OSSL_PARAM_bignum(key) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_BIGNUM, sizeof(BIGNUM *))
int OSSL_PARAM_set_bignum(OSSL_PARAM *p, const char *key, BIGNUM **val);
int OSSL_PARAM_reserve_bignum(OSSL_PARAM *p, const char *key,
                              void *buffer, size_t bufsize);
int OSSL_PARAM_return_bignum(OSSL_PARAM *p, const char *key, BIGNUM *val);
int OSSL_PARAM_get_bignum(OSSL_PARAM *p, const char *key, BIGNUM **val);
int OSSL_PARAM_retrieve_bignum(OSSL_PARAM *p, const char *key, BIGNUM **val);

# define OSSL_PARAM_buffer(key) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_BUFFER, sizeof(.))
int OSSL_PARAM_set_buffer(OSSL_PARAM *p, const char *key,
                          void *buffer, size_t bufsize);
int OSSL_PARAM_reserve_buffer(OSSL_PARAM *p, const char *key,
                              void *buffer, size_t bufsize);
int OSSL_PARAM_get_buffer(OSSL_PARAM *p, const char *key,
                          void **val, size_t *bufsiz);
int OSSL_PARAM_return_buffer(OSSL_PARAM *p, const char *key,
                             void *buffer, size_t bufsize);

# ifdef  __cplusplus
}
# endif
#endif
