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
# include <openssl/bn.h>

# ifdef  __cplusplus
extern "C" {
# endif

# define OSSL_PARAM_END \
    { NULL, 0, NULL, 0, NULL }

# define OSSL_PARAM_DEFN(key, type, addr, sz, rsz)    \
    { (key), (type), (addr), (sz), (rsz) }

/* Basic parameter types without return sizes */
# define OSSL_PARAM_int(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int), NULL)
# define OSSL_PARAM_uint(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(unsigned int), NULL)
# define OSSL_PARAM_long(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(long int), \
                    NULL)
# define OSSL_PARAM_ulong(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(unsigned long int), NULL)
# define OSSL_PARAM_int32(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int32_t), NULL)
# define OSSL_PARAM_uint32(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(uint32_t), NULL)
# define OSSL_PARAM_int64(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int64_t), NULL)
# define OSSL_PARAM_uint64(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(uint64_t), NULL)
# define OSSL_PARAM_size_t(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), sizeof(size_t), \
               NULL)
# define OSSL_PARAM_double(key, addr) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_REAL, (addr), sizeof(double), NULL)

/* Basic parameter types including return sizes */
# define OSSL_PARAM_SIZED_int(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int), &(sz))
# define OSSL_PARAM_SIZED_uint(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(unsigned int), &(sz))
# define OSSL_PARAM_SIZED_long(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(long int), \
                    &(sz))
# define OSSL_PARAM_SIZED_ulong(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(unsigned long int), &(sz))
# define OSSL_PARAM_SIZED_int32(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int32_t), &(sz))
# define OSSL_PARAM_SIZED_uint32(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(uint32_t), &(sz))
# define OSSL_PARAM_SIZED_int64(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int64_t), &(sz))
# define OSSL_PARAM_SIZED_uint64(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(uint64_t), &(sz))
# define OSSL_PARAM_SIZED_size_t(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), sizeof(size_t), \
               &(sz))
# define OSSL_PARAM_SIZED_double(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_REAL, (addr), sizeof(double), &(sz))

# define OSSL_PARAM_SIZED_BN(key, addr, sz, r_sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), sz, \
                    &(sz))

int OSSL_PARAM_get_int(const OSSL_PARAM *p, const char *key, int *val);
int OSSL_PARAM_get_uint(const OSSL_PARAM *p, const char *key,
                        unsigned int *val);
int OSSL_PARAM_get_long(const OSSL_PARAM *p, const char *key, long int *val);
int OSSL_PARAM_get_ulong(const OSSL_PARAM *p, const char *key,
                         unsigned long int *val);
int OSSL_PARAM_get_int32(const OSSL_PARAM *p, const char *key, int32_t *val);
int OSSL_PARAM_get_uint32(const OSSL_PARAM *p, const char *key, uint32_t *val);
int OSSL_PARAM_get_int64(const OSSL_PARAM *p, const char *key, int64_t *val);
int OSSL_PARAM_get_uint64(const OSSL_PARAM *p, const char *key, uint64_t *val);
int OSSL_PARAM_get_size_t(const OSSL_PARAM *p, const char *key, size_t *val);

int OSSL_PARAM_set_int(const OSSL_PARAM *p, const char *key, int val);
int OSSL_PARAM_set_uint(const OSSL_PARAM *p, const char *key, unsigned int val);
int OSSL_PARAM_set_long(const OSSL_PARAM *p, const char *key, long int val);
int OSSL_PARAM_set_ulong(const OSSL_PARAM *p, const char *key,
                         unsigned long int val);
int OSSL_PARAM_set_int32(const OSSL_PARAM *p, const char *key, int32_t val);
int OSSL_PARAM_set_uint32(const OSSL_PARAM *p, const char *key, uint32_t val);
int OSSL_PARAM_set_int64(const OSSL_PARAM *p, const char *key, int64_t val);
int OSSL_PARAM_set_uint64(const OSSL_PARAM *p, const char *key, uint64_t val);
int OSSL_PARAM_set_size_t(const OSSL_PARAM *p, const char *key, size_t val);

int OSSL_PARAM_get_double(const OSSL_PARAM *p, const char *key, double *val);
int OSSL_PARAM_set_double(const OSSL_PARAM *p, const char *key, double val);

int OSSL_PARAM_get_BN(const OSSL_PARAM *p, const char *key, BIGNUM **val);
int OSSL_PARAM_set_BN(const OSSL_PARAM *p, const char *key, const BIGNUM *val);

# ifdef  __cplusplus
}
# endif
#endif
