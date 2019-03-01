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

# define OSSL_PARAM_DEF(key, type, addr, sz, rsz)    \
    { (key), (type), (addr), (sz), (rsz) }

# define OSSL_PARAM_int(key, addr) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_INT, (addr), sizeof(int), NULL)
int OSSL_PARAM_get_int(const OSSL_PARAM *p, const char *key, int *val);
int OSSL_PARAM_set_int(const OSSL_PARAM *p, const char *key, int val);
# define OSSL_PARAM_uint(key, addr) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_UINT, (addr), sizeof(unsigned int), NULL)
int OSSL_PARAM_set_uint(const OSSL_PARAM *p, const char *key, unsigned int val);
int OSSL_PARAM_get_uint(const OSSL_PARAM *p, const char *key,
                        unsigned int *val);

# define OSSL_PARAM_int64(key, addr) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_INT64, (addr), sizeof(int64_t), NULL)
int OSSL_PARAM_get_int64(const OSSL_PARAM *p, const char *key, int64_t *val);
int OSSL_PARAM_set_int64(const OSSL_PARAM *p, const char *key, int64_t val);
# define OSSL_PARAM_uint64(key, addr) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_UINT64, (addr), sizeof(uint64_t), NULL)
int OSSL_PARAM_get_uint64(const OSSL_PARAM *p, const char *key, uint64_t *val);
int OSSL_PARAM_set_uint64(const OSSL_PARAM *p, const char *key, uint64_t val);

# define OSSL_PARAM_long(key, addr) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_LONG, (addr), sizeof(long), NULL)
# define OSSL_PARAM_ulong(key, addr) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_ULONG, (addr), sizeof(unsigned long), NULL)
int OSSL_PARAM_get_long(const OSSL_PARAM *p, const char *key,
                        long int *val);
int OSSL_PARAM_get_ulong(const OSSL_PARAM *p, const char *key,
                         unsigned long int *val);
int OSSL_PARAM_set_long(const OSSL_PARAM *p, const char *key, long int val);
int OSSL_PARAM_set_ulong(const OSSL_PARAM *p, const char *key,
                         unsigned long int val);

# define OSSL_PARAM_size_t(key, addr) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_SIZET, (addr), sizeof(size_t), NULL)
int OSSL_PARAM_get_size_t(const OSSL_PARAM *p, const char *key, size_t *val);
int OSSL_PARAM_set_size_t(const OSSL_PARAM *p, const char *key, size_t val);

# define OSSL_PARAM_double(key, addr) \
    OSSL_PARAM_DEF((key), OSSL_PARAM_DOUBLE, (addr), sizeof(double), NULL)
int OSSL_PARAM_get_double(const OSSL_PARAM *p, const char *key, double *val);
int OSSL_PARAM_set_double(const OSSL_PARAM *p, const char *key, double val);

int OSSL_PARAM_get_BN(const OSSL_PARAM *p, const char *key, BIGNUM **val);
int OSSL_PARAM_set_BN(const OSSL_PARAM *p, const char *key, const BIGNUM *val);

# ifdef  __cplusplus
}
# endif
#endif
