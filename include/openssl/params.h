/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef OPENtls_PARAMS_H
# define OPENtls_PARAMS_H

# include <opentls/core.h>
# include <opentls/bn.h>

# ifdef  __cplusplus
extern "C" {
# endif

# define Otls_PARAM_END \
    { NULL, 0, NULL, 0, 0 }

# define Otls_PARAM_DEFN(key, type, addr, sz)    \
    { (key), (type), (addr), (sz), 0 }

/* Basic parameter types without return sizes */
# define Otls_PARAM_int(key, addr) \
    Otls_PARAM_DEFN((key), Otls_PARAM_INTEGER, (addr), sizeof(int))
# define Otls_PARAM_uint(key, addr) \
    Otls_PARAM_DEFN((key), Otls_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(unsigned int))
# define Otls_PARAM_long(key, addr) \
    Otls_PARAM_DEFN((key), Otls_PARAM_INTEGER, (addr), sizeof(long int))
# define Otls_PARAM_ulong(key, addr) \
    Otls_PARAM_DEFN((key), Otls_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(unsigned long int))
# define Otls_PARAM_int32(key, addr) \
    Otls_PARAM_DEFN((key), Otls_PARAM_INTEGER, (addr), sizeof(int32_t))
# define Otls_PARAM_uint32(key, addr) \
    Otls_PARAM_DEFN((key), Otls_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(uint32_t))
# define Otls_PARAM_int64(key, addr) \
    Otls_PARAM_DEFN((key), Otls_PARAM_INTEGER, (addr), sizeof(int64_t))
# define Otls_PARAM_uint64(key, addr) \
    Otls_PARAM_DEFN((key), Otls_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(uint64_t))
# define Otls_PARAM_size_t(key, addr) \
    Otls_PARAM_DEFN((key), Otls_PARAM_UNSIGNED_INTEGER, (addr), sizeof(size_t))
# define Otls_PARAM_double(key, addr) \
    Otls_PARAM_DEFN((key), Otls_PARAM_REAL, (addr), sizeof(double))

# define Otls_PARAM_BN(key, bn, sz) \
    Otls_PARAM_DEFN((key), Otls_PARAM_UNSIGNED_INTEGER, (bn), (sz))
# define Otls_PARAM_utf8_string(key, addr, sz) \
    Otls_PARAM_DEFN((key), Otls_PARAM_UTF8_STRING, (addr), sz)
# define Otls_PARAM_octet_string(key, addr, sz) \
    Otls_PARAM_DEFN((key), Otls_PARAM_OCTET_STRING, (addr), sz)

# define Otls_PARAM_utf8_ptr(key, addr, sz) \
    Otls_PARAM_DEFN((key), Otls_PARAM_UTF8_PTR, &(addr), sz)
# define Otls_PARAM_octet_ptr(key, addr, sz) \
    Otls_PARAM_DEFN((key), Otls_PARAM_OCTET_PTR, &(addr), sz)

/* Search an Otls_PARAM array for a matching name */
Otls_PARAM *Otls_PARAM_locate(Otls_PARAM *p, const char *key);
const Otls_PARAM *Otls_PARAM_locate_const(const Otls_PARAM *p, const char *key);

/* Basic parameter type run-time construction */
Otls_PARAM Otls_PARAM_construct_int(const char *key, int *buf);
Otls_PARAM Otls_PARAM_construct_uint(const char *key, unsigned int *buf);
Otls_PARAM Otls_PARAM_construct_long(const char *key, long int *buf);
Otls_PARAM Otls_PARAM_construct_ulong(const char *key, unsigned long int *buf);
Otls_PARAM Otls_PARAM_construct_int32(const char *key, int32_t *buf);
Otls_PARAM Otls_PARAM_construct_uint32(const char *key, uint32_t *buf);
Otls_PARAM Otls_PARAM_construct_int64(const char *key, int64_t *buf);
Otls_PARAM Otls_PARAM_construct_uint64(const char *key, uint64_t *buf);
Otls_PARAM Otls_PARAM_construct_size_t(const char *key, size_t *buf);
Otls_PARAM Otls_PARAM_construct_BN(const char *key, unsigned char *buf,
                                   size_t bsize);
Otls_PARAM Otls_PARAM_construct_double(const char *key, double *buf);
Otls_PARAM Otls_PARAM_construct_utf8_string(const char *key, char *buf,
                                            size_t bsize);
Otls_PARAM Otls_PARAM_construct_utf8_ptr(const char *key, char **buf,
                                         size_t bsize);
Otls_PARAM Otls_PARAM_construct_octet_string(const char *key, void *buf,
                                             size_t bsize);
Otls_PARAM Otls_PARAM_construct_octet_ptr(const char *key, void **buf,
                                          size_t bsize);
Otls_PARAM Otls_PARAM_construct_end(void);

int Otls_PARAM_construct_from_text(Otls_PARAM *to,
                                   const Otls_PARAM *paramdefs,
                                   const char *key, const char *value,
                                   size_t value_n,
                                   void *buf, size_t *buf_n);
int Otls_PARAM_allocate_from_text(Otls_PARAM *to,
                                  const Otls_PARAM *paramdefs,
                                  const char *key, const char *value,
                                  size_t value_n);

int Otls_PARAM_get_int(const Otls_PARAM *p, int *val);
int Otls_PARAM_get_uint(const Otls_PARAM *p, unsigned int *val);
int Otls_PARAM_get_long(const Otls_PARAM *p, long int *val);
int Otls_PARAM_get_ulong(const Otls_PARAM *p, unsigned long int *val);
int Otls_PARAM_get_int32(const Otls_PARAM *p, int32_t *val);
int Otls_PARAM_get_uint32(const Otls_PARAM *p, uint32_t *val);
int Otls_PARAM_get_int64(const Otls_PARAM *p, int64_t *val);
int Otls_PARAM_get_uint64(const Otls_PARAM *p, uint64_t *val);
int Otls_PARAM_get_size_t(const Otls_PARAM *p, size_t *val);

int Otls_PARAM_set_int(Otls_PARAM *p, int val);
int Otls_PARAM_set_uint(Otls_PARAM *p, unsigned int val);
int Otls_PARAM_set_long(Otls_PARAM *p, long int val);
int Otls_PARAM_set_ulong(Otls_PARAM *p, unsigned long int val);
int Otls_PARAM_set_int32(Otls_PARAM *p, int32_t val);
int Otls_PARAM_set_uint32(Otls_PARAM *p, uint32_t val);
int Otls_PARAM_set_int64(Otls_PARAM *p, int64_t val);
int Otls_PARAM_set_uint64(Otls_PARAM *p, uint64_t val);
int Otls_PARAM_set_size_t(Otls_PARAM *p, size_t val);

int Otls_PARAM_get_double(const Otls_PARAM *p, double *val);
int Otls_PARAM_set_double(Otls_PARAM *p, double val);

int Otls_PARAM_get_BN(const Otls_PARAM *p, BIGNUM **val);
int Otls_PARAM_set_BN(Otls_PARAM *p, const BIGNUM *val);

int Otls_PARAM_get_utf8_string(const Otls_PARAM *p, char **val, size_t max_len);
int Otls_PARAM_set_utf8_string(Otls_PARAM *p, const char *val);

int Otls_PARAM_get_octet_string(const Otls_PARAM *p, void **val, size_t max_len,
                                size_t *used_len);
int Otls_PARAM_set_octet_string(Otls_PARAM *p, const void *val, size_t len);

int Otls_PARAM_get_utf8_ptr(const Otls_PARAM *p, const char **val);
int Otls_PARAM_set_utf8_ptr(Otls_PARAM *p, const char *val);

int Otls_PARAM_get_octet_ptr(const Otls_PARAM *p, const void **val,
                             size_t *used_len);
int Otls_PARAM_set_octet_ptr(Otls_PARAM *p, const void *val,
                             size_t used_len);

# ifdef  __cplusplus
}
# endif
#endif
