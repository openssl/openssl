/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/params.h>
#include <openssl/types.h>

#define OSSL_PARAM_BLD_MAX 25

typedef struct {
    const char *key;
    int type;
    int secure;
    size_t size;
    size_t alloc_blocks;
    const BIGNUM *bn;
    const void *string;
    union {
        /*
         * These fields are never directly addressed, but their sizes are
         * imporant so that all native types can be copied here without overrun.
         */
        ossl_intmax_t i;
        ossl_uintmax_t u;
        double d;
    } num;
} OSSL_PARAM_BLD_DEF;

typedef struct {
    size_t curr;
    size_t total_blocks;
    size_t secure_blocks;
    OSSL_PARAM_BLD_DEF params[OSSL_PARAM_BLD_MAX];
} OSSL_PARAM_BLD;

void ossl_param_bld_init(OSSL_PARAM_BLD *bld);
OSSL_PARAM *ossl_param_bld_to_param(OSSL_PARAM_BLD *bld);
void ossl_param_bld_free(OSSL_PARAM *params);

int ossl_param_bld_push_int(OSSL_PARAM_BLD *bld, const char *key, int val);
int ossl_param_bld_push_uint(OSSL_PARAM_BLD *bld, const char *key,
                             unsigned int val);
int ossl_param_bld_push_long(OSSL_PARAM_BLD *bld, const char *key,
                             long int val);
int ossl_param_bld_push_ulong(OSSL_PARAM_BLD *bld, const char *key,
                              unsigned long int val);
int ossl_param_bld_push_int32(OSSL_PARAM_BLD *bld, const char *key,
                              int32_t val);
int ossl_param_bld_push_uint32(OSSL_PARAM_BLD *bld, const char *key,
                               uint32_t val);
int ossl_param_bld_push_int64(OSSL_PARAM_BLD *bld, const char *key,
                              int64_t val);
int ossl_param_bld_push_uint64(OSSL_PARAM_BLD *bld, const char *key,
                               uint64_t val);
int ossl_param_bld_push_size_t(OSSL_PARAM_BLD *bld, const char *key,
                               size_t val);
int ossl_param_bld_push_double(OSSL_PARAM_BLD *bld, const char *key,
                               double val);
int ossl_param_bld_push_BN(OSSL_PARAM_BLD *bld, const char *key,
                           const BIGNUM *bn);
int ossl_param_bld_push_BN_pad(OSSL_PARAM_BLD *bld, const char *key,
                               const BIGNUM *bn, size_t sz);
int ossl_param_bld_push_utf8_string(OSSL_PARAM_BLD *bld, const char *key,
                                    const char *buf, size_t bsize);
int ossl_param_bld_push_utf8_ptr(OSSL_PARAM_BLD *bld, const char *key,
                                 char *buf, size_t bsize);
int ossl_param_bld_push_octet_string(OSSL_PARAM_BLD *bld, const char *key,
                                     const void *buf, size_t bsize);
int ossl_param_bld_push_octet_ptr(OSSL_PARAM_BLD *bld, const char *key,
                                  void *buf, size_t bsize);
