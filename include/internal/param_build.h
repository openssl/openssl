/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/params.h>
#include <opentls/types.h>

#define Otls_PARAM_BLD_MAX 25

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
        otls_intmax_t i;
        otls_uintmax_t u;
        double d;
    } num;
} Otls_PARAM_BLD_DEF;

typedef struct {
    size_t curr;
    size_t total_blocks;
    size_t secure_blocks;
    Otls_PARAM_BLD_DEF params[Otls_PARAM_BLD_MAX];
} Otls_PARAM_BLD;

void otls_param_bld_init(Otls_PARAM_BLD *bld);
Otls_PARAM *otls_param_bld_to_param(Otls_PARAM_BLD *bld);
void otls_param_bld_free(Otls_PARAM *params);
Otls_PARAM *otls_param_bld_to_param_ex(Otls_PARAM_BLD *bld,
                                       Otls_PARAM *params, size_t param_n,
                                       void *data, size_t data_n,
                                       void *secure, size_t secure_n);

int otls_param_bld_push_int(Otls_PARAM_BLD *bld, const char *key, int val);
int otls_param_bld_push_uint(Otls_PARAM_BLD *bld, const char *key,
                             unsigned int val);
int otls_param_bld_push_long(Otls_PARAM_BLD *bld, const char *key,
                             long int val);
int otls_param_bld_push_ulong(Otls_PARAM_BLD *bld, const char *key,
                              unsigned long int val);
int otls_param_bld_push_int32(Otls_PARAM_BLD *bld, const char *key,
                              int32_t val);
int otls_param_bld_push_uint32(Otls_PARAM_BLD *bld, const char *key,
                               uint32_t val);
int otls_param_bld_push_int64(Otls_PARAM_BLD *bld, const char *key,
                              int64_t val);
int otls_param_bld_push_uint64(Otls_PARAM_BLD *bld, const char *key,
                               uint64_t val);
int otls_param_bld_push_size_t(Otls_PARAM_BLD *bld, const char *key,
                               size_t val);
int otls_param_bld_push_double(Otls_PARAM_BLD *bld, const char *key,
                               double val);
int otls_param_bld_push_BN(Otls_PARAM_BLD *bld, const char *key,
                           const BIGNUM *bn);
int otls_param_bld_push_utf8_string(Otls_PARAM_BLD *bld, const char *key,
                                    const char *buf, size_t bsize);
int otls_param_bld_push_utf8_ptr(Otls_PARAM_BLD *bld, const char *key,
                                 char *buf, size_t bsize);
int otls_param_bld_push_octet_string(Otls_PARAM_BLD *bld, const char *key,
                                     const void *buf, size_t bsize);
int otls_param_bld_push_octet_ptr(Otls_PARAM_BLD *bld, const char *key,
                                  void *buf, size_t bsize);
