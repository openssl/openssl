/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>

typedef struct {
    char *name;
    char *value;
} INFOPAIR;
DEFINE_STACK_OF(INFOPAIR)

struct provider_info_st {
    char *name;
    char *path;
    OSSL_provider_init_fn *init;
    STACK_OF(INFOPAIR) *parameters;
    unsigned int is_fallback:1;
};

extern const struct provider_info_st ossl_predefined_providers[];

void ossl_provider_info_clear(struct provider_info_st *info);
int ossl_provider_info_add_to_store(OSSL_LIB_CTX *libctx,
                                    const struct provider_info_st *entry);
int ossl_provider_info_add_parameter(struct provider_info_st *provinfo,
                                     const char *name,
                                     const char *value);
