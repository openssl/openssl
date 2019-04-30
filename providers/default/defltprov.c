/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "internal/provider_algs.h"

/* Functions provided by the core */
static OSSL_core_get_param_types_fn *c_get_param_types = NULL;
static OSSL_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_ITEM deflt_param_types[] = {
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_NAME },
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_VERSION },
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_BUILDINFO },
    { 0, NULL }
};

static const OSSL_ITEM *deflt_get_param_types(const OSSL_PROVIDER *prov)
{
    return deflt_param_types;
}

static int deflt_get_params(const OSSL_PROVIDER *prov,
                            const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Default Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;

    return 1;
}

static const OSSL_ALGORITHM deflt_digests[] = {
    { "SHA256", "default=yes", sha256_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_ciphers[] = {
    { "AES-256-ECB", "default=yes", aes256ecb_functions },
    { "AES-192-ECB", "default=yes", aes192ecb_functions },
    { "AES-128-ECB", "default=yes", aes128ecb_functions },
    { "AES-256-CBC", "default=yes", aes256cbc_functions },
    { "AES-192-CBC", "default=yes", aes192cbc_functions },
    { "AES-128-CBC", "default=yes", aes128cbc_functions },
    { "AES-256-OFB", "default=yes", aes256ofb_functions },
    { "AES-192-OFB", "default=yes", aes192ofb_functions },
    { "AES-128-OFB", "default=yes", aes128ofb_functions },
    { "AES-256-CFB", "default=yes", aes256cfb_functions },
    { "AES-192-CFB", "default=yes", aes192cfb_functions },
    { "AES-128-CFB", "default=yes", aes128cfb_functions },
    { "AES-256-CFB1", "default=yes", aes256cfb1_functions },
    { "AES-192-CFB1", "default=yes", aes192cfb1_functions },
    { "AES-128-CFB1", "default=yes", aes128cfb1_functions },
    { "AES-256-CFB8", "default=yes", aes256cfb8_functions },
    { "AES-192-CFB8", "default=yes", aes192cfb8_functions },
    { "AES-128-CFB8", "default=yes", aes128cfb8_functions },
    { "AES-256-CTR", "default=yes", aes256ctr_functions },
    { "AES-192-CTR", "default=yes", aes192ctr_functions },
    { "AES-128-CTR", "default=yes", aes128ctr_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *deflt_query(OSSL_PROVIDER *prov,
                                         int operation_id,
                                         int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return deflt_digests;
    case OSSL_OP_CIPHER:
        return deflt_ciphers;
    }
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH deflt_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GET_PARAM_TYPES, (void (*)(void))deflt_get_param_types },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))deflt_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))deflt_query },
    { 0, NULL }
};

OSSL_provider_init_fn ossl_default_provider_init;

int ossl_default_provider_init(const OSSL_PROVIDER *provider,
                               const OSSL_DISPATCH *in,
                               const OSSL_DISPATCH **out,
                               void **provdata)
{
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_PARAM_TYPES:
            c_get_param_types = OSSL_get_core_get_param_types(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_get_core_get_params(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    *out = deflt_dispatch_table;
    *provdata = NULL;
    return 1;
}
