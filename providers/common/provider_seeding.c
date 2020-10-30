/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include "prov/seeding.h"

static OSSL_FUNC_get_entropy_fn *c_get_entropy = NULL;
static OSSL_FUNC_cleanup_entropy_fn *c_cleanup_entropy = NULL;
static OSSL_FUNC_get_nonce_fn *c_get_nonce = NULL;
static OSSL_FUNC_cleanup_nonce_fn *c_cleanup_nonce = NULL;

int ossl_prov_seeding_from_dispatch(const OSSL_DISPATCH *fns)
{
    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_GET_ENTROPY:
            if (c_get_entropy == NULL)
                c_get_entropy = OSSL_FUNC_get_entropy(fns);
            break;
        case OSSL_FUNC_CLEANUP_ENTROPY:
            if (c_cleanup_entropy == NULL)
                c_cleanup_entropy = OSSL_FUNC_cleanup_entropy(fns);
            break;
        case OSSL_FUNC_GET_NONCE:
            if (c_get_nonce == NULL)
                c_get_nonce = OSSL_FUNC_get_nonce(fns);
            break;
        case OSSL_FUNC_CLEANUP_NONCE:
            if (c_cleanup_nonce == NULL)
                c_cleanup_nonce = OSSL_FUNC_cleanup_nonce(fns);
            break;
        }
    }
    return 1;
}

size_t ossl_prov_get_entropy(PROV_CTX *prov_ctx, unsigned char **pout,
                             int entropy, size_t min_len, size_t max_len)
{
    if (c_get_entropy == NULL)
        return 0;
    return c_get_entropy(ossl_prov_ctx_get0_handle(prov_ctx),
                         pout, entropy, min_len, max_len);
}

void ossl_prov_cleanup_entropy(PROV_CTX *prov_ctx, unsigned char *buf,
                               size_t len)
{
    if (c_cleanup_entropy != NULL)
        c_cleanup_entropy(ossl_prov_ctx_get0_handle(prov_ctx), buf, len);
}

size_t ossl_prov_get_nonce(PROV_CTX *prov_ctx, unsigned char **pout,
                           size_t min_len, size_t max_len,
                           const void *salt,size_t salt_len)
{
    if (c_get_nonce == NULL)
        return 0;
    return c_get_nonce(ossl_prov_ctx_get0_handle(prov_ctx), pout,
                       min_len, max_len, salt, salt_len);
}

void ossl_prov_cleanup_nonce(PROV_CTX *prov_ctx, unsigned char *buf, size_t len)
{
    if (c_cleanup_nonce != NULL)
        c_cleanup_nonce(ossl_prov_ctx_get0_handle(prov_ctx), buf, len);
}
