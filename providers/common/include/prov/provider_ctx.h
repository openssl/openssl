/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/types.h>
#include <openssl/crypto.h>

typedef struct prov_ctx_st {
    const OSSL_PROVIDER *provider;
    OPENSSL_CTX *libctx;         /* For all provider modules */
} PROV_CTX;

/*
 * To be used anywhere the library context needs to be passed, such as to
 * fetching functions.
 */
#define PROV_LIBRARY_CONTEXT_OF(provctx)        \
    PROV_CTX_get0_library_context((provctx))

PROV_CTX *PROV_CTX_new(void);
void PROV_CTX_free(PROV_CTX *ctx);
void PROV_CTX_set0_library_context(PROV_CTX *ctx, OPENSSL_CTX *libctx);
void PROV_CTX_set0_provider(PROV_CTX *ctx, const OSSL_PROVIDER *libctx);
OPENSSL_CTX *PROV_CTX_get0_library_context(PROV_CTX *ctx);
const OSSL_PROVIDER *PROV_CTX_get0_provider(PROV_CTX *ctx);
