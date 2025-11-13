/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ciphercommon_ascon.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/ciphercommon_aead.h"

/*********************************************************************
 *
 *  Provider Context Implementation
 *
 *****/

void provider_ctx_free(struct provider_ctx_st *ctx)
{
    if (ctx != NULL)
        OPENSSL_clear_free(ctx, sizeof(*ctx));
}

struct provider_ctx_st *provider_ctx_new(const OSSL_CORE_HANDLE *core,
                                         const OSSL_DISPATCH *in)
{
    struct provider_ctx_st *ctx;

    if ((ctx = OPENSSL_malloc(sizeof(*ctx))) != NULL) {
        ctx->core_handle = core;
    }
    return ctx;
}
