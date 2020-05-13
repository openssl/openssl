/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include "prov/provider_ctx.h"
#include "prov/bio.h"

PROV_CTX *PROV_CTX_new(void)
{
    return OPENSSL_zalloc(sizeof(PROV_CTX));
}

void PROV_CTX_free(PROV_CTX *ctx)
{
    OPENSSL_free(ctx);
}

void PROV_CTX_set0_library_context(PROV_CTX *ctx, OPENSSL_CTX *libctx)
{
    if (ctx != NULL)
        ctx->libctx = libctx;
}

void PROV_CTX_set0_handle(PROV_CTX *ctx, const OSSL_CORE_HANDLE *handle)
{
    if (ctx != NULL)
        ctx->handle = handle;
}

void PROV_CTX_set0_core_bio_method(PROV_CTX *ctx, BIO_METHOD *corebiometh)
{
    if (ctx != NULL)
        ctx->corebiometh = corebiometh;
}

OPENSSL_CTX *PROV_CTX_get0_library_context(PROV_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->libctx;
}

const OSSL_CORE_HANDLE *PROV_CTX_get0_handle(PROV_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->handle;
}

BIO_METHOD *PROV_CTX_get0_core_bio_method(PROV_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->corebiometh;
}
