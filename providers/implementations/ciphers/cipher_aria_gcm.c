/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for ARIA GCM mode */

#include "cipher_aria_gcm.h"
#include "prov/implementations.h"

static void *aria_gcm_newctx(void *provctx, size_t keybits)
{
    PROV_ARIA_GCM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        gcm_initctx(provctx, &ctx->base, keybits, PROV_ARIA_HW_gcm(keybits), 4);
    return ctx;
}

static OSSL_OP_cipher_freectx_fn aria_gcm_freectx;
static void aria_gcm_freectx(void *vctx)
{
    PROV_ARIA_GCM_CTX *ctx = (PROV_ARIA_GCM_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

/* aria128gcm_functions */
IMPLEMENT_aead_cipher(aria, gcm, GCM, AEAD_FLAGS, 128, 8, 96);
/* aria192gcm_functions */
IMPLEMENT_aead_cipher(aria, gcm, GCM, AEAD_FLAGS, 192, 8, 96);
/* aria256gcm_functions */
IMPLEMENT_aead_cipher(aria, gcm, GCM, AEAD_FLAGS, 256, 8, 96);

