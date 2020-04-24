/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for ARIA CCM mode */

#include "cipher_aria_ccm.h"
#include "prov/implementations.h"

static OSSL_OP_cipher_freectx_fn aria_ccm_freectx;

static void *aria_ccm_newctx(void *provctx, size_t keybits)
{
    PROV_ARIA_CCM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ccm_initctx(&ctx->base, keybits, PROV_ARIA_HW_ccm(keybits));
    return ctx;
}

static void aria_ccm_freectx(void *vctx)
{
    PROV_ARIA_CCM_CTX *ctx = (PROV_ARIA_CCM_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

/* aria128ccm functions */
IMPLEMENT_aead_cipher(aria, ccm, CCM, AEAD_FLAGS, 128, 8, 96);
/* aria192ccm functions */
IMPLEMENT_aead_cipher(aria, ccm, CCM, AEAD_FLAGS, 192, 8, 96);
/* aria256ccm functions */
IMPLEMENT_aead_cipher(aria, ccm, CCM, AEAD_FLAGS, 256, 8, 96);

