/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for ARIA cipher modes ecb, cbc, ofb, cfb, ctr */

#include "cipher_aria.h"
#include "internal/provider_algs.h"

static OSSL_OP_cipher_freectx_fn aria_freectx;
static OSSL_OP_cipher_dupctx_fn aria_dupctx;

static void aria_freectx(void *vctx)
{
    PROV_ARIA_CTX *ctx = (PROV_ARIA_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *aria_dupctx(void *ctx)
{
    PROV_ARIA_CTX *in = (PROV_ARIA_CTX *)ctx;
    PROV_ARIA_CTX *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    *ret = *in;

    return ret;
}

/* aria256ecb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ecb, ECB, 0, 256, 128, 0, block)
= { "ARIA-256-ECB", NULL };
/* aria192ecb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ecb, ECB, 0, 192, 128, 0, block)
= { "ARIA-192-ECB", NULL };
/* aria128ecb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ecb, ECB, 0, 128, 128, 0, block)
= { "ARIA-128-ECB", NULL };
/* aria256cbc_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cbc, CBC, 0, 256, 128, 128, block)
= { "ARIA-256-CBC", "ARIA256", NULL };
/* aria192cbc_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cbc, CBC, 0, 192, 128, 128, block)
= { "ARIA-192-CBC", "ARIA192", NULL };
/* aria128cbc_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cbc, CBC, 0, 128, 128, 128, block)
= { "ARIA-128-CBC", "ARIA128", NULL };
/* aria256ofb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ofb, OFB, 0, 256, 8, 128, stream)
= { "ARIA-256-OFB", NULL };
/* aria192ofb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ofb, OFB, 0, 192, 8, 128, stream)
= { "ARIA-192-OFB", NULL };
/* aria128ofb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ofb, OFB, 0, 128, 8, 128, stream)
= { "ARIA-128-OFB", NULL };
/* aria256cfb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb,  CFB, 0, 256, 8, 128, stream)
= { "ARIA-256-CFB", NULL };
/* aria192cfb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb,  CFB, 0, 192, 8, 128, stream)
= { "ARIA-192-CFB", NULL };
/* aria128cfb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb,  CFB, 0, 128, 8, 128, stream)
= { "ARIA-128-CFB", NULL };
/* aria256cfb1_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb1, CFB, 0, 256, 8, 128, stream)
= { "ARIA-256-CFB1", NULL };
/* aria192cfb1_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb1, CFB, 0, 192, 8, 128, stream)
= { "ARIA-192-CFB1", NULL };
/* aria128cfb1_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb1, CFB, 0, 128, 8, 128, stream)
= { "ARIA-128-CFB1", NULL };
/* aria256cfb8_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb8, CFB, 0, 256, 8, 128, stream)
= { "ARIA-256-CFB8", NULL };
/* aria192cfb8_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb8, CFB, 0, 192, 8, 128, stream)
= { "ARIA-192-CFB8", NULL };
/* aria128cfb8_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb8, CFB, 0, 128, 8, 128, stream)
= { "ARIA-128-CFB8", NULL };
/* aria256ctr_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ctr, CTR, 0, 256, 8, 128, stream)
= { "ARIA-256-CTR", NULL };
/* aria192ctr_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ctr, CTR, 0, 192, 8, 128, stream)
= { "ARIA-192-CTR", NULL };
/* aria128ctr_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ctr, CTR, 0, 128, 8, 128, stream)
= { "ARIA-128-CTR", NULL };
