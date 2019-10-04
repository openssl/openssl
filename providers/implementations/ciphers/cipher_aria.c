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
#include "prov/implementations.h"

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
/* aria192ecb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ecb, ECB, 0, 192, 128, 0, block)
/* aria128ecb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ecb, ECB, 0, 128, 128, 0, block)
/* aria256cbc_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cbc, CBC, 0, 256, 128, 128, block)
/* aria192cbc_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cbc, CBC, 0, 192, 128, 128, block)
/* aria128cbc_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cbc, CBC, 0, 128, 128, 128, block)
/* aria256ofb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ofb, OFB, 0, 256, 8, 128, stream)
/* aria192ofb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ofb, OFB, 0, 192, 8, 128, stream)
/* aria128ofb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ofb, OFB, 0, 128, 8, 128, stream)
/* aria256cfb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb,  CFB, 0, 256, 8, 128, stream)
/* aria192cfb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb,  CFB, 0, 192, 8, 128, stream)
/* aria128cfb_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb,  CFB, 0, 128, 8, 128, stream)
/* aria256cfb1_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb1, CFB, 0, 256, 8, 128, stream)
/* aria192cfb1_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb1, CFB, 0, 192, 8, 128, stream)
/* aria128cfb1_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb1, CFB, 0, 128, 8, 128, stream)
/* aria256cfb8_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb8, CFB, 0, 256, 8, 128, stream)
/* aria192cfb8_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb8, CFB, 0, 192, 8, 128, stream)
/* aria128cfb8_functions */
IMPLEMENT_generic_cipher(aria, ARIA, cfb8, CFB, 0, 128, 8, 128, stream)
/* aria256ctr_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ctr, CTR, 0, 256, 8, 128, stream)
/* aria192ctr_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ctr, CTR, 0, 192, 8, 128, stream)
/* aria128ctr_functions */
IMPLEMENT_generic_cipher(aria, ARIA, ctr, CTR, 0, 128, 8, 128, stream)
