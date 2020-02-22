/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * AES low level APIs are deprecated for public use, but still ok for internal
 * use where we're using them to implement the higher level EVP interface, as is
 * the case here.
 */
#include "internal/deprecated.h"

/* Dispatch functions for AES cipher modes ecb, cbc, ofb, cfb, ctr */

#include "cipher_aes.h"
#include "prov/implementations.h"

static OSSL_OP_cipher_freectx_fn aes_freectx;
static OSSL_OP_cipher_dupctx_fn aes_dupctx;

static void aes_freectx(void *vctx)
{
    PROV_AES_CTX *ctx = (PROV_AES_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *aes_dupctx(void *ctx)
{
    PROV_AES_CTX *in = (PROV_AES_CTX *)ctx;
    PROV_AES_CTX *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    in->base.hw->copyctx(&ret->base, &in->base);

    return ret;
}

/* aes256ecb_functions */
IMPLEMENT_generic_cipher(aes, AES, ecb, ECB, 0, 256, 128, 0, block)
/* aes192ecb_functions */
IMPLEMENT_generic_cipher(aes, AES, ecb, ECB, 0, 192, 128, 0, block)
/* aes128ecb_functions */
IMPLEMENT_generic_cipher(aes, AES, ecb, ECB, 0, 128, 128, 0, block)
/* aes256cbc_functions */
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 256, 128, 128, block)
/* aes192cbc_functions */
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 192, 128, 128, block)
/* aes128cbc_functions */
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 128, 128, 128, block)
/* aes256ofb_functions */
IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 256, 8, 128, stream)
/* aes192ofb_functions */
IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 192, 8, 128, stream)
/* aes128ofb_functions */
IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 128, 8, 128, stream)
/* aes256cfb_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb,  CFB, 0, 256, 8, 128, stream)
/* aes192cfb_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb,  CFB, 0, 192, 8, 128, stream)
/* aes128cfb_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb,  CFB, 0, 128, 8, 128, stream)
/* aes256cfb1_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb1, CFB, 0, 256, 8, 128, stream)
/* aes192cfb1_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb1, CFB, 0, 192, 8, 128, stream)
/* aes128cfb1_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb1, CFB, 0, 128, 8, 128, stream)
/* aes256cfb8_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb8, CFB, 0, 256, 8, 128, stream)
/* aes192cfb8_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb8, CFB, 0, 192, 8, 128, stream)
/* aes128cfb8_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb8, CFB, 0, 128, 8, 128, stream)
/* aes256ctr_functions */
IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 256, 8, 128, stream)
/* aes192ctr_functions */
IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 192, 8, 128, stream)
/* aes128ctr_functions */
IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 128, 8, 128, stream)
