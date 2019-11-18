/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for cast cipher modes ecb, cbc, ofb, cfb */

#include "cipher_sm4.h"
#include "prov/implementations.h"

static OSSL_OP_cipher_freectx_fn sm4_freectx;
static OSSL_OP_cipher_dupctx_fn sm4_dupctx;

static void sm4_freectx(void *vctx)
{
    PROV_SM4_CTX *ctx = (PROV_SM4_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *sm4_dupctx(void *ctx)
{
    PROV_SM4_CTX *in = (PROV_SM4_CTX *)ctx;
    PROV_SM4_CTX *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    in->base.hw->copyctx(&ret->base, &in->base);

    return ret;
}

/* sm4128ecb_functions */
IMPLEMENT_generic_cipher(sm4, SM4, ecb, ECB, 0, 128, 128, 0, block)
/* sm4128cbc_functions */
IMPLEMENT_generic_cipher(sm4, SM4, cbc, CBC, 0, 128, 128, 128, block)
/* sm4128ctr_functions */
IMPLEMENT_generic_cipher(sm4, SM4, ctr, CTR, 0, 128, 8, 128, stream)
/* sm4128ofb128_functions */
IMPLEMENT_generic_cipher(sm4, SM4, ofb128, OFB, 0, 128, 8, 128, stream)
/* sm4128cfb128_functions */
IMPLEMENT_generic_cipher(sm4, SM4, cfb128,  CFB, 0, 128, 8, 128, stream)
