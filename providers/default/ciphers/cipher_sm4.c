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
#include "internal/provider_algs.h"

/* TODO (3.0) Figure out what flags to pass */
#define SM4_FLAGS EVP_CIPH_FLAG_DEFAULT_ASN1

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
    *ret = *in;

    return ret;
}

/* sm4128ecb_functions */
IMPLEMENT_generic_cipher(sm4, SM4, ecb, ECB, SM4_FLAGS, 128, 128, 0, block)
= { "SM4-ECB", NULL };
/* sm4128cbc_functions */
IMPLEMENT_generic_cipher(sm4, SM4, cbc, CBC, SM4_FLAGS, 128, 128, 128, block)
= { "SM4-CBC", "SM4", NULL };
/* sm4128ctr_functions */
IMPLEMENT_generic_cipher(sm4, SM4, ctr, CTR, SM4_FLAGS, 128, 8, 128, stream)
= { "SM4-CTR", NULL };
/* sm4128ofb128_functions */
IMPLEMENT_generic_cipher(sm4, SM4, ofb128, OFB, SM4_FLAGS, 128, 8, 128, stream)
= { "SM4-OFB128", "SM4-OFB", NULL };
/* sm4128cfb128_functions */
IMPLEMENT_generic_cipher(sm4, SM4, cfb128,  CFB, SM4_FLAGS, 128, 8, 128, stream)
= { "SM4-CFB128", "SM4-CFB", NULL };
