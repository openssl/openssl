/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Camellia low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

/* Dispatch functions for CAMELLIA cipher modes ecb, cbc, ofb, cfb, ctr */

#include "cipher_camellia.h"
#include "prov/implementations.h"

static OSSL_OP_cipher_freectx_fn camellia_freectx;
static OSSL_OP_cipher_dupctx_fn camellia_dupctx;

static void camellia_freectx(void *vctx)
{
    PROV_CAMELLIA_CTX *ctx = (PROV_CAMELLIA_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *camellia_dupctx(void *ctx)
{
    PROV_CAMELLIA_CTX *in = (PROV_CAMELLIA_CTX *)ctx;
    PROV_CAMELLIA_CTX *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    in->base.hw->copyctx(&ret->base, &in->base);

    return ret;
}

/* camellia256ecb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ecb, ECB, 0, 256, 128, 0, block)
/* camellia192ecb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ecb, ECB, 0, 192, 128, 0, block)
/* camellia128ecb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ecb, ECB, 0, 128, 128, 0, block)
/* camellia256cbc_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cbc, CBC, 0, 256, 128, 128, block)
/* camellia192cbc_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cbc, CBC, 0, 192, 128, 128, block)
/* camellia128cbc_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cbc, CBC, 0, 128, 128, 128, block)
/* camellia256ofb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ofb, OFB, 0, 256, 8, 128, stream)
/* camellia192ofb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ofb, OFB, 0, 192, 8, 128, stream)
/* camellia128ofb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ofb, OFB, 0, 128, 8, 128, stream)
/* camellia256cfb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb,  CFB, 0, 256, 8, 128, stream)
/* camellia192cfb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb,  CFB, 0, 192, 8, 128, stream)
/* camellia128cfb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb,  CFB, 0, 128, 8, 128, stream)
/* camellia256cfb1_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb1, CFB, 0, 256, 8, 128, stream)
/* camellia192cfb1_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb1, CFB, 0, 192, 8, 128, stream)
/* camellia128cfb1_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb1, CFB, 0, 128, 8, 128, stream)
/* camellia256cfb8_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb8, CFB, 0, 256, 8, 128, stream)
/* camellia192cfb8_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb8, CFB, 0, 192, 8, 128, stream)
/* camellia128cfb8_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb8, CFB, 0, 128, 8, 128, stream)
/* camellia256ctr_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ctr, CTR, 0, 256, 8, 128, stream)
/* camellia192ctr_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ctr, CTR, 0, 192, 8, 128, stream)
/* camellia128ctr_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ctr, CTR, 0, 128, 8, 128, stream)

