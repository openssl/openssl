/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for CAMELLIA cipher modes ecb, cbc, ofb, cfb, ctr */

#include "cipher_camellia.h"
#include "internal/provider_algs.h"

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
    *ret = *in;

    return ret;
}

/* camellia256ecb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ecb, ECB, 0, 256, 128, 0, block)
= { "CAMELLIA-256-ECB", NULL };
/* camellia192ecb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ecb, ECB, 0, 192, 128, 0, block)
= { "CAMELLIA-192-ECB", NULL };
/* camellia128ecb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ecb, ECB, 0, 128, 128, 0, block)
= { "CAMELLIA-128-ECB", NULL };
/* camellia256cbc_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cbc, CBC, 0, 256, 128, 128, block)
= { "CAMELLIA-256-CBC", "CAMELLIA256", NULL };
/* camellia192cbc_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cbc, CBC, 0, 192, 128, 128, block)
= { "CAMELLIA-192-CBC", "CAMELLIA192", NULL };
/* camellia128cbc_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cbc, CBC, 0, 128, 128, 128, block)
= { "CAMELLIA-128-CBC", "CAMELLIA128", NULL };
/* camellia256ofb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ofb, OFB, 0, 256, 8, 128, stream)
= { "CAMELLIA-256-OFB", NULL };
/* camellia192ofb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ofb, OFB, 0, 192, 8, 128, stream)
= { "CAMELLIA-192-OFB", NULL };
/* camellia128ofb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ofb, OFB, 0, 128, 8, 128, stream)
= { "CAMELLIA-128-OFB", NULL };
/* camellia256cfb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb,  CFB, 0, 256, 8, 128, stream)
= { "CAMELLIA-256-CFB", NULL };
/* camellia192cfb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb,  CFB, 0, 192, 8, 128, stream)
= { "CAMELLIA-192-CFB", NULL };
/* camellia128cfb_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb,  CFB, 0, 128, 8, 128, stream)
= { "CAMELLIA-128-CFB", NULL };
/* camellia256cfb1_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb1, CFB, 0, 256, 8, 128, stream)
= { "CAMELLIA-256-CFB1", NULL };
/* camellia192cfb1_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb1, CFB, 0, 192, 8, 128, stream)
= { "CAMELLIA-192-CFB1", NULL };
/* camellia128cfb1_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb1, CFB, 0, 128, 8, 128, stream)
= { "CAMELLIA-128-CFB1", NULL };
/* camellia256cfb8_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb8, CFB, 0, 256, 8, 128, stream)
= { "CAMELLIA-256-CFB8", NULL };
/* camellia192cfb8_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb8, CFB, 0, 192, 8, 128, stream)
= { "CAMELLIA-192-CFB8", NULL };
/* camellia128cfb8_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, cfb8, CFB, 0, 128, 8, 128, stream)
= { "CAMELLIA-128-CFB8", NULL };
/* camellia256ctr_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ctr, CTR, 0, 256, 8, 128, stream)
= { "CAMELLIA-256-CTR", NULL };
/* camellia192ctr_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ctr, CTR, 0, 192, 8, 128, stream)
= { "CAMELLIA-192-CTR", NULL };
/* camellia128ctr_functions */
IMPLEMENT_generic_cipher(camellia, CAMELLIA, ctr, CTR, 0, 128, 8, 128, stream)
= { "CAMELLIA-128-CTR", NULL };

