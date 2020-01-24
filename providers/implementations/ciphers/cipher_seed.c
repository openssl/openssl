/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for Seed cipher modes ecb, cbc, ofb, cfb */

/*
 * SEED low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include "cipher_seed.h"
#include "prov/implementations.h"

static OSSL_OP_cipher_freectx_fn seed_freectx;
static OSSL_OP_cipher_dupctx_fn seed_dupctx;

static void seed_freectx(void *vctx)
{
    PROV_SEED_CTX *ctx = (PROV_SEED_CTX *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *seed_dupctx(void *ctx)
{
    PROV_SEED_CTX *in = (PROV_SEED_CTX *)ctx;
    PROV_SEED_CTX *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    *ret = *in;

    return ret;
}

/* seed128ecb_functions */
IMPLEMENT_generic_cipher(seed, SEED, ecb, ECB, 0, 128, 128, 0, block)
/* seed128cbc_functions */
IMPLEMENT_generic_cipher(seed, SEED, cbc, CBC, 0, 128, 128, 128, block)
/* seed128ofb128_functions */
IMPLEMENT_generic_cipher(seed, SEED, ofb128, OFB, 0, 128, 8, 128, stream)
/* seed128cfb128_functions */
IMPLEMENT_generic_cipher(seed, SEED, cfb128,  CFB, 0, 128, 8, 128, stream)
