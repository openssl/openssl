/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for Seed cipher modes ecb, cbc, ofb, cfb */

#include "cipher_seed.h"
#include "internal/provider_algs.h"

/* TODO (3.0) Figure out what flags are required */
#define SEED_FLAGS EVP_CIPH_FLAG_DEFAULT_ASN1

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
IMPLEMENT_generic_cipher(seed, SEED, ecb, ECB, SEED_FLAGS, 128, 128, 0, block)
= { "SEED-ECB", NULL };
/* seed128cbc_functions */
IMPLEMENT_generic_cipher(seed, SEED, cbc, CBC, SEED_FLAGS, 128, 128, 128, block)
= { "SEED-CBC", "SEED", NULL };
/* seed128ofb128_functions */
IMPLEMENT_generic_cipher(seed, SEED, ofb128, OFB, SEED_FLAGS, 128, 8, 128, stream)
= { "SEED-OFB128", "SEED-OFB", NULL };
/* seed128cfb128_functions */
IMPLEMENT_generic_cipher(seed, SEED, cfb128,  CFB, SEED_FLAGS, 128, 8, 128, stream)
= { "SEED-CFB128", "SEED-CFB", NULL };
