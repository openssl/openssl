/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#define OSSL_INCLUDE_PROVIDER 1
#include "crypto/ascon.h"
#undef OSSL_INCLUDE_PROVIDER
#include "prov/digestcommon.h"
#include "prov/implementations.h"

#define ASCON_HASH256_BLOCK_SIZE 8
#define ASCON_HASH256_DIGEST_SIZE 32
#define ASCON_HASH256_FLAGS PROV_DIGEST_FLAG_ALGID_ABSENT

/* Wrapper functions to match macro expectations */
static int ascon_hash256_init(ascon_hash256_ctx *ctx)
{
    ossl_ascon_hash256_init(ctx);
    return 1;
}

static int ascon_hash256_update(void *vctx, const unsigned char *data, size_t len)
{
    ascon_hash256_ctx *ctx = (ascon_hash256_ctx *)vctx;
    ossl_ascon_hash256_update(ctx, data, len);
    return 1;
}

static int ascon_hash256_final(unsigned char *out, ascon_hash256_ctx *ctx)
{
    ossl_ascon_hash256_final(ctx, out);
    return 1;
}

/* Use the macro to generate all dispatch functions */
IMPLEMENT_digest_functions(ascon_hash256, ascon_hash256_ctx,
                           ASCON_HASH256_BLOCK_SIZE,
                           ASCON_HASH256_DIGEST_SIZE,
                           ASCON_HASH256_FLAGS,
                           ascon_hash256_init,
                           ascon_hash256_update,
                           ascon_hash256_final)
