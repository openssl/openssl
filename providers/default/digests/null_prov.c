/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_numbers.h>
#include <openssl/whrlpool.h>
#include "internal/provider_algs.h"

static int nullmd_dummy = 1;

static OSSL_OP_digest_init_fn nullmd_init;
static OSSL_OP_digest_update_fn nullmd_update;
static OSSL_OP_digest_final_fn nullmd_final;
static OSSL_OP_digest_newctx_fn nullmd_newctx;
static OSSL_OP_digest_freectx_fn nullmd_freectx;
static OSSL_OP_digest_dupctx_fn nullmd_dupctx;
static OSSL_OP_digest_size_fn nullmd_size;
static OSSL_OP_digest_block_size_fn nullmd_block_size;

static size_t nullmd_block_size(void)
{
    return 0;
}

static size_t nullmd_size(void)
{
    return 0;
}

static int nullmd_init(void *vctx)
{
    return 1;
}

static int nullmd_update(void *vctx, const unsigned char *inp, size_t bytes)
{
    return 1;
}

static int nullmd_final(void *ctx, unsigned char *out, size_t *outl, size_t outsz)
{
    *outl = 0;
    return 1;
}

static void *nullmd_newctx(void *prov_ctx)
{
    return &nullmd_dummy;
}

static void nullmd_freectx(void *vctx)
{
}

static void *nullmd_dupctx(void *ctx)
{
    return &nullmd_dummy;
}

const OSSL_DISPATCH nullmd_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))nullmd_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))nullmd_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))nullmd_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))nullmd_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))nullmd_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))nullmd_dupctx },
    { OSSL_FUNC_DIGEST_SIZE, (void (*)(void))nullmd_size },
    { OSSL_FUNC_DIGEST_BLOCK_SIZE, (void (*)(void))nullmd_block_size },
    { 0, NULL }
};
