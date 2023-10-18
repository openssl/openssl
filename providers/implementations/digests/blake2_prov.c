/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/proverr.h>
#include "prov/blake2.h"
#include "prov/digestcommon.h"
#include "prov/implementations.h"

static int ossl_blake2s256_init(void *ctx)
{
    BLAKE2S_PARAM P;

    ossl_blake2s_param_init(&P);
    return ossl_blake2s_init((BLAKE2S_CTX *)ctx, &P);
}

static int ossl_blake2b512_init(void *ctx)
{
    struct blake2b_md_data_st *mdctx = ctx;
    uint8_t digest_length = mdctx->params.digest_length;

    ossl_blake2b_param_init(&mdctx->params);
    if (digest_length != 0)
        mdctx->params.digest_length = digest_length;
    return ossl_blake2b_init(&mdctx->ctx, &mdctx->params);
}

/* ossl_blake2s256_functions */
IMPLEMENT_digest_functions(blake2s256, BLAKE2S_CTX,
                           BLAKE2S_BLOCKBYTES, BLAKE2S_DIGEST_LENGTH, 0,
                           ossl_blake2s256_init, ossl_blake2s_update,
                           ossl_blake2s_final)

/* ossl_blake2b512_functions */

#define IMPLEMENT_BLAKE_functions(variant, VARIANT, variantsize) \
static OSSL_FUNC_digest_init_fn blake##variantsize##_internal_init; \
static OSSL_FUNC_digest_newctx_fn blake##variantsize##_newctx; \
static OSSL_FUNC_digest_freectx_fn blake##variantsize##_freectx; \
static OSSL_FUNC_digest_dupctx_fn blake##variantsize##_dupctx; \
static OSSL_FUNC_digest_final_fn blake##variantsize##_internal_final; \
static OSSL_FUNC_digest_get_params_fn blake##variantsize##_get_params; \
 \
static int blake##variantsize##_internal_init(void *ctx, const OSSL_PARAM params[]) \
{ \
    return ossl_prov_is_running() && ossl_blake##variant##_set_ctx_params(ctx, params) \
        && ossl_blake##variantsize##_init(ctx); \
} \
 \
static void *blake##variantsize##_newctx(void *prov_ctx) \
{ \
    struct blake##variant##_md_data_st *ctx; \
 \
    ctx = ossl_prov_is_running() ? OPENSSL_zalloc(sizeof(*ctx)) : NULL; \
    return ctx; \
} \
 \
static void blake##variantsize##_freectx(void *vctx) \
{ \
    struct blake##variant##_md_data_st *ctx; \
 \
    ctx = (struct blake##variant##_md_data_st *)vctx; \
    OPENSSL_clear_free(ctx, sizeof(*ctx)); \
} \
 \
static void *blake##variantsize##_dupctx(void *ctx) \
{ \
    struct blake##variant##_md_data_st *in, *ret; \
 \
    in = (struct blake##variant##_md_data_st *)ctx; \
    ret = ossl_prov_is_running()? OPENSSL_malloc(sizeof(*ret)) : NULL; \
    if (ret != NULL) \
        *ret = *in; \
    return ret; \
} \
 \
static int blake##variantsize##_internal_final(void *ctx, unsigned char *out, \
                                     size_t *outl, size_t outsz) \
{ \
    struct blake##variant##_md_data_st *b_ctx; \
 \
    b_ctx = (struct blake##variant##_md_data_st *)ctx; \
 \
    if (!ossl_prov_is_running()) \
        return 0; \
 \
    *outl = b_ctx->ctx.outlen; \
 \
    if (outsz == 0) \
       return 1; \
 \
    if (outsz < *outl) { \
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_SIZE); \
        return 0; \
    } \
 \
    return ossl_blake##variant##_final(out, ctx); \
} \
 \
static int blake##variantsize##_get_params(OSSL_PARAM params[]) \
{ \
    return ossl_digest_default_get_params(params, BLAKE##VARIANT##_BLOCKBYTES, 64, 0); \
} \
 \
const OSSL_DISPATCH ossl_blake##variantsize##_functions[] = { \
    {OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))blake##variantsize##_newctx}, \
    {OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))ossl_blake##variant##_update}, \
    {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))blake##variantsize##_internal_final}, \
    {OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))blake##variantsize##_freectx}, \
    {OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))blake##variantsize##_dupctx}, \
    {OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))blake##variantsize##_get_params}, \
    {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, \
     (void (*)(void))ossl_digest_default_gettable_params}, \
    {OSSL_FUNC_DIGEST_INIT, (void (*)(void))blake##variantsize##_internal_init}, \
    {OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, \
     (void (*)(void))ossl_blake##variant##_gettable_ctx_params}, \
    {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, \
     (void (*)(void))ossl_blake##variant##_settable_ctx_params}, \
    {OSSL_FUNC_DIGEST_GET_CTX_PARAMS, \
     (void (*)(void))ossl_blake##variant##_get_ctx_params}, \
    {OSSL_FUNC_DIGEST_SET_CTX_PARAMS, \
     (void (*)(void))ossl_blake##variant##_set_ctx_params}, \
    {0, NULL} \
};

IMPLEMENT_BLAKE_functions(2b, 2B, 2b512)
