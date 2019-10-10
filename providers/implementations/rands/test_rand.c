/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/core_numbers.h>
#include <openssl/evperr.h>
#include <openssl/err.h>
#include "prov/provider_ctx.h"
#include "prov/providercommonerr.h"
#include "prov/implementations.h"
#include "prov/provider_util.h"

static OSSL_OP_rand_newctx_fn test_rand_new;
static OSSL_OP_rand_freectx_fn test_rand_free;
static OSSL_OP_rand_reseed_fn test_rand_reseed;
static OSSL_OP_rand_generate_fn test_rand_generate;
static OSSL_OP_rand_get_nonce_fn test_rand_get_nonce;
static OSSL_OP_rand_settable_ctx_params_fn test_rand_settable_ctx_params;
static OSSL_OP_rand_set_ctx_params_fn test_rand_set_ctx_params;
static OSSL_OP_rand_gettable_params_fn test_rand_gettable_params;
static OSSL_OP_rand_get_params_fn test_rand_get_params;
static OSSL_OP_rand_get_ctx_params_fn test_rand_get_ctx_params;

typedef struct {
    void *provctx;
    size_t length;
    size_t current;
    size_t nonce_len;
    size_t nonce_cur;
    unsigned int strength;
    unsigned char *buf;
    unsigned char *nonce;
} TEST_RAND;

static void *test_rand_new(void *provctx, int secure, int df)
{
    TEST_RAND *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    else
        ctx->provctx = provctx;
    return ctx;
}

static void test_rand_free(void *vctx)
{
    TEST_RAND *ctx = (TEST_RAND *)vctx;

    if (ctx != NULL)
        OPENSSL_free(ctx->buf);
    OPENSSL_free(ctx);
}

static int test_rand_reseed(void *vctx,
                            const unsigned char *ent, size_t ent_len,
                            const unsigned char *adin, size_t adin_len)
{
    TEST_RAND *ctx = (TEST_RAND *)vctx;
    unsigned char *buf;

    ctx->current = 0;
    if (ent != NULL) {
        if ((buf = OPENSSL_memdup(ent, ent_len)) == NULL)
            return 0;
        OPENSSL_free(ctx->buf);
        ctx->buf = buf;
        ctx->length = ent_len;
    }
    return 1;
}

static int test_rand_generate(void *vctx,
                              unsigned char *out, size_t outlen,
                              const unsigned char *adin, size_t adin_len)
{
    TEST_RAND *ctx = vctx;
    unsigned char *p = out;
    size_t n;

    if (ctx->length == 0 || ctx->buf == NULL)
        return 0;
    while (outlen > 0) {
        n = ctx->length - ctx->current;
        if (n > outlen)
            n = outlen;
        memcpy(p, ctx->buf + ctx->current, n);
        outlen -= n;
        p += n;
        ctx->current += n;
        if (ctx->current >= ctx->length)
            ctx->current = 0;
    }
    return 1;
}

static int test_rand_get_nonce(void *vctx, unsigned char *out, size_t outlen)
{
    TEST_RAND *ctx = vctx;
    unsigned char *p = out;
    size_t n;

    if (ctx->nonce_len == 0 || ctx->nonce == NULL)
        return 0;
    while (outlen > 0) {
        n = ctx->nonce_len - ctx->nonce_cur;
        if (n > ctx->nonce_len)
            n = ctx->nonce_len;
        memcpy(p, ctx->nonce + ctx->nonce_cur, n);
        outlen -= n;
        p += n;
        ctx->nonce_cur += n;
        if (ctx->nonce_cur >= ctx->nonce_len)
            ctx->nonce_cur = 0;
    }
    return 1;
}

static int test_rand_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    TEST_RAND *ctx = (TEST_RAND *)vctx;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_SEED)) != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING || p->data_size == 0)
            return 0;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->buf, 0,
                                         &ctx->length))
            return 0;
        ctx->current = 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_NONCE)) != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING || p->data_size == 0)
            return 0;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->nonce, 0,
                                         &ctx->nonce_len))
            return 0;
        ctx->nonce_cur = 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_RAND_PARAM_STRENGTH)) != NULL) {
        if (!OSSL_PARAM_get_uint(p, &ctx->strength))
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *test_rand_settable_ctx_params(void)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_octet_string(OSSL_RAND_PARAM_SEED, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_RAND_PARAM_NONCE, NULL, 0),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int test_rand_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH)) != NULL)
        return OSSL_PARAM_set_uint(p, 0);
    return -2;
}

static int test_rand_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    TEST_RAND *ctx = (TEST_RAND *)vctx;

    if ((p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH)) != NULL)
        return OSSL_PARAM_set_uint(p, ctx->strength);
    return -2;
}

static const OSSL_PARAM *test_rand_gettable_params(void)
{
    static const OSSL_PARAM known_gettable_params[] = {
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_params;
}

const OSSL_DISPATCH test_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void(*)(void))test_rand_new },
    { OSSL_FUNC_RAND_FREECTX, (void(*)(void))test_rand_free },
    { OSSL_FUNC_RAND_RESEED, (void(*)(void))test_rand_reseed },
    { OSSL_FUNC_RAND_GENERATE, (void(*)(void))test_rand_generate },
    { OSSL_FUNC_RAND_GET_NONCE, (void(*)(void))test_rand_get_nonce },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
      (void(*)(void))test_rand_settable_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void(*)(void))test_rand_set_ctx_params },
    { OSSL_FUNC_RAND_GETTABLE_PARAMS,
      (void(*)(void))test_rand_gettable_params },
    { OSSL_FUNC_RAND_GET_PARAMS, (void(*)(void))test_rand_get_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
      (void(*)(void))test_rand_gettable_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))test_rand_get_ctx_params },
    { 0, NULL }
};
