/*
 * Copyright 2017-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include "crypto/evp.h"
#include "prov/implementations.h"
#include "internal/numbers.h"
#include "prov/provider_ctx.h"
#include "prov/providercommonerr.h"
#include "internal/argon2.h"

#ifndef OPENSSL_NO_ARGON2

static OSSL_OP_kdf_newctx_fn kdf_argon2i_new;
static OSSL_OP_kdf_newctx_fn kdf_argon2d_new;
static OSSL_OP_kdf_newctx_fn kdf_argon2id_new;
static OSSL_OP_kdf_freectx_fn kdf_argon2_free;
static OSSL_OP_kdf_reset_fn kdf_argon2_reset;
static OSSL_OP_kdf_derive_fn kdf_argon2_derive;
static OSSL_OP_kdf_settable_ctx_params_fn kdf_argon2_settable_ctx_params;
static OSSL_OP_kdf_set_ctx_params_fn kdf_argon2_set_ctx_params;

typedef struct {
    void * provctx;
    argon2_context ctx;
} KDF_ARGON2;

static void kdf_argon2_init(KDF_ARGON2 * ctx, argon2_type t);
static void * kdf_argon2d_new(void * provctx);
static void * kdf_argon2i_new(void * provctx);
static void * kdf_argon2id_new(void * provctx);
static void   kdf_argon2_free(void * vctx);
static int    kdf_argon2_derive(void * vctx, unsigned char * out,
                                size_t outlen);
static void   kdf_argon2_reset(void * vctx);
static int    kdf_argon2_ctx_set_threads(argon2_context * ctx,
                                         uint32_t threads);
static int    kdf_argon2_ctx_set_lanes(argon2_context * ctx, uint32_t lanes);
static int    kdf_argon2_ctx_set_t_cost(argon2_context * ctx, uint32_t t_cost);
static int    kdf_argon2_ctx_set_m_cost(argon2_context * ctx, uint32_t m_cost);
static int    kdf_argon2_ctx_set_digest_length(argon2_context * ctx,
                                               uint32_t outlen);
static int    kdf_argon2_ctx_set_secret(argon2_context * ctx,
                                        const OSSL_PARAM * p);
static int    kdf_argon2_ctx_set_pwd(argon2_context * ctx,
                                     const OSSL_PARAM * p);
static int    kdf_argon2_ctx_set_salt(argon2_context * ctx,
                                      const OSSL_PARAM * p);
static int    kdf_argon2_ctx_set_ad(argon2_context * ctx,
                                    const OSSL_PARAM * p);
static void   kdf_argon2_ctx_set_flags(argon2_context * ctx,
                                       uint32_t flags);
static int    kdf_argon2_set_ctx_params(void * vctx, const OSSL_PARAM params[]);
static const OSSL_PARAM * kdf_argon2_settable_ctx_params(void);
static int   kdf_argon2_get_ctx_params(void * vctx, OSSL_PARAM params[]);
static const OSSL_PARAM * kdf_argon2_gettable_ctx_params(void);

static void kdf_argon2_init(KDF_ARGON2 * ctx, argon2_type t)
{
    ARGON2_Init(&ctx->ctx, t);
}

static void * kdf_argon2d_new(void * provctx)
{
    KDF_ARGON2 * ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->provctx = provctx;

    kdf_argon2_init(ctx, Argon2_d);
    return ctx;
}

static void * kdf_argon2i_new(void * provctx)
{
    KDF_ARGON2 * ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->provctx = provctx;

    kdf_argon2_init(ctx, Argon2_i);
    return ctx;
}

static void * kdf_argon2id_new(void * provctx)
{
    KDF_ARGON2 * ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->provctx = provctx;

    kdf_argon2_init(ctx, Argon2_id);
    return ctx;
}

static void kdf_argon2_free(void * vctx)
{
    KDF_ARGON2 * ctx_wrap = (KDF_ARGON2 *) vctx;
    argon2_context * ctx = &ctx_wrap->ctx;

    if (ctx->out != NULL)
        OPENSSL_clear_free(ctx->out, ctx->outlen);

    if (ctx->pwd != NULL)
        OPENSSL_clear_free(ctx->pwd, ctx->pwdlen);

    if (ctx->salt != NULL)
        OPENSSL_clear_free(ctx->salt, ctx->saltlen);

    if (ctx->secret != NULL)
        OPENSSL_clear_free(ctx->secret, ctx->secretlen);

    if (ctx->ad != NULL)
        OPENSSL_clear_free(ctx->ad, ctx->adlen);

    memset(ctx, 0, sizeof(*ctx));
    OPENSSL_free(ctx_wrap);
}

static int kdf_argon2_derive(void * vctx, unsigned char * out, size_t outlen)
{
    int ret;
    KDF_ARGON2 * ctx_wrap = (KDF_ARGON2 *)vctx;
    argon2_context * ctx = &ctx_wrap->ctx;

    if (ctx->pwd == NULL || ctx->pwdlen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_PASS);
        return 0;
    }

    if (ctx->salt == NULL || ctx->saltlen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SALT);
        return 0;
    }

    if (outlen > UINT32_MAX)
        return 0;

    kdf_argon2_ctx_set_digest_length(ctx, (uint32_t) outlen);

    ret = ARGON2_Update(ctx, NULL, 0);
    if (ret != 1)
        return ret;

    if (outlen > 0)
        memcpy(out, ctx->out, outlen);

    return 1;
}

static void kdf_argon2_reset(void * vctx)
{
    KDF_ARGON2 * ctx_wrap = (KDF_ARGON2 *) vctx;
    argon2_context * ctx = &ctx_wrap->ctx;
    argon2_type type = ctx->type;

    if (ctx->out != NULL)
        OPENSSL_clear_free(ctx->out, ctx->outlen);

    if (ctx->pwd != NULL)
        OPENSSL_clear_free(ctx->pwd, ctx->pwdlen);

    if (ctx->salt != NULL)
        OPENSSL_clear_free(ctx->salt, ctx->saltlen);

    if (ctx->secret != NULL)
        OPENSSL_clear_free(ctx->secret, ctx->secretlen);

    if (ctx->ad != NULL)
        OPENSSL_clear_free(ctx->ad, ctx->adlen);

    memset(ctx, 0, sizeof(*ctx));
    kdf_argon2_init(ctx_wrap, type);
}

static int kdf_argon2_ctx_set_threads(argon2_context * ctx, uint32_t threads)
{
    if (threads > ARGON2_MAX_THREADS || threads < ARGON2_MIN_THREADS)
        return 0;

    ctx->threads = threads;
    return 1;
}


static int kdf_argon2_ctx_set_lanes(argon2_context * ctx, uint32_t lanes)
{
    if (lanes > ARGON2_MAX_LANES || lanes < ARGON2_MIN_LANES)
        return 0;

    ctx->lanes = lanes;
    return 1;
}

static int kdf_argon2_ctx_set_t_cost(argon2_context * ctx, uint32_t t_cost)
{
    if (t_cost < ARGON2_MIN_TIME || t_cost > ARGON2_MAX_TIME)
        return 0;

    ctx->t_cost = t_cost;
    return 1;
}

static int kdf_argon2_ctx_set_m_cost(argon2_context * ctx, uint32_t m_cost)
{
    /* comparison convoluted due to Werror=type-limits */
    if (m_cost+1 < ARGON2_MIN_MEMORY+1 || m_cost >= ARGON2_MAX_MEMORY)
        if (m_cost != ARGON2_MAX_MEMORY)
            return 0;

    ctx->m_cost = m_cost;
    return 1;
}

static int kdf_argon2_ctx_set_digest_length(argon2_context * ctx,
                                            uint32_t outlen)
{
    if (outlen < ARGON2_MIN_OUTLEN || outlen > ARGON2_MAX_OUTLEN)
        return 0;

    ctx->outlen = outlen;
    return 1;
}

static int kdf_argon2_ctx_set_secret(argon2_context * ctx,
                                     const OSSL_PARAM * p)
{
    size_t buflen;

    if (p->data == NULL)
        return 0;

    if (ctx->secret != NULL) {
        OPENSSL_clear_free(ctx->secret, ctx->secretlen);
        ctx->secret = NULL;
        ctx->secretlen = 0U;
    }

    if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->secret, 0, &buflen))
        return 0;

    if (buflen+1 < ARGON2_MIN_SECRET+1 || buflen > ARGON2_MAX_SECRET
            || buflen > UINT32_MAX) {
        OPENSSL_free(ctx->secret);
        ctx->secret = NULL;
        ctx->secretlen = 0U;
        return 0;
    }

    ctx->secretlen = (uint32_t) buflen;
    return 1;
}

static int kdf_argon2_ctx_set_pwd(argon2_context * ctx, const OSSL_PARAM * p)
{
    size_t buflen;

    if (p->data == NULL)
        return 0;

    if (ctx->pwd != NULL) {
        OPENSSL_clear_free(ctx->pwd, ctx->pwdlen);
        ctx->pwd = NULL;
        ctx->pwdlen = 0U;
    }

    if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->pwd, 0, &buflen))
        return 0;

    if (buflen+1 < ARGON2_MIN_PWD_LENGTH+1 || buflen > ARGON2_MAX_PWD_LENGTH
            || buflen > UINT32_MAX) {
        OPENSSL_free(ctx->pwd);
        ctx->pwd = NULL;
        ctx->pwdlen = 0U;
        return 0;
    }

    ctx->pwdlen = (uint32_t) buflen;
    return 1;
}

static int kdf_argon2_ctx_set_salt(argon2_context * ctx, const OSSL_PARAM * p)
{
    size_t buflen;

    if (p->data == NULL)
        return 0;

    if (ctx->salt != NULL) {
        OPENSSL_clear_free(ctx->salt, ctx->saltlen);
        ctx->salt = NULL;
        ctx->saltlen = 0U;
    }

    if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->salt, 0, &buflen))
        return 0;

    if (buflen < ARGON2_MIN_SALT_LENGTH || buflen > ARGON2_MAX_SALT_LENGTH
            || buflen > UINT32_MAX) {
        OPENSSL_free(ctx->salt);
        ctx->salt = NULL;
        ctx->saltlen = 0U;
        return 0;
    }

    ctx->saltlen = (uint32_t) buflen;
    return 1;
}

static int kdf_argon2_ctx_set_ad(argon2_context * ctx, const OSSL_PARAM * p)
{
    size_t buflen;

    if (p->data == NULL)
        return 0;

    if (ctx->ad != NULL) {
        OPENSSL_clear_free(ctx->ad, ctx->adlen);
        ctx->ad = NULL;
        ctx->adlen = 0U;
    }

    if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->ad, 0, &buflen))
        return 0;

    if (buflen+1 < ARGON2_MIN_AD_LENGTH+1 || buflen > ARGON2_MAX_AD_LENGTH
            || buflen > UINT32_MAX) {
        OPENSSL_free(ctx->ad);
        ctx->ad = NULL;
        ctx->adlen = 0U;
        return 0;
    }

    ctx->adlen = (uint32_t) buflen;
    return 1;
}

static void kdf_argon2_ctx_set_flags(argon2_context * ctx, uint32_t flags)
{
    ctx->flags = flags;
}

static int kdf_argon2_set_ctx_params(void * vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM * p;
    KDF_ARGON2 * ctx = vctx;
    uint32_t u32_value;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PASSWORD)) != NULL)
        if (!kdf_argon2_ctx_set_pwd(&ctx->ctx, p))
            return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT)) != NULL)
        if (!kdf_argon2_ctx_set_salt(&ctx->ctx, p))
            return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SECRET)) != NULL)
        if (!kdf_argon2_ctx_set_secret(&ctx->ctx, p))
            return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ARGON2_AD)) != NULL)
        if (!kdf_argon2_ctx_set_ad(&ctx->ctx, p))
            return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ARGON2_SZ))
          != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        if (!kdf_argon2_ctx_set_digest_length(&ctx->ctx, u32_value))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ITER)) != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        if (!kdf_argon2_ctx_set_t_cost(&ctx->ctx, u32_value))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_THREADS)) != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        if (!kdf_argon2_ctx_set_threads(&ctx->ctx, u32_value))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ARGON2_LANES))
          != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        if (!kdf_argon2_ctx_set_lanes(&ctx->ctx, u32_value))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ARGON2_MEMCOST))
          != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        if (!kdf_argon2_ctx_set_m_cost(&ctx->ctx, u32_value))
            return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ARGON2_FLAGS))
          != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &u32_value))
            return 0;
        kdf_argon2_ctx_set_flags(&ctx->ctx, u32_value);
    }

    return 1;
}

static const OSSL_PARAM * kdf_argon2_settable_ctx_params(void)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_ARGON2_AD, NULL, 0),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_ARGON2_SZ, NULL),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_ITER, NULL),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_THREADS, NULL),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_ARGON2_LANES, NULL),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, NULL),
        OSSL_PARAM_uint32(OSSL_KDF_PARAM_ARGON2_FLAGS, NULL),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int kdf_argon2_get_ctx_params(void * vctx, OSSL_PARAM params[])
{
    OSSL_PARAM * p;
    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL)
        return OSSL_PARAM_set_size_t(p, SIZE_MAX);
    return -2;
}

static const OSSL_PARAM * kdf_argon2_gettable_ctx_params(void)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

const OSSL_DISPATCH kdf_argon2i_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void(*)(void))kdf_argon2i_new },
    { OSSL_FUNC_KDF_FREECTX, (void(*)(void))kdf_argon2_free },
    { OSSL_FUNC_KDF_RESET, (void(*)(void))kdf_argon2_reset },
    { OSSL_FUNC_KDF_DERIVE, (void(*)(void))kdf_argon2_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_argon2_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void(*)(void))kdf_argon2_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_argon2_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void(*)(void))kdf_argon2_get_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH kdf_argon2d_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void(*)(void))kdf_argon2d_new },
    { OSSL_FUNC_KDF_FREECTX, (void(*)(void))kdf_argon2_free },
    { OSSL_FUNC_KDF_RESET, (void(*)(void))kdf_argon2_reset },
    { OSSL_FUNC_KDF_DERIVE, (void(*)(void))kdf_argon2_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_argon2_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void(*)(void))kdf_argon2_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_argon2_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void(*)(void))kdf_argon2_get_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH kdf_argon2id_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void(*)(void))kdf_argon2id_new },
    { OSSL_FUNC_KDF_FREECTX, (void(*)(void))kdf_argon2_free },
    { OSSL_FUNC_KDF_RESET, (void(*)(void))kdf_argon2_reset },
    { OSSL_FUNC_KDF_DERIVE, (void(*)(void))kdf_argon2_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_argon2_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void(*)(void))kdf_argon2_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
      (void(*)(void))kdf_argon2_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void(*)(void))kdf_argon2_get_ctx_params },
    { 0, NULL }
};

#endif
