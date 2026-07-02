/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#define OSSL_INCLUDE_PROVIDER 1
#include "crypto/ascon.h"
#undef OSSL_INCLUDE_PROVIDER
#include "prov/digestcommon.h"
#include "prov/implementations.h"
#include "internal/numbers.h"

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

/* XOF (eXtendable Output Function) implementation */

#define ASCON_XOF128_BLOCK_SIZE 8
#define ASCON_XOF128_FLAGS (PROV_DIGEST_FLAG_XOF | PROV_DIGEST_FLAG_ALGID_ABSENT)

/* Context structure for XOF that includes output length */
typedef struct {
    ascon_xof128_ctx xof_ctx;
    size_t xoflen;  /* Desired output length */
} ascon_xof128_prov_ctx;

/* Context structure for CXOF that includes output length and customization string */
typedef struct {
    ascon_cxof128_ctx cxof_ctx;
    size_t xoflen;  /* Desired output length */
    unsigned char *custom;  /* Customization string */
    size_t custom_len;  /* Length of customization string */
    int initialized;  /* Whether CXOF has been initialized */
} ascon_cxof128_prov_ctx;

/* XOF wrapper functions */
static int ascon_xof128_prov_init(void *vctx, const OSSL_PARAM params[])
{
    ascon_xof128_prov_ctx *ctx = (ascon_xof128_prov_ctx *)vctx;

    if (!ossl_prov_is_running())
        return 0;

    ossl_ascon_xof128_init(&ctx->xof_ctx);
    ctx->xoflen = SIZE_MAX; /* Default: no fixed length */
    return 1;
}

static int ascon_xof128_prov_update(void *vctx, const unsigned char *data,
                                    size_t len)
{
    ascon_xof128_prov_ctx *ctx = (ascon_xof128_prov_ctx *)vctx;

    if (!ossl_prov_is_running())
        return 0;

    ossl_ascon_xof128_update(&ctx->xof_ctx, data, len);
    return 1;
}

static int ascon_xof128_prov_final(void *vctx, unsigned char *out, size_t *outl,
                                   size_t outlen)
{
    ascon_xof128_prov_ctx *ctx = (ascon_xof128_prov_ctx *)vctx;
    size_t len = ctx->xoflen;

    if (!ossl_prov_is_running())
        return 0;

    /* If xoflen is set, use it; otherwise use outlen */
    if (len == SIZE_MAX)
        len = outlen;

    if (outlen < len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    ossl_ascon_xof128_final(&ctx->xof_ctx, out, len);
    *outl = len;
    return 1;
}

static int ascon_xof128_prov_squeeze(void *vctx, unsigned char *out,
                                     size_t *outl, size_t outlen)
{
    ascon_xof128_prov_ctx *ctx = (ascon_xof128_prov_ctx *)vctx;

    if (!ossl_prov_is_running())
        return 0;

    if (outlen == 0) {
        *outl = 0;
        return 1;
    }

    ossl_ascon_xof128_final(&ctx->xof_ctx, out, outlen);
    *outl = outlen;
    return 1;
}

static void *ascon_xof128_prov_newctx(void *provctx)
{
    ascon_xof128_prov_ctx *ctx = ossl_prov_is_running()
        ? OPENSSL_zalloc(sizeof(*ctx)) : NULL;

    return ctx;
}

static void ascon_xof128_prov_freectx(void *vctx)
{
    ascon_xof128_prov_ctx *ctx = (ascon_xof128_prov_ctx *)vctx;

    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *ascon_xof128_prov_dupctx(void *ctx)
{
    ascon_xof128_prov_ctx *in = (ascon_xof128_prov_ctx *)ctx;
    ascon_xof128_prov_ctx *ret = ossl_prov_is_running()
        ? OPENSSL_malloc(sizeof(*ret)) : NULL;

    if (ret != NULL)
        *ret = *in;
    return ret;
}

static void ascon_xof128_prov_copyctx(void *voutctx, void *vinctx)
{
    ascon_xof128_prov_ctx *outctx = (ascon_xof128_prov_ctx *)voutctx;
    ascon_xof128_prov_ctx *inctx = (ascon_xof128_prov_ctx *)vinctx;

    *outctx = *inctx;
}

static const OSSL_PARAM *ascon_xof128_prov_gettable_ctx_params(
    ossl_unused void *ctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_XOFLEN, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

static int ascon_xof128_prov_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    ascon_xof128_prov_ctx *ctx = (ascon_xof128_prov_ctx *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOFLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->xoflen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->xoflen))
        return 0;

    return 1;
}

static const OSSL_PARAM *ascon_xof128_prov_settable_ctx_params(
    ossl_unused void *ctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_XOFLEN, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int ascon_xof128_prov_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    ascon_xof128_prov_ctx *ctx = (ascon_xof128_prov_ctx *)vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &ctx->xoflen))
            return 0;
    }

    /* Also check for SIZE parameter (alias for XOFLEN) */
    p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &ctx->xoflen))
            return 0;
    }

    return 1;
}

static int ascon_xof128_prov_get_params(OSSL_PARAM params[])
{
    return ossl_digest_default_get_params(params, ASCON_XOF128_BLOCK_SIZE, 0,
                                          ASCON_XOF128_FLAGS);
}

const OSSL_DISPATCH ossl_ascon_xof128_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))ascon_xof128_prov_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))ascon_xof128_prov_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))ascon_xof128_prov_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))ascon_xof128_prov_final },
    { OSSL_FUNC_DIGEST_SQUEEZE, (void (*)(void))ascon_xof128_prov_squeeze },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))ascon_xof128_prov_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))ascon_xof128_prov_dupctx },
    { OSSL_FUNC_DIGEST_COPYCTX, (void (*)(void))ascon_xof128_prov_copyctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))ascon_xof128_prov_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,
      (void (*)(void))ossl_digest_default_gettable_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,
      (void (*)(void))ascon_xof128_prov_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
      (void (*)(void))ascon_xof128_prov_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,
      (void (*)(void))ascon_xof128_prov_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,
      (void (*)(void))ascon_xof128_prov_gettable_ctx_params },
    { 0, NULL }
};

/* CXOF (Customized eXtendable Output Function) implementation */

#define ASCON_CXOF128_BLOCK_SIZE 8
#define ASCON_CXOF128_FLAGS (PROV_DIGEST_FLAG_XOF | PROV_DIGEST_FLAG_ALGID_ABSENT)

/* CXOF wrapper functions */
static int ascon_cxof128_prov_init(void *vctx, const OSSL_PARAM params[])
{
    ascon_cxof128_prov_ctx *ctx = (ascon_cxof128_prov_ctx *)vctx;
    const unsigned char *custom = NULL;
    size_t customlen = 0;
    const OSSL_PARAM *p;

    if (!ossl_prov_is_running())
        return 0;

    /* Reset initialized flag to allow re-initialization */
    ctx->initialized = 0;

    /* Process params to extract customization string if provided */
    if (params != NULL) {
        p = OSSL_PARAM_locate_const(params, "custom");
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_OCTET_STRING)
                return 0;

            /* For OSSL_PARAM_OCTET_STRING, data is directly in p->data */
            if (p->data != NULL && p->data_size > 0) {
                custom = (const unsigned char *)p->data;
                customlen = p->data_size;
            } else {
                custom = NULL;
                customlen = 0;
            }
        }

        /* Also process XOFLEN and SIZE parameters */
        p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN);
        if (p != NULL) {
            if (!OSSL_PARAM_get_size_t(p, &ctx->xoflen))
                return 0;
        }

        p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SIZE);
        if (p != NULL) {
            if (!OSSL_PARAM_get_size_t(p, &ctx->xoflen))
                return 0;
        }
    }

    /* Use stored customization string if params didn't provide one */
    if (custom == NULL && ctx->custom != NULL && ctx->custom_len > 0) {
        custom = ctx->custom;
        customlen = ctx->custom_len;
    }

    /* Initialize with customization string */
    ossl_ascon_cxof128_init(&ctx->cxof_ctx, custom, customlen);
    /* xoflen is already initialized in newctx, or set from params above */
    ctx->initialized = 1;
    return 1;
}

static int ascon_cxof128_prov_update(void *vctx, const unsigned char *data,
                                     size_t len)
{
    ascon_cxof128_prov_ctx *ctx = (ascon_cxof128_prov_ctx *)vctx;

    if (!ossl_prov_is_running())
        return 0;

    ossl_ascon_cxof128_update(&ctx->cxof_ctx, data, len);
    return 1;
}

static int ascon_cxof128_prov_final(void *vctx, unsigned char *out, size_t *outl,
                                    size_t outlen)
{
    ascon_cxof128_prov_ctx *ctx = (ascon_cxof128_prov_ctx *)vctx;
    size_t len = ctx->xoflen;

    if (!ossl_prov_is_running())
        return 0;

    /* If xoflen is set, use it; otherwise use outlen */
    if (len == SIZE_MAX)
        len = outlen;

    if (outlen < len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    ossl_ascon_cxof128_final(&ctx->cxof_ctx, out, len);
    *outl = len;
    return 1;
}

static int ascon_cxof128_prov_squeeze(void *vctx, unsigned char *out,
                                      size_t *outl, size_t outlen)
{
    ascon_cxof128_prov_ctx *ctx = (ascon_cxof128_prov_ctx *)vctx;

    if (!ossl_prov_is_running())
        return 0;

    if (outlen == 0) {
        *outl = 0;
        return 1;
    }

    ossl_ascon_cxof128_final(&ctx->cxof_ctx, out, outlen);
    *outl = outlen;
    return 1;
}

static void *ascon_cxof128_prov_newctx(void *provctx)
{
    ascon_cxof128_prov_ctx *ctx = ossl_prov_is_running()
        ? OPENSSL_zalloc(sizeof(*ctx)) : NULL;

    if (ctx != NULL) {
        ctx->xoflen = SIZE_MAX;
        ctx->initialized = 0;
    }

    return ctx;
}

static void ascon_cxof128_prov_freectx(void *vctx)
{
    ascon_cxof128_prov_ctx *ctx = (ascon_cxof128_prov_ctx *)vctx;

    if (ctx != NULL) {
        if (ctx->custom != NULL)
            OPENSSL_free(ctx->custom);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

static void *ascon_cxof128_prov_dupctx(void *ctx)
{
    ascon_cxof128_prov_ctx *in = (ascon_cxof128_prov_ctx *)ctx;
    ascon_cxof128_prov_ctx *ret = ossl_prov_is_running()
        ? OPENSSL_malloc(sizeof(*ret)) : NULL;

    if (ret != NULL)
        *ret = *in;
    return ret;
}

static void ascon_cxof128_prov_copyctx(void *voutctx, void *vinctx)
{
    ascon_cxof128_prov_ctx *outctx = (ascon_cxof128_prov_ctx *)voutctx;
    ascon_cxof128_prov_ctx *inctx = (ascon_cxof128_prov_ctx *)vinctx;

    *outctx = *inctx;
}

static const OSSL_PARAM *ascon_cxof128_prov_gettable_ctx_params(
    ossl_unused void *ctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_XOFLEN, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

static int ascon_cxof128_prov_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    ascon_cxof128_prov_ctx *ctx = (ascon_cxof128_prov_ctx *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOFLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->xoflen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->xoflen))
        return 0;

    return 1;
}

static const OSSL_PARAM *ascon_cxof128_prov_settable_ctx_params(
    ossl_unused void *ctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_XOFLEN, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        /* Note: "custom" is not a standard OSSL_DIGEST_PARAM, but needed for CXOF */
        OSSL_PARAM_octet_string("custom", NULL, 0),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int ascon_cxof128_prov_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    ascon_cxof128_prov_ctx *ctx = (ascon_cxof128_prov_ctx *)vctx;
    const OSSL_PARAM *p;
    const unsigned char *custom_data = NULL;
    size_t custom_len = 0;

    if (ctx == NULL)
        return 0;

    /* Handle XOFLEN and SIZE parameters - these can be set after initialization */
    p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &ctx->xoflen))
            return 0;
    }

    /* Also check for SIZE parameter (alias for XOFLEN) */
    p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &ctx->xoflen))
            return 0;
    }

    /* Handle customization string */
    /* Note: "custom" is not a standard OSSL_DIGEST_PARAM, but needed for CXOF */
    p = OSSL_PARAM_locate_const(params, "custom");
    if (p != NULL) {
        /* Customization string must be set before initialization */
        if (ctx->initialized) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_STATE);
            return 0;
        }

        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;

        if (!OSSL_PARAM_get_octet_string(p, (void **)&custom_data, 0, &custom_len))
            return 0;

        /* Free old customization string if any */
        if (ctx->custom != NULL) {
            OPENSSL_free(ctx->custom);
            ctx->custom = NULL;
        }

        /* Allocate and copy customization string */
        if (custom_len > 0) {
            ctx->custom = OPENSSL_malloc(custom_len);
            if (ctx->custom == NULL)
                return 0;
            memcpy(ctx->custom, custom_data, custom_len);
            ctx->custom_len = custom_len;
        } else {
            ctx->custom = NULL;
            ctx->custom_len = 0;
        }
    }

    return 1;
}

static int ascon_cxof128_prov_get_params(OSSL_PARAM params[])
{
    return ossl_digest_default_get_params(params, ASCON_CXOF128_BLOCK_SIZE, 0,
                                          ASCON_CXOF128_FLAGS);
}

const OSSL_DISPATCH ossl_ascon_cxof128_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))ascon_cxof128_prov_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))ascon_cxof128_prov_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))ascon_cxof128_prov_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))ascon_cxof128_prov_final },
    { OSSL_FUNC_DIGEST_SQUEEZE, (void (*)(void))ascon_cxof128_prov_squeeze },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))ascon_cxof128_prov_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))ascon_cxof128_prov_dupctx },
    { OSSL_FUNC_DIGEST_COPYCTX, (void (*)(void))ascon_cxof128_prov_copyctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))ascon_cxof128_prov_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,
      (void (*)(void))ossl_digest_default_gettable_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,
      (void (*)(void))ascon_cxof128_prov_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
      (void (*)(void))ascon_cxof128_prov_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,
      (void (*)(void))ascon_cxof128_prov_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,
      (void (*)(void))ascon_cxof128_prov_gettable_ctx_params },
    { 0, NULL }
};
