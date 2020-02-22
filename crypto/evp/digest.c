/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "internal/cryptlib.h"
#include "crypto/evp.h"
#include "internal/provider.h"
#include "evp_local.h"

/* This call frees resources associated with the context */
int EVP_MD_CTX_reset(EVP_MD_CTX *ctx)
{
    if (ctx == NULL)
        return 1;

#ifndef FIPS_MODE
    /* TODO(3.0): Temporarily no support for EVP_DigestSign* in FIPS module */
    /*
     * pctx should be freed by the user of EVP_MD_CTX
     * if EVP_MD_CTX_FLAG_KEEP_PKEY_CTX is set
     */
    if (!EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX))
        EVP_PKEY_CTX_free(ctx->pctx);
#endif

    EVP_MD_free(ctx->fetched_digest);
    ctx->fetched_digest = NULL;
    ctx->reqdigest = NULL;

    if (ctx->provctx != NULL) {
        if (ctx->digest->freectx != NULL)
            ctx->digest->freectx(ctx->provctx);
        ctx->provctx = NULL;
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
    }

    /* TODO(3.0): Remove legacy code below */

    /*
     * Don't assume ctx->md_data was cleaned in EVP_Digest_Final, because
     * sometimes only copies of the context are ever finalised.
     */
    if (ctx->digest && ctx->digest->cleanup
        && !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_CLEANED))
        ctx->digest->cleanup(ctx);
    if (ctx->digest && ctx->digest->ctx_size && ctx->md_data
        && !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_REUSE)) {
        OPENSSL_clear_free(ctx->md_data, ctx->digest->ctx_size);
    }

#if !defined(FIPS_MODE) && !defined(OPENSSL_NO_ENGINE)
    ENGINE_finish(ctx->engine);
#endif

    /* TODO(3.0): End of legacy code */

    OPENSSL_cleanse(ctx, sizeof(*ctx));

    return 1;
}

EVP_MD_CTX *EVP_MD_CTX_new(void)
{
    return OPENSSL_zalloc(sizeof(EVP_MD_CTX));
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    if (ctx == NULL)
        return;

    EVP_MD_CTX_reset(ctx);

    OPENSSL_free(ctx);
    return;
}

int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type)
{
    EVP_MD_CTX_reset(ctx);
    return EVP_DigestInit_ex(ctx, type, NULL);
}

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
    ENGINE *tmpimpl = NULL;
#endif

    EVP_MD_CTX_clear_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);

    if (ctx->provctx != NULL) {
        if (!ossl_assert(ctx->digest != NULL)) {
            EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_INITIALIZATION_ERROR);
            return 0;
        }
        if (ctx->digest->freectx != NULL)
            ctx->digest->freectx(ctx->provctx);
        ctx->provctx = NULL;
    }

    if (type != NULL)
        ctx->reqdigest = type;

    /* TODO(3.0): Legacy work around code below. Remove this */
#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
    /*
     * Whether it's nice or not, "Inits" can be used on "Final"'d contexts so
     * this context may already have an ENGINE! Try to avoid releasing the
     * previous handle, re-querying for an ENGINE, and having a
     * reinitialisation, when it may all be unnecessary.
     */
    if (ctx->engine && ctx->digest &&
        (type == NULL || (type->type == ctx->digest->type)))
        goto skip_to_init;

    if (type != NULL) {
        /*
         * Ensure an ENGINE left lying around from last time is cleared (the
         * previous check attempted to avoid this if the same ENGINE and
         * EVP_MD could be used).
         */
        ENGINE_finish(ctx->engine);
        ctx->engine = NULL;
    }

    if (type != NULL && impl == NULL)
        tmpimpl = ENGINE_get_digest_engine(type->type);
#endif

    /*
     * If there are engines involved or EVP_MD_CTX_FLAG_NO_INIT is set then we
     * should use legacy handling for now.
     */
    if (ctx->engine != NULL
            || impl != NULL
#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
            || tmpimpl != NULL
#endif
            || (ctx->flags & EVP_MD_CTX_FLAG_NO_INIT) != 0) {
        if (ctx->digest == ctx->fetched_digest)
            ctx->digest = NULL;
        EVP_MD_free(ctx->fetched_digest);
        ctx->fetched_digest = NULL;
        goto legacy;
    }

    if (ctx->digest != NULL && ctx->digest->ctx_size > 0) {
        OPENSSL_clear_free(ctx->md_data, ctx->digest->ctx_size);
        ctx->md_data = NULL;
    }

    /* TODO(3.0): Start of non-legacy code below */

    if (type->prov == NULL) {
#ifdef FIPS_MODE
        /* We only do explicit fetches inside the FIPS module */
        EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_INITIALIZATION_ERROR);
        return 0;
#else
        EVP_MD *provmd = EVP_MD_fetch(NULL, OBJ_nid2sn(type->type), "");

        if (provmd == NULL) {
            EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_INITIALIZATION_ERROR);
            return 0;
        }
        type = provmd;
        EVP_MD_free(ctx->fetched_digest);
        ctx->fetched_digest = provmd;
#endif
    }

    if (ctx->provctx != NULL && ctx->digest != NULL && ctx->digest != type) {
        if (ctx->digest->freectx != NULL)
            ctx->digest->freectx(ctx->provctx);
        ctx->provctx = NULL;
    }
    ctx->digest = type;
    if (ctx->provctx == NULL) {
        ctx->provctx = ctx->digest->newctx(ossl_provider_ctx(type->prov));
        if (ctx->provctx == NULL) {
            EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_INITIALIZATION_ERROR);
            return 0;
        }
    }

    if (ctx->digest->dinit == NULL) {
        EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_INITIALIZATION_ERROR);
        return 0;
    }

    return ctx->digest->dinit(ctx->provctx);

    /* TODO(3.0): Remove legacy code below */
 legacy:

#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
    if (type) {
        if (impl != NULL) {
            if (!ENGINE_init(impl)) {
                EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_INITIALIZATION_ERROR);
                return 0;
            }
        } else {
            /* Ask if an ENGINE is reserved for this job */
            impl = tmpimpl;
        }
        if (impl != NULL) {
            /* There's an ENGINE for this job ... (apparently) */
            const EVP_MD *d = ENGINE_get_digest(impl, type->type);

            if (d == NULL) {
                EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_INITIALIZATION_ERROR);
                ENGINE_finish(impl);
                return 0;
            }
            /* We'll use the ENGINE's private digest definition */
            type = d;
            /*
             * Store the ENGINE functional reference so we know 'type' came
             * from an ENGINE and we need to release it when done.
             */
            ctx->engine = impl;
        } else
            ctx->engine = NULL;
    } else {
        if (!ctx->digest) {
            EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_NO_DIGEST_SET);
            return 0;
        }
        type = ctx->digest;
    }
#endif
    if (ctx->digest != type) {
        if (ctx->digest && ctx->digest->ctx_size) {
            OPENSSL_clear_free(ctx->md_data, ctx->digest->ctx_size);
            ctx->md_data = NULL;
        }
        ctx->digest = type;
        if (!(ctx->flags & EVP_MD_CTX_FLAG_NO_INIT) && type->ctx_size) {
            ctx->update = type->update;
            ctx->md_data = OPENSSL_zalloc(type->ctx_size);
            if (ctx->md_data == NULL) {
                EVPerr(EVP_F_EVP_DIGESTINIT_EX, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }
    }
#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
 skip_to_init:
#endif
#ifndef FIPS_MODE
    /*
     * TODO(3.0): Temporarily no support for EVP_DigestSign* inside FIPS module
     * or when using providers.
     */
    if (ctx->pctx != NULL
            && (!EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx->pctx)
                 || ctx->pctx->op.sig.signature == NULL)) {
        int r;
        r = EVP_PKEY_CTX_ctrl(ctx->pctx, -1, EVP_PKEY_OP_TYPE_SIG,
                              EVP_PKEY_CTRL_DIGESTINIT, 0, ctx);
        if (r <= 0 && (r != -2))
            return 0;
    }
#endif
    if (ctx->flags & EVP_MD_CTX_FLAG_NO_INIT)
        return 1;
    return ctx->digest->init(ctx);
}

int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    if (count == 0)
        return 1;

    if (ctx->pctx != NULL
            && EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx->pctx)
            && ctx->pctx->op.sig.sigprovctx != NULL) {
        /*
         * Prior to OpenSSL 3.0 EVP_DigestSignUpdate() and
         * EVP_DigestVerifyUpdate() were just macros for EVP_DigestUpdate().
         * Some code calls EVP_DigestUpdate() directly even when initialised
         * with EVP_DigestSignInit_ex() or EVP_DigestVerifyInit_ex(), so we
         * detect that and redirect to the correct EVP_Digest*Update() function
         */
        if (ctx->pctx->operation == EVP_PKEY_OP_SIGNCTX)
            return EVP_DigestSignUpdate(ctx, data, count);
        if (ctx->pctx->operation == EVP_PKEY_OP_VERIFYCTX)
            return EVP_DigestVerifyUpdate(ctx, data, count);
        EVPerr(EVP_F_EVP_DIGESTUPDATE, EVP_R_UPDATE_ERROR);
        return 0;
    }

    if (ctx->digest == NULL
            || ctx->digest->prov == NULL
            || (ctx->flags & EVP_MD_CTX_FLAG_NO_INIT) != 0)
        goto legacy;

    if (ctx->digest->dupdate == NULL) {
        EVPerr(EVP_F_EVP_DIGESTUPDATE, EVP_R_UPDATE_ERROR);
        return 0;
    }
    return ctx->digest->dupdate(ctx->provctx, data, count);

    /* TODO(3.0): Remove legacy code below */
 legacy:
    return ctx->update(ctx, data, count);
}

/* The caller can assume that this removes any secret data from the context */
int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
{
    int ret;
    ret = EVP_DigestFinal_ex(ctx, md, size);
    EVP_MD_CTX_reset(ctx);
    return ret;
}

/* The caller can assume that this removes any secret data from the context */
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *isize)
{
    int ret;
    size_t size = 0;
    size_t mdsize = EVP_MD_size(ctx->digest);

    if (ctx->digest == NULL || ctx->digest->prov == NULL)
        goto legacy;

    if (ctx->digest->dfinal == NULL) {
        EVPerr(EVP_F_EVP_DIGESTFINAL_EX, EVP_R_FINAL_ERROR);
        return 0;
    }

    ret = ctx->digest->dfinal(ctx->provctx, md, &size, mdsize);

    if (isize != NULL) {
        if (size <= UINT_MAX) {
            *isize = (int)size;
        } else {
            EVPerr(EVP_F_EVP_DIGESTFINAL_EX, EVP_R_FINAL_ERROR);
            ret = 0;
        }
    }

    return ret;

    /* TODO(3.0): Remove legacy code below */
 legacy:
    OPENSSL_assert(mdsize <= EVP_MAX_MD_SIZE);
    ret = ctx->digest->final(ctx, md);
    if (isize != NULL)
        *isize = mdsize;
    if (ctx->digest->cleanup) {
        ctx->digest->cleanup(ctx);
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
    }
    OPENSSL_cleanse(ctx->md_data, ctx->digest->ctx_size);
    return ret;
}

int EVP_DigestFinalXOF(EVP_MD_CTX *ctx, unsigned char *md, size_t size)
{
    int ret = 0;
    OSSL_PARAM params[2];
    size_t i = 0;

    if (ctx->digest == NULL || ctx->digest->prov == NULL)
        goto legacy;

    if (ctx->digest->dfinal == NULL) {
        EVPerr(EVP_F_EVP_DIGESTFINALXOF, EVP_R_FINAL_ERROR);
        return 0;
    }

    params[i++] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &size);
    params[i++] = OSSL_PARAM_construct_end();

    if (EVP_MD_CTX_set_params(ctx, params) > 0)
        ret = ctx->digest->dfinal(ctx->provctx, md, &size, size);
    EVP_MD_CTX_reset(ctx);
    return ret;

legacy:
    if (ctx->digest->flags & EVP_MD_FLAG_XOF
        && size <= INT_MAX
        && ctx->digest->md_ctrl(ctx, EVP_MD_CTRL_XOF_LEN, (int)size, NULL)) {
        ret = ctx->digest->final(ctx, md);
        if (ctx->digest->cleanup != NULL) {
            ctx->digest->cleanup(ctx);
            EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
        }
        OPENSSL_cleanse(ctx->md_data, ctx->digest->ctx_size);
    } else {
        EVPerr(EVP_F_EVP_DIGESTFINALXOF, EVP_R_NOT_XOF_OR_INVALID_LENGTH);
    }

    return ret;
}

int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in)
{
    EVP_MD_CTX_reset(out);
    return EVP_MD_CTX_copy_ex(out, in);
}

int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in)
{
    unsigned char *tmp_buf;

    if (in == NULL || in->digest == NULL) {
        EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, EVP_R_INPUT_NOT_INITIALIZED);
        return 0;
    }

    if (in->digest->prov == NULL
            || (in->flags & EVP_MD_CTX_FLAG_NO_INIT) != 0)
        goto legacy;

    if (in->digest->dupctx == NULL) {
        EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, EVP_R_NOT_ABLE_TO_COPY_CTX);
        return 0;
    }

    EVP_MD_CTX_reset(out);
    if (out->fetched_digest != NULL)
        EVP_MD_free(out->fetched_digest);
    *out = *in;
    /* NULL out pointers in case of error */
    out->pctx = NULL;
    out->provctx = NULL;

    if (in->fetched_digest != NULL)
        EVP_MD_up_ref(in->fetched_digest);

    out->provctx = in->digest->dupctx(in->provctx);
    if (out->provctx == NULL) {
        EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, EVP_R_NOT_ABLE_TO_COPY_CTX);
        return 0;
    }

    /* copied EVP_MD_CTX should free the copied EVP_PKEY_CTX */
    EVP_MD_CTX_clear_flags(out, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
#ifndef FIPS_MODE
    /* TODO(3.0): Temporarily no support for EVP_DigestSign* in FIPS module */
    if (in->pctx != NULL) {
        out->pctx = EVP_PKEY_CTX_dup(in->pctx);
        if (out->pctx == NULL) {
            EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, EVP_R_NOT_ABLE_TO_COPY_CTX);
            EVP_MD_CTX_reset(out);
            return 0;
        }
    }
#endif

    return 1;

    /* TODO(3.0): Remove legacy code below */
 legacy:
#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
    /* Make sure it's safe to copy a digest context using an ENGINE */
    if (in->engine && !ENGINE_init(in->engine)) {
        EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, ERR_R_ENGINE_LIB);
        return 0;
    }
#endif

    if (out->digest == in->digest) {
        tmp_buf = out->md_data;
        EVP_MD_CTX_set_flags(out, EVP_MD_CTX_FLAG_REUSE);
    } else
        tmp_buf = NULL;
    EVP_MD_CTX_reset(out);
    memcpy(out, in, sizeof(*out));

    /* copied EVP_MD_CTX should free the copied EVP_PKEY_CTX */
    EVP_MD_CTX_clear_flags(out, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX);

    /* Null these variables, since they are getting fixed up
     * properly below.  Anything else may cause a memleak and/or
     * double free if any of the memory allocations below fail
     */
    out->md_data = NULL;
    out->pctx = NULL;

    if (in->md_data && out->digest->ctx_size) {
        if (tmp_buf)
            out->md_data = tmp_buf;
        else {
            out->md_data = OPENSSL_malloc(out->digest->ctx_size);
            if (out->md_data == NULL) {
                EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }
        memcpy(out->md_data, in->md_data, out->digest->ctx_size);
    }

    out->update = in->update;

#ifndef FIPS_MODE
    /* TODO(3.0): Temporarily no support for EVP_DigestSign* in FIPS module */
    if (in->pctx) {
        out->pctx = EVP_PKEY_CTX_dup(in->pctx);
        if (!out->pctx) {
            EVP_MD_CTX_reset(out);
            return 0;
        }
    }
#endif

    if (out->digest->copy)
        return out->digest->copy(out, in);

    return 1;
}

int EVP_Digest(const void *data, size_t count,
               unsigned char *md, unsigned int *size, const EVP_MD *type,
               ENGINE *impl)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ret;

    if (ctx == NULL)
        return 0;
    EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT);
    ret = EVP_DigestInit_ex(ctx, type, impl)
        && EVP_DigestUpdate(ctx, data, count)
        && EVP_DigestFinal_ex(ctx, md, size);
    EVP_MD_CTX_free(ctx);

    return ret;
}

int EVP_MD_get_params(const EVP_MD *digest, OSSL_PARAM params[])
{
    if (digest != NULL && digest->get_params != NULL)
        return digest->get_params(params);
    return 0;
}

const OSSL_PARAM *EVP_MD_gettable_params(const EVP_MD *digest)
{
    if (digest != NULL && digest->gettable_params != NULL)
        return digest->gettable_params();
    return NULL;
}

int EVP_MD_CTX_set_params(EVP_MD_CTX *ctx, const OSSL_PARAM params[])
{
    EVP_PKEY_CTX *pctx = ctx->pctx;

    if (ctx->digest != NULL && ctx->digest->set_ctx_params != NULL)
        return ctx->digest->set_ctx_params(ctx->provctx, params);

    if (pctx != NULL
            && (pctx->operation == EVP_PKEY_OP_VERIFYCTX
                || pctx->operation == EVP_PKEY_OP_SIGNCTX)
            && pctx->op.sig.sigprovctx != NULL
            && pctx->op.sig.signature->set_ctx_md_params != NULL)
        return pctx->op.sig.signature->set_ctx_md_params(pctx->op.sig.sigprovctx,
                                                         params);
    return 0;
}

const OSSL_PARAM *EVP_MD_settable_ctx_params(const EVP_MD *md)
{
    if (md != NULL && md->settable_ctx_params != NULL)
        return md->settable_ctx_params();
    return NULL;
}

const OSSL_PARAM *EVP_MD_CTX_settable_params(EVP_MD_CTX *ctx)
{
    EVP_PKEY_CTX *pctx;

    if (ctx != NULL
            && ctx->digest != NULL
            && ctx->digest->settable_ctx_params != NULL)
        return ctx->digest->settable_ctx_params();

    pctx = ctx->pctx;
    if (pctx != NULL
            && (pctx->operation == EVP_PKEY_OP_VERIFYCTX
                || pctx->operation == EVP_PKEY_OP_SIGNCTX)
            && pctx->op.sig.sigprovctx != NULL
            && pctx->op.sig.signature->settable_ctx_md_params != NULL)
        return pctx->op.sig.signature->settable_ctx_md_params(
                   pctx->op.sig.sigprovctx);

    return NULL;
}

int EVP_MD_CTX_get_params(EVP_MD_CTX *ctx, OSSL_PARAM params[])
{
    EVP_PKEY_CTX *pctx = ctx->pctx;

    if (ctx->digest != NULL && ctx->digest->get_params != NULL)
        return ctx->digest->get_ctx_params(ctx->provctx, params);

    if (pctx != NULL
            && (pctx->operation == EVP_PKEY_OP_VERIFYCTX
                || pctx->operation == EVP_PKEY_OP_SIGNCTX)
            && pctx->op.sig.sigprovctx != NULL
            && pctx->op.sig.signature->get_ctx_md_params != NULL)
        return pctx->op.sig.signature->get_ctx_md_params(pctx->op.sig.sigprovctx,
                                                         params);

    return 0;
}

const OSSL_PARAM *EVP_MD_gettable_ctx_params(const EVP_MD *md)
{
    if (md != NULL && md->gettable_ctx_params != NULL)
        return md->gettable_ctx_params();
    return NULL;
}

const OSSL_PARAM *EVP_MD_CTX_gettable_params(EVP_MD_CTX *ctx)
{
    EVP_PKEY_CTX *pctx;

    if (ctx != NULL
            && ctx->digest != NULL
            && ctx->digest->gettable_ctx_params != NULL)
        return ctx->digest->gettable_ctx_params();

    pctx = ctx->pctx;
    if (pctx != NULL
            && (pctx->operation == EVP_PKEY_OP_VERIFYCTX
                || pctx->operation == EVP_PKEY_OP_SIGNCTX)
            && pctx->op.sig.sigprovctx != NULL
            && pctx->op.sig.signature->gettable_ctx_md_params != NULL)
        return pctx->op.sig.signature->gettable_ctx_md_params(
                    pctx->op.sig.sigprovctx);

    return NULL;
}

/* TODO(3.0): Remove legacy code below - only used by engines & DigestSign */
int EVP_MD_CTX_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    int ret = EVP_CTRL_RET_UNSUPPORTED;
    int set_params = 1;
    size_t sz;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    if (ctx == NULL || ctx->digest == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_MESSAGE_DIGEST_IS_NULL);
        return 0;
    }

    if (ctx->digest->prov == NULL)
        goto legacy;

    switch (cmd) {
    case EVP_MD_CTRL_XOF_LEN:
        sz = (size_t)p1;
        params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &sz);
        break;
    case EVP_MD_CTRL_MICALG:
        set_params = 0;
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DIGEST_PARAM_MICALG,
                                                     p2, p1 ? p1 : 9999);
        break;
    case EVP_CTRL_SSL3_MASTER_SECRET:
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_DIGEST_PARAM_SSL3_MS,
                                                      p2, p1);
        break;
    default:
        goto conclude;
    }

    if (set_params)
        ret = EVP_MD_CTX_set_params(ctx, params);
    else
        ret = EVP_MD_CTX_get_params(ctx, params);
    goto conclude;


/* TODO(3.0): Remove legacy code below */
 legacy:
    if (ctx->digest->md_ctrl == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_CTRL_NOT_IMPLEMENTED);
        return 0;
    }

    ret = ctx->digest->md_ctrl(ctx, cmd, p1, p2);
 conclude:
    if (ret <= 0)
        return 0;
    return ret;
}

EVP_MD *evp_md_new(void)
{
    EVP_MD *md = OPENSSL_zalloc(sizeof(*md));

    if (md != NULL) {
        md->lock = CRYPTO_THREAD_lock_new();
        if (md->lock == NULL) {
            OPENSSL_free(md);
            return NULL;
        }
        md->refcnt = 1;
    }
    return md;
}

/*
 * FIPS module note: since internal fetches will be entirely
 * provider based, we know that none of its code depends on legacy
 * NIDs or any functionality that use them.
 */
#ifndef FIPS_MODE
/* TODO(3.x) get rid of the need for legacy NIDs */
static void set_legacy_nid(const char *name, void *vlegacy_nid)
{
    int nid;
    int *legacy_nid = vlegacy_nid;
    /*
     * We use lowest level function to get the associated method, because
     * higher level functions such as EVP_get_digestbyname() have changed
     * to look at providers too.
     */
    const void *legacy_method = OBJ_NAME_get(name, OBJ_NAME_TYPE_MD_METH);

    if (*legacy_nid == -1)       /* We found a clash already */
        return;

    if (legacy_method == NULL)
        return;
    nid = EVP_MD_nid(legacy_method);
    if (*legacy_nid != NID_undef && *legacy_nid != nid) {
        *legacy_nid = -1;
        return;
    }
    *legacy_nid = nid;
}
#endif

static void *evp_md_from_dispatch(int name_id,
                                  const OSSL_DISPATCH *fns,
                                  OSSL_PROVIDER *prov)
{
    EVP_MD *md = NULL;
    int fncnt = 0;

    /* EVP_MD_fetch() will set the legacy NID if available */
    if ((md = evp_md_new()) == NULL) {
        EVPerr(0, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

#ifndef FIPS_MODE
    /* TODO(3.x) get rid of the need for legacy NIDs */
    md->type = NID_undef;
    evp_names_do_all(prov, name_id, set_legacy_nid, &md->type);
    if (md->type == -1) {
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        EVP_MD_free(md);
        return NULL;
    }
#endif

    md->name_id = name_id;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_DIGEST_NEWCTX:
            if (md->newctx == NULL) {
                md->newctx = OSSL_get_OP_digest_newctx(fns);
                fncnt++;
            }
            break;
        case OSSL_FUNC_DIGEST_INIT:
            if (md->dinit == NULL) {
                md->dinit = OSSL_get_OP_digest_init(fns);
                fncnt++;
            }
            break;
        case OSSL_FUNC_DIGEST_UPDATE:
            if (md->dupdate == NULL) {
                md->dupdate = OSSL_get_OP_digest_update(fns);
                fncnt++;
            }
            break;
        case OSSL_FUNC_DIGEST_FINAL:
            if (md->dfinal == NULL) {
                md->dfinal = OSSL_get_OP_digest_final(fns);
                fncnt++;
            }
            break;
        case OSSL_FUNC_DIGEST_DIGEST:
            if (md->digest == NULL)
                md->digest = OSSL_get_OP_digest_digest(fns);
            /* We don't increment fnct for this as it is stand alone */
            break;
        case OSSL_FUNC_DIGEST_FREECTX:
            if (md->freectx == NULL) {
                md->freectx = OSSL_get_OP_digest_freectx(fns);
                fncnt++;
            }
            break;
        case OSSL_FUNC_DIGEST_DUPCTX:
            if (md->dupctx == NULL)
                md->dupctx = OSSL_get_OP_digest_dupctx(fns);
            break;
        case OSSL_FUNC_DIGEST_GET_PARAMS:
            if (md->get_params == NULL)
                md->get_params = OSSL_get_OP_digest_get_params(fns);
            break;
        case OSSL_FUNC_DIGEST_SET_CTX_PARAMS:
            if (md->set_ctx_params == NULL)
                md->set_ctx_params = OSSL_get_OP_digest_set_ctx_params(fns);
            break;
        case OSSL_FUNC_DIGEST_GET_CTX_PARAMS:
            if (md->get_ctx_params == NULL)
                md->get_ctx_params = OSSL_get_OP_digest_get_ctx_params(fns);
            break;
        case OSSL_FUNC_DIGEST_GETTABLE_PARAMS:
            if (md->gettable_params == NULL)
                md->gettable_params = OSSL_get_OP_digest_gettable_params(fns);
            break;
        case OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS:
            if (md->settable_ctx_params == NULL)
                md->settable_ctx_params =
                    OSSL_get_OP_digest_settable_ctx_params(fns);
            break;
        case OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS:
            if (md->gettable_ctx_params == NULL)
                md->gettable_ctx_params =
                    OSSL_get_OP_digest_gettable_ctx_params(fns);
            break;
        }
    }
    if ((fncnt != 0 && fncnt != 5)
        || (fncnt == 0 && md->digest == NULL)) {
        /*
         * In order to be a consistent set of functions we either need the
         * whole set of init/update/final etc functions or none of them.
         * The "digest" function can standalone. We at least need one way to
         * generate digests.
         */
        EVP_MD_free(md);
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        return NULL;
    }
    md->prov = prov;
    if (prov != NULL)
        ossl_provider_up_ref(prov);

    return md;
}

static int evp_md_up_ref(void *md)
{
    return EVP_MD_up_ref(md);
}

static void evp_md_free(void *md)
{
    EVP_MD_free(md);
}

EVP_MD *EVP_MD_fetch(OPENSSL_CTX *ctx, const char *algorithm,
                     const char *properties)
{
    EVP_MD *md =
        evp_generic_fetch(ctx, OSSL_OP_DIGEST, algorithm, properties,
                          evp_md_from_dispatch, evp_md_up_ref, evp_md_free);

    return md;
}

int EVP_MD_up_ref(EVP_MD *md)
{
    int ref = 0;

    CRYPTO_UP_REF(&md->refcnt, &ref, md->lock);
    return 1;
}

void EVP_MD_free(EVP_MD *md)
{
    int i;

    if (md == NULL)
        return;

    CRYPTO_DOWN_REF(&md->refcnt, &i, md->lock);
    if (i > 0)
        return;
    ossl_provider_free(md->prov);
    CRYPTO_THREAD_lock_free(md->lock);
    OPENSSL_free(md);
}

void EVP_MD_do_all_provided(OPENSSL_CTX *libctx,
                            void (*fn)(EVP_MD *mac, void *arg),
                            void *arg)
{
    evp_generic_do_all(libctx, OSSL_OP_DIGEST,
                       (void (*)(void *, void *))fn, arg,
                       evp_md_from_dispatch, evp_md_free);
}
