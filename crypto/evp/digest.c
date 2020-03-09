/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
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
#include "legacy_meth.h"

/* This call frees resources associated with the context */
int EVP_MD_CTX_reset(EVP_MD_CTX *ctx)
{
    if (ctx == NULL)
        return 1;

    /*
     * pctx should be freed by the user of EVP_MD_CTX
     * if EVP_MD_CTX_FLAG_KEEP_PKEY_CTX is set
     */
    if (!EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX))
        EVP_PKEY_CTX_free(ctx->pctx);

    EVP_MD_free(ctx->fetched_digest);
    ctx->fetched_digest = NULL;
    ctx->reqdigest = NULL;

    if (ctx->provctx != NULL) {
        if (ctx->digest->freectx != NULL)
            ctx->digest->freectx(ctx->provctx);
        ctx->provctx = NULL;
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
    }

#if !defined(FIPS_MODE)
    legacy_evp_md_ctx_reset(ctx);
#endif
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

#if !defined(FIPS_MODE)
    {
        int ret = 0;

        if (legacy_evp_digest_init_ex(ctx, type, impl, &ret))
            return ret;
    }
#endif

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

#ifndef FIPS_MODE
    {
        int ret = 0;

        if (legacy_evp_digest_update(ctx, data, count, &ret))
            return ret;
    }
#endif /* FIPS_MODE */

    if (ctx->digest->dupdate == NULL) {
        EVPerr(EVP_F_EVP_DIGESTUPDATE, EVP_R_UPDATE_ERROR);
        return 0;
    }
    return ctx->digest->dupdate(ctx->provctx, data, count);
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
    int ret = 0;
    size_t size = 0;
    size_t mdsize;

#ifndef FIPS_MODE
    if (legacy_evp_digest_final_ex(ctx, md, isize, &ret))
        return ret;
#endif
    if (ctx->digest->dfinal == NULL) {
        EVPerr(EVP_F_EVP_DIGESTFINAL_EX, EVP_R_FINAL_ERROR);
        return 0;
    }

    mdsize = EVP_MD_size(ctx->digest);
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
}

int EVP_DigestFinalXOF(EVP_MD_CTX *ctx, unsigned char *md, size_t size)
{
    int ret = 0;
    OSSL_PARAM params[2];
    size_t i = 0;

#ifndef FIPS_MODE
    if (legacy_evp_digest_final_xof(ctx, md, size, &ret))
        return ret;
#endif

    if (ctx->digest->dfinal == NULL) {
        EVPerr(EVP_F_EVP_DIGESTFINALXOF, EVP_R_FINAL_ERROR);
        return 0;
    }

    params[i++] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN, &size);
    params[i++] = OSSL_PARAM_construct_end();

    ret = 0;
    if (EVP_MD_CTX_set_params(ctx, params) > 0)
        ret = ctx->digest->dfinal(ctx->provctx, md, &size, size);
    EVP_MD_CTX_reset(ctx);
    return ret;
}

int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in)
{
    EVP_MD_CTX_reset(out);
    return EVP_MD_CTX_copy_ex(out, in);
}

int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in)
{
    if (in == NULL || in->digest == NULL) {
        EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, EVP_R_INPUT_NOT_INITIALIZED);
        return 0;
    }

#ifndef FIPS_MODE
    {
        int ret = 0;

        if (legacy_evp_md_ctx_copy_ex(out, in, &ret))
            return ret;
    }
#endif

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

int EVP_MD_CTX_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    int ret = 0;
    int set_params = 1;
    size_t sz;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    if (ctx == NULL || ctx->digest == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_MESSAGE_DIGEST_IS_NULL);
        return 0;
    }

#ifndef FIPS_MODE
    if (legacy_evp_md_ctx_ctrl(ctx, cmd, p1, p2, &ret))
        return ret;
#endif

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
        return 0;
    }

    if (set_params)
        ret = EVP_MD_CTX_set_params(ctx, params);
    else
        ret = EVP_MD_CTX_get_params(ctx, params);
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
    evp_names_do_all(prov, name_id, legacy_evp_digest_set_nid, &md->type);
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
