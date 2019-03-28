/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include "internal/evp_int.h"
#include "internal/provider.h"
#include "evp_locl.h"

/* This call frees resources associated with the context */
int EVP_MD_CTX_reset(EVP_MD_CTX *ctx)
{
    if (ctx == NULL)
        return 1;

    if (ctx->digest == NULL || ctx->digest->prov == NULL)
        goto legacy;

    if (ctx->provctx != NULL) {
        if (ctx->digest->freectx != NULL)
            ctx->digest->freectx(ctx->provctx);
        ctx->provctx = NULL;
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
    }

    if (ctx->pctx != NULL)
        goto legacy;

    return 1;

    /* TODO(3.0): Remove legacy code below */
 legacy:

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
    /*
     * pctx should be freed by the user of EVP_MD_CTX
     * if EVP_MD_CTX_FLAG_KEEP_PKEY_CTX is set
     */
    if (!EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX))
        EVP_PKEY_CTX_free(ctx->pctx);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(ctx->engine);
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

    if (ctx->digest == NULL || ctx->digest->prov == NULL)
        goto legacy;

    EVP_MD_CTX_reset(ctx);

    EVP_MD_meth_free(ctx->fetched_digest);
    ctx->fetched_digest = NULL;
    ctx->digest = NULL;
    ctx->reqdigest = NULL;

    OPENSSL_free(ctx);
    return;

    /* TODO(3.0): Remove legacy code below */
 legacy:
    EVP_MD_CTX_reset(ctx);
    OPENSSL_free(ctx);
}

int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type)
{
    EVP_MD_CTX_reset(ctx);
    return EVP_DigestInit_ex(ctx, type, NULL);
}

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
    EVP_MD *provmd;
    ENGINE *tmpimpl = NULL;

    EVP_MD_CTX_clear_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);

    if (type != NULL)
        ctx->reqdigest = type;

    /* TODO(3.0): Legacy work around code below. Remove this */
#ifndef OPENSSL_NO_ENGINE
    /*
     * Whether it's nice or not, "Inits" can be used on "Final"'d contexts so
     * this context may already have an ENGINE! Try to avoid releasing the
     * previous handle, re-querying for an ENGINE, and having a
     * reinitialisation, when it may all be unnecessary.
     */
    if (ctx->engine && ctx->digest &&
        (type == NULL || (type->type == ctx->digest->type)))
        goto skip_to_init;

    if (type != NULL && impl == NULL)
        tmpimpl = ENGINE_get_digest_engine(type->type);
#endif

    /*
     * If there are engines involved or if we're being used as part of
     * EVP_DigestSignInit then we should use legacy handling for now.
     */
    if (ctx->engine != NULL
            || impl != NULL
            || tmpimpl != NULL
            || ctx->pctx != NULL
            || (ctx->flags & EVP_MD_CTX_FLAG_NO_INIT) != 0) {
        if (ctx->digest == ctx->fetched_digest)
            ctx->digest = NULL;
        EVP_MD_meth_free(ctx->fetched_digest);
        ctx->fetched_digest = NULL;
        goto legacy;
    }

    if (type->prov == NULL) {
        switch(type->type) {
        case NID_sha256:
            break;
        default:
            goto legacy;
        }
    }

    if (ctx->digest != NULL && ctx->digest->ctx_size > 0) {
        OPENSSL_clear_free(ctx->md_data, ctx->digest->ctx_size);
        ctx->md_data = NULL;
    }

    /* TODO(3.0): Start of non-legacy code below */

    if (type->prov == NULL) {
        provmd = EVP_MD_fetch(NULL, OBJ_nid2sn(type->type), "");
        if (provmd == NULL) {
            EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_INITIALIZATION_ERROR);
            return 0;
        }
        type = provmd;
        EVP_MD_meth_free(ctx->fetched_digest);
        ctx->fetched_digest = provmd;
    }

    ctx->digest = type;
    if (ctx->provctx == NULL) {
        ctx->provctx = ctx->digest->newctx();
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

#ifndef OPENSSL_NO_ENGINE
    if (type) {
        /*
         * Ensure an ENGINE left lying around from last time is cleared (the
         * previous check attempted to avoid this if the same ENGINE and
         * EVP_MD could be used).
         */
        ENGINE_finish(ctx->engine);
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
#ifndef OPENSSL_NO_ENGINE
 skip_to_init:
#endif
    if (ctx->pctx) {
        int r;
        r = EVP_PKEY_CTX_ctrl(ctx->pctx, -1, EVP_PKEY_OP_TYPE_SIG,
                              EVP_PKEY_CTRL_DIGESTINIT, 0, ctx);
        if (r <= 0 && (r != -2))
            return 0;
    }
    if (ctx->flags & EVP_MD_CTX_FLAG_NO_INIT)
        return 1;
    return ctx->digest->init(ctx);
}

int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    if (count == 0)
        return 1;

    if (ctx->digest == NULL || ctx->digest->prov == NULL)
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

    if (ctx->digest == NULL || ctx->digest->prov == NULL)
        goto legacy;

    if (ctx->digest->dfinal == NULL) {
        EVPerr(EVP_F_EVP_DIGESTFINAL_EX, EVP_R_FINAL_ERROR);
        return 0;
    }

    ret = ctx->digest->dfinal(ctx->provctx, md, &size);

    if (isize != NULL) {
        if (size <= UINT_MAX) {
            *isize = (int)size;
        } else {
            EVPerr(EVP_F_EVP_DIGESTFINAL_EX, EVP_R_FINAL_ERROR);
            ret = 0;
        }
    }

    EVP_MD_CTX_reset(ctx);

    return ret;

    /* TODO(3.0): Remove legacy code below */
 legacy:
    OPENSSL_assert(ctx->digest->md_size <= EVP_MAX_MD_SIZE);
    ret = ctx->digest->final(ctx, md);
    if (isize != NULL)
        *isize = ctx->digest->md_size;
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

    if (in->digest->prov == NULL)
        goto legacy;

    if (in->digest->dupctx == NULL) {
        EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, EVP_R_NOT_ABLE_TO_COPY_CTX);
        return 0;
    }

    EVP_MD_CTX_reset(out);
    if (out->fetched_digest != NULL)
        EVP_MD_meth_free(out->fetched_digest);
    *out = *in;
    /* NULL out pointers in case of error */
    out->pctx = NULL;
    out->provctx = NULL;

    if (in->fetched_digest != NULL)
        EVP_MD_upref(in->fetched_digest);

    out->provctx = in->digest->dupctx(in->provctx);
    if (out->provctx == NULL) {
        EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, EVP_R_NOT_ABLE_TO_COPY_CTX);
        return 0;
    }

    /* copied EVP_MD_CTX should free the copied EVP_PKEY_CTX */
    EVP_MD_CTX_clear_flags(out, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
    if (in->pctx != NULL) {
        out->pctx = EVP_PKEY_CTX_dup(in->pctx);
        if (out->pctx == NULL) {
            EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, EVP_R_NOT_ABLE_TO_COPY_CTX);
            EVP_MD_CTX_reset(out);
            return 0;
        }
    }

    return 1;

    /* TODO(3.0): Remove legacy code below */
 legacy:
#ifndef OPENSSL_NO_ENGINE
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

    if (in->pctx) {
        out->pctx = EVP_PKEY_CTX_dup(in->pctx);
        if (!out->pctx) {
            EVP_MD_CTX_reset(out);
            return 0;
        }
    }

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

int EVP_MD_CTX_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    if (ctx->digest && ctx->digest->md_ctrl) {
        int ret = ctx->digest->md_ctrl(ctx, cmd, p1, p2);
        if (ret <= 0)
            return 0;
        return 1;
    }
    return 0;
}

static void *evp_md_from_dispatch(int mdtype, const OSSL_DISPATCH *fns,
                                    OSSL_PROVIDER *prov)
{
    EVP_MD *md = NULL;
    int fncnt = 0;

    if ((md = EVP_MD_meth_new(mdtype, NID_undef)) == NULL)
        return NULL;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_DIGEST_NEWCTX:
            if (md->newctx != NULL)
                break;
            md->newctx = OSSL_get_OP_digest_newctx(fns);
            fncnt++;
            break;
        case OSSL_FUNC_DIGEST_INIT:
            if (md->dinit != NULL)
                break;
            md->dinit = OSSL_get_OP_digest_init(fns);
            fncnt++;
            break;
        case OSSL_FUNC_DIGEST_UPDDATE:
            if (md->dupdate != NULL)
                break;
            md->dupdate = OSSL_get_OP_digest_update(fns);
            fncnt++;
            break;
        case OSSL_FUNC_DIGEST_FINAL:
            if (md->dfinal != NULL)
                break;
            md->dfinal = OSSL_get_OP_digest_final(fns);
            fncnt++;
            break;
        case OSSL_FUNC_DIGEST_DIGEST:
            if (md->digest != NULL)
                break;
            md->digest = OSSL_get_OP_digest_digest(fns);
            /* We don't increment fnct for this as it is stand alone */
            break;
        case OSSL_FUNC_DIGEST_FREECTX:
            if (md->freectx != NULL)
                break;
            md->freectx = OSSL_get_OP_digest_freectx(fns);
            fncnt++;
            break;
        case OSSL_FUNC_DIGEST_DUPCTX:
            if (md->dupctx != NULL)
                break;
            md->dupctx = OSSL_get_OP_digest_dupctx(fns);
            break;
        case OSSL_FUNC_DIGEST_SIZE:
            if (md->size != NULL)
                break;
            md->size = OSSL_get_OP_digest_size(fns);
            break;
        case OSSL_FUNC_DIGEST_BLOCK_SIZE:
            if (md->dblock_size != NULL)
                break;
            md->dblock_size = OSSL_get_OP_digest_block_size(fns);
            break;
        }
    }
    if ((fncnt != 0 && fncnt != 5)
        || (fncnt == 0 && md->digest == NULL)
        || md->size == NULL) {
        /*
         * In order to be a consistent set of functions we either need the
         * whole set of init/update/final etc functions or none of them.
         * The "digest" function can standalone. We at least need one way to
         * generate digests.
         */
        EVP_MD_meth_free(md);
        return NULL;
    }
    md->prov = prov;
    if (prov != NULL)
        ossl_provider_upref(prov);

    return md;
}

static int evp_md_upref(void *md)
{
    return EVP_MD_upref(md);
}

static void evp_md_free(void *md)
{
    EVP_MD_meth_free(md);
}

EVP_MD *EVP_MD_fetch(OPENSSL_CTX *ctx, const char *algorithm,
                     const char *properties)
{
    return evp_generic_fetch(ctx, OSSL_OP_DIGEST, algorithm, properties,
                             evp_md_from_dispatch, evp_md_upref,
                             evp_md_free);
}
