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

void legacy_evp_md_ctx_reset(EVP_MD_CTX *ctx)
{
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
#if !defined(OPENSSL_NO_ENGINE)
    ENGINE_finish(ctx->engine);
#endif
}

int legacy_evp_digest_init_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl,
                              int *ret)
{
#if !defined(OPENSSL_NO_ENGINE)
    ENGINE *tmpimpl = NULL;
    /*
     * Whether it's nice or not, "Inits" can be used on "Final"'d contexts so
     * this context may already have an ENGINE! Try to avoid releasing the
     * previous handle, re-querying for an ENGINE, and having a
     * reinitialisation, when it may all be unnecessary.
     */
    if (ctx->engine != NULL
        && ctx->digest != NULL
        && (type == NULL || (type->type == ctx->digest->type)))
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
#endif /* !defined(OPENSSL_NO_ENGINE) */

    /*
     * If there are engines involved or EVP_MD_CTX_FLAG_NO_INIT is set then we
     * should use legacy handling for now.
     */
    if (ctx->engine != NULL
            || impl != NULL
#if !defined(OPENSSL_NO_ENGINE)
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
    return 0; /* return 0 if this is not a legacy case */
legacy:
#if !defined(OPENSSL_NO_ENGINE)
    if (type) {
        if (impl != NULL) {
            if (!ENGINE_init(impl)) {
                EVPerr(0, EVP_R_INITIALIZATION_ERROR);
                goto err;
            }
        } else {
            /* Ask if an ENGINE is reserved for this job */
            impl = tmpimpl;
        }
        if (impl != NULL) {
            /* There's an ENGINE for this job ... (apparently) */
            const EVP_MD *d = ENGINE_get_digest(impl, type->type);

            if (d == NULL) {
                EVPerr(0, EVP_R_INITIALIZATION_ERROR);
                ENGINE_finish(impl);
                goto err;
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
            EVPerr(0, EVP_R_NO_DIGEST_SET);
            goto err;
        }
        type = ctx->digest;
    }
#endif /* !defined(OPENSSL_NO_ENGINE) */
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
                EVPerr(0, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
    }
#if !defined(OPENSSL_NO_ENGINE)
skip_to_init:
#endif
    if (ctx->pctx != NULL
            && (!EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx->pctx)
                 || ctx->pctx->op.sig.signature == NULL)) {
        int r;
        r = EVP_PKEY_CTX_ctrl(ctx->pctx, -1, EVP_PKEY_OP_TYPE_SIG,
                              EVP_PKEY_CTRL_DIGESTINIT, 0, ctx);
        if (r <= 0 && (r != -2))
            goto err;
    }
    if (ctx->flags & EVP_MD_CTX_FLAG_NO_INIT) {
        *ret = 1;
        return 1;
    }
    *ret = ctx->digest->init(ctx);
    return 1;
err:
    *ret = 0;
    return 1;
}

int legacy_evp_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count,
                             int *ret)
{
    if (ctx->digest == NULL
        || ctx->digest->prov == NULL
        || (ctx->flags & EVP_MD_CTX_FLAG_NO_INIT) != 0) {
        *ret = ctx->update(ctx, data, count);
        return 1;
    }
    return 0; /* return 0 if this is not a legacy case */
}

int legacy_evp_digest_final_ex(EVP_MD_CTX *ctx, unsigned char *md,
                               unsigned int *isize, int *ret)
{
    if (ctx->digest == NULL)
        goto err;
    if (ctx->digest->prov != NULL)
        return 0; /* return 0 if this is not a legacy case */
    {
        size_t mdsize = EVP_MD_size(ctx->digest);

        OPENSSL_assert(mdsize <= EVP_MAX_MD_SIZE);
        *ret = ctx->digest->final(ctx, md);
        if (isize != NULL)
            *isize = mdsize;
        if (ctx->digest->cleanup) {
            ctx->digest->cleanup(ctx);
            EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
        }
        OPENSSL_cleanse(ctx->md_data, ctx->digest->ctx_size);
        return 1;
    }
err:
    *ret = 0;
    return 1;
}

int legacy_evp_digest_final_xof(EVP_MD_CTX *ctx, unsigned char *md, size_t size,
                                int *ret)
{
    if (ctx->digest == NULL)
        goto err;
    if (ctx->digest->prov != NULL)
        return 0; /* return 0 if this is not a legacy case */

    if (ctx->digest->flags & EVP_MD_FLAG_XOF
        && size <= INT_MAX
        && ctx->digest->md_ctrl(ctx, EVP_MD_CTRL_XOF_LEN, (int)size, NULL)) {
            *ret = ctx->digest->final(ctx, md);
            if (ctx->digest->cleanup != NULL) {
                ctx->digest->cleanup(ctx);
                EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
            }
            OPENSSL_cleanse(ctx->md_data, ctx->digest->ctx_size);
    } else {
        EVPerr(0, EVP_R_NOT_XOF_OR_INVALID_LENGTH);
        goto err;
    }
    return 1;
err:
    *ret = 0;
    return 1;
}

int legacy_evp_md_ctx_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in, int *ret)
{
    unsigned char *tmp_buf;

    if (in->digest->prov == NULL
        || (in->flags & EVP_MD_CTX_FLAG_NO_INIT) != 0) {
#if !defined(OPENSSL_NO_ENGINE)
        /* Make sure it's safe to copy a digest context using an ENGINE */
        if (in->engine && !ENGINE_init(in->engine)) {
            EVPerr(0, ERR_R_ENGINE_LIB);
            goto err;
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
                    EVPerr(0, ERR_R_MALLOC_FAILURE);
                    goto err;
                }
            }
            memcpy(out->md_data, in->md_data, out->digest->ctx_size);
        }
        out->update = in->update;
        if (in->pctx) {
            out->pctx = EVP_PKEY_CTX_dup(in->pctx);
            if (!out->pctx) {
                EVP_MD_CTX_reset(out);
                goto err;
            }
        }
        if (out->digest->copy)
            *ret = out->digest->copy(out, in);
        else
            *ret = 1;
        return 1;
    }
    return 0; /* return 0 if this is not a legacy case */
err:
    *ret = 0;
    return 1;
}

/* only used by engines & DigestSign */
int legacy_evp_md_ctx_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2, int *ret)
{
    if (ctx->digest->prov != NULL)
        return 0; /* return 0 if this is not a legacy case */

    if (ctx->digest->md_ctrl == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_CTRL_NOT_IMPLEMENTED);
        goto err;
    }

    *ret = ctx->digest->md_ctrl(ctx, cmd, p1, p2);
    if (*ret <= 0)
        goto err;
    return 1;
err:
    *ret = 0;
    return 1;
}

/*
 * FIPS module note: since internal fetches will be entirely
 * provider based, we know that none of its code depends on legacy
 * NIDs or any functionality that use them.
 */
/* TODO(3.x) get rid of the need for legacy NIDs */
void legacy_evp_digest_set_nid(const char *name, void *vlegacy_nid)
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
