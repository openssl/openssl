
/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
#include "internal/cryptlib.h"
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "internal/numbers.h"
#include "internal/provider.h"
#include "evp_local.h"

typedef const EVP_PKEY_METHOD *(*pmeth_fn)(void);
typedef int sk_cmp_fn_type(const char *const *a, const char *const *b);

static STACK_OF(EVP_PKEY_METHOD) *app_pkey_methods = NULL;

/* This array needs to be in order of NIDs */
static pmeth_fn standard_methods[] = {
#ifndef OPENSSL_NO_RSA
    rsa_pkey_method,
#endif
#ifndef OPENSSL_NO_DH
    dh_pkey_method,
#endif
#ifndef OPENSSL_NO_DSA
    dsa_pkey_method,
#endif
#ifndef OPENSSL_NO_EC
    ec_pkey_method,
#endif
    hmac_pkey_method,
#ifndef OPENSSL_NO_CMAC
    cmac_pkey_method,
#endif
#ifndef OPENSSL_NO_RSA
    rsa_pss_pkey_method,
#endif
#ifndef OPENSSL_NO_DH
    dhx_pkey_method,
#endif
#ifndef OPENSSL_NO_SCRYPT
    scrypt_pkey_method,
#endif
    tls1_prf_pkey_method,
#ifndef OPENSSL_NO_EC
    ecx25519_pkey_method,
    ecx448_pkey_method,
#endif
    hkdf_pkey_method,
#ifndef OPENSSL_NO_POLY1305
    poly1305_pkey_method,
#endif
#ifndef OPENSSL_NO_SIPHASH
    siphash_pkey_method,
#endif
#ifndef OPENSSL_NO_EC
    ed25519_pkey_method,
    ed448_pkey_method,
#endif
#ifndef OPENSSL_NO_SM2
    sm2_pkey_method,
#endif
};

DECLARE_OBJ_BSEARCH_CMP_FN(const EVP_PKEY_METHOD *, pmeth_fn, pmeth_func);

static int pmeth_func_cmp(const EVP_PKEY_METHOD *const *a, pmeth_fn const *b)
{
    return ((*a)->pkey_id - ((**b)())->pkey_id);
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(const EVP_PKEY_METHOD *, pmeth_fn, pmeth_func);

static int pmeth_cmp(const EVP_PKEY_METHOD *const *a,
                     const EVP_PKEY_METHOD *const *b)
{
    return ((*a)->pkey_id - (*b)->pkey_id);
}

const EVP_PKEY_METHOD *EVP_PKEY_meth_find(int type)
{
    pmeth_fn *ret;
    EVP_PKEY_METHOD tmp;
    const EVP_PKEY_METHOD *t = &tmp;

    tmp.pkey_id = type;
    if (app_pkey_methods) {
        int idx;
        idx = sk_EVP_PKEY_METHOD_find(app_pkey_methods, &tmp);
        if (idx >= 0)
            return sk_EVP_PKEY_METHOD_value(app_pkey_methods, idx);
    }
    ret = OBJ_bsearch_pmeth_func(&t, standard_methods,
                                 sizeof(standard_methods) /
                                 sizeof(pmeth_fn));
    if (ret == NULL || *ret == NULL)
        return NULL;
    return (**ret)();
}

static EVP_PKEY_CTX *int_ctx_new(OPENSSL_CTX *libctx,
                                 EVP_PKEY *pkey, ENGINE *e,
                                 const char *name, const char *propquery,
                                 int id)
{
    EVP_PKEY_CTX *ret;
    const EVP_PKEY_METHOD *pmeth = NULL;

    /*
     * When using providers, the context is bound to the algo implementation
     * later.
     */
    if (pkey == NULL && e == NULL && id == -1)
        goto common;

    /* TODO(3.0) Legacy code should be removed when all is provider based */
    /* BEGIN legacy */
    if (id == -1) {
        if (pkey == NULL)
            return 0;
        id = pkey->type;
    }

    /*
     * Here, we extract what information we can for the purpose of
     * supporting usage with implementations from providers, to make
     * for a smooth transition from legacy stuff to provider based stuff.
     *
     * If an engine is given, this is entirely legacy, and we should not
     * pretend anything else, so we only set the name when no engine is
     * given.  If both are already given, someone made a mistake, and
     * since that can only happen internally, it's safe to make an
     * assertion.
     */
    if (!ossl_assert(e == NULL || name == NULL))
        return NULL;
    if (e == NULL)
        name = OBJ_nid2sn(id);
    propquery = NULL;
    /*
     * We were called using legacy data, or an EVP_PKEY, but an EVP_PKEY
     * isn't tied to a specific library context, so we fall back to the
     * default library context.
     * TODO(v3.0): an EVP_PKEY that doesn't originate from a leagacy key
     * structure only has the pkeys[] cache, where the first element is
     * considered the "origin".  Investigate if that could be a suitable
     * way to find a library context.
     */
    libctx = NULL;

#ifndef OPENSSL_NO_ENGINE
    if (e == NULL && pkey != NULL)
        e = pkey->pmeth_engine != NULL ? pkey->pmeth_engine : pkey->engine;
    /* Try to find an ENGINE which implements this method */
    if (e) {
        if (!ENGINE_init(e)) {
            EVPerr(EVP_F_INT_CTX_NEW, ERR_R_ENGINE_LIB);
            return NULL;
        }
    } else {
        e = ENGINE_get_pkey_meth_engine(id);
    }

    /*
     * If an ENGINE handled this method look it up. Otherwise use internal
     * tables.
     */
    if (e)
        pmeth = ENGINE_get_pkey_meth(e, id);
    else
#endif
        pmeth = EVP_PKEY_meth_find(id);

    if (pmeth == NULL) {
#ifndef OPENSSL_NO_ENGINE
        ENGINE_finish(e);
#endif
        EVPerr(EVP_F_INT_CTX_NEW, EVP_R_UNSUPPORTED_ALGORITHM);
        return NULL;
    }
    /* END legacy */

 common:
    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
#ifndef OPENSSL_NO_ENGINE
        ENGINE_finish(e);
#endif
        EVPerr(EVP_F_INT_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->libctx = libctx;
    ret->algorithm = name;
    ret->propquery = propquery;
    ret->engine = e;
    ret->pmeth = pmeth;
    ret->operation = EVP_PKEY_OP_UNDEFINED;
    ret->pkey = pkey;
    if (pkey != NULL)
        EVP_PKEY_up_ref(pkey);

    if (pmeth != NULL && pmeth->init != NULL) {
        if (pmeth->init(ret) <= 0) {
            ret->pmeth = NULL;
            EVP_PKEY_CTX_free(ret);
            return NULL;
        }
    }

    return ret;
}

void evp_pkey_ctx_free_old_ops(EVP_PKEY_CTX *ctx)
{
    if (EVP_PKEY_CTX_IS_DERIVE_OP(ctx)) {
        if (ctx->op.kex.exchprovctx != NULL && ctx->op.kex.exchange != NULL)
            ctx->op.kex.exchange->freectx(ctx->op.kex.exchprovctx);
        EVP_KEYEXCH_free(ctx->op.kex.exchange);
        ctx->op.kex.exchprovctx = NULL;
        ctx->op.kex.exchange = NULL;
    } else if (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)) {
        if (ctx->op.sig.sigprovctx != NULL && ctx->op.sig.signature != NULL)
            ctx->op.sig.signature->freectx(ctx->op.sig.sigprovctx);
        EVP_SIGNATURE_free(ctx->op.sig.signature);
        ctx->op.sig.sigprovctx = NULL;
        ctx->op.sig.signature = NULL;
    }
}

EVP_PKEY_METHOD *EVP_PKEY_meth_new(int id, int flags)
{
    EVP_PKEY_METHOD *pmeth;

    pmeth = OPENSSL_zalloc(sizeof(*pmeth));
    if (pmeth == NULL) {
        EVPerr(EVP_F_EVP_PKEY_METH_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    pmeth->pkey_id = id;
    pmeth->flags = flags | EVP_PKEY_FLAG_DYNAMIC;
    return pmeth;
}

void EVP_PKEY_meth_get0_info(int *ppkey_id, int *pflags,
                             const EVP_PKEY_METHOD *meth)
{
    if (ppkey_id)
        *ppkey_id = meth->pkey_id;
    if (pflags)
        *pflags = meth->flags;
}

void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst, const EVP_PKEY_METHOD *src)
{

    dst->init = src->init;
    dst->copy = src->copy;
    dst->cleanup = src->cleanup;

    dst->paramgen_init = src->paramgen_init;
    dst->paramgen = src->paramgen;

    dst->keygen_init = src->keygen_init;
    dst->keygen = src->keygen;

    dst->sign_init = src->sign_init;
    dst->sign = src->sign;

    dst->verify_init = src->verify_init;
    dst->verify = src->verify;

    dst->verify_recover_init = src->verify_recover_init;
    dst->verify_recover = src->verify_recover;

    dst->signctx_init = src->signctx_init;
    dst->signctx = src->signctx;

    dst->verifyctx_init = src->verifyctx_init;
    dst->verifyctx = src->verifyctx;

    dst->encrypt_init = src->encrypt_init;
    dst->encrypt = src->encrypt;

    dst->decrypt_init = src->decrypt_init;
    dst->decrypt = src->decrypt;

    dst->derive_init = src->derive_init;
    dst->derive = src->derive;

    dst->ctrl = src->ctrl;
    dst->ctrl_str = src->ctrl_str;

    dst->check = src->check;
}

void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth)
{
    if (pmeth && (pmeth->flags & EVP_PKEY_FLAG_DYNAMIC))
        OPENSSL_free(pmeth);
}

EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e)
{
    return int_ctx_new(NULL, pkey, e, NULL, NULL, -1);
}

EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e)
{
    return int_ctx_new(NULL, NULL, e, NULL, NULL, id);
}

EVP_PKEY_CTX *EVP_PKEY_CTX_new_provided(OPENSSL_CTX *libctx,
                                        const char *name,
                                        const char *propquery)
{
    return int_ctx_new(libctx, NULL, NULL, name, propquery, -1);
}

EVP_PKEY_CTX *EVP_PKEY_CTX_dup(const EVP_PKEY_CTX *pctx)
{
    EVP_PKEY_CTX *rctx;

    if (((pctx->pmeth == NULL) || (pctx->pmeth->copy == NULL))
            && ((EVP_PKEY_CTX_IS_DERIVE_OP(pctx)
                 && pctx->op.kex.exchprovctx == NULL)
                || (EVP_PKEY_CTX_IS_SIGNATURE_OP(pctx)
                    && pctx->op.sig.sigprovctx == NULL)))
        return NULL;
#ifndef OPENSSL_NO_ENGINE
    /* Make sure it's safe to copy a pkey context using an ENGINE */
    if (pctx->engine && !ENGINE_init(pctx->engine)) {
        EVPerr(EVP_F_EVP_PKEY_CTX_DUP, ERR_R_ENGINE_LIB);
        return 0;
    }
#endif
    rctx = OPENSSL_zalloc(sizeof(*rctx));
    if (rctx == NULL) {
        EVPerr(EVP_F_EVP_PKEY_CTX_DUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (pctx->pkey != NULL)
        EVP_PKEY_up_ref(pctx->pkey);
    rctx->pkey = pctx->pkey;
    rctx->operation = pctx->operation;
    rctx->libctx = pctx->libctx;
    rctx->algorithm = pctx->algorithm;
    rctx->propquery = pctx->propquery;

    if (EVP_PKEY_CTX_IS_DERIVE_OP(pctx)) {
        if (pctx->op.kex.exchange != NULL) {
            rctx->op.kex.exchange = pctx->op.kex.exchange;
            if (!EVP_KEYEXCH_up_ref(rctx->op.kex.exchange)) {
                OPENSSL_free(rctx);
                return NULL;
            }
        }
        if (pctx->op.kex.exchprovctx != NULL) {
            if (!ossl_assert(pctx->op.kex.exchange != NULL))
                return NULL;
            rctx->op.kex.exchprovctx
                = pctx->op.kex.exchange->dupctx(pctx->op.kex.exchprovctx);
            if (rctx->op.kex.exchprovctx == NULL) {
                EVP_KEYEXCH_free(rctx->op.kex.exchange);
                OPENSSL_free(rctx);
                return NULL;
            }
            return rctx;
        }
    } else if (EVP_PKEY_CTX_IS_SIGNATURE_OP(pctx)) {
        if (pctx->op.sig.signature != NULL) {
            rctx->op.sig.signature = pctx->op.sig.signature;
            if (!EVP_SIGNATURE_up_ref(rctx->op.sig.signature)) {
                OPENSSL_free(rctx);
                return NULL;
            }
        }
        if (pctx->op.sig.sigprovctx != NULL) {
            if (!ossl_assert(pctx->op.sig.signature != NULL))
                return NULL;
            rctx->op.sig.sigprovctx
                = pctx->op.sig.signature->dupctx(pctx->op.sig.sigprovctx);
            if (rctx->op.sig.sigprovctx == NULL) {
                EVP_SIGNATURE_free(rctx->op.sig.signature);
                OPENSSL_free(rctx);
                return NULL;
            }
            return rctx;
        }
    }

    rctx->pmeth = pctx->pmeth;
#ifndef OPENSSL_NO_ENGINE
    rctx->engine = pctx->engine;
#endif

    if (pctx->peerkey)
        EVP_PKEY_up_ref(pctx->peerkey);
    rctx->peerkey = pctx->peerkey;

    if (pctx->pmeth->copy(rctx, pctx) > 0)
        return rctx;

    rctx->pmeth = NULL;
    EVP_PKEY_CTX_free(rctx);
    return NULL;

}

int EVP_PKEY_meth_add0(const EVP_PKEY_METHOD *pmeth)
{
    if (app_pkey_methods == NULL) {
        app_pkey_methods = sk_EVP_PKEY_METHOD_new(pmeth_cmp);
        if (app_pkey_methods == NULL){
            EVPerr(EVP_F_EVP_PKEY_METH_ADD0, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    if (!sk_EVP_PKEY_METHOD_push(app_pkey_methods, pmeth)) {
        EVPerr(EVP_F_EVP_PKEY_METH_ADD0, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    sk_EVP_PKEY_METHOD_sort(app_pkey_methods);
    return 1;
}

void evp_app_cleanup_int(void)
{
    if (app_pkey_methods != NULL)
        sk_EVP_PKEY_METHOD_pop_free(app_pkey_methods, EVP_PKEY_meth_free);
}

int EVP_PKEY_meth_remove(const EVP_PKEY_METHOD *pmeth)
{
    const EVP_PKEY_METHOD *ret;

    ret = sk_EVP_PKEY_METHOD_delete_ptr(app_pkey_methods, pmeth);

    return ret == NULL ? 0 : 1;
}

size_t EVP_PKEY_meth_get_count(void)
{
    size_t rv = OSSL_NELEM(standard_methods);

    if (app_pkey_methods)
        rv += sk_EVP_PKEY_METHOD_num(app_pkey_methods);
    return rv;
}

const EVP_PKEY_METHOD *EVP_PKEY_meth_get0(size_t idx)
{
    if (idx < OSSL_NELEM(standard_methods))
        return (standard_methods[idx])();
    if (app_pkey_methods == NULL)
        return NULL;
    idx -= OSSL_NELEM(standard_methods);
    if (idx >= (size_t)sk_EVP_PKEY_METHOD_num(app_pkey_methods))
        return NULL;
    return sk_EVP_PKEY_METHOD_value(app_pkey_methods, idx);
}

void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx)
{
    if (ctx == NULL)
        return;
    if (ctx->pmeth && ctx->pmeth->cleanup)
        ctx->pmeth->cleanup(ctx);

    evp_pkey_ctx_free_old_ops(ctx);
    EVP_KEYMGMT_free(ctx->keymgmt);

    EVP_PKEY_free(ctx->pkey);
    EVP_PKEY_free(ctx->peerkey);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(ctx->engine);
#endif
    OPENSSL_free(ctx);
}

int EVP_PKEY_CTX_get_params(EVP_PKEY_CTX *ctx, OSSL_PARAM *params)
{
    if (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)
            && ctx->op.sig.sigprovctx != NULL
            && ctx->op.sig.signature != NULL
            && ctx->op.sig.signature->get_ctx_params != NULL)
        return ctx->op.sig.signature->get_ctx_params(ctx->op.sig.sigprovctx,
                                                     params);
    return 0;
}

const OSSL_PARAM *EVP_PKEY_CTX_gettable_params(EVP_PKEY_CTX *ctx)
{
    if (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)
            && ctx->op.sig.signature != NULL
            && ctx->op.sig.signature->gettable_ctx_params != NULL)
        return ctx->op.sig.signature->gettable_ctx_params();

    return NULL;
}

int EVP_PKEY_CTX_set_params(EVP_PKEY_CTX *ctx, OSSL_PARAM *params)
{
    if (EVP_PKEY_CTX_IS_DERIVE_OP(ctx)
            && ctx->op.kex.exchprovctx != NULL
            && ctx->op.kex.exchange != NULL
            && ctx->op.kex.exchange->set_ctx_params != NULL)
        return ctx->op.kex.exchange->set_ctx_params(ctx->op.kex.exchprovctx,
                                                    params);
    if (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)
            && ctx->op.sig.sigprovctx != NULL
            && ctx->op.sig.signature != NULL
            && ctx->op.sig.signature->set_ctx_params != NULL)
        return ctx->op.sig.signature->set_ctx_params(ctx->op.sig.sigprovctx,
                                                     params);
    return 0;
}

const OSSL_PARAM *EVP_PKEY_CTX_settable_params(EVP_PKEY_CTX *ctx)
{
    if (EVP_PKEY_CTX_IS_DERIVE_OP(ctx)
            && ctx->op.kex.exchange != NULL
            && ctx->op.kex.exchange->settable_ctx_params != NULL)
        return ctx->op.kex.exchange->settable_ctx_params();
    if (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)
            && ctx->op.sig.signature != NULL
            && ctx->op.sig.signature->settable_ctx_params != NULL)
        return ctx->op.sig.signature->settable_ctx_params();

    return NULL;
}

#ifndef OPENSSL_NO_DH
int EVP_PKEY_CTX_set_dh_pad(EVP_PKEY_CTX *ctx, int pad)
{
    OSSL_PARAM dh_pad_params[2];
    unsigned int upad = pad;

    /* We use EVP_PKEY_CTX_ctrl return values */
    if (ctx == NULL || !EVP_PKEY_CTX_IS_DERIVE_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_DH_PAD, pad, NULL);

    dh_pad_params[0] = OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, &upad);
    dh_pad_params[1] = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, dh_pad_params);
}
#endif

int EVP_PKEY_CTX_get_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD **md)
{
    OSSL_PARAM sig_md_params[3], *p = sig_md_params;
    /* 80 should be big enough */
    char name[80] = "";
    const EVP_MD *tmp;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.sig.sigprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_TYPE_SIG,
                                 EVP_PKEY_CTRL_GET_MD, 0, (void *)(md));

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                            name,
                                            sizeof(name));
    *p++ = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_CTX_get_params(ctx, sig_md_params))
        return 0;

    tmp = evp_get_digestbyname_ex(ctx->libctx, name);
    if (tmp == NULL)
        return 0;

    *md = tmp;

    return 1;
}

int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    OSSL_PARAM sig_md_params[3], *p = sig_md_params;
    size_t mdsize;
    const char *name;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.sig.sigprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_TYPE_SIG,
                                 EVP_PKEY_CTRL_MD, 0, (void *)(md));

    if (md == NULL) {
        name = "";
        mdsize = 0;
    } else {
        mdsize = EVP_MD_size(md);
        name = EVP_MD_name(md);
    }

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                            /*
                                             * Cast away the const. This is read
                                             * only so should be safe
                                             */
                                            (char *)name,
                                            strlen(name) + 1);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE,
                                       &mdsize);
    *p++ = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, sig_md_params);
}

static int legacy_ctrl_to_param(EVP_PKEY_CTX *ctx, int keytype, int optype,
                                int cmd, int p1, void *p2)
{
    switch (cmd) {
#ifndef OPENSSL_NO_DH
    case EVP_PKEY_CTRL_DH_PAD:
        return EVP_PKEY_CTX_set_dh_pad(ctx, p1);
#endif
    case EVP_PKEY_CTRL_MD:
        return EVP_PKEY_CTX_set_signature_md(ctx, p2);
    case EVP_PKEY_CTRL_GET_MD:
        return EVP_PKEY_CTX_get_signature_md(ctx, p2);
    }
    return 0;
}

int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2)
{
    int ret;

    if (ctx == NULL) {
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }

    if ((EVP_PKEY_CTX_IS_DERIVE_OP(ctx) && ctx->op.kex.exchprovctx != NULL)
            || (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)
                && ctx->op.sig.sigprovctx != NULL))
        return legacy_ctrl_to_param(ctx, keytype, optype, cmd, p1, p2);

    if (ctx->pmeth == NULL || ctx->pmeth->ctrl == NULL) {
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }
    if ((keytype != -1) && (ctx->pmeth->pkey_id != keytype))
        return -1;

    /* Skip the operation checks since this is called in a very early stage */
    if (ctx->pmeth->digest_custom != NULL)
        goto doit;

    if (ctx->operation == EVP_PKEY_OP_UNDEFINED) {
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_NO_OPERATION_SET);
        return -1;
    }

    if ((optype != -1) && !(ctx->operation & optype)) {
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_INVALID_OPERATION);
        return -1;
    }

 doit:
    ret = ctx->pmeth->ctrl(ctx, cmd, p1, p2);

    if (ret == -2)
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);

    return ret;
}

int EVP_PKEY_CTX_ctrl_uint64(EVP_PKEY_CTX *ctx, int keytype, int optype,
                             int cmd, uint64_t value)
{
    return EVP_PKEY_CTX_ctrl(ctx, keytype, optype, cmd, 0, &value);
}

static int legacy_ctrl_str_to_param(EVP_PKEY_CTX *ctx, const char *name,
                                    const char *value)
{
#ifndef OPENSSL_NO_DH
    if (strcmp(name, "dh_pad") == 0) {
        int pad;

        pad = atoi(value);
        return EVP_PKEY_CTX_set_dh_pad(ctx, pad);
    }
#endif
    if (strcmp(name, "digest") == 0) {
        int ret;
        EVP_MD *md;

        if (!EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx) || ctx->op.sig.signature == NULL)
            return 0;
        md = EVP_MD_fetch(ossl_provider_library_context(ctx->op.sig.signature->prov),
                          value, NULL);
        if (md == NULL)
            return 0;
        ret = EVP_PKEY_CTX_set_signature_md(ctx, md);
        EVP_MD_meth_free(md);
        return ret;
    }

    return 0;
}

int EVP_PKEY_CTX_ctrl_str(EVP_PKEY_CTX *ctx,
                          const char *name, const char *value)
{
    if (ctx == NULL) {
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL_STR, EVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }

    if ((EVP_PKEY_CTX_IS_DERIVE_OP(ctx) && ctx->op.kex.exchprovctx != NULL)
            || (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)
                && ctx->op.sig.sigprovctx != NULL))
        return legacy_ctrl_str_to_param(ctx, name, value);

    if (!ctx || !ctx->pmeth || !ctx->pmeth->ctrl_str) {
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL_STR, EVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }
    if (strcmp(name, "digest") == 0)
        return EVP_PKEY_CTX_md(ctx, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_MD,
                               value);
    return ctx->pmeth->ctrl_str(ctx, name, value);
}

/* Utility functions to send a string of hex string to a ctrl */

int EVP_PKEY_CTX_str2ctrl(EVP_PKEY_CTX *ctx, int cmd, const char *str)
{
    size_t len;

    len = strlen(str);
    if (len > INT_MAX)
        return -1;
    return ctx->pmeth->ctrl(ctx, cmd, len, (void *)str);
}

int EVP_PKEY_CTX_hex2ctrl(EVP_PKEY_CTX *ctx, int cmd, const char *hex)
{
    unsigned char *bin;
    long binlen;
    int rv = -1;

    bin = OPENSSL_hexstr2buf(hex, &binlen);
    if (bin == NULL)
        return 0;
    if (binlen <= INT_MAX)
        rv = ctx->pmeth->ctrl(ctx, cmd, binlen, bin);
    OPENSSL_free(bin);
    return rv;
}

/* Pass a message digest to a ctrl */
int EVP_PKEY_CTX_md(EVP_PKEY_CTX *ctx, int optype, int cmd, const char *md)
{
    const EVP_MD *m;

    if (md == NULL || (m = EVP_get_digestbyname(md)) == NULL) {
        EVPerr(EVP_F_EVP_PKEY_CTX_MD, EVP_R_INVALID_DIGEST);
        return 0;
    }
    return EVP_PKEY_CTX_ctrl(ctx, -1, optype, cmd, 0, (void *)m);
}

int EVP_PKEY_CTX_get_operation(EVP_PKEY_CTX *ctx)
{
    return ctx->operation;
}

void EVP_PKEY_CTX_set0_keygen_info(EVP_PKEY_CTX *ctx, int *dat, int datlen)
{
    ctx->keygen_info = dat;
    ctx->keygen_info_count = datlen;
}

void EVP_PKEY_CTX_set_data(EVP_PKEY_CTX *ctx, void *data)
{
    ctx->data = data;
}

void *EVP_PKEY_CTX_get_data(const EVP_PKEY_CTX *ctx)
{
    return ctx->data;
}

EVP_PKEY *EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX *ctx)
{
    return ctx->pkey;
}

EVP_PKEY *EVP_PKEY_CTX_get0_peerkey(EVP_PKEY_CTX *ctx)
{
    return ctx->peerkey;
}

void EVP_PKEY_CTX_set_app_data(EVP_PKEY_CTX *ctx, void *data)
{
    ctx->app_data = data;
}

void *EVP_PKEY_CTX_get_app_data(EVP_PKEY_CTX *ctx)
{
    return ctx->app_data;
}

void EVP_PKEY_meth_set_init(EVP_PKEY_METHOD *pmeth,
                            int (*init) (EVP_PKEY_CTX *ctx))
{
    pmeth->init = init;
}

void EVP_PKEY_meth_set_copy(EVP_PKEY_METHOD *pmeth,
                            int (*copy) (EVP_PKEY_CTX *dst,
                                         const EVP_PKEY_CTX *src))
{
    pmeth->copy = copy;
}

void EVP_PKEY_meth_set_cleanup(EVP_PKEY_METHOD *pmeth,
                               void (*cleanup) (EVP_PKEY_CTX *ctx))
{
    pmeth->cleanup = cleanup;
}

void EVP_PKEY_meth_set_paramgen(EVP_PKEY_METHOD *pmeth,
                                int (*paramgen_init) (EVP_PKEY_CTX *ctx),
                                int (*paramgen) (EVP_PKEY_CTX *ctx,
                                                 EVP_PKEY *pkey))
{
    pmeth->paramgen_init = paramgen_init;
    pmeth->paramgen = paramgen;
}

void EVP_PKEY_meth_set_keygen(EVP_PKEY_METHOD *pmeth,
                              int (*keygen_init) (EVP_PKEY_CTX *ctx),
                              int (*keygen) (EVP_PKEY_CTX *ctx,
                                             EVP_PKEY *pkey))
{
    pmeth->keygen_init = keygen_init;
    pmeth->keygen = keygen;
}

void EVP_PKEY_meth_set_sign(EVP_PKEY_METHOD *pmeth,
                            int (*sign_init) (EVP_PKEY_CTX *ctx),
                            int (*sign) (EVP_PKEY_CTX *ctx,
                                         unsigned char *sig, size_t *siglen,
                                         const unsigned char *tbs,
                                         size_t tbslen))
{
    pmeth->sign_init = sign_init;
    pmeth->sign = sign;
}

void EVP_PKEY_meth_set_verify(EVP_PKEY_METHOD *pmeth,
                              int (*verify_init) (EVP_PKEY_CTX *ctx),
                              int (*verify) (EVP_PKEY_CTX *ctx,
                                             const unsigned char *sig,
                                             size_t siglen,
                                             const unsigned char *tbs,
                                             size_t tbslen))
{
    pmeth->verify_init = verify_init;
    pmeth->verify = verify;
}

void EVP_PKEY_meth_set_verify_recover(EVP_PKEY_METHOD *pmeth,
                                      int (*verify_recover_init) (EVP_PKEY_CTX
                                                                  *ctx),
                                      int (*verify_recover) (EVP_PKEY_CTX
                                                             *ctx,
                                                             unsigned char
                                                             *sig,
                                                             size_t *siglen,
                                                             const unsigned
                                                             char *tbs,
                                                             size_t tbslen))
{
    pmeth->verify_recover_init = verify_recover_init;
    pmeth->verify_recover = verify_recover;
}

void EVP_PKEY_meth_set_signctx(EVP_PKEY_METHOD *pmeth,
                               int (*signctx_init) (EVP_PKEY_CTX *ctx,
                                                    EVP_MD_CTX *mctx),
                               int (*signctx) (EVP_PKEY_CTX *ctx,
                                               unsigned char *sig,
                                               size_t *siglen,
                                               EVP_MD_CTX *mctx))
{
    pmeth->signctx_init = signctx_init;
    pmeth->signctx = signctx;
}

void EVP_PKEY_meth_set_verifyctx(EVP_PKEY_METHOD *pmeth,
                                 int (*verifyctx_init) (EVP_PKEY_CTX *ctx,
                                                        EVP_MD_CTX *mctx),
                                 int (*verifyctx) (EVP_PKEY_CTX *ctx,
                                                   const unsigned char *sig,
                                                   int siglen,
                                                   EVP_MD_CTX *mctx))
{
    pmeth->verifyctx_init = verifyctx_init;
    pmeth->verifyctx = verifyctx;
}

void EVP_PKEY_meth_set_encrypt(EVP_PKEY_METHOD *pmeth,
                               int (*encrypt_init) (EVP_PKEY_CTX *ctx),
                               int (*encryptfn) (EVP_PKEY_CTX *ctx,
                                                 unsigned char *out,
                                                 size_t *outlen,
                                                 const unsigned char *in,
                                                 size_t inlen))
{
    pmeth->encrypt_init = encrypt_init;
    pmeth->encrypt = encryptfn;
}

void EVP_PKEY_meth_set_decrypt(EVP_PKEY_METHOD *pmeth,
                               int (*decrypt_init) (EVP_PKEY_CTX *ctx),
                               int (*decrypt) (EVP_PKEY_CTX *ctx,
                                               unsigned char *out,
                                               size_t *outlen,
                                               const unsigned char *in,
                                               size_t inlen))
{
    pmeth->decrypt_init = decrypt_init;
    pmeth->decrypt = decrypt;
}

void EVP_PKEY_meth_set_derive(EVP_PKEY_METHOD *pmeth,
                              int (*derive_init) (EVP_PKEY_CTX *ctx),
                              int (*derive) (EVP_PKEY_CTX *ctx,
                                             unsigned char *key,
                                             size_t *keylen))
{
    pmeth->derive_init = derive_init;
    pmeth->derive = derive;
}

void EVP_PKEY_meth_set_ctrl(EVP_PKEY_METHOD *pmeth,
                            int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1,
                                         void *p2),
                            int (*ctrl_str) (EVP_PKEY_CTX *ctx,
                                             const char *type,
                                             const char *value))
{
    pmeth->ctrl = ctrl;
    pmeth->ctrl_str = ctrl_str;
}

void EVP_PKEY_meth_set_check(EVP_PKEY_METHOD *pmeth,
                             int (*check) (EVP_PKEY *pkey))
{
    pmeth->check = check;
}

void EVP_PKEY_meth_set_public_check(EVP_PKEY_METHOD *pmeth,
                                    int (*check) (EVP_PKEY *pkey))
{
    pmeth->public_check = check;
}

void EVP_PKEY_meth_set_param_check(EVP_PKEY_METHOD *pmeth,
                                   int (*check) (EVP_PKEY *pkey))
{
    pmeth->param_check = check;
}

void EVP_PKEY_meth_set_digest_custom(EVP_PKEY_METHOD *pmeth,
                                     int (*digest_custom) (EVP_PKEY_CTX *ctx,
                                                           EVP_MD_CTX *mctx))
{
    pmeth->digest_custom = digest_custom;
}

void EVP_PKEY_meth_get_init(const EVP_PKEY_METHOD *pmeth,
                            int (**pinit) (EVP_PKEY_CTX *ctx))
{
    *pinit = pmeth->init;
}

void EVP_PKEY_meth_get_copy(const EVP_PKEY_METHOD *pmeth,
                            int (**pcopy) (EVP_PKEY_CTX *dst,
                                           const EVP_PKEY_CTX *src))
{
    *pcopy = pmeth->copy;
}

void EVP_PKEY_meth_get_cleanup(const EVP_PKEY_METHOD *pmeth,
                               void (**pcleanup) (EVP_PKEY_CTX *ctx))
{
    *pcleanup = pmeth->cleanup;
}

void EVP_PKEY_meth_get_paramgen(const EVP_PKEY_METHOD *pmeth,
                                int (**pparamgen_init) (EVP_PKEY_CTX *ctx),
                                int (**pparamgen) (EVP_PKEY_CTX *ctx,
                                                   EVP_PKEY *pkey))
{
    if (pparamgen_init)
        *pparamgen_init = pmeth->paramgen_init;
    if (pparamgen)
        *pparamgen = pmeth->paramgen;
}

void EVP_PKEY_meth_get_keygen(const EVP_PKEY_METHOD *pmeth,
                              int (**pkeygen_init) (EVP_PKEY_CTX *ctx),
                              int (**pkeygen) (EVP_PKEY_CTX *ctx,
                                               EVP_PKEY *pkey))
{
    if (pkeygen_init)
        *pkeygen_init = pmeth->keygen_init;
    if (pkeygen)
        *pkeygen = pmeth->keygen;
}

void EVP_PKEY_meth_get_sign(const EVP_PKEY_METHOD *pmeth,
                            int (**psign_init) (EVP_PKEY_CTX *ctx),
                            int (**psign) (EVP_PKEY_CTX *ctx,
                                           unsigned char *sig, size_t *siglen,
                                           const unsigned char *tbs,
                                           size_t tbslen))
{
    if (psign_init)
        *psign_init = pmeth->sign_init;
    if (psign)
        *psign = pmeth->sign;
}

void EVP_PKEY_meth_get_verify(const EVP_PKEY_METHOD *pmeth,
                              int (**pverify_init) (EVP_PKEY_CTX *ctx),
                              int (**pverify) (EVP_PKEY_CTX *ctx,
                                               const unsigned char *sig,
                                               size_t siglen,
                                               const unsigned char *tbs,
                                               size_t tbslen))
{
    if (pverify_init)
        *pverify_init = pmeth->verify_init;
    if (pverify)
        *pverify = pmeth->verify;
}

void EVP_PKEY_meth_get_verify_recover(const EVP_PKEY_METHOD *pmeth,
                                      int (**pverify_recover_init) (EVP_PKEY_CTX
                                                                    *ctx),
                                      int (**pverify_recover) (EVP_PKEY_CTX
                                                               *ctx,
                                                               unsigned char
                                                               *sig,
                                                               size_t *siglen,
                                                               const unsigned
                                                               char *tbs,
                                                               size_t tbslen))
{
    if (pverify_recover_init)
        *pverify_recover_init = pmeth->verify_recover_init;
    if (pverify_recover)
        *pverify_recover = pmeth->verify_recover;
}

void EVP_PKEY_meth_get_signctx(const EVP_PKEY_METHOD *pmeth,
                               int (**psignctx_init) (EVP_PKEY_CTX *ctx,
                                                      EVP_MD_CTX *mctx),
                               int (**psignctx) (EVP_PKEY_CTX *ctx,
                                                 unsigned char *sig,
                                                 size_t *siglen,
                                                 EVP_MD_CTX *mctx))
{
    if (psignctx_init)
        *psignctx_init = pmeth->signctx_init;
    if (psignctx)
        *psignctx = pmeth->signctx;
}

void EVP_PKEY_meth_get_verifyctx(const EVP_PKEY_METHOD *pmeth,
                                 int (**pverifyctx_init) (EVP_PKEY_CTX *ctx,
                                                          EVP_MD_CTX *mctx),
                                 int (**pverifyctx) (EVP_PKEY_CTX *ctx,
                                                     const unsigned char *sig,
                                                     int siglen,
                                                     EVP_MD_CTX *mctx))
{
    if (pverifyctx_init)
        *pverifyctx_init = pmeth->verifyctx_init;
    if (pverifyctx)
        *pverifyctx = pmeth->verifyctx;
}

void EVP_PKEY_meth_get_encrypt(const EVP_PKEY_METHOD *pmeth,
                               int (**pencrypt_init) (EVP_PKEY_CTX *ctx),
                               int (**pencryptfn) (EVP_PKEY_CTX *ctx,
                                                   unsigned char *out,
                                                   size_t *outlen,
                                                   const unsigned char *in,
                                                   size_t inlen))
{
    if (pencrypt_init)
        *pencrypt_init = pmeth->encrypt_init;
    if (pencryptfn)
        *pencryptfn = pmeth->encrypt;
}

void EVP_PKEY_meth_get_decrypt(const EVP_PKEY_METHOD *pmeth,
                               int (**pdecrypt_init) (EVP_PKEY_CTX *ctx),
                               int (**pdecrypt) (EVP_PKEY_CTX *ctx,
                                                 unsigned char *out,
                                                 size_t *outlen,
                                                 const unsigned char *in,
                                                 size_t inlen))
{
    if (pdecrypt_init)
        *pdecrypt_init = pmeth->decrypt_init;
    if (pdecrypt)
        *pdecrypt = pmeth->decrypt;
}

void EVP_PKEY_meth_get_derive(const EVP_PKEY_METHOD *pmeth,
                              int (**pderive_init) (EVP_PKEY_CTX *ctx),
                              int (**pderive) (EVP_PKEY_CTX *ctx,
                                               unsigned char *key,
                                               size_t *keylen))
{
    if (pderive_init)
        *pderive_init = pmeth->derive_init;
    if (pderive)
        *pderive = pmeth->derive;
}

void EVP_PKEY_meth_get_ctrl(const EVP_PKEY_METHOD *pmeth,
                            int (**pctrl) (EVP_PKEY_CTX *ctx, int type, int p1,
                                           void *p2),
                            int (**pctrl_str) (EVP_PKEY_CTX *ctx,
                                               const char *type,
                                               const char *value))
{
    if (pctrl)
        *pctrl = pmeth->ctrl;
    if (pctrl_str)
        *pctrl_str = pmeth->ctrl_str;
}

void EVP_PKEY_meth_get_check(const EVP_PKEY_METHOD *pmeth,
                             int (**pcheck) (EVP_PKEY *pkey))
{
    if (pcheck != NULL)
        *pcheck = pmeth->check;
}

void EVP_PKEY_meth_get_public_check(const EVP_PKEY_METHOD *pmeth,
                                    int (**pcheck) (EVP_PKEY *pkey))
{
    if (pcheck != NULL)
        *pcheck = pmeth->public_check;
}

void EVP_PKEY_meth_get_param_check(const EVP_PKEY_METHOD *pmeth,
                                   int (**pcheck) (EVP_PKEY *pkey))
{
    if (pcheck != NULL)
        *pcheck = pmeth->param_check;
}

void EVP_PKEY_meth_get_digest_custom(EVP_PKEY_METHOD *pmeth,
                                     int (**pdigest_custom) (EVP_PKEY_CTX *ctx,
                                                             EVP_MD_CTX *mctx))
{
    if (pdigest_custom != NULL)
        *pdigest_custom = pmeth->digest_custom;
}
