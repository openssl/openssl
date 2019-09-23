/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "internal/refcount.h"
#include "crypto/evp.h"
#include "internal/provider.h"
#include "internal/numbers.h"   /* includes SIZE_MAX */
#include "evp_local.h"

static EVP_KEYEXCH *evp_keyexch_new(OSSL_PROVIDER *prov)
{
    EVP_KEYEXCH *exchange = OPENSSL_zalloc(sizeof(EVP_KEYEXCH));

    exchange->lock = CRYPTO_THREAD_lock_new();
    if (exchange->lock == NULL) {
        OPENSSL_free(exchange);
        return NULL;
    }
    exchange->prov = prov;
    ossl_provider_up_ref(prov);
    exchange->refcnt = 1;

    return exchange;
}

static void *evp_keyexch_from_dispatch(int name_id,
                                       const OSSL_DISPATCH *fns,
                                       OSSL_PROVIDER *prov,
                                       void *vkeymgmt_data)
{
    /*
     * Key exchange cannot work without a key, and key management
     * from the same provider to manage its keys.  We therefore fetch
     * a key management method using the same algorithm and properties
     * and pass that down to evp_generic_fetch to be passed on to our
     * evp_keyexch_from_dispatch, which will attach the key management
     * method to the newly created key exchange method as long as the
     * provider matches.
     */
    struct keymgmt_data_st *keymgmt_data = vkeymgmt_data;
    EVP_KEYMGMT *keymgmt =
        evp_keymgmt_fetch_by_number(keymgmt_data->ctx, name_id,
                                    keymgmt_data->properties);
    EVP_KEYEXCH *exchange = NULL;
    int fncnt = 0, paramfncnt = 0;

    if (keymgmt == NULL || EVP_KEYMGMT_provider(keymgmt) != prov) {
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_KEYMGMT_AVAILABLE);
        goto err;
    }

    if ((exchange = evp_keyexch_new(prov)) == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    exchange->name_id = name_id;
    exchange->keymgmt = keymgmt;
    keymgmt = NULL;              /* avoid double free on failure below */

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_KEYEXCH_NEWCTX:
            if (exchange->newctx != NULL)
                break;
            exchange->newctx = OSSL_get_OP_keyexch_newctx(fns);
            fncnt++;
            break;
        case OSSL_FUNC_KEYEXCH_INIT:
            if (exchange->init != NULL)
                break;
            exchange->init = OSSL_get_OP_keyexch_init(fns);
            fncnt++;
            break;
        case OSSL_FUNC_KEYEXCH_SET_PEER:
            if (exchange->set_peer != NULL)
                break;
            exchange->set_peer = OSSL_get_OP_keyexch_set_peer(fns);
            break;
        case OSSL_FUNC_KEYEXCH_DERIVE:
            if (exchange->derive != NULL)
                break;
            exchange->derive = OSSL_get_OP_keyexch_derive(fns);
            fncnt++;
            break;
        case OSSL_FUNC_KEYEXCH_FREECTX:
            if (exchange->freectx != NULL)
                break;
            exchange->freectx = OSSL_get_OP_keyexch_freectx(fns);
            fncnt++;
            break;
        case OSSL_FUNC_KEYEXCH_DUPCTX:
            if (exchange->dupctx != NULL)
                break;
            exchange->dupctx = OSSL_get_OP_keyexch_dupctx(fns);
            break;
        case OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS:
            if (exchange->set_ctx_params != NULL)
                break;
            exchange->set_ctx_params = OSSL_get_OP_keyexch_set_ctx_params(fns);
            paramfncnt++;
            break;
        case OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS:
            if (exchange->settable_ctx_params != NULL)
                break;
            exchange->settable_ctx_params
                = OSSL_get_OP_keyexch_settable_ctx_params(fns);
            paramfncnt++;
            break;
        }
    }
    if (fncnt != 4 || (paramfncnt != 0 && paramfncnt != 2)) {
        /*
         * In order to be a consistent set of functions we must have at least
         * a complete set of "exchange" functions: init, derive, newctx,
         * and freectx. The set_ctx_params and settable_ctx_params functions are
         * optional, but if one of them is present then the other one must also
         * be present. The dupctx and set_peer functions are optional.
         */
        EVPerr(EVP_F_EVP_KEYEXCH_FROM_DISPATCH,
               EVP_R_INVALID_PROVIDER_FUNCTIONS);
        goto err;
    }

    return exchange;

 err:
    EVP_KEYEXCH_free(exchange);
    EVP_KEYMGMT_free(keymgmt);
    return NULL;
}

void EVP_KEYEXCH_free(EVP_KEYEXCH *exchange)
{
    if (exchange != NULL) {
        int i;

        CRYPTO_DOWN_REF(&exchange->refcnt, &i, exchange->lock);
        if (i > 0)
            return;
        EVP_KEYMGMT_free(exchange->keymgmt);
        ossl_provider_free(exchange->prov);
        CRYPTO_THREAD_lock_free(exchange->lock);
        OPENSSL_free(exchange);
    }
}

int EVP_KEYEXCH_up_ref(EVP_KEYEXCH *exchange)
{
    int ref = 0;

    CRYPTO_UP_REF(&exchange->refcnt, &ref, exchange->lock);
    return 1;
}

OSSL_PROVIDER *EVP_KEYEXCH_provider(const EVP_KEYEXCH *exchange)
{
    return exchange->prov;
}

EVP_KEYEXCH *EVP_KEYEXCH_fetch(OPENSSL_CTX *ctx, const char *algorithm,
                               const char *properties)
{
    EVP_KEYEXCH *keyexch = NULL;
    struct keymgmt_data_st keymgmt_data;

    keymgmt_data.ctx = ctx;
    keymgmt_data.properties = properties;
    keyexch = evp_generic_fetch(ctx, OSSL_OP_KEYEXCH, algorithm, properties,
                                evp_keyexch_from_dispatch, &keymgmt_data,
                                (int (*)(void *))EVP_KEYEXCH_up_ref,
                                (void (*)(void *))EVP_KEYEXCH_free);

    return keyexch;
}

int EVP_PKEY_derive_init_ex(EVP_PKEY_CTX *ctx, EVP_KEYEXCH *exchange)
{
    int ret;
    void *provkey = NULL;

    evp_pkey_ctx_free_old_ops(ctx);
    ctx->operation = EVP_PKEY_OP_DERIVE;

    if (ctx->engine != NULL)
        goto legacy;

    if (exchange != NULL) {
        if (!EVP_KEYEXCH_up_ref(exchange))
            goto err;
    } else {
        int nid = ctx->pkey != NULL ? ctx->pkey->type : ctx->pmeth->pkey_id;

        /*
         * TODO(3.0): Check for legacy handling. Remove this once all all
         * algorithms are moved to providers.
         */
        if (ctx->pkey != NULL) {
            switch (ctx->pkey->type) {
            case EVP_PKEY_DH:
                break;
            default:
                goto legacy;
            }
            exchange = EVP_KEYEXCH_fetch(NULL, OBJ_nid2sn(nid), NULL);
        } else {
            goto legacy;
        }

        if (exchange == NULL) {
            EVPerr(EVP_F_EVP_PKEY_DERIVE_INIT_EX, EVP_R_INITIALIZATION_ERROR);
            goto err;
        }
    }

    ctx->op.kex.exchange = exchange;
    if (ctx->pkey != NULL) {
        provkey = evp_keymgmt_export_to_provider(ctx->pkey, exchange->keymgmt);
        if (provkey == NULL) {
            EVPerr(EVP_F_EVP_PKEY_DERIVE_INIT_EX, EVP_R_INITIALIZATION_ERROR);
            goto err;
        }
    }
    ctx->op.kex.exchprovctx = exchange->newctx(ossl_provider_ctx(exchange->prov));
    if (ctx->op.kex.exchprovctx == NULL) {
        /* The provider key can stay in the cache */
        EVPerr(EVP_F_EVP_PKEY_DERIVE_INIT_EX, EVP_R_INITIALIZATION_ERROR);
        goto err;
    }
    ret = exchange->init(ctx->op.kex.exchprovctx, provkey);

    return ret ? 1 : 0;
 err:
    ctx->operation = EVP_PKEY_OP_UNDEFINED;
    return 0;

 legacy:
    if (ctx == NULL || ctx->pmeth == NULL || ctx->pmeth->derive == NULL) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_INIT_EX,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    if (ctx->pmeth->derive_init == NULL)
        return 1;
    ret = ctx->pmeth->derive_init(ctx);
    if (ret <= 0)
        ctx->operation = EVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_derive_init_ex(ctx, NULL);
}

int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer)
{
    int ret;
    void *provkey = NULL;

    if (ctx == NULL) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_SET_PEER,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    if (!EVP_PKEY_CTX_IS_DERIVE_OP(ctx) || ctx->op.kex.exchprovctx == NULL)
        goto legacy;

    if (ctx->op.kex.exchange->set_peer == NULL) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_SET_PEER,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    provkey = evp_keymgmt_export_to_provider(peer,
                                             ctx->op.kex.exchange->keymgmt);
    if (provkey == NULL) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_SET_PEER, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    return ctx->op.kex.exchange->set_peer(ctx->op.kex.exchprovctx, provkey);

 legacy:
    if (ctx->pmeth == NULL
        || !(ctx->pmeth->derive != NULL
             || ctx->pmeth->encrypt != NULL
             || ctx->pmeth->decrypt != NULL)
        || ctx->pmeth->ctrl == NULL) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_SET_PEER,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVP_PKEY_OP_DERIVE
        && ctx->operation != EVP_PKEY_OP_ENCRYPT
        && ctx->operation != EVP_PKEY_OP_DECRYPT) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_SET_PEER,
               EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }

    ret = ctx->pmeth->ctrl(ctx, EVP_PKEY_CTRL_PEER_KEY, 0, peer);

    if (ret <= 0)
        return ret;

    if (ret == 2)
        return 1;

    if (ctx->pkey == NULL) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_SET_PEER, EVP_R_NO_KEY_SET);
        return -1;
    }

    if (ctx->pkey->type != peer->type) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_SET_PEER, EVP_R_DIFFERENT_KEY_TYPES);
        return -1;
    }

    /*
     * For clarity.  The error is if parameters in peer are
     * present (!missing) but don't match.  EVP_PKEY_cmp_parameters may return
     * 1 (match), 0 (don't match) and -2 (comparison is not defined).  -1
     * (different key types) is impossible here because it is checked earlier.
     * -2 is OK for us here, as well as 1, so we can check for 0 only.
     */
    if (!EVP_PKEY_missing_parameters(peer) &&
        !EVP_PKEY_cmp_parameters(ctx->pkey, peer)) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE_SET_PEER, EVP_R_DIFFERENT_PARAMETERS);
        return -1;
    }

    EVP_PKEY_free(ctx->peerkey);
    ctx->peerkey = peer;

    ret = ctx->pmeth->ctrl(ctx, EVP_PKEY_CTRL_PEER_KEY, 1, peer);

    if (ret <= 0) {
        ctx->peerkey = NULL;
        return ret;
    }

    EVP_PKEY_up_ref(peer);
    return 1;
}

int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *pkeylen)
{
    int ret;

    if (ctx == NULL) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    if (!EVP_PKEY_CTX_IS_DERIVE_OP(ctx)) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE, EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }

    if (ctx->op.kex.exchprovctx == NULL)
        goto legacy;

    ret = ctx->op.kex.exchange->derive(ctx->op.kex.exchprovctx, key, pkeylen,
                                       SIZE_MAX);

    return ret;
 legacy:
    if (ctx ==  NULL || ctx->pmeth == NULL || ctx->pmeth->derive == NULL) {
        EVPerr(EVP_F_EVP_PKEY_DERIVE,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    M_check_autoarg(ctx, key, pkeylen, EVP_F_EVP_PKEY_DERIVE)
        return ctx->pmeth->derive(ctx, key, pkeylen);
}

int EVP_KEYEXCH_is_a(const EVP_KEYEXCH *keyexch, const char *name)
{
    return evp_is_a(keyexch->prov, keyexch->name_id, name);
}

void EVP_KEYEXCH_do_all_provided(OPENSSL_CTX *libctx,
                                 void (*fn)(EVP_KEYEXCH *keyexch, void *arg),
                                 void *arg)
{
    struct keymgmt_data_st keymgmt_data;

    keymgmt_data.ctx = libctx;
    keymgmt_data.properties = NULL;
    evp_generic_do_all(libctx, OSSL_OP_KEYEXCH,
                       (void (*)(void *, void *))fn, arg,
                       evp_keyexch_from_dispatch, &keymgmt_data,
                       (void (*)(void *))EVP_KEYEXCH_free);
}

void EVP_KEYEXCH_names_do_all(const EVP_KEYEXCH *keyexch,
                              void (*fn)(const char *name, void *data),
                              void *data)
{
    if (keyexch->prov != NULL)
        evp_names_do_all(keyexch->prov, keyexch->name_id, fn, data);
}
