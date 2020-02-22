/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/evp.h>
#include "crypto/bn.h"
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "evp_local.h"

#ifndef FIPS_MODE
int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->paramgen) {
        EVPerr(EVP_F_EVP_PKEY_PARAMGEN_INIT,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVP_PKEY_OP_PARAMGEN;
    if (!ctx->pmeth->paramgen_init)
        return 1;
    ret = ctx->pmeth->paramgen_init(ctx);
    if (ret <= 0)
        ctx->operation = EVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->paramgen) {
        EVPerr(EVP_F_EVP_PKEY_PARAMGEN,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    if (ctx->operation != EVP_PKEY_OP_PARAMGEN) {
        EVPerr(EVP_F_EVP_PKEY_PARAMGEN, EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }

    if (ppkey == NULL)
        return -1;

    if (*ppkey == NULL)
        *ppkey = EVP_PKEY_new();

    if (*ppkey == NULL) {
        EVPerr(EVP_F_EVP_PKEY_PARAMGEN, ERR_R_MALLOC_FAILURE);
        return -1;
    }

    ret = ctx->pmeth->paramgen(ctx, *ppkey);
    if (ret <= 0) {
        EVP_PKEY_free(*ppkey);
        *ppkey = NULL;
    }
    return ret;
}

int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->keygen) {
        EVPerr(EVP_F_EVP_PKEY_KEYGEN_INIT,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    ctx->operation = EVP_PKEY_OP_KEYGEN;
    if (!ctx->pmeth->keygen_init)
        return 1;
    ret = ctx->pmeth->keygen_init(ctx);
    if (ret <= 0)
        ctx->operation = EVP_PKEY_OP_UNDEFINED;
    return ret;
}

int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
    int ret;

    if (!ctx || !ctx->pmeth || !ctx->pmeth->keygen) {
        EVPerr(EVP_F_EVP_PKEY_KEYGEN,
               EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    if (ctx->operation != EVP_PKEY_OP_KEYGEN) {
        EVPerr(EVP_F_EVP_PKEY_KEYGEN, EVP_R_OPERATON_NOT_INITIALIZED);
        return -1;
    }

    if (ppkey == NULL)
        return -1;

    if (*ppkey == NULL)
        *ppkey = EVP_PKEY_new();
    if (*ppkey == NULL)
        return -1;

    ret = ctx->pmeth->keygen(ctx, *ppkey);
    if (ret <= 0) {
        EVP_PKEY_free(*ppkey);
        *ppkey = NULL;
    }
    return ret;
}

void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX *ctx, EVP_PKEY_gen_cb *cb)
{
    ctx->pkey_gencb = cb;
}

EVP_PKEY_gen_cb *EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX *ctx)
{
    return ctx->pkey_gencb;
}

/*
 * "translation callback" to call EVP_PKEY_CTX callbacks using BN_GENCB style
 * callbacks.
 */

static int trans_cb(int a, int b, BN_GENCB *gcb)
{
    EVP_PKEY_CTX *ctx = BN_GENCB_get_arg(gcb);
    ctx->keygen_info[0] = a;
    ctx->keygen_info[1] = b;
    return ctx->pkey_gencb(ctx);
}

void evp_pkey_set_cb_translate(BN_GENCB *cb, EVP_PKEY_CTX *ctx)
{
    BN_GENCB_set(cb, trans_cb, ctx);
}

int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX *ctx, int idx)
{
    if (idx == -1)
        return ctx->keygen_info_count;
    if (idx < 0 || idx > ctx->keygen_info_count)
        return 0;
    return ctx->keygen_info[idx];
}

EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e,
                               const unsigned char *key, int keylen)
{
    EVP_PKEY_CTX *mac_ctx = NULL;
    EVP_PKEY *mac_key = NULL;
    mac_ctx = EVP_PKEY_CTX_new_id(type, e);
    if (!mac_ctx)
        return NULL;
    if (EVP_PKEY_keygen_init(mac_ctx) <= 0)
        goto merr;
    if (EVP_PKEY_CTX_set_mac_key(mac_ctx, key, keylen) <= 0)
        goto merr;
    if (EVP_PKEY_keygen(mac_ctx, &mac_key) <= 0)
        goto merr;
 merr:
    EVP_PKEY_CTX_free(mac_ctx);
    return mac_key;
}

#endif /* FIPS_MODE */

/*- All methods below can also be used in FIPS_MODE */

static int fromdata_init(EVP_PKEY_CTX *ctx, int operation)
{
    if (ctx == NULL || ctx->keytype == NULL)
        goto not_supported;

    evp_pkey_ctx_free_old_ops(ctx);
    ctx->operation = operation;
    if (ctx->keymgmt == NULL)
        ctx->keymgmt = EVP_KEYMGMT_fetch(ctx->libctx, ctx->keytype,
                                         ctx->propquery);
    if (ctx->keymgmt == NULL)
        goto not_supported;

    return 1;

 not_supported:
    ctx->operation = EVP_PKEY_OP_UNDEFINED;
    ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
    return -2;
}

int EVP_PKEY_param_fromdata_init(EVP_PKEY_CTX *ctx)
{
    return fromdata_init(ctx, EVP_PKEY_OP_PARAMFROMDATA);
}

int EVP_PKEY_key_fromdata_init(EVP_PKEY_CTX *ctx)
{
    return fromdata_init(ctx, EVP_PKEY_OP_KEYFROMDATA);
}

int EVP_PKEY_fromdata(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey, OSSL_PARAM params[])
{
    void *keydata = NULL;
    int selection;

    if (ctx == NULL || (ctx->operation & EVP_PKEY_OP_TYPE_FROMDATA) == 0) {
        ERR_raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    if (ppkey == NULL)
        return -1;

    if (*ppkey == NULL)
        *ppkey = EVP_PKEY_new();

    if (*ppkey == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        return -1;
    }

    if (ctx->operation == EVP_PKEY_OP_PARAMFROMDATA)
        selection = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
    else
        selection = OSSL_KEYMGMT_SELECT_KEYPAIR;
    keydata = evp_keymgmt_util_fromdata(*ppkey, ctx->keymgmt, selection,
                                        params);

    if (keydata == NULL)
        return 0;
    /* keydata is cached in *ppkey, so we need not bother with it further */
    return 1;
}

/*
 * TODO(3.0) Re-evaluate the names, it's possible that we find these to be
 * better:
 *
 * EVP_PKEY_param_settable()
 * EVP_PKEY_param_gettable()
 */
const OSSL_PARAM *EVP_PKEY_param_fromdata_settable(EVP_PKEY_CTX *ctx)
{
    /* We call fromdata_init to get ctx->keymgmt populated */
    if (fromdata_init(ctx, EVP_PKEY_OP_UNDEFINED))
        return evp_keymgmt_import_types(ctx->keymgmt,
                                        OSSL_KEYMGMT_SELECT_ALL_PARAMETERS);
    return NULL;
}

const OSSL_PARAM *EVP_PKEY_key_fromdata_settable(EVP_PKEY_CTX *ctx)
{
    /* We call fromdata_init to get ctx->keymgmt populated */
    if (fromdata_init(ctx, EVP_PKEY_OP_UNDEFINED))
        return evp_keymgmt_import_types(ctx->keymgmt,
                                        OSSL_KEYMGMT_SELECT_KEYPAIR);
    return NULL;
}
