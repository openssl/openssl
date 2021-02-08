/*
 * Copyright 2018-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/types.h>
#include "internal/nelem.h"
#include "crypto/evp.h"
#include "internal/provider.h"
#include "evp_local.h"

EVP_MAC_CTX *EVP_MAC_CTX_new(EVP_MAC *mac)
{
    EVP_MAC_CTX *ctx = OPENSSL_zalloc(sizeof(EVP_MAC_CTX));

    if (ctx == NULL
        || (ctx->data = mac->newctx(ossl_provider_ctx(mac->prov))) == NULL
        || !EVP_MAC_up_ref(mac)) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        if (ctx != NULL)
            mac->freectx(ctx->data);
        OPENSSL_free(ctx);
        ctx = NULL;
    } else {
        ctx->meth = mac;
    }
    return ctx;
}

void EVP_MAC_CTX_free(EVP_MAC_CTX *ctx)
{
    if (ctx != NULL) {
        ctx->meth->freectx(ctx->data);
        ctx->data = NULL;
        /* refcnt-- */
        EVP_MAC_free(ctx->meth);
    }
    OPENSSL_free(ctx);
}

EVP_MAC_CTX *EVP_MAC_CTX_dup(const EVP_MAC_CTX *src)
{
    EVP_MAC_CTX *dst;

    if (src->data == NULL)
        return NULL;

    dst = OPENSSL_malloc(sizeof(*dst));
    if (dst == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    *dst = *src;
    if (!EVP_MAC_up_ref(dst->meth)) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(dst);
        return NULL;
    }

    dst->data = src->meth->dupctx(src->data);
    if (dst->data == NULL) {
        EVP_MAC_CTX_free(dst);
        return NULL;
    }

    return dst;
}

EVP_MAC *EVP_MAC_CTX_mac(EVP_MAC_CTX *ctx)
{
    return ctx->meth;
}

size_t EVP_MAC_CTX_get_mac_size(EVP_MAC_CTX *ctx)
{
    size_t sz = 0;

    if (ctx->data != NULL) {
        OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

        params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
        if (ctx->meth->get_ctx_params != NULL) {
            if (ctx->meth->get_ctx_params(ctx->data, params))
                return sz;
        } else if (ctx->meth->get_params != NULL) {
            if (ctx->meth->get_params(params))
                return sz;
        }
    }
    /*
     * If the MAC hasn't been initialized yet, or there is no size to get,
     * we return zero
     */
    return 0;
}

int EVP_MAC_init(EVP_MAC_CTX *ctx)
{
    return ctx->meth->init(ctx->data);
}

int EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen)
{
    return ctx->meth->update(ctx->data, data, datalen);
}

int EVP_MAC_final(EVP_MAC_CTX *ctx,
                  unsigned char *out, size_t *outl, size_t outsize)
{
    size_t l;
    int res = 1;

    if (out != NULL)
        res = ctx->meth->final(ctx->data, out, &l, outsize);
    else
        l = EVP_MAC_CTX_get_mac_size(ctx);
    if (outl != NULL)
        *outl = l;
    return res;
}

/*
 * The {get,set}_params functions return 1 if there is no corresponding
 * function in the implementation.  This is the same as if there was one,
 * but it didn't recognise any of the given params, i.e. nothing in the
 * bag of parameters was useful.
 */
int EVP_MAC_get_params(EVP_MAC *mac, OSSL_PARAM params[])
{
    if (mac->get_params != NULL)
        return mac->get_params(params);
    return 1;
}

int EVP_MAC_CTX_get_params(EVP_MAC_CTX *ctx, OSSL_PARAM params[])
{
    if (ctx->meth->get_ctx_params != NULL)
        return ctx->meth->get_ctx_params(ctx->data, params);
    return 1;
}

int EVP_MAC_CTX_set_params(EVP_MAC_CTX *ctx, const OSSL_PARAM params[])
{
    if (ctx->meth->set_ctx_params != NULL)
        return ctx->meth->set_ctx_params(ctx->data, params);
    return 1;
}

int EVP_MAC_number(const EVP_MAC *mac)
{
    return mac->name_id;
}

const char *EVP_MAC_name(const EVP_MAC *mac)
{
    if (mac->prov != NULL)
        return evp_first_name(mac->prov, mac->name_id);
    return NULL;
}

int EVP_MAC_is_a(const EVP_MAC *mac, const char *name)
{
    return evp_is_a(mac->prov, mac->name_id, NULL, name);
}

void EVP_MAC_names_do_all(const EVP_MAC *mac,
                          void (*fn)(const char *name, void *data),
                          void *data)
{
    if (mac->prov != NULL)
        evp_names_do_all(mac->prov, mac->name_id, fn, data);
}
