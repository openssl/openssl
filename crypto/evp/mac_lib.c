/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
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
        EVPerr(EVP_F_EVP_MAC_CTX_NEW, ERR_R_MALLOC_FAILURE);
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
        EVPerr(EVP_F_EVP_MAC_CTX_DUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    *dst = *src;
    if (!EVP_MAC_up_ref(dst->meth)) {
        EVPerr(EVP_F_EVP_MAC_CTX_DUP, ERR_R_MALLOC_FAILURE);
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

size_t EVP_MAC_size(EVP_MAC_CTX *ctx)
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
    if (datalen == 0)
        return 1;
    return ctx->meth->update(ctx->data, data, datalen);
}

int EVP_MAC_final(EVP_MAC_CTX *ctx,
                  unsigned char *out, size_t *outl, size_t outsize)
{
    int l = EVP_MAC_size(ctx);

    if (l < 0)
        return 0;
    if (outl != NULL)
        *outl = l;
    if (out == NULL)
        return 1;
    return ctx->meth->final(ctx->data, out, outl, outsize);
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

int EVP_MAC_is_a(const EVP_MAC *mac, const char *name)
{
    return evp_is_a(mac->prov, mac->name_id, name);
}

void EVP_MAC_names_do_all(const EVP_MAC *mac,
                          void (*fn)(const char *name, void *data),
                          void *data)
{
    if (mac->prov != NULL)
        evp_names_do_all(mac->prov, mac->name_id, fn, data);
}
