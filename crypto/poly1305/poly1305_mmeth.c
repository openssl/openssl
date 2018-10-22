/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/evp.h>
#include "internal/evp_int.h"
#include "internal/poly1305.h"
#include "internal/cryptlib.h"
#include "poly1305_local.h"

/* typedef EVP_MAC_IMPL */
struct evp_mac_impl_st {
    POLY1305 *ctx;               /* poly1305 context */
};

static EVP_MAC_IMPL *poly1305_new(void)
{
    EVP_MAC_IMPL *ctx;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL
            || (ctx->ctx = OPENSSL_zalloc(sizeof(POLY1305))) == NULL) {
        OPENSSL_free(ctx);
        return 0;
    }
    return ctx;
}

static void poly1305_free(EVP_MAC_IMPL *ctx)
{
    if (ctx != NULL) {
        OPENSSL_free(ctx->ctx);
        OPENSSL_free(ctx);
    }
}

static EVP_MAC_IMPL *poly1305_copy(EVP_MAC_IMPL *src)
{
    EVP_MAC_IMPL *dst = NULL;

    if ((dst = poly1305_new()) == NULL
            || !memcpy(dst->ctx, src->ctx, sizeof(POLY1305))) {
        poly1305_free(dst);
        return NULL;
    }

    return dst;
}

static size_t poly1305_size(EVP_MAC_IMPL *ctx)
{
    return POLY1305_DIGEST_SIZE;
}

static int poly1305_init(EVP_MAC_IMPL *ctx)
{
    POLY1305 *poly_ctx = ctx->ctx;

    /* poly1305 has nothing to return in its init function */
    Poly1305_Init(poly_ctx, poly_ctx->key);
    return 1;
}

static int poly1305_update(EVP_MAC_IMPL *ctx, const unsigned char *data,
                       size_t datalen)
{
    POLY1305 *poly_ctx = ctx->ctx;

    /* poly1305 has nothing to return in its update function */
    Poly1305_Update(poly_ctx, data, datalen);
    return 1;
}

static int poly1305_final(EVP_MAC_IMPL *ctx, unsigned char *out)
{
    POLY1305 *poly_ctx = ctx->ctx;

    Poly1305_Final(poly_ctx, out);
    return 1;
}

static int poly1305_ctrl(EVP_MAC_IMPL *ctx, int cmd, va_list args)
{
    POLY1305 *poly_ctx = ctx->ctx;
    unsigned char *key;
    size_t keylen;

    switch (cmd) {
    case EVP_MAC_CTRL_SET_KEY:
        key = va_arg(args, unsigned char *);
        keylen = va_arg(args, size_t);

        if (keylen != POLY1305_KEY_SIZE)
            return 0;
        memcpy(poly_ctx->key, key, POLY1305_KEY_SIZE);
        return 1;
    default:
        return -2;
    }
    return 1;
}

static const EVP_MAC poly1305_meth = {
    EVP_MAC_POLY1305,
    poly1305_new,
    NULL,
    poly1305_copy,
    poly1305_free,
    poly1305_size,
    poly1305_init,
    poly1305_update,
    poly1305_final,
    poly1305_ctrl,
    NULL
};

const EVP_MAC *EVP_poly1305(void)
{
    return &poly1305_meth;
}
