/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
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

static int poly1305_copy(EVP_MAC_IMPL *dst, EVP_MAC_IMPL *src)
{
    *dst->ctx = *src->ctx;

    return 1;
}

static size_t poly1305_size(EVP_MAC_IMPL *ctx)
{
    return POLY1305_DIGEST_SIZE;
}

static int poly1305_init(EVP_MAC_IMPL *ctx)
{
    /* initialize the context in MAC_ctrl function */
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

        if (keylen != POLY1305_KEY_SIZE) {
            EVPerr(EVP_F_POLY1305_CTRL, EVP_R_INVALID_KEY_LENGTH);
            return 0;
        }
        Poly1305_Init(poly_ctx, key);
        return 1;
    default:
        return -2;
    }
    return 1;
}

static int poly1305_ctrl_int(EVP_MAC_IMPL *ctx, int cmd, ...)
{
    int rv;
    va_list args;

    va_start(args, cmd);
    rv = poly1305_ctrl(ctx, cmd, args);
    va_end(args);

    return rv;
}

static int poly1305_ctrl_str_cb(void *ctx, int cmd, void *buf, size_t buflen)
{
    return poly1305_ctrl_int(ctx, cmd, buf, buflen);
}

static int poly1305_ctrl_str(EVP_MAC_IMPL *ctx,
                             const char *type, const char *value)
{
    if (value == NULL)
        return 0;
    if (strcmp(type, "key") == 0)
        return EVP_str2ctrl(poly1305_ctrl_str_cb, ctx, EVP_MAC_CTRL_SET_KEY,
                            value);
    if (strcmp(type, "hexkey") == 0)
        return EVP_hex2ctrl(poly1305_ctrl_str_cb, ctx, EVP_MAC_CTRL_SET_KEY,
                            value);
    return -2;
}

const EVP_MAC poly1305_meth = {
    EVP_MAC_POLY1305,
    poly1305_new,
    poly1305_copy,
    poly1305_free,
    poly1305_size,
    poly1305_init,
    poly1305_update,
    poly1305_final,
    poly1305_ctrl,
    poly1305_ctrl_str
};
