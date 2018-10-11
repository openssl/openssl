/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"

#ifndef OPENSSL_NO_POLY1305
# include <openssl/evp.h>
# include "internal/evp_int.h"
# include "internal/poly1305.h"
# include "poly1305_local.h"

static int init(EVP_MD_CTX *ctx)
{
    POLY1305 *poly_ctx = EVP_MD_CTX_md_data(ctx);

    Poly1305_Init(poly_ctx, poly_ctx->key);
    return 1;
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    Poly1305_Update(EVP_MD_CTX_md_data(ctx), data, count);
    return 1;
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    Poly1305_Final(EVP_MD_CTX_md_data(ctx), md);
    return 1;
}

static int poly1305_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    POLY1305 *poly_ctx = EVP_MD_CTX_md_data(ctx);

    switch(cmd) {
    case EVP_CTRL_SET_POLY1305_KEY:
        if (p1 != POLY1305_KEY_SIZE)
            return 0;
        memcpy(poly_ctx->key, p2, POLY1305_KEY_SIZE);
        return 1;
    default:
        return -1;
    }
}

static const EVP_MD poly1305_md = {
    NID_poly1305,
    0,
    POLY1305_DIGEST_SIZE,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
    POLY1305_BLOCK_SIZE,
    sizeof(EVP_MD *) + sizeof(POLY1305),
    poly1305_ctrl
};

const EVP_MD *EVP_poly1305(void)
{
    return &poly1305_md;
}
#endif
