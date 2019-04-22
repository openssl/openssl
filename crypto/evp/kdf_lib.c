/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/kdf.h>
#include "internal/asn1_int.h"
#include "internal/evp_int.h"
#include "internal/numbers.h"
#include "evp_locl.h"

EVP_KDF_CTX *EVP_KDF_CTX_new(const EVP_KDF *kdf)
{
    EVP_KDF_CTX *ctx = OPENSSL_zalloc(sizeof(EVP_KDF_CTX));

    if (ctx == NULL || (ctx->data = kdf->new()) == NULL) {
        EVPerr(EVP_F_EVP_KDF_CTX_NEW, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ctx);
        ctx = NULL;
    } else {
        ctx->meth = kdf;
    }
    return ctx;
}

EVP_KDF_CTX *EVP_KDF_CTX_new_id(int id)
{
    const EVP_KDF *kdf = EVP_get_kdfbynid(id);

    if (kdf == NULL)
        return NULL;
    return EVP_KDF_CTX_new(kdf);
}

int EVP_KDF_nid(const EVP_KDF *kdf)
{
    return kdf->type;
}

const EVP_KDF *EVP_KDF_CTX_kdf(EVP_KDF_CTX *ctx)
{
    return ctx->meth;
}

void EVP_KDF_CTX_free(EVP_KDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    ctx->meth->free(ctx->data);
    OPENSSL_free(ctx);
}

void EVP_KDF_reset(EVP_KDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->meth->reset != NULL)
        ctx->meth->reset(ctx->data);
}

int EVP_KDF_ctrl(EVP_KDF_CTX *ctx, int cmd, ...)
{
    int ret;
    va_list args;

    va_start(args, cmd);
    ret = EVP_KDF_vctrl(ctx, cmd, args);
    va_end(args);

    if (ret == -2)
        EVPerr(EVP_F_EVP_KDF_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);

    return ret;
}

int EVP_KDF_vctrl(EVP_KDF_CTX *ctx, int cmd, va_list args)
{
    if (ctx == NULL)
        return 0;

    return ctx->meth->ctrl(ctx->data, cmd, args);
}

int EVP_KDF_ctrl_str(EVP_KDF_CTX *ctx, const char *type, const char *value)
{
    int ret;

    if (ctx == NULL)
        return 0;

    if (ctx->meth->ctrl_str == NULL) {
        EVPerr(EVP_F_EVP_KDF_CTRL_STR, EVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }

    ret = ctx->meth->ctrl_str(ctx->data, type, value);
    if (ret == -2)
        EVPerr(EVP_F_EVP_KDF_CTRL_STR, EVP_R_COMMAND_NOT_SUPPORTED);

    return ret;
}

size_t EVP_KDF_size(EVP_KDF_CTX *ctx)
{
    if (ctx == NULL)
        return 0;

    if (ctx->meth->size == NULL)
        return SIZE_MAX;

    return ctx->meth->size(ctx->data);
}

int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen)
{
    if (ctx == NULL)
        return 0;

    return ctx->meth->derive(ctx->data, key, keylen);
}

