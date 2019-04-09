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

typedef int sk_cmp_fn_type(const char *const *a, const char *const *b);

/* This array needs to be in order of NIDs */
static const EVP_KDF_METHOD *standard_methods[] = {
    &pbkdf2_kdf_meth,
#ifndef OPENSSL_NO_SCRYPT
    &scrypt_kdf_meth,
#endif
    &tls1_prf_kdf_meth,
    &hkdf_kdf_meth,
    &sshkdf_kdf_meth,
    &ss_kdf_meth
};

DECLARE_OBJ_BSEARCH_CMP_FN(const EVP_KDF_METHOD *, const EVP_KDF_METHOD *,
                           kmeth);

static int kmeth_cmp(const EVP_KDF_METHOD *const *a,
                     const EVP_KDF_METHOD *const *b)
{
    return ((*a)->type - (*b)->type);
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(const EVP_KDF_METHOD *, const EVP_KDF_METHOD *,
                             kmeth);

static const EVP_KDF_METHOD *kdf_meth_find(int type)
{
    EVP_KDF_METHOD tmp;
    const EVP_KDF_METHOD *t = &tmp, **ret;

    tmp.type = type;
    ret = OBJ_bsearch_kmeth(&t, standard_methods,
                            OSSL_NELEM(standard_methods));
    if (ret == NULL || *ret == NULL)
        return NULL;

    return *ret;
}

EVP_KDF_CTX *EVP_KDF_CTX_new_id(int id)
{
    EVP_KDF_CTX *ret;
    const EVP_KDF_METHOD *kmeth;

    kmeth = kdf_meth_find(id);
    if (kmeth == NULL) {
        EVPerr(EVP_F_EVP_KDF_CTX_NEW_ID, EVP_R_UNSUPPORTED_ALGORITHM);
        return NULL;
    }

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        EVPerr(EVP_F_EVP_KDF_CTX_NEW_ID, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (kmeth->new != NULL && (ret->impl = kmeth->new()) == NULL) {
        EVP_KDF_CTX_free(ret);
        return NULL;
    }

    ret->kmeth = kmeth;
    return ret;
}

void EVP_KDF_CTX_free(EVP_KDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    ctx->kmeth->free(ctx->impl);
    OPENSSL_free(ctx);
}

void EVP_KDF_reset(EVP_KDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->kmeth->reset != NULL)
        ctx->kmeth->reset(ctx->impl);
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

    return ctx->kmeth->ctrl(ctx->impl, cmd, args);
}

int EVP_KDF_ctrl_str(EVP_KDF_CTX *ctx, const char *type, const char *value)
{
    int ret;

    if (ctx == NULL)
        return 0;

    if (ctx->kmeth->ctrl_str == NULL) {
        EVPerr(EVP_F_EVP_KDF_CTRL_STR, EVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }

    ret = ctx->kmeth->ctrl_str(ctx->impl, type, value);
    if (ret == -2)
        EVPerr(EVP_F_EVP_KDF_CTRL_STR, EVP_R_COMMAND_NOT_SUPPORTED);

    return ret;
}

size_t EVP_KDF_size(EVP_KDF_CTX *ctx)
{
    if (ctx == NULL)
        return 0;

    if (ctx->kmeth->size == NULL)
        return SIZE_MAX;

    return ctx->kmeth->size(ctx->impl);
}

int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen)
{
    if (ctx == NULL)
        return 0;

    return ctx->kmeth->derive(ctx->impl, key, keylen);
}

