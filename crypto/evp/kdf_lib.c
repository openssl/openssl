/*
 * Copyright 2018-2019 The OpenSSL Project Authors. All Rights Reserved.
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
#include "internal/sparse_array.h"
#include "internal/thread_once.h"
#include "internal/nelem.h"
#include "evp_locl.h"

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

DEFINE_SPARSE_ARRAY_OF_CONST(EVP_KDF_METHOD);
static SPARSE_ARRAY_OF(EVP_KDF_METHOD) *kdf_methods;

static void do_kdf_cleanup(void)
{
    ossl_sa_EVP_KDF_METHOD_free(kdf_methods);
    kdf_methods = NULL;
}

static CRYPTO_ONCE kdf_init = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_kdf_init)
{
    size_t i;

    if ((kdf_methods = ossl_sa_EVP_KDF_METHOD_new()) == NULL)
        return 0;

    for (i = 0; i < OSSL_NELEM(standard_methods); i++)
        if (!ossl_sa_EVP_KDF_METHOD_set(kdf_methods, standard_methods[i]->type,
                                        standard_methods[i]))
            goto err;

    if (OPENSSL_atexit(&do_kdf_cleanup))
        return 1;
err:
    ossl_sa_EVP_KDF_METHOD_free(kdf_methods);
    return 0;
}

EVP_KDF_CTX *EVP_KDF_CTX_new_id(int id)
{
    EVP_KDF_CTX *ret;
    const EVP_KDF_METHOD *kmeth;

    if (!RUN_ONCE(&kdf_init, do_kdf_init)) {
        EVPerr(EVP_F_EVP_KDF_CTX_NEW_ID, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    kmeth = ossl_sa_EVP_KDF_METHOD_get(kdf_methods, id);
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

