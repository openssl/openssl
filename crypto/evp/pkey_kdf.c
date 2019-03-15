/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include "internal/numbers.h"
#include "internal/evp_int.h"

static int pkey_kdf_init(EVP_PKEY_CTX *ctx)
{
    EVP_KDF_CTX *kctx;

    kctx = EVP_KDF_CTX_new_id(ctx->pmeth->pkey_id);
    if (kctx == NULL)
        return 0;

    ctx->data = kctx;
    return 1;
}

static void pkey_kdf_cleanup(EVP_PKEY_CTX *ctx)
{
    EVP_KDF_CTX *kctx = ctx->data;

    EVP_KDF_CTX_free(kctx);
}

static int pkey_kdf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    EVP_KDF_CTX *kctx = ctx->data;
    uint64_t u64_value;
    int cmd;
    int ret;

    switch (type) {
    case EVP_PKEY_CTRL_PASS:
        cmd = EVP_KDF_CTRL_SET_PASS;
        break;
    case EVP_PKEY_CTRL_HKDF_SALT:
    case EVP_PKEY_CTRL_SCRYPT_SALT:
        cmd = EVP_KDF_CTRL_SET_SALT;
        break;
    case EVP_PKEY_CTRL_TLS_MD:
    case EVP_PKEY_CTRL_HKDF_MD:
        cmd = EVP_KDF_CTRL_SET_MD;
        break;
    case EVP_PKEY_CTRL_TLS_SECRET:
        cmd = EVP_KDF_CTRL_SET_TLS_SECRET;
        ret = EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_RESET_TLS_SEED);
        if (ret < 1)
            return ret;
        break;
    case EVP_PKEY_CTRL_TLS_SEED:
        cmd = EVP_KDF_CTRL_ADD_TLS_SEED;
        break;
    case EVP_PKEY_CTRL_HKDF_KEY:
        cmd = EVP_KDF_CTRL_SET_KEY;
        break;
    case EVP_PKEY_CTRL_HKDF_INFO:
        cmd = EVP_KDF_CTRL_ADD_HKDF_INFO;
        break;
    case EVP_PKEY_CTRL_HKDF_MODE:
        cmd = EVP_KDF_CTRL_SET_HKDF_MODE;
        break;
    case EVP_PKEY_CTRL_SCRYPT_N:
        cmd = EVP_KDF_CTRL_SET_SCRYPT_N;
        break;
    case EVP_PKEY_CTRL_SCRYPT_R:
        cmd = EVP_KDF_CTRL_SET_SCRYPT_R;
        break;
    case EVP_PKEY_CTRL_SCRYPT_P:
        cmd = EVP_KDF_CTRL_SET_SCRYPT_P;
        break;
    case EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES:
        cmd = EVP_KDF_CTRL_SET_MAXMEM_BYTES;
        break;
    default:
        return -2;
    }

    switch (cmd) {
    case EVP_KDF_CTRL_SET_PASS:
    case EVP_KDF_CTRL_SET_SALT:
    case EVP_KDF_CTRL_SET_KEY:
    case EVP_KDF_CTRL_SET_TLS_SECRET:
    case EVP_KDF_CTRL_ADD_TLS_SEED:
    case EVP_KDF_CTRL_ADD_HKDF_INFO:
        return EVP_KDF_ctrl(kctx, cmd, (const unsigned char *)p2, (size_t)p1);

    case EVP_KDF_CTRL_SET_MD:
        return EVP_KDF_ctrl(kctx, cmd, (const EVP_MD *)p2);

    case EVP_KDF_CTRL_SET_HKDF_MODE:
        return EVP_KDF_ctrl(kctx, cmd, (int)p1);

    case EVP_KDF_CTRL_SET_SCRYPT_R:
    case EVP_KDF_CTRL_SET_SCRYPT_P:
        u64_value = *(uint64_t *)p2;
        if (u64_value > UINT32_MAX) {
            EVPerr(EVP_F_PKEY_KDF_CTRL, EVP_R_PARAMETER_TOO_LARGE);
            return 0;
        }

        return EVP_KDF_ctrl(kctx, cmd, (uint32_t)u64_value);

    case EVP_KDF_CTRL_SET_SCRYPT_N:
    case EVP_KDF_CTRL_SET_MAXMEM_BYTES:
        return EVP_KDF_ctrl(kctx, cmd, *(uint64_t *)p2);

    default:
        return 0;
    }
}

static int pkey_kdf_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
                             const char *value)
{
    EVP_KDF_CTX *kctx = ctx->data;

    if (strcmp(type, "md") == 0)
        return EVP_KDF_ctrl_str(kctx, "digest", value);
    return EVP_KDF_ctrl_str(kctx, type, value);
}

static int pkey_kdf_derive_init(EVP_PKEY_CTX *ctx)
{
    EVP_KDF_CTX *kctx = ctx->data;

    EVP_KDF_reset(kctx);
    return 1;
}

/*
 * For fixed-output algorithms the keylen parameter is an "out" parameter
 * otherwise it is an "in" parameter.
 */
static int pkey_kdf_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                           size_t *keylen)
{
    EVP_KDF_CTX *kctx = ctx->data;
    size_t outlen = EVP_KDF_size(kctx);

    if (outlen == 0 || outlen == SIZE_MAX) {
        /* Variable-output algorithm */
        if (key == NULL)
            return 0;
    } else {
        /* Fixed-output algorithm */
        *keylen = outlen;
        if (key == NULL)
            return 1;
    }
    return EVP_KDF_derive(kctx, key, *keylen);
}

#ifndef OPENSSL_NO_SCRYPT
const EVP_PKEY_METHOD scrypt_pkey_meth = {
    EVP_PKEY_SCRYPT,
    0,
    pkey_kdf_init,
    0,
    pkey_kdf_cleanup,

    0, 0,
    0, 0,

    0,
    0,

    0,
    0,

    0, 0,

    0, 0, 0, 0,

    0, 0,

    0, 0,

    pkey_kdf_derive_init,
    pkey_kdf_derive,
    pkey_kdf_ctrl,
    pkey_kdf_ctrl_str
};
#endif

const EVP_PKEY_METHOD tls1_prf_pkey_meth = {
    EVP_PKEY_TLS1_PRF,
    0,
    pkey_kdf_init,
    0,
    pkey_kdf_cleanup,

    0, 0,
    0, 0,

    0,
    0,

    0,
    0,

    0, 0,

    0, 0, 0, 0,

    0, 0,

    0, 0,

    pkey_kdf_derive_init,
    pkey_kdf_derive,
    pkey_kdf_ctrl,
    pkey_kdf_ctrl_str
};

const EVP_PKEY_METHOD hkdf_pkey_meth = {
    EVP_PKEY_HKDF,
    0,
    pkey_kdf_init,
    0,
    pkey_kdf_cleanup,

    0, 0,
    0, 0,

    0,
    0,

    0,
    0,

    0, 0,

    0, 0, 0, 0,

    0, 0,

    0, 0,

    pkey_kdf_derive_init,
    pkey_kdf_derive,
    pkey_kdf_ctrl,
    pkey_kdf_ctrl_str
};

