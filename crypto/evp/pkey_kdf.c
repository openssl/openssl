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
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "internal/numbers.h"
#include "internal/evp_int.h"

#define MAX_PARAM   20

typedef struct {
    EVP_KDF_CTX *kctx;
    /* TODO(3.0): come up with a better way to do this */
    OSSL_PARAM params[MAX_PARAM];
    int palloc[MAX_PARAM];
    uint64_t uint64s[MAX_PARAM];
    int ints[MAX_PARAM];
    int pidx;
} EVP_PKEY_KDF_CTX;

static void pkey_kdf_free_param_data(EVP_PKEY_KDF_CTX *pkctx)
{
    int i;

    for (i = 0; i < pkctx->pidx; i++)
        if (pkctx->palloc[i])
            OPENSSL_free(pkctx->params[i].data);
    pkctx->pidx = 0;
}

static int pkey_kdf_init(EVP_PKEY_CTX *ctx)
{
    EVP_PKEY_KDF_CTX *pkctx;
    EVP_KDF_CTX *kctx;
    const char *kdf_name = OBJ_nid2sn(ctx->pmeth->pkey_id);
    EVP_KDF *kdf;

    pkctx = OPENSSL_zalloc(sizeof(*pkctx));
    if (pkctx == NULL)
        return 0;

    kdf = EVP_KDF_fetch(NULL, kdf_name, NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx == NULL) {
        OPENSSL_free(pkctx);
        return 0;
    }

    pkctx->kctx = kctx;
    ctx->data = pkctx;
    return 1;
}

static void pkey_kdf_cleanup(EVP_PKEY_CTX *ctx)
{
    EVP_PKEY_KDF_CTX *pkctx = ctx->data;

    EVP_KDF_CTX_free(pkctx->kctx);
    pkey_kdf_free_param_data(pkctx);
    OPENSSL_free(pkctx);
}

static int pkey_kdf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    EVP_PKEY_KDF_CTX *pkctx = ctx->data;
    enum { T_OCTET_STRING, T_UINT64, T_DIGEST, T_INT } cmd;
    const char *name, *mdname;
    OSSL_PARAM *p = pkctx->params + pkctx->pidx;

    switch (type) {
    case EVP_PKEY_CTRL_PASS:
        cmd = T_OCTET_STRING;
        name = OSSL_KDF_PARAM_PASSWORD;
        break;
    case EVP_PKEY_CTRL_HKDF_SALT:
    case EVP_PKEY_CTRL_SCRYPT_SALT:
        cmd = T_OCTET_STRING;
        name = OSSL_KDF_PARAM_SALT;
        break;
    case EVP_PKEY_CTRL_TLS_MD:
    case EVP_PKEY_CTRL_HKDF_MD:
        cmd = T_DIGEST;
        name = OSSL_KDF_PARAM_DIGEST;
        break;
    case EVP_PKEY_CTRL_TLS_SECRET:
        cmd = T_OCTET_STRING;
        name = OSSL_KDF_PARAM_SECRET;
        break;
    case EVP_PKEY_CTRL_TLS_SEED:
        cmd = T_OCTET_STRING;
        name = OSSL_KDF_PARAM_SEED;
        break;
    case EVP_PKEY_CTRL_HKDF_KEY:
        cmd = T_OCTET_STRING;
        name = OSSL_KDF_PARAM_KEY;
        break;
    case EVP_PKEY_CTRL_HKDF_INFO:
        cmd = T_OCTET_STRING;
        name = OSSL_KDF_PARAM_INFO;
        break;
    case EVP_PKEY_CTRL_HKDF_MODE:
        cmd = T_INT;
        name = OSSL_KDF_PARAM_MODE;
        break;
    case EVP_PKEY_CTRL_SCRYPT_N:
        cmd = T_UINT64;
        name = OSSL_KDF_PARAM_SCRYPT_N;
        break;
    case EVP_PKEY_CTRL_SCRYPT_R:
        cmd = T_UINT64; /* Range checking occurs on the provider side */
        name = OSSL_KDF_PARAM_SCRYPT_R;
        break;
    case EVP_PKEY_CTRL_SCRYPT_P:
        cmd = T_UINT64; /* Range checking occurs on the provider side */
        name = OSSL_KDF_PARAM_SCRYPT_P;
        break;
    case EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES:
        cmd = T_UINT64;
        name = OSSL_KDF_PARAM_SCRYPT_MAXMEM;
        break;
    default:
        return -2;
    }

    switch (cmd) {
    case T_OCTET_STRING:
        *p = OSSL_PARAM_construct_octet_string(name, (unsigned char *)p2,
                                               (size_t)p1);
        break;

    case T_DIGEST:
        mdname = EVP_MD_name((const EVP_MD *)p2);
        *p = OSSL_PARAM_construct_utf8_string(name, (char *)mdname,
                                              strlen(mdname) + 1);
        break;

        /*
         * These are special because the helper macros pass a pointer to the
         * stack, so a local copy is required.
         */
    case T_INT:
        pkctx->ints[pkctx->pidx] = *(int *)p2;
        *p = OSSL_PARAM_construct_int(name, pkctx->ints + pkctx->pidx);
        break;

    case T_UINT64:
        pkctx->uint64s[pkctx->pidx] = *(uint64_t *)p2;
        *p = OSSL_PARAM_construct_uint64(name, pkctx->uint64s + pkctx->pidx);
        break;
    }
    pkctx->palloc[pkctx->pidx++] = 0;
    return 1;
}

static int pkey_kdf_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
                             const char *value)
{
    EVP_PKEY_KDF_CTX *pkctx = ctx->data;
    EVP_KDF_CTX *kctx = pkctx->kctx;
    const EVP_KDF *kdf = EVP_KDF_CTX_kdf(kctx);
    const OSSL_PARAM *defs = EVP_KDF_CTX_settable_params(kdf);
    OSSL_PARAM *p = pkctx->params + pkctx->pidx;

    /* Deal with ctrl name aliasing */
    if (strcmp(type, "md") == 0)
        type = OSSL_KDF_PARAM_DIGEST;
    /* scrypt uses 'N', params uses 'n' */
    if (strcmp(type, "N") == 0)
        type = OSSL_KDF_PARAM_SCRYPT_N;

    if (!OSSL_PARAM_allocate_from_text(p, defs, type, value, strlen(value)))
        return 0;
    pkctx->palloc[pkctx->pidx++] = 1;
    return 1;
}

static int pkey_kdf_derive_init(EVP_PKEY_CTX *ctx)
{
    EVP_PKEY_KDF_CTX *pkctx = ctx->data;

    pkey_kdf_free_param_data(pkctx);
    EVP_KDF_reset(pkctx->kctx);
    return 1;
}

/*
 * For fixed-output algorithms the keylen parameter is an "out" parameter
 * otherwise it is an "in" parameter.
 */
static int pkey_kdf_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                           size_t *keylen)
{
    EVP_PKEY_KDF_CTX *pkctx = ctx->data;
    EVP_KDF_CTX *kctx = pkctx->kctx;
    size_t outlen = EVP_KDF_size(kctx);
    int r;

    if (pkctx->pidx > 0) {
        pkctx->params[pkctx->pidx] = OSSL_PARAM_construct_end();
        r = EVP_KDF_CTX_set_params(kctx, pkctx->params);
        pkey_kdf_free_param_data(pkctx);
        if (!r)
            return 0;
    }
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

