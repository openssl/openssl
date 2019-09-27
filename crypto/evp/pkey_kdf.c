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
#include <openssl/buffer.h>
#include <openssl/kdf.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "internal/numbers.h"
#include "crypto/evp.h"

#define MAX_PARAM   20

typedef struct {
    EVP_KDF_CTX *kctx;
    /*
     * EVP_PKEY implementations collect bits of certain data
     */
    BUF_MEM *collected_seed;
    BUF_MEM *collected_info;
} EVP_PKEY_KDF_CTX;

static void pkey_kdf_free_collected(EVP_PKEY_KDF_CTX *pkctx)
{
    BUF_MEM_free(pkctx->collected_seed);
    pkctx->collected_seed = NULL;
    BUF_MEM_free(pkctx->collected_info);
    pkctx->collected_info = NULL;
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
    pkey_kdf_free_collected(pkctx);
    OPENSSL_free(pkctx);
}

static int collect(BUF_MEM **collector, void *data, size_t datalen)
{
    size_t i;

    if (*collector == NULL)
        *collector = BUF_MEM_new();
    if (*collector == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (data != NULL && datalen > 0) {
        i = (*collector)->length; /* BUF_MEM_grow() changes it! */

        if (!BUF_MEM_grow(*collector, i + datalen))
            return 0;
        memcpy((*collector)->data + i, data, datalen);
    }
    return 1;
}

static int pkey_kdf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    EVP_PKEY_KDF_CTX *pkctx = ctx->data;
    EVP_KDF_CTX *kctx = pkctx->kctx;
    enum { T_OCTET_STRING, T_UINT64, T_DIGEST, T_INT } cmd;
    const char *name, *mdname;
    BUF_MEM **collector = NULL;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

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
        /*
         * Perform the semantics described in
         * EVP_PKEY_CTX_add1_tls1_prf_seed(3)
         */
        if (ctx->pmeth->pkey_id == NID_tls1_prf) {
            BUF_MEM_free(pkctx->collected_seed);
            pkctx->collected_seed = NULL;
        }
        break;
    case EVP_PKEY_CTRL_TLS_SEED:
        cmd = T_OCTET_STRING;
        name = OSSL_KDF_PARAM_SEED;
        collector = &pkctx->collected_seed;
        break;
    case EVP_PKEY_CTRL_HKDF_KEY:
        cmd = T_OCTET_STRING;
        name = OSSL_KDF_PARAM_KEY;
        break;
    case EVP_PKEY_CTRL_HKDF_INFO:
        cmd = T_OCTET_STRING;
        name = OSSL_KDF_PARAM_INFO;
        collector = &pkctx->collected_info;
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

    if (collector != NULL) {
        switch (cmd) {
        case T_OCTET_STRING:
            return collect(collector, p2, p1);
        default:
            OPENSSL_assert("You shouldn't be here");
            break;
        }
        return 1;
    }

    switch (cmd) {
    case T_OCTET_STRING:
        params[0] =
            OSSL_PARAM_construct_octet_string(name, (unsigned char *)p2,
                                              (size_t)p1);
        break;

    case T_DIGEST:
        mdname = EVP_MD_name((const EVP_MD *)p2);
        params[0] = OSSL_PARAM_construct_utf8_string(name, (char *)mdname,
                                                     strlen(mdname) + 1);
        break;

        /*
         * These are special because the helper macros pass a pointer to the
         * stack, so a local copy is required.
         */
    case T_INT:
        params[0] = OSSL_PARAM_construct_int(name, &p1);
        break;

    case T_UINT64:
        params[0] = OSSL_PARAM_construct_uint64(name, (uint64_t *)p2);
        break;
    }

    return EVP_KDF_CTX_set_params(kctx, params);
}

static int pkey_kdf_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
                             const char *value)
{
    EVP_PKEY_KDF_CTX *pkctx = ctx->data;
    EVP_KDF_CTX *kctx = pkctx->kctx;
    const EVP_KDF *kdf = EVP_KDF_CTX_kdf(kctx);
    BUF_MEM **collector = NULL;
    const OSSL_PARAM *defs = EVP_KDF_settable_ctx_params(kdf);
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    int ok = 0;

    /* Deal with ctrl name aliasing */
    if (strcmp(type, "md") == 0)
        type = OSSL_KDF_PARAM_DIGEST;
    /* scrypt uses 'N', params uses 'n' */
    if (strcmp(type, "N") == 0)
        type = OSSL_KDF_PARAM_SCRYPT_N;

    if (!OSSL_PARAM_allocate_from_text(&params[0], defs, type,
                                       value, strlen(value)))
        return 0;

    /*
     * We do the same special casing of seed and info here as in
     * pkey_kdf_ctrl()
     */
    if (strcmp(params[0].key, OSSL_KDF_PARAM_SEED) == 0)
        collector = &pkctx->collected_seed;
    else if (strcmp(params[0].key, OSSL_KDF_PARAM_INFO) == 0)
        collector = &pkctx->collected_info;

    if (collector != NULL)
        ok = collect(collector, params[0].data, params[0].data_size);
    else
        ok = EVP_KDF_CTX_set_params(kctx, params);
    OPENSSL_free(params[0].data);
    return ok;
}

static int pkey_kdf_derive_init(EVP_PKEY_CTX *ctx)
{
    EVP_PKEY_KDF_CTX *pkctx = ctx->data;

    pkey_kdf_free_collected(pkctx);
    if (pkctx->kctx != NULL)
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

    if (pkctx->collected_seed != NULL) {
        OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END };

        params[0] =
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED,
                                              pkctx->collected_seed->data,
                                              pkctx->collected_seed->length);

        r = EVP_KDF_CTX_set_params(kctx, params);
        pkey_kdf_free_collected(pkctx);
        if (!r)
            return 0;
    }
    if (pkctx->collected_info != NULL) {
        OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END };

        params[0] =
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                              pkctx->collected_info->data,
                                              pkctx->collected_info->length);

        r = EVP_KDF_CTX_set_params(kctx, params);
        pkey_kdf_free_collected(pkctx);
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
static const EVP_PKEY_METHOD scrypt_pkey_meth = {
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

const EVP_PKEY_METHOD *scrypt_pkey_method(void)
{
    return &scrypt_pkey_meth;
}
#endif

static const EVP_PKEY_METHOD tls1_prf_pkey_meth = {
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

const EVP_PKEY_METHOD *tls1_prf_pkey_method(void)
{
    return &tls1_prf_pkey_meth;
}

static const EVP_PKEY_METHOD hkdf_pkey_meth = {
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

const EVP_PKEY_METHOD *hkdf_pkey_method(void)
{
    return &hkdf_pkey_meth;
}
