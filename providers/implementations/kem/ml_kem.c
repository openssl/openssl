/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "prov/provider_ctx.h"
#include "prov/implementations.h"
#include "prov/securitycheck.h"
#include "prov/providercommon.h"
#include "internal/mlkem.h"

typedef struct {
    OSSL_LIB_CTX *libctx;
    MLKEM_KEY *key;
    int op;
} PROV_MLKEM_CTX;

static OSSL_FUNC_kem_newctx_fn mlkem_newctx;
static OSSL_FUNC_kem_encapsulate_init_fn mlkem_encapsulate_init;
static OSSL_FUNC_kem_encapsulate_fn mlkem_encapsulate;
static OSSL_FUNC_kem_decapsulate_init_fn mlkem_decapsulate_init;
static OSSL_FUNC_kem_decapsulate_fn mlkem_decapsulate;
static OSSL_FUNC_kem_freectx_fn mlkem_freectx;
static OSSL_FUNC_kem_set_ctx_params_fn mlkem_set_ctx_params;

static void *mlkem_newctx(void *provctx)
{
    PROV_MLKEM_CTX *ctx =  OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;
    ctx->libctx = PROV_LIBCTX_OF(provctx);

    return ctx;
}

static void mlkem_freectx(void *vctx)
{
    PROV_MLKEM_CTX *ctx = (PROV_MLKEM_CTX *)vctx;

    OPENSSL_free(ctx);
}

static int mlkem_init(void *vctx, int operation, void *vkey, void *vauth,
                      ossl_unused const OSSL_PARAM params[])
{
    PROV_MLKEM_CTX *ctx = (PROV_MLKEM_CTX *)vctx;
    MLKEM_KEY *mlkemkey = vkey;

    if (!ossl_prov_is_running())
        return 0;

    if (mlkemkey->keytype != MLKEM_KEY_TYPE_768)
        return 0;

    ctx->key = mlkemkey;
    ctx->op = operation;
    return 1;
}

static int mlkem_encapsulate_init(void *vctx, void *vkey,
                                  const OSSL_PARAM params[])
{
    return mlkem_init(vctx, EVP_PKEY_OP_ENCAPSULATE, vkey, NULL, params);
}

static int mlkem_decapsulate_init(void *vctx, void *vkey,
                                  const OSSL_PARAM params[])
{
    return mlkem_init(vctx, EVP_PKEY_OP_DECAPSULATE, vkey, NULL, params);
}

static int mlkem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_MLKEM_CTX *ctx = (PROV_MLKEM_CTX *)vctx;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    return 1;
}

static const OSSL_PARAM known_settable_mlkem_ctx_params[] = {
    OSSL_PARAM_END
};

static const OSSL_PARAM *mlkem_settable_ctx_params(ossl_unused void *vctx,
                                                   ossl_unused void *provctx)
{
    return known_settable_mlkem_ctx_params;
}

static int mlkem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
                                unsigned char *secret, size_t *secretlen)
{
    PROV_MLKEM_CTX *ctx = (PROV_MLKEM_CTX *)vctx;

    if (outlen != NULL)
        *outlen = MLKEM768_CIPHERTEXTBYTES;
    if (secretlen != NULL)
        *secretlen = MLKEM768_SECRETKEYBYTES;

    if (out == NULL)
        return 1;

    if (ctx->key == NULL
            || ctx->key->keytype != MLKEM_KEY_TYPE_768
            || ctx->key->pubkey == NULL
            || secret == NULL)
        return 0;

    if (!mlkem768_ref_enc((uint8_t *)out, (uint8_t *)secret, ctx->key->pubkey))
        return 0;

    return 1;
}

static int mlkem_decapsulate(void *vctx, unsigned char *out, size_t *outlen,
                             const unsigned char *in, size_t inlen)
{
    PROV_MLKEM_CTX *ctx = (PROV_MLKEM_CTX *)vctx;

    if (outlen != NULL)
        *outlen = MLKEM768_SECRETKEYBYTES;

    if (out == NULL)
        return 1;

    if (ctx->key == NULL
            || ctx->key->keytype != MLKEM_KEY_TYPE_768
            || ctx->key->seckey == NULL
            || in == NULL)
        return 0;

    if (inlen != MLKEM768_CIPHERTEXTBYTES)
        return 0;

    if (!mlkem768_ref_dec(out, in, ctx->key->seckey))
        return 0;

    return 1;
}

const OSSL_DISPATCH ossl_mlkem_asym_key_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))mlkem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (void (*)(void))mlkem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))mlkem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (void (*)(void))mlkem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))mlkem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))mlkem_freectx },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS,
      (void (*)(void))mlkem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
      (void (*)(void))mlkem_settable_ctx_params },
    OSSL_DISPATCH_END
};
