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
#include "crypto/ml_kem.h"
#include "prov/provider_ctx.h"
#include "prov/implementations.h"
#include "prov/securitycheck.h"
#include "prov/providercommon.h"

static OSSL_FUNC_kem_newctx_fn ml_kem_newctx;
static OSSL_FUNC_kem_freectx_fn ml_kem_freectx;
static OSSL_FUNC_kem_encapsulate_init_fn ml_kem_encapsulate_init;
static OSSL_FUNC_kem_encapsulate_fn ml_kem_encapsulate;
static OSSL_FUNC_kem_decapsulate_init_fn ml_kem_decapsulate_init;
static OSSL_FUNC_kem_decapsulate_fn ml_kem_decapsulate;
static OSSL_FUNC_kem_set_ctx_params_fn ml_kem_set_ctx_params;
static OSSL_FUNC_kem_settable_ctx_params_fn ml_kem_settable_ctx_params;

typedef struct {
    OSSL_LIB_CTX *libctx;
    ML_KEM_KEY *key;
    uint8_t entropy_buf[ML_KEM_RANDOM_BYTES];
    uint8_t *entropy;
} PROV_ML_KEM_CTX;

static void *ml_kem_newctx(void *provctx)
{
    PROV_ML_KEM_CTX *ctx;

    if ((ctx = OPENSSL_malloc(sizeof(*ctx))) == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->key = NULL;
    ctx->entropy = NULL;
    return ctx;
}

static void ml_kem_freectx(void *vctx)
{
    PROV_ML_KEM_CTX *ctx = vctx;

    if (ctx->entropy != NULL)
        OPENSSL_cleanse(ctx->entropy, ML_KEM_RANDOM_BYTES);
    OPENSSL_free(ctx);
}

static int ml_kem_init(void *vctx, int unused_op, void *key,
                       const OSSL_PARAM params[])
{
    PROV_ML_KEM_CTX *ctx = vctx;

    if (!ossl_prov_is_running())
        return 0;
    ctx->key = key;
    return ml_kem_set_ctx_params(vctx, params);
}

static int ml_kem_encapsulate_init(void *vctx, void *vkey,
                                   const OSSL_PARAM params[])
{
    ML_KEM_KEY *key = vkey;

    if (!ossl_ml_kem_have_pubkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    return ml_kem_init(vctx, EVP_PKEY_OP_ENCAPSULATE, key, params);
}

static int ml_kem_decapsulate_init(void *vctx, void *vkey,
                                   const OSSL_PARAM params[])
{
    ML_KEM_KEY *key = vkey;

    if (!ossl_ml_kem_have_prvkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    return ml_kem_init(vctx, EVP_PKEY_OP_DECAPSULATE, key, params);
}

static int ml_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_ML_KEM_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (ossl_param_is_empty(params))
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_IKME)) != NULL) {
        size_t len = ML_KEM_RANDOM_BYTES;

        ctx->entropy = ctx->entropy_buf;
        if (OSSL_PARAM_get_octet_string(p, (void **)&ctx->entropy,
                                        len, &len)
            && len == ML_KEM_RANDOM_BYTES)
            return 1;

        /* Possibly, but much less likely wrong type */
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
        ctx->entropy = NULL;
        return 0;
    }
    return 1;
}

static const OSSL_PARAM *ml_kem_settable_ctx_params(ossl_unused void *vctx,
                                                    ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_KEM_PARAM_IKME, NULL, 0),
        OSSL_PARAM_END
    };

    return params;
}

static int ml_kem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
                              unsigned char *secret, size_t *secretlen)
{
    PROV_ML_KEM_CTX *ctx = vctx;
    ML_KEM_KEY *key = ctx->key;
    const ML_KEM_VINFO *v;
    int ret = 0;

    if (!ossl_ml_kem_have_pubkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto end;
    }
    v = ossl_ml_kem_key_vinfo(key);

    if (out == NULL) {
        if (outlen == NULL && secretlen == NULL)
            return 0;
        if (outlen != NULL)
            *outlen = v->ctext_bytes;
        if (secretlen != NULL)
            *secretlen = ML_KEM_SHARED_SECRET_BYTES;
        return 1;
    }

    if (*secretlen < ML_KEM_SHARED_SECRET_BYTES) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH,
                       "short ML-KEM encapsulate shared secret");
        goto end;
    }
    if (*outlen < v->ctext_bytes) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH,
                       "short ML-KEM encapsulate ciphertext");
        goto end;
    }

    if (secret == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SECRET);
        goto end;
    }

    *secretlen = ML_KEM_SHARED_SECRET_BYTES;
    *outlen = v->ctext_bytes;
    if (ctx->entropy != NULL)
        ret = ossl_ml_kem_encap_seed(out, *outlen, secret, *secretlen,
                                      ctx->entropy, ML_KEM_RANDOM_BYTES, key);
    else
        ret = ossl_ml_kem_encap_rand(out, *outlen, secret, *secretlen, key);

  end:
    if (ctx->entropy != NULL) {
        OPENSSL_cleanse(ctx->entropy, ML_KEM_RANDOM_BYTES);
        ctx->entropy = NULL;
    }
    return ret;
}

static int ml_kem_decapsulate(void *vctx, unsigned char *out, size_t *outlen,
                              const unsigned char *in, size_t inlen)
{
    PROV_ML_KEM_CTX *ctx = vctx;
    ML_KEM_KEY *key = ctx->key;

    if (!ossl_ml_kem_have_prvkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    if (out == NULL) {
        if (outlen == NULL)
            return 0;
        *outlen = ML_KEM_SHARED_SECRET_BYTES;
        return 1;
    }

    if (*outlen < ML_KEM_SHARED_SECRET_BYTES) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH,
                       "short ML-KEM decapsulate shared secret");
        return 0;
    }

    /* ML-KEM decap handles incorrect ciphertext lengths internally */
    *outlen = ML_KEM_SHARED_SECRET_BYTES;
    return ossl_ml_kem_decap(out, *outlen, in, inlen, key);
}

typedef void (*func_ptr_t)(void);

const OSSL_DISPATCH ossl_ml_kem_asym_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (func_ptr_t) ml_kem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (func_ptr_t) ml_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (func_ptr_t) ml_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (func_ptr_t) ml_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (func_ptr_t) ml_kem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (func_ptr_t) ml_kem_freectx },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS, (func_ptr_t) ml_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (func_ptr_t) ml_kem_settable_ctx_params },
    OSSL_DISPATCH_END
};
