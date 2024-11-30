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
#include "prov/ml_kem.h"

typedef struct {
    OSSL_LIB_CTX *libctx;
    const ossl_ml_kem_vinfo *vinfo;
    ML_KEM_PROVIDER_KEYPAIR *key;
    int op;
    uint8_t entropy_buf[ML_KEM_RANDOM_BYTES];
    uint8_t *entropy;
} PROV_ML_KEM_CTX;

static OSSL_FUNC_kem_newctx_fn ml_kem_512_newctx;
static OSSL_FUNC_kem_newctx_fn ml_kem_768_newctx;
static OSSL_FUNC_kem_newctx_fn ml_kem_1024_newctx;
static OSSL_FUNC_kem_freectx_fn ml_kem_freectx;
static OSSL_FUNC_kem_encapsulate_init_fn ml_kem_encapsulate_init;
static OSSL_FUNC_kem_encapsulate_fn ml_kem_encapsulate;
static OSSL_FUNC_kem_decapsulate_init_fn ml_kem_decapsulate_init;
static OSSL_FUNC_kem_decapsulate_fn ml_kem_decapsulate;
static OSSL_FUNC_kem_set_ctx_params_fn ml_kem_set_ctx_params;

typedef const ossl_ml_kem_vinfo *vinfo_t;

static void *ml_kem_newctx(void *provctx, vinfo_t v)
{
    PROV_ML_KEM_CTX *ctx;

    if (v == NULL
        || (ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->vinfo = v;
    return ctx;
}

static void ml_kem_freectx(void *vctx)
{
    PROV_ML_KEM_CTX *ctx = vctx;

    if (ctx->entropy)
        OPENSSL_cleanse(ctx->entropy, ML_KEM_RANDOM_BYTES);
    OPENSSL_free(ctx);
}

static int ml_kem_init(void *vctx, int op, void *key,
                       const OSSL_PARAM params[])
{
    PROV_ML_KEM_CTX *ctx = vctx;

    if (!ossl_prov_is_running())
        return 0;
    ctx->key = key;
    ctx->op = op;
    return ml_kem_set_ctx_params(vctx, params);
}

static int ml_kem_encapsulate_init(void *vctx, void *vkey,
                                   const OSSL_PARAM params[])
{
    ML_KEM_PROVIDER_KEYPAIR *key = vkey;

    if (key == NULL || !have_keys(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    return ml_kem_init(vctx, EVP_PKEY_OP_ENCAPSULATE, key, params);
}

static int ml_kem_decapsulate_init(void *vctx, void *vkey,
                                   const OSSL_PARAM params[])
{
    ML_KEM_PROVIDER_KEYPAIR *key = vkey;

    if (key == NULL || key->prvkey == NULL) {
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
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_IKME);
    if (p == NULL)
        return 1;

    /*
     * Treat wrong data type as promised, but missing.  Calling the
     * encapsulation "entropy" a "seed" should not be too confusing.
     */
    if (p->data_type != OSSL_PARAM_OCTET_STRING) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SEED);
        return 0;
    }
    if (p->data_size != ML_KEM_RANDOM_BYTES) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
        return 0;
    }

    ctx->entropy = ctx->entropy_buf;
    memcpy(ctx->entropy, p->data, ML_KEM_RANDOM_BYTES);
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
    ML_KEM_PROVIDER_KEYPAIR *key = ctx->key;
    vinfo_t v;
    int ret = 0;

    if (key == NULL || !have_keys(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        goto end;
    }
    v = key->vinfo;

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
    *outlen = key->vinfo->ctext_bytes;
    if (ctx->entropy != NULL)
        ret = ossl_ml_kem_vencap_seed(v, out, *outlen, secret, *secretlen,
                                      key->pubkey, key->prvkey, ctx->entropy,
                                      ML_KEM_RANDOM_BYTES, key->ctx);
    else
        ret = ossl_ml_kem_vencap_rand(v, out, *outlen, secret, *secretlen,
                                      key->pubkey, key->prvkey, key->ctx);

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
    ML_KEM_PROVIDER_KEYPAIR *key = ctx->key;
    vinfo_t v;

    if (key == NULL || key->prvkey == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    v = key->vinfo;

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
    return ossl_ml_kem_vdecap(v, out, *outlen, in, inlen, key->prvkey,
                              key->ctx);
}

#define DECLARE_VARIANT(bits) \
    static void *ml_kem_##bits##_newctx(void *provctx) \
    { \
        return ml_kem_newctx(provctx, ossl_ml_kem_##bits##_get_vinfo()); \
    } \
    const OSSL_DISPATCH ossl_ml_kem_##bits##_asym_kem_functions[] = { \
        { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))ml_kem_##bits##_newctx }, \
        { OSSL_FUNC_KEM_ENCAPSULATE_INIT, \
          (void (*)(void))ml_kem_encapsulate_init }, \
        { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))ml_kem_encapsulate }, \
        { OSSL_FUNC_KEM_DECAPSULATE_INIT, \
          (void (*)(void))ml_kem_decapsulate_init }, \
        { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))ml_kem_decapsulate }, \
        { OSSL_FUNC_KEM_FREECTX, (void (*)(void))ml_kem_freectx }, \
        { OSSL_FUNC_KEM_SET_CTX_PARAMS, \
          (void (*)(void))ml_kem_set_ctx_params }, \
        { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, \
          (void (*)(void))ml_kem_settable_ctx_params }, \
        OSSL_DISPATCH_END \
    }

DECLARE_VARIANT(512);
DECLARE_VARIANT(768);
DECLARE_VARIANT(1024);
