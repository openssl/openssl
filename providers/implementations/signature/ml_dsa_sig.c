/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include <assert.h>
#include <string.h> /* memset */
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/proverr.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "crypto/ml_dsa.h"

#define ML_DSA_ENTROPY_LEN 32

#define ML_DSA_MESSAGE_ENCODE_RAW  0
#define ML_DSA_MESSAGE_ENCODE_PURE 1

static OSSL_FUNC_signature_sign_message_init_fn ml_dsa_sign_msg_init;
static OSSL_FUNC_signature_sign_fn ml_dsa_sign;
static OSSL_FUNC_signature_verify_message_init_fn ml_dsa_verify_msg_init;
static OSSL_FUNC_signature_verify_fn ml_dsa_verify;
static OSSL_FUNC_signature_freectx_fn ml_dsa_freectx;
static OSSL_FUNC_signature_set_ctx_params_fn ml_dsa_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn ml_dsa_settable_ctx_params;

typedef struct {
    ML_DSA_KEY *key;
    ML_DSA_CTX *ctx;
    uint8_t context_string[ML_DSA_MAX_CONTEXT_STRING_LEN];
    size_t context_string_len;
    uint8_t test_entropy[ML_DSA_ENTROPY_LEN];
    size_t test_entropy_len;
    int msg_encode;
    int deterministic;
    OSSL_LIB_CTX *libctx;
    char *propq;
} PROV_ML_DSA_CTX;

static void ml_dsa_freectx(void *vctx)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;

    OPENSSL_free(ctx->propq);
    ossl_ml_dsa_ctx_free(ctx->ctx);
    ossl_ml_dsa_key_free(ctx->key);
    OPENSSL_cleanse(ctx->test_entropy, ctx->test_entropy_len);
    OPENSSL_free(ctx);
}

static void *ml_dsa_newctx(void *provctx, const char *alg, const char *propq)
{
    PROV_ML_DSA_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(PROV_ML_DSA_CTX));
    if (ctx == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL)
        goto err;
    ctx->ctx = ossl_ml_dsa_ctx_new(alg, ctx->libctx, ctx->propq);
    if (ctx->ctx == NULL)
        goto err;
    ctx->msg_encode = ML_DSA_MESSAGE_ENCODE_PURE;

    return ctx;
 err:
    ml_dsa_freectx(ctx);
    return NULL;
}

static int ml_dsa_signverify_msg_init(void *vctx, void *vkey,
                                      const OSSL_PARAM params[], int operation,
                                      const char *desc)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;
    ML_DSA_KEY *key = vkey;

    if (!ossl_prov_is_running()
            || ctx == NULL)
        return 0;

    if (vkey == NULL && ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (key != NULL) {
        if (!ossl_ml_dsa_key_type_matches(ctx->ctx, key))
            return 0;
        if (!ossl_ml_dsa_key_up_ref(vkey))
            return 0;
        ossl_ml_dsa_key_free(ctx->key);
        ctx->key = vkey;
    }

    if (!ml_dsa_set_ctx_params(ctx, params))
        return 0;
    return 1;
}

static int ml_dsa_sign_msg_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return ml_dsa_signverify_msg_init(vctx, vkey, params,
                                      EVP_PKEY_OP_SIGN, "ML_DSA Sign Init");
}

static int ml_dsa_sign(void *vctx, unsigned char *sig, size_t *siglen,
                       size_t sigsize, const unsigned char *msg, size_t msg_len)
{
    int ret = 0;
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;
    uint8_t rand_tmp[ML_DSA_ENTROPY_LEN], *rnd = NULL;

    if (!ossl_prov_is_running())
        return 0;

    if (sig != NULL) {
        if (ctx->test_entropy_len != 0) {
            rnd = ctx->test_entropy;
        } else {
            rnd = rand_tmp;

            if (ctx->deterministic == 1)
                memset(rnd, 0, sizeof(rand_tmp));
            else if (RAND_priv_bytes_ex(ctx->libctx, rnd, sizeof(rand_tmp), 0) <= 0)
                return 0;
        }
    }
    ret = ossl_ml_dsa_sign(ctx->ctx, ctx->key, msg, msg_len,
                           ctx->context_string, ctx->context_string_len,
                           rnd, sizeof(rand_tmp), ctx->msg_encode,
                           sig, siglen, sigsize);
    if (rnd != ctx->test_entropy)
        OPENSSL_cleanse(rand_tmp, sizeof(rand_tmp));
    return ret;
}

static int ml_dsa_verify_msg_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return ml_dsa_signverify_msg_init(vctx, vkey, params, EVP_PKEY_OP_VERIFY,
                                   "ML_DSA Verify Init");
}

static int ml_dsa_verify(void *vctx, const unsigned char *sig, size_t siglen,
                         const unsigned char *msg, size_t msg_len)
{
    PROV_ML_DSA_CTX *ctx = (PROV_ML_DSA_CTX *)vctx;

    if (!ossl_prov_is_running())
        return 0;
    return ossl_ml_dsa_verify(ctx->ctx, ctx->key, msg, msg_len,
                              ctx->context_string, ctx->context_string_len,
                              ctx->msg_encode, sig, siglen);
}

static int ml_dsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_ML_DSA_CTX *pctx = (PROV_ML_DSA_CTX *)vctx;
    const OSSL_PARAM *p;

    if (pctx == NULL)
        return 0;
    if (ossl_param_is_empty(params))
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p != NULL) {
        void *vp = pctx->context_string;

        if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(pctx->context_string),
                                         &(pctx->context_string_len))) {
            pctx->context_string_len = 0;
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY);
    if (p != NULL) {
        void *vp = pctx->test_entropy;

        if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(pctx->test_entropy),
                                         &(pctx->test_entropy_len))
                || pctx->test_entropy_len != sizeof(pctx->test_entropy)) {
            pctx->test_entropy_len = 0;
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC);
    if (p != NULL && !OSSL_PARAM_get_int(p, &pctx->deterministic))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING);
    if (p != NULL && !OSSL_PARAM_get_int(p, &pctx->msg_encode))
        return 0;
    return 1;
}

static const OSSL_PARAM *ml_dsa_settable_ctx_params(void *vctx,
                                                    ossl_unused void *provctx)
{
    static const OSSL_PARAM settable_ctx_params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, NULL, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, 0),
        OSSL_PARAM_END
    };

    return settable_ctx_params;
}

#define MAKE_SIGNATURE_FUNCTIONS(alg, fn)                                      \
    static OSSL_FUNC_signature_newctx_fn ml_dsa_##fn##_newctx;                 \
    static void *ml_dsa_##fn##_newctx(void *provctx, const char *propq)        \
    {                                                                          \
        return ml_dsa_newctx(provctx, alg, propq);                             \
    }                                                                          \
    const OSSL_DISPATCH ossl_ml_dsa_##fn##_signature_functions[] = {           \
        { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))ml_dsa_##fn##_newctx },  \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,                               \
          (void (*)(void))ml_dsa_sign_msg_init },                              \
        { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ml_dsa_sign },             \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,                             \
          (void (*)(void))ml_dsa_verify_msg_init },                            \
        { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))ml_dsa_verify },         \
        { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))ml_dsa_freectx },       \
        { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,                                  \
          (void (*)(void))ml_dsa_set_ctx_params },                             \
        { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,                             \
          (void (*)(void))ml_dsa_settable_ctx_params },                        \
        OSSL_DISPATCH_END                                                      \
    }

MAKE_SIGNATURE_FUNCTIONS("ML-DSA-65", 65);
