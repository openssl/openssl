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
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/proverr.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "crypto/slh_dsa.h"

#define SLH_DSA_MAX_ADD_RANDOM_LEN 32

#define SLH_DSA_MESSAGE_ENCODE_RAW  0
#define SLH_DSA_MESSAGE_ENCODE_PURE 1

static OSSL_FUNC_signature_sign_init_fn slh_sign_init;
static OSSL_FUNC_signature_sign_fn slh_sign;
static OSSL_FUNC_signature_verify_init_fn slh_verify_init;
static OSSL_FUNC_signature_verify_fn slh_verify;
static OSSL_FUNC_signature_freectx_fn slh_freectx;
static OSSL_FUNC_signature_set_ctx_params_fn slh_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn slh_settable_ctx_params;

typedef struct {
    SLH_DSA_KEY *key;
    SLH_DSA_CTX *ctx;
    uint8_t context_string[SLH_DSA_MAX_CONTEXT_STRING_LEN];
    size_t context_string_len;
    uint8_t add_random[SLH_DSA_MAX_ADD_RANDOM_LEN];
    size_t add_random_len;
    int msg_encode;
    int deterministic;
    OSSL_LIB_CTX *libctx;
    char *propq;
} PROV_SLH_DSA_CTX;

static void slh_freectx(void *vctx)
{
    PROV_SLH_DSA_CTX *ctx = (PROV_SLH_DSA_CTX *)vctx;

    OPENSSL_free(ctx->propq);
    ossl_slh_dsa_ctx_free(ctx->ctx);
    ossl_slh_dsa_key_free(ctx->key);
    OPENSSL_cleanse(ctx->add_random, ctx->add_random_len);
    OPENSSL_free(ctx);
}

static void *slh_newctx(void *provctx, const char *alg, const char *propq)
{
    PROV_SLH_DSA_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(PROV_SLH_DSA_CTX));
    if (ctx == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL)
        goto err;
    ctx->ctx = ossl_slh_dsa_ctx_new(alg, ctx->libctx, ctx->propq);
    if (ctx->ctx == NULL)
        goto err;
    ctx->msg_encode = SLH_DSA_MESSAGE_ENCODE_PURE;

    return ctx;
 err:
    slh_freectx(ctx);
    return NULL;
}

static int slh_signverify_init(void *vctx, void *vkey,
                               const OSSL_PARAM params[], int operation,
                               const char *desc)
{
    PROV_SLH_DSA_CTX *ctx = (PROV_SLH_DSA_CTX *)vctx;
    SLH_DSA_KEY *key = vkey;

    if (!ossl_prov_is_running()
            || ctx == NULL)
        return 0;

    if (vkey == NULL && ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (key != NULL) {
        if (!ossl_slh_dsa_key_type_matches(ctx->ctx, key))
            return 0;
        if (!ossl_slh_dsa_key_up_ref(vkey))
            return 0;
        ossl_slh_dsa_key_free(ctx->key);
        ctx->key = vkey;
    }

    if (!slh_set_ctx_params(ctx, params))
        return 0;
    return 1;
}

static int slh_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return slh_signverify_init(vctx, vkey, params,
                               EVP_PKEY_OP_SIGN, "SLH_DSA Sign Init");
}

static int slh_sign(void *vctx, unsigned char *sig, size_t *siglen,
                    size_t sigsize, const unsigned char *msg, size_t msg_len)
{
    int ret = 0;
    PROV_SLH_DSA_CTX *ctx = (PROV_SLH_DSA_CTX *)vctx;
    uint8_t add_rand[SLH_DSA_MAX_ADD_RANDOM_LEN], *opt_rand = NULL;
    size_t n = 0;

    if (!ossl_prov_is_running())
        return 0;
    if (ctx->add_random_len != 0) {
        opt_rand = ctx->add_random;
    } else if (ctx->deterministic == 0) {
        n = ossl_slh_dsa_key_get_n(ctx->key);
        if (RAND_priv_bytes_ex(ctx->libctx, add_rand, n, 0) <= 0)
            return 0;
        opt_rand = add_rand;
    }
    ret = ossl_slh_dsa_sign(ctx->ctx, ctx->key, msg, msg_len,
                            ctx->context_string, ctx->context_string_len,
                            opt_rand, ctx->msg_encode,
                            sig, siglen, sigsize);
    if (opt_rand != add_rand)
        OPENSSL_cleanse(opt_rand, n);
    return ret;
}

static int slh_verify_init(void *vctx, void *vkey,
                           const OSSL_PARAM params[])
{
    return slh_signverify_init(vctx, vkey, params, EVP_PKEY_OP_VERIFY,
                               "SLH_DSA Verify Init");
}

static int slh_verify(void *vctx,
                      const unsigned char *sig, size_t siglen,
                      const unsigned char *msg, size_t msg_len)
{
    PROV_SLH_DSA_CTX *ctx = (PROV_SLH_DSA_CTX *)vctx;

    if (!ossl_prov_is_running())
        return 0;
    return ossl_slh_dsa_verify(ctx->ctx, ctx->key, msg, msg_len,
                               ctx->context_string, ctx->context_string_len,
                               ctx->msg_encode, sig, siglen);

    return 0;
}

static int slh_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_SLH_DSA_CTX *pctx = (PROV_SLH_DSA_CTX *)vctx;
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
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_ADD_RANDOM);
    if (p != NULL) {
        void *vp = pctx->add_random;
        size_t n = ossl_slh_dsa_key_get_n(pctx->key);

        assert(n <= sizeof(pctx->add_random));
        if (!OSSL_PARAM_get_octet_string(p, &vp, n, &(pctx->add_random_len))
                || pctx->add_random_len != n) {
            pctx->add_random_len = 0;
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

static const OSSL_PARAM *slh_settable_ctx_params(void *vctx,
                                                 ossl_unused void *provctx)
{
    static const OSSL_PARAM settable_ctx_params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ADD_RANDOM, NULL, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, 0),
        OSSL_PARAM_END
    };

    return settable_ctx_params;
}

#define MAKE_SIGNATURE_FUNCTIONS(alg, fn)                                      \
static OSSL_FUNC_signature_newctx_fn slh_##fn##_newctx;                        \
static void *slh_##fn##_newctx(void *provctx, const char *propq)               \
{                                                                              \
    return slh_newctx(provctx, alg, propq);                                    \
}                                                                              \
const OSSL_DISPATCH ossl_slh_dsa_##fn##_signature_functions[] = {              \
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))slh_##fn##_newctx },         \
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))slh_sign_init },          \
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))slh_sign },                    \
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))slh_verify_init },      \
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))slh_verify },                \
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))slh_freectx },              \
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))slh_set_ctx_params },\
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,                                 \
      (void (*)(void))slh_settable_ctx_params },                               \
    OSSL_DISPATCH_END                                                          \
}

MAKE_SIGNATURE_FUNCTIONS("SLH-DSA-SHA2-128s", sha2_128s);
