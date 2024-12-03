/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "ml_dsa_local.h"
#include "ml_dsa_params.h"

static EVP_MD_CTX *md_ctx_new(EVP_MD *md)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL)
        return NULL;

    if (EVP_DigestInit_ex2(ctx, md, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

/**
 * @brief Create a ML_DSA_CTX that contains parameters, and pre-fetched hash
 * related objects for a ML-DSA algorithm. This context is passed
 * to many ML-DSA related functions.
 *
 * @param alg An ML-DSA algorithm name such as "ML-DSA-65"
 * @param lib_ctx A library context used for fetching. Can be NULL
 * @param propq A property query to use for algorithm fetching. Can be NULL.
 *
 * @returns The created ML_DSA_CTX object or NULL on failure.
 */
ML_DSA_CTX *ossl_ml_dsa_ctx_new(const char *alg,
                                OSSL_LIB_CTX *lib_ctx, const char *propq)
{
    ML_DSA_CTX *ret;
    EVP_MD *shake128_md = NULL;
    EVP_MD *shake256_md = NULL;
    const ML_DSA_PARAMS *params = ossl_ml_dsa_params_get(alg);

    if (params == NULL)
        return NULL;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL)
        return NULL;

    shake128_md = EVP_MD_fetch(lib_ctx, "SHAKE-128", propq);
    shake256_md = EVP_MD_fetch(lib_ctx, "SHAKE-256", propq);
    if (shake128_md == NULL || shake256_md == NULL)
        goto err;
    ret->g_ctx = md_ctx_new(shake128_md);
    ret->h_ctx = md_ctx_new(shake256_md);
    EVP_MD_free(shake128_md);
    EVP_MD_free(shake256_md);
    if (ret->h_ctx == NULL || ret->g_ctx == NULL)
        goto err;
    ret->params = params;
    return ret;
err:
    ossl_ml_dsa_ctx_free(ret);
    return NULL;
}

/**
 * @brief Destroy a ML_DSA_CTX
 *
 * @param ctx The ML_DSA_CTX object to destroy.
 */
void ossl_ml_dsa_ctx_free(ML_DSA_CTX *ctx)
{
    EVP_MD_CTX_free(ctx->g_ctx);
    EVP_MD_CTX_free(ctx->h_ctx);
    OPENSSL_free(ctx);
}
