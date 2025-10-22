/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stddef.h>
#include <openssl/crypto.h>
#include "slh_dsa_local.h"
#include "slh_dsa_key.h"
#include <openssl/evp.h>

/**
 * @brief Create a SLH_DSA_HASH_CTX that contains parameters, functions, and
 * pre-fetched HASH related objects for a SLH_DSA algorithm.This context is passed
 * to most SLH-DSA functions.
 *
 * @param alg An SLH-DSA algorithm name such as "SLH-DSA-SHA2-128s"
 * @param lib_ctx A library context used for fetching. Can be NULL
 * @param propq A propqery query to use for algorithm fetching. Can be NULL.
 *
 * @returns The created SLH_DSA_HASH_CTX object or NULL on failure.
 */
SLH_DSA_HASH_CTX *ossl_slh_dsa_hash_ctx_new(const SLH_DSA_KEY *key)
{
    SLH_DSA_HASH_CTX *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        return NULL;

    ret->key = key;
    ret->sha_ctx = EVP_MD_CTX_new();
    if (ret->sha_ctx == NULL)
        goto err;
    if (EVP_DigestInit_ex2(ret->sha_ctx, key->md_sha, NULL) != 1)
        goto err;
    ret->sha_ctx_pkseed = EVP_MD_CTX_dup(ret->sha_ctx);
    if (ret->sha_ctx_pkseed == NULL)
        goto err;
    if (key->md_sha512 != NULL) {
        ret->sha512_ctx = EVP_MD_CTX_new();
        if (ret->sha512_ctx == NULL)
            goto err;
        if (EVP_DigestInit_ex2(ret->sha512_ctx, key->md_sha512, NULL) != 1)
            goto err;
    }
    if (key->hmac != NULL) {
        ret->hmac_ctx = EVP_MAC_CTX_new(key->hmac);
        if (ret->hmac_ctx == NULL)
            goto err;
    }
    if (key->pub != NULL
            && !ossl_slh_dsa_hash_ctx_prehash_pk_seed(ret, SLH_DSA_PK_SEED(key), key->params->n))
        goto err;
    return ret;
 err:
    ossl_slh_dsa_hash_ctx_free(ret);
    return NULL;
}

/**
 * @brief Cache the pk seed.
 * SLH_DSA performs a large number of hash operations that consist of either
 *  SHAKE256(PK.seed || .. ) OR
 *  SHA256(PK.seed || toByte(0, 64 - n) || ...)
 * So cache this value and reuse it as the starting point for many hash functions.
 */
int ossl_slh_dsa_hash_ctx_prehash_pk_seed(SLH_DSA_HASH_CTX *ctx,
                                          const uint8_t *pkseed, size_t n)
{
    return ctx->key->hash_func->prehash_pk_seed(ctx, pkseed, n);
}

/**
 * @brief Duplicate a SLH_DSA_HASH_CTX
 *
 * @param ctx The SLH_DSA_HASH_CTX object to duplicate.
 */
SLH_DSA_HASH_CTX *ossl_slh_dsa_hash_ctx_dup(const SLH_DSA_HASH_CTX *src)
{
    SLH_DSA_HASH_CTX *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        return NULL;

    ret->hmac_digest_used = src->hmac_digest_used;
    /* Note that the key is not ref counted, since it does not own the key */
    ret->key = src->key;

    if (src->sha_ctx != NULL
            && (ret->sha_ctx = EVP_MD_CTX_dup(src->sha_ctx)) == NULL)
        goto err;
    if (src->sha_ctx_pkseed != NULL
            && (ret->sha_ctx_pkseed = EVP_MD_CTX_dup(src->sha_ctx_pkseed)) == NULL)
        goto err;
    if (src->sha512_ctx != NULL
            && (ret->sha512_ctx = EVP_MD_CTX_dup(src->sha512_ctx)) == NULL)
                goto err;
    if (src->hmac_ctx != NULL
            && (ret->hmac_ctx = EVP_MAC_CTX_dup(src->hmac_ctx)) == NULL)
        goto err;
    return ret;
 err:
    ossl_slh_dsa_hash_ctx_free(ret);
    return NULL;
}

/**
 * @brief Destroy a SLH_DSA_HASH_CTX
 *
 * @param ctx The SLH_DSA_HASH_CTX object to destroy.
 */
void ossl_slh_dsa_hash_ctx_free(SLH_DSA_HASH_CTX *ctx)
{
    if (ctx == NULL)
        return;
    EVP_MD_CTX_free(ctx->sha_ctx);
    EVP_MD_CTX_free(ctx->sha_ctx_pkseed);
    EVP_MD_CTX_free(ctx->sha512_ctx);
    EVP_MAC_CTX_free(ctx->hmac_ctx);
    OPENSSL_free(ctx);
}
