/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "prov/hybrid_pkey.h"
#include "hybrid_kem_local.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include "crypto/evp.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "internal/e_os.h"
#include "internal/refcount.h"

HYBRID_PKEY_CTX *ossl_hybrid_kem_newctx(void *provctx,
                                        const HYBRID_ALG_INFO *info)
{
    if (!ossl_prov_is_running())
        return NULL;

    /*
     * Nothing really to do here because the PKEY_CTXs cannot be
     * allocated until the init call because we don't have the associated
     * PKEY that it's being build against.
     */
    return ossl_hybrid_pkey_ctx_alloc(PROV_LIBCTX_OF(provctx), info);
}

void *ossl_hybrid_kem_dupctx(void *vctx)
{
    HYBRID_PKEY_CTX *src = (HYBRID_PKEY_CTX *)vctx;
    HYBRID_PKEY_CTX *dest = OPENSSL_zalloc(sizeof(*src));
    unsigned int i;

    if (dest == NULL)
        return NULL;

    dest->libctx = src->libctx;
    dest->info = src->info;

    if (src->propq != NULL
            && (dest->propq = OPENSSL_strdup(src->propq)) == NULL)
        goto err;

    for (i = 0; i < src->info->num_algs; i++)
        if (src->ctxs[i] != NULL
                && (dest->ctxs[i] = EVP_PKEY_CTX_dup(src->ctxs[i])) == NULL)
            goto err;
    return dest;
 err:
    ossl_hybrid_pkey_ctx_free(dest);
    return NULL;
}

int ossl_hybrid_kem_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    HYBRID_PKEY_CTX *ctx = (HYBRID_PKEY_CTX *)vctx;

    return ossl_hybrid_get_ctx_params(ctx, params);
}

int ossl_hybrid_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    HYBRID_PKEY_CTX *ctx = (HYBRID_PKEY_CTX *)vctx;

    return ossl_hybrid_set_ctx_params(ctx, params);
}

static int hybrid_kem_init(HYBRID_PKEY_CTX *ctx, HYBRID_PKEY *peer,
                           const OSSL_PARAM params[],
                           int (*initf)(EVP_PKEY_CTX *ctx,
                                        const OSSL_PARAM params[]))
{
    unsigned int i;

    if (!ossl_prov_is_running())
        return 0;

    if (ctx == NULL)
        return 0;

    for (i = 0; i < ctx->info->num_algs; i++) {
        EVP_PKEY_CTX_free(ctx->ctxs[i]);
        ctx->ctxs[i] = EVP_PKEY_CTX_new_from_pkey(ctx->libctx, peer->keys[i],
                                                  ctx->propq);
        if (ctx->ctxs[i] == NULL)
            return 0;
        if (!(*initf)(ctx->ctxs[i], params)) {
            ERR_raise_data(ERR_LIB_PROV, ERR_R_INIT_FAIL,
                           "%s", ctx->info->alg[i].name);
            return 0;
        }
    }
    return ossl_hybrid_set_ctx_params(ctx, params);
}

int ossl_hybrid_kem_encapsulate_init(void *vctx, void *vpeer,
                                     const OSSL_PARAM params[])
{
    HYBRID_PKEY_CTX *ctx = (HYBRID_PKEY_CTX *)vctx;
    HYBRID_PKEY *peer = (HYBRID_PKEY *)vpeer;

    return hybrid_kem_init(ctx, peer, params, &EVP_PKEY_encapsulate_init);
}

int ossl_hybrid_kem_decapsulate_init(void *vctx, void *vpeer,
                                     const OSSL_PARAM params[])
{
    HYBRID_PKEY_CTX *ctx = (HYBRID_PKEY_CTX *)vctx;
    HYBRID_PKEY *peer = (HYBRID_PKEY *)vpeer;

    return hybrid_kem_init(ctx, peer, params, &EVP_PKEY_decapsulate_init);
}

static int hybrid_kem_auth_init(HYBRID_PKEY_CTX *ctx,
                                HYBRID_PKEY *key, HYBRID_PKEY *auth,
                                const OSSL_PARAM params[],
                                int (*initf)(EVP_PKEY_CTX *ctx,
                                             EVP_PKEY *auth,
                                             const OSSL_PARAM params[]))
{
    unsigned int i;

    if (!ossl_prov_is_running())
        return 0;

    for (i = 0; i < ctx->info->num_algs; i++) {
        EVP_PKEY_CTX_free(ctx->ctxs[i]);
        ctx->ctxs[i] = EVP_PKEY_CTX_new_from_pkey(ctx->libctx,
                                                  key->keys[i], key->propq);
        if (ctx->ctxs[i] == NULL || !(*initf)(ctx->ctxs[i], auth->keys[i], params))
            return 0;
    }
    return ossl_hybrid_set_ctx_params(ctx, params);
}

int ossl_hybrid_kem_auth_encapsulate_init(void *vctx, void *vkey,
                                          void *vauthpriv,
                                          const OSSL_PARAM params[])
{
    HYBRID_PKEY_CTX *ctx = (HYBRID_PKEY_CTX *)vctx;
    HYBRID_PKEY *key = (HYBRID_PKEY *)vkey;
    HYBRID_PKEY *authpriv = (HYBRID_PKEY *)vauthpriv;

    return hybrid_kem_auth_init(ctx, key, authpriv, params,
                                &EVP_PKEY_auth_encapsulate_init);
}

int ossl_hybrid_kem_auth_decapsulate_init(void *vctx, void *vkey,
                                          void *vauthpub,
                                          const OSSL_PARAM params[])
{
    HYBRID_PKEY_CTX *ctx = (HYBRID_PKEY_CTX *)vctx;
    HYBRID_PKEY *key = (HYBRID_PKEY *)vkey;
    HYBRID_PKEY *authpub = (HYBRID_PKEY *)vauthpub;

    return hybrid_kem_auth_init(ctx, key, authpub, params,
                                &EVP_PKEY_auth_decapsulate_init);
}

int ossl_hybrid_kem_encapsulate(void *vctx, unsigned char *enc, size_t *enclen,
                                unsigned char *secret, size_t *secretlen)
{
    HYBRID_PKEY_CTX *ctx = (HYBRID_PKEY_CTX *)vctx;
    size_t ciphertext_bytes, shared_secret_bytes;
    unsigned int i;

    if (ctx->pubkey_length == 0)
        return 0;

    if (secretlen == NULL || enclen == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER,
                       "secretlen is NULL");
        return 0;
    }
    if (enc == NULL) {
        *enclen = ctx->ciphertext_bytes;
        *secretlen = ctx->shared_secret_bytes;
        return 1;
    }
    if (secret == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER,
                       "secret is NULL");
        return 0;
    }
    if (*secretlen < ctx->shared_secret_bytes) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH, "*secretlen too small");
        return 0;
    }
    if (*enclen < ctx->ciphertext_bytes) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH, "*enclen too small");
        return 0;
    }

    /* Encapsulate */
    for (i = 0; i < ctx->info->num_algs; i++) {
        ciphertext_bytes = ctx->info->alg[i].ciphertext_bytes;
        shared_secret_bytes = ctx->info->alg[i].shared_secret_bytes;
        if (!EVP_PKEY_encapsulate(ctx->ctxs[i], enc, &ciphertext_bytes,
                                  secret, &shared_secret_bytes))
            return 0;
        if (ciphertext_bytes != ctx->info->alg[i].ciphertext_bytes
                || shared_secret_bytes != ctx->info->alg[i].shared_secret_bytes) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH,
                           "secretlen or enclen changed");
            return 0;
        }
        secret += shared_secret_bytes;
        enc += ciphertext_bytes;
    }

    /* Set outputs */
    *enclen = ctx->ciphertext_bytes;
    *secretlen = ctx->shared_secret_bytes;
    return 1;
}

int ossl_hybrid_kem_decapsulate(void *vctx,
                                unsigned char *secret, size_t *secretlen,
                                const unsigned char *enc, size_t enclen)
{
    HYBRID_PKEY_CTX *ctx = (HYBRID_PKEY_CTX *)vctx;
    size_t shared_secret_bytes;
    unsigned int i;

    if (ctx->pubkey_length == 0)
        return 0;

    if (secretlen == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER,
                       "secretlen is NULL");
        return 0;
    }
    if (secret == NULL) {
        *secretlen = ctx->shared_secret_bytes;
        return 1;
    }
    if (enc == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER,
                       "enc is NULL");
        return 0;
    }
    if (*secretlen < ctx->shared_secret_bytes) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH, "*secretlen too small");
        return 0;
    }
    if (enclen != ctx->ciphertext_bytes) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY,
                       "Invalid enc public key");
        return 0;
    }

    /* Decapsulate */
    for (i = 0; i < ctx->info->num_algs; i++) {
        shared_secret_bytes = ctx->info->alg[i].shared_secret_bytes;
        if (!EVP_PKEY_decapsulate(ctx->ctxs[i], secret, &shared_secret_bytes,
                                  enc, ctx->info->alg[i].ciphertext_bytes))
            return 0;
        if (shared_secret_bytes != ctx->info->alg[i].shared_secret_bytes) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH,
                           "secretlen changed");
            return 0;
        }
        secret += shared_secret_bytes;
        enc += ctx->info->alg[i].ciphertext_bytes;
    }
    *secretlen = ctx->shared_secret_bytes;
    return 1;
}
