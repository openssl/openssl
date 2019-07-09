/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/ciphers/ciphercommon.h"
#include "internal/ciphers/cipher_aead.h"
#include "internal/provider_algs.h"
#include "internal/providercommonerr.h"
#include "include/crypto/siv.h"

#define SIV_FLAGS AEAD_FLAGS

typedef struct prov_siv_ctx_st {
    unsigned int mode;       /* The mode that we are using */
    unsigned int enc : 1;    /* Set to 1 if we are encrypting or 0 otherwise */
    uint64_t flags;
    size_t keylen;           /* The input keylength (twice the alg key length) */
    size_t taglen;           /* the taglen is the same as the sivlen */
    SIV128_CONTEXT siv;
    EVP_CIPHER *ctr;        /* These are fetched - so we need to free them */
    EVP_CIPHER *cbc;
} PROV_AES_SIV_CTX;

static int aes_siv_init_key(void *vctx, const unsigned char *key, size_t keylen)
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;
    SIV128_CONTEXT *sctx = &ctx->siv;
    size_t klen  = keylen / 2;

    if (key == NULL)
        return 1;

    switch (klen) {
    case 16:
        ctx->cbc = EVP_CIPHER_fetch(NULL, "AES-128-CBC", "");
        ctx->ctr = EVP_CIPHER_fetch(NULL, "AES-128-CTR", "");
        break;
    case 24:
        ctx->cbc = EVP_CIPHER_fetch(NULL, "AES-192-CBC", "");
        ctx->ctr = EVP_CIPHER_fetch(NULL, "AES-192-CTR", "");
        break;
    case 32:
        ctx->cbc = EVP_CIPHER_fetch(NULL, "AES-256-CBC", "");
        ctx->ctr = EVP_CIPHER_fetch(NULL, "AES-256-CTR", "");
        break;
    default:
        return 0;
    }

    /*
     * klen is the length of the underlying cipher, not the input key,
     * which should be twice as long
     */
    return CRYPTO_siv128_init(sctx, key, klen, ctx->cbc, ctx->ctr);
}

static void *aes_siv_newctx(void *provctx, size_t keybits, unsigned int mode,
                            uint64_t flags)
{
    PROV_AES_SIV_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->taglen = SIV_LEN;
        ctx->mode = mode;
        ctx->flags = flags;
        ctx->keylen = keybits / 8;
    }
    return ctx;
}

static void aes_siv_freectx(void *vctx)
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;

    if (ctx != NULL) {
        SIV128_CONTEXT *sctx = &ctx->siv;

        CRYPTO_siv128_cleanup(sctx);
        EVP_CIPHER_free(ctx->cbc);
        EVP_CIPHER_free(ctx->ctr);
        OPENSSL_clear_free(ctx,  sizeof(*ctx));
    }
}

static int siv_init(void *vctx, const unsigned char *key, size_t keylen,
                    const unsigned char *iv, size_t ivlen, int enc)
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;

    ctx->enc = enc;

    if (iv != NULL)
        return 0;

    if (key != NULL) {
        if (keylen != ctx->keylen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        return aes_siv_init_key(ctx, key, ctx->keylen);
    }
    return 1;
}

static int siv_einit(void *vctx, const unsigned char *key, size_t keylen,
                     const unsigned char *iv, size_t ivlen)
{
    return siv_init(vctx, key, keylen, iv, ivlen, 1);
}

static int siv_dinit(void *vctx, const unsigned char *key, size_t keylen,
                     const unsigned char *iv, size_t ivlen)
{
    return siv_init(vctx, key, keylen, iv, ivlen, 0);
}

static int aes_siv_cipher(void *vctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;
    SIV128_CONTEXT *sctx = &ctx->siv;

    /* EncryptFinal or DecryptFinal */
    if (in == NULL)
        return CRYPTO_siv128_finish(sctx) == 0;

    /* Deal with associated data */
    if (out == NULL)
        return (CRYPTO_siv128_aad(sctx, in, len) == 1);

    if (ctx->enc)
        return CRYPTO_siv128_encrypt(sctx, in, out, len) > 0;

    return CRYPTO_siv128_decrypt(sctx, in, out, len) > 0;
}

static int siv_cipher(void *vctx, unsigned char *out, size_t *outl,
                      size_t outsize, const unsigned char *in, size_t inl)
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return -1;
    }

    if (aes_siv_cipher(ctx, out, in, inl) <= 0)
        return -1;

    *outl = inl;
    return 1;
}

static int siv_stream_update(void *vctx, unsigned char *out, size_t *outl,
                             size_t outsize, const unsigned char *in,
                             size_t inl)
{
    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return -1;
    }

    if (aes_siv_cipher(vctx, out, in, inl) <= 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return -1;
    }
    if (outl != NULL)
        *outl = inl;
    return 1;
}

static int siv_stream_final(void *vctx, unsigned char *out, size_t *outl,
                            size_t outsize)
{
    int i;

    i = aes_siv_cipher(vctx, out, NULL, 0);
    if (i <= 0)
        return 0;

    *outl = 0;
    return 1;
}

static int aes_siv_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;
    SIV128_CONTEXT *sctx = &ctx->siv;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL && p->data_type == OSSL_PARAM_OCTET_STRING) {
        if (!ctx->enc
            || p->data_size != ctx->taglen
            || !OSSL_PARAM_set_octet_string(p, &sctx->tag.byte, ctx->taglen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->taglen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

static const OSSL_PARAM aes_siv_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_SPEED, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *aes_siv_gettable_ctx_params(void)
{
    return aes_siv_known_gettable_ctx_params;
}

static int aes_siv_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;
    SIV128_CONTEXT *sctx = &ctx->siv;
    const OSSL_PARAM *p;
    unsigned int speed = 0;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (ctx->enc)
            return 1;
        if (!CRYPTO_siv128_set_tag(sctx, p->data, p->data_size))
            return 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_SPEED);
    if (p != NULL && OSSL_PARAM_get_uint(p, &speed)) {
        CRYPTO_siv128_speed(sctx, (int)speed);
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t keylen;

        if (!OSSL_PARAM_get_size_t(p, &keylen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        /* The key length can not be modified */
        if (keylen != ctx->keylen)
            return 0;
    }
    return 1;
}

static const OSSL_PARAM aes_siv_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_SPEED, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *aes_siv_settable_ctx_params(void)
{
    return aes_siv_known_settable_ctx_params;
}

#define IMPLEMENT_cipher(alg, lc, UCMODE, flags, kbits, blkbits, ivbits)       \
static OSSL_OP_cipher_get_params_fn alg##_##kbits##_##lc##_get_params;         \
static int alg##_##kbits##_##lc##_get_params(OSSL_PARAM params[])              \
{                                                                              \
    return cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE,         \
                                     flags, 2*kbits, blkbits, ivbits);         \
}                                                                              \
static OSSL_OP_cipher_newctx_fn alg##kbits##lc##_newctx;                       \
static void * alg##kbits##lc##_newctx(void *provctx)                           \
{                                                                              \
    return alg##_##lc##_newctx(provctx, 2*kbits, EVP_CIPH_##UCMODE##_MODE, flags);\
}                                                                              \
const OSSL_DISPATCH alg##kbits##lc##_functions[] = {                           \
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))alg##kbits##lc##_newctx },      \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))alg##_##lc##_freectx },        \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) lc##_einit },            \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void)) lc##_dinit },            \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) lc##_stream_update },          \
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void)) lc##_stream_final },            \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void)) lc##_cipher },                 \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void)) alg##_##kbits##_##lc##_get_params },                    \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))cipher_generic_gettable_params },                        \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void)) alg##_##lc##_get_ctx_params },                          \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void)) alg##_##lc##_gettable_ctx_params },                     \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void)) alg##_##lc##_set_ctx_params },                          \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
      (void (*)(void)) alg##_##lc##_settable_ctx_params },                     \
    { 0, NULL }                                                                \
};

IMPLEMENT_cipher(aes, siv, SIV, SIV_FLAGS, 128, 8, 0)
IMPLEMENT_cipher(aes, siv, SIV, SIV_FLAGS, 192, 8, 0)
IMPLEMENT_cipher(aes, siv, SIV, SIV_FLAGS, 256, 8, 0)
