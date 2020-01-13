/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/* Dispatch functions for AES SIV mode */

/*
 * This file uses the low level AES functions (which are deprecated for
 * non-internal use) in order to implement provider AES ciphers.
 */
#include "internal/deprecated.h"

#include "cipher_aes_siv.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"
#include "prov/ciphercommon_aead.h"

#define siv_stream_update siv_cipher
#define SIV_FLAGS AEAD_FLAGS

static void *aes_siv_newctx(void *provctx, size_t keybits, unsigned int mode,
                            uint64_t flags)
{
    PROV_AES_SIV_CTX *ctx = OPENtls_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->taglen = SIV_LEN;
        ctx->mode = mode;
        ctx->flags = flags;
        ctx->keylen = keybits / 8;
        ctx->hw = PROV_CIPHER_HW_aes_siv(keybits);
    }
    return ctx;
}

static void aes_siv_freectx(void *vctx)
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;

    if (ctx != NULL) {
        ctx->hw->cleanup(ctx);
        OPENtls_clear_free(ctx,  sizeof(*ctx));
    }
}

static int siv_init(void *vctx, const unsigned char *key, size_t keylen,
                    const unsigned char *iv, size_t ivlen, int enc)
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;

    ctx->enc = enc;

    if (key != NULL) {
        if (keylen != ctx->keylen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        return ctx->hw->initkey(ctx, key, ctx->keylen);
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

static int siv_cipher(void *vctx, unsigned char *out, size_t *outl,
                      size_t outsize, const unsigned char *in, size_t inl)
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (ctx->hw->cipher(ctx, out, in, inl) <= 0)
        return 0;

    if (outl != NULL)
        *outl = inl;
    return 1;
}

static int siv_stream_final(void *vctx, unsigned char *out, size_t *outl,
                            size_t outsize)
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;

    if (!ctx->hw->cipher(vctx, out, NULL, 0))
        return 0;

    if (outl != NULL)
        *outl = 0;
    return 1;
}

static int aes_siv_get_ctx_params(void *vctx, Otls_PARAM params[])
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;
    SIV128_CONTEXT *sctx = &ctx->siv;
    Otls_PARAM *p;

    p = Otls_PARAM_locate(params, Otls_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL && p->data_type == Otls_PARAM_OCTET_STRING) {
        if (!ctx->enc
            || p->data_size != ctx->taglen
            || !Otls_PARAM_set_octet_string(p, &sctx->tag.byte, ctx->taglen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = Otls_PARAM_locate(params, Otls_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !Otls_PARAM_set_size_t(p, ctx->taglen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = Otls_PARAM_locate(params, Otls_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !Otls_PARAM_set_size_t(p, ctx->keylen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

static const Otls_PARAM aes_siv_known_gettable_ctx_params[] = {
    Otls_PARAM_size_t(Otls_CIPHER_PARAM_KEYLEN, NULL),
    Otls_PARAM_size_t(Otls_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    Otls_PARAM_uint(Otls_CIPHER_PARAM_SPEED, NULL),
    Otls_PARAM_octet_string(Otls_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    Otls_PARAM_END
};
static const Otls_PARAM *aes_siv_gettable_ctx_params(void)
{
    return aes_siv_known_gettable_ctx_params;
}

static int aes_siv_set_ctx_params(void *vctx, const Otls_PARAM params[])
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;
    const Otls_PARAM *p;
    unsigned int speed = 0;

    p = Otls_PARAM_locate_const(params, Otls_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (ctx->enc)
            return 1;
        if (p->data_type != Otls_PARAM_OCTET_STRING
            || !ctx->hw->settag(ctx, p->data, p->data_size)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }
    p = Otls_PARAM_locate_const(params, Otls_CIPHER_PARAM_SPEED);
    if (p != NULL) {
        if (!Otls_PARAM_get_uint(p, &speed)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->hw->setspeed(ctx, (int)speed);
    }
    p = Otls_PARAM_locate_const(params, Otls_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t keylen;

        if (!Otls_PARAM_get_size_t(p, &keylen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        /* The key length can not be modified */
        if (keylen != ctx->keylen)
            return 0;
    }
    return 1;
}

static const Otls_PARAM aes_siv_known_settable_ctx_params[] = {
    Otls_PARAM_size_t(Otls_CIPHER_PARAM_KEYLEN, NULL),
    Otls_PARAM_uint(Otls_CIPHER_PARAM_SPEED, NULL),
    Otls_PARAM_octet_string(Otls_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    Otls_PARAM_END
};
static const Otls_PARAM *aes_siv_settable_ctx_params(void)
{
    return aes_siv_known_settable_ctx_params;
}

#define IMPLEMENT_cipher(alg, lc, UCMODE, flags, kbits, blkbits, ivbits)       \
static Otls_OP_cipher_get_params_fn alg##_##kbits##_##lc##_get_params;         \
static int alg##_##kbits##_##lc##_get_params(Otls_PARAM params[])              \
{                                                                              \
    return cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE,         \
                                     flags, 2*kbits, blkbits, ivbits);         \
}                                                                              \
static Otls_OP_cipher_newctx_fn alg##kbits##lc##_newctx;                       \
static void * alg##kbits##lc##_newctx(void *provctx)                           \
{                                                                              \
    return alg##_##lc##_newctx(provctx, 2*kbits, EVP_CIPH_##UCMODE##_MODE,     \
                               flags);                                         \
}                                                                              \
const Otls_DISPATCH alg##kbits##lc##_functions[] = {                           \
    { Otls_FUNC_CIPHER_NEWCTX, (void (*)(void))alg##kbits##lc##_newctx },      \
    { Otls_FUNC_CIPHER_FREECTX, (void (*)(void))alg##_##lc##_freectx },        \
    { Otls_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) lc##_einit },            \
    { Otls_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void)) lc##_dinit },            \
    { Otls_FUNC_CIPHER_UPDATE, (void (*)(void)) lc##_stream_update },          \
    { Otls_FUNC_CIPHER_FINAL, (void (*)(void)) lc##_stream_final },            \
    { Otls_FUNC_CIPHER_CIPHER, (void (*)(void)) lc##_cipher },                 \
    { Otls_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void)) alg##_##kbits##_##lc##_get_params },                    \
    { Otls_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))cipher_generic_gettable_params },                        \
    { Otls_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void)) alg##_##lc##_get_ctx_params },                          \
    { Otls_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void)) alg##_##lc##_gettable_ctx_params },                     \
    { Otls_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void)) alg##_##lc##_set_ctx_params },                          \
    { Otls_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
      (void (*)(void)) alg##_##lc##_settable_ctx_params },                     \
    { 0, NULL }                                                                \
};

IMPLEMENT_cipher(aes, siv, SIV, SIV_FLAGS, 128, 8, 0)
IMPLEMENT_cipher(aes, siv, SIV, SIV_FLAGS, 192, 8, 0)
IMPLEMENT_cipher(aes, siv, SIV, SIV_FLAGS, 256, 8, 0)
