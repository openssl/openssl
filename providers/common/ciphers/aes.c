/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include "internal/cryptlib.h"
#include "internal/provider_algs.h"
#include "ciphers_locl.h"

static void PROV_AES_KEY_generic_init(PROV_AES_KEY *ctx,
                                      const unsigned char *iv,
                                      int enc)
{
    if (iv != NULL)
        memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
    ctx->enc = enc;
}

static int aes_einit(void *vctx, const unsigned char *key,
                           const unsigned char *iv)
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;

    PROV_AES_KEY_generic_init(ctx, iv, 1);
    if (key != NULL)
        return ctx->ciph->init(ctx, key, ctx->keylen);

    return 1;
}

static int aes_dinit(void *vctx, const unsigned char *key,
                     const unsigned char *iv)
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;

    PROV_AES_KEY_generic_init(ctx, iv, 0);
    if (key != NULL)
        return ctx->ciph->init(ctx, key, ctx->keylen);

    return 1;
}

static int aes_block_update(void *vctx, unsigned char *out, size_t *outl,
                            const unsigned char *in, size_t inl)
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;
    size_t nextblocks = fillblock(ctx->buf, &ctx->bufsz, AES_BLOCK_SIZE, &in,
                                  &inl);
    size_t outlint = 0;

    /*
     * If we're decrypting and we end an update on a block boundary we hold
     * the last block back in case this is the last update call and the last
     * block is padded.
     */
    if (ctx->bufsz == AES_BLOCK_SIZE
            && (ctx->enc || inl > 0 || !ctx->pad)) {
        if (!ctx->ciph->cipher(ctx, out, ctx->buf, AES_BLOCK_SIZE))
            return 0;
        ctx->bufsz = 0;
        outlint = AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
    }
    if (nextblocks > 0) {
        if (!ctx->enc && ctx->pad && nextblocks == inl) {
            if (!ossl_assert(inl >= AES_BLOCK_SIZE))
                return 0;
            nextblocks -= AES_BLOCK_SIZE;
        }
        if (!ctx->ciph->cipher(ctx, out, in, nextblocks))
            return 0;
        in += nextblocks;
        inl -= nextblocks;
        outlint += nextblocks;
    }
    if (!trailingdata(ctx->buf, &ctx->bufsz, AES_BLOCK_SIZE, &in, &inl))
        return 0;

    *outl = outlint;
    return inl == 0;
}

static int aes_block_final(void *vctx, unsigned char *out, size_t *outl)
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;

    if (ctx->enc) {
        if (ctx->pad) {
            padblock(ctx->buf, &ctx->bufsz, AES_BLOCK_SIZE);
        } else if(ctx->bufsz == 0) {
            *outl = 0;
            return 1;
        } else if(ctx->bufsz != AES_BLOCK_SIZE) {
            /* TODO(3.0): What is the correct error code here? */
            return 0;
        }

        if (!ctx->ciph->cipher(ctx, out, ctx->buf, AES_BLOCK_SIZE))
            return 0;
        ctx->bufsz = 0;
        *outl = AES_BLOCK_SIZE;
        return 1;
    }

    /* Decrypting */
    /* TODO(3.0): What's the correct error here */
    if (ctx->bufsz != AES_BLOCK_SIZE) {
        if (ctx->bufsz == 0 && !ctx->pad) {
            *outl = 0;
            return 1;
        }
        return 0;
    }

    if (!ctx->ciph->cipher(ctx, ctx->buf, ctx->buf, AES_BLOCK_SIZE))
        return 0;

    /* TODO(3.0): What is the correct error here */
    if (ctx->pad && !unpadblock(ctx->buf, &ctx->bufsz, AES_BLOCK_SIZE))
        return 0;

    memcpy(out, ctx->buf, ctx->bufsz);
    *outl = ctx->bufsz;
    ctx->bufsz = 0;
    return 1;
}

static int aes_stream_update(void *vctx, unsigned char *out, size_t *outl,
                             const unsigned char *in, size_t inl)
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;

    if (!ctx->ciph->cipher(ctx, out, in, inl))
        return 0;

    *outl = inl;
    return 1;
}
static int aes_stream_final(void *vctx, unsigned char *out, size_t *outl)
{
    *outl = 0;
    return 1;
}

static int aes_cipher(void *vctx, unsigned char *out, const unsigned char *in,
                      size_t inl)
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;

    if (!ctx->ciph->cipher(ctx, out, in, inl))
        return 0;

    return 1;
}

#define IMPLEMENT_new_params(lcmode, UCMODE) \
    static int aes_##lcmode##_get_params(const OSSL_PARAM params[]) \
    { \
        const OSSL_PARAM *p; \
    \
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE); \
        if (p != NULL && !OSSL_PARAM_set_int(p, EVP_CIPH_##UCMODE##_MODE)) \
            return 0; \
    \
        return 1; \
    }

#define IMPLEMENT_new_ctx(lcmode, UCMODE, len) \
    static void *aes_##len##_##lcmode##_newctx(void) \
    { \
        PROV_AES_KEY *ctx = OPENSSL_zalloc(sizeof(*ctx)); \
    \
        ctx->pad = 1; \
        ctx->keylen = (len / 8); \
        ctx->ciph = PROV_AES_CIPHER_##lcmode(); \
        ctx->mode = EVP_CIPH_##UCMODE##_MODE; \
        return ctx; \
    }

/* ECB */
IMPLEMENT_new_params(ecb, ECB)
IMPLEMENT_new_ctx(ecb, ECB, 256)
IMPLEMENT_new_ctx(ecb, ECB, 192)
IMPLEMENT_new_ctx(ecb, ECB, 128)

/* CBC */
IMPLEMENT_new_params(cbc, CBC)
IMPLEMENT_new_ctx(cbc, CBC, 256)
IMPLEMENT_new_ctx(cbc, CBC, 192)
IMPLEMENT_new_ctx(cbc, CBC, 128)

/* OFB */
IMPLEMENT_new_params(ofb, OFB)
IMPLEMENT_new_ctx(ofb, OFB, 256)
IMPLEMENT_new_ctx(ofb, OFB, 192)
IMPLEMENT_new_ctx(ofb, OFB, 128)


static void aes_freectx(void *vctx)
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *aes_dupctx(void *ctx)
{
    PROV_AES_KEY *in = (PROV_AES_KEY *)ctx;
    PROV_AES_KEY *ret = OPENSSL_malloc(sizeof(*ret));

    *ret = *in;

    return ret;
}

static size_t key_length_256(void)
{
    return 256 / 8;
}

static size_t key_length_192(void)
{
    return 192 / 8;
}

static size_t key_length_128(void)
{
    return 128 / 8;
}

static size_t iv_length_16(void)
{
    return 16;
}

static size_t iv_length_0(void)
{
    return 0;
}

static size_t block_size_16(void)
{
    return 16;
}

static size_t block_size_1(void)
{
    return 1;
}

static int aes_ctx_get_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->pad))
        return 0;

    return 1;
}

static int aes_ctx_set_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        int pad;

        if (!OSSL_PARAM_get_int(p, &pad))
            return 0;
        ctx->pad = pad ? 1 : 0;
    }
    return 1;
}

#define IMPLEMENT_block_funcs(mode, keylen, ivlen) \
    const OSSL_DISPATCH aes##keylen##mode##_functions[] = { \
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))aes_##keylen##_##mode##_newctx }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))aes_einit }, \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))aes_dinit }, \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))aes_block_update }, \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))aes_block_final }, \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))aes_cipher }, \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))aes_freectx }, \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))aes_dupctx }, \
        { OSSL_FUNC_CIPHER_KEY_LENGTH, (void (*)(void))key_length_##keylen }, \
        { OSSL_FUNC_CIPHER_IV_LENGTH, (void (*)(void))iv_length_##ivlen }, \
        { OSSL_FUNC_CIPHER_BLOCK_SIZE, (void (*)(void))block_size_16 }, \
        { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))aes_##mode##_get_params }, \
        { OSSL_FUNC_CIPHER_CTX_GET_PARAMS, (void (*)(void))aes_ctx_get_params }, \
        { OSSL_FUNC_CIPHER_CTX_SET_PARAMS, (void (*)(void))aes_ctx_set_params }, \
        { 0, NULL } \
    };

#define IMPLEMENT_stream_funcs(mode, keylen, ivlen) \
    const OSSL_DISPATCH aes##keylen##mode##_functions[] = { \
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))aes_##keylen##_##mode##_newctx }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))aes_einit }, \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))aes_dinit }, \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))aes_stream_update }, \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))aes_stream_final }, \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))aes_cipher }, \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))aes_freectx }, \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))aes_dupctx }, \
        { OSSL_FUNC_CIPHER_KEY_LENGTH, (void (*)(void))key_length_##keylen }, \
        { OSSL_FUNC_CIPHER_IV_LENGTH, (void (*)(void))iv_length_##ivlen }, \
        { OSSL_FUNC_CIPHER_BLOCK_SIZE, (void (*)(void))block_size_1 }, \
        { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))aes_##mode##_get_params }, \
        { OSSL_FUNC_CIPHER_CTX_GET_PARAMS, (void (*)(void))aes_ctx_get_params }, \
        { OSSL_FUNC_CIPHER_CTX_SET_PARAMS, (void (*)(void))aes_ctx_set_params }, \
        { 0, NULL } \
    };

/* ECB */
IMPLEMENT_block_funcs(ecb, 256, 0)
IMPLEMENT_block_funcs(ecb, 192, 0)
IMPLEMENT_block_funcs(ecb, 128, 0)

/* CBC */
IMPLEMENT_block_funcs(cbc, 256, 16)
IMPLEMENT_block_funcs(cbc, 192, 16)
IMPLEMENT_block_funcs(cbc, 128, 16)

/* OFB */
IMPLEMENT_stream_funcs(ofb, 256, 16)
IMPLEMENT_stream_funcs(ofb, 192, 16)
IMPLEMENT_stream_funcs(ofb, 128, 16)
