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
#include <openssl/rand.h>
#include "internal/cryptlib.h"
#include "internal/provider_algs.h"
#include "ciphers_locl.h"
#include "internal/providercommonerr.h"

static OSSL_OP_cipher_encrypt_init_fn aes_einit;
static OSSL_OP_cipher_decrypt_init_fn aes_dinit;
static OSSL_OP_cipher_update_fn aes_block_update;
static OSSL_OP_cipher_final_fn aes_block_final;
static OSSL_OP_cipher_update_fn aes_stream_update;
static OSSL_OP_cipher_final_fn aes_stream_final;
static OSSL_OP_cipher_cipher_fn aes_cipher;
static OSSL_OP_cipher_freectx_fn aes_freectx;
static OSSL_OP_cipher_dupctx_fn aes_dupctx;
static OSSL_OP_cipher_get_ctx_params_fn aes_get_ctx_params;
static OSSL_OP_cipher_set_ctx_params_fn aes_set_ctx_params;

static int PROV_AES_KEY_generic_init(PROV_AES_KEY *ctx,
                                      const unsigned char *iv,
                                      size_t ivlen,
                                      int enc)
{
    if (iv != NULL && ctx->mode != EVP_CIPH_ECB_MODE) {
        if (ivlen != AES_BLOCK_SIZE) {
            PROVerr(PROV_F_PROV_AES_KEY_GENERIC_INIT, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
    }
    ctx->enc = enc;

    return 1;
}

static int aes_einit(void *vctx, const unsigned char *key, size_t keylen,
                           const unsigned char *iv, size_t ivlen)
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;

    if (!PROV_AES_KEY_generic_init(ctx, iv, ivlen, 1)) {
        /* PROVerr already called */
        return 0;
    }
    if (key != NULL) {
        if (keylen != ctx->keylen) {
            PROVerr(PROV_F_AES_EINIT, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        return ctx->ciph->init(ctx, key, ctx->keylen);
    }

    return 1;
}

static int aes_dinit(void *vctx, const unsigned char *key, size_t keylen,
                     const unsigned char *iv, size_t ivlen)
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;

    if (!PROV_AES_KEY_generic_init(ctx, iv, ivlen, 0)) {
        /* PROVerr already called */
        return 0;
    }
    if (key != NULL) {
        if (keylen != ctx->keylen) {
            PROVerr(PROV_F_AES_DINIT, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        return ctx->ciph->init(ctx, key, ctx->keylen);
    }

    return 1;
}

static int aes_block_update(void *vctx, unsigned char *out, size_t *outl,
                            size_t outsize, const unsigned char *in, size_t inl)
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
        if (outsize < AES_BLOCK_SIZE) {
            PROVerr(PROV_F_AES_BLOCK_UPDATE, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        if (!ctx->ciph->cipher(ctx, out, ctx->buf, AES_BLOCK_SIZE)) {
            PROVerr(PROV_F_AES_BLOCK_UPDATE, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        ctx->bufsz = 0;
        outlint = AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
    }
    if (nextblocks > 0) {
        if (!ctx->enc && ctx->pad && nextblocks == inl) {
            if (!ossl_assert(inl >= AES_BLOCK_SIZE)) {
                PROVerr(PROV_F_AES_BLOCK_UPDATE, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
                return 0;
            }
            nextblocks -= AES_BLOCK_SIZE;
        }
        outlint += nextblocks;
        if (outsize < outlint) {
            PROVerr(PROV_F_AES_BLOCK_UPDATE, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        if (!ctx->ciph->cipher(ctx, out, in, nextblocks)) {
            PROVerr(PROV_F_AES_BLOCK_UPDATE, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        in += nextblocks;
        inl -= nextblocks;
    }
    if (!trailingdata(ctx->buf, &ctx->bufsz, AES_BLOCK_SIZE, &in, &inl)) {
        /* PROVerr already called */
        return 0;
    }

    *outl = outlint;
    return inl == 0;
}

static int aes_block_final(void *vctx, unsigned char *out, size_t *outl,
                           size_t outsize)
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;

    if (ctx->enc) {
        if (ctx->pad) {
            padblock(ctx->buf, &ctx->bufsz, AES_BLOCK_SIZE);
        } else if (ctx->bufsz == 0) {
            *outl = 0;
            return 1;
        } else if (ctx->bufsz != AES_BLOCK_SIZE) {
            PROVerr(PROV_F_AES_BLOCK_FINAL, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            return 0;
        }

        if (outsize < AES_BLOCK_SIZE) {
            PROVerr(PROV_F_AES_BLOCK_FINAL, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        if (!ctx->ciph->cipher(ctx, out, ctx->buf, AES_BLOCK_SIZE)) {
            PROVerr(PROV_F_AES_BLOCK_FINAL, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        ctx->bufsz = 0;
        *outl = AES_BLOCK_SIZE;
        return 1;
    }

    /* Decrypting */
    if (ctx->bufsz != AES_BLOCK_SIZE) {
        if (ctx->bufsz == 0 && !ctx->pad) {
            *outl = 0;
            return 1;
        }
        PROVerr(PROV_F_AES_BLOCK_FINAL, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
        return 0;
    }

    if (!ctx->ciph->cipher(ctx, ctx->buf, ctx->buf, AES_BLOCK_SIZE)) {
        PROVerr(PROV_F_AES_BLOCK_FINAL, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    if (ctx->pad && !unpadblock(ctx->buf, &ctx->bufsz, AES_BLOCK_SIZE)) {
        /* PROVerr already called */
        return 0;
    }

    if (outsize < ctx->bufsz) {
        PROVerr(PROV_F_AES_BLOCK_FINAL, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    memcpy(out, ctx->buf, ctx->bufsz);
    *outl = ctx->bufsz;
    ctx->bufsz = 0;
    return 1;
}

static int aes_stream_update(void *vctx, unsigned char *out, size_t *outl,
                             size_t outsize, const unsigned char *in,
                             size_t inl)
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;

    if (outsize < inl) {
        PROVerr(PROV_F_AES_STREAM_UPDATE, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!ctx->ciph->cipher(ctx, out, in, inl)) {
        PROVerr(PROV_F_AES_STREAM_UPDATE, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = inl;
    return 1;
}
static int aes_stream_final(void *vctx, unsigned char *out, size_t *outl,
                            size_t outsize)
{
    *outl = 0;
    return 1;
}

static int aes_cipher(void *vctx,
                      unsigned char *out, size_t *outl, size_t outsize,
                      const unsigned char *in, size_t inl)
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;

    if (outsize < inl) {
        PROVerr(PROV_F_AES_CIPHER, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!ctx->ciph->cipher(ctx, out, in, inl)) {
        PROVerr(PROV_F_AES_CIPHER, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = inl;
    return 1;
}

static void *aes_new_ctx(void *provctx, size_t mode, size_t kbits,
                         const PROV_AES_CIPHER *ciph)
{
    PROV_AES_KEY *ctx = OPENSSL_zalloc(sizeof(*ctx));

    ctx->pad = 1;
    ctx->keylen = kbits / 8;
    ctx->ciph = ciph;
    ctx->mode = mode;
    return ctx;
}

int aes_get_params(OSSL_PARAM params[], int md, unsigned long flags,
                   int kbits, int blkbits, int ivbits)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL) {
        if (!OSSL_PARAM_set_int(p, md))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_FLAGS);
    if (p != NULL) {
        if (!OSSL_PARAM_set_ulong(p, flags))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_set_int(p, kbits / 8))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_set_int(p, blkbits / 8))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_set_int(p, ivbits / 8))
            return 0;
    }
    return 1;
}

#define IMPLEMENT_cipher(lcmode, UCMODE, flags, kbits, blkbits, ivbits)        \
    static OSSL_OP_cipher_get_params_fn aes_##kbits##_##lcmode##_get_params;   \
    static int aes_##kbits##_##lcmode##_get_params(OSSL_PARAM params[])        \
    {                                                                          \
        return aes_get_params(params, EVP_CIPH_##UCMODE##_MODE, flags, kbits,  \
                              blkbits, ivbits);                                \
    }                                                                          \
    static OSSL_OP_cipher_newctx_fn aes_##kbits##_##lcmode##_newctx;           \
    static void *aes_##kbits##_##lcmode##_newctx(void *provctx)                \
    {                                                                          \
        return aes_new_ctx(provctx, EVP_CIPH_##UCMODE##_MODE, kbits,           \
                           PROV_AES_CIPHER_##lcmode(kbits / 8));               \
    }

/* ECB */
IMPLEMENT_cipher(ecb, ECB, 0, 256, 128, 0)
IMPLEMENT_cipher(ecb, ECB, 0, 192, 128, 0)
IMPLEMENT_cipher(ecb, ECB, 0, 128, 128, 0)

/* CBC */
IMPLEMENT_cipher(cbc, CBC, 0, 256, 128, 128)
IMPLEMENT_cipher(cbc, CBC, 0, 192, 128, 128)
IMPLEMENT_cipher(cbc, CBC, 0, 128, 128, 128)

/* OFB */
IMPLEMENT_cipher(ofb, OFB, 0, 256, 8, 128)
IMPLEMENT_cipher(ofb, OFB, 0, 192, 8, 128)
IMPLEMENT_cipher(ofb, OFB, 0, 128, 8, 128)

/* CFB */
IMPLEMENT_cipher(cfb, CFB, 0, 256, 8, 128)
IMPLEMENT_cipher(cfb, CFB, 0, 192, 8, 128)
IMPLEMENT_cipher(cfb, CFB, 0, 128, 8, 128)
IMPLEMENT_cipher(cfb1, CFB, 0, 256, 8, 128)
IMPLEMENT_cipher(cfb1, CFB, 0, 192, 8, 128)
IMPLEMENT_cipher(cfb1, CFB, 0, 128, 8, 128)
IMPLEMENT_cipher(cfb8, CFB, 0, 256, 8, 128)
IMPLEMENT_cipher(cfb8, CFB, 0, 192, 8, 128)
IMPLEMENT_cipher(cfb8, CFB, 0, 128, 8, 128)

/* CTR */
IMPLEMENT_cipher(ctr, CTR, 0, 256, 8, 128)
IMPLEMENT_cipher(ctr, CTR, 0, 192, 8, 128)
IMPLEMENT_cipher(ctr, CTR, 0, 128, 8, 128)

static void aes_freectx(void *vctx)
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *aes_dupctx(void *ctx)
{
    PROV_AES_KEY *in = (PROV_AES_KEY *)ctx;
    PROV_AES_KEY *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL) {
        PROVerr(PROV_F_AES_DUPCTX, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    *ret = *in;

    return ret;
}

static int aes_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_set_int(p, AES_BLOCK_SIZE))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_int(p, ctx->pad)) {
        PROVerr(PROV_F_AES_GET_CTX_PARAMS, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, AES_BLOCK_SIZE)
        && !OSSL_PARAM_set_octet_string(p, &ctx->iv, AES_BLOCK_SIZE)) {
        PROVerr(PROV_F_AES_GET_CTX_PARAMS,
                PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->num)) {
        PROVerr(PROV_F_AES_GET_CTX_PARAMS,
                PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_int(p, ctx->keylen)) {
        PROVerr(PROV_F_AES_GET_CTX_PARAMS,
                PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    return 1;
}

static int aes_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_AES_KEY *ctx = (PROV_AES_KEY *)vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        int pad;

        if (!OSSL_PARAM_get_int(p, &pad)) {
            PROVerr(PROV_F_AES_SET_CTX_PARAMS,
                    PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->pad = pad ? 1 : 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL) {
        int num;

        if (!OSSL_PARAM_get_int(p, &num)) {
            PROVerr(PROV_F_AES_SET_CTX_PARAMS,
                    PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->num = num;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        int keylen;

        if (!OSSL_PARAM_get_int(p, &keylen)) {
            PROVerr(PROV_F_AES_SET_CTX_PARAMS,
                    PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->keylen = keylen;
    }
    return 1;
}

#define IMPLEMENT_block_funcs(mode, kbits) \
    const OSSL_DISPATCH aes##kbits##mode##_functions[] = { \
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))aes_##kbits##_##mode##_newctx }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))aes_einit }, \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))aes_dinit }, \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))aes_block_update }, \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))aes_block_final }, \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))aes_cipher }, \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))aes_freectx }, \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))aes_dupctx }, \
        { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))aes_##kbits##_##mode##_get_params }, \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))aes_get_ctx_params }, \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))aes_set_ctx_params }, \
        { 0, NULL } \
    };

#define IMPLEMENT_stream_funcs(mode, kbits) \
    const OSSL_DISPATCH aes##kbits##mode##_functions[] = { \
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))aes_##kbits##_##mode##_newctx }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))aes_einit }, \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))aes_dinit }, \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))aes_stream_update }, \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))aes_stream_final }, \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))aes_cipher }, \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))aes_freectx }, \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))aes_dupctx }, \
        { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))aes_##kbits##_##mode##_get_params }, \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))aes_get_ctx_params }, \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))aes_set_ctx_params }, \
        { 0, NULL } \
    };

/* ECB */
IMPLEMENT_block_funcs(ecb, 256)
IMPLEMENT_block_funcs(ecb, 192)
IMPLEMENT_block_funcs(ecb, 128)

/* CBC */
IMPLEMENT_block_funcs(cbc, 256)
IMPLEMENT_block_funcs(cbc, 192)
IMPLEMENT_block_funcs(cbc, 128)

/* OFB */
IMPLEMENT_stream_funcs(ofb, 256)
IMPLEMENT_stream_funcs(ofb, 192)
IMPLEMENT_stream_funcs(ofb, 128)

/* CFB */
IMPLEMENT_stream_funcs(cfb, 256)
IMPLEMENT_stream_funcs(cfb, 192)
IMPLEMENT_stream_funcs(cfb, 128)
IMPLEMENT_stream_funcs(cfb1, 256)
IMPLEMENT_stream_funcs(cfb1, 192)
IMPLEMENT_stream_funcs(cfb1, 128)
IMPLEMENT_stream_funcs(cfb8, 256)
IMPLEMENT_stream_funcs(cfb8, 192)
IMPLEMENT_stream_funcs(cfb8, 128)

/* CTR */
IMPLEMENT_stream_funcs(ctr, 256)
IMPLEMENT_stream_funcs(ctr, 192)
IMPLEMENT_stream_funcs(ctr, 128)
