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
#include "internal/providercommonerr.h"

static OSSL_OP_cipher_encrypt_init_fn generic_einit;
static OSSL_OP_cipher_decrypt_init_fn generic_dinit;
static OSSL_OP_cipher_update_fn generic_block_update;
static OSSL_OP_cipher_final_fn generic_block_final;
static OSSL_OP_cipher_update_fn generic_stream_update;
static OSSL_OP_cipher_final_fn generic_stream_final;
static OSSL_OP_cipher_cipher_fn generic_cipher;
static OSSL_OP_cipher_get_ctx_params_fn generic_get_ctx_params;
static OSSL_OP_cipher_set_ctx_params_fn generic_set_ctx_params;

static int generic_key_init(PROV_GENERIC_KEY *ctx,
                            const unsigned char *key, size_t keylen,
                            const unsigned char *iv, size_t ivlen, int enc)
{
    ctx->enc = enc;

    if (iv != NULL && ctx->mode != EVP_CIPH_ECB_MODE) {
        if (ivlen != GENERIC_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        memcpy(ctx->iv, iv, GENERIC_BLOCK_SIZE);
    }
    if (key != NULL) {
        if (keylen != ctx->keylen) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEYLEN);
            return 0;
        }
        return ctx->ciph->init(ctx, key, ctx->keylen);
    }
    return 1;
}

static int generic_einit(void *vctx, const unsigned char *key, size_t keylen,
                         const unsigned char *iv, size_t ivlen)
{
    return generic_key_init((PROV_GENERIC_KEY *)vctx, key, keylen, iv , ivlen, 1);
}

static int generic_dinit(void *vctx, const unsigned char *key, size_t keylen,
                         const unsigned char *iv, size_t ivlen)
{
    return generic_key_init((PROV_GENERIC_KEY *)vctx, key, keylen, iv , ivlen, 0);
}

static int generic_block_update(void *vctx, unsigned char *out, size_t *outl,
                                size_t outsize, const unsigned char *in,
                                size_t inl)
{
    size_t outlint = 0;
    PROV_GENERIC_KEY *ctx = (PROV_GENERIC_KEY *)vctx;
    size_t nextblocks = fillblock(ctx->buf, &ctx->bufsz, GENERIC_BLOCK_SIZE, &in,
                                  &inl);

    /*
     * If we're decrypting and we end an update on a block boundary we hold
     * the last block back in case this is the last update call and the last
     * block is padded.
     */
    if (ctx->bufsz == GENERIC_BLOCK_SIZE && (ctx->enc || inl > 0 || !ctx->pad)) {
        if (outsize < GENERIC_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        if (!ctx->ciph->cipher(ctx, out, ctx->buf, GENERIC_BLOCK_SIZE)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        ctx->bufsz = 0;
        outlint = GENERIC_BLOCK_SIZE;
        out += GENERIC_BLOCK_SIZE;
    }
    if (nextblocks > 0) {
        if (!ctx->enc && ctx->pad && nextblocks == inl) {
            if (!ossl_assert(inl >= GENERIC_BLOCK_SIZE)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
                return 0;
            }
            nextblocks -= GENERIC_BLOCK_SIZE;
        }
        outlint += nextblocks;
        if (outsize < outlint) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        if (!ctx->ciph->cipher(ctx, out, in, nextblocks)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        in += nextblocks;
        inl -= nextblocks;
    }
    if (!trailingdata(ctx->buf, &ctx->bufsz, GENERIC_BLOCK_SIZE, &in, &inl)) {
        /* ERR_raise already called */
        return 0;
    }

    *outl = outlint;
    return inl == 0;
}

static int generic_block_final(void *vctx, unsigned char *out, size_t *outl,
                               size_t outsize)
{
    PROV_GENERIC_KEY *ctx = (PROV_GENERIC_KEY *)vctx;

    if (ctx->enc) {
        if (ctx->pad) {
            padblock(ctx->buf, &ctx->bufsz, GENERIC_BLOCK_SIZE);
        } else if (ctx->bufsz == 0) {
            *outl = 0;
            return 1;
        } else if (ctx->bufsz != GENERIC_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            return 0;
        }

        if (outsize < GENERIC_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        if (!ctx->ciph->cipher(ctx, out, ctx->buf, GENERIC_BLOCK_SIZE)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        ctx->bufsz = 0;
        *outl = GENERIC_BLOCK_SIZE;
        return 1;
    }

    /* Decrypting */
    if (ctx->bufsz != GENERIC_BLOCK_SIZE) {
        if (ctx->bufsz == 0 && !ctx->pad) {
            *outl = 0;
            return 1;
        }
        ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
        return 0;
    }

    if (!ctx->ciph->cipher(ctx, ctx->buf, ctx->buf, GENERIC_BLOCK_SIZE)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    if (ctx->pad && !unpadblock(ctx->buf, &ctx->bufsz, GENERIC_BLOCK_SIZE)) {
        /* ERR_raise already called */
        return 0;
    }

    if (outsize < ctx->bufsz) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    memcpy(out, ctx->buf, ctx->bufsz);
    *outl = ctx->bufsz;
    ctx->bufsz = 0;
    return 1;
}

static int generic_stream_update(void *vctx, unsigned char *out, size_t *outl,
                                 size_t outsize, const unsigned char *in,
                                 size_t inl)
{
    PROV_GENERIC_KEY *ctx = (PROV_GENERIC_KEY *)vctx;

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!ctx->ciph->cipher(ctx, out, in, inl)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = inl;
    return 1;
}
static int generic_stream_final(void *vctx, unsigned char *out, size_t *outl,
                                size_t outsize)
{
    *outl = 0;
    return 1;
}

static int generic_cipher(void *vctx,
                          unsigned char *out, size_t *outl, size_t outsize,
                          const unsigned char *in, size_t inl)
{
    PROV_GENERIC_KEY *ctx = (PROV_GENERIC_KEY *)vctx;

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!ctx->ciph->cipher(ctx, out, in, inl)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = inl;
    return 1;
}

static int generic_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_GENERIC_KEY *ctx = (PROV_GENERIC_KEY *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_int(p, GENERIC_BLOCK_SIZE)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_int(p, ctx->pad)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, GENERIC_BLOCK_SIZE)
        && !OSSL_PARAM_set_octet_string(p, &ctx->iv, GENERIC_BLOCK_SIZE)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->num)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_int(p, ctx->keylen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    return 1;
}

static int generic_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_GENERIC_KEY *ctx = (PROV_GENERIC_KEY *)vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        int pad;

        if (!OSSL_PARAM_get_int(p, &pad)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->pad = pad ? 1 : 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL) {
        int num;

        if (!OSSL_PARAM_get_int(p, &num)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->num = num;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        int keylen;

        if (!OSSL_PARAM_get_int(p, &keylen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->keylen = keylen;
    }
    return 1;
}

static void generic_init(void *vctx, int kbits, int blkbits, int mode,
                         const PROV_GENERIC_CIPHER *ciph)
{
    PROV_GENERIC_KEY *ctx = (PROV_GENERIC_KEY *)vctx;

    ctx->pad = 1;
    ctx->keylen = ((kbits) / 8);
    ctx->ciph = ciph;
    ctx->mode = mode;
    ctx->blocksize = blkbits/8;
}

#define IMPLEMENT_cipher(alg, UCALG, lcmode, UCMODE, flags, kbits, blkbits,    \
                         ivbits, typ)                                          \
static OSSL_OP_cipher_get_params_fn alg##_##kbits##_##lcmode##_get_params;     \
static int alg##_##kbits##_##lcmode##_get_params(OSSL_PARAM params[])          \
{                                                                              \
    return cipher_default_get_params(params,EVP_CIPH_##UCMODE##_MODE, flags,   \
                                     kbits, blkbits, ivbits);                  \
}                                                                              \
static OSSL_OP_cipher_newctx_fn alg##_##kbits##_##lcmode##_newctx;             \
static void * alg##_##kbits##_##lcmode##_newctx(void *provctx)                 \
{                                                                              \
     PROV_##UCALG##_KEY *ctx = OPENSSL_zalloc(sizeof(*ctx));                   \
     if (ctx != NULL) {                                                        \
         generic_init(ctx, kbits, blkbits, EVP_CIPH_##UCMODE##_MODE,           \
                      PROV_##UCALG##_CIPHER_##lcmode(kbits));                  \
     }                                                                         \
     return ctx;                                                               \
}                                                                              \
const OSSL_DISPATCH alg##kbits##lcmode##_functions[] = {                       \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
      (void (*)(void)) alg##_##kbits##_##lcmode##_newctx },                    \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))generic_einit },          \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))generic_dinit },          \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))generic_##typ##_update },       \
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))generic_##typ##_final },         \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))generic_cipher },               \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) alg##_freectx },              \
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void)) alg##_dupctx },                \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void)) alg##_##kbits##_##lcmode##_get_params },                \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void))generic_get_ctx_params },                                \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void))generic_set_ctx_params },                                \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))cipher_default_gettable_params },                        \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))cipher_default_gettable_ctx_params },                    \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
     (void (*)(void))cipher_default_settable_ctx_params },                     \
    { 0, NULL }                                                                \
};

static OSSL_OP_cipher_freectx_fn aes_freectx;
static OSSL_OP_cipher_dupctx_fn aes_dupctx;

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
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    *ret = *in;

    return ret;
}

/* aes256ecb_functions */
IMPLEMENT_cipher(aes, AES, ecb, ECB, 0, 256, 128, 0, block)
/* aes192ecb_functions */
IMPLEMENT_cipher(aes, AES, ecb, ECB, 0, 192, 128, 0, block)
/* aes128ecb_functions */
IMPLEMENT_cipher(aes, AES, ecb, ECB, 0, 128, 128, 0, block)
/* aes256cbc_functions */
IMPLEMENT_cipher(aes, AES, cbc, CBC, 0, 256, 128, 128, block)
/* aes192cbc_functions */
IMPLEMENT_cipher(aes, AES, cbc, CBC, 0, 192, 128, 128, block)
/* aes128cbc_functions */
IMPLEMENT_cipher(aes, AES, cbc, CBC, 0, 128, 128, 128, block)
/* aes256ofb_functions */
IMPLEMENT_cipher(aes, AES, ofb, OFB, 0, 256, 8, 128, stream)
/* aes192ofb_functions */
IMPLEMENT_cipher(aes, AES, ofb, OFB, 0, 192, 8, 128, stream)
/* aes128ofb_functions */
IMPLEMENT_cipher(aes, AES, ofb, OFB, 0, 128, 8, 128, stream)
/* aes256cfb_functions */
IMPLEMENT_cipher(aes, AES, cfb,  CFB, 0, 256, 8, 128, stream)
/* aes192cfb_functions */
IMPLEMENT_cipher(aes, AES, cfb,  CFB, 0, 192, 8, 128, stream)
/* aes128cfb_functions */
IMPLEMENT_cipher(aes, AES, cfb,  CFB, 0, 128, 8, 128, stream)
/* aes256cfb1_functions */
IMPLEMENT_cipher(aes, AES, cfb1, CFB, 0, 256, 8, 128, stream)
/* aes192cfb1_functions */
IMPLEMENT_cipher(aes, AES, cfb1, CFB, 0, 192, 8, 128, stream)
/* aes128cfb1_functions */
IMPLEMENT_cipher(aes, AES, cfb1, CFB, 0, 128, 8, 128, stream)
/* aes256cfb8_functions */
IMPLEMENT_cipher(aes, AES, cfb8, CFB, 0, 256, 8, 128, stream)
/* aes192cfb8_functions */
IMPLEMENT_cipher(aes, AES, cfb8, CFB, 0, 192, 8, 128, stream)
/* aes128cfb8_functions */
IMPLEMENT_cipher(aes, AES, cfb8, CFB, 0, 128, 8, 128, stream)
/* aes256ctr_functions */
IMPLEMENT_cipher(aes, AES, ctr, CTR, 0, 256, 8, 128, stream)
/* aes192ctr_functions */
IMPLEMENT_cipher(aes, AES, ctr, CTR, 0, 192, 8, 128, stream)
/* aes128ctr_functions */
IMPLEMENT_cipher(aes, AES, ctr, CTR, 0, 128, 8, 128, stream)

#ifndef FIPS_MODE

# ifndef OPENSSL_NO_ARIA

static OSSL_OP_cipher_freectx_fn aria_freectx;
static OSSL_OP_cipher_dupctx_fn aria_dupctx;

static void aria_freectx(void *vctx)
{
    PROV_ARIA_KEY *ctx = (PROV_ARIA_KEY *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *aria_dupctx(void *ctx)
{
    PROV_ARIA_KEY *in = (PROV_ARIA_KEY *)ctx;
    PROV_ARIA_KEY *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    *ret = *in;

    return ret;
}

/* aria256ecb_functions */
IMPLEMENT_cipher(aria, ARIA, ecb, ECB, 0, 256, 128, 0, block)
/* aria192ecb_functions */
IMPLEMENT_cipher(aria, ARIA, ecb, ECB, 0, 192, 128, 0, block)
/* aria128ecb_functions */
IMPLEMENT_cipher(aria, ARIA, ecb, ECB, 0, 128, 128, 0, block)
/* aria256cbc_functions */
IMPLEMENT_cipher(aria, ARIA, cbc, CBC, 0, 256, 128, 128, block)
/* aria192cbc_functions */
IMPLEMENT_cipher(aria, ARIA, cbc, CBC, 0, 192, 128, 128, block)
/* aria128cbc_functions */
IMPLEMENT_cipher(aria, ARIA, cbc, CBC, 0, 128, 128, 128, block)
/* aria256ofb_functions */
IMPLEMENT_cipher(aria, ARIA, ofb, OFB, 0, 256, 8, 128, stream)
/* aria192ofb_functions */
IMPLEMENT_cipher(aria, ARIA, ofb, OFB, 0, 192, 8, 128, stream)
/* aria128ofb_functions */
IMPLEMENT_cipher(aria, ARIA, ofb, OFB, 0, 128, 8, 128, stream)
/* aria256cfb_functions */
IMPLEMENT_cipher(aria, ARIA, cfb,  CFB, 0, 256, 8, 128, stream)
/* aria192cfb_functions */
IMPLEMENT_cipher(aria, ARIA, cfb,  CFB, 0, 192, 8, 128, stream)
/* aria128cfb_functions */
IMPLEMENT_cipher(aria, ARIA, cfb,  CFB, 0, 128, 8, 128, stream)
/* aria256cfb1_functions */
IMPLEMENT_cipher(aria, ARIA, cfb1, CFB, 0, 256, 8, 128, stream)
/* aria192cfb1_functions */
IMPLEMENT_cipher(aria, ARIA, cfb1, CFB, 0, 192, 8, 128, stream)
/* aria128cfb1_functions */
IMPLEMENT_cipher(aria, ARIA, cfb1, CFB, 0, 128, 8, 128, stream)
/* aria256cfb8_functions */
IMPLEMENT_cipher(aria, ARIA, cfb8, CFB, 0, 256, 8, 128, stream)
/* aria192cfb8_functions */
IMPLEMENT_cipher(aria, ARIA, cfb8, CFB, 0, 192, 8, 128, stream)
/* aria128cfb8_functions */
IMPLEMENT_cipher(aria, ARIA, cfb8, CFB, 0, 128, 8, 128, stream)
/* aria256ctr_functions */
IMPLEMENT_cipher(aria, ARIA, ctr, CTR, 0, 256, 8, 128, stream)
/* aria192ctr_functions */
IMPLEMENT_cipher(aria, ARIA, ctr, CTR, 0, 192, 8, 128, stream)
/* aria128ctr_functions */
IMPLEMENT_cipher(aria, ARIA, ctr, CTR, 0, 128, 8, 128, stream)

# endif /* OPENSSL_NO_ARIA */


# ifndef OPENSSL_NO_CAMELLIA

static OSSL_OP_cipher_freectx_fn camellia_freectx;
static OSSL_OP_cipher_dupctx_fn camellia_dupctx;

static void camellia_freectx(void *vctx)
{
    PROV_CAMELLIA_KEY *ctx = (PROV_CAMELLIA_KEY *)vctx;

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *camellia_dupctx(void *ctx)
{
    PROV_CAMELLIA_KEY *in = (PROV_CAMELLIA_KEY *)ctx;
    PROV_CAMELLIA_KEY *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    *ret = *in;

    return ret;
}

/* camellia256ecb_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, ecb, ECB, 0, 256, 128, 0, block)
/* camellia192ecb_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, ecb, ECB, 0, 192, 128, 0, block)
/* camellia128ecb_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, ecb, ECB, 0, 128, 128, 0, block)
/* camellia256cbc_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, cbc, CBC, 0, 256, 128, 128, block)
/* camellia192cbc_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, cbc, CBC, 0, 192, 128, 128, block)
/* camellia128cbc_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, cbc, CBC, 0, 128, 128, 128, block)
/* camellia256ofb_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, ofb, OFB, 0, 256, 8, 128, stream)
/* camellia192ofb_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, ofb, OFB, 0, 192, 8, 128, stream)
/* camellia128ofb_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, ofb, OFB, 0, 128, 8, 128, stream)
/* camellia256cfb_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, cfb,  CFB, 0, 256, 8, 128, stream)
/* camellia192cfb_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, cfb,  CFB, 0, 192, 8, 128, stream)
/* camellia128cfb_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, cfb,  CFB, 0, 128, 8, 128, stream)
/* camellia256cfb1_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, cfb1, CFB, 0, 256, 8, 128, stream)
/* camellia192cfb1_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, cfb1, CFB, 0, 192, 8, 128, stream)
/* camellia128cfb1_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, cfb1, CFB, 0, 128, 8, 128, stream)
/* camellia256cfb8_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, cfb8, CFB, 0, 256, 8, 128, stream)
/* camellia192cfb8_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, cfb8, CFB, 0, 192, 8, 128, stream)
/* camellia128cfb8_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, cfb8, CFB, 0, 128, 8, 128, stream)
/* camellia256ctr_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, ctr, CTR, 0, 256, 8, 128, stream)
/* camellia192ctr_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, ctr, CTR, 0, 192, 8, 128, stream)
/* camellia128ctr_functions */
IMPLEMENT_cipher(camellia, CAMELLIA, ctr, CTR, 0, 128, 8, 128, stream)

# endif /* OPENSSL_NO_CAMELLIA */

#endif /* FIPS_MODE */
