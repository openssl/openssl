/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This file uses the low level AES functions (which are deprecated for
 * non-internal use) in order to implement provider AES ciphers.
 */
#include "internal/deprecated.h"

#include "cipher_aes_siv.h"

static int aes_siv_initkey(void *vctx, const unsigned char *key, size_t keylen)
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;
    SIV128_CONTEXT *sctx = &ctx->siv;
    size_t klen  = keylen / 2;

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

static int aes_siv_settag(void *vctx, const unsigned char *tag, size_t tagl)
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;
    SIV128_CONTEXT *sctx = &ctx->siv;

    return CRYPTO_siv128_set_tag(sctx, tag, tagl);
}

static void aes_siv_setspeed(void *vctx, int speed)
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;
    SIV128_CONTEXT *sctx = &ctx->siv;

    CRYPTO_siv128_speed(sctx, (int)speed);
}

static void aes_siv_cleanup(void *vctx)
{
    PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX *)vctx;
    SIV128_CONTEXT *sctx = &ctx->siv;

    CRYPTO_siv128_cleanup(sctx);
    EVP_CIPHER_free(ctx->cbc);
    EVP_CIPHER_free(ctx->ctr);
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

static const PROV_CIPHER_HW_AES_SIV aes_siv_hw =
{
    aes_siv_initkey,
    aes_siv_cipher,
    aes_siv_setspeed,
    aes_siv_settag,
    aes_siv_cleanup
};

const PROV_CIPHER_HW_AES_SIV *PROV_CIPHER_HW_aes_siv(size_t keybits)
{
    return &aes_siv_hw;
}
