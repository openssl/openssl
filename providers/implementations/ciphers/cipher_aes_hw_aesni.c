/*
 * Copyright 2001-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * AES-NI support for AES modes ecb, cbc, ofb, cfb, ctr.
 * This file is used by cipher_aes_hw.c
 */

#include "internal/deprecated.h"
#include "cipher_aes.h"

#if defined(AESNI_CAPABLE)

/* generates AES round keys for AES-NI and VAES implementations */
static int cipher_hw_aesni_initkey(PROV_CIPHER_CTX *ctx,
    const unsigned char *key, size_t keylen)
{
    if ((ctx->mode == EVP_CIPH_ECB_MODE || ctx->mode == EVP_CIPH_CBC_MODE)
        && !ctx->enc) {
        return ossl_cipher_set_aes_initkey(ctx, key, keylen,
            aesni_set_decrypt_key, aesni_decrypt, NULL,
            (cbc128_f)aesni_cbc_encrypt, NULL);
    } else {
        return ossl_cipher_set_aes_initkey(ctx, key, keylen,
            aesni_set_encrypt_key, aesni_encrypt, NULL,
            (cbc128_f)aesni_cbc_encrypt, (ctr128_f)aesni_ctr32_encrypt_blocks);
    }
}

static int cipher_hw_aesni_ecb(PROV_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, size_t len)
{
    if (len < ctx->blocksize)
        return 1;

    aesni_ecb_encrypt(in, out, len, ctx->ks, ctx->enc);

    return 1;
}

static const PROV_CIPHER_HW aesni_ecb = {
    cipher_hw_aesni_initkey,
    cipher_hw_aesni_ecb,
    ossl_cipher_aes_copyctx
};

static int cipher_hw_aesni_cbc(PROV_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, size_t len)
{
    aesni_cbc_encrypt(in, out, len, ctx->ks, ctx->iv, ctx->enc);

    return 1;
}

static const PROV_CIPHER_HW aesni_cbc = {
    cipher_hw_aesni_initkey,
    cipher_hw_aesni_cbc,
    ossl_cipher_aes_copyctx
};

#if (defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64))
/* active in 64-bit builds when AES-NI, AVX512F, and VAES are detected */
#define VAES_CFB128_ELIGIBLE 1
#else
#define VAES_CFB128_ELIGIBLE 0
#endif

#if VAES_CFB128_ELIGIBLE
static int aes_cfb128_vaes_encdec_wrapper(
    PROV_CIPHER_CTX *ctx,
    unsigned char *out,
    const unsigned char *in,
    size_t len)
{
    ossl_ssize_t num;

    num = (ossl_ssize_t)ctx->num;

    if (num < 0) {
        /* behavior from CRYPTO_cfb128_encrypt */
        ctx->num = -1;
        return 1;
    }

    if (ctx->enc)
        ossl_aes_cfb128_vaes_enc(in, out, len, ctx->ks, ctx->iv, &num);
    else
        ossl_aes_cfb128_vaes_dec(in, out, len, ctx->ks, ctx->iv, &num);

    ctx->num = (int)num;

    return 1;
}

static const PROV_CIPHER_HW aesni_vaes_cfb128 = {
    cipher_hw_aesni_initkey,
    aes_cfb128_vaes_encdec_wrapper,
    ossl_cipher_aes_copyctx
};
#endif /* VAES_CFB128_ELIGIBLE */

static const PROV_CIPHER_HW aesni_cfb128 = {
    cipher_hw_aesni_initkey,
    ossl_cipher_hw_generic_cfb128,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW aesni_cfb8 = {
    cipher_hw_aesni_initkey,
    ossl_cipher_hw_generic_cfb8,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW aesni_cfb1 = {
    cipher_hw_aesni_initkey,
    ossl_cipher_hw_generic_cfb1,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW aesni_ofb128 = {
    cipher_hw_aesni_initkey,
    ossl_cipher_hw_generic_ofb128,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW aesni_ctr = {
    cipher_hw_aesni_initkey,
    ossl_cipher_hw_generic_ctr,
    ossl_cipher_aes_copyctx
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_aesni(enum aes_modes mode,
    size_t keybits)
{
    if (AESNI_CAPABLE) {
        switch (mode) {
        case AES_MODE_ECB:
            return &aesni_ecb;
        case AES_MODE_CBC:
            return &aesni_cbc;
        case AES_MODE_CFB128:
#if VAES_CFB128_ELIGIBLE
            if (ossl_aes_cfb128_vaes_eligible())
                return &aesni_vaes_cfb128;
#endif
            return &aesni_cfb128;
        case AES_MODE_CFB8:
            return &aesni_cfb8;
        case AES_MODE_CFB1:
            return &aesni_cfb1;
        case AES_MODE_OFB128:
            return &aesni_ofb128;
        case AES_MODE_CTR:
            return &aesni_ctr;
        default:
            return NULL;
        }
    }
    return NULL;
}

#endif
