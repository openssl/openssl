/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* AES-NI section. */

static int aesni_init_key(PROV_GENERIC_KEY *dat, const unsigned char *key,
                          size_t keylen)
{
    int ret;
    PROV_AES_KEY *adat = (PROV_AES_KEY *)dat;
    AES_KEY *ks = &adat->ks.ks;

    dat->ks = ks;

    if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE)
        && !dat->enc) {
        ret = aesni_set_decrypt_key(key, keylen * 8, ks);
        dat->block = (block128_f) aesni_decrypt;
        dat->stream.cbc = dat->mode == EVP_CIPH_CBC_MODE ?
            (cbc128_f) aesni_cbc_encrypt : NULL;
    } else {
        ret = aesni_set_encrypt_key(key, keylen * 8, ks);
        dat->block = (block128_f) aesni_encrypt;
        if (dat->mode == EVP_CIPH_CBC_MODE)
            dat->stream.cbc = (cbc128_f) aesni_cbc_encrypt;
        else if (dat->mode == EVP_CIPH_CTR_MODE)
            dat->stream.ctr = (ctr128_f) aesni_ctr32_encrypt_blocks;
        else
            dat->stream.cbc = NULL;
    }

    if (ret < 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_AES_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

static int aesni_cbc_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                            const unsigned char *in, size_t len)
{
    const AES_KEY *ks = ctx->ks;

    aesni_cbc_encrypt(in, out, len, ks, ctx->iv, ctx->enc);

    return 1;
}

static int aesni_ecb_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                            const unsigned char *in, size_t len)
{
    if (len < ctx->blocksize)
        return 1;

    aesni_ecb_encrypt(in, out, len, ctx->ks, ctx->enc);

    return 1;
}

# define aesni_ofb128_cipher generic_ofb128_cipher
# define aesni_cfb128_cipher generic_cfb128_cipher
# define aesni_cfb8_cipher generic_cfb8_cipher
# define aesni_cfb1_cipher generic_cfb1_cipher
# define aesni_ctr_cipher generic_ctr_cipher

# define BLOCK_CIPHER_aes_generic_prov(mode)                                   \
static const PROV_GENERIC_CIPHER aesni_##mode = {                              \
        aesni_init_key,                                                        \
        aesni_##mode##_cipher};                                                \
PROV_GENERIC_CIPHER aes_##mode = {                                             \
        aes_init_key,                                                          \
        generic_##mode##_cipher};                                              \
const PROV_GENERIC_CIPHER *PROV_AES_CIPHER_##mode(size_t keybits)              \
{                                                                              \
    return AESNI_CAPABLE ? &aesni_##mode : &aes_##mode;                        \
}

