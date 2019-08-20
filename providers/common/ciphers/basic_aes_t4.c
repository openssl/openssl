/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* AES Sparc t4 support */

static int aes_t4_init_key(PROV_GENERIC_KEY *dat, const unsigned char *key,
                           size_t keylen)
{
    int ret, bits;
    PROV_AES_KEY *adat = (PROV_AES_KEY *)dat;

    dat->ks = &adat->ks.ks;

    bits = keylen * 8;
    if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE)
        && !dat->enc) {
        ret = 0;
        aes_t4_set_decrypt_key(key, bits, dat->ks);
        dat->block = (block128_f) aes_t4_decrypt;
        switch (bits) {
        case 128:
            dat->stream.cbc = dat->mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) aes128_t4_cbc_decrypt : NULL;
            break;
        case 192:
            dat->stream.cbc = dat->mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) aes192_t4_cbc_decrypt : NULL;
            break;
        case 256:
            dat->stream.cbc = dat->mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) aes256_t4_cbc_decrypt : NULL;
            break;
        default:
            ret = -1;
        }
    } else {
        ret = 0;
        aes_t4_set_encrypt_key(key, bits, dat->ks);
        dat->block = (block128_f)aes_t4_encrypt;
        switch (bits) {
        case 128:
            if (dat->mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f)aes128_t4_cbc_encrypt;
            else if (dat->mode == EVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f)aes128_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        case 192:
            if (dat->mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f)aes192_t4_cbc_encrypt;
            else if (dat->mode == EVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f)aes192_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        case 256:
            if (dat->mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f)aes256_t4_cbc_encrypt;
            else if (dat->mode == EVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f)aes256_t4_ctr32_encrypt;
            else
                dat->stream.cbc = NULL;
            break;
        default:
            ret = -1;
        }
    }

    if (ret < 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_AES_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

# define BLOCK_CIPHER_aes_generic_prov(mode)                                   \
static const PROV_GENERIC_CIPHER aes_t4_##mode = {                             \
        aes_t4_init_key,                                                       \
        generic_##mode##_cipher};                                              \
static const PROV_GENERIC_CIPHER aes_##mode = {                                \
        aes_init_key,                                                          \
        generic_##mode##_cipher};                                              \
const PROV_GENERIC_CIPHER *PROV_AES_CIPHER_##mode(size_t keybits)              \
{                                                                              \
    return SPARC_AES_CAPABLE? &aes_t4_##mode : &aes_##mode;                    \
}
