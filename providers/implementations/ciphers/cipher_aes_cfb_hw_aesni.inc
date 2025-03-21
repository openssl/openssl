/*
 * Copyright 2001-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * AES-NI and VAES support for AES CFB mode.
 * This file is included by cipher_aes_cfb_hw.c
 */

#include <assert.h>

#define cipher_hw_vaes_cfb128  aes_cfb128_vaes_encdec_wrapper
#define cipher_hw_vaes_cfb8    ossl_cipher_hw_generic_cfb8
#define cipher_hw_vaes_cfb1    ossl_cipher_hw_generic_cfb1

#define cipher_hw_aesni_cfb128 ossl_cipher_hw_generic_cfb128
#define cipher_hw_aesni_cfb8   ossl_cipher_hw_generic_cfb8
#define cipher_hw_aesni_cfb1   ossl_cipher_hw_generic_cfb1

// active when AES-NI, AVX512F, and VAES are detected
static int aes_cfb128_vaes_encdec_wrapper(
    PROV_CIPHER_CTX* dat,
    unsigned char *out,
    const unsigned char *in,
    size_t len)
{
    assert(dat != NULL);
    assert(out != NULL);
    assert(in  != NULL);

    assert(dat->mode == EVP_CIPH_CFB_MODE);

    assert(dat->keylen == 16 || dat->keylen == 24 || dat->keylen == 32);
    assert(dat->ks != NULL);

    assert(dat->ivlen == 16);
    assert(dat->iv != NULL);

    assert(dat->enc == 0 || dat->enc == 1);

    int num = dat->num;
    assert(num < 16);
    if (num < 0) {
        // from CRYPTO_cfb128_encrypt
        dat->num = -1;
        return 1;
    }

    if (dat->enc) {
        aes_cfb128_vaes_enc(in, out, len, dat->ks, dat->iv, &num);
    } else {
        CRYPTO_cfb128_encrypt(in, out, len, dat->ks, dat->iv, &num, dat->enc,
            dat->block);
    }

    assert(num < 16);
    dat->num = num;

    return 1;
}

// generates AES round keys for AES-NI and VAES implementations
static int cipher_hw_aesni_initkey(PROV_CIPHER_CTX *dat,
                                   const unsigned char *key, size_t keylen)
{
    int ret;
    PROV_AES_CTX *adat = (PROV_AES_CTX *)dat;
    AES_KEY *ks = &adat->ks.ks;

    dat->ks = ks;

    ret = aesni_set_encrypt_key(key, keylen * 8, ks);

    dat->block = (block128_f) aesni_encrypt;
    dat->stream.cbc = NULL;

    if (ret < 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

#define VAES_BIT    (1<<(41-32))
#define AVX512F_BIT (1<<16)

#define AVX512F_VAES_CAPABLE (                                                 \
    (OPENSSL_ia32cap_P[3] & VAES_BIT)                                          \
    &&                                                                         \
    (OPENSSL_ia32cap_P[2] & AVX512F_BIT)                                       \
)

#define PROV_CIPHER_HW_declare(mode)                                           \
static const PROV_CIPHER_HW aesni_##mode = {                                   \
    cipher_hw_aesni_initkey,                                                   \
    cipher_hw_aesni_##mode,                                                    \
    cipher_hw_aes_copyctx                                                      \
};                                                                             \
static const PROV_CIPHER_HW vaes_##mode = {                                    \
    cipher_hw_aesni_initkey,                                                   \
    cipher_hw_vaes_##mode,                                                     \
    cipher_hw_aes_copyctx                                                      \
};
#define PROV_CIPHER_HW_select(mode)                                            \
if (AESNI_CAPABLE) {                                                           \
    if (AVX512F_VAES_CAPABLE)                                                  \
        return &vaes_##mode;                                                   \
    return &aesni_##mode;                                                      \
}
