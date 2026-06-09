/*
 * Copyright 2001-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Sparc t4 support for AES modes ecb, cbc, ofb, cfb, ctr.
 * This file is used by cipher_aes_hw.c
 */

#include "internal/deprecated.h"
#include <openssl/proverr.h>
#include "cipher_aes.h"

#if defined(SPARC_AES_CAPABLE)

static int t4_set_encrypt_key(const unsigned char *key, int bits, AES_KEY *ks)
{
    aes_t4_set_encrypt_key(key, bits, ks);
    return 0;
}

static int t4_set_decrypt_key(const unsigned char *key, int bits, AES_KEY *ks)
{
    aes_t4_set_decrypt_key(key, bits, ks);
    return 0;
}

static int cipher_hw_aes_t4_initkey(PROV_CIPHER_CTX *ctx,
    const unsigned char *key, size_t keylen)
{
    cbc128_f fn_cbc = NULL;
    if ((ctx->mode == EVP_CIPH_ECB_MODE || ctx->mode == EVP_CIPH_CBC_MODE)
        && !ctx->enc) {
        switch (keylen) {
        case 16:
            fn_cbc = (cbc128_f)aes128_t4_cbc_decrypt;
            break;
        case 24:
            fn_cbc = (cbc128_f)aes192_t4_cbc_decrypt;
            break;
        case 32:
            fn_cbc = (cbc128_f)aes256_t4_cbc_decrypt;
            break;
        default:
            ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
            return 0;
        }
        return ossl_cipher_set_aes_initkey(ctx, key, keylen, t4_set_decrypt_key,
            aes_t4_decrypt, NULL, fn_cbc, NULL);
    } else {
        ctr128_f fn_ctr = NULL;
        switch (keylen) {
        case 16:
            fn_cbc = (cbc128_f)aes128_t4_cbc_encrypt;
            fn_ctr = (ctr128_f)aes128_t4_ctr32_encrypt;
            break;
        case 24:
            fn_cbc = (cbc128_f)aes192_t4_cbc_encrypt;
            fn_ctr = (ctr128_f)aes192_t4_ctr32_encrypt;
            break;
        case 32:
            fn_cbc = (cbc128_f)aes256_t4_cbc_encrypt;
            fn_ctr = (ctr128_f)aes256_t4_ctr32_encrypt;
            break;
        default:
            ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
            return 0;
        }
        return ossl_cipher_set_aes_initkey(ctx, key, keylen, t4_set_encrypt_key,
            aes_t4_encrypt, NULL, fn_cbc, fn_ctr);
    }
}

static const PROV_CIPHER_HW aes_t4_ecb = {
    cipher_hw_aes_t4_initkey,
    ossl_cipher_hw_generic_ecb,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW aes_t4_cbc = {
    cipher_hw_aes_t4_initkey,
    ossl_cipher_hw_generic_cbc,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW aes_t4_cfb128 = {
    cipher_hw_aes_t4_initkey,
    ossl_cipher_hw_generic_cfb128,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW aes_t4_cfb8 = {
    cipher_hw_aes_t4_initkey,
    ossl_cipher_hw_generic_cfb8,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW aes_t4_cfb1 = {
    cipher_hw_aes_t4_initkey,
    ossl_cipher_hw_generic_cfb1,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW aes_t4_ofb128 = {
    cipher_hw_aes_t4_initkey,
    ossl_cipher_hw_generic_ofb128,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW aes_t4_ctr = {
    cipher_hw_aes_t4_initkey,
    ossl_cipher_hw_generic_ctr,
    ossl_cipher_aes_copyctx
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_t4(enum aes_modes mode,
    size_t keybits)
{
    if (SPARC_AES_CAPABLE) {
        switch (mode) {
        case AES_MODE_ECB:
            return &aes_t4_ecb;
        case AES_MODE_CBC:
            return &aes_t4_cbc;
        case AES_MODE_CFB128:
            return &aes_t4_cfb128;
        case AES_MODE_CFB8:
            return &aes_t4_cfb8;
        case AES_MODE_CFB1:
            return &aes_t4_cfb1;
        case AES_MODE_OFB128:
            return &aes_t4_ofb128;
        case AES_MODE_CTR:
            return &aes_t4_ctr;
        default:
            return NULL;
        }
    }
    return NULL;
}
#endif
