/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * RISC-V 32 ZKND ZKNE support for AES modes ecb, cbc, ofb, cfb, ctr.
 * This file is used by cipher_aes_hw.c
 */

#include "internal/deprecated.h"
#include "cipher_aes.h"

#if defined(OPENSSL_CPUID_OBJ) && defined(__riscv) && __riscv_xlen == 32

static int cipher_hw_rv32i_initkey(PROV_CIPHER_CTX *ctx,
    const unsigned char *key, size_t keylen)
{
    if ((ctx->mode == EVP_CIPH_ECB_MODE || ctx->mode == EVP_CIPH_CBC_MODE)
        && !ctx->enc) {
        if (RISCV_HAS_ZBKB_AND_ZKND_AND_ZKNE())
            return ossl_cipher_set_aes_initkey(ctx, key, keylen,
                rv32i_zbkb_zknd_zkne_set_decrypt_key, rv32i_zknd_decrypt,
                NULL, NULL, NULL);
        else
            return ossl_cipher_set_aes_initkey(ctx, key, keylen,
                rv32i_zknd_zkne_set_decrypt_key, rv32i_zknd_decrypt,
                NULL, NULL, NULL);
    } else {
        if (RISCV_HAS_ZBKB_AND_ZKND_AND_ZKNE())
            return ossl_cipher_set_aes_initkey(ctx, key, keylen,
                rv32i_zbkb_zkne_set_encrypt_key, rv32i_zkne_encrypt,
                NULL, NULL, NULL);
        else
            return ossl_cipher_set_aes_initkey(ctx, key, keylen,
                rv32i_zkne_set_encrypt_key, rv32i_zkne_encrypt,
                NULL, NULL, NULL);
    }
}

static const PROV_CIPHER_HW rv32i_ecb = {
    cipher_hw_rv32i_initkey,
    ossl_cipher_hw_generic_ecb,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW rv32i_cbc = {
    cipher_hw_rv32i_initkey,
    ossl_cipher_hw_generic_cbc,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW rv32i_cfb128 = {
    cipher_hw_rv32i_initkey,
    ossl_cipher_hw_generic_cfb128,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW rv32i_cfb8 = {
    cipher_hw_rv32i_initkey,
    ossl_cipher_hw_generic_cfb8,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW rv32i_cfb1 = {
    cipher_hw_rv32i_initkey,
    ossl_cipher_hw_generic_cfb1,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW rv32i_ofb128 = {
    cipher_hw_rv32i_initkey,
    ossl_cipher_hw_generic_ofb128,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW rv32i_ctr = {
    cipher_hw_rv32i_initkey,
    ossl_cipher_hw_generic_ctr,
    ossl_cipher_aes_copyctx
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_rv32i(enum aes_modes mode,
    size_t keybits)
{
    if (RISCV_HAS_ZKND_AND_ZKNE()) {
        switch (mode) {
        case AES_MODE_ECB:
            return &rv32i_ecb;
        case AES_MODE_CBC:
            return &rv32i_cbc;
        case AES_MODE_CFB128:
            return &rv32i_cfb128;
        case AES_MODE_CFB8:
            return &rv32i_cfb8;
        case AES_MODE_CFB1:
            return &rv32i_cfb1;
        case AES_MODE_OFB128:
            return &rv32i_ofb128;
        case AES_MODE_CTR:
            return &rv32i_ctr;
        default:
            return NULL;
        }
    }
    return NULL;
}

#endif
