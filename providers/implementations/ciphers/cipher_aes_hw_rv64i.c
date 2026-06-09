/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * RISC-V 64 ZKND ZKNE / ZVKNED support for AES modes ecb, cbc, ofb, cfb, ctr.
 * This file is used by cipher_aes_hw.c
 */

#include "internal/deprecated.h"
#include "cipher_aes.h"

#if defined(OPENSSL_CPUID_OBJ) && defined(__riscv) && __riscv_xlen == 64

static int cipher_hw_rv64i_initkey(PROV_CIPHER_CTX *ctx,
    const unsigned char *key, size_t keylen)
{
    if (RISCV_HAS_ZVKNED() && riscv_vlen() >= 128) {
        /*
         * Zvkned only supports 128 and 256 bit keys for key schedule
         * generation. For the AES-192 case, we fallback to the generic
         * `AES_set_encrypt_key`. All Zvkned-based implementations use the
         * same `encrypt-key` scheduling for both encryption and decryption.
         */
        aes_set_encrypt_key_fn fn_set_key = AES_set_encrypt_key;
        aes_block128_f fn_block = NULL;

        if (keylen * 8 == 128 || keylen * 8 == 256) {
            fn_set_key = rv64i_zvkned_set_encrypt_key;
        }
        ecb128_f fn_ecb = ctx->enc ? rv64i_zvkned_ecb_encrypt : rv64i_zvkned_ecb_decrypt;
        cbc128_f fn_cbc = ctx->enc ? rv64i_zvkned_cbc_encrypt : rv64i_zvkned_cbc_decrypt;
        ctr128_f fn_ctr = RISCV_HAS_ZVKB() ? (ctr128_f)rv64i_zvkb_zvkned_ctr32_encrypt_blocks : NULL;

        /* Zvkned supports aes-128/192/256 encryption and decryption. */
        if ((ctx->mode == EVP_CIPH_ECB_MODE || ctx->mode == EVP_CIPH_CBC_MODE)
            && !ctx->enc) {
            fn_block = rv64i_zvkned_decrypt;
        } else {
            fn_block = (block128_f)rv64i_zvkned_encrypt;
        }
        return ossl_cipher_set_aes_initkey(ctx, key, keylen, fn_set_key,
            fn_block, fn_ecb, fn_cbc, fn_ctr);
    } else if (RISCV_HAS_ZKND_AND_ZKNE()) {
        if ((ctx->mode == EVP_CIPH_ECB_MODE || ctx->mode == EVP_CIPH_CBC_MODE)
            && !ctx->enc) {
            return ossl_cipher_set_aes_initkey(ctx, key, keylen,
                rv64i_zknd_set_decrypt_key, rv64i_zknd_decrypt,
                NULL, NULL, NULL);
        } else {
            return ossl_cipher_set_aes_initkey(ctx, key, keylen,
                rv64i_zkne_set_encrypt_key, rv64i_zkne_encrypt,
                NULL, NULL, NULL);
        }
    }
    return 0;
}

static const PROV_CIPHER_HW rv64i_ecb = {
    cipher_hw_rv64i_initkey,
    ossl_cipher_hw_generic_ecb,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW rv64i_cbc = {
    cipher_hw_rv64i_initkey,
    ossl_cipher_hw_generic_cbc,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW rv64i_cfb128 = {
    cipher_hw_rv64i_initkey,
    ossl_cipher_hw_generic_cfb128,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW rv64i_cfb8 = {
    cipher_hw_rv64i_initkey,
    ossl_cipher_hw_generic_cfb8,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW rv64i_cfb1 = {
    cipher_hw_rv64i_initkey,
    ossl_cipher_hw_generic_cfb1,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW rv64i_ofb128 = {
    cipher_hw_rv64i_initkey,
    ossl_cipher_hw_generic_ofb128,
    ossl_cipher_aes_copyctx
};

static const PROV_CIPHER_HW rv64i_ctr = {
    cipher_hw_rv64i_initkey,
    ossl_cipher_hw_generic_ctr,
    ossl_cipher_aes_copyctx
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_rv64i(enum aes_modes mode,
    size_t keybits)
{
    if ((RISCV_HAS_ZVKNED() && riscv_vlen() >= 128)
        || RISCV_HAS_ZKND_AND_ZKNE()) {
        switch (mode) {
        case AES_MODE_ECB:
            return &rv64i_ecb;
        case AES_MODE_CBC:
            return &rv64i_cbc;
        case AES_MODE_CFB128:
            return &rv64i_cfb128;
        case AES_MODE_CFB8:
            return &rv64i_cfb8;
        case AES_MODE_CFB1:
            return &rv64i_cfb1;
        case AES_MODE_OFB128:
            return &rv64i_ofb128;
        case AES_MODE_CTR:
            return &rv64i_ctr;
        default:
            return NULL;
        }
    }
    return NULL;
}

#endif
