/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * RISC-V 64 ZKND/ZKNE support for AES modes ecb, cbc, ofb, cfb, ctr.
 * This file is included by cipher_aes_hw.c
 *
 * Instruction set dependencies:
 *   rv64i_zkne_set_encrypt_key / rv64i_zkne_encrypt: aes64ks1i, aes64ks2,
 *     aes64es, aes64esm  ->  Zkne only
 *   rv64i_zknd_set_decrypt_key / rv64i_zknd_decrypt: aes64ks1i, aes64ks2
 *     (both present in Zknd), aes64im, aes64ds, aes64dsm  ->  Zknd only
 *
 * Therefore encryption and decryption can be accelerated independently:
 *   - Zkne present: hardware encrypt path, software decrypt fallback
 *   - Zknd present: hardware decrypt path, software encrypt fallback
 *   - Both present: hardware for both directions
 */

#define cipher_hw_rv64i_zkn_cbc    ossl_cipher_hw_generic_cbc
#define cipher_hw_rv64i_zkn_ecb    ossl_cipher_hw_generic_ecb
#define cipher_hw_rv64i_zkn_ofb128 ossl_cipher_hw_generic_ofb128
#define cipher_hw_rv64i_zkn_cfb128 ossl_cipher_hw_generic_cfb128
#define cipher_hw_rv64i_zkn_cfb8   ossl_cipher_hw_generic_cfb8
#define cipher_hw_rv64i_zkn_cfb1   ossl_cipher_hw_generic_cfb1
#define cipher_hw_rv64i_zkn_ctr    ossl_cipher_hw_generic_ctr

static int cipher_hw_rv64i_zkn_initkey(PROV_CIPHER_CTX *dat,
                                       const unsigned char *key, size_t keylen)
{
    int ret;
    PROV_AES_CTX *adat = (PROV_AES_CTX *)dat;
    AES_KEY *ks = &adat->ks.ks;

    dat->ks = ks;
    dat->stream.cbc = NULL;

    if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE)
        && !dat->enc) {
        if (RISCV_HAS_ZKND()) {
            ret = rv64i_zknd_set_decrypt_key(key, keylen * 8, ks);
            dat->block = (block128_f) rv64i_zknd_decrypt;
        } else {
            ret = AES_set_decrypt_key(key, (int)(keylen * 8), ks);
            dat->block = (block128_f) AES_decrypt;
        }
    } else {
        if (RISCV_HAS_ZKNE()) {
            ret = rv64i_zkne_set_encrypt_key(key, keylen * 8, ks);
            dat->block = (block128_f) rv64i_zkne_encrypt;
        } else {
            ret = AES_set_encrypt_key(key, (int)(keylen * 8), ks);
            dat->block = (block128_f) AES_encrypt;
        }
    }

    if (ret < 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

/*-
 * RISC-V RV64 ZVKNED support for AES modes ecb, cbc, ofb, cfb, ctr.
 * This file is included by cipher_aes_hw.c
 */

#define cipher_hw_rv64i_zvkned_cbc    ossl_cipher_hw_generic_cbc
#define cipher_hw_rv64i_zvkned_ecb    ossl_cipher_hw_generic_ecb
#define cipher_hw_rv64i_zvkned_ofb128 ossl_cipher_hw_generic_ofb128
#define cipher_hw_rv64i_zvkned_cfb128 ossl_cipher_hw_generic_cfb128
#define cipher_hw_rv64i_zvkned_cfb8   ossl_cipher_hw_generic_cfb8
#define cipher_hw_rv64i_zvkned_cfb1   ossl_cipher_hw_generic_cfb1
#define cipher_hw_rv64i_zvkned_ctr    ossl_cipher_hw_generic_ctr

static int cipher_hw_rv64i_zvkned_initkey(PROV_CIPHER_CTX *dat,
                                          const unsigned char *key,
                                          size_t keylen)
{
    int ret;
    PROV_AES_CTX *adat = (PROV_AES_CTX *)dat;
    AES_KEY *ks = &adat->ks.ks;

    dat->ks = ks;

    /*
     * Zvkned only supports 128 and 256 bit keys for key schedule generation.
     * For AES-192 case, we could fallback to `AES_set_encrypt_key`.
     * All Zvkned-based implementations use the same `encrypt-key` scheduling
     * for both encryption and decryption.
     */
    if (keylen * 8 == 128 || keylen * 8 == 256) {
        ret = rv64i_zvkned_set_encrypt_key(key, keylen * 8, ks);
    } else {
        ret = AES_set_encrypt_key(key, keylen * 8, ks);
    }

    if (dat->mode == EVP_CIPH_CBC_MODE) {
        if (dat->enc) {
            dat->stream.cbc = (cbc128_f) rv64i_zvkned_cbc_encrypt;
        } else {
            dat->stream.cbc = (cbc128_f) rv64i_zvkned_cbc_decrypt;
        }
    } else if (dat->mode == EVP_CIPH_CTR_MODE) {
        if (RISCV_HAS_ZVKB()) {
            dat->stream.ctr = (ctr128_f) rv64i_zvkb_zvkned_ctr32_encrypt_blocks;
        }
    } else if (dat->mode == EVP_CIPH_ECB_MODE) {
        if (dat->enc) {
            dat->stream.ecb = (ecb128_f) rv64i_zvkned_ecb_encrypt;
        } else {
            dat->stream.ecb = (ecb128_f) rv64i_zvkned_ecb_decrypt;
        }
    }

    /* Zvkned supports aes-128/192/256 encryption and decryption. */
    if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE) &&
        !dat->enc) {
        dat->block = (block128_f) rv64i_zvkned_decrypt;
    } else {
        dat->block = (block128_f) rv64i_zvkned_encrypt;
    }

    if (ret < 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

#define PROV_CIPHER_HW_declare(mode)                                           \
static const PROV_CIPHER_HW rv64i_zkn_##mode = {                               \
    cipher_hw_rv64i_zkn_initkey,                                               \
    cipher_hw_rv64i_zkn_##mode,                                                \
    cipher_hw_aes_copyctx                                                      \
};                                                                             \
static const PROV_CIPHER_HW rv64i_zvkned_##mode = {                            \
    cipher_hw_rv64i_zvkned_initkey,                                            \
    cipher_hw_rv64i_zvkned_##mode,                                             \
    cipher_hw_aes_copyctx                                                      \
};
#define PROV_CIPHER_HW_select(mode)                                            \
if (RISCV_HAS_ZVKNED() && riscv_vlen() >= 128)                                 \
    return &rv64i_zvkned_##mode;                                               \
else if (RISCV_HAS_ZKNE() || RISCV_HAS_ZKND())                                 \
    return &rv64i_zkn_##mode;
