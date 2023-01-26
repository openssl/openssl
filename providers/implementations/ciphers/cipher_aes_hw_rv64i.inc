/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * RISC-V 64 ZKND ZKNE support for AES modes ecb, cbc, ofb, cfb, ctr.
 * This file is included by cipher_aes_hw.c
 */

#define cipher_hw_rv64i_zknd_zkne_cbc    ossl_cipher_hw_generic_cbc
#define cipher_hw_rv64i_zknd_zkne_ecb    ossl_cipher_hw_generic_ecb
#define cipher_hw_rv64i_zknd_zkne_ofb128 ossl_cipher_hw_generic_ofb128
#define cipher_hw_rv64i_zknd_zkne_cfb128 ossl_cipher_hw_generic_cfb128
#define cipher_hw_rv64i_zknd_zkne_cfb8   ossl_cipher_hw_generic_cfb8
#define cipher_hw_rv64i_zknd_zkne_cfb1   ossl_cipher_hw_generic_cfb1
#define cipher_hw_rv64i_zknd_zkne_ctr    ossl_cipher_hw_generic_ctr

static int cipher_hw_rv64i_zknd_zkne_initkey(PROV_CIPHER_CTX *dat,
                                   const unsigned char *key, size_t keylen)
{
    int ret;
    PROV_AES_CTX *adat = (PROV_AES_CTX *)dat;
    AES_KEY *ks = &adat->ks.ks;

    dat->ks = ks;

    if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE)
        && !dat->enc) {
        ret = rv64i_zknd_set_decrypt_key(key, keylen * 8, ks);
        dat->block = (block128_f) rv64i_zknd_decrypt;
        dat->stream.cbc = NULL;
    } else {
        ret = rv64i_zkne_set_encrypt_key(key, keylen * 8, ks);
        dat->block = (block128_f) rv64i_zkne_encrypt;
        dat->stream.cbc = NULL;
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

    /* Zvkned only supports 128 and 256 bit keys. */
    if (keylen * 8 == 128 || keylen * 8 == 256) {
        if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE)
            && !dat->enc) {
            ret = rv64i_zvkned_set_decrypt_key(key, keylen * 8, ks);
            dat->block = (block128_f) rv64i_zvkned_decrypt;
            dat->stream.cbc = NULL;
        } else {
            ret = rv64i_zvkned_set_encrypt_key(key, keylen * 8, ks);
            dat->block = (block128_f) rv64i_zvkned_encrypt;
            dat->stream.cbc = NULL;
        }
    } else {
        if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE)
            && !dat->enc) {
            ret = AES_set_decrypt_key(key, keylen * 8, ks);
            dat->block = (block128_f)AES_decrypt;
            dat->stream.cbc = (dat->mode == EVP_CIPH_CBC_MODE)
                              ? (cbc128_f)AES_cbc_encrypt : NULL;
        } else {
            ret = AES_set_encrypt_key(key, keylen * 8, ks);
            dat->block = (block128_f)AES_encrypt;
            dat->stream.cbc = (dat->mode == EVP_CIPH_CBC_MODE)
                              ? (cbc128_f)AES_cbc_encrypt : NULL;
        }
    }

    if (ret < 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

#define PROV_CIPHER_HW_declare(mode)                                           \
static const PROV_CIPHER_HW rv64i_zknd_zkne_##mode = {                         \
    cipher_hw_rv64i_zknd_zkne_initkey,                                         \
    cipher_hw_rv64i_zknd_zkne_##mode,                                          \
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
else if (RISCV_HAS_ZKND_AND_ZKNE())                                            \
    return &rv64i_zknd_zkne_##mode;
