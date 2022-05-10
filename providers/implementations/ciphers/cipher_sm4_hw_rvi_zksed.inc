/*
 * Copyright 2001-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * RISC-V ZKSED support for SM4 modes ecb, cbc, ofb, cfb, ctr.
 * This file is included by cipher_sm4_hw.c
 */

#define cipher_hw_rvi_zksed_cbc    ossl_cipher_hw_generic_cbc
#define cipher_hw_rvi_zksed_ecb    ossl_cipher_hw_generic_ecb
#define cipher_hw_rvi_zksed_ofb128 ossl_cipher_hw_generic_ofb128
#define cipher_hw_rvi_zksed_cfb128 ossl_cipher_hw_generic_cfb128
#define cipher_hw_rvi_zksed_ctr    ossl_cipher_hw_generic_ctr

static int cipher_hw_rvi_zksed_initkey(PROV_CIPHER_CTX *dat,
                                   const unsigned char *key, size_t keylen)
{
    int ret;
    PROV_SM4_CTX *adat = (PROV_SM4_CTX *)dat;
    SM4_KEY *ks = &adat->ks.ks;

    dat->ks = ks;

    if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE)
        && !dat->enc) {
        ret = rvi_zksed_set_decrypt_key(key, ks);
        dat->block = (block128_f) rvi_zksed_cipher;
        dat->stream.cbc = NULL;
    } else {
        ret = rvi_zksed_set_encrypt_key(key, ks);
        dat->block = (block128_f) rvi_zksed_cipher;
        dat->stream.cbc = NULL;
    }

    if (ret < 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

#define PROV_CIPHER_HW_declare(mode)                                         \
static const PROV_CIPHER_HW rvi_zksed_##mode = {                             \
    cipher_hw_rvi_zksed_initkey,                                             \
    cipher_hw_rvi_zksed_##mode,                                              \
    cipher_hw_sm4_copyctx                                                    \
};
#define PROV_CIPHER_HW_select(mode)                                          \
if (RVI_ZKSED_CAPABLE)                                                       \
    return &rvi_zksed_##mode;
