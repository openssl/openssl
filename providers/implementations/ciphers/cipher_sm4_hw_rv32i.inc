/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * RISC-V 32 scalar ZKSED support for SM4 modes ecb, cbc, ofb, cfb, ctr.
 * This file is included by cipher_sm4_hw.c
 */

#define cipher_hw_rv32i_zksed_sm4_cbc    ossl_cipher_hw_generic_cbc
#define cipher_hw_rv32i_zksed_sm4_ecb    ossl_cipher_hw_generic_ecb
#define cipher_hw_rv32i_zksed_sm4_ofb128 ossl_cipher_hw_generic_ofb128
#define cipher_hw_rv32i_zksed_sm4_cfb128 ossl_cipher_hw_generic_cfb128
#define cipher_hw_rv32i_zksed_sm4_ctr    ossl_cipher_hw_generic_ctr

static int cipher_hw_rv32i_zksed_sm4_initkey(PROV_CIPHER_CTX *ctx,
                                             const unsigned char *key,
                                             size_t keylen)
{
    int ret;
    PROV_SM4_CTX *sctx = (PROV_SM4_CTX *)ctx;
    SM4_KEY *ks = &sctx->ks.ks;

    ctx->ks = ks;

    if (ctx->enc
        || (ctx->mode != EVP_CIPH_ECB_MODE && ctx->mode != EVP_CIPH_CBC_MODE)) {
        ret = rv32i_zksed_sm4_set_encrypt_key(key, ks);
        ctx->block = (block128_f)rv32i_zksed_sm4_encrypt;
        ctx->stream.cbc = NULL;
    } else {
        ret = rv32i_zksed_sm4_set_decrypt_key(key, ks);
        ctx->block = (block128_f)rv32i_zksed_sm4_decrypt;
        ctx->stream.cbc = NULL;
    }

    if (ret < 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

#define PROV_CIPHER_HW_declare(mode)                                   \
static const PROV_CIPHER_HW rv32i_zksed_sm4_##mode = {                 \
    cipher_hw_rv32i_zksed_sm4_initkey,                                 \
    cipher_hw_rv32i_zksed_sm4_##mode,                                  \
    cipher_hw_sm4_copyctx                                              \
};
#define PROV_CIPHER_HW_select(mode)                                    \
if (RISCV_HAS_ZKSED())                                                 \
    return &rv32i_zksed_sm4_##mode;
