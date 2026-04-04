/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * RISC-V 64 ZVKSED support for SM4 XTS.
 * This file is included by cipher_sm4_xts_hw.c
 */

static int rv64i_zvksed_sm4_xts_initkey(PROV_CIPHER_CTX *ctx,
                                        const unsigned char *key,
                                        size_t keylen)
{
    PROV_SM4_XTS_CTX *xctx = (PROV_SM4_XTS_CTX *)ctx;

    XTS_SET_KEY_FN(rv64i_zvksed_sm4_set_encrypt_key,
                   rv64i_zvksed_sm4_set_decrypt_key,
                   rv64i_zvksed_sm4_encrypt,
                   rv64i_zvksed_sm4_decrypt,
                   (OSSL_xts_stream_fn)NULL,
                   (OSSL_xts_stream_fn)NULL);

    return 1;
}

static const PROV_CIPHER_HW rv64i_zvksed_sm4_xts = {
    rv64i_zvksed_sm4_xts_initkey,
    NULL,
    cipher_hw_sm4_xts_copyctx
};

static int cipher_hw_sm4_xts_rv64i_zvbb_zvkg_zvksed_initkey(PROV_CIPHER_CTX *ctx,
                                        const unsigned char *key,
                                        size_t keylen)
{
    PROV_SM4_XTS_CTX *xctx = (PROV_SM4_XTS_CTX *)ctx;

    XTS_SET_KEY_FN(rv64i_zvksed_sm4_set_encrypt_key,
                   rv64i_zvksed_sm4_set_decrypt_key,
                   rv64i_zvksed_sm4_encrypt,
                   rv64i_zvksed_sm4_decrypt,
                   (OSSL_xts_stream_fn)NULL,
                   (OSSL_xts_stream_fn)NULL);
    xctx->stream_gb = NULL;

    if (ctx->enc) {
        xctx->stream = (OSSL_xts_stream_fn)rv64i_zvbb_zvkg_zvksed_sm4_xts_encrypt;
        xctx->stream_gb = (OSSL_xts_stream_fn)rv64i_zvbb_zvkg_zvksed_sm4_xtsgb_encrypt;
    } else {
        xctx->stream = (OSSL_xts_stream_fn)rv64i_zvbb_zvkg_zvksed_sm4_xts_decrypt;
        xctx->stream_gb = (OSSL_xts_stream_fn)rv64i_zvbb_zvkg_zvksed_sm4_xtsgb_decrypt;
    }

    return 1;
}

static const PROV_CIPHER_HW rv64i_zvbb_zvkg_zvksed_sm4_xts = {
    cipher_hw_sm4_xts_rv64i_zvbb_zvkg_zvksed_initkey,
    NULL,
    cipher_hw_sm4_xts_copyctx
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_sm4_xts(size_t keybits)
{
    if (RISCV_HAS_ZVBB() && RISCV_HAS_ZVKG() && RISCV_HAS_ZVKSED() && riscv_vlen() >= 128)
        return &rv64i_zvbb_zvkg_zvksed_sm4_xts;
    else if (RISCV_HAS_ZVKB_AND_ZVKSED() && riscv_vlen() >= 128)
        return &rv64i_zvksed_sm4_xts;
    else
        return &sm4_generic_xts;
}
