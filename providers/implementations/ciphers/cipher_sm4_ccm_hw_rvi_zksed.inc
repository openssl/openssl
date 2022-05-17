/*
 * Copyright 2001-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * RISC-V ZKSED support for SM4 CCM.
 * This file is included by cipher_sm4_gcm_hw.c
 */

static int ccm_rvi_zksed_initkey(PROV_CCM_CTX *ctx,
                                 const unsigned char *key, size_t keylen)
{
    PROV_SM4_CCM_CTX *actx = (PROV_SM4_CCM_CTX *)ctx;

    rvi_zksed_set_encrypt_key(key, &actx->ks.ks);
    CRYPTO_ccm128_init(&ctx->ccm_ctx, ctx->m, ctx->l, &actx->ks.ks,
                       (block128_f)rvi_zksed_cipher);
    ctx->str = NULL;
    ctx->key_set = 1;
    return 1;
}

static const PROV_CCM_HW rvi_zksed_ccm = {
    ccm_rvi_zksed_initkey,
    ossl_ccm_generic_setiv,
    ossl_ccm_generic_setaad,
    ossl_ccm_generic_auth_encrypt,
    ossl_ccm_generic_auth_decrypt,
    ossl_ccm_generic_gettag
};

const PROV_CCM_HW *ossl_prov_sm4_hw_ccm(size_t keybits)
{
    if (RVI_ZKSED_CAPABLE)
        return &rvi_zksed_ccm;
    else
        return &ccm_sm4;
}
