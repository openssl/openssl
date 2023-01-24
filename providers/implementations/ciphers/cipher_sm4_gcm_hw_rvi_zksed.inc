/*
 * Copyright 2001-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * RISC-V ZKSED support for SM4 GCM.
 * This file is included by cipher_sm4_gcm_hw.c
 */


static int rvi_zksed_set_encrypt_key_wrapper(const unsigned char *userKey, size_t bits, SM4_KEY *key) {
    return rvi_zksed_set_encrypt_key(userKey, key);
}

static int rvi_zksed_gcm_initkey(PROV_GCM_CTX *ctx, const unsigned char *key,
                                       size_t keylen)
{
    PROV_SM4_GCM_CTX *actx = (PROV_SM4_GCM_CTX *)ctx;
    SM4_KEY *ks = &actx->ks.ks;
    GCM_HW_SET_KEY_CTR_FN(ks, rvi_zksed_set_encrypt_key_wrapper, rvi_zksed_cipher,
                          NULL);
    return 1;
}

static const PROV_GCM_HW rvi_zksed_gcm = {
    rvi_zksed_gcm_initkey,
    ossl_gcm_setiv,
    ossl_gcm_aad_update,
    ossl_gcm_cipher_update,
    ossl_gcm_cipher_final,
    ossl_gcm_one_shot
};

const PROV_GCM_HW *ossl_prov_sm4_hw_gcm(size_t keybits)
{
    if (RVI_ZKSED_CAPABLE)
        return &rvi_zksed_gcm;
    else
        return &sm4_gcm;
}
