/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * RISC-V 64 ZKND ZKNE support for AES GCM.
 * This file is included by cipher_aes_gcm_hw.c
 */

static int rv64i_zknd_zkne_gcm_initkey(PROV_GCM_CTX *ctx, const unsigned char *key,
                                       size_t keylen)
{
    PROV_AES_GCM_CTX *actx = (PROV_AES_GCM_CTX *)ctx;
    AES_KEY *ks = &actx->ks.ks;
    GCM_HW_SET_KEY_CTR_FN(ks, rv64i_zkne_set_encrypt_key, rv64i_zkne_encrypt,
                          NULL);
    return 1;
}

static const PROV_GCM_HW rv64i_zknd_zkne_gcm = {
    rv64i_zknd_zkne_gcm_initkey,
    ossl_gcm_setiv,
    ossl_gcm_aad_update,
    generic_aes_gcm_cipher_update,
    ossl_gcm_cipher_final,
    ossl_gcm_one_shot
};

const PROV_GCM_HW *ossl_prov_aes_hw_gcm(size_t keybits)
{
    if (RV64I_ZKND_ZKNE_CAPABLE)
        return &rv64i_zknd_zkne_gcm;
    else
        return &aes_gcm;
}
