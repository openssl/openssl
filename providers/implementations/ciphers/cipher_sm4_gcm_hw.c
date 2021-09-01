/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Generic support for SM4 GCM.
 */

#include "cipher_sm4_gcm.h"

static int sm4_gcm_initkey(PROV_GCM_CTX *ctx, const unsigned char *key,
                           size_t keylen)
{
    PROV_SM4_GCM_CTX *actx = (PROV_SM4_GCM_CTX *)ctx;
    SM4_KEY *ks = &actx->ks.ks;

    ctx->ks = ks;
    ossl_sm4_set_key(key, ks);
    CRYPTO_gcm128_init(&ctx->gcm, ks, (block128_f)ossl_sm4_encrypt);
    ctx->ctr = (ctr128_f)NULL;
    ctx->key_set = 1;

    return 1;
}

static const PROV_GCM_HW sm4_gcm = {
    sm4_gcm_initkey,
    ossl_gcm_setiv,
    ossl_gcm_aad_update,
    ossl_gcm_cipher_update,
    ossl_gcm_cipher_final,
    ossl_gcm_one_shot
};

const PROV_GCM_HW *ossl_prov_sm4_hw_gcm(size_t keybits)
{
    return &sm4_gcm;
}
