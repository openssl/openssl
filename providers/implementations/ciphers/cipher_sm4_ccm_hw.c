/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Generic support for SM4 CCM.
 */

#include "cipher_sm4_ccm.h"

static int ccm_sm4_initkey(PROV_CCM_CTX *ctx,
                           const unsigned char *key, size_t keylen)
{
    PROV_SM4_CCM_CTX *actx = (PROV_SM4_CCM_CTX *)ctx;

    ossl_sm4_set_key(key, &actx->ks.ks);
    CRYPTO_ccm128_init(&ctx->ccm_ctx, ctx->m, ctx->l, &actx->ks.ks,
                       (block128_f)ossl_sm4_encrypt);
    ctx->str = NULL;
    ctx->key_set = 1;
    return 1;
}

static const PROV_CCM_HW ccm_sm4 = {
    ccm_sm4_initkey,
    ossl_ccm_generic_setiv,
    ossl_ccm_generic_setaad,
    ossl_ccm_generic_auth_encrypt,
    ossl_ccm_generic_auth_decrypt,
    ossl_ccm_generic_gettag
};

const PROV_CCM_HW *ossl_prov_sm4_hw_ccm(size_t keybits)
{
    return &ccm_sm4;
}
