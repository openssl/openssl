/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Generic support for ARIA GCM.
 */

#include "cipher_aria_gcm.h"

static int aria_gcm_initkey(PROV_GCM_CTX *ctx, const unsigned char *key,
                            size_t keylen)
{
    PROV_ARIA_GCM_CTX *actx = (PROV_ARIA_GCM_CTX *)ctx;
    ARIA_KEY *ks = &actx->ks.ks;

    GCM_HW_SET_KEY_CTR_FN(ks, aria_set_encrypt_key, aria_encrypt, NULL);
    return 1;
}

static int aria_cipher_update(PROV_GCM_CTX *ctx, const unsigned char *in,
                              size_t len, unsigned char *out)
{
    if (ctx->enc) {
        if (CRYPTO_gcm128_encrypt(&ctx->gcm, in, out, len))
            return 0;
    } else {
        if (CRYPTO_gcm128_decrypt(&ctx->gcm, in, out, len))
            return 0;
    }
    return 1;
}

static const PROV_GCM_HW aria_gcm = {
    aria_gcm_initkey,
    gcm_setiv,
    gcm_aad_update,
    aria_cipher_update,
    gcm_cipher_final,
    gcm_one_shot
};
const PROV_GCM_HW *PROV_ARIA_HW_gcm(size_t keybits)
{
    return &aria_gcm;
}
