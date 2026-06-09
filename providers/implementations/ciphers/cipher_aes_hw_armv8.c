/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Crypto extension support for AES modes ecb, cbc, ofb, cfb, ctr.
 * This file is used by cipher_aes_hw.c
 */

#include "internal/deprecated.h"
#include "cipher_aes.h"

#if defined(ARMv8_HWAES_CAPABLE)

static int cipher_hw_aes_arm_initkey(PROV_CIPHER_CTX *ctx,
    const unsigned char *key, size_t keylen)
{
    if (!ossl_cipher_hw_aes_initkey(ctx, key, keylen))
        return 0;

    if (AES_UNROLL12_EOR3_CAPABLE && ctx->mode == EVP_CIPH_CTR_MODE)
        ctx->stream.ctr = (ctr128_f)HWAES_ctr32_encrypt_blocks_unroll12_eor3;

    return 1;
}

static const PROV_CIPHER_HW arm_ctr = {
    cipher_hw_aes_arm_initkey,
    ossl_cipher_hw_generic_ctr,
    ossl_cipher_aes_copyctx
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_arm(enum aes_modes mode,
    size_t keybits)
{
    if (ARMv8_HWAES_CAPABLE && mode == AES_MODE_CTR)
        return &arm_ctr;
    return NULL;
}

#endif
