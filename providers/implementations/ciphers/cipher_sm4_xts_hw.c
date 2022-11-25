/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "cipher_sm4_xts.h"

#define XTS_SET_KEY_FN(fn_set_enc_key, fn_set_dec_key,                         \
                       fn_block_enc, fn_block_dec,                             \
                       fn_stream_enc, fn_stream_dec,                           \
                       fn_stream_gb_enc, fn_stream_gb_dec) {                   \
    size_t bytes = keylen / 2;                                                 \
                                                                               \
    if (ctx->enc) {                                                            \
        fn_set_enc_key(key, &xctx->ks1.ks);                                    \
        xctx->xts.block1 = (block128_f)fn_block_enc;                           \
    } else {                                                                   \
        fn_set_dec_key(key, &xctx->ks1.ks);                                    \
        xctx->xts.block1 = (block128_f)fn_block_dec;                           \
    }                                                                          \
    fn_set_enc_key(key + bytes, &xctx->ks2.ks);                                \
    xctx->xts.block2 = (block128_f)fn_block_enc;                               \
    xctx->xts.key1 = &xctx->ks1;                                               \
    xctx->xts.key2 = &xctx->ks2;                                               \
    xctx->stream = ctx->enc ? fn_stream_enc : fn_stream_dec;                   \
    xctx->stream_gb = ctx->enc ? fn_stream_gb_enc : fn_stream_gb_dec;          \
}

static int cipher_hw_sm4_xts_generic_initkey(PROV_CIPHER_CTX *ctx,
                                             const unsigned char *key,
                                             size_t keylen)
{
    PROV_SM4_XTS_CTX *xctx = (PROV_SM4_XTS_CTX *)ctx;
    OSSL_xts_stream_fn stream_enc = NULL;
    OSSL_xts_stream_fn stream_dec = NULL;
    OSSL_xts_stream_fn stream_gb_enc = NULL;
    OSSL_xts_stream_fn stream_gb_dec = NULL;
#ifdef HWSM4_CAPABLE
    if (HWSM4_CAPABLE) {
        XTS_SET_KEY_FN(HWSM4_set_encrypt_key, HWSM4_set_decrypt_key,
                       HWSM4_encrypt, HWSM4_decrypt, stream_enc, stream_dec,
                       stream_gb_enc, stream_gb_dec);
        return 1;
    } else
#endif /* HWSM4_CAPABLE */
#ifdef VPSM4_CAPABLE
    if (VPSM4_CAPABLE) {
        XTS_SET_KEY_FN(vpsm4_set_encrypt_key, vpsm4_set_decrypt_key,
                       vpsm4_encrypt, vpsm4_decrypt, stream_enc, stream_dec,
                       stream_gb_enc, stream_gb_dec);
        return 1;
    } else
#endif /* VPSM4_CAPABLE */
    {
        (void)0;
    }
    {
        XTS_SET_KEY_FN(ossl_sm4_set_key, ossl_sm4_set_key, ossl_sm4_encrypt,
                       ossl_sm4_decrypt, stream_enc, stream_dec, stream_gb_enc,
                       stream_gb_dec);
    }
    return 1;
}

static void cipher_hw_sm4_xts_copyctx(PROV_CIPHER_CTX *dst,
                                      const PROV_CIPHER_CTX *src)
{
    PROV_SM4_XTS_CTX *sctx = (PROV_SM4_XTS_CTX *)src;
    PROV_SM4_XTS_CTX *dctx = (PROV_SM4_XTS_CTX *)dst;

    *dctx = *sctx;
    dctx->xts.key1 = &dctx->ks1.ks;
    dctx->xts.key2 = &dctx->ks2.ks;
}


static const PROV_CIPHER_HW sm4_generic_xts = {
    cipher_hw_sm4_xts_generic_initkey,
    NULL,
    cipher_hw_sm4_xts_copyctx
};
const PROV_CIPHER_HW *ossl_prov_cipher_hw_sm4_xts(size_t keybits)
{
    return &sm4_generic_xts;
}
