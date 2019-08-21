/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include "cipher_locl.h"
#include "internal/ciphermode_platform.h"

#define AES_CCM_SET_KEY_FN(fn_set_enc_key, fn_blk, fn_ccm_enc, fn_ccm_dec)     \
    fn_set_enc_key(key, keylen * 8, &actx->ccm.ks.ks);                         \
    CRYPTO_ccm128_init(&ctx->ccm_ctx, ctx->m, ctx->l, &actx->ccm.ks.ks,        \
                       (block128_f)fn_blk);                                    \
    ctx->str = ctx->enc ? (ccm128_f)fn_ccm_enc : (ccm128_f)fn_ccm_dec;         \
    ctx->key_set = 1;

static int ccm_generic_aes_initkey(PROV_CCM_CTX *ctx, const unsigned char *key,
                                   size_t keylen)
{
    PROV_AES_CCM_CTX *actx = (PROV_AES_CCM_CTX *)ctx;

#ifdef HWAES_CAPABLE
    if (HWAES_CAPABLE) {
        AES_CCM_SET_KEY_FN(HWAES_set_encrypt_key, HWAES_encrypt, NULL, NULL);
    } else
#endif /* HWAES_CAPABLE */
#ifdef VPAES_CAPABLE
    if (VPAES_CAPABLE) {
        AES_CCM_SET_KEY_FN(vpaes_set_encrypt_key, vpaes_encrypt, NULL, NULL);
    } else
#endif
    {
        AES_CCM_SET_KEY_FN(AES_set_encrypt_key, AES_encrypt, NULL, NULL)
    }
    return 1;
}

static int ccm_generic_setiv(PROV_CCM_CTX *ctx, const unsigned char *nonce,
                             size_t nlen, size_t mlen)
{
    return CRYPTO_ccm128_setiv(&ctx->ccm_ctx, nonce, nlen, mlen) == 0;
}

static int ccm_generic_setaad(PROV_CCM_CTX *ctx, const unsigned char *aad,
                              size_t alen)
{
    CRYPTO_ccm128_aad(&ctx->ccm_ctx, aad, alen);
    return 1;
}

static int ccm_generic_gettag(PROV_CCM_CTX *ctx, unsigned char *tag,
                              size_t tlen)
{
    return CRYPTO_ccm128_tag(&ctx->ccm_ctx, tag, tlen) > 0;
}

static int ccm_generic_auth_encrypt(PROV_CCM_CTX *ctx, const unsigned char *in,
                                    unsigned char *out, size_t len,
                                    unsigned char *tag, size_t taglen)
{
    int rv;

    if (ctx->str != NULL)
        rv = CRYPTO_ccm128_encrypt_ccm64(&ctx->ccm_ctx, in,
                                         out, len, ctx->str) == 0;
    else
        rv = CRYPTO_ccm128_encrypt(&ctx->ccm_ctx, in, out, len) == 0;

    if (rv == 1 && tag != NULL)
        rv = (CRYPTO_ccm128_tag(&ctx->ccm_ctx, tag, taglen) > 0);
    return rv;
}

static int ccm_generic_auth_decrypt(PROV_CCM_CTX *ctx, const unsigned char *in,
                                    unsigned char *out, size_t len,
                                    unsigned char *expected_tag,
                                    size_t taglen)
{
    int rv = 0;

    if (ctx->str != NULL)
        rv = CRYPTO_ccm128_decrypt_ccm64(&ctx->ccm_ctx, in, out, len,
                                         ctx->str) == 0;
    else
        rv = CRYPTO_ccm128_decrypt(&ctx->ccm_ctx, in, out, len) == 0;
    if (rv) {
        unsigned char tag[16];

        if (!CRYPTO_ccm128_tag(&ctx->ccm_ctx, tag, taglen)
            || CRYPTO_memcmp(tag, expected_tag, taglen) != 0)
            rv = 0;
    }
    if (rv == 0)
        OPENSSL_cleanse(out, len);
    return rv;
}

static const PROV_CCM_HW aes_ccm = {
    ccm_generic_aes_initkey,
    ccm_generic_setiv,
    ccm_generic_setaad,
    ccm_generic_auth_encrypt,
    ccm_generic_auth_decrypt,
    ccm_generic_gettag
};
#if defined(S390X_aes_128_CAPABLE)
# include "cipher_aes_ccm_hw_s390x.inc"
#elif defined(AESNI_CAPABLE)
# include "cipher_aes_ccm_hw_aesni.inc"
#elif defined(SPARC_AES_CAPABLE)
# include "cipher_aes_ccm_hw_t4.inc"
#else
const PROV_CCM_HW *PROV_AES_HW_ccm(size_t keybits)
{
    return &aes_ccm;
}
#endif

#include "cipher_aria_ccm_hw.inc"
