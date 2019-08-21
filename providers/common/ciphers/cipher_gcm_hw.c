/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "cipher_locl.h"
#include "internal/ciphermode_platform.h"

static const PROV_GCM_HW aes_gcm;

static int gcm_setiv(PROV_GCM_CTX *ctx, const unsigned char *iv, size_t ivlen);
static int gcm_aad_update(PROV_GCM_CTX *ctx, const unsigned char *aad,
                          size_t aad_len);
static int gcm_cipher_final(PROV_GCM_CTX *ctx, unsigned char *tag);
static int gcm_one_shot(PROV_GCM_CTX *ctx, unsigned char *aad, size_t aad_len,
                        const unsigned char *in, size_t in_len,
                        unsigned char *out, unsigned char *tag, size_t tag_len);
static int gcm_cipher_update(PROV_GCM_CTX *ctx, const unsigned char *in,
                             size_t len, unsigned char *out);

#define SET_KEY_CTR_FN(ks, fn_set_enc_key, fn_block, fn_ctr)                   \
    ctx->ks = ks;                                                              \
    fn_set_enc_key(key, keylen * 8, ks);                                       \
    CRYPTO_gcm128_init(&ctx->gcm, ks, (block128_f)fn_block);                   \
    ctx->ctr = (ctr128_f)fn_ctr;                                               \
    ctx->key_set = 1;

#if defined(AESNI_CAPABLE)
# include "cipher_aes_gcm_hw_aesni.inc"
#elif defined(AES_ASM) && (defined(__sparc) || defined(__sparc__))
# include "cipher_aes_gcm_hw_t4.inc"
#elif defined(OPENSSL_CPUID_OBJ) && defined(__s390__)
# include "cipher_aes_gcm_hw_s390x.inc"
#else
const PROV_GCM_HW *PROV_AES_HW_gcm(size_t keybits)
{
    return &aes_gcm;
}
#endif

static int generic_aes_gcm_initkey(PROV_GCM_CTX *ctx, const unsigned char *key,
                                   size_t keylen)
{
    PROV_AES_GCM_CTX *actx = (PROV_AES_GCM_CTX *)ctx;
    AES_KEY *ks = &actx->ks.ks;

# ifdef HWAES_CAPABLE
    if (HWAES_CAPABLE) {
#  ifdef HWAES_ctr32_encrypt_blocks
        SET_KEY_CTR_FN(ks, HWAES_set_encrypt_key, HWAES_encrypt,
                       HWAES_ctr32_encrypt_blocks);
#  else
        SET_KEY_CTR_FN(ks, HWAES_set_encrypt_key, HWAES_encrypt, NULL);
#  endif /* HWAES_ctr32_encrypt_blocks */
    } else
# endif /* HWAES_CAPABLE */

# ifdef BSAES_CAPABLE
    if (BSAES_CAPABLE) {
        SET_KEY_CTR_FN(ks, AES_set_encrypt_key, AES_encrypt,
                       bsaes_ctr32_encrypt_blocks);
    } else
# endif /* BSAES_CAPABLE */

# ifdef VPAES_CAPABLE
    if (VPAES_CAPABLE) {
        SET_KEY_CTR_FN(ks, vpaes_set_encrypt_key, vpaes_encrypt, NULL);
    } else
# endif /* VPAES_CAPABLE */

    {
# ifdef AES_CTR_ASM
        SET_KEY_CTR_FN(ks, AES_set_encrypt_key, AES_encrypt, AES_ctr32_encrypt);
# else
        SET_KEY_CTR_FN(ks, AES_set_encrypt_key, AES_encrypt, NULL);
# endif /* AES_CTR_ASM */
    }
    ctx->key_set = 1;
    return 1;
}

static int gcm_setiv(PROV_GCM_CTX *ctx, const unsigned char *iv, size_t ivlen)
{
    CRYPTO_gcm128_setiv(&ctx->gcm, iv, ivlen);
    return 1;
}

static int gcm_aad_update(PROV_GCM_CTX *ctx,
                          const unsigned char *aad, size_t aad_len)
{
    return CRYPTO_gcm128_aad(&ctx->gcm, aad, aad_len) == 0;
}

static int gcm_cipher_update(PROV_GCM_CTX *ctx, const unsigned char *in,
                             size_t len, unsigned char *out)
{
    if (ctx->enc) {
        if (ctx->ctr != NULL) {
#if defined(AES_GCM_ASM)
            size_t bulk = 0;

            if (len >= 32 && AES_GCM_ASM(ctx)) {
                size_t res = (16 - ctx->gcm.mres) % 16;

                if (CRYPTO_gcm128_encrypt(&ctx->gcm, in, out, res))
                    return 0;
                bulk = aesni_gcm_encrypt(in + res, out + res, len - res,
                                         ctx->gcm.key,
                                         ctx->gcm.Yi.c, ctx->gcm.Xi.u);
                ctx->gcm.len.u[1] += bulk;
                bulk += res;
            }
            if (CRYPTO_gcm128_encrypt_ctr32(&ctx->gcm, in + bulk, out + bulk,
                                            len - bulk, ctx->ctr))
                return 0;
#else
            if (CRYPTO_gcm128_encrypt_ctr32(&ctx->gcm, in, out, len, ctx->ctr))
                return 0;
#endif /* AES_GCM_ASM */
        } else {
            if (CRYPTO_gcm128_encrypt(&ctx->gcm, in, out, len))
                return 0;
        }
    } else {
        if (ctx->ctr != NULL) {
#if defined(AES_GCM_ASM)
            size_t bulk = 0;

            if (len >= 16 && AES_GCM_ASM(ctx)) {
                size_t res = (16 - ctx->gcm.mres) % 16;

                if (CRYPTO_gcm128_decrypt(&ctx->gcm, in, out, res))
                    return -1;

                bulk = aesni_gcm_decrypt(in + res, out + res, len - res,
                                         ctx->gcm.key,
                                         ctx->gcm.Yi.c, ctx->gcm.Xi.u);
                ctx->gcm.len.u[1] += bulk;
                bulk += res;
            }
            if (CRYPTO_gcm128_decrypt_ctr32(&ctx->gcm, in + bulk, out + bulk,
                                            len - bulk, ctx->ctr))
                return 0;
#else
            if (CRYPTO_gcm128_decrypt_ctr32(&ctx->gcm, in, out, len, ctx->ctr))
                return 0;
#endif /* AES_GCM_ASM */
        } else {
            if (CRYPTO_gcm128_decrypt(&ctx->gcm, in, out, len))
                return 0;
        }
    }
    return 1;
}

static int gcm_cipher_final(PROV_GCM_CTX *ctx, unsigned char *tag)
{
    if (ctx->enc) {
        CRYPTO_gcm128_tag(&ctx->gcm, tag, GCM_TAG_MAX_SIZE);
        ctx->taglen = GCM_TAG_MAX_SIZE;
    } else {
        if (ctx->taglen < 0
            || CRYPTO_gcm128_finish(&ctx->gcm, tag, ctx->taglen) != 0)
            return 0;
    }
    return 1;
}

static int gcm_one_shot(PROV_GCM_CTX *ctx, unsigned char *aad, size_t aad_len,
                        const unsigned char *in, size_t in_len,
                        unsigned char *out, unsigned char *tag, size_t tag_len)
{
    int ret = 0;

    /* Use saved AAD */
    if (!ctx->hw->aadupdate(ctx, aad, aad_len))
        goto err;
    if (!ctx->hw->cipherupdate(ctx, in, in_len, out))
        goto err;
    ctx->taglen = GCM_TAG_MAX_SIZE;
    if (!ctx->hw->cipherfinal(ctx, tag))
        goto err;
    ret = 1;

err:
    return ret;
}

static const PROV_GCM_HW aes_gcm = {
    generic_aes_gcm_initkey,
    gcm_setiv,
    gcm_aad_update,
    gcm_cipher_update,
    gcm_cipher_final,
    gcm_one_shot
};

#include "cipher_aria_gcm_hw.inc"
