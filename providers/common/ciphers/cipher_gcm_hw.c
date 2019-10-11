/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "prov/ciphercommon.h"
#include "prov/cipher_gcm.h"


int gcm_setiv(PROV_GCM_CTX *ctx, const unsigned char *iv, size_t ivlen)
{
    CRYPTO_gcm128_setiv(&ctx->gcm, iv, ivlen);
    return 1;
}

int gcm_aad_update(PROV_GCM_CTX *ctx, const unsigned char *aad, size_t aad_len)
{
    return CRYPTO_gcm128_aad(&ctx->gcm, aad, aad_len) == 0;
}

int gcm_cipher_update(PROV_GCM_CTX *ctx, const unsigned char *in,
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

int gcm_cipher_final(PROV_GCM_CTX *ctx, unsigned char *tag)
{
    if (ctx->enc) {
        CRYPTO_gcm128_tag(&ctx->gcm, tag, GCM_TAG_MAX_SIZE);
        ctx->taglen = GCM_TAG_MAX_SIZE;
    } else {
        if (CRYPTO_gcm128_finish(&ctx->gcm, tag, ctx->taglen) != 0)
            return 0;
    }
    return 1;
}

int gcm_one_shot(PROV_GCM_CTX *ctx, unsigned char *aad, size_t aad_len,
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
