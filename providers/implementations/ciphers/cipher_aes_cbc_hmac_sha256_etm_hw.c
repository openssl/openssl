/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include "internal/deprecated.h"
#include "cipher_aes_cbc_hmac_sha_etm.h"

#if !defined(AES_CBC_HMAC_SHA_ETM_CAPABLE)
int ossl_cipher_capable_aes_cbc_hmac_sha256_etm(void)
{
    return 0;
}

const PROV_CIPHER_HW_AES_HMAC_SHA_ETM *ossl_prov_cipher_hw_aes_cbc_hmac_sha256_etm(void)
{
    return NULL;
}
#else
void sha256_block_data_order(void *c, const void *p, size_t len);

# if defined(__aarch64__)
int asm_aescbc_sha256_hmac(const uint8_t *csrc, uint8_t *cdst, uint64_t clen,
                           uint8_t *dsrc, uint8_t *ddst, uint64_t dlen,
                           CIPH_DIGEST *arg);
void asm_sha256_hmac_aescbc_dec(const uint8_t *csrc, uint8_t *cdst, uint64_t clen,
                                const unsigned char *dsrc, uint8_t *ddst, size_t dlen,
                                CIPH_DIGEST *arg);
#  define HWAES128_ENC_CBC_SHA256_ETM asm_aescbc_sha256_hmac
#  define HWAES128_DEC_CBC_SHA256_ETM asm_sha256_hmac_aescbc_dec
# endif

int ossl_cipher_capable_aes_cbc_hmac_sha256_etm(void)
{
    return HWAES_CBC_HMAC_SHA256_ETM_CAPABLE;
}

static int aes_cbc_hmac_sha256_init_key(PROV_CIPHER_CTX *vctx,
                                        const unsigned char *key, size_t keylen)
{
    int ret;
    PROV_AES_HMAC_SHA_ETM_CTX *ctx = (PROV_AES_HMAC_SHA_ETM_CTX *)vctx;
    PROV_AES_HMAC_SHA256_ETM_CTX *sctx = (PROV_AES_HMAC_SHA256_ETM_CTX *)vctx;

    if (ctx->base.enc)
        ret = aes_v8_set_encrypt_key(key, keylen * 8, &ctx->ks);
    else
        ret = aes_v8_set_decrypt_key(key, keylen * 8, &ctx->ks);

    SHA256_Init(&sctx->head);      /* handy when benchmarking */
    sctx->tail = sctx->head;

    return ret < 0 ? 0 : 1;
}

static void ciph_digest_arg_init(CIPH_DIGEST *arg, PROV_CIPHER_CTX *vctx)
{
    PROV_AES_HMAC_SHA_ETM_CTX *ctx = (PROV_AES_HMAC_SHA_ETM_CTX *)vctx;
    PROV_AES_HMAC_SHA256_ETM_CTX *sctx = (PROV_AES_HMAC_SHA256_ETM_CTX *)vctx;

    arg->cipher.key = (uint8_t *)&(ctx->ks);
    arg->cipher.key_rounds = ctx->ks.rounds;
    arg->cipher.iv = (uint8_t *)&(ctx->base.iv);
    arg->digest.hmac.i_key_pad = (uint8_t *)&(sctx->head);
    arg->digest.hmac.o_key_pad = (uint8_t *)&(sctx->tail);
}

static int hwaes_cbc_hmac_sha256_etm(PROV_CIPHER_CTX *vctx,
                                     unsigned char *out,
                                     const unsigned char *in, size_t len)
{
    PROV_AES_HMAC_SHA_ETM_CTX *ctx = (PROV_AES_HMAC_SHA_ETM_CTX *)vctx;
    CIPH_DIGEST arg = {0};

    ciph_digest_arg_init(&arg, vctx);

    if (len % AES_BLOCK_SIZE) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_INPUT_LENGTH);
        return 0;
    }
    if (ctx->base.enc) {
        HWAES128_ENC_CBC_SHA256_ETM(in, out, len, out, ctx->tag, len, &arg);
        return 1;
    } else {
        if (ctx->taglen == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            return 0;
        }
        HWAES128_DEC_CBC_SHA256_ETM(in, out, len, in, ctx->tag, len, &arg);
        if (CRYPTO_memcmp(ctx->exp_tag, ctx->tag, ctx->taglen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
            return 0;
        }
        return 1;
    }
}

static void sha256_update(SHA256_CTX *c, const void *data, size_t len)
{
    const unsigned char *ptr = data;
    size_t res;

    if ((res = c->num)) {
        res = SHA256_CBLOCK - res;
        if (len < res)
            res = len;
        SHA256_Update(c, ptr, res);
        ptr += res;
        len -= res;
    }

    res = len % SHA256_CBLOCK;
    len -= res;

    if (len) {
        sha256_block_data_order(c, ptr, len / SHA256_CBLOCK);

        ptr += len;
        c->Nh += len >> 29;
        c->Nl += len <<= 3;
        if (c->Nl < (unsigned int)len)
            c->Nh++;
    }

    if (res)
        SHA256_Update(c, ptr, res);
}

static void aes_cbc_hmac_sha256_set_mac_key(void *vctx,
                                            const unsigned char *mac, size_t len)
{
    PROV_AES_HMAC_SHA256_ETM_CTX *ctx = (PROV_AES_HMAC_SHA256_ETM_CTX *)vctx;
    unsigned int i;
    unsigned char hmac_key[64];

    memset(hmac_key, 0, sizeof(hmac_key));

    if (len > (int)sizeof(hmac_key)) {
        SHA256_Init(&ctx->head);
        sha256_update(&ctx->head, mac, len);
        SHA256_Final(hmac_key, &ctx->head);
    } else {
        memcpy(hmac_key, mac, len);
    }

    for (i = 0; i < sizeof(hmac_key); i++)
        hmac_key[i] ^= 0x36; /* ipad */
    SHA256_Init(&ctx->head);
    sha256_update(&ctx->head, hmac_key, sizeof(hmac_key));

    for (i = 0; i < sizeof(hmac_key); i++)
        hmac_key[i] ^= 0x36 ^ 0x5c; /* opad */
    SHA256_Init(&ctx->tail);
    sha256_update(&ctx->tail, hmac_key, sizeof(hmac_key));

    OPENSSL_cleanse(hmac_key, sizeof(hmac_key));
}

static int aes_cbc_hmac_sha256_cipher(PROV_CIPHER_CTX *vctx,
                                      unsigned char *out,
                                      const unsigned char *in, size_t len)
{
    return hwaes_cbc_hmac_sha256_etm(vctx, out, in, len);
}

static const PROV_CIPHER_HW_AES_HMAC_SHA_ETM cipher_hw_aes_hmac_sha256_etm = {
    {
        aes_cbc_hmac_sha256_init_key,
        aes_cbc_hmac_sha256_cipher
    },
    aes_cbc_hmac_sha256_set_mac_key
};

const PROV_CIPHER_HW_AES_HMAC_SHA_ETM *ossl_prov_cipher_hw_aes_cbc_hmac_sha256_etm(void)
{
    return &cipher_hw_aes_hmac_sha256_etm;
}
#endif
