/*
 * Copyright 2001-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * AES-NI support for AES modes ecb, cbc, ofb, ctr.
 * This file is included by cipher_aes_hw.c
 */

#define cipher_hw_aesni_ofb128 ossl_cipher_hw_generic_ofb128
#define cipher_hw_aesni_ctr    ossl_cipher_hw_generic_ctr

static int cipher_hw_aesni_initkey(PROV_CIPHER_CTX *dat,
                                   const unsigned char *key, size_t keylen)
{
    int ret;
    PROV_AES_CTX *adat = (PROV_AES_CTX *)dat;
    AES_KEY *ks = &adat->ks.ks;

    dat->ks = ks;

    if ((dat->mode == EVP_CIPH_ECB_MODE || dat->mode == EVP_CIPH_CBC_MODE)
        && !dat->enc) {
        ret = aesni_set_decrypt_key(key, (int)(keylen * 8), ks);
        dat->block = (block128_f) aesni_decrypt;
        dat->stream.cbc = dat->mode == EVP_CIPH_CBC_MODE ?
            (cbc128_f) aesni_cbc_encrypt : NULL;
    } else {
        ret = aesni_set_encrypt_key(key, (int)(keylen * 8), ks);
        dat->block = (block128_f) aesni_encrypt;
        if (dat->mode == EVP_CIPH_CBC_MODE)
            dat->stream.cbc = (cbc128_f) aesni_cbc_encrypt;
        else if (dat->mode == EVP_CIPH_CTR_MODE)
            dat->stream.ctr = (ctr128_f) aesni_ctr32_encrypt_blocks;
        else
            dat->stream.cbc = NULL;
    }

    if (ret < 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

#if !(defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)) \
    || (!((defined(__GNUC__) && !defined(__clang__) && (__GNUC__ >= 8)) || (defined(__clang__) && (__clang_major__ >= 7)) || (defined(_MSC_VER) && (_MSC_VER >= 1927))))

static int cipher_hw_aesni_cbc(PROV_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    const AES_KEY *ks = ctx->ks;

    aesni_cbc_encrypt(in, out, len, ks, ctx->iv, ctx->enc);

    return 1;
}

#else

static int vaes_cached;
static CRYPTO_ONCE vaes_cached_once = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(vaes_cached_init)
{
    vaes_cached = ossl_aes_cbc_vaes_eligible();
    return 1;
}

static int aes_cbc_vaes_capable(void)
{
    RUN_ONCE(&vaes_cached_once, vaes_cached_init);
    return vaes_cached;
}

/* active in 64-bit builds when AES-NI, AVX512F, and VAES are detected */
static int aes_cbc_vaes_wrapper(
    PROV_CIPHER_CTX *ctx,
    unsigned char *out,
    const unsigned char *in,
    size_t len)
{
    const AES_KEY *ks = ctx->ks;

    ossl_aes_cbc_vaes_decrypt(in, out, len, ks, ctx->iv, ctx->enc);

    return 1;
}

/* CBC mode with VAES support */
static int cipher_hw_aesni_cbc(PROV_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    /* Use VAES only when the payload is large enough to amortize the
     * per-call setup cost (key broadcast).  For small sizes the
     * hand-tuned aesni_cbc_encrypt assembly is faster. */
    if (!ctx->enc && aes_cbc_vaes_capable() && len >= 256) {
        return aes_cbc_vaes_wrapper(ctx, out, in, len);
    }

    aesni_cbc_encrypt(in, out, len, ctx->ks, ctx->iv, ctx->enc);
    return 1;
}

#endif

static int cipher_hw_aesni_ecb(PROV_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    if (len < ctx->blocksize)
        return 1;

    aesni_ecb_encrypt(in, out, len, ctx->ks, ctx->enc);

    return 1;
}

#define PROV_CIPHER_HW_declare(mode)                                           \
static const PROV_CIPHER_HW aesni_##mode = {                                   \
    cipher_hw_aesni_initkey,                                                   \
    cipher_hw_aesni_##mode,                                                    \
    cipher_hw_aes_copyctx                                                      \
};
#define PROV_CIPHER_HW_select(mode)                                            \
if (AESNI_CAPABLE)                                                             \
    return &aesni_##mode;
