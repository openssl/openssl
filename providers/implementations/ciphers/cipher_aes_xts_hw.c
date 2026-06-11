/*
 * Copyright 2019-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This file uses the low level AES functions (which are deprecated for
 * non-internal use) in order to implement provider AES ciphers.
 */
#include "internal/deprecated.h"

#include "cipher_aes_xts.h"

int ossl_cipher_set_aes_xts_initkey(PROV_CIPHER_CTX *ctx,
    const unsigned char *key, size_t keylen,
    aes_set_encrypt_key_fn fn_set_enc_key,
    aes_set_encrypt_key_fn fn_set_dec_key,
    aes_block128_f fn_block_enc, aes_block128_f fn_block_dec,
    OSSL_xts_stream_fn fn_stream_enc, OSSL_xts_stream_fn fn_stream_dec)
{
    PROV_AES_XTS_CTX *xctx = (PROV_AES_XTS_CTX *)ctx;
    size_t bytes = keylen / 2;
    size_t bits = bytes * 8;

    if (ctx->enc) {
        fn_set_enc_key(key, (int)bits, &xctx->ks1.ks);
        xctx->xts.block1 = (block128_f)fn_block_enc;
    } else {
        fn_set_dec_key(key, (int)bits, &xctx->ks1.ks);
        xctx->xts.block1 = (block128_f)fn_block_dec;
    }
    fn_set_enc_key(key + bytes, (int)bits, &xctx->ks2.ks);
    xctx->xts.block2 = (block128_f)fn_block_enc;
    xctx->xts.key1 = &xctx->ks1;
    xctx->xts.key2 = &xctx->ks2;
    xctx->stream = ctx->enc ? fn_stream_enc : fn_stream_dec;

    return 1;
}

static int cipher_hw_aes_xts_generic_initkey(PROV_CIPHER_CTX *ctx,
    const unsigned char *key,
    size_t keylen)
{
    OSSL_xts_stream_fn stream_enc = NULL;
    OSSL_xts_stream_fn stream_dec = NULL;

#ifdef AES_XTS_ASM
    stream_enc = AES_xts_encrypt;
    stream_dec = AES_xts_decrypt;
#endif /* AES_XTS_ASM */

#ifdef HWAES_CAPABLE
    if (HWAES_CAPABLE) {
#ifdef HWAES_xts_encrypt
        stream_enc = HWAES_xts_encrypt;
#endif /* HWAES_xts_encrypt */
#ifdef HWAES_xts_decrypt
        stream_dec = HWAES_xts_decrypt;
#endif /* HWAES_xts_decrypt */
        return ossl_cipher_set_aes_xts_initkey(ctx, key, keylen,
            HWAES_set_encrypt_key, HWAES_set_decrypt_key,
            HWAES_encrypt, HWAES_decrypt, stream_enc, stream_dec);
    }
#endif /* HWAES_CAPABLE */

#ifdef BSAES_CAPABLE
    if (BSAES_CAPABLE) {
        stream_enc = ossl_bsaes_xts_encrypt;
        stream_dec = ossl_bsaes_xts_decrypt;
        return ossl_cipher_set_aes_xts_initkey(ctx, key, keylen,
            AES_set_encrypt_key, AES_set_decrypt_key,
            AES_encrypt, AES_decrypt, stream_enc, stream_dec);
    }
#endif /* BSAES_CAPABLE */

#ifdef VPAES_CAPABLE
    if (VPAES_CAPABLE) {
        return ossl_cipher_set_aes_xts_initkey(ctx, key, keylen,
            vpaes_set_encrypt_key, vpaes_set_decrypt_key,
            vpaes_encrypt, vpaes_decrypt, stream_enc, stream_dec);
    }
#endif /* VPAES_CAPABLE */

    return ossl_cipher_set_aes_xts_initkey(ctx, key, keylen,
        AES_set_encrypt_key, AES_set_decrypt_key,
        AES_encrypt, AES_decrypt, stream_enc, stream_dec);
}

void ossl_cipher_hw_aes_xts_copyctx(PROV_CIPHER_CTX *dst,
    const PROV_CIPHER_CTX *src)
{
    PROV_AES_XTS_CTX *sctx = (PROV_AES_XTS_CTX *)src;
    PROV_AES_XTS_CTX *dctx = (PROV_AES_XTS_CTX *)dst;

    *dctx = *sctx;
    dctx->xts.key1 = &dctx->ks1.ks;
    dctx->xts.key2 = &dctx->ks2.ks;
}

#if defined(SPARC_AES_CAPABLE)

static int cipher_hw_aes_xts_t4_initkey(PROV_CIPHER_CTX *ctx,
    const unsigned char *key, size_t keylen)
{
    OSSL_xts_stream_fn stream_enc = NULL;
    OSSL_xts_stream_fn stream_dec = NULL;

    /* Note: keylen is the size of 2 keys */
    switch (keylen) {
    case 32:
        stream_enc = aes128_t4_xts_encrypt;
        stream_dec = aes128_t4_xts_decrypt;
        break;
    case 64:
        stream_enc = aes256_t4_xts_encrypt;
        stream_dec = aes256_t4_xts_decrypt;
        break;
    default:
        return 0;
    }

    return ossl_cipher_set_aes_xts_initkey(ctx, key, keylen,
        aes_t4_set_encrypt_key, aes_t4_set_decrypt_key,
        aes_t4_encrypt, aes_t4_decrypt, stream_enc, stream_dec);
}

static const PROV_CIPHER_HW aes_xts_t4 = {
    cipher_hw_aes_xts_t4_initkey,
    NULL,
    ossl_cipher_hw_aes_xts_copyctx
};

static const PROV_CIPHER_HW *ossl_prov_cipher_hw_aes_xts_t4()
{
    if (SPARC_AES_CAPABLE)
        return &aes_xts_t4;
    return NULL;
}

#elif defined(AES_XTS_S390X)

int s390x_aes_xts_cipher_stream(PROV_AES_XTS_CTX *xctx,
    unsigned char *out, size_t *outl,
    const unsigned char *in, size_t inl)
{
    S390X_KM_XTS_PARAMS *km = &xctx->plat.s390x.param.km;
    unsigned char *param = (unsigned char *)km + xctx->plat.s390x.offset;
    unsigned int fc = xctx->plat.s390x.fc;
    unsigned char tmp[2][AES_BLOCK_SIZE];
    unsigned char nap_n1[AES_BLOCK_SIZE];
    unsigned char drop[AES_BLOCK_SIZE];
    size_t len_incomplete, len_complete;

    len_incomplete = inl % AES_BLOCK_SIZE;
    len_complete = (len_incomplete == 0) ? inl : (inl / AES_BLOCK_SIZE - 1) * AES_BLOCK_SIZE;

    if (len_complete > 0)
        s390x_km(in, len_complete, out, fc, param);
    if (len_incomplete == 0)
        goto out;

    memcpy(tmp, in + len_complete, AES_BLOCK_SIZE + len_incomplete);
    /* swap NAP for decrypt */
    if (fc & S390X_DECRYPT) {
        memcpy(nap_n1, km->nap, AES_BLOCK_SIZE);
        s390x_km(tmp[0], AES_BLOCK_SIZE, drop, fc, param);
    }
    s390x_km(tmp[0], AES_BLOCK_SIZE, tmp[0], fc, param);
    if (fc & S390X_DECRYPT)
        memcpy(km->nap, nap_n1, AES_BLOCK_SIZE);

    memcpy(tmp[1] + len_incomplete, tmp[0] + len_incomplete,
        AES_BLOCK_SIZE - len_incomplete);
    s390x_km(tmp[1], AES_BLOCK_SIZE, out + len_complete, fc, param);
    memcpy(out + len_complete + AES_BLOCK_SIZE, tmp[0], len_incomplete);

    /* do not expose temporary data */
    OPENSSL_cleanse(tmp, sizeof(tmp));
out:
    memcpy(xctx->base.iv, km->tweak, AES_BLOCK_SIZE);
    *outl = inl;

    return 1;
}

static int cipher_hw_aes_xts_s390x_initkey(PROV_CIPHER_CTX *ctx,
    const unsigned char *key, size_t keylen)
{
    PROV_AES_XTS_CTX *xctx = (PROV_AES_XTS_CTX *)ctx;
    S390X_KM_XTS_PARAMS *km = &xctx->plat.s390x.param.km;
    unsigned int fc, offs;
    unsigned int dec = 0;
    int supported = 0;

    switch (keylen) {
    case 128 / 8 * 2:
        fc = S390X_XTS_AES_128_MSA10;
        offs = 32;
        break;
    case 256 / 8 * 2:
        fc = S390X_XTS_AES_256_MSA10;
        offs = 0;
        break;
    default:
        fc = 0;
        break;
    }

    if (fc != 0)
        supported = (OPENSSL_s390xcap_P.km[1] && S390X_CAPBIT(fc));
    if (!supported) {
        xctx->plat.s390x.fc = 0;
        xctx->plat.s390x.offset = 0;
        return 0;
    }

    if (xctx->base.iv_set) {
        if (xctx->base.ivlen > sizeof(km->tweak)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        memcpy(km->tweak, xctx->base.iv, xctx->base.ivlen);
        xctx->plat.s390x.iv_set = 1;
    }

    if (key != NULL) {
        memcpy(km->key + offs, key, keylen);
        xctx->plat.s390x.key_set = 1;
    }

    if (xctx->base.enc == 0)
        dec = S390X_DECRYPT;

    xctx->plat.s390x.fc = fc | dec;
    xctx->plat.s390x.offset = offs;

    memset(km->nap, 0, sizeof(km->nap));
    km->nap[0] = 0x1;

    return 1;
}

static void cipher_hw_aes_xts_s390x_copyctx(PROV_CIPHER_CTX *dst,
    const PROV_CIPHER_CTX *src)
{
    PROV_AES_XTS_CTX *sctx = (PROV_AES_XTS_CTX *)src;
    PROV_AES_XTS_CTX *dctx = (PROV_AES_XTS_CTX *)dst;

    *dctx = *sctx;
    dctx->xts.key1 = NULL;
    dctx->xts.key2 = NULL;
}

static const PROV_CIPHER_HW aes_xts_s390x = {
    cipher_hw_aes_xts_s390x_initkey,
    NULL,
    cipher_hw_aes_xts_s390x_copyctx
};

static const PROV_CIPHER_HW *ossl_prov_cipher_hw_aes_xts_s390x(size_t keybits)
{
    switch (keybits) {
    case (128 * 2):
        if (OPENSSL_s390xcap_P.km[1] && S390X_CAPBIT(S390X_XTS_AES_128_MSA10))
            return &aes_xts_s390x;
        break;
    case (256 * 2):
        if (OPENSSL_s390xcap_P.km[1] && S390X_CAPBIT(S390X_XTS_AES_256_MSA10))
            return &aes_xts_s390x;
        break;
    default:
        break;
    }

    return NULL;
}

#endif

static const PROV_CIPHER_HW aes_generic_xts = {
    cipher_hw_aes_xts_generic_initkey,
    NULL,
    ossl_cipher_hw_aes_xts_copyctx
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_aes_xts(size_t keybits)
{
    const PROV_CIPHER_HW *aes_xts_hw = NULL;

#if defined(AESNI_CAPABLE)
    aes_xts_hw = ossl_prov_cipher_hw_aes_xts_aesni();
#elif defined(SPARC_AES_CAPABLE)
    aes_xts_hw = ossl_prov_cipher_hw_aes_xts_t4();
#elif defined(OPENSSL_CPUID_OBJ) && defined(__riscv) && __riscv_xlen == 32
    aes_xts_hw = ossl_prov_cipher_hw_aes_xts_rv32i();
#elif defined(OPENSSL_CPUID_OBJ) && defined(__riscv) && __riscv_xlen == 64
    aes_xts_hw = ossl_prov_cipher_hw_aes_xts_rv64i();
#elif defined(AES_XTS_S390X)
    aes_xts_hw = ossl_prov_cipher_hw_aes_xts_s390x(keybits);
#endif

    if (aes_xts_hw == NULL)
        return &aes_generic_xts;

    return aes_xts_hw;
}
