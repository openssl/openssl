/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include "ciphers_locl.h"
#include "internal/provider_algs.h"
#include "internal/providercommonerr.h"

#define MAXBITCHUNK     ((size_t)1 << (sizeof(size_t) * 8 - 4))
#define EVP_MAXCHUNK ((size_t)1<<(sizeof(long)*8-2))

/*-
 * Default cipher functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM cipher_known_gettable_params[] = {
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END
};
const OSSL_PARAM *cipher_default_gettable_params(void)
{
    return cipher_known_gettable_params;
}

int cipher_default_get_params(OSSL_PARAM params[], int md, unsigned long flags,
                              int kbits, int blkbits, int ivbits)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_int(p, md)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_FLAGS);
    if (p != NULL && !OSSL_PARAM_set_ulong(p, flags)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_int(p, kbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, blkbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_int(p, ivbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

static const OSSL_PARAM cipher_known_gettable_ctx_params[] = {
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_NUM, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_END
};
const OSSL_PARAM *cipher_default_gettable_ctx_params(void)
{
    return cipher_known_gettable_ctx_params;
}

static const OSSL_PARAM cipher_known_settable_ctx_params[] = {
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_NUM, NULL),
    OSSL_PARAM_END
};
const OSSL_PARAM *cipher_default_settable_ctx_params(void)
{
    return cipher_known_settable_ctx_params;
}

/*-
 * AEAD cipher functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM cipher_aead_known_gettable_ctx_params[] = {
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
    OSSL_PARAM_END
};
const OSSL_PARAM *cipher_aead_gettable_ctx_params(void)
{
    return cipher_aead_known_gettable_ctx_params;
}

static const OSSL_PARAM cipher_aead_known_settable_ctx_params[] = {
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
    OSSL_PARAM_END
};
const OSSL_PARAM *cipher_aead_settable_ctx_params(void)
{
    return cipher_aead_known_settable_ctx_params;
}



int generic_cbc_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                       const unsigned char *in, size_t len)
{
    if (dat->stream.cbc)
        (*dat->stream.cbc) (in, out, len, dat->ks, dat->iv, dat->enc);
    else if (dat->enc)
        CRYPTO_cbc128_encrypt(in, out, len, dat->ks, dat->iv, dat->block);
    else
        CRYPTO_cbc128_decrypt(in, out, len, dat->ks, dat->iv, dat->block);

    return 1;
}

int generic_ecb_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                       const unsigned char *in, size_t len)
{
    size_t i, bl = dat->blocksize;

    if (len < bl)
        return 1;

    for (i = 0, len -= bl; i <= len; i += bl)
        (*dat->block) (in + i, out + i, dat->ks);

    return 1;
}

int generic_ofb128_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    int num = dat->num;

    CRYPTO_ofb128_encrypt(in, out, len, dat->ks, dat->iv, &num, dat->block);
    dat->num = num;

    return 1;
}

int generic_cfb128_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    int num = dat->num;

    CRYPTO_cfb128_encrypt(in, out, len, dat->ks, dat->iv, &num, dat->enc,
                          dat->block);
    dat->num = num;

    return 1;
}

int generic_cfb8_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                        const unsigned char *in, size_t len)
{
    int num = dat->num;

    CRYPTO_cfb128_8_encrypt(in, out, len, dat->ks, dat->iv, &num, dat->enc,
                            dat->block);
    dat->num = num;

    return 1;
}

int generic_cfb1_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                        const unsigned char *in, size_t len)
{
    int num = dat->num;

    if ((dat->flags & EVP_CIPH_FLAG_LENGTH_BITS) != 0) {
        CRYPTO_cfb128_1_encrypt(in, out, len, dat->ks, dat->iv, &num,
                                dat->enc, dat->block);
        dat->num = num;
        return 1;
    }

    while (len >= MAXBITCHUNK) {
        CRYPTO_cfb128_1_encrypt(in, out, MAXBITCHUNK * 8, dat->ks,
                                dat->iv, &num, dat->enc, dat->block);
        len -= MAXBITCHUNK;
        out += MAXBITCHUNK;
        in  += MAXBITCHUNK;
    }
    if (len)
        CRYPTO_cfb128_1_encrypt(in, out, len * 8, dat->ks, dat->iv, &num,
                                dat->enc, dat->block);

    dat->num = num;

    return 1;
}

int generic_ctr_cipher(PROV_GENERIC_KEY *dat, unsigned char *out,
                       const unsigned char *in, size_t len)
{
    unsigned int num = dat->num;

    if (dat->stream.ctr)
        CRYPTO_ctr128_encrypt_ctr32(in, out, len, dat->ks, dat->iv, dat->buf,
                                    &num, dat->stream.ctr);
    else
        CRYPTO_ctr128_encrypt(in, out, len, dat->ks, dat->iv, dat->buf,
                              &num, dat->block);
    dat->num = num;

    return 1;
}

int chunked_cbc_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                       const unsigned char *in, size_t inl)
{
    while (inl >= EVP_MAXCHUNK) {
        generic_cbc_cipher(ctx, out, in, EVP_MAXCHUNK);
        inl -= EVP_MAXCHUNK;
        in  += EVP_MAXCHUNK;
        out += EVP_MAXCHUNK;
    }
    if (inl > 0)
        generic_cbc_cipher(ctx, out, in, inl);
    return 1;
}

int chunked_cfb8_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                        const unsigned char *in, size_t inl)
{
    size_t chunk = EVP_MAXCHUNK;

    if (inl < chunk)
        chunk = inl;
    while (inl > 0 && inl >= chunk) {
        generic_cfb8_cipher(ctx, out, in, inl);
        inl -= chunk;
        in += chunk;
        out += chunk;
        if (inl < chunk)
            chunk = inl;
    }
    return 1;
}

int chunked_cfb128_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                          const unsigned char *in, size_t inl)
{
    size_t chunk = EVP_MAXCHUNK;

    if (inl < chunk)
        chunk = inl;
    while (inl > 0 && inl >= chunk) {
        generic_cfb128_cipher(ctx, out, in, inl);
        inl -= chunk;
        in += chunk;
        out += chunk;
        if (inl < chunk)
            chunk = inl;
    }
    return 1;
}

int chunked_ofb128_cipher(PROV_GENERIC_KEY *ctx, unsigned char *out,
                          const unsigned char *in, size_t inl)
{
    while (inl >= EVP_MAXCHUNK) {
        generic_ofb128_cipher(ctx, out, in, EVP_MAXCHUNK);
        inl -= EVP_MAXCHUNK;
        in  += EVP_MAXCHUNK;
        out += EVP_MAXCHUNK;
    }
    if (inl > 0)
        generic_ofb128_cipher(ctx, out, in, inl);
    return 1;
}

