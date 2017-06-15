/*
 * Copyright 2006-2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2017, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#ifndef OPENSSL_NO_ARIA
# include <openssl/evp.h>
# include <openssl/modes.h>
# include"internal/aria.h"
# include "internal/evp_int.h"

/* ARIA subkey Structure */
typedef struct {
    ARIA_KEY ks;
} EVP_ARIA_KEY;

/* The subkey for ARIA is generated. */
static int aria_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    int ret;
    int mode = EVP_CIPHER_CTX_mode(ctx);

    if (enc || (mode != EVP_CIPH_ECB_MODE && mode != EVP_CIPH_CBC_MODE))
        ret = aria_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                        EVP_CIPHER_CTX_get_cipher_data(ctx));
    else
        ret = aria_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                        EVP_CIPHER_CTX_get_cipher_data(ctx));
    if (ret < 0) {
        EVPerr(EVP_F_ARIA_INIT_KEY,EVP_R_ARIA_KEY_SETUP_FAILED);
        return 0;
    }
    return 1;
}

static void aria_cbc_encrypt(const unsigned char *in, unsigned char *out,
                             size_t len, const ARIA_KEY *key,
                             unsigned char *ivec, const int enc)
{

    if (enc)
        CRYPTO_cbc128_encrypt(in, out, len, key, ivec,
                              (block128_f) aria_encrypt);
    else
        CRYPTO_cbc128_decrypt(in, out, len, key, ivec,
                              (block128_f) aria_encrypt);
}

static void aria_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                                size_t length, const ARIA_KEY *key,
                                unsigned char *ivec, int *num, const int enc)
{

    CRYPTO_cfb128_encrypt(in, out, length, key, ivec, num, enc,
                          (block128_f) aria_encrypt);
}

static void aria_cfb1_encrypt(const unsigned char *in, unsigned char *out,
                              size_t length, const ARIA_KEY *key,
                              unsigned char *ivec, int *num, const int enc)
{
    CRYPTO_cfb128_1_encrypt(in, out, length, key, ivec, num, enc,
                            (block128_f) aria_encrypt);
}

static void aria_cfb8_encrypt(const unsigned char *in, unsigned char *out,
                              size_t length, const ARIA_KEY *key,
                              unsigned char *ivec, int *num, const int enc)
{
    CRYPTO_cfb128_8_encrypt(in, out, length, key, ivec, num, enc,
                            (block128_f) aria_encrypt);
}

static void aria_ecb_encrypt(const unsigned char *in, unsigned char *out,
                             const ARIA_KEY *key, const int enc)
{
    aria_encrypt(in, out, key);
}

static void aria_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                             size_t length, const ARIA_KEY *key,
                             unsigned char *ivec, int *num)
{
    CRYPTO_ofb128_encrypt(in, out, length, key, ivec, num,
                         (block128_f) aria_encrypt);
}

IMPLEMENT_BLOCK_CIPHER(aria_128, ks, aria, EVP_ARIA_KEY,
                        NID_aria_128, 16, 16, 16, 128,
                        0, aria_init_key, NULL,
                        EVP_CIPHER_set_asn1_iv,
                        EVP_CIPHER_get_asn1_iv,
                        NULL)
IMPLEMENT_BLOCK_CIPHER(aria_192, ks, aria, EVP_ARIA_KEY,
                        NID_aria_192, 16, 24, 16, 128,
                        0, aria_init_key, NULL,
                        EVP_CIPHER_set_asn1_iv,
                        EVP_CIPHER_get_asn1_iv,
                        NULL)
IMPLEMENT_BLOCK_CIPHER(aria_256, ks, aria, EVP_ARIA_KEY,
                        NID_aria_256, 16, 32, 16, 128,
                        0, aria_init_key, NULL,
                        EVP_CIPHER_set_asn1_iv,
                        EVP_CIPHER_get_asn1_iv,
                        NULL)

# define IMPLEMENT_ARIA_CFBR(ksize,cbits) \
                IMPLEMENT_CFBR(aria,aria,EVP_ARIA_KEY,ks,ksize,cbits,16,0)
IMPLEMENT_ARIA_CFBR(128,1)
IMPLEMENT_ARIA_CFBR(192,1)
IMPLEMENT_ARIA_CFBR(256,1)
IMPLEMENT_ARIA_CFBR(128,8)
IMPLEMENT_ARIA_CFBR(192,8)
IMPLEMENT_ARIA_CFBR(256,8)

# define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER aria_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aria_init_key,                  \
        aria_##mode##_cipher,           \
        NULL,                           \
        sizeof(EVP_ARIA_KEY),           \
        NULL,NULL,NULL,NULL };          \
const EVP_CIPHER *EVP_aria_##keylen##_##mode(void) \
{ return &aria_##keylen##_##mode; }

static int aria_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    unsigned int num = EVP_CIPHER_CTX_num(ctx);
    EVP_ARIA_KEY *dat = EVP_C_DATA(EVP_ARIA_KEY,ctx);

    CRYPTO_ctr128_encrypt(in, out, len, &dat->ks,
                          EVP_CIPHER_CTX_iv_noconst(ctx),
                          EVP_CIPHER_CTX_buf_noconst(ctx), &num,
                          (block128_f) aria_encrypt);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

BLOCK_CIPHER_generic(NID_aria, 128, 1, 16, ctr, ctr, CTR, 0)
BLOCK_CIPHER_generic(NID_aria, 192, 1, 16, ctr, ctr, CTR, 0)
BLOCK_CIPHER_generic(NID_aria, 256, 1, 16, ctr, ctr, CTR, 0)

#endif
