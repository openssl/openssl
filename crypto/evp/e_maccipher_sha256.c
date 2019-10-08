/*
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * low level APIs are deprecated for public use, but still ok for internal
 * use where we're using them to implement the higher level EVP interface, as is
 * the case here.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include "crypto/evp.h"
#include "evp_local.h"


#define MACCIPHER_SHA256_KEY_SIZE 64


#define data(ctx) ((EVP_MACCIPHER_SHA256_KEY*) EVP_CIPHER_CTX_get_cipher_data(ctx))

typedef struct {
    unsigned char ks[MACCIPHER_SHA256_KEY_SIZE];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    SHA256_CTX head, tail, md;
} EVP_MACCIPHER_SHA256_KEY;

#define MACCIPHER_SHA256_CTX_DATA_SIZE sizeof(EVP_MACCIPHER_SHA256_KEY)

static int maccipher_sha256_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                         const unsigned char *iv, int enc);
static int maccipher_sha256_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t inl);
static int maccipher_sha256_cipher_ctrl(EVP_CIPHER_CTX *ctx, int type,
                        int arg, void *ptr);
static const EVP_CIPHER cipher = {
#ifdef NID_maccipher_sha256
    NID_maccipher_sha256,
#else
    NID_undef,
#endif
    MACCIPHER_SHA256_KEY_SIZE, MACCIPHER_SHA256_KEY_SIZE, 16, 0,
    EVP_ORIG_GLOBAL,
    maccipher_sha256_init_key,
    maccipher_sha256_cipher,
    NULL,
    MACCIPHER_SHA256_CTX_DATA_SIZE,
    NULL,
    NULL,
    maccipher_sha256_cipher_ctrl,
    NULL
};

const EVP_CIPHER *EVP_maccipher_sha256(void)
{
    return &cipher;
}

static int maccipher_sha256_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                         const unsigned char *iv, int enc)
{
    EVP_MACCIPHER_SHA256_KEY *key_data = data(ctx);
    memset(key_data->ks, 0, ctx->key_len);
    memcpy(key_data->ks, key, ctx->key_len);

    SHA256_Init(&key_data->head);    /* handy when benchmarking */
    key_data->tail = key_data->head;
    key_data->md = key_data->head;

    return 1;
}



static int maccipher_sha256_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t inl)
{
    EVP_MACCIPHER_SHA256_KEY *key = data(ctx);

    if (out != NULL){
        if (EVP_CIPHER_CTX_encrypting(ctx)) {
            if (in != out )
                memcpy(out, in, inl);

            int k = inl - SHA256_DIGEST_LENGTH;
            key->md = key->tail;
            SHA256_Update(&key->md, in, inl - SHA256_DIGEST_LENGTH);
            SHA256_Final(out + inl - SHA256_DIGEST_LENGTH, &key->md);
            key->md = key->head;
            SHA256_Update(&key->md, out + inl - SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
            SHA256_Final(out + inl - SHA256_DIGEST_LENGTH, &key->md);

        }
        else
        {
            if (in != out)
                memcpy(out, in, inl);

            int k = inl - SHA256_DIGEST_LENGTH;
            key->md = key->tail;
            SHA256_Update(&key->md, in, inl - SHA256_DIGEST_LENGTH);
            SHA256_Final(out + inl - SHA256_DIGEST_LENGTH, &key->md);
            key->md = key->head;
            SHA256_Update(&key->md, out + inl - SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
            SHA256_Final(out + inl - SHA256_DIGEST_LENGTH, &key->md);

            if (CRYPTO_memcmp(out + inl - SHA256_DIGEST_LENGTH, in + inl - SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH))
                    return 0;
        }
    }

    return 1;
}


static int maccipher_sha256_cipher_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{

    EVP_MACCIPHER_SHA256_KEY *key_data = data(ctx);

    switch (type) {
        case EVP_CTRL_AEAD_SET_MAC_KEY:
        {
            unsigned int i;
            unsigned char hmac_key[MACCIPHER_SHA256_KEY_SIZE];

            memset(hmac_key, 0, sizeof(hmac_key));

            if (arg > (int)sizeof(hmac_key)) { /* If K > block size, K = H(K) */
                SHA256_Init(&key_data->head);
                SHA256_Update(&key_data->head, ptr, arg);
                SHA256_Final(hmac_key, &key_data->head);
            } else {
                memcpy(hmac_key, key_data->ks, ctx->key_len);
            }

            for (i = 0; i < sizeof(hmac_key); i++)
                hmac_key[i] ^= 0x36; /* ipad */

            SHA256_Init(&key_data->head);
            SHA256_Update(&key_data->head, hmac_key, sizeof(hmac_key));


            for (i = 0; i < sizeof(hmac_key); i++)
                hmac_key[i] ^= 0x36 ^ 0x5c; /* opad */

            SHA256_Init(&key_data->tail);
            SHA256_Update(&key_data->tail, hmac_key, sizeof(hmac_key));
            OPENSSL_cleanse(hmac_key, sizeof(hmac_key));

            return SHA256_DIGEST_LENGTH;
        }

        case EVP_CTRL_GET_IVLEN:
            *(int *)ptr = 16;
            return 1;

        case EVP_CTRL_AEAD_SET_IVLEN:
            return 1;

        case EVP_CTRL_AEAD_SET_TAG:
            if (arg <= 0 || arg > 16)
                return 0;
            memcpy(ctx->buf, ptr, arg);
            return 1;

        case EVP_CTRL_AEAD_GET_TAG:
            memcpy(ptr, ctx->buf, arg);
            return 1;

        default:
            return -1;

        }
}
