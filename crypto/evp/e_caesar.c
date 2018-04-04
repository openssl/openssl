/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"

#ifndef OPENSSL_NO_CAESAR

# include <openssl/evp.h>
# include <openssl/objects.h>
# include <openssl/caesar.h>

# include "internal/evp_int.h"

typedef struct {
    CAESAR_KEY ks;                 /* working key */
} EVP_CAESAR_KEY;

# define data(ctx) ((EVP_CAESAR_KEY *)EVP_CIPHER_CTX_get_cipher_data(ctx))

static int caesar_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc);
static int caesar_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
static const EVP_CIPHER c_cipher = {
    NID_caesar,
    1, EVP_CAESAR_KEY_SIZE, 0,
    EVP_CIPH_VARIABLE_LENGTH,
    caesar_init_key,
    caesar_cipher,
    NULL,
    sizeof(EVP_CAESAR_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};

const EVP_CIPHER *EVP_caesar_ecb(void)
{
    return &c_cipher;
}

static int caesar_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    CAESAR_set_key(&data(ctx)->ks, EVP_CIPHER_CTX_key_length(ctx), key);
    return 1;
}

static int caesar_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl)
{
    CAESAR(&data(ctx)->ks, inl, in, out);
    return 1;
}
#endif
