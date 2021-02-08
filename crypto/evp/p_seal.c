/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                 unsigned char **ek, int *ekl, unsigned char *iv,
                 EVP_PKEY **pubk, int npubk)
{
    unsigned char key[EVP_MAX_KEY_LENGTH];
    int i;
    int rv = 0;

    if (type) {
        EVP_CIPHER_CTX_reset(ctx);
        if (!EVP_EncryptInit_ex(ctx, type, NULL, NULL, NULL))
            return 0;
    }
    if ((npubk <= 0) || !pubk)
        return 1;

    if (EVP_CIPHER_CTX_rand_key(ctx, key) <= 0)
        return 0;

    if (EVP_CIPHER_CTX_iv_length(ctx)
            && RAND_bytes(iv, EVP_CIPHER_CTX_iv_length(ctx)) <= 0)
        goto err;

    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        goto err;

    for (i = 0; i < npubk; i++) {
        size_t keylen = EVP_CIPHER_CTX_key_length(ctx);
        EVP_PKEY_CTX *pctx = NULL;

        if ((pctx = EVP_PKEY_CTX_new(pubk[i], NULL)) == NULL) {
            ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (EVP_PKEY_encrypt_init(pctx) <= 0
            || EVP_PKEY_encrypt(pctx, ek[i], &keylen, key, keylen) <= 0)
            goto err;
        ekl[i] = (int)keylen;
        EVP_PKEY_CTX_free(pctx);
    }
    rv = npubk;
err:
    OPENSSL_cleanse(key, sizeof(key));
    return rv;
}

int EVP_SealFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int i;
    i = EVP_EncryptFinal_ex(ctx, out, outl);
    if (i)
        i = EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL);
    return i;
}
