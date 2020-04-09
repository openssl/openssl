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
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "crypto/evp.h"
#include "evp_local.h"

typedef struct {
    int key_set;                /* Set if key initialised */
    int iv_set;                 /* Set if an iv is set */
    unsigned char *iv;          /* Temporary IV store */
    int ivlen;                  /* IV length */
    int taglen;
    int iv_gen;                 /* It is OK to generate IVs */
    int tls_aad_len;            /* TLS AAD length */

} EVP_NULL_CTX;

static int null_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                         const unsigned char *iv, int enc);
static int null_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t inl);
static int null_cipher_ctrl(EVP_CIPHER_CTX *ctx, int type,
                        int arg, void *ptr);
static const EVP_CIPHER n_cipher = {
    NID_undef,
    1, 0, 0, 0,
    null_init_key,
    null_cipher,
    NULL,
    0,
    NULL,
    NULL,
    null_cipher_ctrl,
    NULL
};

const EVP_CIPHER *EVP_enc_null(void)
{
    return &n_cipher;
}

static int null_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                         const unsigned char *iv, int enc)
{
    return 1;
}



static int null_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t inl)
{
    if (in != out)
        memcpy(out, in, sizeof(inl));
    return 1;
}


static int null_cipher_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
  
    EVP_NULL_CTX *gctx = EVP_C_DATA(EVP_NULL_CTX, ctx);
    switch (type) {
    case EVP_CTRL_INIT:
        gctx->key_set = 0;
        gctx->iv_set = 0;
        gctx->ivlen = EVP_CIPHER_iv_length(ctx->cipher);
        gctx->iv = ctx->iv;
        gctx->taglen = -1;
        gctx->iv_gen = 0;
        gctx->tls_aad_len = -1;
        return 1; 

    case EVP_CTRL_GET_IVLEN: 
        *(int *)ptr = gctx->ivlen;
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        /*if (arg <= 0)
            return 0;
        
        if ((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen)) {
            if (gctx->iv != ctx->iv)
                OPENSSL_free(gctx->iv);
            if ((gctx->iv = OPENSSL_malloc(arg)) == NULL) {
                EVPerr(EVP_F_AES_GCM_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }
        gctx->ivlen = arg; */
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        /*if (arg <= 0 || arg > 16 || ctx->encrypt)
            return 0;
        memcpy(ctx->buf, ptr, arg);
        gctx->taglen = arg; */
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        /*if (arg <= 0 || arg > 16 || !ctx->encrypt
            || gctx->taglen < 0)
            return 0; */
        memcpy(ptr, ctx->buf, arg);
        return 1;
  
    default:
        return -1;

    }
}
