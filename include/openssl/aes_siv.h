/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef AES_SIV_H_
#define AES_SIV_H_

#include <openssl/ossl_typ.h>

#ifdef __cplusplus
extern "C" {
#endif

AES_SIV_CTX *AES_SIV_CTX_new(void);
void AES_SIV_CTX_free(AES_SIV_CTX *ctx);

int AES_SIV_Init(AES_SIV_CTX *ctx, unsigned char const *key, size_t key_len);
int AES_SIV_AssociateData(AES_SIV_CTX *ctx, unsigned char const *data,
                          size_t len);
int AES_SIV_EncryptFinal(AES_SIV_CTX *ctx, unsigned char *v_out,
                         unsigned char *c_out, unsigned char const *plaintext,
                         size_t len);
int AES_SIV_DecryptFinal(AES_SIV_CTX *ctx, unsigned char *out,
                         unsigned char const *v, unsigned char const *c,
                         size_t len);

int AES_SIV_Encrypt(AES_SIV_CTX *ctx, unsigned char *out, size_t *out_len,
                    unsigned char const *key, size_t key_len,
                    unsigned char const *nonce, size_t nonce_len,
                    unsigned char const *plaintext, size_t plaintext_len,
                    unsigned char const *ad, size_t ad_len);

int AES_SIV_Decrypt(AES_SIV_CTX *ctx, unsigned char *out, size_t *out_len,
                    unsigned char const *key, size_t key_len,
                    unsigned char const *nonce, size_t nonce_len,
                    unsigned char const *ciphertext, size_t ciphertext_len,
                    unsigned char const *ad, size_t ad_len);


#ifdef __cplusplus
}
#endif

#endif
