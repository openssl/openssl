/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_HPKE_H
# define OSSL_CRYPTO_HPKE_H
# pragma once

#define OSSL_HPKE_MAX_SECRET 64
#define OSSL_HPKE_MAX_PUBLIC 133
#define OSSL_HPKE_MAX_PRIVATE 66
#define OSSL_HPKE_MAX_NONCE 12
#define OSSL_HPKE_MAX_KDF_INPUTLEN 64

typedef struct hpke_kem_alg_st {
    const char *keytype;
    const char *name;
    const char *kdfname;
    const char *kdfdigestname;
    uint16_t kemid;
    size_t secretlen;
    size_t encodedpublen;
    size_t encodedprivlen;
    uint8_t bitmask;
} OSSL_HPKE_KEM_ALG;

int ossl_hpke_kdf_extract(EVP_KDF_CTX *kctx,
                          unsigned char *prk, size_t prklen,
                          const unsigned char *salt, size_t saltlen,
                          const unsigned char *ikm, size_t ikmlen);

int ossl_hpke_kdf_expand(EVP_KDF_CTX *kctx,
                         unsigned char *okm, size_t okmlen,
                         const unsigned char *prk, size_t prklen,
                         const unsigned char *info, size_t infolen);

int ossl_hpke_labeled_extract(EVP_KDF_CTX *kctx,
                              unsigned char *prk, size_t prklen,
                              const unsigned char *salt, size_t saltlen,
                              const unsigned char *suiteid, size_t suiteidlen,
                              const char *label,
                              const unsigned char *ikm, size_t ikmlen);
int ossl_hpke_labeled_expand(EVP_KDF_CTX *kctx,
                             unsigned char *okm, size_t okmlen,
                             const unsigned char *prk, size_t prklen,
                             const unsigned char *suiteid, size_t suiteidlen,
                             const char *label,
                             const unsigned char *info, size_t infolen);

EVP_KDF_CTX *ossl_kdf_ctx_create(const char *kdfname, const char *mdname,
                                 OSSL_LIB_CTX *libctx, const char *propq);

EVP_CIPHER_CTX *ossl_aead_init(EVP_CIPHER *cipher, const unsigned char *key,
                               int enc);
void ossl_aead_free(EVP_CIPHER_CTX *ctx);

int ossl_aead_seal(EVP_CIPHER_CTX *ctx,
                   unsigned char *ct, size_t *ctlen,
                   const unsigned char *pt, size_t ptlen,
                   const unsigned char *iv, size_t ivlen,
                   const unsigned char *aad, size_t aadlen);
int ossl_aead_open(EVP_CIPHER_CTX *ctx,
                   unsigned char *pt, size_t *ptlen,
                   const unsigned char *ct, size_t ctlen,
                   const unsigned char *iv, size_t ivlen,
                   const unsigned char *aad, size_t aadlen);

const OSSL_HPKE_KEM_ALG *ossl_hpke_get_kemalg(const char *keytype,
                                              const char *curve,
                                              const char *kdfname,
                                              const char *kdfdigestname);
#endif
