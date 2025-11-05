/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_ASCON_H
#define OSSL_CRYPTO_ASCON_H
#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_ASCON128

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t state[5];
    uint64_t key[2];
    size_t offset;
    uint64_t flags;
} ascon_aead128_ctx;

/* Provider compatibility typedef */
typedef ascon_aead128_ctx ASCON_AEAD_CTX;

/* Constants */
#define ASCON_AEAD_NONCE_LEN 16
#define ASCON_AEAD128_KEY_LEN 16
#define ASCON_AEAD_TAG_LEN 16

/* Provider compatibility functions */
void ossl_ascon_aead128_init(ASCON_AEAD_CTX *ctx, const unsigned char *k,
    const unsigned char *n);
void ossl_ascon_aead128_assoc_data_update(ASCON_AEAD_CTX *ctx,
    const unsigned char *in, size_t inl);
size_t ossl_ascon_aead128_encrypt_update(ASCON_AEAD_CTX *ctx,
    unsigned char *out,
    const unsigned char *in, size_t inl);
size_t ossl_ascon_aead128_decrypt_update(ASCON_AEAD_CTX *ctx,
    unsigned char *out,
    const unsigned char *in, size_t inl);
size_t ossl_ascon_aead128_encrypt_final(ASCON_AEAD_CTX *ctx,
    unsigned char *out,
    unsigned char *tag, size_t tag_len);
size_t ossl_ascon_aead128_decrypt_final(ASCON_AEAD_CTX *ctx,
    unsigned char *out,
    int *is_tag_valid,
    const unsigned char *tag,
    size_t tag_len);
void ossl_ascon_aead_cleanup(ASCON_AEAD_CTX *ctx);

#endif /* OPENSSL_NO_ASCON128 */

#endif /* OSSL_CRYPTO_ASCON_H */
