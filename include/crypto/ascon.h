/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_ASCON_H
# define OSSL_CRYPTO_ASCON_H
# pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/*
 * Temporary stub for build testing
 * This is a placeholder for a cleanroom implementation of the ASCON algorithm
 */

#define ASCON_AEAD128_KEY_LEN 16
#define ASCON_AEAD_NONCE_LEN 16
#define ASCON_AEAD_TAG_MIN_SECURE_LEN 16

typedef struct ascon_aead_ctx_st {
    uint8_t dummy[64];
} ascon_aead_ctx_t;

void ascon_aead128_init(ascon_aead_ctx_t *ctx, const uint8_t *key, const uint8_t *nonce);
size_t ascon_aead128_encrypt_update(ascon_aead_ctx_t *ctx, uint8_t *out, const uint8_t *in, size_t inlen);
size_t ascon_aead128_decrypt_update(ascon_aead_ctx_t *ctx, uint8_t *out, const uint8_t *in, size_t inlen);
int ascon_aead128_encrypt_final(ascon_aead_ctx_t *ctx, uint8_t *out, uint8_t *tag, size_t taglen);
int ascon_aead128_decrypt_final(ascon_aead_ctx_t *ctx, uint8_t *out, bool *is_valid, const uint8_t *tag, size_t taglen);
void ascon_aead128_assoc_data_update(ascon_aead_ctx_t *ctx, const uint8_t *aad, size_t aadlen);

#endif /* OSSL_CRYPTO_ASCON_H */

