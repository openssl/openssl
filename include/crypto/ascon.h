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

typedef struct {
    uint64_t state[5];
    size_t offset;
} ascon_hash256_ctx;

/**
 * Start an Ascon-Hash256 computation.
 *
 * @param ctx    Context.
 */
void ossl_ascon_hash256_init(ascon_hash256_ctx *ctx);
/**
 * Absorb message bytes.
 *
 * @param ctx    Context.
 * @param m      Message bytes.
 * @param len    Number of message bytes.
 */
void ossl_ascon_hash256_update(ascon_hash256_ctx *ctx, const unsigned char *m,
    size_t len);
/**
 * Write the 32-byte digest.
 *
 * @param ctx    Context.
 * @param digest Output buffer.
 */
void ossl_ascon_hash256_final(ascon_hash256_ctx *ctx, unsigned char *digest);
/**
 * Clear the context.
 *
 * @param ctx    Context.
 */
void ossl_ascon_hash256_cleanup(ascon_hash256_ctx *ctx);

typedef struct {
    uint64_t state[5];
    size_t offset;
    uint64_t flags;
} ascon_xof128_ctx;

typedef struct {
    uint64_t state[5];
    size_t offset;
    uint64_t flags;
} ascon_cxof128_ctx;

/**
 * Start an Ascon-XOF128 computation.
 *
 * @param ctx    Context.
 */
void ossl_ascon_xof128_init(ascon_xof128_ctx *ctx);
/**
 * Absorb message bytes.
 *
 * @param ctx    Context.
 * @param m      Message bytes.
 * @param len    Number of message bytes.
 */
void ossl_ascon_xof128_update(ascon_xof128_ctx *ctx, const unsigned char *m,
    size_t len);
/**
 * Squeeze output bytes.
 *
 * @param ctx    Context.
 * @param out    Output buffer.
 * @param len    Number of bytes to squeeze.
 */
void ossl_ascon_xof128_final(ascon_xof128_ctx *ctx, unsigned char *out,
    size_t len);
/**
 * Clear the context.
 *
 * @param ctx    Context.
 */
void ossl_ascon_xof128_cleanup(ascon_xof128_ctx *ctx);

/**
 * Start an Ascon-CXOF128 computation.
 *
 * @param ctx    Context.
 * @param in     Customization string, at most 256 bytes.
 * @param len    Length of the customization string.
 */
void ossl_ascon_cxof128_init(ascon_cxof128_ctx *ctx, const unsigned char *in,
    size_t len);
/**
 * Absorb message bytes.
 *
 * @param ctx    Context.
 * @param m      Message bytes.
 * @param len    Number of message bytes.
 */
void ossl_ascon_cxof128_update(ascon_cxof128_ctx *ctx, const unsigned char *m,
    size_t len);
/**
 * Squeeze output bytes.
 *
 * @param ctx    Context.
 * @param out    Output buffer.
 * @param len    Number of bytes to squeeze.
 */
void ossl_ascon_cxof128_final(ascon_cxof128_ctx *ctx, unsigned char *out,
    size_t len);
/**
 * Clear the context.
 *
 * @param ctx    Context.
 */
void ossl_ascon_cxof128_cleanup(ascon_cxof128_ctx *ctx);

#endif /* OPENSSL_NO_ASCON128 */

#endif /* OSSL_CRYPTO_ASCON_H */
