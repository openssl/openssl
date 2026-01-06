/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ASCON_H
# define ASCON_H
# include <stddef.h>
# include <stdint.h>
# include <stdbool.h>

typedef struct {
    uint64_t state[5];
    uint64_t key[2];
    size_t offset;
    uint64_t flags;
} ascon_aead128_ctx;

/* Provider compatibility typedef */
typedef ascon_aead128_ctx ASCON_AEAD_CTX;

/* Constants */
# define ASCON_AEAD_NONCE_LEN 16
# define ASCON_AEAD128_KEY_LEN 16
# define ASCON_AEAD_TAG_MIN_SECURE_LEN 16

/* Type definitions */
typedef struct {
    uint64_t state[5];
    size_t offset;
} ascon_hash256_ctx;

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

/* Crypto function declarations */
void ascon_aead128_init(ascon_aead128_ctx *ctx, const unsigned char *k,
                        const unsigned char *n);
void ascon_aead128_encrypt_update(ascon_aead128_ctx *ctx, unsigned char *ct,
                                  const unsigned char *pt, size_t len);
void ascon_aead128_final(ascon_aead128_ctx *ctx, unsigned char *tag);
void ascon_aead128_aad_update(ascon_aead128_ctx *ctx, const unsigned char *in,
                              size_t len);
void ascon_aead128_decrypt_update(ascon_aead128_ctx *ctx, unsigned char *pt,
                                  const unsigned char *ct, size_t len);
# define ascon_aead128_encrypt_final ascon_aead128_final
# define ascon_aead128_decrypt_final ascon_aead128_final

void ascon_hash256_init(ascon_hash256_ctx *ctx);
void ascon_hash256_update(ascon_hash256_ctx *ctx, const unsigned char *m,
                          size_t len);
void ascon_hash256_final(ascon_hash256_ctx *ctx, unsigned char *digest);

void ascon_xof128_init(ascon_xof128_ctx *ctx);
void ascon_xof128_update(ascon_xof128_ctx *ctx, const unsigned char *m,
                         size_t len);
void ascon_xof128_final(ascon_xof128_ctx *ctx, unsigned char *out, size_t len);

void ascon_cxof128_init(ascon_cxof128_ctx *ctx, const unsigned char *in,
                        size_t len);
void ascon_cxof128_update(ascon_cxof128_ctx *ctx, const unsigned char *m,
                          size_t len);
void ascon_cxof128_final(ascon_cxof128_ctx *ctx, unsigned char *out, size_t len);

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
                                        bool *is_tag_valid,
                                        const unsigned char *tag,
                                        size_t tag_len);
void ossl_ascon_aead_cleanup(ASCON_AEAD_CTX *ctx);

void ossl_ascon_hash256_init(ascon_hash256_ctx *ctx);
void ossl_ascon_hash256_update(ascon_hash256_ctx *ctx, const unsigned char *m,
                                size_t len);
void ossl_ascon_hash256_final(ascon_hash256_ctx *ctx, unsigned char *digest);
void ossl_ascon_hash256_cleanup(ascon_hash256_ctx *ctx);

void ossl_ascon_xof128_init(ascon_xof128_ctx *ctx);
void ossl_ascon_xof128_update(ascon_xof128_ctx *ctx, const unsigned char *m,
                               size_t len);
void ossl_ascon_xof128_final(ascon_xof128_ctx *ctx, unsigned char *out,
                              size_t len);
void ossl_ascon_xof128_cleanup(ascon_xof128_ctx *ctx);

void ossl_ascon_cxof128_init(ascon_cxof128_ctx *ctx, const unsigned char *in,
                              size_t len);
void ossl_ascon_cxof128_update(ascon_cxof128_ctx *ctx, const unsigned char *m,
                                size_t len);
void ossl_ascon_cxof128_final(ascon_cxof128_ctx *ctx, unsigned char *out,
                               size_t len);
void ossl_ascon_cxof128_cleanup(ascon_cxof128_ctx *ctx);

#endif /* ASCON_H */
