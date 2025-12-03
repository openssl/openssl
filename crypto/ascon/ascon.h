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
typedef ascon_aead128_ctx ascon_aead_ctx_t;

/* Constants for provider compatibility */
# define ASCON_AEAD_NONCE_LEN 16
# define ASCON_AEAD128_KEY_LEN 16
# define ASCON_AEAD_TAG_MIN_SECURE_LEN 16

# ifndef OPENSSL_BUILDING_OPENSSL
void ascon_test_state();
# endif

/* Type definitions - always visible */
typedef struct {
    uint64_t state[5];
    size_t offset;
} ascon_hash256_ctx;

/* Original crypto function declarations - visible for external use and crypto implementation */
# ifndef OPENSSL_BUILDING_OPENSSL
void ascon_aead128_init(ascon_aead128_ctx *ctx, const unsigned char *k,
                        const unsigned char *n);
void ascon_aead128_encrypt_update(ascon_aead128_ctx *ctx, unsigned char *ct,
                                  const unsigned char *pt, size_t len);
void ascon_aead128_final(ascon_aead128_ctx *ctx, unsigned char *tag);
void ascon_aead128_aad_update(ascon_aead128_ctx *ctx, const unsigned char *in,
                              size_t len);
void ascon_aead128_decrypt_update(ascon_aead128_ctx *ctx, unsigned char *pt,
                                  const unsigned char *ct, size_t len);
#  define ascon_aead128_encrypt_final ascon_aead128_final
#  define ascon_aead128_decrypt_final ascon_aead128_final

void ascon_hash256_init(ascon_hash256_ctx *ctx);
void ascon_hash256_update(ascon_hash256_ctx *ctx, const unsigned char *m,
                          size_t len);
void ascon_hash256_final(ascon_hash256_ctx *ctx, unsigned char *digest);
# else
/* Forward declarations for crypto implementation - not visible to providers to avoid conflicts */
/* These are only needed internally, providers use ossl_ prefixed functions */
#  ifndef OSSL_INCLUDE_PROVIDER
void ascon_aead128_init(ascon_aead128_ctx *ctx, const unsigned char *k,
                        const unsigned char *n);
void ascon_aead128_encrypt_update(ascon_aead128_ctx *ctx, unsigned char *ct,
                                  const unsigned char *pt, size_t len);
void ascon_aead128_final(ascon_aead128_ctx *ctx, unsigned char *tag);
void ascon_aead128_aad_update(ascon_aead128_ctx *ctx, const unsigned char *in,
                              size_t len);
void ascon_aead128_decrypt_update(ascon_aead128_ctx *ctx, unsigned char *pt,
                                  const unsigned char *ct, size_t len);
#   define ascon_aead128_encrypt_final ascon_aead128_final
#   define ascon_aead128_decrypt_final ascon_aead128_final

void ascon_hash256_init(ascon_hash256_ctx *ctx);
void ascon_hash256_update(ascon_hash256_ctx *ctx, const unsigned char *m,
                          size_t len);
void ascon_hash256_final(ascon_hash256_ctx *ctx, unsigned char *digest);
#  endif
# endif

# ifdef OPENSSL_BUILDING_OPENSSL
/* Provider compatibility functions */
void ossl_ascon_aead128_init(ascon_aead_ctx_t *ctx, const unsigned char *k,
                             const unsigned char *n);
void ossl_ascon_aead128_assoc_data_update(ascon_aead_ctx_t *ctx,
                                          const unsigned char *in, size_t inl);
size_t ossl_ascon_aead128_encrypt_update(ascon_aead_ctx_t *ctx,
                                         unsigned char *out,
                                         const unsigned char *in, size_t inl);
size_t ossl_ascon_aead128_decrypt_update(ascon_aead_ctx_t *ctx,
                                         unsigned char *out,
                                         const unsigned char *in, size_t inl);
size_t ossl_ascon_aead128_encrypt_final(ascon_aead_ctx_t *ctx,
                                        unsigned char *out,
                                        unsigned char *tag, size_t tag_len);
size_t ossl_ascon_aead128_decrypt_final(ascon_aead_ctx_t *ctx,
                                        unsigned char *out,
                                        bool *is_tag_valid,
                                        const unsigned char *tag,
                                        size_t tag_len);
void ossl_ascon_aead_cleanup(ascon_aead_ctx_t *ctx);
# endif

#endif /* ASCON_H */
