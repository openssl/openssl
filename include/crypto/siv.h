/*
 * Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#if !defined(OPENSSL_CRYPTO_SIV_H)
#define OPENSSL_CRYPTO_SIV_H

#ifndef OPENSSL_NO_SIV

#include <stddef.h>

#include <openssl/evp.h>

typedef struct siv128_context SIV128_CONTEXT;

SIV128_CONTEXT *ossl_siv128_new(const unsigned char *key, int klen,
    EVP_CIPHER *cbc, EVP_CIPHER *ctr,
    OSSL_LIB_CTX *libctx, const char *propq);

/**
 * @brief Initialize a SIV context with a key, or restart with the existing one.
 *
 * With a NULL @p key the context keeps its key material, discards any AAD and
 * payload state, and starts a new operation; @p klen, @p cbc, @p ctr,
 * @p libctx and @p propq are then ignored. Fails if the context has no key.
 *
 * @param ctx the context to initialize
 * @param key the key, or NULL to restart with the existing one
 * @param klen the length of @p key in bytes
 * @param cbc the CBC cipher for the CMAC
 * @param ctr the CTR cipher for the encryption
 * @param libctx the library context to fetch from
 * @param propq the property query for fetches
 * @returns 1 on success, 0 on failure
 */
int ossl_siv128_init(SIV128_CONTEXT *ctx, const unsigned char *key, int klen,
    const EVP_CIPHER *cbc, const EVP_CIPHER *ctr,
    OSSL_LIB_CTX *libctx, const char *propq);
int ossl_siv128_copy_ctx(SIV128_CONTEXT *dest, SIV128_CONTEXT *src);
int ossl_siv128_aad(SIV128_CONTEXT *ctx, const unsigned char *aad, size_t len);
int ossl_siv128_encrypt(SIV128_CONTEXT *ctx,
    const unsigned char *in, unsigned char *out, size_t len);
int ossl_siv128_decrypt(SIV128_CONTEXT *ctx,
    const unsigned char *in, unsigned char *out, size_t len);
int ossl_siv128_finish(SIV128_CONTEXT *ctx);
int ossl_siv128_set_tag(SIV128_CONTEXT *ctx, const unsigned char *tag,
    size_t len);
int ossl_siv128_get_tag(SIV128_CONTEXT *ctx, unsigned char *tag, size_t len);
int ossl_siv128_cleanup(SIV128_CONTEXT *ctx);
int ossl_siv128_speed(SIV128_CONTEXT *ctx, int arg);

#endif /* OPENSSL_NO_SIV */
#endif /* !defined (OPENSSL_CRYPTO_SIV_H) */
