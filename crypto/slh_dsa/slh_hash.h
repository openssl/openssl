/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_SLH_HASH_H
# define OSSL_CRYPTO_SLH_HASH_H
# pragma once

# include <openssl/e_os2.h>
# include "slh_adrs.h"

# define SLH_HASH_FUNC_DECLARE(ctx, hashf, hashctx)   \
    const SLH_HASH_FUNC *hashf = ctx->hash_func;      \
    SLH_HASH_CTX *hashctx = &ctx->hash_ctx

# define SLH_HASH_FN_DECLARE(hashf, t) OSSL_SLH_HASHFUNC_##t * t = hashf->t

/* See FIPS 205 Section 11.1 */

typedef struct slh_hash_ctx_st {
    EVP_MD_CTX *md_ctx; /* Used for SHAKE and SHA-256 */
    EVP_MD_CTX *md_big_ctx; /* Used for SHA-256 or SHA-512 */
    EVP_MAC_CTX *hmac_ctx;
    /* Stupid HMAC can't be set up early since the key is required */
    const char *hmac_digest;
    const char *hmac_propq;
    EVP_MD *md; /* Used by the MGF1 */
    size_t n; /* The output size of a HASH - this truncates in some cases */
    size_t m; /* The output size of the HMSG */
    size_t sha2_h_and_t_bound;
} SLH_HASH_CTX;

/*
 * @params out is |m| bytes which ranges from (30..49) bytes
 */
typedef void (OSSL_SLH_HASHFUNC_H_MSG)(SLH_HASH_CTX *ctx, const uint8_t *r,
    const uint8_t *pk_seed, const uint8_t *pk_root,
    const uint8_t *msg, size_t msg_len, uint8_t *out);

typedef void (OSSL_SLH_HASHFUNC_PRF)(SLH_HASH_CTX *ctx, const uint8_t *pk_seed,
    const uint8_t *sk_seed, const SLH_ADRS adrs, uint8_t *out);

typedef void (OSSL_SLH_HASHFUNC_PRF_MSG)(SLH_HASH_CTX *ctx, const uint8_t *sk_prf,
    const uint8_t *opt_rand, const uint8_t *msg, size_t msg_len, uint8_t *out);

typedef void (OSSL_SLH_HASHFUNC_F)(SLH_HASH_CTX *ctx, const uint8_t *pk_seed,
    const SLH_ADRS adrs, const uint8_t *m1, size_t m1_len, uint8_t *out);

typedef void (OSSL_SLH_HASHFUNC_H)(SLH_HASH_CTX *ctx, const uint8_t *pk_seed,
    const SLH_ADRS adrs, const uint8_t *m1, const uint8_t *m2, uint8_t *out);

typedef void (OSSL_SLH_HASHFUNC_T)(SLH_HASH_CTX *ctx, const uint8_t *pk_seed,
    const SLH_ADRS adrs, const uint8_t *m1, size_t m1_len, uint8_t *out);

typedef struct slh_hash_func_st {
    OSSL_SLH_HASHFUNC_H_MSG *H_MSG;
    OSSL_SLH_HASHFUNC_PRF *PRF;
    OSSL_SLH_HASHFUNC_PRF_MSG *PRF_MSG;
    OSSL_SLH_HASHFUNC_F *F;
    OSSL_SLH_HASHFUNC_H *H;
    OSSL_SLH_HASHFUNC_T *T;
} SLH_HASH_FUNC;

const SLH_HASH_FUNC *ossl_slh_get_hash_fn(int is_shake);

int ossl_slh_hash_ctx_init(SLH_HASH_CTX *ctx, OSSL_LIB_CTX *libctx,
                           const char *propq, int is_shake,
                           int security_category, size_t n, size_t m);
void ossl_slh_hash_ctx_cleanup(SLH_HASH_CTX *ctx);

#endif
