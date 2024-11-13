/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "internal/refcount.h"

#define MAX_HYBRID_ALGS 2
#define MAX_HYBRID_PARAMS 20

typedef struct {
    const unsigned int num_algs;
    const struct {
        const char *name;
        size_t pubkey_length_bytes;
        size_t bits;
        size_t security_bits;
        size_t shared_secret_bytes;
        size_t ciphertext_bytes;
    } alg[MAX_HYBRID_ALGS];
} HYBRID_ALG_INFO;

#define HYBRID_COMMON_FIELDS            \
    OSSL_LIB_CTX *libctx;               \
    char *propq;                        \
    const HYBRID_ALG_INFO *info;        \
    size_t pubkey_length;               \
    size_t bits;                        \
    size_t security_bits;               \
    size_t shared_secret_bytes;         \
    size_t ciphertext_bytes
    
typedef struct {
    HYBRID_COMMON_FIELDS;
    EVP_PKEY *keys[MAX_HYBRID_ALGS];
    CRYPTO_REF_COUNT references;
} HYBRID_PKEY;

typedef struct {
    HYBRID_COMMON_FIELDS;
    EVP_PKEY_CTX *ctxs[MAX_HYBRID_ALGS];
} HYBRID_PKEY_CTX;

#define INIT_ACCUMULATE_HYBRID_NUMBERS(p)                                   \
    do {                                                                    \
        p->pubkey_length = 0;                                               \
        p->bits = 0;                                                        \
        p->security_bits = 0;                                               \
        p->shared_secret_bytes = 0;                                         \
        p->ciphertext_bytes = 0;                                            \
    } while (0)

#define ACCUMULATE_HYBRID_NUMBERS(p, n)                                     \
    do {                                                                    \
        p->pubkey_length += p->info->alg[n].pubkey_length_bytes;            \
        p->bits += p->info->alg[n].bits;                                    \
        if (p->security_bits < p->info->alg[n].security_bits)               \
            p->security_bits = p->info->alg[n].security_bits;               \
        p->shared_secret_bytes += p->info->alg[n].shared_secret_bytes;      \
        p->ciphertext_bytes += p->info->alg[n].ciphertext_bytes;            \
    } while (0)

HYBRID_PKEY *ossl_hybrid_kmgmt_new(void *provctx,
                                   const HYBRID_ALG_INFO *info);
void ossl_hybrid_pkey_free(HYBRID_PKEY *key);
int ossl_hybrid_pkey_up_ref(HYBRID_PKEY *key);

HYBRID_PKEY_CTX *ossl_hybrid_pkey_ctx_alloc(OSSL_LIB_CTX *libctx,
                                            const HYBRID_ALG_INFO *info);
HYBRID_PKEY_CTX *ossl_hybrid_pkey_ctx_new(OSSL_LIB_CTX *libctx,
                                          HYBRID_PKEY *pkey,
                                          const HYBRID_ALG_INFO *info);
void ossl_hybrid_pkey_ctx_free(HYBRID_PKEY_CTX *ctx);

/* OSSL_PARAM getters and setters */
int ossl_hybrid_get_ctx_params(HYBRID_PKEY_CTX *ctx, OSSL_PARAM params[]);
int ossl_hybrid_set_ctx_params(HYBRID_PKEY_CTX *ctx,
                               const OSSL_PARAM params[]);

const OSSL_PARAM *ossl_hybrid_gettable_common(const OSSL_PARAM *r);
const OSSL_PARAM *ossl_hybrid_settable_common(const OSSL_PARAM *r);
