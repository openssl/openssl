/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
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
# include "internal/packet.h"

# define SLH_HASH_FUNC_DECLARE(ctx, hashf)            \
    const SLH_HASH_FUNC *hashf = ctx->hash_func       \

# define SLH_HASH_FN_DECLARE(hashf, t) OSSL_SLH_HASHFUNC_##t * t = hashf->t

typedef int (OSSL_SLH_HASHFUNC_HASH)(SLH_DSA_HASH_CTX *ctx,
                                     const uint8_t *pk_seed,
                                     const uint8_t *adrs,
                                     const uint8_t *in, size_t inlen,
                                     uint8_t *out, size_t out_len);

/*
 * @params out is |m| bytes which ranges from (30..49) bytes
 */
typedef int (OSSL_SLH_HASHFUNC_H_MSG)(SLH_DSA_HASH_CTX *ctx, const uint8_t *r,
                                      const uint8_t *pk_seed_and_root,
                                      const uint8_t *msg, size_t msg_len,
                                      uint8_t *out, size_t out_len);

typedef int (OSSL_SLH_HASHFUNC_PRF_MSG)(SLH_DSA_HASH_CTX *ctx, const uint8_t *sk_prf,
                                        const uint8_t *opt_rand,
                                        const uint8_t *msg, size_t msg_len,
                                        WPACKET *pkt);

typedef int (OSSL_SLH_HASHFUNC_prehash_pk_seed)(SLH_DSA_HASH_CTX *hctx,
                                                const uint8_t *pk_seed, size_t n);

typedef struct slh_hash_func_st {
    OSSL_SLH_HASHFUNC_prehash_pk_seed *prehash_pk_seed;
    OSSL_SLH_HASHFUNC_HASH *PRF;
    OSSL_SLH_HASHFUNC_HASH *F;
    OSSL_SLH_HASHFUNC_HASH *T;
    OSSL_SLH_HASHFUNC_HASH *H;
    OSSL_SLH_HASHFUNC_H_MSG *H_MSG;
    OSSL_SLH_HASHFUNC_PRF_MSG *PRF_MSG;
} SLH_HASH_FUNC;

const SLH_HASH_FUNC *ossl_slh_get_hash_fn(int is_shake, int security_category);

#endif
