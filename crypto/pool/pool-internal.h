/*
 * Copyright 2016-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OPENSSL_HEADER_CRYPTO_POOL_INTERNAL_H)
#define OPENSSL_HEADER_CRYPTO_POOL_INTERNAL_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include <openssl/lhash.h>

#include <internal/pool.h>
#include <internal/refcount.h>

DEFINE_LHASH_OF_EX(CRYPTO_BUFFER);

struct crypto_buffer_st {
    CRYPTO_BUFFER_POOL *pool;
    uint8_t *data;
    size_t len;
    CRYPTO_REF_COUNT references;
    int data_is_static;
};

struct crypto_buffer_pool_st {
    LHASH_OF(CRYPTO_BUFFER) *bufs;
    CRYPTO_RWLOCK *lock;
    const uint64_t hash_key[2];
};

#if defined(__cplusplus)
} // extern C
#endif

#endif /* !defined(OPENSSL_HEADER_CRYPTO_POOL_INTERNAL_H) */
