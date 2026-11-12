/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OPENSSL_HEADER_CRYPTO_POOL_INTERNAL_H)
#define OPENSSL_HEADER_CRYPTO_POOL_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/lhash.h>

#include "internal/pool.h"
#include "internal/refcount.h"

#if defined(__cplusplus)
extern "C" {
#endif

DEFINE_LHASH_OF_EX(CRYPTO_BUFFER);

/**
 * @struct crypto_buffer_st
 * @brief A reference-counted, immutable blob of bytes.
 *
 * Owns its data unless data_is_static is set, in which case data aliases
 * caller-provided storage that must outlive the buffer.
 */
struct crypto_buffer_st {
    CRYPTO_BUFFER_POOL *pool; /**< containing pool, or NULL if unpooled */
    uint8_t *data;
    size_t len;
    CRYPTO_REF_COUNT references;
    int data_is_static; /**< nonzero if data aliases static storage */
};

/**
 * @struct crypto_buffer_pool_st
 * @brief A deduplicating table of CRYPTO_BUFFERs.
 *
 * The table does not hold references to its buffers; each buffer removes
 * itself from the table when its last reference is released.
 */
struct crypto_buffer_pool_st {
    LHASH_OF(CRYPTO_BUFFER) *bufs; /**< the buffers, keyed by their contents */
    CRYPTO_RWLOCK *lock; /**< guards bufs and buffer refcount release */
    uint64_t hash_key[2]; /**< per-pool SipHash key for the table hash */
};

#if defined(__cplusplus)
} /* extern C */
#endif

#endif /* !defined(OPENSSL_HEADER_CRYPTO_POOL_INTERNAL_H) */
