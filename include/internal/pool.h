/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OPENSSL_HEADER_INTERNAL_POOL_H)
#define OPENSSL_HEADER_INTERNAL_POOL_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/safestack.h>

#if defined(__cplusplus)
extern "C" {
#endif

/*-
 * Buffers and buffer pools - originally from BoringSSL.
 *
 * A CRYPTO_BUFFER is a reference-counted, immutable blob of bytes.  A
 * CRYPTO_BUFFER_POOL is a table of CRYPTO_BUFFERs allowing a single copy of
 * any given blob to be kept in memory and referenced from multiple places.
 *
 * Without a pool, a CRYPTO_BUFFER is just a reference counted independently
 * allocated object.  Within a pool, you will get one copy of any particular
 * blob, i.e.
 *
 * CRYPTO_BUFFER *buf1, *buf2;
 * buf1 = CRYPTO_BUFFER_new("DERP", 5, NULL);
 * buf2 = CRYPTO_BUFFER_new("DERP", 5, NULL);
 *
 * will result in buf1 != buf2, each an individual allocation with a refcount
 * of 1, but
 *
 * CRYPTO_BUFFER_POOL *buf_pool = CRYPTO_BUFFER_POOL_new();
 * CRYPTO_BUFFER *buf1, *buf2;
 * buf1 = CRYPTO_BUFFER_new("DERP", 5, buf_pool);
 * buf2 = CRYPTO_BUFFER_new("DERP", 5, buf_pool);
 *
 * will have buf1 and buf2 being the same object with a refcount of 2.
 *
 * A pool does not hold references to its buffers: each buffer is removed
 * from its pool when its last reference is released.  A pool must outlive
 * the buffers created within it, and must be empty when it is freed.
 */

typedef struct crypto_buffer_pool_st CRYPTO_BUFFER_POOL;
typedef struct crypto_buffer_st CRYPTO_BUFFER;

DEFINE_STACK_OF(CRYPTO_BUFFER)

/**
 * @brief Create an empty buffer pool.
 *
 * The pool hashes its buffers' contents with SipHash under a key drawn from
 * the default library context's random number generator.
 *
 * @return the new pool, or NULL on error
 */
CRYPTO_BUFFER_POOL *CRYPTO_BUFFER_POOL_new(void);

/**
 * @brief Create an empty buffer pool with the given SipHash key.
 *
 * The key must not be predictable by anyone who chooses the contents of
 * buffers placed in the pool.
 *
 * @param key the SipHash key
 * @param key_len the number of bytes at key, which must be SIPHASH_KEY_SIZE
 * @return the new pool, or NULL on error
 */
CRYPTO_BUFFER_POOL *ossl_crypto_buffer_pool_new(const uint8_t *key,
    size_t key_len);

/**
 * @brief Free a buffer pool, which must be empty.
 *
 * All buffers created within the pool must have been freed before the pool
 * itself is freed.
 *
 * @param pool the pool to free, or NULL
 */
void CRYPTO_BUFFER_POOL_free(CRYPTO_BUFFER_POOL *pool);

/**
 * @brief Create a buffer containing a copy of the given bytes.
 *
 * If pool is not NULL the returned buffer may be a reference to an existing
 * buffer in the pool with the same contents; otherwise the new buffer is
 * added to the pool.
 *
 * @param data the bytes to copy
 * @param len the number of bytes in data
 * @param pool the pool to deduplicate within, or NULL for an unpooled buffer
 * @return the new buffer, or NULL on error
 */
CRYPTO_BUFFER *CRYPTO_BUFFER_new(const uint8_t *data, size_t len,
    CRYPTO_BUFFER_POOL *pool);

/**
 * @brief Create an unpooled buffer whose contents the caller writes.
 *
 * On success, len bytes of contents must be written through out_data before
 * the buffer is passed to any other OpenSSL function.  Once initialised, the
 * buffer must be treated as immutable.
 *
 * @param out_data set to the buffer's data pointer for the caller to fill in
 * @param len the size of the buffer in bytes
 * @return the new buffer, or NULL on error
 */
CRYPTO_BUFFER *CRYPTO_BUFFER_alloc(uint8_t **out_data,
    size_t len);

/**
 * @brief Create a buffer that aliases the given bytes without copying them.
 *
 * The bytes must be immutable and must last for the lifetime of the address
 * space.  Otherwise behaves as CRYPTO_BUFFER_new().
 *
 * @param data the static bytes to alias
 * @param len the number of bytes in data
 * @param pool the pool to deduplicate within, or NULL for an unpooled buffer
 * @return the new buffer, or NULL on error
 */
CRYPTO_BUFFER *CRYPTO_BUFFER_new_from_static_data_unsafe(const uint8_t *data,
    size_t len, CRYPTO_BUFFER_POOL *pool);

/**
 * @brief Release a reference to a buffer.
 *
 * When the last reference is released the buffer is removed from its pool,
 * if any, and freed.
 *
 * @param buf the buffer to release, or NULL
 */
void CRYPTO_BUFFER_free(CRYPTO_BUFFER *buf);

/**
 * @brief Take an additional reference to a buffer.
 *
 * @param buf the buffer
 * @return 1 on success, 0 on error
 */
int CRYPTO_BUFFER_up_ref(CRYPTO_BUFFER *buf);

/** @brief Return a pointer to the bytes contained in the buffer. */
const uint8_t *CRYPTO_BUFFER_data(const CRYPTO_BUFFER *buf);

/** @brief Return the length, in bytes, of the buffer's contents. */
size_t CRYPTO_BUFFER_len(const CRYPTO_BUFFER *buf);

#if defined(__cplusplus)
} /* extern C */
#endif

#endif /* !defined(OPENSSL_HEADER_INTERNAL_POOL_H) */
