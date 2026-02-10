/*
 * Copyright 2016-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OPENSSL_HEADER_INTERNAL_POOL_H)
#define OPENSSL_HEADER_INTERNAL_POOL_H

#include <openssl/safestack.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* Buffers and buffer pools - originally from BoringSSL */

/**
 * |CRYPTO_BUFFER|s are simply reference-counted blobs. A |CRYPTO_BUFFER_POOL|
 * is an internal table for |CRYPTO_BUFFER|s. This allows for a single copy of a
 * given blob to be kept in memory and referenced from multiple places.
 *
 * Without a pool, a |CRYPTO_BUFFER| is just a reference counted independently
 * allocated object.  Within a pool, You will get one copy of any particular blob,
 * I.E.
 *
 * CRYPTO_BUFFER *buf1, buf2;
 * buf1 == CRYPTO_buffer_new("DERP", 5, NULL);
 * buf2 == CRYPTO_buffer_new("DERP", 5, NULL);
 *
 * Will result in buf1 != buf2, each individual allocations with a refcount of 1.
 *
 * but
 *
 * CRYPTO_BUFFER_POOL buf_pool = CRYPTO_BUFFER_POOL_new();
 * CRYPTO_BUFFER *buf1, buf2;
 * buf1 == CRYPTO_buffer_new("DERP", 5, buf_pool);
 * buf2 == CRYPTO_buffer_new("DERP", 5, buf_pool);
 *
 * will have buf1 and buf2 being the same object with a refcount of 2.
 *
 */

typedef struct crypto_buffer_pool_st CRYPTO_BUFFER_POOL;
typedef struct crypto_buffer_st CRYPTO_BUFFER;

DEFINE_STACK_OF(CRYPTO_BUFFER)

/**
 * CRYPTO_BUFFER_POOL_new returns a freshly allocated |CRYPTO_BUFFER_POOL| or
 * NULL on error.
 */
CRYPTO_BUFFER_POOL *CRYPTO_BUFFER_POOL_new(void);

/**
 * CRYPTO_BUFFER_POOL_free frees |pool|, which must be empty.
 */
void CRYPTO_BUFFER_POOL_free(CRYPTO_BUFFER_POOL *pool);

/**
 * CRYPTO_BUFFER_new returns a |CRYPTO_BUFFER| containing a copy of |data|, or
 * else NULL on error. If |pool| is not NULL then the returned value may be a
 * reference to a previously existing |CRYPTO_BUFFER| that contained the same
 * data. Otherwise, the returned, fresh |CRYPTO_BUFFER| will be added to the
 * pool.
 */
CRYPTO_BUFFER *CRYPTO_BUFFER_new(const uint8_t *data, size_t len,
    CRYPTO_BUFFER_POOL *pool);

/**
 * CRYPTO_BUFFER_alloc creates an unpooled |CRYPTO_BUFFER| of the given size and
 * writes the underlying data pointer to |*out_data|. It returns NULL on error.
 *
 * After calling this function, |len| bytes of contents must be written to
 * |out_data| before passing the returned pointer to any other BoringSSL
 * functions. Once initialized, the |CRYPTO_BUFFER| should be treated as
 * immutable.
 */
CRYPTO_BUFFER *CRYPTO_BUFFER_alloc(uint8_t **out_data,
    size_t len);

/**
 * CRYPTO_BUFFER_new_from_static_data_unsafe behaves like |CRYPTO_BUFFER_new|
 * but does not copy |data|. |data| must be immutable and last for the lifetime
 * of the address space.
 */
CRYPTO_BUFFER *CRYPTO_BUFFER_new_from_static_data_unsafe(const uint8_t *data,
    size_t len, CRYPTO_BUFFER_POOL *pool);

/**
 *  CRYPTO_BUFFER_free decrements the reference count of |buf|. If there are no
 * other references, or if the only remaining reference is from a pool, then
 * |buf| will be freed.
 */
void CRYPTO_BUFFER_free(CRYPTO_BUFFER *buf);

/**
 * CRYPTO_BUFFER_up_ref increments the reference count of |buf| and returns
 * one.
 */
int CRYPTO_BUFFER_up_ref(CRYPTO_BUFFER *buf);

/* CRYPTO_BUFFER_data returns a pointer to the data contained in |buf|. */
const uint8_t *CRYPTO_BUFFER_data(const CRYPTO_BUFFER *buf);

/**
 * CRYPTO_BUFFER_len returns the length, in bytes, of the data contained in
 * |buf|.
 */
size_t CRYPTO_BUFFER_len(const CRYPTO_BUFFER *buf);

#if defined(__cplusplus)
} /* extern C */
#endif

#endif /* !defined( OPENSSL_HEADER_INTERNAL_POOL_H) */
