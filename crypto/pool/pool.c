/*
 * Copyright 2016-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/thread.h>

#include <internal/pool.h>
#include <internal/hashtable.h>
#include <internal/hashfunc.h>

#include <crypto/siphash.h>

#include "pool-internal.h"

static inline int refcount_dec_and_test_zero(CRYPTO_REF_COUNT *ref)
{
    int count;
    return CRYPTO_DOWN_REF(ref, &count) && count == 0;
}

static unsigned long CRYPTO_BUFFER_hash(const CRYPTO_BUFFER *buf)
{
    uint64_t out;
    SIPHASH siphash;

    SipHash_set_hash_size(&siphash, 8);
    SipHash_Init(&siphash, (unsigned char *)buf->pool->hash_key, 0, 0);
    SipHash_Update(&siphash, buf->data, buf->len);
    SipHash_Final(&siphash, (unsigned char *)&out, 8);

    return (unsigned long)out;
}

static int CRYPTO_BUFFER_cmp(const CRYPTO_BUFFER *a, const CRYPTO_BUFFER *b)
{
    /* Only |CRYPTO_BUFFER|s from the same pool have compatible hashes. */
    assert(a->pool != NULL);
    assert(a->pool == b->pool);
    if (a->len != b->len) {
        return 1;
    }
    return memcmp(a->data, b->data, a->len);
}

CRYPTO_BUFFER_POOL *CRYPTO_BUFFER_POOL_new(void)
{
    CRYPTO_BUFFER_POOL *pool, *ret = NULL;
    LHASH_OF(CRYPTO_BUFFER) *bufs = NULL;
    CRYPTO_RWLOCK *lock = NULL;

    if ((pool = OPENSSL_zalloc(sizeof(CRYPTO_BUFFER_POOL))) == NULL)
        goto err;

    if ((bufs = lh_CRYPTO_BUFFER_new(CRYPTO_BUFFER_hash, CRYPTO_BUFFER_cmp))
        == NULL)
        goto err;

    if ((lock = CRYPTO_THREAD_lock_new()) == NULL)
        goto err;

    RAND_bytes((uint8_t *)&pool->hash_key, sizeof(pool->hash_key));

    ret = pool;
    pool = NULL;
    ret->bufs = bufs;
    bufs = NULL;
    ret->lock = lock;
    lock = NULL;

err:
    lh_CRYPTO_BUFFER_free(bufs);
    CRYPTO_THREAD_lock_free(lock);
    OPENSSL_free(pool);

    return ret;
}

void CRYPTO_BUFFER_POOL_free(CRYPTO_BUFFER_POOL *pool)
{
    if (pool == NULL)
        return;

#if !defined(NDEBUG)
    assert(CRYPTO_THREAD_write_lock(pool->lock) == 1);
    assert(lh_CRYPTO_BUFFER_num_items(pool->bufs) == 0);
    CRYPTO_THREAD_unlock(pool->lock);
#endif

    lh_CRYPTO_BUFFER_free(pool->bufs);
    CRYPTO_THREAD_lock_free(pool->lock);
    OPENSSL_free(pool);
}

static void crypto_buffer_free_object(CRYPTO_BUFFER *buf)
{
    if (buf != NULL) {
        if (!buf->data_is_static)
            OPENSSL_free(buf->data);
        CRYPTO_FREE_REF(&buf->references);
    }
    OPENSSL_free(buf);
}

static CRYPTO_BUFFER *crypto_buffer_new(const uint8_t *data, size_t len,
    int data_is_static,
    CRYPTO_BUFFER_POOL *pool)
{
    CRYPTO_BUFFER *buf = NULL, *ret = NULL;

    if (pool != NULL) {
        CRYPTO_BUFFER tmp;
        tmp.data = (uint8_t *)data;
        tmp.len = len;
        tmp.pool = pool;

        if (!CRYPTO_THREAD_read_lock(pool->lock))
            goto err;
        CRYPTO_BUFFER *duplicate = lh_CRYPTO_BUFFER_retrieve(pool->bufs, &tmp);
        if (data_is_static && duplicate != NULL && !duplicate->data_is_static) {
            /*
             * If the new |CRYPTO_BUFFER| would have static data, but the duplicate
             * does not, we replace the old one with the new static version
             */
            duplicate = NULL;
        }
        if (duplicate != NULL) {
            if (!CRYPTO_BUFFER_up_ref(duplicate)) {
                CRYPTO_THREAD_unlock(pool->lock);
                goto err;
            }
        }
        CRYPTO_THREAD_unlock(pool->lock);

        if (duplicate != NULL) {
            ret = duplicate;
            goto err;
        }
    }

    buf = (OPENSSL_zalloc(sizeof(CRYPTO_BUFFER)));
    if (buf == NULL) {
        goto err;
    }

    if (data_is_static) {
        buf->data = (uint8_t *)data;
        buf->data_is_static = 1;
    } else {
        buf->data = OPENSSL_memdup(data, len);
        if (len != 0 && buf->data == NULL)
            goto err;
    }
    buf->len = len;
    if (!CRYPTO_NEW_REF(&buf->references, 1))
        goto err;

    if (pool == NULL)
        goto done;

    buf->pool = pool;

    if (!CRYPTO_THREAD_write_lock(pool->lock))
        goto err;
    CRYPTO_BUFFER *duplicate = lh_CRYPTO_BUFFER_retrieve(pool->bufs, buf);
    if (data_is_static && duplicate != NULL && !duplicate->data_is_static) {
        /*
         * If the new |CRYPTO_BUFFER| would have static data, but the duplicate does
         * not, we replace the old one with the new static version.
         */
        duplicate = NULL;
    }
    int inserted = 0;
    if (duplicate == NULL) {
        lh_CRYPTO_BUFFER_insert(pool->bufs, buf);
        inserted = 1;
    } else {
        if (!CRYPTO_BUFFER_up_ref(duplicate))
            goto err;
    }
    CRYPTO_THREAD_unlock(pool->lock);

    if (!inserted) {
        /*
         * We raced to insert |buf| into the pool and lost, or else there was an
         * error inserting.
         */
        crypto_buffer_free_object(buf);
        ret = duplicate;
        goto err;
    }

done:
    ret = buf;
    buf = NULL;

err:
    crypto_buffer_free_object(buf);

    return ret;
}

CRYPTO_BUFFER *CRYPTO_BUFFER_new(const uint8_t *data, size_t len,
    CRYPTO_BUFFER_POOL *pool)
{
    return crypto_buffer_new(data, len, /*data_is_static=*/0, pool);
}

CRYPTO_BUFFER *CRYPTO_BUFFER_alloc(uint8_t **out_data, size_t len)
{
    uint8_t *data = NULL;
    CRYPTO_BUFFER *buf, *ret = NULL;
    CRYPTO_REF_COUNT *ref = NULL;

    if ((buf = OPENSSL_zalloc(sizeof(CRYPTO_BUFFER))) == NULL)
        goto err;

    if ((data = OPENSSL_malloc(len)) == NULL && len != 0)
        goto err;

    ref = &buf->references;
    if (!CRYPTO_NEW_REF(ref, 1))
        goto err;
    ref = NULL;

    ret = buf;
    buf = NULL;
    ret->data = *out_data = data;
    data = NULL;
    ret->len = len;

err:
    OPENSSL_free(buf);
    OPENSSL_free(data);
    CRYPTO_FREE_REF(ref);

    return ret;
}

CRYPTO_BUFFER *CRYPTO_BUFFER_new_from_static_data_unsafe(
    const uint8_t *data, size_t len, CRYPTO_BUFFER_POOL *pool)
{
    return crypto_buffer_new(data, len, /*data_is_static=*/1, pool);
}

void CRYPTO_BUFFER_free(CRYPTO_BUFFER *buf)
{
    if (buf == NULL) {
        return;
    }

    CRYPTO_BUFFER_POOL *const pool = buf->pool;
    if (pool == NULL) {
        if (refcount_dec_and_test_zero(&buf->references))
            /*
             * If a reference count of zero is observed, there cannot be a reference
             * from any pool to this buffer and thus we are able to free this
             * buffer.
             */
            crypto_buffer_free_object(buf);
        return;
    }

    if (!CRYPTO_THREAD_write_lock(pool->lock))
        return;

    if (!refcount_dec_and_test_zero(&buf->references)) {
        CRYPTO_THREAD_unlock(buf->pool->lock);
        return;
    }
    /*
     * The reference count is zero. We have an exclusive lock on the pool,
     * therefore no concurrent lookups can find this buffer and increment
     * the reference count. Thus, if the count is zero there are and can
     * never be any more references and thus we can free this buffer.
     *
     * Note it is possible |buf| is no longer in the pool, if it was replaced by a
     * static version. If that static version was since removed, it is even
     * possible for |found| to be NULL.
     */
    CRYPTO_BUFFER *found = lh_CRYPTO_BUFFER_retrieve(pool->bufs, buf);
    if (found == buf) {
        found = lh_CRYPTO_BUFFER_delete(pool->bufs, buf);
        assert(found == buf);
        (void)found;
    }

    CRYPTO_THREAD_unlock(buf->pool->lock);
    crypto_buffer_free_object(buf);
}

int CRYPTO_BUFFER_up_ref(CRYPTO_BUFFER *buf)
{
    int ref;
    /*
     * This is safe in the case that |buf->pool| is NULL because it's just
     * standard reference counting in that case.
     *
     * This is also safe if |buf->pool| is non-NULL because, if it were racing
     * with |CRYPTO_BUFFER_free| then the two callers must have independent
     * references already and so the reference count will never hit zero.
     */
    return CRYPTO_UP_REF(&buf->references, &ref) == 1;
}

const uint8_t *CRYPTO_BUFFER_data(const CRYPTO_BUFFER *buf)
{
    return buf->data;
}

size_t CRYPTO_BUFFER_len(const CRYPTO_BUFFER *buf) { return buf->len; }
