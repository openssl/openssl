/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include "internal/cryptlib.h"
#include <openssl/opensslconf.h>
#include "internal/rand_int.h"
#include <openssl/engine.h>
#include "internal/thread_once.h"
#include "rand_lcl.h"

#ifndef OPENSSL_NO_ENGINE
/* non-NULL if default_RAND_meth is ENGINE-provided */
static ENGINE *funct_ref;
static CRYPTO_RWLOCK *rand_engine_lock;
#endif
static CRYPTO_RWLOCK *rand_meth_lock;
static const RAND_METHOD *default_RAND_meth;
static CRYPTO_ONCE rand_init = CRYPTO_ONCE_STATIC_INIT;

int rand_fork_count;

#ifdef OPENSSL_RAND_SEED_RDTSC
/*
 * IMPORTANT NOTE:  It is not currently possible to use this code
 * because we are not sure about the amount of randomness it provides.
 * Some SP900 tests have been run, but there is internal skepticism.
 * So for now this code is not used.
 */
# error "RDTSC enabled?  Should not be possible!"

/*
 * Acquire entropy from high-speed clock
 *
 * Since we get some randomness from the low-order bits of the
 * high-speed clock, it can help.
 *
 * Returns the total entropy count, if it exceeds the requested
 * entropy count. Otherwise, returns an entropy count of 0.
 */
size_t rand_acquire_entropy_from_tsc(RAND_POOL *pool)
{
    unsigned char c;
    int i;

    if ((OPENSSL_ia32cap_P[0] & (1 << 4)) != 0) {
        for (i = 0; i < TSC_READ_COUNT; i++) {
            c = (unsigned char)(OPENSSL_rdtsc() & 0xFF);
            RAND_POOL_add(pool, &c, 1, 4);
        }
    }
    return RAND_POOL_entropy_available(pool);
}
#endif

#ifdef OPENSSL_RAND_SEED_RDCPU
size_t OPENSSL_ia32_rdseed_bytes(unsigned char *buf, size_t len);
size_t OPENSSL_ia32_rdrand_bytes(unsigned char *buf, size_t len);

extern unsigned int OPENSSL_ia32cap_P[];

/*
 * Acquire entropy using Intel-specific cpu instructions
 *
 * Uses the RDSEED instruction if available, otherwise uses
 * RDRAND if available.
 *
 * For the differences between RDSEED and RDRAND, and why RDSEED
 * is the preferred choice, see https://goo.gl/oK3KcN
 *
 * Returns the total entropy count, if it exceeds the requested
 * entropy count. Otherwise, returns an entropy count of 0.
 */
size_t rand_acquire_entropy_from_cpu(RAND_POOL *pool)
{
    size_t bytes_needed;
    unsigned char *buffer;

    bytes_needed = RAND_POOL_bytes_needed(pool, 8 /*entropy_per_byte*/);
    if (bytes_needed > 0) {
        buffer = RAND_POOL_add_begin(pool, bytes_needed);

        if (buffer != NULL) {

            /* If RDSEED is available, use that. */
            if ((OPENSSL_ia32cap_P[2] & (1 << 18)) != 0) {
                if (OPENSSL_ia32_rdseed_bytes(buffer, bytes_needed)
                    == bytes_needed)
                    return RAND_POOL_add_end(pool,
                                             bytes_needed,
                                             8 * bytes_needed);
            }

            /* Second choice is RDRAND. */
            if ((OPENSSL_ia32cap_P[1] & (1 << (62 - 32))) != 0) {
                if (OPENSSL_ia32_rdrand_bytes(buffer, bytes_needed)
                    == bytes_needed)
                    return RAND_POOL_add_end(pool,
                                             bytes_needed,
                                             8 * bytes_needed);
            }

            return RAND_POOL_add_end(pool, 0, 0);
        }
    }

    return RAND_POOL_entropy_available(pool);
}
#endif


/*
 * Implements the get_entropy() callback (see RAND_DRBG_set_callbacks())
 *
 * If the DRBG has a parent, then the required amount of entropy input
 * is fetched using the parent's RAND_DRBG_generate().
 *
 * Otherwise, the entropy is polled from the system entropy sources
 * using RAND_POOL_acquire_entropy().
 *
 * If a random pool has been added to the DRBG using RAND_add(), then
 * its entropy will be used up first.
 */
size_t rand_drbg_get_entropy(RAND_DRBG *drbg,
                        unsigned char **pout,
                        int entropy, size_t min_len, size_t max_len)
{
    size_t ret = 0;
    size_t entropy_available = 0;
    RAND_POOL *pool = RAND_POOL_new(entropy, min_len, max_len);

    if (pool == NULL)
        return 0;

    if (drbg->pool) {
        RAND_POOL_add(pool,
                      RAND_POOL_buffer(drbg->pool),
                      RAND_POOL_length(drbg->pool),
                      RAND_POOL_entropy(drbg->pool));
        RAND_POOL_free(drbg->pool);
        drbg->pool = NULL;
    }

    if (drbg->parent) {
        size_t bytes_needed = RAND_POOL_bytes_needed(pool, 8);
        unsigned char *buffer = RAND_POOL_add_begin(pool, bytes_needed);

        if (buffer != NULL) {
            size_t bytes = 0;

            /*
             * Get random from parent, include our state as additional input.
             * Our lock is already held, but we need to lock our parent before
             * generating bits from it.
             */
            if (drbg->parent->lock)
                CRYPTO_THREAD_write_lock(drbg->parent->lock);
            if (RAND_DRBG_generate(drbg->parent,
                                   buffer, bytes_needed,
                                   0,
                                   (unsigned char *)drbg, sizeof(*drbg)) != 0)
                bytes = bytes_needed;
            if (drbg->parent->lock)
                CRYPTO_THREAD_unlock(drbg->parent->lock);

            entropy_available = RAND_POOL_add_end(pool, bytes, 8 * bytes);
        }

    } else {
        /* Get entropy by polling system entropy sources. */
        entropy_available = RAND_POOL_acquire_entropy(pool);
    }

    if (entropy_available > 0) {
        ret   = RAND_POOL_length(pool);
        *pout = RAND_POOL_detach(pool);
    }

    RAND_POOL_free(pool);
    return ret;
}


/*
 * Implements the cleanup_entropy() callback (see RAND_DRBG_set_callbacks())
 *
 */
void rand_drbg_cleanup_entropy(RAND_DRBG *drbg,
                               unsigned char *out, size_t outlen)
{
    OPENSSL_secure_clear_free(out, outlen);
}

void rand_fork()
{
    rand_fork_count++;
}

DEFINE_RUN_ONCE_STATIC(do_rand_init)
{
    int ret = 1;

#ifndef OPENSSL_NO_ENGINE
    rand_engine_lock = CRYPTO_THREAD_glock_new("rand_engine");
    ret &= rand_engine_lock != NULL;
#endif
    rand_meth_lock = CRYPTO_THREAD_glock_new("rand_meth");
    ret &= rand_meth_lock != NULL;

    return ret;
}

void rand_cleanup_int(void)
{
    const RAND_METHOD *meth = default_RAND_meth;

    if (meth != NULL && meth->cleanup != NULL)
        meth->cleanup();
    RAND_set_rand_method(NULL);
#ifndef OPENSSL_NO_ENGINE
    CRYPTO_THREAD_lock_free(rand_engine_lock);
#endif
    CRYPTO_THREAD_lock_free(rand_meth_lock);
}

/*
 * RAND_poll() reseeds the default RNG using random input
 *
 * The random input is obtained from polling various entropy
 * sources which depend on the operating system and are
 * configurable via the --with-rand-seed configure option.
 */
int RAND_poll(void)
{
    int ret = 0;

    RAND_POOL *pool = NULL;

    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth == RAND_OpenSSL()) {
        /* fill random pool and seed the master DRBG */
        RAND_DRBG *drbg = RAND_DRBG_get0_master();

        if (drbg == NULL)
            return 0;

        CRYPTO_THREAD_write_lock(drbg->lock);
        ret = rand_drbg_restart(drbg, NULL, 0, 0);
        CRYPTO_THREAD_unlock(drbg->lock);

        return ret;

    } else {
        /* fill random pool and seed the current legacy RNG */
        pool = RAND_POOL_new(RAND_DRBG_STRENGTH,
                             RAND_DRBG_STRENGTH / 8,
                             DRBG_MINMAX_FACTOR * (RAND_DRBG_STRENGTH / 8));
        if (pool == NULL)
            return 0;

        if (RAND_POOL_acquire_entropy(pool) == 0)
            goto err;

        if (meth->add == NULL
            || meth->add(RAND_POOL_buffer(pool),
                         RAND_POOL_length(pool),
                         (RAND_POOL_entropy(pool) / 8.0)) == 0)
            goto err;

        ret = 1;
    }

err:
    RAND_POOL_free(pool);
    return ret;
}

/*
 * The 'random pool' acts as a dumb container for collecting random
 * input from various entropy sources. The pool has no knowledge about
 * whether its randomness is fed into a legacy RAND_METHOD via RAND_add()
 * or into a new style RAND_DRBG. It is the callers duty to 1) initialize the
 * random pool, 2) pass it to the polling callbacks, 3) seed the RNG, and
 * 4) cleanup the random pool again.
 *
 * The random pool contains no locking mechanism because its scope and
 * lifetime is intended to be restricted to a single stack frame.
 */
struct rand_pool_st {
    unsigned char *buffer;  /* points to the beginning of the random pool */
    size_t len; /* current number of random bytes contained in the pool */

    size_t min_len; /* minimum number of random bytes requested */
    size_t max_len; /* maximum number of random bytes (allocated buffer size) */
    size_t entropy; /* current entropy count in bits */
    size_t requested_entropy; /* requested entropy count in bits */
};

/*
 * Allocate memory and initialize a new random pool
 */

RAND_POOL *RAND_POOL_new(int entropy, size_t min_len, size_t max_len)
{
    RAND_POOL *pool = OPENSSL_zalloc(sizeof(*pool));

    if (pool == NULL) {
        RANDerr(RAND_F_RAND_POOL_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pool->min_len = min_len;
    pool->max_len = max_len;

    pool->buffer = OPENSSL_secure_zalloc(pool->max_len);
    if (pool->buffer == NULL) {
        RANDerr(RAND_F_RAND_POOL_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pool->requested_entropy = entropy;

    return pool;

err:
    OPENSSL_free(pool);
    return NULL;
}

/*
 * Free |pool|, securely erasing its buffer.
 */
void RAND_POOL_free(RAND_POOL *pool)
{
    if (pool == NULL)
        return;

    OPENSSL_secure_clear_free(pool->buffer, pool->max_len);
    OPENSSL_free(pool);
}

/*
 * Return the |pool|'s buffer to the caller (readonly).
 */
const unsigned char *RAND_POOL_buffer(RAND_POOL *pool)
{
    return pool->buffer;
}

/*
 * Return the |pool|'s entropy to the caller.
 */
size_t RAND_POOL_entropy(RAND_POOL *pool)
{
    return pool->entropy;
}

/*
 * Return the |pool|'s buffer length to the caller.
 */
size_t RAND_POOL_length(RAND_POOL *pool)
{
    return pool->len;
}

/*
 * Detach the |pool| buffer and return it to the caller.
 * It's the responsibility of the caller to free the buffer
 * using OPENSSL_secure_clear_free().
 */
unsigned char *RAND_POOL_detach(RAND_POOL *pool)
{
    unsigned char *ret = pool->buffer;
    pool->buffer = NULL;
    return ret;
}


/*
 * If every byte of the input contains |entropy_per_bytes| bits of entropy,
 * how many bytes does one need to obtain at least |bits| bits of entropy?
 */
#define ENTROPY_TO_BYTES(bits, entropy_per_bytes) \
    (((bits) + ((entropy_per_bytes) - 1))/(entropy_per_bytes))


/*
 * Checks whether the |pool|'s entropy is available to the caller.
 * This is the case when entropy count and buffer length are high enough.
 * Returns
 *
 *  |entropy|  if the entropy count and buffer size is large enough
 *      0      otherwise
 */
size_t RAND_POOL_entropy_available(RAND_POOL *pool)
{
    if (pool->entropy < pool->requested_entropy)
        return 0;

    if (pool->len < pool->min_len)
        return 0;

    return pool->entropy;
}

/*
 * Returns the (remaining) amount of entropy needed to fill
 * the random pool.
 */

size_t RAND_POOL_entropy_needed(RAND_POOL *pool)
{
    if (pool->entropy < pool->requested_entropy)
        return pool->requested_entropy - pool->entropy;

    return 0;
}

/*
 * Returns the number of bytes needed to fill the pool, assuming
 * the input has 'entropy_per_byte' entropy bits per byte.
 * In case of an error, 0 is returned.
 */

size_t RAND_POOL_bytes_needed(RAND_POOL *pool, unsigned int entropy_per_byte)
{
    size_t bytes_needed;
    size_t entropy_needed = RAND_POOL_entropy_needed(pool);

    if (entropy_per_byte < 1 || entropy_per_byte > 8) {
        RANDerr(RAND_F_RAND_POOL_BYTES_NEEDED, RAND_R_ARGUMENT_OUT_OF_RANGE);
        return 0;
    }

    bytes_needed = ENTROPY_TO_BYTES(entropy_needed, entropy_per_byte);

    if (bytes_needed > pool->max_len - pool->len) {
        /* not enough space left */
        RANDerr(RAND_F_RAND_POOL_BYTES_NEEDED, RAND_R_RANDOM_POOL_OVERFLOW);
        return 0;
    }

    if (pool->len < pool->min_len &&
        bytes_needed < pool->min_len - pool->len)
        /* to meet the min_len requirement */
        bytes_needed = pool->min_len - pool->len;

    return bytes_needed;
}

/* Returns the remaining number of bytes available */
size_t RAND_POOL_bytes_remaining(RAND_POOL *pool)
{
    return pool->max_len - pool->len;
}

/*
 * Add random bytes to the random pool.
 *
 * It is expected that the |buffer| contains |len| bytes of
 * random input which contains at least |entropy| bits of
 * randomness.
 *
 * Return available amount of entropy after this operation.
 * (see RAND_POOL_entropy_available(pool))
 */
size_t RAND_POOL_add(RAND_POOL *pool,
                     const unsigned char *buffer, size_t len, size_t entropy)
{
    if (len > pool->max_len - pool->len) {
        RANDerr(RAND_F_RAND_POOL_ADD, RAND_R_ENTROPY_INPUT_TOO_LONG);
        return 0;
    }

    if (len > 0) {
        memcpy(pool->buffer + pool->len, buffer, len);
        pool->len += len;
        pool->entropy += entropy;
    }

    return RAND_POOL_entropy_available(pool);
}

/*
 * Start to add random bytes to the random pool in-place.
 *
 * Reserves the next |len| bytes for adding random bytes in-place
 * and returns a pointer to the buffer.
 * The caller is allowed to copy up to |len| bytes into the buffer.
 * If |len| == 0 this is considered a no-op and a NULL pointer
 * is returned without producing an error message.
 *
 * After updating the buffer, RAND_POOL_add_end() needs to be called
 * to finish the udpate operation (see next comment).
 */
unsigned char *RAND_POOL_add_begin(RAND_POOL *pool, size_t len)
{
    if (len == 0)
        return NULL;

    if (len > pool->max_len - pool->len) {
        RANDerr(RAND_F_RAND_POOL_ADD_BEGIN, RAND_R_RANDOM_POOL_OVERFLOW);
        return NULL;
    }

    return pool->buffer + pool->len;
}

/*
 * Finish to add random bytes to the random pool in-place.
 *
 * Finishes an in-place update of the random pool started by
 * RAND_POOL_add_begin() (see previous comment).
 * It is expected that |len| bytes of random input have been added
 * to the buffer which contain at least |entropy| bits of randomness.
 * It is allowed to add less bytes than originally reserved.
 */
size_t RAND_POOL_add_end(RAND_POOL *pool, size_t len, size_t entropy)
{
    if (len > pool->max_len - pool->len) {
        RANDerr(RAND_F_RAND_POOL_ADD_END, RAND_R_RANDOM_POOL_OVERFLOW);
        return 0;
    }

    if (len > 0) {
        pool->len += len;
        pool->entropy += entropy;
    }

    return RAND_POOL_entropy_available(pool);
}

int RAND_set_rand_method(const RAND_METHOD *meth)
{
    if (!RUN_ONCE(&rand_init, do_rand_init))
        return 0;

    CRYPTO_THREAD_write_lock(rand_meth_lock);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(funct_ref);
    funct_ref = NULL;
#endif
    default_RAND_meth = meth;
    CRYPTO_THREAD_unlock(rand_meth_lock);
    return 1;
}

const RAND_METHOD *RAND_get_rand_method(void)
{
    const RAND_METHOD *tmp_meth = NULL;

    if (!RUN_ONCE(&rand_init, do_rand_init))
        return NULL;

    CRYPTO_THREAD_write_lock(rand_meth_lock);
    if (default_RAND_meth == NULL) {
#ifndef OPENSSL_NO_ENGINE
        ENGINE *e;

        /* If we have an engine that can do RAND, use it. */
        if ((e = ENGINE_get_default_RAND()) != NULL
                && (tmp_meth = ENGINE_get_RAND(e)) != NULL) {
            funct_ref = e;
            default_RAND_meth = tmp_meth;
        } else {
            ENGINE_finish(e);
            default_RAND_meth = &rand_meth;
        }
#else
        default_RAND_meth = &rand_meth;
#endif
    }
    tmp_meth = default_RAND_meth;
    CRYPTO_THREAD_unlock(rand_meth_lock);
    return tmp_meth;
}

#ifndef OPENSSL_NO_ENGINE
int RAND_set_rand_engine(ENGINE *engine)
{
    const RAND_METHOD *tmp_meth = NULL;

    if (!RUN_ONCE(&rand_init, do_rand_init))
        return 0;

    if (engine != NULL) {
        if (!ENGINE_init(engine))
            return 0;
        tmp_meth = ENGINE_get_RAND(engine);
        if (tmp_meth == NULL) {
            ENGINE_finish(engine);
            return 0;
        }
    }
    CRYPTO_THREAD_write_lock(rand_engine_lock);
    /* This function releases any prior ENGINE so call it first */
    RAND_set_rand_method(tmp_meth);
    funct_ref = engine;
    CRYPTO_THREAD_unlock(rand_engine_lock);
    return 1;
}
#endif

void RAND_seed(const void *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->seed != NULL)
        meth->seed(buf, num);
}

void RAND_add(const void *buf, int num, double randomness)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->add != NULL)
        meth->add(buf, num, randomness);
}

/*
 * This function is not part of RAND_METHOD, so if we're not using
 * the default method, then just call RAND_bytes().  Otherwise make
 * sure we're instantiated and use the private DRBG.
 */
int RAND_priv_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();
    RAND_DRBG *drbg;
    int ret;

    if (meth != RAND_OpenSSL())
        return RAND_bytes(buf, num);

    drbg = RAND_DRBG_get0_private();
    if (drbg == NULL)
        return 0;

    /* We have to lock the DRBG before generating bits from it. */
    CRYPTO_THREAD_write_lock(drbg->lock);
    ret = RAND_DRBG_generate(drbg, buf, num, 0, NULL, 0);
    CRYPTO_THREAD_unlock(drbg->lock);
    return ret;
}

int RAND_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->bytes != NULL)
        return meth->bytes(buf, num);
    RANDerr(RAND_F_RAND_BYTES, RAND_R_FUNC_NOT_IMPLEMENTED);
    return -1;
}

#if OPENSSL_API_COMPAT < 0x10100000L
int RAND_pseudo_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->pseudorand != NULL)
        return meth->pseudorand(buf, num);
    return -1;
}
#endif

int RAND_status(void)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->status != NULL)
        return meth->status();
    return 0;
}
