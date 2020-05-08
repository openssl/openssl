/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include "internal/cryptlib.h"
#include <openssl/opensslconf.h>
#include "crypto/rand.h"
#include <openssl/engine.h>
#include "internal/thread_once.h"
#include "rand_local.h"
#include "e_os.h"

#ifndef FIPS_MODULE
# ifndef OPENSSL_NO_ENGINE
/* non-NULL if default_RAND_meth is ENGINE-provided */
static ENGINE *funct_ref;
static CRYPTO_RWLOCK *rand_engine_lock;
# endif
static CRYPTO_RWLOCK *rand_meth_lock;
static const RAND_METHOD *default_RAND_meth;
static CRYPTO_ONCE rand_init = CRYPTO_ONCE_STATIC_INIT;

static int rand_inited = 0;
#endif /* FIPS_MODULE */

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
            rand_pool_add(pool, &c, 1, 4);
        }
    }
    return rand_pool_entropy_available(pool);
}
#endif

#ifdef OPENSSL_RAND_SEED_RDCPU
size_t OPENSSL_ia32_rdseed_bytes(unsigned char *buf, size_t len);
size_t OPENSSL_ia32_rdrand_bytes(unsigned char *buf, size_t len);

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

    bytes_needed = rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
    if (bytes_needed > 0) {
        buffer = rand_pool_add_begin(pool, bytes_needed);

        if (buffer != NULL) {
            /* Whichever comes first, use RDSEED, RDRAND or nothing */
            if ((OPENSSL_ia32cap_P[2] & (1 << 18)) != 0) {
                if (OPENSSL_ia32_rdseed_bytes(buffer, bytes_needed)
                    == bytes_needed) {
                    rand_pool_add_end(pool, bytes_needed, 8 * bytes_needed);
                }
            } else if ((OPENSSL_ia32cap_P[1] & (1 << (62 - 32))) != 0) {
                if (OPENSSL_ia32_rdrand_bytes(buffer, bytes_needed)
                    == bytes_needed) {
                    rand_pool_add_end(pool, bytes_needed, 8 * bytes_needed);
                }
            } else {
                rand_pool_add_end(pool, 0, 0);
            }
        }
    }

    return rand_pool_entropy_available(pool);
}
#endif

#if 0
/*
 * Implements the get_entropy() callback (see RAND_DRBG_set_callbacks())
 *
 * If the DRBG has a parent, then the required amount of entropy input
 * is fetched using the parent's RAND_DRBG_generate().
 *
 * Otherwise, the entropy is polled from the system entropy sources
 * using rand_pool_acquire_entropy().
 *
 * If a random pool has been added to the DRBG using RAND_add(), then
 * its entropy will be used up first.
 */
size_t rand_drbg_get_entropy(RAND_DRBG *drbg,
                             unsigned char **pout,
                             int entropy, size_t min_len, size_t max_len,
                             int prediction_resistance)
{
    size_t ret = 0;
    size_t entropy_available = 0;
    RAND_POOL *pool;

    if (drbg->parent != NULL && drbg->strength > drbg->parent->strength) {
        /*
         * We currently don't support the algorithm from NIST SP 800-90C
         * 10.1.2 to use a weaker DRBG as source
         */
        RANDerr(RAND_F_RAND_DRBG_GET_ENTROPY, RAND_R_PARENT_STRENGTH_TOO_WEAK);
        return 0;
    }

    if (drbg->seed_pool != NULL) {
        pool = drbg->seed_pool;
        pool->entropy_requested = entropy;
    } else {
        pool = rand_pool_new(entropy, drbg->secure, min_len, max_len);
        if (pool == NULL)
            return 0;
    }

    if (drbg->parent != NULL) {
        size_t bytes_needed = rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
        unsigned char *buffer = rand_pool_add_begin(pool, bytes_needed);

        if (buffer != NULL) {
            size_t bytes = 0;

            /*
             * Get random data from parent. Include our address as additional input,
             * in order to provide some additional distinction between different
             * DRBG child instances.
             * Our lock is already held, but we need to lock our parent before
             * generating bits from it. (Note: taking the lock will be a no-op
             * if locking if drbg->parent->lock == NULL.)
             */
            rand_drbg_lock(drbg->parent);
            if (RAND_DRBG_generate(drbg->parent,
                                   buffer, bytes_needed,
                                   prediction_resistance,
                                   (unsigned char *)&drbg, sizeof(drbg)) != 0)
                bytes = bytes_needed;
            drbg->reseed_next_counter
                = tsan_load(&drbg->parent->reseed_prop_counter);
            rand_drbg_unlock(drbg->parent);

            rand_pool_add_end(pool, bytes, 8 * bytes);
            entropy_available = rand_pool_entropy_available(pool);
        }

    } else {
        /* Get entropy by polling system entropy sources. */
        entropy_available = rand_pool_acquire_entropy(pool);
    }

    if (entropy_available > 0) {
        ret   = rand_pool_length(pool);
        *pout = rand_pool_detach(pool);
    }

    if (drbg->seed_pool == NULL)
        rand_pool_free(pool);
    return ret;
}

/*
 * Implements the cleanup_entropy() callback (see RAND_DRBG_set_callbacks())
 *
 */
void rand_drbg_cleanup_entropy(RAND_DRBG *drbg,
                               unsigned char *out, size_t outlen)
{
    if (drbg->seed_pool == NULL) {
        if (drbg->secure)
            OPENSSL_secure_clear_free(out, outlen);
        else
            OPENSSL_clear_free(out, outlen);
    }
}

/*
 * Generate additional data that can be used for the drbg. The data does
 * not need to contain entropy, but it's useful if it contains at least
 * some bits that are unpredictable.
 *
 * Returns 0 on failure.
 *
 * On success it allocates a buffer at |*pout| and returns the length of
 * the data. The buffer should get freed using OPENSSL_secure_clear_free().
 */
size_t rand_drbg_get_additional_data(RAND_POOL *pool, unsigned char **pout)
{
    size_t ret = 0;

    if (rand_pool_add_additional_data(pool) == 0)
        goto err;

    ret = rand_pool_length(pool);
    *pout = rand_pool_detach(pool);

 err:
    return ret;
}

void rand_drbg_cleanup_additional_data(RAND_POOL *pool, unsigned char *out)
{
    rand_pool_reattach(pool, out);
}
#endif

#ifndef FIPS_MODULE
DEFINE_RUN_ONCE_STATIC(do_rand_init)
{
# ifndef OPENSSL_NO_ENGINE
    rand_engine_lock = CRYPTO_THREAD_lock_new();
    if (rand_engine_lock == NULL)
        return 0;
# endif

    rand_meth_lock = CRYPTO_THREAD_lock_new();
    if (rand_meth_lock == NULL)
        goto err;

    if (!rand_pool_init())
        goto err;

    rand_inited = 1;
    return 1;

 err:
    CRYPTO_THREAD_lock_free(rand_meth_lock);
    rand_meth_lock = NULL;
# ifndef OPENSSL_NO_ENGINE
    CRYPTO_THREAD_lock_free(rand_engine_lock);
    rand_engine_lock = NULL;
# endif
    return 0;
}

void rand_cleanup_int(void)
{
    const RAND_METHOD *meth = default_RAND_meth;

    if (!rand_inited)
        return;

    if (meth != NULL && meth->cleanup != NULL)
        meth->cleanup();
    RAND_set_rand_method(NULL);
    rand_pool_cleanup();
# ifndef OPENSSL_NO_ENGINE
    CRYPTO_THREAD_lock_free(rand_engine_lock);
    rand_engine_lock = NULL;
# endif
    CRYPTO_THREAD_lock_free(rand_meth_lock);
    rand_meth_lock = NULL;
    rand_inited = 0;
}

/* TODO(3.0): Do we need to handle this somehow in the FIPS module? */
/*
 * RAND_close_seed_files() ensures that any seed file descriptors are
 * closed after use.
 */
void RAND_keep_random_devices_open(int keep)
{
    if (RUN_ONCE(&rand_init, do_rand_init))
        rand_pool_keep_random_devices_open(keep);
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

    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth == NULL)
        return 0;

    if (meth == RAND_OpenSSL()) {
        /* fill random pool and seed the master DRBG */
        RAND_DRBG *drbg = RAND_DRBG_get0_master();

        if (drbg == NULL)
            return 0;

#if 0
        ret = rand_drbg_restart(drbg, NULL, 0, 0);
#endif

        return ret;

    } else {
        RAND_POOL *pool = NULL;

        /* fill random pool and seed the current legacy RNG */
        pool = rand_pool_new(RAND_DRBG_STRENGTH, 1,
                             (RAND_DRBG_STRENGTH + 7) / 8,
                             RAND_POOL_MAX_LENGTH);
        if (pool == NULL)
            return 0;
#if 0
        if (rand_pool_acquire_entropy(pool) == 0)
            goto err;
#endif
        if (meth->add == NULL
            || meth->add(rand_pool_buffer(pool),
                         rand_pool_length(pool),
                         (rand_pool_entropy(pool) / 8.0)) == 0)
            goto err;

        ret = 1;

     err:
        rand_pool_free(pool);
    }

    return ret;
}

int RAND_set_rand_method(const RAND_METHOD *meth)
{
    if (!RUN_ONCE(&rand_init, do_rand_init))
        return 0;

    CRYPTO_THREAD_write_lock(rand_meth_lock);
# ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(funct_ref);
    funct_ref = NULL;
# endif
    default_RAND_meth = meth;
    CRYPTO_THREAD_unlock(rand_meth_lock);
    return 1;
}
#endif /* FIPS_MODULE */

const RAND_METHOD *RAND_get_rand_method(void)
{
#ifdef FIPS_MODULE
    return NULL;
#else
    const RAND_METHOD *tmp_meth = NULL;

    if (!RUN_ONCE(&rand_init, do_rand_init))
        return NULL;

    CRYPTO_THREAD_write_lock(rand_meth_lock);
    if (default_RAND_meth == NULL) {
# ifndef OPENSSL_NO_ENGINE
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
# else
        default_RAND_meth = &rand_meth;
# endif
    }
    tmp_meth = default_RAND_meth;
    CRYPTO_THREAD_unlock(rand_meth_lock);
    return tmp_meth;
#endif
}

#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)
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

    if (meth != NULL && meth->seed != NULL)
        meth->seed(buf, num);
}

void RAND_add(const void *buf, int num, double randomness)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth != NULL && meth->add != NULL)
        meth->add(buf, num, randomness);
}

/*
 * This function is not part of RAND_METHOD, so if we're not using
 * the default method, then just call RAND_bytes().  Otherwise make
 * sure we're instantiated and use the private DRBG.
 */
int RAND_priv_bytes_ex(OPENSSL_CTX *ctx, unsigned char *buf, int num)
{
    RAND_DRBG *drbg;
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth != NULL && meth != RAND_OpenSSL()) {
        if (meth->bytes != NULL)
            return meth->bytes(buf, num);
        RANDerr(RAND_F_RAND_PRIV_BYTES_EX, RAND_R_FUNC_NOT_IMPLEMENTED);
        return -1;
    }

    drbg = OPENSSL_CTX_get0_private_drbg(ctx);
    if (drbg != NULL)
        return RAND_DRBG_bytes(drbg, buf, num);

    return 0;
}

int RAND_priv_bytes(unsigned char *buf, int num)
{
    return RAND_priv_bytes_ex(NULL, buf, num);
}

int RAND_bytes_ex(OPENSSL_CTX *ctx, unsigned char *buf, int num)
{
    RAND_DRBG *drbg;
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth != NULL && meth != RAND_OpenSSL()) {
        if (meth->bytes != NULL)
            return meth->bytes(buf, num);
        RANDerr(RAND_F_RAND_BYTES_EX, RAND_R_FUNC_NOT_IMPLEMENTED);
        return -1;
    }

    drbg = OPENSSL_CTX_get0_public_drbg(ctx);
    if (drbg != NULL)
        return RAND_DRBG_bytes(drbg, buf, num);

    return 0;
}

int RAND_bytes(unsigned char *buf, int num)
{
    return RAND_bytes_ex(NULL, buf, num);
}

#if !defined(OPENSSL_NO_DEPRECATED_1_1_0) && !defined(FIPS_MODULE)
int RAND_pseudo_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth != NULL && meth->pseudorand != NULL)
        return meth->pseudorand(buf, num);
    RANDerr(RAND_F_RAND_PSEUDO_BYTES, RAND_R_FUNC_NOT_IMPLEMENTED);
    return -1;
}
#endif

int RAND_status(void)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth != NULL && meth->status != NULL)
        return meth->status();
    return 0;
}
