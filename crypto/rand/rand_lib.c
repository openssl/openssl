/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
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
RAND_BYTES_BUFFER rand_bytes;

#ifdef OPENSSL_RAND_SEED_RDTSC
/*
 * IMPORTANT NOTE:  It is not currently possible to use this code
 * because we are not sure about the amount of randomness.  Some
 * SP900 tests have been run, but there is internal skepticism.
 * So for now this code is not used.
 */
# error "RDTSC enabled?  Should not be possible!"

/*
 * Since we get some randomness from the low-order bits of the
 * high-speec clock, it can help.  But don't return a status since
 * it's not sufficient to indicate whether or not the seeding was
 * done.
 */
void rand_read_tsc(void)
{
    unsigned char c;
    int i;

    for (i = 0; i < 10; i++) {
        c = (unsigned char)(OPENSSL_rdtsc() & 0xFF);
        RAND_add(&c, 1, 0.5);
    }
}
#endif

#ifdef OPENSSL_RAND_SEED_RDCPU
size_t OPENSSL_ia32_rdseed(void);
size_t OPENSSL_ia32_rdrand(void);

extern unsigned int OPENSSL_ia32cap_P[];

int rand_read_cpu(void)
{
    size_t i, s;

    /* If RDSEED is available, use that. */
    if ((OPENSSL_ia32cap_P[1] & (1 << 18)) != 0) {
        for (i = 0; i < RANDOMNESS_NEEDED; i += sizeof(s)) {
            s = OPENSSL_ia32_rdseed();
            if (s == 0)
                break;
            RAND_add(&s, (int)sizeof(s), sizeof(s));
        }
        if (i >= RANDOMNESS_NEEDED)
            return 1;
    }

    /* Second choice is RDRAND. */
    if ((OPENSSL_ia32cap_P[1] & (1 << (62 - 32))) != 0) {
        for (i = 0; i < RANDOMNESS_NEEDED; i += sizeof(s)) {
            s = OPENSSL_ia32_rdrand();
            if (s == 0)
                break;
            RAND_add(&s, (int)sizeof(s), sizeof(s));
        }
        if (i >= RANDOMNESS_NEEDED)
            return 1;
    }

    return 0;
}
#endif

/*
 */
static size_t entropy_from_system(RAND_DRBG *drbg,
                                  unsigned char **pout,
                                  int entropy, size_t min_len, size_t max_len)
{
    entropy /= 8;

    if (rand_drbg.filled) {
        /* Re-use what we have. */
        *pout = drbg->randomness;
        return sizeof(drbg->randomness);
    }

    /* If we don't have enough, get more. */
    CRYPTO_THREAD_write_lock(rand_bytes.lock);
    if (rand_bytes.curr < entropy) {
        CRYPTO_THREAD_unlock(rand_bytes.lock);
        RAND_poll();
        CRYPTO_THREAD_write_lock(rand_bytes.lock);
    }

    /* Get desired amount, but no more than we have. */
    if (entropy > rand_bytes.curr)
        entropy = rand_bytes.curr;
    if (entropy != 0) {
        memcpy(drbg->randomness, rand_bytes.buff, entropy);
        rand_drbg.filled = 1;
        /* Update amount left and shift it down. */
        rand_bytes.curr -= entropy;
        if (rand_bytes.curr != 0)
            memmove(rand_bytes.buff, &rand_bytes.buff[entropy], rand_bytes.curr);
    }
    CRYPTO_THREAD_unlock(rand_bytes.lock);
    return entropy;
}

DEFINE_RUN_ONCE_STATIC(do_rand_init)
{
    int ret = 1;

#ifndef OPENSSL_NO_ENGINE
    rand_engine_lock = CRYPTO_THREAD_lock_new();
    ret &= rand_engine_lock != NULL;
#endif
    rand_meth_lock = CRYPTO_THREAD_lock_new();
    ret &= rand_meth_lock != NULL;

    rand_bytes.lock = CRYPTO_THREAD_lock_new();
    ret &= rand_bytes.lock != NULL;
    rand_bytes.size = MAX_RANDOMNESS_HELD;
    rand_bytes.buff = malloc(rand_bytes.size);
    ret &= rand_bytes.buff != NULL;

    rand_drbg.lock = CRYPTO_THREAD_lock_new();
    ret &= rand_drbg.lock != NULL;
    ret &= RAND_DRBG_set(&rand_drbg, NID_aes_128_ctr, 0) == 1;
    ret &= RAND_DRBG_set_callbacks(&rand_drbg,
                                   entropy_from_system, rand_cleanup_entropy,
                                   NULL, NULL) == 1;
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
    CRYPTO_THREAD_lock_free(rand_bytes.lock);
    CRYPTO_THREAD_lock_free(rand_drbg.lock);
    RAND_DRBG_uninstantiate(&rand_drbg);
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
