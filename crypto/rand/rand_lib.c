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
 * Since we get some randomness from the low-order bits of the
 * high-speec clock, it can help.  But don't return a status since
 * it's not sufficient to indicate whether or not the seeding was
 * done.
 */
void rand_read_tsc(RAND_poll_fn cb, void *arg)
{
    unsigned char c;
    int i;

    if ((OPENSSL_ia32cap_P[0] & (1 << 4)) != 0) {
        for (i = 0; i < TSC_READ_COUNT; i++) {
            c = (unsigned char)(OPENSSL_rdtsc() & 0xFF);
            cb(arg, &c, 1, 0.5);
        }
    }
}
#endif

#ifdef OPENSSL_RAND_SEED_RDCPU
size_t OPENSSL_ia32_rdseed_bytes(char *buf, size_t len);
size_t OPENSSL_ia32_rdrand_bytes(char *buf, size_t len);

extern unsigned int OPENSSL_ia32cap_P[];

int rand_read_cpu(RAND_poll_fn cb, void *arg)
{
    char buff[RANDOMNESS_NEEDED];

    /* If RDSEED is available, use that. */
    if ((OPENSSL_ia32cap_P[2] & (1 << 18)) != 0) {
        if (OPENSSL_ia32_rdseed_bytes(buff, sizeof(buff)) == sizeof(buff)) {
            cb(arg, buff, (int)sizeof(buff), sizeof(buff));
            return 1;
        }
    }

    /* Second choice is RDRAND. */
    if ((OPENSSL_ia32cap_P[1] & (1 << (62 - 32))) != 0) {
        if (OPENSSL_ia32_rdrand_bytes(buff, sizeof(buff)) == sizeof(buff)) {
            cb(arg, buff, (int)sizeof(buff), sizeof(buff));
            return 1;
        }
    }

    return 0;
}
#endif


/*
 * DRBG has two sets of callbacks; we only discuss the "entropy" one
 * here.  When the DRBG needs additional randomness bits (called entropy
 * in the NIST document), it calls the get_entropy callback which fills in
 * a pointer and returns the number of bytes. When the DRBG is finished with
 * the buffer, it calls the cleanup_entropy callback, with the value of
 * the buffer that the get_entropy callback filled in.
 *
 * Get entropy from the system, via RAND_poll if needed.  The |entropy|
 * is the bits of randomness required, and is expected to fit into a buffer
 * of |min_len|..|max__len| size.  We assume we're getting high-quality
 * randomness from the system, and that |min_len| bytes will do.
 */
size_t drbg_entropy_from_system(RAND_DRBG *drbg,
                                unsigned char **pout,
                                int entropy, size_t min_len, size_t max_len)
{
    int i;


    if (min_len > (size_t)drbg->size) {
        /* Should not happen.  See comment near RANDOMNESS_NEEDED. */
        min_len = drbg->size;
    }

    if (drbg->filled) {
        /* Re-use what we have. */
        *pout = drbg->randomness;
        return drbg->size;
    }

    /* If we don't have enough, try to get more. */
    CRYPTO_THREAD_write_lock(rand_bytes.lock);
    for (i = RAND_POLL_RETRIES; rand_bytes.curr < min_len && --i >= 0; ) {
        CRYPTO_THREAD_unlock(rand_bytes.lock);
        RAND_poll();
        CRYPTO_THREAD_write_lock(rand_bytes.lock);
    }

    /* Get desired amount, but no more than we have. */
    if (min_len > rand_bytes.curr)
        min_len = rand_bytes.curr;
    if (min_len != 0) {
        memcpy(drbg->randomness, rand_bytes.buff, min_len);
        drbg->filled = 1;
        /* Update amount left and shift it down. */
        rand_bytes.curr -= min_len;
        if (rand_bytes.curr != 0)
            memmove(rand_bytes.buff, &rand_bytes.buff[min_len], rand_bytes.curr);
    }
    CRYPTO_THREAD_unlock(rand_bytes.lock);
    *pout = drbg->randomness;
    return min_len;
}

size_t drbg_entropy_from_parent(RAND_DRBG *drbg,
                                unsigned char **pout,
                                int entropy, size_t min_len, size_t max_len)
{
    int st;

    if (min_len > (size_t)drbg->size) {
        /* Should not happen.  See comment near RANDOMNESS_NEEDED. */
        min_len = drbg->size;
    }

    /* Get random from parent, include our state as additional input. */
    st = RAND_DRBG_generate(drbg->parent, drbg->randomness, min_len, 0,
                            (unsigned char *)drbg, sizeof(*drbg));
    if (st == 0)
        return 0;
    drbg->filled = 1;
    *pout = drbg->randomness;
    return min_len;
}

void drbg_release_entropy(RAND_DRBG *drbg, unsigned char *out)
{
    drbg->filled = 0;
    OPENSSL_cleanse(drbg->randomness, drbg->size);
}


/*
 * Set up a global DRBG.
 */
static int setup_drbg(RAND_DRBG *drbg)
{
    int ret = 1;

    drbg->lock = CRYPTO_THREAD_lock_new();
    ret &= drbg->lock != NULL;
    drbg->size = RANDOMNESS_NEEDED;
    drbg->secure = CRYPTO_secure_malloc_initialized();
    drbg->randomness = drbg->secure
        ? OPENSSL_secure_malloc(drbg->size)
        : OPENSSL_malloc(drbg->size);
    ret &= drbg->randomness != NULL;
    /* If you change these parameters, see RANDOMNESS_NEEDED */
    ret &= RAND_DRBG_set(drbg,
                         NID_aes_128_ctr, RAND_DRBG_FLAG_CTR_USE_DF) == 1;
    ret &= RAND_DRBG_set_callbacks(drbg, drbg_entropy_from_system,
                                   drbg_release_entropy, NULL, NULL) == 1;
    return ret;
}

static void free_drbg(RAND_DRBG *drbg)
{
    CRYPTO_THREAD_lock_free(drbg->lock);
    if (drbg->secure)
        OPENSSL_secure_clear_free(drbg->randomness, drbg->size);
    else
        OPENSSL_clear_free(drbg->randomness, drbg->size);
    RAND_DRBG_uninstantiate(drbg);
}

void rand_fork()
{
    rand_fork_count++;
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
    rand_bytes.curr = 0;
    rand_bytes.size = MAX_RANDOMNESS_HELD;
    rand_bytes.secure = CRYPTO_secure_malloc_initialized();
    rand_bytes.buff = rand_bytes.secure
        ? OPENSSL_secure_malloc(rand_bytes.size)
        : OPENSSL_malloc(rand_bytes.size);
    ret &= rand_bytes.buff != NULL;
    ret &= setup_drbg(&rand_drbg);
    ret &= setup_drbg(&priv_drbg);
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
    if (rand_bytes.secure)
        OPENSSL_secure_clear_free(rand_bytes.buff, rand_bytes.size);
    else
        OPENSSL_clear_free(rand_bytes.buff, rand_bytes.size);
    free_drbg(&rand_drbg);
    free_drbg(&priv_drbg);
}

/*
 * RAND_poll_ex() gets a function pointer to call when it has random bytes.
 * RAND_poll() sets the function pointer to be a wrapper that calls RAND_add().
 */
static void call_rand_add(void* arg, const void *buf, int num, double r)
{
    RAND_add(buf, num, r);
}

int RAND_poll(void)
{
    return RAND_poll_ex(call_rand_add, NULL);
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

    if (meth != RAND_OpenSSL())
        return RAND_bytes(buf, num);

    if (priv_drbg.state == DRBG_UNINITIALISED
            && RAND_DRBG_instantiate(&priv_drbg, NULL, 0) == 0)
        return 0;
    return RAND_DRBG_generate(&priv_drbg, buf, num, 0, NULL, 0);

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
