/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some engine deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

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
# include "prov/rand_pool.h"
# include "prov/seeding.h"

# ifndef OPENSSL_NO_ENGINE
/* non-NULL if default_RAND_meth is ENGINE-provided */
static ENGINE *funct_ref;
static CRYPTO_RWLOCK *rand_engine_lock;
# endif
static CRYPTO_RWLOCK *rand_meth_lock;
static const RAND_METHOD *default_RAND_meth;
static CRYPTO_ONCE rand_init = CRYPTO_ONCE_STATIC_INIT;

static int rand_inited = 0;

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

/*
 * RAND_close_seed_files() ensures that any seed file descriptors are
 * closed after use.  This only applies to libcrypto/default provider,
 * it does not apply to other providers.
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
    const RAND_METHOD *meth = RAND_get_rand_method();
    int ret = meth == RAND_OpenSSL();
    RAND_POOL *pool;

    if (meth == NULL)
        return 0;

    if (!ret) {
        /* fill random pool and seed the current legacy RNG */
        pool = rand_pool_new(RAND_DRBG_STRENGTH, 1,
                             (RAND_DRBG_STRENGTH + 7) / 8,
                             RAND_POOL_MAX_LENGTH);
        if (pool == NULL)
            return 0;

        if (prov_pool_acquire_entropy(pool) == 0)
            goto err;

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

const RAND_METHOD *RAND_get_rand_method(void)
{
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
}

# if !defined(OPENSSL_NO_ENGINE)
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
# endif

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

# if !defined(OPENSSL_NO_DEPRECATED_1_1_0)
int RAND_pseudo_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth != NULL && meth->pseudorand != NULL)
        return meth->pseudorand(buf, num);
    RANDerr(RAND_F_RAND_PSEUDO_BYTES, RAND_R_FUNC_NOT_IMPLEMENTED);
    return -1;
}
# endif

int RAND_status(void)
{
    RAND_DRBG *drbg;
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth != NULL && meth != RAND_OpenSSL())
        return meth->status != NULL ? meth->status() : 0;

    if ((drbg = RAND_DRBG_get0_master()) == NULL || drbg->rand == NULL)
        return EVP_RAND_STATE_UNINITIALISED;
    return EVP_RAND_state(drbg->rand) == EVP_RAND_STATE_READY;
}
#else  /* !FIPS_MODULE */

const RAND_METHOD *RAND_get_rand_method(void)
{
    return NULL;
}
#endif /* !FIPS_MODULE */

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
