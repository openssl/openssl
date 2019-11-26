/*
 * Copyright 2011-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include "rand_local.h"
#include "internal/thread_once.h"
#include "internal/provider.h"
#include "crypto/rand.h"
#include "crypto/cryptlib.h"

/*
 * Support framework for NIST SP 800-90A DRBG
 *
 * See manual page RAND_DRBG(7) for a general overview.
 *
 * The OpenSSL model is to have new and free functions, and that new
 * does all initialization.  That is not the NIST model, which has
 * instantiation and un-instantiate, and re-use within a new/free
 * lifecycle.  (No doubt this comes from the desire to support hardware
 * DRBG, where allocation of resources on something like an HSM is
 * a much bigger deal than just re-setting an allocated resource.)
 */


typedef struct drbg_global_st {
    /*
     * The three shared DRBG instances
     *
     * There are three shared DRBG instances: <master>, <public>, and <private>.
     */

    /*
     * The <master> DRBG
     *
     * Not used directly by the application, only for reseeding the two other
     * DRBGs. It reseeds itself by pulling either randomness from os entropy
     * sources or by consuming randomness which was added by RAND_add().
     *
     * The <master> DRBG is a global instance which is accessed concurrently by
     * all threads. The necessary locking is managed automatically by its child
     * DRBG instances during reseeding.
     */
    RAND_DRBG *master_drbg;
    /*
     * The <public> DRBG
     *
     * Used by default for generating random bytes using RAND_bytes().
     *
     * The <public> DRBG is thread-local, i.e., there is one instance per
     * thread.
     */
    CRYPTO_THREAD_LOCAL public_drbg;
    /*
     * The <private> DRBG
     *
     * Used by default for generating private keys using RAND_priv_bytes()
     *
     * The <private> DRBG is thread-local, i.e., there is one instance per
     * thread.
     */
    CRYPTO_THREAD_LOCAL private_drbg;

    /*
     * The randomness source
     *
     * Used by the master DRBG for seeding purposes
     */
    EVP_RAND_CTX *seed;
} DRBG_GLOBAL;

typedef struct drbg_nonce_global_st {
    CRYPTO_RWLOCK *rand_nonce_lock;
    int rand_nonce_count;
} DRBG_NONCE_GLOBAL;

#define RAND_DRBG_TYPE_FLAGS    ( \
    RAND_DRBG_FLAG_MASTER | RAND_DRBG_FLAG_PUBLIC | RAND_DRBG_FLAG_PRIVATE )

#define RAND_DRBG_TYPE_MASTER                     0
#define RAND_DRBG_TYPE_PUBLIC                     1
#define RAND_DRBG_TYPE_PRIVATE                    2

/* Defaults */
static int rand_drbg_type[3] = {
    RAND_DRBG_TYPE, /* Master */
    RAND_DRBG_TYPE, /* Public */
    RAND_DRBG_TYPE  /* Private */
};
static unsigned int rand_drbg_flags[3] = {
    RAND_DRBG_FLAGS | RAND_DRBG_FLAG_MASTER, /* Master */
    RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PUBLIC, /* Public */
    RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PRIVATE /* Private */
};

static unsigned int master_reseed_interval = MASTER_RESEED_INTERVAL;
static unsigned int slave_reseed_interval  = SLAVE_RESEED_INTERVAL;

static time_t master_reseed_time_interval = MASTER_RESEED_TIME_INTERVAL;
static time_t slave_reseed_time_interval  = SLAVE_RESEED_TIME_INTERVAL;

/* A logical OR of all used DRBG flag bits (currently there is only one) */
static const unsigned int rand_drbg_used_flags =
    RAND_DRBG_FLAG_CTR_NO_DF | RAND_DRBG_FLAG_HMAC | RAND_DRBG_TYPE_FLAGS;


static RAND_DRBG *drbg_setup(OPENSSL_CTX *ctx, EVP_RAND_CTX *parent,
                             int drbg_type);

static EVP_RAND_CTX *rand_drbg_evp_ctx(RAND_DRBG *drbg)
{
    return drbg != NULL ? drbg->rand : NULL;
}

static RAND_DRBG *rand_drbg_new(OPENSSL_CTX *ctx,
                                int secure,
                                int type,
                                unsigned int flags,
                                EVP_RAND_CTX *parent);

static int get_drbg_params(int type, unsigned int flags, const char **name,
                           const char **alg_pname, const char **alg_name)
{
    const char *alg = NULL, *pname = NULL, *pval = NULL;

    switch (type) {
    case 0:
        return 1;
    default:
        return 0;
#define CTR(v)                                  \
    alg = OSSL_RAND_NAME_CTR_DRBG;              \
    pname = OSSL_RAND_PARAM_CIPHER;             \
    pval = v
#define DGST(v)                                 \
    if ((flags & RAND_DRBG_FLAG_HMAC) == 0) {   \
        alg = OSSL_RAND_NAME_DIGEST_DRBG;       \
        pname = OSSL_RAND_PARAM_DIGEST;         \
        pval = v;                               \
    } else {                                    \
        alg = OSSL_RAND_NAME_HMAC_DRBG;         \
        pname = OSSL_RAND_PARAM_DIGEST;         \
        pval = v;                               \
    }
    case NID_aes_128_ctr:
        CTR(SN_aes_128_ctr);
        break;
    case NID_aes_192_ctr:
        CTR(SN_aes_192_ctr);
        break;
    case NID_aes_256_ctr:
        CTR(SN_aes_256_ctr);
        break;
    case NID_sha1:
        DGST(SN_sha1);
        break;
    case NID_sha224:
        DGST(SN_sha224);
        break;
    case NID_sha256:
        DGST(SN_sha256);
        break;
    case NID_sha384:
        DGST(SN_sha384);
        break;
    case NID_sha512:
        DGST(SN_sha512);
        break;
    case NID_sha512_224:
        DGST(SN_sha512_224);
        break;
    case NID_sha512_256:
        DGST(SN_sha512_256);
        break;
    case NID_sha3_224:
        DGST(SN_sha3_224);
        break;
    case NID_sha3_256:
        DGST(SN_sha3_256);
        break;
    case NID_sha3_384:
        DGST(SN_sha3_384);
        break;
    case NID_sha3_512:
        DGST(SN_sha3_512);
        break;
    }
    if (name != NULL)
        *name = alg;
    if (alg_pname != NULL) {
        *alg_pname = pname;
        *alg_name = pval;
    }
    return 1;
}

/*
 * Initialize the OPENSSL_CTX global DRBGs on first use.
 * Returns the allocated global data on success or NULL on failure.
 */
static void *drbg_ossl_ctx_new(OPENSSL_CTX *libctx)
{
    DRBG_GLOBAL *dgbl;
    EVP_RAND *rand;

#ifndef FIPS_MODE
    /*
     * We need to ensure that base libcrypto thread handling has been
     * initialised.
     */
     OPENSSL_init_crypto(0, NULL);
#endif

    dgbl = OPENSSL_zalloc(sizeof(*dgbl));
    if (dgbl == NULL)
        return NULL;

    if (!CRYPTO_THREAD_init_local(&dgbl->private_drbg, NULL))
        goto err1;

    if (!CRYPTO_THREAD_init_local(&dgbl->public_drbg, NULL))
        goto err2;

    rand = EVP_RAND_fetch(libctx, "seed", NULL);
    if (rand == NULL)
        goto err3;
    dgbl->seed = EVP_RAND_CTX_new(rand, 1, 0, NULL);
    EVP_RAND_free(rand);
    if (dgbl->seed == NULL)
        goto err3;
    /* TODO: FIPS mode needs a CRNGT rand inserted here */
    dgbl->master_drbg = drbg_setup(libctx, dgbl->seed, RAND_DRBG_TYPE_MASTER);
    if (dgbl->master_drbg == NULL)
        goto err4;
    if (!EVP_RAND_CTX_enable_locking(dgbl->master_drbg->rand))
        goto err5;

    return dgbl;

 err5:
    RAND_DRBG_free(dgbl->master_drbg);
 err4:
    EVP_RAND_CTX_free(dgbl->seed);
 err3:
    CRYPTO_THREAD_cleanup_local(&dgbl->public_drbg);
 err2:
    CRYPTO_THREAD_cleanup_local(&dgbl->private_drbg);
 err1:
    OPENSSL_free(dgbl);
    return NULL;
}

static void drbg_ossl_ctx_free(void *vdgbl)
{
    DRBG_GLOBAL *dgbl = vdgbl;

    if (dgbl == NULL)
        return;

    RAND_DRBG_free(dgbl->master_drbg);
    CRYPTO_THREAD_cleanup_local(&dgbl->private_drbg);
    CRYPTO_THREAD_cleanup_local(&dgbl->public_drbg);

    OPENSSL_free(dgbl);
}

static const OPENSSL_CTX_METHOD drbg_ossl_ctx_method = {
    drbg_ossl_ctx_new,
    drbg_ossl_ctx_free,
};

/*
 * drbg_ossl_ctx_new() calls drgb_setup() which calls rand_drbg_get_nonce()
 * which needs to get the rand_nonce_lock out of the OPENSSL_CTX...but since
 * drbg_ossl_ctx_new() hasn't finished running yet we need the rand_nonce_lock
 * to be in a different global data object. Otherwise we will go into an
 * infinite recursion loop.
 */
static void *drbg_nonce_ossl_ctx_new(OPENSSL_CTX *libctx)
{
    DRBG_NONCE_GLOBAL *dngbl = OPENSSL_zalloc(sizeof(*dngbl));

    if (dngbl == NULL)
        return NULL;

    dngbl->rand_nonce_lock = CRYPTO_THREAD_lock_new();
    if (dngbl->rand_nonce_lock == NULL) {
        OPENSSL_free(dngbl);
        return NULL;
    }

    return dngbl;
}

static void drbg_nonce_ossl_ctx_free(void *vdngbl)
{
    DRBG_NONCE_GLOBAL *dngbl = vdngbl;

    if (dngbl == NULL)
        return;

    CRYPTO_THREAD_lock_free(dngbl->rand_nonce_lock);

    OPENSSL_free(dngbl);
}

static const OPENSSL_CTX_METHOD drbg_nonce_ossl_ctx_method = {
    drbg_nonce_ossl_ctx_new,
    drbg_nonce_ossl_ctx_free,
};

static DRBG_GLOBAL *drbg_get_global(OPENSSL_CTX *libctx)
{
    return openssl_ctx_get_data(libctx, OPENSSL_CTX_DRBG_INDEX,
                                &drbg_ossl_ctx_method);
}

/* Implements the get_nonce() callback (see RAND_DRBG_set_callbacks()) */
size_t rand_drbg_get_nonce(RAND_DRBG *drbg,
                           unsigned char **pout,
                           int entropy, size_t min_len, size_t max_len)
{
    size_t ret = 0;
    RAND_POOL *pool;
    const EVP_RAND *rand = EVP_RAND_CTX_rand(drbg->rand);
    OPENSSL_CTX *libctx
        = ossl_provider_library_context(EVP_RAND_provider(rand));
    DRBG_NONCE_GLOBAL *dngbl
        = openssl_ctx_get_data(libctx, OPENSSL_CTX_DRBG_NONCE_INDEX,
                               &drbg_nonce_ossl_ctx_method);
    struct {
        void *instance;
        int count;
    } data;

    if (dngbl == NULL)
        return 0;

    memset(&data, 0, sizeof(data));
    pool = rand_pool_new(0, 0, min_len, max_len);
    if (pool == NULL)
        return 0;

    if (rand_pool_add_nonce_data(pool) == 0)
        goto err;

    data.instance = drbg;
    CRYPTO_atomic_add(&dngbl->rand_nonce_count, 1, &data.count,
                      dngbl->rand_nonce_lock);

    if (rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0) == 0)
        goto err;

    ret   = rand_pool_length(pool);
    *pout = rand_pool_detach(pool);

 err:
    rand_pool_free(pool);

    return ret;
}

/*
 * Implements the cleanup_nonce() callback (see RAND_DRBG_set_callbacks())
 *
 */
void rand_drbg_cleanup_nonce(RAND_DRBG *drbg,
                             unsigned char *out, size_t outlen)
{
    OPENSSL_clear_free(out, outlen);
}

static int rand_drbg_create_drbg(RAND_DRBG *drbg, const char *name,
                                 const char *alg_pname, const char *alg_name,
                                 int secure, int df, EVP_RAND_CTX *parent)
{
    OSSL_PARAM params[2], *p = params;
    EVP_RAND_CTX *rand = NULL;
    EVP_RAND *e_rand;

    e_rand = EVP_RAND_fetch(NULL, name, NULL);
    if (e_rand == NULL)
        return 0;
    rand = EVP_RAND_CTX_new(e_rand, secure, df, parent);
    EVP_RAND_free(e_rand);
    if (rand == NULL)
        return 0;

    *p++ = OSSL_PARAM_construct_utf8_string(alg_pname, (char *)alg_name, 0);
    *p = OSSL_PARAM_construct_end();

    if (!EVP_RAND_CTX_set_params(rand, params)) {
        EVP_RAND_CTX_free(rand);
        RANDerr(0, RAND_R_ERROR_INITIALISING_DRBG);
        return 0;
    }
    EVP_RAND_CTX_free(drbg->rand);
    drbg->rand = rand;
    return 1;
}

/*
 * Set/initialize |drbg| to be of type |type|, with optional |flags|.
 *
 * If |type| and |flags| are zero, use the defaults
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_set(RAND_DRBG *drbg, int type, unsigned int flags)
{
    const char *name = NULL, *alg_pname, *alg_name;

    if (type == 0 && flags == 0) {
        type = rand_drbg_type[RAND_DRBG_TYPE_MASTER];
        flags = rand_drbg_flags[RAND_DRBG_TYPE_MASTER];
    }

    if (!get_drbg_params(type, flags, &name, &alg_pname, &alg_name)) {
        RANDerr(RAND_F_RAND_DRBG_SET, RAND_R_UNSUPPORTED_DRBG_TYPE);
        return 0;
    }
    if (name == NULL)
        return 1;

    drbg->flags = flags;
    drbg->type = type;
    return rand_drbg_create_drbg(drbg, name, alg_pname, alg_name, drbg->secure,
                                 (flags & RAND_DRBG_FLAG_CTR_NO_DF) ? 0 : 1,
                                 evp_rand_ctx_parent(drbg->rand));
#if 0
    /* If set is called multiple times - clear the old one */
    if (drbg->type != 0 && (type != drbg->type || flags != drbg->flags)) {
        drbg->meth->uninstantiate(drbg);
        rand_pool_free(drbg->adin_pool);
        drbg->adin_pool = NULL;
    }

    if (type == 0) {
        /* Uninitialized; that's okay. */
        drbg->meth = NULL;
        return 1;
    } else if (is_ctr(type)) {
        ret = drbg_ctr_init(drbg);
    } else if (is_digest(type)) {
        if (flags & RAND_DRBG_FLAG_HMAC)
            ret = drbg_hmac_init(drbg);
        else
            ret = drbg_hash_init(drbg);
    } else {
        drbg->type = 0;
        drbg->flags = 0;
        drbg->meth = NULL;
        RANDerr(RAND_F_RAND_DRBG_SET, RAND_R_UNSUPPORTED_DRBG_TYPE);
        return 0;
    }

    if (ret == 0) {
        drbg->state = DRBG_ERROR;
        RANDerr(RAND_F_RAND_DRBG_SET, RAND_R_ERROR_INITIALISING_DRBG);
    }
    return ret;
#endif
}

/*
 * Set/initialize default |type| and |flag| for new drbg instances.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_set_defaults(int type, unsigned int flags)
{
    int all;

    if (!get_drbg_params(type, flags, NULL, NULL, NULL)) {
        RANDerr(RAND_F_RAND_DRBG_SET_DEFAULTS, RAND_R_UNSUPPORTED_DRBG_TYPE);
        return 0;
    }

    if ((flags & ~rand_drbg_used_flags) != 0) {
        RANDerr(RAND_F_RAND_DRBG_SET_DEFAULTS, RAND_R_UNSUPPORTED_DRBG_FLAGS);
        return 0;
    }

    all = ((flags & RAND_DRBG_TYPE_FLAGS) == 0);
    if (all || (flags & RAND_DRBG_FLAG_MASTER) != 0) {
        rand_drbg_type[RAND_DRBG_TYPE_MASTER] = type;
        rand_drbg_flags[RAND_DRBG_TYPE_MASTER] = flags | RAND_DRBG_FLAG_MASTER;
    }
    if (all || (flags & RAND_DRBG_FLAG_PUBLIC) != 0) {
        rand_drbg_type[RAND_DRBG_TYPE_PUBLIC]  = type;
        rand_drbg_flags[RAND_DRBG_TYPE_PUBLIC] = flags | RAND_DRBG_FLAG_PUBLIC;
    }
    if (all || (flags & RAND_DRBG_FLAG_PRIVATE) != 0) {
        rand_drbg_type[RAND_DRBG_TYPE_PRIVATE] = type;
        rand_drbg_flags[RAND_DRBG_TYPE_PRIVATE] = flags | RAND_DRBG_FLAG_PRIVATE;
    }
    return 1;
}

/*
 * Allocate memory and initialize a new DRBG. The DRBG is allocated on
 * the secure heap if |secure| is nonzero and the secure heap is enabled.
 * The |parent|, if not NULL, will be used as random source for reseeding.
 *
 * Returns a pointer to the new DRBG instance on success, NULL on failure.
 */
static RAND_DRBG *rand_drbg_new(OPENSSL_CTX *ctx,
                                int secure,
                                int type,
                                unsigned int flags,
                                EVP_RAND_CTX *parent)
{
    RAND_DRBG *drbg;
    const char *name = NULL, *alg_pname, *alg_name;
    unsigned int reseed_int = slave_reseed_interval;
    unsigned int reseed_time_int = slave_reseed_time_interval;
    OSSL_PARAM params[3], *p = params;
    unsigned int strength, parent_strength;

    if (!get_drbg_params(type, flags, &name, &alg_pname, &alg_name)) {
        RANDerr(0, RAND_R_UNSUPPORTED_DRBG_TYPE);
        return 0;
    }
    drbg = OPENSSL_zalloc(sizeof(*drbg));
    if (drbg == NULL) {
        RANDerr(0, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (name == NULL)
        return drbg;

    if (parent == NULL) {
        reseed_int = master_reseed_interval;
        reseed_time_int = master_reseed_time_interval;
    }
    drbg->secure = secure ? 1 : 0;
    drbg->flags = flags;
    drbg->type = type;
    if (!rand_drbg_create_drbg(drbg, name, alg_pname, alg_name, secure,
                               (flags & RAND_DRBG_FLAG_CTR_NO_DF) ? 0 : 1,
                               parent))
        goto err;

    strength = EVP_RAND_CTX_strength(drbg->rand);
    parent_strength = EVP_RAND_CTX_strength(parent);
    if (parent != NULL && strength > parent_strength) {
        /*
         * We currently don't support the algorithm from NIST SP 800-90C
         * 10.1.2 to use a weaker DRBG as source
         */
        RANDerr(RAND_F_RAND_DRBG_NEW, RAND_R_PARENT_STRENGTH_TOO_WEAK);
        goto err;
    }
    *p++ = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_RESEED_REQUESTS,
                                     &reseed_int);
    *p++ = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_RESEED_TIME_INTERVAL,
                                     &reseed_time_int);
    *p = OSSL_PARAM_construct_end();
    if (!EVP_RAND_CTX_set_params(drbg->rand, params)) {
        RANDerr(0, RAND_R_ERROR_INITIALISING_DRBG);
        goto err;
    }
    return drbg;
err:
    RAND_DRBG_free(drbg);
    return NULL;
#if 0
    RAND_DRBG *drbg = secure ? OPENSSL_secure_zalloc(sizeof(*drbg))
                             : OPENSSL_zalloc(sizeof(*drbg));

    if (drbg == NULL) {
        RANDerr(RAND_F_RAND_DRBG_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    drbg->libctx = ctx;
    drbg->secure = secure && CRYPTO_secure_allocated(drbg);
    drbg->fork_id = openssl_get_fork_id();

    if (parent == NULL) {
#ifdef FIPS_MODE
        drbg->get_entropy = rand_crngt_get_entropy;
        drbg->cleanup_entropy = rand_crngt_cleanup_entropy;
#else
        drbg->get_entropy = rand_drbg_get_entropy;
        drbg->cleanup_entropy = rand_drbg_cleanup_entropy;
#endif
#ifndef RAND_DRBG_GET_RANDOM_NONCE
        drbg->get_nonce = rand_drbg_get_nonce;
        drbg->cleanup_nonce = rand_drbg_cleanup_nonce;
#endif

        drbg->reseed_interval = master_reseed_interval;
        drbg->reseed_time_interval = master_reseed_time_interval;
    } else {
        drbg->get_entropy = rand_drbg_get_entropy;
        drbg->cleanup_entropy = rand_drbg_cleanup_entropy;
        /*
         * Do not provide nonce callbacks, the child DRBGs will
         * obtain their nonce using random bits from the parent.
         */

        drbg->reseed_interval = slave_reseed_interval;
        drbg->reseed_time_interval = slave_reseed_time_interval;
    }

    if (RAND_DRBG_set(drbg, type, flags) == 0)
        goto err;
    return drbg;
#endif
}

static RAND_DRBG *rand_drbg_new_trampoline(OPENSSL_CTX *ctx,
                                          int secure,
                                          int type,
                                          unsigned int flags,
                                          RAND_DRBG *parent)
{
    return rand_drbg_new(ctx, secure, type, flags,
                         rand_drbg_evp_ctx(parent));
}

RAND_DRBG *RAND_DRBG_new_ex(OPENSSL_CTX *ctx, int type, unsigned int flags,
                            RAND_DRBG *parent)
{
    return rand_drbg_new_trampoline(ctx, 0, type, flags, parent);
}

RAND_DRBG *RAND_DRBG_new(int type, unsigned int flags, RAND_DRBG *parent)
{
    return RAND_DRBG_new_ex(NULL, type, flags, parent);
}

RAND_DRBG *RAND_DRBG_secure_new_ex(OPENSSL_CTX *ctx, int type,
                                   unsigned int flags, RAND_DRBG *parent)
{
    return rand_drbg_new_trampoline(ctx, 1, type, flags, parent);
}

RAND_DRBG *RAND_DRBG_secure_new(int type, unsigned int flags, RAND_DRBG *parent)
{
    return RAND_DRBG_secure_new_ex(NULL, type, flags, parent);
}
/*
 * Uninstantiate |drbg| and free all memory.
 */
void RAND_DRBG_free(RAND_DRBG *drbg)
{
    if (drbg == NULL)
        return;

    EVP_RAND_CTX_free(drbg->rand);
    OPENSSL_free(drbg);
    /*
    if (drbg->meth != NULL)
        drbg->meth->uninstantiate(drbg);
    rand_pool_free(drbg->adin_pool);
    CRYPTO_THREAD_lock_free(drbg->lock);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RAND_DRBG, drbg, &drbg->ex_data);

    if (drbg->secure)
        OPENSSL_secure_clear_free(drbg, sizeof(*drbg));
    else
        OPENSSL_clear_free(drbg, sizeof(*drbg));
    */
}

/*
 * Instantiate |drbg|, after it has been initialized.  Use |pers| and
 * |perslen| as prediction-resistance input.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_instantiate(RAND_DRBG *drbg,
                          const unsigned char *pers, size_t perslen)
{
    return EVP_RAND_CTX_instantiate(drbg->rand, pers, perslen);
}

/*
 * Uninstantiate |drbg|. Must be instantiated before it can be used.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_uninstantiate(RAND_DRBG *drbg)
{
    int index = -1, type;
    unsigned int flags;

    if (!EVP_RAND_CTX_uninstantiate(drbg->rand))
        return 0;

    /* The reset uses the default values for type and flags */
    if (drbg->flags & RAND_DRBG_FLAG_MASTER)
        index = RAND_DRBG_TYPE_MASTER;
    else if (drbg->flags & RAND_DRBG_FLAG_PRIVATE)
        index = RAND_DRBG_TYPE_PRIVATE;
    else if (drbg->flags & RAND_DRBG_FLAG_PUBLIC)
        index = RAND_DRBG_TYPE_PUBLIC;

    if (index != -1) {
        flags = rand_drbg_flags[index];
        type = rand_drbg_type[index];
    } else {
        flags = drbg->flags;
        type = drbg->type;
    }
    return RAND_DRBG_set(drbg, type, flags);
}

/*
 * Reseed |drbg|, mixing in the specified data
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_reseed(RAND_DRBG *drbg,
                     const unsigned char *adin, size_t adinlen,
                     int prediction_resistance)
{
    return EVP_RAND_CTX_reseed(drbg->rand, adin, adinlen,
                               prediction_resistance);
}

/*
 * Restart |drbg|, using the specified entropy or additional input
 *
 * Tries its best to get the drbg instantiated by all means,
 * regardless of its current state.
 *
 * Optionally, a |buffer| of |len| random bytes can be passed,
 * which is assumed to contain at least |entropy| bits of entropy.
 *
 * If |entropy| > 0, the buffer content is used as entropy input.
 *
 * If |entropy| == 0, the buffer content is used as additional input
 *
 * Returns 1 on success, 0 on failure.
 *
 * This function is used internally only.
 */
int rand_drbg_restart(RAND_DRBG *drbg,
                      const unsigned char *buffer, size_t len, size_t entropy)
{
    DRBG_STATUS state = evp_rand_ctx_status(drbg->rand);

#if 0
    if (drbg->seed_pool != NULL) {
        RANDerr(RAND_F_RAND_DRBG_RESTART, ERR_R_INTERNAL_ERROR);
        drbg->state = DRBG_ERROR;
        rand_pool_free(drbg->seed_pool);
        drbg->seed_pool = NULL;
        return 0;
    }
    if (buffer != NULL) {
        if (entropy > 0) {
            if (drbg->max_entropylen < len) {
                RANDerr(RAND_F_RAND_DRBG_RESTART,
                    RAND_R_ENTROPY_INPUT_TOO_LONG);
                drbg->state = DRBG_ERROR;
                return 0;
            }

            if (entropy > 8 * len) {
                RANDerr(RAND_F_RAND_DRBG_RESTART, RAND_R_ENTROPY_OUT_OF_RANGE);
                drbg->state = DRBG_ERROR;
                return 0;
            }

            /* will be picked up by the rand_drbg_get_entropy() callback */
            drbg->seed_pool = rand_pool_attach(buffer, len, entropy);
            if (drbg->seed_pool == NULL)
                return 0;
        } else {
            if (drbg->max_adinlen < len) {
                RANDerr(RAND_F_RAND_DRBG_RESTART,
                        RAND_R_ADDITIONAL_INPUT_TOO_LONG);
                drbg->state = DRBG_ERROR;
                return 0;
            }
            adin = buffer;
            adinlen = len;
        }
    }
#endif
    /* repair error state */
    if (state == DRBG_ERROR)
        RAND_DRBG_uninstantiate(drbg);

    /* repair uninitialized state */
    if (state == DRBG_UNINITIALISED) {
        /* reinstantiate drbg */
        RAND_DRBG_instantiate(drbg, NULL, 0);
        /* already reseeded. prevent second reseeding below */
        state = evp_rand_ctx_status(drbg->rand);
#if 0
        reseeded = state == DRBG_READY;
#endif
    }

    /* refresh current state if entropy or additional input has been provided */
    if (state == DRBG_READY) {
#if 0
        if (adin != NULL) {
            /*
             * mix in additional input without reseeding
             *
             * Similar to RAND_DRBG_reseed(), but the provided additional
             * data |adin| is mixed into the current state without pulling
             * entropy from the trusted entropy source using get_entropy().
             * This is not a reseeding in the strict sense of NIST SP 800-90A.
             */
            drbg->meth->reseed(drbg, adin, adinlen, NULL, 0);
        } else if (reseeded == 0) {
            /* do a full reseeding if it has not been done yet above */
            RAND_DRBG_reseed(drbg, NULL, 0, 0);
        }
#endif
        RAND_DRBG_reseed(drbg, NULL, 0, 0);
    }
#if 0
    rand_pool_free(drbg->seed_pool);
    drbg->seed_pool = NULL;
#endif
    return evp_rand_ctx_status(drbg->rand) == DRBG_READY;
}

/*
 * Generate |outlen| bytes into the buffer at |out|.  Reseed if we need
 * to or if |prediction_resistance| is set.  Additional input can be
 * sent in |adin| and |adinlen|.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 *
 */
int RAND_DRBG_generate(RAND_DRBG *drbg, unsigned char *out, size_t outlen,
                       int prediction_resistance,
                       const unsigned char *adin, size_t adinlen)
{
    return EVP_RAND_CTX_generate(drbg->rand, out, outlen, adin, adinlen,
                                 prediction_resistance);
}

/*
 * Generates |outlen| random bytes and stores them in |out|. It will
 * using the given |drbg| to generate the bytes.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success 0 on failure.
 */
int RAND_DRBG_bytes(RAND_DRBG *drbg, unsigned char *out, size_t outlen)
{
    unsigned char *additional = NULL;
    size_t additional_len;
    size_t chunk;
    size_t ret = 0;
    size_t max_request;

    if (drbg->adin_pool == NULL) {
        if (drbg->type == 0)
            goto err;
        drbg->adin_pool = rand_pool_new(0, 0, 0,
                                        evp_rand_ctx_max_adin_length(drbg->rand));
        if (drbg->adin_pool == NULL)
            goto err;
    }

    additional_len = rand_drbg_get_additional_data(drbg->adin_pool,
                                                   &additional);

    max_request = evp_rand_ctx_max_request_length(drbg->rand);
    for ( ; outlen > 0; outlen -= chunk, out += chunk) {
        chunk = outlen;
        if (chunk > max_request)
            chunk = max_request;
        ret = RAND_DRBG_generate(drbg, out, chunk, 0,
                                 additional, additional_len);
        if (!ret)
            goto err;
    }
    ret = 1;

 err:
    if (additional != NULL)
        rand_drbg_cleanup_additional_data(drbg->adin_pool, additional);

    return ret;
}

/*
 * Set the RAND_DRBG callbacks for obtaining entropy and nonce.
 *
 * Setting the callbacks is allowed only if the drbg has not been
 * initialized yet. Otherwise, the operation will fail.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_set_callbacks(RAND_DRBG *drbg,
                            RAND_DRBG_get_entropy_fn get_entropy,
                            RAND_DRBG_cleanup_entropy_fn cleanup_entropy,
                            RAND_DRBG_get_nonce_fn get_nonce,
                            RAND_DRBG_cleanup_nonce_fn cleanup_nonce)
{
    if (evp_rand_ctx_status(drbg->rand) != DRBG_UNINITIALISED
            || evp_rand_ctx_parent(drbg->rand) != NULL)
        return 0;
    drbg->get_entropy = get_entropy;
    drbg->cleanup_entropy = cleanup_entropy;
    drbg->get_nonce = get_nonce;
    drbg->cleanup_nonce = cleanup_nonce;
    return 1;
}

/*
 * Set the reseed interval.
 *
 * The drbg will reseed automatically whenever the number of generate
 * requests exceeds the given reseed interval. If the reseed interval
 * is 0, then this feature is disabled.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_set_reseed_interval(RAND_DRBG *drbg, unsigned int interval)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    if (interval > MAX_RESEED_INTERVAL)
        return 0;
    params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_RESEED_REQUESTS,
                                          &interval);
    return EVP_RAND_CTX_set_params(drbg->rand, params);
}

/*
 * Set the reseed time interval.
 *
 * The drbg will reseed automatically whenever the time elapsed since
 * the last reseeding exceeds the given reseed time interval. For safety,
 * a reseeding will also occur if the clock has been reset to a smaller
 * value.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_set_reseed_time_interval(RAND_DRBG *drbg, time_t interval)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    unsigned int i;

    if (interval > MAX_RESEED_TIME_INTERVAL || interval < 0)
        return 0;

    i = (unsigned int)interval;
    params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_RESEED_TIME_INTERVAL,
                                          &i);
    return EVP_RAND_CTX_set_params(drbg->rand, params);
}

/*
 * Set the default values for reseed (time) intervals of new DRBG instances
 *
 * The default values can be set independently for master DRBG instances
 * (without a parent) and slave DRBG instances (with parent).
 *
 * Returns 1 on success, 0 on failure.
 */

int RAND_DRBG_set_reseed_defaults(
                                  unsigned int _master_reseed_interval,
                                  unsigned int _slave_reseed_interval,
                                  time_t _master_reseed_time_interval,
                                  time_t _slave_reseed_time_interval
                                  )
{
    if (_master_reseed_interval > MAX_RESEED_INTERVAL
        || _slave_reseed_interval > MAX_RESEED_INTERVAL)
        return 0;

    if (_master_reseed_time_interval > MAX_RESEED_TIME_INTERVAL
        || _slave_reseed_time_interval > MAX_RESEED_TIME_INTERVAL)
        return 0;

    master_reseed_interval = _master_reseed_interval;
    slave_reseed_interval = _slave_reseed_interval;

    master_reseed_time_interval = _master_reseed_time_interval;
    slave_reseed_time_interval = _slave_reseed_time_interval;

    return 1;
}

#if 0
/*
 * Enables locking for the given drbg
 *
 * Locking can only be enabled if the random generator
 * is in the uninitialized state.
 *
 * Returns 1 on success, 0 on failure.
 */
int rand_drbg_enable_locking(RAND_DRBG *drbg)
{
    return EVP_RAND_CTX_enable_locking(drbg->rand);
    if (drbg->state != DRBG_UNINITIALISED) {
        RANDerr(RAND_F_RAND_DRBG_ENABLE_LOCKING,
                RAND_R_DRBG_ALREADY_INITIALIZED);
        return 0;
    }
    return 1;
}
#endif

/*
 * Get and set the EXDATA
 */
int RAND_DRBG_set_ex_data(RAND_DRBG *drbg, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&drbg->ex_data, idx, arg);
}

void *RAND_DRBG_get_ex_data(const RAND_DRBG *drbg, int idx)
{
    return CRYPTO_get_ex_data(&drbg->ex_data, idx);
}


/*
 * The following functions provide a RAND_METHOD that works on the
 * global DRBG.  They lock.
 */

/*
 * Allocates a new global DRBG on the secure heap (if enabled) and
 * initializes it with default settings.
 *
 * Returns a pointer to the new DRBG instance on success, NULL on failure.
 */
static RAND_DRBG *drbg_setup(OPENSSL_CTX *ctx, EVP_RAND_CTX *parent,
                             int drbg_type)
{
    RAND_DRBG *drbg;

    drbg = rand_drbg_new(ctx, 1, rand_drbg_type[drbg_type],
                         rand_drbg_flags[drbg_type], parent);
    if (drbg == NULL)
        return NULL;
#if 0
    /* Only the master DRBG needs to have a lock */
    if (parent == NULL && rand_drbg_enable_locking(drbg) == 0)
        goto err;

    /* enable seed propagation */
    tsan_store(&drbg->reseed_prop_counter, 1);
#endif

    /*
     * Ignore instantiation error to support just-in-time instantiation.
     *
     * The state of the drbg will be checked in RAND_DRBG_generate() and
     * an automatic recovery is attempted.
     */
    (void)RAND_DRBG_instantiate(drbg, NULL, 0);
    return drbg;
}

static void drbg_delete_thread_state(void *arg)
{
    OPENSSL_CTX *ctx = arg;
    DRBG_GLOBAL *dgbl = drbg_get_global(ctx);
    RAND_DRBG *drbg;

    if (dgbl == NULL)
        return;
    drbg = CRYPTO_THREAD_get_local(&dgbl->public_drbg);
    CRYPTO_THREAD_set_local(&dgbl->public_drbg, NULL);
    RAND_DRBG_free(drbg);

    drbg = CRYPTO_THREAD_get_local(&dgbl->private_drbg);
    CRYPTO_THREAD_set_local(&dgbl->private_drbg, NULL);
    RAND_DRBG_free(drbg);
}

/* Implements the default OpenSSL RAND_bytes() method */
static int drbg_bytes(unsigned char *out, int count)
{
    int ret;
    RAND_DRBG *drbg = RAND_DRBG_get0_public();

    if (drbg == NULL)
        return 0;

    ret = RAND_DRBG_bytes(drbg, out, count);

    return ret;
}

/*
 * Calculates the minimum length of a full entropy buffer
 * which is necessary to seed (i.e. instantiate) the DRBG
 * successfully.
 */
size_t rand_drbg_seedlen(RAND_DRBG *drbg)
{
    return evp_rand_seedlen(drbg->rand);
}

/* Implements the default OpenSSL RAND_add() method */
static int drbg_add(const void *buf, int num, double randomness)
{
    RAND_DRBG *drbg = RAND_DRBG_get0_master();

    if (drbg == NULL)
        return 0;
    return EVP_RAND_CTX_seed(drbg->rand, buf, num, randomness);
}

/* Implements the default OpenSSL RAND_seed() method */
static int drbg_seed(const void *buf, int num)
{
    return drbg_add(buf, num, num);
}

/* Implements the default OpenSSL RAND_status() method */
static int drbg_status(void)
{
    int ret;
    RAND_DRBG *drbg = RAND_DRBG_get0_master();

    if (drbg == NULL)
        return 0;

    ret = evp_rand_ctx_status(drbg->rand) == DRBG_READY ? 1 : 0;
    return ret;
}

/*
 * Get the master DRBG.
 * Returns pointer to the DRBG on success, NULL on failure.
 *
 */
RAND_DRBG *OPENSSL_CTX_get0_master_drbg(OPENSSL_CTX *ctx)
{
    DRBG_GLOBAL *dgbl = drbg_get_global(ctx);

    if (dgbl == NULL)
        return NULL;

    return dgbl->master_drbg;
}

RAND_DRBG *RAND_DRBG_get0_master(void)
{
    return OPENSSL_CTX_get0_master_drbg(NULL);
}

/*
 * Get the public DRBG.
 * Returns pointer to the DRBG on success, NULL on failure.
 */
RAND_DRBG *OPENSSL_CTX_get0_public_drbg(OPENSSL_CTX *ctx)
{
    DRBG_GLOBAL *dgbl = drbg_get_global(ctx);
    RAND_DRBG *drbg;

    if (dgbl == NULL)
        return NULL;

    drbg = CRYPTO_THREAD_get_local(&dgbl->public_drbg);
    if (drbg == NULL) {
        ctx = openssl_ctx_get_concrete(ctx);
        if (!ossl_init_thread_start(NULL, ctx, drbg_delete_thread_state))
            return NULL;
        drbg = drbg_setup(ctx, dgbl->master_drbg->rand, RAND_DRBG_TYPE_PUBLIC);
        CRYPTO_THREAD_set_local(&dgbl->public_drbg, drbg);
    }
    return drbg;
}

RAND_DRBG *RAND_DRBG_get0_public(void)
{
    return OPENSSL_CTX_get0_public_drbg(NULL);
}

/*
 * Get the private DRBG.
 * Returns pointer to the DRBG on success, NULL on failure.
 */
RAND_DRBG *OPENSSL_CTX_get0_private_drbg(OPENSSL_CTX *ctx)
{
    DRBG_GLOBAL *dgbl = drbg_get_global(ctx);
    RAND_DRBG *drbg;

    if (dgbl == NULL)
        return NULL;

    drbg = CRYPTO_THREAD_get_local(&dgbl->private_drbg);
    if (drbg == NULL) {
        ctx = openssl_ctx_get_concrete(ctx);
        if (!ossl_init_thread_start(NULL, ctx, drbg_delete_thread_state))
            return NULL;
        drbg = drbg_setup(ctx, dgbl->master_drbg->rand, RAND_DRBG_TYPE_PRIVATE);
        CRYPTO_THREAD_set_local(&dgbl->private_drbg, drbg);
    }
    return drbg;
}

RAND_DRBG *RAND_DRBG_get0_private(void)
{
    return OPENSSL_CTX_get0_private_drbg(NULL);
}

RAND_METHOD rand_meth = {
    drbg_seed,
    drbg_bytes,
    NULL,
    drbg_add,
    drbg_bytes,
    drbg_status
};

RAND_METHOD *RAND_OpenSSL(void)
{
#ifndef FIPS_MODE
    return &rand_meth;
#else
    return NULL;
#endif
}
