/*
 * Copyright 2011-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * RAND_DRBG_set is deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include "rand_local.h"
#include "internal/thread_once.h"
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
     * There are three shared DRBG instances: <primary>, <public>, and
     * <private>.  The <public> and <private> DRBGs are secondary ones.
     * These are used for non-secret (e.g. nonces) and secret
     * (e.g. private keys) data respectively.
     */
    CRYPTO_RWLOCK *lock;

    /*
     * The <primary> DRBG
     *
     * Not used directly by the application, only for reseeding the two other
     * DRBGs. It reseeds itself by pulling either randomness from os entropy
     * sources or by consuming randomness which was added by RAND_add().
     *
     * The <primary> DRBG is a global instance which is accessed concurrently by
     * all threads. The necessary locking is managed automatically by its child
     * DRBG instances during reseeding.
     */
    RAND_DRBG *primary_drbg;
    /*
     * The <public> DRBG
     *
     * Used by default for generating random bytes using RAND_bytes().
     *
     * The <public> secondary DRBG is thread-local, i.e., there is one instance
     * per thread.
     */
    CRYPTO_THREAD_LOCAL public_drbg;
    /*
     * The <private> DRBG
     *
     * Used by default for generating private keys using RAND_priv_bytes()
     *
     * The <private> secondary DRBG is thread-local, i.e., there is one
     * instance per thread.
     */
    CRYPTO_THREAD_LOCAL private_drbg;
} DRBG_GLOBAL;

#define RAND_DRBG_TYPE_FLAGS    ( \
    RAND_DRBG_FLAG_PRIMARY | RAND_DRBG_FLAG_PUBLIC | RAND_DRBG_FLAG_PRIVATE )

#define RAND_DRBG_TYPE_PRIMARY                    0
#define RAND_DRBG_TYPE_PUBLIC                     1
#define RAND_DRBG_TYPE_PRIVATE                    2

/* Defaults */
static int rand_drbg_type[3] = {
    RAND_DRBG_TYPE, /* Primary */
    RAND_DRBG_TYPE, /* Public */
    RAND_DRBG_TYPE  /* Private */
};
static unsigned int rand_drbg_flags[3] = {
    RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PRIMARY, /* Primary */
    RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PUBLIC,  /* Public */
    RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PRIVATE  /* Private */
};

static unsigned int primary_reseed_interval = PRIMARY_RESEED_INTERVAL;
static unsigned int secondary_reseed_interval = SECONDARY_RESEED_INTERVAL;

static time_t primary_reseed_time_interval = PRIMARY_RESEED_TIME_INTERVAL;
static time_t secondary_reseed_time_interval = SECONDARY_RESEED_TIME_INTERVAL;

/* A logical OR of all used DRBG flag bits (currently there is only one) */
static const unsigned int rand_drbg_used_flags =
    RAND_DRBG_FLAG_CTR_NO_DF | RAND_DRBG_FLAG_HMAC | RAND_DRBG_TYPE_FLAGS;


static RAND_DRBG *drbg_setup(OPENSSL_CTX *ctx, RAND_DRBG *parent,
                             int drbg_type);

static int get_drbg_params(int type, unsigned int flags, const char **name,
                           OSSL_PARAM params[3])
{
    OSSL_PARAM *p = params;

    switch (type) {
    case 0:
        return 1;
    default:
        return 0;

#define CTR(v)                                                              \
    *name = "CTR-DRBG";                                                     \
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, v, 0)

    case NID_aes_128_ctr:
        CTR(SN_aes_128_ctr);
        break;
    case NID_aes_192_ctr:
        CTR(SN_aes_192_ctr);
        break;
    case NID_aes_256_ctr:
        CTR(SN_aes_256_ctr);
        break;

#define DGST(v)                                                             \
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, v, 0);  \
    if ((flags & RAND_DRBG_FLAG_HMAC) == 0) {                               \
        *name = "HASH-DRBG";                                                \
    } else {                                                                \
        *name = "HMAC-DRBG";                                                \
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC,        \
                                                SN_hmac, 0);                \
    }

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
    }
    *p = OSSL_PARAM_construct_end();
    return 1;
}

/*
 * Initialize the OPENSSL_CTX global DRBGs on first use.
 * Returns the allocated global data on success or NULL on failure.
 */
static void *drbg_ossl_ctx_new(OPENSSL_CTX *libctx)
{
    DRBG_GLOBAL *dgbl = OPENSSL_zalloc(sizeof(*dgbl));

    if (dgbl == NULL)
        return NULL;

#ifndef FIPS_MODULE
    /*
     * We need to ensure that base libcrypto thread handling has been
     * initialised.
     */
     OPENSSL_init_crypto(0, NULL);
#endif

    dgbl->lock = CRYPTO_THREAD_lock_new();
    if (dgbl->lock == NULL)
        goto err0;

    if (!CRYPTO_THREAD_init_local(&dgbl->private_drbg, NULL))
        goto err1;

    if (!CRYPTO_THREAD_init_local(&dgbl->public_drbg, NULL))
        goto err2;

    return dgbl;

 err2:
    CRYPTO_THREAD_cleanup_local(&dgbl->private_drbg);
 err1:
    CRYPTO_THREAD_lock_free(dgbl->lock);
 err0:
    OPENSSL_free(dgbl);
    return NULL;
}

static void drbg_ossl_ctx_free(void *vdgbl)
{
    DRBG_GLOBAL *dgbl = vdgbl;

    if (dgbl == NULL)
        return;

    CRYPTO_THREAD_lock_free(dgbl->lock);
    RAND_DRBG_free(dgbl->primary_drbg);
    CRYPTO_THREAD_cleanup_local(&dgbl->private_drbg);
    CRYPTO_THREAD_cleanup_local(&dgbl->public_drbg);

    OPENSSL_free(dgbl);
}

static const OPENSSL_CTX_METHOD drbg_ossl_ctx_method = {
    drbg_ossl_ctx_new,
    drbg_ossl_ctx_free,
};

static DRBG_GLOBAL *drbg_get_global(OPENSSL_CTX *libctx)
{
    return openssl_ctx_get_data(libctx, OPENSSL_CTX_DRBG_INDEX,
                                &drbg_ossl_ctx_method);
}

/*
 * Set the |drbg|'s callback data pointer for the entropy and nonce callbacks
 *
 * The ownership of the context data remains with the caller,
 * i.e., it is the caller's responsibility to keep it available as long
 * as it is need by the callbacks and free it after use.
 *
 * Setting the callback data is allowed only if the drbg has not been
 * initialized yet. Otherwise, the operation will fail.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_set_callback_data(RAND_DRBG *drbg, void *data)
{
    if (EVP_RAND_state(drbg->rand) != EVP_RAND_STATE_UNINITIALISED
            || drbg->parent != NULL)
        return 0;

    drbg->callback_data = data;
    return 1;
}

/* Retrieve the callback data pointer */
void *RAND_DRBG_get_callback_data(RAND_DRBG *drbg)
{
    return drbg->callback_data;
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
    OSSL_PARAM params[6], *p = params;
    unsigned int reseed_interval;
    time_t reseed_time_interval;
    const char *name = NULL;
    EVP_RAND *rand;
    EVP_RAND_CTX *pctx;
    int use_df;

    RAND_DRBG_get_entropy_fn get_entropy = drbg->get_entropy;
    RAND_DRBG_cleanup_entropy_fn cleanup_entropy = drbg->cleanup_entropy;
    RAND_DRBG_get_nonce_fn get_nonce = drbg->get_nonce;
    RAND_DRBG_cleanup_nonce_fn cleanup_nonce = drbg->cleanup_nonce;

    if (type == 0 && flags == 0) {
        type = rand_drbg_type[RAND_DRBG_TYPE_PRIMARY];
        flags = rand_drbg_flags[RAND_DRBG_TYPE_PRIMARY];
    }

    if (drbg->parent == NULL) {
        reseed_interval = primary_reseed_interval;
        reseed_time_interval = primary_reseed_time_interval;
    } else {
        reseed_interval = secondary_reseed_interval;
        reseed_time_interval = secondary_reseed_time_interval;
    }
    *p++ = OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS,
                                     &reseed_interval);
    *p++ = OSSL_PARAM_construct_time_t(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL,
                                       &reseed_time_interval);
    use_df = (flags & RAND_DRBG_FLAG_CTR_NO_DF) == 0;
    *p++ = OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_USE_DF, &use_df);

    if (!get_drbg_params(type, flags, &name, p)) {
        RANDerr(0, RAND_R_UNSUPPORTED_DRBG_TYPE);
        return 0;
    }

    rand = EVP_RAND_fetch(drbg->libctx, name, NULL);
    if (rand == NULL) {
        RANDerr(0, RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED);
        return 0;
    }

    EVP_RAND_CTX_free(drbg->rand);
    drbg->rand = NULL;

    drbg->flags = flags;
    drbg->type = type;

    pctx = drbg->parent != NULL ? drbg->parent->rand : NULL;
    drbg->rand = EVP_RAND_CTX_new(rand, pctx);
    EVP_RAND_free(rand);
    if (drbg->rand == NULL) {
        RANDerr(0, RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED);
        goto err;
    }

    if (!EVP_RAND_set_ctx_params(drbg->rand, params)) {
        RANDerr(0, RAND_R_ERROR_INITIALISING_DRBG);
        goto err;
    }

    if (!RAND_DRBG_set_callbacks(drbg,
                                 get_entropy, cleanup_entropy,
                                 get_nonce, cleanup_nonce)) {
        RANDerr(0, RAND_R_ERROR_INITIALISING_DRBG);
        goto err;
    }

    return 1;
err:
    EVP_RAND_CTX_free(drbg->rand);
    drbg->rand = NULL;
    drbg->type = 0;
    drbg->flags = 0;
    return 0;
}

/*
 * Set/initialize default |type| and |flag| for new drbg instances.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_set_defaults(int type, unsigned int flags)
{
    int all;
    const char *name;
    OSSL_PARAM params[3];

    if (!get_drbg_params(type, flags, &name, params)) {
        RANDerr(RAND_F_RAND_DRBG_SET_DEFAULTS, RAND_R_UNSUPPORTED_DRBG_TYPE);
        return 0;
    }

    if ((flags & ~rand_drbg_used_flags) != 0) {
        RANDerr(RAND_F_RAND_DRBG_SET_DEFAULTS, RAND_R_UNSUPPORTED_DRBG_FLAGS);
        return 0;
    }

    all = ((flags & RAND_DRBG_TYPE_FLAGS) == 0);
    if (all || (flags & RAND_DRBG_FLAG_PRIMARY) != 0) {
        rand_drbg_type[RAND_DRBG_TYPE_PRIMARY] = type;
        rand_drbg_flags[RAND_DRBG_TYPE_PRIMARY] = flags
                                                  | RAND_DRBG_FLAG_PRIMARY;
    }
    if (all || (flags & RAND_DRBG_FLAG_PUBLIC) != 0) {
        rand_drbg_type[RAND_DRBG_TYPE_PUBLIC]  = type;
        rand_drbg_flags[RAND_DRBG_TYPE_PUBLIC] = flags | RAND_DRBG_FLAG_PUBLIC;
    }
    if (all || (flags & RAND_DRBG_FLAG_PRIVATE) != 0) {
        rand_drbg_type[RAND_DRBG_TYPE_PRIVATE] = type;
        rand_drbg_flags[RAND_DRBG_TYPE_PRIVATE] = flags
                                                  | RAND_DRBG_FLAG_PRIVATE;
    }
    return 1;
}


/*
 * Allocate memory and initialize a new DRBG.
 * The |parent|, if not NULL, will be used as random source for reseeding.
 *
 * Returns a pointer to the new DRBG instance on success, NULL on failure.
 */
static RAND_DRBG *rand_drbg_new(OPENSSL_CTX *ctx,
                                int type,
                                unsigned int flags,
                                RAND_DRBG *parent)
{
    RAND_DRBG *drbg = OPENSSL_zalloc(sizeof(*drbg));

    if (drbg == NULL) {
        RANDerr(RAND_F_RAND_DRBG_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    drbg->libctx = ctx;
    drbg->parent = parent;

    if (RAND_DRBG_set(drbg, type, flags) == 0)
        goto err;

    return drbg;

 err:
    RAND_DRBG_free(drbg);

    return NULL;
}

RAND_DRBG *RAND_DRBG_new_ex(OPENSSL_CTX *ctx, int type, unsigned int flags,
                            RAND_DRBG *parent)
{
    return rand_drbg_new(ctx, type, flags, parent);
}

RAND_DRBG *RAND_DRBG_new(int type, unsigned int flags, RAND_DRBG *parent)
{
    return RAND_DRBG_new_ex(NULL, type, flags, parent);
}

/*
 * Uninstantiate |drbg| and free all memory.
 */
void RAND_DRBG_free(RAND_DRBG *drbg)
{
    if (drbg == NULL)
        return;

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RAND_DRBG, drbg, &drbg->ex_data);
    EVP_RAND_CTX_free(drbg->rand);
    OPENSSL_free(drbg);
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
    return EVP_RAND_instantiate(drbg->rand, EVP_RAND_strength(drbg->rand), 0,
                                pers, perslen);
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
    int index = -1, type, flags;

    if (!EVP_RAND_uninstantiate(drbg->rand))
        return 0;

    /* The reset uses the default values for type and flags */
    if (drbg->flags & RAND_DRBG_FLAG_PRIMARY)
        index = RAND_DRBG_TYPE_PRIMARY;
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
    return EVP_RAND_reseed(drbg->rand, prediction_resistance, NULL, 0,
                           adin, adinlen);
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
    return EVP_RAND_generate(drbg->rand, out, outlen, 0,
                             prediction_resistance, adin, adinlen);
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
    return EVP_RAND_generate(drbg->rand, out, outlen, 0, 0, NULL, 0);
}

/* DRBG call back shims */
static int rand_drbg_get_entroy_cb(const OSSL_PARAM *params, OSSL_PARAM *out,
                                   void *vdrbg)
{
    RAND_DRBG *drbg = (RAND_DRBG *)vdrbg;
    int entropy = 0, prediction_resistance = 0;
    size_t min_len = 0, max_len = 2048;
    const OSSL_PARAM *p;
    OSSL_PARAM *q;

    if (drbg->get_entropy == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_ENTROPY_REQUIRED);
    if (p == NULL || !OSSL_PARAM_get_int(p, &entropy))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_PREDICTION_RESISTANCE);
    if (p == NULL || !OSSL_PARAM_get_int(p, &prediction_resistance))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAX_LENGTH);
    if (p == NULL || !OSSL_PARAM_get_size_t(p, &max_len))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MIN_LENGTH);
    if (p == NULL || !OSSL_PARAM_get_size_t(p, &min_len))
        return 0;

    q = OSSL_PARAM_locate(out, OSSL_DRBG_PARAM_RANDOM_DATA);
    if (q == NULL || q->data_type != OSSL_PARAM_OCTET_PTR || q->data == NULL)
        return 0;

    q->return_size = drbg->get_entropy(drbg, (unsigned char **)q->data, entropy,
                                       min_len, max_len, prediction_resistance);
    return 1;
}

static int rand_drbg_cleanup_entropy_cb(const OSSL_PARAM *params, void *vdrbg)
{
    RAND_DRBG *drbg = (RAND_DRBG *)vdrbg;
    const OSSL_PARAM *p;
    size_t sz;

    if (drbg->cleanup_entropy == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_SIZE);
    if (p == NULL || !OSSL_PARAM_get_size_t(p, &sz))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RANDOM_DATA);
    if (p == NULL || p->data_type != OSSL_PARAM_OCTET_PTR)
        return 0;

    drbg->cleanup_entropy(drbg, p->data, sz);
    return 1;
}

static int rand_drbg_get_nonce_cb(const OSSL_PARAM *params, OSSL_PARAM *out,
                                  void *vdrbg)
{
    RAND_DRBG *drbg = (RAND_DRBG *)vdrbg;
    int entropy = 0;
    size_t min_len = 0, max_len = 10240;
    const OSSL_PARAM *p;
    OSSL_PARAM *q;

    if (drbg->get_nonce == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_ENTROPY_REQUIRED);
    if (p == NULL || !OSSL_PARAM_get_int(p, &entropy))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MAX_LENGTH);
    if (p == NULL || !OSSL_PARAM_get_size_t(p, &max_len))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_MIN_LENGTH);
    if (p == NULL || !OSSL_PARAM_get_size_t(p, &min_len))
        return 0;

    q = OSSL_PARAM_locate(out, OSSL_DRBG_PARAM_RANDOM_DATA);
    if (q == NULL || q->data_type != OSSL_PARAM_OCTET_PTR || q->data == NULL)
        return 0;

    q->return_size = drbg->get_nonce(drbg, (unsigned char **)q->data, entropy,
                                     min_len, max_len);
    return 1;
}

static int rand_drbg_cleanup_nonce_cb(const OSSL_PARAM *params, void *vdrbg)
{
    RAND_DRBG *drbg = (RAND_DRBG *)vdrbg;
    const OSSL_PARAM *p;
    size_t sz;

    if (drbg->cleanup_nonce == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_SIZE);
    if (p == NULL || !OSSL_PARAM_get_size_t(p, &sz))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_RANDOM_DATA);
    if (p == NULL || p->data_type != OSSL_PARAM_OCTET_PTR)
        return 0;

    drbg->cleanup_nonce(drbg, p->data, sz);
    return 1;
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
    EVP_RAND_CTX *rand = drbg->rand;
    OSSL_INOUT_CALLBACK *g_ent = NULL, *g_nonce = NULL;
    OSSL_CALLBACK *c_ent = NULL, *c_nonce = NULL;

    if (get_entropy != NULL) {
        g_ent = &rand_drbg_get_entroy_cb;
        c_ent = &rand_drbg_cleanup_entropy_cb;
    }
    if (get_nonce != NULL) {
        g_nonce = rand_drbg_get_nonce_cb;
        c_nonce = rand_drbg_cleanup_nonce_cb;
    }
    if (!EVP_RAND_set_callbacks(rand, g_ent, c_ent, g_nonce, c_nonce, drbg))
        return 0;

    drbg->get_entropy = g_ent != NULL ? get_entropy : NULL;
    drbg->cleanup_entropy = c_ent != NULL ? cleanup_entropy : NULL;
    drbg->get_nonce = g_nonce != NULL ? get_nonce : NULL;
    drbg->cleanup_nonce = c_nonce != NULL ? cleanup_nonce : NULL;
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
    params[0] = OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS,
                                          &interval);
    return EVP_RAND_set_ctx_params(drbg->rand, params);
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

    if (interval > MAX_RESEED_TIME_INTERVAL)
        return 0;
    params[0] =
        OSSL_PARAM_construct_time_t(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL,
                                    &interval);
    return EVP_RAND_set_ctx_params(drbg->rand, params);
}

/*
 * Set the default values for reseed (time) intervals of new DRBG instances
 *
 * The default values can be set independently for primary DRBG instances
 * (without a parent) and secondary DRBG instances (with parent).
 *
 * Returns 1 on success, 0 on failure.
 */

int RAND_DRBG_set_reseed_defaults(
                                  unsigned int _primary_reseed_interval,
                                  unsigned int _secondary_reseed_interval,
                                  time_t _primary_reseed_time_interval,
                                  time_t _secondary_reseed_time_interval
                                  )
{
    if (_primary_reseed_interval > MAX_RESEED_INTERVAL
        || _secondary_reseed_interval > MAX_RESEED_INTERVAL)
        return 0;

    if (_primary_reseed_time_interval > MAX_RESEED_TIME_INTERVAL
        || _secondary_reseed_time_interval > MAX_RESEED_TIME_INTERVAL)
        return 0;

    primary_reseed_interval = _primary_reseed_interval;
    secondary_reseed_interval = _secondary_reseed_interval;

    primary_reseed_time_interval = _primary_reseed_time_interval;
    secondary_reseed_time_interval = _secondary_reseed_time_interval;

    return 1;
}

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
static RAND_DRBG *drbg_setup(OPENSSL_CTX *ctx, RAND_DRBG *parent, int drbg_type)
{
    RAND_DRBG *drbg;

    drbg = RAND_DRBG_new_ex(ctx, rand_drbg_type[drbg_type],
                            rand_drbg_flags[drbg_type], parent);
    if (drbg == NULL)
        return NULL;

    /* Only the primary DRBG needs to have a lock */
    if (parent == NULL && EVP_RAND_enable_locking(drbg->rand) == 0)
        goto err;

    /*
     * Ignore instantiation error to support just-in-time instantiation.
     *
     * The state of the drbg will be checked in RAND_DRBG_generate() and
     * an automatic recovery is attempted.
     */
    (void)RAND_DRBG_instantiate(drbg, NULL, 0);
    return drbg;

err:
    RAND_DRBG_free(drbg);
    return NULL;
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

/* Implements the default OpenSSL RAND_add() method */
static int drbg_add(const void *buf, int num, double randomness)
{
    RAND_DRBG *drbg = RAND_DRBG_get0_master();

    if (drbg == NULL || num <= 0)
        return 0;

    return EVP_RAND_reseed(drbg->rand, 0, NULL, 0, buf, num);
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

    ret = EVP_RAND_state(drbg->rand) == EVP_RAND_STATE_READY ? 1 : 0;
    return ret;
}

int RAND_DRBG_verify_zeroization(RAND_DRBG *drbg)
{
    return EVP_RAND_verify_zeroization(drbg->rand);
}

/*
 * Get the primary DRBG.
 * Returns pointer to the DRBG on success, NULL on failure.
 *
 */
RAND_DRBG *OPENSSL_CTX_get0_primary_drbg(OPENSSL_CTX *ctx)
{
    DRBG_GLOBAL *dgbl = drbg_get_global(ctx);

    if (dgbl == NULL)
        return NULL;

    if (dgbl->primary_drbg == NULL) {
        if (!CRYPTO_THREAD_write_lock(dgbl->lock))
            return NULL;
        if (dgbl->primary_drbg == NULL)
            dgbl->primary_drbg = drbg_setup(ctx, NULL, RAND_DRBG_TYPE_PRIMARY);
        CRYPTO_THREAD_unlock(dgbl->lock);
    }
    return dgbl->primary_drbg;
}

RAND_DRBG *RAND_DRBG_get0_master(void)
{
    return OPENSSL_CTX_get0_primary_drbg(NULL);
}

/*
 * Get the public DRBG.
 * Returns pointer to the DRBG on success, NULL on failure.
 */
RAND_DRBG *OPENSSL_CTX_get0_public_drbg(OPENSSL_CTX *ctx)
{
    DRBG_GLOBAL *dgbl = drbg_get_global(ctx);
    RAND_DRBG *drbg, *primary;

    if (dgbl == NULL)
        return NULL;

    drbg = CRYPTO_THREAD_get_local(&dgbl->public_drbg);
    if (drbg == NULL) {
        primary = OPENSSL_CTX_get0_primary_drbg(ctx);
        if (primary == NULL)
            return NULL;

        ctx = openssl_ctx_get_concrete(ctx);
        /*
         * If the private_drbg is also NULL then this is the first time we've
         * used this thread.
         */
        if (CRYPTO_THREAD_get_local(&dgbl->private_drbg) == NULL
                && !ossl_init_thread_start(NULL, ctx, drbg_delete_thread_state))
            return NULL;
        drbg = drbg_setup(ctx, primary, RAND_DRBG_TYPE_PUBLIC);
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
    RAND_DRBG *drbg, *primary;

    if (dgbl == NULL)
        return NULL;

    drbg = CRYPTO_THREAD_get_local(&dgbl->private_drbg);
    if (drbg == NULL) {
        primary = OPENSSL_CTX_get0_primary_drbg(ctx);
        if (primary == NULL)
            return NULL;

        ctx = openssl_ctx_get_concrete(ctx);
        /*
         * If the public_drbg is also NULL then this is the first time we've
         * used this thread.
         */
        if (CRYPTO_THREAD_get_local(&dgbl->public_drbg) == NULL
                && !ossl_init_thread_start(NULL, ctx, drbg_delete_thread_state))
            return NULL;
        drbg = drbg_setup(ctx, primary, RAND_DRBG_TYPE_PRIVATE);
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
#ifndef FIPS_MODULE
    return &rand_meth;
#else
    return NULL;
#endif
}
