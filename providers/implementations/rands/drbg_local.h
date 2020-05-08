/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_PROV_LOCAL_H
# define OSSL_CRYPTO_PROV_LOCAL_H

# include <openssl/evp.h>
# include <openssl/core_numbers.h>
# include <openssl/core_names.h>
# include <openssl/params.h>
# include "internal/tsan_assist.h"

# include "internal/numbers.h"

/* How many times to read the TSC as a randomness source. */
# define TSC_READ_COUNT                 4

/* Maximum reseed intervals */
# define MAX_RESEED_INTERVAL                     (1 << 24)
# define MAX_RESEED_TIME_INTERVAL                (1 << 20) /* approx. 12 days */

/* Default reseed intervals */
# define MASTER_RESEED_INTERVAL                  (1 << 8)
# define SLAVE_RESEED_INTERVAL                   (1 << 16)
# define MASTER_RESEED_TIME_INTERVAL             (60*60)   /* 1 hour */
# define SLAVE_RESEED_TIME_INTERVAL              (7*60)    /* 7 minutes */

/*
 * The number of bytes that constitutes an atomic lump of entropy with respect
 * to the FIPS 140-2 section 4.9.2 Conditional Tests.  The size is somewhat
 * arbitrary, the smaller the value, the less entropy is consumed on first
 * read but the higher the probability of the test failing by accident.
 *
 * The value is in bytes.
 */
#define CRNGT_BUFSIZ    16

/*
 * Maximum input size for the DRBG (entropy, nonce, personalization string)
 *
 * NIST SP800 90Ar1 allows a maximum of (1 << 35) bits i.e., (1 << 32) bytes.
 *
 * We lower it to 'only' INT32_MAX bytes, which is equivalent to 2 gigabytes.
 */
# define DRBG_MAX_LENGTH                         INT32_MAX

/* The default nonce */
#ifdef CHARSET_EBCDIC
# define DRBG_DEFAULT_PERS_STRING      { 0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, \
     0x4c, 0x20, 0x4e, 0x49, 0x53, 0x54, 0x20, 0x53, 0x50, 0x20, 0x38, 0x30, \
     0x30, 0x2d, 0x39, 0x30, 0x41, 0x20, 0x44, 0x52, 0x42, 0x47, 0x00};
#else
# define DRBG_DEFAULT_PERS_STRING                "OpenSSL NIST SP 800-90A DRBG"
#endif

typedef struct prov_drbg_st PROV_DRBG;

/* DRBG status values */
typedef enum drbg_status_e {
    DRBG_UNINITIALISED,
    DRBG_READY,
    DRBG_ERROR
} DRBG_STATUS;

/*
 * The DRBG methods
 */

typedef struct rand_drbg_hmac_st {
    EVP_MD *md;
    HMAC_CTX *ctx;
    size_t blocklen;
    unsigned char K[EVP_MAX_MD_SIZE];
    unsigned char V[EVP_MAX_MD_SIZE];
} PROV_DRBG_HMAC;

/*
 * The state of a DRBG AES-CTR.
 */
typedef struct rand_drbg_ctr_st {
    EVP_CIPHER_CTX *ctx_ecb;
    EVP_CIPHER_CTX *ctx_ctr;
    EVP_CIPHER_CTX *ctx_df;
    EVP_CIPHER *cipher_ecb;
    EVP_CIPHER *cipher_ctr;
    size_t keylen;
    unsigned char K[32];
    unsigned char V[16];
    /* Temporary block storage used by ctr_df */
    unsigned char bltmp[16];
    size_t bltmp_pos;
    unsigned char KX[48];
} PROV_DRBG_CTR;


/*
 * The state of all types of DRBGs, even though we only have CTR mode
 * right now.
 */
struct prov_drbg_st {
    CRYPTO_RWLOCK *lock;
    /* The library context this DRBG is associated with, if any */
    OPENSSL_CTX *libctx;
    void *parent;
    const OSSL_DISPATCH *parent_dispatch;
    int secure; /* 1: allocated on the secure heap, 0: otherwise */
    /*
     * Stores the return value of openssl_get_fork_id() as of when we last
     * reseeded.  The DRBG reseeds automatically whenever drbg->fork_id !=
     * openssl_get_fork_id().  Used to provide fork-safety and reseed this
     * DRBG in the child process.
     */
    int fork_id;
    unsigned short flags; /* various external flags */

    /*
     * The random_data is used by PROV_add()/drbg_add() to attach random
     * data to the global drbg, such that the rand_drbg_get_entropy() callback
     * can pull it during instantiation and reseeding. This is necessary to
     * reconcile the different philosophies of the PROV and the PROV_DRBG
     * with respect to how randomness is added to the RNG during reseeding
     * (see PR #4328).
     */
    struct rand_pool_st *seed_pool;

    /*
     * Auxiliary pool for additional data.
     */
    struct rand_pool_st *adin_pool;

    /*
     * The following parameters are setup by the per-type "init" function.
     *
     * The supported types and their init functions are:
     *    (1) CTR_DRBG:  drbg_ctr_init().
     *    (2) HMAC_DRBG: drbg_hmac_init().
     *    (3) HASH_DRBG: drbg_hash_init().
     *
     * The parameters are closely related to the ones described in
     * section '10.2.1 CTR_DRBG' of [NIST SP 800-90Ar1], with one
     * crucial difference: In the NIST standard, all counts are given
     * in bits, whereas in OpenSSL entropy counts are given in bits
     * and buffer lengths are given in bytes.
     *
     * Since this difference has lead to some confusion in the past,
     * (see [GitHub Issue #2443], formerly [rt.openssl.org #4055])
     * the 'len' suffix has been added to all buffer sizes for
     * clarification.
     */

    int strength;
    size_t max_request;
    size_t min_entropylen, max_entropylen;
    size_t min_noncelen, max_noncelen;
    size_t max_perslen, max_adinlen;

    /*
     * Counts the number of generate requests since the last reseed
     * (Starts at 1). This value is the reseed_counter as defined in
     * NIST SP 800-90Ar1
     */
    unsigned int reseed_gen_counter;
    /*
     * Maximum number of generate requests until a reseed is required.
     * This value is ignored if it is zero.
     */
    unsigned int reseed_interval;
    /* Stores the time when the last reseeding occurred */
    time_t reseed_time;
    /*
     * Specifies the maximum time interval (in seconds) between reseeds.
     * This value is ignored if it is zero.
     */
    time_t reseed_time_interval;
    /*
     * Counts the number of reseeds since instantiation.
     * This value is ignored if it is zero.
     *
     * This counter is used only for seed propagation from the <master> DRBG
     * to its two children, the <public> and <private> DRBG. This feature is
     * very special and its sole purpose is to ensure that any randomness which
     * is added by PROV_add() or PROV_seed() will have an immediate effect on
     * the output of PROV_bytes() resp. PROV_priv_bytes().
     */
    TSAN_QUALIFIER unsigned int reseed_prop_counter;
    unsigned int reseed_next_counter;

    size_t seedlen;
    DRBG_STATUS state;

    void *data;

#ifndef FIPS_MODULE
    /* Application data, mainly used in the KATs. */
    CRYPTO_EX_DATA ex_data;
#endif
};

/* DRBG helpers */
int rand_drbg_restart(PROV_DRBG *drbg,
                      const unsigned char *buffer, size_t len, size_t entropy);
size_t rand_drbg_seedlen(PROV_DRBG *drbg);

PROV_DRBG *prov_rand_drbg_new(void *provctx, int secure, void *parent,
                              const OSSL_DISPATCH *parent_dispatch,
                              int (*dnew)(PROV_DRBG *ctx, int secure));
void prov_rand_free(PROV_DRBG *drbg);

int PROV_DRBG_instantiate(PROV_DRBG *drbg, int strength,
                          int prediction_resistance,
                          const unsigned char *pers, size_t perslen,
                          int (*ifnc)(PROV_DRBG *drbg,
                                      const unsigned char *ent, size_t ent_len,
                                      const unsigned char *nonce,
                                      size_t nonce_len,
                                      const unsigned char *pstr,
                                      size_t pstr_len));

int PROV_DRBG_reseed(PROV_DRBG *drbg, int prediction_resistance,
                     const unsigned char *ent, size_t ent_len,
                     const unsigned char *adin, size_t adinlen,
                     int (*reseed)(PROV_DRBG *drbg, const unsigned char *ent,
                                   size_t ent_len, const unsigned char *adin,
                                   size_t adin_len));

int PROV_DRBG_generate(PROV_DRBG *drbg, unsigned char *out, size_t outlen,
                       int strength, int prediction_resistance,
                       const unsigned char *adin, size_t adinlen,
                       int (*generate)(PROV_DRBG *, unsigned char *out,
                                       size_t outlen, const unsigned char *adin,
                                       size_t adin_len),
                       int (*reseed)(PROV_DRBG *drbg, const unsigned char *ent,
                                     size_t ent_len, const unsigned char *adin,
                                     size_t adin_len));

/* locking api */
OSSL_OP_rand_enable_locking_fn drbg_enable_locking;
OSSL_OP_rand_lock_fn drbg_lock;
OSSL_OP_rand_unlock_fn drbg_unlock;

int drbg_get_ctx_params(PROV_DRBG *drbg, OSSL_PARAM params[]);
int drbg_set_ctx_params(PROV_DRBG *drbg, const OSSL_PARAM params[]);

#define OSSL_PARAM_DRBG_SETABLE_CTX_COMMON                                      \
    OSSL_PARAM_uint(OSSL_RAND_PARAM_RESEED_REQUESTS, NULL),             \
    OSSL_PARAM_uint64(OSSL_RAND_PARAM_RESEED_TIME_INTERVAL, NULL)

#define OSSL_PARAM_DRBG_GETABLE_CTX_COMMON                              \
    OSSL_PARAM_int(OSSL_RAND_PARAM_STATUS, NULL),                       \
    OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),                    \
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),               \
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MIN_ENTROPYLEN, NULL),            \
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_ENTROPYLEN, NULL),            \
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MIN_NONCELEN, NULL),              \
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_NONCELEN, NULL),              \
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_PERSLEN, NULL),               \
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_ADINLEN, NULL),               \
    OSSL_PARAM_uint(OSSL_RAND_PARAM_RESEED_CTR, NULL),                  \
    OSSL_PARAM_uint(OSSL_RAND_PARAM_RESEED_REQUESTS, NULL),             \
    OSSL_PARAM_uint64(OSSL_RAND_PARAM_RESEED_TIME_INTERVAL, NULL)

size_t prov_crngt_get_entropy(PROV_DRBG *drbg,
                              unsigned char **pout,
                              int entropy, size_t min_len, size_t max_len,
                              int prediction_resistance);
void prov_crngt_cleanup_entropy(PROV_DRBG *drbg,
                                unsigned char *out, size_t outlen);

/*
 * Entropy call back for the FIPS 140-2 section 4.9.2 Conditional Tests.
 * These need to be exposed for the unit tests.
 */
#if 0
int rand_crngt_get_entropy_cb(OPENSSL_CTX *ctx, PROV_POOL *pool,
                              unsigned char *buf, unsigned char *md,
                              unsigned int *md_size);
extern int (*crngt_get_entropy)(OPENSSL_CTX *ctx, PROV_POOL *pool,
                                unsigned char *buf, unsigned char *md,
                                unsigned int *md_size);
#endif
#endif
