/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_RAND_LCL_H
# define HEADER_RAND_LCL_H

# include <openssl/aes.h>
# include <openssl/evp.h>
# include <openssl/sha.h>
# include <openssl/hmac.h>
# include <openssl/ec.h>
# include "internal/rand.h"

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



/* Max size of additional input and personalization string. */
# define DRBG_MAX_LENGTH                4096

/*
 * The quotient between max_{entropy,nonce}len and min_{entropy,nonce}len
 *
 * The current factor is large enough that the RAND_POOL can store a
 * random input which has a lousy entropy rate of 0.0625 bits per byte.
 * This input will be sent through the derivation function which 'compresses'
 * the low quality input into a high quality output.
 */
# define DRBG_MINMAX_FACTOR              128


/* DRBG status values */
typedef enum drbg_status_e {
    DRBG_UNINITIALISED,
    DRBG_READY,
    DRBG_ERROR
} DRBG_STATUS;


/* intantiate */
typedef int (*RAND_DRBG_instantiate_fn)(RAND_DRBG *ctx,
                                        const unsigned char *ent,
                                        size_t entlen,
                                        const unsigned char *nonce,
                                        size_t noncelen,
                                        const unsigned char *pers,
                                        size_t perslen);
/* reseed */
typedef int (*RAND_DRBG_reseed_fn)(RAND_DRBG *ctx,
                                   const unsigned char *ent,
                                   size_t entlen,
                                   const unsigned char *adin,
                                   size_t adinlen);
/* generat output */
typedef int (*RAND_DRBG_generate_fn)(RAND_DRBG *ctx,
                                     unsigned char *out,
                                     size_t outlen,
                                     const unsigned char *adin,
                                     size_t adinlen);
/* uninstantiate */
typedef int (*RAND_DRBG_uninstantiate_fn)(RAND_DRBG *ctx);


/*
 * The DRBG methods
 */

typedef struct rand_drbg_method_st {
    RAND_DRBG_instantiate_fn instantiate;
    RAND_DRBG_reseed_fn reseed;
    RAND_DRBG_generate_fn generate;
    RAND_DRBG_uninstantiate_fn uninstantiate;
} RAND_DRBG_METHOD;


/*
 * The state of a DRBG AES-CTR.
 */
typedef struct rand_drbg_ctr_st {
    AES_KEY ks;
    size_t keylen;
    unsigned char K[32];
    unsigned char V[16];
    /* Temp variables used by derivation function */
    AES_KEY df_ks;
    AES_KEY df_kxks;
    /* Temporary block storage used by ctr_df */
    unsigned char bltmp[16];
    size_t bltmp_pos;
    unsigned char KX[48];
} RAND_DRBG_CTR;


/*
 * The state of all types of DRBGs, even though we only have CTR mode
 * right now.
 */
struct rand_drbg_st {
    CRYPTO_RWLOCK *lock;
    RAND_DRBG *parent;
    int nid; /* the underlying algorithm */
    int fork_count;
    unsigned short flags; /* various external flags */

    /*
     * The random pool is used by RAND_add()/drbg_add() to attach random
     * data to the global drbg, such that the rand_drbg_get_entropy() callback
     * can pull it during instantiation and reseeding. This is necessary to
     * reconcile the different philosophies of the RAND and the RAND_DRBG
     * with respect to how randomness is added to the RNG during reseeding
     * (see PR #4328).
     */
    RAND_POOL *pool;

    /*
     * The following parameters are setup by the per-type "init" function.
     *
     * Currently the only type is CTR_DRBG, its init function is drbg_ctr_init().
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

    /* Counts the number of generate requests since the last reseed. */
    unsigned int generate_counter;
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
     * is added by RAND_add() or RAND_seed() will have an immediate effect on
     * the output of RAND_bytes() resp. RAND_priv_bytes().
     */
    unsigned int reseed_counter;

    size_t seedlen;
    DRBG_STATUS state;

    /* Application data, mainly used in the KATs. */
    CRYPTO_EX_DATA ex_data;

    /* Implementation specific data (currently only one implementation) */
    union {
        RAND_DRBG_CTR ctr;
    } data;

    /* Implementation specific methods */
    RAND_DRBG_METHOD *meth;

    /* Callback functions.  See comments in rand_lib.c */
    RAND_DRBG_get_entropy_fn get_entropy;
    RAND_DRBG_cleanup_entropy_fn cleanup_entropy;
    RAND_DRBG_get_nonce_fn get_nonce;
    RAND_DRBG_cleanup_nonce_fn cleanup_nonce;
};

/* The global RAND method, and the global buffer and DRBG instance. */
extern RAND_METHOD rand_meth;

/* How often we've forked (only incremented in child). */
extern int rand_fork_count;

/* Hardware-based seeding functions. */
size_t rand_acquire_entropy_from_tsc(RAND_POOL *pool);
size_t rand_acquire_entropy_from_cpu(RAND_POOL *pool);

/* DRBG entropy callbacks. */
size_t rand_drbg_get_entropy(RAND_DRBG *drbg,
                             unsigned char **pout,
                             int entropy, size_t min_len, size_t max_len);
void rand_drbg_cleanup_entropy(RAND_DRBG *drbg,
                               unsigned char *out, size_t outlen);
size_t rand_drbg_get_additional_data(unsigned char **pout, size_t max_len);

/* DRBG helpers */
int rand_drbg_restart(RAND_DRBG *drbg,
                      const unsigned char *buffer, size_t len, size_t entropy);

/* initializes the AES-CTR DRBG implementation */
int drbg_ctr_init(RAND_DRBG *drbg);

#endif
