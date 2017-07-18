/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
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

/* Amount of randomness (in bytes) we want for initial seeding. */
# define RANDOMNESS_NEEDED              (128 / 8)

/* Maximum count allowed in reseeding */
#define MAX_RESEED (1 << 24)

/* DRBG status values */
# define DRBG_STATUS_UNINITIALISED	0
# define DRBG_STATUS_READY		1
# define DRBG_STATUS_RESEED		2
# define DRBG_STATUS_ERROR		3

/* A default maximum length: larger than any reasonable value used in pratice */
# define DRBG_MAX_LENGTH                0x7ffffff0

/*
 * The context for DRBG AES-CTR
 */
typedef struct drbg_ctr_ctx_st {
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
} DRBG_CTR_CTX;


/*
 * The context for all DRBG's
 */
struct drbg_ctx_st {
    CRYPTO_RWLOCK *lock;
    DRBG_CTX *parent;
    int nid; /* the NID of the underlying algorithm */
    unsigned int flags; /* various external flags */

    /* The following parameters are setup by mechanism drbg_init() call */
    int strength;
    size_t blocklength;
    size_t max_request;
    size_t min_entropy, max_entropy;
    size_t min_nonce, max_nonce;
    size_t max_pers, max_adin;
    unsigned int reseed_counter;
    unsigned int reseed_interval;
    size_t seedlen;
    int status;

    /* Application data: typically (only?) used by test get_entropy */
    CRYPTO_EX_DATA ex_data;

    /* Implementation specific structures */
    DRBG_CTR_CTX ctr;

    /* entropy gathering function */
    RAND_DRBG_get_entropy_fn get_entropy;
    /* Indicates we have finished with entropy buffer */
    RAND_DRBG_cleanup_entropy_fn cleanup_entropy;
    /* nonce gathering function */
    RAND_DRBG_get_nonce_fn get_nonce;
    /* Indicates we have finished with nonce buffer */
    RAND_DRBG_cleanup_nonce_fn cleanup_nonce;
};


extern RAND_METHOD openssl_rand_meth;
void rand_drbg_cleanup(void);

/* Hardware-based seeding functions. */
void rand_rdtsc(void);
int rand_rdcpu(void);

/* DRBG functions implementing AES-CTR */
int ctr_init(DRBG_CTX *dctx);
int ctr_uninstantiate(DRBG_CTX *dctx);
int ctr_instantiate(DRBG_CTX *dctx,
                    const unsigned char *ent, size_t entlen,
                    const unsigned char *nonce, size_t noncelen,
                    const unsigned char *pers, size_t perslen);
int ctr_reseed(DRBG_CTX *dctx,
               const unsigned char *ent, size_t entlen,
               const unsigned char *adin, size_t adinlen);
int ctr_generate(DRBG_CTX *dctx,
                 unsigned char *out, size_t outlen,
                 const unsigned char *adin, size_t adinlen);

#endif
