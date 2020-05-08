/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_RAND_LOCAL_H
# define OSSL_CRYPTO_RAND_LOCAL_H

# include <openssl/aes.h>
# include <openssl/evp.h>
# include <openssl/sha.h>
# include <openssl/hmac.h>
# include <openssl/ec.h>
# include <openssl/rand_drbg.h>
# include "internal/tsan_assist.h"
# include "crypto/rand.h"
# include "crypto/rand_pool.h"

# include "internal/numbers.h"

/* Maximum reseed intervals */
# define MAX_RESEED_INTERVAL                     (1 << 24)
# define MAX_RESEED_TIME_INTERVAL                (1 << 20) /* approx. 12 days */

/* Default reseed intervals */
# define MASTER_RESEED_INTERVAL                  (1 << 8)
# define SLAVE_RESEED_INTERVAL                   (1 << 16)
# define MASTER_RESEED_TIME_INTERVAL             (60 * 60) /* 1 hour */
# define SLAVE_RESEED_TIME_INTERVAL              (7 * 60)  /* 7 minutes */

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

/* DRBG status values */
typedef enum drbg_status_e {
    DRBG_UNINITIALISED,
    DRBG_READY,
    DRBG_ERROR
} DRBG_STATUS;

/* instantiate */
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
/* generate output */
typedef int (*RAND_DRBG_generate_fn)(RAND_DRBG *ctx,
                                     unsigned char *out,
                                     size_t outlen,
                                     const unsigned char *adin,
                                     size_t adinlen);
/* uninstantiate */
typedef int (*RAND_DRBG_uninstantiate_fn)(RAND_DRBG *ctx);


/*
 * The state of all types of DRBGs, even though we only have CTR mode
 * right now.
 */
struct rand_drbg_st {
    CRYPTO_RWLOCK *lock;
    /* The library context this DRBG is associated with, if any */
    OPENSSL_CTX *libctx;
    RAND_DRBG *parent;
    int secure; /* 1: allocated on the secure heap, 0: otherwise */
    int type; /* the nid of the underlying algorithm */
    unsigned short flags; /* various external flags */

    /* Application data, mainly used in the KATs. */
    CRYPTO_EX_DATA ex_data;

    /* Implementation */
    EVP_RAND_CTX *rand;

    /* Callback functions.  See comments in rand_lib.c */
    RAND_DRBG_get_entropy_fn get_entropy;
    RAND_DRBG_cleanup_entropy_fn cleanup_entropy;
    RAND_DRBG_get_nonce_fn get_nonce;
    RAND_DRBG_cleanup_nonce_fn cleanup_nonce;

    void *callback_data;
};

/* The global RAND method, and the global buffer and DRBG instance. */
extern RAND_METHOD rand_meth;

/* DRBG helpers */
int rand_drbg_restart(RAND_DRBG *drbg,
                      const unsigned char *buffer, size_t len, size_t entropy);
size_t rand_drbg_seedlen(RAND_DRBG *drbg);

/*
 * Entropy call back for the FIPS 140-2 section 4.9.2 Conditional Tests.
 * These need to be exposed for the unit tests.
 */
int rand_crngt_get_entropy_cb(OPENSSL_CTX *ctx, RAND_POOL *pool,
                              unsigned char *buf, unsigned char *md,
                              unsigned int *md_size);
extern int (*crngt_get_entropy)(OPENSSL_CTX *ctx, RAND_POOL *pool,
                                unsigned char *buf, unsigned char *md,
                                unsigned int *md_size);

#endif
