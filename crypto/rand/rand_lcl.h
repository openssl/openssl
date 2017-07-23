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

/* Maximum amount of randomness to hold in RAND_BYTES_BUFFER. */
# define MAX_RANDOMNESS_HELD            (4 * RANDOMNESS_NEEDED)

/* Maximum count allowed in reseeding */
# define MAX_RESEED                     (1 << 24)

/* DRBG status values */
# define DRBG_STATUS_UNINITIALISED      0
# define DRBG_STATUS_READY              1
# define DRBG_STATUS_RESEED             2
# define DRBG_STATUS_ERROR              3

/* A default maximum length: larger than any reasonable value used in pratice */
# define DRBG_MAX_LENGTH                0x7ffffff0


/*
 * A buffer of random bytes to be fed as "entropy" into the DRBG.  RAND_add()
 * adds data to the buffer, and the entropy_from_system() pulls data from
 * the buffer.
 */
typedef struct rand_bytes_buffer_st {
    CRYPTO_RWLOCK *lock;
    int size;
    int curr;
    char *buff;
} RAND_BYTES_BUFFER;

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
    unsigned short flags; /* various external flags */
    unsigned short cleared;
    unsigned char randomness[RANDOMNESS_NEEDED];

    /* These parameters are setup by the per-type "init" function. */
    int strength;
    size_t max_request;
    size_t min_entropy, max_entropy;
    size_t min_nonce, max_nonce;
    size_t max_pers, max_adin;
    unsigned int reseed_counter;
    unsigned int reseed_interval;
    size_t seedlen;
    int status;

    /* Application data, mainly used in the KATs. */
    CRYPTO_EX_DATA ex_data;

    /* Implementation specific structures; was a union, but inline for now */
    RAND_DRBG_CTR ctr;

    /* Callback functions.  See comments in drbg_lib.c */
    RAND_DRBG_get_entropy_fn get_entropy;
    RAND_DRBG_cleanup_entropy_fn cleanup_entropy;
    RAND_DRBG_get_nonce_fn get_nonce;
    RAND_DRBG_cleanup_nonce_fn cleanup_nonce;
};

/* The global RAND method, and the global buffer and DRBG instance. */
extern RAND_METHOD rand_meth;
extern RAND_BYTES_BUFFER rand_bytes;
extern RAND_DRBG rand_drbg;

void rand_cleanup_entropy(RAND_DRBG *drbg, unsigned char *out);

/* Hardware-based seeding functions. */
void rand_read_tsc(void);
int rand_read_cpu(void);

/* DRBG functions implementing AES-CTR */
int ctr_init(RAND_DRBG *drbg);
int ctr_uninstantiate(RAND_DRBG *drbg);
int ctr_instantiate(RAND_DRBG *drbg,
                    const unsigned char *ent, size_t entlen,
                    const unsigned char *nonce, size_t noncelen,
                    const unsigned char *pers, size_t perslen);
int ctr_reseed(RAND_DRBG *drbg,
               const unsigned char *ent, size_t entlen,
               const unsigned char *adin, size_t adinlen);
int ctr_generate(RAND_DRBG *drbg,
                 unsigned char *out, size_t outlen,
                 const unsigned char *adin, size_t adinlen);

#endif
