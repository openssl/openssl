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

# include "internal/numbers.h"

/* Maximum reseed intervals */
# define MAX_RESEED_INTERVAL                     (1 << 24)
# define MAX_RESEED_TIME_INTERVAL                (1 << 20) /* approx. 12 days */

/* Default reseed intervals */
# define PRIMARY_RESEED_INTERVAL                 (1 << 8)
# define SECONDARY_RESEED_INTERVAL               (1 << 16)
# define PRIMARY_RESEED_TIME_INTERVAL            (60 * 60) /* 1 hour */
# define SECONDARY_RESEED_TIME_INTERVAL          (7 * 60)  /* 7 minutes */

/*
 * The state of all types of DRBGs.
 */
struct rand_drbg_st {
    CRYPTO_RWLOCK *lock;
    /* The library context this DRBG is associated with, if any */
    OPENSSL_CTX *libctx;
    RAND_DRBG *parent;
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

#endif
