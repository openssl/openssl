/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>
#include "internal/refcount.h"

#define SLH_DSA_MAX_N 32
#define SLH_DSA_SK_SEED(key) ((key)->priv)
#define SLH_DSA_SK_PRF(key)  ((key)->priv + (key)->params->n)
#define SLH_DSA_PK_SEED(key) ((key)->priv + (key)->params->n * 2)
#define SLH_DSA_PK_ROOT(key) ((key)->priv + (key)->params->n * 3)
#define SLH_DSA_PUB(key) SLH_DSA_PK_SEED(key)
#define SLH_DSA_PRIV(key) SLH_DSA_SK_SEED(key)

struct slh_dsa_key_st {
    /*
     * A private key consists of
     *  Private SEED and PRF values of size |n|
     *  Public SEED and ROOT values of size |n|
     *  (Unlike X25519 the public key is not (fully) constructed from the
     *  private key so when encoded the private key must contain the public key)
     */
    uint8_t priv[4 * SLH_DSA_MAX_N];
    /*
     * pub will be NULL initially.
     * When either a private or public key is loaded it will then point
     * to &priv[n * 2]
     */
    uint8_t *pub;
    CRYPTO_REF_COUNT references;
    OSSL_LIB_CTX *libctx;
    char *propq;
    /* contains the algorithm name and constants such as |n| */
    const SLH_DSA_PARAMS *params;
    int has_priv; /* Set to 1 if there is a private key component */
};
