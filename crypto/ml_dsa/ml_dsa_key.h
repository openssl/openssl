/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>
#include "crypto/types.h"
#include "internal/refcount.h"
#include "ml_dsa_vector.h"

struct ml_dsa_key_st {

    CRYPTO_REF_COUNT references;
    OSSL_LIB_CTX *libctx;
    const ML_DSA_PARAMS *params;
    char *propq;

    uint8_t rho[ML_DSA_RHO_BYTES]; /* public random seed */
    uint8_t tr[ML_DSA_TR_BYTES];   /* Pre-cached public key Hash */
    uint8_t K[ML_DSA_K_BYTES];     /* Private random seed for signing */
    VECTOR t1;                     /* public Compressed Polynomial of size K */
    VECTOR s1; /* secret size L */
    VECTOR s2; /* secret size K */
    VECTOR t0; /* secret size K */

    uint8_t *pub_encoding;
    uint8_t *priv_encoding;
};
