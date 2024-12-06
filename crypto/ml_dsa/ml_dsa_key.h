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
    /*
     * t0 is the Polynomial encoding of the 13 LSB of each coefficient of the
     * uncompressed public key polynomial t. This is saved as part of the
     * private key. It is column vector of K polynomials.
     */
    VECTOR t0;
    /*
     * t1 is the Polynomial encoding of the 10 MSB of each coefficient of the
     * uncompressed public key polynomial t. This is saved as part of the
     * public key. It is column vector of K polynomials.
     * (There are 23 bits in q-modulus.. i.e 10 bits = 23 - 13)
     */
    VECTOR t1;
    VECTOR s1; /* private secret of size L with short coefficients (-4..4) or (-2..2) */
    VECTOR s2; /* private secret of size K with short coefficients (-4..4) or (-2..2) */

    /*
     * The encoded public and private keys, these are non NULL if the key
     * components are generated or loaded.
     */
    uint8_t *pub_encoding;
    uint8_t *priv_encoding;
};
