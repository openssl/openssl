/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>

/*
 * Refer to FIPS 204 Section 4 Parameter sets.
 * Fields that are shared between all algorithms (such as q & d) have been omitted.
 */
struct ml_dsa_params_st {
    const char *alg;
    int tau;    /* Number of +/-1's in polynomial c */
    int bit_strength; /* The collision strength (lambda) */
    int gamma1; /* coefficient range of y */
    int gamma2; /* coefficient range of ? */
    size_t k, l; /* matrix dimensions of 'A' */
    int eta;    /* Private key range */
    int beta;   /* tau * eta */
    int omega;  /* Number of 1's in the hint 'h' */
    int security_category; /* Category is related to Security strength */
    size_t sk_len; /* private key size */
    size_t pk_len; /* public key size */
    size_t sig_len; /* signature size */
};

const struct ml_dsa_params_st *ossl_ml_dsa_params_get(const char *alg);
