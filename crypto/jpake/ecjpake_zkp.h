/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#import <openssl/ec.h>
#import <openssl/evp.h>
#import "ecjpake.h"

/**
 * Find a random BIGNUM given an order of an EC Curve.
 */
BIGNUM *random_big_num_for_curve_order(BIGNUM *bn, const BIGNUM *order);

/**
 * Creates a zero-knowledge proof for a particular point on an elliptic curve.
 */
int ec_generate_zkp(EC_JPAKE_STEP_PART *step_part,
                     const EC_GROUP *group,
                     const EC_POINT *G,
                     const BIGNUM *x,
                     const EC_POINT *Gx,
                     const BIGNUM *N,
                     const EVP_MD *hashMethod,
                     BN_CTX *bnCtx,
                     const char *name);

/**
 * Verifies the zero-knowledge proof give by a partner.
 */
int ec_verify_zkp(const EC_GROUP *group,
                   const EC_POINT *G,
                   const EC_POINT *Gx,
                   const EC_JPAKE_ZKP *zkp,
                   const EVP_MD *hashMethod,
                   BN_CTX *bnCtx,
                   const char *name);

