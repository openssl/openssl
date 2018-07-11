/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ec.h>
#include <openssl/evp.h>

/**
 * The JPAKE context contains values set and utilized through an exchange.
 */
typedef struct {

    EC_GROUP *group;      /** Elliptic curve group */

    char *name;           /** Must be unique (compared to peer_name) */
    char *peer_name;      /** Partner or peer name */

    BIGNUM *secret;       /** The pre-shared secret */

    BIGNUM *x1;           /** Alice's (My) x1 */
    BIGNUM *x2;           /** Alice's (My) x2 */
    BIGNUM *x2s;          /** Alice's (My) x2*s */

    EC_POINT *gx1;        /** Alice's (My) public key g^x1 or Bob's (Partner) public key g^x3 */
    EC_POINT *gx2;        /** Alice's (My) public key g^x2 or Bob's (Partner) public key g^x4 */
    EC_POINT *gx3;        /** Alice's (My) public key g^x3 or Bob's (Partner) public key g^x1 */
    EC_POINT *gx4;        /** Alice's (My) public key g^x4 or Bob's (Partner) public key g^x2 */
    EC_POINT *b;          /** Alice's B or Bob's A */

    BN_CTX *bnCtx;        /** BIGNUM operation context */

} EC_JPAKE_CTX;

/**
 * JPAKE Return/Error Codes
 */
typedef enum {
    JPAKE_RET_FAILURE = 0,
    JPAKE_RET_SUCCESS = 1
} EC_JPAKE_RET;

/**
 * The structure for our schnorr zero knowledge proof.
 */
typedef struct {
    BIGNUM *gr;
    BIGNUM *b;
} EC_JPAKE_ZKP;

/**
 * The basic components of our exchange: a random point and zero knowledge proof.
 */
typedef struct {
    BIGNUM *gx;
    EC_JPAKE_ZKP zkpx;
} EC_JPAKE_STEP_PART;

/**
 * Round one of JPAKE requires Alice and Bob's respective payload.
 */
typedef struct {
    EC_JPAKE_STEP_PART p1;
    EC_JPAKE_STEP_PART p2;
} EC_JPAKE_STEP1;

/**
 * Round two of JPAKE only requires an EC Point and the zero knowledge proof
 */
typedef EC_JPAKE_STEP_PART EC_JPAKE_STEP2;

/**
 * Third round structure to hold a BIGNUM, which contains the HMAC bytes, and the digest method.
 */
typedef struct {
    BIGNUM *hmac;
    const EVP_MD *method;
} EC_JPAKE_STEP3;

/**
 * Clears fields related to the secret and the random BIGNUMs used to calculate EC Points
 *
 * @param ctx The JPAKE context to clear.
 */
void EC_JPAKE_CTX_clear_private_fields(EC_JPAKE_CTX *ctx);

/**
 * Frees the JPAKE context.
 */
void EC_JPAKE_CTX_free(EC_JPAKE_CTX *ctx);

/**
 * Creates a new EC JPAKE context.
 */
EC_JPAKE_CTX *EC_JPAKE_CTX_new(const char *name,
        const char *curve_name,
        const BIGNUM *secret);

/**
 * A "part" structure is used as a part of the first round structure,
 * but can be re-used as a model for the second step
 */
#define EC_JPAKE_STEP_PART_init    EC_JPAKE_STEP2_init
#define EC_JPAKE_STEP_PART_release EC_JPAKE_STEP2_release

/**
 * Initializes a partial structure
 */
int EC_JPAKE_STEP_PART_init(EC_JPAKE_STEP_PART *p);

/**
 * Releases a partial structure
 */
void EC_JPAKE_STEP_PART_release(EC_JPAKE_STEP_PART *p);

/**
 * Initializes a first round structure
 */
int EC_JPAKE_STEP1_init(EC_JPAKE_STEP1 *s1);
/**
 * Releases a first round structure
 */
void EC_JPAKE_STEP1_release(EC_JPAKE_STEP1 *s1);

/**
 * Initializes the structure for JPAKE's third step.
 */
int EC_JPAKE_STEP3_init(EC_JPAKE_STEP3 *s3, const EVP_MD *method);

/**
 * Frees the third step structure.
 */
void EC_JPAKE_STEP3_release(EC_JPAKE_STEP3 *s3);

/**
 *  Initializes a zero knowledge proof for JPAKE
 */
int EC_JPAKE_ZKP_init(EC_JPAKE_ZKP *zkp);

/**
 *  Rekeases a zero knowledge proof
 */
void EC_JPAKE_ZKP_release(EC_JPAKE_ZKP *zkp);
