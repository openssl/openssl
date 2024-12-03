/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_ML_DSA_LOCAL_H
# define OSSL_CRYPTO_ML_DSA_LOCAL_H

# include "crypto/ml_dsa.h"
# include "internal/constant_time.h"

/* Maximimum size of the 'A' matrix */
# define ML_DSA_K_MAX 8
# define ML_DSA_L_MAX 7

# define ML_DSA_SEED_BYTES 32
# define ML_DSA_Q 8380417   /* The modulus is 23 bits (2^23 - 2^13 + 1) */
# define ML_DSA_Q_MINUS1_DIV2 ((ML_DSA_Q - 1) / 2)
# define ML_DSA_Q_MINUS1_DIV32 ((ML_DSA_Q - 1) / 32)
# define ML_DSA_Q_BITS 23
# define ML_DSA_Q_INV 58728449  /* q^-1 satisfies: q^-1 * q = 1 mod 2^32 */
# define ML_DSA_Q_NEG_INV 4236238847 /* Inverse of -q modulo 2^32 */
# define ML_DSA_DEGREE_INV_MONTGOMERY 41978 /* Inverse of 256 mod q, in Montgomery form. */

# define ML_DSA_D_BITS 13   /* The number of bits dropped from t */
# define ML_DSA_NUM_POLY_COEFFICIENTS 256  /* The number of coefficients in the polynomials */
# define ML_DSA_RHO_BYTES 32   /* p = Public Random Seed */
# define ML_DSA_PRIV_SEED_BYTES 64 /* p' = Private random seed */
# define ML_DSA_K_BYTES 32 /* K = Private random seed for signing */
# define ML_DSA_TR_BYTES 64 /* Hash of public key used for signing */
# define ML_DSA_MU_BYTES 64
# define ML_DSA_RHO_PRIME_BYTES 64

typedef struct ml_dsa_params_st ML_DSA_PARAMS;
typedef struct poly_st POLY;
typedef struct vector_st VECTOR;
typedef struct matrix_st MATRIX;

/*
 * FIPS 204 ML-DSA algorithms have different parameters which includes:
 *   - A set of constants (Section 4. contains 3 parameter sets)
 *
 *   - OpenSSL also uses pre-fetched EVP_MD_CTX objects for Hashing purposes.
 *
 * ML_DSA_CTX is a container to hold all these objects. This object is
 * resolved early and is then passed to most ML-DSA related functions.
 */
struct ml_dsa_ctx_st {
    const ML_DSA_PARAMS *params;
    EVP_MD_CTX *h_ctx; /* SHAKE-256 */
    EVP_MD_CTX *g_ctx; /* SHAKE-128 */
};

int ossl_ml_dsa_sample_expandA(EVP_MD_CTX *g_ctx, const uint8_t *rho, MATRIX *out);
int ossl_ml_dsa_sample_expandS(EVP_MD_CTX *h_ctx, int eta, const uint8_t *seed,
                               VECTOR *s1, VECTOR *s2);
void ossl_ml_dsa_poly_ntt(POLY *s);
void ossl_ml_dsa_poly_ntt_inverse(POLY *s);
void ossl_ml_dsa_poly_ntt_mult(const POLY *lhs, const POLY *rhs, POLY *out);

void ossl_ml_dsa_key_compress_power2_round(uint32_t r, uint32_t *r1, uint32_t *r0);
uint32_t ossl_ml_dsa_key_compress_high_bits(uint32_t r, uint32_t gamma2);
void ossl_ml_dsa_key_compress_decompose(uint32_t r, uint32_t gamma2,
                                        uint32_t *r1, int32_t *r0);
void ossl_ml_dsa_key_compress_decompose(uint32_t r, uint32_t gamma2,
                                        uint32_t *r1, int32_t *r0);
int32_t ossl_ml_dsa_key_compress_low_bits(uint32_t r, uint32_t gamma2);
int32_t ossl_ml_dsa_key_compress_make_hint(uint32_t ct0, uint32_t cs2,
                                           uint32_t gamma2, uint32_t w);
uint32_t ossl_ml_dsa_key_compress_use_hint(uint32_t hint, uint32_t r,
                                           uint32_t gamma2);

int ossl_ml_dsa_pk_encode(ML_DSA_KEY *key);
int ossl_ml_dsa_pk_decode(const uint8_t *in, size_t in_len, ML_DSA_KEY *key);
int ossl_ml_dsa_sk_encode(ML_DSA_KEY *key);
int ossl_ml_dsa_sk_decode(const uint8_t *in, size_t in_len, ML_DSA_KEY *key);

/*
 * @brief Reduces x mod q in constant time
 * i.e. return x < q ? x : x - q;
 *
 * @param x Where x is assumed to be in the range 0 <= x < 2*q
 * @returns the difference in the range 0..q-1
 */
static ossl_inline ossl_unused uint32_t reduce_once(uint32_t x)
{
    return constant_time_select_32(constant_time_lt(x, ML_DSA_Q), x, x - ML_DSA_Q);
}

/*
 * @brief Calculate The positive value of (a-b) mod q in constant time.
 *
 * a - b mod q gives a value in the range -(q-1)..(q-1)
 * By adding q we get a range of 1..(2q-1).
 * Reducing this once then gives the range 0..q-1
 *
 * @param a The minuend assumed to be in the range 0..q-1
 * @param b The subtracthend assumed to be in the range 0..q-1.
 * @returns The value (q + a - b) mod q
 */
static ossl_inline ossl_unused uint32_t mod_sub(uint32_t a, uint32_t b)
{
    return reduce_once(ML_DSA_Q + a - b);
}

#endif /* OSSL_CRYPTO_ML_DSA_LOCAL_H */
