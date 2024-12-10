/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Copyright (c) 2024, Google Inc. */

/* Variant-neutral helper functions */

#include <crypto/ml_kem.h>

typedef struct ossl_ml_kem_scalar_st {
    /* On every function entry and exit, 0 <= c[i] < ML_KEM_PRIME. */
    uint16_t c[ML_KEM_DEGREE];
} scalar;

typedef struct ossl_ml_kem_ctx_st {
    EVP_MD *shake128_cache;
    EVP_MD *shake256_cache;
    EVP_MD *sha3_256_cache;
    EVP_MD *sha3_512_cache;
    OSSL_LIB_CTX *libctx;
    const ossl_ml_kem_vinfo *vinfo;
} mctx;

/*
 * Combine a prefix, the ML-KEM variant bitsize and a suffix, to produce a C
 * symbol name.
 */
#  define ossl_ml_kem_name(v, suffix) ossl_ml_kem_##v##_##suffix

#  define DECLARE_ML_KEM_VEC_ST(var, rank) \
    struct ossl_ml_kem_name(var,vector_st) { \
        scalar v[rank]; \
    }
#  define DECLARE_ML_KEM_MAT_ST(var, rank) \
    struct ossl_ml_kem_name(var,matrix_st) { \
        scalar v[rank][rank]; \
    }
#  define DECLARE_ML_KEM_PUB_ST(v) \
    struct ossl_ml_kem_name(v,public_key_st) { \
        /* Public vector |t| expanded form */ \
        ossl_ml_kem_name(v,vector) t; \
        uint8_t rho[ML_KEM_RANDOM_BYTES]; \
        uint8_t pkhash[ML_KEM_PKHASH_BYTES]; \
        /* Saved matrix |m|. */ \
        ossl_ml_kem_name(v,matrix) m; \
    }
#  define DECLARE_ML_KEM_PRV_ST(v) \
    struct ossl_ml_kem_name(v,private_key_st) { \
        /* Public key in expanded form */ \
        ossl_ml_kem_name(v,public_key) pub; \
        /* Secret vector |s| expanded form. */ \
        ossl_ml_kem_name(v,vector) s; \
        /* The |z| random value */ \
        uint8_t z[ML_KEM_RANDOM_BYTES]; \
    }
#  define DECLARE_VARIANT_STRUCTS(v, rank) \
    DECLARE_ML_KEM_VEC_ST(v, rank); \
    DECLARE_ML_KEM_MAT_ST(v, rank); \
    DECLARE_ML_KEM_PUB_ST(v); \
    DECLARE_ML_KEM_PRV_ST(v)
DECLARE_VARIANT_STRUCTS(512, ML_KEM_512_RANK);
DECLARE_VARIANT_STRUCTS(768, ML_KEM_768_RANK);
DECLARE_VARIANT_STRUCTS(1024, ML_KEM_1024_RANK);
#  undef DECLARE_VARIANT_STRUCTS
#  undef DECLARE_ML_KEM_VEC_ST
#  undef DECLARE_ML_KEM_MAT_ST
#  undef DECLARE_ML_KEM_PUB_ST
#  undef DECLARE_ML_KEM_PRV_ST
#  undef ossl_ml_kem_name

/*
 * Variant-specific CBD vector generation helpers, these generate a single CBD
 * scalar.
 */
__owur ossl_ml_kem_cbd_func ossl_ml_kem_cbd_2;
__owur ossl_ml_kem_cbd_func ossl_ml_kem_cbd_3;

/*
 * These functions implement the internals of the variant-specific API.
 *
 * All vectors and matrices are passed as a pointer to their first scalar
 * element, the mctx->vinfo |rank| value determines the dimensions.
 *
 * Where temporary vectors are needed the caller passes an appropriately sized
 * mutable object.
 */
void ossl_ml_kem_encode_public_key(
        uint8_t *out, const scalar *t, const uint8_t rho[ML_KEM_RANDOM_BYTES],
        const ossl_ml_kem_vinfo *vinfo);

void ossl_ml_kem_encode_private_key(
        uint8_t *out, const scalar *s, const scalar *t,
        const uint8_t rho[ML_KEM_RANDOM_BYTES],
        const uint8_t pkhash[ML_KEM_PKHASH_BYTES],
        const uint8_t z[ML_KEM_RANDOM_BYTES],
        const ossl_ml_kem_vinfo *vinfo);

int ossl_ml_kem_parse_public_key(
        const uint8_t *in, scalar *m, scalar *t,
        uint8_t rho[ML_KEM_RANDOM_BYTES],
        uint8_t pkhash[ML_KEM_PKHASH_BYTES],
        EVP_MD_CTX *mdctx, const mctx *ctx);

__owur
int ossl_ml_kem_parse_private_key(
        const uint8_t *in, scalar *m, scalar *s, scalar *t,
        uint8_t rho[ML_KEM_RANDOM_BYTES], uint8_t pkhash[ML_KEM_PKHASH_BYTES],
        uint8_t z[ML_KEM_RANDOM_BYTES],
        EVP_MD_CTX *mdctx, const mctx *ctx);

__owur
int ossl_ml_kem_genkey(
        const uint8_t *seed, uint8_t *pubenc, scalar *m, scalar *s,
        scalar *t, uint8_t rho[ML_KEM_RANDOM_BYTES],
        uint8_t pkhash[ML_KEM_PKHASH_BYTES],
        uint8_t z[ML_KEM_RANDOM_BYTES],
        scalar *tmp, EVP_MD_CTX *mdctx, const mctx *ctx);

int ossl_ml_kem_encap_seed(
        uint8_t *ctext, uint8_t *shared_secret,
        const uint8_t entropy[ML_KEM_RANDOM_BYTES],
        const scalar *m, const scalar *t,
        const uint8_t rho[ML_KEM_RANDOM_BYTES],
        const uint8_t pkhash[ML_KEM_PKHASH_BYTES],
        scalar *tmp1, scalar *tmp2,
        EVP_MD_CTX *mdctx, const mctx *ctx);

__owur
int ossl_ml_kem_decap(
        uint8_t *shared_secret, const uint8_t *ctext, uint8_t *tmp_ctext,
        const scalar *m, const scalar *s, const scalar *t,
        const uint8_t rho[ML_KEM_RANDOM_BYTES],
        const uint8_t pkhash[ML_KEM_PKHASH_BYTES],
        const uint8_t z[ML_KEM_RANDOM_BYTES],
        scalar *tmp1, scalar *tmp2,
        EVP_MD_CTX *mdctx, const mctx *ctx);
