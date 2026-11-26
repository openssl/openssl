/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_MLX_KEM_H
#define OSSL_MLX_KEM_H
#pragma once

#include <openssl/evp.h>
#include <openssl/ml_kem.h>
#include <crypto/ml_kem.h>
#include <crypto/ecx.h>
#include "prov/provider_ctx.h"

#define MLX_DEFAULT_SEED_BYTES 32
#define MLX_MAX_SEED_BYTES 64
#define MLX_MAX_ENCAP_SEED_BYTES 160
#define MLX_MAX_COMBINED_SHARED_SECRET_BYTES 128
#define MLX_C2PRI_SHA3_256_BYTES 32

/*
 * Internal combiner selector.  CONCAT denotes the direct component-secret
 * concatenation used by the TLS hybrid groups (RFC 10024, Section 4.3).
 * C2PRI denotes C2PRICombiner from Section 5.1.3 of
 * draft-irtf-cfrg-hybrid-kems, as instantiated by X-Wing.
 */
typedef enum {
    MLX_COMBINER_CONCAT = 0,
    MLX_COMBINER_C2PRI
} MLX_COMBINER;

/*
 * CG and CK are the framework names from draft-irtf-cfrg-hybrid-kems:
 * Section 5.5 defines CG as the C2PRI combiner with a nominal group, and
 * Section 5.6 defines CK as the C2PRI combiner with a traditional KEM.
 * TLS_CONCAT is an internal name for the TLS hybrid groups that concatenate
 * their component secrets before passing them to the TLS key schedule.
 */
typedef enum {
    MLX_FRAMEWORK_TLS_CONCAT = 0,
    MLX_FRAMEWORK_CG,
    MLX_FRAMEWORK_CK
} MLX_FRAMEWORK;

typedef struct ecdh_vinfo_st {
    const char *algorithm_name;
    const char *group_name;
    size_t pubkey_bytes;
    size_t prvkey_bytes;
    size_t shsec_bytes;
    int ml_kem_slot;
    int ml_kem_variant;
    MLX_COMBINER combiner;
    MLX_FRAMEWORK framework;
    const unsigned char *label;
    size_t label_len;
    const char *kdf_name;
    const char *prg_name;
    size_t seed_bytes;
    size_t traditional_seed_bytes;
    size_t encap_seed_bytes;
    size_t hybrid_shsec_bytes;
} ECDH_VINFO;

typedef struct mlx_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const ML_KEM_VINFO *minfo;
    const ECDH_VINFO *xinfo;
    EVP_PKEY *mkey;
    EVP_PKEY *xkey;
    unsigned int variant;
    unsigned int state;
    unsigned char seed[MLX_MAX_SEED_BYTES];
    unsigned int has_seed : 1;
} MLX_KEY;

#define MLX_HAVE_NOKEYS 0
#define MLX_HAVE_PUBKEY 1
#define MLX_HAVE_PRVKEY 2

/* Indices in the MLX variant table. */
#define MLX_VARIANT_XWING 7

/* Both key parts have whatever the ML-KEM component has */
#define mlx_kem_have_pubkey(key) ((key)->state > 0)
#define mlx_kem_have_prvkey(key) ((key)->state > 1)
#define mlx_kem_uses_hybrid_seed(key) \
    ((key)->xinfo->framework == MLX_FRAMEWORK_CG)

/* Helpers shared with the X-Wing encoder/decoder implementation. */
/**
 * @brief Allocate an empty MLX key for the selected variant.
 *
 * @param provctx Provider context.
 * @param variant MLX variant table index.
 * @param propq Optional property query, copied into the new key.
 * @returns The new key, or NULL on failure. The caller owns the key.
 */
MLX_KEY *ossl_mlx_key_new(PROV_CTX *provctx, unsigned int variant,
    const char *propq);
/**
 * @brief Free an MLX key and clear its private seed.
 *
 * @param vkey Key to free, or NULL.
 */
void ossl_mlx_key_free(void *vkey);
/**
 * @brief Derive and store an MLX key pair from a private seed.
 *
 * @param key Empty key to populate.
 * @param seed Private seed input.
 * @param seedlen Seed length required by the selected variant.
 * @returns 1 on success, or 0 on failure.
 */
int ossl_mlx_set_seed(MLX_KEY *key, const unsigned char *seed,
    size_t seedlen);
/**
 * @brief Import the concatenated MLX public key.
 *
 * @param key Empty key to populate.
 * @param pub Encoded public key input.
 * @param publen Length of the public key input.
 * @returns 1 on success, or 0 on failure.
 */
int ossl_mlx_set_public_key(MLX_KEY *key, const unsigned char *pub,
    size_t publen);
/**
 * @brief Encode the concatenated MLX public key into a caller-provided buffer.
 *
 * @param key Key containing the public components.
 * @param out Output buffer.
 * @param outlen Buffer length, which must equal the encoded public key length.
 * @returns 1 on success, or 0 on failure.
 */
int ossl_mlx_encode_public_key(const MLX_KEY *key, unsigned char *out,
    size_t outlen);
/**
 * @brief Copy the stored MLX private seed into a caller-provided buffer.
 *
 * @param key Key containing the private seed.
 * @param out Output buffer.
 * @param outlen Buffer length, which must equal the private seed length.
 * @returns 1 on success, or 0 on failure.
 */
int ossl_mlx_encode_seed(const MLX_KEY *key, unsigned char *out,
    size_t outlen);

#endif
