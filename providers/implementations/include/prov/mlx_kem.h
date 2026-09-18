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

typedef enum {
    MLX_COMBINER_CONCAT = 0,
    MLX_COMBINER_C2PRI
} MLX_COMBINER;

typedef enum {
    MLX_FRAMEWORK_LEGACY_TLS = 0,
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
    unsigned int state;
    unsigned char seed[MLX_MAX_SEED_BYTES];
    unsigned int has_seed : 1;
} MLX_KEY;

#define MLX_HAVE_NOKEYS 0
#define MLX_HAVE_PUBKEY 1
#define MLX_HAVE_PRVKEY 2

/* Indices in the MLX variant table. */
#define MLX_VARIANT_XWING 5

/* Both key parts have whatever the ML-KEM component has */
#define mlx_kem_have_pubkey(key) ((key)->state > 0)
#define mlx_kem_have_prvkey(key) ((key)->state > 1)

/* Helpers shared with the X-Wing encoder/decoder implementation. */
MLX_KEY *ossl_mlx_key_new(PROV_CTX *provctx, unsigned int variant,
    const char *propq);
void ossl_mlx_key_free(void *vkey);
int ossl_mlx_set_seed(MLX_KEY *key, const unsigned char *seed,
    size_t seedlen);
int ossl_mlx_set_public_key(MLX_KEY *key, const unsigned char *pub,
    size_t publen);
int ossl_mlx_encode_public_key(const MLX_KEY *key, unsigned char *out,
    size_t outlen);
int ossl_mlx_encode_seed(const MLX_KEY *key, unsigned char *out,
    size_t outlen);

#endif
