/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef PROV_ML_DSA_COMPOSITE_CODECS_H
#define PROV_ML_DSA_COMPOSITE_CODECS_H
#pragma once

#ifndef OPENSSL_NO_ML_DSA_COMPOSITE
#include <openssl/bio.h>
#include <openssl/e_os2.h>
#include "prov/ml_dsa_composite.h"
#include "prov/provider_ctx.h"

/**
 * @brief Encode the ML-DSA composite public key (mldsaPK || tradPK).
 * @param key the key to encode
 * @param out if not NULL, receives a newly allocated buffer that the caller
 * frees with OPENSSL_free(); if NULL only the length is computed
 * @returns the length in bytes on success, 0 on error
 */
__owur int ossl_ml_dsa_composite_i2d_pubkey(const ML_DSA_COMPOSITE_KEY *key,
    unsigned char **out);

/**
 * @brief Encode the ML-DSA composite private key (mldsaSeed[32] || tradSK).
 * @param key the key to encode
 * @param out if not NULL, receives a newly allocated buffer holding secret
 * key material, which the caller frees (preferably with OPENSSL_clear_free());
 * if NULL only the length is computed
 * @returns the length in bytes on success, 0 on error
 */
__owur int ossl_ml_dsa_composite_i2d_prvkey(const ML_DSA_COMPOSITE_KEY *key,
    unsigned char **out);

/**
 * @brief Print a human-readable description of the ML-DSA composite key.
 * @param out the BIO to print to
 * @param key the key to describe
 * @param selection an OSSL_KEYMGMT_SELECT_* mask choosing what to print
 * @returns 1 on success, 0 on error
 */
__owur int ossl_ml_dsa_composite_key_to_text(BIO *out, const ML_DSA_COMPOSITE_KEY *key,
    int selection);

/**
 * @brief Decode an ML-DSA composite public key from its wire format
 * (mldsaPK || tradPK).
 * @param pk the raw concatenated public key bytes (the BIT STRING content of
 * a SubjectPublicKeyInfo)
 * @param pk_len the number of bytes at pk
 * @param ml_dsa_evp_type EVP_PKEY_ML_DSA_44, EVP_PKEY_ML_DSA_65 or
 * EVP_PKEY_ML_DSA_87, selecting the ML-DSA variant
 * @param classic_alg the classical algorithm: "RSA" or "EC"
 * @param classic_bits the expected classical key size in bits, checked for
 * RSA only
 * @param ec_curve the curve name for EC (for example "P-256"), NULL otherwise
 * @param provctx the provider context, used for the library context
 * @param propq the property query string, may be NULL
 * @returns a newly allocated key, or NULL on failure
 */
__owur ML_DSA_COMPOSITE_KEY *ossl_ml_dsa_composite_d2i_pubkey(const unsigned char *pk,
    int pk_len,
    int ml_dsa_evp_type,
    const char *classic_alg,
    int classic_bits,
    const char *ec_curve,
    PROV_CTX *provctx,
    const char *propq);

/**
 * @brief Decode an ML-DSA composite private key from its wire format
 * (mldsaSeed[32] || tradSK).
 * @param priv the raw concatenated private key bytes
 * @param priv_len the number of bytes at priv
 * @param ml_dsa_evp_type EVP_PKEY_ML_DSA_44, EVP_PKEY_ML_DSA_65 or
 * EVP_PKEY_ML_DSA_87, selecting the ML-DSA variant
 * @param classic_alg the classical algorithm: "RSA" or "EC"
 * @param classic_bits the expected classical key size in bits, checked for
 * RSA only
 * @param ec_curve the curve name for EC (for example "P-256"), NULL otherwise
 * @param provctx the provider context, used for the library context
 * @param propq the property query string, may be NULL
 * @returns a newly allocated key, or NULL on failure
 */
__owur ML_DSA_COMPOSITE_KEY *ossl_ml_dsa_composite_d2i_prvkey(const unsigned char *priv,
    int priv_len,
    int ml_dsa_evp_type,
    const char *classic_alg,
    int classic_bits,
    const char *ec_curve,
    PROV_CTX *provctx,
    const char *propq);

#endif /* OPENSSL_NO_ML_DSA_COMPOSITE */
#endif /* PROV_ML_DSA_COMPOSITE_CODECS_H */
