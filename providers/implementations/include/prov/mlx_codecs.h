/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").
 */

#ifndef PROV_MLX_CODECS_H
#define PROV_MLX_CODECS_H
#pragma once

#include "prov/mlx_kem.h"

/**
 * @brief Decode a SubjectPublicKeyInfo into a newly allocated MLX public key.
 *
 * @param der DER input buffer.
 * @param derlen Length of the DER input.
 * @param variant MLX variant table index.
 * @param provctx Provider context.
 * @param propq Optional property query, copied into the new key.
 * @returns The decoded key, or NULL on failure. The caller owns the key.
 */
MLX_KEY *ossl_mlx_d2i_PUBKEY(const unsigned char *der, long derlen,
    unsigned int variant, PROV_CTX *provctx, const char *propq);
/**
 * @brief Decode a PrivateKeyInfo into a newly allocated MLX key pair.
 *
 * @param der DER input buffer.
 * @param derlen Length of the DER input.
 * @param variant MLX variant table index.
 * @param provctx Provider context.
 * @param propq Optional property query, copied into the new key.
 * @returns The decoded key, or NULL on failure. The caller owns the key.
 */
MLX_KEY *ossl_mlx_d2i_PKCS8(const unsigned char *der, long derlen,
    unsigned int variant, PROV_CTX *provctx, const char *propq);
/**
 * @brief Encode the MLX raw public key into an allocated buffer.
 *
 * @param key Key to encode.
 * @param out Receives the buffer, which the caller must free.
 * @returns The encoded length, or 0 on failure.
 */
int ossl_mlx_i2d_pubkey(const MLX_KEY *key, unsigned char **out);
/**
 * @brief Encode the MLX private seed into an allocated buffer.
 *
 * @param key Key to encode.
 * @param out Receives the buffer, which the caller must free.
 * @returns The encoded length, or 0 on failure.
 */
int ossl_mlx_i2d_prvkey(const MLX_KEY *key, unsigned char **out);
/**
 * @brief Write a human-readable representation of an MLX key.
 *
 * @param out Output BIO.
 * @param key Key to print.
 * @param selection Key components requested by the encoder.
 * @returns 1 on success, or 0 on failure.
 */
int ossl_mlx_key_to_text(BIO *out, const MLX_KEY *key, int selection);

#endif
