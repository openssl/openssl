/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HEADER_HQC_KEM_H
#define OPENSSL_HEADER_HQC_KEM_H
#pragma once

#include <openssl/evp.h>

/**
 * @def VEC_SIZE(a, b)
 * @brief Computes the number of elements of size @p b required to store
 *        @p a units.
 *
 * This macro performs ceiling division of @p a by @p b, effectively
 * returning the smallest integer greater than or equal to (a / b).
 * Commonly used to determine the number of words or vector blocks
 * needed to hold a certain number of bits or bytes.
 *
 * @param a Total size (e.g., number of bits or bytes).
 * @param b Unit size (e.g., bits or bytes per word).
 * @return The number of full units of size @p b needed to store @p a.
 */
#define VEC_SIZE(a, b) (((a) / (b)) + ((a) % (b) == 0 ? 0 : 1))

/**
 * @def VEC64_BITMASK(a)
 * @brief Generates a bitmask for the remainder bits of @p a relative to
 *        size 64.
 *
 * This macro produces a mask with the lowest (a % 64) bits set to 1 and
 * the remaining bits cleared. It is typically used to isolate or
 * operate on the trailing bits of a partially filled vector or word.
 *
 * @param a Bit index or size value.
 * @return A bitmask with (a % 64) least significant bits set.
 *
 * NOTE: To maintain constant time operation here we use a bitwise
 * and operation here rather than modulo directly.
 */
#define VEC64_BITMASK(a) ((1ULL << (a & 0x3fULL)) - 1)

typedef enum {
    EVP_PKEY_HQC_KEM_128 = 0,
    EVP_PKEY_HQC_KEM_192 = 1,
    EVP_PKEY_HQC_KEM_256 = 2,
    EVP_PKEY_HQC_KEM_MAX
} hqc_key_type;

typedef struct hqc_variant_info_st {
    hqc_key_type type;
    size_t ek_size;
    size_t dk_size;
    size_t seed_len;
    size_t security_bytes;
    uint32_t security_category;
    uint32_t secbits;
    uint32_t n;
    uint32_t n_mu;
    uint16_t omega;
    uint16_t omega_r;
    uint32_t rej_threshold;
} HQC_VARIANT_INFO;

/*
 * Defines a keypair in the HQC algorithm
 * NOTE: If fields are added to this struct
 * ossl_hqc_kem_key_new and ossl_hqc_kem_dup
 * will need to be updated
 */
typedef struct ossl_hqc_kem_key_st {
    const HQC_VARIANT_INFO *info; /* key size info */
    const void *ctx; /* provider context we came from */
    uint8_t *ek; /* encryption key */
    uint8_t *dk; /* decryption key */
    int selection; /* Presence status of key parts */
} HQC_KEY;

/*
 * Allocate a new empty key
 */
HQC_KEY *ossl_hqc_kem_key_new(const HQC_VARIANT_INFO *info, void *ctx);

/*
 * Duplicate an existing key
 */
HQC_KEY *ossl_hqc_kem_key_dup(const HQC_KEY *src, int selection);

/*
 * Free an HQC_KEY
 */
void ossl_hqc_kem_key_free(HQC_KEY *key);

/*
 * Extracts a specified number of pseudo-random bytes from an extendable-output
 * function (XOF) context.
 */
int ossl_hqc_xof_get_bytes(EVP_MD_CTX *xof_ctx, uint8_t *output, uint32_t output_size);

/*
 * Samples a sparse binary vector deterministically using an
 * extendable-output function (XOF).
 */
int ossl_hqc_sample_xof(EVP_MD_CTX *md_ctx, uint64_t *vec, const HQC_VARIANT_INFO *info);

#endif /* OPENSSL_HEADER_HQC_KEM_H */
