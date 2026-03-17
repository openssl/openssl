/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include "crypto/hqc_kem.h"

HQC_KEY *ossl_hqc_kem_key_new(const HQC_VARIANT_INFO *info, void *ctx)
{
    HQC_KEY *new = OPENSSL_zalloc(sizeof(HQC_KEY));

    if (new != NULL) {
        new->ctx = ctx;
        new->info = info;
        new->ek = OPENSSL_malloc(new->info->ek_size);
        new->dk = OPENSSL_secure_malloc(new->info->dk_size);
        if (new->ek == NULL || new->dk == NULL) {
            OPENSSL_free(new->ek);
            OPENSSL_secure_free(new->dk);
            OPENSSL_free(new);
            new = NULL;
        }
    }
    return new;
}

HQC_KEY *ossl_hqc_kem_key_dup(const HQC_KEY *src, int selection)
{
    HQC_KEY *dup = OPENSSL_zalloc(sizeof(HQC_KEY));

    if (dup != NULL) {
        dup->ctx = src->ctx;
        dup->info = src->info;
        dup->ek = OPENSSL_malloc(src->info->ek_size);
        dup->dk = OPENSSL_secure_malloc(src->info->dk_size);
        if (dup->ek == NULL || dup->dk == NULL) {
            OPENSSL_free(dup->ek);
            OPENSSL_secure_free(dup->dk);
            OPENSSL_free(dup);
            dup = NULL;
        }
        memcpy(dup->ek, src->ek, src->info->ek_size);
        memcpy(dup->dk, src->dk, src->info->dk_size);
        dup->selection = src->selection;
    }
    return dup;
}

void ossl_hqc_kem_key_free(HQC_KEY *key)
{
    if (key == NULL)
        return;
    OPENSSL_free(key->ek);
    OPENSSL_secure_free(key->dk);
    OPENSSL_free(key);
}

/**
 * @brief Extracts a specified number of bytes from an extendable-output
 *        function (XOF) context.
 *
 * This function retrieves pseudorandom bytes from an initialized XOF
 * digest context (e.g., SHAKE256) using the OpenSSL provider API. It
 * ensures that the requested number of bytes is produced even if the
 * total output size is not aligned to 64-bit boundaries.
 *
 * @param xof_ctx
 *   Pointer to the @c EVP_MD_CTX XOF context from which bytes are
 *   squeezed. Must be properly initialized with a SHAKE-based digest.
 *
 * @param output
 *   Pointer to the destination buffer that will receive the generated
 *   pseudorandom bytes.
 *
 * @param output_size
 *   Number of bytes to extract from the XOF stream.
 *
 * @return
 *   Returns 1 on success, or 0 if any call to
 *   @c EVP_DigestSqueeze() fails.
 *
 * @details
 *   - The function first extracts all full 64-bit blocks directly into
 *     the output buffer.
 *   - If @p output_size is not a multiple of 8, an additional 64-bit
 *     block is squeezed into a temporary buffer, and the remaining
 *     bytes are copied to complete the output.
 *   - This design ensures full coverage of the requested output size
 *     without alignment or padding issues.
 *
 * @note
 *   - The @p xof_ctx must be configured for a XOF-capable digest
 *     (e.g., SHAKE128 or SHAKE256).
 *   - This function maintains XOF state continuity — subsequent calls
 *     continue generating the next bytes in the pseudorandom sequence.
 *   - Commonly used in HQC for deterministic sampling and key material
 *     generation.
 */
int ossl_hqc_xof_get_bytes(EVP_MD_CTX *xof_ctx, uint8_t *output, uint32_t output_size)
{
    const uint8_t bsize = sizeof(uint64_t);
    const uint8_t remainder = output_size % bsize;
    uint8_t tmp[sizeof(uint64_t)];

    if (!EVP_DigestSqueeze(xof_ctx, output, output_size - remainder))
        return 0;
    if (remainder != 0) {
        if (!EVP_DigestSqueeze(xof_ctx, tmp, bsize))
            return 0;
        output += output_size - remainder;
        for (uint8_t i = 0; i < remainder; i++) {
            output[i] = tmp[i];
        }
    }

    return 1;
}

/**
 * @brief Performs modular reduction using Barrett reduction for HQC
 *        arithmetic operations.
 *
 * This function computes the value of @p x modulo @c info->n using
 * Barrett reduction, a fast method for modular reduction that avoids
 * expensive division operations. It is used internally within the HQC
 * (Hamming Quasi-Cyclic) cryptographic routines for efficient modular
 * arithmetic.
 *
 * @param x
 *   The input value to be reduced.
 *
 * @param info
 *   Pointer to an @c HQC_VARIANT_INFO structure containing variant-
 *   specific parameters:
 *   - @c n     : The modulus.
 *   - @c n_mu  : The precomputed Barrett constant
 *                (⌊2³² / n⌋ or a scaled equivalent).
 *
 * @return
 *   The reduced value @c r such that @c 0 ≤ r < info->n.
 *
 * @details
 *   - Computes an approximate quotient @c q = ⌊(x * n_mu) / 2³²⌋.
 *   - Calculates the provisional remainder @c r = x − q × n.
 *   - Conditionally subtracts @c n if @c r ≥ n to ensure the result is
 *     within the correct range.
 *   - Uses bitwise operations instead of branching for constant-time
 *     behavior.
 *
 * @note
 *   - The computation is designed to be constant-time, avoiding
 *     conditional branches that could leak timing information.
 *   - The correctness of the reduction depends on the accuracy of the
 *     precomputed @c n_mu parameter for the given HQC variant.
 *   - This function is typically used in finite-field or polynomial
 *     arithmetic within HQC encryption and key encapsulation routines.
 */
static uint32_t barrett_reduce(uint32_t x, const HQC_VARIANT_INFO *info)
{
    uint64_t q = ((uint64_t)x * info->n_mu) >> 32;
    uint32_t r = x - (uint32_t)(q * info->n);
    uint32_t reduce_flag = (((r - info->n) >> 31) ^ 1);
    /*
     * Windows get all cranky about trying to negate a uint32_t
     * Tell it to chill out with some casting
     */
    uint32_t mask = (uint32_t)(-((int32_t)reduce_flag));
    r -= mask & info->n;
    return r;
}

/**
 * @brief Samples a sparse binary vector deterministically using an
 *        extendable-output function (XOF).
 *
 * This function generates a binary vector with exactly
 * @c info->omega bits set, according to the HQC (Hamming Quasi-Cyclic)
 * cryptographic specification. The sampling is performed using a
 * pseudorandom byte stream derived from the provided XOF context.
 * Duplicate positions are rejected to ensure unique bit indices.
 *
 * @param md_ctx
 *   Pointer to the initialized @c EVP_MD_CTX representing the XOF
 *   context (e.g., SHAKE256). Used to generate pseudorandom bytes.
 *
 * @param vec
 *   Pointer to the output vector buffer where sampled bits will be set.
 *   Must be large enough to store @c VEC_SIZE(info->n, 64) 64-bit
 *   blocks.
 *
 * @param info
 *   Pointer to an @c HQC_VARIANT_INFO structure providing variant-
 *   specific parameters:
 *   - @c omega        : Number of bits to set in the vector.
 *   - @c omega_r      : Support vector size.
 *   - @c n            : Modulus size in bits.
 *   - @c rej_threshold: Rejection threshold for candidate values.
 *
 * @return
 *   Returns 1 on success, or 0 on failure (e.g., when random byte
 *   generation via @c ossl_hqc_xof_get_bytes() fails).
 *
 * @details
 *   - Random 24-bit integers are extracted from the XOF stream and
 *     reduced modulo @c n using @c barrett_reduce().
 *   - Duplicate indices are discarded to ensure uniqueness among
 *     selected bit positions.
 *   - For each valid index, the bit position and corresponding 64-bit
 *     word offset are recorded in lookup tables.
 *   - The final binary vector is assembled using bitwise OR operations
 *     across all selected indices.
 *   - The procedure avoids branching where possible to maintain
 *     constant-time behavior.
 *
 * @note
 *   - The caller must ensure that @c md_ctx has been properly seeded
 *     before calling this function.
 *   - The @c vec buffer is modified in place and should be zeroed
 *     before use if accumulation of bits is not intended.
 *   - This function is critical for HQC's error vector and random
 *     support generation steps, where cryptographic uniformity and
 *     reproducibility are required.
 */
int ossl_hqc_sample_xof(EVP_MD_CTX *md_ctx, uint64_t *vec, const HQC_VARIANT_INFO *info)
{
    uint32_t *support;
    size_t random_bytes_size = 3 * info->omega;
    uint8_t *rand_bytes;
    uint8_t inc;
    size_t i, j, k;
    uint32_t *index_tab;
    uint64_t *bit_tab;
    int32_t pos;
    uint64_t val;
    uint32_t tmp;
    int val1;
    uint64_t mask;
    int ret = 0;

    support = OPENSSL_zalloc(info->omega_r * sizeof(uint32_t));
    rand_bytes = OPENSSL_zalloc(info->omega * 3);
    index_tab = OPENSSL_zalloc(info->omega_r * sizeof(uint32_t));
    bit_tab = OPENSSL_zalloc(info->omega_r * sizeof(uint64_t));

    if (support == NULL || rand_bytes == NULL || index_tab == NULL || bit_tab == NULL)
        goto err;

    i = 0;
    j = random_bytes_size;
    while (i < info->omega) {
        do {
            if (j == random_bytes_size) {
                if (!ossl_hqc_xof_get_bytes(md_ctx, rand_bytes, (uint32_t)random_bytes_size))
                    return 0;
                j = 0;
            }
            support[i] = ((uint32_t)rand_bytes[j++]) << 16;
            support[i] |= ((uint32_t)rand_bytes[j++]) << 8;
            support[i] |= rand_bytes[j++];
        } while (support[i] >= info->rej_threshold);

        support[i] = barrett_reduce(support[i], info);

        inc = 1;
        for (k = 0; k < i; k++) {
            if (support[k] == support[i])
                inc = 0;
        }
        i += inc;
    }

    for (i = 0; i < info->omega; i++) {
        index_tab[i] = support[i] >> 6;
        pos = support[i] & 0x3f;
        bit_tab[i] = ((uint64_t)1) << pos;
    }

    val = 0;
    for (i = 0; i < VEC_SIZE(info->n, 64); i++) {
        val = 0;
        for (j = 0; j < info->omega; j++) {
            tmp = (uint32_t)i - index_tab[j];
            val1 = 1 ^ ((tmp | (uint32_t)(-(int32_t)tmp)) >> 31);
            mask = -val1;
            val |= (bit_tab[j] & mask);
        }
        vec[i] |= val;
    }
    ret = 1;
err:
    OPENSSL_free(support);
    OPENSSL_free(rand_bytes);
    OPENSSL_free(index_tab);
    OPENSSL_free(bit_tab);
    return ret;
}
