/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * LibAscon internal header file.
 *
 * Common code (mostly the sponge state permutations and conversion utilities)
 * applied during encryption, decryption and hashing.
 *
 * This file is based on LibAscon (CC0 1.0 license).
 * Original authors: see LibAscon AUTHORS.md file
 */

#ifndef OSSL_CRYPTO_ASCON_INTERNAL_H
# define OSSL_CRYPTO_ASCON_INTERNAL_H
# pragma once

# ifdef __cplusplus
extern "C"
{
# endif

# include "crypto/ascon.h"

# if defined(DEBUG) || defined(MINSIZEREL) || defined(ASCON_WINDOWS)
/* Do not inline in debug mode or when sparing space.
 * Inlining on MSVC creates linking issues: some inlined functions cannot
 * be resolved. */
#  define ASCON_INLINE
# else
#  define ASCON_INLINE inline
# endif

/* Definitions of the initialisation vectors used to initialise the sponge
 * state for AEAD and the two types of hashing functions. */
/**
 * @internal
 * Initialisation vector for the Ascon128 AEAD cipher.
 *
 * Equivalent to the binary concatenation of `k || r || a || b || 0^(160−k)`
 * (from most significant bit on the left to the least significant bit on the
 * right) where:
 *
 * - `k` is the key length in bits: 128 = 0x80
 * - `r` is the AEAD rate in bits: 64 = 0x40
 * - `a` is the amount of rounds during the a-permutation: 12 = 0x0C
 * - `b` is the amount of rounds during the b-permutation: 6 = 0x06
 * - right-padded with zeros until we reach 64 bits of size
 */
# define ASCON_IV_AEAD128  0x80400c0600000000ULL

/**
 * @internal
 * Initialisation vector for the Ascon128a AEAD cipher.
 *
 * Equivalent to the binary concatenation of `k || r || a || b || 0^(160−k)`
 * (from most significant bit on the left to the least significant bit on the
 * right) where:
 *
 * - `k` is the key length in bits: 128 = 0x80
 * - `r` is the AEAD rate in bits: 128 = 0x80
 * - `a` is the amount of rounds during the a-permutation: 12 = 0x0C
 * - `b` is the amount of rounds during the b-permutation: 8 = 0x08
 * - right-padded with zeros until we reach 64 bits of size
 */
# define ASCON_IV_AEAD128a 0x80800c0800000000ULL

/**
 * @internal
 * Initialisation vector for the Ascon80pq AEAD cipher.
 *
 * Equivalent to the binary concatenation of `k || r || a || b || 0^(160−k)`
 * (from most significant bit on the left to the least significant bit on the
 * right) where:
 *
 * - `k` is the key length in bits: 160 = 0xa0
 * - `r` is the AEAD rate in bits: 64 = 0x40
 * - `a` is the amount of rounds during the a-permutation: 12 = 0x0C
 * - `b` is the amount of rounds during the b-permutation: 6 = 0x06
 * - right-padded with zeros until we reach 64 bits of size
 */
# define ASCON_IV_AEAD80pq 0xa0400c0600000000ULL

/**
 * @internal
 * Initialisation vector for the Ascon-Hash hashing function.
 *
 * Equivalent to the binary concatenation of `0^8 || r || a || a − b || h`
 * (from most significant bit on the left to the least significant bit on the
 * right) where:
 *
 * - left-padding with eight zero-bits until we reach 64 bits of size
 * - `r` is the hash rate in bits: 64 = 0x40
 * - `a` is the amount of rounds during the a-permutation: 12 = 0x0C
 * - `b` is the amount of rounds during the b-permutation: 12 = 0x0C
 * - `h` is the digest length in bits expressed as `uint32_t`: 256 = 0x00000100
 */
# define ASCON_IV_HASH     0x00400c0000000100ULL

/**
 * @internal
 * Initialisation vector for the Ascon-Hasha hashing function.
 *
 * Equivalent to the binary concatenation of `0^8 || r || a || a − b || h`
 * (from most significant bit on the left to the least significant bit on the
 * right) where:
 *
 * - left-padding with eight zero-bits until we reach 64 bits of size
 * - `r` is the hash rate in bits: 64 = 0x40
 * - `a` is the amount of rounds during the a-permutation: 12 = 0x0C
 * - `b` is the amount of rounds during the b-permutation: 8 = 0x08
 * - `h` is the digest length in bits expressed as `uint32_t`: 256 = 0x00000100
 */
# define ASCON_IV_HASHa    0x00400c0400000100ULL

/**
 * @internal
 * Initialisation vector for the Ascon-XOF hashing function.
 *
 * Equivalent to the binary concatenation of `0^8 || r || a || a − b || h`
 * (from most significant bit on the left to the least significant bit on the
 * right) where:
 *
 * - left-padding with eight zero-bits until we reach 64 bits of size
 * - `r` is the hash rate in bits: 64 = 0x40
 * - `a` is the amount of rounds during the a-permutation: 12 = 0x0C
 * - `b` is the amount of rounds during the b-permutation: 12 = 0x0C
 * - `h` is the digest length in bits expressed as `uint32_t`: 0 = 0x00000000,
 *   here being zero, because of unlimited length
 */
# define ASCON_IV_XOF      0x00400c0000000000ULL

/**
 * @internal
 * Initialisation vector for the Ascon-XOFa hashing function.
 *
 * Equivalent to the binary concatenation of `0^8 || r || a || a − b || h`
 * (from most significant bit on the left to the least significant bit on the
 * right) where:
 *
 * - left-padding with eight zero-bits until we reach 64 bits of size
 * - `r` is the hash rate in bits: 64 = 0x40
 * - `a` is the amount of rounds during the a-permutation: 12 = 0x0C
 * - `b` is the amount of rounds during the b-permutation: 8 = 0x08
 * - `h` is the digest length in bits expressed as `uint32_t`: 0 = 0x00000000,
 *   here being zero, because of unlimited length
 */
# define ASCON_IV_XOFa     0x00400c0400000000ULL

/**
 * @internal
 * Applies 0b1000...000 right-side padding to a uint8_t[8] array of
 * `bytes` filled elements..
 */
# define PADDING(bytes) (0x80ULL << (56U - 8U * ((unsigned int) (bytes))))

/**
 * @internal
 * Simple minimum out of 2 arguments.
 */
# define MIN(a, b) (((a) < (b)) ? (a) : (b))

/**
 * @internal
 * States used to understand which function of the API was called before
 * for the input assertions and to known if the associated data has been
 * updated or not.
 * @see #ASCON_INPUT_ASSERTS
 */
typedef enum
{
    ASCON_FLOW_CLEANED = 0,
    ASCON_FLOW_HASH_INITIALISED,
    ASCON_FLOW_HASH_UPDATED,
    ASCON_FLOW_AEAD128_80pq_INITIALISED,
    ASCON_FLOW_AEAD128_80pq_ASSOC_DATA_UPDATED,
    ASCON_FLOW_AEAD128_80pq_ENCRYPT_UPDATED,
    ASCON_FLOW_AEAD128_80pq_DECRYPT_UPDATED,
    ASCON_FLOW_AEAD128a_INITIALISED,
    ASCON_FLOW_AEAD128a_ASSOC_DATA_UPDATED,
    ASCON_FLOW_AEAD128a_ENCRYPT_UPDATED,
    ASCON_FLOW_AEAD128a_DECRYPT_UPDATED,
    ASCON_FLOW_HASHA_INITIALISED,
    ASCON_FLOW_HASHA_UPDATED,
} ascon_flow_t;

/** @internal Decodes an uint64_t from a big-endian encoded array of 8 bytes. */
uint64_t
bigendian_decode_u64(const uint8_t* bytes);

/** @internal Decodes an uint64_t from a big-endian encoded array of N bytes.
 * The N bytes are interpreted as the N most significant bytes of the integer,
 * the unspecified bytes are set to 0. */
uint64_t
bigendian_decode_varlen(const uint8_t* bytes, uint_fast8_t n);

/** @internal Encodes an uint64_t into a big-endian encoded array of 8 bytes. */
void
bigendian_encode_u64(uint8_t* bytes, uint64_t value);

/** @internal Encodes an uint64_t into a big-endian encoded array of N bytes.
 * The N most significant bytes of the integer are written into the first N
 * bytes of the array, the unspecified bytes are not written. */
void
bigendian_encode_varlen(uint8_t* bytes, uint64_t x, uint_fast8_t n);

/**
 * @internal
 * Creates a mask to extract the n most significant bytes of a uint64_t.
 *
 * Examples:
 *
 * - `n == 1` returns `FF00 0000 0000 0000` (spaces are just for readability)
 * - `n == 5` returns `FFFF FFFF FF00 0000`
 */
uint64_t
mask_most_signif_bytes(uint_fast8_t n);

/**
 * @internal
 * Performs one permutation round on the Ascon sponge for the given round
 * constant.
 *
 * @warning
 * Do not use directly! Use ascon_permutation_12(), ascon_permutation_8(),
 * ascon_permutation_6() instead.
 *
 * Although this function is never used outside the file where it is
 * defined, it is NOT marked as static, and it is declared globally
 * as it is generally inlined the functions  using it to increase the
 * performance. Inlining static functions into functions used outside their
 * file leads to compilation errors: "error: static function 'ascon_round' is
 * used in an inline function with external linkage
 * [-Werror,-Wstatic-in-inline]".
 */
void
ascon_round(ascon_sponge_t* sponge, uint_fast8_t round_const);

/**
 * @internal
 * Ascon sponge permutation with 12 rounds.
 */
void
ascon_permutation_12(ascon_sponge_t* sponge);

/**
 * @internal
 * Ascon sponge permutation with 8 rounds.
 */
void
ascon_permutation_8(ascon_sponge_t* sponge);

/**
 * @internal
 * Ascon sponge permutation with 6 rounds.
 */
void
ascon_permutation_6(ascon_sponge_t* sponge);

/**
 * @internal
 * Function pointer representing any Ascon sponge permutation.
 */
typedef void (* permutation_fptr)(ascon_sponge_t*);

/**
 * @internal
 * Initialises the AEAD128 or AEAD128a online processing.
 */
void
ascon_aead_init(ascon_aead_ctx_t* ctx,
                const uint8_t* key,
                const uint8_t* nonce,
                uint64_t iv);

/**
 * @internal
 * Handles the finalisation of the associated data before any plaintext or
 * ciphertext is being processed for Ascon128 and Ascon80pq
 *
 * MUST be called ONLY once! In other words, when
 * ctx->bufstate.assoc_data_state == ASCON_FLOW_ASSOC_DATA_FINALISED
 * then it MUST NOT be called anymore.
 *
 * It handles both the case when some or none associated data was given.
 */
void
ascon_aead128_80pq_finalise_assoc_data(ascon_aead_ctx_t* ctx);

/**
 * @internal
 * Generates an arbitrary-length tag from a finalised state for all AEAD
 * ciphers.
 *
 * MUST be called ONLY when all AD and PT/CT is absorbed and state is
 * prepared for tag generation.
 */
void
ascon_aead_generate_tag(ascon_aead_ctx_t* ctx,
                        uint8_t* tag,
                        size_t tag_len);

/**
 * @internal
 * Generates the arbitrary-length tag one chunk at the time and compares
 * it to the tag that came with the ciphertext.
 *
 * MUST be called ONLY when all AD and PT/CT is absorbed and the state is
 * prepared for tag generation. Consumes a fixed amount of stack memory.
 */
bool
ascon_aead_is_tag_valid(ascon_aead_ctx_t* ctx,
                        const uint8_t* expected_tag,
                        size_t expected_tag_len);

/**
 * @internal
 * Function pointer representing the operation run by the
 * buffered_accumulation() when ASCON_RATE bytes ara available in the buffer to
 * be absorbed.
 *
 * @param[in, out] sponge the sponge state to absorb data into.
 * @param[out] data_out optional outgoing data from the sponge, which happens
 *       during encryption or decryption, but not during hashing.
 * @param[in] data_in the input data to be absorbed by the sponge.
 */
typedef void (* absorb_fptr)(ascon_sponge_t* sponge,
                             uint8_t* data_out,
                             const uint8_t* data_in);

/**
 * @internal
 * Buffers any input data into the bufstate and on accumulation of ASCON_RATE
 * bytes, runs the absorb function to process them.
 *
 * This function is used by the AEAD and hash implementations to enable
 * the Init-Update-Final paradigm. The update functions pass the absorb_fptr
 * function specific to them, while this function is the framework handling the
 * accumulation of data until the proper amount is reached.
 *
 * It is not used during the Final step, as that requires padding and special
 * additional operations such as tag/digest generation.
 *
 * @param[in, out] ctx the sponge and the buffer to accumulate data in
 * @param[out] data_out optional output data squeezed from the sponge
 * @param[in] data_in input data to be absorbed by the sponge
 * @param[in] absorb function that handles the absorption and optional squeezing
 *        of the sponge
 * @param[in] data_in_len length of the \p data_in in bytes
 * @param[in] rate buffer size, i.e. number of accumulated bytes after which
 *        an absorption is required
 * @return number of bytes written into \p data_out
 */
size_t
buffered_accumulation(ascon_bufstate_t* ctx,
                      uint8_t* data_out,
                      const uint8_t* data_in,
                      absorb_fptr absorb,
                      size_t data_in_len,
                      uint8_t rate);

# ifdef __cplusplus
}
# endif

# endif  /* OSSL_CRYPTO_ASCON_INTERNAL_H */

