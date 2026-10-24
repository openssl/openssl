/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_INTERNAL_SECRET_CHECK_H)
#define OSSL_INTERNAL_SECRET_CHECK_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/bn.h>

/**
 * @def OSSL_SECRET_CHECK_MIN_LEN
 * Smallest secret length, in bytes, that ossl_secret_bytes_check() tests.
 * Shorter inputs pass without being tested: at those widths the tests'
 * false-positive rates are too high to be useful, and a domain that
 * small is not a security claim.
 */
#define OSSL_SECRET_CHECK_MIN_LEN 16

/**
 * @def OSSL_SECRET_CHECK_MIN_WIDTH_BITS
 * Smallest domain width, in bits, for which the magnitude test is applied.
 * Below this the domain is too small for the test to be meaningful and it
 * is skipped.
 */
#define OSSL_SECRET_CHECK_MIN_WIDTH_BITS 128

/**
 * @brief Check that a fixed-width secret encoding is not evidently
 * something other than key material.
 *
 * Rejects encodings that show structure key material does not have and
 * that an identifier, string, handle, counter or fill pattern mistaken
 * for a key does have. The tests are:
 *
 * - the top 64 bits of the width_bits-wide field are zero, reading it
 *   as either a big-endian or a little-endian integer (skipped when
 *   width_bits is 0 or below OSSL_SECRET_CHECK_MIN_WIDTH_BITS)
 * - at least len / 4 of the bytes are zero
 * - every byte is printable ASCII (0x20 to 0x7E)
 * - fewer than len / 4 distinct byte values occur, with the demand
 *   capped at 64 since only 256 byte values exist
 *
 * Any one of them rejects. A uniformly chosen 32-byte value trips one of
 * them with probability about 2^-40; wider values far less often. The
 * tests detect integers, strings and padded or shifted handles; they do
 * not detect hashed or PRNG-derived values, nor an opaque full-width
 * blob, and they make no claim about randomness.
 *
 * Runs in time independent of the contents of buf. Only len and
 * width_bits affect timing.
 *
 * @param buf the secret, padded to its full width
 * @param len the number of bytes at buf; below OSSL_SECRET_CHECK_MIN_LEN
 *            no test is applied
 * @param width_bits the bit width of the domain the value at buf was
 *                   drawn from (the group order for an EC scalar, the
 *                   modulus for an RSA exponent, and so on), with
 *                   len == (width_bits + 7) / 8; or 0 when buf is an
 *                   octet-string secret such as a seed, in which case
 *                   the magnitude test is skipped
 * @returns 1 if the encoding passes every test, 0 if it is rejected
 */
int ossl_secret_bytes_check(const uint8_t *buf, size_t len, size_t width_bits);

/**
 * @brief Check that a secret integer is not evidently something other
 * than key material.
 *
 * Encodes secret big-endian padded to (width_bits + 7) / 8 bytes and
 * applies ossl_secret_bytes_check() to the result.
 *
 * @param secret the integer to check
 * @param width_bits the bit width of the domain secret was drawn from;
 *                   must be nonzero
 * @returns 1 if the encoding passes every test, 0 if it is rejected, does
 *          not fit the width, or on allocation failure
 */
int ossl_secret_bn_check(const BIGNUM *secret, size_t width_bits);

/**
 * @brief Report whether callers should apply the secret check.
 *
 * The initial value is 0 when the library is configured with
 * no-secret-check and 1 otherwise; CRYPTO_secret_check_enable() and
 * CRYPTO_secret_check_disable() change it. The check functions
 * themselves are unconditional; this switch is consulted by the code
 * that decides whether to call them. When the value cannot be read it
 * is reported as enabled.
 *
 * @returns 1 if the check is enabled, 0 if it is disabled
 */
int ossl_secret_check_enabled(void);

#endif /* !defined(OSSL_INTERNAL_SECRET_CHECK_H) */
