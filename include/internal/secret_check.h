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
 * @def OSSL_SECRET_CHECK_MIN_WIDTH_BITS
 * Smallest field width, in bits, for which the magnitude test is applied.
 */
#define OSSL_SECRET_CHECK_MIN_WIDTH_BITS 96

/**
 * @brief Check that a fixed-width secret encoding is not evidently
 * something other than key material.
 *
 * Rejects encodings that show structure key material does not have and
 * that an identifier, string, handle, counter or fill pattern mistaken
 * for a key does have. The tests are:
 *
 * - the top 72 bits of the field are zero, reading it as either a
 *   big-endian or a little-endian integer; the field is width_bits wide,
 *   or len * 8 bits when width_bits is 0; skipped when the field is
 *   narrower than OSSL_SECRET_CHECK_MIN_WIDTH_BITS
 * - at least len / 4 of the bytes are zero, and never fewer than 16
 * - fewer than len / 4 distinct byte values occur, capped at 64
 *   distinct values
 * - the bytes repeat with a period of 4, 8, 16 or 32, up to len / 2,
 *   tested only where at least 9 bytes are compared
 *
 * Any one of them rejects. A uniformly chosen value of 13 bytes or more
 * trips one of them with probability below 2^-70. The tests detect
 * small integers, padded or shifted handles and fill patterns; they do
 * not detect text that fills the field, hashed or PRNG-derived values,
 * nor an opaque full-width blob, and they make no claim about
 * randomness.
 *
 * Runs in time independent of the contents of buf. Only len and
 * width_bits affect timing.
 *
 * @param buf the secret, padded to its full width
 * @param len the number of bytes at buf
 * @param width_bits the bit width of the integer domain buf encodes,
 *                   with len == (width_bits + 7) / 8; 0 for an octet
 *                   string
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
