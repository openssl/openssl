/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/err.h>
#include "internal/common.h"
#include "internal/constant_time.h"
#include "internal/secret_check.h"

/* Number of leading bits of the field that must not all be zero */
#define MAGNITUDE_BITS 72

/* Largest number of distinct byte values the distinct-value test demands */
#define DISTINCT_THRESHOLD_MAX 64

/* Smallest number of zero bytes the zero-byte test demands */
#define ZERO_THRESHOLD_MIN 16

/* Shortest period the repetition test looks for; it doubles up to len / 2 */
#define PERIOD_MIN 4
#define PERIOD_MAX 32

/* Fewest byte comparisons a period is tested with */
#define PERIOD_MIN_COMPARED 9

/*
 * OR of the top nbits valid bits of the width_bits-wide field held in
 * buf, read big-endian when little_endian is 0 and little-endian
 * otherwise. The pad bits in the most significant byte are ignored.
 */
static uint8_t top_bits_or(const uint8_t *buf, size_t len, size_t width_bits,
    size_t nbits, int little_endian)
{
    size_t pad = len * 8 - width_bits;
    size_t remaining = nbits;
    uint8_t acc = 0;
    size_t i;

    for (i = 0; i < len && remaining > 0; i++) {
        size_t avail = (i == 0) ? 8 - pad : 8;
        size_t take = (remaining < avail) ? remaining : avail;
        uint8_t mask = (i == 0) ? (uint8_t)(0xFFU >> pad) : 0xFF;
        size_t idx = little_endian ? len - 1 - i : i;

        mask &= (uint8_t)(0xFFU << (avail - take));
        acc |= buf[idx] & mask;
        remaining -= take;
    }
    return acc;
}

/* Number of zero bytes in buf */
static size_t count_zero_bytes(const uint8_t *buf, size_t len)
{
    size_t zeros = 0;
    size_t i;

    for (i = 0; i < len; i++)
        zeros += constant_time_is_zero_8(buf[i]) & 1;
    return zeros;
}

/* Number of distinct byte values in buf */
static size_t count_distinct_bytes(const uint8_t *buf, size_t len)
{
    size_t distinct = 0;
    size_t i, j;

    for (i = 0; i < len; i++) {
        uint8_t seen = 0;

        for (j = 0; j < i; j++)
            seen |= constant_time_eq_8(buf[i], buf[j]);
        distinct += (uint8_t)(~seen) & 1;
    }
    return distinct;
}

/* 0xFF if every byte of buf equals the byte period bytes before it, 0 otherwise */
static uint8_t has_period(const uint8_t *buf, size_t len, size_t period)
{
    uint8_t periodic = 0xFF;
    size_t i;

    for (i = period; i < len; i++)
        periodic &= constant_time_eq_8(buf[i], buf[i - period]);
    return periodic;
}

int ossl_secret_bytes_check(const uint8_t *buf, size_t len, size_t width_bits)
{
    size_t zero_threshold = len / 4;
    size_t distinct_threshold = len / 4;
    size_t field_bits = width_bits != 0 ? width_bits : len * 8;
    size_t small = 0, many_zeros, few_distinct, repeated;
    size_t period, reject;

    /* len, the thresholds and width_bits are public; branching on them is safe */
    if (zero_threshold < ZERO_THRESHOLD_MIN)
        zero_threshold = ZERO_THRESHOLD_MIN;
    if (distinct_threshold > DISTINCT_THRESHOLD_MAX)
        distinct_threshold = DISTINCT_THRESHOLD_MAX;

    if (!ossl_assert(width_bits == 0 || (width_bits + 7) / 8 == len)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (field_bits >= OSSL_SECRET_CHECK_MIN_WIDTH_BITS)
        small = constant_time_is_zero_s(
                    top_bits_or(buf, len, field_bits, MAGNITUDE_BITS, 0))
            | constant_time_is_zero_s(
                top_bits_or(buf, len, field_bits, MAGNITUDE_BITS, 1));

    many_zeros = constant_time_ge_s(count_zero_bytes(buf, len),
        zero_threshold);
    few_distinct = constant_time_lt_s(count_distinct_bytes(buf, len),
        distinct_threshold);
    repeated = 0;
    for (period = PERIOD_MIN; period <= PERIOD_MAX && period <= len / 2;
        period *= 2)
        if (len - period >= PERIOD_MIN_COMPARED)
            repeated |= constant_time_eq_s(has_period(buf, len, period), 0xFF);

    reject = small | many_zeros | few_distinct | repeated;
    return (int)(~reject & 1);
}

int ossl_secret_bn_check(const BIGNUM *secret, size_t width_bits)
{
    size_t len = (width_bits + 7) / 8;
    uint8_t *buf;
    int ret = 0;

    if (!ossl_assert(width_bits != 0)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if ((buf = OPENSSL_malloc(len)) == NULL)
        return 0;
    if (BN_bn2binpad(secret, buf, (int)len) == (int)len)
        ret = ossl_secret_bytes_check(buf, len, width_bits);
    OPENSSL_clear_free(buf, len);
    return ret;
}

#if defined(OPENSSL_NO_SECRET_CHECK)
static int secret_check_enabled = 0;
#else
static int secret_check_enabled = 1;
#endif /* defined(OPENSSL_NO_SECRET_CHECK) */

int ossl_secret_check_enabled(void)
{
    int enabled;

    if (!CRYPTO_atomic_load_int(&secret_check_enabled, &enabled, NULL))
        return 1;
    return enabled;
}

int ossl_secret_check_set_enabled(int enabled)
{
    return CRYPTO_atomic_store_int(&secret_check_enabled, enabled != 0, NULL);
}
