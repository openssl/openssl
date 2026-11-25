/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/safe_math.h"
#include "internal/numbers.h"

OSSL_SAFE_MATH_ADDS(intmax, ossl_intmax_t, OSSL_INTMAX_MIN, OSSL_INTMAX_MAX)
OSSL_SAFE_MATH_NEGS(intmax, ossl_intmax_t, OSSL_INTMAX_MIN)
OSSL_SAFE_MATH_ADDU(uintmax, ossl_uintmax_t, OSSL_UINTMAX_MAX)

/*
 * Without a wider type, add and double quotient/remainder pairs while
 * consuming the bits of b. Remainders stay below the denominator's magnitude:
 * compare against c - y before adding y so that the addition cannot overflow.
 * Signed inputs use negative magnitudes to keep the minimum representable.
 * Quotient magnitudes only increase, so an intermediate quotient overflow
 * means that the final quotient cannot fit either.
 */
ossl_intmax_t ossl_safe_muldiv_signed(ossl_intmax_t a, ossl_intmax_t b,
    ossl_intmax_t c, size_t size, ossl_intmax_t min, ossl_intmax_t max,
    int *err)
{
    int e2, negative;
    ossl_intmax_t q, r, x, y;

    /* A type twice as wide can hold the full product of the inputs. */
    if (size <= sizeof(int32_t) / 2) {
        q = (int32_t)a * (int32_t)b / (int32_t)c;
    } else if (size <= sizeof(int64_t) / 2) {
        q = (int64_t)a * (int64_t)b / (int64_t)c;
#ifdef INT128_MAX
    } else if (size <= sizeof(int128_t) / 2) {
        int128_t result = (int128_t)a * (int128_t)b / (int128_t)c;

        if (ossl_unlikely(result > max)) {
            *err |= 1;
            return max;
        }
        if (ossl_unlikely(result < min)) {
            *err |= 1;
            return min;
        }
        return (ossl_intmax_t)result;
#endif
    } else {
        /* Use negative magnitudes: MIN need never be negated. */
        negative = (a < 0) ^ (b < 0) ^ (c < 0);
        if (a > 0)
            a = -a;
        if (b > 0)
            b = -b;
        if (c > 0)
            c = -c;
        x = c == -1 ? a : -(a / c);
        y = c == -1 ? 0 : a % c;
        q = r = 0;
        e2 = 0;
        while (b != 0) {
            if (b % 2 != 0) {
                q = safe_add_intmax(q, x, &e2);
                if (r <= c - y) {
                    r -= c - y;
                    q = safe_add_intmax(q, -1, &e2);
                } else {
                    r += y;
                }
                if (e2)
                    goto overflow;
            }
            b /= 2;
            if (b == 0)
                break;
            /* Double the current quotient/remainder pair. */
            x = safe_add_intmax(x, x, &e2);
            if (y <= c - y) {
                y -= c - y;
                x = safe_add_intmax(x, -1, &e2);
            } else {
                y += y;
            }
            if (e2)
                goto overflow;
        }
        q = negative ? q : safe_neg_intmax(q, err);
    }
    if (ossl_unlikely(q > max || q < min)) {
        *err |= 1;
        return q < 0 ? min : max;
    }
    return q;

overflow:
    *err |= 1;
    return negative ? min : max;
}

ossl_uintmax_t ossl_safe_muldiv_unsigned(ossl_uintmax_t a, ossl_uintmax_t b,
    ossl_uintmax_t c, size_t size, ossl_uintmax_t max, int *err)
{
    int e2;
    ossl_uintmax_t q, r, x, y;

    if (size <= sizeof(uint32_t) / 2) {
        q = (uint32_t)a * (uint32_t)b / (uint32_t)c;
    } else if (size <= sizeof(uint64_t) / 2) {
        q = (uint64_t)a * (uint64_t)b / (uint64_t)c;
#ifdef UINT128_MAX
    } else if (size <= sizeof(uint128_t) / 2) {
        uint128_t result = (uint128_t)a * (uint128_t)b / (uint128_t)c;

        if (ossl_unlikely(result > max)) {
            *err |= 1;
            return max;
        }
        return (ossl_uintmax_t)result;
#endif
    } else {
        /* Add and double quotient/remainder pairs without a wider type. */
        x = a / c;
        y = a % c;
        q = r = 0;
        e2 = 0;
        while (b != 0) {
            if (b % 2 != 0) {
                q = safe_add_uintmax(q, x, &e2);
                if (r >= c - y) {
                    r -= c - y;
                    q = safe_add_uintmax(q, 1, &e2);
                } else {
                    r += y;
                }
                if (e2)
                    goto overflow;
            }
            b /= 2;
            if (b == 0)
                break;
            /* Double the current quotient/remainder pair. */
            x = safe_add_uintmax(x, x, &e2);
            if (y >= c - y) {
                y -= c - y;
                x = safe_add_uintmax(x, 1, &e2);
            } else {
                y += y;
            }
            if (e2)
                goto overflow;
        }
    }
    if (ossl_unlikely(q > max)) {
        *err |= 1;
        return max;
    }
    return q;

overflow:
    *err |= 1;
    return max;
}
