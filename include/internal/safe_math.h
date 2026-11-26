/*
 * Copyright 2021-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_SAFE_MATH_H
#define OSSL_INTERNAL_SAFE_MATH_H
#pragma once

#include <openssl/e_os2.h> /* For 'ossl_inline' */
#include "internal/common.h" /* For ossl_likely and ossl_unlikely */

#ifndef OPENSSL_NO_BUILTIN_OVERFLOW_CHECKING
#ifdef __has_builtin
#define has(func) __has_builtin(func)
#elif defined(__GNUC__)
#if __GNUC__ > 5
#define has(func) 1
#endif
#endif
#endif /* OPENSSL_NO_BUILTIN_OVERFLOW_CHECKING */

#ifndef has
#define has(func) 0
#endif

/*
 * Safe addition helpers
 */
#if has(__builtin_add_overflow)
#define OSSL_SAFE_MATH_ADDS(type_name, type, min, max)               \
    static ossl_inline ossl_unused type safe_add_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        type r;                                                      \
                                                                     \
        if (ossl_likely(!__builtin_add_overflow(a, b, &r)))          \
            return r;                                                \
        *err |= 1;                                                   \
        return a < 0 ? min : max;                                    \
    }

#define OSSL_SAFE_MATH_ADDU(type_name, type, max)                    \
    static ossl_inline ossl_unused type safe_add_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        type r;                                                      \
                                                                     \
        if (ossl_likely(!__builtin_add_overflow(a, b, &r)))          \
            return r;                                                \
        *err |= 1;                                                   \
        return a + b;                                                \
    }

#else /* has(__builtin_add_overflow) */
#define OSSL_SAFE_MATH_ADDS(type_name, type, min, max)               \
    static ossl_inline ossl_unused type safe_add_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        if (ossl_likely((a < 0) ^ (b < 0)                            \
                || (a > 0 && b <= max - a)                           \
                || (a < 0 && b >= min - a)                           \
                || a == 0))                                          \
            return a + b;                                            \
        *err |= 1;                                                   \
        return a < 0 ? min : max;                                    \
    }

#define OSSL_SAFE_MATH_ADDU(type_name, type, max)                    \
    static ossl_inline ossl_unused type safe_add_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        if (ossl_unlikely(b > max - a))                              \
            *err |= 1;                                               \
        return a + b;                                                \
    }
#endif /* has(__builtin_add_overflow) */

/*
 * Safe subtraction helpers
 */
#if has(__builtin_sub_overflow)
#define OSSL_SAFE_MATH_SUBS(type_name, type, min, max)               \
    static ossl_inline ossl_unused type safe_sub_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        type r;                                                      \
                                                                     \
        if (ossl_likely(!__builtin_sub_overflow(a, b, &r)))          \
            return r;                                                \
        *err |= 1;                                                   \
        return a < 0 ? min : max;                                    \
    }

#else /* has(__builtin_sub_overflow) */
#define OSSL_SAFE_MATH_SUBS(type_name, type, min, max)               \
    static ossl_inline ossl_unused type safe_sub_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        if (ossl_likely(!((a < 0) ^ (b < 0))                         \
                || (b > 0 && a >= min + b)                           \
                || (b < 0 && a <= max + b)                           \
                || b == 0))                                          \
            return a - b;                                            \
        *err |= 1;                                                   \
        return a < 0 ? min : max;                                    \
    }

#endif /* has(__builtin_sub_overflow) */

#define OSSL_SAFE_MATH_SUBU(type_name, type)                         \
    static ossl_inline ossl_unused type safe_sub_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        if (ossl_unlikely(b > a))                                    \
            *err |= 1;                                               \
        return a - b;                                                \
    }

/*
 * Safe multiplication helpers
 */
#if has(__builtin_mul_overflow)
#define OSSL_SAFE_MATH_MULS(type_name, type, min, max)               \
    static ossl_inline ossl_unused type safe_mul_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        type r;                                                      \
                                                                     \
        if (ossl_likely(!__builtin_mul_overflow(a, b, &r)))          \
            return r;                                                \
        *err |= 1;                                                   \
        return (a < 0) ^ (b < 0) ? min : max;                        \
    }

#define OSSL_SAFE_MATH_MULU(type_name, type, max)                    \
    static ossl_inline ossl_unused type safe_mul_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        type r;                                                      \
                                                                     \
        if (ossl_likely(!__builtin_mul_overflow(a, b, &r)))          \
            return r;                                                \
        *err |= 1;                                                   \
        return r;                                                    \
    }

#else /* has(__builtin_mul_overflow) */
#define OSSL_SAFE_MATH_MULS(type_name, type, min, max)               \
    static ossl_inline ossl_unused type safe_mul_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        if (a == 0 || b == 0)                                        \
            return 0;                                                \
        if (a == 1)                                                  \
            return b;                                                \
        if (b == 1)                                                  \
            return a;                                                \
        if (ossl_likely(a != min && b != min)) {                     \
            const type x = a < 0 ? -a : a;                           \
            const type y = b < 0 ? -b : b;                           \
                                                                     \
            if (ossl_likely(x <= max / y))                           \
                return a * b;                                        \
            /* A negative product can also equal the minimum. */     \
            if (((a < 0) ^ (b < 0)) && -x == min / y)                \
                return min;                                          \
        }                                                            \
        *err |= 1;                                                   \
        return (a < 0) ^ (b < 0) ? min : max;                        \
    }

#define OSSL_SAFE_MATH_MULU(type_name, type, max)                    \
    static ossl_inline ossl_unused type safe_mul_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        if (ossl_unlikely(b != 0 && a > max / b))                    \
            *err |= 1;                                               \
        /*                                                           \
         * With 16-bit short and 32-bit int, unsigned short          \
         * operands of 65535 promote to int and overflow when        \
         * multiplied. Adding 0U forces unsigned arithmetic.         \
         */                                                          \
        return a * (b + 0U);                                         \
    }
#endif /* has(__builtin_mul_overflow) */

/*
 * Safe division helpers
 */
#define OSSL_SAFE_MATH_DIVS(type_name, type, min, max)               \
    static ossl_inline ossl_unused type safe_div_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        if (ossl_unlikely(b == 0)) {                                 \
            *err |= 1;                                               \
            return a < 0 ? min : max;                                \
        }                                                            \
        if (ossl_unlikely(b == -1 && a == min)) {                    \
            *err |= 1;                                               \
            return max;                                              \
        }                                                            \
        return a / b;                                                \
    }

#define OSSL_SAFE_MATH_DIVU(type_name, type, max)                    \
    static ossl_inline ossl_unused type safe_div_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        if (ossl_likely(b != 0))                                     \
            return a / b;                                            \
        *err |= 1;                                                   \
        return max;                                                  \
    }

/*
 * Safe modulus helpers
 */
#define OSSL_SAFE_MATH_MODS(type_name, type, min, max)               \
    static ossl_inline ossl_unused type safe_mod_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        if (ossl_unlikely(b == 0)) {                                 \
            *err |= 1;                                               \
            return 0;                                                \
        }                                                            \
        if (ossl_unlikely(b == -1 && a == min)) {                    \
            *err |= 1;                                               \
            return max;                                              \
        }                                                            \
        return a % b;                                                \
    }

#define OSSL_SAFE_MATH_MODU(type_name, type)                         \
    static ossl_inline ossl_unused type safe_mod_##type_name(type a, \
        type b,                                                      \
        int *err)                                                    \
    {                                                                \
        if (ossl_likely(b != 0))                                     \
            return a % b;                                            \
        *err |= 1;                                                   \
        return 0;                                                    \
    }

/*
 * Safe negation helpers
 */
#define OSSL_SAFE_MATH_NEGS(type_name, type, min)                    \
    static ossl_inline ossl_unused type safe_neg_##type_name(type a, \
        int *err)                                                    \
    {                                                                \
        if (ossl_likely(a != min))                                   \
            return -a;                                               \
        *err |= 1;                                                   \
        return min;                                                  \
    }

#define OSSL_SAFE_MATH_NEGU(type_name, type)                         \
    static ossl_inline ossl_unused type safe_neg_##type_name(type a, \
        int *err)                                                    \
    {                                                                \
        if (a == 0)                                                  \
            return a;                                                \
        *err |= 1;                                                   \
        return 1 + ~a;                                               \
    }

/*
 * Safe absolute value helpers
 */
#define OSSL_SAFE_MATH_ABSS(type_name, type, min)                    \
    static ossl_inline ossl_unused type safe_abs_##type_name(type a, \
        int *err)                                                    \
    {                                                                \
        if (ossl_likely(a != min))                                   \
            return a < 0 ? -a : a;                                   \
        *err |= 1;                                                   \
        return min;                                                  \
    }

#define OSSL_SAFE_MATH_ABSU(type_name, type)                         \
    static ossl_inline ossl_unused type safe_abs_##type_name(type a, \
        int *err)                                                    \
    {                                                                \
        return a;                                                    \
    }

/**
 * @brief Compute a signed product and quotient with result limits.
 *
 * The operands must fit a signed integer type of size bytes.
 * @param a First factor in the numerator.
 * @param b Second factor in the numerator.
 * @param c Nonzero divisor.
 * @param size Size of the input integer type, in bytes.
 * @param min Minimum allowed result.
 * @param max Maximum allowed result.
 * @param[in,out] err Error flags. Overflow sets bit 0 and preserves other bits.
 * @returns The quotient truncated toward zero, or an arbitrary value on overflow.
 */
ossl_intmax_t ossl_safe_muldiv_signed(ossl_intmax_t a, ossl_intmax_t b,
    ossl_intmax_t c, size_t size, ossl_intmax_t min, ossl_intmax_t max,
    int *err);

/**
 * @brief Compute an unsigned product and quotient with a result limit.
 *
 * The operands must fit an unsigned integer type of size bytes.
 * @param a First factor in the numerator.
 * @param b Second factor in the numerator.
 * @param c Nonzero divisor.
 * @param size Size of the input integer type, in bytes.
 * @param max Maximum allowed result. The minimum is zero.
 * @param[in,out] err Error flags. Overflow sets bit 0 and preserves other bits.
 * @returns The quotient, or an arbitrary value on overflow.
 */
ossl_uintmax_t ossl_safe_muldiv_unsigned(ossl_uintmax_t a, ossl_uintmax_t b,
    ossl_uintmax_t c, size_t size, ossl_uintmax_t max, int *err);

/*
 * Safe fused multiply-divide helpers. Try multiplication in the original
 * type first, then use a wider type or the checked slow algorithm.
 */
#define OSSL_SAFE_MATH_MULDIVS(type_name, type, min, max)               \
    static ossl_inline ossl_unused type safe_muldiv_##type_name(type a, \
        type b, type c, int *err)                                       \
    {                                                                   \
        int e2 = 0;                                                     \
        type x;                                                         \
                                                                        \
        if (ossl_unlikely(c == 0)) {                                    \
            *err |= 1;                                                  \
            return a == 0 || b == 0 ? 0 : max;                          \
        }                                                               \
        x = safe_mul_##type_name(a, b, &e2);                            \
        if (ossl_likely(!e2))                                           \
            return safe_div_##type_name(x, c, err);                     \
        return (type)ossl_safe_muldiv_signed(a, b, c, sizeof(type),     \
            min, max, err);                                             \
    }

#define OSSL_SAFE_MATH_MULDIVU(type_name, type, max)                    \
    static ossl_inline ossl_unused type safe_muldiv_##type_name(type a, \
        type b, type c, int *err)                                       \
    {                                                                   \
        int e2 = 0;                                                     \
        type x;                                                         \
                                                                        \
        if (ossl_unlikely(c == 0)) {                                    \
            *err |= 1;                                                  \
            return a == 0 || b == 0 ? 0 : max;                          \
        }                                                               \
        x = safe_mul_##type_name(a, b, &e2);                            \
        if (ossl_likely(!e2))                                           \
            return x / c;                                               \
        return (type)ossl_safe_muldiv_unsigned(a, b, c, sizeof(type),   \
            max, err);                                                  \
    }

/*
 * Calculate a / b rounding up:
 *     i.e. a / b + (a % b != 0)
 * Which is usually (less safely) converted to (a + b - 1) / b
 * If you *know* that b != 0, then it's safe to ignore err.
 */
#define OSSL_SAFE_MATH_DIV_ROUND_UP(type_name, type, max)                                        \
    static ossl_inline ossl_unused type safe_div_round_up_##type_name(type a, type b, int *errp) \
    {                                                                                            \
        type x;                                                                                  \
        int *err, err_local = 0;                                                                 \
                                                                                                 \
        /* Allow errors to be ignored by callers */                                              \
        err = errp != NULL ? errp : &err_local;                                                  \
        /* Fast path, both positive */                                                           \
        if (ossl_likely(b > 0 && a > 0)) {                                                       \
            /* Faster path: no overflow concerns */                                              \
            if (ossl_likely(a < max - b))                                                        \
                return (a + b - 1) / b;                                                          \
            return a / b + (a % b != 0);                                                         \
        }                                                                                        \
        if (ossl_unlikely(b == 0)) {                                                             \
            *err |= 1;                                                                           \
            return a == 0 ? 0 : max;                                                             \
        }                                                                                        \
        if (a == 0)                                                                              \
            return 0;                                                                            \
        /* Rather slow path because there are negatives involved */                              \
        x = safe_mod_##type_name(a, b, err);                                                     \
        return safe_add_##type_name(safe_div_##type_name(a, b, err),                             \
            x != 0, err);                                                                        \
    }

/* Calculate ranges of types */
#define OSSL_SAFE_MATH_MAXS(type) ((type)((((type)1 << (sizeof(type) * 8 - 2)) - 1) * 2 + 1))
#define OSSL_SAFE_MATH_MINS(type) (-OSSL_SAFE_MATH_MAXS(type) - 1)
#define OSSL_SAFE_MATH_MAXU(type) ((type) ~(type)0)

/*
 * Wrapper macros to create all the functions of a given type
 */
#define OSSL_SAFE_MATH_SIGNED(type_name, type)                         \
    OSSL_SAFE_MATH_ADDS(type_name, type, OSSL_SAFE_MATH_MINS(type),    \
        OSSL_SAFE_MATH_MAXS(type))                                     \
    OSSL_SAFE_MATH_SUBS(type_name, type, OSSL_SAFE_MATH_MINS(type),    \
        OSSL_SAFE_MATH_MAXS(type))                                     \
    OSSL_SAFE_MATH_MULS(type_name, type, OSSL_SAFE_MATH_MINS(type),    \
        OSSL_SAFE_MATH_MAXS(type))                                     \
    OSSL_SAFE_MATH_DIVS(type_name, type, OSSL_SAFE_MATH_MINS(type),    \
        OSSL_SAFE_MATH_MAXS(type))                                     \
    OSSL_SAFE_MATH_MODS(type_name, type, OSSL_SAFE_MATH_MINS(type),    \
        OSSL_SAFE_MATH_MAXS(type))                                     \
    OSSL_SAFE_MATH_DIV_ROUND_UP(type_name, type,                       \
        OSSL_SAFE_MATH_MAXS(type))                                     \
    OSSL_SAFE_MATH_NEGS(type_name, type, OSSL_SAFE_MATH_MINS(type))    \
    OSSL_SAFE_MATH_MULDIVS(type_name, type, OSSL_SAFE_MATH_MINS(type), \
        OSSL_SAFE_MATH_MAXS(type))                                     \
    OSSL_SAFE_MATH_ABSS(type_name, type, OSSL_SAFE_MATH_MINS(type))

#define OSSL_SAFE_MATH_UNSIGNED(type_name, type)                       \
    OSSL_SAFE_MATH_ADDU(type_name, type, OSSL_SAFE_MATH_MAXU(type))    \
    OSSL_SAFE_MATH_SUBU(type_name, type)                               \
    OSSL_SAFE_MATH_MULU(type_name, type, OSSL_SAFE_MATH_MAXU(type))    \
    OSSL_SAFE_MATH_DIVU(type_name, type, OSSL_SAFE_MATH_MAXU(type))    \
    OSSL_SAFE_MATH_MODU(type_name, type)                               \
    OSSL_SAFE_MATH_DIV_ROUND_UP(type_name, type,                       \
        OSSL_SAFE_MATH_MAXU(type))                                     \
    OSSL_SAFE_MATH_MULDIVU(type_name, type, OSSL_SAFE_MATH_MAXU(type)) \
    OSSL_SAFE_MATH_NEGU(type_name, type)                               \
    OSSL_SAFE_MATH_ABSU(type_name, type)

#endif /* OSSL_INTERNAL_SAFE_MATH_H */
