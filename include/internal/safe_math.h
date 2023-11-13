/*
 * Copyright 2021-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_SAFE_MATH_H
# define OSSL_INTERNAL_SAFE_MATH_H
# pragma once

# include <openssl/e_os2.h>              /* For 'ossl_inline' */

# ifndef OPENSSL_NO_BUILTIN_OVERFLOW_CHECKING
#  ifdef __has_builtin
#   define has(func) __has_builtin(func)
#  elif __GNUC__ > 5
#   define has(func) 1
#  endif
# endif /* OPENSSL_NO_BUILTIN_OVERFLOW_CHECKING */

# ifndef has
#  define has(func) 0
# endif

/*
 * Safe addition helpers
 */
# if has(__builtin_add_overflow)
#  define OSSL_SAFE_MATH_ADDS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_add_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        type r;                                                              \
                                                                             \
        if (!__builtin_add_overflow(a, b, &r))                               \
            return r;                                                        \
        *err |= 1;                                                           \
        return a < 0 ? min : max;                                            \
    }

#  define OSSL_SAFE_MATH_ADDU(type_name, type, max) \
    static ossl_inline ossl_unused type safe_add_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        type r;                                                              \
                                                                             \
        if (!__builtin_add_overflow(a, b, &r))                               \
            return r;                                                        \
        *err |= 1;                                                           \
        return a + b;                                                            \
    }

# else  /* has(__builtin_add_overflow) */
#  define OSSL_SAFE_MATH_ADDS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_add_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if ((a < 0) ^ (b < 0)                                                \
                || (a > 0 && b <= max - a)                                   \
                || (a < 0 && b >= min - a)                                   \
                || a == 0)                                                   \
            return a + b;                                                    \
        *err |= 1;                                                           \
        return a < 0 ? min : max;                                            \
    }

#  define OSSL_SAFE_MATH_ADDU(type_name, type, max) \
    static ossl_inline ossl_unused type safe_add_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (b > max - a)                                                     \
            *err |= 1;                                                       \
        return a + b;                                                        \
    }
# endif /* has(__builtin_add_overflow) */

/*
 * Safe subtraction helpers
 */
# if has(__builtin_sub_overflow)
#  define OSSL_SAFE_MATH_SUBS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_sub_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        type r;                                                              \
                                                                             \
        if (!__builtin_sub_overflow(a, b, &r))                               \
            return r;                                                        \
        *err |= 1;                                                           \
        return a < 0 ? min : max;                                            \
    }

# else  /* has(__builtin_sub_overflow) */
#  define OSSL_SAFE_MATH_SUBS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_sub_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (!((a < 0) ^ (b < 0))                                             \
                || (b > 0 && a >= min + b)                                   \
                || (b < 0 && a <= max + b)                                   \
                || b == 0)                                                   \
            return a - b;                                                    \
        *err |= 1;                                                           \
        return a < 0 ? min : max;                                            \
    }

# endif /* has(__builtin_sub_overflow) */

# define OSSL_SAFE_MATH_SUBU(type_name, type) \
    static ossl_inline ossl_unused type safe_sub_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (b > a)                                                           \
            *err |= 1;                                                       \
        return a - b;                                                        \
    }

/*
 * Safe multiplication helpers
 */
# if has(__builtin_mul_overflow)
#  define OSSL_SAFE_MATH_MULS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_mul_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        type r;                                                              \
                                                                             \
        if (!__builtin_mul_overflow(a, b, &r))                               \
            return r;                                                        \
        *err |= 1;                                                           \
        return (a < 0) ^ (b < 0) ? min : max;                                \
    }

#  define OSSL_SAFE_MATH_MULU(type_name, type, max) \
    static ossl_inline ossl_unused type safe_mul_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        type r;                                                              \
                                                                             \
        if (!__builtin_mul_overflow(a, b, &r))                               \
            return r;                                                        \
        *err |= 1;                                                           \
        return a * b;                                                          \
    }

# else  /* has(__builtin_mul_overflow) */
#  define OSSL_SAFE_MATH_MULS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_mul_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (a == 0 || b == 0)                                                \
            return 0;                                                        \
        if (a == 1)                                                          \
            return b;                                                        \
        if (b == 1)                                                          \
            return a;                                                        \
        if (a != min && b != min) {                                          \
            const type x = a < 0 ? -a : a;                                   \
            const type y = b < 0 ? -b : b;                                   \
                                                                             \
            if (x <= max / y)                                                \
                return a * b;                                                \
        }                                                                    \
        *err |= 1;                                                           \
        return (a < 0) ^ (b < 0) ? min : max;                                \
    }

#  define OSSL_SAFE_MATH_MULU(type_name, type, max) \
    static ossl_inline ossl_unused type safe_mul_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (b != 0 && a > max / b)                                           \
            *err |= 1;                                                       \
        return a * b;                                                        \
    }
# endif /* has(__builtin_mul_overflow) */

/*
 * Safe division helpers
 */
# define OSSL_SAFE_MATH_DIVS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_div_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (b == 0) {                                                        \
            *err |= 1;                                                       \
            return a < 0 ? min : max;                                        \
        }                                                                    \
        if (b == -1 && a == min) {                                           \
            *err |= 1;                                                       \
            return max;                                                      \
        }                                                                    \
        return a / b;                                                        \
    }

# define OSSL_SAFE_MATH_DIVU(type_name, type, max) \
    static ossl_inline ossl_unused type safe_div_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (b != 0)                                                          \
            return a / b;                                                    \
        *err |= 1;                                                           \
        return max;                                                        \
    }

/*
 * Safe modulus helpers
 */
# define OSSL_SAFE_MATH_MODS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_mod_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (b == 0) {                                                        \
            *err |= 1;                                                       \
            return 0;                                                        \
        }                                                                    \
        if (b == -1 && a == min) {                                           \
            *err |= 1;                                                       \
            return max;                                                      \
        }                                                                    \
        return a % b;                                                        \
    }

# define OSSL_SAFE_MATH_MODU(type_name, type) \
    static ossl_inline ossl_unused type safe_mod_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (b != 0)                                                          \
            return a % b;                                                    \
        *err |= 1;                                                           \
        return 0;                                                            \
    }

/*
 * Safe negation helpers
 */
# define OSSL_SAFE_MATH_NEGS(type_name, type, min) \
    static ossl_inline ossl_unused type safe_neg_ ## type_name(type a,       \
                                                               int *err)     \
    {                                                                        \
        if (a != min)                                                        \
            return -a;                                                       \
        *err |= 1;                                                           \
        return min;                                                          \
    }

# define OSSL_SAFE_MATH_NEGU(type_name, type) \
    static ossl_inline ossl_unused type safe_neg_ ## type_name(type a,       \
                                                               int *err)     \
    {                                                                        \
        if (a == 0)                                                          \
            return a;                                                        \
        *err |= 1;                                                           \
        return 1 + ~a;                                                       \
    }

/*
 * Safe absolute value helpers
 */
# define OSSL_SAFE_MATH_ABSS(type_name, type, min) \
    static ossl_inline ossl_unused type safe_abs_ ## type_name(type a,       \
                                                               int *err)     \
    {                                                                        \
        if (a != min)                                                        \
            return a < 0 ? -a : a;                                           \
        *err |= 1;                                                           \
        return min;                                                          \
    }

# define OSSL_SAFE_MATH_ABSU(type_name, type) \
    static ossl_inline ossl_unused type safe_abs_ ## type_name(type a,       \
                                                               int *err)     \
    {                                                                        \
        return a;                                                            \
    }

/*
 * Safe shift operations.
 *
 * The C standard defines shifts by negative values and shifts larger than
 * the width of the type to be undefined behaviours.  We treat negative shifts
 * as shifts in the other direction and too large shifts push everything out.
 *
 * Signed left shifts that move a 1 bit into or out of the sign bit are
 * undefined.  Right shifts of negative values are implemenetation defined.
 */

/*
 * Signed shift left fails if set bits are shifted into or out of the sign bit.
 * Shifts zero bits into the lower order end.
 */
# define OSSL_SAFE_MATH_SHLS(type_name, type) \
    static ossl_inline ossl_unused type safe_shr_ ## type_name(type a,      \
                                                               int n,       \
                                                               int *err);   \
    static ossl_inline ossl_unused type safe_shl_ ## type_name(type a,      \
                                                               int n,       \
                                                               int *err)    \
    {                                                                       \
        if (n == 0)                                                         \
            return a;                                                       \
        if (n < 0)                                                          \
            return safe_shr_ ## type_name(a, -n, err);                      \
        if (n >= 8 * (int)sizeof(type)) {                                   \
            *err |= a != 0;                                                 \
            return 0;                                                       \
        }                                                                   \
        if ((a & ~((1 << ((int)sizeof(type) * 8 - n - 1)) - 1)) != 0) {     \
            *err = 1;                                                       \
            return 0;                                                       \
        }                                                                   \
        return a << n;                                                      \
    }

/*
 * Signed shift right inserts zero bits into the top.
 */
# define OSSL_SAFE_MATH_SHRS(type_name, type) \
    static ossl_inline ossl_unused type safe_shr_ ## type_name(type a,      \
                                                               int n,       \
                                                               int *err)    \
    {                                                                       \
        if (n < 0)                                                          \
            return safe_shl_ ## type_name(a, -n, err);                      \
        if (n >= 8 * (int)sizeof(type))                                     \
            return 0;                                                       \
        return (a >> n) & ((1 << ((int)sizeof(type) * 8 - n)) - 1);         \
    }

/*
 * Arithmetic signed shift right replicates the sign bit into the top.
 */
# define OSSL_SAFE_MATH_ASHRS(type_name, type) \
    static ossl_inline ossl_unused type safe_ashr_ ## type_name(type a,     \
                                                                int n,      \
                                                                int *err)   \
    {                                                                       \
        if (n < 0) {                                                        \
            *err |= a != 0;                                                 \
            return 0;                                                       \
        }                                                                   \
        if (n >= 8 * (int)sizeof(type))                                     \
            return a < 0 ? -1 : 0;                                          \
        if (a < 0)                                                          \
            return (a >> n) | ~((1 << ((int)sizeof(type) * 8 - n)) - 1);    \
        return (a >> n) & ((1 << ((int)sizeof(type) * 8 - n)) - 1);         \
    }

/*
 * Unsigned left shift, inserts zero bit at the top.
 */
# define OSSL_SAFE_MATH_SHLU(type_name, type) \
    static ossl_inline ossl_unused type safe_shl_ ## type_name(type a,      \
                                                               int n)       \
    {                                                                       \
        if (n < 0) {                                                        \
            if (n <= -8 * (int)sizeof(type))                                \
                return 0;                                                   \
            return a >> -n;                                                 \
        }                                                                   \
        if (n >= 8 * (int)sizeof(type))                                     \
            return 0;                                                       \
        return a << n;                                                      \
    }

/*
 * Unsigned right shift, inserts zero bit at the bottom.
 */
# define OSSL_SAFE_MATH_SHRU(type_name, type) \
    static ossl_inline ossl_unused type safe_shr_ ## type_name(type a,      \
                                                               int n)       \
    {                                                                       \
        if (n < 0) {                                                        \
            if (n <= -8 * (int)sizeof(type))                                \
                return 0;                                                   \
            return a << -n;                                                 \
        }                                                                   \
        if (n >= 8 * (int)sizeof(type))                                     \
            return 0;                                                       \
        return a >> n;                                                      \
    }

/*
 * Safe fused multiply divide helpers
 *
 * These are a bit obscure:
 *    . They begin by checking the denominator for zero and getting rid of this
 *      corner case.
 *
 *    . Second is an attempt to do the multiplication directly, if it doesn't
 *      overflow, the quotient is returned (for signed values there is a
 *      potential problem here which isn't present for unsigned).
 *
 *    . Finally, the multiplication/division is transformed so that the larger
 *      of the numerators is divided first.  This requires a remainder
 *      correction:
 *
 *          a b / c = (a / c) b + (a mod c) b / c, where a > b
 *
 *      The individual operations need to be overflow checked (again signed
 *      being more problematic).
 *
 * The algorithm used is not perfect but it should be "good enough".
 */
# define OSSL_SAFE_MATH_MULDIVS(type_name, type, max) \
    static ossl_inline ossl_unused type safe_muldiv_ ## type_name(type a,    \
                                                                  type b,    \
                                                                  type c,    \
                                                                  int *err)  \
    {                                                                        \
        int e2 = 0;                                                          \
        type q, r, x, y;                                                     \
                                                                             \
        if (c == 0) {                                                        \
            *err |= 1;                                                       \
            return a == 0 || b == 0 ? 0 : max;                               \
        }                                                                    \
        x = safe_mul_ ## type_name(a, b, &e2);                               \
        if (!e2)                                                             \
            return safe_div_ ## type_name(x, c, err);                        \
        if (b > a) {                                                         \
            x = b;                                                           \
            b = a;                                                           \
            a = x;                                                           \
        }                                                                    \
        q = safe_div_ ## type_name(a, c, err);                               \
        r = safe_mod_ ## type_name(a, c, err);                               \
        x = safe_mul_ ## type_name(r, b, err);                               \
        y = safe_mul_ ## type_name(q, b, err);                               \
        q = safe_div_ ## type_name(x, c, err);                               \
        return safe_add_ ## type_name(y, q, err);                            \
    }

# define OSSL_SAFE_MATH_MULDIVU(type_name, type, max) \
    static ossl_inline ossl_unused type safe_muldiv_ ## type_name(type a,    \
                                                                  type b,    \
                                                                  type c,    \
                                                                  int *err)  \
    {                                                                        \
        int e2 = 0;                                                          \
        type x, y;                                                           \
                                                                             \
        if (c == 0) {                                                        \
            *err |= 1;                                                       \
            return a == 0 || b == 0 ? 0 : max;                               \
        }                                                                    \
        x = safe_mul_ ## type_name(a, b, &e2);                               \
        if (!e2)                                                             \
            return x / c;                                                    \
        if (b > a) {                                                         \
            x = b;                                                           \
            b = a;                                                           \
            a = x;                                                           \
        }                                                                    \
        x = safe_mul_ ## type_name(a % c, b, err);                           \
        y = safe_mul_ ## type_name(a / c, b, err);                           \
        return safe_add_ ## type_name(y, x / c, err);                        \
    }

/*
 * Calculate a / b rounding up:
 *     i.e. a / b + (a % b != 0)
 * Which is usually (less safely) converted to (a + b - 1) / b
 * If you *know* that b != 0, then it's safe to ignore err.
 */
#define OSSL_SAFE_MATH_DIV_ROUND_UP(type_name, type, max) \
    static ossl_inline ossl_unused type safe_div_round_up_ ## type_name      \
        (type a, type b, int *errp)                                          \
    {                                                                        \
        type x;                                                              \
        int *err, err_local = 0;                                             \
                                                                             \
        /* Allow errors to be ignored by callers */                          \
        err = errp != NULL ? errp : &err_local;                              \
        /* Fast path, both positive */                                       \
        if (b > 0 && a > 0) {                                                \
            /* Faster path: no overflow concerns */                          \
            if (a < max - b)                                                 \
                return (a + b - 1) / b;                                      \
            return a / b + (a % b != 0);                                     \
        }                                                                    \
        if (b == 0) {                                                        \
            *err |= 1;                                                       \
            return a == 0 ? 0 : max;                                         \
        }                                                                    \
        if (a == 0)                                                          \
            return 0;                                                        \
        /* Rather slow path because there are negatives involved */          \
        x = safe_mod_ ## type_name(a, b, err);                               \
        return safe_add_ ## type_name(safe_div_ ## type_name(a, b, err),     \
                                      x != 0, err);                          \
    }

/* Calculate ranges of types */
# define OSSL_SAFE_MATH_MINS(type) (type)((type)1 << (sizeof(type) * 8 - 1))
# define OSSL_SAFE_MATH_MAXS(type) (type)(~OSSL_SAFE_MATH_MINS(type))
# define OSSL_SAFE_MATH_MAXU(type) (type)(~(type)0)

/*
 * Wrapper macros to create all the functions of a given type
 */
# define OSSL_SAFE_MATH_SIGNED(type_name, type)                         \
    OSSL_SAFE_MATH_ADDS(type_name, type, OSSL_SAFE_MATH_MINS(type),     \
                        OSSL_SAFE_MATH_MAXS(type))                      \
    OSSL_SAFE_MATH_SUBS(type_name, type, OSSL_SAFE_MATH_MINS(type),     \
                        OSSL_SAFE_MATH_MAXS(type))                      \
    OSSL_SAFE_MATH_MULS(type_name, type, OSSL_SAFE_MATH_MINS(type),     \
                        OSSL_SAFE_MATH_MAXS(type))                      \
    OSSL_SAFE_MATH_DIVS(type_name, type, OSSL_SAFE_MATH_MINS(type),     \
                        OSSL_SAFE_MATH_MAXS(type))                      \
    OSSL_SAFE_MATH_MODS(type_name, type, OSSL_SAFE_MATH_MINS(type),     \
                        OSSL_SAFE_MATH_MAXS(type))                      \
    OSSL_SAFE_MATH_DIV_ROUND_UP(type_name, type,                        \
                                OSSL_SAFE_MATH_MAXS(type))              \
    OSSL_SAFE_MATH_MULDIVS(type_name, type, OSSL_SAFE_MATH_MAXS(type))  \
    OSSL_SAFE_MATH_NEGS(type_name, type, OSSL_SAFE_MATH_MINS(type))     \
    OSSL_SAFE_MATH_ABSS(type_name, type, OSSL_SAFE_MATH_MINS(type))     \
    OSSL_SAFE_MATH_SHLS(type_name, type)                                \
    OSSL_SAFE_MATH_SHRS(type_name, type)                                \
    OSSL_SAFE_MATH_ASHRS(type_name, type)

# define OSSL_SAFE_MATH_UNSIGNED(type_name, type) \
    OSSL_SAFE_MATH_ADDU(type_name, type, OSSL_SAFE_MATH_MAXU(type))     \
    OSSL_SAFE_MATH_SUBU(type_name, type)                                \
    OSSL_SAFE_MATH_MULU(type_name, type, OSSL_SAFE_MATH_MAXU(type))     \
    OSSL_SAFE_MATH_DIVU(type_name, type, OSSL_SAFE_MATH_MAXU(type))     \
    OSSL_SAFE_MATH_MODU(type_name, type)                                \
    OSSL_SAFE_MATH_DIV_ROUND_UP(type_name, type,                        \
                                OSSL_SAFE_MATH_MAXU(type))              \
    OSSL_SAFE_MATH_MULDIVU(type_name, type, OSSL_SAFE_MATH_MAXU(type))  \
    OSSL_SAFE_MATH_NEGU(type_name, type)                                \
    OSSL_SAFE_MATH_ABSU(type_name, type)                                \
    OSSL_SAFE_MATH_SHLU(type_name, type)                                \
    OSSL_SAFE_MATH_SHRU(type_name, type)

#endif                          /* OSSL_INTERNAL_SAFE_MATH_H */
