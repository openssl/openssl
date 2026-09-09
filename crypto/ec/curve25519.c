/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * ECDSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <string.h>
#include "crypto/ecx.h"
#include "ec_local.h"
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "internal/numbers.h"

#if defined(X25519_ASM) && (defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64))

#define BASE_2_64_IMPLEMENTED

typedef uint64_t fe64[4];

int x25519_fe64_eligible(void);

/*
 * Following subroutines perform corresponding operations modulo
 * 2^256-38, i.e. double the curve modulus. However, inputs and
 * outputs are permitted to be partially reduced, i.e. to remain
 * in [0..2^256) range. It's all tied up in final fe64_tobytes
 * that performs full reduction modulo 2^255-19.
 *
 * There are no reference C implementations for these.
 */
void x25519_fe64_mul(fe64 h, const fe64 f, const fe64 g);
void x25519_fe64_sqr(fe64 h, const fe64 f);
void x25519_fe64_mul121666(fe64 h, fe64 f);
void x25519_fe64_add(fe64 h, const fe64 f, const fe64 g);
void x25519_fe64_sub(fe64 h, const fe64 f, const fe64 g);
void x25519_fe64_tobytes(uint8_t *s, const fe64 f);
#define fe64_mul x25519_fe64_mul
#define fe64_sqr x25519_fe64_sqr
#define fe64_mul121666 x25519_fe64_mul121666
#define fe64_add x25519_fe64_add
#define fe64_sub x25519_fe64_sub
#define fe64_tobytes x25519_fe64_tobytes

static uint64_t load_8(const uint8_t *in)
{
    uint64_t result;

    result = in[0];
    result |= ((uint64_t)in[1]) << 8;
    result |= ((uint64_t)in[2]) << 16;
    result |= ((uint64_t)in[3]) << 24;
    result |= ((uint64_t)in[4]) << 32;
    result |= ((uint64_t)in[5]) << 40;
    result |= ((uint64_t)in[6]) << 48;
    result |= ((uint64_t)in[7]) << 56;

    return result;
}

static void fe64_frombytes(fe64 h, const uint8_t *s)
{
    h[0] = load_8(s);
    h[1] = load_8(s + 8);
    h[2] = load_8(s + 16);
    h[3] = load_8(s + 24) & 0x7fffffffffffffff;
}

static void fe64_0(fe64 h)
{
    h[0] = 0;
    h[1] = 0;
    h[2] = 0;
    h[3] = 0;
}

static void fe64_1(fe64 h)
{
    h[0] = 1;
    h[1] = 0;
    h[2] = 0;
    h[3] = 0;
}

static void fe64_copy(fe64 h, const fe64 f)
{
    h[0] = f[0];
    h[1] = f[1];
    h[2] = f[2];
    h[3] = f[3];
}

static void fe64_cswap(fe64 f, fe64 g, unsigned int b)
{
    int i;
    uint64_t mask = 0 - (uint64_t)b;

    for (i = 0; i < 4; i++) {
        uint64_t x = f[i] ^ g[i];
        x &= mask;
        f[i] ^= x;
        g[i] ^= x;
    }
}

static void fe64_invert(fe64 out, const fe64 z)
{
    fe64 t0;
    fe64 t1;
    fe64 t2;
    fe64 t3;
    int i;

    /*
     * Compute z ** -1 = z ** (2 ** 255 - 19 - 2) with the exponent as
     * 2 ** 255 - 21 = (2 ** 5) * (2 ** 250 - 1) + 11.
     */

    /* t0 = z ** 2 */
    fe64_sqr(t0, z);

    /* t1 = t0 ** (2 ** 2) = z ** 8 */
    fe64_sqr(t1, t0);
    fe64_sqr(t1, t1);

    /* t1 = z * t1 = z ** 9 */
    fe64_mul(t1, z, t1);
    /* t0 = t0 * t1 = z ** 11 -- stash t0 away for the end. */
    fe64_mul(t0, t0, t1);

    /* t2 = t0 ** 2 = z ** 22 */
    fe64_sqr(t2, t0);

    /* t1 = t1 * t2 = z ** (2 ** 5 - 1) */
    fe64_mul(t1, t1, t2);

    /* t2 = t1 ** (2 ** 5) = z ** ((2 ** 5) * (2 ** 5 - 1)) */
    fe64_sqr(t2, t1);
    for (i = 1; i < 5; ++i)
        fe64_sqr(t2, t2);

    /* t1 = t1 * t2 = z ** ((2 ** 5 + 1) * (2 ** 5 - 1)) = z ** (2 ** 10 - 1) */
    fe64_mul(t1, t2, t1);

    /* Continuing similarly... */

    /* t2 = z ** (2 ** 20 - 1) */
    fe64_sqr(t2, t1);
    for (i = 1; i < 10; ++i)
        fe64_sqr(t2, t2);

    fe64_mul(t2, t2, t1);

    /* t2 = z ** (2 ** 40 - 1) */
    fe64_sqr(t3, t2);
    for (i = 1; i < 20; ++i)
        fe64_sqr(t3, t3);

    fe64_mul(t2, t3, t2);

    /* t2 = z ** (2 ** 10) * (2 ** 40 - 1) */
    for (i = 0; i < 10; ++i)
        fe64_sqr(t2, t2);

    /* t1 = z ** (2 ** 50 - 1) */
    fe64_mul(t1, t2, t1);

    /* t2 = z ** (2 ** 100 - 1) */
    fe64_sqr(t2, t1);
    for (i = 1; i < 50; ++i)
        fe64_sqr(t2, t2);

    fe64_mul(t2, t2, t1);

    /* t2 = z ** (2 ** 200 - 1) */
    fe64_sqr(t3, t2);
    for (i = 1; i < 100; ++i)
        fe64_sqr(t3, t3);

    fe64_mul(t2, t3, t2);

    /* t2 = z ** ((2 ** 50) * (2 ** 200 - 1) */
    for (i = 0; i < 50; ++i)
        fe64_sqr(t2, t2);

    /* t1 = z ** (2 ** 250 - 1) */
    fe64_mul(t1, t2, t1);

    /* t1 = z ** ((2 ** 5) * (2 ** 250 - 1)) */
    for (i = 0; i < 5; ++i)
        fe64_sqr(t1, t1);

    /* Recall t0 = z ** 11; out = z ** (2 ** 255 - 21) */
    fe64_mul(out, t1, t0);
}

/*
 * Duplicate of original x25519_scalar_mult_generic, but using
 * fe64_* subroutines.
 */
static void x25519_scalar_mulx(uint8_t out[32], const uint8_t scalar[32],
    const uint8_t point[32])
{
    fe64 x1, x2, z2, x3, z3, tmp0, tmp1;
    uint8_t e[32];
    unsigned swap = 0;
    int pos;

    memcpy(e, scalar, 32);
    e[0] &= 0xf8;
    e[31] &= 0x7f;
    e[31] |= 0x40;
    fe64_frombytes(x1, point);
    fe64_1(x2);
    fe64_0(z2);
    fe64_copy(x3, x1);
    fe64_1(z3);

    for (pos = 254; pos >= 0; --pos) {
        unsigned int b = 1 & (e[pos / 8] >> (pos & 7));

        swap ^= b;
        fe64_cswap(x2, x3, swap);
        fe64_cswap(z2, z3, swap);
        swap = b;
        fe64_sub(tmp0, x3, z3);
        fe64_sub(tmp1, x2, z2);
        fe64_add(x2, x2, z2);
        fe64_add(z2, x3, z3);
        /* The original copy in x25519_scalar_mult_generic uses argument order
         * fe_mul(z3, tmp0, x2), with the input arguments swapped.
         *
         * The assembly implementation of fe64_mul used here runs faster in
         * parallel with its nearby instructions when an earlier-computable
         * input (like tmp0) is passed as the 2nd input because it consumes
         * the 2nd input at a faster rate than the 1st input. */
        fe64_mul(z3, x2, tmp0);
        fe64_mul(z2, z2, tmp1);
        fe64_sqr(tmp0, tmp1);
        fe64_sqr(tmp1, x2);
        fe64_add(x3, z3, z2);
        fe64_sub(z2, z3, z2);
        fe64_mul(x2, tmp1, tmp0);
        fe64_sub(tmp1, tmp1, tmp0);
        fe64_sqr(z2, z2);
        fe64_mul121666(z3, tmp1);
        fe64_sqr(x3, x3);
        fe64_add(tmp0, tmp0, z3);
        fe64_mul(z3, x1, z2);
        fe64_mul(z2, tmp1, tmp0);
    }

    fe64_invert(z2, z2);
    fe64_mul(x2, x2, z2);
    fe64_tobytes(out, x2);

    OPENSSL_cleanse(e, sizeof(e));
}
#endif

#if defined(X25519_ASM)                                          \
    || (defined(INT128_MAX)                                      \
        && !defined(__sparc__)                                   \
        && (!defined(__SIZEOF_LONG__) || (__SIZEOF_LONG__ == 8)) \
        && !(defined(__ANDROID__) && !defined(__clang__)))
/*
 * Base 2^51 implementation. It's virtually no different from reference
 * base 2^25.5 implementation in respect to lax boundary conditions for
 * intermediate values and even individual limbs. So that whatever you
 * know about the reference, applies even here...
 *
 * Limb bounds: fe51_mul and fe51_sq produce limbs below 2^51 + 2^13 and
 * fe51_add simply adds limbs. fe51_sub and fe51_neg add 4 * modulus, whose
 * limbs are just below 2^53, so that the subtrahend may be a sum of two
 * products, or a negated product, without any limb going negative; the
 * subtrahend must never be a difference. fe51_mul, fe51_sq and
 * fe51_mul121666, in C as well as in assembly, accept any input with
 * limbs below 2^54: the largest 128-bit accumulator then stays below
 * 77 * 2^108 < 2^115, and the carry out of the top limb, which gets
 * multiplied by 19 in 64-bit arithmetic, stays below 2^60. The X25519
 * ladder and the Ed25519 group operations never add more than three
 * products together, nor subtract from more than the sum of a product
 * and a difference, so every input to fe51_mul and fe51_sq is below
 * 2^53 + 3 * 2^51 + 2^15 < 2^54.
 */
#define BASE_2_51_IMPLEMENTED

typedef uint64_t fe51[5];

static const uint64_t MASK51 = 0x7ffffffffffff;

static uint64_t load_7(const uint8_t *in)
{
    uint64_t result;

    result = in[0];
    result |= ((uint64_t)in[1]) << 8;
    result |= ((uint64_t)in[2]) << 16;
    result |= ((uint64_t)in[3]) << 24;
    result |= ((uint64_t)in[4]) << 32;
    result |= ((uint64_t)in[5]) << 40;
    result |= ((uint64_t)in[6]) << 48;

    return result;
}

static uint64_t load_6(const uint8_t *in)
{
    uint64_t result;

    result = in[0];
    result |= ((uint64_t)in[1]) << 8;
    result |= ((uint64_t)in[2]) << 16;
    result |= ((uint64_t)in[3]) << 24;
    result |= ((uint64_t)in[4]) << 32;
    result |= ((uint64_t)in[5]) << 40;

    return result;
}

static void fe51_frombytes(fe51 h, const uint8_t *s)
{
    uint64_t h0 = load_7(s); /* 56 bits */
    uint64_t h1 = load_6(s + 7) << 5; /* 53 bits */
    uint64_t h2 = load_7(s + 13) << 2; /* 58 bits */
    uint64_t h3 = load_6(s + 20) << 7; /* 55 bits */
    uint64_t h4 = (load_6(s + 26) & 0x7fffffffffff) << 4; /* 51 bits */

    h1 |= h0 >> 51;
    h0 &= MASK51;
    h2 |= h1 >> 51;
    h1 &= MASK51;
    h3 |= h2 >> 51;
    h2 &= MASK51;
    h4 |= h3 >> 51;
    h3 &= MASK51;

    h[0] = h0;
    h[1] = h1;
    h[2] = h2;
    h[3] = h3;
    h[4] = h4;
}

static void fe51_tobytes(uint8_t *s, const fe51 h)
{
    uint64_t h0 = h[0];
    uint64_t h1 = h[1];
    uint64_t h2 = h[2];
    uint64_t h3 = h[3];
    uint64_t h4 = h[4];
    uint64_t q;

    /*
     * Propagate carries so that every limb is below 2^51, bar h0 which may
     * exceed it by a small multiple of 19. The comparison to the modulus
     * below relies on the value being below 2 * modulus, which holds for
     * outputs of fe51_mul and fe51_sq as they are, but not for outputs of
     * fe51_add, fe51_sub and fe51_neg.
     */
    h1 += h0 >> 51;
    h0 &= MASK51;
    h2 += h1 >> 51;
    h1 &= MASK51;
    h3 += h2 >> 51;
    h2 &= MASK51;
    h4 += h3 >> 51;
    h3 &= MASK51;
    h0 += 19 * (h4 >> 51);
    h4 &= MASK51;

    /* compare to modulus */
    q = (h0 + 19) >> 51;
    q = (h1 + q) >> 51;
    q = (h2 + q) >> 51;
    q = (h3 + q) >> 51;
    q = (h4 + q) >> 51;

    /* full reduce */
    h0 += 19 * q;
    h1 += h0 >> 51;
    h0 &= MASK51;
    h2 += h1 >> 51;
    h1 &= MASK51;
    h3 += h2 >> 51;
    h2 &= MASK51;
    h4 += h3 >> 51;
    h3 &= MASK51;
    h4 &= MASK51;

    /* smash */
    s[0] = (uint8_t)(h0 >> 0);
    s[1] = (uint8_t)(h0 >> 8);
    s[2] = (uint8_t)(h0 >> 16);
    s[3] = (uint8_t)(h0 >> 24);
    s[4] = (uint8_t)(h0 >> 32);
    s[5] = (uint8_t)(h0 >> 40);
    s[6] = (uint8_t)((h0 >> 48) | ((uint32_t)h1 << 3));
    s[7] = (uint8_t)(h1 >> 5);
    s[8] = (uint8_t)(h1 >> 13);
    s[9] = (uint8_t)(h1 >> 21);
    s[10] = (uint8_t)(h1 >> 29);
    s[11] = (uint8_t)(h1 >> 37);
    s[12] = (uint8_t)((h1 >> 45) | ((uint32_t)h2 << 6));
    s[13] = (uint8_t)(h2 >> 2);
    s[14] = (uint8_t)(h2 >> 10);
    s[15] = (uint8_t)(h2 >> 18);
    s[16] = (uint8_t)(h2 >> 26);
    s[17] = (uint8_t)(h2 >> 34);
    s[18] = (uint8_t)(h2 >> 42);
    s[19] = (uint8_t)((h2 >> 50) | ((uint32_t)h3 << 1));
    s[20] = (uint8_t)(h3 >> 7);
    s[21] = (uint8_t)(h3 >> 15);
    s[22] = (uint8_t)(h3 >> 23);
    s[23] = (uint8_t)(h3 >> 31);
    s[24] = (uint8_t)(h3 >> 39);
    s[25] = (uint8_t)((h3 >> 47) | ((uint32_t)h4 << 4));
    s[26] = (uint8_t)(h4 >> 4);
    s[27] = (uint8_t)(h4 >> 12);
    s[28] = (uint8_t)(h4 >> 20);
    s[29] = (uint8_t)(h4 >> 28);
    s[30] = (uint8_t)(h4 >> 36);
    s[31] = (uint8_t)(h4 >> 44);
}

#if defined(X25519_ASM)
void x25519_fe51_mul(fe51 h, const fe51 f, const fe51 g);
void x25519_fe51_sqr(fe51 h, const fe51 f);
void x25519_fe51_mul121666(fe51 h, fe51 f);
#define fe51_mul x25519_fe51_mul
#define fe51_sq x25519_fe51_sqr
#define fe51_mul121666 x25519_fe51_mul121666
#else

typedef uint128_t u128;

static void fe51_mul(fe51 h, const fe51 f, const fe51 g)
{
    u128 h0, h1, h2, h3, h4;
    uint64_t f_i, g0, g1, g2, g3, g4;

    f_i = f[0];
    h0 = (u128)f_i * (g0 = g[0]);
    h1 = (u128)f_i * (g1 = g[1]);
    h2 = (u128)f_i * (g2 = g[2]);
    h3 = (u128)f_i * (g3 = g[3]);
    h4 = (u128)f_i * (g4 = g[4]);

    f_i = f[1];
    h0 += (u128)f_i * (g4 *= 19);
    h1 += (u128)f_i * g0;
    h2 += (u128)f_i * g1;
    h3 += (u128)f_i * g2;
    h4 += (u128)f_i * g3;

    f_i = f[2];
    h0 += (u128)f_i * (g3 *= 19);
    h1 += (u128)f_i * g4;
    h2 += (u128)f_i * g0;
    h3 += (u128)f_i * g1;
    h4 += (u128)f_i * g2;

    f_i = f[3];
    h0 += (u128)f_i * (g2 *= 19);
    h1 += (u128)f_i * g3;
    h2 += (u128)f_i * g4;
    h3 += (u128)f_i * g0;
    h4 += (u128)f_i * g1;

    f_i = f[4];
    h0 += (u128)f_i * (g1 *= 19);
    h1 += (u128)f_i * g2;
    h2 += (u128)f_i * g3;
    h3 += (u128)f_i * g4;
    h4 += (u128)f_i * g0;

    /* partial [lazy] reduction */
    h3 += (uint64_t)(h2 >> 51);
    g2 = (uint64_t)h2 & MASK51;
    h1 += (uint64_t)(h0 >> 51);
    g0 = (uint64_t)h0 & MASK51;

    h4 += (uint64_t)(h3 >> 51);
    g3 = (uint64_t)h3 & MASK51;
    g2 += (uint64_t)(h1 >> 51);
    g1 = (uint64_t)h1 & MASK51;

    g0 += (uint64_t)(h4 >> 51) * 19;
    g4 = (uint64_t)h4 & MASK51;
    g3 += g2 >> 51;
    g2 &= MASK51;
    g1 += g0 >> 51;
    g0 &= MASK51;

    h[0] = g0;
    h[1] = g1;
    h[2] = g2;
    h[3] = g3;
    h[4] = g4;
}

static void fe51_sq(fe51 h, const fe51 f)
{
#if defined(OPENSSL_SMALL_FOOTPRINT)
    fe51_mul(h, f, f);
#else
    /* dedicated squaring gives 16-25% overall improvement */
    uint64_t g0 = f[0];
    uint64_t g1 = f[1];
    uint64_t g2 = f[2];
    uint64_t g3 = f[3];
    uint64_t g4 = f[4];
    u128 h0, h1, h2, h3, h4;

    h0 = (u128)g0 * g0;
    g0 *= 2;
    h1 = (u128)g0 * g1;
    h2 = (u128)g0 * g2;
    h3 = (u128)g0 * g3;
    h4 = (u128)g0 * g4;

    g0 = g4; /* borrow g0 */
    h3 += (u128)g0 * (g4 *= 19);

    h2 += (u128)g1 * g1;
    g1 *= 2;
    h3 += (u128)g1 * g2;
    h4 += (u128)g1 * g3;
    h0 += (u128)g1 * g4;

    g0 = g3; /* borrow g0 */
    h1 += (u128)g0 * (g3 *= 19);
    h2 += (u128)(g0 * 2) * g4;

    h4 += (u128)g2 * g2;
    g2 *= 2;
    h0 += (u128)g2 * g3;
    h1 += (u128)g2 * g4;

    /* partial [lazy] reduction */
    h3 += (uint64_t)(h2 >> 51);
    g2 = (uint64_t)h2 & MASK51;
    h1 += (uint64_t)(h0 >> 51);
    g0 = (uint64_t)h0 & MASK51;

    h4 += (uint64_t)(h3 >> 51);
    g3 = (uint64_t)h3 & MASK51;
    g2 += (uint64_t)(h1 >> 51);
    g1 = (uint64_t)h1 & MASK51;

    g0 += (uint64_t)(h4 >> 51) * 19;
    g4 = (uint64_t)h4 & MASK51;
    g3 += g2 >> 51;
    g2 &= MASK51;
    g1 += g0 >> 51;
    g0 &= MASK51;

    h[0] = g0;
    h[1] = g1;
    h[2] = g2;
    h[3] = g3;
    h[4] = g4;
#endif
}

static void fe51_mul121666(fe51 h, fe51 f)
{
    u128 h0 = f[0] * (u128)121666;
    u128 h1 = f[1] * (u128)121666;
    u128 h2 = f[2] * (u128)121666;
    u128 h3 = f[3] * (u128)121666;
    u128 h4 = f[4] * (u128)121666;
    uint64_t g0, g1, g2, g3, g4;

    h3 += (uint64_t)(h2 >> 51);
    g2 = (uint64_t)h2 & MASK51;
    h1 += (uint64_t)(h0 >> 51);
    g0 = (uint64_t)h0 & MASK51;

    h4 += (uint64_t)(h3 >> 51);
    g3 = (uint64_t)h3 & MASK51;
    g2 += (uint64_t)(h1 >> 51);
    g1 = (uint64_t)h1 & MASK51;

    g0 += (uint64_t)(h4 >> 51) * 19;
    g4 = (uint64_t)h4 & MASK51;
    g3 += g2 >> 51;
    g2 &= MASK51;
    g1 += g0 >> 51;
    g0 &= MASK51;

    h[0] = g0;
    h[1] = g1;
    h[2] = g2;
    h[3] = g3;
    h[4] = g4;
}
#endif

static void fe51_add(fe51 h, const fe51 f, const fe51 g)
{
    h[0] = f[0] + g[0];
    h[1] = f[1] + g[1];
    h[2] = f[2] + g[2];
    h[3] = f[3] + g[3];
    h[4] = f[4] + g[4];
}

static void fe51_sub(fe51 h, const fe51 f, const fe51 g)
{
    /*
     * Add 4*modulus to ensure that result remains positive even if
     * subtrahend is only partially reduced. 2*modulus would do for the
     * X25519 ladder, but the Ed25519 group operations subtract sums of
     * two products, whose limbs can slightly exceed 2^52.
     */
    h[0] = (f[0] + 0x1fffffffffffb4) - g[0];
    h[1] = (f[1] + 0x1ffffffffffffc) - g[1];
    h[2] = (f[2] + 0x1ffffffffffffc) - g[2];
    h[3] = (f[3] + 0x1ffffffffffffc) - g[3];
    h[4] = (f[4] + 0x1ffffffffffffc) - g[4];
}

static void fe51_neg(fe51 h, const fe51 f)
{
    /* As in fe51_sub, add 4*modulus to keep the result positive. */
    h[0] = 0x1fffffffffffb4 - f[0];
    h[1] = 0x1ffffffffffffc - f[1];
    h[2] = 0x1ffffffffffffc - f[2];
    h[3] = 0x1ffffffffffffc - f[3];
    h[4] = 0x1ffffffffffffc - f[4];
}

static void fe51_cmov(fe51 f, const fe51 g, unsigned int b)
{
    int i;
    uint64_t mask = 0 - (uint64_t)b;

    for (i = 0; i < 5; i++) {
        uint64_t x = f[i] ^ g[i];
        x &= mask;
        f[i] ^= x;
    }
}

static void fe51_0(fe51 h)
{
    h[0] = 0;
    h[1] = 0;
    h[2] = 0;
    h[3] = 0;
    h[4] = 0;
}

static void fe51_1(fe51 h)
{
    h[0] = 1;
    h[1] = 0;
    h[2] = 0;
    h[3] = 0;
    h[4] = 0;
}

static void fe51_copy(fe51 h, const fe51 f)
{
    h[0] = f[0];
    h[1] = f[1];
    h[2] = f[2];
    h[3] = f[3];
    h[4] = f[4];
}

static void fe51_cswap(fe51 f, fe51 g, unsigned int b)
{
    int i;
    uint64_t mask = 0 - (uint64_t)b;

    for (i = 0; i < 5; i++) {
        int64_t x = f[i] ^ g[i];
        x &= mask;
        f[i] ^= x;
        g[i] ^= x;
    }
}

static void fe51_invert(fe51 out, const fe51 z)
{
    fe51 t0;
    fe51 t1;
    fe51 t2;
    fe51 t3;
    int i;

    /*
     * Compute z ** -1 = z ** (2 ** 255 - 19 - 2) with the exponent as
     * 2 ** 255 - 21 = (2 ** 5) * (2 ** 250 - 1) + 11.
     */

    /* t0 = z ** 2 */
    fe51_sq(t0, z);

    /* t1 = t0 ** (2 ** 2) = z ** 8 */
    fe51_sq(t1, t0);
    fe51_sq(t1, t1);

    /* t1 = z * t1 = z ** 9 */
    fe51_mul(t1, z, t1);
    /* t0 = t0 * t1 = z ** 11 -- stash t0 away for the end. */
    fe51_mul(t0, t0, t1);

    /* t2 = t0 ** 2 = z ** 22 */
    fe51_sq(t2, t0);

    /* t1 = t1 * t2 = z ** (2 ** 5 - 1) */
    fe51_mul(t1, t1, t2);

    /* t2 = t1 ** (2 ** 5) = z ** ((2 ** 5) * (2 ** 5 - 1)) */
    fe51_sq(t2, t1);
    for (i = 1; i < 5; ++i)
        fe51_sq(t2, t2);

    /* t1 = t1 * t2 = z ** ((2 ** 5 + 1) * (2 ** 5 - 1)) = z ** (2 ** 10 - 1) */
    fe51_mul(t1, t2, t1);

    /* Continuing similarly... */

    /* t2 = z ** (2 ** 20 - 1) */
    fe51_sq(t2, t1);
    for (i = 1; i < 10; ++i)
        fe51_sq(t2, t2);

    fe51_mul(t2, t2, t1);

    /* t2 = z ** (2 ** 40 - 1) */
    fe51_sq(t3, t2);
    for (i = 1; i < 20; ++i)
        fe51_sq(t3, t3);

    fe51_mul(t2, t3, t2);

    /* t2 = z ** (2 ** 10) * (2 ** 40 - 1) */
    for (i = 0; i < 10; ++i)
        fe51_sq(t2, t2);

    /* t1 = z ** (2 ** 50 - 1) */
    fe51_mul(t1, t2, t1);

    /* t2 = z ** (2 ** 100 - 1) */
    fe51_sq(t2, t1);
    for (i = 1; i < 50; ++i)
        fe51_sq(t2, t2);

    fe51_mul(t2, t2, t1);

    /* t2 = z ** (2 ** 200 - 1) */
    fe51_sq(t3, t2);
    for (i = 1; i < 100; ++i)
        fe51_sq(t3, t3);

    fe51_mul(t2, t3, t2);

    /* t2 = z ** ((2 ** 50) * (2 ** 200 - 1) */
    for (i = 0; i < 50; ++i)
        fe51_sq(t2, t2);

    /* t1 = z ** (2 ** 250 - 1) */
    fe51_mul(t1, t2, t1);

    /* t1 = z ** ((2 ** 5) * (2 ** 250 - 1)) */
    for (i = 0; i < 5; ++i)
        fe51_sq(t1, t1);

    /* Recall t0 = z ** 11; out = z ** (2 ** 255 - 21) */
    fe51_mul(out, t1, t0);
}

/*
 * Duplicate of original x25519_scalar_mult_generic, but using
 * fe51_* subroutines.
 */
static void x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32],
    const uint8_t point[32])
{
    fe51 x1, x2, z2, x3, z3, tmp0, tmp1;
    uint8_t e[32];
    unsigned swap = 0;
    int pos;

#ifdef BASE_2_64_IMPLEMENTED
    if (x25519_fe64_eligible()) {
        x25519_scalar_mulx(out, scalar, point);
        return;
    }
#endif

    memcpy(e, scalar, 32);
    e[0] &= 0xf8;
    e[31] &= 0x7f;
    e[31] |= 0x40;
    fe51_frombytes(x1, point);
    fe51_1(x2);
    fe51_0(z2);
    fe51_copy(x3, x1);
    fe51_1(z3);

    for (pos = 254; pos >= 0; --pos) {
        unsigned int b = 1 & (e[pos / 8] >> (pos & 7));

        swap ^= b;
        fe51_cswap(x2, x3, swap);
        fe51_cswap(z2, z3, swap);
        swap = b;
        fe51_sub(tmp0, x3, z3);
        fe51_sub(tmp1, x2, z2);
        fe51_add(x2, x2, z2);
        fe51_add(z2, x3, z3);
        fe51_mul(z3, tmp0, x2);
        fe51_mul(z2, z2, tmp1);
        fe51_sq(tmp0, tmp1);
        fe51_sq(tmp1, x2);
        fe51_add(x3, z3, z2);
        fe51_sub(z2, z3, z2);
        fe51_mul(x2, tmp1, tmp0);
        fe51_sub(tmp1, tmp1, tmp0);
        fe51_sq(z2, z2);
        fe51_mul121666(z3, tmp1);
        fe51_sq(x3, x3);
        fe51_add(tmp0, tmp0, z3);
        fe51_mul(z3, x1, z2);
        fe51_mul(z2, tmp1, tmp0);
    }

    fe51_invert(z2, z2);
    fe51_mul(x2, x2, z2);
    fe51_tobytes(out, x2);

    OPENSSL_cleanse(e, sizeof(e));
}
#endif

/*
 * Reference base 2^25.5 implementation.
 *
 * This code is mostly taken from the ref10 version of Ed25519 in SUPERCOP
 * 20141124 (http://bench.cr.yp.to/supercop.html).
 *
 * The field functions are shared by Ed25519 and X25519 where possible.
 * Where the base 2^51 implementation is available, the Ed25519 group
 * operations use it instead of the reference base 2^25.5 field arithmetic,
 * which is then compiled out.
 */

#if defined(BASE_2_51_IMPLEMENTED)

typedef fe51 fe;

#define fe_frombytes fe51_frombytes
#define fe_tobytes fe51_tobytes
#define fe_copy fe51_copy
#define fe_0 fe51_0
#define fe_1 fe51_1
#define fe_add fe51_add
#define fe_sub fe51_sub
#define fe_mul fe51_mul
#define fe_sq fe51_sq
#define fe_invert fe51_invert
#define fe_neg fe51_neg
#define fe_cmov fe51_cmov

/* h = 2 * f * f */
static void fe_sq2(fe h, const fe f)
{
    fe51_sq(h, f);
    h[0] += h[0];
    h[1] += h[1];
    h[2] += h[2];
    h[3] += h[3];
    h[4] += h[4];
}

#else

/*
 * fe means field element. Here the field is \Z/(2^255-19). An element t,
 * entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
 * t[3]+2^102 t[4]+...+2^230 t[9]. Bounds on each t[i] vary depending on
 * context.
 */
typedef int32_t fe[10];

static const int64_t kBottom25Bits = 0x1ffffffLL;
static const int64_t kBottom26Bits = 0x3ffffffLL;
static const int64_t kTop39Bits = 0xfffffffffe000000LL;
static const int64_t kTop38Bits = 0xfffffffffc000000LL;

#endif

static const int64_t kBottom21Bits = 0x1fffffLL;

static uint64_t load_3(const uint8_t *in)
{
    uint64_t result;

    result = ((uint64_t)in[0]);
    result |= ((uint64_t)in[1]) << 8;
    result |= ((uint64_t)in[2]) << 16;
    return result;
}

static uint64_t load_4(const uint8_t *in)
{
    uint64_t result;

    result = ((uint64_t)in[0]);
    result |= ((uint64_t)in[1]) << 8;
    result |= ((uint64_t)in[2]) << 16;
    result |= ((uint64_t)in[3]) << 24;
    return result;
}

#if !defined(BASE_2_51_IMPLEMENTED)

static void fe_frombytes(fe h, const uint8_t *s)
{
    /* Ignores top bit of h. */
    int64_t h0 = load_4(s);
    int64_t h1 = load_3(s + 4) << 6;
    int64_t h2 = load_3(s + 7) << 5;
    int64_t h3 = load_3(s + 10) << 3;
    int64_t h4 = load_3(s + 13) << 2;
    int64_t h5 = load_4(s + 16);
    int64_t h6 = load_3(s + 20) << 7;
    int64_t h7 = load_3(s + 23) << 5;
    int64_t h8 = load_3(s + 26) << 4;
    int64_t h9 = (load_3(s + 29) & 0x7fffff) << 2;
    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;

    carry9 = h9 + (1 << 24);
    h0 += (carry9 >> 25) * 19;
    h9 -= carry9 & kTop39Bits;
    carry1 = h1 + (1 << 24);
    h2 += carry1 >> 25;
    h1 -= carry1 & kTop39Bits;
    carry3 = h3 + (1 << 24);
    h4 += carry3 >> 25;
    h3 -= carry3 & kTop39Bits;
    carry5 = h5 + (1 << 24);
    h6 += carry5 >> 25;
    h5 -= carry5 & kTop39Bits;
    carry7 = h7 + (1 << 24);
    h8 += carry7 >> 25;
    h7 -= carry7 & kTop39Bits;

    carry0 = h0 + (1 << 25);
    h1 += carry0 >> 26;
    h0 -= carry0 & kTop38Bits;
    carry2 = h2 + (1 << 25);
    h3 += carry2 >> 26;
    h2 -= carry2 & kTop38Bits;
    carry4 = h4 + (1 << 25);
    h5 += carry4 >> 26;
    h4 -= carry4 & kTop38Bits;
    carry6 = h6 + (1 << 25);
    h7 += carry6 >> 26;
    h6 -= carry6 & kTop38Bits;
    carry8 = h8 + (1 << 25);
    h9 += carry8 >> 26;
    h8 -= carry8 & kTop38Bits;

    h[0] = (int32_t)h0;
    h[1] = (int32_t)h1;
    h[2] = (int32_t)h2;
    h[3] = (int32_t)h3;
    h[4] = (int32_t)h4;
    h[5] = (int32_t)h5;
    h[6] = (int32_t)h6;
    h[7] = (int32_t)h7;
    h[8] = (int32_t)h8;
    h[9] = (int32_t)h9;
}

/*
 * Preconditions:
 *   |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
 *
 * Write p=2^255-19; q=floor(h/p).
 * Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).
 *
 * Proof:
 *   Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
 *   Also have |h-2^230 h9|<2^231 so |19 2^(-255)(h-2^230 h9)|<1/4.
 *
 *   Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
 *   Then 0<y<1.
 *
 *   Write r=h-pq.
 *   Have 0<=r<=p-1=2^255-20.
 *   Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.
 *
 *   Write x=r+19(2^-255)r+y.
 *   Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.
 *
 *   Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
 *   so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.
 */
static void fe_tobytes(uint8_t *s, const fe h)
{
    int32_t h0 = h[0];
    int32_t h1 = h[1];
    int32_t h2 = h[2];
    int32_t h3 = h[3];
    int32_t h4 = h[4];
    int32_t h5 = h[5];
    int32_t h6 = h[6];
    int32_t h7 = h[7];
    int32_t h8 = h[8];
    int32_t h9 = h[9];
    int32_t q;

    q = (19 * h9 + (((int32_t)1) << 24)) >> 25;
    q = (h0 + q) >> 26;
    q = (h1 + q) >> 25;
    q = (h2 + q) >> 26;
    q = (h3 + q) >> 25;
    q = (h4 + q) >> 26;
    q = (h5 + q) >> 25;
    q = (h6 + q) >> 26;
    q = (h7 + q) >> 25;
    q = (h8 + q) >> 26;
    q = (h9 + q) >> 25;

    /* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
    h0 += 19 * q;
    /* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */

    h1 += h0 >> 26;
    h0 &= kBottom26Bits;
    h2 += h1 >> 25;
    h1 &= kBottom25Bits;
    h3 += h2 >> 26;
    h2 &= kBottom26Bits;
    h4 += h3 >> 25;
    h3 &= kBottom25Bits;
    h5 += h4 >> 26;
    h4 &= kBottom26Bits;
    h6 += h5 >> 25;
    h5 &= kBottom25Bits;
    h7 += h6 >> 26;
    h6 &= kBottom26Bits;
    h8 += h7 >> 25;
    h7 &= kBottom25Bits;
    h9 += h8 >> 26;
    h8 &= kBottom26Bits;
    h9 &= kBottom25Bits;
    /* h10 = carry9 */

    /*
     * Goal: Output h0+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
     * Have h0+...+2^230 h9 between 0 and 2^255-1;
     * evidently 2^255 h10-2^255 q = 0.
     * Goal: Output h0+...+2^230 h9.
     */
    s[0] = (uint8_t)(h0 >> 0);
    s[1] = (uint8_t)(h0 >> 8);
    s[2] = (uint8_t)(h0 >> 16);
    s[3] = (uint8_t)((h0 >> 24) | ((uint32_t)(h1) << 2));
    s[4] = (uint8_t)(h1 >> 6);
    s[5] = (uint8_t)(h1 >> 14);
    s[6] = (uint8_t)((h1 >> 22) | ((uint32_t)(h2) << 3));
    s[7] = (uint8_t)(h2 >> 5);
    s[8] = (uint8_t)(h2 >> 13);
    s[9] = (uint8_t)((h2 >> 21) | ((uint32_t)(h3) << 5));
    s[10] = (uint8_t)(h3 >> 3);
    s[11] = (uint8_t)(h3 >> 11);
    s[12] = (uint8_t)((h3 >> 19) | ((uint32_t)(h4) << 6));
    s[13] = (uint8_t)(h4 >> 2);
    s[14] = (uint8_t)(h4 >> 10);
    s[15] = (uint8_t)(h4 >> 18);
    s[16] = (uint8_t)(h5 >> 0);
    s[17] = (uint8_t)(h5 >> 8);
    s[18] = (uint8_t)(h5 >> 16);
    s[19] = (uint8_t)((h5 >> 24) | ((uint32_t)(h6) << 1));
    s[20] = (uint8_t)(h6 >> 7);
    s[21] = (uint8_t)(h6 >> 15);
    s[22] = (uint8_t)((h6 >> 23) | ((uint32_t)(h7) << 3));
    s[23] = (uint8_t)(h7 >> 5);
    s[24] = (uint8_t)(h7 >> 13);
    s[25] = (uint8_t)((h7 >> 21) | ((uint32_t)(h8) << 4));
    s[26] = (uint8_t)(h8 >> 4);
    s[27] = (uint8_t)(h8 >> 12);
    s[28] = (uint8_t)((h8 >> 20) | ((uint32_t)(h9) << 6));
    s[29] = (uint8_t)(h9 >> 2);
    s[30] = (uint8_t)(h9 >> 10);
    s[31] = (uint8_t)(h9 >> 18);
}

/* h = f */
static void fe_copy(fe h, const fe f)
{
    memmove(h, f, sizeof(int32_t) * 10);
}

/* h = 0 */
static void fe_0(fe h)
{
    memset(h, 0, sizeof(int32_t) * 10);
}

/* h = 1 */
static void fe_1(fe h)
{
    memset(h, 0, sizeof(int32_t) * 10);
    h[0] = 1;
}

/*
 * h = f + g
 *
 * Can overlap h with f or g.
 *
 * Preconditions:
 *    |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 *    |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
 */
static void fe_add(fe h, const fe f, const fe g)
{
    unsigned i;

    for (i = 0; i < 10; i++) {
        h[i] = f[i] + g[i];
    }
}

/*
 * h = f - g
 *
 * Can overlap h with f or g.
 *
 * Preconditions:
 *    |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 *    |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
 */
static void fe_sub(fe h, const fe f, const fe g)
{
    unsigned i;

    for (i = 0; i < 10; i++) {
        h[i] = f[i] - g[i];
    }
}

/*
 * h = f * g
 *
 * Can overlap h with f or g.
 *
 * Preconditions:
 *    |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
 *    |g| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
 *
 * Notes on implementation strategy:
 *
 * Using schoolbook multiplication.
 * Karatsuba would save a little in some cost models.
 *
 * Most multiplications by 2 and 19 are 32-bit precomputations;
 * cheaper than 64-bit postcomputations.
 *
 * There is one remaining multiplication by 19 in the carry chain;
 * one *19 precomputation can be merged into this,
 * but the resulting data flow is considerably less clean.
 *
 * There are 12 carries below.
 * 10 of them are 2-way parallelizable and vectorizable.
 * Can get away with 11 carries, but then data flow is much deeper.
 *
 * With tighter constraints on inputs can squeeze carries into int32.
 */
static void fe_mul(fe h, const fe f, const fe g)
{
    int32_t f0 = f[0];
    int32_t f1 = f[1];
    int32_t f2 = f[2];
    int32_t f3 = f[3];
    int32_t f4 = f[4];
    int32_t f5 = f[5];
    int32_t f6 = f[6];
    int32_t f7 = f[7];
    int32_t f8 = f[8];
    int32_t f9 = f[9];
    int32_t g0 = g[0];
    int32_t g1 = g[1];
    int32_t g2 = g[2];
    int32_t g3 = g[3];
    int32_t g4 = g[4];
    int32_t g5 = g[5];
    int32_t g6 = g[6];
    int32_t g7 = g[7];
    int32_t g8 = g[8];
    int32_t g9 = g[9];
    int32_t g1_19 = 19 * g1; /* 1.959375*2^29 */
    int32_t g2_19 = 19 * g2; /* 1.959375*2^30; still ok */
    int32_t g3_19 = 19 * g3;
    int32_t g4_19 = 19 * g4;
    int32_t g5_19 = 19 * g5;
    int32_t g6_19 = 19 * g6;
    int32_t g7_19 = 19 * g7;
    int32_t g8_19 = 19 * g8;
    int32_t g9_19 = 19 * g9;
    int32_t f1_2 = 2 * f1;
    int32_t f3_2 = 2 * f3;
    int32_t f5_2 = 2 * f5;
    int32_t f7_2 = 2 * f7;
    int32_t f9_2 = 2 * f9;
    int64_t f0g0 = f0 * (int64_t)g0;
    int64_t f0g1 = f0 * (int64_t)g1;
    int64_t f0g2 = f0 * (int64_t)g2;
    int64_t f0g3 = f0 * (int64_t)g3;
    int64_t f0g4 = f0 * (int64_t)g4;
    int64_t f0g5 = f0 * (int64_t)g5;
    int64_t f0g6 = f0 * (int64_t)g6;
    int64_t f0g7 = f0 * (int64_t)g7;
    int64_t f0g8 = f0 * (int64_t)g8;
    int64_t f0g9 = f0 * (int64_t)g9;
    int64_t f1g0 = f1 * (int64_t)g0;
    int64_t f1g1_2 = f1_2 * (int64_t)g1;
    int64_t f1g2 = f1 * (int64_t)g2;
    int64_t f1g3_2 = f1_2 * (int64_t)g3;
    int64_t f1g4 = f1 * (int64_t)g4;
    int64_t f1g5_2 = f1_2 * (int64_t)g5;
    int64_t f1g6 = f1 * (int64_t)g6;
    int64_t f1g7_2 = f1_2 * (int64_t)g7;
    int64_t f1g8 = f1 * (int64_t)g8;
    int64_t f1g9_38 = f1_2 * (int64_t)g9_19;
    int64_t f2g0 = f2 * (int64_t)g0;
    int64_t f2g1 = f2 * (int64_t)g1;
    int64_t f2g2 = f2 * (int64_t)g2;
    int64_t f2g3 = f2 * (int64_t)g3;
    int64_t f2g4 = f2 * (int64_t)g4;
    int64_t f2g5 = f2 * (int64_t)g5;
    int64_t f2g6 = f2 * (int64_t)g6;
    int64_t f2g7 = f2 * (int64_t)g7;
    int64_t f2g8_19 = f2 * (int64_t)g8_19;
    int64_t f2g9_19 = f2 * (int64_t)g9_19;
    int64_t f3g0 = f3 * (int64_t)g0;
    int64_t f3g1_2 = f3_2 * (int64_t)g1;
    int64_t f3g2 = f3 * (int64_t)g2;
    int64_t f3g3_2 = f3_2 * (int64_t)g3;
    int64_t f3g4 = f3 * (int64_t)g4;
    int64_t f3g5_2 = f3_2 * (int64_t)g5;
    int64_t f3g6 = f3 * (int64_t)g6;
    int64_t f3g7_38 = f3_2 * (int64_t)g7_19;
    int64_t f3g8_19 = f3 * (int64_t)g8_19;
    int64_t f3g9_38 = f3_2 * (int64_t)g9_19;
    int64_t f4g0 = f4 * (int64_t)g0;
    int64_t f4g1 = f4 * (int64_t)g1;
    int64_t f4g2 = f4 * (int64_t)g2;
    int64_t f4g3 = f4 * (int64_t)g3;
    int64_t f4g4 = f4 * (int64_t)g4;
    int64_t f4g5 = f4 * (int64_t)g5;
    int64_t f4g6_19 = f4 * (int64_t)g6_19;
    int64_t f4g7_19 = f4 * (int64_t)g7_19;
    int64_t f4g8_19 = f4 * (int64_t)g8_19;
    int64_t f4g9_19 = f4 * (int64_t)g9_19;
    int64_t f5g0 = f5 * (int64_t)g0;
    int64_t f5g1_2 = f5_2 * (int64_t)g1;
    int64_t f5g2 = f5 * (int64_t)g2;
    int64_t f5g3_2 = f5_2 * (int64_t)g3;
    int64_t f5g4 = f5 * (int64_t)g4;
    int64_t f5g5_38 = f5_2 * (int64_t)g5_19;
    int64_t f5g6_19 = f5 * (int64_t)g6_19;
    int64_t f5g7_38 = f5_2 * (int64_t)g7_19;
    int64_t f5g8_19 = f5 * (int64_t)g8_19;
    int64_t f5g9_38 = f5_2 * (int64_t)g9_19;
    int64_t f6g0 = f6 * (int64_t)g0;
    int64_t f6g1 = f6 * (int64_t)g1;
    int64_t f6g2 = f6 * (int64_t)g2;
    int64_t f6g3 = f6 * (int64_t)g3;
    int64_t f6g4_19 = f6 * (int64_t)g4_19;
    int64_t f6g5_19 = f6 * (int64_t)g5_19;
    int64_t f6g6_19 = f6 * (int64_t)g6_19;
    int64_t f6g7_19 = f6 * (int64_t)g7_19;
    int64_t f6g8_19 = f6 * (int64_t)g8_19;
    int64_t f6g9_19 = f6 * (int64_t)g9_19;
    int64_t f7g0 = f7 * (int64_t)g0;
    int64_t f7g1_2 = f7_2 * (int64_t)g1;
    int64_t f7g2 = f7 * (int64_t)g2;
    int64_t f7g3_38 = f7_2 * (int64_t)g3_19;
    int64_t f7g4_19 = f7 * (int64_t)g4_19;
    int64_t f7g5_38 = f7_2 * (int64_t)g5_19;
    int64_t f7g6_19 = f7 * (int64_t)g6_19;
    int64_t f7g7_38 = f7_2 * (int64_t)g7_19;
    int64_t f7g8_19 = f7 * (int64_t)g8_19;
    int64_t f7g9_38 = f7_2 * (int64_t)g9_19;
    int64_t f8g0 = f8 * (int64_t)g0;
    int64_t f8g1 = f8 * (int64_t)g1;
    int64_t f8g2_19 = f8 * (int64_t)g2_19;
    int64_t f8g3_19 = f8 * (int64_t)g3_19;
    int64_t f8g4_19 = f8 * (int64_t)g4_19;
    int64_t f8g5_19 = f8 * (int64_t)g5_19;
    int64_t f8g6_19 = f8 * (int64_t)g6_19;
    int64_t f8g7_19 = f8 * (int64_t)g7_19;
    int64_t f8g8_19 = f8 * (int64_t)g8_19;
    int64_t f8g9_19 = f8 * (int64_t)g9_19;
    int64_t f9g0 = f9 * (int64_t)g0;
    int64_t f9g1_38 = f9_2 * (int64_t)g1_19;
    int64_t f9g2_19 = f9 * (int64_t)g2_19;
    int64_t f9g3_38 = f9_2 * (int64_t)g3_19;
    int64_t f9g4_19 = f9 * (int64_t)g4_19;
    int64_t f9g5_38 = f9_2 * (int64_t)g5_19;
    int64_t f9g6_19 = f9 * (int64_t)g6_19;
    int64_t f9g7_38 = f9_2 * (int64_t)g7_19;
    int64_t f9g8_19 = f9 * (int64_t)g8_19;
    int64_t f9g9_38 = f9_2 * (int64_t)g9_19;
    int64_t h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
    int64_t h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
    int64_t h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
    int64_t h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
    int64_t h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
    int64_t h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
    int64_t h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
    int64_t h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
    int64_t h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
    int64_t h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;
    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;

    /* |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
     *   i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
     * |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
     *   i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9 */

    carry0 = h0 + (1 << 25);
    h1 += carry0 >> 26;
    h0 -= carry0 & kTop38Bits;
    carry4 = h4 + (1 << 25);
    h5 += carry4 >> 26;
    h4 -= carry4 & kTop38Bits;
    /* |h0| <= 2^25 */
    /* |h4| <= 2^25 */
    /* |h1| <= 1.71*2^59 */
    /* |h5| <= 1.71*2^59 */

    carry1 = h1 + (1 << 24);
    h2 += carry1 >> 25;
    h1 -= carry1 & kTop39Bits;
    carry5 = h5 + (1 << 24);
    h6 += carry5 >> 25;
    h5 -= carry5 & kTop39Bits;
    /* |h1| <= 2^24; from now on fits into int32 */
    /* |h5| <= 2^24; from now on fits into int32 */
    /* |h2| <= 1.41*2^60 */
    /* |h6| <= 1.41*2^60 */

    carry2 = h2 + (1 << 25);
    h3 += carry2 >> 26;
    h2 -= carry2 & kTop38Bits;
    carry6 = h6 + (1 << 25);
    h7 += carry6 >> 26;
    h6 -= carry6 & kTop38Bits;
    /* |h2| <= 2^25; from now on fits into int32 unchanged */
    /* |h6| <= 2^25; from now on fits into int32 unchanged */
    /* |h3| <= 1.71*2^59 */
    /* |h7| <= 1.71*2^59 */

    carry3 = h3 + (1 << 24);
    h4 += carry3 >> 25;
    h3 -= carry3 & kTop39Bits;
    carry7 = h7 + (1 << 24);
    h8 += carry7 >> 25;
    h7 -= carry7 & kTop39Bits;
    /* |h3| <= 2^24; from now on fits into int32 unchanged */
    /* |h7| <= 2^24; from now on fits into int32 unchanged */
    /* |h4| <= 1.72*2^34 */
    /* |h8| <= 1.41*2^60 */

    carry4 = h4 + (1 << 25);
    h5 += carry4 >> 26;
    h4 -= carry4 & kTop38Bits;
    carry8 = h8 + (1 << 25);
    h9 += carry8 >> 26;
    h8 -= carry8 & kTop38Bits;
    /* |h4| <= 2^25; from now on fits into int32 unchanged */
    /* |h8| <= 2^25; from now on fits into int32 unchanged */
    /* |h5| <= 1.01*2^24 */
    /* |h9| <= 1.71*2^59 */

    carry9 = h9 + (1 << 24);
    h0 += (carry9 >> 25) * 19;
    h9 -= carry9 & kTop39Bits;
    /* |h9| <= 2^24; from now on fits into int32 unchanged */
    /* |h0| <= 1.1*2^39 */

    carry0 = h0 + (1 << 25);
    h1 += carry0 >> 26;
    h0 -= carry0 & kTop38Bits;
    /* |h0| <= 2^25; from now on fits into int32 unchanged */
    /* |h1| <= 1.01*2^24 */

    h[0] = (int32_t)h0;
    h[1] = (int32_t)h1;
    h[2] = (int32_t)h2;
    h[3] = (int32_t)h3;
    h[4] = (int32_t)h4;
    h[5] = (int32_t)h5;
    h[6] = (int32_t)h6;
    h[7] = (int32_t)h7;
    h[8] = (int32_t)h8;
    h[9] = (int32_t)h9;
}

/*
 * h = f * f
 *
 * Can overlap h with f.
 *
 * Preconditions:
 *    |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
 *
 * See fe_mul.c for discussion of implementation strategy.
 */
static void fe_sq(fe h, const fe f)
{
    int32_t f0 = f[0];
    int32_t f1 = f[1];
    int32_t f2 = f[2];
    int32_t f3 = f[3];
    int32_t f4 = f[4];
    int32_t f5 = f[5];
    int32_t f6 = f[6];
    int32_t f7 = f[7];
    int32_t f8 = f[8];
    int32_t f9 = f[9];
    int32_t f0_2 = 2 * f0;
    int32_t f1_2 = 2 * f1;
    int32_t f2_2 = 2 * f2;
    int32_t f3_2 = 2 * f3;
    int32_t f4_2 = 2 * f4;
    int32_t f5_2 = 2 * f5;
    int32_t f6_2 = 2 * f6;
    int32_t f7_2 = 2 * f7;
    int32_t f5_38 = 38 * f5; /* 1.959375*2^30 */
    int32_t f6_19 = 19 * f6; /* 1.959375*2^30 */
    int32_t f7_38 = 38 * f7; /* 1.959375*2^30 */
    int32_t f8_19 = 19 * f8; /* 1.959375*2^30 */
    int32_t f9_38 = 38 * f9; /* 1.959375*2^30 */
    int64_t f0f0 = f0 * (int64_t)f0;
    int64_t f0f1_2 = f0_2 * (int64_t)f1;
    int64_t f0f2_2 = f0_2 * (int64_t)f2;
    int64_t f0f3_2 = f0_2 * (int64_t)f3;
    int64_t f0f4_2 = f0_2 * (int64_t)f4;
    int64_t f0f5_2 = f0_2 * (int64_t)f5;
    int64_t f0f6_2 = f0_2 * (int64_t)f6;
    int64_t f0f7_2 = f0_2 * (int64_t)f7;
    int64_t f0f8_2 = f0_2 * (int64_t)f8;
    int64_t f0f9_2 = f0_2 * (int64_t)f9;
    int64_t f1f1_2 = f1_2 * (int64_t)f1;
    int64_t f1f2_2 = f1_2 * (int64_t)f2;
    int64_t f1f3_4 = f1_2 * (int64_t)f3_2;
    int64_t f1f4_2 = f1_2 * (int64_t)f4;
    int64_t f1f5_4 = f1_2 * (int64_t)f5_2;
    int64_t f1f6_2 = f1_2 * (int64_t)f6;
    int64_t f1f7_4 = f1_2 * (int64_t)f7_2;
    int64_t f1f8_2 = f1_2 * (int64_t)f8;
    int64_t f1f9_76 = f1_2 * (int64_t)f9_38;
    int64_t f2f2 = f2 * (int64_t)f2;
    int64_t f2f3_2 = f2_2 * (int64_t)f3;
    int64_t f2f4_2 = f2_2 * (int64_t)f4;
    int64_t f2f5_2 = f2_2 * (int64_t)f5;
    int64_t f2f6_2 = f2_2 * (int64_t)f6;
    int64_t f2f7_2 = f2_2 * (int64_t)f7;
    int64_t f2f8_38 = f2_2 * (int64_t)f8_19;
    int64_t f2f9_38 = f2 * (int64_t)f9_38;
    int64_t f3f3_2 = f3_2 * (int64_t)f3;
    int64_t f3f4_2 = f3_2 * (int64_t)f4;
    int64_t f3f5_4 = f3_2 * (int64_t)f5_2;
    int64_t f3f6_2 = f3_2 * (int64_t)f6;
    int64_t f3f7_76 = f3_2 * (int64_t)f7_38;
    int64_t f3f8_38 = f3_2 * (int64_t)f8_19;
    int64_t f3f9_76 = f3_2 * (int64_t)f9_38;
    int64_t f4f4 = f4 * (int64_t)f4;
    int64_t f4f5_2 = f4_2 * (int64_t)f5;
    int64_t f4f6_38 = f4_2 * (int64_t)f6_19;
    int64_t f4f7_38 = f4 * (int64_t)f7_38;
    int64_t f4f8_38 = f4_2 * (int64_t)f8_19;
    int64_t f4f9_38 = f4 * (int64_t)f9_38;
    int64_t f5f5_38 = f5 * (int64_t)f5_38;
    int64_t f5f6_38 = f5_2 * (int64_t)f6_19;
    int64_t f5f7_76 = f5_2 * (int64_t)f7_38;
    int64_t f5f8_38 = f5_2 * (int64_t)f8_19;
    int64_t f5f9_76 = f5_2 * (int64_t)f9_38;
    int64_t f6f6_19 = f6 * (int64_t)f6_19;
    int64_t f6f7_38 = f6 * (int64_t)f7_38;
    int64_t f6f8_38 = f6_2 * (int64_t)f8_19;
    int64_t f6f9_38 = f6 * (int64_t)f9_38;
    int64_t f7f7_38 = f7 * (int64_t)f7_38;
    int64_t f7f8_38 = f7_2 * (int64_t)f8_19;
    int64_t f7f9_76 = f7_2 * (int64_t)f9_38;
    int64_t f8f8_19 = f8 * (int64_t)f8_19;
    int64_t f8f9_38 = f8 * (int64_t)f9_38;
    int64_t f9f9_38 = f9 * (int64_t)f9_38;
    int64_t h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
    int64_t h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
    int64_t h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
    int64_t h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
    int64_t h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
    int64_t h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
    int64_t h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
    int64_t h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
    int64_t h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
    int64_t h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;

    carry0 = h0 + (1 << 25);
    h1 += carry0 >> 26;
    h0 -= carry0 & kTop38Bits;
    carry4 = h4 + (1 << 25);
    h5 += carry4 >> 26;
    h4 -= carry4 & kTop38Bits;

    carry1 = h1 + (1 << 24);
    h2 += carry1 >> 25;
    h1 -= carry1 & kTop39Bits;
    carry5 = h5 + (1 << 24);
    h6 += carry5 >> 25;
    h5 -= carry5 & kTop39Bits;

    carry2 = h2 + (1 << 25);
    h3 += carry2 >> 26;
    h2 -= carry2 & kTop38Bits;
    carry6 = h6 + (1 << 25);
    h7 += carry6 >> 26;
    h6 -= carry6 & kTop38Bits;

    carry3 = h3 + (1 << 24);
    h4 += carry3 >> 25;
    h3 -= carry3 & kTop39Bits;
    carry7 = h7 + (1 << 24);
    h8 += carry7 >> 25;
    h7 -= carry7 & kTop39Bits;

    carry4 = h4 + (1 << 25);
    h5 += carry4 >> 26;
    h4 -= carry4 & kTop38Bits;
    carry8 = h8 + (1 << 25);
    h9 += carry8 >> 26;
    h8 -= carry8 & kTop38Bits;

    carry9 = h9 + (1 << 24);
    h0 += (carry9 >> 25) * 19;
    h9 -= carry9 & kTop39Bits;

    carry0 = h0 + (1 << 25);
    h1 += carry0 >> 26;
    h0 -= carry0 & kTop38Bits;

    h[0] = (int32_t)h0;
    h[1] = (int32_t)h1;
    h[2] = (int32_t)h2;
    h[3] = (int32_t)h3;
    h[4] = (int32_t)h4;
    h[5] = (int32_t)h5;
    h[6] = (int32_t)h6;
    h[7] = (int32_t)h7;
    h[8] = (int32_t)h8;
    h[9] = (int32_t)h9;
}

static void fe_invert(fe out, const fe z)
{
    fe t0;
    fe t1;
    fe t2;
    fe t3;
    int i;

    /*
     * Compute z ** -1 = z ** (2 ** 255 - 19 - 2) with the exponent as
     * 2 ** 255 - 21 = (2 ** 5) * (2 ** 250 - 1) + 11.
     */

    /* t0 = z ** 2 */
    fe_sq(t0, z);

    /* t1 = t0 ** (2 ** 2) = z ** 8 */
    fe_sq(t1, t0);
    fe_sq(t1, t1);

    /* t1 = z * t1 = z ** 9 */
    fe_mul(t1, z, t1);
    /* t0 = t0 * t1 = z ** 11 -- stash t0 away for the end. */
    fe_mul(t0, t0, t1);

    /* t2 = t0 ** 2 = z ** 22 */
    fe_sq(t2, t0);

    /* t1 = t1 * t2 = z ** (2 ** 5 - 1) */
    fe_mul(t1, t1, t2);

    /* t2 = t1 ** (2 ** 5) = z ** ((2 ** 5) * (2 ** 5 - 1)) */
    fe_sq(t2, t1);
    for (i = 1; i < 5; ++i) {
        fe_sq(t2, t2);
    }

    /* t1 = t1 * t2 = z ** ((2 ** 5 + 1) * (2 ** 5 - 1)) = z ** (2 ** 10 - 1) */
    fe_mul(t1, t2, t1);

    /* Continuing similarly... */

    /* t2 = z ** (2 ** 20 - 1) */
    fe_sq(t2, t1);
    for (i = 1; i < 10; ++i) {
        fe_sq(t2, t2);
    }
    fe_mul(t2, t2, t1);

    /* t2 = z ** (2 ** 40 - 1) */
    fe_sq(t3, t2);
    for (i = 1; i < 20; ++i) {
        fe_sq(t3, t3);
    }
    fe_mul(t2, t3, t2);

    /* t2 = z ** (2 ** 10) * (2 ** 40 - 1) */
    for (i = 0; i < 10; ++i) {
        fe_sq(t2, t2);
    }
    /* t1 = z ** (2 ** 50 - 1) */
    fe_mul(t1, t2, t1);

    /* t2 = z ** (2 ** 100 - 1) */
    fe_sq(t2, t1);
    for (i = 1; i < 50; ++i) {
        fe_sq(t2, t2);
    }
    fe_mul(t2, t2, t1);

    /* t2 = z ** (2 ** 200 - 1) */
    fe_sq(t3, t2);
    for (i = 1; i < 100; ++i) {
        fe_sq(t3, t3);
    }
    fe_mul(t2, t3, t2);

    /* t2 = z ** ((2 ** 50) * (2 ** 200 - 1) */
    fe_sq(t2, t2);
    for (i = 1; i < 50; ++i) {
        fe_sq(t2, t2);
    }

    /* t1 = z ** (2 ** 250 - 1) */
    fe_mul(t1, t2, t1);

    /* t1 = z ** ((2 ** 5) * (2 ** 250 - 1)) */
    fe_sq(t1, t1);
    for (i = 1; i < 5; ++i) {
        fe_sq(t1, t1);
    }

    /* Recall t0 = z ** 11; out = z ** (2 ** 255 - 21) */
    fe_mul(out, t1, t0);
}

/*
 * h = -f
 *
 * Preconditions:
 *    |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 */
static void fe_neg(fe h, const fe f)
{
    unsigned i;

    for (i = 0; i < 10; i++) {
        h[i] = -f[i];
    }
}

/*
 * Replace (f,g) with (g,g) if b == 1;
 * replace (f,g) with (f,g) if b == 0.
 *
 * Preconditions: b in {0,1}.
 */
static void fe_cmov(fe f, const fe g, unsigned b)
{
    size_t i;

    b = 0 - b;
    for (i = 0; i < 10; i++) {
        int32_t x = f[i] ^ g[i];
        x &= b;
        f[i] ^= x;
    }
}

#endif /* !BASE_2_51_IMPLEMENTED */

/*
 * return 0 if f == 0
 * return 1 if f != 0
 *
 * Preconditions:
 *    |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
 */
static int fe_isnonzero(const fe f)
{
    uint8_t s[32];
    static const uint8_t zero[32] = { 0 };

    fe_tobytes(s, f);

    return CRYPTO_memcmp(s, zero, sizeof(zero)) != 0;
}

/*
 * return 1 if f is in {1,3,5,...,q-2}
 * return 0 if f is in {0,2,4,...,q-1}
 *
 * Preconditions:
 *    |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
 */
static int fe_isnegative(const fe f)
{
    uint8_t s[32];

    fe_tobytes(s, f);
    return s[0] & 1;
}

#if !defined(BASE_2_51_IMPLEMENTED)

/*
 * h = 2 * f * f
 *
 * Can overlap h with f.
 *
 * Preconditions:
 *    |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
 *
 * See fe_mul.c for discussion of implementation strategy.
 */
static void fe_sq2(fe h, const fe f)
{
    int32_t f0 = f[0];
    int32_t f1 = f[1];
    int32_t f2 = f[2];
    int32_t f3 = f[3];
    int32_t f4 = f[4];
    int32_t f5 = f[5];
    int32_t f6 = f[6];
    int32_t f7 = f[7];
    int32_t f8 = f[8];
    int32_t f9 = f[9];
    int32_t f0_2 = 2 * f0;
    int32_t f1_2 = 2 * f1;
    int32_t f2_2 = 2 * f2;
    int32_t f3_2 = 2 * f3;
    int32_t f4_2 = 2 * f4;
    int32_t f5_2 = 2 * f5;
    int32_t f6_2 = 2 * f6;
    int32_t f7_2 = 2 * f7;
    int32_t f5_38 = 38 * f5; /* 1.959375*2^30 */
    int32_t f6_19 = 19 * f6; /* 1.959375*2^30 */
    int32_t f7_38 = 38 * f7; /* 1.959375*2^30 */
    int32_t f8_19 = 19 * f8; /* 1.959375*2^30 */
    int32_t f9_38 = 38 * f9; /* 1.959375*2^30 */
    int64_t f0f0 = f0 * (int64_t)f0;
    int64_t f0f1_2 = f0_2 * (int64_t)f1;
    int64_t f0f2_2 = f0_2 * (int64_t)f2;
    int64_t f0f3_2 = f0_2 * (int64_t)f3;
    int64_t f0f4_2 = f0_2 * (int64_t)f4;
    int64_t f0f5_2 = f0_2 * (int64_t)f5;
    int64_t f0f6_2 = f0_2 * (int64_t)f6;
    int64_t f0f7_2 = f0_2 * (int64_t)f7;
    int64_t f0f8_2 = f0_2 * (int64_t)f8;
    int64_t f0f9_2 = f0_2 * (int64_t)f9;
    int64_t f1f1_2 = f1_2 * (int64_t)f1;
    int64_t f1f2_2 = f1_2 * (int64_t)f2;
    int64_t f1f3_4 = f1_2 * (int64_t)f3_2;
    int64_t f1f4_2 = f1_2 * (int64_t)f4;
    int64_t f1f5_4 = f1_2 * (int64_t)f5_2;
    int64_t f1f6_2 = f1_2 * (int64_t)f6;
    int64_t f1f7_4 = f1_2 * (int64_t)f7_2;
    int64_t f1f8_2 = f1_2 * (int64_t)f8;
    int64_t f1f9_76 = f1_2 * (int64_t)f9_38;
    int64_t f2f2 = f2 * (int64_t)f2;
    int64_t f2f3_2 = f2_2 * (int64_t)f3;
    int64_t f2f4_2 = f2_2 * (int64_t)f4;
    int64_t f2f5_2 = f2_2 * (int64_t)f5;
    int64_t f2f6_2 = f2_2 * (int64_t)f6;
    int64_t f2f7_2 = f2_2 * (int64_t)f7;
    int64_t f2f8_38 = f2_2 * (int64_t)f8_19;
    int64_t f2f9_38 = f2 * (int64_t)f9_38;
    int64_t f3f3_2 = f3_2 * (int64_t)f3;
    int64_t f3f4_2 = f3_2 * (int64_t)f4;
    int64_t f3f5_4 = f3_2 * (int64_t)f5_2;
    int64_t f3f6_2 = f3_2 * (int64_t)f6;
    int64_t f3f7_76 = f3_2 * (int64_t)f7_38;
    int64_t f3f8_38 = f3_2 * (int64_t)f8_19;
    int64_t f3f9_76 = f3_2 * (int64_t)f9_38;
    int64_t f4f4 = f4 * (int64_t)f4;
    int64_t f4f5_2 = f4_2 * (int64_t)f5;
    int64_t f4f6_38 = f4_2 * (int64_t)f6_19;
    int64_t f4f7_38 = f4 * (int64_t)f7_38;
    int64_t f4f8_38 = f4_2 * (int64_t)f8_19;
    int64_t f4f9_38 = f4 * (int64_t)f9_38;
    int64_t f5f5_38 = f5 * (int64_t)f5_38;
    int64_t f5f6_38 = f5_2 * (int64_t)f6_19;
    int64_t f5f7_76 = f5_2 * (int64_t)f7_38;
    int64_t f5f8_38 = f5_2 * (int64_t)f8_19;
    int64_t f5f9_76 = f5_2 * (int64_t)f9_38;
    int64_t f6f6_19 = f6 * (int64_t)f6_19;
    int64_t f6f7_38 = f6 * (int64_t)f7_38;
    int64_t f6f8_38 = f6_2 * (int64_t)f8_19;
    int64_t f6f9_38 = f6 * (int64_t)f9_38;
    int64_t f7f7_38 = f7 * (int64_t)f7_38;
    int64_t f7f8_38 = f7_2 * (int64_t)f8_19;
    int64_t f7f9_76 = f7_2 * (int64_t)f9_38;
    int64_t f8f8_19 = f8 * (int64_t)f8_19;
    int64_t f8f9_38 = f8 * (int64_t)f9_38;
    int64_t f9f9_38 = f9 * (int64_t)f9_38;
    int64_t h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
    int64_t h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
    int64_t h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
    int64_t h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
    int64_t h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
    int64_t h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
    int64_t h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
    int64_t h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
    int64_t h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
    int64_t h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;

    h0 += h0;
    h1 += h1;
    h2 += h2;
    h3 += h3;
    h4 += h4;
    h5 += h5;
    h6 += h6;
    h7 += h7;
    h8 += h8;
    h9 += h9;

    carry0 = h0 + (1 << 25);
    h1 += carry0 >> 26;
    h0 -= carry0 & kTop38Bits;
    carry4 = h4 + (1 << 25);
    h5 += carry4 >> 26;
    h4 -= carry4 & kTop38Bits;

    carry1 = h1 + (1 << 24);
    h2 += carry1 >> 25;
    h1 -= carry1 & kTop39Bits;
    carry5 = h5 + (1 << 24);
    h6 += carry5 >> 25;
    h5 -= carry5 & kTop39Bits;

    carry2 = h2 + (1 << 25);
    h3 += carry2 >> 26;
    h2 -= carry2 & kTop38Bits;
    carry6 = h6 + (1 << 25);
    h7 += carry6 >> 26;
    h6 -= carry6 & kTop38Bits;

    carry3 = h3 + (1 << 24);
    h4 += carry3 >> 25;
    h3 -= carry3 & kTop39Bits;
    carry7 = h7 + (1 << 24);
    h8 += carry7 >> 25;
    h7 -= carry7 & kTop39Bits;

    carry4 = h4 + (1 << 25);
    h5 += carry4 >> 26;
    h4 -= carry4 & kTop38Bits;
    carry8 = h8 + (1 << 25);
    h9 += carry8 >> 26;
    h8 -= carry8 & kTop38Bits;

    carry9 = h9 + (1 << 24);
    h0 += (carry9 >> 25) * 19;
    h9 -= carry9 & kTop39Bits;

    carry0 = h0 + (1 << 25);
    h1 += carry0 >> 26;
    h0 -= carry0 & kTop38Bits;

    h[0] = (int32_t)h0;
    h[1] = (int32_t)h1;
    h[2] = (int32_t)h2;
    h[3] = (int32_t)h3;
    h[4] = (int32_t)h4;
    h[5] = (int32_t)h5;
    h[6] = (int32_t)h6;
    h[7] = (int32_t)h7;
    h[8] = (int32_t)h8;
    h[9] = (int32_t)h9;
}

#endif /* !BASE_2_51_IMPLEMENTED */

static void fe_pow22523(fe out, const fe z)
{
    fe t0;
    fe t1;
    fe t2;
    int i;

    fe_sq(t0, z);
    fe_sq(t1, t0);
    for (i = 1; i < 2; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t0, t0);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 5; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 10; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (i = 1; i < 20; ++i) {
        fe_sq(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 1; i < 10; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 50; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (i = 1; i < 100; ++i) {
        fe_sq(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 1; i < 50; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sq(t0, t0);
    for (i = 1; i < 2; ++i) {
        fe_sq(t0, t0);
    }
    fe_mul(out, t0, z);
}

/*
 * ge means group element.
 *
 * Here the group is the set of pairs (x,y) of field elements (see fe.h)
 * satisfying -x^2 + y^2 = 1 + d x^2y^2
 * where d = -121665/121666.
 *
 * Representations:
 *   ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
 *   ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
 *   ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
 *   ge_precomp (Duif): (y+x,y-x,2dxy)
 */
typedef struct {
    fe X;
    fe Y;
    fe Z;
} ge_p2;

typedef struct {
    fe X;
    fe Y;
    fe Z;
    fe T;
} ge_p3;

typedef struct {
    fe X;
    fe Y;
    fe Z;
    fe T;
} ge_p1p1;

typedef struct {
    fe yplusx;
    fe yminusx;
    fe xy2d;
} ge_precomp;

typedef struct {
    fe YplusX;
    fe YminusX;
    fe Z;
    fe T2d;
} ge_cached;

static void ge_tobytes(uint8_t *s, const ge_p2 *h)
{
    fe recip;
    fe x;
    fe y;

    fe_invert(recip, h->Z);
    fe_mul(x, h->X, recip);
    fe_mul(y, h->Y, recip);
    fe_tobytes(s, y);
    s[31] ^= fe_isnegative(x) << 7;
}

static void ge_p3_tobytes(uint8_t *s, const ge_p3 *h)
{
    fe recip;
    fe x;
    fe y;

    fe_invert(recip, h->Z);
    fe_mul(x, h->X, recip);
    fe_mul(y, h->Y, recip);
    fe_tobytes(s, y);
    s[31] ^= fe_isnegative(x) << 7;
}

#if defined(BASE_2_51_IMPLEMENTED)
static const fe d = {
    0x34dca135978a3, 0x1a8283b156ebd, 0x5e7a26001c029,
    0x739c663a03cbb, 0x52036cee2b6ff
};

static const fe sqrtm1 = {
    0x61b274a0ea0b0, 0x0d5a5fc8f189d, 0x7ef5e9cbd0c60,
    0x78595a6804c9e, 0x2b8324804fc1d
};
#else
static const fe d = {
    -10913610, 13857413, -15372611, 6949391, 114729,
    -8787816, -6275908, -3247719, -18696448, -12055116
};

static const fe sqrtm1 = {
    -32595792, -7943725, 9377950, 3500415, 12389472,
    -272473, -25146209, -2005654, 326686, 11406482
};
#endif

static int ge_frombytes_vartime(ge_p3 *h, const uint8_t *s)
{
    fe u;
    fe v;
    fe w;
    fe vxx;
    fe check;

    fe_frombytes(h->Y, s);
    fe_1(h->Z);
    fe_sq(u, h->Y);
    fe_mul(v, u, d);
    fe_sub(u, u, h->Z); /* u = y^2-1 */
    fe_add(v, v, h->Z); /* v = dy^2+1 */

    fe_mul(w, u, v); /* w = u*v */

    fe_pow22523(h->X, w); /* x = w^((q-5)/8) */
    fe_mul(h->X, h->X, u); /* x = u * w^((q-5)/8) */

    fe_sq(vxx, h->X);
    fe_mul(vxx, vxx, v);
    /*
     * u-vx^2 rather than vx^2-u: with the base 2^51 arithmetic the
     * subtrahend must not itself be a difference, see fe51_sub.
     */
    fe_sub(check, u, vxx);
    if (fe_isnonzero(check)) {
        fe_add(check, vxx, u); /* vx^2+u */
        if (fe_isnonzero(check)) {
            return -1;
        }
        fe_mul(h->X, h->X, sqrtm1);
    }

    if (fe_isnegative(h->X) != (s[31] >> 7)) {
        fe_neg(h->X, h->X);
    }

    fe_mul(h->T, h->X, h->Y);
    return 0;
}

static void ge_p2_0(ge_p2 *h)
{
    fe_0(h->X);
    fe_1(h->Y);
    fe_1(h->Z);
}

static void ge_p3_0(ge_p3 *h)
{
    fe_0(h->X);
    fe_1(h->Y);
    fe_1(h->Z);
    fe_0(h->T);
}

static void ge_precomp_0(ge_precomp *h)
{
    fe_1(h->yplusx);
    fe_1(h->yminusx);
    fe_0(h->xy2d);
}

/* r = p */
static void ge_p3_to_p2(ge_p2 *r, const ge_p3 *p)
{
    fe_copy(r->X, p->X);
    fe_copy(r->Y, p->Y);
    fe_copy(r->Z, p->Z);
}

#if defined(BASE_2_51_IMPLEMENTED)
static const fe d2 = {
    0x69b9426b2f159, 0x35050762add7a, 0x3cf44c0038052,
    0x6738cc7407977, 0x2406d9dc56dff
};
#else
static const fe d2 = {
    -21827239, -5839606, -30745221, 13898782, 229458,
    15978800, -12551817, -6495438, 29715968, 9444199
};
#endif

/* r = p */
static void ge_p3_to_cached(ge_cached *r, const ge_p3 *p)
{
    fe_add(r->YplusX, p->Y, p->X);
    fe_sub(r->YminusX, p->Y, p->X);
    fe_copy(r->Z, p->Z);
    fe_mul(r->T2d, p->T, d2);
}

/* r = p */
static void ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p)
{
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
}

/* r = p */
static void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p)
{
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
    fe_mul(r->T, p->X, p->Y);
}

/* r = 2 * p */
static void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p)
{
    fe t0;

    fe_sq(r->X, p->X);
    fe_sq(r->Z, p->Y);
    fe_sq2(r->T, p->Z);
    fe_add(r->Y, p->X, p->Y);
    fe_sq(t0, r->Y);
    fe_add(r->Y, r->Z, r->X);
    /*
     * T = 2Z^2 - (Y^2 - X^2) is computed as (2Z^2 - Y^2) + X^2: with the
     * base 2^51 arithmetic the subtrahend must not itself be a difference,
     * see fe51_sub.
     */
    fe_sub(r->T, r->T, r->Z);
    fe_add(r->T, r->T, r->X);
    fe_sub(r->Z, r->Z, r->X);
    fe_sub(r->X, t0, r->Y);
}

/* r = 2 * p */
static void ge_p3_dbl(ge_p1p1 *r, const ge_p3 *p)
{
    ge_p2 q;
    ge_p3_to_p2(&q, p);
    ge_p2_dbl(r, &q);
}

/* r = p + q */
static void ge_madd(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q)
{
    fe t0;

    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(r->Z, r->X, q->yplusx);
    fe_mul(r->Y, r->Y, q->yminusx);
    fe_mul(r->T, q->xy2d, p->T);
    fe_add(t0, p->Z, p->Z);
    fe_sub(r->X, r->Z, r->Y);
    fe_add(r->Y, r->Z, r->Y);
    fe_add(r->Z, t0, r->T);
    fe_sub(r->T, t0, r->T);
}

/* r = p - q */
static void ge_msub(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q)
{
    fe t0;

    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(r->Z, r->X, q->yminusx);
    fe_mul(r->Y, r->Y, q->yplusx);
    fe_mul(r->T, q->xy2d, p->T);
    fe_add(t0, p->Z, p->Z);
    fe_sub(r->X, r->Z, r->Y);
    fe_add(r->Y, r->Z, r->Y);
    fe_sub(r->Z, t0, r->T);
    fe_add(r->T, t0, r->T);
}

/* r = p + q */
static void ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q)
{
    fe t0;

    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(r->Z, r->X, q->YplusX);
    fe_mul(r->Y, r->Y, q->YminusX);
    fe_mul(r->T, q->T2d, p->T);
    fe_mul(r->X, p->Z, q->Z);
    fe_add(t0, r->X, r->X);
    fe_sub(r->X, r->Z, r->Y);
    fe_add(r->Y, r->Z, r->Y);
    fe_add(r->Z, t0, r->T);
    fe_sub(r->T, t0, r->T);
}

/* r = p - q */
static void ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q)
{
    fe t0;

    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(r->Z, r->X, q->YminusX);
    fe_mul(r->Y, r->Y, q->YplusX);
    fe_mul(r->T, q->T2d, p->T);
    fe_mul(r->X, p->Z, q->Z);
    fe_add(t0, r->X, r->X);
    fe_sub(r->X, r->Z, r->Y);
    fe_add(r->Y, r->Z, r->Y);
    fe_sub(r->Z, t0, r->T);
    fe_add(r->T, t0, r->T);
}

static uint8_t equal(signed char b, signed char c)
{
    uint8_t ub = b;
    uint8_t uc = c;
    uint8_t x = ub ^ uc; /* 0: yes; 1..255: no */
    uint32_t y = x; /* 0: yes; 1..255: no */
    y -= 1; /* 4294967295: yes; 0..254: no */
    y >>= 31; /* 1: yes; 0: no */
    return y;
}

static void cmov(ge_precomp *t, const ge_precomp *u, uint8_t b)
{
    fe_cmov(t->yplusx, u->yplusx, b);
    fe_cmov(t->yminusx, u->yminusx, b);
    fe_cmov(t->xy2d, u->xy2d, b);
}

#if defined(BASE_2_51_IMPLEMENTED)
/* k25519Precomp[i][j] = (j+1)*256^i*B */
static const ge_precomp k25519Precomp[32][8] = {
    {
        {
            { 0x493c6f58c3b85, 0x0df7181c325f7, 0x0f50b0b3e4cb7,
                0x5329385a44c32, 0x07cf9d3a33d4b },
            { 0x03905d740913e, 0x0ba2817d673a2, 0x23e2827f4e67c,
                0x133d2e0c21a34, 0x44fd2f9298f81 },
            { 0x11205877aaa68, 0x479955893d579, 0x50d66309b67a0,
                0x2d42d0dbee5ee, 0x6f117b689f0c6 },
        },
        {
            { 0x4e7fc933c71d7, 0x2cf41feb6b244, 0x7581c0a7d1a76,
                0x7172d534d32f0, 0x590c063fa87d2 },
            { 0x1a56042b4d5a8, 0x189cc159ed153, 0x5b8deaa3cae04,
                0x2aaf04f11b5d8, 0x6bb595a669c92 },
            { 0x2a8b3a59b7a5f, 0x3abb359ef087f, 0x4f5a8c4db05af,
                0x5b9a807d04205, 0x701af5b13ea50 },
        },
        {
            { 0x5b0a84cee9730, 0x61d10c97155e4, 0x4059cc8096a10,
                0x47a608da8014f, 0x7a164e1b9a80f },
            { 0x11fe8a4fcd265, 0x7bcb8374faacc, 0x52f5af4ef4d4f,
                0x5314098f98d10, 0x2ab91587555bd },
            { 0x6933f0dd0d889, 0x44386bb4c4295, 0x3cb6d3162508c,
                0x26368b872a2c6, 0x5a2826af12b9b },
        },
        {
            { 0x351b98efc099f, 0x68fbfa4a7050e, 0x42a49959d971b,
                0x393e51a469efd, 0x680e910321e58 },
            { 0x6050a056818bf, 0x62acc1f5532bf, 0x28141ccc9fa25,
                0x24d61f471e683, 0x27933f4c7445a },
            { 0x3fbe9c476ff09, 0x0af6b982e4b42, 0x0ad1251ba78e5,
                0x715aeedee7c88, 0x7f9d0cbf63553 },
        },
        {
            { 0x2bc4408a5bb33, 0x078ebdda05442, 0x2ffb112354123,
                0x375ee8df5862d, 0x2945ccf146e20 },
            { 0x182c3a447d6ba, 0x22964e536eff2, 0x192821f540053,
                0x2f9f19e788e5c, 0x154a7e73eb1b5 },
            { 0x3dbf1812a8285, 0x0fa17ba3f9797, 0x6f69cb49c3820,
                0x34d5a0db3858d, 0x43aabe696b3bb },
        },
        {
            { 0x4eeeb77157131, 0x1201915f10741, 0x1669cda6c9c56,
                0x45ec032db346d, 0x51e57bb6a2cc3 },
            { 0x006b67b7d8ca4, 0x084fa44e72933, 0x1154ee55d6f8a,
                0x4425d842e7390, 0x38b64c41ae417 },
            { 0x4326702ea4b71, 0x06834376030b5, 0x0ef0512f9c380,
                0x0f1a9f2512584, 0x10b8e91a9f0d6 },
        },
        {
            { 0x25cd0944ea3bf, 0x75673b81a4d63, 0x150b925d1c0d4,
                0x13f38d9294114, 0x461bea69283c9 },
            { 0x72c9aaa3221b1, 0x267774474f74d, 0x064b0e9b28085,
                0x3f04ef53b27c9, 0x1d6edd5d2e531 },
            { 0x36dc801b8b3a2, 0x0e0a7d4935e30, 0x1deb7cecc0d7d,
                0x053a94e20dd2c, 0x7a9fbb1c6a0f9 },
        },
        {
            { 0x7596604dd3e8f, 0x6fc510e058b36, 0x3670c8db2cc0d,
                0x297d899ce332f, 0x0915e76061bce },
            { 0x75dedf39234d9, 0x01c36ab1f3c54, 0x0f08fee58f5da,
                0x0e19613a0d637, 0x3a9024a1320e0 },
            { 0x1f5d9c9a2911a, 0x7117994fafcf8, 0x2d8a8cae28dc5,
                0x74ab1b2090c87, 0x26907c5c2ecc4 },
        },
    },
    {
        {
            { 0x4dd0e632f9c1d, 0x2ced12622a5d9, 0x18de9614742da,
                0x79ca96fdbb5d4, 0x6dd37d49a00ee },
            { 0x3635449aa515e, 0x3e178d0475dab, 0x50b4712a19712,
                0x2dcc2860ff4ad, 0x30d76d6f03d31 },
            { 0x444172106e4c7, 0x01251afed2d88, 0x534fc9bed4f5a,
                0x5d85a39cf5234, 0x10c697112e864 },
        },
        {
            { 0x62aa08358c805, 0x46f440848e194, 0x447b771a8f52b,
                0x377ba3269d31d, 0x03bf9baf55080 },
            { 0x3c4277dbe5fde, 0x5a335afd44c92, 0x0c1164099753e,
                0x70487006fe423, 0x25e61cabed66f },
            { 0x3e128cc586604, 0x5968b2e8fc7e2, 0x049a3d5bd61cf,
                0x116505b1ef6e6, 0x566d78634586e },
        },
        {
            { 0x54285c65a2fd0, 0x55e62ccf87420, 0x46bb961b19044,
                0x1153405712039, 0x14fba5f34793b },
            { 0x7a49f9cc10834, 0x2b513788a22c6, 0x5ff4b6ef2395b,
                0x2ec8e5af607bf, 0x33975bca5ecc3 },
            { 0x746166985f7d4, 0x09939000ae79a, 0x5844c7964f97a,
                0x13617e1f95b3d, 0x14829cea83fc5 },
        },
        {
            { 0x70b2f4e71ecb8, 0x728148efc643c, 0x0753e03995b76,
                0x5bf5fb2ab6767, 0x05fc3bc4535d7 },
            { 0x37b8497dd95c2, 0x61549d6b4ffe8, 0x217a22db1d138,
                0x0b9cf062eb09e, 0x2fd9c71e5f758 },
            { 0x0b3ae52afdedd, 0x19da76619e497, 0x6fa0654d2558e,
                0x78219d25e41d4, 0x373767475c651 },
        },
        {
            { 0x095cb14246590, 0x002d82aa6ac68, 0x442f183bc4851,
                0x6464f1c0a0644, 0x6bf5905730907 },
            { 0x299fd40d1add9, 0x5f2de9a04e5f7, 0x7c0eebacc1c59,
                0x4cca1b1f8290a, 0x1fbea56c3b18f },
            { 0x778f1e1415b8a, 0x6f75874efc1f4, 0x28a694019027f,
                0x52b37a96bdc4d, 0x02521cf67a635 },
        },
        {
            { 0x46720772f5ee4, 0x632c0f359d622, 0x2b2092ba3e252,
                0x662257c112680, 0x001753d9f7cd6 },
            { 0x7ee0b0a9d5294, 0x381fbeb4cca27, 0x7841f3a3e639d,
                0x676ea30c3445f, 0x3fa00a7e71382 },
            { 0x1232d963ddb34, 0x35692e70b078d, 0x247ca14777a1f,
                0x6db556be8fcd0, 0x12b5fe2fa048e },
        },
        {
            { 0x37c26ad6f1e92, 0x46a0971227be5, 0x4722f0d2d9b4c,
                0x3dc46204ee03a, 0x6f7e93c20796c },
            { 0x0fbc496fce34d, 0x575be6b7dae3e, 0x4a31585cee609,
                0x037e9023930ff, 0x749b76f96fb12 },
            { 0x2f604aea6ae05, 0x637dc939323eb, 0x3fdad9b048d47,
                0x0a8b0d4045af7, 0x0fcec10f01e02 },
        },
        {
            { 0x2d29dc4244e45, 0x6927b1bc147be, 0x0308534ac0839,
                0x4853664033f41, 0x413779166feab },
            { 0x558a649fe1e44, 0x44635aeefcc89, 0x1ff434887f2ba,
                0x0f981220e2d44, 0x4901aa7183c51 },
            { 0x1b7548c1af8f0, 0x7848c53368116, 0x01b64e7383de9,
                0x109fbb0587c8f, 0x41bb887b726d1 },
        },
    },
    {
        {
            { 0x34c597c6691ae, 0x7a150b6990fc4, 0x52beb9d922274,
                0x70eed7164861a, 0x0a871e070c6a9 },
            { 0x07d44744346be, 0x282b6a564a81d, 0x4ed80f875236b,
                0x6fbbe1d450c50, 0x4eb728c12fcdb },
            { 0x1b5994bbc8989, 0x74b7ba84c0660, 0x75678f1cdaeb8,
                0x23206b0d6f10c, 0x3ee7300f2685d },
        },
        {
            { 0x27947841e7518, 0x32c7388dae87f, 0x414add3971be9,
                0x01850832f0ef1, 0x7d47c6a2cfb89 },
            { 0x255e49e7dd6b7, 0x38c2163d59eba, 0x3861f2a005845,
                0x2e11e4ccbaec9, 0x1381576297912 },
            { 0x2d0148ef0d6e0, 0x3522a8de787fb, 0x2ee055e74f9d2,
                0x64038f6310813, 0x148cf58d34c9e },
        },
        {
            { 0x72f7d9ae4756d, 0x7711e690ffc4a, 0x582a2355b0d16,
                0x0dccfe885b6b4, 0x278febad4eaea },
            { 0x492f67934f027, 0x7ded0815528d4, 0x58461511a6612,
                0x5ea2e50de1544, 0x3ff2fa1ebd5db },
            { 0x2681f8c933966, 0x3840521931635, 0x674f14a308652,
                0x3bd9c88a94890, 0x4104dd02fe9c6 },
        },
        {
            { 0x14e06db096ab8, 0x1219c89e6b024, 0x278abd486a2db,
                0x240b292609520, 0x0165b5a48efca },
            { 0x2bf5e1124422a, 0x673146756ae56, 0x14ad99a87e830,
                0x1eaca65b080fd, 0x2c863b00afaf5 },
            { 0x0a474a0846a76, 0x099a5ef981e32, 0x2a8ae3c4bbfe6,
                0x45c34af14832c, 0x591b67d9bffec },
        },
        {
            { 0x1b3719f18b55d, 0x754318c83d337, 0x27c17b7919797,
                0x145b084089b61, 0x489b4f8670301 },
            { 0x70d1c80b49bfa, 0x3d57e7d914625, 0x3c0722165e545,
                0x5e5b93819e04f, 0x3de02ec7ca8f7 },
            { 0x2102d3aeb92ef, 0x68c22d50c3a46, 0x42ea89385894e,
                0x75f9ebf55f38c, 0x49f5fbba496cb },
        },
        {
            { 0x5628c1e9c572e, 0x598b108e822ab, 0x55d8fae29361a,
                0x0adc8d1a97b28, 0x06a1a6c288675 },
            { 0x49a108a5bcfd4, 0x6178c8e7d6612, 0x1f03473710375,
                0x73a49614a6098, 0x5604a86dcbfa6 },
            { 0x0d1d47c1764b6, 0x01c08316a2e51, 0x2b3db45c95045,
                0x1634f818d300c, 0x20989e89fe274 },
        },
        {
            { 0x4278b85eaec2e, 0x0ef59657be2ce, 0x72fd169588770,
                0x2e9b205260b30, 0x730b9950f7059 },
            { 0x777fd3a2dcc7f, 0x594a9fb124932, 0x01f8e80ca15f0,
                0x714d13cec3269, 0x0403ed1d0ca67 },
            { 0x32d35874ec552, 0x1f3048df1b929, 0x300d73b179b23,
                0x6e67be5a37d0b, 0x5bd7454308303 },
        },
        {
            { 0x4932115e7792a, 0x457b9bbb930b8, 0x68f5d8b193226,
                0x4164e8f1ed456, 0x5bb7db123067f },
            { 0x2d19528b24cc2, 0x4ac66b8302ff3, 0x701c8d9fdad51,
                0x6c1b35c5b3727, 0x133a78007380a },
            { 0x1f467c6ca62be, 0x2c4232a5dc12c, 0x7551dc013b087,
                0x0690c11b03bcd, 0x740dca6d58f0e },
        },
    },
    {
        {
            { 0x28c570478433c, 0x1d8502873a463, 0x7641e7eded49c,
                0x1ecedd54cf571, 0x2c03f5256c2b0 },
            { 0x0ee0752cfce4e, 0x660dd8116fbe9, 0x55167130fffeb,
                0x1c682b885955c, 0x161d25fa963ea },
            { 0x718757b53a47d, 0x619e18b0f2f21, 0x5fbdfe4c1ec04,
                0x5d798c81ebb92, 0x699468bdbd96b },
        },
        {
            { 0x53de66aa91948, 0x045f81a599b1b, 0x3f7a8bd214193,
                0x71d4da412331a, 0x293e1c4e6c4a2 },
            { 0x72f46f4dafecf, 0x2948ffadef7a3, 0x11ecdfdf3bc04,
                0x3c2e98ffeed25, 0x525219a473905 },
            { 0x6134b925112e1, 0x6bb942bb406ed, 0x070c445c0dde2,
                0x411d822c4d7a3, 0x5b605c447f032 },
        },
        {
            { 0x1fec6f0e7f04c, 0x3cebc692c477d, 0x077986a19a95e,
                0x6eaaaa1778b0f, 0x2f12fef4cc5ab },
            { 0x5805920c47c89, 0x1924771f9972c, 0x38bbddf9fc040,
                0x1f7000092b281, 0x24a76dcea8aeb },
            { 0x522b2dfc0c740, 0x7e8193480e148, 0x33fd9a04341b9,
                0x3c863678a20bc, 0x5e607b2518a43 },
        },
        {
            { 0x4431ca596cf14, 0x015da7c801405, 0x03c9b6f8f10b5,
                0x0346922934017, 0x201f33139e457 },
            { 0x31d8f6cdf1818, 0x1f86c4b144b16, 0x39875b8d73e9d,
                0x2fbf0d9ffa7b3, 0x5067acab6ccdd },
            { 0x27f6b08039d51, 0x4802f8000dfaa, 0x09692a062c525,
                0x1baea91075817, 0x397cba8862460 },
        },
        {
            { 0x5c3fbc81379e7, 0x41bbc255e2f02, 0x6a3f756998650,
                0x1297fd4e07c42, 0x771b4022c1e1c },
            { 0x13093f05959b2, 0x1bd352f2ec618, 0x075789b88ea86,
                0x61d1117ea48b9, 0x2339d320766e6 },
            { 0x5d986513a2fa7, 0x63f3a99e11b0f, 0x28a0ecfd6b26d,
                0x53b6835e18d8f, 0x331a189219971 },
        },
        {
            { 0x12f3a9d7572af, 0x10d00e953c4ca, 0x603df116f2f8a,
                0x33dc276e0e088, 0x1ac9619ff649a },
            { 0x66f45fb4f80c6, 0x3cc38eeb9fea2, 0x107647270db1f,
                0x710f1ea740dc8, 0x31167c6b83bdf },
            { 0x33842524b1068, 0x77dd39d30fe45, 0x189432141a0d0,
                0x088fe4eb8c225, 0x612436341f08b },
        },
        {
            { 0x349e31a2d2638, 0x0137a7fa6b16c, 0x681ae92777edc,
                0x222bfc5f8dc51, 0x1522aa3178d90 },
            { 0x541db874e898d, 0x62d80fb841b33, 0x03e6ef027fa97,
                0x7a03c9e9633e8, 0x46ebe2309e5ef },
            { 0x02f5369614938, 0x356e5ada20587, 0x11bc89f6bf902,
                0x036746419c8db, 0x45fe70f505243 },
        },
        {
            { 0x24920c8951491, 0x107ec61944c5e, 0x72752e017c01f,
                0x122b7dda2e97a, 0x16619f6db57a2 },
            { 0x075a6960c0b8c, 0x6dde1c5e41b49, 0x42e3f516da341,
                0x16a03fda8e79e, 0x428d1623a0e39 },
            { 0x74a4401a308fd, 0x06ed4b9558109, 0x746f1f6a08867,
                0x4636f5c6f2321, 0x1d81592d60bd3 },
        },
    },
    {
        {
            { 0x5b69f7b85c5e8, 0x17a2d175650ec, 0x4cc3e6dbfc19e,
                0x73e1d3873be0e, 0x3a5f6d51b0af8 },
            { 0x68756a60dac5f, 0x55d757b8aec26, 0x3383df45f80bd,
                0x6783f8c9f96a6, 0x20234a7789ecd },
            { 0x20db67178b252, 0x73aa3da2c0eda, 0x79045c01c70d3,
                0x1b37b15251059, 0x7cd682353cffe },
        },
        {
            { 0x5cd6068acf4f3, 0x3079afc7a74cc, 0x58097650b64b4,
                0x47fabac9c4e99, 0x3ef0253b2b2cd },
            { 0x1a45bd887fab6, 0x65748076dc17c, 0x5b98000aa11a8,
                0x4a1ecc9080974, 0x2838c8863bdc0 },
            { 0x3b0cf4a465030, 0x022b8aef57a2d, 0x2ad0677e925ad,
                0x4094167d7457a, 0x21dcb8a606a82 },
        },
        {
            { 0x500fabe7731ba, 0x7cc53c3113351, 0x7cf65fe080d81,
                0x3c5d966011ba1, 0x5d840dbf6c6f6 },
            { 0x004468c9d9fc8, 0x5da8554796b8c, 0x3b8be70950025,
                0x6d5892da6a609, 0x0bc3d08194a31 },
            { 0x6380d309fe18b, 0x4d73c2cb8ee0d, 0x6b882adbac0b6,
                0x36eabdddd4cbe, 0x3a4276232ac19 },
        },
        {
            { 0x0c172db447ecb, 0x3f8c505b7a77f, 0x6a857f97f3f10,
                0x4fcc0567fe03a, 0x0770c9e824e1a },
            { 0x2432c8a7084fa, 0x47bf73ca8a968, 0x1639176262867,
                0x5e8df4f8010ce, 0x1ff177cea16de },
            { 0x1d99a45b5b5fd, 0x523674f2499ec, 0x0f8fa26182613,
                0x58f7398048c98, 0x39f264fd41500 },
        },
        {
            { 0x34aabfe097be1, 0x43bfc03253a33, 0x29bc7fe91b7f3,
                0x0a761e4844a16, 0x65c621272c35f },
            { 0x53417dbe7e29c, 0x54573827394f5, 0x565eea6f650dd,
                0x42050748dc749, 0x1712d73468889 },
            { 0x389f8ce3193dd, 0x2d424b8177ce5, 0x073fa0d3440cd,
                0x139020cd49e97, 0x22f9800ab19ce },
        },
        {
            { 0x29fdd9a6efdac, 0x7c694a9282840, 0x6f7cdeee44b3a,
                0x55a3207b25cc3, 0x4171a4d38598c },
            { 0x2368a3e9ef8cb, 0x454aa08e2ac0b, 0x490923f8fa700,
                0x372aa9ea4582f, 0x13f416cd64762 },
            { 0x758aa99c94c8c, 0x5f6001700ff44, 0x7694e488c01bd,
                0x0d5fde948eed6, 0x508214fa574bd },
        },
        {
            { 0x215bb53d003d6, 0x1179e792ca8c3, 0x1a0e96ac840a2,
                0x22393e2bb3ab6, 0x3a7758a4c86cb },
            { 0x269153ed6fe4b, 0x72a23aef89840, 0x052be5299699c,
                0x3a5e5ef132316, 0x22f960ec6faba },
            { 0x111f693ae5076, 0x3e3bfaa94ca90, 0x445799476b887,
                0x24a0912464879, 0x5d9fd15f8de7f },
        },
        {
            { 0x44d2aeed7521e, 0x50865d2c2a7e4, 0x2705b5238ea40,
                0x46c70b25d3b97, 0x3bc187fa47eb9 },
            { 0x408d36d63727f, 0x5faf8f6a66062, 0x2bb892da8de6b,
                0x769d4f0c7e2e6, 0x332f35914f8fb },
            { 0x70115ea86c20c, 0x16d88da24ada8, 0x1980622662adf,
                0x501ebbc195a9d, 0x450d81ce906fb },
        },
    },
    {
        {
            { 0x4d8961cae743f, 0x6bdc38c7dba0e, 0x7d3b4a7e1b463,
                0x0844bdee2adf3, 0x4cbad279663ab },
            { 0x3b6a1a6205275, 0x2e82791d06dcf, 0x23d72caa93c87,
                0x5f0b7ab68aaf4, 0x2de25d4ba6345 },
            { 0x19024a0d71fcd, 0x15f65115f101a, 0x4e99067149708,
                0x119d8d1cba5af, 0x7d7fbcefe2007 },
        },
        {
            { 0x45dc5f3c29094, 0x3455220b579af, 0x070c1631e068a,
                0x26bc0630e9b21, 0x4f9cd196dcd8d },
            { 0x71e6a266b2801, 0x09aae73e2df5d, 0x40dd8b219b1a3,
                0x546fb4517de0d, 0x5975435e87b75 },
            { 0x297d86a7b3768, 0x4835a2f4c6332, 0x070305f434160,
                0x183dd014e56ae, 0x7ccdd084387a0 },
        },
        {
            { 0x484186760cc93, 0x7435665533361, 0x02f686336b801,
                0x5225446f64331, 0x3593ca848190c },
            { 0x6422c6d260417, 0x212904817bb94, 0x5a319deb854f5,
                0x7a9d4e060da7d, 0x428bd0ed61d0c },
            { 0x3189a5e849aa7, 0x6acbb1f59b242, 0x7f6ef4753630c,
                0x1f346292a2da9, 0x27398308da2d6 },
        },
        {
            { 0x10e4c0a702453, 0x4daafa37bd734, 0x49f6bdc3e8961,
                0x1feffdcecdae6, 0x572c2945492c3 },
            { 0x38d28435ed413, 0x4064f19992858, 0x7680fbef543cd,
                0x1aadd83d58d3c, 0x269597aebe8c3 },
            { 0x7c745d6cd30be, 0x27c7755df78ef, 0x1776833937fa3,
                0x5405116441855, 0x7f985498c05bc },
        },
        {
            { 0x615520fbf6363, 0x0b9e9bf74da6a, 0x4fe8308201169,
                0x173f76127de43, 0x30f2653cd69b1 },
            { 0x1ce889f0be117, 0x36f6a94510709, 0x7f248720016b4,
                0x1821ed1e1cf91, 0x76c2ec470a31f },
            { 0x0c938aac10c85, 0x41b64ed797141, 0x1beb1c1185e6d,
                0x1ed5490600f07, 0x2f1273f159647 },
        },
        {
            { 0x08bd755a70bc0, 0x49e3a885ce609, 0x16585881b5ad6,
                0x3c27568d34f5e, 0x38ac1997edc5f },
            { 0x1fc7c8ae01e11, 0x2094d5573e8e7, 0x5ca3cbbf549d2,
                0x4f920ecc54143, 0x5d9e572ad85b6 },
            { 0x6b517a751b13b, 0x0cfd370b180cc, 0x5377925d1f41a,
                0x34e56566008a2, 0x22dfcd9cbfe9e },
        },
        {
            { 0x459b4103be0a1, 0x59a4b3f2d2add, 0x7d734c8bb8eeb,
                0x2393cbe594a09, 0x0fe9877824cde },
            { 0x3d2e0c30d0cd9, 0x3f597686671bb, 0x0aa587eb63999,
                0x0e3c7b592c619, 0x6b2916c05448c },
            { 0x334d10aba913b, 0x045cdb581cfdb, 0x5e3e0553a8f36,
                0x50bb3041effb2, 0x4c303f307ff00 },
        },
        {
            { 0x403580dd94500, 0x48df77d92653f, 0x38a9fe3b349ea,
                0x0ea89850aafe1, 0x416b151ab706a },
            { 0x23bd617b28c85, 0x6e72ee77d5a61, 0x1a972ff174dde,
                0x3e2636373c60f, 0x0d61b8f78b2ab },
            { 0x0d7efe9c136b0, 0x1ab1c89640ad5, 0x55f82aef41f97,
                0x46957f317ed0d, 0x191a2af74277e },
        },
    },
    {
        {
            { 0x62b434f460efb, 0x294c6c0fad3fc, 0x68368937b4c0f,
                0x5c9f82910875b, 0x237e7dbe00545 },
            { 0x6f74bc53c1431, 0x1c40e5dbbd9c2, 0x6c8fb9cae5c97,
                0x4845c5ce1b7da, 0x7e2e0e450b5cc },
            { 0x575ed6701b430, 0x4d3e17fa20026, 0x791fc888c4253,
                0x2f1ba99078ac1, 0x71afa699b1115 },
        },
        {
            { 0x23c1c473b50d6, 0x3e7671de21d48, 0x326fa5547a1e8,
                0x50e4dc25fafd9, 0x00731fbc78f89 },
            { 0x66f9b3953b61d, 0x555f4283cccb9, 0x7dd67fb1960e7,
                0x14707a1affed4, 0x021142e9c2b1c },
            { 0x0c71848f81880, 0x44bd9d8233c86, 0x6e8578efe5830,
                0x4045b6d7041b5, 0x4c4d6f3347e15 },
        },
        {
            { 0x4ddfc988f1970, 0x4f6173ea365e1, 0x645daf9ae4588,
                0x7d43763db623b, 0x38bf9500a88f9 },
            { 0x7eccfc17d1fc9, 0x4ca280782831e, 0x7b8337db1d7d6,
                0x5116def3895fb, 0x193fddaaa7e47 },
            { 0x2c93c37e8876f, 0x3431a28c583fa, 0x49049da8bd879,
                0x4b4a8407ac11c, 0x6a6fb99ebf0d4 },
        },
        {
            { 0x122b5b6e423c6, 0x21e50dff1ddd6, 0x73d76324e75c0,
                0x588485495418e, 0x136fda9f42c5e },
            { 0x6c1bb560855eb, 0x71f127e13ad48, 0x5c6b304905aec,
                0x3756b8e889bc7, 0x75f76914a3189 },
            { 0x4dfb1a305bdd1, 0x3b3ff05811f29, 0x6ed62283cd92e,
                0x65d1543ec52e1, 0x022183510be8d },
        },
        {
            { 0x2710143307a7f, 0x3d88fb48bf3ab, 0x249eb4ec18f7a,
                0x136115dff295f, 0x1387c441fd404 },
            { 0x766385ead2d14, 0x0194f8b06095e, 0x08478f6823b62,
                0x6018689d37308, 0x6a071ce17b806 },
            { 0x3c3d187978af8, 0x7afe1c88276ba, 0x51df281c8ad68,
                0x64906bda4245d, 0x3171b26aaf1ed },
        },
        {
            { 0x5b7d8b28a47d1, 0x2c2ee149e34c1, 0x776f5629afc53,
                0x1f4ea50fc49a9, 0x6c514a6334424 },
            { 0x7319097564ca8, 0x1844ebc233525, 0x21d4543fdeee1,
                0x1ad27aaff1bd2, 0x221fd4873cf08 },
            { 0x2204f3a156341, 0x537414065a464, 0x43c0c3bedcf83,
                0x5557e706ea620, 0x48daa596fb924 },
        },
        {
            { 0x61d5dc84c9793, 0x47de83040c29e, 0x189deb26507e7,
                0x4d4e6fadc479a, 0x58c837fa0e8a7 },
            { 0x28e665ca59cc7, 0x165c715940dd9, 0x0785f3aa11c95,
                0x57b98d7e38469, 0x676dd6fccad84 },
            { 0x1688596fc9058, 0x66f6ad403619f, 0x4d759a87772ef,
                0x7856e6173bea4, 0x1c4f73f2c6a57 },
        },
        {
            { 0x6706efc7c3484, 0x6987839ec366d, 0x0731f95cf7f26,
                0x3ae758ebce4bc, 0x70459adb7daf6 },
            { 0x24fbd305fa0bb, 0x40a98cc75a1cf, 0x78ce1220a7533,
                0x6217a10e1c197, 0x795ac80d1bf64 },
            { 0x1db4991b42bb3, 0x469605b994372, 0x631e3715c9a58,
                0x7e9cfefcf728f, 0x5fe162848ce21 },
        },
    },
    {
        {
            { 0x1852d5d7cb208, 0x60d0fbe5ce50f, 0x5a1e246e37b75,
                0x51aee05ffd590, 0x2b44c043677da },
            { 0x1214fe194961a, 0x0e1ae39a9e9cb, 0x543c8b526f9f7,
                0x119498067e91d, 0x4789d446fc917 },
            { 0x487ab074eb78e, 0x1d33b5e8ce343, 0x13e419feb1b46,
                0x2721f565de6a4, 0x60c52eef2bb9a },
        },
        {
            { 0x3c5c27cae6d11, 0x36a9491956e05, 0x124bac9131da6,
                0x3b6f7de202b5d, 0x70d77248d9b66 },
            { 0x589bc3bfd8bf1, 0x6f93e6aa3416b, 0x4c0a3d6c1ae48,
                0x55587260b586a, 0x10bc9c312ccfc },
            { 0x2e84b3ec2a05b, 0x69da2f03c1551, 0x23a174661a67b,
                0x209bca289f238, 0x63755bd3a976f },
        },
        {
            { 0x7101897f1acb7, 0x3d82cb77b07b8, 0x684083d7769f5,
                0x52b28472dce07, 0x2763751737c52 },
            { 0x7a03e2ad10853, 0x213dcc6ad36ab, 0x1a6e240d5bdd6,
                0x7c24ffcf8fedf, 0x0d8cc1c48bc16 },
            { 0x402d36eb419a9, 0x7cef68c14a052, 0x0f1255bc2d139,
                0x373e7d431186a, 0x70c2dd8a7ad16 },
        },
        {
            { 0x4967db8ed7e13, 0x15aeed02f523a, 0x6149591d094bc,
                0x672f204c17006, 0x32b8613816a53 },
            { 0x194509f6fec0e, 0x528d8ca31acac, 0x7826d73b8b9fa,
                0x24acb99e0f9b3, 0x2e0fac6363948 },
            { 0x7f7bee448cd64, 0x4e10f10da0f3c, 0x3936cb9ab20e9,
                0x7a0fc4fea6cd0, 0x4179215c735a4 },
        },
        {
            { 0x633b9286bcd34, 0x6cab3badb9c95, 0x74e387edfbdfa,
                0x14313c58a0fd9, 0x31fa85662241c },
            { 0x094e7d7dced2a, 0x068fa738e118e, 0x41b640a5fee2b,
                0x6bb709df019d4, 0x700344a30cd99 },
            { 0x26c422e3622f4, 0x0f3066a05b5f0, 0x4e2448f0480a6,
                0x244cde0dbf095, 0x24bb2312a9952 },
        },
        {
            { 0x00c2af5f85c6b, 0x0609f4cf2883f, 0x6e86eb5a1ca13,
                0x68b44a2efccd1, 0x0d1d2af9ffeb5 },
            { 0x0ed1732de67c3, 0x308c369291635, 0x33ef348f2d250,
                0x004475ea1a1bb, 0x0fee3e871e188 },
            { 0x28aa132621edf, 0x42b244caf353b, 0x66b064cc2e08a,
                0x6bb20020cbdd3, 0x16acd79718531 },
        },
        {
            { 0x1c6c57887b6ad, 0x5abf21fd7592b, 0x50bd41253867a,
                0x3800b71273151, 0x164ed34b18161 },
            { 0x772af2d9b1d3d, 0x6d486448b4e5b, 0x2ce58dd8d18a8,
                0x1849f67503c8b, 0x123e0ef6b9302 },
            { 0x6d94c192fe69a, 0x5475222a2690f, 0x693789d86b8b3,
                0x1f5c3bdfb69dc, 0x78da0fc61073f },
        },
        {
            { 0x780f1680c3a94, 0x2a35d3cfcd453, 0x005e5cdc7ddf8,
                0x6ee888078ac24, 0x054aa4b316b38 },
            { 0x15d28e52bc66a, 0x30e1e0351cb7e, 0x30a2f74b11f8c,
                0x39d120cd7de03, 0x2d25deeb256b1 },
            { 0x0468d19267cb8, 0x38cdca9b5fbf9, 0x1bbb05c2ca1e2,
                0x3b015758e9533, 0x134610a6ab7da },
        },
    },
    {
        {
            { 0x265e777d1f515, 0x0f1f54c1e39a5, 0x2f01b95522646,
                0x4fdd8db9dde6d, 0x654878cba97cc },
            { 0x38ec78df6b0fe, 0x13caebea36a22, 0x5ebc6e54e5f6a,
                0x32804903d0eb8, 0x2102fdba2b20d },
            { 0x6e405055ce6a1, 0x5024a35a532d3, 0x1f69054daf29d,
                0x15d1d0d7a8bd5, 0x0ad725db29ecb },
        },
        {
            { 0x7bc0c9b056f85, 0x51cfebffaffd8, 0x44abbe94df549,
                0x7ecbbd7e33121, 0x4f675f5302399 },
            { 0x267b1834e2457, 0x6ae19c378bb88, 0x7457b5ed9d512,
                0x3280d783d05fb, 0x4aefcffb71a03 },
            { 0x536360415171e, 0x2313309077865, 0x251444334afbc,
                0x2b0c3853756e8, 0x0bccbb72a2a86 },
        },
        {
            { 0x55e4c50fe1296, 0x05fdd13efc30d, 0x1c0c6c380e5ee,
                0x3e11de3fb62a8, 0x6678fd69108f3 },
            { 0x6962feab1a9c8, 0x6aca28fb9a30b, 0x56db7ca1b9f98,
                0x39f58497018dd, 0x4024f0ab59d6b },
            { 0x6fa31636863c2, 0x10ae5a67e42b0, 0x27abbf01fda31,
                0x380a7b9e64fbc, 0x2d42e2108ead4 },
        },
        {
            { 0x17b0d0f537593, 0x16263c0c9842e, 0x4ab827e4539a4,
                0x6370ddb43d73a, 0x420bf3a79b423 },
            { 0x5131594dfd29b, 0x3a627e98d52fe, 0x1154041855661,
                0x19175d09f8384, 0x676b2608b8d2d },
            { 0x0ba651c5b2b47, 0x5862363701027, 0x0c4d6c219c6db,
                0x0f03dff8658de, 0x745d2ffa9c0cf },
        },
        {
            { 0x6df5721d34e6a, 0x4f32f767a0c06, 0x1d5abeac76e20,
                0x41ce9e104e1e4, 0x06e15be54c1dc },
            { 0x25a1e2bc9c8bd, 0x104c8f3b037ea, 0x405576fa96c98,
                0x2e86a88e3876f, 0x1ae23ceb960cf },
            { 0x25d871932994a, 0x6b9d63b560b6e, 0x2df2814c8d472,
                0x0fbbee20aa4ed, 0x58ded861278ec },
        },
        {
            { 0x35ba8b6c2c9a8, 0x1dea58b3185bf, 0x4b455cd23bbbe,
                0x5ec19c04883f8, 0x08ba696b531d5 },
            { 0x73793f266c55c, 0x0b988a9c93b02, 0x09b0ea32325db,
                0x37cae71c17c5e, 0x2ff39de85485f },
            { 0x53eeec3efc57a, 0x2fa9fe9022efd, 0x699c72c138154,
                0x72a751ebd1ff8, 0x120633b4947cf },
        },
        {
            { 0x531474912100a, 0x5afcdf7c0d057, 0x7a9e71b788ded,
                0x5ef708f3b0c88, 0x07433be3cb393 },
            { 0x4987891610042, 0x79d9d7f5d0172, 0x3c293013b9ec4,
                0x0c2b85f39caca, 0x35d30a99b4d59 },
            { 0x144c05ce997f4, 0x4960b8a347fef, 0x1da11f15d74f7,
                0x54fac19c0fead, 0x2d873ede7af6d },
        },
        {
            { 0x202e14e5df981, 0x2ea02bc3eb54c, 0x38875b2883564,
                0x1298c513ae9dd, 0x0543618a01600 },
            { 0x2316443373409, 0x5de95503b22af, 0x699201beae2df,
                0x3db5849ff737a, 0x2e773654707fa },
            { 0x2bdf4974c23c1, 0x4b3b9c8d261bd, 0x26ae8b2a9bc28,
                0x3068210165c51, 0x4b1443362d079 },
        },
    },
    {
        {
            { 0x454e91c529ccb, 0x24c98c6bf72cf, 0x0486594c3d89a,
                0x7ae13a3d7fa3c, 0x17038418eaf66 },
            { 0x4b7c7b66e1f7a, 0x4bea185efd998, 0x4fabc711055f8,
                0x1fb9f7836fe38, 0x582f446752da6 },
            { 0x17bd320324ce4, 0x51489117898c6, 0x1684d92a0410b,
                0x6e4d90f78c5a7, 0x0c2a1c4bcda28 },
        },
        {
            { 0x4814869bd6945, 0x7b7c391a45db8, 0x57316ac35b641,
                0x641e31de9096a, 0x5a6a9b30a314d },
            { 0x5c7d06f1f0447, 0x7db70f80b3a49, 0x6cb4a3ec89a78,
                0x43be8ad81397d, 0x7c558bd1c6f64 },
            { 0x41524d396463d, 0x1586b449e1a1d, 0x2f17e904aed8a,
                0x7e1d2861d3c8e, 0x0404a5ca0afba },
        },
        {
            { 0x49e1b2a416fd1, 0x51c6a0b316c57, 0x575a59ed71bdc,
                0x74c021a1fec1e, 0x39527516e7f8e },
            { 0x740070aa743d6, 0x16b64cbdd1183, 0x23f4b7b32eb43,
                0x319aba58235b3, 0x46395bfdcadd9 },
            { 0x7db2d1a5d9a9c, 0x79a200b85422f, 0x355bfaa71dd16,
                0x00b77ea5f78aa, 0x76579a29e822d },
        },
        {
            { 0x4b51352b434f2, 0x1327bd01c2667, 0x434d73b60c8a1,
                0x3e0daa89443ba, 0x02c514bb2a277 },
            { 0x68e7e49c02a17, 0x45795346fe8b6, 0x089306c8f3546,
                0x6d89f6b2f88f6, 0x43a384dc9e05b },
            { 0x3d5da8bf1b645, 0x7ded6a96a6d09, 0x6c3494fee2f4d,
                0x02c989c8b6bd4, 0x1160920961548 },
        },
        {
            { 0x05616369b4dcd, 0x4ecab86ac6f47, 0x3c60085d700b2,
                0x0213ee10dfcea, 0x2f637d7491e6e },
            { 0x5166929dacfaa, 0x190826b31f689, 0x4f55567694a7d,
                0x705f4f7b1e522, 0x351e125bc5698 },
            { 0x49b461af67bbe, 0x75915712c3a96, 0x69a67ef580c0d,
                0x54d38ef70cffc, 0x7f182d06e7ce2 },
        },
        {
            { 0x54b728e217522, 0x69a90971b0128, 0x51a40f2a963a3,
                0x10be9ac12a6bf, 0x44acc043241c5 },
            { 0x48e64ab0168ec, 0x2a2bdb8a86f4f, 0x7343b6b2d6929,
                0x1d804aa8ce9a3, 0x67d4ac8c343e9 },
            { 0x56bbb4f7a5777, 0x29230627c238f, 0x5ad1a122cd7fb,
                0x0dea56e50e364, 0x556d1c8312ad7 },
        },
        {
            { 0x06756b11be821, 0x462147e7bb03e, 0x26519743ebfe0,
                0x782fc59682ab5, 0x097abe38cc8c7 },
            { 0x740e30c8d3982, 0x7c2b47f4682fd, 0x5cd91b8c7dc1c,
                0x77fa790f9e583, 0x746c6c6d1d824 },
            { 0x1c9877ea52da4, 0x2b37b83a86189, 0x733af49310da5,
                0x25e81161c04fb, 0x577e14a34bee8 },
        },
        {
            { 0x6cebebd4dd72b, 0x340c1e442329f, 0x32347ffd1a93f,
                0x14a89252cbbe0, 0x705304b8fb009 },
            { 0x268ac61a73b0a, 0x206f234bebe1c, 0x5b403a7cbebe8,
                0x7a160f09f4135, 0x60fa7ee96fd78 },
            { 0x51d354d296ec6, 0x7cbf5a63b16c7, 0x2f50bb3cf0c14,
                0x1feb385cac65a, 0x21398e0ca1635 },
        },
    },
    {
        {
            { 0x0aaf9b4b75601, 0x26b91b5ae44f3, 0x6de808d7ab1c8,
                0x6a769675530b0, 0x1bbfb284e98f7 },
            { 0x5058a382b33f3, 0x175a91816913e, 0x4f6cdb96b8ae8,
                0x17347c9da81d2, 0x5aa3ed9d95a23 },
            { 0x777e9c7d96561, 0x28e58f006ccac, 0x541bbbb2cac49,
                0x3e63282994cec, 0x4a07e14e5e895 },
        },
        {
            { 0x358cdc477a49b, 0x3cc88fe02e481, 0x721aab7f4e36b,
                0x0408cc9469953, 0x50af7aed84afa },
            { 0x412cb980df999, 0x5e78dd8ee29dc, 0x171dff68c575d,
                0x2015dd2f6ef49, 0x3f0bac391d313 },
            { 0x7de0115f65be5, 0x4242c21364dc9, 0x6b75b64a66098,
                0x0033c0102c085, 0x1921a316baebd },
        },
        {
            { 0x2ad9ad9f3c18b, 0x5ec1638339aeb, 0x5703b6559a83b,
                0x3fa9f4d05d612, 0x7b049deca062c },
            { 0x22f7edfb870fc, 0x569eed677b128, 0x30937dcb0a5af,
                0x758039c78ea1b, 0x6458df41e273a },
            { 0x3e37a35444483, 0x661fdb7d27b99, 0x317761dd621e4,
                0x7323c30026189, 0x6093dccbc2950 },
        },
        {
            { 0x6eebe6084034b, 0x6cf01f70a8d7b, 0x0b41a54c6670a,
                0x6c84b99bb55db, 0x6e3180c98b647 },
            { 0x39a8585e0706d, 0x3167ce72663fe, 0x63d14ecdb4297,
                0x4be21dcf970b8, 0x57d1ea084827a },
            { 0x2b6e7a128b071, 0x5b27511755dcf, 0x08584c2930565,
                0x68c7bda6f4159, 0x363e999ddd97b },
        },
        {
            { 0x048dce24baec6, 0x2b75795ec05e3, 0x3bfa4c5da6dc9,
                0x1aac8659e371e, 0x231f979bc6f9b },
            { 0x043c135ee1fc4, 0x2a11c9919f2d5, 0x6334cc25dbacd,
                0x295da17b400da, 0x48ee9b78693a0 },
            { 0x1de4bcc2af3c6, 0x61fc411a3eb86, 0x53ed19ac12ec0,
                0x209dbc6b804e0, 0x079bfa9b08792 },
        },
        {
            { 0x1ed80a2d54245, 0x70efec72a5e79, 0x42151d42a822d,
                0x1b5ebb6d631e8, 0x1ef4fb1594706 },
            { 0x03a51da300df4, 0x467b52b561c72, 0x4d5920210e590,
                0x0ca769e789685, 0x038c77f684817 },
            { 0x65ee65b167bec, 0x052da19b850a9, 0x0408665656429,
                0x7ab39596f9a4c, 0x575ee92a4a0bf },
        },
        {
            { 0x6bc450aa4d801, 0x4f4a6773b0ba8, 0x6241b0b0ebc48,
                0x40d9c4f1d9315, 0x200a1e7e382f5 },
            { 0x080908a182fcf, 0x0532913b7ba98, 0x3dccf78c385c3,
                0x68002dd5eaba9, 0x43d4e7112cd3f },
            { 0x5b967eaf93ac5, 0x360acca580a31, 0x1c65fd5c6f262,
                0x71c7f15c2ecab, 0x050eca52651e4 },
        },
        {
            { 0x4397660e668ea, 0x7c2a75692f2f5, 0x3b29e7e6c66ef,
                0x72ba658bcda9a, 0x6151c09fa131a },
            { 0x31ade453f0c9c, 0x3dfee07737868, 0x611ecf7a7d411,
                0x2637e6cbd64f6, 0x4b0ee6c21c58f },
            { 0x55c0dfdf05d96, 0x405569dcf475e, 0x05c5c277498bb,
                0x18588d95dc389, 0x1fef24fa800f0 },
        },
    },
    {
        {
            { 0x2aff530976b86, 0x0d85a48c0845a, 0x796eb963642e0,
                0x60bee50c4b626, 0x28005fe6c8340 },
            { 0x653fb1aa73196, 0x607faec8306fa, 0x4e85ec83e5254,
                0x09f56900584fd, 0x544d49292fc86 },
            { 0x7ba9f34528688, 0x284a20fb42d5d, 0x3652cd9706ffe,
                0x6fd7baddde6b3, 0x72e472930f316 },
        },
        {
            { 0x3f635d32a7627, 0x0cbecacde00fe, 0x3411141eaa936,
                0x21c1e42f3cb94, 0x1fee7f000fe06 },
            { 0x5208c9781084f, 0x16468a1dc24d2, 0x7bf780ac540a8,
                0x1a67eced75301, 0x5a9d2e8c2733a },
            { 0x305da03dbf7e5, 0x1228699b7aeca, 0x12a23b2936bc9,
                0x2a1bda56ae6e9, 0x00f94051ee040 },
        },
        {
            { 0x793bb07af9753, 0x1e7b6ecd4fafd, 0x02c7b1560fb43,
                0x2296734cc5fb7, 0x47b7ffd25dd40 },
            { 0x56b23c3d330b2, 0x37608e360d1a6, 0x10ae0f3c8722e,
                0x086d9b618b637, 0x07d79c7e8beab },
            { 0x3fb9cbc08dd12, 0x75c3dd85370ff, 0x47f06fe2819ac,
                0x5db06ab9215ed, 0x1c3520a35ea64 },
        },
        {
            { 0x06f40216bc059, 0x3a2579b0fd9b5, 0x71c26407eec8c,
                0x72ada4ab54f0b, 0x38750c3b66d12 },
            { 0x253a6bccba34a, 0x427070433701a, 0x20b8e58f9870e,
                0x337c861db00cc, 0x1c3d05775d0ee },
            { 0x6f1409422e51a, 0x7856bbece2d25, 0x13380a72f031c,
                0x43e1080a7f3ba, 0x0621e2c7d3304 },
        },
        {
            { 0x61796b0dbf0f3, 0x73c2f9c32d6f5, 0x6aa8ed1537ebe,
                0x74e92c91838f4, 0x5d8e589ca1002 },
            { 0x060cc8259838d, 0x038d3f35b95f3, 0x56078c243a923,
                0x2de3293241bb2, 0x0007d6097bd3a },
            { 0x71d950842a94b, 0x46b11e5c7d817, 0x5478bbecb4f0d,
                0x7c3054b0a1c5d, 0x1583d7783c1cb },
        },
        {
            { 0x34704cc9d28c7, 0x3dee598b1f200, 0x16e1c98746d9e,
                0x4050b7095afdf, 0x4958064e83c55 },
            { 0x6a2ef5da27ae1, 0x28aace02e9d9d, 0x02459e965f0e8,
                0x7b864d3150933, 0x252a5f2e81ed8 },
            { 0x094265066e80d, 0x0a60f918d61a5, 0x0444bf7f30fde,
                0x1c40da9ed3c06, 0x079c170bd843b },
        },
        {
            { 0x6cd50c0d5d056, 0x5b7606ae779ba, 0x70fbd226bdda1,
                0x5661e53391ff9, 0x6768c0d7317b8 },
            { 0x6ece464fa6fff, 0x3cc40bca460a0, 0x6e3a90afb8d0c,
                0x5801abca11228, 0x6dec05e34ac9f },
            { 0x625e5f155c1b3, 0x4f32f6f723296, 0x5ac980105efce,
                0x17a61165eee36, 0x51445e14ddcd5 },
        },
        {
            { 0x147ab2bbea455, 0x1f240f2253126, 0x0c3de9e314e89,
                0x21ea5a4fca45f, 0x12e990086e4fd },
            { 0x02b4b3b144951, 0x5688977966aea, 0x18e176e399ffd,
                0x2e45c5eb4938b, 0x13186f31e3929 },
            { 0x496b37fdfbb2e, 0x3c2439d5f3e21, 0x16e60fe7e6a4d,
                0x4d7ef889b621d, 0x77b2e3f05d3e9 },
        },
    },
    {
        {
            { 0x0639c12ddb0a4, 0x6180490cd7ab3, 0x3f3918297467c,
                0x74568be1781ac, 0x07a195152e095 },
            { 0x7a9c59c2ec4de, 0x7e9f09e79652d, 0x6a3e422f22d86,
                0x2ae8e3b836c8b, 0x63b795fc7ad32 },
            { 0x68f02389e5fc8, 0x059f1bc877506, 0x504990e410cec,
                0x09bd7d0feaee2, 0x3e8fe83d032f0 },
        },
        {
            { 0x04c8de8efd13c, 0x1c67c06e6210e, 0x183378f7f146a,
                0x64352ceaed289, 0x22d60899a6258 },
            { 0x315b90570a294, 0x60ce108a925f1, 0x6eff61253c909,
                0x003ef0e2d70b0, 0x75ba3b797fac4 },
            { 0x1dbc070cdd196, 0x16d8fb1534c47, 0x500498183fa2a,
                0x72f59c423de75, 0x0904d07b87779 },
        },
        {
            { 0x22d6648f940b9, 0x197a5a1873e86, 0x207e4c41a54bc,
                0x5360b3b4bd6d0, 0x6240aacebaf72 },
            { 0x61fd4ddba919c, 0x7d8e991b55699, 0x61b31473cc76c,
                0x7039631e631d6, 0x43e2143fbc1dd },
            { 0x4749c5ba295a0, 0x37946fa4b5f06, 0x724c5ab5a51f1,
                0x65633789dd3f3, 0x56bdaf238db40 },
        },
        {
            { 0x0d36cc19d3bb2, 0x6ec4470d72262, 0x6853d7018a9ae,
                0x3aa3e4dc2c8eb, 0x03aa31507e1e5 },
            { 0x2b9e3f53533eb, 0x2add727a806c5, 0x56955c8ce15a3,
                0x18c4f070a290e, 0x1d24a86d83741 },
            { 0x47648ffd4ce1f, 0x60a9591839e9d, 0x424d5f38117ab,
                0x42cc46912c10e, 0x43b261dc9aeb4 },
        },
        {
            { 0x13d8b6c951364, 0x4c0017e8f632a, 0x53e559e53f9c4,
                0x4b20146886eea, 0x02b4d5e242940 },
            { 0x31e1988bb79bb, 0x7b82f46b3bcab, 0x0f7a8ce827b41,
                0x5e15816177130, 0x326055cf5b276 },
            { 0x155cb28d18df2, 0x0c30d9ca11694, 0x2090e27ab3119,
                0x208624e7a49b6, 0x27a6c809ae5d3 },
        },
        {
            { 0x4270ac43d6954, 0x2ed4cd95659a5, 0x75c0db37528f9,
                0x2ccbcfd2c9234, 0x221503603d8c2 },
            { 0x6ebcd1f0db188, 0x74ceb4b7d1174, 0x7d56168df4f5c,
                0x0bf79176fd18a, 0x2cb67174ff60a },
            { 0x6cdf9390be1d0, 0x08e519c7e2b3d, 0x253c3d2a50881,
                0x21b41448e333d, 0x7b1df4b73890f },
        },
        {
            { 0x6221807f8f58c, 0x3fa92813a8be5, 0x6da98c38d5572,
                0x01ed95554468f, 0x68698245d352e },
            { 0x2f2e0b3b2a224, 0x0c56aa22c1c92, 0x5fdec39f1b278,
                0x4c90af5c7f106, 0x61fcef2658fc5 },
            { 0x15d852a18187a, 0x270dbb59afb76, 0x7db120bcf92ab,
                0x0e7a25d714087, 0x46cf4c473daf0 },
        },
        {
            { 0x46ea7f1498140, 0x70725690a8427, 0x0a73ae9f079fb,
                0x2dd924461c62b, 0x1065aae50d8cc },
            { 0x525ed9ec4e5f9, 0x022d20660684c, 0x7972b70397b68,
                0x7a03958d3f965, 0x29387bcd14eb5 },
            { 0x44525df200d57, 0x2d7f94ce94385, 0x60d00c170ecb7,
                0x38b0503f3d8f0, 0x69a198e64f1ce },
        },
    },
    {
        {
            { 0x14434dcc5caed, 0x2c7909f667c20, 0x61a839d1fb576,
                0x4f23800cabb76, 0x25b2697bd267f },
            { 0x2b2e0d91a78bc, 0x3990a12ccf20c, 0x141c2e11f2622,
                0x0dfcefaa53320, 0x7369e6a92493a },
            { 0x73ffb13986864, 0x3282bb8f713ac, 0x49ced78f297ef,
                0x6697027661def, 0x1420683db54e4 },
        },
        {
            { 0x6bb6fc1cc5ad0, 0x532c8d591669d, 0x1af794da86c33,
                0x0e0e9d86d24d3, 0x31e83b4161d08 },
            { 0x0bd1e249dd197, 0x00bcb1820568f, 0x2eab1718830d4,
                0x396fd816997e6, 0x60b63bebf508a },
            { 0x0c7129e062b4f, 0x1e526415b12fd, 0x461a0fd27923d,
                0x18badf670a5b7, 0x55cf1eb62d550 },
        },
        {
            { 0x6b5e37df58c52, 0x3bcf33986c60e, 0x44fb8835ceae7,
                0x099dec18e71a4, 0x1a56fbaa62ba0 },
            { 0x1101065c23d58, 0x5aa1290338b0f, 0x3157e9e2e7421,
                0x0ea712017d489, 0x669a656457089 },
            { 0x66b505c9dc9ec, 0x774ef86e35287, 0x4d1d944c0955e,
                0x52e4c39d72b20, 0x13c4836799c58 },
        },
        {
            { 0x4fb6a5d8bd080, 0x58ae34908589b, 0x3954d977baf13,
                0x413ea597441dc, 0x50bdc87dc8e5b },
            { 0x25d465ab3e1b9, 0x0f8fe27ec2847, 0x2d6e6dbf04f06,
                0x3038cfc1b3276, 0x66f80c93a637b },
            { 0x537836edfe111, 0x2be02357b2c0d, 0x6dcee58c8d4f8,
                0x2d732581d6192, 0x1dd56444725fd },
        },
        {
            { 0x7e60008bac89a, 0x23d5c387c1852, 0x79e5df1f533a8,
                0x2e6f9f1c5f0cf, 0x3a3a450f63a30 },
            { 0x47ff83362127d, 0x08e39af82b1f4, 0x488322ef27dab,
                0x1973738a2a1a4, 0x0e645912219f7 },
            { 0x72f31d8394627, 0x07bd294a200f1, 0x665be00e274c6,
                0x43de8f1b6368b, 0x318c8d9393a9a },
        },
        {
            { 0x69e29ab1dd398, 0x30685b3c76bac, 0x565cf37f24859,
                0x57b2ac28efef9, 0x509a41c325950 },
            { 0x45d032afffe19, 0x12fe49b6cde4e, 0x21663bc327cf1,
                0x18a5e4c69f1dd, 0x224c7c679a1d5 },
            { 0x06edca6f925e9, 0x68c8363e677b8, 0x60cfa25e4fbcf,
                0x1c4c17609404e, 0x05bff02328a11 },
        },
        {
            { 0x1a0dd0dc512e4, 0x10894bf5fcd10, 0x52949013f9c37,
                0x1f50fba4735c7, 0x576277cdee01a },
            { 0x2137023cae00b, 0x15a3599eb26c6, 0x0687221512b3c,
                0x253cb3a0824e9, 0x780b8cc3fa2a4 },
            { 0x38abc234f305f, 0x7a280bbc103de, 0x398a836695dfe,
                0x3d0af41528a1a, 0x5ff418726271b },
        },
        {
            { 0x347e813b69540, 0x76864c21c3cbb, 0x1e049dbcd74a8,
                0x5b4d60f93749c, 0x29d4db8ca0a0c },
            { 0x6080c1789db9d, 0x4be7cef1ea731, 0x2f40d769d8080,
                0x35f7d4c44a603, 0x106a03dc25a96 },
            { 0x50aaf333353d0, 0x4b59a613cbb35, 0x223dfc0e19a76,
                0x77d1e2bb2c564, 0x4ab38a51052cb },
        },
    },
    {
        {
            { 0x7d1ef5fddc09c, 0x7beeaebb9dad9, 0x058d30ba0acfb,
                0x5cd92eab5ae90, 0x3041c6bb04ed2 },
            { 0x42b256768d593, 0x2e88459427b4f, 0x02b3876630701,
                0x34878d405eae5, 0x29cdd1adc088a },
            { 0x2f2f9d956e148, 0x6b3e6ad65c1fe, 0x5b00972b79e5d,
                0x53d8d234c5daf, 0x104bbd6814049 },
        },
        {
            { 0x59a5fd67ff163, 0x3a998ead0352b, 0x083c95fa4af9a,
                0x6fadbfc01266f, 0x204f2a20fb072 },
            { 0x0fd3168f1ed67, 0x1bb0de7784a3e, 0x34bcb78b20477,
                0x0a4a26e2e2182, 0x5be8cc57092a7 },
            { 0x43b3d30ebb079, 0x357aca5c61902, 0x5b570c5d62455,
                0x30fb29e1e18c7, 0x2570fb17c2791 },
        },
        {
            { 0x6a9550bb8245a, 0x511f20a1a2325, 0x29324d7239bee,
                0x3343cc37516c4, 0x241c5f91de018 },
            { 0x2367f2cb61575, 0x6c39ac04d87df, 0x6d4958bd7e5bd,
                0x566f4638a1532, 0x3dcb65ea53030 },
            { 0x0172940de6caa, 0x6045b2e67451b, 0x56c07463efcb3,
                0x0728b6bfe6e91, 0x08420edd5fcdf },
        },
        {
            { 0x0c34e04f410ce, 0x344edc0d0a06b, 0x6e45486d84d6d,
                0x44e2ecb3863f5, 0x04d654f321db8 },
            { 0x720ab8362fa4a, 0x29c4347cdd9bf, 0x0e798ad5f8463,
                0x4fef18bcb0bfe, 0x0d9a53efbc176 },
            { 0x5c116ddbdb5d5, 0x6d1b4bba5abcf, 0x4d28a48a5537a,
                0x56b8e5b040b99, 0x4a7a4f2618991 },
        },
        {
            { 0x3b291af372a4b, 0x60e3028fe4498, 0x2267bca4f6a09,
                0x719eec242b243, 0x4a96314223e0e },
            { 0x718025fb15f95, 0x68d6b8371fe94, 0x3804448f7d97c,
                0x42466fe784280, 0x11b50c4cddd31 },
            { 0x0274408a4ffd6, 0x7d382aedb34dd, 0x40acfc9ce385d,
                0x628bb99a45b1e, 0x4f4bce4dce6bc },
        },
        {
            { 0x2616ec49d0b6f, 0x1f95d8462e61c, 0x1ad3e9b9159c6,
                0x79ba475a04df9, 0x3042cee561595 },
            { 0x7ce5ae2242584, 0x2d25eb153d4e3, 0x3a8f3d09ba9c9,
                0x0f3690d04eb8e, 0x73fcdd14b71c0 },
            { 0x67079449bac41, 0x5b79c4621484f, 0x61069f2156b8d,
                0x0eb26573b10af, 0x389e740c9a9ce },
        },
        {
            { 0x578f6570eac28, 0x644f2339c3937, 0x66e47b7956c2c,
                0x34832fe1f55d0, 0x25c425e5d6263 },
            { 0x4b3ae34dcb9ce, 0x47c691a15ac9f, 0x318e06e5d400c,
                0x3c422d9f83eb1, 0x61545379465a6 },
            { 0x606a6f1d7de6e, 0x4f1c0c46107e7, 0x229b1dcfbe5d8,
                0x3acc60a7b1327, 0x6539a08915484 },
        },
        {
            { 0x4dbd414bb4a19, 0x7930849f1dbb8, 0x329c5a466caf0,
                0x6c824544feb9b, 0x0f65320ef019b },
            { 0x21f74c3d2f773, 0x024b88d08bd3a, 0x6e678cf054151,
                0x43631272e747c, 0x11c5e4aac5cd1 },
            { 0x6d1b1cafde0c6, 0x462c76a303a90, 0x3ca4e693cff9b,
                0x3952cd45786fd, 0x4cabc7bdec330 },
        },
    },
    {
        {
            { 0x7788f3f78d289, 0x5942809b3f811, 0x5973277f8c29c,
                0x010f93bc5fe67, 0x7ee498165acb2 },
            { 0x69624089c0a2e, 0x0075fc8e70473, 0x13e84ab1d2313,
                0x2c10bedf6953b, 0x639b93f0321c8 },
            { 0x508e39111a1c3, 0x290120e912f7a, 0x1cbf464acae43,
                0x15373e9576157, 0x0edf493c85b60 },
        },
        {
            { 0x7c4d284764113, 0x7fefebf06acec, 0x39afb7a824100,
                0x1b48e47e7fd65, 0x04c00c54d1dfa },
            { 0x48158599b5a68, 0x1fd75bc41d5d9, 0x2d9fc1fa95d3c,
                0x7da27f20eba11, 0x403b92e3019d4 },
            { 0x22f818b465cf8, 0x342901dff09b8, 0x31f595dc683cd,
                0x37a57745fd682, 0x355bb12ab2617 },
        },
        {
            { 0x1dac75a8c7318, 0x3b679d5423460, 0x6b8fcb7b6400e,
                0x6c73783be5f9d, 0x7518eaf8e052a },
            { 0x664cc7493bbf4, 0x33d94761874e3, 0x0179e1796f613,
                0x1890535e2867d, 0x0f9b8132182ec },
            { 0x059c41b7f6c32, 0x79e8706531491, 0x6c747643cb582,
                0x2e20c0ad494e4, 0x47c3871bbb175 },
        },
        {
            { 0x65d50c85066b0, 0x6167453361f7c, 0x06ba3818bb312,
                0x6aff29baa7522, 0x08fea02ce8d48 },
            { 0x4539771ec4f48, 0x7b9318badca28, 0x70f19afe016c5,
                0x4ee7bb1608d23, 0x00b89b8576469 },
            { 0x5dd7668deead0, 0x4096d0ba47049, 0x6275997219114,
                0x29bda8a67e6ae, 0x473829a74f75d },
        },
        {
            { 0x1533aad3902c9, 0x1dde06b11e47b, 0x784bed1930b77,
                0x1c80a92b9c867, 0x6c668b4d44e4d },
            { 0x2da754679c418, 0x3164c31be105a, 0x11fac2b98ef5f,
                0x35a1aaf779256, 0x2078684c4833c },
            { 0x0cf217a78820c, 0x65024e7d2e769, 0x23bb5efdda82a,
                0x19fd4b632d3c6, 0x7411a6054f8a4 },
        },
        {
            { 0x2e53d18b175b4, 0x33e7254204af3, 0x3bcd7d5a1c4c5,
                0x4c7c22af65d0f, 0x1ec9a872458c3 },
            { 0x59d32b99dc86d, 0x6ac075e22a9ac, 0x30b9220113371,
                0x27fd9a638966e, 0x7c136574fb813 },
            { 0x6a4d400a2509b, 0x041791056971c, 0x655d5866e075c,
                0x2302bf3e64df8, 0x3add88a5c7cd6 },
        },
        {
            { 0x298d459393046, 0x30bfecb3d90b8, 0x3d9b8ea3df8d6,
                0x3900e96511579, 0x61ba1131a406a },
            { 0x15770b635dcf2, 0x59ecd83f79571, 0x2db461c0b7fbd,
                0x73a42a981345f, 0x249929fccc879 },
            { 0x0a0f116959029, 0x5974fd7b1347a, 0x1e0cc1c08edad,
                0x673bdf8ad1f13, 0x5620310cbbd8e },
        },
        {
            { 0x6b5f477e285d6, 0x4ed91ec326cc8, 0x6d6537503a3fd,
                0x626d3763988d5, 0x7ec846f3658ce },
            { 0x193434934d643, 0x0d4a2445eaa51, 0x7d0708ae76fe0,
                0x39847b6c3c7e1, 0x37676a2a4d9d9 },
            { 0x68f3f1da22ec7, 0x6ed8039a2736b, 0x2627ee04c3c75,
                0x6ea90a647e7d1, 0x6daaf723399b9 },
        },
    },
    {
        {
            { 0x304bfacad8ea2, 0x502917d108b07, 0x043176ca6dd0f,
                0x5d5158f2c1d84, 0x2b5449e58eb3b },
            { 0x27562eb3dbe47, 0x291d7b4170be7, 0x5d1ca67dfa8e1,
                0x2a88061f298a2, 0x1304e9e71627d },
            { 0x014d26adc9cfe, 0x7f1691ba16f13, 0x5e71828f06eac,
                0x349ed07f0fffc, 0x4468de2d7c2dd },
        },
        {
            { 0x2d8c6f86307ce, 0x6286ba1850973, 0x5e9dcb08444d4,
                0x1a96a543362b2, 0x5da6427e63247 },
            { 0x3355e9419469e, 0x1847bb8ea8a37, 0x1fe6588cf9b71,
                0x6b1c9d2db6b22, 0x6cce7c6ffb44b },
            { 0x4c688deac22ca, 0x6f775c3ff0352, 0x565603ee419bb,
                0x6544456c61c46, 0x58f29abfe79f2 },
        },
        {
            { 0x264bf710ecdf6, 0x708c58527896b, 0x42ceae6c53394,
                0x4381b21e82b6a, 0x6af93724185b4 },
            { 0x6cfab8de73e68, 0x3e6efced4bd21, 0x0056609500dbe,
                0x71b7824ad85df, 0x577629c4a7f41 },
            { 0x0024509c6a888, 0x2696ab12e6644, 0x0cca27f4b80d8,
                0x0c7c1f11b119e, 0x701f25bb0caec },
        },
        {
            { 0x0f6d97cbec113, 0x4ce97fb7c93a3, 0x139835a11281b,
                0x728907ada9156, 0x720a5bc050955 },
            { 0x0b0f8e4616ced, 0x1d3c4b50fb875, 0x2f29673dc0198,
                0x5f4b0f1830ffa, 0x2e0c92bfbdc40 },
            { 0x709439b805a35, 0x6ec48557f8187, 0x08a4d1ba13a2c,
                0x076348a0bf9ae, 0x0e9b9cbb144ef },
        },
        {
            { 0x69bd55db1beee, 0x6e14e47f731bd, 0x1a35e47270eac,
                0x66f225478df8e, 0x366d44191cfd3 },
            { 0x2d48ffb5720ad, 0x57b7f21a1df77, 0x5550effba0645,
                0x5ec6a4098a931, 0x221104eb3f337 },
            { 0x41743f2bc8c14, 0x796b0ad8773c7, 0x29fee5cbb689b,
                0x122665c178734, 0x4167a4e6bc593 },
        },
        {
            { 0x62665f8ce8fee, 0x29d101ac59857, 0x4d93bbba59ffc,
                0x17b7897373f17, 0x34b33370cb7ed },
            { 0x39d2876f62700, 0x001cecd1d6c87, 0x7f01a11747675,
                0x2350da5a18190, 0x7938bb7e22552 },
            { 0x591ee8681d6cc, 0x39db0b4ea79b8, 0x202220f380842,
                0x2f276ba42e0ac, 0x1176fc6e2dfe6 },
        },
        {
            { 0x0e28949770eb8, 0x5559e88147b72, 0x35e1e6e63ef30,
                0x35b109aa7ff6f, 0x1f6a3e54f2690 },
            { 0x76cd05b9c619b, 0x69654b0901695, 0x7a53710b77f27,
                0x79a1ea7d28175, 0x08fc3a4c677d5 },
            { 0x4c199d30734ea, 0x6c622cb9acc14, 0x5660a55030216,
                0x068f1199f11fb, 0x4f2fad0116b90 },
        },
        {
            { 0x4d91db73bb638, 0x55f82538112c5, 0x6d85a279815de,
                0x740b7b0cd9cf9, 0x3451995f2944e },
            { 0x6b24194ae4e54, 0x2230afded8897, 0x23412617d5071,
                0x3d5d30f35969b, 0x445484a4972ef },
            { 0x2fcd09fea7d7c, 0x296126b9ed22a, 0x4a171012a05b2,
                0x1db92c74d5523, 0x10b89ca604289 },
        },
    },
    {
        {
            { 0x141be5a45f06e, 0x5adb38becaea7, 0x3fd46db41f2bb,
                0x6d488bbb5ce39, 0x17d2d1d9ef0d4 },
            { 0x147499718289c, 0x0a48a67e4c7ab, 0x30fbc544bafe3,
                0x0c701315fe58a, 0x20b878d577b75 },
            { 0x2af18073f3e6a, 0x33aea420d24fe, 0x298008bf4ff94,
                0x3539171db961e, 0x72214f63cc65c },
        },
        {
            { 0x5b7b9f43b29c9, 0x149ea31eea3b3, 0x4be7713581609,
                0x2d87960395e98, 0x1f24ac855a154 },
            { 0x37f405307a693, 0x2e5e66cf2b69c, 0x5d84266ae9c53,
                0x5e4eb7de853b9, 0x5fdf48c58171c },
            { 0x608328e9505aa, 0x22182841dc49a, 0x3ec96891d2307,
                0x2f363fff22e03, 0x00ba739e2ae39 },
        },
        {
            { 0x426f5ea88bb26, 0x33092e77f75c8, 0x1a53940d819e7,
                0x1132e4f818613, 0x72297de7d518d },
            { 0x698de5c8790d6, 0x268b8545beb25, 0x6d2648b96fedf,
                0x47988ad1db07c, 0x03283a3e67ad7 },
            { 0x41dc7be0cb939, 0x1b16c66100904, 0x0a24c20cbc66d,
                0x4a2e9efe48681, 0x05e1296846271 },
        },
        {
            { 0x7bbc8242c4550, 0x59a06103b35b7, 0x7237e4af32033,
                0x726421ab3537a, 0x78cf25d38258c },
            { 0x2eeb32d9c495a, 0x79e25772f9750, 0x6d747833bbf23,
                0x6cdd816d5d749, 0x39c00c9c13698 },
            { 0x66b8e31489d68, 0x573857e10e2b5, 0x13be816aa1472,
                0x41964d3ad4bf8, 0x006b52076b3ff },
        },
        {
            { 0x37e16b9ce082d, 0x1882f57853eb9, 0x7d29eacd01fc5,
                0x2e76a59b5e715, 0x7de2e9561a9f7 },
            { 0x0cfe19d95781c, 0x312cc621c453c, 0x145ace6da077c,
                0x0912bef9ce9b8, 0x4d57e3443bc76 },
            { 0x0d4f4b6a55ecb, 0x7ebb0bb733bce, 0x7ba6a05200549,
                0x4f6ede4e22069, 0x6b2a90af1a602 },
        },
        {
            { 0x3f3245bb2d80a, 0x0e5f720f36efd, 0x3b9cccf60c06d,
                0x084e323f37926, 0x465812c8276c2 },
            { 0x3f4fc9ae61e97, 0x3bc07ebfa2d24, 0x3b744b55cd4a0,
                0x72553b25721f3, 0x5fd8f4e9d12d3 },
            { 0x3beb22a1062d9, 0x6a7063b82c9a8, 0x0a5a35dc197ed,
                0x3c80c06a53def, 0x05b32c2b1cb16 },
        },
        {
            { 0x4a42c7ad58195, 0x5c8667e799eff, 0x02e5e74c850a1,
                0x3f0db614e869a, 0x31771a4856730 },
            { 0x05eccd24da8fd, 0x580bbfdf07918, 0x7e73586873c6a,
                0x74ceddf77f93e, 0x3b5556a37b471 },
            { 0x0c524e14dd482, 0x283457496c656, 0x0ad6bcfb6cd45,
                0x375d1e8b02414, 0x4fc079d27a733 },
        },
        {
            { 0x48b440c86c50d, 0x139929cca3b86, 0x0f8f2e44cdf2f,
                0x68432117ba6b2, 0x241170c2bae3c },
            { 0x138b089bf2f7f, 0x4a05bfd34ea39, 0x203914c925ef5,
                0x7497fffe04e3c, 0x124567cecaf98 },
            { 0x1ab860ac473b4, 0x5c0227c86a7ff, 0x71b12bfc24477,
                0x006a573a83075, 0x3f8612966c870 },
        },
    },
    {
        {
            { 0x0fcfa36048d13, 0x66e7133bbb383, 0x64b42a8a45676,
                0x4ea6e4f9a85cf, 0x26f57eee878a1 },
            { 0x20cc9782a0dde, 0x65d4e3070aab3, 0x7bc8e31547736,
                0x09ebfb1432d98, 0x504aa77679736 },
            { 0x32cd55687efb1, 0x4448f5e2f6195, 0x568919d460345,
                0x034c2e0ad1a27, 0x4041943d9dba3 },
        },
        {
            { 0x17743a26caadd, 0x48c9156f9c964, 0x7ef278d1e9ad0,
                0x00ce58ea7bd01, 0x12d931429800d },
            { 0x0eeba43ebcc96, 0x384dd5395f878, 0x1df331a35d272,
                0x207ecfd4af70e, 0x1420a1d976843 },
            { 0x67799d337594f, 0x01647548f6018, 0x57fce5578f145,
                0x009220c142a71, 0x1b4f92314359a },
        },
        {
            { 0x73030a49866b1, 0x2442be90b2679, 0x77bd3d8947dcf,
                0x1fb55c1552028, 0x5ff191d56f9a2 },
            { 0x4109d89150951, 0x225bd2d2d47cb, 0x57cc080e73bea,
                0x6d71075721fcb, 0x239b572a7f132 },
            { 0x6d433ac2d9068, 0x72bf930a47033, 0x64facf4a20ead,
                0x365f7a2b9402a, 0x020c526a758f3 },
        },
        {
            { 0x1ef59f042cc89, 0x3b1c24976dd26, 0x31d665cb16272,
                0x28656e470c557, 0x452cfe0a5602c },
            { 0x034f89ed8dbbc, 0x73b8f948d8ef3, 0x786c1d323caab,
                0x43bd4a9266e51, 0x02aacc4615313 },
            { 0x0f7a0647877df, 0x4e1cc0f93f0d4, 0x7ec4726ef1190,
                0x3bdd58bf512f8, 0x4cfb7d7b304b8 },
        },
        {
            { 0x699c29789ef12, 0x63beae321bc50, 0x325c340adbb35,
                0x562e1a1e42bf6, 0x5b1d4cbc434d3 },
            { 0x43d6cb89b75fe, 0x3338d5b900e56, 0x38d327d531a53,
                0x1b25c61d51b9f, 0x14b4622b39075 },
            { 0x32615cc0a9f26, 0x57711b99cb6df, 0x5a69c14e93c38,
                0x6e88980a4c599, 0x2f98f71258592 },
        },
        {
            { 0x2ae444f54a701, 0x615397afbc5c2, 0x60d7783f3f8fb,
                0x2aa675fc486ba, 0x1d8062e9e7614 },
            { 0x4a74cb50f9e56, 0x531d1c2640192, 0x0c03d9d6c7fd2,
                0x57ccd156610c1, 0x3a6ae249d806a },
            { 0x2da85a9907c5a, 0x6b23721ec4caf, 0x4d2d3a4683aa2,
                0x7f9c6870efdef, 0x298b8ce8aef25 },
        },
        {
            { 0x272ea0a2165de, 0x68179ef3ed06f, 0x4e2b9c0feac1e,
                0x3ee290b1b63bb, 0x6ba6271803a7d },
            { 0x27953eff70cb2, 0x54f22ae0ec552, 0x29f3da92e2724,
                0x242ca0c22bd18, 0x34b8a8404d5ce },
            { 0x6ecb583693335, 0x3ec76bfdfb84d, 0x2c895cf56a04f,
                0x6355149d54d52, 0x71d62bdd465e1 },
        },
        {
            { 0x5b5dab1f75ef5, 0x1e2d60cbeb9a5, 0x527c2175dfe57,
                0x59e8a2b8ff51f, 0x1c333621262b2 },
            { 0x3cc28d378df80, 0x72141f4968ca6, 0x407696bdb6d0d,
                0x5d271b22ffcfb, 0x74d5f317f3172 },
            { 0x7e55467d9ca81, 0x6a5653186f50d, 0x6b188ece62df1,
                0x4c66d36844971, 0x4aebcc4547e9d },
        },
    },
    {
        {
            { 0x08d9e7354b610, 0x26b750b6dc168, 0x162881e01acc9,
                0x7966df31d01a5, 0x173bd9ddc9a1d },
            { 0x0071b276d01c9, 0x0b0d8918e025e, 0x75beea79ee2eb,
                0x3c92984094db8, 0x5d88fbf95a3db },
            { 0x00f1efe5872df, 0x5da872318256a, 0x59ceb81635960,
                0x18cf37693c764, 0x06e1cd13b19ea },
        },
        {
            { 0x3af629e5b0353, 0x204f1a088e8e5, 0x10efc9ceea82e,
                0x589863c2fa34b, 0x7f3a6a1a8d837 },
            { 0x0ad516f166f23, 0x263f56d57c81a, 0x13422384638ca,
                0x1331ff1af0a50, 0x3080603526e16 },
            { 0x644395d3d800b, 0x2b9203dbedefc, 0x4b18ce656a355,
                0x03f3466bc182c, 0x30d0fded2e513 },
        },
        {
            { 0x4971e68b84750, 0x52ccc9779f396, 0x3e904ae8255c8,
                0x4ecae46f39339, 0x4615084351c58 },
            { 0x14d1af21233b3, 0x1de1989b39c0b, 0x52669dc6f6f9e,
                0x43434b28c3fc7, 0x0a9214202c099 },
            { 0x019c0aeb9a02e, 0x1a2c06995d792, 0x664cbb1571c44,
                0x6ff0736fa80b2, 0x3bca0d2895ca5 },
        },
        {
            { 0x08eb69ecc01bf, 0x5b4c8912df38d, 0x5ea7f8bc2f20e,
                0x120e516caafaf, 0x4ea8b4038df28 },
            { 0x031bc3c5d62a4, 0x7d9fe0f4c081e, 0x43ed51467f22c,
                0x1e6cc0c1ed109, 0x5631deddae8f1 },
            { 0x5460af1cad202, 0x0b4919dd0655d, 0x7c4697d18c14c,
                0x231c890bba2a4, 0x24ce0930542ca },
        },
        {
            { 0x7a155fdf30b85, 0x1c6c6e5d487f9, 0x24be1134bdc5a,
                0x1405970326f32, 0x549928a7324f4 },
            { 0x090f5fd06c106, 0x6abb1021e43fd, 0x232bcfad711a0,
                0x3a5c13c047f37, 0x41d4e3c28a06d },
            { 0x632a763ee1a2e, 0x6fa4bffbd5e4d, 0x5fd35a6ba4792,
                0x7b55e1de99de8, 0x491b66dec0dcf },
        },
        {
            { 0x04a8ed0da64a1, 0x5ecfc45096ebe, 0x5edee93b488b2,
                0x5b3c11a51bc8f, 0x4cf6b8b0b7018 },
            { 0x5b13dc7ea32a7, 0x18fc2db73131e, 0x7e3651f8f57e3,
                0x25656055fa965, 0x08f338d0c85ee },
            { 0x3a821991a73bd, 0x03be6418f5870, 0x1ddc18eac9ef0,
                0x54ce09e998dc2, 0x530d4a82eb078 },
        },
        {
            { 0x173456c9abf9e, 0x7892015100dad, 0x33ee14095fecb,
                0x6ad95d67a0964, 0x0db3e7e00cbfb },
            { 0x43630e1f94825, 0x4d1956a6b4009, 0x213fe2df8b5e0,
                0x05ce3a41191e6, 0x65ea753f10177 },
            { 0x6fc3ee2096363, 0x7ec36b96d67ac, 0x510ec6a0758b1,
                0x0ed87df022109, 0x02a4ec1921e1a },
        },
        {
            { 0x06162f1cf795f, 0x324ddcafe5eb9, 0x018d5e0463218,
                0x7e78b9092428e, 0x36d12b5dec067 },
            { 0x6259a3b24b8a2, 0x188b5f4170b9c, 0x681c0dee15deb,
                0x4dfe665f37445, 0x3d143c5112780 },
            { 0x5279179154557, 0x39f8f0741424d, 0x45e6eb357923d,
                0x42c9b5edb746f, 0x2ef517885ba82 },
        },
    },
    {
        {
            { 0x6bffb305b2f51, 0x5b112b2d712dd, 0x35774974fe4e2,
                0x04af87a96e3a3, 0x57968290bb3a0 },
            { 0x7974e8c58aedc, 0x7757e083488c6, 0x601c62ae7bc8b,
                0x45370c2ecab74, 0x2f1b78fab143a },
            { 0x2b8430a20e101, 0x1a49e1d88fee3, 0x38bbb47ce4d96,
                0x1f0e7ba84d437, 0x7dc43e35dc2aa },
        },
        {
            { 0x02a5c273e9718, 0x32bc9dfb28b4f, 0x48df4f8d5db1a,
                0x54c87976c028f, 0x044fb81d82d50 },
            { 0x66665887dd9c3, 0x629760a6ab0b2, 0x481e6c7243e6c,
                0x097e37046fc77, 0x7ef72016758cc },
            { 0x718c5a907e3d9, 0x3b9c98c6b383b, 0x006ed255eccdc,
                0x6976538229a59, 0x7f79823f9c30d },
        },
        {
            { 0x41ff068f587ba, 0x1c00a191bcd53, 0x7b56f9c209e25,
                0x3781e5fccaabe, 0x64a9b0431c06d },
            { 0x4d239a3b513e8, 0x29723f51b1066, 0x642f4cf04d9c3,
                0x4da095aa09b7a, 0x0a4e0373d784d },
            { 0x3d6a15b7d2919, 0x41aa75046a5d6, 0x691751ec2d3da,
                0x23638ab6721c4, 0x071a7d0ace183 },
        },
        {
            { 0x4355220e14431, 0x0e1362a283981, 0x2757cd8359654,
                0x2e9cd7ab10d90, 0x7c69bcf761775 },
            { 0x72daac887ba0b, 0x0b7f4ac5dda60, 0x3bdda2c0498a4,
                0x74e67aa180160, 0x2c3bcc7146ea7 },
            { 0x0d7eb04e8295f, 0x4a5ea1e6fa0fe, 0x45e635c436c60,
                0x28ef4a8d4d18b, 0x6f5a9a7322aca },
        },
        {
            { 0x1d4eba3d944be, 0x0100f15f3dce5, 0x61a700e367825,
                0x5922292ab3d23, 0x02ab9680ee8d3 },
            { 0x1000c2f41c6c5, 0x0219fdf737174, 0x314727f127de7,
                0x7e5277d23b81e, 0x494e21a2e147a },
            { 0x48a85dde50d9a, 0x1c1f734493df4, 0x47bdb64866889,
                0x59a7d048f8eec, 0x6b5d76cbea46b },
        },
        {
            { 0x141171e782522, 0x6806d26da7c1f, 0x3f31d1bc79ab9,
                0x09f20459f5168, 0x16fb869c03dd3 },
            { 0x7556cec0cd994, 0x5eb9a03b7510a, 0x50ad1dd91cb71,
                0x1aa5780b48a47, 0x0ae333f685277 },
            { 0x6199733b60962, 0x69b157c266511, 0x64740f893f1ca,
                0x03aa408fbf684, 0x3f81e38b8f70d },
        },
        {
            { 0x37f355f17c824, 0x07ae85334815b, 0x7e3abddd2e48f,
                0x61eeabe1f45e5, 0x0ad3e2d34cded },
            { 0x10fcc7ed9affe, 0x4248cb0e96ff2, 0x4311c115172e2,
                0x4c9d41cbf6925, 0x50510fc104f50 },
            { 0x40fc5336e249d, 0x3386639fb2de1, 0x7bbf871d17b78,
                0x75f796b7e8004, 0x127c158bf0fa1 },
        },
        {
            { 0x28fc4ae51b974, 0x26e89bfd2dbd4, 0x4e122a07665cf,
                0x7cab1203405c3, 0x4ed82479d167d },
            { 0x17c422e9879a2, 0x28a5946c8fec3, 0x53ab32e912b77,
                0x7b44da09fe0a5, 0x354ef87d07ef4 },
            { 0x3b52260c5d975, 0x79d6836171fdc, 0x7d994f140d4bb,
                0x1b6c404561854, 0x302d92d205392 },
        },
    },
    {
        {
            { 0x46fb6e4e0f177, 0x53497ad5265b7, 0x1ebdba01386fc,
                0x0302f0cb36a3c, 0x0edc5f5eb426d },
            { 0x3c1a2bca4283d, 0x23430c7bb2f02, 0x1a3ea1bb58bc2,
                0x7265763de5c61, 0x10e5d3b76f1ca },
            { 0x3bfd653da8e67, 0x584953ec82a8a, 0x55e288fa7707b,
                0x5395fc3931d81, 0x45b46c51361cb },
        },
        {
            { 0x54ddd8a7fe3e4, 0x2cecc41c619d3, 0x43a6562ac4d91,
                0x4efa5aca7bdd9, 0x5c1c0aef32122 },
            { 0x02abf314f7fa1, 0x391d19e8a1528, 0x6a2fa13895fc7,
                0x09d8eddeaa591, 0x2177bfa36dcb7 },
            { 0x01bbcfa79db8f, 0x3d84beb3666e1, 0x20c921d812204,
                0x2dd843d3b32ce, 0x4ae619387d8ab },
        },
        {
            { 0x17e44985bfb83, 0x54e32c626cc22, 0x096412ff38118,
                0x6b241d61a246a, 0x75685abe5ba43 },
            { 0x3f6aa5344a32e, 0x69683680f11bb, 0x04c3581f623aa,
                0x701af5875cba5, 0x1a00d91b17bf3 },
            { 0x60933eb61f2b2, 0x5193fe92a4dd2, 0x3d995a550f43e,
                0x3556fb93a883d, 0x135529b623b0e },
        },
        {
            { 0x716bce22e83fe, 0x33d0130b83eb8, 0x0952abad0afac,
                0x309f64ed31b8a, 0x5972ea051590a },
            { 0x0dbd7add1d518, 0x119f823e2231e, 0x451d66e5e7de2,
                0x500c39970f838, 0x79b5b81a65ca3 },
            { 0x4ac20dc8f7811, 0x29589a9f501fa, 0x4d810d26a6b4a,
                0x5ede00d96b259, 0x4f7e9c95905f3 },
        },
        {
            { 0x0443d355299fe, 0x39b7d7d5aee39, 0x692519a2f34ec,
                0x6e4404924cf78, 0x1942eec4a144a },
            { 0x74bbc5781302e, 0x73135bb81ec4c, 0x7ef671b61483c,
                0x7264614ccd729, 0x31993ad92e638 },
            { 0x45319ae234992, 0x2219d47d24fb5, 0x4f04488b06cf6,
                0x53aaa9e724a12, 0x2a0a65314ef9c },
        },
        {
            { 0x61acd3c1c793a, 0x58b46b78779e6, 0x3369aacbe7af2,
                0x509b0743074d4, 0x055dc39b6dea1 },
            { 0x7937ff7f927c2, 0x0c2fa14c6a5b6, 0x556bddb6dd07c,
                0x6f6acc179d108, 0x4cf6e218647c2 },
            { 0x1227cc28d5bb6, 0x78ee9bff57623, 0x28cb2241f893a,
                0x25b541e3c6772, 0x121a307710aa2 },
        },
        {
            { 0x1713ec77483c9, 0x6f70572d5facb, 0x25ef34e22ff81,
                0x54d944f141188, 0x527bb94a6ced3 },
            { 0x35d5e9f034a97, 0x126069785bc9b, 0x5474ec7854ff0,
                0x296a302a348ca, 0x333fc76c7a40e },
            { 0x5992a995b482e, 0x78dc707002ac7, 0x5936394d01741,
                0x4fba4281aef17, 0x6b89069b20a7a },
        },
        {
            { 0x2fa8cb5c7db77, 0x718e6982aa810, 0x39e95f81a1a1b,
                0x5e794f3646cfb, 0x0473d308a7639 },
            { 0x2a0416270220d, 0x75f248b69d025, 0x1cbbc16656a27,
                0x5b9ffd6e26728, 0x23bc2103aa73e },
            { 0x6792603589e05, 0x248db9892595d, 0x006a53cad2d08,
                0x20d0150f7ba73, 0x102f73bfde043 },
        },
    },
    {
        {
            { 0x4dae0b5511c9a, 0x5257fffe0d456, 0x54108d1eb2180,
                0x096cc0f9baefa, 0x3f6bd725da4ea },
            { 0x0b9ab7f5745c6, 0x5caf0f8d21d63, 0x7debea408ea2b,
                0x09edb93896d16, 0x36597d25ea5c0 },
            { 0x58d7b106058ac, 0x3cdf8d20bee69, 0x00a4cb765015e,
                0x36832337c7cc9, 0x7b7ecc19da60d },
        },
        {
            { 0x64a51a77cfa9b, 0x29cf470ca0db5, 0x4b60b6e0898d9,
                0x55d04ddffe6c7, 0x03bedc661bf5c },
            { 0x2373c695c690d, 0x4c0c8520dcf18, 0x384af4b7494b9,
                0x4ab4a8ea22225, 0x4235ad7601743 },
            { 0x0cb0d078975f5, 0x292313e530c4b, 0x38dbb9124a509,
                0x350d0655a11f1, 0x0e7ce2b0cdf06 },
        },
        {
            { 0x6fedfd94b70f9, 0x2383f9745bfd4, 0x4beae27c4c301,
                0x75aa4416a3f3f, 0x615256138aece },
            { 0x4643ac48c85a3, 0x6878c2735b892, 0x3a53523f4d877,
                0x3a504ed8bee9d, 0x666e0a5d8fb46 },
            { 0x3f64e4870cb0d, 0x61548b16d6557, 0x7a261773596f3,
                0x7724d5f275d3a, 0x7f0bc810d514d },
        },
        {
            { 0x49dad737213a0, 0x745dee5d31075, 0x7b1a55e7fdbe2,
                0x5ba988f176ea1, 0x1d3a907ddec5a },
            { 0x06ba426f4136f, 0x3cafc0606b720, 0x518f0a2359cda,
                0x5fae5e46feca7, 0x0d1f8dbcf8eed },
            { 0x693313ed081dc, 0x5b0a366901742, 0x40c872ca4ca7e,
                0x6f18094009e01, 0x00011b44a31bf },
        },
        {
            { 0x61f696a0aa75c, 0x38b0a57ad42ca, 0x1e59ab706fdc9,
                0x01308d46ebfcd, 0x63d988a2d2851 },
            { 0x7a06c3fc66c0c, 0x1c9bac1ba47fb, 0x23935c575038e,
                0x3f0bd71c59c13, 0x3ac48d916e835 },
            { 0x20753afbd232e, 0x71fbb1ed06002, 0x39cae47a4af3a,
                0x0337c0b34d9c2, 0x33fad52b2368a },
        },
        {
            { 0x4c8d0c422cfe8, 0x760b4275971a5, 0x3da95bc1cad3d,
                0x0f151ff5b7376, 0x3cc355ccb90a7 },
            { 0x649c6c5e41e16, 0x60667eee6aa80, 0x4179d182be190,
                0x653d9567e6979, 0x16c0f429a256d },
            { 0x69443903e9131, 0x16f4ac6f9dd36, 0x2ea4912e29253,
                0x2b4643e68d25d, 0x631eaf426bae7 },
        },
        {
            { 0x175b9a3700de8, 0x77c5f00aa48fb, 0x3917785ca0317,
                0x05aa9b2c79399, 0x431f2c7f665f8 },
            { 0x10410da66fe9f, 0x24d82dcb4d67d, 0x3e6fe0e17752d,
                0x4dade1ecbb08f, 0x5599648b1ea91 },
            { 0x26344858f7b19, 0x5f43d4a295ac0, 0x242a75c52acd4,
                0x5934480220d10, 0x7b04715f91253 },
        },
        {
            { 0x6c280c4e6bac6, 0x3ada3b361766e, 0x42fe5125c3b4f,
                0x111d84d4aac22, 0x48d0acfa57cde },
            { 0x5bd28acf6ae43, 0x16fab8f56907d, 0x7acb11218d5f2,
                0x41fe02023b4db, 0x59b37bf5c2f65 },
            { 0x726e47dabe671, 0x2ec45e746f6c1, 0x6580e53c74686,
                0x5eda104673f74, 0x16234191336d3 },
        },
    },
    {
        {
            { 0x19cd61ff38640, 0x060c6c4b41ba9, 0x75cf70ca7366f,
                0x118a8f16c011e, 0x4a25707a203b9 },
            { 0x499def6267ff6, 0x76e858108773c, 0x693cac5ddcb29,
                0x00311d00a9ff4, 0x2cdfdfecd5d05 },
            { 0x7668a53f6ed6a, 0x303ba2e142556, 0x3880584c10909,
                0x4fe20000a261d, 0x5721896d248e4 },
        },
        {
            { 0x55091a1d0da4e, 0x4f6bfc7c1050b, 0x64e4ecd2ea9be,
                0x07eb1f28bbe70, 0x03c935afc4b03 },
            { 0x65517fd181bae, 0x3e5772c76816d, 0x019189640898a,
                0x1ed2a84de7499, 0x578edd74f63c1 },
            { 0x276c6492b0c3d, 0x09bfc40bf932e, 0x588e8f11f330b,
                0x3d16e694dc26e, 0x3ec2ab590288c },
        },
        {
            { 0x13a09ae32d1cb, 0x3e81eb85ab4e4, 0x07aaca43cae1f,
                0x62f05d7526374, 0x0e1bf66c6adba },
            { 0x0d27be4d87bb9, 0x56c27235db434, 0x72e6e0ea62d37,
                0x5674cd06ee839, 0x2dd5c25a200fc },
            { 0x3d5e9792c887e, 0x319724dabbc55, 0x2b97c78680800,
                0x7afdfdd34e6dd, 0x730548b35ae88 },
        },
        {
            { 0x3094ba1d6e334, 0x6e126a7e3300b, 0x089c0aefcfbc5,
                0x2eea11f836583, 0x585a2277d8784 },
            { 0x551a3cba8b8ee, 0x3b6422be2d886, 0x630e1419689bc,
                0x4653b07a7a955, 0x3043443b411db },
            { 0x25f8233d48962, 0x6bd8f04aff431, 0x4f907fd9a6312,
                0x40fd3c737d29b, 0x7656278950ef9 },
        },
        {
            { 0x073a3ea86cf9d, 0x6e0e2abfb9c2e, 0x60e2a38ea33ee,
                0x30b2429f3fe18, 0x28bbf484b613f },
            { 0x3cf59d51fc8c0, 0x7a0a0d6de4718, 0x55c3a3e6fb74b,
                0x353135f884fd5, 0x3f4160a8c1b84 },
            { 0x12f5c6f136c7c, 0x0fedba237de4c, 0x779bccebfab44,
                0x3aea93f4d6909, 0x1e79cb358188f },
        },
        {
            { 0x153d8f5e08181, 0x08533bbdb2efd, 0x1149796129431,
                0x17a6e36168643, 0x478ab52d39d1f },
            { 0x436c3eef7e3f1, 0x7ffd3c21f0026, 0x3e77bf20a2da9,
                0x418bffc8472de, 0x65d7951b3a3b3 },
            { 0x6a4d39252d159, 0x790e35900ecd4, 0x30725bf977786,
                0x10a5c1635a053, 0x16d87a411a212 },
        },
        {
            { 0x4d5e2d54e0583, 0x2e5d7b33f5f74, 0x3a5de3f887ebf,
                0x6ef24bd6139b7, 0x1f990b577a5a6 },
            { 0x57e5a42066215, 0x1a18b44983677, 0x3e652de1e6f8f,
                0x6532be02ed8eb, 0x28f87c8165f38 },
            { 0x44ead1be8f7d6, 0x5759d4f31f466, 0x0378149f47943,
                0x69f3be32b4f29, 0x45882fe1534d6 },
        },
        {
            { 0x49929943c6fe4, 0x4347072545b15, 0x3226bced7e7c5,
                0x03a134ced89df, 0x7dcf843ce405f },
            { 0x1345d757983d6, 0x222f54234cccd, 0x1784a3d8adbb4,
                0x36ebeee8c2bcc, 0x688fe5b8f626f },
            { 0x0d6484a4732c0, 0x7b94ac6532d92, 0x5771b8754850f,
                0x48dd9df1461c8, 0x6739687e73271 },
        },
    },
    {
        {
            { 0x5cc9dc80c1ac0, 0x683671486d4cd, 0x76f5f1a5e8173,
                0x6d5d3f5f9df4a, 0x7da0b8f68d7e7 },
            { 0x02014385675a6, 0x6155fb53d1def, 0x37ea32e89927c,
                0x059a668f5a82e, 0x46115aba1d4dc },
            { 0x71953c3b5da76, 0x6642233d37a81, 0x2c9658076b1bd,
                0x5a581e63010ff, 0x5a5f887e83674 },
        },
        {
            { 0x628d3a0a643b9, 0x01cd8640c93d2, 0x0b7b0cad70f2c,
                0x3864da98144be, 0x43e37ae2d5d1c },
            { 0x301cf70a13d11, 0x2a6a1ba1891ec, 0x2f291fb3f3ae0,
                0x21a7b814bea52, 0x3669b656e44d1 },
            { 0x63f06eda6e133, 0x233342758070f, 0x098e0459cc075,
                0x4df5ead6c7c1b, 0x6a21e6cd4fd5e },
        },
        {
            { 0x129126699b2e3, 0x0ee11a2603de8, 0x60ac2f5c74c21,
                0x59b192a196808, 0x45371b07001e8 },
            { 0x6170a3046e65f, 0x5401a46a49e38, 0x20add5561c4a8,
                0x7abb4edde9e46, 0x586bf9f1a195f },
            { 0x3088d5ef8790b, 0x38c2126fcb4db, 0x685bae149e3c3,
                0x0bcd601a4e930, 0x0eafb03790e52 },
        },
        {
            { 0x0805e0f75ae1d, 0x464cc59860a28, 0x248e5b7b00bef,
                0x5d99675ef8f75, 0x44ae3344c5435 },
            { 0x555c13748042f, 0x4d041754232c0, 0x521b430866907,
                0x3308e40fb9c39, 0x309acc675a02c },
            { 0x289b9bba543ee, 0x3ab592e28539e, 0x64d82abcdd83a,
                0x3c78ec172e327, 0x62d5221b7f946 },
        },
        {
            { 0x5d4263af77a3c, 0x23fdd2289aeb0, 0x7dc64f77eb9ec,
                0x01bd28338402c, 0x14f29a5383922 },
            { 0x4299c18d0936d, 0x5914183418a49, 0x52a18c721aed5,
                0x2b151ba82976d, 0x5c0efde4bc754 },
            { 0x17edc25b2d7f5, 0x37336a6081bee, 0x7b5318887e5c3,
                0x49f6d491a5be1, 0x5e72365c7bee0 },
        },
        {
            { 0x339062f08b33e, 0x4bbf3e657cfb2, 0x67af7f56e5967,
                0x4dbd67f9ed68f, 0x70b20555cb734 },
            { 0x3fc074571217f, 0x3a0d29b2b6aeb, 0x06478ccdde59d,
                0x55e4d051bddfa, 0x77f1104c47b4e },
            { 0x113c555112c4c, 0x7535103f9b7ca, 0x140ed1d9a2108,
                0x02522333bc2af, 0x0e34398f4a064 },
        },
        {
            { 0x30b093e4b1928, 0x1ce7e7ec80312, 0x4e575bdf78f84,
                0x61f7a190bed39, 0x6f8aded6ca379 },
            { 0x522d93ecebde8, 0x024f045e0f6cf, 0x16db63426cfa1,
                0x1b93a1fd30fd8, 0x5e5405368a362 },
            { 0x0123dfdb7b29a, 0x4344356523c68, 0x79a527921ee5f,
                0x74bfccb3e817e, 0x780de72ec8d3d },
        },
        {
            { 0x7eaf300f42772, 0x5455188354ce3, 0x4dcca4a3dcbac,
                0x3d314d0bfebcb, 0x1defc6ad32b58 },
            { 0x28545089ae7bc, 0x1e38fe9a0c15c, 0x12046e0e2377b,
                0x6721c560aa885, 0x0eb28bf671928 },
            { 0x3be1aef5195a7, 0x6f22f62bdb5eb, 0x39768b8523049,
                0x43394c8fbfdbd, 0x467d201bf8dd2 },
        },
    },
    {
        {
            { 0x6f4bd567ae7a9, 0x65ac89317b783, 0x07d3b20fd8932,
                0x000f208326916, 0x2ef9c5a5ba384 },
            { 0x6919a74ef4fad, 0x59ed4611452bf, 0x691ec04ea09ef,
                0x3cbcb2700e984, 0x71c43c4f5ba3c },
            { 0x56df6fa9e74cd, 0x79c95e4cf56df, 0x7be643bc609e2,
                0x149c12ad9e878, 0x5a758ca390c5f },
        },
        {
            { 0x0918b1d61dc94, 0x0d350260cd19c, 0x7a2ab4e37b4d9,
                0x21fea735414d7, 0x0a738027f639d },
            { 0x72710d9462495, 0x25aafaa007456, 0x2d21f28eaa31b,
                0x17671ea005fd0, 0x2dbae244b3eb7 },
            { 0x74a2f57ffe1cc, 0x1bc3073087301, 0x7ec57f4019c34,
                0x34e082e1fa524, 0x2698ca635126a },
        },
        {
            { 0x5702f5e3dd90e, 0x31c9a4a70c5c7, 0x136a5aa78fc24,
                0x1992f3b9f7b01, 0x3c004b0c4afa3 },
            { 0x5318832b0ba78, 0x6f24b9ff17cec, 0x0a47f30e060c7,
                0x58384540dc8d0, 0x1fb43dcc49cae },
            { 0x146ac06f4b82b, 0x4b500d89e7355, 0x3351e1c728a12,
                0x10b9f69932fe3, 0x6b43fd01cd1fd },
        },
        {
            { 0x742583e760ef3, 0x73dc1573216b8, 0x4ae48fdd7714a,
                0x4f85f8a13e103, 0x73420b2d6ff0d },
            { 0x75d4b4697c544, 0x11be1fff7f8f4, 0x119e16857f7e1,
                0x38a14345cf5d5, 0x5a68d7105b52f },
            { 0x4f6cb9e851e06, 0x278c4471895e5, 0x7efcdce3d64e4,
                0x64f6d455c4b4c, 0x3db5632fea34b },
        },
        {
            { 0x190b1829825d5, 0x0e7d3513225c9, 0x1c12be3b7abae,
                0x58777781e9ca6, 0x59197ea495df2 },
            { 0x6ee2bf75dd9d8, 0x6c72ceb34be8d, 0x679c9cc345ec7,
                0x7898df96898a4, 0x04321adf49d75 },
            { 0x16019e4e55aae, 0x74fc5f25d209c, 0x4566a939ded0d,
                0x66063e716e0b7, 0x45eafdc1f4d70 },
        },
        {
            { 0x64624cfccb1ed, 0x257ab8072b6c1, 0x0120725676f0a,
                0x4a018d04e8eee, 0x3f73ceea5d56d },
            { 0x401858045d72b, 0x459e5e0ca2d30, 0x488b719308bea,
                0x56f4a0d1b32b5, 0x5a5eebc80362d },
            { 0x7bfd10a4e8dc6, 0x7c899366736f4, 0x55ebbeaf95c01,
                0x46db060903f8a, 0x2605889126621 },
        },
        {
            { 0x18e3cc676e542, 0x26079d995a990, 0x04a7c217908b2,
                0x1dc7603e6655a, 0x0dedfa10b2444 },
            { 0x704a68360ff04, 0x3cecc3cde8b3e, 0x21cd5470f64ff,
                0x6abc18d953989, 0x54ad0c2e4e615 },
            { 0x367d5b82b522a, 0x0d3f4b83d7dc7, 0x3067f4cdbc58d,
                0x20452da697937, 0x62ecb2baa77a9 },
        },
        {
            { 0x72836afb62874, 0x0af3c2094b240, 0x0c285297f357a,
                0x7cc2d5680d6e3, 0x61913d5075663 },
            { 0x5795261152b3d, 0x7a1dbbafa3cbd, 0x5ad31c52588d5,
                0x45f3a4164685c, 0x2e59f919a966d },
            { 0x62d361a3231da, 0x65284004e01b8, 0x656533be91d60,
                0x6ae016c00a89f, 0x3ddbc2a131c05 },
        },
    },
    {
        {
            { 0x257a22796bb14, 0x6f360fb443e75, 0x680e47220eaea,
                0x2fcf2a5f10c18, 0x5ee7fb38d8320 },
            { 0x40ff9ce5ec54b, 0x57185e261b35b, 0x3e254540e70a9,
                0x1b5814003e3f8, 0x78968314ac04b },
            { 0x5fdcb41446a8e, 0x5286926ff2a71, 0x0f231e296b3f6,
                0x684a357c84693, 0x61d0633c9bca0 },
        },
        {
            { 0x328bcf8fc73df, 0x3b4de06ff95b4, 0x30aa427ba11a5,
                0x5ee31bfda6d9c, 0x5b23ac2df8067 },
            { 0x44935ffdb2566, 0x12f016d176c6e, 0x4fbb00f16f5ae,
                0x3fab78d99402a, 0x6e965fd847aed },
            { 0x2b953ee80527b, 0x55f5bcdb1b35a, 0x43a0b3fa23c66,
                0x76e07388b820a, 0x79b9bbb9dd95d },
        },
        {
            { 0x17dae8e9f7374, 0x719f76102da33, 0x5117c2a80ca8b,
                0x41a66b65d0936, 0x1ba811460accb },
            { 0x355406a3126c2, 0x50d1918727d76, 0x6e5ea0b498e0e,
                0x0a3b6063214f2, 0x5065f158c9fd2 },
            { 0x169fb0c429954, 0x59aedd9ecee10, 0x39916eb851802,
                0x57917555cc538, 0x3981f39e58a4f },
        },
        {
            { 0x5dfa56de66fde, 0x0058809075908, 0x6d3d8cb854a94,
                0x5b2f4e970b1e3, 0x30f4452edcbc1 },
            { 0x38a7559230a93, 0x52c1cde8ba31f, 0x2a4f2d4745a3d,
                0x07e9d42d4a28a, 0x38dc083705acd },
            { 0x52782c5759740, 0x53f3397d990ad, 0x3a939c7e84d15,
                0x234c4227e39e0, 0x632d9a1a593f2 },
        },
        {
            { 0x1fd11ed0c84a7, 0x021b3ed2757e1, 0x73e1de58fc1c6,
                0x5d110c84616ab, 0x3a5a7df28af64 },
            { 0x36b15b807cba6, 0x3f78a9e1afed7, 0x0a59c2c608f1f,
                0x52bdd8ecb81b7, 0x0b24f48847ed4 },
            { 0x2d4be511beac7, 0x6bda4d99e5b9b, 0x17e6996914e01,
                0x7b1f0ce7fcf80, 0x34fcf74475481 },
        },
        {
            { 0x31dab78cfaa98, 0x4e3216e5e54b7, 0x249823973b689,
                0x2584984e48885, 0x0119a3042fb37 },
            { 0x7e04c789767ca, 0x1671b28cfb832, 0x7e57ea2e1c537,
                0x1fbaaef444141, 0x3d3bdc164dfa6 },
            { 0x2d89ce8c2177d, 0x6cd12ba182cf4, 0x20a8ac19a7697,
                0x539fab2cc72d9, 0x56c088f1ede20 },
        },
        {
            { 0x35fac24f38f02, 0x7d75c6197ab03, 0x33e4bc2a42fa7,
                0x1c7cd10b48145, 0x038b7ea483590 },
            { 0x53d1110a86e17, 0x6416eb65f466d, 0x41ca6235fce20,
                0x5c3fc8a99bb12, 0x09674c6b99108 },
            { 0x6f82199316ff8, 0x05d54f1a9f3e9, 0x3bcc5d0bd274a,
                0x5b284b8d2d5ad, 0x6e5e31025969e },
        },
        {
            { 0x4fb0e63066222, 0x130f59747e660, 0x041868fecd41a,
                0x3105e8c923bc6, 0x3058ad43d1838 },
            { 0x462f587e593fb, 0x3d94ba7ce362d, 0x330f9b52667b7,
                0x5d45a48e0f00a, 0x08f5114789a8d },
            { 0x40ffde57663d0, 0x71445d4c20647, 0x2653e68170f7c,
                0x64cdee3c55ed6, 0x26549fa4efe3d },
        },
    },
    {
        {
            { 0x68549af3f666e, 0x09e2941d4bb68, 0x2e8311f5dff3c,
                0x6429ef91ffbd2, 0x3a10dfe132ce3 },
            { 0x55a461e6bf9d6, 0x78eeef4b02e83, 0x1d34f648c16cf,
                0x07fea2aba5132, 0x1926e1dc6401e },
            { 0x74e8aea17cea0, 0x0c743f83fbc0f, 0x7cb03c4bf5455,
                0x68a8ba9917e98, 0x1fa1d01d861e5 },
        },
        {
            { 0x4ac00d1df94ab, 0x3ba2101bd271b, 0x7578988b9c4af,
                0x0f2bf89f49f7e, 0x73fced18ee9a0 },
            { 0x055947d599832, 0x346fe2aa41990, 0x0164c8079195b,
                0x799ccfb7bba27, 0x773563bc6a75c },
            { 0x1e90863139cb3, 0x4f8b407d9a0d6, 0x58e24ca924f69,
                0x7a246bbe76456, 0x1f426b701b864 },
        },
        {
            { 0x635c891a12552, 0x26aebd38ede2f, 0x66dc8faddae05,
                0x21c7d41a03786, 0x0b76bb1b3fa7e },
            { 0x1264c41911c01, 0x702f44584bdf9, 0x43c511fc68ede,
                0x0482c3aed35f9, 0x4e1af5271d31b },
            { 0x0c1f97f92939b, 0x17a88956dc117, 0x6ee005ef99dc7,
                0x4aa9172b231cc, 0x7b6dd61eb772a },
        },
        {
            { 0x0abf9ab01d2c7, 0x3880287630ae6, 0x32eca045beddb,
                0x57f43365f32d0, 0x53fa9b659bff6 },
            { 0x5c1e850f33d92, 0x1ec119ab9f6f5, 0x7f16f6de663e9,
                0x7a7d6cb16dec6, 0x703e9bceaf1d2 },
            { 0x4c8e994885455, 0x4ccb5da9cad82, 0x3596bc610e975,
                0x7a80c0ddb9f5e, 0x398d93e5c4c61 },
        },
        {
            { 0x77c60d2e7e3f2, 0x4061051763870, 0x67bc4e0ecd2aa,
                0x2bb941f1373b9, 0x699c9c9002c30 },
            { 0x3d16733e248f3, 0x0e2b7e14be389, 0x42c0ddaf6784a,
                0x589ea1fc67850, 0x53b09b5ddf191 },
            { 0x6a7235946f1cc, 0x6b99cbb2fbe60, 0x6d3a5d6485c62,
                0x4839466e923c0, 0x51caf30c6fcdd },
        },
        {
            { 0x2f99a18ac54c7, 0x398a39661ee6f, 0x384331e40cde3,
                0x4cd15c4de19a6, 0x12ae29c189f8e },
            { 0x3a7427674e00a, 0x6142f4f7e74c1, 0x4cc93318c3a15,
                0x6d51bac2b1ee7, 0x5504aa292383f },
            { 0x6c0cb1f0d01cf, 0x187469ef5d533, 0x27138883747bf,
                0x2f52ae53a90e8, 0x5fd14fe958eba },
        },
        {
            { 0x2fe5ebf93cb8e, 0x226da8acbe788, 0x10883a2fb7ea1,
                0x094707842cf44, 0x7dd73f960725d },
            { 0x42ddf2845ab2c, 0x6214ffd3276bb, 0x00b8d181a5246,
                0x268a6d579eb20, 0x093ff26e58647 },
            { 0x524fe68059829, 0x65b75e47cb621, 0x15eb0a5d5cc19,
                0x05209b3929d5a, 0x2f59bcbc86b47 },
        },
        {
            { 0x1d560b691c301, 0x7f5bafce3ce08, 0x4cd561614806c,
                0x4588b6170b188, 0x2aa55e3d01082 },
            { 0x47d429917135f, 0x3eacfa07af070, 0x1deab46b46e44,
                0x7a53f3ba46cdf, 0x5458b42e2e51a },
            { 0x192e60c07444f, 0x5ae8843a21daa, 0x6d721910b1538,
                0x3321a95a6417e, 0x13e9004a8a768 },
        },
    },
    {
        {
            { 0x600c9193b877f, 0x21c1b8a0d7765, 0x379927fb38ea2,
                0x70d7679dbe01b, 0x5f46040898de9 },
            { 0x58845832fcedb, 0x135cd7f0c6e73, 0x53ffbdfe8e35b,
                0x22f195e06e55b, 0x73937e8814bce },
            { 0x37116297bf48d, 0x45a9e0d069720, 0x25af71aa744ec,
                0x41af0cb8aaba3, 0x2cf8a4e891d5e },
        },
        {
            { 0x5487e17d06ba2, 0x3872a032d6596, 0x65e28c09348e0,
                0x27b6bb2ce40c2, 0x7a6f7f2891d6a },
            { 0x3fd8707110f67, 0x26f8716a92db2, 0x1cdaa1b753027,
                0x504be58b52661, 0x2049bd6e58252 },
            { 0x1fd8d6a9aef49, 0x7cb67b7216fa1, 0x67aff53c3b982,
                0x20ea610da9628, 0x6011aadfc5459 },
        },
        {
            { 0x6d0c802cbf890, 0x141bfed554c7b, 0x6dbb667ef4263,
                0x58f3126857edc, 0x69ce18b779340 },
            { 0x7926dcf95f83c, 0x42e25120e2bec, 0x63de96df1fa15,
                0x4f06b50f3f9cc, 0x6fc5cc1b0b62f },
            { 0x75528b29879cb, 0x79a8fd2125a3d, 0x27c8d4b746ab8,
                0x0f8893f02210c, 0x15596b3ae5710 },
        },
        {
            { 0x731167e5124ca, 0x17b38e8bbe13f, 0x3d55b942f9056,
                0x09c1495be913f, 0x3aa4e241afb6d },
            { 0x739d23f9179a2, 0x632fadbb9e8c4, 0x7c8522bfe0c48,
                0x6ed0983ef5aa9, 0x0d2237687b5f4 },
            { 0x138bf2a3305f5, 0x1f45d24d86598, 0x5274bad2160fe,
                0x1b6041d58d12a, 0x32fcaa6e4687a },
        },
        {
            { 0x7a4732787ccdf, 0x11e427c7f0640, 0x03659385f8c64,
                0x5f4ead9766bfb, 0x746f6336c2600 },
            { 0x56e8dc57d9af5, 0x5b3be17be4f78, 0x3bf928cf82f4b,
                0x52e55600a6f11, 0x4627e9cefebd6 },
            { 0x2f345ab6c971c, 0x653286e63e7e9, 0x51061b78a23ad,
                0x14999acb54501, 0x7b4917007ed66 },
        },
        {
            { 0x41b28dd53a2dd, 0x37be85f87ea86, 0x74be3d2a85e41,
                0x1be87fac96ca6, 0x1d03620fe08cd },
            { 0x5fb5cab84b064, 0x2513e778285b0, 0x457383125e043,
                0x6bda3b56e223d, 0x122ba376f844f },
            { 0x232cda2b4e554, 0x0422ba30ff840, 0x751e7667b43f5,
                0x6261755da5f3e, 0x02c70bf52b68e },
        },
        {
            { 0x532bf458d72e1, 0x40f96e796b59c, 0x22ef79d6f9da3,
                0x501ab67beca77, 0x6b0697e3feb43 },
            { 0x7ec4b5d0b2fbb, 0x200e910595450, 0x742057105715e,
                0x2f07022530f60, 0x26334f0a409ef },
            { 0x0f04adf62a3c0, 0x5e0edb48bb6d9, 0x7c34aa4fbc003,
                0x7d74e4e5cac24, 0x1cc37f43441b2 },
        },
        {
            { 0x656f1c9ceaeb9, 0x7031cacad5aec, 0x1308cd0716c57,
                0x41c1373941942, 0x3a346f772f196 },
            { 0x7565a5cc7324f, 0x01ca0d5244a11, 0x116b067418713,
                0x0a57d8c55edae, 0x6c6809c103803 },
            { 0x55112e2da6ac8, 0x6363d0a3dba5a, 0x319c98ba6f40c,
                0x2e84b03a36ec7, 0x05911b9f6ef7c },
        },
    },
    {
        {
            { 0x1acf3512eeaef, 0x2639839692a69, 0x669a234830507,
                0x68b920c0603d4, 0x555ef9d1c64b2 },
            { 0x39983f5df0ebb, 0x1ea2589959826, 0x6ce638703cdd6,
                0x6311678898505, 0x6b3cecf9aa270 },
            { 0x770ba3b73bd08, 0x11475f7e186d4, 0x0251bc9892bbc,
                0x24eab9bffcc5a, 0x675f4de133817 },
        },
        {
            { 0x7f6d93bdab31d, 0x1f3aca5bfd425, 0x2fa521c1c9760,
                0x62180ce27f9cd, 0x60f450b882cd3 },
            { 0x452036b1782fc, 0x02d95b07681c5, 0x5901cf99205b2,
                0x290686e5eecb4, 0x13d99df70164c },
            { 0x35ec321e5c0ca, 0x13ae337f44029, 0x4008e813f2da7,
                0x640272f8e0c3a, 0x1c06de9e55eda },
        },
        {
            { 0x52b40ff6d69aa, 0x31b8809377ffa, 0x536625cd14c2c,
                0x516af252e17d1, 0x78096f8e7d32b },
            { 0x77ad6a33ec4e2, 0x717c5dc11d321, 0x4a114559823e4,
                0x306ce50a1e2b1, 0x4cf38a1fec2db },
            { 0x2aa650dfa5ce7, 0x54916a8f19415, 0x00dc96fe71278,
                0x55f2784e63eb8, 0x373cad3a26091 },
        },
        {
            { 0x6a8fb89ddbbad, 0x78c35d5d97e37, 0x66e3674ef2cb2,
                0x34347ac53dd8f, 0x21547eda5112a },
            { 0x4634d82c9f57c, 0x4249268a6d652, 0x6336d687f2ff7,
                0x4fe4f4e26d9a0, 0x0040f3d945441 },
            { 0x5e939fd5986d3, 0x12a2147019bdf, 0x4c466e7d09cb2,
                0x6fa5b95d203dd, 0x63550a334a254 },
        },
        {
            { 0x2584572547b49, 0x75c58811c1377, 0x4d3c637cc171b,
                0x33d30747d34e3, 0x39a92bafaa7d7 },
            { 0x7d6edb569cf37, 0x60194a5dc2ca0, 0x5af59745e10a6,
                0x7a8f53e004875, 0x3eea62c7daf78 },
            { 0x4c713e693274e, 0x6ed1b7a6eb3a4, 0x62ace697d8e15,
                0x266b8292ab075, 0x68436a0665c9c },
        },
        {
            { 0x6d317e820107c, 0x090815d2ca3ca, 0x03ff1eb1499a1,
                0x23960f050e319, 0x5373669c91611 },
            { 0x235e8202f3f27, 0x44c9f2eb61780, 0x630905b1d7003,
                0x4fcc8d274ead1, 0x17b6e7f68ab78 },
            { 0x014ab9a0e5257, 0x09939567f8ba5, 0x4b47b2a423c82,
                0x688d7e57ac42d, 0x1cb4b5a678f87 },
        },
        {
            { 0x4aa62a2a007e7, 0x61e0e38f62d6e, 0x02f888fcc4782,
                0x7562b83f21c00, 0x2dc0fd2d82ef6 },
            { 0x4c06b394afc6c, 0x4931b4bf636cc, 0x72b60d0322378,
                0x25127c6818b25, 0x330bca78de743 },
            { 0x6ff841119744e, 0x2c560e8e49305, 0x7254fefe5a57a,
                0x67ae2c560a7df, 0x3c31be1b369f1 },
        },
        {
            { 0x0bc93f9cb4272, 0x3f8f9db73182d, 0x2b235eabae1c4,
                0x2ddbf8729551a, 0x41cec1097e7d5 },
            { 0x4864d08948aee, 0x5d237438df61e, 0x2b285601f7067,
                0x25dbcbae6d753, 0x330b61134262d },
            { 0x619d7a26d808a, 0x3c3b3c2adbef2, 0x6877c9eec7f52,
                0x3beb9ebe1b66d, 0x26b44cd91f287 },
        },
    },
    {
        {
            { 0x7f29362730383, 0x7fd7951459c36, 0x7504c512d49e7,
                0x087ed7e3bc55f, 0x7deb10149c726 },
            { 0x048478f387475, 0x69397d9678a3e, 0x67c8156c976f3,
                0x2eb4d5589226c, 0x2c709e6c1c10a },
            { 0x2af6a8766ee7a, 0x08aaa79a1d96c, 0x42f92d59b2fb0,
                0x1752c40009c07, 0x08e68e9ff62ce },
        },
        {
            { 0x509d50ab8f2f9, 0x1b8ab247be5e5, 0x5d9b2e6b2e486,
                0x4faa5479a1339, 0x4cb13bd738f71 },
            { 0x5500a4bc130ad, 0x127a17a938695, 0x02a26fa34e36d,
                0x584d12e1ecc28, 0x2f1f3f87eeba3 },
            { 0x48c75e515b64a, 0x75b6952071ef0, 0x5d46d42965406,
                0x7746106989f9f, 0x19a1e353c0ae2 },
        },
        {
            { 0x172cdd596bdbd, 0x0731ddf881684, 0x10426d64f8115,
                0x71a4fd8a9a3da, 0x736bd3990266a },
            { 0x47560bafa05c3, 0x418dcabcc2fa3, 0x35991cecf8682,
                0x24371a94b8c60, 0x41546b11c20c3 },
            { 0x32d509334b3b4, 0x16c102cae70aa, 0x1720dd51bf445,
                0x5ae662faf9821, 0x412295a2b87fa },
        },
        {
            { 0x55261e293eac6, 0x06426759b65cc, 0x40265ae116a48,
                0x6c02304bae5bc, 0x0760bb8d195ad },
            { 0x19b88f57ed6e9, 0x4cdbf1904a339, 0x42b49cd4e4f2c,
                0x71a2e771909d9, 0x14e153ebb52d2 },
            { 0x61a17cde6818a, 0x53dad34108827, 0x32b32c55c55b6,
                0x2f9165f9347a3, 0x6b34be9bc33ac },
        },
        {
            { 0x469656571f2d3, 0x0aa61ce6f423f, 0x3f940d71b27a1,
                0x185f19d73d16a, 0x01b9c7b62e6dd },
            { 0x72f643a78c0b2, 0x3de45c04f9e7b, 0x706d68d30fa5c,
                0x696f63e8e2f24, 0x2012c18f0922d },
            { 0x355e55ac89d29, 0x3e8b414ec7101, 0x39db07c520c90,
                0x6f41e9b77efe1, 0x08af5b784e4ba },
        },
        {
            { 0x314d289cc2c4b, 0x23450e2f1bc4e, 0x0cd93392f92f4,
                0x1370c6a946b7d, 0x6423c1d5afd98 },
            { 0x499dc881f2533, 0x34ef26476c506, 0x4d107d2741497,
                0x346c4bd6efdb3, 0x32b79d71163a1 },
            { 0x5f8d9edfcb36a, 0x1e6e8dcbf3990, 0x7974f348af30a,
                0x6e6724ef19c7c, 0x480a5efbc13e2 },
        },
        {
            { 0x14ce442ce221f, 0x18980a72516cc, 0x072f80db86677,
                0x703331fda526e, 0x24b31d47691c8 },
            { 0x1e70b01622071, 0x1f163b5f8a16a, 0x56aaf341ad417,
                0x7989635d830f7, 0x47aa27600cb7b },
            { 0x41eedc015f8c3, 0x7cf8d27ef854a, 0x289e3584693f9,
                0x04a7857b309a7, 0x545b585d14dda },
        },
        {
            { 0x4e4d0e3b321e1, 0x7451fe3d2ac40, 0x666f678eea98d,
                0x038858667fead, 0x4d22dc3e64c8d },
            { 0x7275ea0d43a0f, 0x681137dd7ccf7, 0x1e79cbab79a38,
                0x22a214489a66a, 0x0f62f9c332ba5 },
            { 0x46589d63b5f39, 0x7eaf979ec3f96, 0x4ebe81572b9a8,
                0x21b7f5d61694a, 0x1c0fa01a36371 },
        },
    },
    {
        {
            { 0x02b0e8c936a50, 0x6b83b58b6cd21, 0x37ed8d3e72680,
                0x0a037db9f2a62, 0x4005419b1d2bc },
            { 0x604b622943dff, 0x1c899f6741a58, 0x60219e2f232fb,
                0x35fae92a7f9cb, 0x0fa3614f3b1ca },
            { 0x3febdb9be82f0, 0x5e74895921400, 0x553ea38822706,
                0x5a17c24cfc88c, 0x1fba218aef40a },
        },
        {
            { 0x657043e7b0194, 0x5c11b55efe9e7, 0x7737bc6a074fb,
                0x0eae41ce355cc, 0x6c535d13ff776 },
            { 0x49448fac8f53e, 0x34f74c6e8356a, 0x0ad780607dba2,
                0x7213a7eb63eb6, 0x392e3acaa8c86 },
            { 0x534e93e8a35af, 0x08b10fd02c997, 0x26ac2acb81e05,
                0x09d8c98ce3b79, 0x25e17fe4d50ac },
        },
        {
            { 0x77ff576f121a7, 0x4e5f9b0fc722b, 0x46f949b0d28c8,
                0x4cde65d17ef26, 0x6bba828f89698 },
            { 0x09bd71e04f676, 0x25ac841f2a145, 0x1a47eac823871,
                0x1a8a8c36c581a, 0x255751442a9fb },
            { 0x1bc6690fe3901, 0x314132f5abc5a, 0x611835132d528,
                0x5f24b8eb48a57, 0x559d504f7f6b7 },
        },
        {
            { 0x091e7f6d266fd, 0x36060ef037389, 0x18788ec1d1286,
                0x287441c478eb0, 0x123ea6a3354bd },
            { 0x38378b3eb54d5, 0x4d4aaa78f94ee, 0x4a002e875a74d,
                0x10b851367b17c, 0x01ab12d5807e3 },
            { 0x5189041e32d96, 0x05b062b090231, 0x0c91766e7b78f,
                0x0aa0f55a138ec, 0x4a3961e2c918a },
        },
        {
            { 0x7d644f3233f1e, 0x1c69f9e02c064, 0x36ae5e5266898,
                0x08fc1dad38b79, 0x68aceead9bd41 },
            { 0x43be0f8e6bba0, 0x68fdffc614e3b, 0x4e91dab5b3be0,
                0x3b1d4c9212ff0, 0x2cd6bce3fb1db },
            { 0x4c90ef3d7c210, 0x496f5a0818716, 0x79cf88cc239b8,
                0x2cb9c306cf8db, 0x595760d5b508f },
        },
        {
            { 0x2cbebfd022790, 0x0b8822aec1105, 0x4d1cfd226bccc,
                0x515b2fa4971be, 0x2cb2c5df54515 },
            { 0x1bfe104aa6397, 0x11494ff996c25, 0x64251623e5800,
                0x0d49fc5e044be, 0x709fa43edcb29 },
            { 0x25d8c63fd2aca, 0x4c5cd29dffd61, 0x32ec0eb48af05,
                0x18f9391f9b77c, 0x70f029ecf0c81 },
        },
        {
            { 0x2afaa5e10b0b9, 0x61de08355254d, 0x0eb587de3c28d,
                0x4f0bb9f7dbbd5, 0x44eca5a2a74bd },
            { 0x307b32eed3e33, 0x6748ab03ce8c2, 0x57c0d9ab810bc,
                0x42c64a224e98c, 0x0b7d5d8a6c314 },
            { 0x448327b95d543, 0x0146681e3a4ba, 0x38714adc34e0c,
                0x4f26f0e298e30, 0x272224512c7de },
        },
        {
            { 0x3bb8a42a975fc, 0x6f2d5b46b17ef, 0x7b6a9223170e5,
                0x053713fe3b7e6, 0x19735fd7f6bc2 },
            { 0x492af49c5342e, 0x2365cdf5a0357, 0x32138a7ffbb60,
                0x2a1f7d14646fe, 0x11b5df18a44cc },
            { 0x390d042c84266, 0x1efe32a8fdc75, 0x6925ee7ae1238,
                0x4af9281d0e832, 0x0fef911191df8 },
        },
    },
};
#else
/* k25519Precomp[i][j] = (j+1)*256^i*B */
static const ge_precomp k25519Precomp[32][8] = {
    {
        {
            { 25967493, -14356035, 29566456, 3660896, -12694345, 4014787,
                27544626, -11754271, -6079156, 2047605 },
            { -12545711, 934262, -2722910, 3049990, -727428, 9406986, 12720692,
                5043384, 19500929, -15469378 },
            { -8738181, 4489570, 9688441, -14785194, 10184609, -12363380,
                29287919, 11864899, -24514362, -4438546 },
        },
        {
            { -12815894, -12976347, -21581243, 11784320, -25355658, -2750717,
                -11717903, -3814571, -358445, -10211303 },
            { -21703237, 6903825, 27185491, 6451973, -29577724, -9554005,
                -15616551, 11189268, -26829678, -5319081 },
            { 26966642, 11152617, 32442495, 15396054, 14353839, -12752335,
                -3128826, -9541118, -15472047, -4166697 },
        },
        {
            { 15636291, -9688557, 24204773, -7912398, 616977, -16685262,
                27787600, -14772189, 28944400, -1550024 },
            { 16568933, 4717097, -11556148, -1102322, 15682896, -11807043,
                16354577, -11775962, 7689662, 11199574 },
            { 30464156, -5976125, -11779434, -15670865, 23220365, 15915852,
                7512774, 10017326, -17749093, -9920357 },
        },
        {
            { -17036878, 13921892, 10945806, -6033431, 27105052, -16084379,
                -28926210, 15006023, 3284568, -6276540 },
            { 23599295, -8306047, -11193664, -7687416, 13236774, 10506355,
                7464579, 9656445, 13059162, 10374397 },
            { 7798556, 16710257, 3033922, 2874086, 28997861, 2835604, 32406664,
                -3839045, -641708, -101325 },
        },
        {
            { 10861363, 11473154, 27284546, 1981175, -30064349, 12577861,
                32867885, 14515107, -15438304, 10819380 },
            { 4708026, 6336745, 20377586, 9066809, -11272109, 6594696, -25653668,
                12483688, -12668491, 5581306 },
            { 19563160, 16186464, -29386857, 4097519, 10237984, -4348115,
                28542350, 13850243, -23678021, -15815942 },
        },
        {
            { -15371964, -12862754, 32573250, 4720197, -26436522, 5875511,
                -19188627, -15224819, -9818940, -12085777 },
            { -8549212, 109983, 15149363, 2178705, 22900618, 4543417, 3044240,
                -15689887, 1762328, 14866737 },
            { -18199695, -15951423, -10473290, 1707278, -17185920, 3916101,
                -28236412, 3959421, 27914454, 4383652 },
        },
        {
            { 5153746, 9909285, 1723747, -2777874, 30523605, 5516873, 19480852,
                5230134, -23952439, -15175766 },
            { -30269007, -3463509, 7665486, 10083793, 28475525, 1649722,
                20654025, 16520125, 30598449, 7715701 },
            { 28881845, 14381568, 9657904, 3680757, -20181635, 7843316,
                -31400660, 1370708, 29794553, -1409300 },
        },
        {
            { 14499471, -2729599, -33191113, -4254652, 28494862, 14271267,
                30290735, 10876454, -33154098, 2381726 },
            { -7195431, -2655363, -14730155, 462251, -27724326, 3941372,
                -6236617, 3696005, -32300832, 15351955 },
            { 27431194, 8222322, 16448760, -3907995, -18707002, 11938355,
                -32961401, -2970515, 29551813, 10109425 },
        },
    },
    {
        {
            { -13657040, -13155431, -31283750, 11777098, 21447386, 6519384,
                -2378284, -1627556, 10092783, -4764171 },
            { 27939166, 14210322, 4677035, 16277044, -22964462, -12398139,
                -32508754, 12005538, -17810127, 12803510 },
            { 17228999, -15661624, -1233527, 300140, -1224870, -11714777,
                30364213, -9038194, 18016357, 4397660 },
        },
        {
            { -10958843, -7690207, 4776341, -14954238, 27850028, -15602212,
                -26619106, 14544525, -17477504, 982639 },
            { 29253598, 15796703, -2863982, -9908884, 10057023, 3163536, 7332899,
                -4120128, -21047696, 9934963 },
            { 5793303, 16271923, -24131614, -10116404, 29188560, 1206517,
                -14747930, 4559895, -30123922, -10897950 },
        },
        {
            { -27643952, -11493006, 16282657, -11036493, 28414021, -15012264,
                24191034, 4541697, -13338309, 5500568 },
            { 12650548, -1497113, 9052871, 11355358, -17680037, -8400164,
                -17430592, 12264343, 10874051, 13524335 },
            { 25556948, -3045990, 714651, 2510400, 23394682, -10415330, 33119038,
                5080568, -22528059, 5376628 },
        },
        {
            { -26088264, -4011052, -17013699, -3537628, -6726793, 1920897,
                -22321305, -9447443, 4535768, 1569007 },
            { -2255422, 14606630, -21692440, -8039818, 28430649, 8775819,
                -30494562, 3044290, 31848280, 12543772 },
            { -22028579, 2943893, -31857513, 6777306, 13784462, -4292203,
                -27377195, -2062731, 7718482, 14474653 },
        },
        {
            { 2385315, 2454213, -22631320, 46603, -4437935, -15680415, 656965,
                -7236665, 24316168, -5253567 },
            { 13741529, 10911568, -33233417, -8603737, -20177830, -1033297,
                33040651, -13424532, -20729456, 8321686 },
            { 21060490, -2212744, 15712757, -4336099, 1639040, 10656336,
                23845965, -11874838, -9984458, 608372 },
        },
        {
            { -13672732, -15087586, -10889693, -7557059, -6036909, 11305547,
                1123968, -6780577, 27229399, 23887 },
            { -23244140, -294205, -11744728, 14712571, -29465699, -2029617,
                12797024, -6440308, -1633405, 16678954 },
            { -29500620, 4770662, -16054387, 14001338, 7830047, 9564805,
                -1508144, -4795045, -17169265, 4904953 },
        },
        {
            { 24059557, 14617003, 19037157, -15039908, 19766093, -14906429,
                5169211, 16191880, 2128236, -4326833 },
            { -16981152, 4124966, -8540610, -10653797, 30336522, -14105247,
                -29806336, 916033, -6882542, -2986532 },
            { -22630907, 12419372, -7134229, -7473371, -16478904, 16739175,
                285431, 2763829, 15736322, 4143876 },
        },
        {
            { 2379352, 11839345, -4110402, -5988665, 11274298, 794957, 212801,
                -14594663, 23527084, -16458268 },
            { 33431127, -11130478, -17838966, -15626900, 8909499, 8376530,
                -32625340, 4087881, -15188911, -14416214 },
            { 1767683, 7197987, -13205226, -2022635, -13091350, 448826, 5799055,
                4357868, -4774191, -16323038 },
        },
    },
    {
        {
            { 6721966, 13833823, -23523388, -1551314, 26354293, -11863321,
                23365147, -3949732, 7390890, 2759800 },
            { 4409041, 2052381, 23373853, 10530217, 7676779, -12885954, 21302353,
                -4264057, 1244380, -12919645 },
            { -4421239, 7169619, 4982368, -2957590, 30256825, -2777540, 14086413,
                9208236, 15886429, 16489664 },
        },
        {
            { 1996075, 10375649, 14346367, 13311202, -6874135, -16438411,
                -13693198, 398369, -30606455, -712933 },
            { -25307465, 9795880, -2777414, 14878809, -33531835, 14780363,
                13348553, 12076947, -30836462, 5113182 },
            { -17770784, 11797796, 31950843, 13929123, -25888302, 12288344,
                -30341101, -7336386, 13847711, 5387222 },
        },
        {
            { -18582163, -3416217, 17824843, -2340966, 22744343, -10442611,
                8763061, 3617786, -19600662, 10370991 },
            { 20246567, -14369378, 22358229, -543712, 18507283, -10413996,
                14554437, -8746092, 32232924, 16763880 },
            { 9648505, 10094563, 26416693, 14745928, -30374318, -6472621,
                11094161, 15689506, 3140038, -16510092 },
        },
        {
            { -16160072, 5472695, 31895588, 4744994, 8823515, 10365685,
                -27224800, 9448613, -28774454, 366295 },
            { 19153450, 11523972, -11096490, -6503142, -24647631, 5420647,
                28344573, 8041113, 719605, 11671788 },
            { 8678025, 2694440, -6808014, 2517372, 4964326, 11152271, -15432916,
                -15266516, 27000813, -10195553 },
        },
        {
            { -15157904, 7134312, 8639287, -2814877, -7235688, 10421742, 564065,
                5336097, 6750977, -14521026 },
            { 11836410, -3979488, 26297894, 16080799, 23455045, 15735944,
                1695823, -8819122, 8169720, 16220347 },
            { -18115838, 8653647, 17578566, -6092619, -8025777, -16012763,
                -11144307, -2627664, -5990708, -14166033 },
        },
        {
            { -23308498, -10968312, 15213228, -10081214, -30853605, -11050004,
                27884329, 2847284, 2655861, 1738395 },
            { -27537433, -14253021, -25336301, -8002780, -9370762, 8129821,
                21651608, -3239336, -19087449, -11005278 },
            { 1533110, 3437855, 23735889, 459276, 29970501, 11335377, 26030092,
                5821408, 10478196, 8544890 },
        },
        {
            { 32173121, -16129311, 24896207, 3921497, 22579056, -3410854,
                19270449, 12217473, 17789017, -3395995 },
            { -30552961, -2228401, -15578829, -10147201, 13243889, 517024,
                15479401, -3853233, 30460520, 1052596 },
            { -11614875, 13323618, 32618793, 8175907, -15230173, 12596687,
                27491595, -4612359, 3179268, -9478891 },
        },
        {
            { 31947069, -14366651, -4640583, -15339921, -15125977, -6039709,
                -14756777, -16411740, 19072640, -9511060 },
            { 11685058, 11822410, 3158003, -13952594, 33402194, -4165066,
                5977896, -5215017, 473099, 5040608 },
            { -20290863, 8198642, -27410132, 11602123, 1290375, -2799760,
                28326862, 1721092, -19558642, -3131606 },
        },
    },
    {
        {
            { 7881532, 10687937, 7578723, 7738378, -18951012, -2553952, 21820786,
                8076149, -27868496, 11538389 },
            { -19935666, 3899861, 18283497, -6801568, -15728660, -11249211,
                8754525, 7446702, -5676054, 5797016 },
            { -11295600, -3793569, -15782110, -7964573, 12708869, -8456199,
                2014099, -9050574, -2369172, -5877341 },
        },
        {
            { -22472376, -11568741, -27682020, 1146375, 18956691, 16640559,
                1192730, -3714199, 15123619, 10811505 },
            { 14352098, -3419715, -18942044, 10822655, 32750596, 4699007, -70363,
                15776356, -28886779, -11974553 },
            { -28241164, -8072475, -4978962, -5315317, 29416931, 1847569,
                -20654173, -16484855, 4714547, -9600655 },
        },
        {
            { 15200332, 8368572, 19679101, 15970074, -31872674, 1959451,
                24611599, -4543832, -11745876, 12340220 },
            { 12876937, -10480056, 33134381, 6590940, -6307776, 14872440,
                9613953, 8241152, 15370987, 9608631 },
            { -4143277, -12014408, 8446281, -391603, 4407738, 13629032, -7724868,
                15866074, -28210621, -8814099 },
        },
        {
            { 26660628, -15677655, 8393734, 358047, -7401291, 992988, -23904233,
                858697, 20571223, 8420556 },
            { 14620715, 13067227, -15447274, 8264467, 14106269, 15080814,
                33531827, 12516406, -21574435, -12476749 },
            { 236881, 10476226, 57258, -14677024, 6472998, 2466984, 17258519,
                7256740, 8791136, 15069930 },
        },
        {
            { 1276410, -9371918, 22949635, -16322807, -23493039, -5702186,
                14711875, 4874229, -30663140, -2331391 },
            { 5855666, 4990204, -13711848, 7294284, -7804282, 1924647, -1423175,
                -7912378, -33069337, 9234253 },
            { 20590503, -9018988, 31529744, -7352666, -2706834, 10650548,
                31559055, -11609587, 18979186, 13396066 },
        },
        {
            { 24474287, 4968103, 22267082, 4407354, 24063882, -8325180,
                -18816887, 13594782, 33514650, 7021958 },
            { -11566906, -6565505, -21365085, 15928892, -26158305, 4315421,
                -25948728, -3916677, -21480480, 12868082 },
            { -28635013, 13504661, 19988037, -2132761, 21078225, 6443208,
                -21446107, 2244500, -12455797, -8089383 },
        },
        {
            { -30595528, 13793479, -5852820, 319136, -25723172, -6263899,
                33086546, 8957937, -15233648, 5540521 },
            { -11630176, -11503902, -8119500, -7643073, 2620056, 1022908,
                -23710744, -1568984, -16128528, -14962807 },
            { 23152971, 775386, 27395463, 14006635, -9701118, 4649512, 1689819,
                892185, -11513277, -15205948 },
        },
        {
            { 9770129, 9586738, 26496094, 4324120, 1556511, -3550024, 27453819,
                4763127, -19179614, 5867134 },
            { -32765025, 1927590, 31726409, -4753295, 23962434, -16019500,
                27846559, 5931263, -29749703, -16108455 },
            { 27461885, -2977536, 22380810, 1815854, -23033753, -3031938,
                7283490, -15148073, -19526700, 7734629 },
        },
    },
    {
        {
            { -8010264, -9590817, -11120403, 6196038, 29344158, -13430885,
                7585295, -3176626, 18549497, 15302069 },
            { -32658337, -6171222, -7672793, -11051681, 6258878, 13504381,
                10458790, -6418461, -8872242, 8424746 },
            { 24687205, 8613276, -30667046, -3233545, 1863892, -1830544,
                19206234, 7134917, -11284482, -828919 },
        },
        {
            { 11334899, -9218022, 8025293, 12707519, 17523892, -10476071,
                10243738, -14685461, -5066034, 16498837 },
            { 8911542, 6887158, -9584260, -6958590, 11145641, -9543680, 17303925,
                -14124238, 6536641, 10543906 },
            { -28946384, 15479763, -17466835, 568876, -1497683, 11223454,
                -2669190, -16625574, -27235709, 8876771 },
        },
        {
            { -25742899, -12566864, -15649966, -846607, -33026686, -796288,
                -33481822, 15824474, -604426, -9039817 },
            { 10330056, 70051, 7957388, -9002667, 9764902, 15609756, 27698697,
                -4890037, 1657394, 3084098 },
            { 10477963, -7470260, 12119566, -13250805, 29016247, -5365589,
                31280319, 14396151, -30233575, 15272409 },
        },
        {
            { -12288309, 3169463, 28813183, 16658753, 25116432, -5630466,
                -25173957, -12636138, -25014757, 1950504 },
            { -26180358, 9489187, 11053416, -14746161, -31053720, 5825630,
                -8384306, -8767532, 15341279, 8373727 },
            { 28685821, 7759505, -14378516, -12002860, -31971820, 4079242,
                298136, -10232602, -2878207, 15190420 },
        },
        {
            { -32932876, 13806336, -14337485, -15794431, -24004620, 10940928,
                8669718, 2742393, -26033313, -6875003 },
            { -1580388, -11729417, -25979658, -11445023, -17411874, -10912854,
                9291594, -16247779, -12154742, 6048605 },
            { -30305315, 14843444, 1539301, 11864366, 20201677, 1900163,
                13934231, 5128323, 11213262, 9168384 },
        },
        {
            { -26280513, 11007847, 19408960, -940758, -18592965, -4328580,
                -5088060, -11105150, 20470157, -16398701 },
            { -23136053, 9282192, 14855179, -15390078, -7362815, -14408560,
                -22783952, 14461608, 14042978, 5230683 },
            { 29969567, -2741594, -16711867, -8552442, 9175486, -2468974,
                21556951, 3506042, -5933891, -12449708 },
        },
        {
            { -3144746, 8744661, 19704003, 4581278, -20430686, 6830683,
                -21284170, 8971513, -28539189, 15326563 },
            { -19464629, 10110288, -17262528, -3503892, -23500387, 1355669,
                -15523050, 15300988, -20514118, 9168260 },
            { -5353335, 4488613, -23803248, 16314347, 7780487, -15638939,
                -28948358, 9601605, 33087103, -9011387 },
        },
        {
            { -19443170, -15512900, -20797467, -12445323, -29824447, 10229461,
                -27444329, -15000531, -5996870, 15664672 },
            { 23294591, -16632613, -22650781, -8470978, 27844204, 11461195,
                13099750, -2460356, 18151676, 13417686 },
            { -24722913, -4176517, -31150679, 5988919, -26858785, 6685065,
                1661597, -12551441, 15271676, -15452665 },
        },
    },
    {
        {
            { 11433042, -13228665, 8239631, -5279517, -1985436, -725718,
                -18698764, 2167544, -6921301, -13440182 },
            { -31436171, 15575146, 30436815, 12192228, -22463353, 9395379,
                -9917708, -8638997, 12215110, 12028277 },
            { 14098400, 6555944, 23007258, 5757252, -15427832, -12950502,
                30123440, 4617780, -16900089, -655628 },
        },
        {
            { -4026201, -15240835, 11893168, 13718664, -14809462, 1847385,
                -15819999, 10154009, 23973261, -12684474 },
            { -26531820, -3695990, -1908898, 2534301, -31870557, -16550355,
                18341390, -11419951, 32013174, -10103539 },
            { -25479301, 10876443, -11771086, -14625140, -12369567, 1838104,
                21911214, 6354752, 4425632, -837822 },
        },
        {
            { -10433389, -14612966, 22229858, -3091047, -13191166, 776729,
                -17415375, -12020462, 4725005, 14044970 },
            { 19268650, -7304421, 1555349, 8692754, -21474059, -9910664, 6347390,
                -1411784, -19522291, -16109756 },
            { -24864089, 12986008, -10898878, -5558584, -11312371, -148526,
                19541418, 8180106, 9282262, 10282508 },
        },
        {
            { -26205082, 4428547, -8661196, -13194263, 4098402, -14165257,
                15522535, 8372215, 5542595, -10702683 },
            { -10562541, 14895633, 26814552, -16673850, -17480754, -2489360,
                -2781891, 6993761, -18093885, 10114655 },
            { -20107055, -929418, 31422704, 10427861, -7110749, 6150669,
                -29091755, -11529146, 25953725, -106158 },
        },
        {
            { -4234397, -8039292, -9119125, 3046000, 2101609, -12607294,
                19390020, 6094296, -3315279, 12831125 },
            { -15998678, 7578152, 5310217, 14408357, -33548620, -224739,
                31575954, 6326196, 7381791, -2421839 },
            { -20902779, 3296811, 24736065, -16328389, 18374254, 7318640,
                6295303, 8082724, -15362489, 12339664 },
        },
        {
            { 27724736, 2291157, 6088201, -14184798, 1792727, 5857634, 13848414,
                15768922, 25091167, 14856294 },
            { -18866652, 8331043, 24373479, 8541013, -701998, -9269457, 12927300,
                -12695493, -22182473, -9012899 },
            { -11423429, -5421590, 11632845, 3405020, 30536730, -11674039,
                -27260765, 13866390, 30146206, 9142070 },
        },
        {
            { 3924129, -15307516, -13817122, -10054960, 12291820, -668366,
                -27702774, 9326384, -8237858, 4171294 },
            { -15921940, 16037937, 6713787, 16606682, -21612135, 2790944,
                26396185, 3731949, 345228, -5462949 },
            { -21327538, 13448259, 25284571, 1143661, 20614966, -8849387,
                2031539, -12391231, -16253183, -13582083 },
        },
        {
            { 31016211, -16722429, 26371392, -14451233, -5027349, 14854137,
                17477601, 3842657, 28012650, -16405420 },
            { -5075835, 9368966, -8562079, -4600902, -15249953, 6970560,
                -9189873, 16292057, -8867157, 3507940 },
            { 29439664, 3537914, 23333589, 6997794, -17555561, -11018068,
                -15209202, -15051267, -9164929, 6580396 },
        },
    },
    {
        {
            { -12185861, -7679788, 16438269, 10826160, -8696817, -6235611,
                17860444, -9273846, -2095802, 9304567 },
            { 20714564, -4336911, 29088195, 7406487, 11426967, -5095705,
                14792667, -14608617, 5289421, -477127 },
            { -16665533, -10650790, -6160345, -13305760, 9192020, -1802462,
                17271490, 12349094, 26939669, -3752294 },
        },
        {
            { -12889898, 9373458, 31595848, 16374215, 21471720, 13221525,
                -27283495, -12348559, -3698806, 117887 },
            { 22263325, -6560050, 3984570, -11174646, -15114008, -566785,
                28311253, 5358056, -23319780, 541964 },
            { 16259219, 3261970, 2309254, -15534474, -16885711, -4581916,
                24134070, -16705829, -13337066, -13552195 },
        },
        {
            { 9378160, -13140186, -22845982, -12745264, 28198281, -7244098,
                -2399684, -717351, 690426, 14876244 },
            { 24977353, -314384, -8223969, -13465086, 28432343, -1176353,
                -13068804, -12297348, -22380984, 6618999 },
            { -1538174, 11685646, 12944378, 13682314, -24389511, -14413193,
                8044829, -13817328, 32239829, -5652762 },
        },
        {
            { -18603066, 4762990, -926250, 8885304, -28412480, -3187315, 9781647,
                -10350059, 32779359, 5095274 },
            { -33008130, -5214506, -32264887, -3685216, 9460461, -9327423,
                -24601656, 14506724, 21639561, -2630236 },
            { -16400943, -13112215, 25239338, 15531969, 3987758, -4499318,
                -1289502, -6863535, 17874574, 558605 },
        },
        {
            { -13600129, 10240081, 9171883, 16131053, -20869254, 9599700,
                33499487, 5080151, 2085892, 5119761 },
            { -22205145, -2519528, -16381601, 414691, -25019550, 2170430,
                30634760, -8363614, -31999993, -5759884 },
            { -6845704, 15791202, 8550074, -1312654, 29928809, -12092256,
                27534430, -7192145, -22351378, 12961482 },
        },
        {
            { -24492060, -9570771, 10368194, 11582341, -23397293, -2245287,
                16533930, 8206996, -30194652, -5159638 },
            { -11121496, -3382234, 2307366, 6362031, -135455, 8868177, -16835630,
                7031275, 7589640, 8945490 },
            { -32152748, 8917967, 6661220, -11677616, -1192060, -15793393,
                7251489, -11182180, 24099109, -14456170 },
        },
        {
            { 5019558, -7907470, 4244127, -14714356, -26933272, 6453165,
                -19118182, -13289025, -6231896, -10280736 },
            { 10853594, 10721687, 26480089, 5861829, -22995819, 1972175,
                -1866647, -10557898, -3363451, -6441124 },
            { -17002408, 5906790, 221599, -6563147, 7828208, -13248918, 24362661,
                -2008168, -13866408, 7421392 },
        },
        {
            { 8139927, -6546497, 32257646, -5890546, 30375719, 1886181,
                -21175108, 15441252, 28826358, -4123029 },
            { 6267086, 9695052, 7709135, -16603597, -32869068, -1886135,
                14795160, -7840124, 13746021, -1742048 },
            { 28584902, 7787108, -6732942, -15050729, 22846041, -7571236,
                -3181936, -363524, 4771362, -8419958 },
        },
    },
    {
        {
            { 24949256, 6376279, -27466481, -8174608, -18646154, -9930606,
                33543569, -12141695, 3569627, 11342593 },
            { 26514989, 4740088, 27912651, 3697550, 19331575, -11472339, 6809886,
                4608608, 7325975, -14801071 },
            { -11618399, -14554430, -24321212, 7655128, -1369274, 5214312,
                -27400540, 10258390, -17646694, -8186692 },
        },
        {
            { 11431204, 15823007, 26570245, 14329124, 18029990, 4796082,
                -31446179, 15580664, 9280358, -3973687 },
            { -160783, -10326257, -22855316, -4304997, -20861367, -13621002,
                -32810901, -11181622, -15545091, 4387441 },
            { -20799378, 12194512, 3937617, -5805892, -27154820, 9340370,
                -24513992, 8548137, 20617071, -7482001 },
        },
        {
            { -938825, -3930586, -8714311, 16124718, 24603125, -6225393,
                -13775352, -11875822, 24345683, 10325460 },
            { -19855277, -1568885, -22202708, 8714034, 14007766, 6928528,
                16318175, -1010689, 4766743, 3552007 },
            { -21751364, -16730916, 1351763, -803421, -4009670, 3950935, 3217514,
                14481909, 10988822, -3994762 },
        },
        {
            { 15564307, -14311570, 3101243, 5684148, 30446780, -8051356,
                12677127, -6505343, -8295852, 13296005 },
            { -9442290, 6624296, -30298964, -11913677, -4670981, -2057379,
                31521204, 9614054, -30000824, 12074674 },
            { 4771191, -135239, 14290749, -13089852, 27992298, 14998318,
                -1413936, -1556716, 29832613, -16391035 },
        },
        {
            { 7064884, -7541174, -19161962, -5067537, -18891269, -2912736,
                25825242, 5293297, -27122660, 13101590 },
            { -2298563, 2439670, -7466610, 1719965, -27267541, -16328445,
                32512469, -5317593, -30356070, -4190957 },
            { -30006540, 10162316, -33180176, 3981723, -16482138, -13070044,
                14413974, 9515896, 19568978, 9628812 },
        },
        {
            { 33053803, 199357, 15894591, 1583059, 27380243, -4580435, -17838894,
                -6106839, -6291786, 3437740 },
            { -18978877, 3884493, 19469877, 12726490, 15913552, 13614290,
                -22961733, 70104, 7463304, 4176122 },
            { -27124001, 10659917, 11482427, -16070381, 12771467, -6635117,
                -32719404, -5322751, 24216882, 5944158 },
        },
        {
            { 8894125, 7450974, -2664149, -9765752, -28080517, -12389115,
                19345746, 14680796, 11632993, 5847885 },
            { 26942781, -2315317, 9129564, -4906607, 26024105, 11769399,
                -11518837, 6367194, -9727230, 4782140 },
            { 19916461, -4828410, -22910704, -11414391, 25606324, -5972441,
                33253853, 8220911, 6358847, -1873857 },
        },
        {
            { 801428, -2081702, 16569428, 11065167, 29875704, 96627, 7908388,
                -4480480, -13538503, 1387155 },
            { 19646058, 5720633, -11416706, 12814209, 11607948, 12749789,
                14147075, 15156355, -21866831, 11835260 },
            { 19299512, 1155910, 28703737, 14890794, 2925026, 7269399, 26121523,
                15467869, -26560550, 5052483 },
        },
    },
    {
        {
            { -3017432, 10058206, 1980837, 3964243, 22160966, 12322533, -6431123,
                -12618185, 12228557, -7003677 },
            { 32944382, 14922211, -22844894, 5188528, 21913450, -8719943,
                4001465, 13238564, -6114803, 8653815 },
            { 22865569, -4652735, 27603668, -12545395, 14348958, 8234005,
                24808405, 5719875, 28483275, 2841751 },
        },
        {
            { -16420968, -1113305, -327719, -12107856, 21886282, -15552774,
                -1887966, -315658, 19932058, -12739203 },
            { -11656086, 10087521, -8864888, -5536143, -19278573, -3055912,
                3999228, 13239134, -4777469, -13910208 },
            { 1382174, -11694719, 17266790, 9194690, -13324356, 9720081,
                20403944, 11284705, -14013818, 3093230 },
        },
        {
            { 16650921, -11037932, -1064178, 1570629, -8329746, 7352753, -302424,
                16271225, -24049421, -6691850 },
            { -21911077, -5927941, -4611316, -5560156, -31744103, -10785293,
                24123614, 15193618, -21652117, -16739389 },
            { -9935934, -4289447, -25279823, 4372842, 2087473, 10399484,
                31870908, 14690798, 17361620, 11864968 },
        },
        {
            { -11307610, 6210372, 13206574, 5806320, -29017692, -13967200,
                -12331205, -7486601, -25578460, -16240689 },
            { 14668462, -12270235, 26039039, 15305210, 25515617, 4542480,
                10453892, 6577524, 9145645, -6443880 },
            { 5974874, 3053895, -9433049, -10385191, -31865124, 3225009,
                -7972642, 3936128, -5652273, -3050304 },
        },
        {
            { 30625386, -4729400, -25555961, -12792866, -20484575, 7695099,
                17097188, -16303496, -27999779, 1803632 },
            { -3553091, 9865099, -5228566, 4272701, -5673832, -16689700,
                14911344, 12196514, -21405489, 7047412 },
            { 20093277, 9920966, -11138194, -5343857, 13161587, 12044805,
                -32856851, 4124601, -32343828, -10257566 },
        },
        {
            { -20788824, 14084654, -13531713, 7842147, 19119038, -13822605,
                4752377, -8714640, -21679658, 2288038 },
            { -26819236, -3283715, 29965059, 3039786, -14473765, 2540457,
                29457502, 14625692, -24819617, 12570232 },
            { -1063558, -11551823, 16920318, 12494842, 1278292, -5869109,
                -21159943, -3498680, -11974704, 4724943 },
        },
        {
            { 17960970, -11775534, -4140968, -9702530, -8876562, -1410617,
                -12907383, -8659932, -29576300, 1903856 },
            { 23134274, -14279132, -10681997, -1611936, 20684485, 15770816,
                -12989750, 3190296, 26955097, 14109738 },
            { 15308788, 5320727, -30113809, -14318877, 22902008, 7767164,
                29425325, -11277562, 31960942, 11934971 },
        },
        {
            { -27395711, 8435796, 4109644, 12222639, -24627868, 14818669,
                20638173, 4875028, 10491392, 1379718 },
            { -13159415, 9197841, 3875503, -8936108, -1383712, -5879801,
                33518459, 16176658, 21432314, 12180697 },
            { -11787308, 11500838, 13787581, -13832590, -22430679, 10140205,
                1465425, 12689540, -10301319, -13872883 },
        },
    },
    {
        {
            { 5414091, -15386041, -21007664, 9643570, 12834970, 1186149,
                -2622916, -1342231, 26128231, 6032912 },
            { -26337395, -13766162, 32496025, -13653919, 17847801, -12669156,
                3604025, 8316894, -25875034, -10437358 },
            { 3296484, 6223048, 24680646, -12246460, -23052020, 5903205,
                -8862297, -4639164, 12376617, 3188849 },
        },
        {
            { 29190488, -14659046, 27549113, -1183516, 3520066, -10697301,
                32049515, -7309113, -16109234, -9852307 },
            { -14744486, -9309156, 735818, -598978, -20407687, -5057904,
                25246078, -15795669, 18640741, -960977 },
            { -6928835, -16430795, 10361374, 5642961, 4910474, 12345252,
                -31638386, -494430, 10530747, 1053335 },
        },
        {
            { -29265967, -14186805, -13538216, -12117373, -19457059, -10655384,
                -31462369, -2948985, 24018831, 15026644 },
            { -22592535, -3145277, -2289276, 5953843, -13440189, 9425631,
                25310643, 13003497, -2314791, -15145616 },
            { -27419985, -603321, -8043984, -1669117, -26092265, 13987819,
                -27297622, 187899, -23166419, -2531735 },
        },
        {
            { -21744398, -13810475, 1844840, 5021428, -10434399, -15911473,
                9716667, 16266922, -5070217, 726099 },
            { 29370922, -6053998, 7334071, -15342259, 9385287, 2247707,
                -13661962, -4839461, 30007388, -15823341 },
            { -936379, 16086691, 23751945, -543318, -1167538, -5189036, 9137109,
                730663, 9835848, 4555336 },
        },
        {
            { -23376435, 1410446, -22253753, -12899614, 30867635, 15826977,
                17693930, 544696, -11985298, 12422646 },
            { 31117226, -12215734, -13502838, 6561947, -9876867, -12757670,
                -5118685, -4096706, 29120153, 13924425 },
            { -17400879, -14233209, 19675799, -2734756, -11006962, -5858820,
                -9383939, -11317700, 7240931, -237388 },
        },
        {
            { -31361739, -11346780, -15007447, -5856218, -22453340, -12152771,
                1222336, 4389483, 3293637, -15551743 },
            { -16684801, -14444245, 11038544, 11054958, -13801175, -3338533,
                -24319580, 7733547, 12796905, -6335822 },
            { -8759414, -10817836, -25418864, 10783769, -30615557, -9746811,
                -28253339, 3647836, 3222231, -11160462 },
        },
        {
            { 18606113, 1693100, -25448386, -15170272, 4112353, 10045021,
                23603893, -2048234, -7550776, 2484985 },
            { 9255317, -3131197, -12156162, -1004256, 13098013, -9214866,
                16377220, -2102812, -19802075, -3034702 },
            { -22729289, 7496160, -5742199, 11329249, 19991973, -3347502,
                -31718148, 9936966, -30097688, -10618797 },
        },
        {
            { 21878590, -5001297, 4338336, 13643897, -3036865, 13160960,
                19708896, 5415497, -7360503, -4109293 },
            { 27736861, 10103576, 12500508, 8502413, -3413016, -9633558,
                10436918, -1550276, -23659143, -8132100 },
            { 19492550, -12104365, -29681976, -852630, -3208171, 12403437,
                30066266, 8367329, 13243957, 8709688 },
        },
    },
    {
        {
            { 12015105, 2801261, 28198131, 10151021, 24818120, -4743133,
                -11194191, -5645734, 5150968, 7274186 },
            { 2831366, -12492146, 1478975, 6122054, 23825128, -12733586,
                31097299, 6083058, 31021603, -9793610 },
            { -2529932, -2229646, 445613, 10720828, -13849527, -11505937,
                -23507731, 16354465, 15067285, -14147707 },
        },
        {
            { 7840942, 14037873, -33364863, 15934016, -728213, -3642706,
                21403988, 1057586, -19379462, -12403220 },
            { 915865, -16469274, 15608285, -8789130, -24357026, 6060030,
                -17371319, 8410997, -7220461, 16527025 },
            { 32922597, -556987, 20336074, -16184568, 10903705, -5384487,
                16957574, 52992, 23834301, 6588044 },
        },
        {
            { 32752030, 11232950, 3381995, -8714866, 22652988, -10744103,
                17159699, 16689107, -20314580, -1305992 },
            { -4689649, 9166776, -25710296, -10847306, 11576752, 12733943,
                7924251, -2752281, 1976123, -7249027 },
            { 21251222, 16309901, -2983015, -6783122, 30810597, 12967303, 156041,
                -3371252, 12331345, -8237197 },
        },
        {
            { 8651614, -4477032, -16085636, -4996994, 13002507, 2950805,
                29054427, -5106970, 10008136, -4667901 },
            { 31486080, 15114593, -14261250, 12951354, 14369431, -7387845,
                16347321, -13662089, 8684155, -10532952 },
            { 19443825, 11385320, 24468943, -9659068, -23919258, 2187569,
                -26263207, -6086921, 31316348, 14219878 },
        },
        {
            { -28594490, 1193785, 32245219, 11392485, 31092169, 15722801,
                27146014, 6992409, 29126555, 9207390 },
            { 32382935, 1110093, 18477781, 11028262, -27411763, -7548111,
                -4980517, 10843782, -7957600, -14435730 },
            { 2814918, 7836403, 27519878, -7868156, -20894015, -11553689,
                -21494559, 8550130, 28346258, 1994730 },
        },
        {
            { -19578299, 8085545, -14000519, -3948622, 2785838, -16231307,
                -19516951, 7174894, 22628102, 8115180 },
            { -30405132, 955511, -11133838, -15078069, -32447087, -13278079,
                -25651578, 3317160, -9943017, 930272 },
            { -15303681, -6833769, 28856490, 1357446, 23421993, 1057177,
                24091212, -1388970, -22765376, -10650715 },
        },
        {
            { -22751231, -5303997, -12907607, -12768866, -15811511, -7797053,
                -14839018, -16554220, -1867018, 8398970 },
            { -31969310, 2106403, -4736360, 1362501, 12813763, 16200670,
                22981545, -6291273, 18009408, -15772772 },
            { -17220923, -9545221, -27784654, 14166835, 29815394, 7444469,
                29551787, -3727419, 19288549, 1325865 },
        },
        {
            { 15100157, -15835752, -23923978, -1005098, -26450192, 15509408,
                12376730, -3479146, 33166107, -8042750 },
            { 20909231, 13023121, -9209752, 16251778, -5778415, -8094914,
                12412151, 10018715, 2213263, -13878373 },
            { 32529814, -11074689, 30361439, -16689753, -9135940, 1513226,
                22922121, 6382134, -5766928, 8371348 },
        },
    },
    {
        {
            { 9923462, 11271500, 12616794, 3544722, -29998368, -1721626,
                12891687, -8193132, -26442943, 10486144 },
            { -22597207, -7012665, 8587003, -8257861, 4084309, -12970062, 361726,
                2610596, -23921530, -11455195 },
            { 5408411, -1136691, -4969122, 10561668, 24145918, 14240566,
                31319731, -4235541, 19985175, -3436086 },
        },
        {
            { -13994457, 16616821, 14549246, 3341099, 32155958, 13648976,
                -17577068, 8849297, 65030, 8370684 },
            { -8320926, -12049626, 31204563, 5839400, -20627288, -1057277,
                -19442942, 6922164, 12743482, -9800518 },
            { -2361371, 12678785, 28815050, 4759974, -23893047, 4884717,
                23783145, 11038569, 18800704, 255233 },
        },
        {
            { -5269658, -1773886, 13957886, 7990715, 23132995, 728773, 13393847,
                9066957, 19258688, -14753793 },
            { -2936654, -10827535, -10432089, 14516793, -3640786, 4372541,
                -31934921, 2209390, -1524053, 2055794 },
            { 580882, 16705327, 5468415, -2683018, -30926419, -14696000,
                -7203346, -8994389, -30021019, 7394435 },
        },
        {
            { 23838809, 1822728, -15738443, 15242727, 8318092, -3733104,
                -21672180, -3492205, -4821741, 14799921 },
            { 13345610, 9759151, 3371034, -16137791, 16353039, 8577942, 31129804,
                13496856, -9056018, 7402518 },
            { 2286874, -4435931, -20042458, -2008336, -13696227, 5038122,
                11006906, -15760352, 8205061, 1607563 },
        },
        {
            { 14414086, -8002132, 3331830, -3208217, 22249151, -5594188,
                18364661, -2906958, 30019587, -9029278 },
            { -27688051, 1585953, -10775053, 931069, -29120221, -11002319,
                -14410829, 12029093, 9944378, 8024 },
            { 4368715, -3709630, 29874200, -15022983, -20230386, -11410704,
                -16114594, -999085, -8142388, 5640030 },
        },
        {
            { 10299610, 13746483, 11661824, 16234854, 7630238, 5998374, 9809887,
                -16694564, 15219798, -14327783 },
            { 27425505, -5719081, 3055006, 10660664, 23458024, 595578, -15398605,
                -1173195, -18342183, 9742717 },
            { 6744077, 2427284, 26042789, 2720740, -847906, 1118974, 32324614,
                7406442, 12420155, 1994844 },
        },
        {
            { 14012521, -5024720, -18384453, -9578469, -26485342, -3936439,
                -13033478, -10909803, 24319929, -6446333 },
            { 16412690, -4507367, 10772641, 15929391, -17068788, -4658621,
                10555945, -10484049, -30102368, -4739048 },
            { 22397382, -7767684, -9293161, -12792868, 17166287, -9755136,
                -27333065, 6199366, 21880021, -12250760 },
        },
        {
            { -4283307, 5368523, -31117018, 8163389, -30323063, 3209128,
                16557151, 8890729, 8840445, 4957760 },
            { -15447727, 709327, -6919446, -10870178, -29777922, 6522332,
                -21720181, 12130072, -14796503, 5005757 },
            { -2114751, -14308128, 23019042, 15765735, -25269683, 6002752,
                10183197, -13239326, -16395286, -2176112 },
        },
    },
    {
        {
            { -19025756, 1632005, 13466291, -7995100, -23640451, 16573537,
                -32013908, -3057104, 22208662, 2000468 },
            { 3065073, -1412761, -25598674, -361432, -17683065, -5703415,
                -8164212, 11248527, -3691214, -7414184 },
            { 10379208, -6045554, 8877319, 1473647, -29291284, -12507580,
                16690915, 2553332, -3132688, 16400289 },
        },
        {
            { 15716668, 1254266, -18472690, 7446274, -8448918, 6344164,
                -22097271, -7285580, 26894937, 9132066 },
            { 24158887, 12938817, 11085297, -8177598, -28063478, -4457083,
                -30576463, 64452, -6817084, -2692882 },
            { 13488534, 7794716, 22236231, 5989356, 25426474, -12578208, 2350710,
                -3418511, -4688006, 2364226 },
        },
        {
            { 16335052, 9132434, 25640582, 6678888, 1725628, 8517937, -11807024,
                -11697457, 15445875, -7798101 },
            { 29004207, -7867081, 28661402, -640412, -12794003, -7943086,
                31863255, -4135540, -278050, -15759279 },
            { -6122061, -14866665, -28614905, 14569919, -10857999, -3591829,
                10343412, -6976290, -29828287, -10815811 },
        },
        {
            { 27081650, 3463984, 14099042, -4517604, 1616303, -6205604, 29542636,
                15372179, 17293797, 960709 },
            { 20263915, 11434237, -5765435, 11236810, 13505955, -10857102,
                -16111345, 6493122, -19384511, 7639714 },
            { -2830798, -14839232, 25403038, -8215196, -8317012, -16173699,
                18006287, -16043750, 29994677, -15808121 },
        },
        {
            { 9769828, 5202651, -24157398, -13631392, -28051003, -11561624,
                -24613141, -13860782, -31184575, 709464 },
            { 12286395, 13076066, -21775189, -1176622, -25003198, 4057652,
                -32018128, -8890874, 16102007, 13205847 },
            { 13733362, 5599946, 10557076, 3195751, -5557991, 8536970, -25540170,
                8525972, 10151379, 10394400 },
        },
        {
            { 4024660, -16137551, 22436262, 12276534, -9099015, -2686099,
                19698229, 11743039, -33302334, 8934414 },
            { -15879800, -4525240, -8580747, -2934061, 14634845, -698278,
                -9449077, 3137094, -11536886, 11721158 },
            { 17555939, -5013938, 8268606, 2331751, -22738815, 9761013, 9319229,
                8835153, -9205489, -1280045 },
        },
        {
            { -461409, -7830014, 20614118, 16688288, -7514766, -4807119,
                22300304, 505429, 6108462, -6183415 },
            { -5070281, 12367917, -30663534, 3234473, 32617080, -8422642,
                29880583, -13483331, -26898490, -7867459 },
            { -31975283, 5726539, 26934134, 10237677, -3173717, -605053,
                24199304, 3795095, 7592688, -14992079 },
        },
        {
            { 21594432, -14964228, 17466408, -4077222, 32537084, 2739898,
                6407723, 12018833, -28256052, 4298412 },
            { -20650503, -11961496, -27236275, 570498, 3767144, -1717540,
                13891942, -1569194, 13717174, 10805743 },
            { -14676630, -15644296, 15287174, 11927123, 24177847, -8175568,
                -796431, 14860609, -26938930, -5863836 },
        },
    },
    {
        {
            { 12962541, 5311799, -10060768, 11658280, 18855286, -7954201,
                13286263, -12808704, -4381056, 9882022 },
            { 18512079, 11319350, -20123124, 15090309, 18818594, 5271736,
                -22727904, 3666879, -23967430, -3299429 },
            { -6789020, -3146043, 16192429, 13241070, 15898607, -14206114,
                -10084880, -6661110, -2403099, 5276065 },
        },
        {
            { 30169808, -5317648, 26306206, -11750859, 27814964, 7069267,
                7152851, 3684982, 1449224, 13082861 },
            { 10342826, 3098505, 2119311, 193222, 25702612, 12233820, 23697382,
                15056736, -21016438, -8202000 },
            { -33150110, 3261608, 22745853, 7948688, 19370557, -15177665,
                -26171976, 6482814, -10300080, -11060101 },
        },
        {
            { 32869458, -5408545, 25609743, 15678670, -10687769, -15471071,
                26112421, 2521008, -22664288, 6904815 },
            { 29506923, 4457497, 3377935, -9796444, -30510046, 12935080, 1561737,
                3841096, -29003639, -6657642 },
            { 10340844, -6630377, -18656632, -2278430, 12621151, -13339055,
                30878497, -11824370, -25584551, 5181966 },
        },
        {
            { 25940115, -12658025, 17324188, -10307374, -8671468, 15029094,
                24396252, -16450922, -2322852, -12388574 },
            { -21765684, 9916823, -1300409, 4079498, -1028346, 11909559, 1782390,
                12641087, 20603771, -6561742 },
            { -18882287, -11673380, 24849422, 11501709, 13161720, -4768874,
                1925523, 11914390, 4662781, 7820689 },
        },
        {
            { 12241050, -425982, 8132691, 9393934, 32846760, -1599620, 29749456,
                12172924, 16136752, 15264020 },
            { -10349955, -14680563, -8211979, 2330220, -17662549, -14545780,
                10658213, 6671822, 19012087, 3772772 },
            { 3753511, -3421066, 10617074, 2028709, 14841030, -6721664, 28718732,
                -15762884, 20527771, 12988982 },
        },
        {
            { -14822485, -5797269, -3707987, 12689773, -898983, -10914866,
                -24183046, -10564943, 3299665, -12424953 },
            { -16777703, -15253301, -9642417, 4978983, 3308785, 8755439, 6943197,
                6461331, -25583147, 8991218 },
            { -17226263, 1816362, -1673288, -6086439, 31783888, -8175991,
                -32948145, 7417950, -30242287, 1507265 },
        },
        {
            { 29692663, 6829891, -10498800, 4334896, 20945975, -11906496,
                -28887608, 8209391, 14606362, -10647073 },
            { -3481570, 8707081, 32188102, 5672294, 22096700, 1711240, -33020695,
                9761487, 4170404, -2085325 },
            { -11587470, 14855945, -4127778, -1531857, -26649089, 15084046,
                22186522, 16002000, -14276837, -8400798 },
        },
        {
            { -4811456, 13761029, -31703877, -2483919, -3312471, 7869047,
                -7113572, -9620092, 13240845, 10965870 },
            { -7742563, -8256762, -14768334, -13656260, -23232383, 12387166,
                4498947, 14147411, 29514390, 4302863 },
            { -13413405, -12407859, 20757302, -13801832, 14785143, 8976368,
                -5061276, -2144373, 17846988, -13971927 },
        },
    },
    {
        {
            { -2244452, -754728, -4597030, -1066309, -6247172, 1455299,
                -21647728, -9214789, -5222701, 12650267 },
            { -9906797, -16070310, 21134160, 12198166, -27064575, 708126, 387813,
                13770293, -19134326, 10958663 },
            { 22470984, 12369526, 23446014, -5441109, -21520802, -9698723,
                -11772496, -11574455, -25083830, 4271862 },
        },
        {
            { -25169565, -10053642, -19909332, 15361595, -5984358, 2159192,
                75375, -4278529, -32526221, 8469673 },
            { 15854970, 4148314, -8893890, 7259002, 11666551, 13824734,
                -30531198, 2697372, 24154791, -9460943 },
            { 15446137, -15806644, 29759747, 14019369, 30811221, -9610191,
                -31582008, 12840104, 24913809, 9815020 },
        },
        {
            { -4709286, -5614269, -31841498, -12288893, -14443537, 10799414,
                -9103676, 13438769, 18735128, 9466238 },
            { 11933045, 9281483, 5081055, -5183824, -2628162, -4905629, -7727821,
                -10896103, -22728655, 16199064 },
            { 14576810, 379472, -26786533, -8317236, -29426508, -10812974,
                -102766, 1876699, 30801119, 2164795 },
        },
        {
            { 15995086, 3199873, 13672555, 13712240, -19378835, -4647646,
                -13081610, -15496269, -13492807, 1268052 },
            { -10290614, -3659039, -3286592, 10948818, 23037027, 3794475,
                -3470338, -12600221, -17055369, 3565904 },
            { 29210088, -9419337, -5919792, -4952785, 10834811, -13327726,
                -16512102, -10820713, -27162222, -14030531 },
        },
        {
            { -13161890, 15508588, 16663704, -8156150, -28349942, 9019123,
                -29183421, -3769423, 2244111, -14001979 },
            { -5152875, -3800936, -9306475, -6071583, 16243069, 14684434,
                -25673088, -16180800, 13491506, 4641841 },
            { 10813417, 643330, -19188515, -728916, 30292062, -16600078,
                27548447, -7721242, 14476989, -12767431 },
        },
        {
            { 10292079, 9984945, 6481436, 8279905, -7251514, 7032743, 27282937,
                -1644259, -27912810, 12651324 },
            { -31185513, -813383, 22271204, 11835308, 10201545, 15351028,
                17099662, 3988035, 21721536, -3148940 },
            { 10202177, -6545839, -31373232, -9574638, -32150642, -8119683,
                -12906320, 3852694, 13216206, 14842320 },
        },
        {
            { -15815640, -10601066, -6538952, -7258995, -6984659, -6581778,
                -31500847, 13765824, -27434397, 9900184 },
            { 14465505, -13833331, -32133984, -14738873, -27443187, 12990492,
                33046193, 15796406, -7051866, -8040114 },
            { 30924417, -8279620, 6359016, -12816335, 16508377, 9071735,
                -25488601, 15413635, 9524356, -7018878 },
        },
        {
            { 12274201, -13175547, 32627641, -1785326, 6736625, 13267305,
                5237659, -5109483, 15663516, 4035784 },
            { -2951309, 8903985, 17349946, 601635, -16432815, -4612556,
                -13732739, -15889334, -22258478, 4659091 },
            { -16916263, -4952973, -30393711, -15158821, 20774812, 15897498,
                5736189, 15026997, -2178256, -13455585 },
        },
    },
    {
        {
            { -8858980, -2219056, 28571666, -10155518, -474467, -10105698,
                -3801496, 278095, 23440562, -290208 },
            { 10226241, -5928702, 15139956, 120818, -14867693, 5218603, 32937275,
                11551483, -16571960, -7442864 },
            { 17932739, -12437276, -24039557, 10749060, 11316803, 7535897,
                22503767, 5561594, -3646624, 3898661 },
        },
        {
            { 7749907, -969567, -16339731, -16464, -25018111, 15122143, -1573531,
                7152530, 21831162, 1245233 },
            { 26958459, -14658026, 4314586, 8346991, -5677764, 11960072,
                -32589295, -620035, -30402091, -16716212 },
            { -12165896, 9166947, 33491384, 13673479, 29787085, 13096535,
                6280834, 14587357, -22338025, 13987525 },
        },
        {
            { -24349909, 7778775, 21116000, 15572597, -4833266, -5357778,
                -4300898, -5124639, -7469781, -2858068 },
            { 9681908, -6737123, -31951644, 13591838, -6883821, 386950, 31622781,
                6439245, -14581012, 4091397 },
            { -8426427, 1470727, -28109679, -1596990, 3978627, -5123623,
                -19622683, 12092163, 29077877, -14741988 },
        },
        {
            { 5269168, -6859726, -13230211, -8020715, 25932563, 1763552,
                -5606110, -5505881, -20017847, 2357889 },
            { 32264008, -15407652, -5387735, -1160093, -2091322, -3946900,
                23104804, -12869908, 5727338, 189038 },
            { 14609123, -8954470, -6000566, -16622781, -14577387, -7743898,
                -26745169, 10942115, -25888931, -14884697 },
        },
        {
            { 20513500, 5557931, -15604613, 7829531, 26413943, -2019404,
                -21378968, 7471781, 13913677, -5137875 },
            { -25574376, 11967826, 29233242, 12948236, -6754465, 4713227,
                -8940970, 14059180, 12878652, 8511905 },
            { -25656801, 3393631, -2955415, -7075526, -2250709, 9366908,
                -30223418, 6812974, 5568676, -3127656 },
        },
        {
            { 11630004, 12144454, 2116339, 13606037, 27378885, 15676917,
                -17408753, -13504373, -14395196, 8070818 },
            { 27117696, -10007378, -31282771, -5570088, 1127282, 12772488,
                -29845906, 10483306, -11552749, -1028714 },
            { 10637467, -5688064, 5674781, 1072708, -26343588, -6982302,
                -1683975, 9177853, -27493162, 15431203 },
        },
        {
            { 20525145, 10892566, -12742472, 12779443, -29493034, 16150075,
                -28240519, 14943142, -15056790, -7935931 },
            { -30024462, 5626926, -551567, -9981087, 753598, 11981191, 25244767,
                -3239766, -3356550, 9594024 },
            { -23752644, 2636870, -5163910, -10103818, 585134, 7877383, 11345683,
                -6492290, 13352335, -10977084 },
        },
        {
            { -1931799, -5407458, 3304649, -12884869, 17015806, -4877091,
                -29783850, -7752482, -13215537, -319204 },
            { 20239939, 6607058, 6203985, 3483793, -18386976, -779229, -20723742,
                15077870, -22750759, 14523817 },
            { 27406042, -6041657, 27423596, -4497394, 4996214, 10002360,
                -28842031, -4545494, -30172742, -4805667 },
        },
    },
    {
        {
            { 11374242, 12660715, 17861383, -12540833, 10935568, 1099227,
                -13886076, -9091740, -27727044, 11358504 },
            { -12730809, 10311867, 1510375, 10778093, -2119455, -9145702,
                32676003, 11149336, -26123651, 4985768 },
            { -19096303, 341147, -6197485, -239033, 15756973, -8796662, -983043,
                13794114, -19414307, -15621255 },
        },
        {
            { 6490081, 11940286, 25495923, -7726360, 8668373, -8751316, 3367603,
                6970005, -1691065, -9004790 },
            { 1656497, 13457317, 15370807, 6364910, 13605745, 8362338, -19174622,
                -5475723, -16796596, -5031438 },
            { -22273315, -13524424, -64685, -4334223, -18605636, -10921968,
                -20571065, -7007978, -99853, -10237333 },
        },
        {
            { 17747465, 10039260, 19368299, -4050591, -20630635, -16041286,
                31992683, -15857976, -29260363, -5511971 },
            { 31932027, -4986141, -19612382, 16366580, 22023614, 88450, 11371999,
                -3744247, 4882242, -10626905 },
            { 29796507, 37186, 19818052, 10115756, -11829032, 3352736, 18551198,
                3272828, -5190932, -4162409 },
        },
        {
            { 12501286, 4044383, -8612957, -13392385, -32430052, 5136599,
                -19230378, -3529697, 330070, -3659409 },
            { 6384877, 2899513, 17807477, 7663917, -2358888, 12363165, 25366522,
                -8573892, -271295, 12071499 },
            { -8365515, -4042521, 25133448, -4517355, -6211027, 2265927,
                -32769618, 1936675, -5159697, 3829363 },
        },
        {
            { 28425966, -5835433, -577090, -4697198, -14217555, 6870930, 7921550,
                -6567787, 26333140, 14267664 },
            { -11067219, 11871231, 27385719, -10559544, -4585914, -11189312,
                10004786, -8709488, -21761224, 8930324 },
            { -21197785, -16396035, 25654216, -1725397, 12282012, 11008919,
                1541940, 4757911, -26491501, -16408940 },
        },
        {
            { 13537262, -7759490, -20604840, 10961927, -5922820, -13218065,
                -13156584, 6217254, -15943699, 13814990 },
            { -17422573, 15157790, 18705543, 29619, 24409717, -260476, 27361681,
                9257833, -1956526, -1776914 },
            { -25045300, -10191966, 15366585, 15166509, -13105086, 8423556,
                -29171540, 12361135, -18685978, 4578290 },
        },
        {
            { 24579768, 3711570, 1342322, -11180126, -27005135, 14124956,
                -22544529, 14074919, 21964432, 8235257 },
            { -6528613, -2411497, 9442966, -5925588, 12025640, -1487420,
                -2981514, -1669206, 13006806, 2355433 },
            { -16304899, -13605259, -6632427, -5142349, 16974359, -10911083,
                27202044, 1719366, 1141648, -12796236 },
        },
        {
            { -12863944, -13219986, -8318266, -11018091, -6810145, -4843894,
                13475066, -3133972, 32674895, 13715045 },
            { 11423335, -5468059, 32344216, 8962751, 24989809, 9241752,
                -13265253, 16086212, -28740881, -15642093 },
            { -1409668, 12530728, -6368726, 10847387, 19531186, -14132160,
                -11709148, 7791794, -27245943, 4383347 },
        },
    },
    {
        {
            { -28970898, 5271447, -1266009, -9736989, -12455236, 16732599,
                -4862407, -4906449, 27193557, 6245191 },
            { -15193956, 5362278, -1783893, 2695834, 4960227, 12840725, 23061898,
                3260492, 22510453, 8577507 },
            { -12632451, 11257346, -32692994, 13548177, -721004, 10879011,
                31168030, 13952092, -29571492, -3635906 },
        },
        {
            { 3877321, -9572739, 32416692, 5405324, -11004407, -13656635,
                3759769, 11935320, 5611860, 8164018 },
            { -16275802, 14667797, 15906460, 12155291, -22111149, -9039718,
                32003002, -8832289, 5773085, -8422109 },
            { -23788118, -8254300, 1950875, 8937633, 18686727, 16459170, -905725,
                12376320, 31632953, 190926 },
        },
        {
            { -24593607, -16138885, -8423991, 13378746, 14162407, 6901328,
                -8288749, 4508564, -25341555, -3627528 },
            { 8884438, -5884009, 6023974, 10104341, -6881569, -4941533, 18722941,
                -14786005, -1672488, 827625 },
            { -32720583, -16289296, -32503547, 7101210, 13354605, 2659080,
                -1800575, -14108036, -24878478, 1541286 },
        },
        {
            { 2901347, -1117687, 3880376, -10059388, -17620940, -3612781,
                -21802117, -3567481, 20456845, -1885033 },
            { 27019610, 12299467, -13658288, -1603234, -12861660, -4861471,
                -19540150, -5016058, 29439641, 15138866 },
            { 21536104, -6626420, -32447818, -10690208, -22408077, 5175814,
                -5420040, -16361163, 7779328, 109896 },
        },
        {
            { 30279744, 14648750, -8044871, 6425558, 13639621, -743509, 28698390,
                12180118, 23177719, -554075 },
            { 26572847, 3405927, -31701700, 12890905, -19265668, 5335866,
                -6493768, 2378492, 4439158, -13279347 },
            { -22716706, 3489070, -9225266, -332753, 18875722, -1140095,
                14819434, -12731527, -17717757, -5461437 },
        },
        {
            { -5056483, 16566551, 15953661, 3767752, -10436499, 15627060,
                -820954, 2177225, 8550082, -15114165 },
            { -18473302, 16596775, -381660, 15663611, 22860960, 15585581,
                -27844109, -3582739, -23260460, -8428588 },
            { -32480551, 15707275, -8205912, -5652081, 29464558, 2713815,
                -22725137, 15860482, -21902570, 1494193 },
        },
        {
            { -19562091, -14087393, -25583872, -9299552, 13127842, 759709,
                21923482, 16529112, 8742704, 12967017 },
            { -28464899, 1553205, 32536856, -10473729, -24691605, -406174,
                -8914625, -2933896, -29903758, 15553883 },
            { 21877909, 3230008, 9881174, 10539357, -4797115, 2841332, 11543572,
                14513274, 19375923, -12647961 },
        },
        {
            { 8832269, -14495485, 13253511, 5137575, 5037871, 4078777, 24880818,
                -6222716, 2862653, 9455043 },
            { 29306751, 5123106, 20245049, -14149889, 9592566, 8447059, -2077124,
                -2990080, 15511449, 4789663 },
            { -20679756, 7004547, 8824831, -9434977, -4045704, -3750736,
                -5754762, 108893, 23513200, 16652362 },
        },
    },
    {
        {
            { -33256173, 4144782, -4476029, -6579123, 10770039, -7155542,
                -6650416, -12936300, -18319198, 10212860 },
            { 2756081, 8598110, 7383731, -6859892, 22312759, -1105012, 21179801,
                2600940, -9988298, -12506466 },
            { -24645692, 13317462, -30449259, -15653928, 21365574, -10869657,
                11344424, 864440, -2499677, -16710063 },
        },
        {
            { -26432803, 6148329, -17184412, -14474154, 18782929, -275997,
                -22561534, 211300, 2719757, 4940997 },
            { -1323882, 3911313, -6948744, 14759765, -30027150, 7851207,
                21690126, 8518463, 26699843, 5276295 },
            { -13149873, -6429067, 9396249, 365013, 24703301, -10488939, 1321586,
                149635, -15452774, 7159369 },
        },
        {
            { 9987780, -3404759, 17507962, 9505530, 9731535, -2165514, 22356009,
                8312176, 22477218, -8403385 },
            { 18155857, -16504990, 19744716, 9006923, 15154154, -10538976,
                24256460, -4864995, -22548173, 9334109 },
            { 2986088, -4911893, 10776628, -3473844, 10620590, -7083203,
                -21413845, 14253545, -22587149, 536906 },
        },
        {
            { 4377756, 8115836, 24567078, 15495314, 11625074, 13064599, 7390551,
                10589625, 10838060, -15420424 },
            { -19342404, 867880, 9277171, -3218459, -14431572, -1986443,
                19295826, -15796950, 6378260, 699185 },
            { 7895026, 4057113, -7081772, -13077756, -17886831, -323126, -716039,
                15693155, -5045064, -13373962 },
        },
        {
            { -7737563, -5869402, -14566319, -7406919, 11385654, 13201616,
                31730678, -10962840, -3918636, -9669325 },
            { 10188286, -15770834, -7336361, 13427543, 22223443, 14896287,
                30743455, 7116568, -21786507, 5427593 },
            { 696102, 13206899, 27047647, -10632082, 15285305, -9853179,
                10798490, -4578720, 19236243, 12477404 },
        },
        {
            { -11229439, 11243796, -17054270, -8040865, -788228, -8167967,
                -3897669, 11180504, -23169516, 7733644 },
            { 17800790, -14036179, -27000429, -11766671, 23887827, 3149671,
                23466177, -10538171, 10322027, 15313801 },
            { 26246234, 11968874, 32263343, -5468728, 6830755, -13323031,
                -15794704, -101982, -24449242, 10890804 },
        },
        {
            { -31365647, 10271363, -12660625, -6267268, 16690207, -13062544,
                -14982212, 16484931, 25180797, -5334884 },
            { -586574, 10376444, -32586414, -11286356, 19801893, 10997610,
                2276632, 9482883, 316878, 13820577 },
            { -9882808, -4510367, -2115506, 16457136, -11100081, 11674996,
                30756178, -7515054, 30696930, -3712849 },
        },
        {
            { 32988917, -9603412, 12499366, 7910787, -10617257, -11931514,
                -7342816, -9985397, -32349517, 7392473 },
            { -8855661, 15927861, 9866406, -3649411, -2396914, -16655781,
                -30409476, -9134995, 25112947, -2926644 },
            { -2504044, -436966, 25621774, -5678772, 15085042, -5479877,
                -24884878, -13526194, 5537438, -13914319 },
        },
    },
    {
        {
            { -11225584, 2320285, -9584280, 10149187, -33444663, 5808648,
                -14876251, -1729667, 31234590, 6090599 },
            { -9633316, 116426, 26083934, 2897444, -6364437, -2688086, 609721,
                15878753, -6970405, -9034768 },
            { -27757857, 247744, -15194774, -9002551, 23288161, -10011936,
                -23869595, 6503646, 20650474, 1804084 },
        },
        {
            { -27589786, 15456424, 8972517, 8469608, 15640622, 4439847, 3121995,
                -10329713, 27842616, -202328 },
            { -15306973, 2839644, 22530074, 10026331, 4602058, 5048462, 28248656,
                5031932, -11375082, 12714369 },
            { 20807691, -7270825, 29286141, 11421711, -27876523, -13868230,
                -21227475, 1035546, -19733229, 12796920 },
        },
        {
            { 12076899, -14301286, -8785001, -11848922, -25012791, 16400684,
                -17591495, -12899438, 3480665, -15182815 },
            { -32361549, 5457597, 28548107, 7833186, 7303070, -11953545,
                -24363064, -15921875, -33374054, 2771025 },
            { -21389266, 421932, 26597266, 6860826, 22486084, -6737172,
                -17137485, -4210226, -24552282, 15673397 },
        },
        {
            { -20184622, 2338216, 19788685, -9620956, -4001265, -8740893,
                -20271184, 4733254, 3727144, -12934448 },
            { 6120119, 814863, -11794402, -622716, 6812205, -15747771, 2019594,
                7975683, 31123697, -10958981 },
            { 30069250, -11435332, 30434654, 2958439, 18399564, -976289,
                12296869, 9204260, -16432438, 9648165 },
        },
        {
            { 32705432, -1550977, 30705658, 7451065, -11805606, 9631813, 3305266,
                5248604, -26008332, -11377501 },
            { 17219865, 2375039, -31570947, -5575615, -19459679, 9219903, 294711,
                15298639, 2662509, -16297073 },
            { -1172927, -7558695, -4366770, -4287744, -21346413, -8434326,
                32087529, -1222777, 32247248, -14389861 },
        },
        {
            { 14312628, 1221556, 17395390, -8700143, -4945741, -8684635,
                -28197744, -9637817, -16027623, -13378845 },
            { -1428825, -9678990, -9235681, 6549687, -7383069, -468664, 23046502,
                9803137, 17597934, 2346211 },
            { 18510800, 15337574, 26171504, 981392, -22241552, 7827556,
                -23491134, -11323352, 3059833, -11782870 },
        },
        {
            { 10141598, 6082907, 17829293, -1947643, 9830092, 13613136,
                -25556636, -5544586, -33502212, 3592096 },
            { 33114168, -15889352, -26525686, -13343397, 33076705, 8716171,
                1151462, 1521897, -982665, -6837803 },
            { -32939165, -4255815, 23947181, -324178, -33072974, -12305637,
                -16637686, 3891704, 26353178, 693168 },
        },
        {
            { 30374239, 1595580, -16884039, 13186931, 4600344, 406904, 9585294,
                -400668, 31375464, 14369965 },
            { -14370654, -7772529, 1510301, 6434173, -18784789, -6262728,
                32732230, -13108839, 17901441, 16011505 },
            { 18171223, -11934626, -12500402, 15197122, -11038147, -15230035,
                -19172240, -16046376, 8764035, 12309598 },
        },
    },
    {
        {
            { 5975908, -5243188, -19459362, -9681747, -11541277, 14015782,
                -23665757, 1228319, 17544096, -10593782 },
            { 5811932, -1715293, 3442887, -2269310, -18367348, -8359541,
                -18044043, -15410127, -5565381, 12348900 },
            { -31399660, 11407555, 25755363, 6891399, -3256938, 14872274,
                -24849353, 8141295, -10632534, -585479 },
        },
        {
            { -12675304, 694026, -5076145, 13300344, 14015258, -14451394,
                -9698672, -11329050, 30944593, 1130208 },
            { 8247766, -6710942, -26562381, -7709309, -14401939, -14648910,
                4652152, 2488540, 23550156, -271232 },
            { 17294316, -3788438, 7026748, 15626851, 22990044, 113481, 2267737,
                -5908146, -408818, -137719 },
        },
        {
            { 16091085, -16253926, 18599252, 7340678, 2137637, -1221657,
                -3364161, 14550936, 3260525, -7166271 },
            { -4910104, -13332887, 18550887, 10864893, -16459325, -7291596,
                -23028869, -13204905, -12748722, 2701326 },
            { -8574695, 16099415, 4629974, -16340524, -20786213, -6005432,
                -10018363, 9276971, 11329923, 1862132 },
        },
        {
            { 14763076, -15903608, -30918270, 3689867, 3511892, 10313526,
                -21951088, 12219231, -9037963, -940300 },
            { 8894987, -3446094, 6150753, 3013931, 301220, 15693451, -31981216,
                -2909717, -15438168, 11595570 },
            { 15214962, 3537601, -26238722, -14058872, 4418657, -15230761,
                13947276, 10730794, -13489462, -4363670 },
        },
        {
            { -2538306, 7682793, 32759013, 263109, -29984731, -7955452,
                -22332124, -10188635, 977108, 699994 },
            { -12466472, 4195084, -9211532, 550904, -15565337, 12917920,
                19118110, -439841, -30534533, -14337913 },
            { 31788461, -14507657, 4799989, 7372237, 8808585, -14747943, 9408237,
                -10051775, 12493932, -5409317 },
        },
        {
            { -25680606, 5260744, -19235809, -6284470, -3695942, 16566087,
                27218280, 2607121, 29375955, 6024730 },
            { 842132, -2794693, -4763381, -8722815, 26332018, -12405641,
                11831880, 6985184, -9940361, 2854096 },
            { -4847262, -7969331, 2516242, -5847713, 9695691, -7221186, 16512645,
                960770, 12121869, 16648078 },
        },
        {
            { -15218652, 14667096, -13336229, 2013717, 30598287, -464137,
                -31504922, -7882064, 20237806, 2838411 },
            { -19288047, 4453152, 15298546, -16178388, 22115043, -15972604,
                12544294, -13470457, 1068881, -12499905 },
            { -9558883, -16518835, 33238498, 13506958, 30505848, -1114596,
                -8486907, -2630053, 12521378, 4845654 },
        },
        {
            { -28198521, 10744108, -2958380, 10199664, 7759311, -13088600,
                3409348, -873400, -6482306, -12885870 },
            { -23561822, 6230156, -20382013, 10655314, -24040585, -11621172,
                10477734, -1240216, -3113227, 13974498 },
            { 12966261, 15550616, -32038948, -1615346, 21025980, -629444,
                5642325, 7188737, 18895762, 12629579 },
        },
    },
    {
        {
            { 14741879, -14946887, 22177208, -11721237, 1279741, 8058600,
                11758140, 789443, 32195181, 3895677 },
            { 10758205, 15755439, -4509950, 9243698, -4879422, 6879879, -2204575,
                -3566119, -8982069, 4429647 },
            { -2453894, 15725973, -20436342, -10410672, -5803908, -11040220,
                -7135870, -11642895, 18047436, -15281743 },
        },
        {
            { -25173001, -11307165, 29759956, 11776784, -22262383, -15820455,
                10993114, -12850837, -17620701, -9408468 },
            { 21987233, 700364, -24505048, 14972008, -7774265, -5718395,
                32155026, 2581431, -29958985, 8773375 },
            { -25568350, 454463, -13211935, 16126715, 25240068, 8594567,
                20656846, 12017935, -7874389, -13920155 },
        },
        {
            { 6028182, 6263078, -31011806, -11301710, -818919, 2461772,
                -31841174, -5468042, -1721788, -2776725 },
            { -12278994, 16624277, 987579, -5922598, 32908203, 1248608, 7719845,
                -4166698, 28408820, 6816612 },
            { -10358094, -8237829, 19549651, -12169222, 22082623, 16147817,
                20613181, 13982702, -10339570, 5067943 },
        },
        {
            { -30505967, -3821767, 12074681, 13582412, -19877972, 2443951,
                -19719286, 12746132, 5331210, -10105944 },
            { 30528811, 3601899, -1957090, 4619785, -27361822, -15436388,
                24180793, -12570394, 27679908, -1648928 },
            { 9402404, -13957065, 32834043, 10838634, -26580150, -13237195,
                26653274, -8685565, 22611444, -12715406 },
        },
        {
            { 22190590, 1118029, 22736441, 15130463, -30460692, -5991321,
                19189625, -4648942, 4854859, 6622139 },
            { -8310738, -2953450, -8262579, -3388049, -10401731, -271929,
                13424426, -3567227, 26404409, 13001963 },
            { -31241838, -15415700, -2994250, 8939346, 11562230, -12840670,
                -26064365, -11621720, -15405155, 11020693 },
        },
        {
            { 1866042, -7949489, -7898649, -10301010, 12483315, 13477547,
                3175636, -12424163, 28761762, 1406734 },
            { -448555, -1777666, 13018551, 3194501, -9580420, -11161737,
                24760585, -4347088, 25577411, -13378680 },
            { -24290378, 4759345, -690653, -1852816, 2066747, 10693769,
                -29595790, 9884936, -9368926, 4745410 },
        },
        {
            { -9141284, 6049714, -19531061, -4341411, -31260798, 9944276,
                -15462008, -11311852, 10931924, -11931931 },
            { -16561513, 14112680, -8012645, 4817318, -8040464, -11414606,
                -22853429, 10856641, -20470770, 13434654 },
            { 22759489, -10073434, -16766264, -1871422, 13637442, -10168091,
                1765144, -12654326, 28445307, -5364710 },
        },
        {
            { 29875063, 12493613, 2795536, -3786330, 1710620, 15181182,
                -10195717, -8788675, 9074234, 1167180 },
            { -26205683, 11014233, -9842651, -2635485, -26908120, 7532294,
                -18716888, -9535498, 3843903, 9367684 },
            { -10969595, -6403711, 9591134, 9582310, 11349256, 108879, 16235123,
                8601684, -139197, 4242895 },
        },
    },
    {
        {
            { 22092954, -13191123, -2042793, -11968512, 32186753, -11517388,
                -6574341, 2470660, -27417366, 16625501 },
            { -11057722, 3042016, 13770083, -9257922, 584236, -544855, -7770857,
                2602725, -27351616, 14247413 },
            { 6314175, -10264892, -32772502, 15957557, -10157730, 168750,
                -8618807, 14290061, 27108877, -1180880 },
        },
        {
            { -8586597, -7170966, 13241782, 10960156, -32991015, -13794596,
                33547976, -11058889, -27148451, 981874 },
            { 22833440, 9293594, -32649448, -13618667, -9136966, 14756819,
                -22928859, -13970780, -10479804, -16197962 },
            { -7768587, 3326786, -28111797, 10783824, 19178761, 14905060,
                22680049, 13906969, -15933690, 3797899 },
        },
        {
            { 21721356, -4212746, -12206123, 9310182, -3882239, -13653110,
                23740224, -2709232, 20491983, -8042152 },
            { 9209270, -15135055, -13256557, -6167798, -731016, 15289673,
                25947805, 15286587, 30997318, -6703063 },
            { 7392032, 16618386, 23946583, -8039892, -13265164, -1533858,
                -14197445, -2321576, 17649998, -250080 },
        },
        {
            { -9301088, -14193827, 30609526, -3049543, -25175069, -1283752,
                -15241566, -9525724, -2233253, 7662146 },
            { -17558673, 1763594, -33114336, 15908610, -30040870, -12174295,
                7335080, -8472199, -3174674, 3440183 },
            { -19889700, -5977008, -24111293, -9688870, 10799743, -16571957,
                40450, -4431835, 4862400, 1133 },
        },
        {
            { -32856209, -7873957, -5422389, 14860950, -16319031, 7956142,
                7258061, 311861, -30594991, -7379421 },
            { -3773428, -1565936, 28985340, 7499440, 24445838, 9325937, 29727763,
                16527196, 18278453, 15405622 },
            { -4381906, 8508652, -19898366, -3674424, -5984453, 15149970,
                -13313598, 843523, -21875062, 13626197 },
        },
        {
            { 2281448, -13487055, -10915418, -2609910, 1879358, 16164207,
                -10783882, 3953792, 13340839, 15928663 },
            { 31727126, -7179855, -18437503, -8283652, 2875793, -16390330,
                -25269894, -7014826, -23452306, 5964753 },
            { 4100420, -5959452, -17179337, 6017714, -18705837, 12227141,
                -26684835, 11344144, 2538215, -7570755 },
        },
        {
            { -9433605, 6123113, 11159803, -2156608, 30016280, 14966241,
                -20474983, 1485421, -629256, -15958862 },
            { -26804558, 4260919, 11851389, 9658551, -32017107, 16367492,
                -20205425, -13191288, 11659922, -11115118 },
            { 26180396, 10015009, -30844224, -8581293, 5418197, 9480663, 2231568,
                -10170080, 33100372, -1306171 },
        },
        {
            { 15121113, -5201871, -10389905, 15427821, -27509937, -15992507,
                21670947, 4486675, -5931810, -14466380 },
            { 16166486, -9483733, -11104130, 6023908, -31926798, -1364923,
                2340060, -16254968, -10735770, -10039824 },
            { 28042865, -3557089, -12126526, 12259706, -3717498, -6945899,
                6766453, -8689599, 18036436, 5803270 },
        },
    },
    {
        {
            { -817581, 6763912, 11803561, 1585585, 10958447, -2671165, 23855391,
                4598332, -6159431, -14117438 },
            { -31031306, -14256194, 17332029, -2383520, 31312682, -5967183,
                696309, 50292, -20095739, 11763584 },
            { -594563, -2514283, -32234153, 12643980, 12650761, 14811489, 665117,
                -12613632, -19773211, -10713562 },
        },
        {
            { 30464590, -11262872, -4127476, -12734478, 19835327, -7105613,
                -24396175, 2075773, -17020157, 992471 },
            { 18357185, -6994433, 7766382, 16342475, -29324918, 411174, 14578841,
                8080033, -11574335, -10601610 },
            { 19598397, 10334610, 12555054, 2555664, 18821899, -10339780,
                21873263, 16014234, 26224780, 16452269 },
        },
        {
            { -30223925, 5145196, 5944548, 16385966, 3976735, 2009897, -11377804,
                -7618186, -20533829, 3698650 },
            { 14187449, 3448569, -10636236, -10810935, -22663880, -3433596,
                7268410, -10890444, 27394301, 12015369 },
            { 19695761, 16087646, 28032085, 12999827, 6817792, 11427614,
                20244189, -1312777, -13259127, -3402461 },
        },
        {
            { 30860103, 12735208, -1888245, -4699734, -16974906, 2256940,
                -8166013, 12298312, -8550524, -10393462 },
            { -5719826, -11245325, -1910649, 15569035, 26642876, -7587760,
                -5789354, -15118654, -4976164, 12651793 },
            { -2848395, 9953421, 11531313, -5282879, 26895123, -12697089,
                -13118820, -16517902, 9768698, -2533218 },
        },
        {
            { -24719459, 1894651, -287698, -4704085, 15348719, -8156530,
                32767513, 12765450, 4940095, 10678226 },
            { 18860224, 15980149, -18987240, -1562570, -26233012, -11071856,
                -7843882, 13944024, -24372348, 16582019 },
            { -15504260, 4970268, -29893044, 4175593, -20993212, -2199756,
                -11704054, 15444560, -11003761, 7989037 },
        },
        {
            { 31490452, 5568061, -2412803, 2182383, -32336847, 4531686,
                -32078269, 6200206, -19686113, -14800171 },
            { -17308668, -15879940, -31522777, -2831, -32887382, 16375549,
                8680158, -16371713, 28550068, -6857132 },
            { -28126887, -5688091, 16837845, -1820458, -6850681, 12700016,
                -30039981, 4364038, 1155602, 5988841 },
        },
        {
            { 21890435, -13272907, -12624011, 12154349, -7831873, 15300496,
                23148983, -4470481, 24618407, 8283181 },
            { -33136107, -10512751, 9975416, 6841041, -31559793, 16356536,
                3070187, -7025928, 1466169, 10740210 },
            { -1509399, -15488185, -13503385, -10655916, 32799044, 909394,
                -13938903, -5779719, -32164649, -15327040 },
        },
        {
            { 3960823, -14267803, -28026090, -15918051, -19404858, 13146868,
                15567327, 951507, -3260321, -573935 },
            { 24740841, 5052253, -30094131, 8961361, 25877428, 6165135,
                -24368180, 14397372, -7380369, -6144105 },
            { -28888365, 3510803, -28103278, -1158478, -11238128, -10631454,
                -15441463, -14453128, -1625486, -6494814 },
        },
    },
    {
        {
            { 793299, -9230478, 8836302, -6235707, -27360908, -2369593, 33152843,
                -4885251, -9906200, -621852 },
            { 5666233, 525582, 20782575, -8038419, -24538499, 14657740, 16099374,
                1468826, -6171428, -15186581 },
            { -4859255, -3779343, -2917758, -6748019, 7778750, 11688288,
                -30404353, -9871238, -1558923, -9863646 },
        },
        {
            { 10896332, -7719704, 824275, 472601, -19460308, 3009587, 25248958,
                14783338, -30581476, -15757844 },
            { 10566929, 12612572, -31944212, 11118703, -12633376, 12362879,
                21752402, 8822496, 24003793, 14264025 },
            { 27713862, -7355973, -11008240, 9227530, 27050101, 2504721,
                23886875, -13117525, 13958495, -5732453 },
        },
        {
            { -23481610, 4867226, -27247128, 3900521, 29838369, -8212291,
                -31889399, -10041781, 7340521, -15410068 },
            { 4646514, -8011124, -22766023, -11532654, 23184553, 8566613,
                31366726, -1381061, -15066784, -10375192 },
            { -17270517, 12723032, -16993061, 14878794, 21619651, -6197576,
                27584817, 3093888, -8843694, 3849921 },
        },
        {
            { -9064912, 2103172, 25561640, -15125738, -5239824, 9582958,
                32477045, -9017955, 5002294, -15550259 },
            { -12057553, -11177906, 21115585, -13365155, 8808712, -12030708,
                16489530, 13378448, -25845716, 12741426 },
            { -5946367, 10645103, -30911586, 15390284, -3286982, -7118677,
                24306472, 15852464, 28834118, -7646072 },
        },
        {
            { -17335748, -9107057, -24531279, 9434953, -8472084, -583362,
                -13090771, 455841, 20461858, 5491305 },
            { 13669248, -16095482, -12481974, -10203039, -14569770, -11893198,
                -24995986, 11293807, -28588204, -9421832 },
            { 28497928, 6272777, -33022994, 14470570, 8906179, -1225630,
                18504674, -14165166, 29867745, -8795943 },
        },
        {
            { -16207023, 13517196, -27799630, -13697798, 24009064, -6373891,
                -6367600, -13175392, 22853429, -4012011 },
            { 24191378, 16712145, -13931797, 15217831, 14542237, 1646131,
                18603514, -11037887, 12876623, -2112447 },
            { 17902668, 4518229, -411702, -2829247, 26878217, 5258055, -12860753,
                608397, 16031844, 3723494 },
        },
        {
            { -28632773, 12763728, -20446446, 7577504, 33001348, -13017745,
                17558842, -7872890, 23896954, -4314245 },
            { -20005381, -12011952, 31520464, 605201, 2543521, 5991821, -2945064,
                7229064, -9919646, -8826859 },
            { 28816045, 298879, -28165016, -15920938, 19000928, -1665890,
                -12680833, -2949325, -18051778, -2082915 },
        },
        {
            { 16000882, -344896, 3493092, -11447198, -29504595, -13159789,
                12577740, 16041268, -19715240, 7847707 },
            { 10151868, 10572098, 27312476, 7922682, 14825339, 4723128,
                -32855931, -6519018, -10020567, 3852848 },
            { -11430470, 15697596, -21121557, -4420647, 5386314, 15063598,
                16514493, -15932110, 29330899, -15076224 },
        },
    },
    {
        {
            { -25499735, -4378794, -15222908, -6901211, 16615731, 2051784,
                3303702, 15490, -27548796, 12314391 },
            { 15683520, -6003043, 18109120, -9980648, 15337968, -5997823,
                -16717435, 15921866, 16103996, -3731215 },
            { -23169824, -10781249, 13588192, -1628807, -3798557, -1074929,
                -19273607, 5402699, -29815713, -9841101 },
        },
        {
            { 23190676, 2384583, -32714340, 3462154, -29903655, -1529132,
                -11266856, 8911517, -25205859, 2739713 },
            { 21374101, -3554250, -33524649, 9874411, 15377179, 11831242,
                -33529904, 6134907, 4931255, 11987849 },
            { -7732, -2978858, -16223486, 7277597, 105524, -322051, -31480539,
                13861388, -30076310, 10117930 },
        },
        {
            { -29501170, -10744872, -26163768, 13051539, -25625564, 5089643,
                -6325503, 6704079, 12890019, 15728940 },
            { -21972360, -11771379, -951059, -4418840, 14704840, 2695116, 903376,
                -10428139, 12885167, 8311031 },
            { -17516482, 5352194, 10384213, -13811658, 7506451, 13453191,
                26423267, 4384730, 1888765, -5435404 },
        },
        {
            { -25817338, -3107312, -13494599, -3182506, 30896459, -13921729,
                -32251644, -12707869, -19464434, -3340243 },
            { -23607977, -2665774, -526091, 4651136, 5765089, 4618330, 6092245,
                14845197, 17151279, -9854116 },
            { -24830458, -12733720, -15165978, 10367250, -29530908, -265356,
                22825805, -7087279, -16866484, 16176525 },
        },
        {
            { -23583256, 6564961, 20063689, 3798228, -4740178, 7359225, 2006182,
                -10363426, -28746253, -10197509 },
            { -10626600, -4486402, -13320562, -5125317, 3432136, -6393229,
                23632037, -1940610, 32808310, 1099883 },
            { 15030977, 5768825, -27451236, -2887299, -6427378, -15361371,
                -15277896, -6809350, 2051441, -15225865 },
        },
        {
            { -3362323, -7239372, 7517890, 9824992, 23555850, 295369, 5148398,
                -14154188, -22686354, 16633660 },
            { 4577086, -16752288, 13249841, -15304328, 19958763, -14537274,
                18559670, -10759549, 8402478, -9864273 },
            { -28406330, -1051581, -26790155, -907698, -17212414, -11030789,
                9453451, -14980072, 17983010, 9967138 },
        },
        {
            { -25762494, 6524722, 26585488, 9969270, 24709298, 1220360, -1677990,
                7806337, 17507396, 3651560 },
            { -10420457, -4118111, 14584639, 15971087, -15768321, 8861010,
                26556809, -5574557, -18553322, -11357135 },
            { 2839101, 14284142, 4029895, 3472686, 14402957, 12689363, -26642121,
                8459447, -5605463, -7621941 },
        },
        {
            { -4839289, -3535444, 9744961, 2871048, 25113978, 3187018, -25110813,
                -849066, 17258084, -7977739 },
            { 18164541, -10595176, -17154882, -1542417, 19237078, -9745295,
                23357533, -15217008, 26908270, 12150756 },
            { -30264870, -7647865, 5112249, -7036672, -1499807, -6974257, 43168,
                -5537701, -32302074, 16215819 },
        },
    },
    {
        {
            { -6898905, 9824394, -12304779, -4401089, -31397141, -6276835,
                32574489, 12532905, -7503072, -8675347 },
            { -27343522, -16515468, -27151524, -10722951, 946346, 16291093,
                254968, 7168080, 21676107, -1943028 },
            { 21260961, -8424752, -16831886, -11920822, -23677961, 3968121,
                -3651949, -6215466, -3556191, -7913075 },
        },
        {
            { 16544754, 13250366, -16804428, 15546242, -4583003, 12757258,
                -2462308, -8680336, -18907032, -9662799 },
            { -2415239, -15577728, 18312303, 4964443, -15272530, -12653564,
                26820651, 16690659, 25459437, -4564609 },
            { -25144690, 11425020, 28423002, -11020557, -6144921, -15826224,
                9142795, -2391602, -6432418, -1644817 },
        },
        {
            { -23104652, 6253476, 16964147, -3768872, -25113972, -12296437,
                -27457225, -16344658, 6335692, 7249989 },
            { -30333227, 13979675, 7503222, -12368314, -11956721, -4621693,
                -30272269, 2682242, 25993170, -12478523 },
            { 4364628, 5930691, 32304656, -10044554, -8054781, 15091131,
                22857016, -10598955, 31820368, 15075278 },
        },
        {
            { 31879134, -8918693, 17258761, 90626, -8041836, -4917709, 24162788,
                -9650886, -17970238, 12833045 },
            { 19073683, 14851414, -24403169, -11860168, 7625278, 11091125,
                -19619190, 2074449, -9413939, 14905377 },
            { 24483667, -11935567, -2518866, -11547418, -1553130, 15355506,
                -25282080, 9253129, 27628530, -7555480 },
        },
        {
            { 17597607, 8340603, 19355617, 552187, 26198470, -3176583, 4593324,
                -9157582, -14110875, 15297016 },
            { 510886, 14337390, -31785257, 16638632, 6328095, 2713355, -20217417,
                -11864220, 8683221, 2921426 },
            { 18606791, 11874196, 27155355, -5281482, -24031742, 6265446,
                -25178240, -1278924, 4674690, 13890525 },
        },
        {
            { 13609624, 13069022, -27372361, -13055908, 24360586, 9592974,
                14977157, 9835105, 4389687, 288396 },
            { 9922506, -519394, 13613107, 5883594, -18758345, -434263, -12304062,
                8317628, 23388070, 16052080 },
            { 12720016, 11937594, -31970060, -5028689, 26900120, 8561328,
                -20155687, -11632979, -14754271, -10812892 },
        },
        {
            { 15961858, 14150409, 26716931, -665832, -22794328, 13603569,
                11829573, 7467844, -28822128, 929275 },
            { 11038231, -11582396, -27310482, -7316562, -10498527, -16307831,
                -23479533, -9371869, -21393143, 2465074 },
            { 20017163, -4323226, 27915242, 1529148, 12396362, 15675764,
                13817261, -9658066, 2463391, -4622140 },
        },
        {
            { -16358878, -12663911, -12065183, 4996454, -1256422, 1073572,
                9583558, 12851107, 4003896, 12673717 },
            { -1731589, -15155870, -3262930, 16143082, 19294135, 13385325,
                14741514, -9103726, 7903886, 2348101 },
            { 24536016, -16515207, 12715592, -3862155, 1511293, 10047386,
                -3842346, -7129159, -28377538, 10048127 },
        },
    },
    {
        {
            { -12622226, -6204820, 30718825, 2591312, -10617028, 12192840,
                18873298, -7297090, -32297756, 15221632 },
            { -26478122, -11103864, 11546244, -1852483, 9180880, 7656409,
                -21343950, 2095755, 29769758, 6593415 },
            { -31994208, -2907461, 4176912, 3264766, 12538965, -868111, 26312345,
                -6118678, 30958054, 8292160 },
        },
        {
            { 31429822, -13959116, 29173532, 15632448, 12174511, -2760094,
                32808831, 3977186, 26143136, -3148876 },
            { 22648901, 1402143, -22799984, 13746059, 7936347, 365344, -8668633,
                -1674433, -3758243, -2304625 },
            { -15491917, 8012313, -2514730, -12702462, -23965846, -10254029,
                -1612713, -1535569, -16664475, 8194478 },
        },
        {
            { 27338066, -7507420, -7414224, 10140405, -19026427, -6589889,
                27277191, 8855376, 28572286, 3005164 },
            { 26287124, 4821776, 25476601, -4145903, -3764513, -15788984,
                -18008582, 1182479, -26094821, -13079595 },
            { -7171154, 3178080, 23970071, 6201893, -17195577, -4489192,
                -21876275, -13982627, 32208683, -1198248 },
        },
        {
            { -16657702, 2817643, -10286362, 14811298, 6024667, 13349505,
                -27315504, -10497842, -27672585, -11539858 },
            { 15941029, -9405932, -21367050, 8062055, 31876073, -238629,
                -15278393, -1444429, 15397331, -4130193 },
            { 8934485, -13485467, -23286397, -13423241, -32446090, 14047986,
                31170398, -1441021, -27505566, 15087184 },
        },
        {
            { -18357243, -2156491, 24524913, -16677868, 15520427, -6360776,
                -15502406, 11461896, 16788528, -5868942 },
            { -1947386, 16013773, 21750665, 3714552, -17401782, -16055433,
                -3770287, -10323320, 31322514, -11615635 },
            { 21426655, -5650218, -13648287, -5347537, -28812189, -4920970,
                -18275391, -14621414, 13040862, -12112948 },
        },
        {
            { 11293895, 12478086, -27136401, 15083750, -29307421, 14748872,
                14555558, -13417103, 1613711, 4896935 },
            { -25894883, 15323294, -8489791, -8057900, 25967126, -13425460,
                2825960, -4897045, -23971776, -11267415 },
            { -15924766, -5229880, -17443532, 6410664, 3622847, 10243618,
                20615400, 12405433, -23753030, -8436416 },
        },
        {
            { -7091295, 12556208, -20191352, 9025187, -17072479, 4333801,
                4378436, 2432030, 23097949, -566018 },
            { 4565804, -16025654, 20084412, -7842817, 1724999, 189254, 24767264,
                10103221, -18512313, 2424778 },
            { 366633, -11976806, 8173090, -6890119, 30788634, 5745705, -7168678,
                1344109, -3642553, 12412659 },
        },
        {
            { -24001791, 7690286, 14929416, -168257, -32210835, -13412986,
                24162697, -15326504, -3141501, 11179385 },
            { 18289522, -14724954, 8056945, 16430056, -21729724, 7842514,
                -6001441, -1486897, -18684645, -11443503 },
            { 476239, 6601091, -6152790, -9723375, 17503545, -4863900, 27672959,
                13403813, 11052904, 5219329 },
        },
    },
    {
        {
            { 20678546, -8375738, -32671898, 8849123, -5009758, 14574752,
                31186971, -3973730, 9014762, -8579056 },
            { -13644050, -10350239, -15962508, 5075808, -1514661, -11534600,
                -33102500, 9160280, 8473550, -3256838 },
            { 24900749, 14435722, 17209120, -15292541, -22592275, 9878983,
                -7689309, -16335821, -24568481, 11788948 },
        },
        {
            { -3118155, -11395194, -13802089, 14797441, 9652448, -6845904,
                -20037437, 10410733, -24568470, -1458691 },
            { -15659161, 16736706, -22467150, 10215878, -9097177, 7563911,
                11871841, -12505194, -18513325, 8464118 },
            { -23400612, 8348507, -14585951, -861714, -3950205, -6373419,
                14325289, 8628612, 33313881, -8370517 },
        },
        {
            { -20186973, -4967935, 22367356, 5271547, -1097117, -4788838,
                -24805667, -10236854, -8940735, -5818269 },
            { -6948785, -1795212, -32625683, -16021179, 32635414, -7374245,
                15989197, -12838188, 28358192, -4253904 },
            { -23561781, -2799059, -32351682, -1661963, -9147719, 10429267,
                -16637684, 4072016, -5351664, 5596589 },
        },
        {
            { -28236598, -3390048, 12312896, 6213178, 3117142, 16078565,
                29266239, 2557221, 1768301, 15373193 },
            { -7243358, -3246960, -4593467, -7553353, -127927, -912245, -1090902,
                -4504991, -24660491, 3442910 },
            { -30210571, 5124043, 14181784, 8197961, 18964734, -11939093,
                22597931, 7176455, -18585478, 13365930 },
        },
        {
            { -7877390, -1499958, 8324673, 4690079, 6261860, 890446, 24538107,
                -8570186, -9689599, -3031667 },
            { 25008904, -10771599, -4305031, -9638010, 16265036, 15721635,
                683793, -11823784, 15723479, -15163481 },
            { -9660625, 12374379, -27006999, -7026148, -7724114, -12314514,
                11879682, 5400171, 519526, -1235876 },
        },
        {
            { 22258397, -16332233, -7869817, 14613016, -22520255, -2950923,
                -20353881, 7315967, 16648397, 7605640 },
            { -8081308, -8464597, -8223311, 9719710, 19259459, -15348212,
                23994942, -5281555, -9468848, 4763278 },
            { -21699244, 9220969, -15730624, 1084137, -25476107, -2852390,
                31088447, -7764523, -11356529, 728112 },
        },
        {
            { 26047220, -11751471, -6900323, -16521798, 24092068, 9158119,
                -4273545, -12555558, -29365436, -5498272 },
            { 17510331, -322857, 5854289, 8403524, 17133918, -3112612, -28111007,
                12327945, 10750447, 10014012 },
            { -10312768, 3936952, 9156313, -8897683, 16498692, -994647,
                -27481051, -666732, 3424691, 7540221 },
        },
        {
            { 30322361, -6964110, 11361005, -4143317, 7433304, 4989748, -7071422,
                -16317219, -9244265, 15258046 },
            { 13054562, -2779497, 19155474, 469045, -12482797, 4566042, 5631406,
                2711395, 1062915, -5136345 },
            { -19240248, -11254599, -29509029, -7499965, -5835763, 13005411,
                -6066489, 12194497, 32960380, 1459310 },
        },
    },
    {
        {
            { 19852034, 7027924, 23669353, 10020366, 8586503, -6657907, 394197,
                -6101885, 18638003, -11174937 },
            { 31395534, 15098109, 26581030, 8030562, -16527914, -5007134,
                9012486, -7584354, -6643087, -5442636 },
            { -9192165, -2347377, -1997099, 4529534, 25766844, 607986, -13222,
                9677543, -32294889, -6456008 },
        },
        {
            { -2444496, -149937, 29348902, 8186665, 1873760, 12489863, -30934579,
                -7839692, -7852844, -8138429 },
            { -15236356, -15433509, 7766470, 746860, 26346930, -10221762,
                -27333451, 10754588, -9431476, 5203576 },
            { 31834314, 14135496, -770007, 5159118, 20917671, -16768096,
                -7467973, -7337524, 31809243, 7347066 },
        },
        {
            { -9606723, -11874240, 20414459, 13033986, 13716524, -11691881,
                19797970, -12211255, 15192876, -2087490 },
            { -12663563, -2181719, 1168162, -3804809, 26747877, -14138091,
                10609330, 12694420, 33473243, -13382104 },
            { 33184999, 11180355, 15832085, -11385430, -1633671, 225884,
                15089336, -11023903, -6135662, 14480053 },
        },
        {
            { 31308717, -5619998, 31030840, -1897099, 15674547, -6582883,
                5496208, 13685227, 27595050, 8737275 },
            { -20318852, -15150239, 10933843, -16178022, 8335352, -7546022,
                -31008351, -12610604, 26498114, 66511 },
            { 22644454, -8761729, -16671776, 4884562, -3105614, -13559366,
                30540766, -4286747, -13327787, -7515095 },
        },
        {
            { -28017847, 9834845, 18617207, -2681312, -3401956, -13307506,
                8205540, 13585437, -17127465, 15115439 },
            { 23711543, -672915, 31206561, -8362711, 6164647, -9709987,
                -33535882, -1426096, 8236921, 16492939 },
            { -23910559, -13515526, -26299483, -4503841, 25005590, -7687270,
                19574902, 10071562, 6708380, -6222424 },
        },
        {
            { 2101391, -4930054, 19702731, 2367575, -15427167, 1047675, 5301017,
                9328700, 29955601, -11678310 },
            { 3096359, 9271816, -21620864, -15521844, -14847996, -7592937,
                -25892142, -12635595, -9917575, 6216608 },
            { -32615849, 338663, -25195611, 2510422, -29213566, -13820213,
                24822830, -6146567, -26767480, 7525079 },
        },
        {
            { -23066649, -13985623, 16133487, -7896178, -3389565, 778788,
                -910336, -2782495, -19386633, 11994101 },
            { 21691500, -13624626, -641331, -14367021, 3285881, -3483596,
                -25064666, 9718258, -7477437, 13381418 },
            { 18445390, -4202236, 14979846, 11622458, -1727110, -3582980,
                23111648, -6375247, 28535282, 15779576 },
        },
        {
            { 30098053, 3089662, -9234387, 16662135, -21306940, 11308411,
                -14068454, 12021730, 9955285, -16303356 },
            { 9734894, -14576830, -7473633, -9138735, 2060392, 11313496,
                -18426029, 9924399, 20194861, 13380996 },
            { -26378102, -7965207, -22167821, 15789297, -18055342, -6168792,
                -1984914, 15707771, 26342023, 10146099 },
        },
    },
    {
        {
            { -26016874, -219943, 21339191, -41388, 19745256, -2878700,
                -29637280, 2227040, 21612326, -545728 },
            { -13077387, 1184228, 23562814, -5970442, -20351244, -6348714,
                25764461, 12243797, -20856566, 11649658 },
            { -10031494, 11262626, 27384172, 2271902, 26947504, -15997771, 39944,
                6114064, 33514190, 2333242 },
        },
        {
            { -21433588, -12421821, 8119782, 7219913, -21830522, -9016134,
                -6679750, -12670638, 24350578, -13450001 },
            { -4116307, -11271533, -23886186, 4843615, -30088339, 690623,
                -31536088, -10406836, 8317860, 12352766 },
            { 18200138, -14475911, -33087759, -2696619, -23702521, -9102511,
                -23552096, -2287550, 20712163, 6719373 },
        },
        {
            { 26656208, 6075253, -7858556, 1886072, -28344043, 4262326, 11117530,
                -3763210, 26224235, -3297458 },
            { -17168938, -14854097, -3395676, -16369877, -19954045, 14050420,
                21728352, 9493610, 18620611, -16428628 },
            { -13323321, 13325349, 11432106, 5964811, 18609221, 6062965,
                -5269471, -9725556, -30701573, -16479657 },
        },
        {
            { -23860538, -11233159, 26961357, 1640861, -32413112, -16737940,
                12248509, -5240639, 13735342, 1934062 },
            { 25089769, 6742589, 17081145, -13406266, 21909293, -16067981,
                -15136294, -3765346, -21277997, 5473616 },
            { 31883677, -7961101, 1083432, -11572403, 22828471, 13290673,
                -7125085, 12469656, 29111212, -5451014 },
        },
        {
            { 24244947, -15050407, -26262976, 2791540, -14997599, 16666678,
                24367466, 6388839, -10295587, 452383 },
            { -25640782, -3417841, 5217916, 16224624, 19987036, -4082269,
                -24236251, -5915248, 15766062, 8407814 },
            { -20406999, 13990231, 15495425, 16395525, 5377168, 15166495,
                -8917023, -4388953, -8067909, 2276718 },
        },
        {
            { 30157918, 12924066, -17712050, 9245753, 19895028, 3368142,
                -23827587, 5096219, 22740376, -7303417 },
            { 2041139, -14256350, 7783687, 13876377, -25946985, -13352459,
                24051124, 13742383, -15637599, 13295222 },
            { 33338237, -8505733, 12532113, 7977527, 9106186, -1715251,
                -17720195, -4612972, -4451357, -14669444 },
        },
        {
            { -20045281, 5454097, -14346548, 6447146, 28862071, 1883651,
                -2469266, -4141880, 7770569, 9620597 },
            { 23208068, 7979712, 33071466, 8149229, 1758231, -10834995, 30945528,
                -1694323, -33502340, -14767970 },
            { 1439958, -16270480, -1079989, -793782, 4625402, 10647766, -5043801,
                1220118, 30494170, -11440799 },
        },
        {
            { -5037580, -13028295, -2970559, -3061767, 15640974, -6701666,
                -26739026, 926050, -1684339, -13333647 },
            { 13908495, -3549272, 30919928, -6273825, -21521863, 7989039,
                9021034, 9078865, 3353509, 4033511 },
            { -29663431, -15113610, 32259991, -344482, 24295849, -12912123,
                23161163, 8839127, 27485041, 7356032 },
        },
    },
    {
        {
            { 9661027, 705443, 11980065, -5370154, -1628543, 14661173, -6346142,
                2625015, 28431036, -16771834 },
            { -23839233, -8311415, -25945511, 7480958, -17681669, -8354183,
                -22545972, 14150565, 15970762, 4099461 },
            { 29262576, 16756590, 26350592, -8793563, 8529671, -11208050,
                13617293, -9937143, 11465739, 8317062 },
        },
        {
            { -25493081, -6962928, 32500200, -9419051, -23038724, -2302222,
                14898637, 3848455, 20969334, -5157516 },
            { -20384450, -14347713, -18336405, 13884722, -33039454, 2842114,
                -21610826, -3649888, 11177095, 14989547 },
            { -24496721, -11716016, 16959896, 2278463, 12066309, 10137771,
                13515641, 2581286, -28487508, 9930240 },
        },
        {
            { -17751622, -2097826, 16544300, -13009300, -15914807, -14949081,
                18345767, -13403753, 16291481, -5314038 },
            { -33229194, 2553288, 32678213, 9875984, 8534129, 6889387, -9676774,
                6957617, 4368891, 9788741 },
            { 16660756, 7281060, -10830758, 12911820, 20108584, -8101676,
                -21722536, -8613148, 16250552, -11111103 },
        },
        {
            { -19765507, 2390526, -16551031, 14161980, 1905286, 6414907, 4689584,
                10604807, -30190403, 4782747 },
            { -1354539, 14736941, -7367442, -13292886, 7710542, -14155590,
                -9981571, 4383045, 22546403, 437323 },
            { 31665577, -12180464, -16186830, 1491339, -18368625, 3294682,
                27343084, 2786261, -30633590, -14097016 },
        },
        {
            { -14467279, -683715, -33374107, 7448552, 19294360, 14334329,
                -19690631, 2355319, -19284671, -6114373 },
            { 15121312, -15796162, 6377020, -6031361, -10798111, -12957845,
                18952177, 15496498, -29380133, 11754228 },
            { -2637277, -13483075, 8488727, -14303896, 12728761, -1622493,
                7141596, 11724556, 22761615, -10134141 },
        },
        {
            { 16918416, 11729663, -18083579, 3022987, -31015732, -13339659,
                -28741185, -12227393, 32851222, 11717399 },
            { 11166634, 7338049, -6722523, 4531520, -29468672, -7302055,
                31474879, 3483633, -1193175, -4030831 },
            { -185635, 9921305, 31456609, -13536438, -12013818, 13348923,
                33142652, 6546660, -19985279, -3948376 },
        },
        {
            { -32460596, 11266712, -11197107, -7899103, 31703694, 3855903,
                -8537131, -12833048, -30772034, -15486313 },
            { -18006477, 12709068, 3991746, -6479188, -21491523, -10550425,
                -31135347, -16049879, 10928917, 3011958 },
            { -6957757, -15594337, 31696059, 334240, 29576716, 14796075,
                -30831056, -12805180, 18008031, 10258577 },
        },
        {
            { -22448644, 15655569, 7018479, -4410003, -30314266, -1201591,
                -1853465, 1367120, 25127874, 6671743 },
            { 29701166, -14373934, -10878120, 9279288, -17568, 13127210,
                21382910, 11042292, 25838796, 4642684 },
            { -20430234, 14955537, -24126347, 8124619, -5369288, -5990470,
                30468147, -13900640, 18423289, 4177476 },
        },
    },
};
#endif

static uint8_t negative(signed char b)
{
    uint32_t x = b;

    x >>= 31; /* 1: yes; 0: no */
    return x;
}

static void table_select(ge_precomp *t, int pos, signed char b)
{
    ge_precomp minust;
    uint8_t bnegative = negative(b);
    uint8_t babs = b - ((uint8_t)((-bnegative) & b) << 1);

    ge_precomp_0(t);
    cmov(t, &k25519Precomp[pos][0], equal(babs, 1));
    cmov(t, &k25519Precomp[pos][1], equal(babs, 2));
    cmov(t, &k25519Precomp[pos][2], equal(babs, 3));
    cmov(t, &k25519Precomp[pos][3], equal(babs, 4));
    cmov(t, &k25519Precomp[pos][4], equal(babs, 5));
    cmov(t, &k25519Precomp[pos][5], equal(babs, 6));
    cmov(t, &k25519Precomp[pos][6], equal(babs, 7));
    cmov(t, &k25519Precomp[pos][7], equal(babs, 8));
    fe_copy(minust.yplusx, t->yminusx);
    fe_copy(minust.yminusx, t->yplusx);
    fe_neg(minust.xy2d, t->xy2d);
    cmov(t, &minust, bnegative);
}

/*
 * h = a * B
 *
 * where a = a[0]+256*a[1]+...+256^31 a[31]
 * B is the Ed25519 base point (x,4/5) with x positive.
 *
 * Preconditions:
 *   a[31] <= 127
 */
static void ge_scalarmult_base(ge_p3 *h, const uint8_t *a)
{
    signed char e[64];
    signed char carry;
    ge_p1p1 r;
    ge_p2 s;
    ge_precomp t;
    int i;

    for (i = 0; i < 32; ++i) {
        e[2 * i + 0] = (a[i] >> 0) & 15;
        e[2 * i + 1] = (a[i] >> 4) & 15;
    }
    /* each e[i] is between 0 and 15 */
    /* e[63] is between 0 and 7 */

    carry = 0;
    for (i = 0; i < 63; ++i) {
        e[i] += carry;
        carry = e[i] + 8;
        carry >>= 4;
        e[i] -= carry << 4;
    }
    e[63] += carry;
    /* each e[i] is between -8 and 8 */

    ge_p3_0(h);
    for (i = 1; i < 64; i += 2) {
        table_select(&t, i / 2, e[i]);
        ge_madd(&r, h, &t);
        ge_p1p1_to_p3(h, &r);
    }

    ge_p3_dbl(&r, h);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p3(h, &r);

    for (i = 0; i < 64; i += 2) {
        table_select(&t, i / 2, e[i]);
        ge_madd(&r, h, &t);
        ge_p1p1_to_p3(h, &r);
    }

    OPENSSL_cleanse(e, sizeof(e));
}

#if !defined(BASE_2_51_IMPLEMENTED)
/*
 * Replace (f,g) with (g,f) if b == 1;
 * replace (f,g) with (f,g) if b == 0.
 *
 * Preconditions: b in {0,1}.
 */
static void fe_cswap(fe f, fe g, unsigned int b)
{
    size_t i;

    b = 0 - b;
    for (i = 0; i < 10; i++) {
        int32_t x = f[i] ^ g[i];
        x &= b;
        f[i] ^= x;
        g[i] ^= x;
    }
}

/*
 * h = f * 121666
 *
 * Can overlap h with f.
 *
 * Preconditions:
 *    |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 */
static void fe_mul121666(fe h, fe f)
{
    int32_t f0 = f[0];
    int32_t f1 = f[1];
    int32_t f2 = f[2];
    int32_t f3 = f[3];
    int32_t f4 = f[4];
    int32_t f5 = f[5];
    int32_t f6 = f[6];
    int32_t f7 = f[7];
    int32_t f8 = f[8];
    int32_t f9 = f[9];
    int64_t h0 = f0 * (int64_t)121666;
    int64_t h1 = f1 * (int64_t)121666;
    int64_t h2 = f2 * (int64_t)121666;
    int64_t h3 = f3 * (int64_t)121666;
    int64_t h4 = f4 * (int64_t)121666;
    int64_t h5 = f5 * (int64_t)121666;
    int64_t h6 = f6 * (int64_t)121666;
    int64_t h7 = f7 * (int64_t)121666;
    int64_t h8 = f8 * (int64_t)121666;
    int64_t h9 = f9 * (int64_t)121666;
    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;

    carry9 = h9 + (1 << 24);
    h0 += (carry9 >> 25) * 19;
    h9 -= carry9 & kTop39Bits;
    carry1 = h1 + (1 << 24);
    h2 += carry1 >> 25;
    h1 -= carry1 & kTop39Bits;
    carry3 = h3 + (1 << 24);
    h4 += carry3 >> 25;
    h3 -= carry3 & kTop39Bits;
    carry5 = h5 + (1 << 24);
    h6 += carry5 >> 25;
    h5 -= carry5 & kTop39Bits;
    carry7 = h7 + (1 << 24);
    h8 += carry7 >> 25;
    h7 -= carry7 & kTop39Bits;

    carry0 = h0 + (1 << 25);
    h1 += carry0 >> 26;
    h0 -= carry0 & kTop38Bits;
    carry2 = h2 + (1 << 25);
    h3 += carry2 >> 26;
    h2 -= carry2 & kTop38Bits;
    carry4 = h4 + (1 << 25);
    h5 += carry4 >> 26;
    h4 -= carry4 & kTop38Bits;
    carry6 = h6 + (1 << 25);
    h7 += carry6 >> 26;
    h6 -= carry6 & kTop38Bits;
    carry8 = h8 + (1 << 25);
    h9 += carry8 >> 26;
    h8 -= carry8 & kTop38Bits;

    h[0] = (int32_t)h0;
    h[1] = (int32_t)h1;
    h[2] = (int32_t)h2;
    h[3] = (int32_t)h3;
    h[4] = (int32_t)h4;
    h[5] = (int32_t)h5;
    h[6] = (int32_t)h6;
    h[7] = (int32_t)h7;
    h[8] = (int32_t)h8;
    h[9] = (int32_t)h9;
}

static void x25519_scalar_mult_generic(uint8_t out[32],
    const uint8_t scalar[32],
    const uint8_t point[32])
{
    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    uint8_t e[32];
    unsigned swap = 0;
    int pos;

    memcpy(e, scalar, 32);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    fe_frombytes(x1, point);
    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    for (pos = 254; pos >= 0; --pos) {
        unsigned b = 1 & (e[pos / 8] >> (pos & 7));
        swap ^= b;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;
        fe_sub(tmp0, x3, z3);
        fe_sub(tmp1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, tmp0, x2);
        fe_mul(z2, z2, tmp1);
        fe_sq(tmp0, tmp1);
        fe_sq(tmp1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, tmp1, tmp0);
        fe_sub(tmp1, tmp1, tmp0);
        fe_sq(z2, z2);
        fe_mul121666(z3, tmp1);
        fe_sq(x3, x3);
        fe_add(tmp0, tmp0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, tmp1, tmp0);
    }

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);

    OPENSSL_cleanse(e, sizeof(e));
}

static void x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32],
    const uint8_t point[32])
{
    x25519_scalar_mult_generic(out, scalar, point);
}
#endif

static void slide(signed char *r, const uint8_t *a)
{
    int i;
    int b;
    int k;

    for (i = 0; i < 256; ++i) {
        r[i] = 1 & (a[i >> 3] >> (i & 7));
    }

    for (i = 0; i < 256; ++i) {
        if (r[i]) {
            for (b = 1; b <= 6 && i + b < 256; ++b) {
                if (r[i + b]) {
                    if (r[i] + (r[i + b] << b) <= 15) {
                        r[i] += r[i + b] << b;
                        r[i + b] = 0;
                    } else if (r[i] - (r[i + b] << b) >= -15) {
                        r[i] -= r[i + b] << b;
                        for (k = i + b; k < 256; ++k) {
                            if (!r[k]) {
                                r[k] = 1;
                                break;
                            }
                            r[k] = 0;
                        }
                    } else {
                        break;
                    }
                }
            }
        }
    }
}

#if defined(BASE_2_51_IMPLEMENTED)
static const ge_precomp Bi[8] = {
    {
        { 0x493c6f58c3b85, 0x0df7181c325f7, 0x0f50b0b3e4cb7,
            0x5329385a44c32, 0x07cf9d3a33d4b },
        { 0x03905d740913e, 0x0ba2817d673a2, 0x23e2827f4e67c,
            0x133d2e0c21a34, 0x44fd2f9298f81 },
        { 0x11205877aaa68, 0x479955893d579, 0x50d66309b67a0,
            0x2d42d0dbee5ee, 0x6f117b689f0c6 },
    },
    {
        { 0x5b0a84cee9730, 0x61d10c97155e4, 0x4059cc8096a10,
            0x47a608da8014f, 0x7a164e1b9a80f },
        { 0x11fe8a4fcd265, 0x7bcb8374faacc, 0x52f5af4ef4d4f,
            0x5314098f98d10, 0x2ab91587555bd },
        { 0x6933f0dd0d889, 0x44386bb4c4295, 0x3cb6d3162508c,
            0x26368b872a2c6, 0x5a2826af12b9b },
    },
    {
        { 0x2bc4408a5bb33, 0x078ebdda05442, 0x2ffb112354123,
            0x375ee8df5862d, 0x2945ccf146e20 },
        { 0x182c3a447d6ba, 0x22964e536eff2, 0x192821f540053,
            0x2f9f19e788e5c, 0x154a7e73eb1b5 },
        { 0x3dbf1812a8285, 0x0fa17ba3f9797, 0x6f69cb49c3820,
            0x34d5a0db3858d, 0x43aabe696b3bb },
    },
    {
        { 0x25cd0944ea3bf, 0x75673b81a4d63, 0x150b925d1c0d4,
            0x13f38d9294114, 0x461bea69283c9 },
        { 0x72c9aaa3221b1, 0x267774474f74d, 0x064b0e9b28085,
            0x3f04ef53b27c9, 0x1d6edd5d2e531 },
        { 0x36dc801b8b3a2, 0x0e0a7d4935e30, 0x1deb7cecc0d7d,
            0x053a94e20dd2c, 0x7a9fbb1c6a0f9 },
    },
    {
        { 0x6678aa6a8632f, 0x5ea3788d8b365, 0x21bd6d6994279,
            0x7ace75919e4e3, 0x34b9ed338add7 },
        { 0x6217e039d8064, 0x6dea408337e6d, 0x57ac112628206,
            0x647cb65e30473, 0x49c05a51fadc9 },
        { 0x4e8bf9045af1b, 0x514e33a45e0d6, 0x7533c5b8bfe0f,
            0x583557b7e14c9, 0x73c172021b008 },
    },
    {
        { 0x700848a802ade, 0x1e04605c4e5f7, 0x5c0d01b9767fb,
            0x7d7889f42388b, 0x4275aae2546d8 },
        { 0x75b0249864348, 0x52ee11070262b, 0x237ae54fb5acd,
            0x3bfd1d03aaab5, 0x18ab598029d5c },
        { 0x32cc5fd6089e9, 0x426505c949b05, 0x46a18880c7ad2,
            0x4a4221888ccda, 0x3dc65522b53df },
    },
    {
        { 0x0c222a2007f6d, 0x356b79bdb77ee, 0x41ee81efe12ce,
            0x120a9bd07097d, 0x234fd7eec346f },
        { 0x7013b327fbf93, 0x1336eeded6a0d, 0x2b565a2bbf3af,
            0x253ce89591955, 0x0267882d17602 },
        { 0x0a119732ea378, 0x63bf1ba8e2a6c, 0x69f94cc90df9a,
            0x431d1779bfc48, 0x497ba6fdaa097 },
    },
    {
        { 0x6cc0313cfeaa0, 0x1a313848da499, 0x7cb534219230a,
            0x39596dedefd60, 0x61e22917f12de },
        { 0x3cd86468ccf0b, 0x48553221ac081, 0x6c9464b4e0a6e,
            0x75fba84180403, 0x43b5cd4218d05 },
        { 0x2762f9bd0b516, 0x1c6e7fbddcbb3, 0x75909c3ace2bd,
            0x42101972d3ec9, 0x511d61210ae4d },
    },
};
#else
static const ge_precomp Bi[8] = {
    {
        { 25967493, -14356035, 29566456, 3660896, -12694345, 4014787, 27544626,
            -11754271, -6079156, 2047605 },
        { -12545711, 934262, -2722910, 3049990, -727428, 9406986, 12720692,
            5043384, 19500929, -15469378 },
        { -8738181, 4489570, 9688441, -14785194, 10184609, -12363380, 29287919,
            11864899, -24514362, -4438546 },
    },
    {
        { 15636291, -9688557, 24204773, -7912398, 616977, -16685262, 27787600,
            -14772189, 28944400, -1550024 },
        { 16568933, 4717097, -11556148, -1102322, 15682896, -11807043, 16354577,
            -11775962, 7689662, 11199574 },
        { 30464156, -5976125, -11779434, -15670865, 23220365, 15915852, 7512774,
            10017326, -17749093, -9920357 },
    },
    {
        { 10861363, 11473154, 27284546, 1981175, -30064349, 12577861, 32867885,
            14515107, -15438304, 10819380 },
        { 4708026, 6336745, 20377586, 9066809, -11272109, 6594696, -25653668,
            12483688, -12668491, 5581306 },
        { 19563160, 16186464, -29386857, 4097519, 10237984, -4348115, 28542350,
            13850243, -23678021, -15815942 },
    },
    {
        { 5153746, 9909285, 1723747, -2777874, 30523605, 5516873, 19480852,
            5230134, -23952439, -15175766 },
        { -30269007, -3463509, 7665486, 10083793, 28475525, 1649722, 20654025,
            16520125, 30598449, 7715701 },
        { 28881845, 14381568, 9657904, 3680757, -20181635, 7843316, -31400660,
            1370708, 29794553, -1409300 },
    },
    {
        { -22518993, -6692182, 14201702, -8745502, -23510406, 8844726, 18474211,
            -1361450, -13062696, 13821877 },
        { -6455177, -7839871, 3374702, -4740862, -27098617, -10571707, 31655028,
            -7212327, 18853322, -14220951 },
        { 4566830, -12963868, -28974889, -12240689, -7602672, -2830569, -8514358,
            -10431137, 2207753, -3209784 },
    },
    {
        { -25154831, -4185821, 29681144, 7868801, -6854661, -9423865, -12437364,
            -663000, -31111463, -16132436 },
        { 25576264, -2703214, 7349804, -11814844, 16472782, 9300885, 3844789,
            15725684, 171356, 6466918 },
        { 23103977, 13316479, 9739013, -16149481, 817875, -15038942, 8965339,
            -14088058, -30714912, 16193877 },
    },
    {
        { -33521811, 3180713, -2394130, 14003687, -16903474, -16270840, 17238398,
            4729455, -18074513, 9256800 },
        { -25182317, -4174131, 32336398, 5036987, -21236817, 11360617, 22616405,
            9761698, -19827198, 630305 },
        { -13720693, 2639453, -24237460, -7406481, 9494427, -5774029, -6554551,
            -15960994, -2449256, -14291300 },
    },
    {
        { -3151181, -5046075, 9282714, 6866145, -31907062, -863023, -18940575,
            15033784, 25105118, -7894876 },
        { -24326370, 15950226, -31801215, -14592823, -11662737, -5090925,
            1573892, -2625887, 2198790, -15804619 },
        { -3099351, 10324967, -2241613, 7453183, -5446979, -2735503, -13812022,
            -16236442, -32461234, -12290683 },
    },
};
#endif

/*
 * r = a * A + b * B
 *
 * where a = a[0]+256*a[1]+...+256^31 a[31].
 * and b = b[0]+256*b[1]+...+256^31 b[31].
 * B is the Ed25519 base point (x,4/5) with x positive.
 */
static void ge_double_scalarmult_vartime(ge_p2 *r, const uint8_t *a,
    const ge_p3 *A, const uint8_t *b)
{
    signed char aslide[256];
    signed char bslide[256];
    ge_cached Ai[8]; /* A,3A,5A,7A,9A,11A,13A,15A */
    ge_p1p1 t;
    ge_p3 u;
    ge_p3 A2;
    int i;

    slide(aslide, a);
    slide(bslide, b);

    ge_p3_to_cached(&Ai[0], A);
    ge_p3_dbl(&t, A);
    ge_p1p1_to_p3(&A2, &t);
    ge_add(&t, &A2, &Ai[0]);
    ge_p1p1_to_p3(&u, &t);
    ge_p3_to_cached(&Ai[1], &u);
    ge_add(&t, &A2, &Ai[1]);
    ge_p1p1_to_p3(&u, &t);
    ge_p3_to_cached(&Ai[2], &u);
    ge_add(&t, &A2, &Ai[2]);
    ge_p1p1_to_p3(&u, &t);
    ge_p3_to_cached(&Ai[3], &u);
    ge_add(&t, &A2, &Ai[3]);
    ge_p1p1_to_p3(&u, &t);
    ge_p3_to_cached(&Ai[4], &u);
    ge_add(&t, &A2, &Ai[4]);
    ge_p1p1_to_p3(&u, &t);
    ge_p3_to_cached(&Ai[5], &u);
    ge_add(&t, &A2, &Ai[5]);
    ge_p1p1_to_p3(&u, &t);
    ge_p3_to_cached(&Ai[6], &u);
    ge_add(&t, &A2, &Ai[6]);
    ge_p1p1_to_p3(&u, &t);
    ge_p3_to_cached(&Ai[7], &u);

    ge_p2_0(r);

    for (i = 255; i >= 0; --i) {
        if (aslide[i] || bslide[i]) {
            break;
        }
    }

    for (; i >= 0; --i) {
        ge_p2_dbl(&t, r);

        if (aslide[i] > 0) {
            ge_p1p1_to_p3(&u, &t);
            ge_add(&t, &u, &Ai[aslide[i] / 2]);
        } else if (aslide[i] < 0) {
            ge_p1p1_to_p3(&u, &t);
            ge_sub(&t, &u, &Ai[(-aslide[i]) / 2]);
        }

        if (bslide[i] > 0) {
            ge_p1p1_to_p3(&u, &t);
            ge_madd(&t, &u, &Bi[bslide[i] / 2]);
        } else if (bslide[i] < 0) {
            ge_p1p1_to_p3(&u, &t);
            ge_msub(&t, &u, &Bi[(-bslide[i]) / 2]);
        }

        ge_p1p1_to_p2(r, &t);
    }
}

/*
 * The set of scalars is \Z/l
 * where l = 2^252 + 27742317777372353535851937790883648493.
 *
 * Input:
 *   s[0]+256*s[1]+...+256^63*s[63] = s
 *
 * Output:
 *   s[0]+256*s[1]+...+256^31*s[31] = s mod l
 *   where l = 2^252 + 27742317777372353535851937790883648493.
 *   Overwrites s in place.
 */
static void x25519_sc_reduce(uint8_t *s)
{
    int64_t s0 = kBottom21Bits & load_3(s);
    int64_t s1 = kBottom21Bits & (load_4(s + 2) >> 5);
    int64_t s2 = kBottom21Bits & (load_3(s + 5) >> 2);
    int64_t s3 = kBottom21Bits & (load_4(s + 7) >> 7);
    int64_t s4 = kBottom21Bits & (load_4(s + 10) >> 4);
    int64_t s5 = kBottom21Bits & (load_3(s + 13) >> 1);
    int64_t s6 = kBottom21Bits & (load_4(s + 15) >> 6);
    int64_t s7 = kBottom21Bits & (load_3(s + 18) >> 3);
    int64_t s8 = kBottom21Bits & load_3(s + 21);
    int64_t s9 = kBottom21Bits & (load_4(s + 23) >> 5);
    int64_t s10 = kBottom21Bits & (load_3(s + 26) >> 2);
    int64_t s11 = kBottom21Bits & (load_4(s + 28) >> 7);
    int64_t s12 = kBottom21Bits & (load_4(s + 31) >> 4);
    int64_t s13 = kBottom21Bits & (load_3(s + 34) >> 1);
    int64_t s14 = kBottom21Bits & (load_4(s + 36) >> 6);
    int64_t s15 = kBottom21Bits & (load_3(s + 39) >> 3);
    int64_t s16 = kBottom21Bits & load_3(s + 42);
    int64_t s17 = kBottom21Bits & (load_4(s + 44) >> 5);
    int64_t s18 = kBottom21Bits & (load_3(s + 47) >> 2);
    int64_t s19 = kBottom21Bits & (load_4(s + 49) >> 7);
    int64_t s20 = kBottom21Bits & (load_4(s + 52) >> 4);
    int64_t s21 = kBottom21Bits & (load_3(s + 55) >> 1);
    int64_t s22 = kBottom21Bits & (load_4(s + 57) >> 6);
    int64_t s23 = (load_4(s + 60) >> 3);
    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;
    int64_t carry10;
    int64_t carry11;
    int64_t carry12;
    int64_t carry13;
    int64_t carry14;
    int64_t carry15;
    int64_t carry16;

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    s23 = 0;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    s22 = 0;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    s21 = 0;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    s20 = 0;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    s19 = 0;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    s18 = 0;

    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 * (1 << 21);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 * (1 << 21);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 * (1 << 21);
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 * (1 << 21);
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 * (1 << 21);
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 * (1 << 21);

    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 * (1 << 21);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 * (1 << 21);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 * (1 << 21);
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 * (1 << 21);
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 * (1 << 21);

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;
    s17 = 0;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;
    s16 = 0;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;
    s15 = 0;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;
    s14 = 0;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;
    s13 = 0;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 * (1 << 21);
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 * (1 << 21);
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 * (1 << 21);
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 * (1 << 21);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 * (1 << 21);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 * (1 << 21);

    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 * (1 << 21);
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 * (1 << 21);
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 * (1 << 21);
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 * (1 << 21);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 * (1 << 21);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 * (1 << 21);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 * (1 << 21);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 * (1 << 21);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 * (1 << 21);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 * (1 << 21);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 * (1 << 21);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 * (1 << 21);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 * (1 << 21);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 * (1 << 21);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 * (1 << 21);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 * (1 << 21);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 * (1 << 21);
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= carry11 * (1 << 21);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 * (1 << 21);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 * (1 << 21);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 * (1 << 21);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 * (1 << 21);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 * (1 << 21);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 * (1 << 21);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 * (1 << 21);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 * (1 << 21);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 * (1 << 21);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 * (1 << 21);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 * (1 << 21);

    s[0] = (uint8_t)(s0 >> 0);
    s[1] = (uint8_t)(s0 >> 8);
    s[2] = (uint8_t)((s0 >> 16) | (s1 << 5));
    s[3] = (uint8_t)(s1 >> 3);
    s[4] = (uint8_t)(s1 >> 11);
    s[5] = (uint8_t)((s1 >> 19) | (s2 << 2));
    s[6] = (uint8_t)(s2 >> 6);
    s[7] = (uint8_t)((s2 >> 14) | (s3 << 7));
    s[8] = (uint8_t)(s3 >> 1);
    s[9] = (uint8_t)(s3 >> 9);
    s[10] = (uint8_t)((s3 >> 17) | (s4 << 4));
    s[11] = (uint8_t)(s4 >> 4);
    s[12] = (uint8_t)(s4 >> 12);
    s[13] = (uint8_t)((s4 >> 20) | (s5 << 1));
    s[14] = (uint8_t)(s5 >> 7);
    s[15] = (uint8_t)((s5 >> 15) | (s6 << 6));
    s[16] = (uint8_t)(s6 >> 2);
    s[17] = (uint8_t)(s6 >> 10);
    s[18] = (uint8_t)((s6 >> 18) | (s7 << 3));
    s[19] = (uint8_t)(s7 >> 5);
    s[20] = (uint8_t)(s7 >> 13);
    s[21] = (uint8_t)(s8 >> 0);
    s[22] = (uint8_t)(s8 >> 8);
    s[23] = (uint8_t)((s8 >> 16) | (s9 << 5));
    s[24] = (uint8_t)(s9 >> 3);
    s[25] = (uint8_t)(s9 >> 11);
    s[26] = (uint8_t)((s9 >> 19) | (s10 << 2));
    s[27] = (uint8_t)(s10 >> 6);
    s[28] = (uint8_t)((s10 >> 14) | (s11 << 7));
    s[29] = (uint8_t)(s11 >> 1);
    s[30] = (uint8_t)(s11 >> 9);
    s[31] = (uint8_t)(s11 >> 17);
}

/*
 * Input:
 *   a[0]+256*a[1]+...+256^31*a[31] = a
 *   b[0]+256*b[1]+...+256^31*b[31] = b
 *   c[0]+256*c[1]+...+256^31*c[31] = c
 *
 * Output:
 *   s[0]+256*s[1]+...+256^31*s[31] = (ab+c) mod l
 *   where l = 2^252 + 27742317777372353535851937790883648493.
 */
static void sc_muladd(uint8_t *s, const uint8_t *a, const uint8_t *b,
    const uint8_t *c)
{
    int64_t a0 = kBottom21Bits & load_3(a);
    int64_t a1 = kBottom21Bits & (load_4(a + 2) >> 5);
    int64_t a2 = kBottom21Bits & (load_3(a + 5) >> 2);
    int64_t a3 = kBottom21Bits & (load_4(a + 7) >> 7);
    int64_t a4 = kBottom21Bits & (load_4(a + 10) >> 4);
    int64_t a5 = kBottom21Bits & (load_3(a + 13) >> 1);
    int64_t a6 = kBottom21Bits & (load_4(a + 15) >> 6);
    int64_t a7 = kBottom21Bits & (load_3(a + 18) >> 3);
    int64_t a8 = kBottom21Bits & load_3(a + 21);
    int64_t a9 = kBottom21Bits & (load_4(a + 23) >> 5);
    int64_t a10 = kBottom21Bits & (load_3(a + 26) >> 2);
    int64_t a11 = (load_4(a + 28) >> 7);
    int64_t b0 = kBottom21Bits & load_3(b);
    int64_t b1 = kBottom21Bits & (load_4(b + 2) >> 5);
    int64_t b2 = kBottom21Bits & (load_3(b + 5) >> 2);
    int64_t b3 = kBottom21Bits & (load_4(b + 7) >> 7);
    int64_t b4 = kBottom21Bits & (load_4(b + 10) >> 4);
    int64_t b5 = kBottom21Bits & (load_3(b + 13) >> 1);
    int64_t b6 = kBottom21Bits & (load_4(b + 15) >> 6);
    int64_t b7 = kBottom21Bits & (load_3(b + 18) >> 3);
    int64_t b8 = kBottom21Bits & load_3(b + 21);
    int64_t b9 = kBottom21Bits & (load_4(b + 23) >> 5);
    int64_t b10 = kBottom21Bits & (load_3(b + 26) >> 2);
    int64_t b11 = (load_4(b + 28) >> 7);
    int64_t c0 = kBottom21Bits & load_3(c);
    int64_t c1 = kBottom21Bits & (load_4(c + 2) >> 5);
    int64_t c2 = kBottom21Bits & (load_3(c + 5) >> 2);
    int64_t c3 = kBottom21Bits & (load_4(c + 7) >> 7);
    int64_t c4 = kBottom21Bits & (load_4(c + 10) >> 4);
    int64_t c5 = kBottom21Bits & (load_3(c + 13) >> 1);
    int64_t c6 = kBottom21Bits & (load_4(c + 15) >> 6);
    int64_t c7 = kBottom21Bits & (load_3(c + 18) >> 3);
    int64_t c8 = kBottom21Bits & load_3(c + 21);
    int64_t c9 = kBottom21Bits & (load_4(c + 23) >> 5);
    int64_t c10 = kBottom21Bits & (load_3(c + 26) >> 2);
    int64_t c11 = (load_4(c + 28) >> 7);
    int64_t s0;
    int64_t s1;
    int64_t s2;
    int64_t s3;
    int64_t s4;
    int64_t s5;
    int64_t s6;
    int64_t s7;
    int64_t s8;
    int64_t s9;
    int64_t s10;
    int64_t s11;
    int64_t s12;
    int64_t s13;
    int64_t s14;
    int64_t s15;
    int64_t s16;
    int64_t s17;
    int64_t s18;
    int64_t s19;
    int64_t s20;
    int64_t s21;
    int64_t s22;
    int64_t s23;
    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;
    int64_t carry10;
    int64_t carry11;
    int64_t carry12;
    int64_t carry13;
    int64_t carry14;
    int64_t carry15;
    int64_t carry16;
    int64_t carry17;
    int64_t carry18;
    int64_t carry19;
    int64_t carry20;
    int64_t carry21;
    int64_t carry22;

    s0 = c0 + a0 * b0;
    s1 = c1 + a0 * b1 + a1 * b0;
    s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
    s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
    s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0;
    s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0;
    s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 + a8 * b2 + a9 * b1 + a10 * b0;
    s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3 + a9 * b2 + a10 * b1 + a11 * b0;
    s12 = a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3 + a10 * b2 + a11 * b1;
    s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 + a10 * b3 + a11 * b2;
    s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3;
    s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
    s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
    s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
    s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
    s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
    s20 = a9 * b11 + a10 * b10 + a11 * b9;
    s21 = a10 * b11 + a11 * b10;
    s22 = a11 * b11;
    s23 = 0;

    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 * (1 << 21);
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 * (1 << 21);
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 * (1 << 21);
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 * (1 << 21);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 * (1 << 21);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 * (1 << 21);
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 * (1 << 21);
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 * (1 << 21);
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 * (1 << 21);
    carry18 = (s18 + (1 << 20)) >> 21;
    s19 += carry18;
    s18 -= carry18 * (1 << 21);
    carry20 = (s20 + (1 << 20)) >> 21;
    s21 += carry20;
    s20 -= carry20 * (1 << 21);
    carry22 = (s22 + (1 << 20)) >> 21;
    s23 += carry22;
    s22 -= carry22 * (1 << 21);

    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 * (1 << 21);
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 * (1 << 21);
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 * (1 << 21);
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 * (1 << 21);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 * (1 << 21);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 * (1 << 21);
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 * (1 << 21);
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 * (1 << 21);
    carry17 = (s17 + (1 << 20)) >> 21;
    s18 += carry17;
    s17 -= carry17 * (1 << 21);
    carry19 = (s19 + (1 << 20)) >> 21;
    s20 += carry19;
    s19 -= carry19 * (1 << 21);
    carry21 = (s21 + (1 << 20)) >> 21;
    s22 += carry21;
    s21 -= carry21 * (1 << 21);

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    s23 = 0;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    s22 = 0;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    s21 = 0;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    s20 = 0;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    s19 = 0;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    s18 = 0;

    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 * (1 << 21);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 * (1 << 21);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 * (1 << 21);
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 * (1 << 21);
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 * (1 << 21);
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 * (1 << 21);

    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 * (1 << 21);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 * (1 << 21);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 * (1 << 21);
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 * (1 << 21);
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 * (1 << 21);

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;
    s17 = 0;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;
    s16 = 0;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;
    s15 = 0;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;
    s14 = 0;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;
    s13 = 0;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 * (1 << 21);
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 * (1 << 21);
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 * (1 << 21);
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 * (1 << 21);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 * (1 << 21);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 * (1 << 21);

    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 * (1 << 21);
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 * (1 << 21);
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 * (1 << 21);
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 * (1 << 21);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 * (1 << 21);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 * (1 << 21);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 * (1 << 21);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 * (1 << 21);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 * (1 << 21);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 * (1 << 21);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 * (1 << 21);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 * (1 << 21);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 * (1 << 21);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 * (1 << 21);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 * (1 << 21);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 * (1 << 21);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 * (1 << 21);
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= carry11 * (1 << 21);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 * (1 << 21);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 * (1 << 21);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 * (1 << 21);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 * (1 << 21);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 * (1 << 21);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 * (1 << 21);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 * (1 << 21);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 * (1 << 21);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 * (1 << 21);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 * (1 << 21);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 * (1 << 21);

    s[0] = (uint8_t)(s0 >> 0);
    s[1] = (uint8_t)(s0 >> 8);
    s[2] = (uint8_t)((s0 >> 16) | (s1 << 5));
    s[3] = (uint8_t)(s1 >> 3);
    s[4] = (uint8_t)(s1 >> 11);
    s[5] = (uint8_t)((s1 >> 19) | (s2 << 2));
    s[6] = (uint8_t)(s2 >> 6);
    s[7] = (uint8_t)((s2 >> 14) | (s3 << 7));
    s[8] = (uint8_t)(s3 >> 1);
    s[9] = (uint8_t)(s3 >> 9);
    s[10] = (uint8_t)((s3 >> 17) | (s4 << 4));
    s[11] = (uint8_t)(s4 >> 4);
    s[12] = (uint8_t)(s4 >> 12);
    s[13] = (uint8_t)((s4 >> 20) | (s5 << 1));
    s[14] = (uint8_t)(s5 >> 7);
    s[15] = (uint8_t)((s5 >> 15) | (s6 << 6));
    s[16] = (uint8_t)(s6 >> 2);
    s[17] = (uint8_t)(s6 >> 10);
    s[18] = (uint8_t)((s6 >> 18) | (s7 << 3));
    s[19] = (uint8_t)(s7 >> 5);
    s[20] = (uint8_t)(s7 >> 13);
    s[21] = (uint8_t)(s8 >> 0);
    s[22] = (uint8_t)(s8 >> 8);
    s[23] = (uint8_t)((s8 >> 16) | (s9 << 5));
    s[24] = (uint8_t)(s9 >> 3);
    s[25] = (uint8_t)(s9 >> 11);
    s[26] = (uint8_t)((s9 >> 19) | (s10 << 2));
    s[27] = (uint8_t)(s10 >> 6);
    s[28] = (uint8_t)((s10 >> 14) | (s11 << 7));
    s[29] = (uint8_t)(s11 >> 1);
    s[30] = (uint8_t)(s11 >> 9);
    s[31] = (uint8_t)(s11 >> 17);
}

static int hash_init_with_dom(EVP_MD_CTX *hash_ctx,
    EVP_MD *sha512,
    const uint8_t dom2flag,
    const uint8_t phflag,
    const uint8_t *context,
    const size_t context_len)
{
    /* ASCII: "SigEd25519 no Ed25519 collisions", in hex for EBCDIC compatibility */
    const char dom_s[] = "\x53\x69\x67\x45\x64\x32\x35\x35\x31\x39\x20\x6e"
                         "\x6f\x20\x45\x64\x32\x35\x35\x31\x39\x20\x63\x6f"
                         "\x6c\x6c\x69\x73\x69\x6f\x6e\x73";
    uint8_t dom[2];

    if (!EVP_DigestInit_ex(hash_ctx, sha512, NULL))
        return 0;

    /* return early if dom2flag is not set */
    if (!dom2flag)
        return 1;

    if (context_len > UINT8_MAX)
        return 0;

    dom[0] = (uint8_t)(phflag >= 1 ? 1 : 0);
    dom[1] = (uint8_t)context_len;

    if (!EVP_DigestUpdate(hash_ctx, dom_s, sizeof(dom_s) - 1)
        || !EVP_DigestUpdate(hash_ctx, dom, sizeof(dom))
        || !EVP_DigestUpdate(hash_ctx, context, context_len)) {
        return 0;
    }

    return 1;
}

int ossl_ed25519_sign(uint8_t *out_sig, const uint8_t *tbs, size_t tbs_len,
    const uint8_t public_key[32], const uint8_t private_key[32],
    const uint8_t dom2flag, const uint8_t phflag, const uint8_t csflag,
    const uint8_t *context, size_t context_len,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    uint8_t az[SHA512_DIGEST_LENGTH];
    uint8_t nonce[SHA512_DIGEST_LENGTH];
    ge_p3 R;
    uint8_t hram[SHA512_DIGEST_LENGTH];
    EVP_MD *sha512 = EVP_MD_fetch(libctx, SN_sha512, propq);
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    unsigned int sz;
    int res = 0;

    if (context == NULL)
        context_len = 0;

    /* if csflag is set, then a non-empty context-string is required */
    if (csflag && context_len == 0)
        goto err;

    /* if dom2flag is not set, then an empty context-string is required */
    if (!dom2flag && context_len > 0)
        goto err;

    if (sha512 == NULL || hash_ctx == NULL)
        goto err;

    if (!EVP_DigestInit_ex(hash_ctx, sha512, NULL)
        || !EVP_DigestUpdate(hash_ctx, private_key, 32)
        || !EVP_DigestFinal_ex(hash_ctx, az, &sz))
        goto err;

    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    if (!hash_init_with_dom(hash_ctx, sha512, dom2flag, phflag, context, context_len)
        || !EVP_DigestUpdate(hash_ctx, az + 32, 32)
        || !EVP_DigestUpdate(hash_ctx, tbs, tbs_len)
        || !EVP_DigestFinal_ex(hash_ctx, nonce, &sz))
        goto err;

    x25519_sc_reduce(nonce);
    ge_scalarmult_base(&R, nonce);
    ge_p3_tobytes(out_sig, &R);

    if (!hash_init_with_dom(hash_ctx, sha512, dom2flag, phflag, context, context_len)
        || !EVP_DigestUpdate(hash_ctx, out_sig, 32)
        || !EVP_DigestUpdate(hash_ctx, public_key, 32)
        || !EVP_DigestUpdate(hash_ctx, tbs, tbs_len)
        || !EVP_DigestFinal_ex(hash_ctx, hram, &sz))
        goto err;

    x25519_sc_reduce(hram);
    sc_muladd(out_sig + 32, hram, az, nonce);

    res = 1;
err:
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(az, sizeof(az));
    EVP_MD_free(sha512);
    EVP_MD_CTX_free(hash_ctx);
    return res;
}

/*
 * This function should not be necessary since ossl_ed25519_verify() already
 * does this check internally.
 * For some reason the FIPS ACVP requires a EDDSA KeyVer test.
 */
int ossl_ed25519_pubkey_verify(const uint8_t *pub, size_t pub_len)
{
    ge_p3 A;

    if (pub_len != ED25519_KEYLEN)
        return 0;
    return (ge_frombytes_vartime(&A, pub) == 0);
}

static const char allzeroes[15];

int ossl_ed25519_verify(const uint8_t *tbs, size_t tbs_len,
    const uint8_t signature[64], const uint8_t public_key[32],
    const uint8_t dom2flag, const uint8_t phflag, const uint8_t csflag,
    const uint8_t *context, size_t context_len,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    int i;
    ge_p3 A;
    const uint8_t *r, *s;
    EVP_MD *sha512;
    EVP_MD_CTX *hash_ctx = NULL;
    unsigned int sz;
    int res = 0;
    ge_p2 R;
    uint8_t rcheck[32];
    uint8_t h[SHA512_DIGEST_LENGTH];
    /* 27742317777372353535851937790883648493 in little endian format */
    const uint8_t l_low[16] = {
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2,
        0xDE, 0xF9, 0xDE, 0x14
    };

    if (context == NULL)
        context_len = 0;

    /* if csflag is set, then a non-empty context-string is required */
    if (csflag && context_len == 0)
        return 0;

    /* if dom2flag is not set, then an empty context-string is required */
    if (!dom2flag && context_len > 0)
        return 0;

    r = signature;
    s = signature + 32;

    /*
     * Check 0 <= s < L where L = 2^252 + 27742317777372353535851937790883648493
     *
     * If not the signature is publicly invalid. Since it's public we can do the
     * check in variable time.
     *
     * First check the most significant byte
     */
    if (s[31] > 0x10)
        return 0;
    if (s[31] == 0x10) {
        /*
         * Most significant byte indicates a value close to 2^252 so check the
         * rest
         */
        if (memcmp(s + 16, allzeroes, sizeof(allzeroes)) != 0)
            return 0;
        for (i = 15; i >= 0; i--) {
            if (s[i] < l_low[i])
                break;
            if (s[i] > l_low[i])
                return 0;
        }
        if (i < 0)
            return 0;
    }

    if (ge_frombytes_vartime(&A, public_key) != 0) {
        return 0;
    }

    fe_neg(A.X, A.X);
    fe_neg(A.T, A.T);

    sha512 = EVP_MD_fetch(libctx, SN_sha512, propq);
    if (sha512 == NULL)
        return 0;
    hash_ctx = EVP_MD_CTX_new();
    if (hash_ctx == NULL)
        goto err;

    if (!hash_init_with_dom(hash_ctx, sha512, dom2flag, phflag, context, context_len)
        || !EVP_DigestUpdate(hash_ctx, r, 32)
        || !EVP_DigestUpdate(hash_ctx, public_key, 32)
        || !EVP_DigestUpdate(hash_ctx, tbs, tbs_len)
        || !EVP_DigestFinal_ex(hash_ctx, h, &sz))
        goto err;

    x25519_sc_reduce(h);

    ge_double_scalarmult_vartime(&R, h, &A, s);

    ge_tobytes(rcheck, &R);

    res = CRYPTO_memcmp(rcheck, r, sizeof(rcheck)) == 0;

    /* note that we have used the strict verification equation here.
     * we checked that  ENC( [h](-A) + [s]B ) == r
     * B is the base point.
     *
     * the less strict verification equation uses the curve cofactor:
     *          [h*8](-A) + [s*8]B == [8]R
     */
err:
    EVP_MD_free(sha512);
    EVP_MD_CTX_free(hash_ctx);
    return res;
}

int ossl_ed25519_public_from_private(OSSL_LIB_CTX *ctx, uint8_t out_public_key[32],
    const uint8_t private_key[32],
    const char *propq)
{
    uint8_t az[SHA512_DIGEST_LENGTH];
    ge_p3 A;
    int r;
    EVP_MD *sha512 = NULL;

    sha512 = EVP_MD_fetch(ctx, SN_sha512, propq);
    if (sha512 == NULL)
        return 0;
    r = EVP_Digest(private_key, 32, az, NULL, sha512, NULL);
    EVP_MD_free(sha512);
    if (!r) {
        OPENSSL_cleanse(az, sizeof(az));
        return 0;
    }

    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    ge_scalarmult_base(&A, az);
    ge_p3_tobytes(out_public_key, &A);

    OPENSSL_cleanse(az, sizeof(az));
    return 1;
}

int ossl_x25519(uint8_t out_shared_key[32], const uint8_t private_key[32],
    const uint8_t peer_public_value[32])
{
    static const uint8_t kZeros[32] = { 0 };
    x25519_scalar_mult(out_shared_key, private_key, peer_public_value);
    /* The all-zero output results when the input is a point of small order. */
    return CRYPTO_memcmp(kZeros, out_shared_key, 32) != 0;
}

void ossl_x25519_public_from_private(uint8_t out_public_value[32],
    const uint8_t private_key[32])
{
    uint8_t e[32];
    ge_p3 A;
    fe zplusy, zminusy, zminusy_inv;

    memcpy(e, private_key, 32);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    ge_scalarmult_base(&A, e);

    /*
     * We only need the u-coordinate of the curve25519 point.
     * The map is u=(y+1)/(1-y). Since y=Y/Z, this gives
     * u=(Z+Y)/(Z-Y).
     */
    fe_add(zplusy, A.Z, A.Y);
    fe_sub(zminusy, A.Z, A.Y);
    fe_invert(zminusy_inv, zminusy);
    fe_mul(zplusy, zplusy, zminusy_inv);
    fe_tobytes(out_public_value, zplusy);

    OPENSSL_cleanse(e, sizeof(e));
}
