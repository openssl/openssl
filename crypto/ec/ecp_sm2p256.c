/* ====================================================================
 * Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */
/*
 * Copyright 2011-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * A 64-bit implementation of the NIST P-256 elliptic curve point multiplication
 *
 * OpenSSL integration was taken from Emilia Kasper's work in ecp_nistp224.c.
 * Otherwise based on Emilia's P224 work, which was inspired by my curve25519
 * work which got its smarts from Daniel J. Bernstein's work on the same.
 */

#include <openssl/opensslconf.h>
#ifdef OPENSSL_NO_EC_NISTP_64_GCC_128
NON_EMPTY_TRANSLATION_UNIT
#else

# include <stdint.h>
# include <string.h>
# include <openssl/err.h>
# include "ec_local.h"

# if defined(__GNUC__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1))
  /* even with gcc, the typedef won't work for 32-bit platforms */
typedef __uint128_t uint128_t;  /* nonstandard; implemented by gcc on 64-bit
                                 * platforms */
typedef __int128_t int128_t;
# else
#  error "Need GCC 3.1 or later to define type uint128_t"
# endif

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;

/*
 * The underlying field. SM2-P256 operates over GF(2^256-2^224-2^96+2^64-1).
 * We can serialise an element of this field into 32 bytes. We call this an
 * felem_bytearray.
 */

typedef u8 felem_bytearray[32];

/*
 * These are the parameters of SM2, taken from GM/T 0003.5-2012. These
 * values are big-endian.
 */
static const felem_bytearray sm2p256v1_curve_params[5] = {
    {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, /* p */
     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
    {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, /* a = -3 */
     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC},
    {0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, /* b */
     0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
     0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
     0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93},
    {0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, /* x */
     0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
     0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
     0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7},
    {0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, /* y */
     0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
     0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
     0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0}
};

/*-
 * The representation of field elements.
 * ------------------------------------
 *
 * We represent field elements with either four 128-bit values, eight 128-bit
 * values, or four 64-bit values. The field element represented is:
 *   v[0]*2^0 + v[1]*2^64 + v[2]*2^128 + v[3]*2^192  (mod p)
 * or:
 *   v[0]*2^0 + v[1]*2^64 + v[2]*2^128 + ... + v[8]*2^512  (mod p)
 *
 * 128-bit values are called 'limbs'. Since the limbs are spaced only 64 bits
 * apart, but are 128-bits wide, the most significant bits of each limb overlap
 * with the least significant bits of the next.
 *
 * A field element with four limbs is an 'felem'. One with eight limbs is a
 * 'longfelem'
 *
 * A field element with four, 64-bit values is called a 'smallfelem'. Small
 * values are used as intermediate values before multiplication.
 */

# define NLIMBS 4

typedef uint128_t limb;
typedef limb felem[NLIMBS];
typedef limb longfelem[NLIMBS * 2];
typedef u64 smallfelem[NLIMBS];

/* This is the value of the prime as four 64-bit words, little-endian. */
static const u64 kPrime[4] = {
    0xfffffffffffffffful, 0xffffffff00000000ul,
    0xfffffffffffffffful, 0xfffffffefffffffful};
static const u64 bottom63bits = 0x7ffffffffffffffful;

/*
 * bin32_to_felem takes a little-endian byte array and converts it into felem
 * form. This assumes that the CPU is little-endian.
 */
static void bin32_to_felem(felem out, const u8 in[32])
{
    out[0] = *((u64 *)&in[0]);
    out[1] = *((u64 *)&in[8]);
    out[2] = *((u64 *)&in[16]);
    out[3] = *((u64 *)&in[24]);
}

/*
 * smallfelem_to_bin32 takes a smallfelem and serialises into a little
 * endian, 32 byte array. This assumes that the CPU is little-endian.
 */
static void smallfelem_to_bin32(u8 out[32], const smallfelem in)
{
    *((u64 *)&out[0]) = in[0];
    *((u64 *)&out[8]) = in[1];
    *((u64 *)&out[16]) = in[2];
    *((u64 *)&out[24]) = in[3];
}

/* To preserve endianness when using BN_bn2bin and BN_bin2bn */
static void flip_endian(u8 *out, const u8 *in, unsigned len)
{
    unsigned i;
    for (i = 0; i < len; ++i)
        out[i] = in[len - 1 - i];
}

/* BN_to_felem converts an OpenSSL BIGNUM into an felem */
static int BN_to_felem(felem out, const BIGNUM *bn)
{
    felem_bytearray b_in;
    felem_bytearray b_out;
    unsigned num_bytes;

    /* BN_bn2bin eats leading zeroes */
    memset(b_out, 0, sizeof(b_out));
    num_bytes = BN_num_bytes(bn);
    if (num_bytes > sizeof b_out) {
        ECerr(EC_F_BN_TO_FELEM, EC_R_BIGNUM_OUT_OF_RANGE);
        return 0;
    }
    if (BN_is_negative(bn)) {
        ECerr(EC_F_BN_TO_FELEM, EC_R_BIGNUM_OUT_OF_RANGE);
        return 0;
    }
    num_bytes = BN_bn2bin(bn, b_in);
    flip_endian(b_out, b_in, num_bytes);
    bin32_to_felem(out, b_out);
    return 1;
}


/* felem_to_BN converts an felem into an OpenSSL BIGNUM */
static BIGNUM *smallfelem_to_BN(BIGNUM *out, const smallfelem in)
{
    felem_bytearray b_in, b_out;
    smallfelem_to_bin32(b_in, in);
    flip_endian(b_out, b_in, sizeof b_out);
    return BN_bin2bn(b_out, sizeof b_out, out);
}


/*-
 * Field operations
 * ----------------
 */

static void smallfelem_one(smallfelem out)
{
    out[0] = 1;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
}

static void smallfelem_assign(smallfelem out, const smallfelem in)
{
    out[0] = in[0];
    out[1] = in[1];
    out[2] = in[2];
    out[3] = in[3];
}

static void felem_assign(felem out, const felem in)
{
    out[0] = in[0];
    out[1] = in[1];
    out[2] = in[2];
    out[3] = in[3];
}

/* felem_sum sets out = out + in. */
static void felem_sum(felem out, const felem in)
{
    out[0] += in[0];
    out[1] += in[1];
    out[2] += in[2];
    out[3] += in[3];
}

/* felem_small_sum sets out = out + in. */
static void felem_small_sum(felem out, const smallfelem in)
{
    out[0] += in[0];
    out[1] += in[1];
    out[2] += in[2];
    out[3] += in[3];
}

/* felem_scalar sets out = out * scalar */
static void felem_scalar(felem out, const u64 scalar)
{
    out[0] *= scalar;
    out[1] *= scalar;
    out[2] *= scalar;
    out[3] *= scalar;
}

/* longfelem_scalar sets out = out * scalar */
static void longfelem_scalar(longfelem out, const u64 scalar)
{
    out[0] *= scalar;
    out[1] *= scalar;
    out[2] *= scalar;
    out[3] *= scalar;
    out[4] *= scalar;
    out[5] *= scalar;
    out[6] *= scalar;
    out[7] *= scalar;
}

# define two105m73m41 (((limb)1) << 105) - (((limb)1) << 73) - (((limb)1) << 41)
# define two105m41 (((limb)1) << 105) - (((limb)1) << 41)
# define two105m73 (((limb)1) << 105) - (((limb)1) << 73)

/* zero105 is 0 mod p */
static const felem zero105 =
    { two105m41, two105m73, two105m41, two105m73m41 };

/*-
 * smallfelem_neg sets |out| to |-small|
 * On exit:
 *   out[i] < out[i] + 2^105
 */
static void smallfelem_neg(felem out, const smallfelem small)
{
    /* In order to prevent underflow, we subtract from 0 mod p. */
    out[0] = zero105[0] - small[0];
    out[1] = zero105[1] - small[1];
    out[2] = zero105[2] - small[2];
    out[3] = zero105[3] - small[3];
}

/*-
 * felem_diff subtracts |in| from |out|
 * On entry:
 *   in[i] < 2^104
 * On exit:
 *   out[i] < out[i] + 2^105
 */
static void felem_diff(felem out, const felem in)
{
    /*
     * In order to prevent underflow, we add 0 mod p before subtracting.
     */
    out[0] += zero105[0];
    out[1] += zero105[1];
    out[2] += zero105[2];
    out[3] += zero105[3];

    out[0] -= in[0];
    out[1] -= in[1];
    out[2] -= in[2];
    out[3] -= in[3];
}

# define two107m75m43 (((limb)1) << 107) - (((limb)1) << 75) - (((limb)1) << 43)
# define two107m43 (((limb)1) << 107) - (((limb)1) << 43)
# define two107m75 (((limb)1) << 107) - (((limb)1) << 75)

/* zero107 is 0 mod p */
static const felem zero107 =
    { two107m43, two107m75, two107m43, two107m75m43 };

/*-
 * An alternative felem_diff for larger inputs |in|
 * felem_diff_zero107 subtracts |in| from |out|
 * On entry:
 *   in[i] < 2^106
 * On exit:
 *   out[i] < out[i] + 2^107
 */
static void felem_diff_zero107(felem out, const felem in)
{
    /*
     * In order to prevent underflow, we add 0 mod p before subtracting.
     */
    out[0] += zero107[0];
    out[1] += zero107[1];
    out[2] += zero107[2];
    out[3] += zero107[3];

    out[0] -= in[0];
    out[1] -= in[1];
    out[2] -= in[2];
    out[3] -= in[3];
}

/*-
 * longfelem_diff subtracts |in| from |out|
 * On entry:
 *   in[i] < 7*2^67
 * On exit:
 *   out[i] < out[i] + 2^70 + 2^40
 */
static void longfelem_diff(longfelem out, const longfelem in)
{
    static const limb two70m39m7m6 =
        (((limb) 1) << 70) - (((limb) 1) << 39)- (((limb) 1) << 7) -
        (((limb) 1) << 6);
    static const limb two70m40p38 =
        (((limb) 1) << 70) - (((limb) 1) << 40) + (((limb) 1) << 38);
    static const limb two70m38m7 =
        (((limb) 1) << 70) - (((limb) 1) << 38) - (((limb) 1) << 7);
    static const limb two70m40m7m6 =
        (((limb) 1) << 70) - (((limb) 1) << 40) - (((limb) 1) << 7) -
        (((limb) 1) << 6);
    static const limb two70m6 = (((limb) 1) << 70) - (((limb) 1) << 6);

    /* add 0 mod p to avoid underflow */
    out[0] += two70m39m7m6;
    out[1] += two70m40p38;
    out[2] += two70m38m7;
    out[3] += two70m40m7m6;
    out[4] += two70m6;
    out[5] += two70m6;
    out[6] += two70m6;
    out[7] += two70m6;

    out[0] -= in[0];
    out[1] -= in[1];
    out[2] -= in[2];
    out[3] -= in[3];
    out[4] -= in[4];
    out[5] -= in[5];
    out[6] -= in[6];
    out[7] -= in[7];
}

# define two64m32m0 (((limb)1) << 64) - (((limb)1) << 32) - 1
# define two64m0 (((limb)1) << 64) - 1
# define two64m32 (((limb)1) << 64) - (((limb)1) << 32)

/* zero64 == p */
static const felem zero64 = { two64m0, two64m32, two64m0, two64m32m0 };

/*-
 * felem_shrink converts an felem into a smallfelem. The result isn't quite
 * minimal as the value may be greater than p.
 *
 * On entry:
 *   in[i] < 2^109
 * On exit:
 *   out[i] < 2^64
 */
static void felem_shrink(smallfelem out, const felem in)
{
    felem tmp;
    u64 a, b, mask;
    s64 high, low;

    static const u64 kPrime3Test = 0x7ffffffefffffffful;

    /* Carry 2->3 */
    tmp[3] = zero64[3] + in[3] + ((u64)(in[2] >> 64));
    /* tmp[3] < 2^110 */

    tmp[2] = zero64[2] + (u64)in[2];
    tmp[1] = zero64[1] + in[1];
    tmp[0] = zero64[0] + in[0];
    /* tmp[0] < 2**110, tmp[1] < 2^111, tmp[2] < 2**65 */

    /*
     * We perform two partial reductions where we eliminate the high-word of
     * tmp[3]. We don't update the other words till the end.
     */
    a = tmp[3] >> 64;           /* a < 2^46 */
    tmp[3] = (u64)tmp[3];
    tmp[3] += ((limb) a) << 32;
    /* tmp[3] < 2^79 */

    b = a;
    a = tmp[3] >> 64;           /* a < 2^15 */
    b += a;                     /* b < 2^46 + 2^15 < 2^47 */
    tmp[3] = (u64)tmp[3];
    tmp[3] += ((limb) a) << 32;
    /* tmp[3] < 2^64 + 2^47 */

    /*
     * This adjusts the other two words to complete the two partial
     * reductions.
     */
    tmp[1] += (((limb) b) << 32);
    tmp[1] -= b;
    tmp[0] += b;

    /*
     * In order to make space in tmp[3] for the carry from 2 -> 3, we
     * conditionally subtract kPrime if tmp[3] is large enough.
     */
    high = tmp[3] >> 64;
    /* As tmp[3] < 2^65, high is either 1 or 0 */
    high <<= 63;
    high >>= 63;
    /*-
     * high is:
     *   all ones   if the high word of tmp[3] is 1
     *   all zeros  if the high word of tmp[3] if 0 */
    low = tmp[3];
    mask = low >> 63;
    /*-
     * mask is:
     *   all ones   if the MSB of low is 1
     *   all zeros  if the MSB of low if 0 */
    low &= bottom63bits;
    low -= kPrime3Test;
    /* if low was greater than kPrime3Test then the MSB is zero */
    low = ~low;
    low >>= 63;
    /*-
     * low is:
     *   all ones   if low was > kPrime3Test
     *   all zeros  if low was <= kPrime3Test */
    mask = (mask & low) | high;
    tmp[0] -= mask & kPrime[0];
    tmp[1] -= mask & kPrime[1];
    tmp[2] -= mask & kPrime[2];
    tmp[3] -= mask & kPrime[3];
    /* tmp[3] < 2**64 - 2**32 + 1 */

    tmp[1] += ((u64)(tmp[0] >> 64));
    tmp[0] = (u64)tmp[0];
    tmp[2] += ((u64)(tmp[1] >> 64));
    tmp[1] = (u64)tmp[1];
    tmp[3] += ((u64)(tmp[2] >> 64));
    tmp[2] = (u64)tmp[2];
    /* tmp[i] < 2^64 */

    out[0] = tmp[0];
    out[1] = tmp[1];
    out[2] = tmp[2];
    out[3] = tmp[3];
}

/* smallfelem_expand converts a smallfelem to an felem */
static void smallfelem_expand(felem out, const smallfelem in)
{
    out[0] = in[0];
    out[1] = in[1];
    out[2] = in[2];
    out[3] = in[3];
}

/*-
 * smallfelem_square sets |out| = |small|^2
 * On entry:
 *   small[i] < 2^64
 * On exit:
 *   out[i] < 7 * 2^64 < 2^67
 */
static void smallfelem_square(longfelem out, const smallfelem small)
{
    limb a;
    u64 high, low;

    a = ((uint128_t) small[0]) * small[0];
    low = a;
    high = a >> 64;
    out[0] = low;
    out[1] = high;

    a = ((uint128_t) small[0]) * small[1];
    low = a;
    high = a >> 64;
    out[1] += low;
    out[1] += low;
    out[2] = high;

    a = ((uint128_t) small[0]) * small[2];
    low = a;
    high = a >> 64;
    out[2] += low;
    out[2] *= 2;
    out[3] = high;

    a = ((uint128_t) small[0]) * small[3];
    low = a;
    high = a >> 64;
    out[3] += low;
    out[4] = high;

    a = ((uint128_t) small[1]) * small[2];
    low = a;
    high = a >> 64;
    out[3] += low;
    out[3] *= 2;
    out[4] += high;

    a = ((uint128_t) small[1]) * small[1];
    low = a;
    high = a >> 64;
    out[2] += low;
    out[3] += high;

    a = ((uint128_t) small[1]) * small[3];
    low = a;
    high = a >> 64;
    out[4] += low;
    out[4] *= 2;
    out[5] = high;

    a = ((uint128_t) small[2]) * small[3];
    low = a;
    high = a >> 64;
    out[5] += low;
    out[5] *= 2;
    out[6] = high;
    out[6] += high;

    a = ((uint128_t) small[2]) * small[2];
    low = a;
    high = a >> 64;
    out[4] += low;
    out[5] += high;

    a = ((uint128_t) small[3]) * small[3];
    low = a;
    high = a >> 64;
    out[6] += low;
    out[7] = high;
}

/*-
 * felem_square sets |out| = |in|^2
 * On entry:
 *   in[i] < 2^109
 * On exit:
 *   out[i] < 7 * 2^64 < 2^67
 */
static void felem_square(longfelem out, const felem in)
{
    u64 small[4];
    felem_shrink(small, in);
    smallfelem_square(out, small);
}

/*-
 * smallfelem_mul sets |out| = |small1| * |small2|
 * On entry:
 *   small1[i] < 2^64
 *   small2[i] < 2^64
 * On exit:
 *   out[i] < 7 * 2^64 < 2^67
 */
static void smallfelem_mul(longfelem out, const smallfelem small1,
                           const smallfelem small2)
{
    limb a;
    u64 high, low;

    a = ((uint128_t) small1[0]) * small2[0];
    low = a;
    high = a >> 64;
    out[0] = low;
    out[1] = high;

    a = ((uint128_t) small1[0]) * small2[1];
    low = a;
    high = a >> 64;
    out[1] += low;
    out[2] = high;

    a = ((uint128_t) small1[1]) * small2[0];
    low = a;
    high = a >> 64;
    out[1] += low;
    out[2] += high;

    a = ((uint128_t) small1[0]) * small2[2];
    low = a;
    high = a >> 64;
    out[2] += low;
    out[3] = high;

    a = ((uint128_t) small1[1]) * small2[1];
    low = a;
    high = a >> 64;
    out[2] += low;
    out[3] += high;

    a = ((uint128_t) small1[2]) * small2[0];
    low = a;
    high = a >> 64;
    out[2] += low;
    out[3] += high;

    a = ((uint128_t) small1[0]) * small2[3];
    low = a;
    high = a >> 64;
    out[3] += low;
    out[4] = high;

    a = ((uint128_t) small1[1]) * small2[2];
    low = a;
    high = a >> 64;
    out[3] += low;
    out[4] += high;

    a = ((uint128_t) small1[2]) * small2[1];
    low = a;
    high = a >> 64;
    out[3] += low;
    out[4] += high;

    a = ((uint128_t) small1[3]) * small2[0];
    low = a;
    high = a >> 64;
    out[3] += low;
    out[4] += high;

    a = ((uint128_t) small1[1]) * small2[3];
    low = a;
    high = a >> 64;
    out[4] += low;
    out[5] = high;

    a = ((uint128_t) small1[2]) * small2[2];
    low = a;
    high = a >> 64;
    out[4] += low;
    out[5] += high;

    a = ((uint128_t) small1[3]) * small2[1];
    low = a;
    high = a >> 64;
    out[4] += low;
    out[5] += high;

    a = ((uint128_t) small1[2]) * small2[3];
    low = a;
    high = a >> 64;
    out[5] += low;
    out[6] = high;

    a = ((uint128_t) small1[3]) * small2[2];
    low = a;
    high = a >> 64;
    out[5] += low;
    out[6] += high;

    a = ((uint128_t) small1[3]) * small2[3];
    low = a;
    high = a >> 64;
    out[6] += low;
    out[7] = high;
}

/*-
 * felem_mul sets |out| = |in1| * |in2|
 * On entry:
 *   in1[i] < 2^109
 *   in2[i] < 2^109
 * On exit:
 *   out[i] < 7 * 2^64 < 2^67
 */
static void felem_mul(longfelem out, const felem in1, const felem in2)
{
    smallfelem small1, small2;
    felem_shrink(small1, in1);
    felem_shrink(small2, in2);
    smallfelem_mul(out, small1, small2);
}

/*-
 * felem_small_mul sets |out| = |small1| * |in2|
 * On entry:
 *   small1[i] < 2^64
 *   in2[i] < 2^109
 * On exit:
 *   out[i] < 7 * 2^64 < 2^67
 */
static void felem_small_mul(longfelem out, const smallfelem small1,
                            const felem in2)
{
    smallfelem small2;
    felem_shrink(small2, in2);
    smallfelem_mul(out, small1, small2);
}

/*-
 * Internal function for the different flavours of felem_reduce.
 * felem_reduce_ reduces the higher coefficients in[4]-in[7].
 * On entry:
 *   out[0] >= in[6] + 2^32*in[6] + in[7] + 2^32*in[7]
 *   out[1] >= in[7] + 2^32*in[4]
 *   out[2] >= in[5] + 2^32*in[5]
 *   out[3] >= in[4] + 2^32*in[5] + 2^32*in[6]
 * On exit:
 *   out[0] <= out[0] + in[4] + 2^32*in[5]
 *   out[1] <= out[1] + in[5] + 2^33*in[6]
 *   out[2] <= out[2] + in[7] + 2*in[6] + 2^33*in[7]
 *   out[3] <= out[3] + 2^32*in[4] + 3*in[7]
 */
static void felem_reduce(felem out, const longfelem in)
{
    uint128_t a, b, c, d;
    a = in[6] + in[7];
    b = in[5] + in[7];
    c = in[4] + in[7];
    d = a + b;

    out[3] = in[3] + ((in[4] + in[5] + a * 2) << 32) + in[7];
    out[2] = in[2] + (b << 32) + a + in[7];
    out[1] = in[1] + ((c + in[6]) << 32) - c;
    out[0] = in[0] + (d << 32) + d + in[4];
}

/*
 * subtract_u64 sets *result = *result - v and *carry to one if the
 * subtraction underflowed.
 */
static void subtract_u64(u64 *result, u64 *carry, u64 v)
{
    uint128_t r = *result;
    r -= v;
    *carry = (r >> 64) & 1;
    *result = (u64)r;
}

/*
 * felem_contract converts |in| to its unique, minimal representation. On
 * entry: in[i] < 2^109
 */
static void felem_contract(smallfelem out, const felem in)
{
    unsigned i;
    u64 all_equal_so_far = 0, result = 0, carry;

    felem_shrink(out, in);
    /* small is minimal except that the value might be > p */

    all_equal_so_far--;
    /*
     * We are doing a constant time test if out >= kPrime. We need to compare
     * each u64, from most-significant to least significant. For each one, if
     * all words so far have been equal (m is all ones) then a non-equal
     * result is the answer. Otherwise we continue.
     */
    for (i = 3; i < 4; i--) {
        u64 equal;
        uint128_t a = ((uint128_t) kPrime[i]) - out[i];
        /*
         * if out[i] > kPrime[i] then a will underflow and the high 64-bits
         * will all be set.
         */
        result |= all_equal_so_far & ((u64)(a >> 64));

        /*
         * if kPrime[i] == out[i] then |equal| will be all zeros and the
         * decrement will make it all ones.
         */
        equal = kPrime[i] ^ out[i];
        equal--;
        equal &= equal << 32;
        equal &= equal << 16;
        equal &= equal << 8;
        equal &= equal << 4;
        equal &= equal << 2;
        equal &= equal << 1;
        equal = ((s64) equal) >> 63;

        all_equal_so_far &= equal;
    }

    /*
     * if all_equal_so_far is still all ones then the two values are equal
     * and so out >= kPrime is true.
     */
    result |= all_equal_so_far;

    /* if out >= kPrime then we subtract kPrime. */
    subtract_u64(&out[0], &carry, result & kPrime[0]);
    subtract_u64(&out[1], &carry, carry);
    subtract_u64(&out[2], &carry, carry);
    subtract_u64(&out[3], &carry, carry);

    subtract_u64(&out[1], &carry, result & kPrime[1]);
    subtract_u64(&out[2], &carry, carry);
    subtract_u64(&out[3], &carry, carry);

    subtract_u64(&out[2], &carry, result & kPrime[2]);
    subtract_u64(&out[3], &carry, carry);

    subtract_u64(&out[3], &carry, result & kPrime[3]);
}

static void smallfelem_square_contract(smallfelem out, const smallfelem in)
{
    longfelem longtmp;
    felem tmp;

    smallfelem_square(longtmp, in);
    felem_reduce(tmp, longtmp);
    felem_contract(out, tmp);
}

static void smallfelem_mul_contract(smallfelem out, const smallfelem in1,
                                    const smallfelem in2)
{
    longfelem longtmp;
    felem tmp;

    smallfelem_mul(longtmp, in1, in2);
    felem_reduce(tmp, longtmp);
    felem_contract(out, tmp);
}

/*-
 * felem_is_zero returns a limb with all bits set if |in| == 0 (mod p) and 0
 * otherwise.
 * On entry:
 *   small[i] < 2^64
 */
static limb smallfelem_is_zero(const smallfelem small)
{
    limb result;
    u64 is_p;

    u64 is_zero = small[0] | small[1] | small[2] | small[3];
    is_zero--;
    is_zero &= is_zero << 32;
    is_zero &= is_zero << 16;
    is_zero &= is_zero << 8;
    is_zero &= is_zero << 4;
    is_zero &= is_zero << 2;
    is_zero &= is_zero << 1;
    is_zero = ((s64) is_zero) >> 63;

    is_p = (small[0] ^ kPrime[0]) |
        (small[1] ^ kPrime[1]) |
        (small[2] ^ kPrime[2]) | (small[3] ^ kPrime[3]);
    is_p--;
    is_p &= is_p << 32;
    is_p &= is_p << 16;
    is_p &= is_p << 8;
    is_p &= is_p << 4;
    is_p &= is_p << 2;
    is_p &= is_p << 1;
    is_p = ((s64) is_p) >> 63;

    is_zero |= is_p;

    result = is_zero;
    result |= ((limb) is_zero) << 64;
    return result;
}

static int smallfelem_is_zero_int(const smallfelem small)
{
    return (int)(smallfelem_is_zero(small) & ((limb) 1));
}

/*-
 * felem_inv calculates |out| = |in|^{-1}
 */
static void felem_inv(felem out, const felem in)
{
    felem ftmp;
    felem a1, a2, a3, a4, a5;
    longfelem tmp;
    unsigned i;

    felem_square(tmp, in);
    felem_reduce(a1, tmp);
    felem_mul(tmp, a1, in);
    felem_reduce(a2, tmp);
    felem_square(tmp, a2);
    felem_reduce(ftmp, tmp);
    felem_square(tmp, ftmp);
    felem_reduce(ftmp, tmp);
    felem_mul(tmp, ftmp, a2);
    felem_reduce(a3, tmp);
    felem_square(tmp, a3);
    felem_reduce(ftmp, tmp);
    felem_square(tmp, ftmp);
    felem_reduce(ftmp, tmp);
    felem_square(tmp, ftmp);
    felem_reduce(ftmp, tmp);
    felem_square(tmp, ftmp);
    felem_reduce(ftmp, tmp);
    felem_mul(tmp, ftmp, a3);
    felem_reduce(a4, tmp);
    felem_square(tmp, a4);
    felem_reduce(a5, tmp);
    for (i = 1; i < 8; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a4);
    felem_reduce(a5, tmp);
    for (i = 0; i < 8; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a4);
    felem_reduce(a5, tmp);
    for (i = 0; i < 4; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a3);
    felem_reduce(a5, tmp);
    felem_square(tmp, a5);
    felem_reduce(a5, tmp);
    felem_square(tmp, a5);
    felem_reduce(a5, tmp);
    felem_mul(tmp, a5, a2);
    felem_reduce(a5, tmp);
    felem_square(tmp, a5);
    felem_reduce(ftmp, tmp);
    felem_mul(tmp, ftmp, in);
    felem_reduce(a5, tmp);
    felem_square(tmp, a5);
    felem_reduce(a4, tmp);
    felem_mul(tmp, a4, a1);
    felem_reduce(a3, tmp);
    felem_square(tmp, a4);
    felem_reduce(a5, tmp);
    for (i = 0; i < 30; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a4);
    felem_reduce(a4, tmp);
    felem_square(tmp, a4);
    felem_reduce(a4, tmp);
    felem_mul(tmp, a4, in);
    felem_reduce(a4, tmp);
    felem_mul(tmp, a4, a2);
    felem_reduce(a3, tmp);
    for (i = 0; i < 33; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a3);
    felem_reduce(a2, tmp);
    felem_mul(tmp, a2, a3);
    felem_reduce(a3, tmp);
    for (i = 0; i < 32; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a3);
    felem_reduce(a2, tmp);
    felem_mul(tmp, a2, a3);
    felem_reduce(a3, tmp);
    felem_mul(tmp, a2, a4);
    felem_reduce(a4, tmp);
    for (i = 0; i < 32; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a3);
    felem_reduce(a2, tmp);
    felem_mul(tmp, a2, a3);
    felem_reduce(a3, tmp);
    felem_mul(tmp, a2, a4);
    felem_reduce(a4, tmp);
    for (i = 0; i < 32; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a3);
    felem_reduce(a2, tmp);
    felem_mul(tmp, a2, a3);
    felem_reduce(a3, tmp);
    felem_mul(tmp, a2, a4);
    felem_reduce(a4, tmp);
    for (i = 0; i < 32; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a3);
    felem_reduce(a2, tmp);
    felem_mul(tmp, a2, a3);
    felem_reduce(a3, tmp);
    felem_mul(tmp, a2, a4);
    felem_reduce(a4, tmp);
    for (i = 0; i < 32; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a4, a5);
    felem_reduce(out, tmp);
}

#ifdef SM2_USE_INV_SQR
static void felem_inv_sqr(felem out, const felem in)
{
    felem ftmp;
    felem a1, a2, a3, a4, a5;
    longfelem tmp;
    unsigned i;

    felem_square(tmp, in);
    felem_reduce(a1, tmp);
    felem_mul(tmp, a1, in);
    felem_reduce(a2, tmp);
    felem_square(tmp, a2);
    felem_reduce(ftmp, tmp);
    felem_square(tmp, ftmp);
    felem_reduce(ftmp, tmp);
    felem_mul(tmp, ftmp, a2);
    felem_reduce(a3, tmp);
    felem_square(tmp, a3);
    felem_reduce(ftmp, tmp);
    felem_square(tmp, ftmp);
    felem_reduce(ftmp, tmp);
    felem_square(tmp, ftmp);
    felem_reduce(ftmp, tmp);
    felem_square(tmp, ftmp);
    felem_reduce(ftmp, tmp);
    felem_mul(tmp, ftmp, a3);
    felem_reduce(a4, tmp);
    felem_square(tmp, a4);
    felem_reduce(a5, tmp);
    for (i = 1; i < 8; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a4);
    felem_reduce(a5, tmp);
    for (i = 0; i < 8; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a4);
    felem_reduce(a5, tmp);
    for (i = 0; i < 4; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a3);
    felem_reduce(a5, tmp);
    felem_square(tmp, a5);
    felem_reduce(a5, tmp);
    felem_square(tmp, a5);
    felem_reduce(a5, tmp);
    felem_mul(tmp, a5, a2);
    felem_reduce(a5, tmp);
    felem_square(tmp, a5);
    felem_reduce(ftmp, tmp);
    felem_mul(tmp, ftmp, in);
    felem_reduce(a2, tmp);
    felem_mul(tmp, a2, in);
    felem_reduce(a4, tmp);
    felem_square(tmp, a2);
    felem_reduce(a5, tmp);
    for (i = 0; i < 30; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a2);
    felem_reduce(a3, tmp);
    felem_mul(tmp, a3, in);
    felem_reduce(a4, tmp);
    felem_square(tmp, a4);
    felem_reduce(a4, tmp);
    for (i = 0;  i < 32; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a4);
    felem_reduce(a4, tmp);
    for (i = 0; i < 32; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a4);
    felem_reduce(a2, tmp);
    felem_mul(tmp, a3, a2);
    felem_reduce(a3, tmp);
    felem_mul(tmp, a2, a4);
    felem_reduce(a4, tmp);
    for (i = 0; i < 32; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a4);
    felem_reduce(a2, tmp);
    felem_mul(tmp, a3, a2);
    felem_reduce(a3, tmp);
    felem_mul(tmp, a2, a4);
    felem_reduce(a4, tmp);
    for (i = 0; i < 32; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a4);
    felem_reduce(a2, tmp);
    felem_mul(tmp, a3, a2);
    felem_reduce(a3, tmp);
    felem_mul(tmp, a2, a4);
    felem_reduce(a4, tmp);
    for (i = 0; i < 32; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a4);
    felem_reduce(a2, tmp);
    felem_mul(tmp, a3, a2);
    felem_reduce(a3, tmp);
    felem_mul(tmp, a2, a4);
    felem_reduce(a4, tmp);
    for (i = 0; i < 32; i++) {
        felem_square(tmp, a5);
        felem_reduce(a5, tmp);
    }
    felem_mul(tmp, a5, a3);
    felem_reduce(a3, tmp);
    felem_square(tmp, a3);
    felem_reduce(a3, tmp);
    felem_square(tmp, a3);
    felem_reduce(out, tmp);
}
#endif

static void smallfelem_inv_contract(smallfelem out, const smallfelem in)
{
    felem tmp;

    smallfelem_expand(tmp, in);
    felem_inv(tmp, tmp);
    felem_contract(out, tmp);
}

/*-
 * Group operations
 * ----------------
 *
 * Building on top of the field operations we have the operations on the
 * elliptic curve group itself. Points on the curve are represented in Jacobian
 * coordinates
 */

/*-
 * point_double calculates 2*(x_in, y_in, z_in)
 *
 * The method is taken from:
 *   http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
 *
 * Outputs can equal corresponding inputs, i.e., x_out == x_in is allowed.
 * while x_out == y_in is not (maybe this works, but it's not tested).
 */
static void
point_double(felem x_out, felem y_out, felem z_out,
             const felem x_in, const felem y_in, const felem z_in)
{
    longfelem tmp, tmp2;
    felem delta, gamma, beta, alpha, ftmp, ftmp2;
    smallfelem small1, small2;

    felem_assign(ftmp, x_in);
    /* ftmp[i] < 2^106 */
    felem_assign(ftmp2, x_in);
    /* ftmp2[i] < 2^106 */

    /* delta = z^2 */
    felem_square(tmp, z_in);
    felem_reduce(delta, tmp);
    /* delta[i] < 2^101 */

    /* gamma = y^2 */
    felem_square(tmp, y_in);
    felem_reduce(gamma, tmp);

    /* gamma[i] < 2^101 */
    felem_shrink(small1, gamma);

    /* beta = x*gamma */
    felem_small_mul(tmp, small1, x_in);
    felem_reduce(beta, tmp);
    /* beta[i] < 2^101 */

    /* alpha = 3*(x-delta)*(x+delta) */
    felem_diff(ftmp, delta);
    /* ftmp[i] < 2^105 + 2^106 < 2^107 */

    felem_sum(ftmp2, delta);
    /* ftmp2[i] < 2^105 + 2^106 < 2^107 */

    felem_scalar(ftmp2, 3);
    /* ftmp2[i] < 3 * 2^107 < 2^109 */

    felem_mul(tmp, ftmp, ftmp2);
    felem_reduce(alpha, tmp);
    felem_shrink(small2, alpha);
    /* alpha[i] < 2^101 */

    /* x' = alpha^2 - 8*beta */
    smallfelem_square(tmp, small2);
    felem_reduce(x_out, tmp);
    felem_assign(ftmp, beta);
    felem_scalar(ftmp, 8);
    /* ftmp[i] < 8 * 2^101 = 2^104 */
    felem_diff(x_out, ftmp);
    /* x_out[i] < 2^105 + 2^101 < 2^106 */

    /* z' = (y + z)^2 - gamma - delta */
    felem_sum(delta, gamma);
    /* delta[i] < 2^101 + 2^101 = 2^102 */
    felem_assign(ftmp, y_in);
    felem_sum(ftmp, z_in);
    /* ftmp[i] < 2^106 + 2^106 = 2^107 */
    felem_square(tmp, ftmp);
    felem_reduce(z_out, tmp);
    felem_diff(z_out, delta);
    /* z_out[i] < 2^105 + 2^101 < 2^106 */

    /* y' = alpha*(4*beta - x') - 8*gamma^2 */
    felem_scalar(beta, 4);
    /* beta[i] < 4 * 2^101 = 2^103 */
    felem_diff_zero107(beta, x_out);
    /* beta[i] < 2^107 + 2^103 < 2^108 */
    felem_small_mul(tmp, small2, beta);
    /* tmp[i] < 7 * 2^64 < 2^67 */
    smallfelem_square(tmp2, small1);
    /* tmp2[i] < 7 * 2^64 */
    longfelem_scalar(tmp2, 8);
    /* tmp2[i] < 8 * 7 * 2^64 = 7 * 2^67 */

    longfelem_diff(tmp, tmp2);
    /* tmp[i] < 2^67 + 2^70 + 2^40 < 2^71 */
    felem_reduce(y_out, tmp);
    /* y_out[i] < 2^106 */
}

/*
 * point_double_small is the same as point_double, except that it operates on
 * smallfelems
 */
static void
point_double_small(smallfelem x_out, smallfelem y_out, smallfelem z_out,
                   const smallfelem x_in, const smallfelem y_in,
                   const smallfelem z_in)
{
    felem felem_x_out, felem_y_out, felem_z_out;
    felem felem_x_in, felem_y_in, felem_z_in;

    smallfelem_expand(felem_x_in, x_in);
    smallfelem_expand(felem_y_in, y_in);
    smallfelem_expand(felem_z_in, z_in);
    point_double(felem_x_out, felem_y_out, felem_z_out,
                 felem_x_in, felem_y_in, felem_z_in);
    felem_shrink(x_out, felem_x_out);
    felem_shrink(y_out, felem_y_out);
    felem_shrink(z_out, felem_z_out);
}

/* copy_conditional copies in to out iff mask is all ones. */
static void copy_conditional(felem out, const felem in, limb mask)
{
    unsigned i;
    for (i = 0; i < NLIMBS; ++i) {
        const limb tmp = mask & (in[i] ^ out[i]);
        out[i] ^= tmp;
    }
}

/* copy_small_conditional copies in to out iff mask is all ones. */
static void copy_small_conditional(felem out, const smallfelem in, limb mask)
{
    unsigned i;
    const u64 mask64 = mask;
    for (i = 0; i < NLIMBS; ++i) {
        out[i] = ((limb) (in[i] & mask64)) | (out[i] & ~mask);
    }
}

/*-
 * point_add calculates (x1, y1, z1) + (x2, y2, z2)
 *
 * The method is taken from:
 *   http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl,
 * adapted for mixed addition (z2 = 1, or z2 = 0 for the point at infinity).
 *
 * This function includes a branch for checking whether the two input points
 * are equal, (while not equal to the point at infinity). This case never
 * happens during single point multiplication, so there is no timing leak for
 * ECDH or ECDSA signing.
 */
static void point_add(felem x3, felem y3, felem z3,
                      const felem x1, const felem y1, const felem z1,
                      const int mixed, const smallfelem x2,
                      const smallfelem y2, const smallfelem z2)
{
    felem ftmp, ftmp2, ftmp3, ftmp4, ftmp5, ftmp6, x_out, y_out, z_out;
    longfelem tmp, tmp2;
    smallfelem small1, small2, small3, small4, small5;
    limb x_equal, y_equal, z1_is_zero, z2_is_zero;


    felem_shrink(small3, z1);

    z1_is_zero = smallfelem_is_zero(small3);
    z2_is_zero = smallfelem_is_zero(z2);

    /* ftmp = z1z1 = z1**2 */
    smallfelem_square(tmp, small3);
    felem_reduce(ftmp, tmp);
    /* ftmp[i] < 2^101 */
    felem_shrink(small1, ftmp);

    if (!mixed) {
        /* ftmp2 = z2z2 = z2**2 */
        smallfelem_square(tmp, z2);
        felem_reduce(ftmp2, tmp);
        /* ftmp2[i] < 2^101 */
        felem_shrink(small2, ftmp2);

        felem_shrink(small5, x1);

        /* u1 = ftmp3 = x1*z2z2 */
        smallfelem_mul(tmp, small5, small2);
        felem_reduce(ftmp3, tmp);
        /* ftmp3[i] < 2^101 */

        /* ftmp5 = z1 + z2 */
        felem_assign(ftmp5, z1);
        felem_small_sum(ftmp5, z2);
        /* ftmp5[i] < 2^107 */

        /* ftmp5 = (z1 + z2)**2 - (z1z1 + z2z2) = 2z1z2 */
        felem_square(tmp, ftmp5);
        felem_reduce(ftmp5, tmp);
        /* ftmp2 = z2z2 + z1z1 */
        felem_sum(ftmp2, ftmp);
        /* ftmp2[i] < 2^101 + 2^101 = 2^102 */
        felem_diff(ftmp5, ftmp2);
        /* ftmp5[i] < 2^105 + 2^101 < 2^106 */

        /* ftmp2 = z2 * z2z2 */
        smallfelem_mul(tmp, small2, z2);
        felem_reduce(ftmp2, tmp);

        /* s1 = ftmp2 = y1 * z2**3 */
        felem_mul(tmp, y1, ftmp2);
        felem_reduce(ftmp6, tmp);
        /* ftmp6[i] < 2^101 */
    } else {
        /*
         * We'll assume z2 = 1 (special case z2 = 0 is handled later)
         */

        /* u1 = ftmp3 = x1*z2z2 */
        felem_assign(ftmp3, x1);
        /* ftmp3[i] < 2^106 */

        /* ftmp5 = 2z1z2 */
        felem_assign(ftmp5, z1);
        felem_scalar(ftmp5, 2);
        /* ftmp5[i] < 2*2^106 = 2^107 */

        /* s1 = ftmp2 = y1 * z2**3 */
        felem_assign(ftmp6, y1);
        /* ftmp6[i] < 2^106 */
    }

    /* u2 = x2*z1z1 */
    smallfelem_mul(tmp, x2, small1);
    felem_reduce(ftmp4, tmp);

    /* h = ftmp4 = u2 - u1 */
    felem_diff_zero107(ftmp4, ftmp3);
    /* ftmp4[i] < 2^107 + 2^101 < 2^108 */
    felem_shrink(small4, ftmp4);

    x_equal = smallfelem_is_zero(small4);

    /* z_out = ftmp5 * h */
    felem_small_mul(tmp, small4, ftmp5);
    felem_reduce(z_out, tmp);
    /* z_out[i] < 2^101 */

    /* ftmp = z1 * z1z1 */
    smallfelem_mul(tmp, small1, small3);
    felem_reduce(ftmp, tmp);

    /* s2 = tmp = y2 * z1**3 */
    felem_small_mul(tmp, y2, ftmp);
    felem_reduce(ftmp5, tmp);

    /* r = ftmp5 = (s2 - s1)*2 */
    felem_diff_zero107(ftmp5, ftmp6);
    /* ftmp5[i] < 2^107 + 2^107 = 2^108 */
    felem_scalar(ftmp5, 2);
    /* ftmp5[i] < 2^109 */
    felem_shrink(small1, ftmp5);
    y_equal = smallfelem_is_zero(small1);

    if (x_equal && y_equal && !z1_is_zero && !z2_is_zero) {
        point_double(x3, y3, z3, x1, y1, z1);
        return;
    }

    /* I = ftmp = (2h)**2 */
    felem_assign(ftmp, ftmp4);
    felem_scalar(ftmp, 2);
    /* ftmp[i] < 2*2^108 = 2^109 */
    felem_square(tmp, ftmp);
    felem_reduce(ftmp, tmp);

    /* J = ftmp2 = h * I */
    felem_mul(tmp, ftmp4, ftmp);
    felem_reduce(ftmp2, tmp);

    /* V = ftmp4 = U1 * I */
    felem_mul(tmp, ftmp3, ftmp);
    felem_reduce(ftmp4, tmp);

    /* x_out = r**2 - J - 2V */
    smallfelem_square(tmp, small1);
    felem_reduce(x_out, tmp);
    felem_assign(ftmp3, ftmp4);
    felem_scalar(ftmp4, 2);
    felem_sum(ftmp4, ftmp2);
    /* ftmp4[i] < 2*2^101 + 2^101 < 2^103 */
    felem_diff(x_out, ftmp4);
    /* x_out[i] < 2^105 + 2^101 */

    /* y_out = r(V-x_out) - 2 * s1 * J */
    felem_diff_zero107(ftmp3, x_out);
    /* ftmp3[i] < 2^107 + 2^101 < 2^108 */
    felem_small_mul(tmp, small1, ftmp3);
    felem_mul(tmp2, ftmp6, ftmp2);
    longfelem_scalar(tmp2, 2);
    /* tmp2[i] < 2*2^67 = 2^68 */
    longfelem_diff(tmp, tmp2);
    /* tmp[i] < 2^67 + 2^70 + 2^40 < 2^71 */
    felem_reduce(y_out, tmp);
    /* y_out[i] < 2^106 */

    copy_small_conditional(x_out, x2, z1_is_zero);
    copy_conditional(x_out, x1, z2_is_zero);
    copy_small_conditional(y_out, y2, z1_is_zero);
    copy_conditional(y_out, y1, z2_is_zero);
    copy_small_conditional(z_out, z2, z1_is_zero);
    copy_conditional(z_out, z1, z2_is_zero);
    felem_assign(x3, x_out);
    felem_assign(y3, y_out);
    felem_assign(z3, z_out);
}

/*
 * point_add_small is the same as point_add, except that it operates on
 * smallfelems
 */
static void point_add_small(smallfelem x3, smallfelem y3, smallfelem z3,
                            smallfelem x1, smallfelem y1, smallfelem z1,
                            smallfelem x2, smallfelem y2, smallfelem z2)
{
    felem felem_x3, felem_y3, felem_z3;
    felem felem_x1, felem_y1, felem_z1;
    smallfelem_expand(felem_x1, x1);
    smallfelem_expand(felem_y1, y1);
    smallfelem_expand(felem_z1, z1);
    point_add(felem_x3, felem_y3, felem_z3, felem_x1, felem_y1, felem_z1, 0,
              x2, y2, z2);
    felem_shrink(x3, felem_x3);
    felem_shrink(y3, felem_y3);
    felem_shrink(z3, felem_z3);
}

/*-
 * Base point pre computation
 * --------------------------
 *
 * Two different sorts of precomputed tables are used in the following code.
 * Each contain various points on the curve, where each point is three field
 * elements (x, y, z).
 *
 * For the base point table, z is usually 1 (0 for the point at infinity).
 * This table has 2 * 16 elements, starting with the following:
 * index | bits    | point
 * ------+---------+------------------------------
 *     0 | 0 0 0 0 | 0G
 *     1 | 0 0 0 1 | 1G
 *     2 | 0 0 1 0 | 2^64G
 *     3 | 0 0 1 1 | (2^64 + 1)G
 *     4 | 0 1 0 0 | 2^128G
 *     5 | 0 1 0 1 | (2^128 + 1)G
 *     6 | 0 1 1 0 | (2^128 + 2^64)G
 *     7 | 0 1 1 1 | (2^128 + 2^64 + 1)G
 *     8 | 1 0 0 0 | 2^192G
 *     9 | 1 0 0 1 | (2^192 + 1)G
 *    10 | 1 0 1 0 | (2^192 + 2^64)G
 *    11 | 1 0 1 1 | (2^192 + 2^64 + 1)G
 *    12 | 1 1 0 0 | (2^192 + 2^128)G
 *    13 | 1 1 0 1 | (2^192 + 2^128 + 1)G
 *    14 | 1 1 1 0 | (2^192 + 2^128 + 2^64)G
 *    15 | 1 1 1 1 | (2^192 + 2^128 + 2^64 + 1)G
 * followed by a copy of this with each element multiplied by 2^32.
 *
 * The reason for this is so that we can clock bits into four different
 * locations when doing simple scalar multiplies against the base point,
 * and then another four locations using the second 16 elements.
 *
 * Tables for other points have table[i] = iG for i in 0 .. 16. */

/* gmul is the table of precomputed base points */
static const smallfelem gmul[2][16][3] = {
    {{{0, 0, 0, 0},
      {0, 0, 0, 0},
      {0, 0, 0, 0}},
     {{0x715a4589334c74c7, 0x8fe30bbff2660be1, 0x5f9904466a39c994,
       0x32c4ae2c1f198119},
      {0x2df32e52139f0a0, 0xd0a9877cc62a4740, 0x59bdcee36b692153,
       0xbc3736a2f4f6779c},
      {1, 0, 0, 0}},
     {{0xe18bd546b5824517, 0x673891d791caa486, 0xba220b99df9f9a14,
       0x95afbd1155c1da54},
      {0x8e4450eb334acdcb, 0xc3c7d1898a53f20d, 0x2eee750f4053017c,
       0xe8a6d82c517388c2},
      {1, 0, 0, 0}},
     {{0xf81c8da9b99fba55, 0x137f6c6149feef6e, 0xcb129aa494da9ad4,
       0x82a0f5407d123db6},
      {0xfdeca00772c4dbc9, 0xa961b58f0cf58373, 0xecacab94e973f9c3,
       0xf12fa4696a22ca3f},
      {1, 0, 0, 0}},
     {{0xeae3d9a9d13a42ed, 0x2b2308f6484e1b38, 0x3db7b24888c21f3a,
       0xb692e5b574d55da9},
      {0xd186469de295e5ab, 0xdb61ac1773438e6d, 0x5a924f85544926f9,
       0xa175051b0f3fb613},
      {1, 0, 0, 0}},
     {{0xa72d084f62c8d58b, 0xe3d6467deaf48fd7, 0x8fe75e5a128a56a7,
       0xc0023fe7ff2b68bd},
      {0x64f67782316815f9, 0xb52b6d9b19a69cd2, 0x5d1ed6fa89cbbade,
       0x796c910ee7f4ccdb},
      {1, 0, 0, 0}},
     {{0x1b2150c1c5f13015, 0xdaaba91b5d952c9b, 0xe8cc24c3f546142,
       0x75a34b243705f260},
      {0x77d195421cef1339, 0x636644aa0c3a0623, 0x4683df176eeb2444,
       0x642ce3bd3535e74d},
      {1, 0, 0, 0}},
     {{0x4a59ac2c6e7ecc08, 0xaf2b71164f191d63, 0x3622a87fb284554f,
       0xd9eb397b441e9cd0},
      {0xa66b8a4893b6a54d, 0x26fb89a40b4a663a, 0xafa87501eedfc9f4,
       0xf3f000bc66f98108},
      {1, 0, 0, 0}},
     {{0xad8bc68ce031d616, 0x16888d8ee4003187, 0x44c0757f3bb8b600,
       0x793fae7af0164245},
      {0x210cd042973f333b, 0x8666ff52dbd25f9, 0x65c5b129f5f7ad5d,
       0xe03d7a8d19b3219a},
      {1, 0, 0, 0}},
     {{0xd68bfbace0e00392, 0x261014f7d3445dc7, 0xd9f46b2714a071ee,
       0x1b200af30810b682},
      {0xd91d8b12ae69bcd, 0x74a08f17bf8cd981, 0xd822913cf0d2b82d,
       0x248b7af0b05bfad2},
      {1, 0, 0, 0}},
     {{0xba119a049e62f2e2, 0xf278e8a34df05ae5, 0xd269f3564eb5d180,
       0x8e74ad0f4f957cb1},
      {0x112ff4dabd76e2dd, 0x91373f20630fdb7f, 0xf43eab474992904c,
       0x55a5ccc7af3b6db4},
      {1, 0, 0, 0}},
     {{0x5ad104a8bdd23de9, 0xf5a9e515eb71c2c1, 0x390542a0ba95c174,
       0x4c55fb20426491bf},
      {0x91525735ef626289, 0xd2ed977f88f09635, 0xfd48731b7a8a8521,
       0x8f89a03b8fdebea},
      {1, 0, 0, 0}},
     {{0x7e8e61ea35eb8e2e, 0x1bb2700db98a762c, 0xd81ea23b7738c17c,
       0xf9def2a46dba26a3},
      {0x183a7912d05e329f, 0x34664a0896ccde0e, 0x56c22652614283bb,
       0x91692899d5ff0513},
      {1, 0, 0, 0}},
     {{0x449d48d8f3bdbe19, 0xab95de03cc8510cb, 0xaef159463f8bfb25,
       0xda72c379dae3ca8b},
      {0xcba9315ce82cc3ea, 0x4e524bac38a58020, 0x36ba2752538e348c,
       0xb170d0da75ed450f},
      {1, 0, 0, 0}},
     {{0x947af0f52b4f8da6, 0x7eda17d917827976, 0x5ba79a0c705853a0,
       0xa5d9873b3fb2ddc7},
      {0xc2a48162a5fd9ce9, 0x80ee8ae526f25f02, 0xf60c8ef6633be6a9,
       0xe2e23f0229a84a35},
      {1, 0, 0, 0}},
     {{0xbc4945bd86bb6afb, 0x237eb711eba46fee, 0x7c1db58b7b86eb33,
       0xd94eb728273b3ac7},
      {0xbe1717e59568d0a4, 0x4a6067cc45f70212, 0x19b32eb5afc2fb17,
       0xbe3c1e7ac3ac9d3c},
      {1, 0, 0, 0}}},
    {{{0, 0, 0, 0},
      {0, 0, 0, 0},
      {0, 0, 0, 0}},
     {{0x68a88405ae53c1e9, 0x51e46707fd558656, 0x71e834cf86896c10,
       0x3d251b54e10d581f},
      {0x1884d5b0eeb19032, 0xeeaf729853e526fe, 0x5931f6831a8d8c11,
       0x87891d33fb98b4d8},
      {1, 0, 0, 0}},
     {{0x9047673fcac14893, 0xf5df5d83bfb58659, 0xa6230c81642e71a,
       0xef14b33800777791},
      {0xcf1e99afa3386fca, 0x7ace937791313d53, 0x36fe159b6dcd01bb,
       0xc9bc50d02e2b960a},
      {1, 0, 0, 0}},
     {{0x716e5a7ee12e162d, 0xbbf9bb2c62dd5a00, 0xca235ccb4144dd05,
       0xbcb7de0f8f70520e},
      {0x981e8964947cb8eb, 0x53c7102ea04de08d, 0xe9076332afc6a10d,
       0x93d90f776b58c35d},
      {1, 0, 0, 0}},
     {{0x834dbff6678337ee, 0xc607e811fef0785a, 0xaaefc62be30a298b,
       0xeb5ca335326afad3},
      {0x9774fe1384af54a8, 0xca4b6ef5785388b4, 0x1346c82d66f6c642,
       0xedcc0c2aaa2d53ce},
      {1, 0, 0, 0}},
     {{0xb896b3f764b9e6f4, 0x47e4018c736fb3d0, 0xfc2fc86707413920,
       0x1a8526428e1aeae7},
      {0x1386802650e2ae60, 0x7474dedc995384d0, 0x2c4cc396dd43b011,
       0x63b0e9c7141de1b0},
      {1, 0, 0, 0}},
     {{0xeb5fb3b369d17771, 0x1fe07b18933ed257, 0xdfc4c81ce3673912,
       0x913614c66a91a647},
      {0x18aee853c0ba877f, 0x3109c2deceff091, 0x8532307e7e4ee08c,
       0xcef0791a6e6ce0bb},
      {1, 0, 0, 0}},
     {{0xf0e9f5d8057a4a0f, 0xbbf7f8b49f125aa9, 0x51e8fdd6283187c2,
       0xe0997d4759d36298},
      {0x67ec3c5c6f4221c3, 0x3ea275dbc860722f, 0x152d01e23859f5e2,
       0xfb57404312680f44},
      {1, 0, 0, 0}},
     {{0x21ac3df849be2a1f, 0x11006e9fc51d112f, 0x9151aa584775c857,
       0x5159d218ba04a8d9},
      {0x98b7d1a925fd1866, 0x8f4753cafc2ad9d8, 0x8eb91ec1569c05a9,
       0x4abbd1ae27e13f11},
      {1, 0, 0, 0}},
     {{0x616f6644b2c11f4c, 0x251cd7140e540758, 0xf927a40110f02017,
       0x92ff3cc3c1c941b6},
      {0x3249906213f565fe, 0x4633e3ddeb9dbd4e, 0xea9a9d1ec402e6c2,
       0xdc84ce34b14bb7cf},
      {1, 0, 0, 0}},
     {{0xa93e23e5436ff69a, 0x52dcb0a79b63efce, 0x34f6538a9e90cb41,
       0x9cac08f200234bc0},
      {0x6661825b5174a02d, 0x7d4d06de036be57, 0x589d74610ae6bd27,
       0xa296f5577fc91a93},
      {1, 0, 0, 0}},
     {{0x10acefa9d29721d0, 0x8b0f6b8bb5bcd340, 0x921d318c3d86785c,
       0xd6916f3bc16aa378},
      {0x2a0d646a7ad84a0e, 0x7b93256c2fe7e97a, 0x5765e27626479e41,
       0xae9da2272daaced3},
      {1, 0, 0, 0}},
     {{0x56fdc215f7f34ac5, 0xebcb4ff2da3877d3, 0x1eb96792aba6b832,
       0x807ce6bea24741aa},
      {0xff1c10109c721fb4, 0xd187d4bc796353a7, 0x7639ae749af2d303,
       0xaff6d783d56c9286},
      {1, 0, 0, 0}},
     {{0x6002d51b6290dd01, 0xcba3ab0099a836a5, 0x71776611e00d2528,
       0xfaf2cb8c87fce119},
      {0xd445228bdf6882ae, 0xcbbfade17cbce919, 0x837b6335a2eb2453,
       0x11ad7c4b8597f6b6},
      {1, 0, 0, 0}},
     {{0x48de8f368cf2e399, 0x7ae3d25630a74277, 0xdef1a9a6c505323f,
       0xe55f203b4b8d9672},
      {0xc58d8f0d9a1e6e97, 0xe160e6d4b2737a76, 0xd60bd087d47cbdd8,
       0x687d41364d5fef53},
      {1, 0, 0, 0}},
     {{0x83f21bbe056bbf9b, 0x4c2a9d120b4ba5ab, 0xff383d1845b64e4f,
       0x8f13cc8d06dd7867},
      {0xf3a292d8424f0995, 0xfd2546eae7cbe44b, 0x67d14dee6c1e75a3,
       0x53b49e6cc93fb5a8},
      {1, 0, 0, 0}}}
};

/*
 * select_point selects the |idx|th point from a precomputation table and
 * copies it to out.
 */
static void select_point(const u64 idx, unsigned int size,
                         const smallfelem pre_comp[16][3], smallfelem out[3])
{
    unsigned j;
    u64 *outlimbs = &out[0][0];

#ifdef SM2_NO_CONST_TIME
    const u64 *inlimbs = (u64 *)&pre_comp[idx][0][0];
    for (j = 0; j < NLIMBS * 3; j++) {
        outlimbs[j] = inlimbs[j];
    }
#else
    int i;
    memset(out, 0, sizeof(*out) * 3);

    for (i = 0; i < size; i++) {
        const u64 *inlimbs = (u64 *)&pre_comp[i][0][0];
        u64 mask = i ^ idx;
        mask |= mask >> 4;
        mask |= mask >> 2;
        mask |= mask >> 1;
        mask &= 1;
        mask--;
        for (j = 0; j < NLIMBS * 3; j++)
            outlimbs[j] |= inlimbs[j] & mask;
    }
#endif
}

/* get_bit returns the |i|th bit in |in| */
static char get_bit(const felem_bytearray in, int i)
{
    if ((i < 0) || (i >= 256))
        return 0;
    return (in[i >> 3] >> (i & 7)) & 1;
}

/*
 * Interleaved point multiplication using precomputed point multiples: The
 * small point multiples 0*P, 1*P, ..., 17*P are in pre_comp[], the scalars
 * in scalars[]. If g_scalar is non-NULL, we also add this multiple of the
 * generator, using certain (large) precomputed multiples in g_pre_comp.
 * Output point (X, Y, Z) is stored in x_out, y_out, z_out
 */
static void batch_mul(felem x_out, felem y_out, felem z_out,
                      const felem_bytearray scalars[],
                      const unsigned num_points, const u8 *g_scalar,
                      const int mixed, const smallfelem pre_comp[][17][3],
                      const smallfelem g_pre_comp[2][16][3])
{
    int i, skip;
    unsigned num, gen_mul = (g_scalar != NULL);
    felem nq[3], ftmp;
    smallfelem tmp[3];
    u64 bits;
    u8 sign, digit;

    /* set nq to the point at infinity */
    memset(nq, 0, sizeof(nq));


    /*
     * Loop over all scalars msb-to-lsb, interleaving additions of multiples
     * of the generator (two in each of the last 32 rounds) and additions of
     * other points multiples (every 5th round).
     */
    skip = 1;                   /* save two point operations in the first
                                 * round */
    for (i = (num_points ? 255 : 31); i >= 0; --i) {
        /* double */
        if (!skip)
            point_double(nq[0], nq[1], nq[2], nq[0], nq[1], nq[2]);

        /* add multiples of the generator */
        if (gen_mul && (i <= 31)) {
            /* first, look 32 bits upwards */
            bits = get_bit(g_scalar, i + 224) << 3;
            bits |= get_bit(g_scalar, i + 160) << 2;
            bits |= get_bit(g_scalar, i + 96) << 1;
            bits |= get_bit(g_scalar, i + 32);
            /* select the point to add, in constant time */
            select_point(bits, 16, g_pre_comp[1], tmp);

            if (!skip) {
                /* Arg 1 below is for "mixed" */
                point_add(nq[0], nq[1], nq[2],
                          nq[0], nq[1], nq[2], 1, tmp[0], tmp[1], tmp[2]);
            } else {
                smallfelem_expand(nq[0], tmp[0]);
                smallfelem_expand(nq[1], tmp[1]);
                smallfelem_expand(nq[2], tmp[2]);
                skip = 0;
            }

            /* second, look at the current position */
            bits = get_bit(g_scalar, i + 192) << 3;
            bits |= get_bit(g_scalar, i + 128) << 2;
            bits |= get_bit(g_scalar, i + 64) << 1;
            bits |= get_bit(g_scalar, i);
            /* select the point to add, in constant time */
            select_point(bits, 16, g_pre_comp[0], tmp);
            /* Arg 1 below is for "mixed" */
            point_add(nq[0], nq[1], nq[2],
                      nq[0], nq[1], nq[2], 1, tmp[0], tmp[1], tmp[2]);
        }

        /* do other additions every 5 doublings */
        if (num_points && (i % 5 == 0)) {
            /* loop over all scalars */
            for (num = 0; num < num_points; ++num) {
                bits = get_bit(scalars[num], i + 4) << 5;
                bits |= get_bit(scalars[num], i + 3) << 4;
                bits |= get_bit(scalars[num], i + 2) << 3;
                bits |= get_bit(scalars[num], i + 1) << 2;
                bits |= get_bit(scalars[num], i) << 1;
                bits |= get_bit(scalars[num], i - 1);
                ec_GFp_nistp_recode_scalar_bits(&sign, &digit, bits);
                /*
                 * select the point to add or subtract, in constant time
                 */
                select_point(digit, 17, pre_comp[num], tmp);
                smallfelem_neg(ftmp, tmp[1]); /* (X, -Y, Z) is the negative
                                               * point */
                copy_small_conditional(ftmp, tmp[1], (((limb) sign) - 1));
                felem_contract(tmp[1], ftmp);

                if (!skip) {
                    point_add(nq[0], nq[1], nq[2],
                              nq[0], nq[1], nq[2],
                              mixed, tmp[0], tmp[1], tmp[2]);
                } else {
                    smallfelem_expand(nq[0], tmp[0]);
                    smallfelem_expand(nq[1], tmp[1]);
                    smallfelem_expand(nq[2], tmp[2]);
                    skip = 0;
                }
            }
        }
    }
    felem_assign(x_out, nq[0]);
    felem_assign(y_out, nq[1]);
    felem_assign(z_out, nq[2]);
}

/* Precomputation for the group generator. */
struct sm2p256_pre_comp_st {
    smallfelem g_pre_comp[2][16][3];
    int references;
    CRYPTO_RWLOCK *lock;
};

const EC_METHOD *EC_GFp_sm2p256_method(void)
{
    static const EC_METHOD ret = {
        EC_FLAGS_DEFAULT_OCT,
        NID_X9_62_prime_field,
        ec_GFp_sm2p256_group_init,
        ec_GFp_simple_group_finish,
        ec_GFp_simple_group_clear_finish,
        ec_GFp_nist_group_copy,
        ec_GFp_sm2p256_group_set_curve,
        ec_GFp_simple_group_get_curve,
        ec_GFp_simple_group_get_degree,
        ec_group_simple_order_bits,
        ec_GFp_simple_group_check_discriminant,
        ec_GFp_simple_point_init,
        ec_GFp_simple_point_finish,
        ec_GFp_simple_point_clear_finish,
        ec_GFp_simple_point_copy,
        ec_GFp_simple_point_set_to_infinity,
        //ec_GFp_simple_set_Jprojective_coordinates_GFp,
        //ec_GFp_simple_get_Jprojective_coordinates_GFp,
        ec_GFp_simple_point_set_affine_coordinates,
        ec_GFp_sm2p256_point_get_affine_coordinates,
        0 /* point_set_compressed_coordinates */ ,
        0 /* point2oct */ ,
        0 /* oct2point */ ,
        ec_GFp_simple_add,
        ec_GFp_simple_dbl,
        ec_GFp_simple_invert,
        ec_GFp_simple_is_at_infinity,
        ec_GFp_simple_is_on_curve,
        ec_GFp_simple_cmp,
        ec_GFp_simple_make_affine,
        ec_GFp_simple_points_make_affine,
        ec_GFp_sm2p256_points_mul,
        ec_GFp_sm2p256_precompute_mult,
        ec_GFp_sm2p256_have_precompute_mult,
        ec_GFp_nist_field_mul,
        ec_GFp_nist_field_sqr,
        0 /* field_div */ ,
        0 /* field_inv */,
        0 /* field_encode */ ,
        0 /* field_decode */ ,
        0,                      /* field_set_to_one */
        ec_key_simple_priv2oct,
        ec_key_simple_oct2priv,
        0, /* set private */
        ec_key_simple_generate_key,
        ec_key_simple_check_key,
        ec_key_simple_generate_public_key,
        0, /* keycopy */
        0, /* keyfinish */
        ecdh_simple_compute_key,
        0, 0, 0, 0, 0, 0, 0, 0
    };
    return &ret;
}

/******************************************************************************/
/*
 * FUNCTIONS TO MANAGE PRECOMPUTATION
 */

static SM2P256_PRE_COMP *sm2p256_pre_comp_new()
{
    SM2P256_PRE_COMP *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        ECerr(EC_F_SM2P256_PRE_COMP_NEW, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    ret->references = 1;

    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        ECerr(EC_F_SM2P256_PRE_COMP_NEW, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return NULL;
    }
    return ret;
}

SM2P256_PRE_COMP *EC_sm2p256_pre_comp_dup(SM2P256_PRE_COMP *p)
{
    int i;
    if (p != NULL)
        CRYPTO_atomic_add(&p->references, 1, &i, p->lock);
    return p;
}

void EC_sm2p256_pre_comp_free(SM2P256_PRE_COMP *pre)
{
    int i;

    if (pre == NULL)
        return;

    CRYPTO_atomic_add(&pre->references, -1, &i, pre->lock);
    REF_PRINT_COUNT("EC_sm2p256", x);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    CRYPTO_THREAD_lock_free(pre->lock);
    OPENSSL_free(pre);
}

/******************************************************************************/
/*
 * OPENSSL EC_METHOD FUNCTIONS
 */

int ec_GFp_sm2p256_group_init(EC_GROUP *group)
{
    int ret;
    ret = ec_GFp_simple_group_init(group);
    group->a_is_minus3 = 1;
    return ret;
}

int ec_GFp_sm2p256_group_set_curve(EC_GROUP *group, const BIGNUM *p,
                                   const BIGNUM *a, const BIGNUM *b,
                                   BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX *new_ctx = NULL;
    BIGNUM *curve_p, *curve_a, *curve_b;

    if (ctx == NULL)
        if ((ctx = new_ctx = BN_CTX_new()) == NULL)
            return 0;
    BN_CTX_start(ctx);
    if (((curve_p = BN_CTX_get(ctx)) == NULL) ||
        ((curve_a = BN_CTX_get(ctx)) == NULL) ||
        ((curve_b = BN_CTX_get(ctx)) == NULL))
        goto err;
    BN_bin2bn(sm2p256v1_curve_params[0], sizeof(felem_bytearray), curve_p);
    BN_bin2bn(sm2p256v1_curve_params[1], sizeof(felem_bytearray), curve_a);
    BN_bin2bn(sm2p256v1_curve_params[2], sizeof(felem_bytearray), curve_b);
    if ((BN_cmp(curve_p, p)) || (BN_cmp(curve_a, a)) || (BN_cmp(curve_b, b))) {
        ECerr(EC_F_EC_GFP_SM2P256_GROUP_SET_CURVE,
              EC_R_WRONG_CURVE_PARAMETERS);
        goto err;
    }
    group->field_mod_func = BN_sm2_mod_256;
    ret = ec_GFp_simple_group_set_curve(group, p, a, b, ctx);
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

/*
 * Takes the Jacobian coordinates (X, Y, Z) of a point and returns (X', Y') =
 * (X/Z^2, Y/Z^3)
 */
int ec_GFp_sm2p256_point_get_affine_coordinates(const EC_GROUP *group,
                                                const EC_POINT *point,
                                                BIGNUM *x, BIGNUM *y,
                                                BN_CTX *ctx)
{
    felem z1, z2, x_in, y_in;
    smallfelem x_out, y_out;
    longfelem tmp;

    if (EC_POINT_is_at_infinity(group, point)) {
        ECerr(EC_F_EC_GFP_SM2P256_POINT_GET_AFFINE_COORDINATES,
              EC_R_POINT_AT_INFINITY);
        return 0;
    }
    if ((!BN_to_felem(x_in, point->X)) || (!BN_to_felem(y_in, point->Y)) ||
        (!BN_to_felem(z1, point->Z)))
        return 0;

#ifdef SM2_USE_INV_SQR
    /* z2 = z^-2 */
    felem_inv_sqr(z2, z1);
    felem_mul(tmp, x_in, z2);
#else
    felem_inv(z2, z1);
    felem_square(tmp, z2);
    felem_reduce(z1, tmp);
    felem_mul(tmp, x_in, z1);
#endif

    felem_reduce(x_in, tmp);
    felem_contract(x_out, x_in);
    if (x != NULL) {
        if (!smallfelem_to_BN(x, x_out)) {
            ECerr(EC_F_EC_GFP_SM2P256_POINT_GET_AFFINE_COORDINATES,
                  ERR_R_BN_LIB);
            return 0;
        }
    }
    if (y != NULL) {
#ifdef SM2_USE_INV_SQR
        felem_square(tmp, z2);
        felem_reduce(z2, tmp);
        felem_mul(tmp, z1, z2);
#else
        felem_mul(tmp, z1, z2);
#endif
        felem_reduce(z1, tmp);
        felem_mul(tmp, y_in, z1);
        felem_reduce(y_in, tmp);
        felem_contract(y_out, y_in);

        if (!smallfelem_to_BN(y, y_out)) {
            ECerr(EC_F_EC_GFP_SM2P256_POINT_GET_AFFINE_COORDINATES,
                  ERR_R_BN_LIB);
            return 0;
        }
    }
    return 1;
}

/* points below is of size |num|, and tmp_smallfelems is of size |num+1| */
static void make_points_affine(size_t num, smallfelem points[][3],
                               smallfelem tmp_smallfelems[])
{
    /*
     * Runs in constant time, unless an input is the point at infinity (which
     * normally shouldn't happen).
     */
    ec_GFp_nistp_points_make_affine_internal(num,
                                             points,
                                             sizeof(smallfelem),
                                             tmp_smallfelems,
                                             (void (*)(void *))smallfelem_one,
                                             (int (*)(const void *))
                                             smallfelem_is_zero_int,
                                             (void (*)(void *, const void *))
                                             smallfelem_assign,
                                             (void (*)(void *, const void *))
                                             smallfelem_square_contract,
                                             (void (*)
                                              (void *, const void *,
                                               const void *))
                                             smallfelem_mul_contract,
                                             (void (*)(void *, const void *))
                                             smallfelem_inv_contract,
                                             /* nothing to contract */
                                             (void (*)(void *, const void *))
                                             smallfelem_assign);
}

/*
 * Computes scalar*generator + \sum scalars[i]*points[i], ignoring NULL
 * values Result is stored in r (r can equal one of the inputs).
 */
int ec_GFp_sm2p256_points_mul(const EC_GROUP *group, EC_POINT *r,
                              const BIGNUM *scalar, size_t num,
                              const EC_POINT *points[],
                              const BIGNUM *scalars[], BN_CTX *ctx)
{
    int ret = 0;
    int j;
    int mixed = 0;
    BN_CTX *new_ctx = NULL;
    BIGNUM *x, *y, *z, *tmp_scalar;
    felem_bytearray g_secret;
    felem_bytearray *secrets = NULL;
    smallfelem (*pre_comp)[17][3] = NULL;
    smallfelem *tmp_smallfelems = NULL;
    felem_bytearray tmp;
    unsigned i, num_bytes;
    int have_pre_comp = 0;
    size_t num_points = num;
    smallfelem x_in, y_in, z_in;
    felem x_out, y_out, z_out;
    SM2P256_PRE_COMP *pre = NULL;
    const smallfelem(*g_pre_comp)[16][3] = NULL;
    EC_POINT *generator = NULL;
    const EC_POINT *p = NULL;
    const BIGNUM *p_scalar = NULL;

    if (ctx == NULL)
        if ((ctx = new_ctx = BN_CTX_new()) == NULL)
            return 0;
    BN_CTX_start(ctx);
    if (((x = BN_CTX_get(ctx)) == NULL) ||
        ((y = BN_CTX_get(ctx)) == NULL) ||
        ((z = BN_CTX_get(ctx)) == NULL) ||
        ((tmp_scalar = BN_CTX_get(ctx)) == NULL))
        goto err;

    if (scalar != NULL) {
        pre = group->pre_comp.sm2p256;
        if (pre)
            /* we have precomputation, try to use it */
            g_pre_comp = (const smallfelem(*)[16][3])pre->g_pre_comp;
        else {
            /* try to use the standard precomputation */
            g_pre_comp = &gmul[0];
        }
        generator = EC_POINT_new(group);
        if (generator == NULL)
            goto err;
        /* get the generator from precomputation */
        if (!smallfelem_to_BN(x, g_pre_comp[0][1][0]) ||
            !smallfelem_to_BN(y, g_pre_comp[0][1][1]) ||
            !smallfelem_to_BN(z, g_pre_comp[0][1][2])) {
            ECerr(EC_F_EC_GFP_SM2P256_POINTS_MUL, ERR_R_BN_LIB);
            goto err;
        }
        if (!EC_POINT_set_Jprojective_coordinates_GFp(group,
                                                      generator, x, y, z,
                                                      ctx))
            goto err;
        if (0 == EC_POINT_cmp(group, generator, group->generator, ctx))
            /* precomputation matches generator */
            have_pre_comp = 1;
        else
            /*
             * we don't have valid precomputation: treat the generator as a
             * random point
             */
            num_points++;
    }
    if (num_points > 0) {
        if (num_points >= 3) {
            /*
             * unless we precompute multiples for just one or two points,
             * converting those into affine form is time well spent
             */
            mixed = 1;
        }
        secrets = OPENSSL_malloc(sizeof(*secrets) * num_points);
        pre_comp = OPENSSL_malloc(sizeof(*pre_comp) * num_points);
        if (mixed)
            tmp_smallfelems =
              OPENSSL_malloc(sizeof(*tmp_smallfelems) * (num_points * 17 + 1));
        if ((secrets == NULL) || (pre_comp == NULL)
            || (mixed && (tmp_smallfelems == NULL))) {
            ECerr(EC_F_EC_GFP_SM2P256_POINTS_MUL, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /*
         * we treat NULL scalars as 0, and NULL points as points at infinity,
         * i.e., they contribute nothing to the linear combination
         */
        memset(secrets, 0, sizeof(*secrets) * num_points);
        memset(pre_comp, 0, sizeof(*pre_comp) * num_points);
        for (i = 0; i < num_points; ++i) {
            if (i == num)
                /*
                 * we didn't have a valid precomputation, so we pick the
                 * generator
                 */
            {
                p = EC_GROUP_get0_generator(group);
                p_scalar = scalar;
            } else
                /* the i^th point */
            {
                p = points[i];
                p_scalar = scalars[i];
            }
            if ((p_scalar != NULL) && (p != NULL)) {
                /* reduce scalar to 0 <= scalar < 2^256 */
                if ((BN_num_bits(p_scalar) > 256)
                    || (BN_is_negative(p_scalar))) {
                    /*
                     * this is an unusual input, and we don't guarantee
                     * constant-timeness
                     */
                    if (!BN_nnmod(tmp_scalar, p_scalar, group->order, ctx)) {
                        ECerr(EC_F_EC_GFP_SM2P256_POINTS_MUL, ERR_R_BN_LIB);
                        goto err;
                    }
                    num_bytes = BN_bn2bin(tmp_scalar, tmp);
                } else
                    num_bytes = BN_bn2bin(p_scalar, tmp);
                flip_endian(secrets[i], tmp, num_bytes);
                /* precompute multiples */
                if ((!BN_to_felem(x_out, p->X)) ||
                    (!BN_to_felem(y_out, p->Y)) ||
                    (!BN_to_felem(z_out, p->Z)))
                    goto err;
                felem_shrink(pre_comp[i][1][0], x_out);
                felem_shrink(pre_comp[i][1][1], y_out);
                felem_shrink(pre_comp[i][1][2], z_out);
                for (j = 2; j <= 16; ++j) {
                    if (j & 1) {
                        point_add_small(pre_comp[i][j][0], pre_comp[i][j][1],
                                        pre_comp[i][j][2], pre_comp[i][1][0],
                                        pre_comp[i][1][1], pre_comp[i][1][2],
                                        pre_comp[i][j - 1][0],
                                        pre_comp[i][j - 1][1],
                                        pre_comp[i][j - 1][2]);
                    } else {
                        point_double_small(pre_comp[i][j][0],
                                           pre_comp[i][j][1],
                                           pre_comp[i][j][2],
                                           pre_comp[i][j / 2][0],
                                           pre_comp[i][j / 2][1],
                                           pre_comp[i][j / 2][2]);
                    }
                }
            }
        }
        if (mixed)
            make_points_affine(num_points * 17, pre_comp[0], tmp_smallfelems);
    }

    /* the scalar for the generator */
    if ((scalar != NULL) && (have_pre_comp)) {
        memset(g_secret, 0, sizeof(g_secret));
        /* reduce scalar to 0 <= scalar < 2^256 */
        if ((BN_num_bits(scalar) > 256) || (BN_is_negative(scalar))) {
            /*
             * this is an unusual input, and we don't guarantee
             * constant-timeness
             */
            if (!BN_nnmod(tmp_scalar, scalar, group->order, ctx)) {
                ECerr(EC_F_EC_GFP_SM2P256_POINTS_MUL, ERR_R_BN_LIB);
                goto err;
            }
            num_bytes = BN_bn2bin(tmp_scalar, tmp);
        } else
            num_bytes = BN_bn2bin(scalar, tmp);
        flip_endian(g_secret, tmp, num_bytes);
        /* do the multiplication with generator precomputation */
        batch_mul(x_out, y_out, z_out,
                  (const felem_bytearray(*))secrets, num_points,
                  g_secret,
                  mixed, (const smallfelem(*)[17][3])pre_comp, g_pre_comp);
    } else
        /* do the multiplication without generator precomputation */
        batch_mul(x_out, y_out, z_out,
                  (const felem_bytearray(*))secrets, num_points,
                  NULL, mixed, (const smallfelem(*)[17][3])pre_comp, NULL);
    /* reduce the output to its unique minimal representation */
    felem_contract(x_in, x_out);
    felem_contract(y_in, y_out);
    felem_contract(z_in, z_out);
    if ((!smallfelem_to_BN(x, x_in)) || (!smallfelem_to_BN(y, y_in)) ||
        (!smallfelem_to_BN(z, z_in))) {
        ECerr(EC_F_EC_GFP_SM2P256_POINTS_MUL, ERR_R_BN_LIB);
        goto err;
    }
    ret = EC_POINT_set_Jprojective_coordinates_GFp(group, r, x, y, z, ctx);

 err:
    BN_CTX_end(ctx);
    EC_POINT_free(generator);
    BN_CTX_free(new_ctx);
    OPENSSL_free(secrets);
    OPENSSL_free(pre_comp);
    OPENSSL_free(tmp_smallfelems);
    return ret;
}

int ec_GFp_sm2p256_precompute_mult(EC_GROUP *group, BN_CTX *ctx)
{
    int ret = 0;
    SM2P256_PRE_COMP *pre = NULL;
    int i, j;
    BN_CTX *new_ctx = NULL;
    BIGNUM *x, *y;
    EC_POINT *generator = NULL;
    smallfelem tmp_smallfelems[32];
    felem x_tmp, y_tmp, z_tmp;

    /* throw away old precomputation */
    EC_pre_comp_free(group);
    if (ctx == NULL)
        if ((ctx = new_ctx = BN_CTX_new()) == NULL)
            return 0;
    BN_CTX_start(ctx);
    if (((x = BN_CTX_get(ctx)) == NULL) || ((y = BN_CTX_get(ctx)) == NULL))
        goto err;
    /* get the generator */
    if (group->generator == NULL)
        goto err;
    generator = EC_POINT_new(group);
    if (generator == NULL)
        goto err;
    BN_bin2bn(sm2p256v1_curve_params[3], sizeof(felem_bytearray), x);
    BN_bin2bn(sm2p256v1_curve_params[4], sizeof(felem_bytearray), y);
    if (!EC_POINT_set_affine_coordinates_GFp(group, generator, x, y, ctx))
        goto err;
    if ((pre = sm2p256_pre_comp_new()) == NULL)
        goto err;
    /*
     * if the generator is the standard one, use built-in precomputation
     */
    if (0 == EC_POINT_cmp(group, generator, group->generator, ctx)) {
        memcpy(pre->g_pre_comp, gmul, sizeof(pre->g_pre_comp));
        goto done;
    }
    if ((!BN_to_felem(x_tmp, group->generator->X)) ||
        (!BN_to_felem(y_tmp, group->generator->Y)) ||
        (!BN_to_felem(z_tmp, group->generator->Z)))
        goto err;
    felem_shrink(pre->g_pre_comp[0][1][0], x_tmp);
    felem_shrink(pre->g_pre_comp[0][1][1], y_tmp);
    felem_shrink(pre->g_pre_comp[0][1][2], z_tmp);
    /*
     * compute 2^64*G, 2^128*G, 2^192*G for the first table, 2^32*G, 2^96*G,
     * 2^160*G, 2^224*G for the second one
     */
    for (i = 1; i <= 8; i <<= 1) {
        point_double_small(pre->g_pre_comp[1][i][0], pre->g_pre_comp[1][i][1],
                           pre->g_pre_comp[1][i][2], pre->g_pre_comp[0][i][0],
                           pre->g_pre_comp[0][i][1],
                           pre->g_pre_comp[0][i][2]);
        for (j = 0; j < 31; ++j) {
            point_double_small(pre->g_pre_comp[1][i][0],
                               pre->g_pre_comp[1][i][1],
                               pre->g_pre_comp[1][i][2],
                               pre->g_pre_comp[1][i][0],
                               pre->g_pre_comp[1][i][1],
                               pre->g_pre_comp[1][i][2]);
        }
        if (i == 8)
            break;
        point_double_small(pre->g_pre_comp[0][2 * i][0],
                           pre->g_pre_comp[0][2 * i][1],
                           pre->g_pre_comp[0][2 * i][2],
                           pre->g_pre_comp[1][i][0], pre->g_pre_comp[1][i][1],
                           pre->g_pre_comp[1][i][2]);
        for (j = 0; j < 31; ++j) {
            point_double_small(pre->g_pre_comp[0][2 * i][0],
                               pre->g_pre_comp[0][2 * i][1],
                               pre->g_pre_comp[0][2 * i][2],
                               pre->g_pre_comp[0][2 * i][0],
                               pre->g_pre_comp[0][2 * i][1],
                               pre->g_pre_comp[0][2 * i][2]);
        }
    }
    for (i = 0; i < 2; i++) {
        /* g_pre_comp[i][0] is the point at infinity */
        memset(pre->g_pre_comp[i][0], 0, sizeof(pre->g_pre_comp[i][0]));
        /* the remaining multiples */
        /* 2^64*G + 2^128*G resp. 2^96*G + 2^160*G */
        point_add_small(pre->g_pre_comp[i][6][0], pre->g_pre_comp[i][6][1],
                        pre->g_pre_comp[i][6][2], pre->g_pre_comp[i][4][0],
                        pre->g_pre_comp[i][4][1], pre->g_pre_comp[i][4][2],
                        pre->g_pre_comp[i][2][0], pre->g_pre_comp[i][2][1],
                        pre->g_pre_comp[i][2][2]);
        /* 2^64*G + 2^192*G resp. 2^96*G + 2^224*G */
        point_add_small(pre->g_pre_comp[i][10][0], pre->g_pre_comp[i][10][1],
                        pre->g_pre_comp[i][10][2], pre->g_pre_comp[i][8][0],
                        pre->g_pre_comp[i][8][1], pre->g_pre_comp[i][8][2],
                        pre->g_pre_comp[i][2][0], pre->g_pre_comp[i][2][1],
                        pre->g_pre_comp[i][2][2]);
        /* 2^128*G + 2^192*G resp. 2^160*G + 2^224*G */
        point_add_small(pre->g_pre_comp[i][12][0], pre->g_pre_comp[i][12][1],
                        pre->g_pre_comp[i][12][2], pre->g_pre_comp[i][8][0],
                        pre->g_pre_comp[i][8][1], pre->g_pre_comp[i][8][2],
                        pre->g_pre_comp[i][4][0], pre->g_pre_comp[i][4][1],
                        pre->g_pre_comp[i][4][2]);
        /*
         * 2^64*G + 2^128*G + 2^192*G resp. 2^96*G + 2^160*G + 2^224*G
         */
        point_add_small(pre->g_pre_comp[i][14][0], pre->g_pre_comp[i][14][1],
                        pre->g_pre_comp[i][14][2], pre->g_pre_comp[i][12][0],
                        pre->g_pre_comp[i][12][1], pre->g_pre_comp[i][12][2],
                        pre->g_pre_comp[i][2][0], pre->g_pre_comp[i][2][1],
                        pre->g_pre_comp[i][2][2]);
        for (j = 1; j < 8; ++j) {
            /* odd multiples: add G resp. 2^32*G */
            point_add_small(pre->g_pre_comp[i][2 * j + 1][0],
                            pre->g_pre_comp[i][2 * j + 1][1],
                            pre->g_pre_comp[i][2 * j + 1][2],
                            pre->g_pre_comp[i][2 * j][0],
                            pre->g_pre_comp[i][2 * j][1],
                            pre->g_pre_comp[i][2 * j][2],
                            pre->g_pre_comp[i][1][0],
                            pre->g_pre_comp[i][1][1],
                            pre->g_pre_comp[i][1][2]);
        }
    }
    make_points_affine(31, &(pre->g_pre_comp[0][1]), tmp_smallfelems);

 done:
    SETPRECOMP(group, sm2p256, pre);
    pre = NULL;
    ret = 1;

 err:
    BN_CTX_end(ctx);
    EC_POINT_free(generator);
    BN_CTX_free(new_ctx);
    EC_sm2p256_pre_comp_free(pre);
    return ret;
}

int ec_GFp_sm2p256_have_precompute_mult(const EC_GROUP *group)
{
    return HAVEPRECOMP(group, sm2p256);
}
#endif
