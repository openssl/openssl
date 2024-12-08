/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Copyright (c) 2024, Google Inc. */

#ifndef OPENSSL_NO_ML_KEM

# include <assert.h>
# include <internal/common.h>
# include <internal/constant_time.h>
# include <crypto/ml_kem.h>
# include "ml_kem_local.h"

typedef ossl_ml_kem_cbd_func cbd_t;
typedef const ossl_ml_kem_vinfo *vinfo_t;

# define DEGREE ML_KEM_DEGREE
static const int kPrime = ML_KEM_PRIME;

/*
 * Remainders modulo `kPrime`, for sufficiently small inputs, are computed in
 * constant time via Barrett reduction, and a final call to reduce_once(),
 * which reduces inputs that are at most 2*kPrime and is also constant-time.
 */
# define BARRETT_SHIFT (2 * ML_KEM_LOG2PRIME)
static const unsigned kBarrettShift = BARRETT_SHIFT;
static const size_t   kBarrettMultiplier = (1 << BARRETT_SHIFT) / ML_KEM_PRIME;
static const uint16_t kHalfPrime = (ML_KEM_PRIME - 1) / 2;
static const uint16_t kInverseDegree = ML_KEM_INVERSE_DEGREE;

/*
 * Python helper:
 *
 * p = 3329
 * def bitreverse(i):
 *     ret = 0
 *     for n in range(7):
 *         bit = i & 1
 *         ret <<= 1
 *         ret |= bit
 *         i >>= 1
 *     return ret
 */

/*-
 * First precomputed array from Appendix A of FIPS 203, or else Python:
 * kNTTRoots = [pow(17, bitreverse(i), p) for i in range(128)]
 */
static const uint16_t kNTTRoots[128] = {
    1,    1729, 2580, 3289, 2642, 630,  1897, 848,  1062, 1919, 193,  797,
    2786, 3260, 569,  1746, 296,  2447, 1339, 1476, 3046, 56,   2240, 1333,
    1426, 2094, 535,  2882, 2393, 2879, 1974, 821,  289,  331,  3253, 1756,
    1197, 2304, 2277, 2055, 650,  1977, 2513, 632,  2865, 33,   1320, 1915,
    2319, 1435, 807,  452,  1438, 2868, 1534, 2402, 2647, 2617, 1481, 648,
    2474, 3110, 1227, 910,  17,   2761, 583,  2649, 1637, 723,  2288, 1100,
    1409, 2662, 3281, 233,  756,  2156, 3015, 3050, 1703, 1651, 2789, 1789,
    1847, 952,  1461, 2687, 939,  2308, 2437, 2388, 733,  2337, 268,  641,
    1584, 2298, 2037, 3220, 375,  2549, 2090, 1645, 1063, 319,  2773, 757,
    2099, 561,  2466, 2594, 2804, 1092, 403,  1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885,  2154,
};

/* InverseNTTRoots = [pow(17, -bitreverse(i), p) for i in range(128)] */
static const uint16_t kInverseNTTRoots[128] = {
    1,    1600, 40,   749,  2481, 1432, 2699, 687,  1583, 2760, 69,   543,
    2532, 3136, 1410, 2267, 2508, 1355, 450,  936,  447,  2794, 1235, 1903,
    1996, 1089, 3273, 283,  1853, 1990, 882,  3033, 2419, 2102, 219,  855,
    2681, 1848, 712,  682,  927,  1795, 461,  1891, 2877, 2522, 1894, 1010,
    1414, 2009, 3296, 464,  2697, 816,  1352, 2679, 1274, 1052, 1025, 2132,
    1573, 76,   2998, 3040, 1175, 2444, 394,  1219, 2300, 1455, 2117, 1607,
    2443, 554,  1179, 2186, 2303, 2926, 2237, 525,  735,  863,  2768, 1230,
    2572, 556,  3010, 2266, 1684, 1239, 780,  2954, 109,  1292, 1031, 1745,
    2688, 3061, 992,  2596, 941,  892,  1021, 2390, 642,  1868, 2377, 1482,
    1540, 540,  1678, 1626, 279,  314,  1173, 2573, 3096, 48,   667,  1920,
    2229, 1041, 2606, 1692, 680,  2746, 568,  3312,
};

/*
 * Second precomputed array from Appendix A of FIPS 203 (normalised positive),
 * or else Python:
 * ModRoots = [pow(17, 2*bitreverse(i) + 1, p) for i in range(128)]
 */
static const uint16_t kModRoots[128] = {
    17,   3312, 2761, 568,  583,  2746, 2649, 680,  1637, 1692, 723,  2606,
    2288, 1041, 1100, 2229, 1409, 1920, 2662, 667,  3281, 48,   233,  3096,
    756,  2573, 2156, 1173, 3015, 314,  3050, 279,  1703, 1626, 1651, 1678,
    2789, 540,  1789, 1540, 1847, 1482, 952,  2377, 1461, 1868, 2687, 642,
    939,  2390, 2308, 1021, 2437, 892,  2388, 941,  733,  2596, 2337, 992,
    268,  3061, 641,  2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109,
    375,  2954, 2549, 780,  2090, 1239, 1645, 1684, 1063, 2266, 319,  3010,
    2773, 556,  757,  2572, 2099, 1230, 561,  2768, 2466, 863,  2594, 735,
    2804, 525,  1092, 2237, 403,  2926, 1026, 2303, 1143, 2186, 2150, 1179,
    2775, 554,  886,  2443, 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
    2110, 1219, 2935, 394,  885,  2444, 2154, 1175,
};

# define STATIC_CHECK(cond) ((void)sizeof(char[1 - 2 * !(cond)]))

/*
 * single_keccak hashes |inlen| bytes from |in| and writes |outlen| bytes of
 * output to |out|. If the |md| specifies a fixed-output function, like
 * SHA3-256, then |outlen| must be the correct length for that function.
 */
static __owur
int single_keccak(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen,
                  const EVP_MD *md)
{
    EVP_MD_CTX *mdctx;
    int ret = 0;
    unsigned int sz = (unsigned int) outlen;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL
        || !EVP_DigestInit_ex(mdctx, md, NULL)
        || !EVP_DigestUpdate(mdctx, in, inlen))
        return 0;

    if (EVP_MD_xof(md))
        ret = EVP_DigestFinalXOF(mdctx, out, outlen);
    else
        ret = EVP_DigestFinal_ex(mdctx, out, &sz);
    EVP_MD_CTX_free(mdctx);

    return (ret && (size_t) sz == outlen);
}

/*
 * FIPS 203, Section 4.1, equation (4.3): PRF_eta. Takes 32+1 input bytes, to
 * produce the input to SamplePolyCBD_eta: FIPS 203, algorithm 8.
 */
static __owur
int prf(uint8_t *out, size_t len, const uint8_t in[ML_KEM_RANDOM_BYTES + 1],
        mctx *ctx)
{
    return single_keccak(out, len, in, ML_KEM_RANDOM_BYTES + 1,
                         ctx->shake256_cache);
}

/*
 * FIPS 203, Section 4.1, equation (4.4): H.  SHA3-256 hash of a variable
 * length input, producing 32 bytes of output.
 */
static __owur
int hash_h(uint8_t out[ML_KEM_PKHASH_BYTES], const uint8_t *in, size_t len,
           mctx *ctx)
{
    return single_keccak(out, ML_KEM_PKHASH_BYTES, in, len,
                         ctx->sha3_256_cache);
}

/*
 * FIPS 203, Section 4.1, equation (4.5): G.  SHA3-512 hash of a variable
 * length input, producing 64 bytes of output, in particular the seeds
 * (d,z) for key generation.
 */
static __owur
int hash_g(uint8_t out[ML_KEM_SEED_BYTES], const uint8_t *in, size_t len,
           mctx *ctx)
{
    return single_keccak(out, ML_KEM_SEED_BYTES, in, len, ctx->sha3_512_cache);
}

/*
 * FIPS 203, Section 4.1, equation (4.4): J. SHAKE256 taking a variable length
 * input to compute a 32-byte implicit rejection shared secret, of the same
 * length as the expected shared secret.  (Computed even on success to avoid
 * side-channel leaks).
 */
static
int kdf(uint8_t out[ML_KEM_SHARED_SECRET_BYTES],
         const uint8_t z[ML_KEM_RANDOM_BYTES],
         const uint8_t *ctext, size_t len, mctx *ctx)
{
    EVP_MD_CTX *mdctx;
    int ret = 0;

    /*
     * This function's return value will be ignored, but we're not allowed to
     * ignore the return value of EVP_DigestFinalXOF()...
     */
    if ((mdctx = EVP_MD_CTX_new()) != NULL
        && EVP_DigestInit_ex(mdctx, ctx->shake256_cache, NULL)
        && EVP_DigestUpdate(mdctx, z, ML_KEM_RANDOM_BYTES)
        && EVP_DigestUpdate(mdctx, ctext, len)
        && EVP_DigestFinalXOF(mdctx, out, ML_KEM_SHARED_SECRET_BYTES))
        ret = 1;

    EVP_MD_CTX_free(mdctx);
    return ret;
}

/*
 * FIPS 203, Section 4.2.2, Algorithm 7: SampleNTT. Rejection samples a Keccak
 * stream to get uniformly distributed elements. This is used for matrix
 * expansion and only operates on public inputs.
 *
 * The block size below needs to be a multiple of 3, but is otherwise
 * arbitrary, the chosen block size avoids internal buffering in SHAKE128, by
 * matching the Keccac output block size of (1600 - 256)/8 bytes, which, being
 * 168, just happens to be a multiple of 3!
 */
static __owur
int sample_scalar(scalar *out, EVP_MD_CTX *mdctx)
{
    int done = 0;
    uint8_t block[168];
    size_t i;
    uint16_t d1, d2;

    while (done < DEGREE) {
        if (!EVP_DigestSqueeze(mdctx, block, sizeof(block)))
            return 0;
        for (i = 0; i < sizeof(block) && done < DEGREE; i += 3) {
            d1 = block[i] + ((block[i + 1] & 0x0f) << 8);
            d2 = (block[i + 1] >> 4) + (block[i + 2] << 4);
            if (d1 < kPrime)
                out->c[done++] = d1;
            if (d2 < kPrime && done < DEGREE)
                out->c[done++] = d2;
        }
    }
    return 1;
}

/* reduce_once reduces 0 <= x < 2*kPrime, mod kPrime. */
static __owur uint16_t reduce_once(uint16_t x)
{
    const uint16_t subtracted = x - kPrime;
    uint16_t mask = 0u - (subtracted >> 15);

    assert(x < 2 * kPrime);
    /*
     * On Aarch64, omitting a |value_barrier_u16| results in a 2x speedup of
     * ML-KEM overall and Clang still produces constant-time code using `csel`.
     */
    return (mask & x) | (~mask & subtracted);
}

/*
 * Constant-time reduce x mod kPrime using Barrett reduction. x must be less
 * than kPrime + 2 * kPrime^2.  This is sufficient to reduce a product of
 * two already reduced u_int16 values, in fact it is sufficient for each
 * to be less than 2^12, because (kPrime * (2 * kPrime + 1)) > 2^24.
 */
static __owur uint16_t reduce(uint32_t x)
{
    uint64_t product = (uint64_t)x * kBarrettMultiplier;
    uint32_t quotient = (uint32_t)(product >> kBarrettShift);
    uint32_t remainder = x - quotient * kPrime;

    assert(x < kPrime + 2u * kPrime * kPrime);
    return reduce_once(remainder);
}

/*
 * FIPS 203, Section 4.3, Algoritm 9: NTT.  In-place number theoretic transform
 * of a given scalar.  Note that ML-KEM's kPrime 3329 does not have a 512th
 * root of unity, so this transform leaves off the last iteration of the usual
 * FFT code, with the 128 relevant roots of unity being stored in NTTRoots.
 * This means the output should be seen as 128 elements in GF(3329^2), with the
 * coefficients of the elements being consecutive entries in |s->c|.
 */
static void scalar_ntt(scalar *s)
{
    int offset = DEGREE;
    int k, step, i, j;
    uint32_t step_root;
    uint16_t odd, even;

    /*
     * `int` is used here because using `size_t` throughout caused a ~5%
     * slowdown with Clang 14 on Aarch64.
     */
    for (step = 1; step < DEGREE / 2; step <<= 1) {
        offset >>= 1;
        k = 0;
        for (i = 0; i < step; i++) {
            step_root = kNTTRoots[i + step];
            for (j = k; j < k + offset; j++) {
                odd = reduce(step_root * s->c[j + offset]);
                even = s->c[j];
                s->c[j] = reduce_once(odd + even);
                s->c[j + offset] = reduce_once(even - odd + kPrime);
            }
            k += 2 * offset;
        }
    }
}

/*
 * FIPS 203, Section 4.3, Algoritm 10: NTT^(-1).  In-place inverse number
 * theoretic transform of a given scalar, with pairs of entries of s->v being
 * interpreted as elements of GF(3329^2). Just as with the number theoretic
 * transform, this leaves off the first step of the normal iFFT to account for
 * the fact that 3329 does not have a 512th root of unity, using the
 * precomputed 128 roots of unity stored in InverseNTTRoots.
 *
 * FIPS 203, Algorithm 10, performs this transformation in a slightly different
 * manner, using the same NTTRoots table as the forward NTT transform.
 */
static void scalar_inverse_ntt(scalar *s)
{
    int step = DEGREE / 2;
    int offset, k, i, j;
    uint32_t step_root;
    uint16_t odd, even;

    /*
     * `int` is used here because using `size_t` throughout caused a ~5%
     * slowdown with Clang 14 on Aarch64.
     */
    for (offset = 2; offset < DEGREE; offset <<= 1) {
        step >>= 1;
        k = 0;
        for (i = 0; i < step; i++) {
            step_root = kInverseNTTRoots[i + step];
            for (j = k; j < k + offset; j++) {
                odd = s->c[j + offset];
                even = s->c[j];
                s->c[j] = reduce_once(odd + even);
                s->c[j + offset] = reduce(step_root * (even - odd + kPrime));
            }
            k += 2 * offset;
        }
    }
    for (i = 0; i < DEGREE; i++)
        s->c[i] = reduce(s->c[i] * kInverseDegree);
}

/* Addition updating the LHS scalar in-place. */
static void scalar_add(scalar *lhs, const scalar *rhs)
{
    int i;

    for (i = 0; i < DEGREE; i++)
        lhs->c[i] = reduce_once(lhs->c[i] + rhs->c[i]);
}

/* Subtraction updating the LHS scalar in-place. */
static void scalar_sub(scalar *lhs, const scalar *rhs)
{
    int i;

    for (i = 0; i < DEGREE; i++)
        lhs->c[i] = reduce_once(lhs->c[i] - rhs->c[i] + kPrime);
}

/*
 * Multiplying two scalars in the number theoretically transformed state. Since
 * 3329 does not have a 512th root of unity, this means we have to interpret
 * the 2*ith and (2*i+1)th entries of the scalar as elements of
 * GF(3329)[X]/(X^2 - 17^(2*bitreverse(i)+1)).
 *
 * The value of 17^(2*bitreverse(i)+1) mod 3329 is stored in the precomputed
 * ModRoots table. Note that our Barrett transform only allows us to multipy
 * two reduced numbers together, so we need some intermediate reduction steps,
 * even if an uint64_t could hold 3 multiplied numbers.
 */
static void scalar_mult(scalar *out, const scalar *lhs,
                        const scalar *rhs)
{
    int i;
    uint32_t real_real, img_img, real_img, img_real;

    for (i = 0; i < DEGREE / 2; i++) {
        real_real = (uint32_t)lhs->c[2 * i] * rhs->c[2 * i];
        img_img = (uint32_t)lhs->c[2 * i + 1] * rhs->c[2 * i + 1];
        real_img = (uint32_t)lhs->c[2 * i] * rhs->c[2 * i + 1];
        img_real = (uint32_t)lhs->c[2 * i + 1] * rhs->c[2 * i];
        out->c[2 * i] =
            reduce(real_real +
                   (uint32_t)reduce(img_img) * kModRoots[i]);
        out->c[2 * i + 1] = reduce(img_real + real_img);
    }
}

static ossl_inline
void scalar_mult_add(scalar *out, const scalar *lhs,
                     const scalar *rhs)
{
    scalar product;

    scalar_mult(&product, lhs, rhs);
    scalar_add(out, &product);
}

static const uint8_t kMasks[8] = {0x01, 0x03, 0x07, 0x0f,
                                  0x1f, 0x3f, 0x7f, 0xff};

/*
 * FIPS 203, Section 4.2.1, Algorithm 5: ByteEncode_d, for 2<=d<=12 Here |bits|
 * is |d|.  For efficiency, we handle the d=1 case separately.
 */
static void scalar_encode(uint8_t *out, const scalar *s, int bits)
{
    uint8_t out_byte = 0;
    int out_byte_bits = 0;
    int i, element_bits_done, chunk_bits, out_bits_remaining;
    uint16_t element;

    assert(bits <= (int)sizeof(*s->c) * 8 && bits != 1);
    for (i = 0; i < DEGREE; i++) {
        element = s->c[i];
        element_bits_done = 0;
        while (element_bits_done < bits) {
            chunk_bits = bits - element_bits_done;
            out_bits_remaining = 8 - out_byte_bits;
            if (chunk_bits >= out_bits_remaining) {
                chunk_bits = out_bits_remaining;
                out_byte |= (element & kMasks[chunk_bits - 1]) << out_byte_bits;
                *out = out_byte;
                out++;
                out_byte_bits = 0;
                out_byte = 0;
            } else {
                out_byte |= (element & kMasks[chunk_bits - 1]) << out_byte_bits;
                out_byte_bits += chunk_bits;
            }
            element_bits_done += chunk_bits;
            element >>= chunk_bits;
        }
    }
    if (out_byte_bits > 0)
        *out = out_byte;
}

/*
 * scalar_encode_12 is |scalar_encode| specialised for |bits| == 12.
 */
static void scalar_encode_12(uint8_t *out, const scalar *s)
{
    const uint16_t *c = s->c;
    int i;

    for (i = 0; i < DEGREE / 2; ++i) {
        uint16_t c1 = *c++;
        uint16_t c2 = *c++;

        *out++ = (uint8_t) c1;
        *out++ = (uint8_t) (((c1 >> 8) & 0x0f) | ((c2 & 0x0f) << 4));
        *out++ = (uint8_t) (c2 >> 4);
    }
}

/*
 * scalar_encode_1 is |scalar_encode| specialised for |bits| == 1.
 * uint8_t out[32]
 */
static void scalar_encode_1(uint8_t *out, const scalar *s)
{
    int i, j;
    uint8_t out_byte;

    for (i = 0; i < DEGREE; i += 8) {
        out_byte = 0;
        for (j = 0; j < 8; j++)
            out_byte |= (s->c[i + j] & 1) << j;
        *out = out_byte;
        out++;
    }
}

/*
 * FIPS 203, Section 4.2.1, Algorithm 6: ByteDecode_d, for 2<=d<=12 Here |bits|
 * is |d|.  For efficiency, we handle the d=1 case separately.
 *
 * scalar_decode parses |DEGREE * bits| bits from |in| into |DEGREE| values in
 * |out|. It returns one on success and zero if any parsed value is >=
 * |kPrime|.
 */
static int scalar_decode(scalar *out, const uint8_t *in, int bits)
{
    uint8_t in_byte = 0;
    int in_byte_bits_left = 0;
    int i, element_bits_done, chunk_bits;
    uint16_t element;

    if (!ossl_assert(bits < 12 && bits != 1))
        return 0;
    for (i = 0; i < DEGREE; i++) {
        element = 0;
        element_bits_done = 0;
        while (element_bits_done < bits) {
            if (in_byte_bits_left == 0) {
                in_byte = *in;
                in++;
                in_byte_bits_left = 8;
            }
            chunk_bits = bits - element_bits_done;
            if (chunk_bits > in_byte_bits_left)
                chunk_bits = in_byte_bits_left;
            element |= (in_byte & kMasks[chunk_bits - 1]) << element_bits_done;
            in_byte_bits_left -= chunk_bits;
            in_byte >>= chunk_bits;
            element_bits_done += chunk_bits;
        }
        if (element >= kPrime)
            return 0;
        out->c[i] = element;
    }
    return 1;
}

static int scalar_decode_12(scalar *out, const uint8_t *in)
{
    int i;
    uint16_t *c = out->c;

    for (i = 0; i < DEGREE / 2; ++i) {
        uint8_t b1 = *in++;
        uint8_t b2 = *in++;
        uint8_t b3 = *in++;

        if ((*c++ = b1 | ((b2 & 0x0f) << 8)) >= kPrime
            || (*c++ = (b2 >> 4) | (b3 << 4)) >= kPrime)
            return 0;
    }
    return 1;
}

/* scalar_decode_1 is |scalar_decode| specialised for |bits| == 1. */
static void scalar_decode_1(scalar *out, const uint8_t *in)
{
    int i, j;
    uint8_t in_byte;

    for (i = 0; i < DEGREE; i += 8) {
        in_byte = *in;
        in++;
        for (j = 0; j < 8; j++) {
            out->c[i + j] = in_byte & 1;
            in_byte >>= 1;
        }
    }
}

/*
 * FIPS 203, Section 4.2.1, Equation (4.7): Compress_d.
 *
 * Compresses (lossily) an input |x| mod 3329 into |bits| many bits by grouping
 * numbers close to each other together. The formula used is
 * round(2^|bits|/kPrime*x) mod 2^|bits|.
 * Uses Barrett reduction to achieve constant time. Since we need both the
 * remainder (for rounding) and the quotient (as the result), we cannot use
 * |reduce| here, but need to do the Barrett reduction directly.
 */
static __owur uint16_t compress(uint16_t x, int bits)
{
    uint32_t shifted = (uint32_t)x << bits;
    uint64_t product = (uint64_t)shifted * kBarrettMultiplier;
    uint32_t quotient = (uint32_t)(product >> kBarrettShift);
    uint32_t remainder = shifted - quotient * kPrime;

    /*
     * Adjust the quotient to round correctly:
     *   0 <= remainder <= kHalfPrime round to 0
     *   kHalfPrime < remainder <= kPrime + kHalfPrime round to 1
     *   kPrime + kHalfPrime < remainder < 2 * kPrime round to 2
     */
    assert(remainder < 2u * kPrime);
    quotient += 1 & constant_time_lt_32(kHalfPrime, remainder);
    quotient += 1 & constant_time_lt_32(kPrime + kHalfPrime, remainder);
    return quotient & ((1 << bits) - 1);
}

/*
 * FIPS 203, Section 4.2.1, Equation (4.8): Decompress_d.

 * Decompresses |x| by using a close equi-distant representative. The formula
 * is round(kPrime/2^|bits|*x). Note that 2^|bits| being the divisor allows us
 * to implement this logic using only bit operations.
 */
static __owur uint16_t decompress(uint16_t x, int bits)
{
    uint32_t product = (uint32_t)x * kPrime;
    uint32_t power = 1 << bits;
    /* This is |product| % power, since |power| is a power of 2. */
    uint32_t remainder = product & (power - 1);
    /* This is |product| / power, since |power| is a power of 2. */
    uint32_t lower = product >> bits;

    /*
     * The rounding logic works since the first half of numbers mod |power|
     * have a 0 as first bit, and the second half has a 1 as first bit, since
     * |power| is a power of 2. As a 12 bit number, |remainder| is always
     * positive, so we will shift in 0s for a right shift.
     */
    return lower + (remainder >> (bits - 1));
}

static void scalar_compress(scalar *s, int bits)
{
    int i;

    for (i = 0; i < DEGREE; i++)
        s->c[i] = compress(s->c[i], bits);
}

static void scalar_decompress(scalar *s, int bits)
{
    int i;

    for (i = 0; i < DEGREE; i++)
        s->c[i] = decompress(s->c[i], bits);
}

/* Addition updating the LHS vector in-place. */
static void vector_add(scalar *lhs, const scalar *rhs, int rank)
{
    while (rank-- > 0)
        scalar_add(lhs++, rhs++);
}

/*
 * Encodes an entire vector into 32*|rank|*|bits| bytes. Note that since 256
 * (DEGREE) is divisible by 8, the individual vector entries will always fill a
 * whole number of bytes, so we do not need to worry about bit packing here.
 */
static void vector_encode(uint8_t *out, const scalar *a, int bits, int rank)
{
    int stride = bits * DEGREE / 8;

    for (; rank-- > 0; out += stride)
        scalar_encode(out, a++, bits);
}

/*
 * Decodes 32*|rank|*|bits| bytes from |in| into |out|. It returns one on
 * success or zero if any parsed value is >= |ML_KEM_PRIME|.
 */
static int vector_decode(scalar *out, const uint8_t *in, int bits, int rank)
{
    int stride = bits * DEGREE / 8;

    for (; rank-- > 0; in += stride)
        if (!scalar_decode(out++, in, bits))
            return 0;
    return 1;
}

/* vector_encode, specialised to bits == 12. */
static void vector_encode_12(uint8_t *out, const scalar *a, int rank)
{
    int stride = 3 * DEGREE / 2;

    for (; rank-- > 0; out += stride)
        scalar_encode_12(out, a++);
}

/* vector_decode, specialised to bits == 12. */
static __owur
int vector_decode_12(scalar *out, const uint8_t *in, int rank)
{
    int stride = 3 * DEGREE / 2;

    for (; rank-- > 0; in += stride)
        if (!scalar_decode_12(out++, in))
            return 0;
    return 1;
}

static void vector_compress(scalar *a, int bits, int rank)
{
    while (rank-- > 0)
        scalar_compress(a++, bits);
}

static void vector_decompress(scalar *a, int bits, int rank)
{
    while (rank-- > 0)
        scalar_decompress(a++, bits);
}

static void inner_product(scalar *out, const scalar *lhs, const scalar *rhs,
                          int rank)
{
    scalar_mult(out, lhs, rhs);
    while (--rank > 0)
        scalar_mult_add(out, ++lhs, ++rhs);
}

/* In-place NTT transform of a vector */
static void vector_ntt(scalar *a, int rank)
{
    while (rank-- > 0)
        scalar_ntt(a++);
}

/* In-place inverse NTT transform of a vector */
static void vector_inverse_ntt(scalar *a, int rank)
{
    while (rank-- > 0)
        scalar_inverse_ntt(a++);
}

static void
matrix_mult(scalar *out, const scalar *m, const scalar *a, int rank)
{
    const scalar *ar;
    int i, j;

    for (i = rank; i-- > 0; ++out) {
        scalar_mult(out, m++, ar = a);
        for (j = rank - 1; j > 0; --j)
            scalar_mult_add(out, m++, ++ar);
    }
}

static void
matrix_mult_transpose(scalar *out, const scalar *m, const scalar *a, int rank)
{
    const scalar *mc = m, *mr, *ar;
    int i, j;

    for (i = rank; i-- > 0; ++out)  {
        scalar_mult(out, mr = mc++, ar = a);
        for (j = rank; --j > 0; )
            scalar_mult_add(out, (mr += rank), ++ar);
    }
}

/*
 * Generates a secret vector by using |cbd| with the given seed to generate
 * scalar elements and incrementing |counter| for each slot of the vector.
 */
static __owur
int gencbd_vector(scalar *out, cbd_t cbd, uint8_t *counter,
                  const uint8_t seed[ML_KEM_RANDOM_BYTES], int rank, mctx *ctx)
{
    uint8_t input[ML_KEM_RANDOM_BYTES + 1];

    memcpy(input, seed, ML_KEM_RANDOM_BYTES);
    while (rank-- > 0) {
        input[ML_KEM_RANDOM_BYTES] = (*counter)++;
        if (!cbd(out++, input, ctx))
            return 0;
    }
    return 1;
}

/*-
 * Expands the matrix from a seed for key generation and for encaps-CPA.
 * NOTE: FIPS 203 matrix "A" is the transpose of this matrix, computed
 * by appending the (i,j) indices to the seed in the opposite order!
 *
 * Where FIPS 203 computs $t = A * s + e$, we use the transpose of "m".
 */
static __owur
int matrix_expand(scalar *out, const uint8_t rho[ML_KEM_RANDOM_BYTES],
                  int rank, mctx *ctx)
{
    uint8_t input[ML_KEM_RANDOM_BYTES + 2];
    int i, j, ret = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL)
        goto end;
    memcpy(input, rho, ML_KEM_RANDOM_BYTES);
    for (i = 0; i < rank; i++) {
        for (j = 0; j < rank; j++) {
            input[ML_KEM_RANDOM_BYTES] = i;
            input[ML_KEM_RANDOM_BYTES + 1] = j;
            if (!EVP_DigestInit_ex(mdctx, ctx->shake128_cache, NULL)
                || !EVP_DigestUpdate(mdctx, input, sizeof(input))
                || !sample_scalar(out++, mdctx))
                goto end;
        }
    }

    ret = 1;
end:
    EVP_MD_CTX_free(mdctx);
    return ret;
}

/*
 * FIPS 203, Section 5.2, Algorithm 14: K-PKE.Encrypt.
 *
 * Encrypts a message with given randomness to the ciphertext in |out|. Without
 * applying the Fujisaki-Okamoto transform this would not result in a CCA
 * secure scheme, since lattice schemes are vulnerable to decryption failure
 * oracles.
 *
 * Caller passes storage for |y|, |e1| and |u|.
 */
static __owur
int encrypt_cpa(uint8_t *out, const uint8_t *message, const scalar *m,
                const scalar *t, const uint8_t *randomness, scalar *y,
                scalar *e1, scalar *u, vinfo_t vinfo, mctx *ctx)
{
    uint8_t counter = 0;
    uint8_t input[ML_KEM_RANDOM_BYTES + 1];
    scalar e2;
    scalar v;
    scalar expanded_message;
    int rank = vinfo->rank;

    /* FIPS 203 "y" vector */
    if (!gencbd_vector(y, vinfo->cbd1, &counter, randomness, rank, ctx))
        return 0;
    vector_ntt(y, rank);
    /* FIPS 203 "e1" vector */
    if (!gencbd_vector(e1, vinfo->cbd2, &counter, randomness, rank, ctx))
        return 0;
    memcpy(input, randomness, ML_KEM_RANDOM_BYTES);
    input[ML_KEM_RANDOM_BYTES] = counter;
    /* FIPS 203 "e2" scalar */
    if (!vinfo->cbd2(&e2, input, ctx))
        return 0;
    /* FIPS 203 "u" vector */
    matrix_mult(u, m, y, rank);
    vector_inverse_ntt(u, rank);
    vector_add(u, e1, rank);
    /* FIPS 203 "v" scalar */
    inner_product(&v, t, y, rank);
    scalar_inverse_ntt(&v);
    scalar_add(&v, &e2);
    /* Extract ciphertext */
    scalar_decode_1(&expanded_message, message);
    scalar_decompress(&expanded_message, 1);
    scalar_add(&v, &expanded_message);
    vector_compress(u, vinfo->du, rank);
    vector_encode(out, u, vinfo->du, rank);
    scalar_compress(&v, vinfo->dv);
    scalar_encode(out + vinfo->u_vector_bytes, &v, vinfo->dv);
    return 1;
}

/*
 * FIPS 203, Section 5.3, Algorithm 15: K-PKE.Decrypt.
 */
static void
decrypt_cpa(uint8_t *out, const uint8_t *ctext, const scalar *s, scalar *u,
            vinfo_t vinfo)
{
    scalar v, mask;
    int rank = vinfo->rank;
    int du = vinfo->du;
    int dv = vinfo->dv;

    vector_decode(u, ctext, du, rank);
    vector_decompress(u, du, rank);
    vector_ntt(u, rank);
    scalar_decode(&v, ctext + vinfo->u_vector_bytes, dv);
    scalar_decompress(&v, dv);
    inner_product(&mask, s, u, rank);
    scalar_inverse_ntt(&mask);
    scalar_sub(&v, &mask);
    scalar_compress(&v, 1);
    scalar_encode_1(out, &v);
}

/*
 * -----
 *
 * Internal API implements details of variant-specific ML-KEM algorithms for
 * multiple variants given explicit parameters and additional caller allocated
 * temporary storage as needed.
 */

mctx *ossl_ml_kem_newctx(OSSL_LIB_CTX *libctx, const char *properties)
{
    mctx *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* Precondition of ML-KEM implementation correctness */
    STATIC_CHECK(sizeof(unsigned int) >= sizeof (uint32_t));

    ctx->libctx = libctx;
    ctx->shake128_cache = EVP_MD_fetch(libctx, "SHAKE128", properties);
    ctx->shake256_cache = EVP_MD_fetch(libctx, "SHAKE256", properties);
    ctx->sha3_256_cache = EVP_MD_fetch(libctx, "SHA3-256", properties);
    ctx->sha3_512_cache = EVP_MD_fetch(libctx, "SHA3-512", properties);

    if (ctx->shake128_cache == NULL || ctx->shake256_cache == NULL ||
        ctx->sha3_256_cache == NULL || ctx->sha3_512_cache == NULL)
        goto err;

    return ctx;

  err:
    ossl_ml_kem_ctx_free(ctx);
    return NULL;
}

mctx *ossl_ml_kem_ctx_dup(mctx *ctx)
{
    mctx *ret = OPENSSL_memdup(ctx, sizeof(*ret));

    EVP_MD_up_ref(ret->shake128_cache);
    EVP_MD_up_ref(ret->shake256_cache);
    EVP_MD_up_ref(ret->sha3_256_cache);
    EVP_MD_up_ref(ret->sha3_512_cache);

    return ret;
}

void ossl_ml_kem_ctx_free(mctx *ctx)
{
    if (ctx != NULL) {
        EVP_MD_free(ctx->shake128_cache);
        EVP_MD_free(ctx->shake256_cache);
        EVP_MD_free(ctx->sha3_256_cache);
        EVP_MD_free(ctx->sha3_512_cache);
    }
    OPENSSL_free(ctx);
}

/*
 * Algorithm 7 from the spec, with eta fixed to two and the PRF call
 * included. Creates binominally distributed elements by sampling 2*|eta| bits,
 * and setting the coefficient to the count of the first bits minus the count of
 * the second bits, resulting in a centered binomial distribution. Since eta is
 * two this gives -2/2 with a probability of 1/16, -1/1 with probability 1/4,
 * and 0 with probability 3/8.
 */
int ossl_ml_kem_cbd_2(scalar *out,
                      uint8_t in[ML_KEM_RANDOM_BYTES + 1],
                      mctx *ctx)
{
    uint8_t randbuf[2 * 2 * DEGREE / 8];    /* 64 * eta */
    int i;
    uint8_t byte;
    uint16_t value;

    if (!prf(randbuf, sizeof(randbuf), in, ctx))
        return 0;
    for (i = 0; i < DEGREE; i += 2) {
        byte = randbuf[i / 2];
        value = kPrime;
        value += (byte & 1) + ((byte >> 1) & 1);
        value -= ((byte >> 2) & 1) + ((byte >> 3) & 1);
        out->c[i] = reduce_once(value);
        byte >>= 4;
        value = kPrime;
        value += (byte & 1) + ((byte >> 1) & 1);
        value -= ((byte >> 2) & 1) + ((byte >> 3) & 1);
        out->c[i + 1] = reduce_once(value);
    }
    return 1;
}

/*
 * Algorithm 7 from the spec, with eta fixed to three and the PRF call
 * included. Creates binominally distributed elements by sampling 3*|eta| bits,
 * and setting the coefficient to the count of the first bits minus the count of
 * the second bits, resulting in a centered binomial distribution.
 */
int ossl_ml_kem_cbd_3(scalar *out,
                      uint8_t in[ML_KEM_RANDOM_BYTES + 1],
                      mctx *ctx)
{
    uint8_t randbuf[6 * DEGREE / 8];    /* 64 * eta */
    int i = 0, j = 0;
    uint8_t b1, b2, b3;
    uint16_t value;

# define bit0(b) (b & 1)
# define bitn(n, b) ((b >> n) & 1)

    if (!prf(randbuf, sizeof(randbuf), in, ctx))
        return 0;
    /* Unrolled loop uses 3 bytes at a time, yielding 4 values (6 bits each) */
    while (j < (int) sizeof(randbuf)) {
        b1 = randbuf[j++];
        b2 = randbuf[j++];
        b3 = randbuf[j++];

        value = kPrime + bit0(b1) + bitn(1, b1) + bitn(2, b1);
        value -= bitn(3, b1)  + bitn(4, b1) + bitn(5, b1);
        out->c[i++] = reduce_once(value);

        value = kPrime + bitn(6, b1) + bitn(7, b1) + bit0(b2);
        value -= bitn(1, b2) + bitn(2, b2) + bitn(3, b2);
        out->c[i++] = reduce_once(value);

        value = kPrime + bitn(4, b2) + bitn(5, b2) + bitn(6, b2);
        value -= bitn(7, b2) + bit0(b3) + bitn(1, b3);
        out->c[i++] = reduce_once(value);

        value = kPrime + bitn(2, b3) + bitn(3, b3) + bitn(4, b3);
        value -= bitn(5, b3) + bitn(6, b3) + bitn(7, b3);
        out->c[i++] = reduce_once(value);
    }
# undef bit0
# undef bitn

    return 1;
}

void ossl_ml_kem_encode_public_key(uint8_t *out,
                                   const scalar *t,
                                   const uint8_t rho[ML_KEM_RANDOM_BYTES],
                                   vinfo_t vinfo)
{
    vector_encode_12(out, t, vinfo->rank);
    memcpy(out + vinfo->vector_bytes, rho, ML_KEM_RANDOM_BYTES);
}

int ossl_ml_kem_parse_public_key(const uint8_t *in,
                                 scalar *m, scalar *t,
                                 uint8_t rho[ML_KEM_RANDOM_BYTES],
                                 uint8_t pkhash[ML_KEM_PKHASH_BYTES],
                                 vinfo_t vinfo,
                                 mctx *ctx)
{
    /* Decode and check |t| */
    if (!vector_decode_12(t, in, vinfo->rank))
        return 0;
    /* Save the matrix |m| recovery seed |rho| */
    memcpy(rho, in + vinfo->vector_bytes, ML_KEM_RANDOM_BYTES);
    /*
     * Pre-compute the public key hash, needed for both encap and decap.
     * Also pre-compute the matrix expansion, stored with the public key.
     */
    return hash_h(pkhash, in, vinfo->pubkey_bytes, ctx)
        && matrix_expand(m, rho, vinfo->rank, ctx);
}

void ossl_ml_kem_encode_private_key(uint8_t *out,
                                    const scalar *s,
                                    const scalar *t,
                                    const uint8_t rho[ML_KEM_RANDOM_BYTES],
                                    const uint8_t pkhash[ML_KEM_PKHASH_BYTES],
                                    const uint8_t z[ML_KEM_RANDOM_BYTES],
                                    vinfo_t vinfo)
{
    vector_encode_12(out, s, vinfo->rank);
    out += vinfo->vector_bytes;
    ossl_ml_kem_encode_public_key(out, t, rho, vinfo);
    out += vinfo->pubkey_bytes;
    memcpy(out, pkhash, ML_KEM_PKHASH_BYTES);
    out += ML_KEM_PKHASH_BYTES;
    memcpy(out, z, ML_KEM_RANDOM_BYTES);
}

/* Loading of explicit private keys is a test-only interface. */
int ossl_ml_kem_parse_private_key(const uint8_t *in,
                                  scalar *m,
                                  scalar *s,
                                  scalar *t,
                                  uint8_t rho[ML_KEM_RANDOM_BYTES],
                                  uint8_t pkhash[ML_KEM_PKHASH_BYTES],
                                  uint8_t z[ML_KEM_RANDOM_BYTES],
                                  vinfo_t vinfo,
                                  mctx *ctx)
{
    int rank = vinfo->rank;

    /* Decode and check |s|. */
    if (!vector_decode_12(s, in, rank))
        return 0;
    in += vinfo->vector_bytes;

    if (!ossl_ml_kem_parse_public_key(in, m, t, rho, pkhash, vinfo, ctx))
        return 0;
    in += vinfo->pubkey_bytes;

    /* Check public key hash. */
    if (memcmp(pkhash, in, ML_KEM_PKHASH_BYTES) != 0)
        return 0;
    in += ML_KEM_PKHASH_BYTES;

    memcpy(z, in, ML_KEM_RANDOM_BYTES);
    return 1;
}

/*
 * Key generation consumes a 32-byte RNG output plus 1 byte for the rank
 * (domain separation) which are hashed together to produce a pair of
 * 32-byte seeds public "rho" and private "sigma".
 */
int ossl_ml_kem_genkey(const uint8_t *seed,
                       uint8_t *pubenc,
                       scalar *m,
                       scalar *s,
                       scalar *tmp_e,
                       scalar *t,
                       uint8_t rho[ML_KEM_RANDOM_BYTES],
                       uint8_t pkhash[ML_KEM_PKHASH_BYTES],
                       uint8_t z[ML_KEM_RANDOM_BYTES],
                       vinfo_t vinfo,
                       mctx *ctx)
{
    uint8_t augmented_seed[ML_KEM_RANDOM_BYTES + 1];
    uint8_t hashed[ML_KEM_SEED_BYTES];
    const uint8_t *const sigma = hashed + ML_KEM_RANDOM_BYTES;
    uint8_t counter = 0;
    int rank = vinfo->rank;

    /* Use "d" portion of seed salted with the rank to generate key material */
    memcpy(augmented_seed, seed, ML_KEM_RANDOM_BYTES);
    augmented_seed[ML_KEM_RANDOM_BYTES] = (uint8_t) rank;
    if (!hash_g(hashed, augmented_seed, sizeof(augmented_seed), ctx))
        return 0;
    if (!matrix_expand(m, hashed, rank, ctx)
        || !gencbd_vector(s, vinfo->cbd1, &counter, sigma, rank, ctx))
        return 0;
    vector_ntt(s, rank);
    if (!gencbd_vector(tmp_e, vinfo->cbd1, &counter, sigma, rank, ctx))
        return 0;
    vector_ntt(tmp_e, rank);

    /* Fill in the public key */
    matrix_mult_transpose(t, m, s, rank);
    vector_add(t, tmp_e, rank);
    memcpy(rho, hashed, ML_KEM_RANDOM_BYTES);
    ossl_ml_kem_encode_public_key(pubenc, t, rho, vinfo);
    if (!hash_h(pkhash, pubenc, vinfo->pubkey_bytes, ctx))
        return 0;

    /* Save "z" portion of seed for "implicit rejection" on failure */
    memcpy(z, seed + ML_KEM_RANDOM_BYTES, ML_KEM_RANDOM_BYTES);
    return 1;
}

/*
 * FIPS 203, Section 6.2, Algorithm 17: ML-KEM.Encaps_internal
 * This is the deterministic version with randomness supplied externally.
 */
int ossl_ml_kem_encap_seed(uint8_t *out,
                           uint8_t *out_shared_secret,
                           const uint8_t entropy[ML_KEM_RANDOM_BYTES],
                           const scalar *m,
                           const scalar *t,
                           const uint8_t rho[ML_KEM_RANDOM_BYTES],
                           const uint8_t pkhash[ML_KEM_PKHASH_BYTES],
                           scalar *tmp_y,
                           scalar *tmp_e1,
                           scalar *tmp_u,
                           vinfo_t vinfo,
                           mctx *ctx)
{
    uint8_t input[ML_KEM_RANDOM_BYTES + ML_KEM_PKHASH_BYTES];
    uint8_t Kr[ML_KEM_SHARED_SECRET_BYTES + ML_KEM_RANDOM_BYTES];
    uint8_t *r = Kr + ML_KEM_SHARED_SECRET_BYTES;

# if ML_KEM_SEED_BYTES != ML_KEM_SHARED_SECRET_BYTES + ML_KEM_RANDOM_BYTES
#  error "ML-KEM keygen seed length != shared secret + random bytes length"
# endif

    memcpy(input, entropy, ML_KEM_RANDOM_BYTES);
    memcpy(input + ML_KEM_RANDOM_BYTES, pkhash, ML_KEM_PKHASH_BYTES);
    if (!hash_g(Kr, input, sizeof(input), ctx)
        || !encrypt_cpa(out, entropy, m, t, r, tmp_y, tmp_e1, tmp_u,
                        vinfo, ctx))
        return 0;
    memcpy(out_shared_secret, Kr, ML_KEM_SHARED_SECRET_BYTES);
    return 1;
}

/*
 * FIPS 203, Section 6.3, Algorithm 18: ML-KEM.Decaps_internal
 *
 * Barring failure of the supporting SHA3/SHAKE primitives, this is fully
 * deterministic, the randomness for the FO transform is extracted during
 * private key generation.
 */
int ossl_ml_kem_decap(uint8_t *shared_secret,
                      const uint8_t *ctext,
                      uint8_t *tmp_ctext,
                      const scalar *m,
                      const scalar *s,
                      const scalar *t,
                      const uint8_t rho[ML_KEM_RANDOM_BYTES],
                      const uint8_t pkhash[ML_KEM_PKHASH_BYTES],
                      const uint8_t z[ML_KEM_RANDOM_BYTES],
                      scalar *tmp_y,
                      scalar *tmp_e1,
                      scalar *tmp_u,
                      vinfo_t vinfo,
                      mctx *ctx)
{
    uint8_t decrypted[ML_KEM_SHARED_SECRET_BYTES + ML_KEM_PKHASH_BYTES];
    uint8_t Kr[ML_KEM_SHARED_SECRET_BYTES + ML_KEM_RANDOM_BYTES];
    uint8_t failure_key[ML_KEM_RANDOM_BYTES];
    uint8_t *r = Kr + ML_KEM_SHARED_SECRET_BYTES;
    uint8_t mask;
    int i;

# if ML_KEM_SHARED_SECRET_BYTES != ML_KEM_RANDOM_BYTES
#  error "Invalid unequal lengths of ML-KEM shared secret and random inputs"
# endif

    /*
     * If our KDF is unavailable, fail early! Otherwise, keep going ignoring
     * any further errors, returning success, and whatever we got for a shared
     * secret.  The decrypt_cpa() function is just arithmetic on secret data,
     * so should not be subject to failure that makes its output predictable.
     *
     * We guard against "should never happen" catastrophic failure of the
     * "pure" function |hash_g| by overwriting the shared secret with the
     * content of the failure key and returning early, if nevertheless hash_g
     * fails.  This is not constant-time, but a failure of |hash_g| already
     * implies loss of side-channel resistance.
     *
     * The same action is taken, if also |encrypt_cpa| should catastrophically
     * fail, due to failure of the |PRF| underlyign the CBD functions.
     */
    if (!kdf(failure_key, z, ctext, vinfo->ctext_bytes, ctx))
        return 0;
    decrypt_cpa(decrypted, ctext, s, tmp_u, vinfo);
    memcpy(decrypted + ML_KEM_SHARED_SECRET_BYTES, pkhash, ML_KEM_PKHASH_BYTES);
    if (!hash_g(Kr, decrypted, sizeof(decrypted), ctx)
        || !encrypt_cpa(tmp_ctext, decrypted, m, t, r, tmp_y, tmp_e1, tmp_u,
                        vinfo, ctx)) {
        memcpy(shared_secret, failure_key, ML_KEM_SHARED_SECRET_BYTES);
        return 1;
    }
    mask = constant_time_eq_int_8(0,
        CRYPTO_memcmp(ctext, tmp_ctext, vinfo->ctext_bytes));
    for (i = 0; i < ML_KEM_SHARED_SECRET_BYTES; i++)
        shared_secret[i] = constant_time_select_8(mask, Kr[i], failure_key[i]);
    return 1;
}

/*
 * -----
 *
 * Perform ML_KEM ops for a specific parameter set, the public and private key
 * pointers are (void *), in that order, when either is accepted in lieu of a
 * public key of the appropriate type.  Parameters with an implicit fixed
 * length in each variant have an explicit checked additional length argument
 * here.
 */
# define ml_kem_bname(bits, b)  ossl_ml_kem_##bits##_##b
# define encode_pubkey(bits)    ml_kem_bname(bits, encode_public_key)
# define encode_prvkey(bits)    ml_kem_bname(bits, encode_private_key)
# define parse_pubkey(bits)     ml_kem_bname(bits, parse_public_key)
# define parse_prvkey(bits)     ml_kem_bname(bits, parse_private_key)
# define genkey_rand(bits)      ml_kem_bname(bits, genkey_rand)
# define genkey_seed(bits)      ml_kem_bname(bits, genkey_seed)
# define encap_rand(bits)       ml_kem_bname(bits, encap_rand)
# define encap_seed(bits)       ml_kem_bname(bits, encap_seed)
# define decap(bits)            ml_kem_bname(bits, decap)
# define pub_t(bits)            ml_kem_bname(bits, public_key)
# define prv_t(bits)            ml_kem_bname(bits, private_key)

/*
 * Convert either a public or private key (void *) pointer to
 * a pointer of the correct type with a possible "const" qualifier.
 * In the case of public keys, we may be willing to also accept a private key,
 * which embeds an associated public key (|pubish| and |constish|).
 */
# define pubcast(bits, p)       ((pub_t(bits) *) (p))
# define pubconst(bits, p)      ((const pub_t(bits) *) (p))
# define prvcast(bits, p)       ((prv_t(bits) *) (p))
# define prvconst(bits, p)      ((const prv_t(bits) *) (p))
# define pubish(bits, p, q)     pubcast((p) != NULL ? \
                                        pubcast(bits, p) : \
                                        &(prvcast(bits, q)->pub))
# define constish(bits, p, q)   pubconst(bits, (p) != NULL ? \
                                         pubconst(bits, p) : \
                                         &(prvconst(bits, q)->pub))

int ossl_ml_kem_vencode_public_key(vinfo_t v,
                                   uint8_t *out,
                                   size_t len,
                                   const void *pub,
                                   const void *prv)
{
# define case_encode_pubkey(bits) \
    case ML_KEM_##bits##_RANK: \
        if ((pub == NULL && prv == NULL) || len != v->pubkey_bytes) \
            return 0; \
        encode_pubkey(bits)(out, constish(bits, pub, prv)); \
        return 1

    switch (v->rank) {
    case_encode_pubkey(512);
    case_encode_pubkey(768);
    case_encode_pubkey(1024);
    }
    return 0;
# undef case_encode_pubkey
}

int ossl_ml_kem_vparse_public_key(vinfo_t  v,
                                  void **pub,
                                  const uint8_t *in,
                                  size_t len,
                                  mctx *ctx)
{
# define case_parse_pubkey(bits) \
    case ML_KEM_##bits##_RANK: \
        if (pub == NULL || len != v->pubkey_bytes) \
            return 0; \
        if (*pub == NULL \
            && (*pub = OPENSSL_malloc(sizeof(*pubcast(bits, 0)))) == NULL) \
            return 0; \
        return parse_pubkey(bits)(pubcast(bits, *pub), in, ctx)

    switch (v->rank) {
    case_parse_pubkey(512);
    case_parse_pubkey(768);
    case_parse_pubkey(1024);
    }
    return 0;
# undef case_parse_pubkey
}

int ossl_ml_kem_vencode_private_key(vinfo_t v,
                                    uint8_t *out,
                                    size_t len,
                                    const void *prv)
{
# define case_encode_prvkey(bits) \
    case ML_KEM_##bits##_RANK: \
        if (prv == NULL || len != v->prvkey_bytes) \
            return 0; \
        encode_prvkey(bits)(out, prvconst(bits, prv)); \
        return 1

    switch (v->rank) {
    case_encode_prvkey(512);
    case_encode_prvkey(768);
    case_encode_prvkey(1024);
    }
    return 0;
# undef case_encode_prvkey
}

int ossl_ml_kem_vparse_private_key(vinfo_t v,
                                   void **prv,
                                   const uint8_t *in,
                                   size_t len,
                                   mctx *ctx)
{
# define case_parse_prvkey(bits) \
    case ML_KEM_##bits##_RANK: \
        if (prv == NULL || len != v->prvkey_bytes) \
            return 0; \
        if (*prv == NULL \
            && (*prv = OPENSSL_malloc(sizeof(*prvcast(bits, 0)))) == NULL) \
            return 0; \
        return parse_prvkey(bits)(prvcast(bits, *prv), in, ctx)

    switch (v->rank) {
    case_parse_prvkey(512);
    case_parse_prvkey(768);
    case_parse_prvkey(1024);
    }
    return 0;
# undef case_parse_prvkey
}

/*
 * The caller can elect to not collect the seed or the encoded public key
 */
int ossl_ml_kem_vgenkey_rand(vinfo_t v,
                             uint8_t *seed,
                             size_t seedlen,
                             uint8_t *pubenc,
                             size_t publen,
                             void **prv,
                             mctx *ctx)
{
# define case_genkey_rand(bits) \
    case ML_KEM_##bits##_RANK: \
        if ((seed != NULL && seedlen != ML_KEM_SEED_BYTES) \
            || (pubenc != NULL && publen != v->pubkey_bytes) \
            || prv == NULL) \
            return 0; \
        if (*prv == NULL \
            && (*prv = OPENSSL_malloc(sizeof(*prvcast(bits, 0)))) == NULL) \
            return 0; \
        return genkey_rand(bits)(seed, pubenc, prvcast(bits, *prv), ctx)

    switch (v->rank) {
    case_genkey_rand(512);
    case_genkey_rand(768);
    case_genkey_rand(1024);
    }
    return 0;
# undef case_genkey_rand
}

int ossl_ml_kem_vgenkey_seed(vinfo_t v,
                             const uint8_t *seed,
                             size_t seed_len,
                             uint8_t *pubenc,
                             size_t publen,
                             void **prv,
                             mctx *ctx)
{
# define case_genkey_seed(bits) \
    case ML_KEM_##bits##_RANK: \
        if (seed == NULL || (pubenc != NULL && publen != v->pubkey_bytes) \
            || prv == NULL) \
            return 0; \
        if (*prv == NULL \
            && (*prv = OPENSSL_malloc(sizeof(*prvcast(bits, 0)))) == NULL) \
            return 0; \
        return genkey_seed(bits)(seed, seed_len, pubenc, \
                                 prvcast(bits, *prv), ctx)

    switch (v->rank) {
    case_genkey_seed(512);
    case_genkey_seed(768);
    case_genkey_seed(1024);
    }
    return 0;
# undef case_genkey_seed
}

/*
 * FIPS 203, Section 6.2, Algorithm 17: ML-KEM.Encaps_internal
 * This is the deterministic version with randomness supplied externally.
 */
int ossl_ml_kem_vencap_seed(vinfo_t v,
                            uint8_t *ctext,
                            size_t clen,
                            uint8_t *shared_secret,
                            size_t slen,
                            const void *pub,
                            const void *prv,
                            const uint8_t *entropy,
                            size_t elen,
                            mctx *ctx)
{
# define case_encap_seed(bits) \
    case ML_KEM_##bits##_RANK: \
        if (ctext == NULL || clen != v->ctext_bytes \
            || shared_secret == NULL \
            || slen != ML_KEM_SHARED_SECRET_BYTES \
            || entropy == NULL || elen != ML_KEM_RANDOM_BYTES \
            || (pub == NULL && prv == NULL)) \
            return 0; \
        return encap_seed(bits)(ctext, shared_secret, \
                                constish(bits, pub, prv), entropy, ctx)

    switch (v->rank) {
    case_encap_seed(512);
    case_encap_seed(768);
    case_encap_seed(1024);
    }
    return 0;
# undef case_encap_seed
}

int ossl_ml_kem_vencap_rand(vinfo_t v,
                            uint8_t *ctext,
                            size_t clen,
                            uint8_t *shared_secret,
                            size_t slen,
                            const void *pub,
                            void *prv,
                            mctx *ctx)
{
# define case_encap_rand(bits) \
    case ML_KEM_##bits##_RANK: \
        if (ctext == NULL || clen != v->ctext_bytes \
            || shared_secret == NULL \
            || slen != ML_KEM_SHARED_SECRET_BYTES \
            || (pub == NULL && prv == NULL)) \
            return 0; \
        return encap_rand(bits)(ctext, shared_secret, \
                                constish(bits, pub, prv), ctx)

    switch (v->rank) {
    case_encap_rand(512);
    case_encap_rand(768);
    case_encap_rand(1024);
    }
    return 0;
# undef case_encap_rand
}

int ossl_ml_kem_vdecap(vinfo_t v,
                       uint8_t *shared_secret,
                       size_t slen,
                       const uint8_t *ctext,
                       size_t clen,
                       const void *prv,
                       mctx *ctx)
{
# define case_decap(bits) \
    case ML_KEM_##bits##_RANK: \
        if (shared_secret == NULL || slen != ML_KEM_SHARED_SECRET_BYTES \
            || ctext == NULL || prv == NULL) \
            return 0; \
        return decap(bits)(shared_secret, ctext, clen, prvcast(bits, prv), ctx)

    switch (v->rank) {
    case_decap(512);
    case_decap(768);
    case_decap(1024);
    }
    return 0;
# undef case_decap
}

int ossl_ml_kem_vcompare_pubkeys(vinfo_t v1,
                                 const void *pub1,
                                 const void *prv1,
                                 vinfo_t v2,
                                 const void *pub2,
                                 const void *prv2)
{
# define case_compare(bits) \
    case ML_KEM_##bits##_RANK: \
        /* No match if either or both are not available */ \
        if (pub1 == NULL && prv1 == NULL) \
            return 0; \
        if (pub2 == NULL && prv2 == NULL) \
            return 0; \
        return memcmp(constish(bits, pub1, prv1)->pkhash, \
                      constish(bits, pub2, prv2)->pkhash, \
                      ML_KEM_PKHASH_BYTES) == 0

    /*
     * Rank mismatch should not happen, distinct ML-KEM variants have separate
     * dispatch methods.
     */
    if (v1->rank != v2->rank)
        return 0;

    switch (v1->rank) {
    case_compare(512);
    case_compare(768);
    case_compare(1024);
    }
    return 0;
# undef case_compare
}

int ossl_ml_kem_vcleanse_prvkey(vinfo_t v,
                                void **prv)
{
# define case_cleanse(bits) \
    case ML_KEM_##bits##_RANK: \
        { \
            prv_t(bits) *k = prvcast(bits, *prv); \
                                                  \
            if (prv == NULL || *prv == NULL) \
                return 1;  \
            OPENSSL_cleanse(&k->s, sizeof((k)->s)); \
            OPENSSL_cleanse(k->z, sizeof(k->z)); \
            OPENSSL_free(k); \
            *prv = NULL; \
            return 1; \
        }

    switch (v->rank) {
    case_cleanse(512);
    case_cleanse(768);
    case_cleanse(1024);
    }
    return 0;
# undef case_cleanse
}

#else
NON_EMPTY_TRANSLATION_UNIT
#endif
