/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Copyright (c) 2024, Google Inc. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <crypto/mlkem.h>
#include <internal/sha3.h>
#include <internal/constant_time.h>
#include <internal/common.h>
#ifndef NDEBUG
# include <stdio.h>
#endif

#ifndef OPENSSL_NO_MLKEM

/* Constants that are common across all sizes. */
# define DEGREE 256
static const size_t kBarrettMultiplier = 5039;
static const unsigned kBarrettShift = 24;
static const uint16_t kPrime = 3329;
static const int kLog2Prime = 12;
static const uint16_t kHalfPrime = (/* kPrime= */ 3329 - 1) / 2;

/*
 * kInverseDegree is 128^-1 mod 3329; 128 because kPrime does not have a 512th
 * root of unity.
 */
static const uint16_t kInverseDegree = 3303;

/* Rank-specific constants. */
# define RANK768 3
static const int kDU768 = 10;
static const int kDV768 = 4;
# define RANK1024 4
static const int kDU1024 = 11;
static const int kDV1024 = 5;

static ossl_inline size_t compressed_vector_size(int rank)
{
    return (rank == RANK768 ? kDU768 : kDU1024) * (size_t)rank *
        DEGREE / 8;
}

static ossl_inline size_t ciphertext_size(int rank)
{
    return compressed_vector_size(rank) +
        (rank == RANK768 ? kDV768 : kDV1024) * DEGREE / 8;
}

typedef struct scalar {
    /* On every function entry and exit, 0 <= c < kPrime. */
    uint16_t c[DEGREE];
} scalar;

/* TODO(ML-KEM): possibly rename vector768 to allow for other algs */
typedef struct vector {
    scalar v[RANK768];
} vector;

/* TODO(ML-KEM): possibly rename matrix768 to allow for other algs */
typedef struct matrix {
    scalar v[RANK768][RANK768];
} matrix;

typedef struct public_key_RANK768 {
    vector t;
    uint8_t rho[32];
    uint8_t public_key_hash[32];
    matrix m;
} public_key_RANK768;

typedef struct private_key_RANK768 {
    struct public_key_RANK768 pub;
    vector s;
    uint8_t fo_failure_secret[32];
} private_key_RANK768;

static ossl_inline size_t encoded_vector_size(int rank)
{
    return (kLog2Prime * DEGREE / 8) * (size_t)rank;
}

static ossl_inline size_t encoded_public_key_size(int rank)
{
    return encoded_vector_size(rank) + /* sizeof(rho)= */ 32;
}

/* MD&XOF handles */

/* Cache mgmt as per https://github.com/openssl/private/issues/700 */

ossl_mlkem_ctx *ossl_mlkem_newctx(OSSL_LIB_CTX *libctx, const char *properties)
{
    ossl_mlkem_ctx *nctx = OPENSSL_zalloc(sizeof(ossl_mlkem_ctx));

    /* replacing static asserts: */
    if (nctx == NULL
        || (OSSL_MLKEM768_SHARED_SECRET_BYTES != 32)
        || (sizeof(unsigned int) < sizeof (uint32_t))
        || (sizeof(struct ossl_mlkem768_public_key) <
            sizeof(struct public_key_RANK768))
        || (sizeof(struct ossl_mlkem768_private_key) <
            sizeof(struct private_key_RANK768))
        || (encoded_public_key_size(RANK768) != OSSL_MLKEM768_PUBLIC_KEY_BYTES)
        || (encoded_public_key_size(RANK1024) != OSSL_MLKEM1024_PUBLIC_KEY_BYTES)
        || (ciphertext_size(RANK768) != OSSL_MLKEM768_CIPHERTEXT_BYTES)
        || (ciphertext_size(RANK1024) != OSSL_MLKEM1024_CIPHERTEXT_BYTES))
        goto err;

    nctx->shake128_cache = EVP_MD_fetch(libctx, "SHAKE128", properties);
    nctx->shake256_cache = EVP_MD_fetch(libctx, "SHAKE256", properties);
    nctx->sha3_256_cache = EVP_MD_fetch(libctx, "SHA3-256", properties);
    nctx->sha3_512_cache = EVP_MD_fetch(libctx, "SHA3-512", properties);
    nctx->libctx = libctx;
    if (properties != NULL)
        if ((nctx->properties = OPENSSL_strdup(properties)) == NULL)
            goto err;
    if (nctx->shake128_cache == NULL || nctx->shake256_cache == NULL ||
        nctx->sha3_256_cache == NULL || nctx->sha3_512_cache == NULL)
        goto err;
    return nctx;

err:
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
    ossl_mlkem_ctx_free(nctx);
    return NULL;
}

void ossl_mlkem_ctx_free(ossl_mlkem_ctx *ctx)
{
    if (ctx != NULL) {
        EVP_MD_free(ctx->shake128_cache);
        EVP_MD_free(ctx->shake256_cache);
        EVP_MD_free(ctx->sha3_256_cache);
        EVP_MD_free(ctx->sha3_512_cache);
        OPENSSL_free(ctx->properties);
    }
    OPENSSL_free(ctx);
}

/*
 * single_keccak hashes |in_len| bytes from |in| and writes |out_len| bytes
 * of output to |out|. If the |md| specifies a fixed-output function, like
 * SHA3-256, then |out_len| must be the correct length for that function.
 */
static int single_keccak(uint8_t *out, size_t out_len,
                         const uint8_t *in, size_t in_len,
                         EVP_MD *md)
{
    EVP_MD_CTX *mdctx;
    int ret = 0;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL
        || !EVP_DigestInit_ex(mdctx, md, NULL)
        || !EVP_DigestUpdate(mdctx, in, in_len))
        return 0;

    if (EVP_MD_xof(md))
        ret = EVP_DigestFinalXOF(mdctx, out, out_len);
    else
        ret = EVP_DigestFinal_ex(mdctx, out, NULL);
    EVP_MD_CTX_free(mdctx);

    return ret;
}

/* TODO(ML-KEM) revisit utility of this function/remove eventually */
static void print_hex(const uint8_t *data, int len, const char *msg)
{
# ifndef NDEBUG
    if (msg)
        printf("%s: \n", msg);
    BIO_dump_fp(stdout, data, len);
    fflush(0);
# endif
}

/*
 * MLKEM_ENCAP_ENTROPY is the number of bytes of uniformly random entropy
 * necessary to encapsulate a secret. The entropy will be leaked to the
 * decapsulating party.
 */
# define MLKEM_ENCAP_ENTROPY 32

/* See https://csrc.nist.gov/pubs/fips/203/final */
static int prf(uint8_t *out, size_t out_len, const uint8_t in[33],
               ossl_mlkem_ctx *mlkem_ctx)
{
    return single_keccak(out, out_len, in, 33, mlkem_ctx->shake256_cache);
}

/*
 * Section 4.1
 * uint8_t out[32]
 */
static int hash_h(uint8_t *out, const uint8_t *in, size_t len,
                  ossl_mlkem_ctx *mlkem_ctx)
{
    return single_keccak(out, 32, in, len, mlkem_ctx->sha3_256_cache);
}

/* uint8_t out[64] */
static int hash_g(uint8_t *out, const uint8_t *in, size_t len,
                  ossl_mlkem_ctx *mlkem_ctx)
{
    return single_keccak(out, 64, in, len, mlkem_ctx->sha3_512_cache);
}

/*
 * This is called `J` in the spec.
 * uint8_t out[ossl_mlkem768_SHARED_SECRET_BYTES],
 * const uint8_t failure_secret[32]
 */
static int kdf(uint8_t *out,
               const uint8_t *failure_secret, const uint8_t *ciphertext,
               size_t ciphertext_len,
               ossl_mlkem_ctx *mlkem_ctx)
{
    EVP_MD_CTX *mdctx;
    int ret = 0;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL
        || !EVP_DigestInit_ex(mdctx, mlkem_ctx->shake256_cache, NULL)
        || !EVP_DigestUpdate(mdctx, failure_secret, 32)
        || !EVP_DigestUpdate(mdctx, ciphertext, ciphertext_len)
        || !EVP_DigestFinalXOF(mdctx, out, OSSL_MLKEM768_SHARED_SECRET_BYTES))
        goto end;

    ret = 1;

end:
    EVP_MD_CTX_free(mdctx);
    return ret;
}

/*
 * This bit of Python will be referenced in some of the following comments:
 *
 * p = 3329
 *
 * def bitreverse(i):
 *     ret = 0
 *     for n in range(7):
 *         bit = i & 1
 *         ret <<= 1
 *         ret |= bit
 *         i >>= 1
 *     return ret
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

/* kInverseNTTRoots = [pow(17, -bitreverse(i), p) for i in range(128)] */
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

/* kModRoots = [pow(17, 2*bitreverse(i) + 1, p) for i in range(128)] */
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

/* reduce_once reduces 0 <= x < 2*kPrime, mod kPrime. */
static uint16_t reduce_once(uint16_t x)
{
    const uint16_t subtracted = x - kPrime;
    uint16_t mask = 0u - (subtracted >> 15);

    assert(x < 2 * kPrime);
    /*
     * On Aarch64, omitting a |value_barrier_u16| results in a 2x speedup of
     * ML-KEM overall and Clang still produces constant-time code using `csel`. On
     * other platforms & compilers on godbolt that we care about, this code also
     * produces constant-time output.
     */
    return (mask & x) | (~mask & subtracted);
}

/*
 * constant time reduce x mod kPrime using Barrett reduction. x must be less
 * than kPrime + 2xkPrime^2.
 */
static uint16_t reduce(uint32_t x)
{
    uint64_t product = (uint64_t)x * kBarrettMultiplier;
    uint32_t quotient = (uint32_t)(product >> kBarrettShift);
    uint32_t remainder = x - quotient * kPrime;

    assert(x < kPrime + 2u * kPrime * kPrime);
    return reduce_once(remainder);
}

static void scalar_zero(scalar *out)
{
    memset(out, 0, sizeof(*out));
}

static void vector_zero(vector *out)
{
    memset(out->v, 0, sizeof(scalar) * RANK768);
}

/*
 * In place number theoretic transform of a given scalar.
 * Note that MLKEM's kPrime 3329 does not have a 512th root of unity, so this
 * transform leaves off the last iteration of the usual FFT code, with the 128
 * relevant roots of unity being stored in |kNTTRoots|. This means the output
 * should be seen as 128 elements in GF(3329^2), with the coefficients of the
 * elements being consecutive entries in |s->c|.
 */
static void scalar_ntt(scalar *s)
{
    int offset = DEGREE;
    int k, step, i, j;
    uint32_t step_root;
    uint16_t odd, even;

    /*
     * `int` is used here because using `size_t` throughout caused a ~5% slowdown
     * with Clang 14 on Aarch64.
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

static void vector_ntt(vector *a)
{
    int i;

    for (i = 0; i < RANK768; i++)
        scalar_ntt(&a->v[i]);
}

/*
 * In place inverse number theoretic transform of a given scalar, with pairs of
 * entries of s->v being interpreted as elements of GF(3329^2). Just as with the
 * number theoretic transform, this leaves off the first step of the normal iFFT
 * to account for the fact that 3329 does not have a 512th root of unity, using
 * the precomputed 128 roots of unity stored in |kInverseNTTRoots|.
 */
static void scalar_inverse_ntt(scalar *s)
{
    int step = DEGREE / 2;
    int offset, k, i, j;
    uint32_t step_root;
    uint16_t odd, even;

    /*
     * `int` is used here because using `size_t` throughout caused a ~5% slowdown
     * with Clang 14 on Aarch64.
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

static void vector_inverse_ntt(vector *a)
{
    int i;

    for (i = 0; i < RANK768; i++)
        scalar_inverse_ntt(&a->v[i]);
}

static void scalar_add(scalar *lhs, const scalar *rhs)
{
    int i;

    for (i = 0; i < DEGREE; i++)
        lhs->c[i] = reduce_once(lhs->c[i] + rhs->c[i]);
}

static void scalar_sub(scalar *lhs, const scalar *rhs)
{
    int i;

    for (i = 0; i < DEGREE; i++)
        lhs->c[i] = reduce_once(lhs->c[i] - rhs->c[i] + kPrime);
}

/*
 * Multiplying two scalars in the number theoretically transformed state. Since
 * 3329 does not have a 512th root of unity, this means we have to interpret
 * the 2*ith and (2*i+1)th entries of the scalar as elements of GF(3329)[X]/(X^2
 * - 17^(2*bitreverse(i)+1)) The value of 17^(2*bitreverse(i)+1) mod 3329 is
 * stored in the precomputed |kModRoots| table. Note that our Barrett transform
 * only allows us to multipy two reduced numbers together, so we need some
 * intermediate reduction steps, even if an uint64_t could hold 3 multiplied
 * numbers.
 */
static void scalar_mult(scalar *out, const scalar *lhs, const scalar *rhs)
{
    int i;
    uint32_t real_real, img_img, real_img, img_real;

    for (i = 0; i < DEGREE / 2; i++) {
        real_real = (uint32_t)lhs->c[2 * i] * rhs->c[2 * i];
        img_img = (uint32_t)lhs->c[2 * i + 1] * rhs->c[2 * i + 1];
        real_img = (uint32_t)lhs->c[2 * i] * rhs->c[2 * i + 1];
        img_real = (uint32_t)lhs->c[2 * i + 1] * rhs->c[2 * i];
        out->c[2 * i] =
            reduce(real_real + (uint32_t)reduce(img_img) * kModRoots[i]);
        out->c[2 * i + 1] = reduce(img_real + real_img);
    }
}

static void vector_add(vector *lhs, const vector *rhs)
{
    int i;

    for (i = 0; i < RANK768; i++)
        scalar_add(&lhs->v[i], &rhs->v[i]);
}

static void matrix_mult(vector *out, const matrix *m,
                        const vector *a)
{
    int i, j;

    vector_zero(out);
    for (i = 0; i < RANK768; i++) {
        for (j = 0; j < RANK768; j++) {
            scalar product;

            scalar_mult(&product, &m->v[i][j], &a->v[j]);
            scalar_add(&out->v[i], &product);
        }
    }
}

static void matrix_mult_transpose(vector *out, const matrix *m,
                                  const vector *a)
{
    int i, j;

    vector_zero(out);
    for (i = 0; i < RANK768; i++) {
        for (j = 0; j < RANK768; j++) {
            scalar product;

            scalar_mult(&product, &m->v[j][i], &a->v[j]);
            scalar_add(&out->v[i], &product);
        }
    }
}

static void scalar_inner_product(scalar *out, const vector *lhs,
                                 const vector *rhs)
{
    int i;

    scalar_zero(out);
    for (i = 0; i < RANK768; i++) {
        scalar product;

        scalar_mult(&product, &lhs->v[i], &rhs->v[i]);
        scalar_add(out, &product);
    }
}

/*
 * Algorithm 6 from the spec. Rejection samples a Keccak stream to get
 * uniformly distributed elements. This is used for matrix expansion and only
 * operates on public inputs.
 */
static int scalar_from_keccak_vartime(scalar *out, EVP_MD_CTX *mdctx)
{
    int done = 0;
    uint8_t block[168];
    size_t i;
    uint16_t d1, d2;

    while (done < DEGREE) {
        if (!EVP_DigestSqueeze(mdctx, block, sizeof(block)))
            return 0;
        for (i = 0; i < sizeof(block) && done < DEGREE; i += 3) {
            d1 = block[i] + 256 * (block[i + 1] % 16);
            d2 = block[i + 1] / 16 + 16 * block[i + 2];
            if (d1 < kPrime)
                out->c[done++] = d1;
            if (d2 < kPrime && done < DEGREE)
                out->c[done++] = d2;
        }
    }
    return 1;
}

/*
 * Algorithm 7 from the spec, with eta fixed to two and the PRF call
 * included. Creates binominally distributed elements by sampling 2*|eta| bits,
 * and setting the coefficient to the count of the first bits minus the count of
 * the second bits, resulting in a centered binomial distribution. Since eta is
 * two this gives -2/2 with a probability of 1/16, -1/1 with probability 1/4,
 * and 0 with probability 3/8.
 */
static
int scalar_centered_binomial_distribution_eta_2_with_prf(scalar *out,
                                                         const uint8_t input[33],
                                                         ossl_mlkem_ctx *mlkem_ctx)
{
    uint8_t entropy[128];
    int i;
    uint8_t byte;
    uint16_t value;

    assert(sizeof(entropy) == 2 * /* kEta= */ 2 * DEGREE / 8);
    if (!prf(entropy, sizeof(entropy), input, mlkem_ctx))
        return 0;
    for (i = 0; i < DEGREE; i += 2) {
        byte = entropy[i / 2];
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
 * Generates a secret vector by using
 * |scalar_centered_binomial_distribution_eta_2_with_prf|, using the given seed
 * appending and incrementing |counter| for entry of the vector.
 */
static int vector_generate_secret_eta_2(vector *out, uint8_t *counter,
                                        const uint8_t seed[32],
                                        ossl_mlkem_ctx *mlkem_ctx)
{
    uint8_t input[33];
    int i;

    memcpy(input, seed, 32);
    for (i = 0; i < RANK768; i++) {
        input[32] = (*counter)++;
        if (!scalar_centered_binomial_distribution_eta_2_with_prf(&out->v[i],
                                                                  input, mlkem_ctx))
            return 0;
    }
    return 1;
}

/* Expands the matrix of a seed for key generation and for encaps-CPA. */
static int matrix_expand(matrix *out, const uint8_t rho[32],
                         ossl_mlkem_ctx *mlkem_ctx)
{
    uint8_t input[34];
    int i, j, ret = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL)
        goto end;
    memcpy(input, rho, 32);
    for (i = 0; i < RANK768; i++) {
        for (j = 0; j < RANK768; j++) {
            input[32] = i;
            input[33] = j;
            if (!EVP_DigestInit_ex(mdctx, mlkem_ctx->shake128_cache, NULL)
                || !EVP_DigestUpdate(mdctx, input, sizeof(input))
                || !scalar_from_keccak_vartime(&out->v[i][j], mdctx))
                goto end;
        }
    }

    ret = 1;
end:
    EVP_MD_CTX_free(mdctx);
    return ret;
}

static const uint8_t kMasks[8] = {0x01, 0x03, 0x07, 0x0f,
                                  0x1f, 0x3f, 0x7f, 0xff};

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
 * Encodes an entire vector into 32*|RANK|*|bits| bytes. Note that since 256
 * (DEGREE) is divisible by 8, the individual vector entries will always fill a
 * whole number of bytes, so we do not need to worry about bit packing here.
 */
static void vector_encode(uint8_t *out, const vector *a, int bits)
{
    int i;

    for (i = 0; i < RANK768; i++)
        scalar_encode(out + i * bits * DEGREE / 8, &a->v[i], bits);
}

/*
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

    if (!ossl_assert(bits <= (int)sizeof(*out->c) * 8 && bits != 1))
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

/* scalar_decode_1 is |scalar_decode| specialised for |bits| == 1. */
static void scalar_decode_1(scalar *out, const uint8_t in[32])
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
 * Decodes 32*|RANK|*|bits| bytes from |in| into |out|. It returns one on
 * success or zero if any parsed value is >= |kPrime|.
 */
static int vector_decode(vector *out, const uint8_t *in, int bits)
{
    int i;

    for (i = 0; i < RANK768; i++) {
        if (!scalar_decode(&out->v[i], in + i * bits * DEGREE / 8, bits))
            return 0;
    }
    return 1;
}

/*
 * Compresses (lossily) an input |x| mod 3329 into |bits| many bits by grouping
 * numbers close to each other together. The formula used is
 * round(2^|bits|/kPrime*x) mod 2^|bits|.
 * Uses Barrett reduction to achieve constant time. Since we need both the
 * remainder (for rounding) and the quotient (as the result), we cannot use
 * |reduce| here, but need to do the Barrett reduction directly.
 */
static uint16_t compress(uint16_t x, int bits)
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
 * Decompresses |x| by using an equi-distant representative. The formula is
 * round(kPrime/2^|bits|*x). Note that 2^|bits| being the divisor allows us to
 * implement this logic using only bit operations.
 */
static uint16_t decompress(uint16_t x, int bits)
{
    uint32_t product = (uint32_t)x * kPrime;
    uint32_t power = 1 << bits;
    /* This is |product| % power, since |power| is a power of 2. */
    uint32_t remainder = product & (power - 1);
    /* This is |product| / power, since |power| is a power of 2. */
    uint32_t lower = product >> bits;

    /*
     * The rounding logic works since the first half of numbers mod |power| have a
     * 0 as first bit, and the second half has a 1 as first bit, since |power| is
     * a power of 2. As a 12 bit number, |remainder| is always positive, so we
     * will shift in 0s for a right shift.
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

static void vector_compress(vector *a, int bits)
{
    int i;

    for (i = 0; i < RANK768; i++)
        scalar_compress(&a->v[i], bits);
}

static void vector_decompress(vector *a, int bits)
{
    int i;

    for (i = 0; i < RANK768; i++)
        scalar_decompress(&a->v[i], bits);
}

static
public_key_RANK768 *public_key_768_from_external(const ossl_mlkem768_public_key *external)
{
    return (struct public_key_RANK768 *)external;
}

static
private_key_RANK768 *private_key_768_from_external(const ossl_mlkem768_private_key *external)
{
    return (struct private_key_RANK768 *)external;
}

static int mlkem_marshal_public_key(uint8_t *out,
                                    const struct public_key_RANK768 *pub)
{
    /*
     * replace CBB logic with straight copy to out and memcpy of rho at tail end
     * TODO(ML-KEM): Check this is OK to protect incorrect buffer(sizes) passed
     * possibly use WPACKET?
     */
    vector_encode(out, &pub->t, kLog2Prime);
    memcpy(out + encoded_vector_size(RANK768), pub->rho, sizeof(pub->rho));
    return 1;
}

static int mlkem_generate_key_external_seed(uint8_t *out_encoded_public_key,
                                            private_key_RANK768 *priv,
                                            const uint8_t *seed,
                                            ossl_mlkem_ctx *mlkem_ctx)
{
    uint8_t augmented_seed[33];
    uint8_t hashed[64];
    const uint8_t *const rho = hashed;
    const uint8_t *const sigma = hashed + 32;
    uint8_t counter = 0;
    vector error;

    if (mlkem_ctx == NULL)
        return 0;

    memcpy(augmented_seed, seed, 32);
    augmented_seed[32] = RANK768;
    if (!hash_g(hashed, augmented_seed, sizeof(augmented_seed), mlkem_ctx))
        return 0;
    memcpy(priv->pub.rho, hashed, sizeof(priv->pub.rho));
    if (!matrix_expand(&priv->pub.m, rho, mlkem_ctx)
        || (!vector_generate_secret_eta_2(&priv->s, &counter, sigma, mlkem_ctx)))
        return 0;
    vector_ntt(&priv->s);
    if (!vector_generate_secret_eta_2(&error, &counter, sigma, mlkem_ctx))
        return 0;
    vector_ntt(&error);
    matrix_mult_transpose(&priv->pub.t, &priv->pub.m, &priv->s);
    vector_add(&priv->pub.t, &error);
    if (!mlkem_marshal_public_key(out_encoded_public_key, &priv->pub)
        || !hash_h(priv->pub.public_key_hash, out_encoded_public_key,
                   encoded_public_key_size(RANK768), mlkem_ctx))
        return 0;
    memcpy(priv->fo_failure_secret, seed + 32, 32);
    return 1;
}

static
int ossl_mlkem768_generate_key_external_seed(uint8_t *out_encoded_public_key,
                                             ossl_mlkem768_private_key *out_private_key,
                                             const uint8_t *seed,
                                             ossl_mlkem_ctx *mlkem_ctx)
{
    private_key_RANK768 *priv = NULL;

    priv = private_key_768_from_external(out_private_key);
    return mlkem_generate_key_external_seed(out_encoded_public_key, priv, seed, mlkem_ctx);
}

int ossl_mlkem768_generate_key(uint8_t *out_encoded_public_key,
                               uint8_t *optional_out_seed,
                               ossl_mlkem768_private_key *out_private_key,
                               ossl_mlkem_ctx *mlkem_ctx)
{
    uint8_t seed[OSSL_MLKEM_SEED_BYTES];

    if (mlkem_ctx == NULL)
        return 0;

    /* TODO(ML-KEM): Review requested randomness strength */
    if (RAND_priv_bytes_ex(mlkem_ctx->libctx, seed, sizeof(seed), 256) == 1) {
        if (optional_out_seed)
            memcpy(optional_out_seed, seed, sizeof(seed));
        return ossl_mlkem768_generate_key_external_seed(out_encoded_public_key,
                                                        out_private_key,
                                                        seed, mlkem_ctx);
    }
    return 0;
}

int ossl_mlkem768_private_key_from_seed(ossl_mlkem768_private_key *out_private_key,
                                        const uint8_t *seed, size_t seed_len,
                                        ossl_mlkem_ctx *mlkem_ctx)
{
    uint8_t public_key_bytes[OSSL_MLKEM768_PUBLIC_KEY_BYTES];

    if (seed_len != OSSL_MLKEM_SEED_BYTES)
        return 0;
    ossl_mlkem768_generate_key_external_seed(public_key_bytes, out_private_key,
                                             seed, mlkem_ctx);
    return 1;
}

int ossl_mlkem768_public_from_private(ossl_mlkem768_public_key *out_public_key,
                                      const ossl_mlkem768_private_key *private_key)
{
    struct public_key_RANK768 *const pub = public_key_768_from_external(out_public_key);
    const struct private_key_RANK768 *const priv =
        private_key_768_from_external(private_key);

    if (priv == NULL)
        return 0;
    *pub = priv->pub;
    return 1;
}

/*
 * Encrypts a message with given randomness to
 * the ciphertext in |out|. Without applying the Fujisaki-Okamoto transform this
 * would not result in a CCA secure scheme, since lattice schemes are vulnerable
 * to decryption failure oracles.
 */
static int encrypt_cpa(uint8_t *out, const struct public_key_RANK768 *pub,
                       const uint8_t *message,
                       const uint8_t *randomness,
                       ossl_mlkem_ctx *mlkem_ctx)
{
    int du = kDU768;
    int dv = kDV768;
    uint8_t counter = 0;
    vector secret, error;
    uint8_t input[33];
    scalar scalar_error;
    vector u;
    scalar v;
    scalar expanded_message;

    if (!vector_generate_secret_eta_2(&secret, &counter, randomness, mlkem_ctx))
        return 0;
    vector_ntt(&secret);
    if (!vector_generate_secret_eta_2(&error, &counter, randomness, mlkem_ctx))
        return 0;
    memcpy(input, randomness, 32);
    input[32] = counter;
    if (!scalar_centered_binomial_distribution_eta_2_with_prf(&scalar_error, input, mlkem_ctx))
        return 0;
    matrix_mult(&u, &pub->m, &secret);
    vector_inverse_ntt(&u);
    vector_add(&u, &error);
    scalar_inner_product(&v, &pub->t, &secret);
    scalar_inverse_ntt(&v);
    scalar_add(&v, &scalar_error);
    scalar_decode_1(&expanded_message, message);
    scalar_decompress(&expanded_message, 1);
    scalar_add(&v, &expanded_message);
    vector_compress(&u, du);
    vector_encode(out, &u, du);
    scalar_compress(&v, dv);
    scalar_encode(out + compressed_vector_size(RANK768), &v, dv);
    return 1;
}

/*
 * See section 6.2.
 * entropy[MLKEM_ENCAP_ENTROPY])
 */
static int mlkem_encap_external_entropy(uint8_t *out_ciphertext,
                                        uint8_t *out_shared_secret,
                                        const public_key_RANK768 *pub,
                                        const uint8_t *entropy,
                                        ossl_mlkem_ctx *mlkem_ctx)
{
    uint8_t input[64];
    uint8_t key_and_randomness[64];

    memcpy(input, entropy, MLKEM_ENCAP_ENTROPY);
    memcpy(input + MLKEM_ENCAP_ENTROPY, pub->public_key_hash,
           sizeof(input) - MLKEM_ENCAP_ENTROPY);
    if (!hash_g(key_and_randomness, input, sizeof(input), mlkem_ctx)
        || !encrypt_cpa(out_ciphertext, pub, entropy,
                        key_and_randomness + 32, mlkem_ctx))
        return 0;
    memcpy(out_shared_secret, key_and_randomness, 32);
    return 1;
}

/*
 * out_ciphertext[ossl_mlkem768_CIPHERTEXT_BYTES],
 * out_shared_secret[ossl_mlkem768_SHARED_SECRET_BYTES],
 * entropy[MLKEM_ENCAP_ENTROPY])
 */
int ossl_mlkem768_encap_external_entropy(uint8_t *out_ciphertext,
                                         uint8_t *out_shared_secret,
                                         const ossl_mlkem768_public_key *public_key,
                                         const uint8_t *entropy,
                                         ossl_mlkem_ctx *mlkem_ctx)
{
    const struct public_key_RANK768 *pub =
        public_key_768_from_external(public_key);

    return mlkem_encap_external_entropy(out_ciphertext, out_shared_secret, pub,
                                        entropy, mlkem_ctx);
}

/* Calls |ossl_mlkem768_encap_external_entropy| with random bytes from |RAND_bytes| */
int ossl_mlkem768_encap(uint8_t *out_ciphertext,
                        uint8_t *out_shared_secret,
                        const ossl_mlkem768_public_key *public_key,
                        ossl_mlkem_ctx *mlkem_ctx)
{
    uint8_t entropy[MLKEM_ENCAP_ENTROPY];

    if (mlkem_ctx == NULL)
        return 0;

    /* TODO(ML-KEM): Review requested randomness strength */
    if (RAND_bytes_ex(mlkem_ctx->libctx, entropy, MLKEM_ENCAP_ENTROPY, 256) != 1
        || !ossl_mlkem768_encap_external_entropy(out_ciphertext,
                                                 out_shared_secret, public_key,
                                                 entropy, mlkem_ctx))
        return 0;
    print_hex((uint8_t *)public_key, sizeof(ossl_mlkem768_public_key), "PK");
    print_hex(out_shared_secret, OSSL_MLKEM768_SHARED_SECRET_BYTES, "SS2");
    print_hex(out_ciphertext, OSSL_MLKEM768_CIPHERTEXT_BYTES, "CT2");
    return 1;
}

static void decrypt_cpa(uint8_t *out, const struct private_key_RANK768 *priv,
                        const uint8_t *ciphertext)
{
    int du = kDU768;
    int dv = kDV768;
    vector u;
    scalar v, mask;

    vector_decode(&u, ciphertext, du);
    vector_decompress(&u, du);
    vector_ntt(&u);
    scalar_decode(&v, ciphertext + compressed_vector_size(RANK768), dv);
    scalar_decompress(&v, dv);
    scalar_inner_product(&mask, &priv->s, &u);
    scalar_inverse_ntt(&mask);
    scalar_sub(&v, &mask);
    scalar_compress(&v, 1);
    scalar_encode_1(out, &v);
}

/* See section 6.3 */
static int mlkem_decap(uint8_t *out_shared_secret,
                       const uint8_t *ciphertext,
                       const struct private_key_RANK768 *priv,
                       ossl_mlkem_ctx *mlkem_ctx)
{
    uint8_t decrypted[64];
    uint8_t key_and_randomness[64];
    size_t ciphertext_len = ciphertext_size(RANK768);
    /* TODO(ML-KEM): Maximum also applicable for other algs? */
    uint8_t expected_ciphertext[OSSL_MLKEM1024_CIPHERTEXT_BYTES];
    uint8_t failure_key[32];
    uint8_t mask;
    int i;

    print_hex((uint8_t *)&priv->pub, sizeof(ossl_mlkem768_public_key), "PK1");
    print_hex(ciphertext, OSSL_MLKEM768_CIPHERTEXT_BYTES, "CT");
    decrypt_cpa(decrypted, priv, ciphertext);
    memcpy(decrypted + 32, priv->pub.public_key_hash,
           sizeof(decrypted) - 32);
    if (!hash_g(key_and_randomness, decrypted, sizeof(decrypted), mlkem_ctx))
        return 0;
    assert(ciphertext_len <= sizeof(expected_ciphertext));
    encrypt_cpa(expected_ciphertext, &priv->pub, decrypted,
                key_and_randomness + 32, mlkem_ctx);
    kdf(failure_key, priv->fo_failure_secret, ciphertext, ciphertext_len, mlkem_ctx);
    mask = constant_time_eq_int_8(CRYPTO_memcmp(ciphertext,
                                                expected_ciphertext, ciphertext_len), 0);
    for (i = 0; i < OSSL_MLKEM768_SHARED_SECRET_BYTES; i++)
        out_shared_secret[i] = constant_time_select_8(mask,
                                                      key_and_randomness[i],
                                                      failure_key[i]);
    print_hex(out_shared_secret, OSSL_MLKEM768_SHARED_SECRET_BYTES, "SS");
    return 1;
}

int ossl_mlkem768_decap(uint8_t *out_shared_secret,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        const ossl_mlkem768_private_key *private_key,
                        ossl_mlkem_ctx *mlkem_ctx)
{
    const struct private_key_RANK768 *priv;

    if (mlkem_ctx == NULL)
        return 0;

    if (ciphertext_len != OSSL_MLKEM768_CIPHERTEXT_BYTES) {
        /* TODO(ML-KEM): Review requested randomness strength */
        RAND_bytes_ex(mlkem_ctx->libctx, out_shared_secret,
                      OSSL_MLKEM768_SHARED_SECRET_BYTES, 256);
        return 0;
    }
    priv = private_key_768_from_external(private_key);
    return mlkem_decap(out_shared_secret, ciphertext, priv, mlkem_ctx);
}

int ossl_mlkem768_marshal_public_key(uint8_t *out,
                                     const struct ossl_mlkem768_public_key *public_key)
{
    struct public_key_RANK768 *pub = public_key_768_from_external(public_key);

    return mlkem_marshal_public_key(out, pub);
}

/*
 * mlkem_parse_public_key_no_hash parses |in| into |pub| but doesn't calculate
 * the value of |pub->public_key_hash|.
 */
static int mlkem_parse_public_key_no_hash(public_key_RANK768 *pub, uint8_t *in,
                                          ossl_mlkem_ctx *mlkem_ctx)
{
    if (vector_decode(&pub->t, in, kLog2Prime) != 1)
        return 0;
    memcpy(pub->rho, in + encoded_vector_size(RANK768), sizeof(pub->rho));
    matrix_expand(&pub->m, pub->rho, mlkem_ctx);
    return 1;
}

static int mlkem_parse_public_key(public_key_RANK768 *pub, uint8_t *in,
                                  ossl_mlkem_ctx *mlkem_ctx)
{
    if (!mlkem_parse_public_key_no_hash(pub, in, mlkem_ctx)
        || !hash_h(pub->public_key_hash, in, OSSL_MLKEM768_PUBLIC_KEY_BYTES,
                   mlkem_ctx))
        return 0;
    return 1;
}

int ossl_mlkem768_parse_public_key(struct ossl_mlkem768_public_key *public_key,
                                   uint8_t *in, ossl_mlkem_ctx *mlkem_ctx)
{
    struct public_key_RANK768 *pub = public_key_768_from_external(public_key);

    return mlkem_parse_public_key(pub, in, mlkem_ctx);
}

static int mlkem_marshal_private_key(uint8_t *out,
                                     const struct private_key_RANK768 *priv)
{
    uint8_t *out_curr = out;

    vector_encode(out_curr, &priv->s, kLog2Prime);
    out_curr += encoded_vector_size(RANK768);

    if (mlkem_marshal_public_key(out_curr, &priv->pub) != 1)
        return 0;
    out_curr += OSSL_MLKEM768_PUBLIC_KEY_BYTES;

    memcpy(out_curr, priv->pub.public_key_hash,
           sizeof(priv->pub.public_key_hash));
    out_curr += sizeof(priv->pub.public_key_hash);

    memcpy(out_curr, priv->fo_failure_secret, sizeof(priv->fo_failure_secret));
    return 1;
}

int ossl_mlkem768_marshal_private_key(uint8_t *out,
                                      struct ossl_mlkem768_private_key *private_key)
{
    struct private_key_RANK768 *priv = private_key_768_from_external(private_key);

    return mlkem_marshal_private_key(out, priv);
}

static int mlkem_parse_private_key(private_key_RANK768 *priv, uint8_t *in,
                                   ossl_mlkem_ctx *mlkem_ctx)
{
    uint8_t *in_curr = in;

    if (!vector_decode(&priv->s, in_curr, kLog2Prime))
        return 0;
    in_curr += encoded_vector_size(RANK768);

    if (!mlkem_parse_public_key_no_hash(&priv->pub, in_curr, mlkem_ctx))
        return 0;
    in_curr += OSSL_MLKEM768_PUBLIC_KEY_BYTES;

    memcpy(priv->pub.public_key_hash, in_curr,
           sizeof(priv->pub.public_key_hash));
    in_curr += sizeof(priv->pub.public_key_hash);

    memcpy(priv->fo_failure_secret, in_curr, sizeof(priv->fo_failure_secret));
    return 1;
}

int ossl_mlkem768_parse_private_key(ossl_mlkem768_private_key *out_private_key,
                                    uint8_t *in, ossl_mlkem_ctx *mlkem_ctx)
{
    struct private_key_RANK768 *priv =
        private_key_768_from_external(out_private_key);

    return mlkem_parse_private_key(priv, in, mlkem_ctx);
}

#endif /* OPENSSL_NO_MLKEM */
