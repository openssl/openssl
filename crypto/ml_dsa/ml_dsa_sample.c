/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/byteorder.h>
#include <openssl/crypto.h>
#include "ml_dsa_local.h"
#include "ml_dsa_vector.h"
#include "ml_dsa_matrix.h"
#include "ml_dsa_hash.h"
#include "internal/sha3.h"
#include "internal/packet.h"

#define SHAKE128_BLOCKSIZE SHA3_BLOCKSIZE(128)
#define SHAKE256_BLOCKSIZE SHA3_BLOCKSIZE(256)

#if defined(KECCAK1600_ASM) && defined(__x86_64__) && !defined(OPENSSL_NO_ASM)
#define ML_DSA_MB_CAPABLE_BUILD 1
#define ML_DSA_SHAKE_X4_BATCH_SIZE 4
#define ML_DSA_SHAKE_X4_DONE_MASK ((1 << ML_DSA_SHAKE_X4_BATCH_SIZE) - 1)
#define ML_DSA_EXPAND_MASK_BYTES_PER_COEFF 32
#define ML_DSA_EXPAND_MASK_COEFFS_GAMMA1_19 20
#define ML_DSA_EXPAND_MASK_COEFFS_GAMMA1_17 18
#define ML_DSA_EXPAND_MASK_BUF_SIZE_GAMMA1_19 \
    (ML_DSA_EXPAND_MASK_BYTES_PER_COEFF * ML_DSA_EXPAND_MASK_COEFFS_GAMMA1_19)
#define ML_DSA_EXPAND_MASK_BUF_SIZE_GAMMA1_17 \
    (ML_DSA_EXPAND_MASK_BYTES_PER_COEFF * ML_DSA_EXPAND_MASK_COEFFS_GAMMA1_17)
#define ML_DSA_EXPAND_MASK_BUF_SIZE(gamma1)         \
    ((gamma1) == ML_DSA_GAMMA1_TWO_POWER_19         \
            ? ML_DSA_EXPAND_MASK_BUF_SIZE_GAMMA1_19 \
            : ML_DSA_EXPAND_MASK_BUF_SIZE_GAMMA1_17)
#else
#define ML_DSA_MB_CAPABLE_BUILD 0
#endif

/*
 * This is a constant time version of n % 5
 * Note that 0xFFFF / 5 = 0x3333, 2 is added to make an over-estimate of 1/5
 * and then we divide by (0xFFFF + 1)
 */
#define MOD5(n) ((n) - 5 * (0x3335 * (n) >> 16))

#if SHAKE128_BLOCKSIZE % 3 != 0
#error "rej_ntt_poly() requires SHAKE128_BLOCKSIZE to be a multiple of 3"
#endif

typedef int(COEFF_FROM_NIBBLE_FUNC)(uint32_t nibble, uint32_t *out);
typedef int(MATRIX_EXPAND_A_FUNC)(EVP_MD_CTX *g_ctx, const EVP_MD *md,
    const uint8_t *rho, MATRIX *out);
typedef int(VECTOR_EXPAND_S_FUNC)(EVP_MD_CTX *h_ctx, const EVP_MD *md, int eta,
    const uint8_t *seed, VECTOR *s1, VECTOR *s2);
typedef void(VECTOR_EXPAND_MASK_FUNC)(VECTOR *out, const uint8_t *rho_prime,
    size_t rho_prime_len, uint32_t kappa, uint32_t gamma1,
    EVP_MD_CTX *h_ctx, const EVP_MD *md);

static COEFF_FROM_NIBBLE_FUNC coeff_from_nibble_4;
static COEFF_FROM_NIBBLE_FUNC coeff_from_nibble_2;

static MATRIX_EXPAND_A_FUNC matrix_expand_A_scalar;
static VECTOR_EXPAND_S_FUNC vector_expand_S_scalar;
static VECTOR_EXPAND_MASK_FUNC vector_expand_mask_scalar;

static CRYPTO_ONCE ml_dsa_sample_once = CRYPTO_ONCE_STATIC_INIT;
static MATRIX_EXPAND_A_FUNC *matrix_expand_A_impl = matrix_expand_A_scalar;
static VECTOR_EXPAND_S_FUNC *vector_expand_S_impl = vector_expand_S_scalar;
static VECTOR_EXPAND_MASK_FUNC *vector_expand_mask_impl = vector_expand_mask_scalar;

#if ML_DSA_MB_CAPABLE_BUILD
static MATRIX_EXPAND_A_FUNC matrix_expand_A_mb;
static VECTOR_EXPAND_S_FUNC vector_expand_S_mb;
static VECTOR_EXPAND_MASK_FUNC vector_expand_mask_mb;
#endif

static void ml_dsa_sample_init(void)
{
#if ML_DSA_MB_CAPABLE_BUILD
    if (SHA3_avx512vl_capable()) {
        matrix_expand_A_impl = matrix_expand_A_mb;
        vector_expand_S_impl = vector_expand_S_mb;
        vector_expand_mask_impl = vector_expand_mask_mb;
    }
#endif
    return;
}

static ossl_inline void ml_dsa_sample_dispatch_init(void)
{
    (void)CRYPTO_THREAD_run_once(&ml_dsa_sample_once, ml_dsa_sample_init);
}

/**
 * @brief Combine 3 bytes to form an coefficient.
 * See FIPS 204, Algorithm 14, CoeffFromThreeBytes()
 *
 * This is not constant time as it is used to generate the matrix A which is public.
 *
 * @param s A byte array of 3 uniformly distributed bytes.
 * @param out The returned coefficient in the range 0..q-1.
 * @returns 1 if the value is less than q or 0 otherwise.
 *          This is used for rejection sampling.
 */
static ossl_inline int coeff_from_three_bytes(const uint8_t *s, uint32_t *out)
{
    /* Zero out the top bit of the 3rd byte to get a value in the range 0..2^23-1) */
    *out = (uint32_t)s[0] | ((uint32_t)s[1] << 8) | (((uint32_t)s[2] & 0x7f) << 16);
    return *out < ML_DSA_Q;
}

/**
 * @brief Generate a value in the range (q-4..0..4)
 * See FIPS 204, Algorithm 15, CoeffFromHalfByte() where eta = 4
 * Note the FIPS 204 code uses the range -4..4 (whereas this code adds q to the
 * negative numbers).
 *
 * @param nibble A value in the range 0..15
 * @param out The returned value if the range (q-4)..0..4 if nibble is < 9
 * @returns 1 nibble was in range, or 0 if the nibble was rejected.
 */
static ossl_inline int coeff_from_nibble_4(uint32_t nibble, uint32_t *out)
{
    /*
     * This is not constant time but will not leak any important info since
     * the value is either chosen or thrown away.
     */
    if (value_barrier_32(nibble < 9)) {
        *out = mod_sub(4, nibble);
        return 1;
    }
    return 0;
}

/**
 * @brief Generate a value in the range (q-2..0..2)
 * See FIPS 204, Algorithm 15, CoeffFromHalfByte() where eta = 2
 * Note the FIPS 204 code uses the range -2..2 (whereas this code adds q to the
 * negative numbers).
 *
 * @param nibble A value in the range 0..15
 * @param out The returned value if the range (q-2)..0..2 if nibble is < 15
 * @returns 1 nibble was in range, or 0 if the nibble was rejected.
 */
static ossl_inline int coeff_from_nibble_2(uint32_t nibble, uint32_t *out)
{
    if (value_barrier_32(nibble < 15)) {
        *out = mod_sub(2, MOD5(nibble));
        return 1;
    }
    return 0;
}

/**
 * @brief Use a seed value to generate a polynomial with coefficients in the
 * range of 0..q-1 using rejection sampling.
 * SHAKE128 is used to absorb the seed, and then sequences of 3 sample bytes are
 * squeezed to try to produce coefficients.
 * The SHAKE128 stream is used to get uniformly distributed elements.
 * This algorithm is used for matrix expansion and only operates on public inputs.
 *
 * See FIPS 204, Algorithm 30, RejNTTPoly()
 *
 * @param g_ctx A EVP_MD_CTX object used for sampling the seed.
 * @param md A pre-fetched SHAKE128 object.
 * @param seed The seed to use for sampling.
 * @param seed_len The size of |seed|
 * @param out The returned polynomial with coefficients in the range of
 *            0..q-1. This range is required for NTT.
 * @returns 1 if the polynomial was successfully generated, or 0 if any of the
 *            digest operations failed.
 */
static int rej_ntt_poly(EVP_MD_CTX *g_ctx, const EVP_MD *md,
    const uint8_t *seed, size_t seed_len, POLY *out)
{
    int j = 0;
    uint8_t blocks[SHAKE128_BLOCKSIZE], *b, *end = blocks + sizeof(blocks);

    /*
     * Instead of just squeezing 3 bytes at a time, we grab a whole block
     * Note that the shake128 blocksize of 168 is divisible by 3.
     */
    if (!shake_xof(g_ctx, md, seed, seed_len, blocks, sizeof(blocks)))
        return 0;

    while (1) {
        for (b = blocks; b < end; b += 3) {
            if (coeff_from_three_bytes(b, &(out->coeff[j]))) {
                if (++j >= ML_DSA_NUM_POLY_COEFFICIENTS)
                    return 1; /* finished */
            }
        }
        if (!EVP_DigestSqueeze(g_ctx, blocks, sizeof(blocks)))
            return 0;
    }
}

/**
 * @brief Use a seed value to generate a polynomial with coefficients in the
 * range of ((q-eta)..0..eta) using rejection sampling. eta is either 2 or 4.
 * SHAKE256 is used to absorb the seed, and then samples are squeezed.
 * See FIPS 204, Algorithm 31, RejBoundedPoly()
 *
 * @param h_ctx A EVP_MD_CTX object context used to sample the seed.
 * @param md A pre-fetched SHAKE256 object.
 * @param coef_from_nibble A function that is dependent on eta, which takes a
 *                         nibble and tries to see if it is in the correct range.
 * @param seed The seed to use for sampling.
 * @param seed_len The size of |seed|
 * @param out The returned polynomial with coefficients in the range of
 *            ((q-eta)..0..eta)
 * @returns 1 if the polynomial was successfully generated, or 0 if any of the
 *            digest operations failed.
 */
static int rej_bounded_poly(EVP_MD_CTX *h_ctx, const EVP_MD *md,
    COEFF_FROM_NIBBLE_FUNC *coef_from_nibble,
    const uint8_t *seed, size_t seed_len, POLY *out)
{
    int j = 0;
    uint32_t z0, z1;
    uint8_t blocks[SHAKE256_BLOCKSIZE], *b, *end = blocks + sizeof(blocks);

    /* Instead of just squeezing 1 byte at a time, we grab a whole block */
    if (!shake_xof(h_ctx, md, seed, seed_len, blocks, sizeof(blocks)))
        return 0;

    while (1) {
        for (b = blocks; b < end; b++) {
            z0 = *b & 0x0F; /* lower nibble of byte */
            z1 = *b >> 4; /* high nibble of byte */

            if (coef_from_nibble(z0, &out->coeff[j])
                && ++j >= ML_DSA_NUM_POLY_COEFFICIENTS)
                return 1;
            if (coef_from_nibble(z1, &out->coeff[j])
                && ++j >= ML_DSA_NUM_POLY_COEFFICIENTS)
                return 1;
        }
        if (!EVP_DigestSqueeze(h_ctx, blocks, sizeof(blocks)))
            return 0;
    }
}

/**
 * @brief Generate a k * l matrix that has uniformly distributed polynomial
 *        elements using rejection sampling.
 * See FIPS 204, Algorithm 32, ExpandA()
 *
 * @param g_ctx A EVP_MD_CTX context used for rejection sampling
 *              seed values generated from the seed rho.
 * @param md A pre-fetched SHAKE128 object
 * @param rho A 32 byte seed to generated the matrix from.
 * @param out The generated k * l matrix of polynomials with coefficients
 *            in the range of 0..q-1.
 * @returns 1 if the matrix was generated, or 0 on error.
 */
static int matrix_expand_A_scalar(EVP_MD_CTX *g_ctx, const EVP_MD *md,
    const uint8_t *rho, MATRIX *out)
{
    int ret = 0;
    size_t i, j;
    uint8_t derived_seed[ML_DSA_RHO_BYTES + 2];
    POLY *poly = out->m_poly;

    /* The seed used for each matrix element is rho + column_index + row_index */
    memcpy(derived_seed, rho, ML_DSA_RHO_BYTES);
    for (i = 0; i < out->k; i++) {
        for (j = 0; j < out->l; j++) {
            derived_seed[ML_DSA_RHO_BYTES + 1] = (uint8_t)i;
            derived_seed[ML_DSA_RHO_BYTES] = (uint8_t)j;
            /* Generate the polynomial for each matrix element using a unique seed */
            if (!rej_ntt_poly(g_ctx, md, derived_seed, sizeof(derived_seed), poly++))
                goto err;
        }
    }
    ret = 1;
err:
    return ret;
}

/**
 * @brief Generates 2 vectors using rejection sampling whose polynomial
 * coefficients are in the interval [q-eta..0..eta]
 *
 * See FIPS 204, Algorithm 33, ExpandS().
 * Note that in FIPS 204 the range -eta..eta is used.
 *
 * @param h_ctx A EVP_MD_CTX context to use to sample the seed.
 * @param md A pre-fetched SHAKE256 object.
 * @param eta Is either 2 or 4, and determines the range of the coefficients for
 *            s1 and s2.
 * @param seed A 64 byte seed to use for sampling.
 * @param s1 A 1 * l column vector containing polynomials with coefficients in
 *           the range (q-eta)..0..eta
 * @param s2 A 1 * k column vector containing polynomials with coefficients in
 *           the range (q-eta)..0..eta
 * @returns 1 if s1 and s2 were successfully generated, or 0 otherwise.
 */
static int vector_expand_S_scalar(EVP_MD_CTX *h_ctx, const EVP_MD *md, int eta,
    const uint8_t *seed, VECTOR *s1, VECTOR *s2)
{
    int ret = 0;
    size_t i;
    size_t l = s1->num_poly;
    size_t k = s2->num_poly;
    uint8_t derived_seed[ML_DSA_PRIV_SEED_BYTES + 2];
    COEFF_FROM_NIBBLE_FUNC *coef_from_nibble_fn;

    coef_from_nibble_fn = (eta == ML_DSA_ETA_4) ? coeff_from_nibble_4 : coeff_from_nibble_2;

    /*
     * Each polynomial generated uses a unique seed that consists of
     * seed + counter (where the counter is 2 bytes starting at 0)
     */
    memcpy(derived_seed, seed, ML_DSA_PRIV_SEED_BYTES);
    derived_seed[ML_DSA_PRIV_SEED_BYTES] = 0;
    derived_seed[ML_DSA_PRIV_SEED_BYTES + 1] = 0;

    for (i = 0; i < l; i++) {
        if (!rej_bounded_poly(h_ctx, md, coef_from_nibble_fn,
                derived_seed, sizeof(derived_seed), &s1->poly[i]))
            goto err;
        ++derived_seed[ML_DSA_PRIV_SEED_BYTES];
    }
    for (i = 0; i < k; i++) {
        if (!rej_bounded_poly(h_ctx, md, coef_from_nibble_fn,
                derived_seed, sizeof(derived_seed), &s2->poly[i]))
            goto err;
        ++derived_seed[ML_DSA_PRIV_SEED_BYTES];
    }
    ret = 1;
err:
    return ret;
}

/* See FIPS 204, Algorithm 34, ExpandMask(), Step 4 & 5 */
int ossl_ml_dsa_poly_expand_mask(POLY *out, const uint8_t *seed, size_t seed_len,
    uint32_t gamma1,
    EVP_MD_CTX *h_ctx, const EVP_MD *md)
{
    uint8_t buf[32 * 20];
    size_t buf_len = 32 * (gamma1 == ML_DSA_GAMMA1_TWO_POWER_19 ? 20 : 18);

    return shake_xof(h_ctx, md, seed, seed_len, buf, buf_len)
        && ossl_ml_dsa_poly_decode_expand_mask(out, buf, buf_len, gamma1);
}

/*
 * @brief Sample a polynomial with coefficients in the range {-1..1}.
 * The number of non zero values (hamming weight) is given by tau
 *
 * See FIPS 204, Algorithm 29, SampleInBall()
 * This function is assumed to not be constant time.
 * The algorithm is based on Durstenfeld's version of the Fisher-Yates shuffle.
 *
 * Note that the coefficients returned by this implementation are positive
 * i.e one of q-1, 0, or 1.
 *
 * @param tau is the number of +1 or -1's in the polynomial 'out_c' (39, 49 or 60)
 *            that is less than or equal to 64
 */
int ossl_ml_dsa_poly_sample_in_ball(POLY *out_c, const uint8_t *seed, int seed_len,
    EVP_MD_CTX *h_ctx, const EVP_MD *md,
    uint32_t tau)
{
    uint8_t block[SHAKE256_BLOCKSIZE];
    uint64_t signs;
    int offset = 8;
    size_t end;

    /*
     * Rather than squeeze 8 bytes followed by lots of 1 byte squeezes
     * the SHAKE blocksize is squeezed each time and buffered into 'block'.
     */
    if (!shake_xof(h_ctx, md, seed, seed_len, block, sizeof(block)))
        return 0;

    /*
     * grab the first 64 bits - since tau < 64
     * Each bit gives a +1 or -1 value.
     */
    OPENSSL_load_u64_le(&signs, block);

    poly_zero(out_c);

    /* Loop tau times */
    for (end = 256 - tau; end < 256; end++) {
        size_t index; /* index is a random offset to write +1 or -1 */

        /* rejection sample in {0..end} to choose an index to place -1 or 1 into */
        for (;;) {
            if (offset == sizeof(block)) {
                /* squeeze another block if the bytes from block have been used */
                if (!EVP_DigestSqueeze(h_ctx, block, sizeof(block)))
                    return 0;
                offset = 0;
            }

            index = block[offset++];
            if (index <= end)
                break;
        }

        /*
         * In-place swap the coefficient we are about to replace to the end so
         * we don't lose any values that have been already written.
         */
        out_c->coeff[end] = out_c->coeff[index];
        /* set the random coefficient value to either 1 or q-1 */
        out_c->coeff[index] = mod_sub(1, 2 * (signs & 1));
        signs >>= 1; /* grab the next random bit */
    }
    return 1;
}

static void vector_expand_mask_scalar(VECTOR *out, const uint8_t *rho_prime,
    size_t rho_prime_len, uint32_t kappa, uint32_t gamma1,
    EVP_MD_CTX *h_ctx, const EVP_MD *md)
{
    size_t i;
    uint8_t derived_seed[ML_DSA_RHO_PRIME_BYTES + 2];

    (void)rho_prime_len;

    memcpy(derived_seed, rho_prime, ML_DSA_RHO_PRIME_BYTES);

    for (i = 0; i < out->num_poly; i++) {
        size_t index = kappa + i;

        derived_seed[ML_DSA_RHO_PRIME_BYTES] = index & 0xFF;
        derived_seed[ML_DSA_RHO_PRIME_BYTES + 1] = (index >> 8) & 0xFF;
        poly_expand_mask(out->poly + i, derived_seed, sizeof(derived_seed),
            gamma1, h_ctx, md);
    }
}

int ossl_ml_dsa_matrix_expand_A(EVP_MD_CTX *g_ctx, const EVP_MD *md,
    const uint8_t *rho, MATRIX *out)
{
    ml_dsa_sample_dispatch_init();
    return matrix_expand_A_impl(g_ctx, md, rho, out);
}

int ossl_ml_dsa_vector_expand_S(EVP_MD_CTX *h_ctx, const EVP_MD *md, int eta,
    const uint8_t *seed, VECTOR *s1, VECTOR *s2)
{
    ml_dsa_sample_dispatch_init();
    return vector_expand_S_impl(h_ctx, md, eta, seed, s1, s2);
}

/* See FIPS 204, Algorithm 34, ExpandMask(), Step 4 & 5 */
void ossl_ml_dsa_vector_expand_mask(VECTOR *out, const uint8_t *rho_prime,
    size_t rho_prime_len, uint32_t kappa, uint32_t gamma1,
    EVP_MD_CTX *h_ctx, const EVP_MD *md)
{
    ml_dsa_sample_dispatch_init();
    vector_expand_mask_impl(out, rho_prime, rho_prime_len, kappa, gamma1, h_ctx, md);
}

#if ML_DSA_MB_CAPABLE_BUILD
/**
 * @brief Multi-buffer version of rej_ntt_poly for processing 4 polynomials
 *
 * Processes up to 4 independent rejection sampling operations in parallel.
 *
 * @param g_ctx A EVP_MD_CTX object used for sampling (scratch context)
 * @param md A pre-fetched SHAKE128 object
 * @param seeds Array of 4 seed pointers (NULL entries are skipped)
 * @param seed_len Seed length (all seeds must have the same length)
 * @param outs Array of 4 output polynomial pointers (NULL entries are skipped)
 * @param count Number of valid operations (1-4)
 * @returns 1 if all polynomials were successfully generated, 0 otherwise
 */
static ossl_unused int rej_ntt_poly_mb(EVP_MD_CTX *g_ctx, const EVP_MD *md,
    const uint8_t *seeds[ML_DSA_SHAKE_X4_BATCH_SIZE], const size_t seed_len,
    POLY *outs[ML_DSA_SHAKE_X4_BATCH_SIZE], const size_t count)
{
    KECCAK1600_X4_CTX ctx;
    uint8_t blocks[ML_DSA_SHAKE_X4_BATCH_SIZE][SHAKE128_BLOCKSIZE];
    int coeff_idx[ML_DSA_SHAKE_X4_BATCH_SIZE] = { 0, 0, 0, 0 };
    int done_mask = 0;
    int lane;

    /* process 4 lanes in parallel if possible */
    for (lane = count; lane < ML_DSA_SHAKE_X4_BATCH_SIZE; lane++)
        done_mask |= (1 << lane); /* mark NULL lanes as done */

    /* Initialize and absorb for all 4 lanes */
    ossl_sha3_shake128_x4_inc_init(&ctx);
    ossl_sha3_shake128_x4_inc_absorb(&ctx, seeds[0], seeds[1],
        seeds[2], seeds[3], seed_len);
    ossl_sha3_shake128_x4_inc_finalize(&ctx);

    /* Squeeze 1 block at a time until all lanes complete */
    while (done_mask != ML_DSA_SHAKE_X4_DONE_MASK) {
        ossl_sha3_shake128_x4_inc_squeeze(blocks[0], blocks[1],
            blocks[2], blocks[3],
            SHAKE128_BLOCKSIZE, &ctx);

        for (lane = 0; lane < ML_DSA_SHAKE_X4_BATCH_SIZE; lane++) {
            if (done_mask & (1 << lane))
                continue; /* Lane already done */

            const uint8_t *b = blocks[lane];
            const uint8_t *end = b + SHAKE128_BLOCKSIZE;

            for (; b < end && coeff_idx[lane] < ML_DSA_NUM_POLY_COEFFICIENTS; b += 3) {
                uint32_t *coeff_ptr = &(outs[lane]->coeff[coeff_idx[lane]]);

                if (coeff_from_three_bytes(b, coeff_ptr))
                    coeff_idx[lane]++;
            }

            if (coeff_idx[lane] >= ML_DSA_NUM_POLY_COEFFICIENTS)
                done_mask |= (1 << lane);
        }
    }

    return 1;
}

static void vector_expand_mask_mb(VECTOR *out, const uint8_t *rho_prime,
    const size_t rho_prime_len, const uint32_t kappa, const uint32_t gamma1,
    EVP_MD_CTX *h_ctx, const EVP_MD *md)
{
    size_t i;
    const size_t num_polys = out->num_poly;
    uint8_t derived_seeds[ML_DSA_SHAKE_X4_BATCH_SIZE][ML_DSA_RHO_PRIME_BYTES + 2];
    const size_t seed_len = sizeof(derived_seeds[0]);
    const size_t buf_size = ML_DSA_EXPAND_MASK_BUF_SIZE(gamma1);
    uint8_t buffers[ML_DSA_SHAKE_X4_BATCH_SIZE][ML_DSA_EXPAND_MASK_BUF_SIZE_GAMMA1_19];

    (void)rho_prime_len;

    for (i = 0; i < ML_DSA_SHAKE_X4_BATCH_SIZE; i++)
        memcpy(derived_seeds[i], rho_prime, ML_DSA_RHO_PRIME_BYTES);

    for (i = 0; i + (ML_DSA_SHAKE_X4_BATCH_SIZE - 1) < num_polys; i += ML_DSA_SHAKE_X4_BATCH_SIZE) {
        size_t b;

        for (b = 0; b < ML_DSA_SHAKE_X4_BATCH_SIZE; b++) {
            const size_t index = kappa + i + b;

            derived_seeds[b][ML_DSA_RHO_PRIME_BYTES] = index & 0xFF;
            derived_seeds[b][ML_DSA_RHO_PRIME_BYTES + 1] = (index >> 8) & 0xFF;
        }

        ossl_sha3_shake256_x4(buffers[0], buffers[1], buffers[2], buffers[3], buf_size,
            derived_seeds[0], derived_seeds[1], derived_seeds[2], derived_seeds[3], seed_len);

        ossl_ml_dsa_poly_decode_expand_mask(&out->poly[i + 0], buffers[0], buf_size, gamma1);
        ossl_ml_dsa_poly_decode_expand_mask(&out->poly[i + 1], buffers[1], buf_size, gamma1);
        ossl_ml_dsa_poly_decode_expand_mask(&out->poly[i + 2], buffers[2], buf_size, gamma1);
        ossl_ml_dsa_poly_decode_expand_mask(&out->poly[i + 3], buffers[3], buf_size, gamma1);
    }

    if (i < num_polys) {
        const size_t left = num_polys - i;
        size_t b;

        for (b = 0; b < left; b++) {
            const size_t index = kappa + i + b;

            derived_seeds[b][ML_DSA_RHO_PRIME_BYTES] = (uint8_t)index;
            derived_seeds[b][ML_DSA_RHO_PRIME_BYTES + 1] = (uint8_t)(index >> 8);
        }

        ossl_sha3_shake256_x4(buffers[0], buffers[1], buffers[2], buffers[3], buf_size,
            derived_seeds[0], derived_seeds[1], derived_seeds[2], derived_seeds[3], seed_len);

        /* there has to be at least one lane to process */
        ossl_ml_dsa_poly_decode_expand_mask(&out->poly[i + 0], buffers[0], buf_size, gamma1);

        if ((i + 1) < num_polys)
            ossl_ml_dsa_poly_decode_expand_mask(&out->poly[i + 1], buffers[1], buf_size, gamma1);

        if ((i + 2) < num_polys)
            ossl_ml_dsa_poly_decode_expand_mask(&out->poly[i + 2], buffers[2], buf_size, gamma1);

        /* there can be no more than 3 lanes to process */
    }
}

/**
 * @brief Multi-buffer version of rej_bounded_poly for processing 4 polynomials
 *
 * Processes up to 4 independent rejection sampling operations in parallel when
 * |count| is 4, using the SHAKE x4 API. That API will select an AVX-512VL
 * implementation when available at runtime, or fall back to a scalar
 * implementation otherwise. For other values of |count|, this function falls
 * back to the sequential implementation.
 *
 * @param h_ctx A EVP_MD_CTX object used for sampling (scratch context)
 * @param md A pre-fetched SHAKE256 object
 * @param coef_from_nibble Function to convert nibble to coefficient
 * @param seeds Array of 4 seed pointers (NULL entries are skipped)
 * @param seed_len Seed length (all seeds must have the same length)
 * @param outs Array of 4 output polynomial pointers (NULL entries are skipped)
 * @param count Number of valid operations (1-4)
 * @returns 1 if all polynomials were successfully generated, 0 otherwise
 */
static ossl_unused int rej_bounded_poly_mb(EVP_MD_CTX *h_ctx, const EVP_MD *md,
    COEFF_FROM_NIBBLE_FUNC *coef_from_nibble,
    const uint8_t *seeds[ML_DSA_SHAKE_X4_BATCH_SIZE], const size_t seed_len,
    POLY *outs[ML_DSA_SHAKE_X4_BATCH_SIZE], const size_t count)
{
    KECCAK1600_X4_CTX ctx;
    uint8_t blocks[ML_DSA_SHAKE_X4_BATCH_SIZE][SHAKE256_BLOCKSIZE];
    int coeff_idx[ML_DSA_SHAKE_X4_BATCH_SIZE] = { 0, 0, 0, 0 };
    int done_mask = 0;
    size_t lane;

    for (lane = count; lane < ML_DSA_SHAKE_X4_BATCH_SIZE; lane++)
        done_mask |= (1 << lane); /* mark NULL lanes as done */

    /* Initialize context once and keep it alive */
    ossl_sha3_shake256_x4_inc_init(&ctx);
    ossl_sha3_shake256_x4_inc_absorb(&ctx, seeds[0], seeds[1],
        seeds[2], seeds[3], seed_len);
    ossl_sha3_shake256_x4_inc_finalize(&ctx);

    /* Squeeze 1 block at a time until all lanes complete */
    while (done_mask != ML_DSA_SHAKE_X4_DONE_MASK) {
        ossl_sha3_shake256_x4_inc_squeeze(blocks[0], blocks[1],
            blocks[2], blocks[3],
            SHAKE256_BLOCKSIZE, &ctx);

        for (lane = 0; lane < ML_DSA_SHAKE_X4_BATCH_SIZE; lane++) {
            if (done_mask & (1 << lane))
                continue;

            const uint8_t *b = blocks[lane];
            const uint8_t *end = b + SHAKE256_BLOCKSIZE;

            for (; b < end && coeff_idx[lane] < ML_DSA_NUM_POLY_COEFFICIENTS; b++) {
                uint32_t z0 = *b & 0x0F;
                uint32_t z1 = *b >> 4;

                if (coef_from_nibble(z0, &outs[lane]->coeff[coeff_idx[lane]]))
                    coeff_idx[lane]++;

                if (coeff_idx[lane] >= ML_DSA_NUM_POLY_COEFFICIENTS) {
                    done_mask |= (1 << lane);
                    break;
                }

                if (coef_from_nibble(z1, &outs[lane]->coeff[coeff_idx[lane]]))
                    coeff_idx[lane]++;

                if (coeff_idx[lane] >= ML_DSA_NUM_POLY_COEFFICIENTS) {
                    done_mask |= (1 << lane);
                    break;
                }
            }
        }
    }

    return 1;
}

/**
 * @brief Generate a k * l matrix that has uniformly distributed polynomial
 *        elements using rejection sampling.
 * See FIPS 204, Algorithm 32, ExpandA()
 *
 * @param g_ctx A EVP_MD_CTX context used for rejection sampling
 *              seed values generated from the seed rho.
 * @param md A pre-fetched SHAKE128 object
 * @param rho A 32 byte seed to generated the matrix from.
 * @param out The generated k * l matrix of polynomials with coefficients
 *            in the range of 0..q-1.
 * @returns 1 if the matrix was generated, or 0 on error.
 */
static int matrix_expand_A_mb(EVP_MD_CTX *g_ctx, const EVP_MD *md,
    const uint8_t *rho, MATRIX *out)
{
    size_t b, idx;
    uint8_t derived_seeds[ML_DSA_SHAKE_X4_BATCH_SIZE][ML_DSA_RHO_BYTES + 2];
    const size_t seed_len = sizeof(derived_seeds[0]);
    const uint8_t *seeds[ML_DSA_SHAKE_X4_BATCH_SIZE];
    POLY *polys[ML_DSA_SHAKE_X4_BATCH_SIZE];
    POLY *poly = out->m_poly;

    for (b = 0; b < ML_DSA_SHAKE_X4_BATCH_SIZE; b++) {
        memcpy(derived_seeds[b], rho, ML_DSA_RHO_BYTES);
        seeds[b] = derived_seeds[b];
    }

    const size_t total = (out->k * out->l);

    for (idx = 0; (idx + ML_DSA_SHAKE_X4_BATCH_SIZE - 1) < total; idx += ML_DSA_SHAKE_X4_BATCH_SIZE) {
        for (b = 0; b < ML_DSA_SHAKE_X4_BATCH_SIZE; b++) {
            const size_t row = (idx + b) / out->l;
            const size_t col = (idx + b) % out->l;

            derived_seeds[b][ML_DSA_RHO_BYTES] = (uint8_t)col;
            derived_seeds[b][ML_DSA_RHO_BYTES + 1] = (uint8_t)row;
            polys[b] = &poly[idx + b];
        }

        if (!rej_ntt_poly_mb(g_ctx, md, seeds, seed_len, polys, 4))
            return 0;
    }

    if (idx < total) {
        const size_t left = total - idx;

        for (b = 0; b < left; b++) {
            const size_t row = (idx + b) / out->l;
            const size_t col = (idx + b) % out->l;

            derived_seeds[b][ML_DSA_RHO_BYTES] = (uint8_t)col;
            derived_seeds[b][ML_DSA_RHO_BYTES + 1] = (uint8_t)row;
            polys[b] = &poly[idx + b];
        }

        if (!rej_ntt_poly_mb(g_ctx, md, seeds, seed_len, polys, left))
            return 0;
    }

    return 1;
}

/**
 * @brief Generates 2 vectors using rejection sampling whose polynomial
 * coefficients are in the interval [q-eta..0..eta]
 *
 * See FIPS 204, Algorithm 33, ExpandS().
 * Note that in FIPS 204 the range -eta..eta is used.
 *
 * @param h_ctx A EVP_MD_CTX context to use to sample the seed.
 * @param md A pre-fetched SHAKE256 object.
 * @param eta Is either 2 or 4, and determines the range of the coefficients for
 *            s1 and s2.
 * @param seed A 64 byte seed to use for sampling.
 * @param s1 A 1 * l column vector containing polynomials with coefficients in
 *           the range (q-eta)..0..eta
 * @param s2 A 1 * k column vector containing polynomials with coefficients in
 *           the range (q-eta)..0..eta
 * @returns 1 if s1 and s2 were successfully generated, or 0 otherwise.
 */
static int vector_expand_S_mb(EVP_MD_CTX *h_ctx, const EVP_MD *md, const int eta,
    const uint8_t *seed, VECTOR *s1, VECTOR *s2)
{
    size_t b, idx;
    const size_t l = s1->num_poly;
    const size_t k = s2->num_poly;
    const size_t total = l + k;
    uint8_t derived_seeds[ML_DSA_SHAKE_X4_BATCH_SIZE][ML_DSA_PRIV_SEED_BYTES + 2];
    const uint8_t *seeds[ML_DSA_SHAKE_X4_BATCH_SIZE];
    const size_t seed_len = sizeof(derived_seeds[0]);
    POLY *polys[ML_DSA_SHAKE_X4_BATCH_SIZE];
    COEFF_FROM_NIBBLE_FUNC *coef_from_nibble_fn = (eta == ML_DSA_ETA_4) ? coeff_from_nibble_4 : coeff_from_nibble_2;

    /* Initialize base seeds */
    for (b = 0; b < ML_DSA_SHAKE_X4_BATCH_SIZE; b++) {
        memcpy(derived_seeds[b], seed, ML_DSA_PRIV_SEED_BYTES);
        seeds[b] = derived_seeds[b];
    }

    /* Process all polynomials (s1 then s2) in batches of 4 */
    for (idx = 0; (idx + ML_DSA_SHAKE_X4_BATCH_SIZE - 1) < total; idx += ML_DSA_SHAKE_X4_BATCH_SIZE) {

        /* Prepare batch of up to 4 seeds and output pointers */
        for (b = 0; b < ML_DSA_SHAKE_X4_BATCH_SIZE; b++) {
            const size_t poly_idx = idx + b;

            /* Set counter in seed */
            derived_seeds[b][ML_DSA_PRIV_SEED_BYTES] = (uint8_t)(poly_idx);
            derived_seeds[b][ML_DSA_PRIV_SEED_BYTES + 1] = (uint8_t)(poly_idx >> 8);

            /* Point to correct output polynomial (s1 or s2) */
            if (poly_idx < l)
                polys[b] = &s1->poly[poly_idx];
            else
                polys[b] = &s2->poly[poly_idx - l];
        }

        /* Process batch using multi-buffer */
        if (!rej_bounded_poly_mb(h_ctx, md, coef_from_nibble_fn,
                seeds, seed_len, polys, ML_DSA_SHAKE_X4_BATCH_SIZE))
            return 0;
    }

    if (idx < total) {
        const size_t batch_count = total - idx;

        /* Prepare batch of up to 4 seeds and output pointers */
        for (b = 0; b < batch_count; b++) {
            const size_t poly_idx = idx + b;

            /* Set counter in seed */
            derived_seeds[b][ML_DSA_PRIV_SEED_BYTES] = (uint8_t)(poly_idx);
            derived_seeds[b][ML_DSA_PRIV_SEED_BYTES + 1] = (uint8_t)(poly_idx >> 8);

            /* Point to correct output polynomial (s1 or s2) */
            if (poly_idx < l)
                polys[b] = &s1->poly[poly_idx];
            else
                polys[b] = &s2->poly[poly_idx - l];
        }

        /* Process batch using multi-buffer */
        if (!rej_bounded_poly_mb(h_ctx, md, coef_from_nibble_fn,
                seeds, seed_len, polys, batch_count))
            return 0;
    }

    return 1;
}
#endif /* ML_DSA_MB_CAPABLE_BUILD */
