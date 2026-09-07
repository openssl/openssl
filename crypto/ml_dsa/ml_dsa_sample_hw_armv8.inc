/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/common.h"

#define BLOCK_ALIGNED(sz, algn) (algn) * (1 + (sz) / (algn))

#define SHAKE128_RATE SHA3_BLOCKSIZE(128)
#define SHAKE128_WORDS (SHAKE128_RATE * 8 / 64)
#define SHAKE256_RATE SHA3_BLOCKSIZE(256)
#define SHAKE256_WORDS (SHAKE256_RATE * 8 / 64)

#define ML_DSA_SHAKE_X2_BATCH_SIZE 2
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
#define ML_DSA_EXPAND_MASK_BUF_SIZE_BLOCKS(gamma1) \
    ((gamma1) == ML_DSA_GAMMA1_TWO_POWER_19         \
            ? BLOCK_ALIGNED(ML_DSA_EXPAND_MASK_BUF_SIZE_GAMMA1_19, SHAKE256_RATE) \
            : BLOCK_ALIGNED(ML_DSA_EXPAND_MASK_BUF_SIZE_GAMMA1_17, SHAKE256_RATE))
#define ML_DSA_EXPAND_MASK_BLOCKS_MAX ML_DSA_EXPAND_MASK_BUF_SIZE_BLOCKS(ML_DSA_GAMMA1_TWO_POWER_19)

/* Assembler API */
extern void ossl_shake128_2x_oneshot_singleblock_absorb_interleaved_squeeze(uint64_t *statex2_out, const uint64_t *in_interleaved, uint8_t *out1, uint8_t *out2);
extern void ossl_shake256_2x_oneshot_singleblock_absorb_interleaved_squeeze(uint64_t *statex2_out, const uint64_t *in_interleaved, uint8_t *out1, uint8_t *out2);
extern void ossl_shake128_2x_squeeze_singleblock(uint64_t *statex2, uint8_t *out1, uint8_t *out2);
extern void ossl_shake256_2x_squeeze_singleblock(uint64_t *statex2, uint8_t *out1, uint8_t *out2);
extern void ossl_shake256_2x_oneshot_singleblock_absorb_interleaved_multi_block_squeeze(const uint64_t *in_interleaved, uint8_t *out1, uint8_t *out2, size_t outlen);
extern void SHA3_secure_vector_clear_armv8(void);

/*
 * The data used for sampling are all of a known size, so we can store the 2
 * parallel inputs in interleaved form and simplify the assembler so that the
 * input is passed in the following form:
 *   words[0] = input1 first 8 bytes,  words[1] = input2 first 8 bytes
 *   words[2] = input1 next 8 bytes,   words[3] = input2 next 8 bytes
 * The rate for SHAKE128 is 168 which is 21 * uint64 values
 * The rate for SHAKE256 is 136 which is 17 * uint64 values
 * The end of the absorb does padding, so we can the ending 0x80 here.
 * The inputs used in ML-DSA for shake are all less than the capacity, and all
 * 3 variants input a small fixed seed of 32 or 64 bytes that is used multiple
 * times, so we just do this once. This is followed by a variable index that
 * can change. We return the index of this changing value which can then be passed
 * to set_index()
 */
static uint64_t *absorb_once_shake128(uint64_t *state, const uint8_t *in, size_t inlen)
{
    size_t i;

    memset((uint8_t *)state, 0, 168*2);
    /* write trailing interleaved bytes for SHAKE128 */
    state[40] = 0x8000000000000000; /* 20 * 2 */
    state[41] = 0x8000000000000000;

    /*
     * Assuming inlen is a multiple of 8 bytes
     * Store this value twice into uint64_t interleaved blocks
     * Which is the order required for 2 x parallel processing on armv8.
     */
    for (i = 0; i < inlen/4; i += 2) {
        uint64_t val;
        in = OPENSSL_load_u64_le(&val, in);
        state[i] = val;
        state[i+1] = val;
    }
    return state+i;
}

static uint64_t *absorb_once_shake256(uint64_t *state, const uint8_t *in, size_t inlen)
{
    size_t i;

    memset((uint8_t *)state, 0, 136*2);

    /*
     * Assuming inlen is a multiple of 8 bytes
     * Store this value twice into uint64_t interleaved blocks
     * Which is the order required for 2 x parallel processing on armv8.
     */
    for (i = 0; i < inlen/4; i+=2) {
        uint64_t val;
        in = OPENSSL_load_u64_le(&val, in);
        state[i] = val;
        state[i+1] = val;
    }
    /* write trailing 0x80 interleaved bytes for SHAKE256 */
    state[32] = 0x8000000000000000;
    state[33] = 0x8000000000000000;
    return state+i;
}

/*
 * After calling the absorb_once() to set the seed, the 3 variants all
 * Write a 2 byte index that changes.
 * As this is the  end of the input we set the SHAKE related 0x1F padding also.
 * As this is interleaved data it inputs 2 separate indexes.
 */
static void set_index(uint64_t *state, uint64_t index1, uint64_t index2)
{
    state[0] = index1 | ((uint64_t)0x1F0000);
    state[1] = index2 | ((uint64_t)0x1F0000);
}

static ossl_unused int rej_ntt_poly_mb(const uint64_t *words,
    POLY *outs[ML_DSA_SHAKE_X2_BATCH_SIZE])
{
    KECCAK1600_X2_ARMV8_CTX ctx;
    ALIGN16 uint8_t blocks[ML_DSA_SHAKE_X2_BATCH_SIZE][SHAKE128_BLOCKSIZE];
    int coeff_idx[ML_DSA_SHAKE_X2_BATCH_SIZE] = { 0, 0 };
    size_t lane;

    ossl_shake128_2x_oneshot_singleblock_absorb_interleaved_squeeze(ctx.A, words, blocks[0], blocks[1]);
    while(1) {
        int finished = 0;
        for (lane = 0; lane < ML_DSA_SHAKE_X2_BATCH_SIZE; ++lane) {
            const uint8_t *b = blocks[lane];
            const uint8_t *end = b + SHAKE128_BLOCKSIZE;
            uint32_t *coeff = outs[lane]->coeff;
            int j = coeff_idx[lane];

            if (j == ML_DSA_NUM_POLY_COEFFICIENTS) {
                finished++;
                continue;
            }
            for (; b < end; b += 3) {
                if (coeff_from_three_bytes(b, coeff+j)) {
                    if (++j == ML_DSA_NUM_POLY_COEFFICIENTS) {
                        finished++;
                        break;
                    }
                }
            }
            coeff_idx[lane] = j;
        }
        if (finished == 2)
            break;
        /*
         * This loop is likely to run 5 times which produces 5 * 168 bytes
         * (840 bytes) and with no failures 3 * 256 = 768 bytes are consumed,
         * so there is a very small chance that one lane will consume more
         * than this. In this rare case it will take the hit of consuming
         * another parallel block (even though it may only use one of them).
         */
        ossl_shake128_2x_squeeze_singleblock(ctx.A, blocks[0], blocks[1]);
    }
    ossl_shakex2_cleanup_armv8(&ctx);
    return 1;
}

static void vector_expand_mask_mb(VECTOR *out,
    const uint8_t rho_prime[ML_DSA_RHO_PRIME_BYTES], const uint32_t kappa, const uint32_t gamma1,
    EVP_MD_CTX *h_ctx, const EVP_MD *md)
{
    ALIGN16 uint64_t words[2 * SHAKE256_WORDS]; /* 21 = 168 bytes * 8 / 64 */
    ALIGN16 uint8_t buffers[ML_DSA_SHAKE_X2_BATCH_SIZE][ML_DSA_EXPAND_MASK_BLOCKS_MAX];
    size_t i;
    const size_t num_polys = out->num_poly;
    const size_t buf_size = ML_DSA_EXPAND_MASK_BUF_SIZE(gamma1);
    const size_t buf_size_blocks = ML_DSA_EXPAND_MASK_BUF_SIZE_BLOCKS(gamma1);
    uint64_t *pindx = absorb_once_shake256(words, rho_prime, ML_DSA_RHO_PRIME_BYTES);

    for (i = 0; i + (ML_DSA_SHAKE_X2_BATCH_SIZE - 1) < num_polys; i += ML_DSA_SHAKE_X2_BATCH_SIZE) {
        set_index(pindx, (uint64_t)(kappa + i), (uint64_t)(kappa + i + 1));
        ossl_shake256_2x_oneshot_singleblock_absorb_interleaved_multi_block_squeeze(words, buffers[0], buffers[1], buf_size_blocks);
        ossl_ml_dsa_poly_decode_expand_mask(&out->poly[i + 0], buffers[0], buf_size, gamma1);
        ossl_ml_dsa_poly_decode_expand_mask(&out->poly[i + 1], buffers[1], buf_size, gamma1);
    }
    /*
     * num_polys is always 4+4 (ML-DSA-44), 6+5 (ML-DSA-65), or 8+7 (ML-DSA-87)
     * As we run 2 in parallel, there will be 1 left over for ML-DSA-65 and ML-DSA-87.
     * We still process 2 lanes here, but only use the first result.
     */
    if (i < num_polys) {
        set_index(pindx, (uint64_t)(kappa + i), (uint64_t)(kappa + i));
        ossl_shake256_2x_oneshot_singleblock_absorb_interleaved_multi_block_squeeze(words, buffers[0], buffers[1], buf_size_blocks);
        ossl_ml_dsa_poly_decode_expand_mask(&out->poly[i + 0], buffers[0], buf_size, gamma1);
    }

    OPENSSL_cleanse(buffers, sizeof(buffers));
    OPENSSL_cleanse(words, sizeof(words));
    SHA3_secure_vector_clear_armv8();
}

static ossl_unused int rej_bounded_poly_mb(COEFF_FROM_NIBBLE_FUNC *coef_from_nibble,
    const uint64_t *words, POLY *outs[ML_DSA_SHAKE_X2_BATCH_SIZE], int count)
{
    KECCAK1600_X2_ARMV8_CTX ctx;
    ALIGN16 uint8_t blocks[ML_DSA_SHAKE_X2_BATCH_SIZE][SHAKE256_BLOCKSIZE];
    int coeff_idx[ML_DSA_SHAKE_X2_BATCH_SIZE] = { 0, 0 };
    int lane;

    ossl_shake256_2x_oneshot_singleblock_absorb_interleaved_squeeze(ctx.A, words, blocks[0], blocks[1]);
    while (1) {
        int finished = 0;
        for (lane = 0; lane < count; lane++) {
            const uint8_t *b = blocks[lane];
            const uint8_t *end = b + SHAKE256_BLOCKSIZE;
            uint32_t *coeff = outs[lane]->coeff;
            int j = coeff_idx[lane];

            if (j == ML_DSA_NUM_POLY_COEFFICIENTS) {
                finished++;
                continue;
            }

            for (; b < end; b++) {
                uint32_t z0 = *b & 0x0F;
                uint32_t z1 = *b >> 4;

                if (coef_from_nibble(z0, coeff + j)
                    && ++j == ML_DSA_NUM_POLY_COEFFICIENTS) {
                        finished++;
                        break;
                }
                if (coef_from_nibble(z1, coeff + j)
                    && ++j == ML_DSA_NUM_POLY_COEFFICIENTS) {
                        finished++;
                        break;
                }
            }
            coeff_idx[lane] = j;
        }
        if (finished == count)
            break;
        ossl_shake256_2x_squeeze_singleblock(ctx.A, blocks[0], blocks[1]);
    }
    OPENSSL_cleanse(blocks, sizeof(blocks));
    ossl_shakex2_cleanup_armv8(&ctx);
    return 1;
}

static int matrix_expand_A_mb(EVP_MD_CTX *g_ctx, const EVP_MD *md,
    const uint8_t *rho, MATRIX *out)
{
    ALIGN16 uint64_t words[2 * SHAKE128_WORDS];
    uint64_t index;
    size_t id, cols, rows;
    POLY *polys[ML_DSA_SHAKE_X2_BATCH_SIZE];
    POLY *poly = out->m_poly;
    uint64_t *pindx = absorb_once_shake128(words, rho, ML_DSA_RHO_BYTES);

    /*
     * This code assume ML_DSA_SHAKE_X2_BATCH_SIZE = 2.
     * ML_DSA rows are an even number of 4, 6 or 8, so traverse the
     * matrix in rows pairs in order to avoid extra processing.
     * The l * k matrix polynomial indexes are in column order.
     */
    for (cols = 0; cols < out->l; cols++) {
        id = cols;
        index = cols;
        for (rows = 0; rows < out->k; rows += 2, index += (2<<8), id += (2*out->l)) {
            set_index(pindx, index, index + (1<<8));
            /* Generate the polynomial for each matrix element using a unique seed */
            polys[0] = &poly[id];
            polys[1] = &poly[id + out->l];
            if (!rej_ntt_poly_mb(words, polys))
                return 0;
        }
    }
    /* The values produced here are not secret, so there is no cleanup. */
    return 1;
}

static int vector_expand_S_mb(EVP_MD_CTX *h_ctx, const EVP_MD *md, const int eta,
    const uint8_t *seed, VECTOR *s1, VECTOR *s2)
{
    ALIGN16 uint64_t words[2 * SHAKE256_WORDS];
    int ret = 0;
    size_t b, idx;
    const size_t l = s1->num_poly;
    const size_t total = l + s2->num_poly;
    POLY *polys[ML_DSA_SHAKE_X2_BATCH_SIZE];
    COEFF_FROM_NIBBLE_FUNC *coef_from_nibble_fn = (eta == ML_DSA_ETA_4) ? coeff_from_nibble_4 : coeff_from_nibble_2;
    uint64_t *pindx = absorb_once_shake256(words, seed, ML_DSA_PRIV_SEED_BYTES);

    for (idx = 0; (idx + ML_DSA_SHAKE_X2_BATCH_SIZE - 1) < total; idx += ML_DSA_SHAKE_X2_BATCH_SIZE) {
        set_index(pindx, idx, idx + 1);
        for (b = 0; b < ML_DSA_SHAKE_X2_BATCH_SIZE; b++) {
            const uint64_t poly_idx = (uint64_t)(idx + b);
            if (poly_idx < l)
                polys[b] = &s1->poly[poly_idx];
            else
                polys[b] = &s2->poly[poly_idx - l];
        }
        if (!rej_bounded_poly_mb(coef_from_nibble_fn, words, polys, ML_DSA_SHAKE_X2_BATCH_SIZE))
            goto err;
    }

    if (idx < total) {
        uint64_t poly_idx = idx;
        set_index(pindx, poly_idx, poly_idx);
        polys[0] = &s2->poly[poly_idx - l];
        if (!rej_bounded_poly_mb(coef_from_nibble_fn, words, polys, 1))
            goto err;
    }

    ret = 1;
err:
    SHA3_secure_vector_clear_armv8();
    OPENSSL_cleanse(words, sizeof(words));
    return ret;
}

static const OSSL_ML_DSA_SAMPLE_OPS ml_dsa_sample_armv8 = {
    matrix_expand_A_mb,
    vector_expand_S_mb,
    vector_expand_mask_mb
};
