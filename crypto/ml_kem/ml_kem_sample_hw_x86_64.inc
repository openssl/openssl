/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Matrix A generation with four SHAKE128 streams. Included from ml_kem.c
 * when the x4 Keccak assembly is part of the build. The caller has
 * checked SHA3_avx512vl_capable().
 */

#define ML_KEM_SHAKE_X4_LANES 4
#define ML_KEM_SHAKE_X4_DONE_MASK ((1 << ML_KEM_SHAKE_X4_LANES) - 1)

/*-
 * Absorb seeds of ML_KEM_RANDOM_BYTES + 2 bytes and rejection-sample
 * |count| polynomials. |count| is 2, 3, or 4. Lanes at and above |count|
 * are marked done before the first squeeze, and their blocks are not
 * parsed. The x4 absorb takes a pointer in every lane. Unused lanes
 * alias lane 0.
 *
 * A lane that reaches DEGREE coefficients remains in the permutation
 * until every live lane is full. The seeds and blocks are public matrix
 * data and are not cleansed.
 */
static int sample_polys_x4(scalar *out[ML_KEM_SHAKE_X4_LANES],
    const uint8_t *seeds[ML_KEM_SHAKE_X4_LANES], int count)
{
    KECCAK1600_X4_AVX512VL_CTX ctx;
    uint8_t blocks[ML_KEM_SHAKE_X4_LANES][SCALAR_SAMPLING_BUFSIZE];
    uint16_t *curr[ML_KEM_SHAKE_X4_LANES];
    const uint16_t *endout[ML_KEM_SHAKE_X4_LANES];
    size_t done_mask = 0;
    int lane;

    for (lane = count; lane < ML_KEM_SHAKE_X4_LANES; lane++)
        done_mask |= (size_t)1 << lane;

    for (lane = 0; lane < count; lane++) {
        curr[lane] = out[lane]->c;
        endout[lane] = curr[lane] + DEGREE;
    }

    ossl_sha3_shake128_x4_inc_init_avx512vl(&ctx);
    ossl_sha3_shake128_x4_inc_absorb_avx512vl(&ctx, seeds[0], seeds[1],
        seeds[2], seeds[3], ML_KEM_RANDOM_BYTES + 2);

    while (done_mask != ML_KEM_SHAKE_X4_DONE_MASK) {
        ossl_sha3_shake128_x4_inc_squeeze_avx512vl(blocks[0], blocks[1],
            blocks[2], blocks[3], SCALAR_SAMPLING_BUFSIZE, &ctx);

        for (lane = 0; lane < ML_KEM_SHAKE_X4_LANES; lane++) {
            if (done_mask & ((size_t)1 << lane))
                continue;

            sample_rejection_block(&curr[lane], endout[lane], blocks[lane],
                SCALAR_SAMPLING_BUFSIZE);
            if (curr[lane] >= endout[lane])
                done_mask |= (size_t)1 << lane;
        }
    }
    return 1;
}

/*-
 * Seeds are rho || i || j, with i = index / rank and j = index % rank,
 * the same order as the scalar loop in matrix_expand(). Groups of 2, 3,
 * or 4 polynomials use the x4 API. One remaining polynomial, the ninth
 * of ML-KEM-768, uses the scalar EVP path.
 */
static int matrix_expand_x4(EVP_MD_CTX *mdctx, ML_KEM_KEY *key)
{
    scalar *out = key->m;
    int rank = key->vinfo->rank;
    int total = rank * rank;
    int n = 0, b, count;
    uint8_t seeds[ML_KEM_SHAKE_X4_LANES][ML_KEM_RANDOM_BYTES + 2];
    const uint8_t *in[ML_KEM_SHAKE_X4_LANES];
    scalar *polys[ML_KEM_SHAKE_X4_LANES];

    for (b = 0; b < ML_KEM_SHAKE_X4_LANES; b++) {
        memcpy(seeds[b], key->rho, ML_KEM_RANDOM_BYTES);
        seeds[b][ML_KEM_RANDOM_BYTES] = 0;
        seeds[b][ML_KEM_RANDOM_BYTES + 1] = 0;
    }

    while (total - n >= 2) {
        count = total - n;
        if (count > ML_KEM_SHAKE_X4_LANES)
            count = ML_KEM_SHAKE_X4_LANES;

        for (b = 0; b < count; b++) {
            int idx = n + b;

            seeds[b][ML_KEM_RANDOM_BYTES] = (uint8_t)(idx / rank);
            seeds[b][ML_KEM_RANDOM_BYTES + 1] = (uint8_t)(idx % rank);
            in[b] = seeds[b];
            polys[b] = out + idx;
        }
        for (; b < ML_KEM_SHAKE_X4_LANES; b++)
            in[b] = seeds[0];

        if (!sample_polys_x4(polys, in, count))
            return 0;
        n += count;
    }

    if (n < total) {
        uint8_t input[ML_KEM_RANDOM_BYTES + 2];

        memcpy(input, key->rho, ML_KEM_RANDOM_BYTES);
        input[ML_KEM_RANDOM_BYTES] = (uint8_t)(n / rank);
        input[ML_KEM_RANDOM_BYTES + 1] = (uint8_t)(n % rank);
        if (!sample_poly_scalar(out + n, input, mdctx, key))
            return 0;
    }
    return 1;
}
