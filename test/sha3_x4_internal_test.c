/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2026 Intel Corporation. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal cross-validation tests for the SHAKE x4 multi-buffer API.
 *
 * Each test computes SHAKE-128 or SHAKE-256 on four independent inputs
 * using the x4 (AVX-512VL) path and compares every lane's output to the
 * equivalent result produced by the scalar ossl_sha3_* API.
 *
 * Tests cover:
 *   - Single-call (ossl_sha3_shake{128,256}_x4_avx512vl) for many (inlen, outlen) pairs
 *   - Incremental init/absorb/squeeze for the same (inlen, outlen) pairs
 *   - Multi-absorb: input split at every possible block boundary
 *   - Multi-squeeze: output produced in two successive squeeze calls
 */

#include <string.h>
#include "testutil.h"

/*
 * KECCAK1600_ASM is only added to the library compilation flags by the build
 * system, not to test binaries. Since the x4 declarations in internal/sha3.h
 * are guarded by that macro, we define it here before the include so that the
 * KECCAK1600_X4_AVX512VL_CTX type and function prototypes are visible.
 * The symbols themselves live in libcrypto and are always present.
 * We additionally gate all x4 code on x86_64 (GCC/Clang: __x86_64__,
 * MSVC: _M_AMD64/_M_X64) and !OPENSSL_NO_ASM so that the test still
 * compiles on other platforms or in no-asm builds.
 */
#if (defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)) \
    && !defined(OPENSSL_NO_ASM)
#ifndef KECCAK1600_ASM
#define KECCAK1600_ASM
#endif
#endif
#include "internal/sha3.h"

/*
 * A single deterministic 1024-byte message.  Each of the four lanes receives
 * a different slice of this buffer, with lane base pointers spaced 64 bytes
 * apart, so their inputs are distinct yet entirely self-contained.
 */
#define MSG_BUF_SIZE 1024
#define LANE_STRIDE 64 /* byte offset between lane base pointers */
#define NUM_LANES 4

static unsigned char msg[MSG_BUF_SIZE];

/* Maximum output length used in this file – must fit chunk1 + chunk2. */
#define MAX_OUT 640

#if defined(KECCAK1600_ASM)                                                               \
    && (defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)) \
    && !defined(OPENSSL_NO_ASM)

/*
 * Input lengths exercising: empty, tiny, sub-block, block boundary ±1,
 * multiple blocks and a longer message for SHAKE-128 (rate=168) and
 * SHAKE-256 (rate=136).
 */
static const size_t input_sizes[] = {
    0, 1, 17, 100, 135, 136, 137, 168, 169, 200, 400
};
#define NUM_INPUT_SIZES (sizeof(input_sizes) / sizeof(input_sizes[0]))

/* Output lengths chosen to straddle rate boundaries for both variants. */
static const size_t output_sizes[] = {
    16, 32, 64, 136, 168, 256, 512
};
#define NUM_OUTPUT_SIZES (sizeof(output_sizes) / sizeof(output_sizes[0]))

/* Helpers functions */

/*
 * Compute a scalar SHAKE-128 or SHAKE-256 digest.
 * bitlen: 128 or 256.  Returns 1 on success, 0 on failure.
 */
static int scalar_shake(const unsigned int bitlen,
    const unsigned char *in, const size_t inlen,
    unsigned char *out, const size_t outlen)
{
    KECCAK1600_CTX ctx;

    if (!ossl_sha3_init(&ctx, 0x1f, bitlen))
        return 0;
    /* ossl_sha3_init does not populate the method vtable; do it here. */
    ctx.meth.absorb = ossl_sha3_absorb_default;
    ctx.meth.final = ossl_sha3_final_default;
    ctx.meth.squeeze = ossl_shake_squeeze_default;
    return ossl_sha3_absorb(&ctx, in, inlen)
        && ossl_sha3_squeeze(&ctx, out, outlen);
}

/*
 * Encode (inlen_idx, outlen_idx) into a single test index and back.
 * test index n = inlen_idx * NUM_OUTPUT_SIZES + outlen_idx
 */
static void decode_idx(const int n, size_t *inlen, size_t *outlen)
{
    *inlen = input_sizes[n / (int)NUM_OUTPUT_SIZES];
    *outlen = output_sizes[n % (int)NUM_OUTPUT_SIZES];
}

/* One-shot tests */

static int test_shake_x4_oneshot(const unsigned int bitlen, const int n)
{
    size_t inlen, outlen;
    const unsigned char *in[NUM_LANES];
    unsigned char x4_out[NUM_LANES][MAX_OUT];
    unsigned char ref_out[NUM_LANES][MAX_OUT];
    int i;

    decode_idx(n, &inlen, &outlen);

    for (i = 0; i < NUM_LANES; i++)
        in[i] = msg + i * LANE_STRIDE;

    /* Ensure the lane inputs fit within the message buffer. */
    if (!TEST_size_t_le(inlen + (NUM_LANES - 1) * LANE_STRIDE, MSG_BUF_SIZE))
        return 0;
    if (!TEST_size_t_le(outlen, MAX_OUT))
        return 0;

    /* x4 single-call */
    if (bitlen == 128)
        ossl_sha3_shake128_x4_avx512vl(x4_out[0], x4_out[1], x4_out[2], x4_out[3],
            outlen,
            in[0], in[1], in[2], in[3], inlen);
    else
        ossl_sha3_shake256_x4_avx512vl(x4_out[0], x4_out[1], x4_out[2], x4_out[3],
            outlen,
            in[0], in[1], in[2], in[3], inlen);

    /* scalar reference */
    for (i = 0; i < NUM_LANES; i++)
        if (!TEST_true(scalar_shake(bitlen, in[i], inlen, ref_out[i], outlen)))
            return 0;

    /* compare */
    for (i = 0; i < NUM_LANES; i++) {
        if (!TEST_mem_eq(x4_out[i], outlen, ref_out[i], outlen)) {
            TEST_info("SHAKE-%u x4 oneshot lane %d: inlen=%zu outlen=%zu",
                bitlen, i, inlen, outlen);
            return 0;
        }
    }
    return 1;
}

static int test_shake128_x4_oneshot(const int n)
{
    return test_shake_x4_oneshot(128, n);
}

static int test_shake256_x4_oneshot(const int n)
{
    return test_shake_x4_oneshot(256, n);
}

/* Incremental (init / absorb / finalize / squeeze) tests */

static int test_shake_x4_incremental(const unsigned int bitlen, const int n)
{
    size_t inlen, outlen;
    const unsigned char *in[NUM_LANES];
    unsigned char x4_out[NUM_LANES][MAX_OUT];
    unsigned char ref_out[NUM_LANES][MAX_OUT];
    KECCAK1600_X4_AVX512VL_CTX ctx;
    int i;

    decode_idx(n, &inlen, &outlen);

    for (i = 0; i < NUM_LANES; i++)
        in[i] = msg + i * LANE_STRIDE;

    if (!TEST_size_t_le(inlen + (NUM_LANES - 1) * LANE_STRIDE, MSG_BUF_SIZE))
        return 0;

    /* x4 incremental */
    if (bitlen == 128) {
        ossl_sha3_shake128_x4_inc_init_avx512vl(&ctx);
        ossl_sha3_shake128_x4_inc_absorb_avx512vl(&ctx, in[0], in[1], in[2], in[3],
            inlen);
        ossl_sha3_shake128_x4_inc_squeeze_avx512vl(x4_out[0], x4_out[1],
            x4_out[2], x4_out[3], outlen, &ctx);
    } else {
        ossl_sha3_shake256_x4_inc_init_avx512vl(&ctx);
        ossl_sha3_shake256_x4_inc_absorb_avx512vl(&ctx, in[0], in[1], in[2], in[3],
            inlen);
        ossl_sha3_shake256_x4_inc_squeeze_avx512vl(x4_out[0], x4_out[1],
            x4_out[2], x4_out[3], outlen, &ctx);
    }

    /* scalar reference */
    for (i = 0; i < NUM_LANES; i++)
        if (!TEST_true(scalar_shake(bitlen, in[i], inlen, ref_out[i], outlen)))
            return 0;

    for (i = 0; i < NUM_LANES; i++) {
        if (!TEST_mem_eq(x4_out[i], outlen, ref_out[i], outlen)) {
            TEST_info("SHAKE-%u x4 incremental lane %d: inlen=%zu outlen=%zu",
                bitlen, i, inlen, outlen);
            return 0;
        }
    }
    return 1;
}

static int test_shake128_x4_incremental(const int n)
{
    return test_shake_x4_incremental(128, n);
}

static int test_shake256_x4_incremental(const int n)
{
    return test_shake_x4_incremental(256, n);
}

/* Multi-absorb tests */

/*
 * Split the input at every tested input size, absorbing the two halves
 * in separate calls.  The split length is chosen as input_sizes[n] so that
 * we exercise sub-block, at-block and multi-block split points.
 *
 * Full message length is fixed at the largest tested input size so that
 * every split index is meaningful.
 */
static int test_shake_x4_multi_absorb(const unsigned int bitlen, const int n)
{
    const size_t total = input_sizes[NUM_INPUT_SIZES - 1];
    const size_t split = input_sizes[n];
    const size_t outlen = 64; /* fixed output length for this sub-test */
    const unsigned char *in[NUM_LANES];
    unsigned char x4_out[NUM_LANES][MAX_OUT];
    unsigned char ref_out[NUM_LANES][MAX_OUT];
    KECCAK1600_X4_AVX512VL_CTX ctx;
    int i;

    if (split > total)
        return 1; /* nothing to test */

    for (i = 0; i < NUM_LANES; i++)
        in[i] = msg + i * LANE_STRIDE;

    if (!TEST_size_t_le(total + (NUM_LANES - 1) * LANE_STRIDE, MSG_BUF_SIZE))
        return 0;

    /* x4 split absorb */
    if (bitlen == 128) {
        ossl_sha3_shake128_x4_inc_init_avx512vl(&ctx);
        ossl_sha3_shake128_x4_inc_absorb_avx512vl(&ctx,
            in[0], in[1], in[2], in[3], split);
        ossl_sha3_shake128_x4_inc_absorb_avx512vl(&ctx,
            in[0] + split, in[1] + split, in[2] + split, in[3] + split,
            total - split);
        ossl_sha3_shake128_x4_inc_squeeze_avx512vl(x4_out[0], x4_out[1],
            x4_out[2], x4_out[3], outlen, &ctx);
    } else {
        ossl_sha3_shake256_x4_inc_init_avx512vl(&ctx);
        ossl_sha3_shake256_x4_inc_absorb_avx512vl(&ctx,
            in[0], in[1], in[2], in[3], split);
        ossl_sha3_shake256_x4_inc_absorb_avx512vl(&ctx,
            in[0] + split, in[1] + split, in[2] + split, in[3] + split,
            total - split);
        ossl_sha3_shake256_x4_inc_squeeze_avx512vl(x4_out[0], x4_out[1],
            x4_out[2], x4_out[3], outlen, &ctx);
    }

    /* scalar reference (single absorb of full message) */
    for (i = 0; i < NUM_LANES; i++)
        if (!TEST_true(scalar_shake(bitlen, in[i], total, ref_out[i], outlen)))
            return 0;

    for (i = 0; i < NUM_LANES; i++) {
        if (!TEST_mem_eq(x4_out[i], outlen, ref_out[i], outlen)) {
            TEST_info("SHAKE-%u x4 multi-absorb lane %d: total=%zu split=%zu",
                bitlen, i, total, split);
            return 0;
        }
    }
    return 1;
}

static int test_shake128_x4_multi_absorb(const int n)
{
    return test_shake_x4_multi_absorb(128, n);
}

static int test_shake256_x4_multi_absorb(const int n)
{
    return test_shake_x4_multi_absorb(256, n);
}

/* Multi-squeeze tests */

/*
 * Squeeze in two successive calls and verify that the concatenated output
 * matches a single scalar squeeze of the same total length.
 * Parameterized over output_sizes[] for the first chunk; the second chunk
 * is always 64 bytes so the total length varies.
 */
static int test_shake_x4_multi_squeeze(const unsigned int bitlen, const int n)
{
    const size_t inlen = 200; /* fixed input length */
    const size_t chunk1 = output_sizes[n];
    const size_t chunk2 = 64;
    const size_t total = chunk1 + chunk2;
    const unsigned char *in[NUM_LANES];
    unsigned char x4_a[NUM_LANES][MAX_OUT]; /* first chunk              */
    unsigned char x4_b[NUM_LANES][MAX_OUT]; /* second chunk             */
    unsigned char ref_out[NUM_LANES][MAX_OUT];
    KECCAK1600_X4_AVX512VL_CTX ctx;
    int i;

    if (!TEST_size_t_le(total, MAX_OUT))
        return 0;
    if (!TEST_size_t_le(inlen + (NUM_LANES - 1) * LANE_STRIDE, MSG_BUF_SIZE))
        return 0;

    for (i = 0; i < NUM_LANES; i++)
        in[i] = msg + i * LANE_STRIDE;

    /* x4 two-shot squeeze */
    if (bitlen == 128) {
        ossl_sha3_shake128_x4_inc_init_avx512vl(&ctx);
        ossl_sha3_shake128_x4_inc_absorb_avx512vl(&ctx, in[0], in[1], in[2], in[3],
            inlen);
        /* first squeeze */
        ossl_sha3_shake128_x4_inc_squeeze_avx512vl(x4_a[0], x4_a[1], x4_a[2], x4_a[3],
            chunk1, &ctx);
        /* second squeeze – context carries state from previous call */
        ossl_sha3_shake128_x4_inc_squeeze_avx512vl(x4_b[0], x4_b[1], x4_b[2], x4_b[3],
            chunk2, &ctx);
    } else {
        ossl_sha3_shake256_x4_inc_init_avx512vl(&ctx);
        ossl_sha3_shake256_x4_inc_absorb_avx512vl(&ctx, in[0], in[1], in[2], in[3],
            inlen);
        ossl_sha3_shake256_x4_inc_squeeze_avx512vl(x4_a[0], x4_a[1], x4_a[2], x4_a[3],
            chunk1, &ctx);
        ossl_sha3_shake256_x4_inc_squeeze_avx512vl(x4_b[0], x4_b[1], x4_b[2], x4_b[3],
            chunk2, &ctx);
    }

    /* scalar reference – squeeze the full total in one call */
    for (i = 0; i < NUM_LANES; i++)
        if (!TEST_true(scalar_shake(bitlen, in[i], inlen, ref_out[i], total)))
            return 0;

    /* check first chunk, then second chunk */
    for (i = 0; i < NUM_LANES; i++) {
        if (!TEST_mem_eq(x4_a[i], chunk1, ref_out[i], chunk1)) {
            TEST_info("SHAKE-%u x4 multi-squeeze lane %d chunk1: "
                      "inlen=%zu chunk1=%zu chunk2=%zu",
                bitlen, i, inlen, chunk1, chunk2);
            return 0;
        }
        if (!TEST_mem_eq(x4_b[i], chunk2, ref_out[i] + chunk1, chunk2)) {
            TEST_info("SHAKE-%u x4 multi-squeeze lane %d chunk2: "
                      "inlen=%zu chunk1=%zu chunk2=%zu",
                bitlen, i, inlen, chunk1, chunk2);
            return 0;
        }
    }
    return 1;
}

static int test_shake128_x4_multi_squeeze(const int n)
{
    return test_shake_x4_multi_squeeze(128, n);
}

static int test_shake256_x4_multi_squeeze(const int n)
{
    return test_shake_x4_multi_squeeze(256, n);
}

#endif /* KECCAK1600_ASM && x86_64 && !OPENSSL_NO_ASM */

/* Test entry point */

int setup_tests(void)
{
    size_t i;

    /* Fill the message buffer with a deterministic non-zero pattern. */
    for (i = 0; i < MSG_BUF_SIZE; i++)
        msg[i] = (unsigned char)(251 * i + 17);

#ifdef OPENSSL_CPUID_OBJ
    OPENSSL_cpuid_setup();
#endif

#if !defined(KECCAK1600_ASM)                                                               \
    || !(defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)) \
    || defined(OPENSSL_NO_ASM)
    return TEST_skip("SHAKE x4 API not available in this build");
#else
    if (!SHA3_avx512vl_capable()) {
        return TEST_skip("AVX-512VL not available; skipping SHAKE x4 tests");
    }

    ADD_ALL_TESTS(test_shake128_x4_oneshot,
        (int)(NUM_INPUT_SIZES * NUM_OUTPUT_SIZES));
    ADD_ALL_TESTS(test_shake256_x4_oneshot,
        (int)(NUM_INPUT_SIZES * NUM_OUTPUT_SIZES));

    ADD_ALL_TESTS(test_shake128_x4_incremental,
        (int)(NUM_INPUT_SIZES * NUM_OUTPUT_SIZES));
    ADD_ALL_TESTS(test_shake256_x4_incremental,
        (int)(NUM_INPUT_SIZES * NUM_OUTPUT_SIZES));

    ADD_ALL_TESTS(test_shake128_x4_multi_absorb, (int)NUM_INPUT_SIZES);
    ADD_ALL_TESTS(test_shake256_x4_multi_absorb, (int)NUM_INPUT_SIZES);

    ADD_ALL_TESTS(test_shake128_x4_multi_squeeze, (int)NUM_OUTPUT_SIZES);
    ADD_ALL_TESTS(test_shake256_x4_multi_squeeze, (int)NUM_OUTPUT_SIZES);
#endif

    return 1;
}
