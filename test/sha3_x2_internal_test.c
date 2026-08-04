/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2026 Intel Corporation. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if defined(__aarch64__) && defined(__AARCH64EL__) && !defined(OPENSSL_NO_ASM)
#ifndef KECCAK1600_ASM
#define KECCAK1600_ASM
#endif
#include <string.h>
#include <openssl/byteorder.h>
#include <openssl/rand.h>
#include "testutil.h"
#include "internal/sha3.h"

#define SHAKE256_RATE SHA3_BLOCKSIZE(256)
#define SHAKE256_WORDS (SHAKE256_RATE * 8 / 64)
#define SHAKE256_BUFFER_SZ 5 * SHAKE256_RATE
#define SHAKE128_RATE SHA3_BLOCKSIZE(128)
#define SHAKE128_WORDS (SHAKE128_RATE * 8 / 64)
#define SHAKE128_BUFFER_SZ 5 * SHAKE128_RATE

extern void ossl_shake128_2x_oneshot_singleblock_absorb_interleaved_squeeze(uint64_t *statex2_out, const uint64_t *in_interleaved, uint8_t *out1, uint8_t *out2);
extern void ossl_shake256_2x_oneshot_singleblock_absorb_interleaved_squeeze(uint64_t *statex2_out, const uint64_t *in_interleaved, uint8_t *out1, uint8_t *out2);
extern void ossl_shake128_2x_squeeze_singleblock(uint64_t *statex2, uint8_t *out1, uint8_t *out2);
extern void ossl_shake256_2x_squeeze_singleblock(uint64_t *statex2, uint8_t *out1, uint8_t *out2);
extern void ossl_shake256_2x_oneshot_singleblock_absorb_interleaved_multi_block_squeeze(const uint64_t *in_interleaved, uint8_t *out1, uint8_t *out2, size_t outlen);
extern void SHA3_secure_vector_clear_armv8(void);

static int do_single_shake(const uint8_t *in1, const uint8_t *in2, size_t inlen,
    uint8_t *out1, uint8_t *out2, size_t outlen)
{
    int ret = 0;
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;

    if (!TEST_ptr(md = EVP_MD_fetch(NULL, "SHAKE256", NULL))
        || !TEST_ptr(ctx = EVP_MD_CTX_new())
        || !TEST_int_eq(EVP_DigestInit(ctx, md), 1)
        || !TEST_int_eq(EVP_DigestUpdate(ctx, in1, inlen), 1)
        || !TEST_int_eq(EVP_DigestFinalXOF(ctx, out1, outlen), 1)
        || !TEST_int_eq(EVP_DigestInit(ctx, md), 1)
        || !TEST_int_eq(EVP_DigestUpdate(ctx, in2, inlen), 1)
        || !TEST_int_eq(EVP_DigestFinalXOF(ctx, out2, outlen), 1))
        goto err;
    ret = 1;
err:
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * Setup a single block of interleaved data for a 2 way absorb.
 * It adds the padding data 0x1f, zeros, and a trailing 1 bit.
 * This has the repeated format of 64 bits for stream 1, followed by
 * 64 bits for stream 2.
 * @param rate 136 for SHAKE256, 168 for SHAKE128
 * @param in1 Byte stream 1.
 * @param in2 Byte stream 2.
 * @param The size of in1 and in2, it must be less than the rate.
 * @param out Output 64 bit interleaved data of size (2 * rate / 8)
 */
static void do_interleave(size_t rate, const uint8_t *in1, const uint8_t *in2, size_t inlen, uint64_t *out)
{
    size_t last_word, shift;
    uint64_t val1, val2;

    memset(out, 0, 2 * rate);
    last_word = (rate / 8) - 1;
    /* write trailing 0x80 interleaved bytes for SHA3 padding */
    out[2 * last_word] = (uint64_t)0x80 << 56;
    out[2 * last_word + 1] = (uint64_t)0x80 << 56;

    while (inlen >= 8) {
        in1 = OPENSSL_load_u64_le(&val1, in1);
        in2 = OPENSSL_load_u64_le(&val2, in2);
        *out++ = val1;
        *out++ = val2;
        inlen -= 8;
    }
    val1 = 0;
    val2 = 0;
    for (shift = 0; inlen > 0; shift += 8, inlen--) {
        val1 |= (*in1++) << shift;
        val2 |= (*in2++) << shift;
    }
    /* Write 0x1f padding after the input data */
    *out++ = val1 | (0x1f << shift);
    *out++ = val2 | (0x1f << shift);
}

static int do_shake_single_absorb_multiblock_squeeze(size_t rate, size_t outlen)
{
    KECCAK1600_X2_ARMV8_CTX ctx;
    ALIGN16 uint64_t inx2[2 * SHAKE128_WORDS];
    uint8_t out1[SHAKE128_BUFFER_SZ], out2[SHAKE128_BUFFER_SZ];
    uint8_t in1[34];
    uint8_t in2[34];
    uint8_t expected_out1[SHAKE128_BUFFER_SZ], expected_out2[SHAKE128_BUFFER_SZ];
    uint8_t *o1 = out1, *o2 = out2;
    size_t inlen = sizeof(in1);
    int ret = 0;

    RAND_bytes(in1, sizeof(in1));
    RAND_bytes(in2, sizeof(in2));
    if (!do_single_shake(in1, in2, inlen, expected_out1, expected_out2, outlen))
        goto err;
    do_interleave(rate, in1, in2, inlen, inx2);
    ossl_shake256_2x_oneshot_singleblock_absorb_interleaved_squeeze(ctx.A, inx2, o1, o2);
    outlen -= rate;
    while (outlen > 0) {
        o1 += rate;
        o2 += rate;
        ossl_shake256_2x_squeeze_singleblock(ctx.A, o1, o2);
        outlen -= rate;
    }
    if (!TEST_mem_eq(out1, outlen, expected_out1, outlen)
        || !TEST_mem_eq(out2, outlen, expected_out2, outlen))
        goto err;
    ret = 1;
err:
    SHA3_secure_vector_clear_armv8();
    return ret;
}

static int test_shake128_single_absorb_multiblock_squeeze(void)
{
    return do_shake_single_absorb_multiblock_squeeze(SHAKE128_RATE, SHAKE128_BUFFER_SZ);
}

static int test_shake256_single_absorb_multiblock_squeeze(void)
{
    return do_shake_single_absorb_multiblock_squeeze(SHAKE256_RATE, SHAKE256_BUFFER_SZ);
}

/* Test the one shot can squeeze multiple blocks */
static int test_shake256_stateless_multiblock_squeeze_once(int tstid)
{
    ALIGN16 uint64_t inx2[2 * SHAKE256_WORDS];
    uint8_t out1[SHAKE256_BUFFER_SZ], out2[SHAKE256_BUFFER_SZ];
    uint8_t expected_out1[SHAKE256_BUFFER_SZ], expected_out2[SHAKE256_BUFFER_SZ];
    uint8_t in1[2] = { 0x01, 0x02 };
    uint8_t in2[2] = { 0x11, 0x12 };
    size_t inlen = sizeof(in1);
    size_t outlen = SHAKE256_RATE * (tstid + 1);
    int ret = 0;

    if (!do_single_shake(in1, in2, inlen, expected_out1, expected_out2, outlen))
        goto err;
    do_interleave(SHAKE256_RATE, in1, in2, inlen, inx2);
    ossl_shake256_2x_oneshot_singleblock_absorb_interleaved_multi_block_squeeze(inx2, out1, out2, outlen);
    if (!TEST_mem_eq(out1, outlen, expected_out1, outlen)
        || !TEST_mem_eq(out2, outlen, expected_out2, outlen))
        goto err;
    ret = 1;
err:
    return ret;
}

/* Test the one shot absorb with different inputs */
static int test_shake256_stateless_absorb_multiblock_squeeze_once(void)
{
    ALIGN16 uint64_t inx2[2 * SHAKE256_WORDS];
    uint8_t out1[SHAKE256_BUFFER_SZ], out2[SHAKE256_BUFFER_SZ];
    uint8_t in1[66];
    uint8_t in2[66];
    size_t inlen = sizeof(in1);
    uint8_t expected_out1[SHAKE256_BUFFER_SZ], expected_out2[SHAKE256_BUFFER_SZ];
    size_t outlen = 3 * SHAKE256_RATE;
    int ret = 0;

    RAND_bytes(in1, sizeof(in1));
    RAND_bytes(in2, sizeof(in2));
    if (!do_single_shake(in1, in2, inlen, expected_out1, expected_out2, outlen))
        goto err;
    do_interleave(SHAKE256_RATE, in1, in2, inlen, inx2);
    ossl_shake256_2x_oneshot_singleblock_absorb_interleaved_multi_block_squeeze(inx2, out1, out2, outlen);
    if (!TEST_mem_eq(out1, outlen, expected_out1, outlen)
        || !TEST_mem_eq(out2, outlen, expected_out2, outlen))
        goto err;
    ret = 1;
err:
    return ret;
}

#endif /* KECCAK1600_ASM && aarch64 && !OPENSSL_NO_ASM */

/* Test entry point */

int setup_tests(void)
{
#ifdef OPENSSL_CPUID_OBJ
    OPENSSL_cpuid_setup();
#endif

#if !defined(KECCAK1600_ASM) || !defined(__aarch64__) || defined(OPENSSL_NO_ASM)
    return TEST_skip("SHAKE x2 AARCH64 API not available in this build");
#else
    if (!ossl_shakex2_sha3_capable_armv8())
        return TEST_skip("ARM SHA3_FEAT not available; skipping SHAKE x2 tests");
    ADD_TEST(test_shake128_single_absorb_multiblock_squeeze);
    ADD_TEST(test_shake256_single_absorb_multiblock_squeeze);
    ADD_TEST(test_shake256_stateless_absorb_multiblock_squeeze_once);
    ADD_ALL_TESTS(test_shake256_stateless_multiblock_squeeze_once, 4);
#endif

    return 1;
}
