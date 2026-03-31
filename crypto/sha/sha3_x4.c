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
 * SHAKE x4 multi-buffer implementation for AVX-512VL
 *
 * This file provides incremental API wrappers around the AVX-512VL
 * assembly implementations for processing 4 SHAKE instances in parallel.
 *
 * Callers should check SHA3_avx512vl_capable() before calling.
 */

#include "internal/sha3.h"
#include <string.h>

#if defined(KECCAK1600_ASM) && defined(__x86_64__) && !defined(OPENSSL_NO_ASM)

/* External assembly function declarations */
extern void SHA3_shake128_x4_inc_absorb_avx512vl(
    uint64_t *state,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen);

extern void SHA3_shake256_x4_inc_absorb_avx512vl(
    uint64_t *state,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen);

extern void SHA3_shake128_x4_inc_finalize_avx512vl(uint64_t *state);
extern void SHA3_shake256_x4_inc_finalize_avx512vl(uint64_t *state);

extern void SHA3_shake128_x4_inc_squeeze_avx512vl(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    uint64_t *state);

extern void SHA3_shake256_x4_inc_squeeze_avx512vl(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    uint64_t *state);

/* One-shot assembly function declarations */
extern void SHA3_shake128_x4_avx512vl(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen);

extern void SHA3_shake256_x4_avx512vl(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen);

/*
 * SHAKE-128 x4 Implementation
 */

void ossl_sha3_shake128_x4_inc_init(KECCAK1600_X4_CTX *ctx)
{
    memset(ctx->A, 0, sizeof(ctx->A));
    ctx->rate = 168; /* SHAKE-128 rate in bytes */
    ctx->finalized = 0;
}

void ossl_sha3_shake128_x4_inc_absorb(
    KECCAK1600_X4_CTX *ctx,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen)
{
    if (ctx->finalized) {
        /* Error: cannot absorb after finalize */
        return;
    }

    SHA3_shake128_x4_inc_absorb_avx512vl(
        ctx->A, in0, in1, in2, in3, inlen);
}

void ossl_sha3_shake128_x4_inc_finalize(KECCAK1600_X4_CTX *ctx)
{
    if (ctx->finalized) {
        return; /* Already finalized */
    }

    SHA3_shake128_x4_inc_finalize_avx512vl(ctx->A);
    ctx->finalized = 1;
}

void ossl_sha3_shake128_x4_inc_squeeze(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    KECCAK1600_X4_CTX *ctx)
{
    if (!ctx->finalized) {
        /* Auto-finalize on first squeeze */
        ossl_sha3_shake128_x4_inc_finalize(ctx);
    }

    SHA3_shake128_x4_inc_squeeze_avx512vl(
        out0, out1, out2, out3, outlen, ctx->A);
}

/*
 * SHAKE-256 x4 Implementation
 */

void ossl_sha3_shake256_x4_inc_init(KECCAK1600_X4_CTX *ctx)
{
    memset(ctx->A, 0, sizeof(ctx->A));
    ctx->rate = 136; /* SHAKE-256 rate in bytes */
    ctx->finalized = 0;
}

void ossl_sha3_shake256_x4_inc_absorb(
    KECCAK1600_X4_CTX *ctx,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen)
{
    if (ctx->finalized) {
        /* Error: cannot absorb after finalize */
        return;
    }

    SHA3_shake256_x4_inc_absorb_avx512vl(
        ctx->A, in0, in1, in2, in3, inlen);
}

void ossl_sha3_shake256_x4_inc_finalize(KECCAK1600_X4_CTX *ctx)
{
    if (ctx->finalized) {
        return; /* Already finalized */
    }

    SHA3_shake256_x4_inc_finalize_avx512vl(ctx->A);
    ctx->finalized = 1;
}

void ossl_sha3_shake256_x4_inc_squeeze(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    KECCAK1600_X4_CTX *ctx)
{
    if (!ctx->finalized) {
        /* Auto-finalize on first squeeze */
        ossl_sha3_shake256_x4_inc_finalize(ctx);
    }

    SHA3_shake256_x4_inc_squeeze_avx512vl(
        out0, out1, out2, out3, outlen, ctx->A);
}

/*
 * Single-call wrapper APIs
 */

void ossl_sha3_shake128_x4(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen)
{
    SHA3_shake128_x4_avx512vl(out0, out1, out2, out3, outlen,
        in0, in1, in2, in3, inlen);
}

void ossl_sha3_shake256_x4(
    void *out0, void *out1,
    void *out2, void *out3,
    size_t outlen,
    const void *in0, const void *in1,
    const void *in2, const void *in3,
    size_t inlen)
{
    SHA3_shake256_x4_avx512vl(out0, out1, out2, out3, outlen,
        in0, in1, in2, in3, inlen);
}

#endif /* KECCAK1600_ASM && __x86_64__ && !OPENSSL_NO_ASM */
