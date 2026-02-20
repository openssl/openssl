/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Tests for the AVX2 streaming base64 decoder (decode_base64_avx2).
 *
 * Generates random plaintext, encodes it with various WS patterns,
 * then decodes through EVP_DecodeUpdate (which dispatches to AVX2)
 * and through a pure-scalar reference. Compares outputs.
 *
 * Covers both standard and SRP base64 alphabets.
 *
 * Exercises all three AVX2 decoder loops:
 *   1) 128-byte fast loop  -- clean data, no WS
 *   2) Skip-WS loop        -- PEM 64-char lines
 *   3) General loop        -- mid-block WS, 76-char lines, random WS
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "crypto/evp.h"
#include "evp_local.h"
#include "testutil.h"

static inline uint32_t next_u32(uint32_t *state)
{
    *state = (*state * 1664525u) + 1013904223u;
    return *state;
}

/*
 * Encode raw bytes to base64 using the SRP alphabet via the internal API.
 * Returns the number of base64 characters written (no NUL terminator).
 */
static int encode_block_srp(const unsigned char *in, int inlen,
    unsigned char *out)
{
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    int outl = 0, finl = 0, total;

    if (ctx == NULL)
        return -1;

    EVP_EncodeInit(ctx);
    ctx->flags = EVP_ENCODE_CTX_USE_SRP_ALPHABET | EVP_ENCODE_CTX_NO_NEWLINES;
    EVP_EncodeUpdate(ctx, out, &outl, in, inlen);
    EVP_EncodeFinal(ctx, out + outl, &finl);
    EVP_ENCODE_CTX_free(ctx);

    total = outl + finl;
    /* Strip trailing NUL that EVP_Encode* appends */
    if (total > 0 && out[total - 1] == '\0')
        total--;
    return total;
}

/*
 * Scalar reference decoder: EVP_DecodeInit + byte-at-a-time feeding.
 * By feeding one byte at a time, the AVX2 fast path never triggers
 * (needs >= 64 bytes), so this always exercises the scalar loop.
 */
static int decode_scalar_ref(const unsigned char *in, int inlen,
    unsigned char *out, int *outlen, int use_srp)
{
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    int partial = 0, final = 0, i;
    unsigned char *p = out;

    if (ctx == NULL)
        return -1;

    EVP_DecodeInit(ctx);
    if (use_srp)
        ctx->flags |= EVP_ENCODE_CTX_USE_SRP_ALPHABET;

    for (i = 0; i < inlen; i++) {
        int ret;

        partial = 0;
        ret = EVP_DecodeUpdate(ctx, p, &partial, in + i, 1);
        if (ret < 0) {
            EVP_ENCODE_CTX_free(ctx);
            return -1;
        }
        p += partial;
        if (ret == 0 && partial == 0 && in[i] == '-')
            break;
    }

    final = 0;
    if (EVP_DecodeFinal(ctx, p, &final) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }
    p += final;
    EVP_ENCODE_CTX_free(ctx);

    *outlen = (int)(p - out);
    return 0;
}

/*
 * Full-buffer decoder: EVP_DecodeInit + single EVP_DecodeUpdate call.
 * This exercises the AVX2 path when input >= 64 bytes.
 */
static int decode_full(const unsigned char *in, int inlen,
    unsigned char *out, int *outlen, int use_srp)
{
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    int partial = 0, final = 0, ret;

    if (ctx == NULL)
        return -1;

    EVP_DecodeInit(ctx);
    if (use_srp)
        ctx->flags |= EVP_ENCODE_CTX_USE_SRP_ALPHABET;

    ret = EVP_DecodeUpdate(ctx, out, &partial, in, inlen);
    if (ret < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }
    if (EVP_DecodeFinal(ctx, out + partial, &final) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }
    EVP_ENCODE_CTX_free(ctx);

    *outlen = partial + final;
    return 0;
}

/*
 * Insert newlines into base64 data at a given line length.
 * Returns the total length including newlines.
 */
static int insert_newlines(const unsigned char *b64, int b64len,
    unsigned char *out, int linelen)
{
    int si = 0, di = 0;

    while (si < b64len) {
        int chunk = b64len - si;

        if (chunk > linelen)
            chunk = linelen;
        memcpy(out + di, b64 + si, chunk);
        di += chunk;
        si += chunk;
        out[di++] = '\n';
    }
    return di;
}

/*
 * Insert random whitespace at random positions.
 * ws_pct is the approximate percentage of output bytes that are WS.
 */
static int insert_random_ws(const unsigned char *b64, int b64len,
    unsigned char *out, uint32_t *seed,
    int ws_pct)
{
    static const char ws_chars[] = " \t\r\n";
    int di = 0, i;

    for (i = 0; i < b64len; i++) {
        if ((int)(next_u32(seed) % 100) < ws_pct)
            out[di++] = ws_chars[next_u32(seed) % 4];
        out[di++] = b64[i];
    }
    out[di++] = '\n';
    return di;
}

/*
 * Input sizes chosen to exercise different decoder paths.
 * Sorted ascending; NUM_LARGE_SIZES counts entries >= 48 (AVX2 threshold)
 * for tests that only make sense with large inputs.
 */
static const int test_sizes[] = {
    0, /* empty */
    1, /* single byte - padding */
    2, /* two bytes - padding */
    3, /* exactly one base64 group */
    15, /* small, no AVX2 */
    47, /* just under 64 encoded bytes */
    48, /* exactly 64 encoded bytes (AVX2 threshold) */
    96, /* 128 encoded bytes (128B fast loop) */
    192, /* 256 encoded bytes (multiple 128B iterations) */
    768, /* ~1KB encoded - exercises all loops */
    1536, /* ~2KB - realistic PEM certificate size */
    4096, /* 4KB - larger PEM */
};
#define NUM_SIZES (int)(sizeof(test_sizes) / sizeof(test_sizes[0]))
/* Index of first entry >= 48 (for chunked/block tests that skip small sizes) */
#define LARGE_SIZE_OFFSET 6
#define NUM_LARGE_SIZES (NUM_SIZES - LARGE_SIZE_OFFSET)

/* WS pattern types */
enum {
    WS_NONE, /* no whitespace (clean) */
    WS_PEM64, /* newline every 64 base64 chars (standard PEM) */
    WS_PEM76, /* newline every 76 base64 chars (MIME) */
    WS_CRLF64, /* \r\n every 64 chars */
    WS_RANDOM_5, /* ~5% random WS insertion */
    WS_RANDOM_20, /* ~20% random WS insertion */
    WS_COUNT
};

static const char *ws_names[] = {
    "none", "pem64", "pem76", "crlf64", "random5%", "random20%"
};

/*
 * Apply a WS pattern to raw base64 data.  Returns the output length.
 */
static int apply_ws_pattern(const unsigned char *b64, int b64len,
    unsigned char *out, int ws_type,
    uint32_t *seed)
{
    switch (ws_type) {
    case WS_NONE:
        memcpy(out, b64, b64len);
        out[b64len] = '\n';
        return b64len + 1;
    case WS_PEM64:
        return insert_newlines(b64, b64len, out, 64);
    case WS_PEM76:
        return insert_newlines(b64, b64len, out, 76);
    case WS_CRLF64: {
        int si = 0, di = 0;

        while (si < b64len) {
            int chunk = b64len - si;

            if (chunk > 64)
                chunk = 64;
            memcpy(out + di, b64 + si, chunk);
            di += chunk;
            si += chunk;
            out[di++] = '\r';
            out[di++] = '\n';
        }
        return di;
    }
    case WS_RANDOM_5:
        return insert_random_ws(b64, b64len, out, seed, 5);
    case WS_RANDOM_20:
        return insert_random_ws(b64, b64len, out, seed, 20);
    default:
        return 0;
    }
}

/*
 * Core test: encode random data, apply WS pattern, decode with both
 * AVX2 (full-buffer) and scalar (byte-at-a-time), compare outputs.
 */
static int run_decode_test(int rawlen, int ws_type, int use_srp,
    uint32_t seed)
{
    const char *alpha = use_srp ? "srp" : "std";
    unsigned char *raw = NULL;
    unsigned char *b64 = NULL;
    unsigned char *input = NULL;
    unsigned char *out_full = NULL;
    unsigned char *out_ref = NULL;
    int b64len, inputlen;
    int outlen_full = 0, outlen_ref = 0;
    int ret = 0;
    int i;

    raw = OPENSSL_malloc(rawlen + 1);
    b64 = OPENSSL_malloc(rawlen * 2 + 256);
    input = OPENSSL_malloc(rawlen * 3 + 256);
    out_full = OPENSSL_malloc(rawlen + 256);
    out_ref = OPENSSL_malloc(rawlen + 256);

    if (!TEST_ptr(raw) || !TEST_ptr(b64) || !TEST_ptr(input)
        || !TEST_ptr(out_full) || !TEST_ptr(out_ref))
        goto end;

    for (i = 0; i < rawlen; i++)
        raw[i] = (unsigned char)(next_u32(&seed) & 0xFF);

    /* Encode with the appropriate alphabet */
    if (use_srp) {
        b64len = encode_block_srp(raw, rawlen, b64);
        if (!TEST_int_ge(b64len, 0))
            goto end;
    } else {
        b64len = EVP_EncodeBlock(b64, raw, rawlen);
    }

    inputlen = apply_ws_pattern(b64, b64len, input, ws_type, &seed);

    /* Decode with full-buffer path (exercises AVX2) */
    if (!TEST_int_eq(decode_full(input, inputlen, out_full,
                         &outlen_full, use_srp),
            0)) {
        TEST_info("decode_full failed: size=%d ws=%s alpha=%s",
            rawlen, ws_names[ws_type], alpha);
        goto end;
    }

    /* Decode with scalar reference (byte-at-a-time) */
    if (!TEST_int_eq(decode_scalar_ref(input, inputlen, out_ref,
                         &outlen_ref, use_srp),
            0)) {
        TEST_info("decode_scalar_ref failed: size=%d ws=%s alpha=%s",
            rawlen, ws_names[ws_type], alpha);
        goto end;
    }

    /* Compare AVX2 vs scalar output */
    if (!TEST_int_eq(outlen_full, outlen_ref)) {
        TEST_info("length mismatch: size=%d ws=%s alpha=%s full=%d ref=%d",
            rawlen, ws_names[ws_type], alpha, outlen_full, outlen_ref);
        goto end;
    }

    if (!TEST_mem_eq(out_full, outlen_full, out_ref, outlen_ref)) {
        TEST_info("data mismatch: size=%d ws=%s alpha=%s",
            rawlen, ws_names[ws_type], alpha);
        goto end;
    }

    /* Verify round-trip against original plaintext */
    if (!TEST_int_eq(outlen_full, rawlen)) {
        TEST_info("round-trip length: size=%d ws=%s alpha=%s decoded=%d",
            rawlen, ws_names[ws_type], alpha, outlen_full);
        goto end;
    }

    if (rawlen > 0 && !TEST_mem_eq(out_full, outlen_full, raw, rawlen)) {
        TEST_info("round-trip data mismatch: size=%d ws=%s alpha=%s",
            rawlen, ws_names[ws_type], alpha);
        goto end;
    }

    ret = 1;

end:
    OPENSSL_free(raw);
    OPENSSL_free(b64);
    OPENSSL_free(input);
    OPENSSL_free(out_full);
    OPENSSL_free(out_ref);
    return ret;
}

static int test_decode_avx2_vs_scalar(int idx)
{
    int size_idx = idx / WS_COUNT;
    int ws_type = idx % WS_COUNT;

    return run_decode_test(test_sizes[size_idx], ws_type, 0,
        (uint32_t)idx);
}

static int test_decode_srp(int idx)
{
    int size_idx = idx / WS_COUNT;
    int ws_type = idx % WS_COUNT;

    return run_decode_test(test_sizes[size_idx], ws_type, 1,
        (uint32_t)(idx + NUM_SIZES * WS_COUNT));
}

/*
 * Test chunked decode: feed input in varying chunk sizes.
 * This exercises the AVX2 path with different ctx->num states
 * and verifies leftover handling across multiple Update calls.
 */
static int test_decode_chunked(int idx)
{
    int rawlen = test_sizes[idx + LARGE_SIZE_OFFSET];
    uint32_t seed = (uint32_t)idx;
    unsigned char *raw = NULL;
    unsigned char *b64 = NULL;
    unsigned char *pem = NULL;
    unsigned char *out_chunked = NULL;
    unsigned char *out_ref = NULL;
    int b64len, pemlen;
    int total_chunked = 0, outlen_ref = 0;
    int ret = 0;
    int i;
    EVP_ENCODE_CTX *ctx = NULL;

    /*
     * b64: base64 is ceil(n/3)*4, so *2 is generous.
     * pem: b64 + one newline per 64 chars + CRLF headroom.
     * out: decoded output <= rawlen.
     * +256 on each for padding/rounding safety.
     */
    raw = OPENSSL_malloc(rawlen + 1);
    b64 = OPENSSL_malloc(rawlen * 2 + 256);
    pem = OPENSSL_malloc(rawlen * 3 + 256);
    out_chunked = OPENSSL_malloc(rawlen + 256);
    out_ref = OPENSSL_malloc(rawlen + 256);

    if (!TEST_ptr(raw) || !TEST_ptr(b64) || !TEST_ptr(pem)
        || !TEST_ptr(out_chunked) || !TEST_ptr(out_ref))
        goto end;

    for (i = 0; i < rawlen; i++)
        raw[i] = (unsigned char)(next_u32(&seed) & 0xFF);

    b64len = EVP_EncodeBlock(b64, raw, rawlen);
    pemlen = insert_newlines(b64, b64len, pem, 64);

    ctx = EVP_ENCODE_CTX_new();
    if (!TEST_ptr(ctx))
        goto end;

    EVP_DecodeInit(ctx);
    {
        const unsigned char *p = pem;
        int remaining = pemlen;
        unsigned char *outp = out_chunked;

        while (remaining > 0) {
            int chunk = (int)(next_u32(&seed) % 200) + 1;
            int partial = 0, r;

            if (chunk > remaining)
                chunk = remaining;

            r = EVP_DecodeUpdate(ctx, outp, &partial, p, chunk);
            if (r < 0) {
                TEST_info("chunked DecodeUpdate failed at offset %d, chunk=%d",
                    (int)(p - pem), chunk);
                goto end;
            }
            outp += partial;
            total_chunked += partial;
            p += chunk;
            remaining -= chunk;
        }
        {
            int final = 0;

            if (!TEST_int_ge(EVP_DecodeFinal(ctx, outp, &final), 0))
                goto end;
            total_chunked += final;
        }
    }

    if (!TEST_int_eq(decode_full(pem, pemlen, out_ref, &outlen_ref, 0), 0))
        goto end;
    if (!TEST_int_eq(total_chunked, outlen_ref)) {
        TEST_info("chunked vs full length: size=%d chunked=%d full=%d",
            rawlen, total_chunked, outlen_ref);
        goto end;
    }
    if (!TEST_mem_eq(out_chunked, total_chunked, out_ref, outlen_ref))
        goto end;
    if (!TEST_int_eq(total_chunked, rawlen))
        goto end;
    if (!TEST_mem_eq(out_chunked, total_chunked, raw, rawlen))
        goto end;

    ret = 1;

end:
    EVP_ENCODE_CTX_free(ctx);
    OPENSSL_free(raw);
    OPENSSL_free(b64);
    OPENSSL_free(pem);
    OPENSSL_free(out_chunked);
    OPENSSL_free(out_ref);
    return ret;
}

/*
 * Test partial-context decode: split PEM input at every byte position.
 *
 * Two EVP_DecodeUpdate calls with the split at position `split`.
 * This systematically exercises every possible ctx->num state (0-3
 * pending base64 chars) at the AVX2/scalar handoff boundary.
 *
 * 768 raw bytes -> 1024 base64 chars -> 1040 PEM bytes (16 × 65).
 * Testing all 1041 split points covers: pre-AVX2 threshold, mid-fast-loop,
 * mid-skip-WS-loop, on newlines, mid-base64-group, and post-AVX2 tail.
 */
#define PARTIAL_RAW_LEN 768
/* 768 / 3 * 4 = 1024 b64 chars; 1024 / 64 = 16 lines × 65 bytes = 1040 */
#define PARTIAL_PEM_LEN 1040

static int test_decode_partial_ctx(int split)
{
    uint32_t seed = 54321;
    unsigned char *raw = NULL;
    unsigned char *b64 = NULL;
    unsigned char *pem = NULL;
    unsigned char *out_split = NULL;
    unsigned char *out_ref = NULL;
    int b64len, pemlen;
    int outlen_ref = 0;
    int ret = 0;
    int i;
    EVP_ENCODE_CTX *ctx = NULL;

    raw = OPENSSL_malloc(PARTIAL_RAW_LEN);
    b64 = OPENSSL_malloc(PARTIAL_RAW_LEN * 2 + 256);
    pem = OPENSSL_malloc(PARTIAL_RAW_LEN * 3 + 256);
    out_split = OPENSSL_malloc(PARTIAL_RAW_LEN + 256);
    out_ref = OPENSSL_malloc(PARTIAL_RAW_LEN + 256);

    if (!TEST_ptr(raw) || !TEST_ptr(b64) || !TEST_ptr(pem)
        || !TEST_ptr(out_split) || !TEST_ptr(out_ref))
        goto end;

    for (i = 0; i < PARTIAL_RAW_LEN; i++)
        raw[i] = (unsigned char)(next_u32(&seed) & 0xFF);

    b64len = EVP_EncodeBlock(b64, raw, PARTIAL_RAW_LEN);
    pemlen = insert_newlines(b64, b64len, pem, 64);

    if (!TEST_int_eq(pemlen, PARTIAL_PEM_LEN))
        goto end;

    if (!TEST_int_eq(decode_full(pem, pemlen, out_ref, &outlen_ref, 0), 0))
        goto end;

    /* Two-call decode split at position 'split' */
    ctx = EVP_ENCODE_CTX_new();
    if (!TEST_ptr(ctx))
        goto end;

    EVP_DecodeInit(ctx);
    {
        unsigned char *outp = out_split;
        int total = 0, partial = 0, r;
        int final = 0;

        if (split > 0) {
            r = EVP_DecodeUpdate(ctx, outp, &partial, pem, split);
            if (!TEST_int_ge(r, 0)) {
                TEST_info("split=%d part1 failed", split);
                goto end;
            }
            outp += partial;
            total += partial;
        }

        if (split < pemlen) {
            partial = 0;
            r = EVP_DecodeUpdate(ctx, outp, &partial,
                pem + split, pemlen - split);
            if (!TEST_int_ge(r, 0)) {
                TEST_info("split=%d part2 failed", split);
                goto end;
            }
            outp += partial;
            total += partial;
        }

        if (!TEST_int_ge(EVP_DecodeFinal(ctx, outp, &final), 0)) {
            TEST_info("split=%d DecodeFinal failed", split);
            goto end;
        }
        total += final;

        if (!TEST_int_eq(total, outlen_ref)) {
            TEST_info("split=%d length: got=%d ref=%d", split, total,
                outlen_ref);
            goto end;
        }
        if (!TEST_mem_eq(out_split, total, out_ref, outlen_ref)) {
            TEST_info("split=%d data mismatch", split);
            goto end;
        }
    }

    ret = 1;

end:
    EVP_ENCODE_CTX_free(ctx);
    OPENSSL_free(raw);
    OPENSSL_free(b64);
    OPENSSL_free(pem);
    OPENSSL_free(out_split);
    OPENSSL_free(out_ref);
    return ret;
}

/* EVP_DecodeBlock round-trip for each test size */
static int test_decode_block(int idx)
{
    int rawlen = test_sizes[idx + 1]; /* skip size 0 */
    uint32_t seed = (uint32_t)idx;
    unsigned char *raw = NULL, *b64 = NULL, *out = NULL;
    int b64len, block_len;
    int ret = 0, i;

    raw = OPENSSL_malloc(rawlen);
    b64 = OPENSSL_malloc(rawlen * 2 + 256);
    out = OPENSSL_malloc(rawlen + 256);

    if (!TEST_ptr(raw) || !TEST_ptr(b64) || !TEST_ptr(out))
        goto end;

    for (i = 0; i < rawlen; i++)
        raw[i] = (unsigned char)(next_u32(&seed) & 0xFF);

    b64len = EVP_EncodeBlock(b64, raw, rawlen);
    block_len = EVP_DecodeBlock(out, b64, b64len);

    if (!TEST_int_ge(block_len, rawlen))
        goto end;
    if (!TEST_mem_eq(out, rawlen, raw, rawlen))
        goto end;

    ret = 1;

end:
    OPENSSL_free(raw);
    OPENSSL_free(b64);
    OPENSSL_free(out);
    return ret;
}

/*
 * EVP_DecodeBlock overflow regression: prepend '=' to valid base64
 * so AVX2 consumes 0 bytes, forcing the full input through the tail
 * path. Must not crash.
 */
/* Index of first entry >= 96 (need >= 128 b64 chars for overflow test) */
#define OVERFLOW_SIZE_OFFSET 7
#define NUM_OVERFLOW_SIZES (NUM_SIZES - OVERFLOW_SIZE_OFFSET)

static int test_decode_block_overflow(int idx)
{
    int rawlen = test_sizes[idx + OVERFLOW_SIZE_OFFSET];
    uint32_t seed = (uint32_t)idx;
    unsigned char *raw = NULL, *b64 = NULL, *bad = NULL, *out = NULL;
    int b64len;
    int ret = 0, i;

    raw = OPENSSL_malloc(rawlen);
    b64 = OPENSSL_malloc(rawlen * 2 + 256);
    bad = OPENSSL_malloc(rawlen * 2 + 258);
    out = OPENSSL_malloc(rawlen + 256);

    if (!TEST_ptr(raw) || !TEST_ptr(b64) || !TEST_ptr(bad) || !TEST_ptr(out))
        goto end;

    for (i = 0; i < rawlen; i++)
        raw[i] = (unsigned char)(next_u32(&seed) & 0xFF);

    b64len = EVP_EncodeBlock(b64, raw, rawlen);
    bad[0] = '=';
    memcpy(bad + 1, b64, b64len);

    if (!TEST_int_eq(EVP_DecodeBlock(out, bad, b64len + 1), -1))
        goto end;

    ret = 1;

end:
    OPENSSL_free(raw);
    OPENSSL_free(b64);
    OPENSSL_free(bad);
    OPENSSL_free(out);
    return ret;
}

int setup_tests(void)
{
    /* Standard alphabet: test_sizes x WS patterns */
    ADD_ALL_TESTS(test_decode_avx2_vs_scalar, NUM_SIZES * WS_COUNT);

    /* SRP alphabet: test_sizes x WS patterns */
    ADD_ALL_TESTS(test_decode_srp, NUM_SIZES * WS_COUNT);

    /* Chunked decode for sizes >= 48 */
    ADD_ALL_TESTS(test_decode_chunked, NUM_LARGE_SIZES);

    /* Every split point 0..1040 — exercises all ctx->num handoff states */
    ADD_ALL_TESTS(test_decode_partial_ctx, PARTIAL_PEM_LEN + 1);

    /* EVP_DecodeBlock round-trip (skip size 0) */
    ADD_ALL_TESTS(test_decode_block, NUM_SIZES - 1);

    /* EVP_DecodeBlock overflow regression (sizes >= 96) */
    ADD_ALL_TESTS(test_decode_block_overflow, NUM_OVERFLOW_SIZES);

    return 1;
}
