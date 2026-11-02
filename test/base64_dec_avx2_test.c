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
 * The AVX2 and scalar paths must be indistinguishable, so the reference
 * here is the same call sequence rerun with the AVX2 capability bit
 * cleared: return values, *outl, ctx->num and the decoded bytes are all
 * compared. Where AVX2 cannot be dispatched, or cannot be turned off
 * again, those comparisons are skipped rather than quietly running the
 * scalar path twice.
 *
 * Exercises all three AVX2 decoder loops:
 *   1) 128-byte fast loop  -- clean data, no WS
 *   2) Skip-WS loop        -- PEM 64-char lines
 *   3) General loop        -- mid-block WS, 76-char lines, random WS
 *
 * Decoding in place (out == in) is covered throughout: that is what
 * PEM_read_bio_ex does.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include "crypto/evp.h"
#include "evp_local.h"
#include "b64_avx2_common.h"
#include "testutil.h"

/*
 * encode.c dispatches on HAVE_AVX2(). When that is the runtime capability
 * check we can clear the bit and rerun; when the build hardwires AVX2
 * (-mavx2) there is no scalar path left to compare against.
 */
#if defined(HAVE_AVX2) && !defined(__AVX2__)
#define B64_AVX2_SWITCHABLE 1
#endif

#define AVX2_CAP_BIT (1u << 5)

/* True when a comparison run can select each path in turn. */
static int avx2_switchable(void)
{
#ifdef B64_AVX2_SWITCHABLE
    return HAVE_AVX2();
#else
    return 0;
#endif
}

static unsigned int avx2_disable(void)
{
#ifdef B64_AVX2_SWITCHABLE
    unsigned int saved = OPENSSL_ia32cap_P[2];

    OPENSSL_ia32cap_P[2] &= ~AVX2_CAP_BIT;
    return saved;
#else
    return 0;
#endif
}

static void avx2_restore(unsigned int saved)
{
#ifdef B64_AVX2_SWITCHABLE
    OPENSSL_ia32cap_P[2] = saved;
#else
    (void)saved;
#endif
}

static int test_avx2_dispatch(void)
{
#ifndef HAVE_AVX2
    TEST_skip("AVX2 decoder is not compiled in for this target");
#else
    if (!HAVE_AVX2()) {
        TEST_skip("CPU does not support AVX2, only the scalar path runs");
    } else if (!avx2_switchable()) {
        TEST_skip("built with -mavx2, the scalar path cannot be selected");
    } else {
        unsigned int saved = avx2_disable();
        int off = HAVE_AVX2();
        avx2_restore(saved);

        if (!TEST_true(HAVE_AVX2()) || !TEST_false(off))
            return 0;
        TEST_info("AVX2 decoder dispatchable, scalar reference available");
    }
#endif
    return 1;
}

static ossl_inline uint32_t next_u32(uint32_t *state)
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

/* Upper bound on EVP_DecodeUpdate calls a single comparison may make. */
#define MAX_CALLS 256

/*
 * Everything one run of EVP_DecodeUpdate calls plus EVP_DecodeFinal
 * produced. Two runs of the same script must agree field for field.
 */
struct dec_result {
    int ncalls;
    int rv[MAX_CALLS];
    int outl[MAX_CALLS];
    int num[MAX_CALLS];
    int final_rv;
    int final_outl;
    int total;
    unsigned char *out;
};

/*
 * Feed `in` to EVP_DecodeUpdate in the chunk sizes listed in cuts[], then
 * call EVP_DecodeFinal, recording every return value and context state.
 * With in_place the input is decoded over itself, as PEM_read_bio_ex does.
 */
static int decode_run(struct dec_result *r, const unsigned char *in, int inl,
    const int *cuts, int ncuts, int use_srp, int in_place, int no_avx2)
{
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    unsigned char *work = NULL;
    const unsigned char *p;
    unsigned char *outp;
    unsigned int saved = 0;
    int i, off = 0, ret = 0;

    if (!TEST_ptr(ctx) || !TEST_int_le(ncuts, MAX_CALLS))
        goto end;

    if (in_place) {
        if (!TEST_ptr(work = OPENSSL_malloc(inl > 0 ? inl : 1)))
            goto end;
        memcpy(work, in, inl);
        p = work;
        outp = work;
    } else {
        p = in;
        outp = r->out;
    }

    r->ncalls = 0;
    r->total = 0;

    EVP_DecodeInit(ctx);
    if (use_srp)
        ctx->flags |= EVP_ENCODE_CTX_USE_SRP_ALPHABET;

    if (no_avx2)
        saved = avx2_disable();

    for (i = 0; i < ncuts; i++) {
        int outl = 0;
        int rv = EVP_DecodeUpdate(ctx, outp, &outl, p + off, cuts[i]);

        r->rv[r->ncalls] = rv;
        r->outl[r->ncalls] = outl;
        r->num[r->ncalls] = EVP_ENCODE_CTX_num(ctx);
        r->ncalls++;
        off += cuts[i];
        outp += outl;
        r->total += outl;
        if (rv < 0)
            break;
    }

    r->final_outl = 0;
    r->final_rv = EVP_DecodeFinal(ctx, outp, &r->final_outl);
    r->total += r->final_outl;

    if (no_avx2)
        avx2_restore(saved);

    if (in_place && r->total > 0)
        memcpy(r->out, work, r->total);

    ret = 1;

end:
    OPENSSL_free(work);
    EVP_ENCODE_CTX_free(ctx);
    return ret;
}

static int dec_result_eq(const char *desc, const struct dec_result *avx2,
    const struct dec_result *scalar)
{
    int i;

    if (!TEST_int_eq(avx2->ncalls, scalar->ncalls))
        goto err;
    for (i = 0; i < avx2->ncalls; i++) {
        if (!TEST_int_eq(avx2->rv[i], scalar->rv[i])
            || !TEST_int_eq(avx2->outl[i], scalar->outl[i])
            || !TEST_int_eq(avx2->num[i], scalar->num[i])) {
            TEST_info("call %d of %d", i, avx2->ncalls);
            goto err;
        }
    }
    if (!TEST_int_eq(avx2->final_rv, scalar->final_rv)
        || !TEST_int_eq(avx2->final_outl, scalar->final_outl)
        || !TEST_int_eq(avx2->total, scalar->total))
        goto err;
    if (!TEST_mem_eq(avx2->out, avx2->total, scalar->out, scalar->total))
        goto err;

    return 1;

err:
    TEST_info("AVX2 vs scalar mismatch: %s", desc);
    return 0;
}

/*
 * Run one script through both paths and compare
 */
static int compare_paths(const char *desc, const unsigned char *in, int inl,
    const int *cuts, int ncuts, int use_srp,
    int in_place, int outsz,
    unsigned char *decoded, int *decoded_len)
{
    struct dec_result avx2, scalar;
    int ret = 0;

    memset(&avx2, 0, sizeof(avx2));
    memset(&scalar, 0, sizeof(scalar));
    avx2.out = OPENSSL_malloc(outsz > 0 ? outsz : 1);
    scalar.out = OPENSSL_malloc(outsz > 0 ? outsz : 1);

    if (!TEST_ptr(avx2.out) || !TEST_ptr(scalar.out))
        goto end;

    if (!decode_run(&avx2, in, inl, cuts, ncuts, use_srp, in_place, 0)
        || !decode_run(&scalar, in, inl, cuts, ncuts, use_srp, in_place, 1))
        goto end;

    if (!dec_result_eq(desc, &avx2, &scalar))
        goto end;

    if (decoded != NULL && avx2.total > 0)
        memcpy(decoded, avx2.out, avx2.total);
    if (decoded_len != NULL)
        *decoded_len = avx2.total;

    ret = 1;

end:
    OPENSSL_free(avx2.out);
    OPENSSL_free(scalar.out);
    return ret;
}

/*
 * Break base64 data into lines ending in LF, or CRLF when crlf is set.
 * Returns the total length including the line endings.
 */
static int insert_newlines(const unsigned char *b64, int b64len, unsigned char *out,
    int linelen, int crlf)
{
    int si = 0, di = 0;

    while (si < b64len) {
        int chunk = b64len - si;

        if (chunk > linelen)
            chunk = linelen;
        memcpy(out + di, b64 + si, chunk);
        di += chunk;
        si += chunk;
        if (crlf)
            out[di++] = '\r';
        out[di++] = '\n';
    }
    return di;
}

/*
 * Insert random whitespace at random positions.
 * ws_pct is the approximate percentage of output bytes that are WS.
 */
static int insert_random_ws(const unsigned char *b64, int b64len,
    unsigned char *out, uint32_t *seed, int ws_pct)
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
    WS_PEM63, /* newline every 63 chars, WS walks through the block */
    WS_CRLF64, /* \r\n every 64 chars */
    WS_RANDOM_5, /* ~5% random WS insertion */
    WS_RANDOM_20, /* ~20% random WS insertion */
    WS_COUNT
};

static const char *ws_names[] = {
    "none", "pem64", "pem76", "pem63", "crlf64", "random5%", "random20%"
};

/*
 * Apply a WS pattern to raw base64 data.  Returns the output length.
 */
static int apply_ws_pattern(const unsigned char *b64, int b64len,
    unsigned char *out, int ws_type, uint32_t *seed)
{
    switch (ws_type) {
    case WS_NONE:
        memcpy(out, b64, b64len);
        out[b64len] = '\n';
        return b64len + 1;
    case WS_PEM64:
        return insert_newlines(b64, b64len, out, 64, 0);
    case WS_PEM76:
        return insert_newlines(b64, b64len, out, 76, 0);
    case WS_PEM63:
        return insert_newlines(b64, b64len, out, 63, 0);
    case WS_CRLF64:
        return insert_newlines(b64, b64len, out, 64, 1);
    case WS_RANDOM_5:
        return insert_random_ws(b64, b64len, out, seed, 5);
    case WS_RANDOM_20:
        return insert_random_ws(b64, b64len, out, seed, 20);
    default:
        return 0;
    }
}

/*
 * Core test: encode random data, apply a WS pattern, decode through both
 * paths in one call and compare, then check the round trip.
 */
static int run_decode_test(int rawlen, int ws_type, int use_srp,
    int in_place, uint32_t seed)
{
    const char *alpha = use_srp ? "srp" : "std";
    unsigned char *raw = NULL;
    unsigned char *b64 = NULL;
    unsigned char *input = NULL;
    unsigned char *decoded = NULL;
    char desc[128];
    int b64len, inputlen, decoded_len = 0;
    int ret = 0;
    int i;

    raw = OPENSSL_malloc(rawlen + 1);
    b64 = OPENSSL_malloc(rawlen * 2 + 256);
    input = OPENSSL_malloc(rawlen * 3 + 256);
    decoded = OPENSSL_malloc(rawlen > 0 ? rawlen : 1);

    if (!TEST_ptr(raw) || !TEST_ptr(b64) || !TEST_ptr(input)
        || !TEST_ptr(decoded))
        goto end;

    for (i = 0; i < rawlen; i++)
        raw[i] = (unsigned char)(next_u32(&seed) & 0xFF);

    if (use_srp) {
        b64len = encode_block_srp(raw, rawlen, b64);
        if (!TEST_int_ge(b64len, 0))
            goto end;
    } else {
        b64len = EVP_EncodeBlock(b64, raw, rawlen);
    }

    inputlen = apply_ws_pattern(b64, b64len, input, ws_type, &seed);

    snprintf(desc, sizeof(desc), "size=%d ws=%s alpha=%s%s", rawlen,
        ws_names[ws_type], alpha, in_place ? " in-place" : "");

    /* the output buffer is exactly the decoded size, so overshoot traps */
    if (!compare_paths(desc, input, inputlen, &inputlen, 1, use_srp,
            in_place, rawlen, decoded, &decoded_len))
        goto end;

    if (!TEST_int_eq(decoded_len, rawlen)) {
        TEST_info("round-trip length: %s", desc);
        goto end;
    }
    if (rawlen > 0 && !TEST_mem_eq(decoded, decoded_len, raw, rawlen)) {
        TEST_info("round-trip data: %s", desc);
        goto end;
    }

    ret = 1;

end:
    OPENSSL_free(raw);
    OPENSSL_free(b64);
    OPENSSL_free(input);
    OPENSSL_free(decoded);
    return ret;
}

static int test_decode_avx2_vs_scalar(int idx)
{
    int size_idx = idx / WS_COUNT;
    int ws_type = idx % WS_COUNT;

    if (!avx2_switchable()) {
        TEST_skip("no AVX2/scalar comparison available");
        return 1;
    }
    return run_decode_test(test_sizes[size_idx], ws_type, 0, 0,
        (uint32_t)idx);
}

/* Same coverage with out == in, the shape PEM_read_bio_ex uses. */
static int test_decode_in_place(int idx)
{
    int size_idx = idx / WS_COUNT;
    int ws_type = idx % WS_COUNT;

    if (!avx2_switchable()) {
        TEST_skip("no AVX2/scalar comparison available");
        return 1;
    }
    return run_decode_test(test_sizes[size_idx], ws_type, 0, 1,
        (uint32_t)idx);
}

static int test_decode_srp(int idx)
{
    int size_idx = idx / WS_COUNT;
    int ws_type = idx % WS_COUNT;

    if (!avx2_switchable()) {
        TEST_skip("no AVX2/scalar comparison available");
        return 1;
    }
    return run_decode_test(test_sizes[size_idx], ws_type, 1, idx & 1,
        (uint32_t)(idx + NUM_SIZES * WS_COUNT));
}

/*
 * Chunked decode: the same random chunk boundaries through both paths,
 * exercising the AVX2 entry condition against varying ctx->num states.
 */
static int test_decode_chunked(int idx)
{
    int rawlen = test_sizes[idx + LARGE_SIZE_OFFSET];
    uint32_t seed = (uint32_t)idx;
    unsigned char *raw = NULL;
    unsigned char *b64 = NULL;
    unsigned char *pem = NULL;
    unsigned char *decoded = NULL;
    int cuts[MAX_CALLS];
    char desc[64];
    int b64len, pemlen, ncuts = 0, remaining, decoded_len = 0;
    int ret = 0;
    int i;

    if (!avx2_switchable()) {
        TEST_skip("no AVX2/scalar comparison available");
        return 1;
    }

    raw = OPENSSL_malloc(rawlen + 1);
    b64 = OPENSSL_malloc(rawlen * 2 + 256);
    pem = OPENSSL_malloc(rawlen * 3 + 256);
    decoded = OPENSSL_malloc(rawlen);

    if (!TEST_ptr(raw) || !TEST_ptr(b64) || !TEST_ptr(pem)
        || !TEST_ptr(decoded))
        goto end;

    for (i = 0; i < rawlen; i++)
        raw[i] = (unsigned char)(next_u32(&seed) & 0xFF);

    b64len = EVP_EncodeBlock(b64, raw, rawlen);
    pemlen = insert_newlines(b64, b64len, pem, 64, 0);

    remaining = pemlen;
    while (remaining > 0) {
        int chunk = (int)(next_u32(&seed) % 200) + 1;

        /* the last slot takes whatever is left */
        if (chunk > remaining || ncuts == MAX_CALLS - 1)
            chunk = remaining;
        cuts[ncuts++] = chunk;
        remaining -= chunk;
    }

    snprintf(desc, sizeof(desc), "chunked size=%d calls=%d", rawlen, ncuts);
    if (!compare_paths(desc, pem, pemlen, cuts, ncuts, 0, 0, rawlen, decoded, &decoded_len))
        goto end;

    if (!TEST_int_eq(decoded_len, rawlen)
        || !TEST_mem_eq(decoded, decoded_len, raw, rawlen))
        goto end;

    ret = 1;

end:
    OPENSSL_free(raw);
    OPENSSL_free(b64);
    OPENSSL_free(pem);
    OPENSSL_free(decoded);
    return ret;
}

/*
 * Split PEM input at every byte position and compare both paths. This
 * systematically exercises every ctx->num state (0-3 pending base64
 * chars) at the AVX2/scalar handoff boundary.
 *
 * 768 raw bytes -> 1024 base64 chars -> 1040 PEM bytes (16 x 65).
 */
#define PARTIAL_RAW_LEN 768
#define PARTIAL_PEM_LEN 1040

static int test_decode_partial_ctx(int split)
{
    uint32_t seed = 54321;
    unsigned char *raw = NULL;
    unsigned char *b64 = NULL;
    unsigned char *pem = NULL;
    unsigned char *decoded = NULL;
    int cuts[2];
    char desc[64];
    int b64len, pemlen, ncuts = 0, decoded_len = 0;
    int ret = 0;
    int i;

    if (!avx2_switchable()) {
        TEST_skip("no AVX2/scalar comparison available");
        return 1;
    }

    raw = OPENSSL_malloc(PARTIAL_RAW_LEN);
    b64 = OPENSSL_malloc(PARTIAL_RAW_LEN * 2 + 256);
    pem = OPENSSL_malloc(PARTIAL_RAW_LEN * 3 + 256);
    decoded = OPENSSL_malloc(PARTIAL_RAW_LEN);

    if (!TEST_ptr(raw) || !TEST_ptr(b64) || !TEST_ptr(pem)
        || !TEST_ptr(decoded))
        goto end;

    for (i = 0; i < PARTIAL_RAW_LEN; i++)
        raw[i] = (unsigned char)(next_u32(&seed) & 0xFF);

    b64len = EVP_EncodeBlock(b64, raw, PARTIAL_RAW_LEN);
    pemlen = insert_newlines(b64, b64len, pem, 64, 0);

    if (!TEST_int_eq(pemlen, PARTIAL_PEM_LEN))
        goto end;

    if (split > 0)
        cuts[ncuts++] = split;
    if (split < pemlen)
        cuts[ncuts++] = pemlen - split;

    snprintf(desc, sizeof(desc), "split=%d", split);
    if (!compare_paths(desc, pem, pemlen, cuts, ncuts, 0, 0,
            PARTIAL_RAW_LEN, decoded, &decoded_len))
        goto end;

    if (!TEST_int_eq(decoded_len, PARTIAL_RAW_LEN)
        || !TEST_mem_eq(decoded, decoded_len, raw, PARTIAL_RAW_LEN))
        goto end;

    ret = 1;

end:
    OPENSSL_free(raw);
    OPENSSL_free(b64);
    OPENSSL_free(pem);
    OPENSSL_free(decoded);
    return ret;
}

/*
 * EVP_DecodeBlock through both paths, comparing the return value and the
 * bytes touched. The output buffer is sentinel-filled first so that writes
 * made before a rejection are visible.
 */
#define BLK_SENTINEL 0xCC

struct blk_result {
    int rv;
    int written;
    unsigned char *out;
};

static int blk_touched(const unsigned char *b, int n)
{
    int i, last = -1;

    for (i = 0; i < n; i++)
        if (b[i] != BLK_SENTINEL)
            last = i;
    return last + 1;
}

static void decode_block_run(struct blk_result *r, const unsigned char *in,
    int inl, int outsz, int no_avx2)
{
    unsigned int saved = 0;

    memset(r->out, BLK_SENTINEL, outsz);
    if (no_avx2)
        saved = avx2_disable();
    r->rv = EVP_DecodeBlock(r->out, in, inl);
    if (no_avx2)
        avx2_restore(saved);
    r->written = blk_touched(r->out, outsz);
}

/* outsz is the documented bound, 3 bytes per input quad. */
static int compare_block_paths(const char *desc, const unsigned char *in,
    int inl, int outsz, int *rv_out,
    unsigned char *decoded)
{
    struct blk_result avx2, scalar;
    int sz = outsz > 0 ? outsz : 1;
    int ret = 0;

    memset(&avx2, 0, sizeof(avx2));
    memset(&scalar, 0, sizeof(scalar));
    avx2.out = OPENSSL_malloc(sz);
    scalar.out = OPENSSL_malloc(sz);

    if (!TEST_ptr(avx2.out) || !TEST_ptr(scalar.out))
        goto end;

    decode_block_run(&avx2, in, inl, sz, 0);
    decode_block_run(&scalar, in, inl, sz, 1);

    if (!TEST_int_eq(avx2.rv, scalar.rv)
        || !TEST_int_eq(avx2.written, scalar.written)
        || !TEST_mem_eq(avx2.out, sz, scalar.out, sz)) {
        TEST_info("EVP_DecodeBlock AVX2 vs scalar mismatch: %s", desc);
        goto end;
    }

    if (rv_out != NULL)
        *rv_out = avx2.rv;
    if (decoded != NULL && avx2.rv > 0)
        memcpy(decoded, avx2.out, avx2.rv);

    ret = 1;

end:
    OPENSSL_free(avx2.out);
    OPENSSL_free(scalar.out);
    return ret;
}

/* EVP_DecodeBlock round-trip for each test size */
static int test_decode_block(int idx)
{
    int rawlen = test_sizes[idx + 1]; /* skip size 0 */
    uint32_t seed = (uint32_t)idx;
    unsigned char *raw = NULL, *b64 = NULL, *decoded = NULL;
    char desc[64];
    int b64len, outsz, rv = 0;
    int ret = 0, i;

    if (!avx2_switchable()) {
        TEST_skip("no AVX2/scalar comparison available");
        return 1;
    }

    raw = OPENSSL_malloc(rawlen);
    b64 = OPENSSL_malloc(rawlen * 2 + 256);
    /* exactly 3 bytes per input quad, incl. padding */
    outsz = (rawlen + 2) / 3 * 3;
    decoded = OPENSSL_malloc(outsz);

    if (!TEST_ptr(raw) || !TEST_ptr(b64) || !TEST_ptr(decoded))
        goto end;

    for (i = 0; i < rawlen; i++)
        raw[i] = (unsigned char)(next_u32(&seed) & 0xFF);

    b64len = EVP_EncodeBlock(b64, raw, rawlen);

    snprintf(desc, sizeof(desc), "round-trip size=%d", rawlen);
    if (!compare_block_paths(desc, b64, b64len, outsz, &rv, decoded))
        goto end;

    if (!TEST_int_ge(rv, rawlen))
        goto end;
    if (!TEST_mem_eq(decoded, rawlen, raw, rawlen))
        goto end;

    ret = 1;

end:
    OPENSSL_free(raw);
    OPENSSL_free(b64);
    OPENSSL_free(decoded);
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
    /* correct behavior writes nothing before rejecting */
    out = OPENSSL_malloc(1);

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

#define A4 "AAAA"
#define A8 A4 A4
#define A16 A8 A8
#define A32 A16 A16
#define A64 A32 A32
#define A28 A16 A8 A4
#define A30 A28 "AA"
#define A34 A32 "AA"
#define A60 A32 A28
#define A62 A60 "AA"
#define A63 A60 "AAA"
#define SP4 "    "
#define SP8 SP4 SP4
#define SP56 SP8 SP8 SP8 SP8 SP8 SP8 SP8
#define SP57 SP56 " "

/*
 * EVP_DecodeBlock accept/reject vectors. Expected values are the scalar
 * behaviour, which the AVX2 path must match. `written` is how many output
 * bytes the call may touch, which for a rejected input pins down whether
 * anything was written before the rejection.
 */
static const struct block_vec {
    const char *desc;
    const char *in;
    int expected;
    int written;
} block_vecs[] = {
    { "internal spaces", A30 SP4 A30, -1, 21 },
    { "internal space after full block", A64 " " A4, -1, 0 },
    { "leading space", " " A64, 48, 48 },
    { "leading tab", "\t" A64, 48, 48 },
    { "leading LF", "\n" A64, -1, 0 },
    { "leading CR", "\r" A64, -1, 0 },
    { "trailing LF", A64 "\n", 48, 48 },
    { "trailing space", A64 " ", 48, 48 },
    { "trailing LF LF", A64 "\n\n", 48, 48 },
    { "trailing junk", A64 "!", -1, 0 },
    { "invalid char in first quad", "!" A63, -1, 0 },
    { "invalid char in last quad", A63 "!", -1, 45 },
    { "length not a multiple of four", A64 "A", -1, 0 },
    { "length not a multiple of four, two blocks", A64 "\n" A64, -1, 0 },
    { "embedded LF, quad aligned", A64 "\n" A63, -1, 48 },
    { "embedded spaces, quad aligned", A64 SP4 A60, -1, 48 },
    { "padding at the end", A62 "==", 48, 48 },
    { "padding mid-input", A34 "==" A28, 48, 48 },
    { "high bit bytes", A64 "\xC3\xA9\xC3\xA9", -1, 48 },
    { "vertical tab in quad", A60 "\vAAA", -1, 45 },
    { "EOF marker in last quad", A60 "-AAA", -1, 45 },
    { "trailing EOF marker", A64 "-", 48, 48 },
    { "whitespace only", SP56 SP8, 0, 0 },
};

static int check_decode_block(const struct block_vec *v)
{
    static const unsigned char zeros[64];
    unsigned char *out = NULL;
    struct blk_result r;
    int inlen = (int)strlen(v->in);
    /* EVP_DecodeBlock writes at most 3 bytes per full input quad */
    int outsz = inlen / 4 * 3;
    int sz = outsz > 0 ? outsz : 1;
    int ret = 0;

    memset(&r, 0, sizeof(r));
    if (!TEST_ptr(out = OPENSSL_malloc(sz)))
        return 0;
    r.out = out;

    decode_block_run(&r, (const unsigned char *)v->in, inlen, sz, 0);
    if (!TEST_int_eq(r.rv, v->expected)
        || !TEST_int_eq(r.written, v->written)) {
        TEST_info("EVP_DecodeBlock semantics: %s", v->desc);
        goto end;
    }
    /* every accept vector decodes to zero bytes ('A' and '=' map to 0) */
    if (r.rv > 0
        && (!TEST_int_le(r.rv, (int)sizeof(zeros))
            || !TEST_mem_eq(out, r.rv, zeros, r.rv))) {
        TEST_info("EVP_DecodeBlock semantics: %s", v->desc);
        goto end;
    }

    if (avx2_switchable()
        && !compare_block_paths(v->desc, (const unsigned char *)v->in, inlen,
            outsz, NULL, NULL))
        goto end;

    ret = 1;

end:
    OPENSSL_free(out);
    return ret;
}

static int test_decode_block_vec(int i)
{
    return check_decode_block(&block_vecs[i]);
}

/*
 * EVP_DecodeUpdate vectors, one full-buffer call checked against the
 * scalar behaviour. All inputs decode to zero bytes.
 */
static const struct update_vec {
    const char *desc;
    const char *in;
    int rv, outl, num;
} update_vecs[] = {
    { "invalid byte after full lines", A64 "\n" A64 "\n!AAA", -1, 96, 0 },
    { "invalid byte in first block", A63 "\f", -1, 0, 63 },
    { "invalid bytes between whitespace", A64 "\n" A4 "!!!!" SP56, -1, 48, 4 },
    { "invalid byte in stashed leftover", A64 "\nAA" SP57 A4 "!", -1, 48, 6 },
    { "leftover stashed whole", "A " A62, 1, 0, 63 },
    { "stash into padding and trailing data", "A " A62 "=A", -1, 47, 0 },
    { "quad-aligned leftover stashed", "A" SP4 A60, 1, 0, 61 },
    { "high bit byte", A64 "\xC3\xA9", -1, 48, 0 },
    { "EOF marker after full block", A64 "\n-XYZ", 0, 48, 0 },
    { "vertical tab in quad", A64 "\n" A60 "\vAAA", -1, 48, 60 },
};

static int check_update(const struct update_vec *v)
{
    static const unsigned char zeros[128];
    EVP_ENCODE_CTX *ctx = NULL;
    unsigned char *out = NULL;
    int inlen = (int)strlen(v->in);
    int outl = 0, rv, ret = 0;

    /* exactly the expected output size, no room for overshoot */
    out = OPENSSL_malloc(v->outl > 0 ? v->outl : 1);
    if (!TEST_ptr(out) || !TEST_ptr(ctx = EVP_ENCODE_CTX_new()))
        goto end;
    EVP_DecodeInit(ctx);
    rv = EVP_DecodeUpdate(ctx, out, &outl, (const unsigned char *)v->in,
        inlen);
    if (!TEST_int_eq(rv, v->rv) || !TEST_int_eq(outl, v->outl)
        || !TEST_int_eq(EVP_ENCODE_CTX_num(ctx), v->num)
        || !TEST_int_le(outl, (int)sizeof(zeros))
        || !TEST_mem_eq(out, outl, zeros, outl)) {
        TEST_info("EVP_DecodeUpdate semantics: %s", v->desc);
        goto end;
    }

    /*
     * The comparison run also calls EVP_DecodeFinal, which flushes up to
     * 63 stashed characters, so it needs more room than v->outl.
     */
    if (avx2_switchable()
        && !compare_paths(v->desc, (const unsigned char *)v->in, inlen,
            &inlen, 1, 0, 0, v->outl + 64, NULL, NULL))
        goto end;

    ret = 1;

end:
    OPENSSL_free(out);
    EVP_ENCODE_CTX_free(ctx);
    return ret;
}

static int test_decode_update_vec(int i)
{
    return check_update(&update_vecs[i]);
}

/*
 * An invalid byte a long way into whitespace-bearing input. The AVX2
 * general loop compresses whitespace out into a scratch buffer, so it must
 * reject the input without asking the scalar loop to re-read source bytes
 * it has already decoded over. Line lengths are swept so the whitespace
 * lands at every offset within the decoder's 64-byte window.
 */
static int test_decode_error_after_ws(int idx)
{
    static const int linelens[] = { 4, 16, 60, 63, 64, 65, 76, 100 };
    int linelen = linelens[idx / 2];
    int in_place = idx & 1;
    uint32_t seed = (uint32_t)idx;
    unsigned char *raw = NULL, *b64 = NULL, *input = NULL;
    char desc[80];
    int rawlen = 2500, b64len, inputlen, bad_at;
    int ret = 0, i;

    if (!avx2_switchable()) {
        TEST_skip("no AVX2/scalar comparison available");
        return 1;
    }

    raw = OPENSSL_malloc(rawlen);
    b64 = OPENSSL_malloc(rawlen * 2 + 256);
    input = OPENSSL_malloc(rawlen * 3 + 256);

    if (!TEST_ptr(raw) || !TEST_ptr(b64) || !TEST_ptr(input))
        goto end;

    for (i = 0; i < rawlen; i++)
        raw[i] = (unsigned char)(next_u32(&seed) & 0xFF);

    b64len = EVP_EncodeBlock(b64, raw, rawlen);
    inputlen = insert_newlines(b64, b64len, input, linelen, 0);

    /* far enough in that output has already been produced */
    bad_at = inputlen * 3 / 4;
    input[bad_at] = '!';

    snprintf(desc, sizeof(desc), "bad byte at %d, lines of %d%s", bad_at,
        linelen, in_place ? ", in-place" : "");

    /* rawlen is a bound: the input is rejected partway through */
    if (!compare_paths(desc, input, inputlen, &inputlen, 1, 0, in_place,
            rawlen, NULL, NULL))
        goto end;

    ret = 1;

end:
    OPENSSL_free(raw);
    OPENSSL_free(b64);
    OPENSSL_free(input);
    return ret;
}

/*
 * The decoded bytes of an all-'A' payload are themselves base64, and a
 * leading '-' is the PEM end-of-content marker, so replaying input that has
 * been decoded over reports end of content rather than an error: with the
 * buffer shared, EVP_DecodeUpdate returned 0 with *outl 0 where the scalar
 * path returns -1. Callers that only test for a negative return, which is
 * all PEM_read_bio_ex does, would take that as success.
 */
static int test_decode_replayed_output(int idx)
{
    static const int linelens[] = { 60, 63, 64, 76 };
    int linelen = linelens[idx / 2];
    int in_place = idx & 1;
    unsigned char *raw = NULL, *b64 = NULL, *input = NULL;
    char desc[80];
    int rawlen = 2500, b64len, inputlen, bad_at;
    int ret = 0;

    if (!avx2_switchable()) {
        TEST_skip("no AVX2/scalar comparison available");
        return 1;
    }

    raw = OPENSSL_malloc(rawlen);
    b64 = OPENSSL_malloc(rawlen * 2 + 256);
    input = OPENSSL_malloc(rawlen * 3 + 256);

    if (!TEST_ptr(raw) || !TEST_ptr(b64) || !TEST_ptr(input))
        goto end;

    memset(raw, 'A', rawlen);
    raw[0] = '-';

    b64len = EVP_EncodeBlock(b64, raw, rawlen);
    inputlen = insert_newlines(b64, b64len, input, linelen, 0);

    /* late enough that the compress buffer has not drained since the start */
    bad_at = inputlen * 7 / 8;
    input[bad_at] = '!';

    snprintf(desc, sizeof(desc), "replayed output, lines of %d%s", linelen,
        in_place ? ", in-place" : "");

    if (!compare_paths(desc, input, inputlen, &inputlen, 1, 0, in_place,
            rawlen, NULL, NULL))
        goto end;

    ret = 1;

end:
    OPENSSL_free(raw);
    OPENSSL_free(b64);
    OPENSSL_free(input);
    return ret;
}

/*
 * PEM_read_bio_ex hands EVP_DecodeUpdate the same buffer for input and
 * output and treats only a negative return as failure, so a path that
 * reports success after writing over its own input is accepted here.
 */
static int pem_build(unsigned char *out, const unsigned char *raw, int rawlen,
    int linelen, int corrupt_at)
{
    unsigned char *b64 = OPENSSL_malloc(rawlen * 2 + 256);
    int b64len, n = 0;

    if (b64 == NULL)
        return -1;

    b64len = EVP_EncodeBlock(b64, raw, rawlen);
    n += snprintf((char *)out + n, 64, "-----BEGIN TESTDATA-----\n");
    n += insert_newlines(b64, b64len, out + n, linelen, 0);
    if (corrupt_at >= 0)
        out[corrupt_at] = '!';
    n += snprintf((char *)out + n, 64, "-----END TESTDATA-----\n");
    OPENSSL_free(b64);

    return n;
}

static int pem_read(const unsigned char *pem, int pemlen, unsigned char **data,
    long *datalen, int no_avx2)
{
    BIO *bio = BIO_new_mem_buf(pem, pemlen);
    char *name = NULL, *header = NULL;
    unsigned int saved = 0;
    int rv;

    if (bio == NULL)
        return -1;

    if (no_avx2)
        saved = avx2_disable();
    rv = PEM_read_bio_ex(bio, &name, &header, data, datalen, 0);
    if (no_avx2)
        avx2_restore(saved);

    OPENSSL_free(name);
    OPENSSL_free(header);
    BIO_free(bio);
    return rv;
}

/* idx selects the line length; clean and corrupted documents are both read */
static int test_pem_read_bio_in_place(int idx)
{
    static const int linelens[] = { 16, 63, 64, 76 };
    int linelen = linelens[idx];
    uint32_t seed = (uint32_t)idx + 99;
    unsigned char *raw = NULL, *pem = NULL;
    unsigned char *good = NULL, *bad_avx2 = NULL, *bad_scalar = NULL;
    long goodlen = 0, badlen_avx2 = 0, badlen_scalar = 0;
    int rawlen = 2500, pemlen, corrupt_at;
    int rv_avx2, rv_scalar;
    int ret = 0, i;

    if (!avx2_switchable()) {
        TEST_skip("no AVX2/scalar comparison available");
        return 1;
    }

    raw = OPENSSL_malloc(rawlen);
    pem = OPENSSL_malloc(rawlen * 3 + 256);
    if (!TEST_ptr(raw) || !TEST_ptr(pem))
        goto end;

    for (i = 0; i < rawlen; i++)
        raw[i] = (unsigned char)(next_u32(&seed) & 0xFF);

    /* a well-formed document must round-trip */
    pemlen = pem_build(pem, raw, rawlen, linelen, -1);
    if (!TEST_int_gt(pemlen, 0))
        goto end;
    if (!TEST_int_eq(pem_read(pem, pemlen, &good, &goodlen, 0), 1)
        || !TEST_long_eq(goodlen, (long)rawlen)
        || !TEST_mem_eq(good, (int)goodlen, raw, rawlen)) {
        TEST_info("PEM round-trip, lines of %d", linelen);
        goto end;
    }

    /* an invalid byte anywhere in the body must be rejected on both paths */
    for (corrupt_at = 96; corrupt_at < pemlen - 32; corrupt_at += 331) {
        OPENSSL_free(bad_avx2);
        OPENSSL_free(bad_scalar);
        bad_avx2 = bad_scalar = NULL;

        if (!TEST_int_gt(pem_build(pem, raw, rawlen, linelen, corrupt_at), 0))
            goto end;

        rv_avx2 = pem_read(pem, pemlen, &bad_avx2, &badlen_avx2, 0);
        rv_scalar = pem_read(pem, pemlen, &bad_scalar, &badlen_scalar, 1);

        if (!TEST_int_eq(rv_avx2, rv_scalar)
            || !TEST_long_eq(badlen_avx2, badlen_scalar)
            || !TEST_int_eq(rv_avx2, 0)) {
            TEST_info("PEM corrupt at %d, lines of %d", corrupt_at, linelen);
            goto end;
        }
    }

    ret = 1;

end:
    OPENSSL_free(raw);
    OPENSSL_free(pem);
    OPENSSL_free(good);
    OPENSSL_free(bad_avx2);
    OPENSSL_free(bad_scalar);
    return ret;
}

int setup_tests(void)
{
    /* states up front whether the AVX2 path is reached at all */
    ADD_TEST(test_avx2_dispatch);

    /* Standard alphabet: test_sizes x WS patterns */
    ADD_ALL_TESTS(test_decode_avx2_vs_scalar, NUM_SIZES * WS_COUNT);

    /* Same coverage, decoding over the input buffer */
    ADD_ALL_TESTS(test_decode_in_place, NUM_SIZES * WS_COUNT);

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

    /* EVP_DecodeBlock accept/reject parity with the scalar path */
    ADD_ALL_TESTS(test_decode_block_vec,
        (int)(sizeof(block_vecs) / sizeof(block_vecs[0])));

    /* EVP_DecodeUpdate outl and ctx state parity with the scalar path */
    ADD_ALL_TESTS(test_decode_update_vec,
        (int)(sizeof(update_vecs) / sizeof(update_vecs[0])));

    /* invalid byte after whitespace, separate buffers and in place */
    ADD_ALL_TESTS(test_decode_error_after_ws, 16);

    /* input whose decoded bytes would themselves parse as base64 */
    ADD_ALL_TESTS(test_decode_replayed_output, 8);

    /* the in-tree in-place caller */
    ADD_ALL_TESTS(test_pem_read_bio_in_place, 4);

    return 1;
}
