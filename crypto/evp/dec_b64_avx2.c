/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * AVX2 streaming base64 decoder with whitespace handling fallbacks
 *
 * EVP_DecodeUpdate receives raw PEM/SMIME input with newlines embedded
 * in the data. Three loops handle this with decreasing assumptions,
 * falling through to the next when broken:
 *
 *   1. Fast loop: assumes no whitespace at all. The decoder's error
 *      accumulator flags any non-base64 byte, so WS detection is free,
 *      a WS byte simply triggers fallthrough. This is the fastest path
 *      that has zero overhead beyond raw decoding.
 *   2. Skip-WS loop: assumes WS falls between 64-byte blocks, not within
 *      them. Skips WS scalarly, then decodes a clean 64-byte block.
 *      Handles PEM 64-char lines entirely (newline always between blocks).
 *      Falls through for 76-char lines where the newline lands mid-block.
 *   3. General loop: handles WS at arbitrary positions. Detects WS via SIMD,
 *      compresses it out into a stack buffer, and decodes from the buffer
 *      when 64 clean bytes accumulate. A single-byte removal fast path
 *      avoids the full compress cost when a chunk has exactly 1 WS byte
 *      (~83% of chunks for 76-char PEM lines).
 *
 * Whitespace detection, compression routines, and lookup tables are derived
 * from simdutf (https://github.com/simdutf/simdutf), dual-licensed under
 * Apache-2.0 and MIT, based on: D. Lemire & W. Mula, "Base64 encoding and
 * decoding at almost the speed of a memory copy", Software: Practice and
 * Experience 50 (2), 2020.
 */

#include <openssl/evp.h>
#include "dec_b64_avx2.h"

#if defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
#include "b64_avx2_common.h"
#include "dec_b64_avx2_tables.h"

/*
 * Decode one 32-byte vector of base64 ASCII to 6-bit values (standard).
 * Accumulates invalid-byte flags into *err_acc (caller checks once after batch).
 */
OPENSSL_TARGET_AVX2
static inline __m256i decode_std(__m256i input, __m256i *err_acc)
{
    const __m256i mask_0f = _mm256_set1_epi8(0x0F);
    const __m256i lo_nib = _mm256_and_si256(input, mask_0f);
    const __m256i hi_nib = _mm256_and_si256(_mm256_srli_epi32(input, 4),
        mask_0f);

    const __m256i hi_lut = _mm256_setr_epi8(
        0x00, 0x00, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

    /*
     * lo_lut[n] = union of hi-group bits for valid chars with lo nibble n.
     *   0:0x0A 1-9:0x0E A:0x0C B:0x05 C-E:0x04 F:0x05
     */
    const __m256i lo_lut = _mm256_setr_epi8(
        0x0A, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E,
        0x0E, 0x0E, 0x0C, 0x05, 0x04, 0x04, 0x04, 0x05,
        0x0A, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E,
        0x0E, 0x0E, 0x0C, 0x05, 0x04, 0x04, 0x04, 0x05);

    /* Validate. AND of hi and lo class bits must be nonzero. */
    __m256i check = _mm256_and_si256(_mm256_shuffle_epi8(hi_lut, hi_nib),
        _mm256_shuffle_epi8(lo_lut, lo_nib));
    *err_acc = _mm256_or_si256(*err_acc, _mm256_cmpeq_epi8(check, _mm256_setzero_si256()));

    /*
     * Translate ASCII to 6-bit value = input + offset.
     * offset_lut indexed by hi nibble:
     *   hi=2: 16  ('/'=47 -> 47+16=63)
     *   hi=3: 4   ('0'=48 -> 48+4=52)
     *   hi=4,5: -65 ('A'=65 -> 0, 'Z'=90 -> 25)
     *   hi=6,7: -71 ('a'=97 -> 26, 'z'=122 -> 51)
     *
     * '+'=43 also has hi=2, but needs offset 19 (43+19=62), not 16.
     * A separate fixup adds 3 for '+' bytes only (see below).
     */
    const __m256i off_lut = _mm256_setr_epi8(
        0, 0, 16, 4, -65, -65, -71, -71,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 16, 4, -65, -65, -71, -71,
        0, 0, 0, 0, 0, 0, 0, 0);

    __m256i offset = _mm256_shuffle_epi8(off_lut, hi_nib);

    /*
     * '+' (0x2B) and '/' (0x2F) share hi nibble 2, so off_lut[2] can only
     * hold one offset. We pick 16 (correct for '/'), then fix up '+' here:
     * '+' needs 62-43=19, got 16, difference is 3.
     */
    __m256i plus_fix = _mm256_and_si256(
        _mm256_cmpeq_epi8(input, _mm256_set1_epi8('+')),
        _mm256_set1_epi8(3));
    offset = _mm256_add_epi8(offset, plus_fix);

    return _mm256_add_epi8(input, offset);
}
OPENSSL_UNTARGET_AVX2

/*
 * SRP alphabet decode (same structure, different LUT values).
 *   0-9->0-9 A-Z->10-35 a-z->36-61 .->62 /->63
 *
 * No '+' fixup needed: SRP's two hi=2 characters are '.'=46 and '/'=47,
 * and both map correctly with a single offset of 16 (46+16=62, 47+16=63).
 */
OPENSSL_TARGET_AVX2
static inline __m256i decode_srp(__m256i input, __m256i *err_acc)
{
    const __m256i mask_0f = _mm256_set1_epi8(0x0F);
    const __m256i lo_nib = _mm256_and_si256(input, mask_0f);
    const __m256i hi_nib = _mm256_and_si256(_mm256_srli_epi32(input, 4),
        mask_0f);

    const __m256i hi_lut = _mm256_setr_epi8(
        0x00, 0x00, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

    /* SRP lo_lut: differs from standard at indices 0xB (no '+') and 0xE/0xF ('.','/') */
    const __m256i lo_lut = _mm256_setr_epi8(
        0x0A, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E,
        0x0E, 0x0E, 0x0C, 0x04, 0x04, 0x04, 0x05, 0x05,
        0x0A, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E,
        0x0E, 0x0E, 0x0C, 0x04, 0x04, 0x04, 0x05, 0x05);

    __m256i check = _mm256_and_si256(_mm256_shuffle_epi8(hi_lut, hi_nib),
        _mm256_shuffle_epi8(lo_lut, lo_nib));
    *err_acc = _mm256_or_si256(*err_acc, _mm256_cmpeq_epi8(check, _mm256_setzero_si256()));

    /*
     * SRP offsets:
     *   hi=2: 16  ('.'=46->62, '/'=47->63)
     *   hi=3: -48 ('0'=48->0)
     *   hi=4,5: -55 ('A'=65->10)
     *   hi=6,7: -61 ('a'=97->36)
     */
    const __m256i off_lut = _mm256_setr_epi8(
        0, 0, 16, -48, -55, -55, -61, -61,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 16, -48, -55, -55, -61, -61,
        0, 0, 0, 0, 0, 0, 0, 0);

    return _mm256_add_epi8(input, _mm256_shuffle_epi8(off_lut, hi_nib));
}
OPENSSL_UNTARGET_AVX2

/*
 * Pack 6-bit values to bytes. Returns a 256-bit register with 12 valid
 * bytes per lane at [0..11] and 4 garbage bytes at [12..15].
 */
OPENSSL_TARGET_AVX2
static inline __m256i pack(__m256i in)
{
    /* Merge pairs: [00aaaaaa|00bbbbbb] -> [0000aaaa|aabbbbbb] */
    __m256i merged = _mm256_maddubs_epi16(in, _mm256_set1_epi32(0x01400140));

    /* Merge quads: two 16-bit halves -> one 32-bit [00000000|aaaaaabb|bbbbcccc|ccdddddd] */
    __m256i packed = _mm256_madd_epi16(merged, _mm256_set1_epi32(0x00011000));

    /* Byte-shuffle within each lane: extract 3 of 4 bytes per dword -> 12 valid bytes per lane */
    const __m256i shuf = _mm256_setr_epi8(
        2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1,
        2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1);

    return _mm256_shuffle_epi8(packed, shuf);
}
OPENSSL_UNTARGET_AVX2

/*
 * Store 48 decoded bytes via 4 overlapping 128-bit stores.
 * Writes 4 garbage bytes at [48..51] past valid output.
 */
OPENSSL_TARGET_AVX2
static inline void store_48(unsigned char *out, __m256i p0, __m256i p1)
{
    _mm_storeu_si128((__m128i *)out, _mm256_castsi256_si128(p0));
    _mm_storeu_si128((__m128i *)(out + 12), _mm256_extracti128_si256(p0, 1));
    _mm_storeu_si128((__m128i *)(out + 24), _mm256_castsi256_si128(p1));
    _mm_storeu_si128((__m128i *)(out + 36), _mm256_extracti128_si256(p1, 1));
}
OPENSSL_UNTARGET_AVX2

/*
 * Store 48 decoded bytes without overshoot. Second half goes through
 * a stack buffer so the 4 trailing garbage bytes never reach the
 * output. Used for the last block near the end of the output buffer.
 */
OPENSSL_TARGET_AVX2
static inline void store_48_safe(unsigned char *out, __m256i p0, __m256i p1)
{
    unsigned char tmp[28];

    _mm_storeu_si128((__m128i *)out, _mm256_castsi256_si128(p0));
    _mm_storeu_si128((__m128i *)(out + 12), _mm256_extracti128_si256(p0, 1));
    _mm_storeu_si128((__m128i *)tmp, _mm256_castsi256_si128(p1));
    _mm_storeu_si128((__m128i *)(tmp + 12), _mm256_extracti128_si256(p1, 1));
    memcpy(out + 24, tmp, 24);
}
OPENSSL_UNTARGET_AVX2

/* Portable popcount for 32-bit values using BitsSetTable256mul2 */
static inline int popcount32(uint32_t x)
{
    return (BitsSetTable256mul2[x & 0xFF] + BitsSetTable256mul2[(x >> 8) & 0xFF] + BitsSetTable256mul2[(x >> 16) & 0xFF] + BitsSetTable256mul2[x >> 24]) >> 1;
}

/*
 * Compress 16 bytes: remove bytes whose corresponding mask bits are set.
 * Always stores 16 bytes at output (trailing bytes may be garbage).
 */
OPENSSL_TARGET_AVX2
static inline void compress128(__m128i data, uint16_t mask,
    unsigned char *output)
{
    uint8_t mask1, mask2;
    __m128i shufmask, pruned, compactmask;
    int pop1;

    if (mask == 0) {
        _mm_storeu_si128((__m128i *)output, data);
        return;
    }
    mask1 = (uint8_t)mask;
    mask2 = (uint8_t)(mask >> 8);
    shufmask = _mm_set_epi64x(
        (long long)thintable_epi8[mask2],
        (long long)thintable_epi8[mask1]);
    shufmask = _mm_add_epi8(shufmask,
        _mm_set_epi32(0x08080808, 0x08080808, 0, 0));
    pruned = _mm_shuffle_epi8(data, shufmask);
    pop1 = BitsSetTable256mul2[mask1];
    compactmask = _mm_loadu_si128(
        (const __m128i *)(pshufb_combine_table + pop1 * 8));
    _mm_storeu_si128((__m128i *)output, _mm_shuffle_epi8(pruned, compactmask));
}
OPENSSL_UNTARGET_AVX2

/*
 * Compress 32 bytes (one __m256i), removing bytes whose mask bits are set.
 */
OPENSSL_TARGET_AVX2
static inline void compress256(__m256i data, uint32_t mask,
    unsigned char *output)
{
    if (mask == 0) {
        _mm256_storeu_si256((__m256i *)output, data);
        return;
    }
    compress128(_mm256_castsi256_si128(data), (uint16_t)mask, output);
    compress128(_mm256_extracti128_si256(data, 1), (uint16_t)(mask >> 16),
        output + 16 - popcount32(mask & 0xFFFF));
}
OPENSSL_UNTARGET_AVX2

/*
 * Remove exactly one whitespace byte from a 64-byte block (v0 || v1).
 * mask must have exactly one bit set. Writes 63 valid bytes at output
 * (with up to 1 byte of trailing garbage from overlapping stores).
 */
OPENSSL_TARGET_AVX2
static inline void compress_block_single(__m256i v0, __m256i v1, uint64_t mask,
    unsigned char *output)
{
    int pos64, pos, lane;
    __m128i threshold, iota, gt, sh;

#ifdef __GNUC__
    pos64 = __builtin_ctzll(mask);
#else
    pos64 = 0;
    {
        uint64_t tmp = mask;

        while ((tmp & 1) == 0) {
            pos64++;
            tmp >>= 1;
        }
    }
#endif
    pos = pos64 & 0xf;
    lane = pos64 >> 4;

    threshold = _mm_set1_epi8((char)(pos - 1));
    iota = _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    gt = _mm_cmpgt_epi8(iota, threshold);
    sh = _mm_sub_epi8(iota, gt);

    /*
     * Input: v0 = [L0(16) | L1(16)], v1 = [L2(16) | L3(16)].
     * Output: 63 contiguous bytes. sh(Lk) = shuffle that removes
     * the WS byte, yielding 15 valid bytes + 1 garbage byte.
     * The next store overlaps by 1 to cover the garbage.
     */
    switch (lane) {
    case 0: {
        __m128i lane0 = _mm256_castsi256_si128(v0);
        __m128i lane1 = _mm256_extracti128_si256(v0, 1);
        _mm_storeu_si128((__m128i *)output,
            _mm_shuffle_epi8(lane0, sh));
        _mm_storeu_si128((__m128i *)(output + 15), lane1);
        _mm256_storeu_si256((__m256i *)(output + 31), v1);
        break;
    }
    case 1: {
        __m128i lane0 = _mm256_castsi256_si128(v0);
        __m128i lane1 = _mm256_extracti128_si256(v0, 1);
        _mm_storeu_si128((__m128i *)output, lane0);
        _mm_storeu_si128((__m128i *)(output + 16),
            _mm_shuffle_epi8(lane1, sh));
        _mm256_storeu_si256((__m256i *)(output + 31), v1);
        break;
    }
    case 2: {
        __m128i lane2 = _mm256_castsi256_si128(v1);
        __m128i lane3 = _mm256_extracti128_si256(v1, 1);
        _mm256_storeu_si256((__m256i *)output, v0);
        _mm_storeu_si128((__m128i *)(output + 32),
            _mm_shuffle_epi8(lane2, sh));
        _mm_storeu_si128((__m128i *)(output + 47), lane3);
        break;
    }
    case 3: {
        __m128i lane2 = _mm256_castsi256_si128(v1);
        __m128i lane3 = _mm256_extracti128_si256(v1, 1);
        _mm256_storeu_si256((__m256i *)output, v0);
        _mm_storeu_si128((__m128i *)(output + 32), lane2);
        _mm_storeu_si128((__m128i *)(output + 48),
            _mm_shuffle_epi8(lane3, sh));
        break;
    }
    }
}
OPENSSL_UNTARGET_AVX2

/*
 * Decode 64 buffer bytes (pure base64 ASCII) into 48 output bytes.
 * Returns 0 on success, -1 on invalid character.
 */
OPENSSL_TARGET_AVX2
static inline int decode_buffer_block(const unsigned char *buf,
    unsigned char *out,
    int use_srp,
    unsigned char *safe_end)
{
    __m256i bv0 = _mm256_loadu_si256((const __m256i *)buf);
    __m256i bv1 = _mm256_loadu_si256((const __m256i *)(buf + 32));
    __m256i err = _mm256_setzero_si256();
    __m256i d0, d1, p0, p1;

    if (use_srp) {
        d0 = decode_srp(bv0, &err);
        p0 = pack(d0);
        d1 = decode_srp(bv1, &err);
        p1 = pack(d1);
    } else {
        d0 = decode_std(bv0, &err);
        p0 = pack(d0);
        d1 = decode_std(bv1, &err);
        p1 = pack(d1);
    }

    if (_mm256_movemask_epi8(err) != 0)
        return -1;

    if (out >= safe_end)
        store_48_safe(out, p0, p1);
    else
        store_48(out, p0, p1);
    return 0;
}
OPENSSL_UNTARGET_AVX2

/*
 * AVX2 streaming base64 decoder with whitespace handling.
 *
 * Three loops in priority order:
 *   1. 128-byte fast loop: clean data, no WS/stop detection needed.
 *      decode_std's error accumulator catches everything. 128 bytes
 *      (4 vectors) per iteration with interleaved decode and store.
 *   2. Skip-WS loop: skips WS scalarly, then decodes 64 clean bytes.
 *      Handles PEM 64-char lines and any remaining clean data after loop 1.
 *   3. General loop: arbitrary WS patterns. SIMD WS detection +
 *      compression into a stack buffer, decoded on flush.
 *      Three sub-paths: single-WS compress, general compress, copy.
 *
 * Returns decoded byte count (>= 0), or -1 on error.
 * Sets *consumed_out to the number of input bytes consumed.
 * Stores 0-3 leftover base64 bytes in ctx->enc_data / ctx->num.
 */
OPENSSL_TARGET_AVX2
int decode_base64_avx2(EVP_ENCODE_CTX *ctx, unsigned char *dst,
    const unsigned char *src, int srclen,
    int *consumed_out)
{
    unsigned char *out = dst;
    int consumed = 0;
    const int use_srp = (ctx != NULL
        && (ctx->flags & EVP_ENCODE_CTX_USE_SRP_ALPHABET) != 0);

    /*
     * Stack buffer for whitespace-compressed data.
     * 512 bytes allows a read pointer to advance without frequent
     * memmove. We decode from buf_rpos whenever 64 bytes are
     * available and only shift when the read pointer gets high.
     */
    unsigned char buffer[512];
    unsigned char *bufferptr = buffer;
    int buf_rpos = 0;

    /*
     * Safe zone boundary: beyond this point, store_48 would overshoot
     * the output buffer. Conservative: assumes maximum output of 3/4
     * of input (clean base64, no whitespace).
     */
    int max_out = (srclen / 4) * 3;
    unsigned char *safe_end = max_out >= 52 ? dst + max_out - 52 : dst;

    /*
     * Tight inner loop for clean data (no WS, no stops).
     * Processes 128 bytes (4 vectors) per iteration.
     *
     * decode_std/decode_srp already flag WS, '=', '-', and all other
     * non-base64 bytes via the error accumulator, so no separate
     * WS/stop detection is needed. We just decode and check the
     * error. Zero overhead for the common clean path.
     *
     * We check errors per 64-byte half: if the first half has an
     * error, we don't store anything and fall through. If only the
     * second half has an error, we commit the first half's output.
     */
    while (consumed + 128 <= srclen) {
        __m256i v0, v1, v2, v3;
        __m256i err01 = _mm256_setzero_si256();
        __m256i err23 = _mm256_setzero_si256();
        __m256i d0, d1, d2, d3, p0, p1, p2, p3;

        /*
         * Interleaved load-decode: give the OoO engine independent
         * work chains across load and execution ports.
         */
        v0 = _mm256_loadu_si256((const __m256i *)(src + consumed));
        v1 = _mm256_loadu_si256((const __m256i *)(src + consumed + 32));
        if (use_srp) {
            d0 = decode_srp(v0, &err01);
            d1 = decode_srp(v1, &err01);
        } else {
            d0 = decode_std(v0, &err01);
            d1 = decode_std(v1, &err01);
        }
        p0 = pack(d0);
        p1 = pack(d1);

        /* Check first 64 bytes, bail out on error */
        if (_mm256_movemask_epi8(err01) != 0)
            break;

        v2 = _mm256_loadu_si256((const __m256i *)(src + consumed + 64));
        v3 = _mm256_loadu_si256((const __m256i *)(src + consumed + 96));

        /* Store first half while second half decodes */
        if (out >= safe_end)
            store_48_safe(out, p0, p1);
        else
            store_48(out, p0, p1);

        if (use_srp) {
            d2 = decode_srp(v2, &err23);
            d3 = decode_srp(v3, &err23);
        } else {
            d2 = decode_std(v2, &err23);
            d3 = decode_std(v3, &err23);
        }
        p2 = pack(d2);
        p3 = pack(d3);

        /* Check second 64 bytes, if error commit first half only */
        if (_mm256_movemask_epi8(err23) != 0) {
            out += 48;
            consumed += 64;
            break;
        }

        if (out + 48 >= safe_end)
            store_48_safe(out + 48, p2, p3);
        else
            store_48(out + 48, p2, p3);
        out += 96;
        consumed += 128;
    }

    /*
     * Skip-WS-then-decode loop for PEM 64-char lines.
     * Skip WS scalarly, then decode 64 clean bytes directly.
     * No buffer, no compress. Falls through to the general loop if
     * WS appears mid-block.
     */
    while (bufferptr == buffer && consumed < srclen) {
        __m256i v0, v1, err, d0, d1, p0, p1;

        /* Skip inter-line whitespace (typically 1 LF per PEM line) */
        while (consumed < srclen) {
            unsigned char c = src[consumed];

            if (c != '\n' && c != '\r' && c != ' ' && c != '\t')
                break;
            consumed++;
        }

        if (consumed + 64 > srclen)
            break;

        v0 = _mm256_loadu_si256((const __m256i *)(src + consumed));
        v1 = _mm256_loadu_si256((const __m256i *)(src + consumed + 32));
        err = _mm256_setzero_si256();

        if (use_srp) {
            d0 = decode_srp(v0, &err);
            p0 = pack(d0);
            d1 = decode_srp(v1, &err);
            p1 = pack(d1);
        } else {
            d0 = decode_std(v0, &err);
            p0 = pack(d0);
            d1 = decode_std(v1, &err);
            p1 = pack(d1);
        }

        /* Non-base64 byte in block, either WS mid-block or stop char */
        if (_mm256_movemask_epi8(err) != 0)
            break;

        if (out >= safe_end)
            store_48_safe(out, p0, p1);
        else
            store_48(out, p0, p1);
        out += 48;
        consumed += 64;
    }

    /*
     * General loop: handles whitespace, stop characters, and buffer
     * management. Entered when WS appears mid-block or after the
     * skip-WS loop encounters non-standard formatting.
     */
    {
        /* WS detection via low nibble (each WS char has a unique one) */
        const __m256i ws_tbl = _mm256_setr_epi8(
            0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0x09, 0x0A, 0, 0, 0x0D, 0, 0,
            0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0x09, 0x0A, 0, 0, 0x0D, 0, 0);
        const __m256i eq_char = _mm256_set1_epi8('=');
        const __m256i dash_char = _mm256_set1_epi8('-');

        while (consumed + 64 <= srclen) {
            __m256i v0 = _mm256_loadu_si256((const __m256i *)(src + consumed));
            __m256i v1 = _mm256_loadu_si256((const __m256i *)(src + consumed + 32));

            /* Detect whitespace */
            __m256i ws0 = _mm256_cmpeq_epi8(_mm256_shuffle_epi8(ws_tbl, v0), v0);
            __m256i ws1 = _mm256_cmpeq_epi8(_mm256_shuffle_epi8(ws_tbl, v1), v1);
            uint32_t wsmask0 = (uint32_t)_mm256_movemask_epi8(ws0);
            uint32_t wsmask1 = (uint32_t)_mm256_movemask_epi8(ws1);
            uint64_t wsmask = (uint64_t)wsmask0 | ((uint64_t)wsmask1 << 32);

            /* Detect stop chars, '=' (padding) or '-' (PEM EOF marker) */
            __m256i stop0 = _mm256_or_si256(
                _mm256_cmpeq_epi8(v0, eq_char),
                _mm256_cmpeq_epi8(v0, dash_char));
            __m256i stop1 = _mm256_or_si256(
                _mm256_cmpeq_epi8(v1, eq_char),
                _mm256_cmpeq_epi8(v1, dash_char));
            if ((_mm256_movemask_epi8(stop0)
                    | _mm256_movemask_epi8(stop1))
                != 0)
                break;

            if (wsmask != 0) {
                if ((wsmask & (wsmask - 1)) == 0) {
                    /* Exactly 1 WS byte (PEM hot path) */
                    compress_block_single(v0, v1, wsmask, bufferptr);
                    bufferptr += 63;
                } else {
                    /* General compress */
                    compress256(v0, wsmask0, bufferptr);
                    bufferptr += 32 - popcount32(wsmask0);
                    compress256(v1, wsmask1, bufferptr);
                    bufferptr += 32 - popcount32(wsmask1);
                }
            } else {
                /* No WS, but buffer has pending data from earlier WS blocks.
                 * Must go through the buffer to keep output in input order. */
                _mm256_storeu_si256((__m256i *)bufferptr, v0);
                _mm256_storeu_si256((__m256i *)(bufferptr + 32), v1);
                bufferptr += 64;
            }

            consumed += 64;

            /*
             * Flush: decode every complete 64-byte block immediately.
             * This interleaves compress and decode, keeping buffer data
             * hot in L1 rather than accumulating a large cold batch.
             */
            {
                int buf_avail = (int)(bufferptr - buffer) - buf_rpos;

                while (buf_avail >= 64) {
                    if (decode_buffer_block(buffer + buf_rpos, out, use_srp, safe_end) < 0) {
                        *consumed_out = consumed;
                        return -1;
                    }
                    out += 48;
                    buf_rpos += 64;
                    buf_avail -= 64;
                }
                /* Shift down when read pointer gets high */
                if (buf_rpos >= 256) {
                    memmove(buffer, buffer + buf_rpos, buf_avail);
                    bufferptr = buffer + buf_avail;
                    buf_rpos = 0;
                }
            }
        }
    } /* end general loop scope */

    /* Handle leftover < 64 bytes remaining in the compress buffer */
    {
        int buf_avail = (int)(bufferptr - buffer) - buf_rpos;

        if (buf_avail > 0) {
            int complete = buf_avail & ~3;

            if (complete > 0) {
                int decoded = evp_decodeblock_int(ctx, out, buffer + buf_rpos,
                    complete, 0);
                if (decoded < 0) {
                    *consumed_out = consumed;
                    return -1;
                }
                out += decoded;
            }
            memcpy(ctx->enc_data, buffer + buf_rpos + complete,
                buf_avail - complete);
            ctx->num = buf_avail - complete;
        } else {
            ctx->num = 0;
        }
    }

    *consumed_out = consumed;
    return (int)(out - dst);
}
OPENSSL_UNTARGET_AVX2
#endif
