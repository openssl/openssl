/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include "enc_b64_scalar.h"
#include "enc_b64_avx2.h"
#include "internal/cryptlib.h"
#include "crypto/evp.h"
#include "evp_local.h"

#if defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
#if !defined(_M_ARM64EC)
#define STRINGIFY_IMPLEMENTATION_(a) #a
#define STRINGIFY(a) STRINGIFY_IMPLEMENTATION_(a)

#ifdef __clang__
/*
 * clang does not have GCC push pop
 * warning: clang attribute push can't be used within a namespace in clang up
 * til 8.0 so OPENSSL_TARGET_REGION and OPENSSL_UNTARGET_REGION must be
 * outside* of a namespace.
 */
#define OPENSSL_TARGET_REGION(T)                                       \
    _Pragma(STRINGIFY(clang attribute push(__attribute__((target(T))), \
        apply_to = function)))
#define OPENSSL_UNTARGET_REGION _Pragma("clang attribute pop")
#elif defined(__GNUC__)
#define OPENSSL_TARGET_REGION(T) \
    _Pragma("GCC push_options") _Pragma(STRINGIFY(GCC target(T)))
#define OPENSSL_UNTARGET_REGION _Pragma("GCC pop_options")
#endif /* clang then gcc */

/* Default target region macros don't do anything. */
#ifndef OPENSSL_TARGET_REGION
#define OPENSSL_TARGET_REGION(T)
#define OPENSSL_UNTARGET_REGION
#endif

#define OPENSSL_TARGET_AVX2 \
    OPENSSL_TARGET_REGION("avx2")
#define OPENSSL_UNTARGET_AVX2 OPENSSL_UNTARGET_REGION

/*
 * Ensure this whole block is compiled with AVX2 enabled on GCC.
 * Clang/MSVC will just ignore these pragmas.
 */

#include <assert.h>
#include <string.h>
#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>

OPENSSL_TARGET_AVX2
static __m256i lookup_pshufb_std(__m256i input)
{
    __m256i result = _mm256_subs_epu8(input, _mm256_set1_epi8(51));
    const __m256i less = _mm256_cmpgt_epi8(_mm256_set1_epi8(26), input);

    result = _mm256_or_si256(result, _mm256_and_si256(less, _mm256_set1_epi8(13)));
    __m256i shift_LUT = _mm256_setr_epi8('a' - 26, '0' - 52, '0' - 52, '0' - 52, '0' - 52,
        '0' - 52, '0' - 52,
        '0' - 52, '0' - 52, '0' - 52, '0' - 52, '+' - 62,
        '/' - 63, 'A', 0, 0,
        'a' - 26, '0' - 52, '0' - 52, '0' - 52, '0' - 52,
        '0' - 52, '0' - 52,
        '0' - 52, '0' - 52, '0' - 52, '0' - 52, '+' - 62,
        '/' - 63, 'A', 0, 0);

    result = _mm256_shuffle_epi8(shift_LUT, result);
    return _mm256_add_epi8(result, input);
}
OPENSSL_UNTARGET_AVX2

OPENSSL_TARGET_AVX2
static inline __m256i lookup_pshufb_srp(__m256i input)
{
    const __m256i zero = _mm256_setzero_si256();
    const __m256i hi = _mm256_set1_epi8((char)0x80);
    __m256i invalid = _mm256_or_si256(_mm256_cmpgt_epi8(zero, input),
        _mm256_cmpgt_epi8(input,
            _mm256_set1_epi8(63)));
    __m256i idx = _mm256_setzero_si256();

    idx = _mm256_sub_epi8(idx, _mm256_cmpgt_epi8(input, _mm256_set1_epi8(9)));
    idx = _mm256_sub_epi8(idx, _mm256_cmpgt_epi8(input, _mm256_set1_epi8(35)));
    idx = _mm256_blendv_epi8(idx, _mm256_set1_epi8(3),
        _mm256_cmpeq_epi8(input, _mm256_set1_epi8(62)));
    idx = _mm256_blendv_epi8(idx, _mm256_set1_epi8(4),
        _mm256_cmpeq_epi8(input, _mm256_set1_epi8(63)));

    /* Zero-out invalid lanes via PSHUFB's high-bit mechanism */
    idx = _mm256_or_si256(idx, _mm256_and_si256(invalid, hi));

    const __m256i shift_LUT = _mm256_setr_epi8('0' - 0, 'A' - 10, 'a' - 36, '.' - 62, '/' - 63, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        '0' - 0, 'A' - 10, 'a' - 36, '.' - 62, '/' - 63, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0);

    __m256i shift = _mm256_shuffle_epi8(shift_LUT, idx);
    __m256i ascii = _mm256_add_epi8(shift, input);
    return ascii;
}
OPENSSL_UNTARGET_AVX2

OPENSSL_TARGET_AVX2
static inline __m256i shift_right_zeros(__m256i v, int n)
{
    switch (n) {
    case 0:
        return v;
    case 1:
        return _mm256_srli_si256(v, 1);
    case 2:
        return _mm256_srli_si256(v, 2);
    case 3:
        return _mm256_srli_si256(v, 3);
    case 4:
        return _mm256_srli_si256(v, 4);
    case 5:
        return _mm256_srli_si256(v, 5);
    case 6:
        return _mm256_srli_si256(v, 6);
    case 7:
        return _mm256_srli_si256(v, 7);
    case 8:
        return _mm256_srli_si256(v, 8);
    case 9:
        return _mm256_srli_si256(v, 9);
    case 10:
        return _mm256_srli_si256(v, 10);
    case 11:
        return _mm256_srli_si256(v, 11);
    case 12:
        return _mm256_srli_si256(v, 12);
    case 13:
        return _mm256_srli_si256(v, 13);
    case 14:
        return _mm256_srli_si256(v, 14);
    case 15:
        return _mm256_srli_si256(v, 15);
    default:
        return _mm256_setzero_si256();
    }
}
OPENSSL_UNTARGET_AVX2

OPENSSL_TARGET_AVX2
static inline __m256i shift_left_zeros(__m256i v, int n)
{
    switch (n) {
    case 0:
        return v;
    case 1:
        return _mm256_slli_si256(v, 1);
    case 2:
        return _mm256_slli_si256(v, 2);
    case 3:
        return _mm256_slli_si256(v, 3);
    case 4:
        return _mm256_slli_si256(v, 4);
    case 5:
        return _mm256_slli_si256(v, 5);
    case 6:
        return _mm256_slli_si256(v, 6);
    case 7:
        return _mm256_slli_si256(v, 7);
    case 8:
        return _mm256_slli_si256(v, 8);
    case 9:
        return _mm256_slli_si256(v, 9);
    case 10:
        return _mm256_slli_si256(v, 10);
    case 11:
        return _mm256_slli_si256(v, 11);
    case 12:
        return _mm256_slli_si256(v, 12);
    case 13:
        return _mm256_slli_si256(v, 13);
    case 14:
        return _mm256_slli_si256(v, 14);
    case 15:
        return _mm256_slli_si256(v, 15);
    case 16:
        return _mm256_setzero_si256();
    default:
        return _mm256_setzero_si256();
    }
}
OPENSSL_UNTARGET_AVX2

static const uint8_t shuffle_masks[16][16] = {
    { 0x80, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 },
    { 0, 0x80, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 },
    { 0, 1, 0x80, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 },
    { 0, 1, 2, 0x80, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 },
    { 0, 1, 2, 3, 0x80, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 },
    { 0, 1, 2, 3, 4, 0x80, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 },
    { 0, 1, 2, 3, 4, 5, 0x80, 6, 7, 8, 9, 10, 11, 12, 13, 14 },
    { 0, 1, 2, 3, 4, 5, 6, 0x80, 7, 8, 9, 10, 11, 12, 13, 14 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 0x80, 8, 9, 10, 11, 12, 13, 14 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 0x80, 9, 10, 11, 12, 13, 14 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x80, 10, 11, 12, 13, 14 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x80, 11, 12, 13, 14 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x80, 12, 13, 14 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x80, 13, 14 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0x80, 14 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0x80 }
};

/**
 * Insert a line feed character in the 64-byte input at index K in [0,32).
 */
OPENSSL_TARGET_AVX2
static inline __m256i insert_line_feed32(__m256i input, int K)
{
    __m256i line_feed_vector = _mm256_set1_epi8('\n');
    __m128i identity = _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

    if (K >= 16) {
        __m128i maskhi = _mm_loadu_si128((__m128i *)shuffle_masks[K - 16]);
        __m256i mask = _mm256_set_m128i(maskhi, identity);
        __m256i lf_pos = _mm256_cmpeq_epi8(mask, _mm256_set1_epi8((char)0x80));
        __m256i shuffled = _mm256_shuffle_epi8(input, mask);
        __m256i result = _mm256_blendv_epi8(shuffled, line_feed_vector, lf_pos);

        return result;
    }
    /* Shift input right by 1 byte */
    __m256i shift = _mm256_alignr_epi8(input, _mm256_permute2x128_si256(input, input, 0x21),
        15);
    input = _mm256_blend_epi32(input, shift, 0xF0);
    __m128i masklo = _mm_loadu_si128((__m128i *)shuffle_masks[K]);
    __m256i mask = _mm256_set_m128i(identity, masklo);
    __m256i lf_pos = _mm256_cmpeq_epi8(mask, _mm256_set1_epi8((char)0x80));
    __m256i shuffled = _mm256_shuffle_epi8(input, mask);
    __m256i result = _mm256_blendv_epi8(shuffled, line_feed_vector, lf_pos);
    return result;
}
OPENSSL_UNTARGET_AVX2

OPENSSL_TARGET_AVX2
static inline size_t ins_nl_gt32(__m256i v, uint8_t *out, int stride,
    int *wrap_cnt)
{
    const int until_nl = stride - *wrap_cnt;

    if (until_nl > 32) {
        _mm256_storeu_si256((__m256i *)out, v);

        *wrap_cnt += 32;
        return 32;
    }

    if (until_nl == 32) {
        _mm256_storeu_si256((__m256i *)out, v);

        out[32] = '\n';
        *wrap_cnt = 0;
        return 33;
    }

    const uint8_t last = (uint8_t)_mm256_extract_epi8(v, 31);
    const __m256i with_lf = insert_line_feed32(v, until_nl);
    _mm256_storeu_si256((__m256i *)out, with_lf);
    out[32] = last;

    *wrap_cnt = 32 - until_nl;
    return 33;
}
OPENSSL_UNTARGET_AVX2

OPENSSL_TARGET_AVX2
static inline size_t insert_nl_gt16(const __m256i v0,
    uint8_t *output,
    int wrap_max, int *wrap_cnt)
{
    uint8_t *out = output;
    int wrap_rem = wrap_max - *wrap_cnt;
    _mm256_storeu_si256((__m256i *)(output), v0);

    if (wrap_rem > 32) {
        *wrap_cnt += 32;
        return 32;
    }

    __m256i all_ff_mask = _mm256_set1_epi8((char)0xFF);

    __m256i mask_second_lane = _mm256_setr_epi8(0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        (char)0xFF, (char)0xFF, (char)0xFF, (char)0xFF,
        (char)0xFF, (char)0xFF, (char)0xFF, (char)0xFF,
        (char)0xFF, (char)0xFF, (char)0xFF, (char)0xFF,
        (char)0xFF, (char)0xFF, (char)0xFF, (char)0xFF);

    __m256i blended_0L = v0;
    int surplus_0 = wrap_rem < 16 ? 1 : 0;
    if (surplus_0 == 1) {
        __m256i shifted_0_L = shift_left_zeros(shift_right_zeros(v0, wrap_rem),
            wrap_rem + surplus_0);
        __m256i mask_shifted_0_L = shift_left_zeros(all_ff_mask, wrap_rem + surplus_0);
        __m256i mask = _mm256_or_si256(mask_shifted_0_L, mask_second_lane);
        __m256i shifted_1_L = shift_left_zeros(v0, 1);
        __m256i shifted = _mm256_blendv_epi8(shifted_0_L, shifted_1_L, mask);

        blended_0L = _mm256_blendv_epi8(v0, shifted, mask);
        _mm256_storeu_si256((__m256i *)(output), blended_0L);
        wrap_rem += wrap_max;
    }

    int surplus_1 = (wrap_rem >= 16 && wrap_rem < 32) ? 1 : 0;
    int last_of_1L = _mm256_extract_epi8(v0, 31);

    if (surplus_1 == 1) {
        uint16_t sec_last_of_1L = _mm256_extract_epi8(v0, 30);
        int wrap_rem_1 = wrap_rem - 16;
        __m256i shifted_1_L = shift_left_zeros(shift_right_zeros(v0, wrap_rem_1),
            wrap_rem_1 + surplus_0 + surplus_1);
        __m256i mask_shifted_1_L = shift_left_zeros(all_ff_mask, wrap_rem_1 + surplus_0 + surplus_1);
        __m256i mask = _mm256_and_si256(mask_second_lane, mask_shifted_1_L);
        __m256i blended_1L = _mm256_blendv_epi8(blended_0L, shifted_1_L, mask);
        _mm256_storeu_si256((__m256i *)(output), blended_1L);

        output[wrap_rem + surplus_0] = '\n';
        output[31 + surplus_0] = (uint8_t)sec_last_of_1L;
        output[31 + surplus_0 + surplus_1] = last_of_1L;
    }

    if (surplus_0 == 1) {
        output[wrap_rem - wrap_max] = '\n';
        output[16] = _mm256_extract_epi8(v0, 15);
        output[31 + surplus_0 + surplus_1] = last_of_1L;
    }

    *wrap_cnt = wrap_rem > 32 ? 32 - (wrap_rem - wrap_max) : 32 - wrap_rem;

    int nl_at_end = 0;
    if (*wrap_cnt == wrap_max || *wrap_cnt == 0) {
        *wrap_cnt = 0;
        output[32 + surplus_0 + surplus_1] = '\n';
        nl_at_end = 1;
    }

    out += 32 + surplus_0 + surplus_1 + nl_at_end;
    size_t written = (size_t)(out - output);

    return written;
}
OPENSSL_UNTARGET_AVX2

OPENSSL_TARGET_AVX2
static inline size_t insert_nl_2nd_vec_stride_12(const __m256i v0,
    uint8_t *output,
    int dummy_stride,
    int *wrap_cnt)
{
    __m256i shuffling_mask = _mm256_setr_epi8(0, 1, 2, 3, (char)0xFF, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
        (char)0xFF,
        (char)0xFF, (char)0xFF, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, (char)0xFF,
        12);
    __m256i shuffled = _mm256_shuffle_epi8(v0, shuffling_mask);

    _mm256_storeu_si256((__m256i *)(output + 0), shuffled);

    int16_t rem_1_L_ext = _mm256_extract_epi16(v0, 7);
    int8_t rem_2_L_ext_P1 = _mm256_extract_epi8(v0, 29);
    int16_t rem_2_L_ext_P2 = _mm256_extract_epi16(v0, 15);

    uint8_t *out = output;
    out[4] = '\n';
    memcpy(out + 15, &rem_1_L_ext, sizeof(rem_1_L_ext));
    out[16 + 1] = '\n';
    memcpy(out + 15 + 17, &rem_2_L_ext_P1, sizeof(rem_2_L_ext_P1));
    out[16 + 14] = '\n';
    memcpy(out + 15 + 17 + 1, &rem_2_L_ext_P2, sizeof(rem_2_L_ext_P2));

    out += 32 + 3;
    *wrap_cnt = 4;

    size_t written = (out - output);
    return written;
}
OPENSSL_UNTARGET_AVX2

OPENSSL_TARGET_AVX2
static inline __m256i insert_newlines_by_mask(__m256i data, __m256i mask)
{
    __m256i newline = _mm256_set1_epi8('\n');

    return _mm256_or_si256(_mm256_and_si256(mask, newline),
        _mm256_andnot_si256(mask, data));
}
OPENSSL_UNTARGET_AVX2

OPENSSL_TARGET_AVX2
static inline size_t insert_nl_str4(const __m256i v0, uint8_t *output)
{
    __m256i shuffling_mask = _mm256_setr_epi8(0, 1, 2, 3, (char)0xFF, 4, 5, 6,
        7, (char)0xFF, 8, 9, 10, 11, (char)0xFF, 12,
        (char)0xFF, (char)0xFF, (char)0xFF, (char)0xFF, 0, 1, 2, 3,
        (char)0xFF, 4, 5, 6, 7, (char)0xFF, 8, 9);
    __m256i mask_5_bytes = _mm256_setr_epi8(0, 0, 0, 0, (char)0xFF, 0, 0, 0, 0, (char)0xFF,
        0, 0, 0, 0, (char)0xFF, 0, 0, 0, 0, (char)0xFF,
        0, 0, 0, 0, (char)0xFF, 0, 0, 0, 0, (char)0xFF,
        0, 0);
    __m256i shuffled_4_bytes = _mm256_shuffle_epi8(v0, shuffling_mask);
    __m256i v0_w_nl = insert_newlines_by_mask(shuffled_4_bytes, mask_5_bytes);

    _mm256_storeu_si256((__m256i *)(output + 0), v0_w_nl);

    /* Handle cross-lane remainder logic */
    /* Without macros, _mm256_srli_si256 complains that the last arg must be an 8-bit immediate */
#define B_LANE 16 /* Bytes per lane */
#define N_RET_1_L 3 /* bytes "shifted out" of lane 0 */
#define N_RET_2_L (N_RET_1_L + 4) /* bytes "shifted out" of lane 1 */

    /* Bytes that were shifted out of lane 0 */
    __m256i rem_1_L = _mm256_srli_si256(v0, B_LANE - N_RET_1_L);

    /* Bytes that were shifted out of lane 1 */
    __m256i rem_2_L_P1 = _mm256_srli_si256(_mm256_slli_si256(_mm256_srli_si256(v0, B_LANE - N_RET_2_L),
                                               B_LANE - N_RET_1_L),
        B_LANE - 2);

    /* isolate the bytes that were shifted out of lane 1 */
    __m256i rem_2_L_P2 = _mm256_slli_si256(
        _mm256_srli_si256(v0,
            B_LANE - N_RET_2_L + N_RET_1_L),
        N_RET_1_L);

    __m256i rem_2_L = _mm256_or_si256(rem_2_L_P1, rem_2_L_P2);

    int32_t rem_1_L_ext = _mm256_extract_epi32(rem_1_L, 0);
    int64_t rem_2_L_ext = _mm256_extract_epi64(rem_2_L, 2);

    uint8_t *out = output + 16;
    memcpy(out, &rem_1_L_ext, sizeof(rem_1_L_ext));
    out += 3;
    *out++ = '\n';

    out = output + 32;
    memcpy(out, &rem_2_L_ext, sizeof(rem_2_L_ext));
    out += 2;
    *out++ = '\n';
    out += 4;
    *out++ = '\n';

    size_t written = (out - output);
    return written;
}
OPENSSL_UNTARGET_AVX2

OPENSSL_TARGET_AVX2
static inline size_t insert_nl_str8(const __m256i v0, uint8_t *output)
{
    __m256i shuffling_mask = _mm256_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, (char)0xFF,
        8, 9, 10, 11, 12, 13, 14,
        (char)0xFF, (char)0xFF, 0, 1, 2, 3, 4, 5, 6,
        7, (char)0xFF, 8, 9, 10, 11, 12);
    __m256i shuffled_4_bytes = _mm256_shuffle_epi8(v0, shuffling_mask);
    _mm256_storeu_si256((__m256i *)(output), shuffled_4_bytes);
    int8_t rem_1_L = _mm256_extract_epi8(v0, 15);
    int8_t rem_2_L_P1 = _mm256_extract_epi8(v0, 29);
    int16_t rem_2_L_P2 = _mm256_extract_epi16(v0, 15);
    uint8_t *out = output;

    memcpy(out + 16, &rem_1_L, sizeof(rem_1_L));
    memcpy(out + 32, &rem_2_L_P1, sizeof(rem_2_L_P1));
    memcpy(out + 32 + 1, &rem_2_L_P2, sizeof(rem_2_L_P2));

    output[8] = '\n';
    output[17] = '\n';
    output[26] = '\n';
    output[35] = '\n';

    out += 32 + 4;

    size_t written = (out - output);
    return written;
}
OPENSSL_UNTARGET_AVX2

OPENSSL_TARGET_AVX2
int encode_base64_avx2(EVP_ENCODE_CTX *ctx, unsigned char *dst,
    const unsigned char *src, int srclen, int ctx_length,
    int *final_wrap_cnt)
{
    const uint8_t *input = (const uint8_t *)src;
    uint8_t *out = (uint8_t *)dst;
    int i = 0;
    int stride = (ctx == NULL) ? 0 : ctx_length / 3 * 4;
    int wrap_cnt = 0;
    const int use_srp = (ctx != NULL
        && (ctx->flags & EVP_ENCODE_CTX_USE_SRP_ALPHABET) != 0);
    const __m256i shuf = _mm256_set_epi8(10, 11, 9, 10, 7, 8, 6, 7, 4, 5, 3, 4, 1, 2, 0, 1,
        10, 11, 9, 10, 7, 8, 6, 7, 4, 5, 3, 4, 1, 2, 0, 1);
    int base = 0;

    /* Process 96 bytes at a time */
    for (; i + 100 <= srclen; i += 96) {
        _mm_prefetch((const char *)(input + i + 192), _MM_HINT_T0);
        /*
         * Interleaved for each vector: load, shuffle, bit-split, lookup
         * before starting the next, giving the OoO engine independent work chains
         * across execution ports.
         */
        const __m128i lo0 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 0));
        const __m128i hi0 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 1));
        __m256i in0 = _mm256_shuffle_epi8(_mm256_set_m128i(hi0, lo0), shuf);
        const __m256i t0_0 = _mm256_and_si256(in0, _mm256_set1_epi32(0x0fc0fc00));
        const __m256i t1_0 = _mm256_mulhi_epu16(t0_0, _mm256_set1_epi32(0x04000040));
        const __m256i t2_0 = _mm256_and_si256(in0, _mm256_set1_epi32(0x003f03f0));
        const __m256i t3_0 = _mm256_mullo_epi16(t2_0, _mm256_set1_epi32(0x01000010));
        const __m256i input0 = _mm256_or_si256(t1_0, t3_0);

        const __m128i lo1 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 2));
        const __m128i hi1 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 3));
        __m256i in1 = _mm256_shuffle_epi8(_mm256_set_m128i(hi1, lo1), shuf);
        const __m256i t0_1 = _mm256_and_si256(in1, _mm256_set1_epi32(0x0fc0fc00));
        const __m256i t1_1 = _mm256_mulhi_epu16(t0_1, _mm256_set1_epi32(0x04000040));
        const __m256i t2_1 = _mm256_and_si256(in1, _mm256_set1_epi32(0x003f03f0));
        const __m256i t3_1 = _mm256_mullo_epi16(t2_1, _mm256_set1_epi32(0x01000010));
        const __m256i input1 = _mm256_or_si256(t1_1, t3_1);

        const __m128i lo2 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 4));
        const __m128i hi2 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 5));
        __m256i in2 = _mm256_shuffle_epi8(_mm256_set_m128i(hi2, lo2), shuf);
        const __m256i t0_2 = _mm256_and_si256(in2, _mm256_set1_epi32(0x0fc0fc00));
        const __m256i t1_2 = _mm256_mulhi_epu16(t0_2, _mm256_set1_epi32(0x04000040));
        const __m256i t2_2 = _mm256_and_si256(in2, _mm256_set1_epi32(0x003f03f0));
        const __m256i t3_2 = _mm256_mullo_epi16(t2_2, _mm256_set1_epi32(0x01000010));
        const __m256i input2 = _mm256_or_si256(t1_2, t3_2);

        const __m128i lo3 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 6));
        const __m128i hi3 = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3 * 7));
        __m256i in3 = _mm256_shuffle_epi8(_mm256_set_m128i(hi3, lo3), shuf);
        const __m256i t0_3 = _mm256_and_si256(in3, _mm256_set1_epi32(0x0fc0fc00));
        const __m256i t1_3 = _mm256_mulhi_epu16(t0_3, _mm256_set1_epi32(0x04000040));
        const __m256i t2_3 = _mm256_and_si256(in3, _mm256_set1_epi32(0x003f03f0));
        const __m256i t3_3 = _mm256_mullo_epi16(t2_3, _mm256_set1_epi32(0x01000010));
        const __m256i input3 = _mm256_or_si256(t1_3, t3_3);

        __m256i vec0;
        __m256i vec1;
        __m256i vec2;
        __m256i vec3;

        if (use_srp) {
            vec0 = lookup_pshufb_srp(input0);
            vec1 = lookup_pshufb_srp(input1);
            vec2 = lookup_pshufb_srp(input2);
            vec3 = lookup_pshufb_srp(input3);

        } else {
            vec0 = lookup_pshufb_std(input0);
            vec1 = lookup_pshufb_std(input1);
            vec2 = lookup_pshufb_std(input2);
            vec3 = lookup_pshufb_std(input3);
        }

        if (stride == 0) {
            _mm256_storeu_si256((__m256i *)out, vec0);

            out += 32;
            _mm256_storeu_si256((__m256i *)out, vec1);

            out += 32;
            _mm256_storeu_si256((__m256i *)out, vec2);

            out += 32;
            _mm256_storeu_si256((__m256i *)out, vec3);

            out += 32;
        } else if (stride == 64) {
            _mm256_storeu_si256((__m256i *)out, vec0);

            out += 32;
            _mm256_storeu_si256((__m256i *)out, vec1);

            out += 32;
            *(out++) = '\n';

            _mm256_storeu_si256((__m256i *)out, vec2);
            out += 32;

            _mm256_storeu_si256((__m256i *)out, vec3);
            out += 32;

            *(out++) = '\n';
        } else if (stride == 4) {
            int out_idx = 0;

            out_idx += (int)insert_nl_str4(vec0, out + out_idx);
            out_idx += (int)insert_nl_str4(vec1, out + out_idx);
            out_idx += (int)insert_nl_str4(vec2, out + out_idx);
            out_idx += (int)insert_nl_str4(vec3, out + out_idx);

            out += out_idx;
        } else if (stride == 8) {

            out += insert_nl_str8(vec0, out);
            out += insert_nl_str8(vec1, out);
            out += insert_nl_str8(vec2, out);
            out += insert_nl_str8(vec3, out);

        } else if (stride == 12) {
            switch (base) {
            case 0:

                out += insert_nl_gt16(vec0, out, stride, &wrap_cnt);
                out += insert_nl_2nd_vec_stride_12(vec1, out, stride, &wrap_cnt);
                out += insert_nl_gt16(vec2, out, stride, &wrap_cnt);
                out += insert_nl_gt16(vec3, out, stride, &wrap_cnt);
                break;
            case 1:
                out += insert_nl_2nd_vec_stride_12(vec0, out, stride, &wrap_cnt);
                out += insert_nl_gt16(vec1, out, stride, &wrap_cnt);
                out += insert_nl_gt16(vec2, out, stride, &wrap_cnt);
                out += insert_nl_2nd_vec_stride_12(vec3, out, stride, &wrap_cnt);
                break;
            default: /* base == 2 */
                out += insert_nl_gt16(vec0, out, stride, &wrap_cnt);
                out += insert_nl_gt16(vec1, out, stride, &wrap_cnt);
                out += insert_nl_2nd_vec_stride_12(vec2, out, stride, &wrap_cnt);
                out += insert_nl_gt16(vec3, out, stride, &wrap_cnt);
                break;
            }

            if (++base == 3)
                base = 0;
        } else if (stride >= 32) {
            out += ins_nl_gt32(vec0, out, stride, &wrap_cnt);
            out += ins_nl_gt32(vec1, out, stride, &wrap_cnt);
            out += ins_nl_gt32(vec2, out, stride, &wrap_cnt);
            out += ins_nl_gt32(vec3, out, stride, &wrap_cnt);
        } else if (stride >= 16) {
            out += insert_nl_gt16(vec0, out, stride, &wrap_cnt);
            out += insert_nl_gt16(vec1, out, stride, &wrap_cnt);
            out += insert_nl_gt16(vec2, out, stride, &wrap_cnt);
            out += insert_nl_gt16(vec3, out, stride, &wrap_cnt);
        }
    }

    if (stride == 0) {
        for (; i + 28 <= srclen; i += 24) {
            /* lo = [xxxx|DDDC|CCBB|BAAA] */
            /* hi = [xxxx|HHHG|GGFF|FEEE] */
            const __m128i lo = _mm_loadu_si128((const __m128i *)(input + i));
            const __m128i hi = _mm_loadu_si128((const __m128i *)(input + i + 4 * 3));
            /*
             * bytes from groups A, B and C are needed in separate 32-bit lanes
             * in = [0HHH|0GGG|0FFF|0EEE[0DDD|0CCC|0BBB|0AAA]
             */
            __m256i in = _mm256_shuffle_epi8(_mm256_set_m128i(hi, lo), shuf);
            const __m256i t0 = _mm256_and_si256(in, _mm256_set1_epi32(0x0fc0fc00));
            const __m256i t1 = _mm256_mulhi_epu16(t0, _mm256_set1_epi32(0x04000040));
            const __m256i t2 = _mm256_and_si256(in, _mm256_set1_epi32(0x003f03f0));
            const __m256i t3 = _mm256_mullo_epi16(t2, _mm256_set1_epi32(0x01000010));
            const __m256i indices = _mm256_or_si256(t1, t3);
            _mm256_storeu_si256((__m256i *)out, (use_srp ? lookup_pshufb_srp : lookup_pshufb_std)(indices));

            out += 32;
        }
    }
    *final_wrap_cnt = wrap_cnt;

    if (stride >= 32 && wrap_cnt == stride) {
        wrap_cnt = 0;
        *out++ = '\n';
    }

    return (int)(out - (uint8_t *)dst) + evp_encodeblock_int(ctx, out, src + i, srclen - i, final_wrap_cnt);
}
OPENSSL_UNTARGET_AVX2

/*
 * Base64 decode: map ASCII to 6-bit values (0-63). Invalid/whitespace etc.
 * map to 0x80+. We use four 32-byte PSHUFB tables per alphabet (index by
 * high 2 bits of byte, low 5 bits index within table). Tables match
 * data_ascii2bin and srpdata_ascii2bin from encode.c.
 */
#define B64D_FF 0xFF
/* Shared by both alphabets (indices 0-31 are identical). */
static const uint8_t decode_0[32] = {
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    0xE0,
    0xF0,
    B64D_FF,
    B64D_FF,
    0xF1,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
};
static const uint8_t decode_std_1[32] = {
    B64D_FF,
    0xE0,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    0x3E,
    B64D_FF,
    0xF2,
    B64D_FF,
    0x3F,
    0x34,
    0x35,
    0x36,
    0x37,
    0x38,
    0x39,
    0x3A,
    0x3B,
    0x3C,
    0x3D,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    0x00,
    B64D_FF,
    B64D_FF,
    B64D_FF,
};
static const uint8_t decode_std_2[32] = {
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0A,
    0x0B,
    0x0C,
    0x0D,
    0x0E,
    0x0F,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
};
static const uint8_t decode_std_3[32] = {
    0x1A,
    0x1B,
    0x1C,
    0x1D,
    0x1E,
    0x1F,
    0x20,
    0x21,
    0x22,
    0x23,
    0x24,
    0x25,
    0x26,
    0x27,
    0x28,
    0x29,
    0x2A,
    0x2B,
    0x2C,
    0x2D,
    0x2E,
    0x2F,
    0x30,
    0x31,
    0x32,
    0x33,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
};

static const uint8_t decode_srp_1[32] = {
    B64D_FF,
    0xE0,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    0xF2,
    0x3E,
    0x3F,
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    0x00,
    B64D_FF,
    B64D_FF,
    B64D_FF,
};
static const uint8_t decode_srp_2[32] = {
    0x0A,
    0x0B,
    0x0C,
    0x0D,
    0x0E,
    0x0F,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19,
    0x1A,
    0x1B,
    0x1C,
    0x1D,
    0x1E,
    0x1F,
    0x20,
    0x21,
    0x22,
    0x23,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
};
static const uint8_t decode_srp_3[32] = {
    0x24,
    0x25,
    0x26,
    0x27,
    0x28,
    0x29,
    0x2A,
    0x2B,
    0x2C,
    0x2D,
    0x2E,
    0x2F,
    0x30,
    0x31,
    0x32,
    0x33,
    0x34,
    0x35,
    0x36,
    0x37,
    0x38,
    0x39,
    0x3A,
    0x3B,
    0x3C,
    0x3D,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
    B64D_FF,
};

/* Alphabet selection: [0] = standard, [1] = SRP; each row is 3 LUTs (decode_0 shared). */
static const uint8_t *const decode_alphabets[2][3] = {
    { decode_std_1, decode_std_2, decode_std_3 },
    { decode_srp_1, decode_srp_2, decode_srp_3 },
};

/* De-interleave control for packus_epi16 output: [0,2,...,30, 1,3,...,31] -> [0..31]. */
static const uint8_t b64d_shuf_sel[32] = {
    0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15,
    16, 24, 17, 25, 18, 26, 19, 27, 20, 28, 21, 29, 22, 30, 23, 31
};

/* Pack 32 decoded 6-bit bytes -> 24 output bytes: shuffle and permute controls. */
static const uint8_t b64d_dec_shuf[32] = {
    2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, 0xFF, 0xFF, 0xFF, 0xFF,
    2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, 0xFF, 0xFF, 0xFF, 0xFF
};
static const int32_t b64d_dec_perm[8] = { 0, 1, 2, 4, 5, 6, -1, -1 };

typedef char ossl_b64_avx2_chk_decode_0[(sizeof(decode_0) == 32) ? 1 : -1];
typedef char ossl_b64_avx2_chk_shuf_sel[(sizeof(b64d_shuf_sel) == 32) ? 1 : -1];
typedef char ossl_b64_avx2_chk_dec_shuf[(sizeof(b64d_dec_shuf) == 32) ? 1 : -1];

OPENSSL_TARGET_AVX2
static inline __m256i ascii2bin_avx2(__m256i input, int use_srp)
{
    const __m256i indices = _mm256_and_si256(input, _mm256_set1_epi8(31));
    const __m256i zero = _mm256_setzero_si256();
    __m256i lo = _mm256_unpacklo_epi8(input, zero);
    __m256i hi = _mm256_unpackhi_epi8(input, zero);
    __m256i lo5 = _mm256_and_si256(_mm256_srli_epi16(lo, 5), _mm256_set1_epi16(0x0003));
    __m256i hi5 = _mm256_and_si256(_mm256_srli_epi16(hi, 5), _mm256_set1_epi16(0x0003));
    __m256i sel = _mm256_packus_epi16(lo5, hi5);
    sel = _mm256_shuffle_epi8(sel, _mm256_loadu_si256((const __m256i *)b64d_shuf_sel));

    const __m256i t0 = _mm256_loadu_si256((const __m256i *)decode_0);
    const __m256i t1 = _mm256_loadu_si256((const __m256i *)decode_alphabets[use_srp][0]);
    const __m256i t2 = _mm256_loadu_si256((const __m256i *)decode_alphabets[use_srp][1]);
    const __m256i t3 = _mm256_loadu_si256((const __m256i *)decode_alphabets[use_srp][2]);

    __m256i r0 = _mm256_shuffle_epi8(t0, indices);
    __m256i r1 = _mm256_shuffle_epi8(t1, indices);
    __m256i r2 = _mm256_shuffle_epi8(t2, indices);
    __m256i r3 = _mm256_shuffle_epi8(t3, indices);

    __m256i mask1 = _mm256_cmpeq_epi8(sel, _mm256_set1_epi8(1));
    __m256i mask2 = _mm256_cmpeq_epi8(sel, _mm256_set1_epi8(2));
    __m256i mask3 = _mm256_cmpeq_epi8(sel, _mm256_set1_epi8(3));
    __m256i out = _mm256_blendv_epi8(r0, r1, mask1);
    out = _mm256_blendv_epi8(out, r2, mask2);
    out = _mm256_blendv_epi8(out, r3, mask3);
    return out;
}

/* Pack 32 decoded 6-bit bytes into 24 output bytes (8 groups of 4 -> 3). */
static inline void dec_reshuffle(__m256i in, uint8_t *out)
{
    const __m256i merge = _mm256_maddubs_epi16(in, _mm256_set1_epi32(0x01400140));
    __m256i packed = _mm256_madd_epi16(merge, _mm256_set1_epi32(0x00011000));
    packed = _mm256_shuffle_epi8(packed, _mm256_loadu_si256((const __m256i *)b64d_dec_shuf));
    packed = _mm256_permutevar8x32_epi32(packed, _mm256_loadu_si256((const __m256i *)b64d_dec_perm));
    /*
     * Only 24 output bytes are defined; the permuted register may leave
     * undefined bytes in the upper 8 lanes. A 32-byte store can overrun
     * EVP_DecodeBlock output buffers sized exactly for 24-byte chunks.
     */
    uint8_t tmp[32];
    _mm256_storeu_si256((__m256i *)tmp, packed);
    memcpy(out, tmp, 24);
}

/*
 * Process one 32-byte vector: decode, validate, write 24 bytes to dst.
 * Returns 0 on success, -1 if any lane is invalid for base64 (scalar rules).
 */
static inline int decode_one_vector(const uint8_t *src, uint8_t *dst, int use_srp)
{
    __m256i str = _mm256_loadu_si256((const __m256i *)src);
    __m256i decoded = ascii2bin_avx2(str, use_srp);
    /*
     * Match scalar evp_decodeblock_int: reject if any lane has bit 7 set
     * (invalid / whitespace / control from data_ascii2bin), or any value
     * outside 0..63. Signed cmpgt_epi8(decoded, 63) misses 0x80..0xff
     * because those are negative as int8.
     */
    __m256i bad_hi = _mm256_and_si256(decoded, _mm256_set1_epi8((char)0x80));
    __m256i bad_gt = _mm256_cmpgt_epi8(decoded, _mm256_set1_epi8(63));
    if (_mm256_movemask_epi8(_mm256_or_si256(bad_hi, bad_gt)) != 0)
        return -1;
    dec_reshuffle(decoded, dst);
    return 0;
}

__owur int decode_base64_avx2(int use_srp, unsigned char *restrict out,
    const unsigned char *restrict src, int srclen)
{
    uint8_t *dst = (uint8_t *)out;
    const uint8_t *input = (const uint8_t *)src;
    int total = 0;

    while (srclen >= 64) {
        _mm_prefetch((const char *)(input + 64), _MM_HINT_T0);
        if (decode_one_vector(input, dst, use_srp) != 0
            || decode_one_vector(input + 32, dst + 24, use_srp) != 0)
            return -1;
        input += 64;
        dst += 48;
        total += 48;
        srclen -= 64;
    }

    if (srclen >= 32) {
        _mm_prefetch((const char *)(input + 32), _MM_HINT_T0);
        if (decode_one_vector(input, dst, use_srp) != 0)
            return -1;
        total += 24;
    }
    return total;
}
OPENSSL_UNTARGET_AVX2
#endif /* !defined(_M_ARM64EC) */
#endif
