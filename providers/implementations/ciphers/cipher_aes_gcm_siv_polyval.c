/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * AES low level APIs are deprecated for public use, but still ok for internal
 * use where we're using them to implement the higher level EVP interface, as is
 * the case here.
 */
#include "internal/deprecated.h"

#include <string.h>
#include <openssl/crypto.h>
#include <internal/endian.h>
#include <prov/implementations.h>
#include "cipher_aes_gcm_siv.h"

#if defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>
#define GCM_SIV_REVERSE_NEON 1
#if defined(HWAES_CAPABLE) && (defined(__GNUC__) || defined(__clang__)) \
    && !defined(OPENSSL_NO_GCM_SIV_PMULL)
#define GCM_SIV_POLYVAL_PMULL 1
#endif
#elif defined(__x86_64__) && defined(AESNI_CAPABLE) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define GCM_SIV_REVERSE_SSSE3 1
#ifndef OPENSSL_NO_GCM_SIV_VAES
#define GCM_SIV_POLYVAL_VPCLMUL 1
int ossl_vaes_vpclmulqdq_capable(void);
#endif
#endif

#ifdef GCM_SIV_POLYVAL_VPCLMUL
/*
 * Native POLYVAL on VPCLMULQDQ: no byte reversal, no GHASH kernel. POLYVAL is
 * dot(a, b) = a * b * x^-128 mod (x^128 + x^127 + x^126 + x^121 + 1) over
 * little-endian elements; 16 blocks are multiplied by H^16..H^1 as four
 * 4-lane Karatsuba products (three VPCLMULQDQ each), the lanes are folded and
 * ONE Montgomery reduction closes the step. Math and layout after libkryp's
 * gcm_vaes.c (MIT, Alexey Eromenko and Claude AI), which is byte-verified
 * against this provider. Engaged only for runs of >= 256 bytes; the tail
 * takes the GHASH route below, which continues the same accumulator.
 */
__attribute__((target("pclmul,sse4.1,ssse3"))) static __m128i pv_reduce(__m128i zlo, __m128i zhi)
{
    uint64_t z0 = (uint64_t)_mm_cvtsi128_si64(zlo);
    uint64_t z1 = (uint64_t)_mm_extract_epi64(zlo, 1);
    uint64_t z2 = (uint64_t)_mm_cvtsi128_si64(zhi);
    uint64_t z3 = (uint64_t)_mm_extract_epi64(zhi, 1);
    uint64_t w1 = z1 ^ (z0 << 57) ^ (z0 << 62) ^ (z0 << 63);
    uint64_t w2 = z2 ^ z0 ^ (z0 >> 7) ^ (z0 >> 2) ^ (z0 >> 1);
    uint64_t rl = w2 ^ (w1 << 57) ^ (w1 << 62) ^ (w1 << 63);
    uint64_t rh = z3 ^ w1 ^ (w1 >> 7) ^ (w1 >> 2) ^ (w1 >> 1);

    return _mm_set_epi64x((long long)rh, (long long)rl);
}

__attribute__((target("pclmul,sse4.1,ssse3"))) static __m128i pv_mul(__m128i a, __m128i h)
{
    __m128i lo = _mm_clmulepi64_si128(a, h, 0x00);
    __m128i hi = _mm_clmulepi64_si128(a, h, 0x11);
    __m128i ax = _mm_xor_si128(a, _mm_shuffle_epi32(a, 0x4e));
    __m128i hx = _mm_xor_si128(h, _mm_shuffle_epi32(h, 0x4e));
    __m128i mid = _mm_clmulepi64_si128(ax, hx, 0x00);

    mid = _mm_xor_si128(mid, _mm_xor_si128(lo, hi));
    lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));
    return pv_reduce(lo, hi);
}

/*
 * 128-bit PCLMULQDQ POLYVAL for AES-NI CPUs without VPCLMULQDQ (Westmere through
 * Zen 3): four blocks against H^4..H^1 per Montgomery reduction (three PCLMULQDQ
 * Karatsuba products each), the same math as pv_mul. Consumes floor(len/64)*64.
 */
__attribute__((target("pclmul,sse4.1,ssse3"))) static ossl_inline void clmul128_acc(__m128i a, __m128i h, __m128i *zlo, __m128i *zhi)
{
    __m128i lo = _mm_clmulepi64_si128(a, h, 0x00);
    __m128i hi = _mm_clmulepi64_si128(a, h, 0x11);
    __m128i ax = _mm_xor_si128(a, _mm_shuffle_epi32(a, 0x4e));
    __m128i hx = _mm_xor_si128(h, _mm_shuffle_epi32(h, 0x4e));
    __m128i mid = _mm_clmulepi64_si128(ax, hx, 0x00);

    mid = _mm_xor_si128(mid, _mm_xor_si128(lo, hi));
    lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));
    *zlo = _mm_xor_si128(*zlo, lo);
    *zhi = _mm_xor_si128(*zhi, hi);
}

__attribute__((target("pclmul,sse4.1,ssse3"))) static size_t polyval_pclmulqdq(const uint8_t H[16], const uint8_t *data, size_t len,
    uint8_t acc16[16])
{
    __m128i h1, h2, h3, h4, acc;
    size_t done = 0;

    h1 = _mm_loadu_si128((const __m128i *)H);
    h2 = pv_mul(h1, h1);
    h3 = pv_mul(h2, h1);
    h4 = pv_mul(h3, h1);
    acc = _mm_loadu_si128((const __m128i *)acc16);
    while (len - done >= 64) {
        __m128i zlo = _mm_setzero_si128(), zhi = _mm_setzero_si128();

        clmul128_acc(_mm_xor_si128(acc, _mm_loadu_si128((const __m128i *)(data + done))), h4, &zlo, &zhi);
        clmul128_acc(_mm_loadu_si128((const __m128i *)(data + done + 16)), h3, &zlo, &zhi);
        clmul128_acc(_mm_loadu_si128((const __m128i *)(data + done + 32)), h2, &zlo, &zhi);
        clmul128_acc(_mm_loadu_si128((const __m128i *)(data + done + 48)), h1, &zlo, &zhi);
        acc = pv_reduce(zlo, zhi);
        done += 64;
    }
    _mm_storeu_si128((__m128i *)acc16, acc);
    return done;
}

/* POLYVAL floor(len/256)*256 bytes of data into acc16; returns the bytes consumed. */
__attribute__((target("avx512f,avx512bw,vpclmulqdq,pclmul,sse4.1,ssse3"))) static size_t polyval_vpclmulqdq(const uint8_t H[16], const uint8_t *data, size_t len,
    uint8_t acc16[16])
{
    __m128i p[16], acc;
    __m512i pw[4];
    size_t done = 0;
    int i;

    /* P_1 = H, P_k = P_(k-1) * H; pw[j] lane l holds P_(16 - (4j + l)) so that
     * block 0 (with the accumulator) pairs with P_16 and block 15 with P_1 */
    p[0] = _mm_loadu_si128((const __m128i *)H);
    for (i = 1; i < 16; i++)
        p[i] = pv_mul(p[i - 1], p[0]);
    for (i = 0; i < 4; i++)
        pw[i] = _mm512_set_epi64(
            _mm_extract_epi64(p[16 - (4 * i + 3) - 1], 1), _mm_cvtsi128_si64(p[16 - (4 * i + 3) - 1]),
            _mm_extract_epi64(p[16 - (4 * i + 2) - 1], 1), _mm_cvtsi128_si64(p[16 - (4 * i + 2) - 1]),
            _mm_extract_epi64(p[16 - (4 * i + 1) - 1], 1), _mm_cvtsi128_si64(p[16 - (4 * i + 1) - 1]),
            _mm_extract_epi64(p[16 - (4 * i + 0) - 1], 1), _mm_cvtsi128_si64(p[16 - (4 * i + 0) - 1]));
    acc = _mm_loadu_si128((const __m128i *)acc16);

    while (len - done >= 256) {
        __m512i zlo = _mm512_setzero_si512(), zhi = zlo, zmid = zlo;
        __m512i d[4];
        __m256i lo2, hi2;
        __m128i lo1, hi1;

        d[0] = _mm512_loadu_si512((const void *)(data + done));
        d[1] = _mm512_loadu_si512((const void *)(data + done + 64));
        d[2] = _mm512_loadu_si512((const void *)(data + done + 128));
        d[3] = _mm512_loadu_si512((const void *)(data + done + 192));
        /* the accumulator enters with block 0 (zext: lanes 1..3 must be zero) */
        d[0] = _mm512_xor_si512(d[0], _mm512_zextsi128_si512(acc));
        for (i = 0; i < 4; i++) {
            __m512i a = d[i], h = pw[i];
            __m512i lo = _mm512_clmulepi64_epi128(a, h, 0x00);
            __m512i hi = _mm512_clmulepi64_epi128(a, h, 0x11);
            __m512i ax = _mm512_xor_si512(a, _mm512_shuffle_epi32(a, 0x4e));
            __m512i hx = _mm512_xor_si512(h, _mm512_shuffle_epi32(h, 0x4e));
            __m512i mid = _mm512_clmulepi64_epi128(ax, hx, 0x00);

            mid = _mm512_xor_si512(mid, _mm512_xor_si512(lo, hi));
            zlo = _mm512_xor_si512(zlo, lo);
            zhi = _mm512_xor_si512(zhi, hi);
            zmid = _mm512_xor_si512(zmid, mid);
        }
        /* fold mid into lo/hi per lane, then the four lanes into one 256-bit product */
        zlo = _mm512_xor_si512(zlo, _mm512_bslli_epi128(zmid, 8));
        zhi = _mm512_xor_si512(zhi, _mm512_bsrli_epi128(zmid, 8));
        lo2 = _mm256_xor_si256(_mm512_castsi512_si256(zlo), _mm512_extracti64x4_epi64(zlo, 1));
        hi2 = _mm256_xor_si256(_mm512_castsi512_si256(zhi), _mm512_extracti64x4_epi64(zhi, 1));
        lo1 = _mm_xor_si128(_mm256_castsi256_si128(lo2), _mm256_extracti128_si256(lo2, 1));
        hi1 = _mm_xor_si128(_mm256_castsi256_si128(hi2), _mm256_extracti128_si256(hi2, 1));
        acc = pv_reduce(lo1, hi1);
        done += 256;
    }
    _mm_storeu_si128((__m128i *)acc16, acc);
    OPENSSL_cleanse(p, sizeof(p));
    OPENSSL_cleanse(pw, sizeof(pw));
    _mm256_zeroupper();
    return done;
}
#endif

#ifdef GCM_SIV_POLYVAL_PMULL
/*
 * Native POLYVAL on PMULL (ARMv8 Crypto Extensions): no byte reversal, no GHASH
 * kernel. Eight blocks are multiplied by H^8..H^1 as Karatsuba products (three
 * PMULLs each, the key's Karatsuba half precomputed), the three partial sums
 * are folded once and ONE Montgomery reduction closes the step. Eight, not
 * four, because on these cores the hash is bound by the latency of the
 * reduction chain rather than by PMULL throughput: the 4-block gcm_ghash_v8
 * route runs 8.4-8.9 GB/s on an M3 Max, this kernel 14 GB/s. PMULL/PMULL2 are
 * inline asm on full vector registers: fed through vmull_p64's scalar
 * operands the compiler hoists the key halves into general-purpose registers
 * and pays an fmov/dup before every multiply. Math and layout after libkryp's
 * kryp_pmull_armv8.h (MIT, Alexey Eromenko and Claude AI), byte-verified
 * against this provider. Engaged for runs of >= 64 bytes; the tail takes the
 * GHASH route below, which continues the same accumulator.
 */
#if defined(__clang__)
#define GCM_SIV_ARMV8 __attribute__((target("crypto")))
#else
#define GCM_SIV_ARMV8 __attribute__((target("+crypto")))
#endif

GCM_SIV_ARMV8 static ossl_inline uint64x2_t pvn_pmull_lo(uint64x2_t a, uint64x2_t b)
{
    uint64x2_t r;

    __asm__("pmull %0.1q, %1.1d, %2.1d" : "=w"(r) : "w"(a), "w"(b));
    return r;
}

GCM_SIV_ARMV8 static ossl_inline uint64x2_t pvn_pmull_hi(uint64x2_t a, uint64x2_t b)
{
    uint64x2_t r;

    __asm__("pmull2 %0.1q, %1.2d, %2.2d" : "=w"(r) : "w"(a), "w"(b));
    return r;
}

/* (zlo, zhi, zmid) += a * h, Karatsuba, no reduction; hx = both lanes lo(h)^hi(h) */
GCM_SIV_ARMV8 static ossl_inline void pvn_clmul3(uint64x2_t a, uint64x2_t h, uint64x2_t hx,
    uint64x2_t *zlo, uint64x2_t *zhi, uint64x2_t *zmid)
{
    uint64x2_t ax = veorq_u64(a, vextq_u64(a, a, 1));

    *zlo = veorq_u64(*zlo, pvn_pmull_lo(a, h));
    *zhi = veorq_u64(*zhi, pvn_pmull_hi(a, h));
    *zmid = veorq_u64(*zmid, pvn_pmull_lo(ax, hx));
}

/* Montgomery reduction by x^-128 mod x^128+x^127+x^126+x^121+1 (two PMULL by x^57+x^62+x^63) */
GCM_SIV_ARMV8 static ossl_inline uint64x2_t pvn_reduce(uint64x2_t zlo, uint64x2_t zhi, uint64x2_t zmid)
{
    const uint64x2_t M = vdupq_n_u64(0xC200000000000000ULL);
    const uint64x2_t zero = vdupq_n_u64(0);
    uint64x2_t P1, P2, WW, R;

    zmid = veorq_u64(zmid, veorq_u64(zlo, zhi)); /* fold the middle term */
    zlo = veorq_u64(zlo, vextq_u64(zero, zmid, 1));
    zhi = veorq_u64(zhi, vextq_u64(zmid, zero, 1));
    P1 = pvn_pmull_lo(zlo, M);
    WW = vcombine_u64(vget_high_u64(zlo), vget_low_u64(zhi)); /* [z1, z2] */
    WW = veorq_u64(WW, P1);
    WW = veorq_u64(WW, vcombine_u64(vget_low_u64(zero), vget_low_u64(zlo)));
    P2 = pvn_pmull_lo(WW, M);
    R = vcombine_u64(vget_high_u64(WW), vget_high_u64(zhi)); /* [w2, z3] */
    R = veorq_u64(R, P2);
    R = veorq_u64(R, vcombine_u64(vget_low_u64(zero), vget_low_u64(WW)));
    return R;
}

GCM_SIV_ARMV8 static ossl_inline uint64x2_t pvn_mul(uint64x2_t a, uint64x2_t h)
{
    uint64x2_t zlo = vdupq_n_u64(0), zhi = zlo, zmid = zlo;

    pvn_clmul3(a, h, veorq_u64(h, vextq_u64(h, h, 1)), &zlo, &zhi, &zmid);
    return pvn_reduce(zlo, zhi, zmid);
}

/* POLYVAL floor(len/64)*64 bytes of data into acc16; returns the bytes consumed. */
GCM_SIV_ARMV8 static size_t polyval_pmull(const uint8_t H[16], const uint8_t *data, size_t len,
    uint8_t acc16[16])
{
    uint64x2_t h[8], hx[8], acc;
    size_t done = 0;
    int n = len >= 128 ? 8 : 4, i;

    h[0] = vreinterpretq_u64_u8(vld1q_u8(H));
    h[1] = pvn_mul(h[0], h[0]);
    h[2] = pvn_mul(h[1], h[0]);
    h[3] = pvn_mul(h[1], h[1]);
    if (n == 8) {
        h[4] = pvn_mul(h[3], h[0]);
        h[5] = pvn_mul(h[3], h[1]);
        h[6] = pvn_mul(h[3], h[2]);
        h[7] = pvn_mul(h[3], h[3]);
    }
    for (i = 0; i < n; i++)
        hx[i] = veorq_u64(h[i], vextq_u64(h[i], h[i], 1));
    acc = vreinterpretq_u64_u8(vld1q_u8(acc16));
    while (len - done >= 128) {
        uint64x2_t zlo = vdupq_n_u64(0), zhi = zlo, zmid = zlo;
        const uint8_t *d = data + done;

        pvn_clmul3(veorq_u64(acc, vreinterpretq_u64_u8(vld1q_u8(d))), h[7], hx[7], &zlo, &zhi, &zmid);
        pvn_clmul3(vreinterpretq_u64_u8(vld1q_u8(d + 16)), h[6], hx[6], &zlo, &zhi, &zmid);
        pvn_clmul3(vreinterpretq_u64_u8(vld1q_u8(d + 32)), h[5], hx[5], &zlo, &zhi, &zmid);
        pvn_clmul3(vreinterpretq_u64_u8(vld1q_u8(d + 48)), h[4], hx[4], &zlo, &zhi, &zmid);
        pvn_clmul3(vreinterpretq_u64_u8(vld1q_u8(d + 64)), h[3], hx[3], &zlo, &zhi, &zmid);
        pvn_clmul3(vreinterpretq_u64_u8(vld1q_u8(d + 80)), h[2], hx[2], &zlo, &zhi, &zmid);
        pvn_clmul3(vreinterpretq_u64_u8(vld1q_u8(d + 96)), h[1], hx[1], &zlo, &zhi, &zmid);
        pvn_clmul3(vreinterpretq_u64_u8(vld1q_u8(d + 112)), h[0], hx[0], &zlo, &zhi, &zmid);
        acc = pvn_reduce(zlo, zhi, zmid);
        done += 128;
    }
    if (len - done >= 64) {
        uint64x2_t zlo = vdupq_n_u64(0), zhi = zlo, zmid = zlo;
        const uint8_t *d = data + done;

        pvn_clmul3(veorq_u64(acc, vreinterpretq_u64_u8(vld1q_u8(d))), h[3], hx[3], &zlo, &zhi, &zmid);
        pvn_clmul3(vreinterpretq_u64_u8(vld1q_u8(d + 16)), h[2], hx[2], &zlo, &zhi, &zmid);
        pvn_clmul3(vreinterpretq_u64_u8(vld1q_u8(d + 32)), h[1], hx[1], &zlo, &zhi, &zmid);
        pvn_clmul3(vreinterpretq_u64_u8(vld1q_u8(d + 48)), h[0], hx[0], &zlo, &zhi, &zmid);
        acc = pvn_reduce(zlo, zhi, zmid);
        done += 64;
    }
    vst1q_u8(acc16, vreinterpretq_u8_u64(acc));
    OPENSSL_cleanse(h, sizeof(h));
    OPENSSL_cleanse(hx, sizeof(hx));
    return done;
}
#endif

static ossl_inline void mulx_ghash(uint64_t *a)
{
    uint64_t t[2], mask;
    DECLARE_IS_ENDIAN;

    if (IS_LITTLE_ENDIAN) {
        t[0] = GSWAP8(a[0]);
        t[1] = GSWAP8(a[1]);
    } else {
        t[0] = a[0];
        t[1] = a[1];
    }
    mask = -(int64_t)(t[1] & 1) & 0xe1;
    mask <<= 56;

    if (IS_LITTLE_ENDIAN) {
        a[1] = GSWAP8((t[1] >> 1) ^ (t[0] << 63));
        a[0] = GSWAP8((t[0] >> 1) ^ mask);
    } else {
        a[1] = (t[1] >> 1) ^ (t[0] << 63);
        a[0] = (t[0] >> 1) ^ mask;
    }
}

/*
 * Reverse 16 bytes: two 64-bit loads, each byte-swapped, stored crosswise. A pure
 * byte reversal on either endianness; memcpy keeps it alignment-safe. Reads both
 * halves before writing, so in == out works.
 */
static ossl_inline void byte_reverse16(uint8_t *out, const uint8_t *in)
{
    uint64_t lo, hi;

    memcpy(&lo, in, 8);
    memcpy(&hi, in + 8, 8);
    lo = GSWAP8(lo);
    hi = GSWAP8(hi);
    memcpy(out, &hi, 8);
    memcpy(out + 8, &lo, 8);
}

#ifdef GCM_SIV_REVERSE_SSSE3
__attribute__((target("ssse3"))) static void reverse_blocks_ssse3(uint8_t *out, const uint8_t *in, size_t n)
{
    /* pshufb control: output byte i takes input byte 15 - i */
    const __m128i m = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    size_t i;

    for (i = 0; i < n; i += 16)
        _mm_storeu_si128((__m128i *)(out + i),
            _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(in + i)), m));
}
#endif

/* Byte-reverse n bytes (a multiple of 16) block by block, in -> out. */
static void reverse_blocks(uint8_t *out, const uint8_t *in, size_t n)
{
    size_t i;

#if defined(GCM_SIV_REVERSE_NEON)
    for (i = 0; i < n; i += 16) {
        uint8x16_t v = vld1q_u8(in + i);

        v = vrev64q_u8(v); /* reverse within each 64-bit half ... */
        v = vextq_u8(v, v, 8); /* ... then swap the halves */
        vst1q_u8(out + i, v);
    }
    return;
#elif defined(GCM_SIV_REVERSE_SSSE3)
    if (OPENSSL_ia32cap_P[1] & (1 << 9)) { /* SSSE3 */
        reverse_blocks_ssse3(out, in, n);
        return;
    }
#endif
    for (i = 0; i < n; i += 16)
        byte_reverse16(out + i, in + i);
}

/* Initialization of POLYVAL via existing GHASH implementation */
void ossl_polyval_ghash_init(u128 Htable[16], const uint64_t H[2])
{
    uint64_t tmp[2];
    DECLARE_IS_ENDIAN;

    byte_reverse16((uint8_t *)tmp, (const uint8_t *)H);
    mulx_ghash(tmp);
    if (IS_LITTLE_ENDIAN) {
        /* "H is stored in host byte order" */
        tmp[0] = GSWAP8(tmp[0]);
        tmp[1] = GSWAP8(tmp[1]);
    }

    ossl_gcm_init_4bit(Htable, (uint64_t *)tmp);
}

/*
 * POLYVAL via the GHASH implementation (RFC 8452 Appendix A):
 *   POLYVAL(H, X_1..X_n)
 *     = ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)), ByteReverse(X_1), ...))
 *
 * The input is reversed into the staging buffer a run at a time and each run is
 * handed to ghash in ONE call, so the platform kernel (PCLMULQDQ / PMULL / ...)
 * runs its aggregated loop. Entering it per 16-byte block, as the original did,
 * cost ~10x; from 4 KiB runs upward the kernels are flat, so the runs stay small
 * enough to keep the staging buffer and the input inside L1D.
 */
void ossl_polyval_ghash_hash(const u128 Htable[16], uint8_t *tag, const uint8_t *inp,
    size_t len, uint8_t *scratch, size_t scratch_len, const uint8_t *H)
{
    uint64_t out[2];
    uint8_t small[256];
    uint8_t *buf = scratch != NULL ? scratch : small;
    size_t cap = scratch != NULL ? scratch_len : sizeof(small);
    size_t n;

#ifdef GCM_SIV_POLYVAL_VPCLMUL
    /* tag IS the POLYVAL accumulator in POLYVAL byte order, so the native
     * kernel updates it directly and the GHASH route below continues from it */
    if (H != NULL) {
        if (len >= 256 && ossl_vaes_vpclmulqdq_capable())
            n = polyval_vpclmulqdq(H, inp, len, tag);
        else if (len >= 64)
            n = polyval_pclmulqdq(H, inp, len, tag);
        else
            n = 0;
        inp += n;
        len -= n;
        if (len == 0)
            return;
    }
#elif defined(GCM_SIV_POLYVAL_PMULL)
    if (H != NULL && len >= 64) {
        n = polyval_pmull(H, inp, len, tag);
        inp += n;
        len -= n;
        if (len == 0)
            return;
    }
#else
    (void)H;
#endif
    byte_reverse16((uint8_t *)out, tag);

    /*
     * This implementation doesn't deal with partials, callers do,
     * so, len is a multiple of 16
     */
    while (len > 0) {
        n = len < cap ? len : cap;
        reverse_blocks(buf, inp, n);
        ossl_gcm_ghash_4bit((uint64_t *)out, Htable, buf, n);
        inp += n;
        len -= n;
    }
    byte_reverse16(tag, (uint8_t *)out);
    if (scratch == NULL)
        OPENSSL_cleanse(small, sizeof(small));
}
