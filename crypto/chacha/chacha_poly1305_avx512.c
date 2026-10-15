/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Fused ChaCha20-Poly1305.
 *
 * ChaCha20 (vpaddd / vpxord / vprold) and Poly1305 IFMA (vpmadd52, radix
 * 2^44) issue on different pipes, so one loop hashes chunk k while
 * generating keystream for chunk k+1.  Decrypt hashes the input during
 * the rounds, because it is already ciphertext.
 *
 * A chunk is 16 ChaCha20 blocks, 1024 bytes, and a pass always runs every
 * lane.  Unused blocks are parked.  Poly1305 uses 8 lanes.  The r^n table
 * is built on the first call of at least POLY_VEC_MIN bytes.
 *
 * Block 0 is the one-time Poly1305 key.  hint in (192, 960] parks 960
 * payload bytes; any other hint parks 192.  An update that fits claims
 * the park.  A longer update drops it and leaves the block counter at 1.
 * Seal hashes after the XOR.  Open hashes before the XOR, so an in-place
 * decrypt still sees ciphertext.
 *
 * From the second cipher call on, a 1024-byte encrypt stores the next
 * chunk while hashing the one just written, when the r^n table exists and
 * a full prefetched chunk is waiting or nothing is parked.  Decrypt does
 * not prefetch.
 */

#include <stddef.h>
#include <string.h>

#include "internal/cryptlib.h"
#include "crypto/chacha_poly1305.h"

#ifdef CHACHA20_POLY1305_AVX512_CAPABLE

#include <stdint.h>
#include <immintrin.h>

#define STRINGIFY_IMPLEMENTATION_(a) #a
#define STRINGIFY(a) STRINGIFY_IMPLEMENTATION_(a)

#ifdef __clang__
#define OPENSSL_TARGET_REGION(T)                                       \
    _Pragma(STRINGIFY(clang attribute push(__attribute__((target(T))), \
        apply_to = function)))
#define OPENSSL_UNTARGET_REGION _Pragma("clang attribute pop")
#elif defined(__GNUC__)
#define OPENSSL_TARGET_REGION(T) \
    _Pragma("GCC push_options") _Pragma(STRINGIFY(GCC target(T)))
#define OPENSSL_UNTARGET_REGION _Pragma("GCC pop_options")
#endif

#define OPENSSL_TARGET_FUSED \
    OPENSSL_TARGET_REGION("avx512f,avx512vl,avx512ifma,sse4.1,bmi2,adx")
#define OPENSSL_UNTARGET_FUSED OPENSSL_UNTARGET_REGION

#define CHACHA_BLK 64
#define GROUP_BYTES (4 * CHACHA_BLK) /* one ChaCha20 group      */
#define CHUNK_BYTES (4 * GROUP_BYTES) /* four groups, 16 blocks  */
/* Payload blocks init parks.  Block 0 is the one-time Poly1305 key, so a
 * 4-block group parks 3 blocks and a 16-block pass parks 15. */
#define PARK_192 (3 * CHACHA_BLK)
#define PARK_960 (15 * CHACHA_BLK)

#define POLY_LANES 8
#define POLY_GROUP_BYTES (POLY_LANES * 16)

/*
 * Shortest payload that justifies building r^1..r^8.  Below it the table
 * costs more than the 8-lane path saves and the MAC stays scalar.  Must not
 * exceed CHUNK_BYTES, which always takes the vector path.
 */
#ifndef POLY_VEC_MIN
#define POLY_VEC_MIN 256
#endif

#define MASK44 0x00000fffffffffffULL
#define MASK42 0x000003ffffffffffULL

typedef struct {
    uint64_t h[3];
    uint64_t r0, r1, r2;
    uint64_t s1, s2; /* 20*r1 and 20*r2 */
    uint64_t nonce0, nonce1;
} poly1305_state;

OPENSSL_TARGET_FUSED

static void poly_init(poly1305_state *st, const unsigned char key[32])
{
    uint64_t t0, t1;

    memcpy(&t0, key, 8);
    memcpy(&t1, key + 8, 8);
    t0 &= 0x0ffffffc0fffffffULL;
    t1 &= 0x0ffffffc0ffffffcULL;

    st->r0 = t0 & MASK44;
    st->r1 = ((t0 >> 44) | (t1 << 20)) & MASK44;
    st->r2 = t1 >> 24;
    st->s1 = st->r1 * 20;
    st->s2 = st->r2 * 20;

    st->h[0] = st->h[1] = st->h[2] = 0;
    memcpy(&st->nonce0, key + 16, 8);
    memcpy(&st->nonce1, key + 24, 8);
}

/* c = a * b mod 2^130-5, radix 2^44, used to build the r^n table. */
static void poly44_mul(uint64_t c[3], const uint64_t a[3], const uint64_t b[3])
{
    const uint64_t r0 = b[0], r1 = b[1], r2 = b[2];
    const uint64_t s1 = r1 * 20, s2 = r2 * 20;
    __uint128_t d0, d1, d2;
    uint64_t c0, c1, c2, k;

    d0 = (__uint128_t)a[0] * r0 + (__uint128_t)a[1] * s2 + (__uint128_t)a[2] * s1;
    d1 = (__uint128_t)a[0] * r1 + (__uint128_t)a[1] * r0 + (__uint128_t)a[2] * s2;
    d2 = (__uint128_t)a[0] * r2 + (__uint128_t)a[1] * r1 + (__uint128_t)a[2] * r0;

    c0 = (uint64_t)d0 & MASK44;
    d1 += (uint64_t)(d0 >> 44);
    c1 = (uint64_t)d1 & MASK44;
    d2 += (uint64_t)(d1 >> 44);
    c2 = (uint64_t)d2 & MASK42;
    k = (uint64_t)(d2 >> 42);

    c0 += k * 5;
    c1 += c0 >> 44;
    c0 &= MASK44;
    c2 += c1 >> 44;
    c1 &= MASK44;

    c[0] = c0;
    c[1] = c1;
    c[2] = c2;
}

/* h = (h + m) * r mod 2^130-5 */
static ossl_inline void poly_block(poly1305_state *st, uint64_t m0, uint64_t m1,
    uint64_t m2)
{
    uint64_t h0 = st->h[0] + m0;
    uint64_t h1 = st->h[1] + m1;
    uint64_t h2 = st->h[2] + m2;
    uint64_t r0 = st->r0, r1 = st->r1, r2 = st->r2;
    uint64_t s1 = st->s1, s2 = st->s2;
    __uint128_t d0, d1, d2;
    uint64_t c;

    d0 = (__uint128_t)h0 * r0 + (__uint128_t)h1 * s2 + (__uint128_t)h2 * s1;
    d1 = (__uint128_t)h0 * r1 + (__uint128_t)h1 * r0 + (__uint128_t)h2 * s2;
    d2 = (__uint128_t)h0 * r2 + (__uint128_t)h1 * r1 + (__uint128_t)h2 * r0;

    h0 = (uint64_t)d0 & MASK44;
    d1 += (uint64_t)(d0 >> 44);
    h1 = (uint64_t)d1 & MASK44;
    d2 += (uint64_t)(d1 >> 44);
    h2 = (uint64_t)d2 & MASK42;
    c = (uint64_t)(d2 >> 42);

    h0 += c * 5;
    h1 += h0 >> 44;
    h0 &= MASK44;

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
}

static ossl_inline void poly_block16(poly1305_state *st, uint64_t lo, uint64_t hi)
{
    poly_block(st, lo & MASK44, ((lo >> 44) | (hi << 20)) & MASK44,
        (hi >> 24) | (1ULL << 40));
}

static ossl_inline void st_load(poly1305_state *st, const OSSL_CP_AVX512_CTX *c)
{
    st->h[0] = c->h[0];
    st->h[1] = c->h[1];
    st->h[2] = c->h[2];
    st->r0 = c->r0;
    st->r1 = c->r1;
    st->r2 = c->r2;
    st->s1 = c->s1;
    st->s2 = c->s2;
    st->nonce0 = c->nonce0;
    st->nonce1 = c->nonce1;
}

static ossl_inline void st_save(OSSL_CP_AVX512_CTX *c, const poly1305_state *st)
{
    c->h[0] = st->h[0];
    c->h[1] = st->h[1];
    c->h[2] = st->h[2];
}

/*
 * Hash a run of bytes through the 16-byte block buffer.  A short tail stays
 * buffered until poly_stream_pad.  AAD and payload may be split across calls.
 */
static void poly_stream(OSSL_CP_AVX512_CTX *ctx, poly1305_state *st,
    const unsigned char *p, size_t n)
{
    uint64_t lo, hi;

    if (ctx->blocklen != 0) {
        size_t k = 16 - ctx->blocklen;

        if (k > n) {
            memcpy(ctx->block + ctx->blocklen, p, n);
            ctx->blocklen += (unsigned int)n;
            return;
        }
        memcpy(ctx->block + ctx->blocklen, p, k);
        memcpy(&lo, ctx->block, 8);
        memcpy(&hi, ctx->block + 8, 8);
        poly_block16(st, lo, hi);
        ctx->blocklen = 0;
        p += k;
        n -= k;
    }

    for (; n >= 16; p += 16, n -= 16) {
        memcpy(&lo, p, 8);
        memcpy(&hi, p + 8, 8);
        poly_block16(st, lo, hi);
    }

    if (n != 0) {
        memcpy(ctx->block, p, n);
        ctx->blocklen = (unsigned int)n;
    }
}

/*
 * Close out a buffered partial block with zeros.  RFC 8439 pads the AAD and
 * the ciphertext separately, so the padded block still carries the 2^128 bit.
 */
static void poly_stream_pad(OSSL_CP_AVX512_CTX *ctx, poly1305_state *st)
{
    uint64_t lo, hi;

    if (ctx->blocklen == 0)
        return;

    memset(ctx->block + ctx->blocklen, 0, 16 - ctx->blocklen);
    memcpy(&lo, ctx->block, 8);
    memcpy(&hi, ctx->block + 8, 8);
    poly_block16(st, lo, hi);
    ctx->blocklen = 0;
}

static void poly_final(poly1305_state *st, unsigned char tag[16])
{
    uint64_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2];
    uint64_t g0, g1, g2, mask, t0, t1;
    __uint128_t f;
    uint64_t c;

    c = h1 >> 44;
    h1 &= MASK44;
    h2 += c;
    c = h2 >> 42;
    h2 &= MASK42;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= MASK44;
    h1 += c;
    c = h1 >> 44;
    h1 &= MASK44;
    h2 += c;

    g0 = h0 + 5;
    c = g0 >> 44;
    g0 &= MASK44;
    g1 = h1 + c;
    c = g1 >> 44;
    g1 &= MASK44;
    g2 = h2 + c - (1ULL << 42);

    mask = 0 - (g2 >> 63);
    g0 &= ~mask;
    g1 &= ~mask;
    g2 &= ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;

    t0 = h0 | (h1 << 44);
    t1 = (h1 >> 20) | (h2 << 24);

    f = (__uint128_t)t0 + st->nonce0;
    t0 = (uint64_t)f;
    f = (__uint128_t)t1 + st->nonce1 + (uint64_t)(f >> 64);
    t1 = (uint64_t)f;

    memcpy(tag, &t0, 8);
    memcpy(tag + 8, &t1, 8);
}

/* --- Poly1305, 8 lanes, AVX512-IFMA ------------------------------------- */

#define VMASK44 _mm512_set1_epi64((long long)MASK44)
#define VMASK42 _mm512_set1_epi64((long long)MASK42)
#define VHIBIT _mm512_set1_epi64(1LL << 40)

/*
 * Two ZMM registers (128 bytes) -> 8 lanes of radix 2^44 limbs, each with the
 * 2^128 bit set.  Callers load those registers from memory.  Seal reads the
 * ciphertext it just stored; open reads the input before the XOR.
 */
static ossl_inline void poly_limbs(__m512i z0, __m512i z1, __m512i *m0,
    __m512i *m1, __m512i *m2)
{
    const __m512i ilo = _mm512_setr_epi64(0, 2, 4, 6, 8, 10, 12, 14);
    const __m512i ihi = _mm512_setr_epi64(1, 3, 5, 7, 9, 11, 13, 15);
    __m512i lo = _mm512_permutex2var_epi64(z0, ilo, z1);
    __m512i hi = _mm512_permutex2var_epi64(z0, ihi, z1);

    *m0 = _mm512_and_si512(lo, VMASK44);
    *m1 = _mm512_and_si512(_mm512_or_si512(_mm512_srli_epi64(lo, 44),
                               _mm512_slli_epi64(hi, 20)),
        VMASK44);
    *m2 = _mm512_or_si512(_mm512_srli_epi64(hi, 24), VHIBIT);
}

static ossl_inline void poly_load8(const unsigned char *p, __m512i *m0,
    __m512i *m1, __m512i *m2)
{
    poly_limbs(_mm512_loadu_si512(p), _mm512_loadu_si512(p + 64), m0, m1, m2);
}

/*
 * acc = acc * r (+ m when add_m).  r0 and r1 are below 2^44 and r2 is below
 * 2^36.  s1 = 20*r1 still fits the 52-bit vpmadd52 operand and can exceed
 * 2^47; s2 = 20*r2 stays below 2^41.  After this partial reduction a0 is
 * below 2^45 once the message limb is added and a2 stays below 2^43.  a1
 * also holds the carry out of a0, so it can exceed 2^45 and stays below
 * 2^46.  Those bounds keep each vpmadd52hi sum below 2^42 and the carry
 * chain inside 64 bits.
 */
#define POLY_MULADD(a0, a1, a2, m0, m1, m2, r0, r1, r2, s1, s2, add_m)             \
    do {                                                                           \
        const __m512i zz = _mm512_setzero_si512();                                 \
        __m512i d0l, d0h, d1l, d1h, d2l, d2h, cc;                                  \
                                                                                   \
        d0l = _mm512_madd52lo_epu64(zz, a0, r0);                                   \
        d0h = _mm512_madd52hi_epu64(zz, a0, r0);                                   \
        d1l = _mm512_madd52lo_epu64(zz, a0, r1);                                   \
        d1h = _mm512_madd52hi_epu64(zz, a0, r1);                                   \
        d2l = _mm512_madd52lo_epu64(zz, a0, r2);                                   \
        d2h = _mm512_madd52hi_epu64(zz, a0, r2);                                   \
                                                                                   \
        d0l = _mm512_madd52lo_epu64(d0l, a1, s2);                                  \
        d0h = _mm512_madd52hi_epu64(d0h, a1, s2);                                  \
        d1l = _mm512_madd52lo_epu64(d1l, a1, r0);                                  \
        d1h = _mm512_madd52hi_epu64(d1h, a1, r0);                                  \
        d2l = _mm512_madd52lo_epu64(d2l, a1, r1);                                  \
        d2h = _mm512_madd52hi_epu64(d2h, a1, r1);                                  \
                                                                                   \
        d0l = _mm512_madd52lo_epu64(d0l, a2, s1);                                  \
        d0h = _mm512_madd52hi_epu64(d0h, a2, s1);                                  \
        d1l = _mm512_madd52lo_epu64(d1l, a2, s2);                                  \
        d1h = _mm512_madd52hi_epu64(d1h, a2, s2);                                  \
        d2l = _mm512_madd52lo_epu64(d2l, a2, r0);                                  \
        d2h = _mm512_madd52hi_epu64(d2h, a2, r0);                                  \
                                                                                   \
        cc = _mm512_add_epi64(_mm512_srli_epi64(d0l, 44),                          \
            _mm512_slli_epi64(d0h, 8));                                            \
        a0 = _mm512_and_si512(d0l, VMASK44);                                       \
        d1l = _mm512_add_epi64(d1l, cc);                                           \
                                                                                   \
        cc = _mm512_add_epi64(_mm512_srli_epi64(d1l, 44),                          \
            _mm512_slli_epi64(d1h, 8));                                            \
        a1 = _mm512_and_si512(d1l, VMASK44);                                       \
        d2l = _mm512_add_epi64(d2l, cc);                                           \
                                                                                   \
        cc = _mm512_add_epi64(_mm512_srli_epi64(d2l, 42),                          \
            _mm512_slli_epi64(d2h, 10));                                           \
        a2 = _mm512_and_si512(d2l, VMASK42);                                       \
                                                                                   \
        a0 = _mm512_add_epi64(a0, _mm512_add_epi64(_mm512_slli_epi64(cc, 2), cc)); \
        a1 = _mm512_add_epi64(a1, _mm512_srli_epi64(a0, 44));                      \
        a0 = _mm512_and_si512(a0, VMASK44);                                        \
                                                                                   \
        if (add_m) {                                                               \
            a0 = _mm512_add_epi64(a0, m0);                                         \
            a1 = _mm512_add_epi64(a1, m1);                                         \
            a2 = _mm512_add_epi64(a2, m2);                                         \
        }                                                                          \
    } while (0)

/* --- ChaCha20 ----------------------------------------------------------- */

#define QROUND(a, b, c, d)           \
    do {                             \
        a = _mm512_add_epi32(a, b);  \
        d = _mm512_xor_si512(d, a);  \
        d = _mm512_rol_epi32(d, 16); \
        c = _mm512_add_epi32(c, d);  \
        b = _mm512_xor_si512(b, c);  \
        b = _mm512_rol_epi32(b, 12); \
        a = _mm512_add_epi32(a, b);  \
        d = _mm512_xor_si512(d, a);  \
        d = _mm512_rol_epi32(d, 8);  \
        c = _mm512_add_epi32(c, d);  \
        b = _mm512_xor_si512(b, c);  \
        b = _mm512_rol_epi32(b, 7);  \
    } while (0)

#define DIAGONALIZE(b, c, d)                              \
    do {                                                  \
        b = _mm512_shuffle_epi32(b, (_MM_PERM_ENUM)0x39); \
        c = _mm512_shuffle_epi32(c, (_MM_PERM_ENUM)0x4e); \
        d = _mm512_shuffle_epi32(d, (_MM_PERM_ENUM)0x93); \
    } while (0)

#define UNDIAGONALIZE(b, c, d)                            \
    do {                                                  \
        b = _mm512_shuffle_epi32(b, (_MM_PERM_ENUM)0x93); \
        c = _mm512_shuffle_epi32(c, (_MM_PERM_ENUM)0x4e); \
        d = _mm512_shuffle_epi32(d, (_MM_PERM_ENUM)0x39); \
    } while (0)

/* Gather four blocks spread one per 128-bit lane into four contiguous blocks. */
#define TRANSPOSE128(a, b, c, d, t)                    \
    do {                                               \
        __m512i u0 = _mm512_shuffle_i32x4(a, b, 0x44); \
        __m512i u1 = _mm512_shuffle_i32x4(a, b, 0xee); \
        __m512i u2 = _mm512_shuffle_i32x4(c, d, 0x44); \
        __m512i u3 = _mm512_shuffle_i32x4(c, d, 0xee); \
                                                       \
        t[0] = _mm512_shuffle_i32x4(u0, u2, 0x88);     \
        t[1] = _mm512_shuffle_i32x4(u0, u2, 0xdd);     \
        t[2] = _mm512_shuffle_i32x4(u1, u3, 0x88);     \
        t[3] = _mm512_shuffle_i32x4(u1, u3, 0xdd);     \
    } while (0)

#define XS1(dst, src, kk)      \
    _mm512_storeu_si512((dst), \
        _mm512_xor_si512(_mm512_loadu_si512(src), (kk)))

static ossl_inline __m512i chacha_counter_state(const unsigned int counter[4],
    uint32_t ctr)
{
    __m512i v = _mm512_broadcast_i32x4(_mm_setr_epi32((int)ctr,
        (int)counter[1],
        (int)counter[2],
        (int)counter[3]));

    return _mm512_add_epi32(v, _mm512_setr_epi32(0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0));
}

/* One group: 4 blocks / 256 bytes. */
static ossl_inline void chacha_group(__m512i s0, __m512i s1, __m512i s2,
    __m512i s3, __m512i t[4])
{
    __m512i a = s0, b = s1, c = s2, d = s3;
    int i;

    for (i = 0; i < 10; i++) {
        QROUND(a, b, c, d);
        DIAGONALIZE(b, c, d);
        QROUND(a, b, c, d);
        UNDIAGONALIZE(b, c, d);
    }
    a = _mm512_add_epi32(a, s0);
    b = _mm512_add_epi32(b, s1);
    c = _mm512_add_epi32(c, s2);
    d = _mm512_add_epi32(d, s3);
    TRANSPOSE128(a, b, c, d, t);
}

/*
 * 16 blocks, 1024 bytes.  Register w holds state word w for all 16 blocks,
 * so a diagonal round is a different choice of registers and the round
 * itself has no shuffles.  A 16x16 transpose runs before the XOR.
 */
#define CHACHA_DECL                         \
    __m512i v0, v1, v2, v3, v4, v5, v6, v7; \
    __m512i v8, v9, v10, v11, v12, v13, v14, v15

#define VINCR _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7, \
    8, 9, 10, 11, 12, 13, 14, 15)

#define CHACHA_INIT(cv)                                              \
    do {                                                             \
        v0 = _mm512_set1_epi32(0x61707865);                          \
        v1 = _mm512_set1_epi32(0x3320646e);                          \
        v2 = _mm512_set1_epi32(0x79622d32);                          \
        v3 = _mm512_set1_epi32(0x6b206574);                          \
        v4 = _mm512_set1_epi32((int)key[0]);                         \
        v5 = _mm512_set1_epi32((int)key[1]);                         \
        v6 = _mm512_set1_epi32((int)key[2]);                         \
        v7 = _mm512_set1_epi32((int)key[3]);                         \
        v8 = _mm512_set1_epi32((int)key[4]);                         \
        v9 = _mm512_set1_epi32((int)key[5]);                         \
        v10 = _mm512_set1_epi32((int)key[6]);                        \
        v11 = _mm512_set1_epi32((int)key[7]);                        \
        v12 = _mm512_add_epi32(_mm512_set1_epi32((int)(cv)), VINCR); \
        v13 = _mm512_set1_epi32((int)counter[1]);                    \
        v14 = _mm512_set1_epi32((int)counter[2]);                    \
        v15 = _mm512_set1_epi32((int)counter[3]);                    \
    } while (0)

#define CHACHA_DROUND()           \
    do {                          \
        QROUND(v0, v4, v8, v12);  \
        QROUND(v1, v5, v9, v13);  \
        QROUND(v2, v6, v10, v14); \
        QROUND(v3, v7, v11, v15); \
        QROUND(v0, v5, v10, v15); \
        QROUND(v1, v6, v11, v12); \
        QROUND(v2, v7, v8, v13);  \
        QROUND(v3, v4, v9, v14);  \
    } while (0)

#define CHACHA_FINISH(cv)                                                \
    do {                                                                 \
        v0 = _mm512_add_epi32(v0, _mm512_set1_epi32(0x61707865));        \
        v1 = _mm512_add_epi32(v1, _mm512_set1_epi32(0x3320646e));        \
        v2 = _mm512_add_epi32(v2, _mm512_set1_epi32(0x79622d32));        \
        v3 = _mm512_add_epi32(v3, _mm512_set1_epi32(0x6b206574));        \
        v4 = _mm512_add_epi32(v4, _mm512_set1_epi32((int)key[0]));       \
        v5 = _mm512_add_epi32(v5, _mm512_set1_epi32((int)key[1]));       \
        v6 = _mm512_add_epi32(v6, _mm512_set1_epi32((int)key[2]));       \
        v7 = _mm512_add_epi32(v7, _mm512_set1_epi32((int)key[3]));       \
        v8 = _mm512_add_epi32(v8, _mm512_set1_epi32((int)key[4]));       \
        v9 = _mm512_add_epi32(v9, _mm512_set1_epi32((int)key[5]));       \
        v10 = _mm512_add_epi32(v10, _mm512_set1_epi32((int)key[6]));     \
        v11 = _mm512_add_epi32(v11, _mm512_set1_epi32((int)key[7]));     \
        v12 = _mm512_add_epi32(v12,                                      \
            _mm512_add_epi32(_mm512_set1_epi32((int)(cv)), VINCR));      \
        v13 = _mm512_add_epi32(v13, _mm512_set1_epi32((int)counter[1])); \
        v14 = _mm512_add_epi32(v14, _mm512_set1_epi32((int)counter[2])); \
        v15 = _mm512_add_epi32(v15, _mm512_set1_epi32((int)counter[3])); \
    } while (0)

#define UNPACK32(a, b)                            \
    do {                                          \
        __m512i tt = _mm512_unpacklo_epi32(a, b); \
                                                  \
        b = _mm512_unpackhi_epi32(a, b);          \
        a = tt;                                   \
    } while (0)

#define UNPACK64(a, b)                            \
    do {                                          \
        __m512i tt = _mm512_unpacklo_epi64(a, b); \
                                                  \
        b = _mm512_unpackhi_epi64(a, b);          \
        a = tt;                                   \
    } while (0)

/*
 * After the two unpack stages, register A/B/C/D of column k holds words
 * 0-3 / 4-7 / 8-11 / 12-15 of block (4j + k) in its 128-bit lane j.  Gathering
 * lane j from all four yields one whole block, so column k emits blocks
 * k, k+4, k+8 and k+12.
 */
#define EMIT4(dst, src, A, B, C, D, kk)                                       \
    do {                                                                      \
        __m512i ab_lo = _mm512_shuffle_i32x4(A, B, 0x44);                     \
        __m512i ab_hi = _mm512_shuffle_i32x4(A, B, 0xee);                     \
        __m512i cd_lo = _mm512_shuffle_i32x4(C, D, 0x44);                     \
        __m512i cd_hi = _mm512_shuffle_i32x4(C, D, 0xee);                     \
                                                                              \
        XS1((dst) + ((kk) + 0) * CHACHA_BLK, (src) + ((kk) + 0) * CHACHA_BLK, \
            _mm512_shuffle_i32x4(ab_lo, cd_lo, 0x88));                        \
        XS1((dst) + ((kk) + 4) * CHACHA_BLK, (src) + ((kk) + 4) * CHACHA_BLK, \
            _mm512_shuffle_i32x4(ab_lo, cd_lo, 0xdd));                        \
        XS1((dst) + ((kk) + 8) * CHACHA_BLK, (src) + ((kk) + 8) * CHACHA_BLK, \
            _mm512_shuffle_i32x4(ab_hi, cd_hi, 0x88));                        \
        XS1((dst) + ((kk) + 12) * CHACHA_BLK,                                 \
            (src) + ((kk) + 12) * CHACHA_BLK,                                 \
            _mm512_shuffle_i32x4(ab_hi, cd_hi, 0xdd));                        \
    } while (0)

/*
 * Partial emit, for a run shorter than 16 blocks.  Blocks below nfull are
 * XORed out whole.  Block nfull and every block after it are parked in ksp.
 * When the tail is not a multiple of 64, block nfull is only partly consumed
 * and the rest of it stays parked.  nfull and ksp come from the enclosing
 * scope, as v0-v15 do.
 */
#define EMIT1_N(dst, src, kk, blk)                                         \
    do {                                                                   \
        if ((size_t)(kk) < nfull)                                          \
            XS1((dst) + (size_t)(kk) * CHACHA_BLK,                         \
                (src) + (size_t)(kk) * CHACHA_BLK, (blk));                 \
        else                                                               \
            _mm512_storeu_si512(ksp + ((size_t)(kk) - nfull) * CHACHA_BLK, \
                (blk));                                                    \
    } while (0)

#define EMIT4_N(dst, src, A, B, C, D, kk)                 \
    do {                                                  \
        __m512i ab_lo = _mm512_shuffle_i32x4(A, B, 0x44); \
        __m512i ab_hi = _mm512_shuffle_i32x4(A, B, 0xee); \
        __m512i cd_lo = _mm512_shuffle_i32x4(C, D, 0x44); \
        __m512i cd_hi = _mm512_shuffle_i32x4(C, D, 0xee); \
                                                          \
        EMIT1_N((dst), (src), (kk) + 0,                   \
            _mm512_shuffle_i32x4(ab_lo, cd_lo, 0x88));    \
        EMIT1_N((dst), (src), (kk) + 4,                   \
            _mm512_shuffle_i32x4(ab_lo, cd_lo, 0xdd));    \
        EMIT1_N((dst), (src), (kk) + 8,                   \
            _mm512_shuffle_i32x4(ab_hi, cd_hi, 0x88));    \
        EMIT1_N((dst), (src), (kk) + 12,                  \
            _mm512_shuffle_i32x4(ab_hi, cd_hi, 0xdd));    \
    } while (0)

/* Keystream straight out, no message to XOR against. */
#define KS4(dst, A, B, C, D, kk)                              \
    do {                                                      \
        __m512i ab_lo = _mm512_shuffle_i32x4(A, B, 0x44);     \
        __m512i ab_hi = _mm512_shuffle_i32x4(A, B, 0xee);     \
        __m512i cd_lo = _mm512_shuffle_i32x4(C, D, 0x44);     \
        __m512i cd_hi = _mm512_shuffle_i32x4(C, D, 0xee);     \
                                                              \
        _mm512_storeu_si512((dst) + ((kk) + 0) * CHACHA_BLK,  \
            _mm512_shuffle_i32x4(ab_lo, cd_lo, 0x88));        \
        _mm512_storeu_si512((dst) + ((kk) + 4) * CHACHA_BLK,  \
            _mm512_shuffle_i32x4(ab_lo, cd_lo, 0xdd));        \
        _mm512_storeu_si512((dst) + ((kk) + 8) * CHACHA_BLK,  \
            _mm512_shuffle_i32x4(ab_hi, cd_hi, 0x88));        \
        _mm512_storeu_si512((dst) + ((kk) + 12) * CHACHA_BLK, \
            _mm512_shuffle_i32x4(ab_hi, cd_hi, 0xdd));        \
    } while (0)

#define CHACHA_KS_STORE(dst)             \
    do {                                 \
        UNPACK32(v0, v1);                \
        UNPACK32(v2, v3);                \
        UNPACK32(v4, v5);                \
        UNPACK32(v6, v7);                \
        UNPACK32(v8, v9);                \
        UNPACK32(v10, v11);              \
        UNPACK32(v12, v13);              \
        UNPACK32(v14, v15);              \
        UNPACK64(v0, v2);                \
        UNPACK64(v1, v3);                \
        UNPACK64(v4, v6);                \
        UNPACK64(v5, v7);                \
        UNPACK64(v8, v10);               \
        UNPACK64(v9, v11);               \
        UNPACK64(v12, v14);              \
        UNPACK64(v13, v15);              \
        KS4((dst), v0, v4, v8, v12, 0);  \
        KS4((dst), v2, v6, v10, v14, 1); \
        KS4((dst), v1, v5, v9, v13, 2);  \
        KS4((dst), v3, v7, v11, v15, 3); \
    } while (0)

#define CHACHA_XOR_STORE_N(dst, src)                \
    do {                                            \
        UNPACK32(v0, v1);                           \
        UNPACK32(v2, v3);                           \
        UNPACK32(v4, v5);                           \
        UNPACK32(v6, v7);                           \
        UNPACK32(v8, v9);                           \
        UNPACK32(v10, v11);                         \
        UNPACK32(v12, v13);                         \
        UNPACK32(v14, v15);                         \
        UNPACK64(v0, v2);                           \
        UNPACK64(v1, v3);                           \
        UNPACK64(v4, v6);                           \
        UNPACK64(v5, v7);                           \
        UNPACK64(v8, v10);                          \
        UNPACK64(v9, v11);                          \
        UNPACK64(v12, v14);                         \
        UNPACK64(v13, v15);                         \
        EMIT4_N((dst), (src), v0, v4, v8, v12, 0);  \
        EMIT4_N((dst), (src), v2, v6, v10, v14, 1); \
        EMIT4_N((dst), (src), v1, v5, v9, v13, 2);  \
        EMIT4_N((dst), (src), v3, v7, v11, v15, 3); \
    } while (0)

#define CHACHA_XOR_STORE(dst, src)                \
    do {                                          \
        UNPACK32(v0, v1);                         \
        UNPACK32(v2, v3);                         \
        UNPACK32(v4, v5);                         \
        UNPACK32(v6, v7);                         \
        UNPACK32(v8, v9);                         \
        UNPACK32(v10, v11);                       \
        UNPACK32(v12, v13);                       \
        UNPACK32(v14, v15);                       \
        UNPACK64(v0, v2);                         \
        UNPACK64(v1, v3);                         \
        UNPACK64(v4, v6);                         \
        UNPACK64(v5, v7);                         \
        UNPACK64(v8, v10);                        \
        UNPACK64(v9, v11);                        \
        UNPACK64(v12, v14);                       \
        UNPACK64(v13, v15);                       \
        EMIT4((dst), (src), v0, v4, v8, v12, 0);  \
        EMIT4((dst), (src), v2, v6, v10, v14, 1); \
        EMIT4((dst), (src), v1, v5, v9, v13, 2);  \
        EMIT4((dst), (src), v3, v7, v11, v15, 3); \
    } while (0)

/*
 * One 8-block Poly1305 group.  The first group after POLY_SEED is an add,
 * so the accumulator seeded into lane 0 has the same weight as the message
 * blocks in that group.  Later groups are multiply-adds by r^8.
 */
#define POLY_STEP(m0_, m1_, m2_)                   \
    do {                                           \
        if (started) {                             \
            POLY_MULADD(a0, a1, a2, m0_, m1_, m2_, \
                vr0, vr1, vr2, vs1, vs2, 1);       \
        } else {                                   \
            a0 = _mm512_add_epi64(a0, m0_);        \
            a1 = _mm512_add_epi64(a1, m1_);        \
            a2 = _mm512_add_epi64(a2, m2_);        \
            started = 1;                           \
        }                                          \
    } while (0)

#define POLY_GROUP(p)                      \
    do {                                   \
        __m512i m0_, m1_, m2_;             \
                                           \
        poly_load8((p), &m0_, &m1_, &m2_); \
        POLY_STEP(m0_, m1_, m2_);          \
    } while (0)

/*
 * Lane 0 carries the accumulator built so far.  The first group is an add,
 * so the seed and the blocks of that group share the same r^(8k) weight.
 * Later groups are multiplied by r^8 first.
 */
#define POLY_SEED()                                             \
    do {                                                        \
        a0 = _mm512_maskz_set1_epi64(0x01, (long long)st.h[0]); \
        a1 = _mm512_maskz_set1_epi64(0x01, (long long)st.h[1]); \
        a2 = _mm512_maskz_set1_epi64(0x01, (long long)st.h[2]); \
        started = 0;                                            \
    } while (0)

/* Collapse the 8 lanes: lane i is weighted by r^(8-i), then summed. */
#define POLY_FOLD()                                                     \
    do {                                                                \
        if (started) {                                                  \
            __m512i p0 = _mm512_loadu_si512(pw[0]);                     \
            __m512i p1 = _mm512_loadu_si512(pw[1]);                     \
            __m512i p2 = _mm512_loadu_si512(pw[2]);                     \
            __m512i q1 = _mm512_add_epi64(_mm512_slli_epi64(p1, 4),     \
                _mm512_slli_epi64(p1, 2));                              \
            __m512i q2 = _mm512_add_epi64(_mm512_slli_epi64(p2, 4),     \
                _mm512_slli_epi64(p2, 2));                              \
            __m512i zm = _mm512_setzero_si512();                        \
                                                                        \
            POLY_MULADD(a0, a1, a2, zm, zm, zm, p0, p1, p2, q1, q2, 0); \
                                                                        \
            st.h[0] = (uint64_t)_mm512_reduce_add_epi64(a0);            \
            st.h[1] = (uint64_t)_mm512_reduce_add_epi64(a1);            \
            st.h[2] = (uint64_t)_mm512_reduce_add_epi64(a2);            \
            started = 0;                                                \
        }                                                               \
    } while (0)

static void stream_init(OSSL_CP_AVX512_CTX *ctx, const unsigned int key[8],
    const unsigned int counter[4], size_t hint)
{
    poly1305_state st;
    unsigned char polyblock[CHACHA_BLK];

    /*
     * (192, 960] parks 960 bytes.  Any other hint parks 192.  Input is
     * not read.
     */
    if (hint > PARK_192 && hint <= PARK_960) {
        /* Block 0 is the one-time Poly1305 key.  Blocks 1..15 stay parked. */
        CHACHA_DECL;
        int rr;

        CHACHA_INIT(0);
        for (rr = 0; rr < 10; rr++)
            CHACHA_DROUND();
        CHACHA_FINISH(0);
        CHACHA_KS_STORE(ctx->ks);

        poly_init(&st, ctx->ks);
        /* Block 0 is already in r and the nonce. */
        OPENSSL_cleanse(ctx->ks, CHACHA_BLK);
        ctx->ksoff = CHACHA_BLK;
        ctx->ksinit = PARK_960;
    } else {
        /* Block 0 is the one-time Poly1305 key.  Blocks 1..3 stay parked. */
        __m512i s0, s1, s2, ks[4];

        s0 = _mm512_broadcast_i32x4(_mm_setr_epi32(0x61707865, 0x3320646e,
            0x79622d32, 0x6b206574));
        s1 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *)key));
        s2 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *)(key + 4)));

        chacha_group(s0, s1, s2, chacha_counter_state(counter, 0), ks);
        _mm512_storeu_si512(polyblock, ks[0]);
        poly_init(&st, polyblock);
        OPENSSL_cleanse(polyblock, sizeof(polyblock));

        _mm512_storeu_si512(ctx->ks, ks[1]);
        _mm512_storeu_si512(ctx->ks + CHACHA_BLK, ks[2]);
        _mm512_storeu_si512(ctx->ks + 2 * CHACHA_BLK, ks[3]);
        ctx->ksoff = 0;
        ctx->ksinit = PARK_192;
    }

    ctx->h[0] = ctx->h[1] = ctx->h[2] = 0;
    ctx->r0 = st.r0;
    ctx->r1 = st.r1;
    ctx->r2 = st.r2;
    ctx->s1 = st.s1;
    ctx->s2 = st.s2;
    ctx->nonce0 = st.nonce0;
    ctx->nonce1 = st.nonce1;
    memcpy(ctx->key, key, 8 * sizeof(unsigned int));
    memcpy(ctx->counter, counter, 4 * sizeof(unsigned int));
    ctx->ctr = 1;
    ctx->textlen = 0;
    ctx->kslen = 0;
    ctx->blocklen = 0;
    ctx->powers = 0;
    ctx->calls = 0;
    ctx->ahead = 0;
    OPENSSL_cleanse(&st, sizeof(st));
}

/*
 * r^1..r^8 laid out so lane i holds r^(8-i), which is both the fold weight and
 * (in lane 0) the r^8 step the 8 lanes advance by.  Only worth building once
 * there is enough payload to reach the vector path.
 */
static void stream_powers(OSSL_CP_AVX512_CTX *ctx)
{
    uint64_t r[3], cur[3];
    int k;

    r[0] = ctx->r0;
    r[1] = ctx->r1;
    r[2] = ctx->r2;
    cur[0] = r[0];
    cur[1] = r[1];
    cur[2] = r[2];

    /* Lane (8-k) receives r^k.  ctx->pw is the table the fold loads. */
    for (k = 1; k <= POLY_LANES; k++) {
        ctx->pw[0][POLY_LANES - k] = cur[0];
        ctx->pw[1][POLY_LANES - k] = cur[1];
        ctx->pw[2][POLY_LANES - k] = cur[2];
        if (k != POLY_LANES)
            poly44_mul(cur, cur, r);
    }
    ctx->powers = 1;
    OPENSSL_cleanse(cur, sizeof(cur));
    OPENSSL_cleanse(r, sizeof(r));
}

/*
 * Hash a whole region: 8-block groups through the lanes, the rest scalar.
 * Used where there is no ChaCha20 work left to interleave with.
 *
 * The lanes read the message directly and so bypass the 16-byte block
 * buffer, which a call that stopped mid-block will have left occupied.  That
 * has to be emptied first, and the accumulator seeded only afterwards, since
 * emptying it moves h.
 */
#define POLY_REGION(p, nbytes)                            \
    do {                                                  \
        const unsigned char *p_ = (p);                    \
        size_t nb_ = (nbytes);                            \
        size_t vb_, g_;                                   \
                                                          \
        if (ctx->blocklen != 0) {                         \
            size_t f_ = 16 - ctx->blocklen;               \
                                                          \
            if (f_ > nb_)                                 \
                f_ = nb_;                                 \
            poly_stream(ctx, &st, p_, f_);                \
            p_ += f_;                                     \
            nb_ -= f_;                                    \
        }                                                 \
        POLY_SEED();                                      \
        vb_ = ctx->powers                                 \
            ? (nb_ / POLY_GROUP_BYTES) * POLY_GROUP_BYTES \
            : 0;                                          \
        for (g_ = 0; g_ < vb_; g_ += POLY_GROUP_BYTES)    \
            POLY_GROUP(p_ + g_);                          \
        POLY_FOLD();                                      \
        if (nb_ > vb_)                                    \
            poly_stream(ctx, &st, p_ + vb_, nb_ - vb_);   \
    } while (0)

/*
 * One 16-block ChaCha20 pass.  When mac_len is at least 128, one 128-byte
 * group is hashed after each of the first eight double rounds.  Hashing
 * stops once mac_len is exhausted, so a short prefix is not read as a full
 * chunk.  Returns how many mac bytes were hashed.  ks_dst != NULL stores
 * the keystream and skips the XOR.  The first encrypt chunk passes a NULL
 * mac: its ciphertext does not exist until the XOR.  always_inline keeps
 * the 16 live ZMM registers from being spilled around a call.
 */
static ossl_inline __attribute__((always_inline)) size_t chacha16_xor(uint32_t cv,
    const unsigned int key[8], const unsigned int counter[4],
    unsigned char *out, const unsigned char *in,
    const unsigned char *mac, size_t mac_len, unsigned char *ks_dst,
    __m512i *a0p, __m512i *a1p, __m512i *a2p, int *startedp,
    __m512i vr0, __m512i vr1, __m512i vr2,
    __m512i vs1, __m512i vs2)
{
    CHACHA_DECL;
    __m512i a0 = *a0p, a1 = *a1p, a2 = *a2p;
    int started = *startedp;
    size_t hashed = 0;
    int rr;

    CHACHA_INIT(cv);
    for (rr = 0; rr < 10; rr++) {
        CHACHA_DROUND();
        if (mac != NULL && hashed + POLY_GROUP_BYTES <= mac_len
            && rr < (int)(CHUNK_BYTES / POLY_GROUP_BYTES)) {
            POLY_GROUP(mac + hashed);
            hashed += POLY_GROUP_BYTES;
        }
    }
    CHACHA_FINISH(cv);
    if (ks_dst != NULL)
        CHACHA_KS_STORE(ks_dst);
    else
        CHACHA_XOR_STORE(out, in);

    *a0p = a0;
    *a1p = a1;
    *a2p = a2;
    *startedp = started;
    return hashed;
}

/* The lane state is local to the caller; this only shortens the calls. */
#define CHACHA16_XOR(cv, dst, src, macp)                         \
    (void)chacha16_xor((cv), key, counter, (dst), (src), (macp), \
        (macp) != NULL ? (size_t)CHUNK_BYTES : (size_t)0, NULL,  \
        &a0, &a1, &a2, &started, vr0, vr1, vr2, vs1, vs2)

#define CHACHA16_KS(cv, ksdst, macp, macn)                             \
    (void)chacha16_xor((cv), key, counter, NULL, NULL, (macp), (macn), \
        (ksdst), &a0, &a1, &a2, &started, vr0, vr1, vr2, vs1, vs2)

/*
 * Claim the init park when this update fits.  Otherwise drop it and leave
 * ctr at 1.  The 960-byte park starts at ksoff 64.  A dropped park is empty
 * when ksoff >= kslen.
 */
#define STREAM_CLAIM_INIT()                              \
    do {                                                 \
        if (ctx->ksinit != 0) {                          \
            if (len <= ctx->ksinit) {                    \
                ctx->kslen = ctx->ksoff + ctx->ksinit;   \
                ctx->ctr = 1 + ctx->ksinit / CHACHA_BLK; \
            } else {                                     \
                ctx->ksoff = 0;                          \
                ctx->kslen = 0;                          \
            }                                            \
            ctx->ksinit = 0;                             \
        }                                                \
    } while (0)

#define STREAM_LOAD_POWERS()                                      \
    do {                                                          \
        if (!ctx->powers && len >= POLY_VEC_MIN)                  \
            stream_powers(ctx);                                   \
        if (ctx->powers) {                                        \
            vr0 = _mm512_set1_epi64((long long)pw[0][0]);         \
            vr1 = _mm512_set1_epi64((long long)pw[1][0]);         \
            vr2 = _mm512_set1_epi64((long long)pw[2][0]);         \
            vs1 = _mm512_set1_epi64((long long)(pw[1][0] * 20));  \
            vs2 = _mm512_set1_epi64((long long)(pw[2][0] * 20));  \
        } else {                                                  \
            vr0 = vr1 = vr2 = vs1 = vs2 = _mm512_setzero_si512(); \
        }                                                         \
    } while (0)

/* XOR parked keystream.  The caller hashes before or after this. */
#define STREAM_XOR_PARKED(k_, ks_)                                  \
    do {                                                            \
        size_t j_;                                                  \
                                                                    \
        for (j_ = 0; j_ + CHACHA_BLK <= (k_); j_ += CHACHA_BLK)     \
            XS1(out + j_, in + j_, _mm512_loadu_si512((ks_) + j_)); \
        for (; j_ < (k_); j_++)                                     \
            out[j_] = in[j_] ^ (ks_)[j_];                           \
    } while (0)

/*
 * Spend keystream already parked in the context.  MAC_AFTER is 1 for seal
 * (hash the ciphertext just written) and 0 for open (hash the input first).
 * Returns from the caller when that finishes the update.  Uses the caller's
 * out, in, len, st, and Poly1305 lanes, so it does not copy them.
 */
#define STREAM_SPEND_PARKED(mac_after)                       \
    do {                                                     \
        if (ctx->ksoff < ctx->kslen) {                       \
            const unsigned char *ks_ = ctx->ks + ctx->ksoff; \
            size_t k_ = ctx->kslen - ctx->ksoff;             \
                                                             \
            if (k_ > len)                                    \
                k_ = len;                                    \
            if (mac_after) {                                 \
                STREAM_XOR_PARKED(k_, ks_);                  \
                POLY_REGION(out, k_);                        \
            } else {                                         \
                POLY_REGION(in, k_);                         \
                STREAM_XOR_PARKED(k_, ks_);                  \
            }                                                \
            ctx->ksoff += (unsigned int)k_;                  \
            in += k_;                                        \
            out += k_;                                       \
            len -= k_;                                       \
            if (len == 0) {                                  \
                ctx->calls++;                                \
                st_save(ctx, &st);                           \
                OPENSSL_cleanse(&st, sizeof(st));            \
                return;                                      \
            }                                                \
        }                                                    \
    } while (0)

/*
 * Park the blocks this tail did not emit.  The pass covered ctr..ctr+15
 * whatever the message used, so the counter moves on by all of them.
 */
#define STREAM_PARK_TAIL(rem_, nfull_)                        \
    do {                                                      \
        ctx->ksoff = (unsigned int)(rem_);                    \
        ctx->kslen = (unsigned int)((CHUNK_BYTES / CHACHA_BLK \
                                        - (nfull_))           \
            * CHACHA_BLK);                                    \
        ctr += CHUNK_BYTES / CHACHA_BLK;                      \
    } while (0)

/*
 * Seal: ciphertext appears at the XOR, so the bulk loop hashes chunk k
 * while generating keystream for chunk k+1.  A tail is hashed after its XOR.
 */
static void stream_seal(OSSL_CP_AVX512_CTX *ctx, unsigned char *out,
    const unsigned char *in, size_t len)
{
    poly1305_state st;
    __m512i a0, a1, a2, vr0, vr1, vr2, vs1, vs2;
    uint64_t (*pw)[POLY_LANES] = ctx->pw;
    const unsigned int *key = ctx->key;
    const unsigned int *counter = ctx->counter;
    uint32_t ctr;
    size_t n;
    int started = 0;

    if (len == 0)
        return;

    st_load(&st, ctx);
    /* A prefetched chunk is keystream for this call only when the call is
     * another 1024-byte encrypt.  Any other length spends it as a normal
     * park and hashes it on its own. */
    if (ctx->ahead && len != CHUNK_BYTES)
        ctx->ahead = 0;

    STREAM_CLAIM_INIT();
    STREAM_LOAD_POWERS();
    ctr = ctx->ctr;

    if (len == CHUNK_BYTES && ctx->calls >= 1 && ctx->powers) {
        int prefetch = 0;

        if (ctx->ahead && ctx->kslen > ctx->ksoff
            && ctx->kslen - ctx->ksoff >= CHUNK_BYTES) {
            const unsigned char *ks = ctx->ks + ctx->ksoff;
            size_t j;

            for (j = 0; j < CHUNK_BYTES; j += CHACHA_BLK)
                XS1(out + j, in + j, _mm512_loadu_si512(ks + j));
            prefetch = 1;
        } else if (ctx->ksoff >= ctx->kslen) {
            CHACHA16_XOR(ctr, out, in, NULL);
            ctr += CHUNK_BYTES / CHACHA_BLK;
            prefetch = 1;
        }

        if (prefetch) {
            if (!started)
                POLY_SEED();
            CHACHA16_KS(ctr, ctx->ks, out, CHUNK_BYTES);
            ctr += CHUNK_BYTES / CHACHA_BLK;
            ctx->ksoff = 0;
            ctx->kslen = CHUNK_BYTES;
            ctx->ahead = 1;
            ctx->calls++;
            ctx->ctr = ctr;
            POLY_FOLD();
            st_save(ctx, &st);
            OPENSSL_cleanse(&st, sizeof(st));
            return;
        }
    }

    /* Parked keystream is hashed on its own. */
    STREAM_SPEND_PARKED(1);

    ctr = ctx->ctr;
    n = len;
    POLY_SEED();

    if (n >= CHUNK_BYTES) {
        const size_t nchunks = n / CHUNK_BYTES;
        size_t c;

        /* No ciphertext yet, so this pass only generates keystream. */
        CHACHA16_XOR(ctr, out, in, NULL);
        ctr += 16;

        for (c = 1; c < nchunks; c++) {
            const unsigned char *prev = out;

            out += CHUNK_BYTES;
            in += CHUNK_BYTES;
            /* Hash the chunk just produced while generating the next. */
            CHACHA16_XOR(ctr, out, in, prev);
            ctr += 16;
        }

        /* The last chunk exists only after the loop above. */
        for (c = 0; c < CHUNK_BYTES / POLY_GROUP_BYTES; c++)
            POLY_GROUP(out + c * POLY_GROUP_BYTES);

        out += CHUNK_BYTES;
        in += CHUNK_BYTES;
        n -= nchunks * CHUNK_BYTES;
    }

    /*
     * Tail: fewer than 1024 bytes left.  One 16-block pass still runs every
     * lane.  Only the blocks the tail reaches are emitted.  The ciphertext
     * does not exist until the XOR, so the tail MAC follows it.
     */
    if (n != 0) {
        const size_t tail = n;
        const size_t nfull = tail / CHACHA_BLK;
        const size_t rem = tail % CHACHA_BLK;
        const size_t vec_bytes = ctx->powers
            ? (tail / POLY_GROUP_BYTES) * POLY_GROUP_BYTES
            : 0;
        unsigned char *const ksp = ctx->ks;
        size_t g;
        int rr;
        CHACHA_DECL;

        CHACHA_INIT(ctr);
        for (rr = 0; rr < 10; rr++)
            CHACHA_DROUND();
        CHACHA_FINISH(ctr);
        CHACHA_XOR_STORE_N(out, in);

        if (rem != 0) {
            const size_t base = nfull * CHACHA_BLK;
            size_t k;

            for (k = 0; k < rem; k++)
                out[base + k] = in[base + k] ^ ksp[k];
        }

        STREAM_PARK_TAIL(rem, nfull);

        for (g = 0; g < vec_bytes; g += POLY_GROUP_BYTES)
            POLY_GROUP(out + g);
        POLY_FOLD();
        if (tail > vec_bytes)
            poly_stream(ctx, &st, out + vec_bytes, tail - vec_bytes);
    } else {
        POLY_FOLD();
    }

    ctx->ctr = ctr;
    ctx->calls++;
    st_save(ctx, &st);
    OPENSSL_cleanse(&st, sizeof(st));
}

/*
 * Open: the input is already ciphertext, so each chunk hashes itself during
 * the rounds.  An in-place update hashes before the XOR overwrites it.
 */
static void stream_open(OSSL_CP_AVX512_CTX *ctx, unsigned char *out,
    const unsigned char *in, size_t len)
{
    poly1305_state st;
    __m512i a0, a1, a2, vr0, vr1, vr2, vs1, vs2;
    uint64_t (*pw)[POLY_LANES] = ctx->pw;
    const unsigned int *key = ctx->key;
    const unsigned int *counter = ctx->counter;
    uint32_t ctr;
    size_t n;
    int started = 0;

    if (len == 0)
        return;

    if (ctx->ahead)
        ctx->ahead = 0;

    st_load(&st, ctx);
    STREAM_CLAIM_INIT();
    STREAM_LOAD_POWERS();

    /* Parked keystream is hashed on its own. */
    STREAM_SPEND_PARKED(0);

    ctr = ctx->ctr;
    n = len;
    POLY_SEED();

    if (n >= CHUNK_BYTES) {
        const size_t nchunks = n / CHUNK_BYTES;
        size_t c;

        for (c = 0; c < nchunks; c++) {
            /* Input is already ciphertext, so this chunk hashes itself. */
            CHACHA16_XOR(ctr, out, in, in);
            ctr += 16;
            out += CHUNK_BYTES;
            in += CHUNK_BYTES;
        }
        n -= nchunks * CHUNK_BYTES;
    }

    /*
     * Tail: fewer than 1024 bytes left.  One 16-block pass still runs every
     * lane.  Once the r^n table exists, whole 128-byte groups are hashed
     * during the rounds, and the MAC is finished before the XOR.
     */
    if (n != 0) {
        const size_t tail = n;
        const size_t nfull = tail / CHACHA_BLK;
        const size_t rem = tail % CHACHA_BLK;
        const size_t vec_bytes = ctx->powers
            ? (tail / POLY_GROUP_BYTES) * POLY_GROUP_BYTES
            : 0;
        unsigned char *const ksp = ctx->ks;
        int rr;
        CHACHA_DECL;

        CHACHA_INIT(ctr);
        for (rr = 0; rr < 10; rr++) {
            CHACHA_DROUND();
            if ((size_t)rr * POLY_GROUP_BYTES < vec_bytes)
                POLY_GROUP(in + (size_t)rr * POLY_GROUP_BYTES);
        }
        CHACHA_FINISH(ctr);
        POLY_FOLD();
        if (tail > vec_bytes)
            poly_stream(ctx, &st, in + vec_bytes, tail - vec_bytes);

        CHACHA_XOR_STORE_N(out, in);

        if (rem != 0) {
            const size_t base = nfull * CHACHA_BLK;
            size_t k;

            for (k = 0; k < rem; k++)
                out[base + k] = in[base + k] ^ ksp[k];
        }

        STREAM_PARK_TAIL(rem, nfull);
    } else {
        POLY_FOLD();
    }

    ctx->ctr = ctr;
    ctx->calls++;
    st_save(ctx, &st);
    OPENSSL_cleanse(&st, sizeof(st));
}

static void stream_aad(OSSL_CP_AVX512_CTX *ctx, const unsigned char *aad,
    size_t len)
{
    poly1305_state st;

    st_load(&st, ctx);
    poly_stream(ctx, &st, aad, len);
    st_save(ctx, &st);
    OPENSSL_cleanse(&st, sizeof(st));
}

static void stream_pad(OSSL_CP_AVX512_CTX *ctx)
{
    poly1305_state st;

    st_load(&st, ctx);
    poly_stream_pad(ctx, &st);
    st_save(ctx, &st);
    OPENSSL_cleanse(&st, sizeof(st));
}

static void stream_final(OSSL_CP_AVX512_CTX *ctx, unsigned char tag[16],
    uint64_t aad_len, uint64_t text_len)
{
    poly1305_state st;

    st_load(&st, ctx);
    poly_stream_pad(ctx, &st);
    poly_block16(&st, aad_len, text_len);
    poly_final(&st, tag);
    OPENSSL_cleanse(&st, sizeof(st));
    /* The tag is in the caller's buffer.  The context cannot be reused. */
    OPENSSL_cleanse(ctx, sizeof(*ctx));
}

OPENSSL_UNTARGET_FUSED

int ossl_chacha20_poly1305_avx512_available(void)
{
#if defined(OPENSSL_CPUID_OBJ)
    /* CPUID.(EAX=07H,ECX=0):EBX is cached in OPENSSL_ia32cap_P[2]. */
    static const unsigned int need = (1u << 8) /* BMI2        */
        | (1u << 16) /* AVX512F     */
        | (1u << 19) /* ADX         */
        | (1u << 21) /* AVX512IFMA  */
        | (1u << 31); /* AVX512VL    */

    return (OPENSSL_ia32cap_P[2] & need) == need;
#else
    return 0;
#endif
}

void ossl_chacha20_poly1305_avx512_init(OSSL_CP_AVX512_CTX *ctx,
    const unsigned int key[8],
    const unsigned int counter[4],
    size_t hint)
{
    stream_init(ctx, key, counter, hint);
}

void ossl_chacha20_poly1305_avx512_aad(OSSL_CP_AVX512_CTX *ctx,
    const unsigned char *aad, size_t len)
{
    if (len != 0)
        stream_aad(ctx, aad, len);
}

void ossl_chacha20_poly1305_avx512_aad_done(OSSL_CP_AVX512_CTX *ctx)
{
    stream_pad(ctx);
}

int ossl_chacha20_poly1305_avx512_cipher(OSSL_CP_AVX512_CTX *ctx,
    unsigned char *out,
    const unsigned char *in, size_t len,
    int enc)
{
    if (len == 0)
        return 1;
    /*
     * Reject before generating keystream.  A tail pass is 16 blocks wide, so
     * near the end it can compute ChaCha block 0, but that block is only
     * parked.  This check runs first, so a later update cannot XOR it in.
     */
    if (ctx->textlen > OSSL_CP_AVX512_MAX_TEXT
        || len > OSSL_CP_AVX512_MAX_TEXT - ctx->textlen)
        return 0;
    if (enc)
        stream_seal(ctx, out, in, len);
    else
        stream_open(ctx, out, in, len);
    ctx->textlen += len;
    return 1;
}

void ossl_chacha20_poly1305_avx512_final(OSSL_CP_AVX512_CTX *ctx,
    unsigned char tag[16],
    uint64_t aad_len, uint64_t text_len)
{
    stream_final(ctx, tag, aad_len, text_len);
}

int ossl_chacha20_poly1305_avx512(unsigned char *out, const unsigned char *in,
    size_t len, const unsigned char *aad,
    size_t aad_len, const unsigned int key[8],
    const unsigned int counter[4],
    unsigned char tag[16], int enc)
{
    OSSL_CP_AVX512_CTX ctx;

    if (!ossl_chacha20_poly1305_avx512_available())
        return 0;
    if (len != 0 && (in == NULL || out == NULL))
        return 0;

    /* The 32-bit block counter starts at 1, so cap the message accordingly. */
    if ((uint64_t)len > OSSL_CP_AVX512_MAX_TEXT)
        return 0;

    ossl_chacha20_poly1305_avx512_init(&ctx, key, counter, len);
    ossl_chacha20_poly1305_avx512_aad(&ctx, aad, aad_len);
    ossl_chacha20_poly1305_avx512_aad_done(&ctx);
    if (!ossl_chacha20_poly1305_avx512_cipher(&ctx, out, in, len, enc)) {
        /* final did not run, so the one-time key is still in ctx. */
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 0;
    }
    /* final wipes ctx, including the key and any parked keystream. */
    ossl_chacha20_poly1305_avx512_final(&ctx, tag, (uint64_t)aad_len,
        (uint64_t)len);
    return 1;
}

#else

NON_EMPTY_TRANSLATION_UNIT

#endif /* CHACHA20_POLY1305_AVX512_CAPABLE */
