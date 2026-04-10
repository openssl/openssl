/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (C) 2026, Advanced Micro Devices, all rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Implements AES-CTR encryption with VAES (AVX-512)
 */

#include <openssl/opensslconf.h>
#include "internal/cryptlib.h"
#include <openssl/aes.h>
#include "aes_local.h"

#if defined(__x86_64__) || defined(__x86_64) || defined(_M_AMD64) || defined(_M_X64)

#include <openssl/modes.h>

/* Forward declaration — defined in aesni-x86_64.pl assembly          */
void aesni_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);

/* Enable AVX-512 and VAES for this compilation unit                  */
#pragma GCC target("avx512f,avx512dq,avx512bw,vaes,aes")

#include <immintrin.h>

#define AES_BLOCK_SIZE 16

/* ------------------------------------------------------------------ */
/* AES encryption helpers: 1x, 2x, 4x parallel 512-bit blocks         */
/* Each 512-bit register holds 4 independent 128-bit AES blocks.      */
/* always_inline guarantees the compiler keeps keys in ZMM regs.      */
/* ------------------------------------------------------------------ */

#define DEFINE_AES_ENCRYPT_FUNCS(ROUNDS)                                       \
__attribute__((always_inline))                                                 \
static inline void AesEnc_4x512_##ROUNDS(                                      \
    __m512i *b1, __m512i *b2, __m512i *b3, __m512i *b4,                        \
    const __m512i *rk)                                                         \
{                                                                              \
    *b1 = _mm512_xor_si512(*b1, rk[0]);                                        \
    *b2 = _mm512_xor_si512(*b2, rk[0]);                                        \
    *b3 = _mm512_xor_si512(*b3, rk[0]);                                        \
    *b4 = _mm512_xor_si512(*b4, rk[0]);                                        \
    for (int i = 1; i < ROUNDS; i++) {                                         \
        *b1 = _mm512_aesenc_epi128(*b1, rk[i]);                                \
        *b2 = _mm512_aesenc_epi128(*b2, rk[i]);                                \
        *b3 = _mm512_aesenc_epi128(*b3, rk[i]);                                \
        *b4 = _mm512_aesenc_epi128(*b4, rk[i]);                                \
    }                                                                          \
    *b1 = _mm512_aesenclast_epi128(*b1, rk[ROUNDS]);                           \
    *b2 = _mm512_aesenclast_epi128(*b2, rk[ROUNDS]);                           \
    *b3 = _mm512_aesenclast_epi128(*b3, rk[ROUNDS]);                           \
    *b4 = _mm512_aesenclast_epi128(*b4, rk[ROUNDS]);                           \
}                                                                              \
                                                                               \
__attribute__((always_inline))                                                 \
static inline void AesEnc_2x512_##ROUNDS(                                      \
    __m512i *b1, __m512i *b2, const __m512i *rk)                               \
{                                                                              \
    *b1 = _mm512_xor_si512(*b1, rk[0]);                                        \
    *b2 = _mm512_xor_si512(*b2, rk[0]);                                        \
    for (int i = 1; i < ROUNDS; i++) {                                         \
        *b1 = _mm512_aesenc_epi128(*b1, rk[i]);                                \
        *b2 = _mm512_aesenc_epi128(*b2, rk[i]);                                \
    }                                                                          \
    *b1 = _mm512_aesenclast_epi128(*b1, rk[ROUNDS]);                           \
    *b2 = _mm512_aesenclast_epi128(*b2, rk[ROUNDS]);                           \
}                                                                              \
                                                                               \
__attribute__((always_inline))                                                 \
static inline void AesEnc_1x512_##ROUNDS(                                      \
    __m512i *b1, const __m512i *rk)                                            \
{                                                                              \
    *b1 = _mm512_xor_si512(*b1, rk[0]);                                        \
    for (int i = 1; i < ROUNDS; i++)                                           \
        *b1 = _mm512_aesenc_epi128(*b1, rk[i]);                                \
    *b1 = _mm512_aesenclast_epi128(*b1, rk[ROUNDS]);                           \
}

DEFINE_AES_ENCRYPT_FUNCS(10)   /* AES-128 */
DEFINE_AES_ENCRYPT_FUNCS(12)   /* AES-192 */
DEFINE_AES_ENCRYPT_FUNCS(14)   /* AES-256 */

/* ------------------------------------------------------------------ */
/* Counter initialisation                                             */
/*                                                                    */
/* Counters are kept in little-endian form (full 128-bit byte swap)   */
/* and incremented with 64-bit arithmetic.  This is safe for all      */
/* practical counter values — encrypting data less than 2^68 bytes    */
/* ------------------------------------------------------------------ */

static inline __m512i ctr_swap_mask(void)
{
    return _mm512_set_epi32(0x00010203, 0x04050607,
                            0x08090a0b, 0x0c0d0e0f,
                            0x00010203, 0x04050607,
                            0x08090a0b, 0x0c0d0e0f,
                            0x00010203, 0x04050607,
                            0x08090a0b, 0x0c0d0e0f,
                            0x00010203, 0x04050607,
                            0x08090a0b, 0x0c0d0e0f);
}

static inline __m512i ctr_init4(const unsigned char *iv, __m512i swap)
{
    /* unaligned 128-bit load for iv and broadcast                    */
    __m128i iv128 = _mm_loadu_si128((const __m128i *)iv);
    __m512i c = _mm512_broadcast_i64x2(iv128);
    c = _mm512_shuffle_epi8(c, swap);
    c = _mm512_add_epi64(c, _mm512_set_epi64(0, 3, 0, 2, 0, 1, 0, 0));
    return c;
}

/* ------------------------------------------------------------------ */
/* CTR-mode processing — templated per round count                    */
/*                                                                    */
/* Processes as many blocks as possible:                              */
/*   16 blocks at a time (4×zmm = 4×4 = 16 blocks)                    */
/*    8 blocks at a time (2×zmm)                                      */
/*    4 blocks at a time (1×zmm)                                      */
/*   0-3 tail blocks + partial residue via masked load/store          */
/* ------------------------------------------------------------------ */

#define DEFINE_CTR_BLOCK(NR)                                                   \
__attribute__((noinline))                                                      \
static void ctr_process_##NR(                                                  \
    const unsigned char *in, unsigned char *out,                               \
    size_t len, const AES_KEY *key, unsigned char *iv)                         \
{                                                                              \
    const unsigned char *rk_bytes = (const unsigned char *)key->rd_key;        \
    __m512i rk[NR + 1];                                                        \
    for (int i = 0; i <= NR; i++) {                                            \
        __m128i t = _mm_loadu_si128((const __m128i *)(rk_bytes + i * 16));     \
        rk[i] = _mm512_broadcast_i32x4(t);                                     \
    }                                                                          \
                                                                               \
    const __m512i *p_in  = (const __m512i *)in;                                \
    __m512i       *p_out = (__m512i *)out;                                     \
    __m512i swap = ctr_swap_mask();                                            \
    __m512i c1   = ctr_init4(iv, swap);                                        \
                                                                               \
    __m512i a1, a2, a3, a4;                                                    \
    __m512i b1, b2, b3, b4;                                                    \
    __m512i c2, c3, c4;                                                        \
                                                                               \
    size_t blocks = len / AES_BLOCK_SIZE;                                      \
    size_t res    = len % AES_BLOCK_SIZE;                                      \
                                                                               \
    const __m512i inc4  = _mm512_set_epi64(0,4, 0,4, 0,4, 0,4);                \
    const __m512i inc8  = _mm512_set_epi64(0,8, 0,8, 0,8, 0,8);                \
    const __m512i inc12 = _mm512_set_epi64(0,12,0,12,0,12,0,12);               \
    const __m512i inc16 = _mm512_set_epi64(0,16,0,16,0,16,0,16);               \
                                                                               \
    /* --- 16-block (4×zmm) main loop ---                                   */ \
    while (blocks >= 16) {                                                     \
        c2 = _mm512_add_epi64(c1, inc4);                                       \
        c3 = _mm512_add_epi64(c1, inc8);                                       \
        c4 = _mm512_add_epi64(c1, inc12);                                      \
                                                                               \
        a1 = _mm512_loadu_si512(p_in);                                         \
        a2 = _mm512_loadu_si512(p_in + 1);                                     \
        a3 = _mm512_loadu_si512(p_in + 2);                                     \
        a4 = _mm512_loadu_si512(p_in + 3);                                     \
                                                                               \
        b1 = _mm512_shuffle_epi8(c1, swap);                                    \
        b2 = _mm512_shuffle_epi8(c2, swap);                                    \
        b3 = _mm512_shuffle_epi8(c3, swap);                                    \
        b4 = _mm512_shuffle_epi8(c4, swap);                                    \
                                                                               \
        AesEnc_4x512_##NR(&b1, &b2, &b3, &b4, rk);                             \
                                                                               \
        _mm512_storeu_si512(p_out,     _mm512_xor_si512(b1, a1));              \
        _mm512_storeu_si512(p_out + 1, _mm512_xor_si512(b2, a2));              \
        _mm512_storeu_si512(p_out + 2, _mm512_xor_si512(b3, a3));              \
        _mm512_storeu_si512(p_out + 3, _mm512_xor_si512(b4, a4));              \
                                                                               \
        c1 = _mm512_add_epi64(c1, inc16);                                      \
        p_in  += 4;                                                            \
        p_out += 4;                                                            \
        blocks -= 16;                                                          \
    }                                                                          \
                                                                               \
    /* --- 8-block (2×zmm) ---                                              */ \
    if (blocks >= 8) {                                                         \
        c2 = _mm512_add_epi64(c1, inc4);                                       \
                                                                               \
        a1 = _mm512_loadu_si512(p_in);                                         \
        a2 = _mm512_loadu_si512(p_in + 1);                                     \
                                                                               \
        b1 = _mm512_shuffle_epi8(c1, swap);                                    \
        b2 = _mm512_shuffle_epi8(c2, swap);                                    \
                                                                               \
        AesEnc_2x512_##NR(&b1, &b2, rk);                                       \
                                                                               \
        _mm512_storeu_si512(p_out,     _mm512_xor_si512(b1, a1));              \
        _mm512_storeu_si512(p_out + 1, _mm512_xor_si512(b2, a2));              \
                                                                               \
        c1 = _mm512_add_epi64(c1, inc8);                                       \
        p_in  += 2;                                                            \
        p_out += 2;                                                            \
        blocks -= 8;                                                           \
    }                                                                          \
                                                                               \
    /* --- 4-block (1×zmm) ---                                              */ \
    if (blocks >= 4) {                                                         \
        a1 = _mm512_loadu_si512(p_in);                                         \
        b1 = _mm512_shuffle_epi8(c1, swap);                                    \
        AesEnc_1x512_##NR(&b1, rk);                                            \
        _mm512_storeu_si512(p_out, _mm512_xor_si512(b1, a1));                  \
                                                                               \
        c1 = _mm512_add_epi64(c1, inc4);                                       \
        p_in  += 1;                                                            \
        p_out += 1;                                                            \
        blocks -= 4;                                                           \
    }                                                                          \
                                                                               \
    /* --- Tail: 0-3 full blocks + residue partial block ---                */ \
    {                                                                          \
        size_t tail_bytes = (blocks * AES_BLOCK_SIZE) + res;                   \
        if (tail_bytes > 0) {                                                  \
            __mmask64 mask = (__mmask64)((1ULL << tail_bytes) - 1ULL);         \
            a1 = _mm512_maskz_loadu_epi8(mask, p_in);                          \
            b1 = _mm512_shuffle_epi8(c1, swap);                                \
            AesEnc_1x512_##NR(&b1, rk);                                        \
            _mm512_mask_storeu_epi8(p_out, mask, _mm512_xor_si512(b1, a1));    \
                                                                               \
            size_t adv = blocks + (res > 0 ? 1 : 0);                           \
            __m512i one_lo = _mm512_set_epi64(0,0, 0,0, 0,0, 0,1);             \
            for (size_t i = 0; i < adv; i++)                                   \
                c1 = _mm512_add_epi64(c1, one_lo);                             \
        }                                                                      \
    }                                                                          \
                                                                               \
    /* Write back updated counter (lane 0 only, byte-swapped to BE)         */ \
    {                                                                          \
        __m512i c_be = _mm512_shuffle_epi8(c1, swap);                          \
        _mm512_mask_storeu_epi64((__m128i *)iv, 0x03, c_be);                   \
    }                                                                          \
                                                                               \
    /* Clear round-key material from the stack                              */ \
    {                                                                          \
        __m512i z = _mm512_setzero_si512();                                    \
        for (int i = 0; i <= NR; i++)                                          \
            rk[i] = z;                                                         \
    }                                                                          \
}

DEFINE_CTR_BLOCK(10)    /* AES-128 */
DEFINE_CTR_BLOCK(12)    /* AES-192 */
DEFINE_CTR_BLOCK(14)    /* AES-256 */

/* ------------------------------------------------------------------ */
/* Public entry point                                                 */
/* ------------------------------------------------------------------ */

void ossl_aes_ctr_vaes(const unsigned char *in, unsigned char *out,
                        size_t length, const AES_KEY *key,
                        unsigned char *counter,
                        unsigned char *ecount_buf, unsigned int *num)
{
    size_t n = *num;
    size_t l = length;
    int nr = key->rounds + 1;

    /* Drain leftover bytes from a previous partial block */
    if (n != 0) {
        while (l > 0 && n < 16) {
            *(out++) = *(in++) ^ ecount_buf[n];
            ++n;
            l--;
        }
        *num = n % 16;
        if (l == 0)
            return;
    }

    /* Process full 16-byte blocks with VAES.
     *
     * The VAES loop uses 64-bit counter arithmetic (no carry into the
     * upper 64 bits).  If processing all requested blocks would overflow
     * the low 64 bits of the BE counter:
     *   Phase 1 — VAES processes the safe blocks before the boundary.
     *   Phase 2 — Scalar handles 1 block to cross the 64-bit carry.
     *   Phase 3 — VAES resumes for the remaining bulk (>= 512 bytes),
     *             since the counter low-64 is now near zero and safe.
     * Any final partial block is always handled by the scalar path.
     */
    {
        size_t block_bytes = (l / 16) * 16;
        if (block_bytes > 0) {
            size_t total_blocks = block_bytes / 16;
            /* Read low 64 bits of the big-endian counter (bytes 8..15) */
            uint64_t ctr_lo = ((uint64_t)counter[8]  << 56)
                            | ((uint64_t)counter[9]  << 48)
                            | ((uint64_t)counter[10] << 40)
                            | ((uint64_t)counter[11] << 32)
                            | ((uint64_t)counter[12] << 24)
                            | ((uint64_t)counter[13] << 16)
                            | ((uint64_t)counter[14] << 8)
                            | ((uint64_t)counter[15]);

            /* Clamp to the number of blocks safe for 64-bit arithmetic */
            size_t safe_blocks = (ctr_lo <= UINT64_MAX - total_blocks)
                               ? total_blocks
                               : (size_t)(UINT64_MAX - ctr_lo);
            size_t safe_bytes = safe_blocks * 16;

            /* Phase 1: VAES for the safe portion before the boundary */
            if (safe_bytes > 0) {
                switch (nr) {
                case 12:
                    ctr_process_12(in, out, safe_bytes, key, counter);
                    break;
                case 14:
                    ctr_process_14(in, out, safe_bytes, key, counter);
                    break;
                default:   /* 10 (AES-128) */
                    ctr_process_10(in, out, safe_bytes, key, counter);
                    break;
                }
                in  += safe_bytes;
                out += safe_bytes;
                l   -= safe_bytes;
            }

            /* Phase 2 & 3: only entered when clamping actually occurred */
            if (safe_blocks < total_blocks && l > 0) {
                /* Phase 2: scalar encrypts 1 block across the carry */
                CRYPTO_ctr128_encrypt(in, out, 16, key, counter,
                                     ecount_buf, num,
                                     (block128_f)aesni_encrypt);
                in  += 16;
                out += 16;
                l   -= 16;

                /* Phase 3: counter low-64 is now ~0 — VAES is safe again.
                 * Resume VAES if enough data remains (>= 512 bytes). */
                if (l >= 512) {
                    size_t resume_bytes = (l / 16) * 16;
                    switch (nr) {
                    case 12:
                        ctr_process_12(in, out, resume_bytes, key, counter);
                        break;
                    case 14:
                        ctr_process_14(in, out, resume_bytes, key, counter);
                        break;
                    default:
                        ctr_process_10(in, out, resume_bytes, key, counter);
                        break;
                    }
                    in  += resume_bytes;
                    out += resume_bytes;
                    l   -= resume_bytes;
                }
            }
        }
    }

    /* Handle any remaining bytes (partial block or small tail) */
    if (l > 0)
        CRYPTO_ctr128_encrypt(in, out, l, key, counter,
                              ecount_buf, num, (block128_f)aesni_encrypt);
    else
        *num = 0;
}

/* ------------------------------------------------------------------ */
/* CPU feature check                                                  */
/* ------------------------------------------------------------------ */

int ossl_aes_ctr_vaes_eligible(void)
{
    return (OPENSSL_ia32cap_P[2] & (1 << 16))    /* AVX512F            */
        && (OPENSSL_ia32cap_P[2] & (1 << 17))    /* AVX512DQ           */
        && (OPENSSL_ia32cap_P[2] & (1 << 30))    /* AVX512BW           */
        && (OPENSSL_ia32cap_P[3] & (1 << 9));    /* AVX512VAES         */
}

#endif /* __x86_64__ || _M_AMD64 */
