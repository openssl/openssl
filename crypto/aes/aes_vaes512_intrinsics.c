/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (C) 2026, Advanced Micro Devices, all rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * AVX-512/VAES-512 intrinsic implementations of AES modes.
 *
 * This translation unit gathers the VAES-accelerated AES mode
 * implementations together with the shared 512-bit primitives they rely on:
 *   - portable compiler abstractions for ISA targeting and inlining,
 *   - a macro that emits 1x/2x/4x parallel 512-bit AES round functions,
 *   - macros to broadcast-load and securely scrub the round-key schedule,
 *   - a runtime CPU capability check.
 *
 * Currently implemented: AES-CTR encryption and AES-CBC decryption.
 *
 * CBC encryption is inherently serial (each ciphertext block depends on the
 * previous one), so VAES provides no benefit there -- that path falls back to
 * the aesni_cbc_encrypt assembly routine.  CBC decryption is parallel: all
 * blocks are decrypted independently, then XORed with the preceding ciphertext
 * block (or the IV for the first).
 */

#include "internal/deprecated.h"

#include <openssl/opensslconf.h>
#include "internal/cryptlib.h"
#include <openssl/aes.h>
#include "crypto/modes.h"
#include "crypto/aes_platform.h"

#if VAES512_ELIGIBLE

#include <openssl/e_os2.h>
#include <openssl/modes.h>
#include <immintrin.h>

/* Function prototypes */
void ossl_aes_ctr_vaes(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key,
    unsigned char *counter,
    unsigned char *ecount_buf, unsigned int *num);
int ossl_aes_ctr_vaes_eligible(void);
void ossl_aes_cbc_vaes_decrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], int enc);
int ossl_aes_cbc_vaes_eligible(void);

/* Forward declarations — defined in aesni-x86_64.pl assembly         */
void aesni_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void aesni_cbc_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const AES_KEY *key,
    unsigned char *ivec, int enc);
void aesni_decrypt(const unsigned char *in, unsigned char *out,
    const AES_KEY *key);

/* Portable compiler abstractions for inlining and ISA target selection */
#define OSSL_VAES512_STRINGIFY_IMPL_(a) #a
#define OSSL_VAES512_STRINGIFY_(a) OSSL_VAES512_STRINGIFY_IMPL_(a)

#ifdef __clang__
#define OPENSSL_TARGET_VAES512                                         \
    _Pragma(OSSL_VAES512_STRINGIFY_(clang attribute push(              \
        __attribute__((target("avx512f,avx512dq,avx512bw,vaes,aes"))), \
        apply_to = function)))
#define OPENSSL_UNTARGET_VAES512 _Pragma("clang attribute pop")
#elif defined(__GNUC__)
#define OPENSSL_TARGET_VAES512  \
    _Pragma("GCC push_options") \
        _Pragma(OSSL_VAES512_STRINGIFY_(GCC target("avx512f,avx512dq,avx512bw,vaes,aes")))
#define OPENSSL_UNTARGET_VAES512 _Pragma("GCC pop_options")
#else
/* MSVC: all intrinsics are always available via <immintrin.h>. */
#define OPENSSL_TARGET_VAES512
#define OPENSSL_UNTARGET_VAES512
#endif

#if defined(__GNUC__) || defined(__clang__)
#define OSSL_FUNC_ALWAYS_INLINE static inline __attribute__((always_inline))
#define OSSL_FUNC_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define OSSL_FUNC_ALWAYS_INLINE static __forceinline
#define OSSL_FUNC_NOINLINE __declspec(noinline)
#else
#define OSSL_FUNC_ALWAYS_INLINE static inline
#define OSSL_FUNC_NOINLINE
#endif

/*
 * Runtime CPU capability check shared by all VAES-512 mode helpers.
 * Uses only OPENSSL_ia32cap_P bit tests, so it requires no special ISA
 * target and is safe to define outside an OPENSSL_TARGET_VAES512 region.
 */
static ossl_inline int ossl_vaes512_cpu_capable(void)
{
    return (OPENSSL_ia32cap_P[2] & (1 << 16)) /* AVX512F    */
        && (OPENSSL_ia32cap_P[2] & (1 << 17)) /* AVX512DQ   */
        && (OPENSSL_ia32cap_P[2] & (1 << 30)) /* AVX512BW   */
        && (OPENSSL_ia32cap_P[3] & (1 << 9)); /* AVX512VAES */
}

/*
 * Emit the 1x/2x/4x parallel 512-bit AES round functions for a given round
 * count.  TAG names the generated functions (e.g. AesEnc, AesDec); AESOP and
 * AESLAST select the middle-round and last-round intrinsics (encrypt vs
 * decrypt).  Each __m512i packs four independent 128-bit AES blocks, and
 * always_inline keeps the round keys resident in ZMM registers.
 *
 * Must be expanded inside an OPENSSL_TARGET_VAES512 region.
 */
#define OSSL_VAES512_DEFINE_ROUNDS(TAG, ROUNDS, AESOP, AESLAST) \
    OSSL_FUNC_ALWAYS_INLINE                                     \
    void TAG##_4x512_##ROUNDS(                                  \
        __m512i *b1, __m512i *b2, __m512i *b3, __m512i *b4,     \
        const __m512i *rk)                                      \
    {                                                           \
        *b1 = _mm512_xor_si512(*b1, rk[0]);                     \
        *b2 = _mm512_xor_si512(*b2, rk[0]);                     \
        *b3 = _mm512_xor_si512(*b3, rk[0]);                     \
        *b4 = _mm512_xor_si512(*b4, rk[0]);                     \
        for (int i = 1; i < ROUNDS; i++) {                      \
            *b1 = AESOP(*b1, rk[i]);                            \
            *b2 = AESOP(*b2, rk[i]);                            \
            *b3 = AESOP(*b3, rk[i]);                            \
            *b4 = AESOP(*b4, rk[i]);                            \
        }                                                       \
        *b1 = AESLAST(*b1, rk[ROUNDS]);                         \
        *b2 = AESLAST(*b2, rk[ROUNDS]);                         \
        *b3 = AESLAST(*b3, rk[ROUNDS]);                         \
        *b4 = AESLAST(*b4, rk[ROUNDS]);                         \
    }                                                           \
                                                                \
    OSSL_FUNC_ALWAYS_INLINE                                     \
    void TAG##_2x512_##ROUNDS(                                  \
        __m512i *b1, __m512i *b2, const __m512i *rk)            \
    {                                                           \
        *b1 = _mm512_xor_si512(*b1, rk[0]);                     \
        *b2 = _mm512_xor_si512(*b2, rk[0]);                     \
        for (int i = 1; i < ROUNDS; i++) {                      \
            *b1 = AESOP(*b1, rk[i]);                            \
            *b2 = AESOP(*b2, rk[i]);                            \
        }                                                       \
        *b1 = AESLAST(*b1, rk[ROUNDS]);                         \
        *b2 = AESLAST(*b2, rk[ROUNDS]);                         \
    }                                                           \
                                                                \
    OSSL_FUNC_ALWAYS_INLINE                                     \
    void TAG##_1x512_##ROUNDS(                                  \
        __m512i *b1, const __m512i *rk)                         \
    {                                                           \
        *b1 = _mm512_xor_si512(*b1, rk[0]);                     \
        for (int i = 1; i < ROUNDS; i++)                        \
            *b1 = AESOP(*b1, rk[i]);                            \
        *b1 = AESLAST(*b1, rk[ROUNDS]);                         \
    }

/* Emit the AES encryption round helpers (used by CTR, CFB, GCM, ...). */
#define OSSL_VAES512_DEFINE_ENCRYPT(ROUNDS)    \
    OSSL_VAES512_DEFINE_ROUNDS(AesEnc, ROUNDS, \
        _mm512_aesenc_epi128, _mm512_aesenclast_epi128)

/* Emit the AES decryption round helpers (used by CBC decrypt). */
#define OSSL_VAES512_DEFINE_DECRYPT(ROUNDS)    \
    OSSL_VAES512_DEFINE_ROUNDS(AesDec, ROUNDS, \
        _mm512_aesdec_epi128, _mm512_aesdeclast_epi128)

/*
 * Broadcast-load the AES round-key schedule into an array of ZMM registers,
 * replicating each 128-bit round key across all four lanes.  key is an
 * AES_KEY *, rk an array of at least NR+1 __m512i.
 *
 * Must be expanded inside an OPENSSL_TARGET_VAES512 region.
 */
#define OSSL_VAES512_LOAD_ROUNDKEYS(rk, key, NR)                               \
    do {                                                                       \
        const unsigned char *rk_bytes_ = (const unsigned char *)(key)->rd_key; \
        for (int i_ = 0; i_ <= (NR); i_++) {                                   \
            __m128i t_ = _mm_loadu_si128(                                      \
                (const __m128i *)(rk_bytes_ + i_ * 16));                       \
            (rk)[i_] = _mm512_broadcast_i32x4(t_);                             \
        }                                                                      \
    } while (0)

/*
 * Securely scrub the round-key schedule from the stack.  The volatile
 * qualifier prevents the compiler from eliminating the dead stores.
 *
 * Must be expanded inside an OPENSSL_TARGET_VAES512 region.
 */
#define OSSL_VAES512_CLEAR_ROUNDKEYS(rk, NR)                                \
    do {                                                                    \
        volatile __m512i *vrk_ = (volatile __m512i *)(volatile void *)(rk); \
        for (int i_ = 0; i_ <= (NR); i_++)                                  \
            vrk_[i_] = _mm512_setzero_si512();                              \
    } while (0)

OPENSSL_TARGET_VAES512

/* AES encryption round helpers (1x/2x/4x parallel 512-bit blocks). */
OSSL_VAES512_DEFINE_ENCRYPT(10) /* AES-128 */
OSSL_VAES512_DEFINE_ENCRYPT(12) /* AES-192 */
OSSL_VAES512_DEFINE_ENCRYPT(14) /* AES-256 */

/*-
 * Counter initialisation.
 *
 * Counters are kept in little-endian form (full 128-bit byte swap) and
 * incremented with 64-bit arithmetic.  This is safe for all practical
 * counter values — encrypting data less than 2^68 bytes.
 */
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

/*-
 * CTR-mode processing, templated per round count.
 *
 * Processes as many blocks as possible:
 *   16 blocks at a time (4×zmm = 4×4 = 16 blocks)
 *    8 blocks at a time (2×zmm)
 *    4 blocks at a time (1×zmm)
 *   0-3 tail blocks + partial residue via masked load/store
 */
#define DEFINE_CTR_BLOCK(NR)                                                       \
    OSSL_FUNC_NOINLINE                                                             \
    static void ctr_process_##NR(                                                  \
        const unsigned char *in, unsigned char *out,                               \
        size_t len, const AES_KEY *key, unsigned char *iv)                         \
    {                                                                              \
        __m512i rk[NR + 1];                                                        \
        OSSL_VAES512_LOAD_ROUNDKEYS(rk, key, NR);                                  \
                                                                                   \
        const __m512i *p_in = (const __m512i *)in;                                 \
        __m512i *p_out = (__m512i *)out;                                           \
        __m512i swap = ctr_swap_mask();                                            \
        __m512i c1 = ctr_init4(iv, swap);                                          \
                                                                                   \
        __m512i a1, a2, a3, a4;                                                    \
        __m512i b1, b2, b3, b4;                                                    \
        __m512i c2, c3, c4;                                                        \
                                                                                   \
        size_t blocks = len / AES_BLOCK_SIZE;                                      \
        size_t res = len % AES_BLOCK_SIZE;                                         \
                                                                                   \
        const __m512i inc4 = _mm512_set_epi64(0, 4, 0, 4, 0, 4, 0, 4);             \
        const __m512i inc8 = _mm512_set_epi64(0, 8, 0, 8, 0, 8, 0, 8);             \
        const __m512i inc12 = _mm512_set_epi64(0, 12, 0, 12, 0, 12, 0, 12);        \
        const __m512i inc16 = _mm512_set_epi64(0, 16, 0, 16, 0, 16, 0, 16);        \
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
            _mm512_storeu_si512(p_out, _mm512_xor_si512(b1, a1));                  \
            _mm512_storeu_si512(p_out + 1, _mm512_xor_si512(b2, a2));              \
            _mm512_storeu_si512(p_out + 2, _mm512_xor_si512(b3, a3));              \
            _mm512_storeu_si512(p_out + 3, _mm512_xor_si512(b4, a4));              \
                                                                                   \
            c1 = _mm512_add_epi64(c1, inc16);                                      \
            p_in += 4;                                                             \
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
            _mm512_storeu_si512(p_out, _mm512_xor_si512(b1, a1));                  \
            _mm512_storeu_si512(p_out + 1, _mm512_xor_si512(b2, a2));              \
                                                                                   \
            c1 = _mm512_add_epi64(c1, inc8);                                       \
            p_in += 2;                                                             \
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
            p_in += 1;                                                             \
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
                __m512i one_lo = _mm512_set_epi64(0, 0, 0, 0, 0, 0, 0, 1);         \
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
        OSSL_VAES512_CLEAR_ROUNDKEYS(rk, NR);                                      \
    }

DEFINE_CTR_BLOCK(10) /* AES-128 */
DEFINE_CTR_BLOCK(12) /* AES-192 */
DEFINE_CTR_BLOCK(14) /* AES-256 */

/* Public entry point. */
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
            uint64_t ctr_lo = ((uint64_t)counter[8] << 56)
                | ((uint64_t)counter[9] << 48)
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
                case 10:
                    ctr_process_10(in, out, safe_bytes, key, counter);
                    break;
                case 12:
                    ctr_process_12(in, out, safe_bytes, key, counter);
                    break;
                case 14:
                    ctr_process_14(in, out, safe_bytes, key, counter);
                    break;
                default: /* invalid key size */
                    CRYPTO_ctr128_encrypt(in, out, safe_bytes, key, counter,
                        ecount_buf, num,
                        (block128_f)aesni_encrypt);
                    break;
                }
                in += safe_bytes;
                out += safe_bytes;
                l -= safe_bytes;
            }

            /* Phase 2 & 3: only entered when clamping actually occurred */
            if (safe_blocks < total_blocks && l > 0) {
                /* Phase 2: scalar encrypts 1 block across the carry */
                CRYPTO_ctr128_encrypt(in, out, 16, key, counter,
                    ecount_buf, num,
                    (block128_f)aesni_encrypt);
                in += 16;
                out += 16;
                l -= 16;

                /* Phase 3: counter low-64 is now ~0 — VAES is safe again.
                 * Resume VAES if enough data remains (>= 512 bytes). */
                if (l >= 512) {
                    size_t resume_bytes = (l / 16) * 16;
                    switch (nr) {
                    case 10:
                        ctr_process_10(in, out, resume_bytes, key, counter);
                        break;
                    case 12:
                        ctr_process_12(in, out, resume_bytes, key, counter);
                        break;
                    case 14:
                        ctr_process_14(in, out, resume_bytes, key, counter);
                        break;
                    default: /* invalid key size */
                        CRYPTO_ctr128_encrypt(in, out, resume_bytes, key,
                            counter, ecount_buf, num,
                            (block128_f)aesni_encrypt);
                        break;
                    }
                    in += resume_bytes;
                    out += resume_bytes;
                    l -= resume_bytes;
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

/* CPU feature check. */
int ossl_aes_ctr_vaes_eligible(void)
{
    return ossl_vaes512_cpu_capable();
}

/* AES decryption round helpers (1x/2x/4x parallel 512-bit blocks). */
OSSL_VAES512_DEFINE_DECRYPT(10) /* AES-128 */
OSSL_VAES512_DEFINE_DECRYPT(12) /* AES-192 */
OSSL_VAES512_DEFINE_DECRYPT(14) /* AES-256 */

/*-
 * CBC-mode decryption -- templated per round count.
 *
 * Processes as many full blocks as possible:
 *   16 blocks at a time (4 x zmm = 4 x 4 = 16 blocks)
 *    8 blocks at a time (2 x zmm)
 *    4 blocks at a time (1 x zmm)
 *    1 block at a time for the remaining 0-3 blocks
 *
 * The chaining vector b1 packs [prev_ct[last] | ct[0] | ct[1] | ct[2]] so
 * that a single XOR after decryption applies the CBC feedback to all four
 * lanes simultaneously.
 */
#define DEFINE_CBC_DECRYPT(NR)                                                      \
    OSSL_FUNC_NOINLINE                                                              \
    static void cbc_decrypt_##NR(                                                   \
        const unsigned char *in, unsigned char *out, size_t len,                    \
        const AES_KEY *key, unsigned char *iv)                                      \
    {                                                                               \
        __m512i rk[NR + 1];                                                         \
        OSSL_VAES512_LOAD_ROUNDKEYS(rk, key, NR);                                   \
                                                                                    \
        __m512i a1, a2, a3, a4;                                                     \
        __m512i b1, b2, b3, b4;                                                     \
                                                                                    \
        const __m128i *pa = (const __m128i *)in;                                    \
        __m512i *po = (__m512i *)out;                                               \
        size_t blocks = len / AES_BLOCK_SIZE;                                       \
                                                                                    \
        /* Save last ciphertext block for IV update (in-place safe)             */  \
        __m128i saved_iv = _mm_setzero_si128();                                     \
        int has_blocks = (blocks > 0);                                              \
        if (has_blocks)                                                             \
            saved_iv = _mm_loadu_si128(pa + blocks - 1);                            \
                                                                                    \
        if (blocks >= 4) {                                                          \
            /* Build b1 = [IV | ct[0] | ct[1] | ct[2]]                          */  \
            __m512i idx = _mm512_set_epi64(5, 4, 3, 2, 1, 0, 0, 0);                 \
            __m512i ct0;                                                            \
                                                                                    \
            /* CBC C[0]=IV; 0x03 loads one 128-bit block (two 64-bit lanes). */     \
            b1 = _mm512_maskz_loadu_epi64(0x03, iv);                                \
            ct0 = _mm512_loadu_si512(pa);                                           \
            ct0 = _mm512_permutexvar_epi64(idx, ct0);                               \
            b1 = _mm512_mask_blend_epi64(0xFC, b1, ct0);                            \
                                                                                    \
            /* --- 16-block (4 x zmm) main loop ---                             */  \
            while (blocks >= 16) {                                                  \
                __m128i last;                                                       \
                                                                                    \
                a1 = _mm512_loadu_si512(pa);                                        \
                a2 = _mm512_loadu_si512(pa + 4);                                    \
                a3 = _mm512_loadu_si512(pa + 8);                                    \
                a4 = _mm512_loadu_si512(pa + 12);                                   \
                                                                                    \
                b2 = _mm512_loadu_si512(pa + 3);                                    \
                b3 = _mm512_loadu_si512(pa + 7);                                    \
                b4 = _mm512_loadu_si512(pa + 11);                                   \
                                                                                    \
                last = _mm_loadu_si128(pa + 15);                                    \
                                                                                    \
                AesDec_4x512_##NR(&a1, &a2, &a3, &a4, rk);                          \
                                                                                    \
                a1 = _mm512_xor_si512(a1, b1);                                      \
                a2 = _mm512_xor_si512(a2, b2);                                      \
                a3 = _mm512_xor_si512(a3, b3);                                      \
                a4 = _mm512_xor_si512(a4, b4);                                      \
                                                                                    \
                _mm512_storeu_si512(po, a1);                                        \
                _mm512_storeu_si512(po + 1, a2);                                    \
                _mm512_storeu_si512(po + 2, a3);                                    \
                _mm512_storeu_si512(po + 3, a4);                                    \
                                                                                    \
                /* Build next b1 from last ciphertext block                     */  \
                b1 = _mm512_maskz_loadu_epi64(0x03, &last);                         \
                if (blocks > 16) {                                                  \
                    size_t rem = blocks - 16;                                       \
                    /* Load only available lookahead blocks to avoid OOB read. */   \
                    /* One AES block is 16 bytes, it maps to two 64-bit lanes. */   \
                    /* 0x03 (00000011) for 1 block (2 lanes), */                    \
                    /* 0x0F (00001111) for 2 blocks (4 lanes), */                   \
                    /* 0x3F (00111111) for 3 or more blocks (6 lanes). */           \
                    __mmask8 nxmask = (rem >= 3) ? 0x3F : (rem == 2 ? 0x0F : 0x03); \
                    __m512i nx = _mm512_maskz_loadu_epi64(nxmask, pa + 16);         \
                    nx = _mm512_permutexvar_epi64(idx, nx);                         \
                    b1 = _mm512_mask_blend_epi64(0xFC, b1, nx);                     \
                }                                                                   \
                                                                                    \
                pa += 16;                                                           \
                po += 4;                                                            \
                blocks -= 16;                                                       \
            }                                                                       \
                                                                                    \
            /* --- 8-block (2 x zmm) ---                                        */  \
            if (blocks >= 8) {                                                      \
                __m128i last8;                                                      \
                                                                                    \
                a1 = _mm512_loadu_si512(pa);                                        \
                a2 = _mm512_loadu_si512(pa + 4);                                    \
                b2 = _mm512_loadu_si512(pa + 3);                                    \
                last8 = _mm_loadu_si128(pa + 7);                                    \
                                                                                    \
                AesDec_2x512_##NR(&a1, &a2, rk);                                    \
                a1 = _mm512_xor_si512(a1, b1);                                      \
                a2 = _mm512_xor_si512(a2, b2);                                      \
                                                                                    \
                _mm512_storeu_si512(po, a1);                                        \
                _mm512_storeu_si512(po + 1, a2);                                    \
                                                                                    \
                b1 = _mm512_maskz_loadu_epi64(0x03, &last8);                        \
                pa += 8;                                                            \
                po += 2;                                                            \
                blocks -= 8;                                                        \
                                                                                    \
                if (blocks >= 4) {                                                  \
                    __m512i nx = _mm512_loadu_si512(pa);                            \
                    nx = _mm512_permutexvar_epi64(idx, nx);                         \
                    b1 = _mm512_mask_blend_epi64(0xFC, b1, nx);                     \
                }                                                                   \
            }                                                                       \
                                                                                    \
            /* --- 4-block (1 x zmm) ---                                        */  \
            if (blocks >= 4) {                                                      \
                __m128i last4;                                                      \
                                                                                    \
                a1 = _mm512_loadu_si512(pa);                                        \
                last4 = _mm_loadu_si128(pa + 3);                                    \
                                                                                    \
                AesDec_1x512_##NR(&a1, rk);                                         \
                a1 = _mm512_xor_si512(a1, b1);                                      \
                _mm512_storeu_si512(po, a1);                                        \
                                                                                    \
                b1 = _mm512_maskz_loadu_epi64(0x03, &last4);                        \
                pa += 4;                                                            \
                po += 1;                                                            \
                blocks -= 4;                                                        \
            }                                                                       \
                                                                                    \
            /* --- Remaining 1-3 blocks ---                                     */  \
            {                                                                       \
                __m128i *po128 = (__m128i *)po;                                     \
                while (blocks > 0) {                                                \
                    __m128i ct = _mm_loadu_si128(pa);                               \
                    a1 = _mm512_maskz_loadu_epi64(0x03, pa);                        \
                    AesDec_1x512_##NR(&a1, rk);                                     \
                    a1 = _mm512_xor_si512(a1, b1);                                  \
                    _mm512_mask_storeu_epi64(po128, 0x03, a1);                      \
                    b1 = _mm512_maskz_loadu_epi64(0x03, &ct);                       \
                    pa++;                                                           \
                    po128++;                                                        \
                    blocks--;                                                       \
                }                                                                   \
            }                                                                       \
        } else {                                                                    \
            /* Less than 4 blocks -- process individually                       */  \
            __m128i *po128 = (__m128i *)po;                                         \
            b1 = _mm512_maskz_loadu_epi64(0x03, iv);                                \
            while (blocks > 0) {                                                    \
                __m128i ct = _mm_loadu_si128(pa);                                   \
                a1 = _mm512_maskz_loadu_epi64(0x03, pa);                            \
                AesDec_1x512_##NR(&a1, rk);                                         \
                a1 = _mm512_xor_si512(a1, b1);                                      \
                _mm512_mask_storeu_epi64(po128, 0x03, a1);                          \
                b1 = _mm512_maskz_loadu_epi64(0x03, &ct);                           \
                pa++;                                                               \
                po128++;                                                            \
                blocks--;                                                           \
            }                                                                       \
        }                                                                           \
                                                                                    \
        if (has_blocks)                                                             \
            _mm_storeu_si128((__m128i *)iv, saved_iv);                              \
                                                                                    \
        /* Clear round-key material from the stack                              */  \
        OSSL_VAES512_CLEAR_ROUNDKEYS(rk, NR);                                       \
    }

DEFINE_CBC_DECRYPT(10) /* AES-128 */
DEFINE_CBC_DECRYPT(12) /* AES-192 */
DEFINE_CBC_DECRYPT(14) /* AES-256 */

/* Public entry point. */
void ossl_aes_cbc_vaes_decrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], int enc)
{
    size_t full_bytes;
    int nr = ((const AES_KEY *)key)->rounds + 1;

    if (len == 0)
        return;

    /* VAES path only optimises decryption; encrypt falls back to asm */
    if (enc) {
        aesni_cbc_encrypt(in, out, len, (const AES_KEY *)key, ivec, enc);
        return;
    }

    full_bytes = (len / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    if (full_bytes > 0) {
        switch (nr) {
        case 10:
            cbc_decrypt_10(in, out, full_bytes, (const AES_KEY *)key, ivec);
            break;
        case 12:
            cbc_decrypt_12(in, out, full_bytes, (const AES_KEY *)key, ivec);
            break;
        case 14:
            cbc_decrypt_14(in, out, full_bytes, (const AES_KEY *)key, ivec);
            break;
        default: /* invalid key size */
            aesni_cbc_encrypt(in, out, len, (const AES_KEY *)key, ivec, 0);
            break;
        }
    }
}

/* CPU feature check. */
int ossl_aes_cbc_vaes_eligible(void)
{
    return ossl_vaes512_cpu_capable();
}

OPENSSL_UNTARGET_VAES512

#endif /* VAES512_ELIGIBLE */
