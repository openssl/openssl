/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (C) 2026, Advanced Micro Devices, all rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * AVX2/VAES-256 intrinsic implementations of AES-CTR, AES-CFB128, and
 * AES-CBC decryption.
 *
 * Each YMM register holds two independent 128-bit AES blocks. CPUs with
 * AVX-512 VAES keep the 512-bit kernels. CBC encryption stays on
 * aesni_cbc_encrypt: each ciphertext block depends on the previous one.
 * CFB encryption is serial for the same reason. CFB decryption encrypts
 * ciphertext that is already available, so it runs two blocks wide.
 */

#include "internal/deprecated.h"

#include <openssl/opensslconf.h>
#include "internal/cryptlib.h"
#include <openssl/aes.h>
#include "crypto/modes.h"
#include "crypto/aes_platform.h"

#if VAES256_ELIGIBLE

#include <openssl/e_os2.h>
#include <string.h>
#include <immintrin.h>

#if VAES256_CTR_ELIGIBLE
void ossl_aes_ctr_vaes256(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key,
    unsigned char *counter,
    unsigned char *ecount_buf, unsigned int *num);
int ossl_aes_ctr_vaes256_eligible(void);
#endif

#if VAES256_CBC_ELIGIBLE
void ossl_aes_cbc_vaes256_decrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], int enc);
int ossl_aes_cbc_vaes256_eligible(void);
#endif

#if VAES256_CFB_ELIGIBLE
void ossl_aes_cfb128_vaes256_enc(const unsigned char *in, unsigned char *out,
    size_t len, const AES_KEY *key,
    unsigned char ivec[16], ossl_ssize_t *num);
void ossl_aes_cfb128_vaes256_dec(const unsigned char *in, unsigned char *out,
    size_t len, const AES_KEY *key,
    unsigned char ivec[16], ossl_ssize_t *num);
int ossl_aes_cfb128_vaes256_eligible(void);
#endif

void aesni_encrypt(const unsigned char *in, unsigned char *out,
    const AES_KEY *key);
void aesni_cbc_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const AES_KEY *key,
    unsigned char *ivec, int enc);

/*
 * Out of line so the schedule wipe and the YMM clear survive LTO.
 * num_keys counts 32-byte broadcast round keys.
 */
void ossl_aes_vaes256_cleanup(void *key_schedule, size_t num_keys);

#define OSSL_VAES256_STRINGIFY_IMPL_(a) #a
#define OSSL_VAES256_STRINGIFY_(a) OSSL_VAES256_STRINGIFY_IMPL_(a)

#ifdef __clang__
#define OPENSSL_TARGET_VAES256                            \
    _Pragma(OSSL_VAES256_STRINGIFY_(clang attribute push( \
        __attribute__((target("avx2,vaes,aes"))),         \
        apply_to = function)))
#define OPENSSL_UNTARGET_VAES256 _Pragma("clang attribute pop")
#elif defined(__GNUC__)
#define OPENSSL_TARGET_VAES256  \
    _Pragma("GCC push_options") \
        _Pragma(OSSL_VAES256_STRINGIFY_(GCC target("avx2,vaes,aes")))
#define OPENSSL_UNTARGET_VAES256 _Pragma("GCC pop_options")
#else
#define OPENSSL_TARGET_VAES256
#define OPENSSL_UNTARGET_VAES256
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
 * AVX2 is EBX bit 5 of CPUID leaf 7, stored in OPENSSL_ia32cap_P[2].
 * VAES is ECX bit 9 of that leaf, stored in OPENSSL_ia32cap_P[3].
 * This check uses no vector instructions and stays outside the ISA target.
 */
static ossl_inline int ossl_vaes256_cpu_capable(void)
{
    return (OPENSSL_ia32cap_P[2] & (1u << 5))
        && (OPENSSL_ia32cap_P[3] & (1u << 9));
}

#define OSSL_VAES256_DEFINE_ROUNDS(TAG, ROUNDS, AESOP, AESLAST) \
    OSSL_FUNC_ALWAYS_INLINE                                     \
    void TAG##_4x256_##ROUNDS(                                  \
        __m256i *b1, __m256i *b2, __m256i *b3, __m256i *b4,     \
        const __m256i *rk)                                      \
    {                                                           \
        *b1 = _mm256_xor_si256(*b1, rk[0]);                     \
        *b2 = _mm256_xor_si256(*b2, rk[0]);                     \
        *b3 = _mm256_xor_si256(*b3, rk[0]);                     \
        *b4 = _mm256_xor_si256(*b4, rk[0]);                     \
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
    void TAG##_2x256_##ROUNDS(                                  \
        __m256i *b1, __m256i *b2, const __m256i *rk)            \
    {                                                           \
        *b1 = _mm256_xor_si256(*b1, rk[0]);                     \
        *b2 = _mm256_xor_si256(*b2, rk[0]);                     \
        for (int i = 1; i < ROUNDS; i++) {                      \
            *b1 = AESOP(*b1, rk[i]);                            \
            *b2 = AESOP(*b2, rk[i]);                            \
        }                                                       \
        *b1 = AESLAST(*b1, rk[ROUNDS]);                         \
        *b2 = AESLAST(*b2, rk[ROUNDS]);                         \
    }                                                           \
                                                                \
    OSSL_FUNC_ALWAYS_INLINE                                     \
    void TAG##_1x256_##ROUNDS(                                  \
        __m256i *b1, const __m256i *rk)                         \
    {                                                           \
        *b1 = _mm256_xor_si256(*b1, rk[0]);                     \
        for (int i = 1; i < ROUNDS; i++)                        \
            *b1 = AESOP(*b1, rk[i]);                            \
        *b1 = AESLAST(*b1, rk[ROUNDS]);                         \
    }

#define OSSL_VAES256_DEFINE_ENCRYPT(ROUNDS)    \
    OSSL_VAES256_DEFINE_ROUNDS(AesEnc, ROUNDS, \
        _mm256_aesenc_epi128, _mm256_aesenclast_epi128)

#define OSSL_VAES256_DEFINE_DECRYPT(ROUNDS)    \
    OSSL_VAES256_DEFINE_ROUNDS(AesDec, ROUNDS, \
        _mm256_aesdec_epi128, _mm256_aesdeclast_epi128)

#define OSSL_VAES256_LOAD_ROUNDKEYS(rk, key, NR)                               \
    do {                                                                       \
        const unsigned char *rk_bytes_ = (const unsigned char *)(key)->rd_key; \
        for (int i_ = 0; i_ <= (NR); i_++) {                                   \
            __m128i t_ = _mm_loadu_si128(                                      \
                (const __m128i *)(rk_bytes_ + i_ * 16));                       \
            (rk)[i_] = _mm256_broadcastsi128_si256(t_);                        \
        }                                                                      \
    } while (0)

OPENSSL_TARGET_VAES256

#if VAES256_CTR_ELIGIBLE || VAES256_CFB_ELIGIBLE

OSSL_VAES256_DEFINE_ENCRYPT(10) /* AES-128 */
OSSL_VAES256_DEFINE_ENCRYPT(12) /* AES-192 */
OSSL_VAES256_DEFINE_ENCRYPT(14) /* AES-256 */

#endif

#if VAES256_CTR_ELIGIBLE

/*-
 * Counters are a full 128-bit byte swap of the big-endian block, then a
 * 64-bit add. The low lane is counter+0 and the high lane is counter+1.
 * The caller clamps the length so the low 64 bits do not wrap.
 */
static inline __m256i ctr256_swap_mask(void)
{
    return _mm256_set_epi32(0x00010203, 0x04050607,
        0x08090a0b, 0x0c0d0e0f,
        0x00010203, 0x04050607,
        0x08090a0b, 0x0c0d0e0f);
}

static inline __m256i ctr256_init2(const unsigned char *iv, __m256i swap)
{
    __m128i iv128 = _mm_loadu_si128((const __m128i *)iv);
    __m256i c = _mm256_broadcastsi128_si256(iv128);

    c = _mm256_shuffle_epi8(c, swap);
    c = _mm256_add_epi64(c, _mm256_set_epi64x(0, 1, 0, 0));
    return c;
}

#define DEFINE_CTR256_BLOCK(NR)                                          \
    OSSL_FUNC_NOINLINE                                                   \
    static void ctr256_process_##NR(                                     \
        const unsigned char *in, unsigned char *out,                     \
        size_t len, const AES_KEY *key, unsigned char *iv)               \
    {                                                                    \
        __m256i rk[NR + 1];                                              \
        OSSL_VAES256_LOAD_ROUNDKEYS(rk, key, NR);                        \
                                                                         \
        const __m256i *p_in = (const __m256i *)in;                       \
        __m256i *p_out = (__m256i *)out;                                 \
        __m256i swap = ctr256_swap_mask();                               \
        __m256i c1 = ctr256_init2(iv, swap);                             \
        __m256i a1, a2, a3, a4;                                          \
        __m256i b1, b2, b3, b4;                                          \
        __m256i c2, c3, c4;                                              \
        size_t blocks = len / AES_BLOCK_SIZE;                            \
        size_t res = len % AES_BLOCK_SIZE;                               \
        const __m256i inc2 = _mm256_set_epi64x(0, 2, 0, 2);              \
        const __m256i inc4 = _mm256_set_epi64x(0, 4, 0, 4);              \
        const __m256i inc6 = _mm256_set_epi64x(0, 6, 0, 6);              \
        const __m256i inc8 = _mm256_set_epi64x(0, 8, 0, 8);              \
                                                                         \
        while (blocks >= 8) {                                            \
            c2 = _mm256_add_epi64(c1, inc2);                             \
            c3 = _mm256_add_epi64(c1, inc4);                             \
            c4 = _mm256_add_epi64(c1, inc6);                             \
                                                                         \
            a1 = _mm256_loadu_si256(p_in);                               \
            a2 = _mm256_loadu_si256(p_in + 1);                           \
            a3 = _mm256_loadu_si256(p_in + 2);                           \
            a4 = _mm256_loadu_si256(p_in + 3);                           \
                                                                         \
            b1 = _mm256_shuffle_epi8(c1, swap);                          \
            b2 = _mm256_shuffle_epi8(c2, swap);                          \
            b3 = _mm256_shuffle_epi8(c3, swap);                          \
            b4 = _mm256_shuffle_epi8(c4, swap);                          \
                                                                         \
            AesEnc_4x256_##NR(&b1, &b2, &b3, &b4, rk);                   \
                                                                         \
            _mm256_storeu_si256(p_out, _mm256_xor_si256(b1, a1));        \
            _mm256_storeu_si256(p_out + 1, _mm256_xor_si256(b2, a2));    \
            _mm256_storeu_si256(p_out + 2, _mm256_xor_si256(b3, a3));    \
            _mm256_storeu_si256(p_out + 3, _mm256_xor_si256(b4, a4));    \
                                                                         \
            c1 = _mm256_add_epi64(c1, inc8);                             \
            p_in += 4;                                                   \
            p_out += 4;                                                  \
            blocks -= 8;                                                 \
        }                                                                \
                                                                         \
        if (blocks >= 4) {                                               \
            c2 = _mm256_add_epi64(c1, inc2);                             \
            a1 = _mm256_loadu_si256(p_in);                               \
            a2 = _mm256_loadu_si256(p_in + 1);                           \
            b1 = _mm256_shuffle_epi8(c1, swap);                          \
            b2 = _mm256_shuffle_epi8(c2, swap);                          \
            AesEnc_2x256_##NR(&b1, &b2, rk);                             \
            _mm256_storeu_si256(p_out, _mm256_xor_si256(b1, a1));        \
            _mm256_storeu_si256(p_out + 1, _mm256_xor_si256(b2, a2));    \
            c1 = _mm256_add_epi64(c1, inc4);                             \
            p_in += 2;                                                   \
            p_out += 2;                                                  \
            blocks -= 4;                                                 \
        }                                                                \
                                                                         \
        if (blocks >= 2) {                                               \
            a1 = _mm256_loadu_si256(p_in);                               \
            b1 = _mm256_shuffle_epi8(c1, swap);                          \
            AesEnc_1x256_##NR(&b1, rk);                                  \
            _mm256_storeu_si256(p_out, _mm256_xor_si256(b1, a1));        \
            c1 = _mm256_add_epi64(c1, inc2);                             \
            p_in += 1;                                                   \
            p_out += 1;                                                  \
            blocks -= 2;                                                 \
        }                                                                \
                                                                         \
        {                                                                \
            size_t tail_bytes = (blocks * AES_BLOCK_SIZE) + res;         \
                                                                         \
            if (tail_bytes > 0) {                                        \
                unsigned char tmp_in[32], tmp_out[32];                   \
                size_t adv = blocks + (res > 0 ? 1 : 0);                 \
                __m256i one_lo = _mm256_set_epi64x(0, 0, 0, 1);          \
                size_t i;                                                \
                                                                         \
                memset(tmp_in, 0, sizeof(tmp_in));                       \
                memcpy(tmp_in, (const unsigned char *)p_in, tail_bytes); \
                a1 = _mm256_loadu_si256((const __m256i *)tmp_in);        \
                b1 = _mm256_shuffle_epi8(c1, swap);                      \
                AesEnc_1x256_##NR(&b1, rk);                              \
                _mm256_storeu_si256((__m256i *)tmp_out,                  \
                    _mm256_xor_si256(b1, a1));                           \
                memcpy((unsigned char *)p_out, tmp_out, tail_bytes);     \
                OPENSSL_cleanse(tmp_in, sizeof(tmp_in));                 \
                OPENSSL_cleanse(tmp_out, sizeof(tmp_out));               \
                for (i = 0; i < adv; i++)                                \
                    c1 = _mm256_add_epi64(c1, one_lo);                   \
            }                                                            \
        }                                                                \
                                                                         \
        {                                                                \
            __m256i c_be = _mm256_shuffle_epi8(c1, swap);                \
            __m128i lo = _mm256_castsi256_si128(c_be);                   \
                                                                         \
            _mm_storeu_si128((__m128i *)iv, lo);                         \
        }                                                                \
                                                                         \
        ossl_aes_vaes256_cleanup(rk, NR + 1);                            \
    }

DEFINE_CTR256_BLOCK(10)
DEFINE_CTR256_BLOCK(12)
DEFINE_CTR256_BLOCK(14)

void ossl_aes_ctr_vaes256(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key,
    unsigned char *counter,
    unsigned char *ecount_buf, unsigned int *num)
{
    size_t n = *num;
    size_t l = length;
    int nr = key->rounds + 1;

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

    {
        size_t block_bytes = (l / 16) * 16;

        if (block_bytes > 0) {
            size_t total_blocks = block_bytes / 16;
            uint64_t ctr_lo = ((uint64_t)counter[8] << 56)
                | ((uint64_t)counter[9] << 48)
                | ((uint64_t)counter[10] << 40)
                | ((uint64_t)counter[11] << 32)
                | ((uint64_t)counter[12] << 24)
                | ((uint64_t)counter[13] << 16)
                | ((uint64_t)counter[14] << 8)
                | ((uint64_t)counter[15]);
            size_t safe_blocks = (ctr_lo <= UINT64_MAX - total_blocks)
                ? total_blocks
                : (size_t)(UINT64_MAX - ctr_lo);
            size_t safe_bytes = safe_blocks * 16;

            if (safe_bytes > 0) {
                switch (nr) {
                case 10:
                    ctr256_process_10(in, out, safe_bytes, key, counter);
                    break;
                case 12:
                    ctr256_process_12(in, out, safe_bytes, key, counter);
                    break;
                case 14:
                    ctr256_process_14(in, out, safe_bytes, key, counter);
                    break;
                default:
                    CRYPTO_ctr128_encrypt(in, out, safe_bytes, key, counter,
                        ecount_buf, num, (block128_f)aesni_encrypt);
                    break;
                }
                in += safe_bytes;
                out += safe_bytes;
                l -= safe_bytes;
            }

            if (safe_blocks < total_blocks && l > 0) {
                CRYPTO_ctr128_encrypt(in, out, 16, key, counter,
                    ecount_buf, num, (block128_f)aesni_encrypt);
                in += 16;
                out += 16;
                l -= 16;

                if (l >= 512) {
                    size_t resume_bytes = (l / 16) * 16;

                    switch (nr) {
                    case 10:
                        ctr256_process_10(in, out, resume_bytes, key, counter);
                        break;
                    case 12:
                        ctr256_process_12(in, out, resume_bytes, key, counter);
                        break;
                    case 14:
                        ctr256_process_14(in, out, resume_bytes, key, counter);
                        break;
                    default:
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

    if (l > 0)
        CRYPTO_ctr128_encrypt(in, out, l, key, counter,
            ecount_buf, num, (block128_f)aesni_encrypt);
    else
        *num = 0;
}

#endif /* VAES256_CTR_ELIGIBLE */

#if VAES256_CBC_ELIGIBLE

OSSL_VAES256_DEFINE_DECRYPT(10)
OSSL_VAES256_DEFINE_DECRYPT(12)
OSSL_VAES256_DEFINE_DECRYPT(14)

/* Low 128 bits are the previous ciphertext. High 128 bits are this block. */
static inline __m256i cbc256_chain(__m128i prev, __m128i curr)
{
    return _mm256_inserti128_si256(_mm256_castsi128_si256(prev), curr, 1);
}

#define DEFINE_CBC256_DECRYPT(NR)                                \
    OSSL_FUNC_NOINLINE                                           \
    static void cbc256_decrypt_##NR(                             \
        const unsigned char *in, unsigned char *out, size_t len, \
        const AES_KEY *key, unsigned char *iv)                   \
    {                                                            \
        __m256i rk[NR + 1];                                      \
        const __m256i *pa = (const __m256i *)in;                 \
        __m256i *po = (__m256i *)out;                            \
        __m128i prev = _mm_loadu_si128((const __m128i *)iv);     \
        size_t blocks = len / AES_BLOCK_SIZE;                    \
        __m256i a1, a2, a3, a4;                                  \
        __m256i b1, b2, b3, b4;                                  \
                                                                 \
        OSSL_VAES256_LOAD_ROUNDKEYS(rk, key, NR);                \
                                                                 \
        while (blocks >= 8) {                                    \
            a1 = _mm256_loadu_si256(pa);                         \
            a2 = _mm256_loadu_si256(pa + 1);                     \
            a3 = _mm256_loadu_si256(pa + 2);                     \
            a4 = _mm256_loadu_si256(pa + 3);                     \
            b1 = cbc256_chain(prev, _mm256_castsi256_si128(a1)); \
            b2 = cbc256_chain(_mm256_extracti128_si256(a1, 1),   \
                _mm256_castsi256_si128(a2));                     \
            b3 = cbc256_chain(_mm256_extracti128_si256(a2, 1),   \
                _mm256_castsi256_si128(a3));                     \
            b4 = cbc256_chain(_mm256_extracti128_si256(a3, 1),   \
                _mm256_castsi256_si128(a4));                     \
            prev = _mm256_extracti128_si256(a4, 1);              \
            AesDec_4x256_##NR(&a1, &a2, &a3, &a4, rk);           \
            a1 = _mm256_xor_si256(a1, b1);                       \
            a2 = _mm256_xor_si256(a2, b2);                       \
            a3 = _mm256_xor_si256(a3, b3);                       \
            a4 = _mm256_xor_si256(a4, b4);                       \
            _mm256_storeu_si256(po, a1);                         \
            _mm256_storeu_si256(po + 1, a2);                     \
            _mm256_storeu_si256(po + 2, a3);                     \
            _mm256_storeu_si256(po + 3, a4);                     \
            pa += 4;                                             \
            po += 4;                                             \
            blocks -= 8;                                         \
        }                                                        \
                                                                 \
        if (blocks >= 4) {                                       \
            a1 = _mm256_loadu_si256(pa);                         \
            a2 = _mm256_loadu_si256(pa + 1);                     \
            b1 = cbc256_chain(prev, _mm256_castsi256_si128(a1)); \
            b2 = cbc256_chain(_mm256_extracti128_si256(a1, 1),   \
                _mm256_castsi256_si128(a2));                     \
            prev = _mm256_extracti128_si256(a2, 1);              \
            AesDec_2x256_##NR(&a1, &a2, rk);                     \
            a1 = _mm256_xor_si256(a1, b1);                       \
            a2 = _mm256_xor_si256(a2, b2);                       \
            _mm256_storeu_si256(po, a1);                         \
            _mm256_storeu_si256(po + 1, a2);                     \
            pa += 2;                                             \
            po += 2;                                             \
            blocks -= 4;                                         \
        }                                                        \
                                                                 \
        if (blocks >= 2) {                                       \
            a1 = _mm256_loadu_si256(pa);                         \
            b1 = cbc256_chain(prev, _mm256_castsi256_si128(a1)); \
            prev = _mm256_extracti128_si256(a1, 1);              \
            AesDec_1x256_##NR(&a1, rk);                          \
            a1 = _mm256_xor_si256(a1, b1);                       \
            _mm256_storeu_si256(po, a1);                         \
            pa += 1;                                             \
            po += 1;                                             \
            blocks -= 2;                                         \
        }                                                        \
                                                                 \
        if (blocks == 1) {                                       \
            const __m128i *pa128 = (const __m128i *)pa;          \
            __m128i *po128 = (__m128i *)po;                      \
            __m128i ct = _mm_loadu_si128(pa128);                 \
                                                                 \
            a1 = _mm256_castsi128_si256(ct);                     \
            b1 = _mm256_castsi128_si256(prev);                   \
            AesDec_1x256_##NR(&a1, rk);                          \
            a1 = _mm256_xor_si256(a1, b1);                       \
            _mm_storeu_si128(po128, _mm256_castsi256_si128(a1)); \
            prev = ct;                                           \
        }                                                        \
                                                                 \
        _mm_storeu_si128((__m128i *)iv, prev);                   \
        ossl_aes_vaes256_cleanup(rk, NR + 1);                    \
    }

DEFINE_CBC256_DECRYPT(10)
DEFINE_CBC256_DECRYPT(12)
DEFINE_CBC256_DECRYPT(14)

void ossl_aes_cbc_vaes256_decrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], int enc)
{
    size_t full_bytes;
    int nr = ((const AES_KEY *)key)->rounds + 1;

    if (len == 0)
        return;

    if (enc) {
        aesni_cbc_encrypt(in, out, len, (const AES_KEY *)key, ivec, enc);
        return;
    }

    full_bytes = (len / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    if (full_bytes == 0)
        return;

    switch (nr) {
    case 10:
        cbc256_decrypt_10(in, out, full_bytes, (const AES_KEY *)key, ivec);
        break;
    case 12:
        cbc256_decrypt_12(in, out, full_bytes, (const AES_KEY *)key, ivec);
        break;
    case 14:
        cbc256_decrypt_14(in, out, full_bytes, (const AES_KEY *)key, ivec);
        break;
    default:
        aesni_cbc_encrypt(in, out, len, (const AES_KEY *)key, ivec, 0);
        break;
    }
}

#endif /* VAES256_CBC_ELIGIBLE */

#if VAES256_CFB_ELIGIBLE

/* Low 128 bits are the previous ciphertext. High 128 bits are this block. */
static inline __m256i cfb256_chain(__m128i prev, __m128i curr)
{
    return _mm256_inserti128_si256(_mm256_castsi128_si256(prev), curr, 1);
}

/* XOR count bytes of a feedback block. n + count stays within 16. */
static inline void cfb256_apply(const unsigned char *in, unsigned char *out,
    unsigned char *iv, size_t n, size_t count, int enc)
{
    size_t i;

    for (i = 0; i < count; i++) {
        unsigned char c = in[i];

        if (enc) {
            iv[n] ^= c;
            out[i] = iv[n];
        } else {
            out[i] = (unsigned char)(iv[n] ^ c);
            iv[n] = c;
        }
        n++;
    }
}

/* Resume a feedback block that already holds keystream. */
static void cfb256_pre(const unsigned char **inp, unsigned char **outp,
    size_t *len, unsigned char *iv, size_t *np, int enc)
{
    size_t n = *np;

    while (n != 0 && *len != 0) {
        cfb256_apply(*inp, *outp, iv, n, 1, enc);
        *inp += 1;
        *outp += 1;
        *len -= 1;
        n = (n + 1) & 15;
    }
    *np = n;
}

/*-
 * CFB-128 encryption: AES(previous ciphertext) XOR plaintext.
 * The feedback depends on the ciphertext just produced, so each
 * block is encrypted on its own. A short tail encrypts the feedback
 * block and leaves the unused keystream bytes in ivec.
 */
#define DEFINE_CFB256_ENC(NR)                                     \
    OSSL_FUNC_NOINLINE                                            \
    static void cfb256_enc_##NR(                                  \
        const unsigned char *in, unsigned char *out, size_t len,  \
        const AES_KEY *key, unsigned char *iv, ossl_ssize_t *num) \
    {                                                             \
        __m256i rk[NR + 1];                                       \
        __m256i b1;                                               \
        __m128i prev = _mm_loadu_si128((const __m128i *)iv);      \
        size_t rem;                                               \
                                                                  \
        OSSL_VAES256_LOAD_ROUNDKEYS(rk, key, NR);                 \
                                                                  \
        while (len >= AES_BLOCK_SIZE) {                           \
            __m128i pt = _mm_loadu_si128((const __m128i *)in);    \
                                                                  \
            b1 = _mm256_castsi128_si256(prev);                    \
            AesEnc_1x256_##NR(&b1, rk);                           \
            prev = _mm_xor_si128(_mm256_castsi256_si128(b1), pt); \
            _mm_storeu_si128((__m128i *)out, prev);               \
            in += AES_BLOCK_SIZE;                                 \
            out += AES_BLOCK_SIZE;                                \
            len -= AES_BLOCK_SIZE;                                \
        }                                                         \
                                                                  \
        rem = len;                                                \
        if (rem != 0) {                                           \
            b1 = _mm256_castsi128_si256(prev);                    \
            AesEnc_1x256_##NR(&b1, rk);                           \
            prev = _mm256_castsi256_si128(b1);                    \
            _mm_storeu_si128((__m128i *)iv, prev);                \
            cfb256_apply(in, out, iv, 0, rem, 1);                 \
            *num = (ossl_ssize_t)rem;                             \
        } else {                                                  \
            _mm_storeu_si128((__m128i *)iv, prev);                \
            *num = 0;                                             \
        }                                                         \
        ossl_aes_vaes256_cleanup(rk, NR + 1);                     \
    }

/*-
 * CFB-128 decryption: AES(previous ciphertext) XOR ciphertext.
 * Every AES input is already in the ciphertext, so two blocks share
 * one YMM register. The last ciphertext block becomes the next ivec.
 * A short tail leaves unused keystream bytes in ivec, matching
 * CRYPTO_cfb128_encrypt.
 */
#define DEFINE_CFB256_DEC(NR)                                      \
    OSSL_FUNC_NOINLINE                                             \
    static void cfb256_dec_##NR(                                   \
        const unsigned char *in, unsigned char *out, size_t len,   \
        const AES_KEY *key, unsigned char *iv, ossl_ssize_t *num)  \
    {                                                              \
        __m256i rk[NR + 1];                                        \
        __m128i prev = _mm_loadu_si128((const __m128i *)iv);       \
        size_t blocks = len / AES_BLOCK_SIZE;                      \
        size_t rem = len % AES_BLOCK_SIZE;                         \
        __m256i a1, a2, a3, a4;                                    \
        __m256i b1, b2, b3, b4;                                    \
                                                                   \
        OSSL_VAES256_LOAD_ROUNDKEYS(rk, key, NR);                  \
                                                                   \
        while (blocks >= 8) {                                      \
            a1 = _mm256_loadu_si256((const __m256i *)in);          \
            a2 = _mm256_loadu_si256((const __m256i *)(in + 32));   \
            a3 = _mm256_loadu_si256((const __m256i *)(in + 64));   \
            a4 = _mm256_loadu_si256((const __m256i *)(in + 96));   \
            b1 = cfb256_chain(prev, _mm256_castsi256_si128(a1));   \
            b2 = cfb256_chain(_mm256_extracti128_si256(a1, 1),     \
                _mm256_castsi256_si128(a2));                       \
            b3 = cfb256_chain(_mm256_extracti128_si256(a2, 1),     \
                _mm256_castsi256_si128(a3));                       \
            b4 = cfb256_chain(_mm256_extracti128_si256(a3, 1),     \
                _mm256_castsi256_si128(a4));                       \
            prev = _mm256_extracti128_si256(a4, 1);                \
            AesEnc_4x256_##NR(&b1, &b2, &b3, &b4, rk);             \
            b1 = _mm256_xor_si256(b1, a1);                         \
            b2 = _mm256_xor_si256(b2, a2);                         \
            b3 = _mm256_xor_si256(b3, a3);                         \
            b4 = _mm256_xor_si256(b4, a4);                         \
            _mm256_storeu_si256((__m256i *)out, b1);               \
            _mm256_storeu_si256((__m256i *)(out + 32), b2);        \
            _mm256_storeu_si256((__m256i *)(out + 64), b3);        \
            _mm256_storeu_si256((__m256i *)(out + 96), b4);        \
            in += 128;                                             \
            out += 128;                                            \
            blocks -= 8;                                           \
        }                                                          \
                                                                   \
        if (blocks >= 4) {                                         \
            a1 = _mm256_loadu_si256((const __m256i *)in);          \
            a2 = _mm256_loadu_si256((const __m256i *)(in + 32));   \
            b1 = cfb256_chain(prev, _mm256_castsi256_si128(a1));   \
            b2 = cfb256_chain(_mm256_extracti128_si256(a1, 1),     \
                _mm256_castsi256_si128(a2));                       \
            prev = _mm256_extracti128_si256(a2, 1);                \
            AesEnc_2x256_##NR(&b1, &b2, rk);                       \
            b1 = _mm256_xor_si256(b1, a1);                         \
            b2 = _mm256_xor_si256(b2, a2);                         \
            _mm256_storeu_si256((__m256i *)out, b1);               \
            _mm256_storeu_si256((__m256i *)(out + 32), b2);        \
            in += 64;                                              \
            out += 64;                                             \
            blocks -= 4;                                           \
        }                                                          \
                                                                   \
        if (blocks >= 2) {                                         \
            a1 = _mm256_loadu_si256((const __m256i *)in);          \
            b1 = cfb256_chain(prev, _mm256_castsi256_si128(a1));   \
            prev = _mm256_extracti128_si256(a1, 1);                \
            AesEnc_1x256_##NR(&b1, rk);                            \
            b1 = _mm256_xor_si256(b1, a1);                         \
            _mm256_storeu_si256((__m256i *)out, b1);               \
            in += 32;                                              \
            out += 32;                                             \
            blocks -= 2;                                           \
        }                                                          \
                                                                   \
        if (blocks == 1) {                                         \
            __m128i ct = _mm_loadu_si128((const __m128i *)in);     \
                                                                   \
            b1 = _mm256_castsi128_si256(prev);                     \
            AesEnc_1x256_##NR(&b1, rk);                            \
            b1 = _mm256_xor_si256(b1, _mm256_castsi128_si256(ct)); \
            _mm_storeu_si128((__m128i *)out,                       \
                _mm256_castsi256_si128(b1));                       \
            prev = ct;                                             \
            in += AES_BLOCK_SIZE;                                  \
            out += AES_BLOCK_SIZE;                                 \
        }                                                          \
                                                                   \
        if (rem != 0) {                                            \
            b1 = _mm256_castsi128_si256(prev);                     \
            AesEnc_1x256_##NR(&b1, rk);                            \
            prev = _mm256_castsi256_si128(b1);                     \
            _mm_storeu_si128((__m128i *)iv, prev);                 \
            cfb256_apply(in, out, iv, 0, rem, 0);                  \
            *num = (ossl_ssize_t)rem;                              \
        } else {                                                   \
            _mm_storeu_si128((__m128i *)iv, prev);                 \
            *num = 0;                                              \
        }                                                          \
        ossl_aes_vaes256_cleanup(rk, NR + 1);                      \
    }

DEFINE_CFB256_ENC(10)
DEFINE_CFB256_ENC(12)
DEFINE_CFB256_ENC(14)
DEFINE_CFB256_DEC(10)
DEFINE_CFB256_DEC(12)
DEFINE_CFB256_DEC(14)

static int cfb256_begin(const unsigned char **in, unsigned char **out,
    size_t *len, unsigned char *iv, ossl_ssize_t *num, int enc)
{
    size_t n;

    if (*num < 0) {
        *num = -1;
        return 0;
    }
    if (*len == 0)
        return 0;

    n = (size_t)*num;
    cfb256_pre(in, out, len, iv, &n, enc);
    if (*len == 0) {
        *num = (ossl_ssize_t)n;
        return 0;
    }
    return 1;
}

static void cfb256_run(const unsigned char *in, unsigned char *out,
    size_t len, const AES_KEY *key, unsigned char *iv,
    ossl_ssize_t *num, int enc)
{
    int nr = key->rounds + 1;
    int n;

    if (!cfb256_begin(&in, &out, &len, iv, num, enc))
        return;

    if (enc) {
        switch (nr) {
        case 10:
            cfb256_enc_10(in, out, len, key, iv, num);
            return;
        case 12:
            cfb256_enc_12(in, out, len, key, iv, num);
            return;
        case 14:
            cfb256_enc_14(in, out, len, key, iv, num);
            return;
        default:
            break;
        }
    } else {
        switch (nr) {
        case 10:
            cfb256_dec_10(in, out, len, key, iv, num);
            return;
        case 12:
            cfb256_dec_12(in, out, len, key, iv, num);
            return;
        case 14:
            cfb256_dec_14(in, out, len, key, iv, num);
            return;
        default:
            break;
        }
    }

    n = 0;
    CRYPTO_cfb128_encrypt(in, out, len, key, iv, &n, enc,
        (block128_f)aesni_encrypt);
    *num = n;
}

void ossl_aes_cfb128_vaes256_enc(const unsigned char *in, unsigned char *out,
    size_t len, const AES_KEY *key,
    unsigned char ivec[16], ossl_ssize_t *num)
{
    cfb256_run(in, out, len, key, ivec, num, 1);
}

void ossl_aes_cfb128_vaes256_dec(const unsigned char *in, unsigned char *out,
    size_t len, const AES_KEY *key,
    unsigned char ivec[16], ossl_ssize_t *num)
{
    cfb256_run(in, out, len, key, ivec, num, 0);
}

#endif /* VAES256_CFB_ELIGIBLE */

OPENSSL_UNTARGET_VAES256

#if VAES256_CTR_ELIGIBLE
int ossl_aes_ctr_vaes256_eligible(void)
{
    return ossl_vaes256_cpu_capable();
}
#endif

#if VAES256_CBC_ELIGIBLE
int ossl_aes_cbc_vaes256_eligible(void)
{
    return ossl_vaes256_cpu_capable();
}
#endif

#if VAES256_CFB_ELIGIBLE
int ossl_aes_cfb128_vaes256_eligible(void)
{
    return ossl_vaes256_cpu_capable();
}
#endif

#endif /* VAES256_ELIGIBLE */
