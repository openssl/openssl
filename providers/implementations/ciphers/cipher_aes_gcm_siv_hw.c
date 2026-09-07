/*
 * Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#include <openssl/proverr.h>
#include <internal/endian.h>
#include <prov/implementations.h>
#include "cipher_aes_gcm_siv.h"

static int aes_gcm_siv_ctr32(PROV_AES_GCM_SIV_CTX *ctx, const unsigned char *init_counter,
    unsigned char *out, const unsigned char *in, size_t len);
static int aes_gcm_siv_decrypt(PROV_AES_GCM_SIV_CTX *ctx, const unsigned char *in,
    unsigned char *out, size_t len);
static int aes_gcm_siv_encrypt(PROV_AES_GCM_SIV_CTX *ctx, const unsigned char *in,
    unsigned char *out, size_t len);

/*
 * The scratch is per context and NOT copied by dupctx (a copy re-creates its own),
 * so it is made here, on first use, rather than only in initkey: EVP_CIPHER_CTX_copy
 * of a keyed context followed by an update must work (evp_test does exactly that).
 */
static int scratch_ready(PROV_AES_GCM_SIV_CTX *ctx)
{
    if (ctx->scratch == NULL)
        ctx->scratch = OPENSSL_malloc(GCM_SIV_SCRATCH);
    return ctx->scratch != NULL;
}

/*
 * No-hardware tiers (v4 prototype).
 *  x86-64 with SSSE3 but no AES-NI (Core 2, early Atom): OpenSSL's vector-permute
 *  AES (vpaes) does ~340 MB/s per core-class here while its BITSLICED AES (bsaes,
 *  eight blocks in parallel, used by OpenSSL only for CTR/CBC/XTS) does ~700. The
 *  bitsliced ECB exists in bsaes-x86_64.pl behind `$ecb=1` and takes the STANDARD
 *  key schedule; single blocks (key derivation, the tag) stay on vpaes, which is
 *  constant-time, so a second schedule of the message key is kept for the bulk.
 *  aarch64 without FEAT_AES (Raspberry Pi 3/4): vpaes-armv8 exports a two-block
 *  interleaved ECB; use it instead of one vpaes_encrypt per block.
 */
#if defined(__x86_64__) && defined(BSAES_CAPABLE) && defined(VPAES_CAPABLE)
void bsaes_ecb_encrypt_blocks(const unsigned char *in, unsigned char *out, size_t blocks,
    const AES_KEY *key);
static void bsaes_ecb_wrap(const unsigned char *in, unsigned char *out, size_t len,
    const void *key, int enc)
{
    (void)enc;
    bsaes_ecb_encrypt_blocks(in, out, len / BLOCK_SIZE, (const AES_KEY *)key);
}
#define GCM_SIV_BSAES 1
#endif
#if defined(__aarch64__) && defined(VPAES_CAPABLE)
void vpaes_ecb_encrypt(const unsigned char *in, unsigned char *out, size_t len,
    const AES_KEY *key);
static void vpaes_ecb_wrap(const unsigned char *in, unsigned char *out, size_t len,
    const void *key, int enc)
{
    (void)enc;
    vpaes_ecb_encrypt(in, out, len, (const AES_KEY *)key);
}
#define GCM_SIV_VPAES_ECB 1
#endif

static ossl_inline void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/*
 * x86-64 with AVX-512 + VAES: the keystream for 32 blocks at a time in eight zmm
 * registers, XORed straight over the input — one pass, no buffers. The counter is
 * the little-endian 32-bit word in bytes 0..3 (RFC 8452 section 4), so it is
 * advanced with a lane-wise 32-bit add that wraps exactly as the spec's counter
 * does. Gated at run time on OpenSSL's own VAES/VPCLMULQDQ/AVX-512 probe (the one
 * the AES-GCM provider uses), and compiled only where the compiler supports
 * per-function target attributes.
 */
#if defined(__x86_64__) && defined(AESNI_CAPABLE) && (defined(__GNUC__) || defined(__clang__)) \
    && !defined(OPENSSL_NO_GCM_SIV_VAES)
#include <immintrin.h>
int ossl_vaes_vpclmulqdq_capable(void);
#define GCM_SIV_VAES 1

__attribute__((target("avx512f,avx512bw,vaes")))
/*
 * nr is the AES round count from the KEY LENGTH (10/12/14). It is deliberately not
 * read from key->rounds: aesni_set_encrypt_key() records Nr - 1 there (aesni_encrypt
 * counts aesenc iterations), where AES_set_encrypt_key() records Nr — and a kernel
 * that trusted the field ran every block one round short.
 */
static size_t ctr32le_vaes(const AES_KEY *key, int nr, const unsigned char ctr[16],
    unsigned char *out, const unsigned char *in, size_t len)
{
    const unsigned char *rk = (const unsigned char *)key->rd_key;
    const int rounds = nr;
    __m512i k[15], x[8], c, inc4;
    size_t done = 0;
    int r, i;

    for (r = 0; r <= rounds; r++)
        k[r] = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *)(rk + 16 * r)));
    /* lane i of c holds counter + i in its first dword; each further vector adds 4 */
    c = _mm512_add_epi32(_mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *)ctr)),
        _mm512_set_epi32(0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0));
    inc4 = _mm512_set_epi32(0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4);

    while (len - done >= 512) {
        for (i = 0; i < 8; i++) {
            x[i] = _mm512_xor_si512(c, k[0]);
            c = _mm512_add_epi32(c, inc4);
        }
        for (r = 1; r < rounds; r++)
            for (i = 0; i < 8; i++)
                x[i] = _mm512_aesenc_epi128(x[i], k[r]);
        for (i = 0; i < 8; i++) {
            x[i] = _mm512_aesenclast_epi128(x[i], k[rounds]);
            _mm512_storeu_si512((void *)(out + done + 64 * i),
                _mm512_xor_si512(x[i], _mm512_loadu_si512((const void *)(in + done + 64 * i))));
        }
        done += 512;
    }
    while (len - done >= 64) {
        __m512i y = _mm512_xor_si512(c, k[0]);

        c = _mm512_add_epi32(c, inc4);
        for (r = 1; r < rounds; r++)
            y = _mm512_aesenc_epi128(y, k[r]);
        y = _mm512_aesenclast_epi128(y, k[rounds]);
        _mm512_storeu_si512((void *)(out + done),
            _mm512_xor_si512(y, _mm512_loadu_si512((const void *)(in + done))));
        done += 64;
    }
    OPENSSL_cleanse(k, sizeof(k));
    OPENSSL_cleanse(x, sizeof(x));
    _mm256_zeroupper();
    return done;
}
#endif

/*
 * x86-64 with AES-NI but no VAES (Westmere through Zen 2/3, most Intel client
 * parts): the keystream 8 blocks at a time in xmm registers, XORed straight
 * over the input — the same shape as ctr32le_vaes at 128 bits. Replaces the
 * fill / ECB / XOR passes over the scratch on this tier.
 */
#if defined(__x86_64__) && defined(AESNI_CAPABLE) && (defined(__GNUC__) || defined(__clang__))
#include <wmmintrin.h>
#define GCM_SIV_AESNI_CTR 1

__attribute__((target("aes,sse4.1,ssse3"))) static size_t ctr32le_aesni(const AES_KEY *key, int nr, const unsigned char ctr[16],
    unsigned char *out, const unsigned char *in, size_t len)
{
    const unsigned char *rk = (const unsigned char *)key->rd_key;
    __m128i k[15], x[8], c, one;
    size_t done = 0;
    int r, i;

    for (r = 0; r <= nr; r++)
        k[r] = _mm_loadu_si128((const __m128i *)(rk + 16 * r));
    c = _mm_loadu_si128((const __m128i *)ctr);
    one = _mm_set_epi32(0, 0, 0, 1); /* the little-endian counter is dword 0 */

    while (len - done >= 128) {
        for (i = 0; i < 8; i++) {
            x[i] = _mm_xor_si128(c, k[0]);
            c = _mm_add_epi32(c, one);
        }
        for (r = 1; r < nr; r++)
            for (i = 0; i < 8; i++)
                x[i] = _mm_aesenc_si128(x[i], k[r]);
        for (i = 0; i < 8; i++) {
            x[i] = _mm_aesenclast_si128(x[i], k[nr]);
            _mm_storeu_si128((__m128i *)(out + done + 16 * i),
                _mm_xor_si128(x[i], _mm_loadu_si128((const __m128i *)(in + done + 16 * i))));
        }
        done += 128;
    }
    while (len - done >= 16) {
        __m128i y = _mm_xor_si128(c, k[0]);

        c = _mm_add_epi32(c, one);
        for (r = 1; r < nr; r++)
            y = _mm_aesenc_si128(y, k[r]);
        y = _mm_aesenclast_si128(y, k[nr]);
        _mm_storeu_si128((__m128i *)(out + done),
            _mm_xor_si128(y, _mm_loadu_si128((const __m128i *)(in + done))));
        done += 16;
    }
    OPENSSL_cleanse(k, sizeof(k));
    OPENSSL_cleanse(x, sizeof(x));
    return done;
}
#endif

/*
 * aarch64 with FEAT_AES: the keystream for eight blocks at a time in NEON
 * registers, XORed straight over the input — one pass, no buffers (v5 filled the
 * scratch with counter blocks, ran aes_v8_ecb_encrypt over it and XORed: three
 * passes). aes_v8_set_encrypt_key stores the round keys in the byte order AESE
 * consumes (aes_v8_encrypt loads them with ld1 and feeds aese directly), so they
 * load straight into registers. The rounds are unrolled per key size: a runtime
 * round loop is left rolled by the compiler and its AESE+AESMC pairs drift apart,
 * losing the fusion Apple and Arm cores rely on. The little-endian counter is
 * lane 0 (RFC 8452 section 4); nr from the key length, as above.
 */
#if defined(__aarch64__) && defined(__ARM_NEON) && defined(HWAES_CAPABLE) \
    && (defined(__GNUC__) || defined(__clang__)) && !defined(OPENSSL_NO_GCM_SIV_ARMV8)
#include <arm_neon.h>
#define GCM_SIV_ARMV8_CTR 1
#if defined(__clang__)
#define GCM_SIV_ARMV8 __attribute__((target("crypto")))
#else
#define GCM_SIV_ARMV8 __attribute__((target("+crypto")))
#endif
#define GCM_SIV_CTR8_R(i)                   \
    do {                                    \
        const uint8x16_t k_ = k[i];         \
        b0 = vaesmcq_u8(vaeseq_u8(b0, k_)); \
        b1 = vaesmcq_u8(vaeseq_u8(b1, k_)); \
        b2 = vaesmcq_u8(vaeseq_u8(b2, k_)); \
        b3 = vaesmcq_u8(vaeseq_u8(b3, k_)); \
        b4 = vaesmcq_u8(vaeseq_u8(b4, k_)); \
        b5 = vaesmcq_u8(vaeseq_u8(b5, k_)); \
        b6 = vaesmcq_u8(vaeseq_u8(b6, k_)); \
        b7 = vaesmcq_u8(vaeseq_u8(b7, k_)); \
    } while (0)

/* nr is a compile-time constant after inlining (the caller switches on it) */
GCM_SIV_ARMV8 static ossl_inline __attribute__((always_inline))
size_t
ctr32le_armv8_nr(const uint8x16_t *k, const int nr, uint32x4_t base, uint32_t c,
    unsigned char *out, const unsigned char *in, size_t len)
{
    size_t done = 0;

    while (len - done >= 128) {
        uint8x16_t b0 = vreinterpretq_u8_u32(vsetq_lane_u32(c, base, 0));
        uint8x16_t b1 = vreinterpretq_u8_u32(vsetq_lane_u32(c + 1, base, 0));
        uint8x16_t b2 = vreinterpretq_u8_u32(vsetq_lane_u32(c + 2, base, 0));
        uint8x16_t b3 = vreinterpretq_u8_u32(vsetq_lane_u32(c + 3, base, 0));
        uint8x16_t b4 = vreinterpretq_u8_u32(vsetq_lane_u32(c + 4, base, 0));
        uint8x16_t b5 = vreinterpretq_u8_u32(vsetq_lane_u32(c + 5, base, 0));
        uint8x16_t b6 = vreinterpretq_u8_u32(vsetq_lane_u32(c + 6, base, 0));
        uint8x16_t b7 = vreinterpretq_u8_u32(vsetq_lane_u32(c + 7, base, 0));
        const unsigned char *p = in + done;
        unsigned char *q = out + done;

        GCM_SIV_CTR8_R(0);
        GCM_SIV_CTR8_R(1);
        GCM_SIV_CTR8_R(2);
        GCM_SIV_CTR8_R(3);
        GCM_SIV_CTR8_R(4);
        GCM_SIV_CTR8_R(5);
        GCM_SIV_CTR8_R(6);
        GCM_SIV_CTR8_R(7);
        GCM_SIV_CTR8_R(8);
        if (nr >= 12) {
            GCM_SIV_CTR8_R(9);
            GCM_SIV_CTR8_R(10);
        }
        if (nr >= 14) {
            GCM_SIV_CTR8_R(11);
            GCM_SIV_CTR8_R(12);
        }
        {
            const uint8x16_t kl = k[nr - 1], kf = k[nr];

            b0 = veorq_u8(vaeseq_u8(b0, kl), kf);
            b1 = veorq_u8(vaeseq_u8(b1, kl), kf);
            b2 = veorq_u8(vaeseq_u8(b2, kl), kf);
            b3 = veorq_u8(vaeseq_u8(b3, kl), kf);
            b4 = veorq_u8(vaeseq_u8(b4, kl), kf);
            b5 = veorq_u8(vaeseq_u8(b5, kl), kf);
            b6 = veorq_u8(vaeseq_u8(b6, kl), kf);
            b7 = veorq_u8(vaeseq_u8(b7, kl), kf);
        }
        vst1q_u8(q, veorq_u8(b0, vld1q_u8(p)));
        vst1q_u8(q + 16, veorq_u8(b1, vld1q_u8(p + 16)));
        vst1q_u8(q + 32, veorq_u8(b2, vld1q_u8(p + 32)));
        vst1q_u8(q + 48, veorq_u8(b3, vld1q_u8(p + 48)));
        vst1q_u8(q + 64, veorq_u8(b4, vld1q_u8(p + 64)));
        vst1q_u8(q + 80, veorq_u8(b5, vld1q_u8(p + 80)));
        vst1q_u8(q + 96, veorq_u8(b6, vld1q_u8(p + 96)));
        vst1q_u8(q + 112, veorq_u8(b7, vld1q_u8(p + 112)));
        done += 128;
        c += 8;
    }
    while (len - done >= 16) {
        uint8x16_t b = vreinterpretq_u8_u32(vsetq_lane_u32(c, base, 0));
        int r;

        for (r = 0; r < nr - 1; r++)
            b = vaesmcq_u8(vaeseq_u8(b, k[r]));
        b = veorq_u8(vaeseq_u8(b, k[nr - 1]), k[nr]);
        vst1q_u8(out + done, veorq_u8(b, vld1q_u8(in + done)));
        done += 16;
        c++;
    }
    return done;
}

GCM_SIV_ARMV8 static size_t ctr32le_armv8(const AES_KEY *key, int nr, const unsigned char ctr[16],
    unsigned char *out, const unsigned char *in, size_t len)
{
    const unsigned char *rk = (const unsigned char *)key->rd_key;
    uint8x16_t k[15];
    uint32x4_t base;
    uint32_t c;
    size_t done;
    int r;

    for (r = 0; r <= nr; r++)
        k[r] = vld1q_u8(rk + 16 * r);
    base = vreinterpretq_u32_u8(vld1q_u8(ctr));
    c = vgetq_lane_u32(base, 0);
    switch (nr) {
    case 10:
        done = ctr32le_armv8_nr(k, 10, base, c, out, in, len);
        break;
    case 12:
        done = ctr32le_armv8_nr(k, 12, base, c, out, in, len);
        break;
    default:
        done = ctr32le_armv8_nr(k, 14, base, c, out, in, len);
        break;
    }
    OPENSSL_cleanse(k, sizeof(k));
    return done;
}
#endif

static int aes_gcm_siv_initkey(void *vctx)
{
    PROV_AES_GCM_SIV_CTX *ctx = (PROV_AES_GCM_SIV_CTX *)vctx;
    int (*set_key)(const unsigned char *, int, AES_KEY *);
    AES_KEY kgk;
    uint8_t block_in[BLOCK_SIZE], block_out[BLOCK_SIZE];
    uint32_t counter = 0;
    size_t i;
    int ret = 0;

    if (ctx->key_len != 16 && ctx->key_len != 24 && ctx->key_len != 32)
        return 0;

    ctx->generated_tag = 0;
    memset(ctx->tag, 0, TAG_SIZE);

    /* The platform AES, the same ladder the other AES providers climb. */
    ctx->ecb = NULL;
    ctx->ecb_key = &ctx->ks;
    ctx->ecb_min_blocks = 1;
    ctx->vaes = 0;
    ctx->aesni_ctr = 0;
    ctx->native_polyval = 0;
    ctx->armv8_ctr = 0;
#ifdef HWAES_CAPABLE
    if (HWAES_CAPABLE) {
        set_key = HWAES_set_encrypt_key;
        ctx->block = (block128_f)HWAES_encrypt;
#ifdef HWAES_ecb_encrypt
        ctx->ecb = (ecb128_f)HWAES_ecb_encrypt;
#endif
#ifdef GCM_SIV_ARMV8_CTR
        /* the fused keystream kernel above, and the PMULL POLYVAL kernel in
         * _polyval.c where the CPU has PMULL (every FEAT_AES core does) */
        ctx->armv8_ctr = 1;
        ctx->native_polyval = (OPENSSL_armcap_P & ARMV8_PMULL) ? 1 : 0;
#endif
    } else
#endif
#ifdef AESNI_CAPABLE
        if (AESNI_CAPABLE) {
        set_key = aesni_set_encrypt_key;
        ctx->block = (block128_f)aesni_encrypt;
        ctx->ecb = (ecb128_f)aesni_ecb_encrypt;
#ifdef GCM_SIV_VAES
        ctx->vaes = ossl_vaes_vpclmulqdq_capable() ? 1 : 0;
#endif
#ifdef GCM_SIV_AESNI_CTR
        ctx->aesni_ctr = !ctx->vaes;
#endif
        /*
         * native POLYVAL: VPCLMULQDQ (with VAES); else the 128-bit PCLMULQDQ kernel,
         * but ONLY where OpenSSL itself would use the 4-block gcm_ghash_clmul — on
         * CPUs with AVX and MOVBE (Haswell onward, every Zen) gcm128.c picks the
         * 8-block gcm_ghash_avx, which is faster than the 4-block kernel (measured:
         * -6 % on Zen 2 with the kernel forced on). Same predicate as gcm_get_funcs.
         */
        ctx->native_polyval = ctx->vaes
            || ((OPENSSL_ia32cap_P[1] & (1 << 1)) /* PCLMULQDQ */
                && ((OPENSSL_ia32cap_P[1] >> 22) & 0x41) != 0x41 /* not (MOVBE && AVX) */);
    } else
#endif
#ifdef VPAES_CAPABLE
        if (VPAES_CAPABLE) {
        set_key = vpaes_set_encrypt_key;
        ctx->block = (block128_f)vpaes_encrypt;
#ifdef GCM_SIV_BSAES
        if (BSAES_CAPABLE) { /* bulk keystream on the bitsliced kernel */
            ctx->ecb = bsaes_ecb_wrap;
            ctx->ecb_key = &ctx->ks_bulk;
            /* bsaes_ecb_encrypt_blocks converts the key only on its >= 8-block
             * path; entered with fewer it uses an unconverted key and crashes
             * (measured), so short runs take the block function */
            ctx->ecb_min_blocks = 8;
        }
#endif
#ifdef GCM_SIV_VPAES_ECB
        ctx->ecb = vpaes_ecb_wrap;
#endif
    } else
#endif
    {
        set_key = AES_set_encrypt_key;
        ctx->block = (block128_f)AES_encrypt;
    }

    if (!scratch_ready(ctx))
        return 0;

    /* RFC 8452 section 4: both keys from AES(key_gen_key) over LE32(counter) || nonce */
    if (set_key(ctx->key_gen_key, (int)(ctx->key_len * 8), &kgk) < 0)
        goto err;
    memset(block_in, 0, BLOCK_SIZE);
    memcpy(block_in + sizeof(counter), ctx->nonce, NONCE_SIZE);

    /* msg_auth_key is always 16 bytes in size, regardless of AES128/AES256 */
    for (i = 0; i < BLOCK_SIZE; i += 8) {
        put_le32(block_in, counter);
        ctx->block(block_in, block_out, &kgk);
        memcpy(&ctx->msg_auth_key[i], block_out, 8);
        counter++;
    }
    /* msg_enc_key length is directly tied to key length AES128/AES256 */
    for (i = 0; i < ctx->key_len; i += 8) {
        put_le32(block_in, counter);
        ctx->block(block_in, block_out, &kgk);
        memcpy(&ctx->msg_enc_key[i], block_out, 8);
        counter++;
    }
    if (set_key(ctx->msg_enc_key, (int)(ctx->key_len * 8), &ctx->ks) < 0)
        goto err;
#ifdef GCM_SIV_BSAES
    if (ctx->ecb_key == &ctx->ks_bulk
        && AES_set_encrypt_key(ctx->msg_enc_key, (int)(ctx->key_len * 8), &ctx->ks_bulk) < 0)
        goto err;
#endif

    /* Freshen up the state */
    ctx->used_enc = 0;
    ctx->used_dec = 0;
    ret = 1;
err:
    OPENSSL_cleanse(&kgk, sizeof(kgk));
    OPENSSL_cleanse(block_out, sizeof(block_out));
    return ret;
}

static int aes_gcm_siv_aad(PROV_AES_GCM_SIV_CTX *ctx,
    const unsigned char *aad, size_t len)
{
    size_t to_alloc;
    uint8_t *ptr;
    uint64_t len64;

    /* length of 0 resets the AAD */
    if (len == 0) {
        OPENSSL_free(ctx->aad);
        ctx->aad = NULL;
        ctx->aad_len = 0;
        return 1;
    }
    to_alloc = UP16(ctx->aad_len + len);
    /* need to check the size of the AAD per RFC8452 */
    len64 = to_alloc;
    if (len64 > ((uint64_t)1 << 36))
        return 0;
    ptr = OPENSSL_realloc(ctx->aad, to_alloc);
    if (ptr == NULL)
        return 0;
    ctx->aad = ptr;
    memcpy(&ctx->aad[ctx->aad_len], aad, len);
    ctx->aad_len += len;
    if (to_alloc > ctx->aad_len)
        memset(&ctx->aad[ctx->aad_len], 0, to_alloc - ctx->aad_len);
    return 1;
}

static int aes_gcm_siv_finish(PROV_AES_GCM_SIV_CTX *ctx)
{
    int ret = 0;

    if (ctx->enc) {
        /*
         * generate the tag on FINAL so an init/final with no update
         * (an empty message) still produces it, matching the other AEADs
         */
        if (ctx->generated_tag == 0
            && aes_gcm_siv_encrypt(ctx, NULL, NULL, 0) == 0)
            return 0;
        return ctx->generated_tag;
    }
    if (ctx->generated_tag == 0
        && aes_gcm_siv_decrypt(ctx, NULL, NULL, 0) == 0)
        return 0;
    ret = CRYPTO_memcmp(ctx->tag, ctx->user_tag, sizeof(ctx->tag)) == 0;
    ret &= ctx->have_user_tag;
    if (ret == 0 && ctx->have_user_tag)
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
    return ret;
}

static int aes_gcm_siv_encrypt(PROV_AES_GCM_SIV_CTX *ctx, const unsigned char *in,
    unsigned char *out, size_t len)
{
    uint64_t len_blk[2];
    uint8_t S_s[TAG_SIZE];
    uint8_t counter_block[TAG_SIZE];
    uint8_t padding[BLOCK_SIZE];
    size_t i;
    int64_t len64 = len;
    int error = 0;
    DECLARE_IS_ENDIAN;

    ctx->generated_tag = 0;
    /* need to check the size of the input! */
    if (len64 > ((int64_t)1 << 36))
        return 0;
    if (!scratch_ready(ctx))
        return 0;

    if (IS_LITTLE_ENDIAN) {
        len_blk[0] = (uint64_t)ctx->aad_len * 8;
        len_blk[1] = (uint64_t)len * 8;
    } else {
        len_blk[0] = GSWAP8((uint64_t)ctx->aad_len * 8);
        len_blk[1] = GSWAP8((uint64_t)len * 8);
    }
    memset(S_s, 0, TAG_SIZE);
    ossl_polyval_ghash_init(ctx->Htable, (const uint64_t *)ctx->msg_auth_key);

    if (ctx->aad != NULL) {
        /* AAD is allocated with padding, but need to adjust length */
        ossl_polyval_ghash_hash(ctx->Htable, S_s, ctx->aad, UP16(ctx->aad_len),
            ctx->scratch, GCM_SIV_SCRATCH, ctx->native_polyval ? ctx->msg_auth_key : NULL);
    }
    if (DOWN16(len) > 0)
        ossl_polyval_ghash_hash(ctx->Htable, S_s, in, DOWN16(len),
            ctx->scratch, GCM_SIV_SCRATCH, ctx->native_polyval ? ctx->msg_auth_key : NULL);
    if (!IS16(len)) {
        /* deal with padding - probably easier to memset the padding first rather than calculate */
        memset(padding, 0, sizeof(padding));
        memcpy(padding, &in[DOWN16(len)], REMAINDER16(len));
        ossl_polyval_ghash_hash(ctx->Htable, S_s, padding, sizeof(padding), NULL, 0, NULL);
    }
    ossl_polyval_ghash_hash(ctx->Htable, S_s, (uint8_t *)len_blk, sizeof(len_blk), NULL, 0, NULL);

    for (i = 0; i < NONCE_SIZE; i++)
        S_s[i] ^= ctx->nonce[i];

    S_s[TAG_SIZE - 1] &= 0x7f;
    ctx->block(S_s, ctx->tag, &ctx->ks);
    memcpy(counter_block, ctx->tag, TAG_SIZE);
    counter_block[TAG_SIZE - 1] |= 0x80;

    error |= !aes_gcm_siv_ctr32(ctx, counter_block, out, in, len);

    ctx->generated_tag = !error;
    /* Regardless of error */
    ctx->used_enc = 1;
    return !error;
}

static int aes_gcm_siv_decrypt(PROV_AES_GCM_SIV_CTX *ctx, const unsigned char *in,
    unsigned char *out, size_t len)
{
    uint8_t counter_block[TAG_SIZE];
    uint64_t len_blk[2];
    uint8_t S_s[TAG_SIZE];
    size_t i;
    uint64_t padding[2];
    int64_t len64 = len;
    int error = 0;
    DECLARE_IS_ENDIAN;

    ctx->generated_tag = 0;
    /* need to check the size of the input! */
    if (len64 > ((int64_t)1 << 36))
        return 0;
    if (!scratch_ready(ctx))
        return 0;

    memcpy(counter_block, ctx->user_tag, sizeof(counter_block));
    counter_block[TAG_SIZE - 1] |= 0x80;

    error |= !aes_gcm_siv_ctr32(ctx, counter_block, out, in, len);

    if (IS_LITTLE_ENDIAN) {
        len_blk[0] = (uint64_t)ctx->aad_len * 8;
        len_blk[1] = (uint64_t)len * 8;
    } else {
        len_blk[0] = GSWAP8((uint64_t)ctx->aad_len * 8);
        len_blk[1] = GSWAP8((uint64_t)len * 8);
    }
    memset(S_s, 0, TAG_SIZE);
    ossl_polyval_ghash_init(ctx->Htable, (const uint64_t *)ctx->msg_auth_key);
    if (ctx->aad != NULL) {
        /* AAD allocated with padding, but need to adjust length */
        ossl_polyval_ghash_hash(ctx->Htable, S_s, ctx->aad, UP16(ctx->aad_len),
            ctx->scratch, GCM_SIV_SCRATCH, ctx->native_polyval ? ctx->msg_auth_key : NULL);
    }
    if (DOWN16(len) > 0)
        ossl_polyval_ghash_hash(ctx->Htable, S_s, out, DOWN16(len),
            ctx->scratch, GCM_SIV_SCRATCH, ctx->native_polyval ? ctx->msg_auth_key : NULL);
    if (!IS16(len)) {
        /* deal with padding - probably easier to "memset" the padding first rather than calculate */
        padding[0] = padding[1] = 0;
        memcpy(padding, &out[DOWN16(len)], REMAINDER16(len));
        ossl_polyval_ghash_hash(ctx->Htable, S_s, (uint8_t *)padding, sizeof(padding), NULL, 0, NULL);
    }
    ossl_polyval_ghash_hash(ctx->Htable, S_s, (uint8_t *)len_blk, TAG_SIZE, NULL, 0, NULL);

    for (i = 0; i < NONCE_SIZE; i++)
        S_s[i] ^= ctx->nonce[i];

    S_s[TAG_SIZE - 1] &= 0x7f;

    /*
     * In the ctx, user_tag is the one received/set by the user,
     * and tag is generated from the input
     */
    ctx->block(S_s, ctx->tag, &ctx->ks);
    ctx->generated_tag = !error;
    /* Regardless of error */
    ctx->used_dec = 1;
    return !error;
}

static int aes_gcm_siv_cipher(void *vctx, unsigned char *out,
    const unsigned char *in, size_t len)
{
    PROV_AES_GCM_SIV_CTX *ctx = (PROV_AES_GCM_SIV_CTX *)vctx;

    /* EncryptFinal or DecryptFinal */
    if (in == NULL)
        return aes_gcm_siv_finish(ctx);

    /*
     * SIV derives the CTR IV from the tag, which depends on the whole plaintext,
     * so the payload cannot be streamed.
     * Payload must arrive in a single update, after which the tag is fixed.
     * Any later AAD or payload update is therefore out of order and errors out.
     * The speed benchmark test is exempt.
     */
    if (!ctx->speed && (ctx->used_enc || ctx->used_dec)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER);
        return 0;
    }

    /* Deal with associated data */
    if (out == NULL)
        return aes_gcm_siv_aad(ctx, in, len);

    if (ctx->enc)
        return aes_gcm_siv_encrypt(ctx, in, out, len);

    return aes_gcm_siv_decrypt(ctx, in, out, len);
}

static void aes_gcm_siv_clean_ctx(void *vctx)
{
    PROV_AES_GCM_SIV_CTX *ctx = (PROV_AES_GCM_SIV_CTX *)vctx;

    OPENSSL_clear_free(ctx->scratch, GCM_SIV_SCRATCH);
    ctx->scratch = NULL;
    OPENSSL_cleanse(&ctx->ks, sizeof(ctx->ks));
    OPENSSL_cleanse(&ctx->ks_bulk, sizeof(ctx->ks_bulk));
}

static int aes_gcm_siv_dup_ctx(void *vdst, void *vsrc)
{
    PROV_AES_GCM_SIV_CTX *dst = (PROV_AES_GCM_SIV_CTX *)vdst;
    const PROV_AES_GCM_SIV_CTX *src = (const PROV_AES_GCM_SIV_CTX *)vsrc;

    /*
     * The key schedules and dispatch pointers were copied with the struct, but
     * ecb_key POINTS INTO the struct (&ks or &ks_bulk of the source): left as
     * copied, the copy would run its bulk kernel on the source's schedule — a
     * dangling pointer once the source is freed or re-keyed. This was latent in
     * v2..v5: test_evp copies a keyed context before every variant and passed
     * only because the source's memory still held the schedule; a four-byte
     * change to the struct (v6) moved the heap layout and it read a zeroed
     * schedule instead. The scratch is re-created on the copy's first use.
     */
    dst->ecb_key = (src->ecb_key == &src->ks_bulk) ? &dst->ks_bulk : &dst->ks;
    dst->scratch = NULL;
    return 1;
}

static const PROV_CIPHER_HW_AES_GCM_SIV aes_gcm_siv_hw = {
    aes_gcm_siv_initkey,
    aes_gcm_siv_cipher,
    aes_gcm_siv_dup_ctx,
    aes_gcm_siv_clean_ctx,
};

const PROV_CIPHER_HW_AES_GCM_SIV *ossl_prov_cipher_hw_aes_gcm_siv(size_t keybits)
{
    return &aes_gcm_siv_hw;
}

/*
 * AES-GCM-SIV needs AES-CTR32 with a LITTLE-endian 32-bit counter in the first
 * four bytes of the block (RFC 8452 section 4), which the AES-CTR kernels
 * (big-endian counter in the last four bytes) cannot provide. On AVX-512/VAES
 * the keystream is made and applied in one pass (ctr32le_vaes). Elsewhere the
 * counter blocks are written into the scratch a run at a time, the platform
 * ECB kernel encrypts them IN PLACE, and the keystream is XORed eight bytes at
 * a time. Measured on Zen 2 / Haswell / Skylake-SP: this exact shape (one
 * buffer, in-place ECB, 8-byte XOR) is 30-40 % faster than a counter template
 * encrypted out of place with a 64-byte XOR, which the compiler turns into
 * stack traffic. Without an ECB kernel the block function is used.
 */
static int aes_gcm_siv_ctr32(PROV_AES_GCM_SIV_CTX *ctx, const unsigned char *init_counter,
    unsigned char *out, const unsigned char *in, size_t len)
{
    uint8_t *ks = ctx->scratch;
    uint32_t counter;
    size_t done = 0, i, j, todo, nblocks;

    if (ctx->scratch == NULL)
        return 0;
    counter = (uint32_t)init_counter[0] | ((uint32_t)init_counter[1] << 8)
        | ((uint32_t)init_counter[2] << 16) | ((uint32_t)init_counter[3] << 24);

#ifdef GCM_SIV_VAES
    if (ctx->vaes && len >= 64) {
        done = ctr32le_vaes(&ctx->ks, (int)(ctx->key_len / 4 + 6), init_counter, out, in, len);
        counter += (uint32_t)(done / BLOCK_SIZE);
        if (done == len)
            return 1;
    }
#endif
#ifdef GCM_SIV_AESNI_CTR
    if (ctx->aesni_ctr && len - done >= 16) {
        uint8_t ctr2[16];

        memcpy(ctr2, init_counter, 16);
        put_le32(ctr2, counter);
        done += ctr32le_aesni(&ctx->ks, (int)(ctx->key_len / 4 + 6), ctr2, out + done, in + done,
            len - done);
        counter = (uint32_t)init_counter[0] | ((uint32_t)init_counter[1] << 8)
            | ((uint32_t)init_counter[2] << 16) | ((uint32_t)init_counter[3] << 24);
        counter += (uint32_t)(done / BLOCK_SIZE);
        if (done == len)
            return 1;
    }
#endif
#ifdef GCM_SIV_ARMV8_CTR
    if (ctx->armv8_ctr && len - done >= 16) {
        uint8_t ctr2[16];

        memcpy(ctr2, init_counter, 16);
        put_le32(ctr2, counter);
        done += ctr32le_armv8(&ctx->ks, (int)(ctx->key_len / 4 + 6), ctr2, out + done, in + done,
            len - done);
        counter = (uint32_t)init_counter[0] | ((uint32_t)init_counter[1] << 8)
            | ((uint32_t)init_counter[2] << 16) | ((uint32_t)init_counter[3] << 24);
        counter += (uint32_t)(done / BLOCK_SIZE);
        if (done == len)
            return 1;
    }
#endif

    while (done < len) {
        todo = len - done;
        if (todo > GCM_SIV_SCRATCH)
            todo = GCM_SIV_SCRATCH;
        nblocks = UP16(todo) / BLOCK_SIZE;
        for (i = 0; i < nblocks; i++) {
            memcpy(ks + i * BLOCK_SIZE, init_counter, BLOCK_SIZE);
            put_le32(ks + i * BLOCK_SIZE, counter);
            counter++;
        }
        if (ctx->ecb != NULL && nblocks >= ctx->ecb_min_blocks) {
            ctx->ecb(ks, ks, nblocks * BLOCK_SIZE, ctx->ecb_key, 1);
        } else {
            for (i = 0; i < nblocks; i++)
                ctx->block(ks + i * BLOCK_SIZE, ks + i * BLOCK_SIZE, &ctx->ks);
        }
        for (j = 0; j + 8 <= todo; j += 8) {
            uint64_t a, b;

            memcpy(&a, in + done + j, 8);
            memcpy(&b, ks + j, 8);
            a ^= b;
            memcpy(out + done + j, &a, 8);
        }
        for (; j < todo; j++)
            out[done + j] = in[done + j] ^ ks[j];
        done += todo;
    }
    return 1;
}
