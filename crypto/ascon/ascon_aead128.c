#include "ascon.h"
#include <string.h>

#define ROR64(x, i) ((x << (64 - i)) | (x >> i))

/**
 * constant addition layer, NIST SP 800-232 Table 5
 * 3c 2d 1e 0f f0 e1 d2 c3 b4 a5 96 87 78 69 5a 4b
 */
#define ASCONPC(x0, x1, x2, x3, x4, rcon) \
    do {                                  \
        x2 ^= rcon;                       \
    } while (0)

/**
 * nonlinear layer, lifted from p43 of
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
 */
#define ASCONPS(x0, x1, x2, x3, x4) \
    do {                            \
        uint64_t q0, q1;            \
        x0 ^= x4;                   \
        x4 ^= x3;                   \
        x2 ^= x1;                   \
        q0 = x0 & (~x4);            \
        q1 = x2 & (~x1);            \
        x0 ^= q1;                   \
        q1 = x4 & (~x3);            \
        x2 ^= q1;                   \
        q1 = x1 & (~x0);            \
        x4 ^= q1;                   \
        q1 = x3 & (~x2);            \
        x1 ^= q1;                   \
        x3 ^= q0;                   \
        x1 ^= x0;                   \
        x3 ^= x2;                   \
        x0 ^= x4;                   \
        x2 = ~x2;                   \
    } while (0)

/* linear layer, NIST SP 800-232 Figure 3 */
#define ASCONPL(x0, x1, x2, x3, x4)          \
    do {                                     \
        x0 ^= ROR64(x0, 19) ^ ROR64(x0, 28); \
        x1 ^= ROR64(x1, 61) ^ ROR64(x1, 39); \
        x2 ^= ROR64(x2, 1) ^ ROR64(x2, 6);   \
        x3 ^= ROR64(x3, 10) ^ ROR64(x3, 17); \
        x4 ^= ROR64(x4, 7) ^ ROR64(x4, 41);  \
    } while (0)

/* one round */
#define ASCONP1(x0, x1, x2, x3, x4, rcon)  \
    do {                                   \
        ASCONPC(x0, x1, x2, x3, x4, rcon); \
        ASCONPS(x0, x1, x2, x3, x4);       \
        ASCONPL(x0, x1, x2, x3, x4);       \
    } while (0)

/* 8 rounds */
#define ASCONP8(x0, x1, x2, x3, x4)           \
    do {                                      \
        ASCONP1(x0, x1, x2, x3, x4, 0xB4ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0xA5ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0x96ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0x87ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0x78ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0x69ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0x5AULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0x4BULL); \
    } while (0)

/* 12 rounds */
#define ASCONP12(x0, x1, x2, x3, x4)          \
    do {                                      \
        ASCONP1(x0, x1, x2, x3, x4, 0xF0ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0xE1ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0xD2ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0xC3ULL); \
        ASCONP8(x0, x1, x2, x3, x4);          \
    } while (0)

/* misc ascon flags for the context */
#define ASCONFLG_AAD 0x0000000000000001ULL /* has AAD inputs? */
#define ASCONFLG_DEC 0x0000000000000002ULL /* in decrypt mode? */
#define ASCONFLG_DOMAINSEP 0x8000000000000000ULL /* ready to absorb non-AAD? */

/* semi-portable inline declaration */
#ifdef OPENSSL_BUILDING_OPENSSL
#define ASCON_INLINE ossl_inline /* use the openssl one if we can */
#elif defined(__OPTIMIZE__)
#if defined(_MSC_VER) && !defined(__INTEL_COMPILER)
#define ASCON_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__) || defined(__INTEL_COMPILER) || defined(__ICC)
#define ASCON_INLINE __attribute__((always_inline)) inline
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define ASCON_INLINE inline /* C99? */
#else
#define ASCON_INLINE
#endif
#else
#define ASCON_INLINE
#endif

/* omit test harness if this is openssl-internal */
#ifndef OPENSSL_BUILDING_OPENSSL
#include <stdio.h>

void ascon_test_state()
{
    uint64_t s0 = 0, s1 = 0, s2 = 0, s3 = 0, s4 = 0;
    s4 = 0x0000080100CC0002ULL;
    ASCONP12(s0, s1, s2, s3, s4);
    printf("%lx%lx%lx%lx%lx\n", s0, s1, s2, s3, s4);
}

#endif

static ASCON_INLINE void ascon_aead128_update(ascon_aead128_ctx* ctx, unsigned char* out, const unsigned char* in, size_t len)
{
    uint64_t s0, s1, s2, s3, s4, flags;
    unsigned char pad = 0x01;

    if (ctx->flags & ASCONFLG_DOMAINSEP) {
        flags = ctx->flags;
        if (flags & ASCONFLG_AAD) {
            ctx->flags = 0;
            ascon_aead128_update(ctx, NULL, &pad, 1);
            ASCONP8(ctx->state[0], ctx->state[1], ctx->state[2], ctx->state[3], ctx->state[4]);
            flags ^= ASCONFLG_AAD;
            ctx->offset = 0;
        }
        ctx->state[4] ^= ASCONFLG_DOMAINSEP;
        flags ^= ASCONFLG_DOMAINSEP;
        ctx->flags = flags;
    }

    s0 = ctx->state[0];
    s1 = ctx->state[1];
    s2 = ctx->state[2];
    s3 = ctx->state[3];
    s4 = ctx->state[4];

    while (len--) {
        unsigned char ob, ib = *in++;
        if (ctx->offset >= 16) {
            ASCONP8(s0, s1, s2, s3, s4);
            ctx->offset = 0;
        }

        if (ctx->flags & ASCONFLG_DEC) {
            if (ctx->offset >= 8) {
                ob = (unsigned char)(s1 >> 8 * (ctx->offset & 0x7)) ^ ib;
                s1 ^= (uint64_t)(ob) << 8 * (ctx->offset & 0x7);
            } else {
                ob = (unsigned char)(s0 >> 8 * ctx->offset) ^ ib;
                s0 ^= (uint64_t)(ob) << 8 * ctx->offset;
            }
        } else {
            if (ctx->offset >= 8) {
                s1 ^= (uint64_t)(ib) << 8 * (ctx->offset & 0x7);
                ob = (unsigned char)(s1 >> 8 * (ctx->offset & 0x7));
            } else {
                s0 ^= (uint64_t)(ib) << 8 * ctx->offset;
                ob = (unsigned char)(s0 >> 8 * ctx->offset);
            }
        }

        if (out != NULL)
            *out++ = ob;

        ctx->offset++;
    }

    ctx->state[0] = s0;
    ctx->state[1] = s1;
    ctx->state[2] = s2;
    ctx->state[3] = s3;
    ctx->state[4] = s4;
}

size_t ascon_aead128_encrypt_update(ascon_aead128_ctx* ctx, unsigned char* ct, const unsigned char* pt, size_t len)
{
    ascon_aead128_update(ctx, ct, pt, len);
    return len;
}

size_t ascon_aead128_decrypt_update(ascon_aead128_ctx* ctx, unsigned char* pt, const unsigned char* ct, size_t len)
{
    ctx->flags |= ASCONFLG_DEC;
    ascon_aead128_update(ctx, pt, ct, len);
    return len;
}

size_t ascon_aead128_init(ascon_aead128_ctx* ctx, const unsigned char* k, const unsigned char* n)
{
    uint64_t s0, s1, s2, s3, s4, k0, k1;

    memcpy(&s1, k, 8);
    memcpy(&s2, k + 8, 8);
    memcpy(&s3, n, 8);
    memcpy(&s4, n + 8, 8);
    ctx->key[0] = k0 = s1;
    ctx->key[1] = k1 = s2;
    s0 = 0x00001000808C0001ULL;
    ASCONP12(s0, s1, s2, s3, s4);
    s3 ^= k0;
    s4 ^= k1;
    ctx->state[0] = s0;
    ctx->state[1] = s1;
    ctx->state[2] = s2;
    ctx->state[3] = s3;
    ctx->state[4] = s4;
    ctx->offset = 0;
    ctx->flags = ASCONFLG_DOMAINSEP;
    return 0;
}

size_t ascon_aead128_aad_update(ascon_aead128_ctx* ctx, const unsigned char* in, size_t len)
{
    uint64_t flags;
    size_t orig_len = len;

    flags = ctx->flags;
    ctx->flags = 0;
    if (len > 0)
        flags |= ASCONFLG_AAD;
    while (len--) {
        unsigned char ib = *in++;
        ascon_aead128_update(ctx, NULL, &ib, 1);
    }
    ctx->flags = flags;
    return orig_len;
}

size_t ascon_aead128_encrypt_final(ascon_aead128_ctx* ctx, unsigned char* tag)
{
    uint64_t s0, s1, s2, s3, s4, k0, k1;
    unsigned char pad = 0x01;

    ascon_aead128_update(ctx, NULL, NULL, 0);
    ctx->flags = 0;
    ascon_aead128_update(ctx, NULL, &pad, 1);

    k0 = ctx->key[0];
    k1 = ctx->key[1];
    s0 = ctx->state[0];
    s1 = ctx->state[1];
    s2 = ctx->state[2] ^ k0;
    s3 = ctx->state[3] ^ k1;
    s4 = ctx->state[4];
    ASCONP12(s0, s1, s2, s3, s4);
    s3 ^= k0;
    s4 ^= k1;
    memcpy(tag, &s3, 8);
    memcpy(tag + 8, &s4, 8);
    return 16;
}

size_t ascon_aead128_decrypt_final(ascon_aead128_ctx* ctx, unsigned char* out, int* is_valid, const unsigned char* expected_tag, size_t expected_tag_len)
{
    unsigned char computed_tag[16];
    size_t i;
    unsigned char diff = 0;

    /* Generate the tag (same as encrypt_final) */
    ascon_aead128_encrypt_final(ctx, computed_tag);

    if (expected_tag_len != 16) {
        *is_valid = 0;
        return 0;
    }

    for (i = 0; i < 16; i++) {
        diff |= computed_tag[i] ^ expected_tag[i];
    }

    *is_valid = (diff == 0) ? 1 : 0;

    (void)out;

    return 0;
}