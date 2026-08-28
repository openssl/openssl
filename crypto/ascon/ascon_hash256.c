/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ascon.h"
#include <string.h>
#ifdef OPENSSL_BUILDING_OPENSSL
# include "internal/cryptlib.h"
# include "internal/endian.h"
#endif

#if defined(B_ENDIAN) || defined(__BIG_ENDIAN__) || defined(_BIG_ENDIAN) || defined(__MIPSEB__)
/* BE */
# define GETU64(v, p)                         \
    do {                                     \
        (v) = ((uint64_t)*((p) + 0));        \
        (v) |= ((uint64_t)*((p) + 1) << 8);  \
        (v) |= ((uint64_t)*((p) + 2) << 16); \
        (v) |= ((uint64_t)*((p) + 3) << 24); \
        (v) |= ((uint64_t)*((p) + 4) << 32); \
        (v) |= ((uint64_t)*((p) + 5) << 40); \
        (v) |= ((uint64_t)*((p) + 6) << 48); \
        (v) |= ((uint64_t)*((p) + 7) << 56); \
    } while (0)

# define PUTU64(p, v)                             \
    do {                                         \
        *((p) + 0) = (unsigned char)(v);         \
        *((p) + 1) = (unsigned char)((v) >> 8);  \
        *((p) + 2) = (unsigned char)((v) >> 16); \
        *((p) + 3) = (unsigned char)((v) >> 24); \
        *((p) + 4) = (unsigned char)((v) >> 32); \
        *((p) + 5) = (unsigned char)((v) >> 40); \
        *((p) + 6) = (unsigned char)((v) >> 48); \
        *((p) + 7) = (unsigned char)((v) >> 56); \
    } while (0)

#else
/* LE */
# define GETU64(v, p)          \
    do {                      \
        memcpy(&(v), (p), 8); \
    } while (0)

# define PUTU64(p, v)          \
    do {                      \
        uint64_t _q0 = (v);    \
                                \
        memcpy((p), &_q0, 8); \
    } while (0)

#endif

/* semi-portable inline declaration */
#ifdef OPENSSL_BUILDING_OPENSSL
# define ASCON_INLINE ossl_inline /* use the openssl one if we can */
#elif defined(__OPTIMIZE__)
# if defined(_MSC_VER) && !defined(__INTEL_COMPILER)
#  define ASCON_INLINE __forceinline
# elif defined(__GNUC__) || defined(__clang__) || defined(__INTEL_COMPILER) || defined(__ICC)
#  define ASCON_INLINE __attribute__((always_inline)) inline
# elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#  define ASCON_INLINE inline /* C99? */
# else
#  define ASCON_INLINE
# endif
#else
# define ASCON_INLINE
#endif

#define ROR64(x, i) (((x) << (64 - (i))) | ((x) >> (i)))

/**
 * constant addition layer, NIST SP 800-232 Table 5
 * 3c 2d 1e 0f f0 e1 d2 c3 b4 a5 96 87 78 69 5a 4b
 */
#define ASCONPC(x0, x1, x2, x3, x4, rcon) \
    do {                                  \
        x2 ^= (rcon);                     \
    } while (0)

/**
 * nonlinear layer, lifted from p43 of
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/
 * documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
 */
#define ASCONPS(x0, x1, x2, x3, x4) \
    do {                            \
        uint64_t _q0, _q1;          \
        x0 ^= x4;                   \
        x4 ^= x3;                   \
        x2 ^= x1;                   \
        _q0 = x0 & (~(x4));         \
        _q1 = x2 & (~(x1));         \
        x0 ^= _q1;                  \
        _q1 = x4 & (~(x3));         \
        x2 ^= _q1;                  \
        _q1 = x1 & (~(x0));         \
        x4 ^= _q1;                  \
        _q1 = x3 & (~(x2));         \
        x1 ^= _q1;                  \
        x3 ^= _q0;                  \
        x1 ^= x0;                   \
        x3 ^= x2;                   \
        x0 ^= x4;                   \
        x2 = ~(x2);                 \
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
#define ASCONFLG_XOF 0x0000000000000004ULL /* XOF needs termination? */

void ascon_hash256_init(ascon_hash256_ctx *ctx)
{
    /* precomputed state lifted from NIST SP 800-232 Sec. A.3 p39 */
    ctx->state[0] = 0X9B1E5494E934D681ULL;
    ctx->state[1] = 0X4BC3A01E333751D2ULL;
    ctx->state[2] = 0XAE65396C6B34B81AULL;
    ctx->state[3] = 0X3C7FD4A4D56A4DB3ULL;
    ctx->state[4] = 0X1A5C464906C5976DULL;
    ctx->offset = 0;
}

void ascon_hash256_update(ascon_hash256_ctx *ctx, const unsigned char *m,
                          size_t len)
{
    while (len--) {
        if (ctx->offset >= 8) {
            /* sponge: compression function */
            ASCONP12(ctx->state[0], ctx->state[1], ctx->state[2], ctx->state[3],
                     ctx->state[4]);
            ctx->offset = 0;
        }
        /* sponge: absorb a message byte */
        ctx->state[0] ^= (uint64_t)(*m++) << 8 * ctx->offset++;
    }
}

void ascon_hash256_final(ascon_hash256_ctx *ctx, unsigned char *digest)
{
    uint64_t s0, s1, s2, s3, s4;
    unsigned char pad = 0x01;

    /* message termination */
    ascon_hash256_update(ctx, &pad, 1);

    s0 = ctx->state[0];
    s1 = ctx->state[1];
    s2 = ctx->state[2];
    s3 = ctx->state[3];
    s4 = ctx->state[4];

    /* sponge: squeeze out four words for the hash */
    ASCONP12(s0, s1, s2, s3, s4);
    PUTU64(digest, s0);
    ASCONP12(s0, s1, s2, s3, s4);
    PUTU64(digest + 8, s0);
    ASCONP12(s0, s1, s2, s3, s4);
    PUTU64(digest + 16, s0);
    ASCONP12(s0, s1, s2, s3, s4);
    PUTU64(digest + 24, s0);
}

#ifdef OPENSSL_BUILDING_OPENSSL
/* Provider compatibility wrapper functions */
void ossl_ascon_hash256_init(ascon_hash256_ctx *ctx)
{
    ascon_hash256_init(ctx);
}

void ossl_ascon_hash256_update(ascon_hash256_ctx *ctx, const unsigned char *m,
                                size_t len)
{
    ascon_hash256_update(ctx, m, len);
}

void ossl_ascon_hash256_final(ascon_hash256_ctx *ctx, unsigned char *digest)
{
    ascon_hash256_final(ctx, digest);
}

void ossl_ascon_hash256_cleanup(ascon_hash256_ctx *ctx)
{
    if (ctx != NULL)
        OPENSSL_cleanse(ctx, sizeof(ascon_hash256_ctx));
}
#endif

/* XOF (eXtendable Output Function) implementation */

void ascon_xof128_init(ascon_xof128_ctx *ctx)
{
    /* precomputed state lifted from NIST SP 800-232 Tbl 12 p40 */
    ctx->state[0] = 0xDA82CE768D9447EBULL;
    ctx->state[1] = 0xCC7CE6C75F1EF969ULL;
    ctx->state[2] = 0xE7508FD780085631ULL;
    ctx->state[3] = 0x0EE0EA53416B58CCULL;
    ctx->state[4] = 0xE0547524DB6F0BDEULL;
    ctx->offset = 0;
    ctx->flags = ASCONFLG_XOF;
}

void ascon_xof128_update(ascon_xof128_ctx *ctx, const unsigned char *m,
                         size_t len)
{
    while (len--) {
        if (ctx->offset >= 8) {
            /* sponge: compression function */
            ASCONP12(ctx->state[0], ctx->state[1], ctx->state[2],
                     ctx->state[3], ctx->state[4]);
            ctx->offset = 0;
        }
        /* sponge: absorb a message byte */
        ctx->state[0] ^= (uint64_t)(*m++) << 8 * ctx->offset++;
    }
}

void ascon_xof128_final(ascon_xof128_ctx *ctx, unsigned char *out, size_t len)
{
    if (ctx->flags & ASCONFLG_XOF) {
        /* message termination */
        unsigned char pad = 0x01;
        ascon_xof128_update(ctx, &pad, 1);
        ASCONP12(ctx->state[0], ctx->state[1], ctx->state[2], ctx->state[3],
                 ctx->state[4]);
        ctx->offset = 0;
        ctx->flags ^= ASCONFLG_XOF;
    }

    while (len--) {
        if (ctx->offset >= 8) {
            /* sponge: squeeze out a new word */
            ASCONP12(ctx->state[0], ctx->state[1], ctx->state[2], ctx->state[3],
                     ctx->state[4]);
            ctx->offset = 0;
        }
        *out++ = (unsigned char)(ctx->state[0] >> 8 * ctx->offset++);
    }
}

/* CXOF (Customizable eXtendable Output Function) implementation */

void ascon_cxof128_init(ascon_cxof128_ctx *ctx, const unsigned char *in,
                        size_t len)
{
    unsigned char pad = 0x01;

    /* precomputed state lifted from NIST SP 800-232 Tbl 12 p40 */
    ctx->state[0] = 0x675527C2A0E8DE03ULL;
    ctx->state[1] = 0x43D12D7DC0377BBCULL;
    ctx->state[2] = 0xE9901DEC426E81B5ULL;
    ctx->state[3] = 0x2AB14907720780B6ULL;
    ctx->state[4] = 0x8F3F1D02D432BC46ULL;
    ctx->flags = ASCONFLG_XOF;

    /* customization string has maxlen 256 bytes and the input here is bitlen */
    ctx->state[0] ^= (uint64_t)(len << 3);
    /* skip ahead, it's the bitlen of the customization string as a U64 */
    ctx->offset = 8;

    /* absorb the customization string */
    ascon_cxof128_update(ctx, in, len);

    /* terminate the customization string */
    ascon_cxof128_update(ctx, &pad, 1);

    /* compress all that */
    ASCONP12(ctx->state[0], ctx->state[1], ctx->state[2], ctx->state[3],
             ctx->state[4]);
    ctx->offset = 0;
}

void ascon_cxof128_update(ascon_cxof128_ctx *ctx, const unsigned char *m,
                           size_t len)
{
    while (len--) {
        if (ctx->offset >= 8) {
            /* sponge: compression function */
            ASCONP12(ctx->state[0], ctx->state[1], ctx->state[2],
                     ctx->state[3], ctx->state[4]);
            ctx->offset = 0;
        }
        /* sponge: absorb a message byte */
        ctx->state[0] ^= (uint64_t)(*m++) << 8 * ctx->offset++;
    }
}

void ascon_cxof128_final(ascon_cxof128_ctx *ctx, unsigned char *out, size_t len)
{
    if (ctx->flags & ASCONFLG_XOF) {
        /* message termination */
        unsigned char pad = 0x01;
        ascon_cxof128_update(ctx, &pad, 1);
        ASCONP12(ctx->state[0], ctx->state[1], ctx->state[2], ctx->state[3],
                 ctx->state[4]);
        ctx->offset = 0;
        ctx->flags ^= ASCONFLG_XOF;
    }

    while (len--) {
        if (ctx->offset >= 8) {
            /* sponge: squeeze out a new word */
            ASCONP12(ctx->state[0], ctx->state[1], ctx->state[2], ctx->state[3],
                     ctx->state[4]);
            ctx->offset = 0;
        }
        *out++ = (unsigned char)(ctx->state[0] >> 8 * ctx->offset++);
    }
}

#ifdef OPENSSL_BUILDING_OPENSSL
/* Provider compatibility wrapper functions for XOF/CXOF */
void ossl_ascon_xof128_init(ascon_xof128_ctx *ctx)
{
    ascon_xof128_init(ctx);
}

void ossl_ascon_xof128_update(ascon_xof128_ctx *ctx, const unsigned char *m,
                               size_t len)
{
    ascon_xof128_update(ctx, m, len);
}

void ossl_ascon_xof128_final(ascon_xof128_ctx *ctx, unsigned char *out,
                              size_t len)
{
    ascon_xof128_final(ctx, out, len);
}

void ossl_ascon_xof128_cleanup(ascon_xof128_ctx *ctx)
{
    if (ctx != NULL)
        OPENSSL_cleanse(ctx, sizeof(ascon_xof128_ctx));
}

void ossl_ascon_cxof128_init(ascon_cxof128_ctx *ctx, const unsigned char *in,
                              size_t len)
{
    ascon_cxof128_init(ctx, in, len);
}

void ossl_ascon_cxof128_update(ascon_cxof128_ctx *ctx, const unsigned char *m,
                                size_t len)
{
    ascon_cxof128_update(ctx, m, len);
}

void ossl_ascon_cxof128_final(ascon_cxof128_ctx *ctx, unsigned char *out,
                               size_t len)
{
    ascon_cxof128_final(ctx, out, len);
}

void ossl_ascon_cxof128_cleanup(ascon_cxof128_ctx *ctx)
{
    if (ctx != NULL)
        OPENSSL_cleanse(ctx, sizeof(ascon_cxof128_ctx));
}
#endif

