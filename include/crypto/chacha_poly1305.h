/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_CHACHA_POLY1305_H
#define OSSL_CRYPTO_CHACHA_POLY1305_H
#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * Fused ChaCha20-Poly1305 for GCC/clang on x86_64.  ChaCha20 and Poly1305
 * run in one loop.  The kernel needs __uint128_t and function target
 * attributes.
 */
#if (defined(__x86_64) || defined(__x86_64__))   \
    && (defined(__GNUC__) || defined(__clang__)) \
    && !defined(OPENSSL_NO_ASM)
#define CHACHA20_POLY1305_AVX512_CAPABLE
#endif

#ifdef CHACHA20_POLY1305_AVX512_CAPABLE

/*
 * Streaming state.  The 8-lane accumulator is folded back into h at the end of
 * every cipher call, so nothing here is a vector type and the struct can be
 * embedded anywhere without alignment constraints.
 */
typedef struct {
    uint64_t h[3]; /* accumulator, radix 2^44        */
    uint64_t r0, r1, r2, s1, s2; /* clamped key, s = 20*r          */
    uint64_t nonce0, nonce1;
    uint64_t pw[3][8]; /* r^8..r^1, one power per lane   */
    unsigned int key[8];
    unsigned int counter[4];
    uint32_t ctr; /* next ChaCha20 block counter    */
    uint64_t textlen; /* payload bytes accepted so far  */
    unsigned int ksoff; /* start of live parked bytes     */
    unsigned int kslen; /* end of live parked bytes       */
    unsigned int ksinit; /* init park not yet claimed      */
    unsigned char block[16]; /* partial Poly1305 block         */
    unsigned int blocklen;
    int powers; /* r^n table has been built       */
    unsigned int calls; /* cipher calls finished so far   */
    unsigned int ahead; /* 1: ks[0..1024) is prefetched
                         * and ctr is already past it    */
    unsigned char ks[16 * 64]; /* parked keystream, [ksoff, kslen) */
} OSSL_CP_AVX512_CTX;

/*
 * Payload uses ChaCha counters 1..2^32-1.  Block 0 is the one-time
 * Poly1305 key.  A longer message would wrap that counter and reuse
 * block 0 as keystream.
 */
#define OSSL_CP_AVX512_MAX_TEXT ((((uint64_t)1) << 32) - 1) * 64

/* Returns 1 when the running CPU can execute the fused kernel. */
int ossl_chacha20_poly1305_avx512_available(void);

/*
 * Streaming interface.  counter[1..3] is the nonce.  The kernel ignores
 * counter[0].  Block 0 is the one-time Poly1305 key; the payload starts
 * at block 1.
 *
 * hint is the payload length, or 0 if it is not known yet.  It only
 * selects the park.
 *
 * Call init, then aad, then aad_done, then cipher, then final.  final does
 * not compare the tag; the caller does.  final wipes the context.
 *
 * cipher returns 0 when this update would pass OSSL_CP_AVX512_MAX_TEXT and
 * leaves the context unchanged.  len 0 returns 1.
 */
void ossl_chacha20_poly1305_avx512_init(OSSL_CP_AVX512_CTX *ctx,
    const unsigned int key[8],
    const unsigned int counter[4],
    size_t hint);
void ossl_chacha20_poly1305_avx512_aad(OSSL_CP_AVX512_CTX *ctx,
    const unsigned char *aad, size_t len);
void ossl_chacha20_poly1305_avx512_aad_done(OSSL_CP_AVX512_CTX *ctx);
int ossl_chacha20_poly1305_avx512_cipher(OSSL_CP_AVX512_CTX *ctx,
    unsigned char *out,
    const unsigned char *in, size_t len,
    int enc);
void ossl_chacha20_poly1305_avx512_final(OSSL_CP_AVX512_CTX *ctx,
    unsigned char tag[16],
    uint64_t aad_len, uint64_t text_len);

/* One-shot wrapper used by TLS records and the tests. */
int ossl_chacha20_poly1305_avx512(unsigned char *out, const unsigned char *in,
    size_t len, const unsigned char *aad,
    size_t aad_len, const unsigned int key[8],
    const unsigned int counter[4],
    unsigned char tag[16], int enc);

#endif /* CHACHA20_POLY1305_AVX512_CAPABLE */

#endif /* OSSL_CRYPTO_CHACHA_POLY1305_H */
