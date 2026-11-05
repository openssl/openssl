/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HASHFUNC_H
#define OPENSSL_HASHFUNC_H

#include <openssl/e_os2.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

/**
 * Generalized fnv1a 64 bit hash function
 */
ossl_unused uint64_t ossl_fnv1a_hash(uint8_t *key, size_t len);

/*
 * Mix a 64-bit value so that every bit of the result depends on every bit
 * of the input (the splitmix64 finaliser). An LHASH bucket is the hash
 * modulo a power of two, so a hash that is a raw integer or pointer must be
 * mixed first: a pointer's low bits are its allocation alignment, and
 * objects of one size from the allocator sit at a fixed stride, so without
 * mixing they share a handful of buckets and the chains grow with the
 * number of objects. Likewise an integer whose low bits are a type tag.
 */
static ossl_unused ossl_inline uint64_t ossl_hash_mix64(uint64_t x)
{
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

/* A pointer's identity, mixed, as a 64-bit hash value. */
static ossl_unused ossl_inline uint64_t ossl_hash_ptr(const void *p)
{
    return ossl_hash_mix64((uint64_t)(uintptr_t)p);
}

/* A 64-bit value, mixed, as an LHASH hash value. */
static ossl_unused ossl_inline unsigned long ossl_lh_hash_u64(uint64_t x)
{
    x = ossl_hash_mix64(x);
#if ULONG_MAX > 0xFFFFFFFFUL
    return (unsigned long)x;
#else
    return (unsigned long)(x ^ (x >> 32));
#endif
}

/* A pointer's identity, mixed, as an LHASH hash value. */
static ossl_unused ossl_inline unsigned long ossl_lh_hash_ptr(const void *p)
{
    return ossl_lh_hash_u64((uint64_t)(uintptr_t)p);
}

/*
 * One-shot SipHash-2-4 with a 64-bit result under the 128-bit key |k|, the
 * same function as SipHash_Init(ctx, k, 0, 0) with an 8-byte hash size. It
 * is the keyed hash for tables whose keys an attacker chooses. Unlike
 * crypto/siphash it is inline, keeps no context, and is available to libssl
 * and the FIPS module, neither of which links crypto/siphash/siphash.c.
 */
#define OSSL_SIPHASH24_KEY_SIZE 16
#define OSSL_SIPHASH24_C_ROUNDS 2
#define OSSL_SIPHASH24_D_ROUNDS 4

#define OSSL_SIPHASH24_ROTL_(x, b) (((x) << (b)) | ((x) >> (64 - (b))))
#define OSSL_SIPHASH24_ROUND_(v0, v1, v2, v3) \
    do {                                      \
        v0 += v1;                             \
        v1 = OSSL_SIPHASH24_ROTL_(v1, 13);    \
        v1 ^= v0;                             \
        v0 = OSSL_SIPHASH24_ROTL_(v0, 32);    \
        v2 += v3;                             \
        v3 = OSSL_SIPHASH24_ROTL_(v3, 16);    \
        v3 ^= v2;                             \
        v0 += v3;                             \
        v3 = OSSL_SIPHASH24_ROTL_(v3, 21);    \
        v3 ^= v0;                             \
        v2 += v1;                             \
        v1 = OSSL_SIPHASH24_ROTL_(v1, 17);    \
        v1 ^= v2;                             \
        v2 = OSSL_SIPHASH24_ROTL_(v2, 32);    \
    } while (0)

static ossl_unused ossl_inline uint64_t
ossl_siphash24_u8to64_le(const unsigned char *p)
{
    return (uint64_t)p[0] | (uint64_t)p[1] << 8 | (uint64_t)p[2] << 16
        | (uint64_t)p[3] << 24 | (uint64_t)p[4] << 32 | (uint64_t)p[5] << 40
        | (uint64_t)p[6] << 48 | (uint64_t)p[7] << 56;
}

static ossl_unused ossl_inline uint64_t
ossl_siphash24_u64(const unsigned char k[OSSL_SIPHASH24_KEY_SIZE],
    const void *data, size_t len)
{
    const unsigned char *in = data;
    const unsigned char *end = in + (len & ~(size_t)7);
    uint64_t k0 = ossl_siphash24_u8to64_le(k);
    uint64_t k1 = ossl_siphash24_u8to64_le(k + 8);
    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;
    uint64_t b = (uint64_t)len << 56, m;
    size_t i;

    for (; in != end; in += 8) {
        m = ossl_siphash24_u8to64_le(in);
        v3 ^= m;
        for (i = 0; i < OSSL_SIPHASH24_C_ROUNDS; i++)
            OSSL_SIPHASH24_ROUND_(v0, v1, v2, v3);
        v0 ^= m;
    }
    for (i = 0; i < (len & 7); i++)
        b |= (uint64_t)in[i] << (8 * i);
    v3 ^= b;
    for (i = 0; i < OSSL_SIPHASH24_C_ROUNDS; i++)
        OSSL_SIPHASH24_ROUND_(v0, v1, v2, v3);
    v0 ^= b;
    v2 ^= 0xff;
    for (i = 0; i < OSSL_SIPHASH24_D_ROUNDS; i++)
        OSSL_SIPHASH24_ROUND_(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

#endif
