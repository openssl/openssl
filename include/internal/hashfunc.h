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
    x *= UINT64_C(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x *= UINT64_C(0x94d049bb133111eb);
    x ^= x >> 31;
    return x;
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

#endif
