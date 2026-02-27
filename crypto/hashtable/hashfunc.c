/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 */

#include "internal/hashfunc.h"

ossl_unused uint64_t ossl_fnv1a_hash(uint8_t *key, size_t len)
{
    uint64_t hash = 0xcbf29ce484222325ULL;
    size_t i;

    for (i = 0; i < len; i++) {
        hash ^= key[i];
        hash *= 0x00000100000001B3ULL;
    }
    return hash;
}

uint64_t ossl_murmur2_64(uint8_t *key, size_t len)
{
    const uint64_t m = 0xc6a4a7935bd1e995ULL;
    uint64_t *key64 = (uint64_t *)key;
    uint64_t hash;
    size_t i;

    hash = 0 ^ (len * m);
    for (i = 0; i < len / 8; i++) {
        uint64_t k;

        k = key64[i] * m;
        k = k ^ (k >> 47);
        k = k * m;
        hash = hash ^ k;
        hash = hash * m;
    }

    key = (uint8_t *)&key64[i];
    switch (len & 7) {
    case 7:
        hash = hash ^ (uint64_t)key[6] << 48;
        /* FALLTHRU */
    case 6:
        hash = hash ^ (uint64_t)key[5] << 40;
        /* FALLTHRU */
    case 5:
        hash = hash ^ (uint64_t)key[4] << 32;
        /* FALLTHRU */
    case 4:
        hash = hash ^ (uint64_t)key[3] << 24;
        /* FALLTHRU */
    case 3:
        hash = hash ^ (uint64_t)key[2] << 16;
        /* FALLTHRU */
    case 2:
        hash = hash ^ (uint64_t)key[1] << 8;
        /* FALLTHRU */
    case 1:
        hash = hash ^ (uint64_t)key[0];
        hash = hash * m;
        /* FALLTHRU */
    }

    hash = hash ^ (hash >> 47);
    hash = hash * m;
    hash = hash ^ (hash >> 47);

    return hash;
}
