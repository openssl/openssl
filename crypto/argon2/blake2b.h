/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of the Apache Public License 2.0.
 * The terms of this licenses can be found at:
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of the license along with this
 * software. If not, it may be obtained at the above URL.
 */

#ifndef __BLAKE2B_H
# define __BLAKE2B_H

# include <stdio.h>
# include <stdlib.h>
# include <string.h>

# include "core.h"

# include <openssl/evp.h>
# include <openssl/objects.h>
# include <openssl/crypto.h>
# include <prov/blake2.h>

static ossl_inline uint32_t load32(const uint8_t *src)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };

    if (is_endian.little) {
        uint32_t w;
        memcpy(&w, src, sizeof(w));
        return w;
    } else {
        uint32_t w = ((uint32_t)src[0])
                   | ((uint32_t)src[1] <<  8)
                   | ((uint32_t)src[2] << 16)
                   | ((uint32_t)src[3] << 24);
        return w;
    }
}

static ossl_inline uint64_t load64(const uint8_t *src)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };

    if (is_endian.little) {
        uint64_t w;
        memcpy(&w, src, sizeof(w));
        return w;
    } else {
        uint64_t w = ((uint64_t)src[0])
                   | ((uint64_t)src[1] <<  8)
                   | ((uint64_t)src[2] << 16)
                   | ((uint64_t)src[3] << 24)
                   | ((uint64_t)src[4] << 32)
                   | ((uint64_t)src[5] << 40)
                   | ((uint64_t)src[6] << 48)
                   | ((uint64_t)src[7] << 56);
        return w;
    }
}

static ossl_inline void store32(uint8_t *dst, uint32_t w)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };

    if (is_endian.little) {
        memcpy(dst, &w, sizeof(w));
    } else {
        uint8_t *p = (uint8_t *)dst;
        int i;

        for (i = 0; i < 4; i++)
            p[i] = (uint8_t)(w >> (8 * i));
    }
}

static ossl_inline void store64(uint8_t *dst, uint64_t w)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };

    if (is_endian.little) {
        memcpy(dst, &w, sizeof(w));
    } else {
        uint8_t *p = (uint8_t *)dst;
        int i;

        for (i = 0; i < 8; i++)
            p[i] = (uint8_t)(w >> (8 * i));
    }
}

static ossl_inline uint64_t load48(const uint8_t *src)
{
    uint64_t w = ((uint64_t)src[0])
               | ((uint64_t)src[1] <<  8)
               | ((uint64_t)src[2] << 16)
               | ((uint64_t)src[3] << 24)
               | ((uint64_t)src[4] << 32)
               | ((uint64_t)src[5] << 40);
    return w;
}

static ossl_inline void store48(uint8_t *dst, uint64_t w)
{
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)w;
    p[1] = (uint8_t)(w>>8);
    p[2] = (uint8_t)(w>>16);
    p[3] = (uint8_t)(w>>24);
    p[4] = (uint8_t)(w>>32);
    p[5] = (uint8_t)(w>>40);
}

static ossl_inline uint32_t rotr32(const uint32_t w, const unsigned int c)
{
    return (w >> c) | (w << (32 - c));
}

static ossl_inline uint64_t rotr64(const uint64_t w, const unsigned int c)
{
    return (w >> c) | (w << (64 - c));
}

/* designed by the Lyra PHC team */
static ossl_inline uint64_t fBlaMka(uint64_t x, uint64_t y) {
    const uint64_t m = UINT64_C(0xFFFFFFFF);
    const uint64_t xy = (x & m) * (y & m);
    return x + y + 2 * xy;
}

# ifndef G
#  define G(a, b, c, d)                                                        \
    do {                                                                       \
        a = fBlaMka(a, b);                                                     \
        d = rotr64(d ^ a, 32);                                                 \
        c = fBlaMka(c, d);                                                     \
        b = rotr64(b ^ c, 24);                                                 \
        a = fBlaMka(a, b);                                                     \
        d = rotr64(d ^ a, 16);                                                 \
        c = fBlaMka(c, d);                                                     \
        b = rotr64(b ^ c, 63);                                                 \
    } while ((void)0, 0)
# endif

# ifndef BLAKE2_ROUND_NOMSG
#  define BLAKE2_ROUND_NOMSG(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, \
                           v12, v13, v14, v15)                                 \
    do {                                                                       \
        G(v0, v4, v8, v12);                                                    \
        G(v1, v5, v9, v13);                                                    \
        G(v2, v6, v10, v14);                                                   \
        G(v3, v7, v11, v15);                                                   \
        G(v0, v5, v10, v15);                                                   \
        G(v1, v6, v11, v12);                                                   \
        G(v2, v7, v8, v13);                                                    \
        G(v3, v4, v9, v14);                                                    \
    } while ((void)0, 0)
# endif

int blake2b_nokey(void *out, size_t outlen, const void *in, size_t inlen);
int blake2b(void *out, size_t outlen, const void *in, size_t inlen,
                   const void *key, size_t keylen);
int blake2b_long(void *pout, uint32_t outlen, const void *in, size_t inlen);

#endif
