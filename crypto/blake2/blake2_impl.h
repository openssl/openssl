/*
 * BLAKE2 reference source code package - reference C implementations
 *
 * Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.
 * You may use this under the terms of the CC0, the OpenSSL Licence, or the
 * Apache Public License 2.0, at your option.  The terms of these licenses can
 * be found at:
 *
 * - OpenSSL license   : https://www.openssl.org/source/license.html
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 * - CC0 1.0 Universal : http://www.apache.org/licenses/LICENSE-2.0
 *
 * More information about the BLAKE2 hash function can be found at
 * https://blake2.net.
 * 
 */

/* crypto/blake2/blake2_impl.h */

#include <stdint.h>
#include <string.h>

static inline uint32_t load32(const void *src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    const uint8_t *p = (const uint8_t *)src;
    uint32_t w = *p++;
    w |= (uint32_t)(*p++) <<  8;
    w |= (uint32_t)(*p++) << 16;
    w |= (uint32_t)(*p++) << 24;
    return w;
#endif
}

static inline uint64_t load64(const void *src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    const uint8_t *p = (const uint8_t *)src;
    uint64_t w = *p++;
    w |= (uint64_t)(*p++) <<  8;
    w |= (uint64_t)(*p++) << 16;
    w |= (uint64_t)(*p++) << 24;
    w |= (uint64_t)(*p++) << 32;
    w |= (uint64_t)(*p++) << 40;
    w |= (uint64_t)(*p++) << 48;
    w |= (uint64_t)(*p++) << 56;
    return w;
#endif
}

static inline void store32(void *dst, uint32_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
    memcpy(dst, &w, sizeof w);
#else
    uint8_t *p = (uint8_t *)dst;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
#endif
}

static inline void store64(void *dst, uint64_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
    memcpy(dst, &w, sizeof w);
#else
    uint8_t *p = (uint8_t *)dst;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
#endif
}

static inline uint64_t load48(const void *src)
{
    const uint8_t *p = (const uint8_t *)src;
    uint64_t w = *p++;
    w |= (uint64_t)(*p++) <<  8;
    w |= (uint64_t)(*p++) << 16;
    w |= (uint64_t)(*p++) << 24;
    w |= (uint64_t)(*p++) << 32;
    w |= (uint64_t)(*p++) << 40;
    return w;
}

static inline void store48(void *dst, uint64_t w)
{
    uint8_t *p = (uint8_t *)dst;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
}

static inline uint32_t rotl32(const uint32_t w, const unsigned c)
{
    return (w << c) | (w >> (32 - c));
}

static inline uint64_t rotl64(const uint64_t w, const unsigned c)
{
    return (w << c) | (w >> (64 - c));
}

static inline uint32_t rotr32(const uint32_t w, const unsigned c)
{
    return (w >> c) | (w << (32 - c));
}

static inline uint64_t rotr64(const uint64_t w, const unsigned c)
{
    return (w >> c) | (w << (64 - c));
}

/* prevents compiler optimizing out memset() */
static inline void secure_zero_memory(void *v, size_t n)
{
    static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
    memset_v(v, 0, n);
}
