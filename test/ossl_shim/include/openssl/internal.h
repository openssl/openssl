/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HEADER_CRYPTO_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_INTERNAL_H

#if defined(__cplusplus)
extern "C" {
#endif

// Endianness conversions.

#if defined(__GNUC__) && __GNUC__ >= 2
    static inline uint16_t CRYPTO_bswap2(uint16_t x) {
        return __builtin_bswap16(x);
    }

    static inline uint32_t CRYPTO_bswap4(uint32_t x) {
        return __builtin_bswap32(x);
    }

    static inline uint64_t CRYPTO_bswap8(uint64_t x) {
        return __builtin_bswap64(x);
    }
#elif defined(_MSC_VER)
#pragma intrinsic(_byteswap_uint64, _byteswap_ulong, _byteswap_ushort)
    static inline uint16_t CRYPTO_bswap2(uint16_t x) { return _byteswap_ushort(x); }

    static inline uint32_t CRYPTO_bswap4(uint32_t x) { return _byteswap_ulong(x); }

    static inline uint64_t CRYPTO_bswap8(uint64_t x) { return _byteswap_uint64(x); }
#else
    static inline uint16_t CRYPTO_bswap2(uint16_t x) { return (x >> 8) | (x << 8); }

    static inline uint32_t CRYPTO_bswap4(uint32_t x) {
        x = (x >> 16) | (x << 16);
        x = ((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8);
        return x;
    }

    static inline uint64_t CRYPTO_bswap8(uint64_t x) {
        return CRYPTO_bswap4(x >> 32) | (((uint64_t)CRYPTO_bswap4(x)) << 32);
    }
#endif

static inline void *OPENSSL_memcpy(void *dst, const void *src, size_t n) {
    if (n == 0) {
        return dst;
    }

    return memcpy(dst, src, n);
}

static inline uint32_t CRYPTO_load_u32_be(const void *in) {
    uint32_t v;
    OPENSSL_memcpy(&v, in, sizeof(v));
    return CRYPTO_bswap4(v);
}

static inline void CRYPTO_store_u64_le(void *out, uint64_t v) {
    OPENSSL_memcpy(out, &v, sizeof(v));
}

static inline uint64_t CRYPTO_load_u64_be(const void *ptr) {
    uint64_t ret;
    OPENSSL_memcpy(&ret, ptr, sizeof(ret));
    return CRYPTO_bswap8(ret);
}

// FROM mem.h

static inline int OPENSSL_isdigit(int c) { return c >= '0' && c <= '9'; }

#if defined(__cplusplus)
}
#endif

#endif //OPENSSL_HEADER_CRYPTO_INTERNAL_H
