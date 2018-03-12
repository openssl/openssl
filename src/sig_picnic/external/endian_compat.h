/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef PICNIC_COMPAT_ENDIAN_H
#define PICNIC_COMPAT_ENDIAN_H

#include <stdint.h>

#if defined(__GCC__) || defined(__clang__)
#define bswap16(x) __builtin_bswap16(x)
#define bswap32(x) __builtin_bswap32(x)
#define bswap64(x) __builtin_bswap64(x)
#elif defined(_MSC_VER)
#include <stdlib.h>

#define bswap16(x) _byteswap_ushort(x)
#define bswap32(x) _byteswap_ulong(x)
#define bswap64(x) _byteswap_uint64(x)
#else
static inline uint16_t bswap16(uint16_t x) {
  return ((x & 0xff00) >> 8) | ((x & 0x00ff) << 8);
}

static inline uint32_t bswap32(uint32_t x) {
  return ((x & 0xff000000) >> 24) | ((x & 0x00ff0000) >> 8) | ((x & 0x0000ff00) << 8) |
         ((x & 0x000000ff) << 24);
}

static inline uint64_t bswap64(uint64_t x) {
  return ((x & UINT64_C(0xff00000000000000)) >> 56) | ((x & UINT64_C(0x00ff000000000000)) >> 40) |
         ((x & UINT64_C(0x0000ff0000000000)) >> 24) | ((x & UINT64_C(0x000000ff00000000)) >> 8) |
         ((x & UINT64_C(0x00000000ff000000)) << 8) | ((x & UINT64_C(0x0000000000ff0000)) << 24) |
         ((x & UINT64_C(0x000000000000ff00)) << 40) | ((x & UINT64_C(0x00000000000000ff)) << 56);
}
#endif

/* Linux / GLIBC */
#if defined(__linux__) || defined(__GLIBC__)
#include <endian.h>
/* endian.h only provides conversion functions if built with one these defines */
#if defined(_DEFAULT_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define HAVE_HOSTSWAP
#endif
#endif

/* Windows */
#if defined(_WIN16) || defined(_WIN32) || defined(_WIN64)
#if defined(__MINGW32__) || defined(__MINGW64__)
#include <sys/param.h>
#else
#define PICNIC_IS_LITTLE_ENDIAN
#endif
#endif

/* OS X / OpenBSD */
#if defined(__APPLE__) || defined(__OpenBSD__)
#include <machine/endian.h>
#endif

/* other BSDs */
#if defined(__FreeBSD__) || defined(__NETBSD__) || defined(__NetBSD__)
#include <sys/endian.h>
#endif

#if !defined(PICNIC_IS_LITTLE_ENDIAN) && !defined(PICNIC_IS_BIG_ENDIAN)
#if defined(BIG_ENDIAN) && defined(LITTLE_ENDIAN)
#if defined(BYTE_ORDER) && BYTE_ORDER == BIG_ENDIAN
#define PICNIC_IS_BIG_ENDIAN
#elif defined(BYTE_ORDER) && BYTE_ORDER == LITTLE_ENDIAN
#define PICNIC_IS_LITTLE_ENDIAN
#endif
#elif defined(BIG_ENDIAN)
#define PICNIC_IS_BIG_ENDIAN
#elif defined(LITTLE_ENDIAN)
#define PICNIC_IS_LITTLE_ENDIAN
#endif
#endif

#if !defined(PICNIC_IS_LITTLE_ENDIAN) && !defined(PICNIC_IS_BIG_ENDIAN)
#if defined(_BIG_ENDIAN) && defined(_LITTLE_ENDIAN)
#if defined(_BYTE_ORDER) && _BYTE_ORDER == _BIG_ENDIAN
#define PICNIC_IS_BIG_ENDIAN
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _LITTLE_ENDIAN
#define PICNIC_IS_LITTLE_ENDIAN
#endif
#elif defined(_BIG_ENDIAN)
#define PICNIC_IS_BIG_ENDIAN
#elif defined(_LITTLE_ENDIAN)
#define PICNIC_IS_LITTLE_ENDIAN
#endif
#endif

#if !defined(PICNIC_IS_LITTLE_ENDIAN) && !defined(PICNIC_IS_BIG_ENDIAN)
#if defined(__BIG_ENDIAN) && defined(__LITTLE_ENDIAN)
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
#define PICNIC_IS_BIG_ENDIAN
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
#define PICNIC_IS_LITTLE_ENDIAN
#endif
#elif defined(__BIG_ENDIAN)
#define PICNIC_IS_BIG_ENDIAN
#elif defined(__LITTLE_ENDIAN)
#define PICNIC_IS_LITTLE_ENDIAN
#endif
#endif

#if !defined(PICNIC_IS_LITTLE_ENDIAN) && !defined(PICNIC_IS_BIG_ENDIAN)
#if defined(__BIG_ENDIAN__) && defined(__LITTLE_ENDIAN__)
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __BIG_ENDIAN__
#define PICNIC_IS_BIG_ENDIAN
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __LITTLE_ENDIAN__
#define PICNIC_IS_LITTLE_ENDIAN
#endif
#elif defined(__BIG_ENDIAN__)
#define PICNIC_IS_BIG_ENDIAN
#elif defined(__LITTLE_ENDIAN__)
#define PICNIC_IS_LITTLE_ENDIAN
#endif
#endif

#if !defined(PICNIC_IS_LITTLE_ENDIAN) && !defined(PICNIC_IS_BIG_ENDIAN)
#error "Unknown platform!"
#endif

#if !defined(HAVE_HOSTSWAP)
#if defined(PICNIC_IS_LITTLE_ENDIAN)
#define htobe16(x) bswap16((x))
#define htole16(x) ((uint16_t)(x))
#define be16toh(x) bswap16((x))
#define le16toh(x) ((uint16_t)(x))

#define htobe32(x) bswap32((x))
#define htole32(x) ((uint32_t)(x))
#define be32toh(x) bswap32((x))
#define le32toh(x) ((uint32_t)(x))

#define htobe64(x) bswap64((x))
#define htole64(x) ((uint64_t)(x))
#define be64toh(x) bswap64((x))
#define le64toh(x) ((uint64_t)(x))
#elif defined(PICNIC_IS_BIG_ENDIAN)
#define htobe16(x) ((uint16_t)(x))
#define htole16(x) bswap16((x))
#define be16toh(x) ((uint16_t)(x))
#define le16toh(x) bswap16((x))

#define htobe32(x) ((uint32_t)(x))
#define htole32(x) bswap32((x))
#define be32toh(x) ((uint32_t)(x))
#define le32toh(x) bswap32((x))

#define htobe64(x) ((uint64_t)(x))
#define htole64(x) bswap64((x))
#define be64toh(x) ((uint64_t)(x))
#define le64toh(x) bswap64((x))
#endif
#endif

#endif
