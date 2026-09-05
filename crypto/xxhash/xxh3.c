/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * An independent implementation of the 64-bit XXH3 non-cryptographic hash,
 * written from the algorithm description in the xxHash specification
 * (https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md) rather
 * than derived from the reference source.  Output is bit-compatible with
 * XXH3_64bits_withSeed().
 *
 * The prime constants and the 192-byte default secret below are parameters
 * of the algorithm: any implementation has to use these exact values to
 * produce interoperable digests.
 *
 * Structure of the algorithm, and therefore of this file:
 *
 *   len <= 16       a handful of keyed multiplies over both ends of the
 *                   input, followed by an avalanche;
 *   len <= 128      one to four 16-byte "mix" rounds taken from the head
 *                   and the tail of the input, summed and avalanched;
 *   len <= 240      eight head rounds plus up to seven interior rounds,
 *                   accumulated into two independent sums;
 *   otherwise       a wide 8-lane accumulator absorbs the input in 64-byte
 *                   stripes, is re-scrambled once per block of stripes,
 *                   and is finally folded down to 64 bits.
 *
 * Only the scalar accumulator is implemented; the specification's SIMD
 * variants are an optimisation of the same lane arithmetic.
 */

#include <assert.h>

#include <openssl/byteorder.h>

#include "internal/common.h"
#include "internal/constant_time.h"
#include "internal/xxhash.h"

/* Algorithm constants. */
#define XH3_STRIPE 64 /* bytes absorbed per accumulator pass */
#define XH3_LANES (XH3_STRIPE / 8)
#define XH3_KEY_STEP 8 /* secret bytes consumed per stripe */
#define XH3_SECRET_MIN 136
#define XH3_SECRET_LEN 192
#define XH3_MIDSIZE_MAX 240
#define XH3_MERGE_KEY_OFF 11 /* secret offset used by the final fold */
#define XH3_LAST_KEY_OFF 7 /* secret backshift for the trailing stripe */
#define XH3_MID_HEAD_OFF 3 /* secret offset of the interior mid rounds */
#define XH3_MID_TAIL_OFF 17 /* secret backshift of the mid tail round */

#define XH3_P32_1 0x9e3779b1U
#define XH3_P32_2 0x85ebca77U
#define XH3_P32_3 0xc2b2ae3dU

#define XH3_P64_1 0x9e3779b185ebca87ULL
#define XH3_P64_2 0xc2b2ae3d27d4eb4fULL
#define XH3_P64_3 0x165667b19e3779f9ULL
#define XH3_P64_4 0x85ebca77c2b2ae63ULL
#define XH3_P64_5 0x27d4eb2f165667c5ULL

#define XH3_MX_1 0x165667919e3779f9ULL
#define XH3_MX_2 0x9fb21c651e98df25ULL

/*
 * The default secret, eight bytes per line to match the lane granularity of
 * the accumulator.  Sub-word offsets into this table are deliberate, so it
 * has to stay byte addressable.
 */
static const uint8_t xh3_secret[XH3_SECRET_LEN] = {
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe,
    0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb,
    0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78,
    0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e,
    0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb,
    0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e,
    0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f,
    0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31,
    0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3,
    0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49,
    0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc,
    0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28,
    0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e
};

/* Little-endian loads, kept short because they appear everywhere below. */
static ossl_always_inline uint64_t xh3_ld64(const uint8_t *p)
{
    uint64_t v;

    OPENSSL_load_u64_le(&v, p);
    return v;
}

static ossl_always_inline uint32_t xh3_ld32(const uint8_t *p)
{
    uint32_t v;

    OPENSSL_load_u32_le(&v, p);
    return v;
}

static ossl_inline uint32_t xh3_rev32(uint32_t v)
{
    v = ((v & 0x00ff00ffU) << 8) | ((v >> 8) & 0x00ff00ffU);
    return (v << 16) | (v >> 16);
}

static ossl_inline uint64_t xh3_rev64(uint64_t v)
{
    const uint64_t m8 = 0x00ff00ff00ff00ffULL;
    const uint64_t m16 = 0x0000ffff0000ffffULL;

    v = ((v & m8) << 8) | ((v >> 8) & m8);
    v = ((v & m16) << 16) | ((v >> 16) & m16);
    return (v << 32) | (v >> 32);
}

static ossl_inline uint64_t xh3_rotl64(uint64_t v, unsigned int n)
{
    return (v << n) | (v >> (64 - n));
}

static ossl_always_inline uint64_t xh3_mul32(uint64_t a, uint64_t b)
{
    return (uint64_t)(uint32_t)a * (uint64_t)(uint32_t)b;
}

/*
 * Multiply two 64-bit values and fold the 128-bit product down by xoring its
 * halves together.  This is the only place that needs a wide multiply, so the
 * platform specifics are confined here.
 */
#if defined(__SIZEOF_INT128__) && __SIZEOF_INT128__ == 16

static ossl_always_inline uint64_t xh3_mulfold(uint64_t a, uint64_t b)
{
    __uint128_t p = (__uint128_t)a * (__uint128_t)b;

    return (uint64_t)p ^ (uint64_t)(p >> 64);
}

#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_ARM64)) \
    && !defined(_M_ARM64EC)

#include <intrin.h>

static ossl_always_inline uint64_t xh3_mulfold(uint64_t a, uint64_t b)
{
    uint64_t hi, lo;

    lo = _umul128(a, b, &hi);
    return lo ^ hi;
}

#else

/*
 * Long multiplication on 32-bit limbs.  With a = a1:a0 and b = b1:b0 the
 * product is a1*b1 << 64 plus the two cross terms << 32 plus a0*b0, so the
 * bits landing in the middle 32-bit column decide the carry into the upper
 * half. Collecting that column separately keeps every intermediate value
 * inside 64 bits.
 */
static uint64_t xh3_mulfold(uint64_t a, uint64_t b)
{
    uint64_t ll = xh3_mul32(a, b);
    uint64_t hl = xh3_mul32(a >> 32, b);
    uint64_t lh = xh3_mul32(a, b >> 32);
    uint64_t hh = xh3_mul32(a >> 32, b >> 32);
    uint64_t mid = (ll >> 32) + (uint32_t)hl + (uint32_t)lh;
    uint64_t lo = (mid << 32) | (uint32_t)ll;
    uint64_t hi = hh + (hl >> 32) + (lh >> 32) + (mid >> 32);

    return lo ^ hi;
}

#endif

static ossl_inline uint64_t xh3_avalanche64(uint64_t h)
{
    h ^= h >> 33;
    h *= XH3_P64_2;
    h ^= h >> 29;
    h *= XH3_P64_3;
    h ^= h >> 32;
    return h;
}

static ossl_inline uint64_t xh3_avalanche(uint64_t h)
{
    h ^= h >> 37;
    h *= XH3_MX_1;
    h ^= h >> 32;
    return h;
}

static ossl_always_inline uint64_t xh3_mix16(const uint8_t *in,
    const uint8_t *key,
    uint64_t seed)
{
    return xh3_mulfold(xh3_ld64(in) ^ (xh3_ld64(key) + seed),
        xh3_ld64(in + 8) ^ (xh3_ld64(key + 8) - seed));
}

static ossl_always_inline uint64_t xh3_hash_0(const uint8_t *key, uint64_t seed)
{
    return xh3_avalanche64(seed ^ xh3_ld64(key + 56) ^ xh3_ld64(key + 64));
}

static ossl_always_inline uint64_t xh3_hash_1_3(const uint8_t *in, size_t len,
    const uint8_t *key, uint64_t seed)
{
    uint32_t packed = ((uint32_t)in[0] << 16)
        | ((uint32_t)in[len >> 1] << 24)
        | ((uint32_t)in[len - 1])
        | ((uint32_t)len << 8);
    uint64_t mask = (uint64_t)(xh3_ld32(key) ^ xh3_ld32(key + 4)) + seed;

    return xh3_avalanche64(packed ^ mask);
}

static ossl_always_inline uint64_t xh3_hash_4_8(const uint8_t *in, size_t len,
    const uint8_t *key, uint64_t seed)
{
    uint64_t packed, mask, h;

    seed ^= (uint64_t)xh3_rev32((uint32_t)seed) << 32;

    packed = ((uint64_t)xh3_ld32(in) << 32) | xh3_ld32(in + len - 4);
    mask = (xh3_ld64(key + 8) ^ xh3_ld64(key + 16)) - seed;

    h = packed ^ mask;
    h ^= xh3_rotl64(h, 49) ^ xh3_rotl64(h, 24);
    h *= XH3_MX_2;
    h ^= (h >> 35) + len;
    h *= XH3_MX_2;
    h ^= h >> 28;

    return h;
}

static ossl_always_inline uint64_t xh3_hash_9_16(const uint8_t *in, size_t len,
    const uint8_t *key, uint64_t seed)
{
    uint64_t lo = xh3_ld64(in)
        ^ ((xh3_ld64(key + 24) ^ xh3_ld64(key + 32)) + seed);
    uint64_t hi = xh3_ld64(in + len - 8)
        ^ ((xh3_ld64(key + 40) ^ xh3_ld64(key + 48)) - seed);

    return xh3_avalanche(len + xh3_rev64(lo) + hi + xh3_mulfold(lo, hi));
}

static ossl_always_inline uint64_t xh3_hash_short(const uint8_t *in, size_t len,
    const uint8_t *key, uint64_t seed)
{
    if (ossl_likely(len > 8))
        return xh3_hash_9_16(in, len, key, seed);
    if (ossl_likely(len >= 4))
        return xh3_hash_4_8(in, len, key, seed);
    if (len > 0)
        return xh3_hash_1_3(in, len, key, seed);
    return xh3_hash_0(key, seed);
}

static uint64_t xh3_hash_17_128(const uint8_t *in, size_t len,
    const uint8_t *key, uint64_t seed)
{
    size_t pairs = ((len - 1) >> 5) + 1;
    uint64_t acc = (uint64_t)len * XH3_P64_1;
    size_t i;

    assert(len > 16 && len <= 128);

    for (i = 0; i < pairs; i++) {
        acc += xh3_mix16(in + 16 * i, key + 32 * i, seed);
        acc += xh3_mix16(in + len - 16 * (i + 1), key + 32 * i + 16, seed);
    }

    return xh3_avalanche(acc);
}

static uint64_t xh3_hash_129_240(const uint8_t *in, size_t len,
    const uint8_t *key, uint64_t seed)
{
    size_t rounds = len / 16;
    uint64_t head = (uint64_t)len * XH3_P64_1;
    uint64_t tail;
    size_t i;

    assert(len > 128 && len <= XH3_MIDSIZE_MAX);

    for (i = 0; i < 8; i++)
        head += xh3_mix16(in + 16 * i, key + 16 * i, seed);
    head = xh3_avalanche(head);

    tail = xh3_mix16(in + len - 16,
        key + XH3_SECRET_MIN - XH3_MID_TAIL_OFF, seed);
    for (i = 8; i < rounds; i++) {
        /*
         * The two sums are independent, which invites the compiler to fuse
         * this loop with the one above; feeding the finished head sum through
         * a barrier keeps them apart and measurably faster.
         */
        head = value_barrier_64(head);
        tail += xh3_mix16(in + 16 * i,
            key + 16 * (i - 8) + XH3_MID_HEAD_OFF, seed);
    }

    return xh3_avalanche(head + tail);
}

static ossl_always_inline void xh3_absorb(uint64_t *acc, const uint8_t *in,
    const uint8_t *key)
{
    size_t i;

    for (i = 0; i < XH3_LANES; i += 2) {
        uint64_t even = xh3_ld64(in + 8 * i);
        uint64_t odd = xh3_ld64(in + 8 * i + 8);
        uint64_t keyed_even = even ^ xh3_ld64(key + 8 * i);
        uint64_t keyed_odd = odd ^ xh3_ld64(key + 8 * i + 8);

        acc[i] += odd + xh3_mul32(keyed_even, keyed_even >> 32);
        acc[i + 1] += even + xh3_mul32(keyed_odd, keyed_odd >> 32);
    }
}

static void xh3_scramble(uint64_t *acc, const uint8_t *key)
{
    size_t i;

    for (i = 0; i < XH3_LANES; i++) {
        uint64_t lane = acc[i];

        lane ^= lane >> 47;
        lane ^= xh3_ld64(key + 8 * i);
        acc[i] = lane * XH3_P32_1;
    }
}

static ossl_always_inline void xh3_absorb_round(uint64_t *acc, const uint8_t *in,
    const uint8_t *key,
    size_t stripes)
{
    size_t n;

    for (n = 0; n < stripes; n++)
        xh3_absorb(acc, in + n * XH3_STRIPE, key + n * XH3_KEY_STEP);
}

static void xh3_absorb_input(uint64_t *acc, const uint8_t *in, size_t len,
    const uint8_t *key, size_t key_len)
{
    size_t stripes_per_block = (key_len - XH3_STRIPE) / XH3_KEY_STEP;
    size_t stripes = (len - 1) / XH3_STRIPE;
    size_t blocks = stripes / stripes_per_block;
    size_t n;

    assert(key_len >= XH3_SECRET_MIN);
    assert(len > XH3_STRIPE);

    for (n = 0; n < blocks; n++) {
        xh3_absorb_round(acc, in + n * stripes_per_block * XH3_STRIPE, key,
            stripes_per_block);
        xh3_scramble(acc, key + key_len - XH3_STRIPE);
    }

    stripes -= blocks * stripes_per_block;
    xh3_absorb_round(acc, in + blocks * stripes_per_block * XH3_STRIPE, key,
        stripes);

    xh3_absorb(acc, in + len - XH3_STRIPE,
        key + key_len - XH3_STRIPE - XH3_LAST_KEY_OFF);
}

static uint64_t xh3_fold(const uint64_t *acc, const uint8_t *key, uint64_t init)
{
    uint64_t h = init;
    size_t i;

    for (i = 0; i < XH3_LANES / 2; i++)
        h += xh3_mulfold(acc[2 * i] ^ xh3_ld64(key + 16 * i),
            acc[2 * i + 1] ^ xh3_ld64(key + 16 * i + 8));

    return xh3_avalanche(h);
}

static uint64_t xh3_hash_long(const uint8_t *in, size_t len,
    const uint8_t *key, size_t key_len)
{
    uint64_t acc[XH3_LANES] = {
        XH3_P32_3, XH3_P64_1, XH3_P64_2, XH3_P64_3,
        XH3_P64_4, XH3_P32_2, XH3_P64_5, XH3_P32_1
    };

    xh3_absorb_input(acc, in, len, key, key_len);

    return xh3_fold(acc, key + XH3_MERGE_KEY_OFF, (uint64_t)len * XH3_P64_1);
}

static void xh3_seed_secret(uint8_t *out, uint64_t seed)
{
    size_t i;

    for (i = 0; i < XH3_SECRET_LEN; i += 16) {
        OPENSSL_store_u64_le(out + i, xh3_ld64(xh3_secret + i) + seed);
        OPENSSL_store_u64_le(out + i + 8, xh3_ld64(xh3_secret + i + 8) - seed);
    }
}

/*
 * Kept out of line, where the compiler honours the hint, so that the seeded
 * secret does not sit in the frame of ossl_xxh3() itself: there it would cost
 * every short hash a frame setup.
 */
static ossl_noinline uint64_t xh3_hash_long_gen_secret(const uint8_t *in,
    size_t len, uint64_t seed)
{
    uint8_t key[XH3_SECRET_LEN];

    xh3_seed_secret(key, seed);

    return xh3_hash_long(in, len, key, sizeof(key));
}

uint64_t ossl_xxh3(const void *input, size_t len, uint64_t seed)
{
    const uint8_t *in = input;

    if (len <= 16)
        return xh3_hash_short(in, len, xh3_secret, seed);
    if (len <= 128)
        return xh3_hash_17_128(in, len, xh3_secret, seed);
    if (len <= XH3_MIDSIZE_MAX)
        return xh3_hash_129_240(in, len, xh3_secret, seed);
    if (seed == 0)
        return xh3_hash_long(in, len, xh3_secret, sizeof(xh3_secret));

    return xh3_hash_long_gen_secret(in, len, seed);
}
