/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdint.h>
#include <string.h>
#include "internal/common.h"
#include "crypto/bn.h"

#define P256_LIMBS (256 / BN_BITS2)

typedef __uint128_t u128;
typedef __int128_t i128;

static const BN_ULONG SM2P256_P[P256_LIMBS] = {
    0xffffffffffffffffULL, 0xffffffff00000000ULL,
    0xffffffffffffffffULL, 0xfffffffeffffffffULL
};

static const BN_ULONG SM2P256_N[P256_LIMBS] = {
    0x53bbf40939d54123ULL, 0x7203df6b21c6052bULL,
    0xffffffffffffffffULL, 0xfffffffeffffffffULL
};

static const BN_ULONG SM2P256_P_DIV_2[P256_LIMBS] = {
    0x8000000000000000ULL, 0xffffffff80000000ULL,
    0xffffffffffffffffULL, 0x7fffffff7fffffffULL
};

static const BN_ULONG SM2P256_N_DIV_2[P256_LIMBS] = {
    0xa9ddfa049ceaa092ULL, 0xb901efb590e30295ULL,
    0xffffffffffffffffULL, 0x7fffffff7fffffffULL
};

static ossl_inline BN_ULONG add4(BN_ULONG r[P256_LIMBS],
    const BN_ULONG a[P256_LIMBS], const BN_ULONG b[P256_LIMBS])
{
    u128 t;
    BN_ULONG carry;

    t = (u128)a[0] + b[0];
    r[0] = (BN_ULONG)t;
    carry = (BN_ULONG)(t >> 64);

    t = (u128)a[1] + b[1] + carry;
    r[1] = (BN_ULONG)t;
    carry = (BN_ULONG)(t >> 64);

    t = (u128)a[2] + b[2] + carry;
    r[2] = (BN_ULONG)t;
    carry = (BN_ULONG)(t >> 64);

    t = (u128)a[3] + b[3] + carry;
    r[3] = (BN_ULONG)t;
    return (BN_ULONG)(t >> 64);
}

static ossl_inline BN_ULONG sub4(BN_ULONG r[P256_LIMBS],
    const BN_ULONG a[P256_LIMBS], const BN_ULONG b[P256_LIMBS])
{
    BN_ULONG borrow, ai, bi;

    ai = a[0];
    bi = b[0];
    r[0] = ai - bi;
    borrow = (ai < bi);

    ai = a[1];
    bi = b[1] + borrow;
    r[1] = ai - bi;
    borrow = (ai < bi) | (borrow & (bi == 0));

    ai = a[2];
    bi = b[2] + borrow;
    r[2] = ai - bi;
    borrow = (ai < bi) | (borrow & (bi == 0));

    ai = a[3];
    bi = b[3] + borrow;
    r[3] = ai - bi;
    borrow = (ai < bi) | (borrow & (bi == 0));

    return borrow;
}

static ossl_inline void copy_cond(BN_ULONG dst[P256_LIMBS],
    const BN_ULONG src[P256_LIMBS], BN_ULONG mask)
{
    size_t i;

    for (i = 0; i < P256_LIMBS; i++)
        dst[i] = (dst[i] & ~mask) | (src[i] & mask);
}

static ossl_inline void mod_add(BN_ULONG r[P256_LIMBS],
    const BN_ULONG a[P256_LIMBS], const BN_ULONG b[P256_LIMBS],
    const BN_ULONG mod[P256_LIMBS])
{
    BN_ULONG t[P256_LIMBS], carry, borrow, mask;

    carry = add4(t, a, b);
    borrow = sub4(r, t, mod);

    /*
     * Keep t when the addition did not overflow and t < mod. Otherwise keep
     * t - mod. Inputs are assumed reduced, so one subtraction is sufficient.
     */
    mask = (BN_ULONG)0 - (borrow & (carry ^ 1));
    copy_cond(r, t, mask);
}

static ossl_inline void mod_sub(BN_ULONG r[P256_LIMBS],
    const BN_ULONG a[P256_LIMBS], const BN_ULONG b[P256_LIMBS],
    const BN_ULONG mod[P256_LIMBS])
{
    BN_ULONG t[P256_LIMBS], borrow, mask;

    borrow = sub4(t, a, b);
    add4(r, t, mod);

    mask = (BN_ULONG)0 - (borrow ^ 1);
    copy_cond(r, t, mask);
}

static ossl_inline void add_mod_div2(BN_ULONG r[P256_LIMBS],
    const BN_ULONG a[P256_LIMBS], const BN_ULONG odd_add[P256_LIMBS])
{
    BN_ULONG odd = a[0] & 1;
    BN_ULONG mask = (BN_ULONG)0 - odd;
    BN_ULONG t[P256_LIMBS], addend[P256_LIMBS];

    t[0] = (a[0] >> 1) | (a[1] << 63);
    t[1] = (a[1] >> 1) | (a[2] << 63);
    t[2] = (a[2] >> 1) | (a[3] << 63);
    t[3] = a[3] >> 1;

    addend[0] = odd_add[0] & mask;
    addend[1] = odd_add[1] & mask;
    addend[2] = odd_add[2] & mask;
    addend[3] = odd_add[3] & mask;
    add4(r, t, addend);
}

static void bn_to_u32(uint32_t out[8], const BN_ULONG in[P256_LIMBS])
{
    size_t i;

    for (i = 0; i < P256_LIMBS; i++) {
        out[2 * i] = (uint32_t)in[i];
        out[2 * i + 1] = (uint32_t)(in[i] >> 32);
    }
}

static void normalize_word(i128 acc[9], size_t idx)
{
    const i128 base = (i128)1 << 32;
    i128 q = acc[idx] / base;
    i128 rem = acc[idx] % base;

    if (rem < 0) {
        rem += base;
        q--;
    }
    acc[idx] = rem;
    acc[idx + 1] += q;
}

/*
 * Reduce modulo p = 2^256 - 2^224 - 2^96 + 2^64 - 1.
 * In base B=2^32:
 *   B^8 == B^7 + B^3 - B^2 + 1 (mod p)
 */
static void sm2p256_reduce(BN_ULONG r[P256_LIMBS], i128 acc[16])
{
    size_t i;
    BN_ULONG tmp[P256_LIMBS];

    for (i = 15; i >= 8; i--) {
        i128 x = acc[i];

        acc[i] = 0;
        acc[i - 1] += x;
        acc[i - 5] += x;
        acc[i - 6] -= x;
        acc[i - 8] += x;
        if (i == 8)
            break;
    }

    for (;;) {
        i128 x;

        for (i = 0; i < 8; i++)
            normalize_word(acc, i);

        x = acc[8];
        if (x == 0)
            break;
        acc[8] = 0;
        acc[7] += x;
        acc[3] += x;
        acc[2] -= x;
        acc[0] += x;
    }

    r[0] = (BN_ULONG)acc[0] | ((BN_ULONG)acc[1] << 32);
    r[1] = (BN_ULONG)acc[2] | ((BN_ULONG)acc[3] << 32);
    r[2] = (BN_ULONG)acc[4] | ((BN_ULONG)acc[5] << 32);
    r[3] = (BN_ULONG)acc[6] | ((BN_ULONG)acc[7] << 32);

    if (sub4(tmp, r, SM2P256_P) == 0)
        memcpy(r, tmp, sizeof(tmp));
}

/* Right shift: a >>= 1 */
void bn_rshift1(BN_ULONG *a)
{
    a[0] = (a[0] >> 1) | (a[1] << 63);
    a[1] = (a[1] >> 1) | (a[2] << 63);
    a[2] = (a[2] >> 1) | (a[3] << 63);
    a[3] >>= 1;
}

/* Sub: r = a - b */
void bn_sub(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b)
{
    sub4(r, a, b);
}

/* Modular div by 2: r = a / 2 mod p */
void ecp_sm2p256_div_by_2(BN_ULONG *r, const BN_ULONG *a)
{
    add_mod_div2(r, a, SM2P256_P_DIV_2);
}

/* Modular div by 2: r = a / 2 mod n, where n = ord(p) */
void ecp_sm2p256_div_by_2_mod_ord(BN_ULONG *r, const BN_ULONG *a)
{
    add_mod_div2(r, a, SM2P256_N_DIV_2);
}

/* Modular add: r = a + b mod p */
void ecp_sm2p256_add(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b)
{
    mod_add(r, a, b, SM2P256_P);
}

/* Modular sub: r = a - b mod p */
void ecp_sm2p256_sub(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b)
{
    mod_sub(r, a, b, SM2P256_P);
}

/* Modular sub: r = a - b mod n, where n = ord(p) */
void ecp_sm2p256_sub_mod_ord(BN_ULONG *r, const BN_ULONG *a,
    const BN_ULONG *b)
{
    mod_sub(r, a, b, SM2P256_N);
}

/* Modular mul by 3: out = 3 * a mod p */
void ecp_sm2p256_mul_by_3(BN_ULONG *r, const BN_ULONG *a)
{
    BN_ULONG t[P256_LIMBS];

    mod_add(t, a, a, SM2P256_P);
    mod_add(r, t, a, SM2P256_P);
}

/* Modular mul: r = a * b mod p */
void ecp_sm2p256_mul(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b)
{
    uint32_t aw[8], bw[8];
    i128 acc[16] = { 0 };
    size_t i, j;

    bn_to_u32(aw, a);
    bn_to_u32(bw, b);

    for (i = 0; i < 8; i++)
        for (j = 0; j < 8; j++)
            acc[i + j] += (uint64_t)aw[i] * bw[j];

    sm2p256_reduce(r, acc);
}

/* Modular sqr: r = a ^ 2 mod p */
void ecp_sm2p256_sqr(BN_ULONG *r, const BN_ULONG *a)
{
    uint32_t aw[8];
    i128 acc[16] = { 0 };
    size_t i, j;

    bn_to_u32(aw, a);

    for (i = 0; i < 8; i++) {
        acc[2 * i] += (uint64_t)aw[i] * aw[i];
        for (j = i + 1; j < 8; j++)
            acc[i + j] += (i128)2 * aw[i] * aw[j];
    }

    sm2p256_reduce(r, acc);
}
