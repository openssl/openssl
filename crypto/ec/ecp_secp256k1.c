/*
 * Copyright 2011-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*
 * The main parts of the code were extracted from
 * https://github.com/llamasoft/secp256k1_fast_unsafe/ which was itself
 * adapted from https://github.com/bitcoin-core/secp256k1 and adapted by
 * Michael Adjedj to match OpenSSL requirements.
 */
/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

/*
 * ECDSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdint.h>
#include <string.h>
#include <openssl/err.h>
#include "crypto/bn.h"
#include "ec_local.h"
#include "internal/numbers.h"
#include "ecp_secp256k1_modinv64.h"


#ifndef INT128_MAX
# error "Your compiler doesn't appear to support 128-bit integer types"
#endif

#define P256_LIMBS (256 / BN_BITS2)

/** Maximum allowed magnitudes for group element coordinates
 *  in affine (x, y) and jacobian (x, y, z) representation. */
#define SECP256K1_GE_X_MAGNITUDE_MAX  4
#define SECP256K1_GE_Y_MAGNITUDE_MAX  3
#define SECP256K1_GEJ_X_MAGNITUDE_MAX 4
#define SECP256K1_GEJ_Y_MAGNITUDE_MAX 4
#define SECP256K1_GEJ_Z_MAGNITUDE_MAX 1

typedef struct {
    /* X = sum(i=0..4, elem[i]*2^52) mod n */
    uint64_t n[5];
} secp256k1_fe;

/* Unpacks a constant into a overlapping multi-limbed FE element. */
#define SECP256K1_FE_CONST_INNER(d7, d6, d5, d4, d3, d2, d1, d0) { \
    (d0) | (((uint64_t)(d1) & 0xFFFFFUL) << 32), \
    ((uint64_t)(d1) >> 20) | (((uint64_t)(d2)) << 12) | (((uint64_t)(d3) & 0xFFUL) << 44), \
    ((uint64_t)(d3) >> 8) | (((uint64_t)(d4) & 0xFFFFFFFUL) << 24), \
    ((uint64_t)(d4) >> 28) | (((uint64_t)(d5)) << 4) | (((uint64_t)(d6) & 0xFFFFUL) << 36), \
    ((uint64_t)(d6) >> 16) | (((uint64_t)(d7)) << 16) \
}

#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0))}

static const secp256k1_fe secp256k1_fe_one = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1);

typedef struct {
    uint64_t n[4];
} secp256k1_fe_storage;

#define SECP256K1_FE_STORAGE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {{ \
    (d0) | (((uint64_t)(d1)) << 32), \
    (d2) | (((uint64_t)(d3)) << 32), \
    (d4) | (((uint64_t)(d5)) << 32), \
    (d6) | (((uint64_t)(d7)) << 32) \
}}

/* optimal for 128-bit and 256-bit exponents. */
#define WINDOW_A 5
/** The number of entries a table with precomputed multiples needs to have. */
#define ECMULT_TABLE_SIZE(w) (1 << ((w)-2))


static ossl_inline void secp256k1_fe_mul_inner(uint64_t *r, const uint64_t *a, const uint64_t * b) {
    secp256k1_uint128 c, d;
    uint64_t t3, t4, tx, u0;
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;

    /*  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
     *  for 0 <= x <= 4, px is a shorthand for sum(a[i]*b[x-i], i=0..x).
     *  for 4 <= x <= 8, px is a shorthand for sum(a[i]*b[x-i], i=(x-4)..4)
     *  Note that [x 0 0 0 0 0] = [x*R].
     */

    secp256k1_u128_mul(&d, a0, b[3]);
    secp256k1_u128_accum_mul(&d, a1, b[2]);
    secp256k1_u128_accum_mul(&d, a2, b[1]);
    secp256k1_u128_accum_mul(&d, a3, b[0]);

    /* [d 0 0 0] = [p3 0 0 0] */
    secp256k1_u128_mul(&c, a4, b[4]);

    /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    secp256k1_u128_accum_mul(&d, R, secp256k1_u128_to_u64(&c)); secp256k1_u128_rshift(&c, 64);

    /* [(c<<12) 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    t3 = secp256k1_u128_to_u64(&d) & M; secp256k1_u128_rshift(&d, 52);

    /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

    secp256k1_u128_accum_mul(&d, a0, b[4]);
    secp256k1_u128_accum_mul(&d, a1, b[3]);
    secp256k1_u128_accum_mul(&d, a2, b[2]);
    secp256k1_u128_accum_mul(&d, a3, b[1]);
    secp256k1_u128_accum_mul(&d, a4, b[0]);

    /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    secp256k1_u128_accum_mul(&d, R << 12, secp256k1_u128_to_u64(&c));

    /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    t4 = secp256k1_u128_to_u64(&d) & M; secp256k1_u128_rshift(&d, 52);

    /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    tx = (t4 >> 48); t4 &= (M >> 4);

    /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

    secp256k1_u128_mul(&c, a0, b[0]);

    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
    secp256k1_u128_accum_mul(&d, a1, b[4]);
    secp256k1_u128_accum_mul(&d, a2, b[3]);
    secp256k1_u128_accum_mul(&d, a3, b[2]);
    secp256k1_u128_accum_mul(&d, a4, b[1]);

    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = secp256k1_u128_to_u64(&d) & M; secp256k1_u128_rshift(&d, 52);

    /* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = (u0 << 4) | tx;

    /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    secp256k1_u128_accum_mul(&c, u0, R >> 4);

    /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    r[0] = secp256k1_u128_to_u64(&c) & M; secp256k1_u128_rshift(&c, 52);

    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

    secp256k1_u128_accum_mul(&c, a0, b[1]);
    secp256k1_u128_accum_mul(&c, a1, b[0]);

    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
    secp256k1_u128_accum_mul(&d, a2, b[4]);
    secp256k1_u128_accum_mul(&d, a3, b[3]);
    secp256k1_u128_accum_mul(&d, a4, b[2]);

    /* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    secp256k1_u128_accum_mul(&c, secp256k1_u128_to_u64(&d) & M, R); secp256k1_u128_rshift(&d, 52);

    /* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    r[1] = secp256k1_u128_to_u64(&c) & M; secp256k1_u128_rshift(&c, 52);

    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

    secp256k1_u128_accum_mul(&c, a0, b[2]);
    secp256k1_u128_accum_mul(&c, a1, b[1]);
    secp256k1_u128_accum_mul(&c, a2, b[0]);

    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
    secp256k1_u128_accum_mul(&d, a3, b[4]);
    secp256k1_u128_accum_mul(&d, a4, b[3]);

    /* [d 0 0 t4 t3 c t1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    secp256k1_u128_accum_mul(&c, R, secp256k1_u128_to_u64(&d)); secp256k1_u128_rshift(&d, 64);
    /* [(d<<12) 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    r[2] = secp256k1_u128_to_u64(&c) & M; secp256k1_u128_rshift(&c, 52);
    /* [(d<<12) 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    secp256k1_u128_accum_mul(&c, R << 12, secp256k1_u128_to_u64(&d));
    secp256k1_u128_accum_u64(&c, t3);
    /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[3] = secp256k1_u128_to_u64(&c) & M; secp256k1_u128_rshift(&c, 52);
    /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[4] = secp256k1_u128_to_u64(&c) + t4;
    /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}

static ossl_inline void secp256k1_fe_sqr_inner(uint64_t *r, const uint64_t *a) {
    secp256k1_uint128 c, d;
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    uint64_t t3, t4, tx, u0;
    const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;

    /**  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
     *  px is a shorthand for sum(a[i]*a[x-i], i=0..x).
     *  Note that [x 0 0 0 0 0] = [x*R].
     */

    secp256k1_u128_mul(&d, a0*2, a3);
    secp256k1_u128_accum_mul(&d, a1*2, a2);
    /* [d 0 0 0] = [p3 0 0 0] */
    secp256k1_u128_mul(&c, a4, a4);
    /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    secp256k1_u128_accum_mul(&d, R, secp256k1_u128_to_u64(&c)); secp256k1_u128_rshift(&c, 64);
    /* [(c<<12) 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    t3 = secp256k1_u128_to_u64(&d) & M; secp256k1_u128_rshift(&d, 52);
    /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

    a4 *= 2;
    secp256k1_u128_accum_mul(&d, a0, a4);
    secp256k1_u128_accum_mul(&d, a1*2, a3);
    secp256k1_u128_accum_mul(&d, a2, a2);
    /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    secp256k1_u128_accum_mul(&d, R << 12, secp256k1_u128_to_u64(&c));
    /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    t4 = secp256k1_u128_to_u64(&d) & M; secp256k1_u128_rshift(&d, 52);
    /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    tx = (t4 >> 48); t4 &= (M >> 4);
    /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

    secp256k1_u128_mul(&c, a0, a0);
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
    secp256k1_u128_accum_mul(&d, a1, a4);
    secp256k1_u128_accum_mul(&d, a2*2, a3);
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = secp256k1_u128_to_u64(&d) & M; secp256k1_u128_rshift(&d, 52);
    /* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = (u0 << 4) | tx;
    /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    secp256k1_u128_accum_mul(&c, u0, R >> 4);
    /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    r[0] = secp256k1_u128_to_u64(&c) & M; secp256k1_u128_rshift(&c, 52);
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

    a0 *= 2;
    secp256k1_u128_accum_mul(&c, a0, a1);
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
    secp256k1_u128_accum_mul(&d, a2, a4);
    secp256k1_u128_accum_mul(&d, a3, a3);
    /* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    secp256k1_u128_accum_mul(&c, secp256k1_u128_to_u64(&d) & M, R); secp256k1_u128_rshift(&d, 52);
    /* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    r[1] = secp256k1_u128_to_u64(&c) & M; secp256k1_u128_rshift(&c, 52);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

    secp256k1_u128_accum_mul(&c, a0, a2);
    secp256k1_u128_accum_mul(&c, a1, a1);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
    secp256k1_u128_accum_mul(&d, a3, a4);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    secp256k1_u128_accum_mul(&c, R, secp256k1_u128_to_u64(&d)); secp256k1_u128_rshift(&d, 64);
    /* [(d<<12) 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[2] = secp256k1_u128_to_u64(&c) & M; secp256k1_u128_rshift(&c, 52);
    /* [(d<<12) 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    secp256k1_u128_accum_mul(&c, R << 12, secp256k1_u128_to_u64(&d));
    secp256k1_u128_accum_u64(&c, t3);
    /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[3] = secp256k1_u128_to_u64(&c) & M; secp256k1_u128_rshift(&c, 52);
    /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[4] = secp256k1_u128_to_u64(&c) + t4;
    /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}

/** Implements arithmetic modulo FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F,
 *  represented as 5 uint64_t's in base 2^52. The values are allowed to contain >52 each. In particular,
 *  each FieldElem has a 'magnitude' associated with it. Internally, a magnitude M means each element
 *  is at most M*(2^53-1), except the most significant one, which is limited to M*(2^49-1). All operations
 *  accept any input with magnitude at most M, and have different rules for propagating magnitude to their
 *  output.
 */
static void secp256k1_fe_normalize_weak(secp256k1_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL;

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;
}

static void secp256k1_fe_normalize(secp256k1_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    uint64_t m;
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; m = t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; m &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; m &= t3;

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t4 >> 48) | ((t4 == 0x0FFFFFFFFFFFFULL) & (m == 0xFFFFFFFFFFFFFULL)
        & (t0 >= 0xFFFFEFFFFFC2FULL));

    /* Apply the final reduction (for constant-time behaviour, we do it always) */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL;

    /* Mask off the possible multiple of 2^256 from the final reduction */
    t4 &= 0x0FFFFFFFFFFFFULL;

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;
}

static void secp256k1_fe_normalize_var(secp256k1_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    uint64_t m;
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; m = t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; m &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; m &= t3;

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t4 >> 48) | ((t4 == 0x0FFFFFFFFFFFFULL) & (m == 0xFFFFFFFFFFFFFULL)
        & (t0 >= 0xFFFFEFFFFFC2FULL));

    if (x) {
        t0 += 0x1000003D1ULL;
        t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
        t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL;
        t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL;
        t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL;

        /* Mask off the possible multiple of 2^256 from the final reduction */
        t4 &= 0x0FFFFFFFFFFFFULL;
    }

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;
}

static int secp256k1_fe_normalizes_to_zero_var(secp256k1_fe *r) {
    uint64_t t0, t1, t2, t3, t4;
    uint64_t z0, z1;
    uint64_t x;

    t0 = r->n[0];
    t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    x = t4 >> 48;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    z0 = t0 & 0xFFFFFFFFFFFFFULL;
    z1 = z0 ^ 0x1000003D0ULL;

    /* Fast return path should catch the majority of cases */
    if ((z0 != 0ULL) && (z1 != 0xFFFFFFFFFFFFFULL)) {
        return 0;
    }

    t1 = r->n[1];
    t2 = r->n[2];
    t3 = r->n[3];

    t4 &= 0x0FFFFFFFFFFFFULL;

    t1 += (t0 >> 52);
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; z0 |= t1; z1 &= t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; z0 |= t3; z1 &= t3;
                                                z0 |= t4; z1 &= t4 ^ 0xF000000000000ULL;

    return (z0 == 0) | (z1 == 0xFFFFFFFFFFFFFULL);
}

static int secp256k1_fe_normalizes_to_zero(const secp256k1_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    uint64_t z0, z1;

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL; z0  = t0; z1  = t0 ^ 0x1000003D0ULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; z0 |= t1; z1 &= t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; z0 |= t3; z1 &= t3;
                                                z0 |= t4; z1 &= t4 ^ 0xF000000000000ULL;

    return (z0 == 0) | (z1 == 0xFFFFFFFFFFFFFULL);
}

static ossl_inline void secp256k1_fe_set_int(secp256k1_fe *r, int a) {
    r->n[0] = a;
    r->n[1] = r->n[2] = r->n[3] = r->n[4] = 0;
}

static ossl_inline int secp256k1_fe_is_zero(const secp256k1_fe *a) {
    const uint64_t *t = a->n;
    return (t[0] | t[1] | t[2] | t[3] | t[4]) == 0;
}

static ossl_inline int secp256k1_fe_is_odd(const secp256k1_fe *a) {
    return a->n[0] & 1;
}

static ossl_inline void secp256k1_fe_clear(secp256k1_fe *a) {
    int i;
    for (i=0; i<5; i++) {
        a->n[i] = 0;
    }
}

static ossl_inline void secp256k1_fe_negate(secp256k1_fe *r, const secp256k1_fe *a, int m) {
    r->n[0] = 0xFFFFEFFFFFC2FULL * 2 * (m + 1) - a->n[0];
    r->n[1] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[1];
    r->n[2] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[2];
    r->n[3] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[3];
    r->n[4] = 0x0FFFFFFFFFFFFULL * 2 * (m + 1) - a->n[4];
}

static ossl_inline void secp256k1_fe_mul_int(secp256k1_fe *r, int a) {
    r->n[0] *= a;
    r->n[1] *= a;
    r->n[2] *= a;
    r->n[3] *= a;
    r->n[4] *= a;
}

static ossl_inline void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a) {
    r->n[0] += a->n[0];
    r->n[1] += a->n[1];
    r->n[2] += a->n[2];
    r->n[3] += a->n[3];
    r->n[4] += a->n[4];
}

static void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * b) {
    secp256k1_fe_mul_inner(r->n, a->n, b->n);
}

static void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a) {
    secp256k1_fe_sqr_inner(r->n, a->n);
}

static ossl_inline void secp256k1_fe_cmov(secp256k1_fe *r, const secp256k1_fe *a, int flag) {
    uint64_t mask0, mask1;
    volatile int vflag = flag;

    mask0 = vflag + ~((uint64_t)0);
    mask1 = ~mask0;
    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
    r->n[4] = (r->n[4] & mask0) | (a->n[4] & mask1);
}

static ossl_inline void secp256k1_fe_storage_cmov(secp256k1_fe_storage *r, const secp256k1_fe_storage *a, int flag) {
    uint64_t mask0, mask1;
    volatile int vflag = flag;

    mask0 = vflag + ~((uint64_t)0);
    mask1 = ~mask0;
    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
}

static void secp256k1_fe_to_storage(secp256k1_fe_storage *r, const secp256k1_fe *a) {
    r->n[0] = a->n[0] | a->n[1] << 52;
    r->n[1] = a->n[1] >> 12 | a->n[2] << 40;
    r->n[2] = a->n[2] >> 24 | a->n[3] << 28;
    r->n[3] = a->n[3] >> 36 | a->n[4] << 16;
}

static ossl_inline void secp256k1_fe_from_storage(secp256k1_fe *r, const secp256k1_fe_storage *a) {
    r->n[0] = a->n[0] & 0xFFFFFFFFFFFFFULL;
    r->n[1] = a->n[0] >> 52 | ((a->n[1] << 12) & 0xFFFFFFFFFFFFFULL);
    r->n[2] = a->n[1] >> 40 | ((a->n[2] << 24) & 0xFFFFFFFFFFFFFULL);
    r->n[3] = a->n[2] >> 28 | ((a->n[3] << 36) & 0xFFFFFFFFFFFFFULL);
    r->n[4] = a->n[3] >> 16;
}

static ossl_inline int ecp_secp256k1_bignum_field_elem(secp256k1_fe* out, const BIGNUM* in) {
    secp256k1_fe_storage out_st;
    if (!bn_copy_words(out_st.n, in, P256_LIMBS)) {
        return 0;
    }
    secp256k1_fe_from_storage(out, &out_st);
    return 1;
}

static ossl_inline int ecp_secp256k1_field_elem_bignum(BIGNUM* out, const secp256k1_fe* in) {
    secp256k1_fe_storage in_st;
    secp256k1_fe in_norm = *in;
    secp256k1_fe_normalize_var(&in_norm);
    secp256k1_fe_to_storage(&in_st, &in_norm);
    return bn_set_words(out, in_st.n, P256_LIMBS);
}

#define ecp_secp256k1_bignum_scalar(out, in) \
    bn_copy_words(out.d, in, P256_LIMBS)
#define ecp_secp256k1_scalar_bignum(out, in) \
    bn_set_words(out, in.d, P256_LIMBS)


ossl_inline static int secp256k1_fe_equal(const secp256k1_fe *a, const secp256k1_fe *b) {
    secp256k1_fe na;

    secp256k1_fe_negate(&na, a, 1);
    secp256k1_fe_add(&na, b);
    return secp256k1_fe_normalizes_to_zero(&na);
}

static void secp256k1_fe_from_signed62(secp256k1_fe *r, const secp256k1_modinv64_signed62 *a) {
    const uint64_t M52 = UINT64_MAX >> 12;
    const uint64_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4];

    r->n[0] =  a0                   & M52;
    r->n[1] = (a0 >> 52 | a1 << 10) & M52;
    r->n[2] = (a1 >> 42 | a2 << 20) & M52;
    r->n[3] = (a2 >> 32 | a3 << 30) & M52;
    r->n[4] = (a3 >> 22 | a4 << 40);
}

static void secp256k1_fe_to_signed62(secp256k1_modinv64_signed62 *r, const secp256k1_fe *a) {
    const uint64_t M62 = UINT64_MAX >> 2;
    const uint64_t a0 = a->n[0], a1 = a->n[1], a2 = a->n[2], a3 = a->n[3], a4 = a->n[4];

    r->v[0] = (a0       | a1 << 52) & M62;
    r->v[1] = (a1 >> 10 | a2 << 42) & M62;
    r->v[2] = (a2 >> 20 | a3 << 32) & M62;
    r->v[3] = (a3 >> 30 | a4 << 22) & M62;
    r->v[4] =  a4 >> 40;
}

static void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *x) {
    secp256k1_fe tmp = *x;
    secp256k1_modinv64_signed62 s;

    secp256k1_fe_normalize(&tmp);
    secp256k1_fe_to_signed62(&s, &tmp);
    secp256k1_modinv64(&s, &secp256k1_const_modinfo_fe);
    secp256k1_fe_from_signed62(r, &s);
}

static ossl_inline void secp256k1_fe_half(secp256k1_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];
    uint64_t one = (uint64_t)1;
    uint64_t mask = -(t0 & one) >> 12;

    /* Bounds analysis (over the rationals).
     *
     * Let m = r->magnitude
     *     C = 0xFFFFFFFFFFFFFULL * 2
     *     D = 0x0FFFFFFFFFFFFULL * 2
     *
     * Initial bounds: t0..t3 <= C * m
     *                     t4 <= D * m
     */

    t0 += 0xFFFFEFFFFFC2FULL & mask;
    t1 += mask;
    t2 += mask;
    t3 += mask;
    t4 += mask >> 4;

    /* t0..t3: added <= C/2
     *     t4: added <= D/2
     *
     * Current bounds: t0..t3 <= C * (m + 1/2)
     *                     t4 <= D * (m + 1/2)
     */

    r->n[0] = (t0 >> 1) + ((t1 & one) << 51);
    r->n[1] = (t1 >> 1) + ((t2 & one) << 51);
    r->n[2] = (t2 >> 1) + ((t3 & one) << 51);
    r->n[3] = (t3 >> 1) + ((t4 & one) << 51);
    r->n[4] = (t4 >> 1);

    /* t0..t3: shifted right and added <= C/4 + 1/2
     *     t4: shifted right
     *
     * Current bounds: t0..t3 <= C * (m/2 + 1/2)
     *                     t4 <= D * (m/2 + 1/4)
     *
     * Therefore the output magnitude (M) has to be set such that:
     *     t0..t3: C * M >= C * (m/2 + 1/2)
     *         t4: D * M >= D * (m/2 + 1/4)
     *
     * It suffices for all limbs that, for any input magnitude m:
     *     M >= m/2 + 1/2
     *
     * and since we want the smallest such integer value for M:
     *     M == floor(m/2) + 1
     */
}

/** A scalar modulo the group order of the secp256k1 curve. */
typedef struct {
    uint64_t d[4];
} secp256k1_scalar;

#define SECP256K1_SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {{((uint64_t)(d1)) << 32 | (d0), ((uint64_t)(d3)) << 32 | (d2), ((uint64_t)(d5)) << 32 | (d4), ((uint64_t)(d7)) << 32 | (d6)}}

/* Limbs of the secp256k1 order. */
#define SECP256K1_N_0 ((uint64_t)0xBFD25E8CD0364141ULL)
#define SECP256K1_N_1 ((uint64_t)0xBAAEDCE6AF48A03BULL)
#define SECP256K1_N_2 ((uint64_t)0xFFFFFFFFFFFFFFFEULL)
#define SECP256K1_N_3 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)

/* Limbs of 2^256 minus the secp256k1 order. */
#define SECP256K1_N_C_0 (~SECP256K1_N_0 + 1)
#define SECP256K1_N_C_1 (~SECP256K1_N_1)
#define SECP256K1_N_C_2 (1)

/* Limbs of half the secp256k1 order. */
#define SECP256K1_N_H_0 ((uint64_t)0xDFE92F46681B20A0ULL)
#define SECP256K1_N_H_1 ((uint64_t)0x5D576E7357A4501DULL)
#define SECP256K1_N_H_2 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)
#define SECP256K1_N_H_3 ((uint64_t)0x7FFFFFFFFFFFFFFFULL)

ossl_inline static void secp256k1_scalar_clear(secp256k1_scalar *r) {
    r->d[0] = r->d[1] = r->d[2] = r->d[3] = 0;
}

ossl_inline static void secp256k1_scalar_set_int(secp256k1_scalar *r, unsigned int v) {
    r->d[0] = v;
    r->d[1] = 0;
    r->d[2] = 0;
    r->d[3] = 0;
}

ossl_inline static unsigned int secp256k1_scalar_get_bits(const secp256k1_scalar *a, unsigned int offset, unsigned int count) {
    return (a->d[offset >> 6] >> (offset & 0x3F)) & ((((uint64_t)1) << count) - 1);
}

ossl_inline static unsigned int secp256k1_scalar_get_bits_var(const secp256k1_scalar *a, unsigned int offset, unsigned int count) {
    if ((offset + count - 1) >> 6 == offset >> 6) {
        return secp256k1_scalar_get_bits(a, offset, count);
    } else {
        return ((a->d[offset >> 6] >> (offset & 0x3F)) | (a->d[(offset >> 6) + 1] << (64 - (offset & 0x3F)))) & ((((uint64_t)1) << count) - 1);
    }
}

ossl_inline static int secp256k1_scalar_check_overflow(const secp256k1_scalar *a) {
    int yes = 0;
    int no = 0;
    no |= (a->d[3] < SECP256K1_N_3); /* No need for a > check. */
    no |= (a->d[2] < SECP256K1_N_2);
    yes |= (a->d[2] > SECP256K1_N_2) & ~no;
    no |= (a->d[1] < SECP256K1_N_1);
    yes |= (a->d[1] > SECP256K1_N_1) & ~no;
    yes |= (a->d[0] >= SECP256K1_N_0) & ~no;
    return yes;
}

ossl_inline static int secp256k1_scalar_reduce(secp256k1_scalar *r, unsigned int overflow) {
    secp256k1_uint128 t;

    secp256k1_u128_from_u64(&t, r->d[0]);
    secp256k1_u128_accum_u64(&t, overflow * SECP256K1_N_C_0);
    r->d[0] = secp256k1_u128_to_u64(&t); secp256k1_u128_rshift(&t, 64);
    secp256k1_u128_accum_u64(&t, r->d[1]);
    secp256k1_u128_accum_u64(&t, overflow * SECP256K1_N_C_1);
    r->d[1] = secp256k1_u128_to_u64(&t); secp256k1_u128_rshift(&t, 64);
    secp256k1_u128_accum_u64(&t, r->d[2]);
    secp256k1_u128_accum_u64(&t, overflow * SECP256K1_N_C_2);
    r->d[2] = secp256k1_u128_to_u64(&t); secp256k1_u128_rshift(&t, 64);
    secp256k1_u128_accum_u64(&t, r->d[3]);
    r->d[3] = secp256k1_u128_to_u64(&t);

    return overflow;
}

static void secp256k1_scalar_cadd_bit(secp256k1_scalar *r, unsigned int bit, int flag) {
    secp256k1_uint128 t;
    volatile int vflag = flag;

    bit += ((uint32_t) vflag - 1) & 0x100;  /* forcing (bit >> 6) > 3 makes this a noop */
    secp256k1_u128_from_u64(&t, r->d[0]);
    secp256k1_u128_accum_u64(&t, ((uint64_t)((bit >> 6) == 0)) << (bit & 0x3F));
    r->d[0] = secp256k1_u128_to_u64(&t); secp256k1_u128_rshift(&t, 64);
    secp256k1_u128_accum_u64(&t, r->d[1]);
    secp256k1_u128_accum_u64(&t, ((uint64_t)((bit >> 6) == 1)) << (bit & 0x3F));
    r->d[1] = secp256k1_u128_to_u64(&t); secp256k1_u128_rshift(&t, 64);
    secp256k1_u128_accum_u64(&t, r->d[2]);
    secp256k1_u128_accum_u64(&t, ((uint64_t)((bit >> 6) == 2)) << (bit & 0x3F));
    r->d[2] = secp256k1_u128_to_u64(&t); secp256k1_u128_rshift(&t, 64);
    secp256k1_u128_accum_u64(&t, r->d[3]);
    secp256k1_u128_accum_u64(&t, ((uint64_t)((bit >> 6) == 3)) << (bit & 0x3F));
    r->d[3] = secp256k1_u128_to_u64(&t);
}

ossl_inline static int secp256k1_scalar_is_zero(const secp256k1_scalar *a) {
    return (a->d[0] | a->d[1] | a->d[2] | a->d[3]) == 0;
}

static void secp256k1_scalar_negate(secp256k1_scalar *r, const secp256k1_scalar *a) {
    uint64_t nonzero = 0xFFFFFFFFFFFFFFFFULL * (secp256k1_scalar_is_zero(a) == 0);
    secp256k1_uint128 t;

    secp256k1_u128_from_u64(&t, ~a->d[0]);
    secp256k1_u128_accum_u64(&t, SECP256K1_N_0 + 1);
    r->d[0] = secp256k1_u128_to_u64(&t) & nonzero; secp256k1_u128_rshift(&t, 64);
    secp256k1_u128_accum_u64(&t, ~a->d[1]);
    secp256k1_u128_accum_u64(&t, SECP256K1_N_1);
    r->d[1] = secp256k1_u128_to_u64(&t) & nonzero; secp256k1_u128_rshift(&t, 64);
    secp256k1_u128_accum_u64(&t, ~a->d[2]);
    secp256k1_u128_accum_u64(&t, SECP256K1_N_2);
    r->d[2] = secp256k1_u128_to_u64(&t) & nonzero; secp256k1_u128_rshift(&t, 64);
    secp256k1_u128_accum_u64(&t, ~a->d[3]);
    secp256k1_u128_accum_u64(&t, SECP256K1_N_3);
    r->d[3] = secp256k1_u128_to_u64(&t) & nonzero;
}

ossl_inline static int secp256k1_scalar_is_one(const secp256k1_scalar *a) {
    return ((a->d[0] ^ 1) | a->d[1] | a->d[2] | a->d[3]) == 0;
}

/* Inspired by the macros in OpenSSL's crypto/bn/asm/x86_64-gcc.c. */

/** Add a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
#define muladd(a,b) { \
    uint64_t tl, th; \
    { \
        secp256k1_uint128 t; \
        secp256k1_u128_mul(&t, a, b); \
        th = secp256k1_u128_hi_u64(&t);  /* at most 0xFFFFFFFFFFFFFFFE */ \
        tl = secp256k1_u128_to_u64(&t); \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl);          /* at most 0xFFFFFFFFFFFFFFFF */ \
    c1 += th;                 /* overflow is handled on the next line */ \
    c2 += (c1 < th);          /* never overflows by contract (verified in the next line) */ \
}

/** Add a*b to the number defined by (c0,c1). c1 must never overflow. */
#define muladd_fast(a,b) { \
    uint64_t tl, th; \
    { \
        secp256k1_uint128 t; \
        secp256k1_u128_mul(&t, a, b); \
        th = secp256k1_u128_hi_u64(&t);  /* at most 0xFFFFFFFFFFFFFFFE */ \
        tl = secp256k1_u128_to_u64(&t); \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl);          /* at most 0xFFFFFFFFFFFFFFFF */ \
    c1 += th;                 /* never overflows by contract (verified in the next line) */ \
}

/** Add a to the number defined by (c0,c1,c2). c2 must never overflow. */
#define sumadd(a) { \
    unsigned int over; \
    c0 += (a);                  /* overflow is handled on the next line */ \
    over = (c0 < (a));         \
    c1 += over;                 /* overflow is handled on the next line */ \
    c2 += (c1 < over);          /* never overflows by contract */ \
}

/** Add a to the number defined by (c0,c1). c1 must never overflow, c2 must be zero. */
#define sumadd_fast(a) { \
    c0 += (a);                 /* overflow is handled on the next line */ \
    c1 += (c0 < (a));          /* never overflows by contract (verified the next line) */ \
}

/** Extract the lowest 64 bits of (c0,c1,c2) into n, and left shift the number 64 bits. */
#define extract(n) { \
    (n) = c0; \
    c0 = c1; \
    c1 = c2; \
    c2 = 0; \
}

/** Extract the lowest 64 bits of (c0,c1,c2) into n, and left shift the number 64 bits. c2 is required to be zero. */
#define extract_fast(n) { \
    (n) = c0; \
    c0 = c1; \
    c1 = 0; \
}
#if 0
static void secp256k1_scalar_reduce_512(secp256k1_scalar *r, const uint64_t *l) {
    secp256k1_uint128 c128;
    uint64_t c, c0, c1, c2;
    uint64_t n0 = l[4], n1 = l[5], n2 = l[6], n3 = l[7];
    uint64_t m0, m1, m2, m3, m4, m5;
    uint32_t m6;
    uint64_t p0, p1, p2, p3;
    uint32_t p4;

    /* Reduce 512 bits into 385. */
    /* m[0..6] = l[0..3] + n[0..3] * SECP256K1_N_C. */
    c0 = l[0]; c1 = 0; c2 = 0;
    muladd_fast(n0, SECP256K1_N_C_0);
    extract_fast(m0);
    sumadd_fast(l[1]);
    muladd(n1, SECP256K1_N_C_0);
    muladd(n0, SECP256K1_N_C_1);
    extract(m1);
    sumadd(l[2]);
    muladd(n2, SECP256K1_N_C_0);
    muladd(n1, SECP256K1_N_C_1);
    sumadd(n0);
    extract(m2);
    sumadd(l[3]);
    muladd(n3, SECP256K1_N_C_0);
    muladd(n2, SECP256K1_N_C_1);
    sumadd(n1);
    extract(m3);
    muladd(n3, SECP256K1_N_C_1);
    sumadd(n2);
    extract(m4);
    sumadd_fast(n3);
    extract_fast(m5);
    m6 = c0;

    /* Reduce 385 bits into 258. */
    /* p[0..4] = m[0..3] + m[4..6] * SECP256K1_N_C. */
    c0 = m0; c1 = 0; c2 = 0;
    muladd_fast(m4, SECP256K1_N_C_0);
    extract_fast(p0);
    sumadd_fast(m1);
    muladd(m5, SECP256K1_N_C_0);
    muladd(m4, SECP256K1_N_C_1);
    extract(p1);
    sumadd(m2);
    muladd(m6, SECP256K1_N_C_0);
    muladd(m5, SECP256K1_N_C_1);
    sumadd(m4);
    extract(p2);
    sumadd_fast(m3);
    muladd_fast(m6, SECP256K1_N_C_1);
    sumadd_fast(m5);
    extract_fast(p3);
    p4 = c0 + m6;

    /* Reduce 258 bits into 256. */
    /* r[0..3] = p[0..3] + p[4] * SECP256K1_N_C. */
    secp256k1_u128_from_u64(&c128, p0);
    secp256k1_u128_accum_mul(&c128, SECP256K1_N_C_0, p4);
    r->d[0] = secp256k1_u128_to_u64(&c128); secp256k1_u128_rshift(&c128, 64);
    secp256k1_u128_accum_u64(&c128, p1);
    secp256k1_u128_accum_mul(&c128, SECP256K1_N_C_1, p4);
    r->d[1] = secp256k1_u128_to_u64(&c128); secp256k1_u128_rshift(&c128, 64);
    secp256k1_u128_accum_u64(&c128, p2);
    secp256k1_u128_accum_u64(&c128, p4);
    r->d[2] = secp256k1_u128_to_u64(&c128); secp256k1_u128_rshift(&c128, 64);
    secp256k1_u128_accum_u64(&c128, p3);
    r->d[3] = secp256k1_u128_to_u64(&c128);
    c = secp256k1_u128_hi_u64(&c128);

    /* Final reduction of r. */
    secp256k1_scalar_reduce(r, c + secp256k1_scalar_check_overflow(r));
}
#endif

static void secp256k1_scalar_mul_512(uint64_t *l8, const secp256k1_scalar *a, const secp256k1_scalar *b) {
    /* 160 bit accumulator. */
    uint64_t c0 = 0, c1 = 0;
    uint32_t c2 = 0;

    /* l8[0..7] = a[0..3] * b[0..3]. */
    muladd_fast(a->d[0], b->d[0]);
    extract_fast(l8[0]);
    muladd(a->d[0], b->d[1]);
    muladd(a->d[1], b->d[0]);
    extract(l8[1]);
    muladd(a->d[0], b->d[2]);
    muladd(a->d[1], b->d[1]);
    muladd(a->d[2], b->d[0]);
    extract(l8[2]);
    muladd(a->d[0], b->d[3]);
    muladd(a->d[1], b->d[2]);
    muladd(a->d[2], b->d[1]);
    muladd(a->d[3], b->d[0]);
    extract(l8[3]);
    muladd(a->d[1], b->d[3]);
    muladd(a->d[2], b->d[2]);
    muladd(a->d[3], b->d[1]);
    extract(l8[4]);
    muladd(a->d[2], b->d[3]);
    muladd(a->d[3], b->d[2]);
    extract(l8[5]);
    muladd_fast(a->d[3], b->d[3]);
    extract_fast(l8[6]);
    l8[7] = c0;
}

#undef sumadd
#undef sumadd_fast
#undef muladd
#undef muladd_fast
#undef muladd2
#undef extract
#undef extract_fast


#if 0
static void secp256k1_scalar_mul(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) {
    uint64_t l[8];
    secp256k1_scalar_mul_512(l, a, b);
    secp256k1_scalar_reduce_512(r, l);
}
static int secp256k1_scalar_shr_int(secp256k1_scalar *r, int n) {
    int ret;

    ret = r->d[0] & ((1 << n) - 1);
    r->d[0] = (r->d[0] >> n) + (r->d[1] << (64 - n));
    r->d[1] = (r->d[1] >> n) + (r->d[2] << (64 - n));
    r->d[2] = (r->d[2] >> n) + (r->d[3] << (64 - n));
    r->d[3] = (r->d[3] >> n);
    return ret;
}
#endif

ossl_inline static int secp256k1_scalar_eq(const secp256k1_scalar *a, const secp256k1_scalar *b) {
    return ((a->d[0] ^ b->d[0]) | (a->d[1] ^ b->d[1]) | (a->d[2] ^ b->d[2]) | (a->d[3] ^ b->d[3])) == 0;
}

ossl_inline static void secp256k1_scalar_mul_shift_var(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b, unsigned int shift) {
    uint64_t l[8];
    unsigned int shiftlimbs;
    unsigned int shiftlow;
    unsigned int shifthigh;

    secp256k1_scalar_mul_512(l, a, b);
    shiftlimbs = shift >> 6;
    shiftlow = shift & 0x3F;
    shifthigh = 64 - shiftlow;
    r->d[0] = shift < 512 ? (l[0 + shiftlimbs] >> shiftlow | (shift < 448 && shiftlow ? (l[1 + shiftlimbs] << shifthigh) : 0)) : 0;
    r->d[1] = shift < 448 ? (l[1 + shiftlimbs] >> shiftlow | (shift < 384 && shiftlow ? (l[2 + shiftlimbs] << shifthigh) : 0)) : 0;
    r->d[2] = shift < 384 ? (l[2 + shiftlimbs] >> shiftlow | (shift < 320 && shiftlow ? (l[3 + shiftlimbs] << shifthigh) : 0)) : 0;
    r->d[3] = shift < 320 ? (l[3 + shiftlimbs] >> shiftlow) : 0;
    secp256k1_scalar_cadd_bit(r, 0, (l[(shift - 1) >> 6] >> ((shift - 1) & 0x3f)) & 1);
}

static void secp256k1_scalar_from_signed62(secp256k1_scalar *r, const secp256k1_modinv64_signed62 *a) {
    const uint64_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4];

    r->d[0] = a0      | a1 << 62;
    r->d[1] = a1 >> 2 | a2 << 60;
    r->d[2] = a2 >> 4 | a3 << 58;
    r->d[3] = a3 >> 6 | a4 << 56;
}

static void secp256k1_scalar_to_signed62(secp256k1_modinv64_signed62 *r, const secp256k1_scalar *a) {
    const uint64_t M62 = UINT64_MAX >> 2;
    const uint64_t a0 = a->d[0], a1 = a->d[1], a2 = a->d[2], a3 = a->d[3];

    r->v[0] =  a0                   & M62;
    r->v[1] = (a0 >> 62 | a1 <<  2) & M62;
    r->v[2] = (a1 >> 60 | a2 <<  4) & M62;
    r->v[3] = (a2 >> 58 | a3 <<  6) & M62;
    r->v[4] =  a3 >> 56;
}

static void secp256k1_scalar_inverse(secp256k1_scalar *r, const secp256k1_scalar *x) {
    secp256k1_modinv64_signed62 s;

    secp256k1_scalar_to_signed62(&s, x);
    secp256k1_modinv64(&s, &secp256k1_const_modinfo_scalar);
    secp256k1_scalar_from_signed62(r, &s);
}

ossl_inline static int secp256k1_scalar_is_even(const secp256k1_scalar *a) {
    /* d[0] is present and is the lowest word for all representations */
    return !(a->d[0] & 1);
}

/** A group element of the secp256k1 curve, in affine coordinates. */
typedef struct {
    secp256k1_fe x;
    secp256k1_fe y;
    int infinity; /* whether this represents the point at infinity */
} secp256k1_ge;

#define SECP256K1_GE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), 0}
#define SECP256K1_GE_CONST_INFINITY {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

/** A group element of the secp256k1 curve, in jacobian coordinates. */
typedef struct {
    secp256k1_fe x; /* actual X: x/z^2 */
    secp256k1_fe y; /* actual Y: y/z^3 */
    secp256k1_fe z;
    int infinity; /* whether this represents the point at infinity */
} secp256k1_gej;

#define SECP256K1_GEJ_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), 0}
#define SECP256K1_GEJ_CONST_INFINITY {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

typedef struct {
    secp256k1_fe_storage x;
    secp256k1_fe_storage y;
} secp256k1_ge_storage;

#define SECP256K1_GE_STORAGE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_STORAGE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_STORAGE_CONST((i),(j),(k),(l),(m),(n),(o),(p))}

#include "ecp_secp256k1_table.h"

/** Generator for secp256k1, value 'g' defined in
 *  "Standards for Efficient Cryptography" (SEC2) 2.7.1.
 */
static const secp256k1_ge secp256k1_ge_const_g = SECP256K1_GE_CONST(
    0x79BE667EUL, 0xF9DCBBACUL, 0x55A06295UL, 0xCE870B07UL,
    0x029BFCDBUL, 0x2DCE28D9UL, 0x59F2815BUL, 0x16F81798UL,
    0x483ADA77UL, 0x26A3C465UL, 0x5DA4FBFCUL, 0x0E1108A8UL,
    0xFD17B448UL, 0xA6855419UL, 0x9C47D08FUL, 0xFB10D4B8UL
);

static void secp256k1_ge_set_gej_zinv(secp256k1_ge *r, const secp256k1_gej *a, const secp256k1_fe *zi) {
    secp256k1_fe zi2;
    secp256k1_fe zi3;
    secp256k1_fe_sqr(&zi2, zi);
    secp256k1_fe_mul(&zi3, &zi2, zi);
    secp256k1_fe_mul(&r->x, &a->x, &zi2);
    secp256k1_fe_mul(&r->y, &a->y, &zi3);
    r->infinity = a->infinity;
}
#if 0
static void secp256k1_ge_set_xy(secp256k1_ge *r, const secp256k1_fe *x, const secp256k1_fe *y) {
    r->infinity = 0;
    r->x = *x;
    r->y = *y;
}

static int secp256k1_ge_is_infinity(const secp256k1_ge *a) {
    return a->infinity;
}
#endif
static void secp256k1_ge_neg(secp256k1_ge *r, const secp256k1_ge *a) {
    *r = *a;
    secp256k1_fe_normalize_weak(&r->y);
    secp256k1_fe_negate(&r->y, &r->y, 1);
}

static void secp256k1_ge_set_gej(secp256k1_ge *r, secp256k1_gej *a) {
    secp256k1_fe z2, z3;
    r->infinity = a->infinity;
    secp256k1_fe_inv(&a->z, &a->z);
    secp256k1_fe_sqr(&z2, &a->z);
    secp256k1_fe_mul(&z3, &a->z, &z2);
    secp256k1_fe_mul(&a->x, &a->x, &z2);
    secp256k1_fe_mul(&a->y, &a->y, &z3);
    secp256k1_fe_set_int(&a->z, 1);
    r->x = a->x;
    r->y = a->y;
}

static void secp256k1_ge_globalz_set_table_gej(size_t len, secp256k1_ge *r, secp256k1_fe *globalz, const secp256k1_gej *a, const secp256k1_fe *zr) {
    size_t i = len - 1;
    secp256k1_fe zs;

    if (len > 0) {
        /* The z of the final point gives us the "global Z" for the table. */
        r[i].x = a[i].x;
        r[i].y = a[i].y;
        *globalz = a[i].z;
        r[i].infinity = 0;
        zs = zr[i];

        /* Work our way backwards, using the z-ratios to scale the x/y values. */
        while (i > 0) {
            if (i != len - 1) {
                secp256k1_fe_mul(&zs, &zs, &zr[i]);
            }
            i--;
            secp256k1_ge_set_gej_zinv(&r[i], &a[i], &zs);
        }
    }
}

static void secp256k1_gej_set_infinity(secp256k1_gej *r) {
    r->infinity = 1;
    secp256k1_fe_set_int(&r->x, 0);
    secp256k1_fe_set_int(&r->y, 0);
    secp256k1_fe_set_int(&r->z, 0);
}

static void secp256k1_gej_set_ge(secp256k1_gej *r, const secp256k1_ge *a) {
   r->infinity = a->infinity;
   r->x = a->x;
   r->y = a->y;
   secp256k1_fe_set_int(&r->z, 1);
}

static void secp256k1_gej_neg(secp256k1_gej *r, const secp256k1_gej *a) {
    r->infinity = a->infinity;
    r->x = a->x;
    r->y = a->y;
    r->z = a->z;
    secp256k1_fe_normalize_weak(&r->y);
    secp256k1_fe_negate(&r->y, &r->y, 1);
}

static ossl_inline void secp256k1_gej_double(secp256k1_gej *r, const secp256k1_gej *a) {
    /* Operations: 3 mul, 4 sqr, 8 add/half/mul_int/negate */
    secp256k1_fe l, s, t;

    r->infinity = a->infinity;

    /* Formula used:
     * L = (3/2) * X1^2
     * S = Y1^2
     * T = -X1*S
     * X3 = L^2 + 2*T
     * Y3 = -(L*(X3 + T) + S^2)
     * Z3 = Y1*Z1
     */

    secp256k1_fe_mul(&r->z, &a->z, &a->y); /* Z3 = Y1*Z1 (1) */
    secp256k1_fe_sqr(&s, &a->y);           /* S = Y1^2 (1) */
    secp256k1_fe_sqr(&l, &a->x);           /* L = X1^2 (1) */
    secp256k1_fe_mul_int(&l, 3);           /* L = 3*X1^2 (3) */
    secp256k1_fe_half(&l);                 /* L = 3/2*X1^2 (2) */
    secp256k1_fe_negate(&t, &s, 1);        /* T = -S (2) */
    secp256k1_fe_mul(&t, &t, &a->x);       /* T = -X1*S (1) */
    secp256k1_fe_sqr(&r->x, &l);           /* X3 = L^2 (1) */
    secp256k1_fe_add(&r->x, &t);           /* X3 = L^2 + T (2) */
    secp256k1_fe_add(&r->x, &t);           /* X3 = L^2 + 2*T (3) */
    secp256k1_fe_sqr(&s, &s);              /* S' = S^2 (1) */
    secp256k1_fe_add(&t, &r->x);           /* T' = X3 + T (4) */
    secp256k1_fe_mul(&r->y, &t, &l);       /* Y3 = L*(X3 + T) (1) */
    secp256k1_fe_add(&r->y, &s);           /* Y3 = L*(X3 + T) + S^2 (2) */
    secp256k1_fe_negate(&r->y, &r->y, 2);  /* Y3 = -(L*(X3 + T) + S^2) (3) */
}

static void secp256k1_gej_double_var(secp256k1_gej *r, const secp256k1_gej *a, secp256k1_fe *rzr) {

    /** For secp256k1, 2Q is infinity if and only if Q is infinity. This is because if 2Q = infinity,
     *  Q must equal -Q, or that Q.y == -(Q.y), or Q.y is 0. For a point on y^2 = x^3 + 7 to have
     *  y=0, x^3 must be -7 mod p. However, -7 has no cube root mod p.
     *
     *  Having said this, if this function receives a point on a sextic twist, e.g. by
     *  a fault attack, it is possible for y to be 0. This happens for y^2 = x^3 + 6,
     *  since -6 does have a cube root mod p. For this point, this function will not set
     *  the infinity flag even though the point doubles to infinity, and the result
     *  point will be gibberish (z = 0 but infinity = 0).
     */
    if (a->infinity) {
        secp256k1_gej_set_infinity(r);
        if (rzr != NULL) {
            secp256k1_fe_set_int(rzr, 1);
        }
        return;
    }

    if (rzr != NULL) {
        *rzr = a->y;
        secp256k1_fe_normalize_weak(rzr);
    }

    secp256k1_gej_double(r, a);
}

static ossl_inline void secp256k1_gej_double_nonzero(secp256k1_gej *r, const secp256k1_gej *a, secp256k1_fe *rzr) {
    secp256k1_gej_double_var(r, a, rzr);
}

static void secp256k1_gej_add_ge_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, secp256k1_fe *rzr) {
    /* Operations: 8 mul, 3 sqr, 11 add/negate/normalizes_to_zero (ignoring special cases) */
    secp256k1_fe z12, u1, u2, s1, s2, h, i, h2, h3, t;

    if (a->infinity) {
        secp256k1_gej_set_ge(r, b);
        return;
    }
    if (b->infinity) {
        if (rzr != NULL) {
            secp256k1_fe_set_int(rzr, 1);
        }
        *r = *a;
        return;
    }

    secp256k1_fe_sqr(&z12, &a->z);
    u1 = a->x;
    secp256k1_fe_mul(&u2, &b->x, &z12);
    s1 = a->y;
    secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &a->z);
    secp256k1_fe_negate(&h, &u1, SECP256K1_GEJ_X_MAGNITUDE_MAX); secp256k1_fe_add(&h, &u2);
    secp256k1_fe_negate(&i, &s2, 1); secp256k1_fe_add(&i, &s1);
    if (secp256k1_fe_normalizes_to_zero_var(&h)) {
        if (secp256k1_fe_normalizes_to_zero_var(&i)) {
            secp256k1_gej_double_var(r, a, rzr);
        } else {
            if (rzr != NULL) {
                secp256k1_fe_set_int(rzr, 0);
            }
            secp256k1_gej_set_infinity(r);
        }
        return;
    }

    r->infinity = 0;
    if (rzr != NULL) {
        *rzr = h;
    }
    secp256k1_fe_mul(&r->z, &a->z, &h);

    secp256k1_fe_sqr(&h2, &h);
    secp256k1_fe_negate(&h2, &h2, 1);
    secp256k1_fe_mul(&h3, &h2, &h);
    secp256k1_fe_mul(&t, &u1, &h2);

    secp256k1_fe_sqr(&r->x, &i);
    secp256k1_fe_add(&r->x, &h3);
    secp256k1_fe_add(&r->x, &t);
    secp256k1_fe_add(&r->x, &t);

    secp256k1_fe_add(&t, &r->x);
    secp256k1_fe_mul(&r->y, &t, &i);
    secp256k1_fe_mul(&h3, &h3, &s1);
    secp256k1_fe_add(&r->y, &h3);
}

static int secp256k1_gej_is_infinity(const secp256k1_gej *a) {
    return a->infinity;
}

static int secp256k1_gej_equals_ge_var(const secp256k1_gej *a, const secp256k1_ge *b) {
    secp256k1_gej tmp;

    secp256k1_gej_neg(&tmp, a);
    secp256k1_gej_add_ge_var(&tmp, &tmp, b, NULL);
    return secp256k1_gej_is_infinity(&tmp);
}

static int secp256k1_gej_is_valid_var(const secp256k1_gej *a) {
    secp256k1_fe y2, x3, z2, z6;
    if (a->infinity) {
        return 1;
    }
    /** y^2 = x^3 + 7
     *  (Y/Z^3)^2 = (X/Z^2)^3 + 7
     *  Y^2 / Z^6 = X^3 / Z^6 + 7
     *  Y^2 = X^3 + 7*Z^6
     */
    secp256k1_fe_sqr(&y2, &a->y);
    secp256k1_fe_sqr(&x3, &a->x); secp256k1_fe_mul(&x3, &x3, &a->x);
    secp256k1_fe_sqr(&z2, &a->z);
    secp256k1_fe_sqr(&z6, &z2); secp256k1_fe_mul(&z6, &z6, &z2);
    secp256k1_fe_mul_int(&z6, 7);
    secp256k1_fe_add(&x3, &z6);
    secp256k1_fe_normalize_weak(&x3);
    return secp256k1_fe_equal(&y2, &x3);
}

static void secp256k1_gej_add_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_gej *b, secp256k1_fe *rzr) {
    /* 12 mul, 4 sqr, 11 add/negate/normalizes_to_zero (ignoring special cases) */
    secp256k1_fe z22, z12, u1, u2, s1, s2, h, i, h2, h3, t;

    if (a->infinity) {
        *r = *b;
        return;
    }
    if (b->infinity) {
        if (rzr != NULL) {
            secp256k1_fe_set_int(rzr, 1);
        }
        *r = *a;
        return;
    }

    secp256k1_fe_sqr(&z22, &b->z);
    secp256k1_fe_sqr(&z12, &a->z);
    secp256k1_fe_mul(&u1, &a->x, &z22);
    secp256k1_fe_mul(&u2, &b->x, &z12);
    secp256k1_fe_mul(&s1, &a->y, &z22); secp256k1_fe_mul(&s1, &s1, &b->z);
    secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &a->z);
    secp256k1_fe_negate(&h, &u1, 1); secp256k1_fe_add(&h, &u2);
    secp256k1_fe_negate(&i, &s2, 1); secp256k1_fe_add(&i, &s1);
    if (secp256k1_fe_normalizes_to_zero_var(&h)) {
        if (secp256k1_fe_normalizes_to_zero_var(&i)) {
            secp256k1_gej_double_var(r, a, rzr);
        } else {
            if (rzr != NULL) {
                secp256k1_fe_set_int(rzr, 0);
            }
            secp256k1_gej_set_infinity(r);
        }
        return;
    }

    r->infinity = 0;
    secp256k1_fe_mul(&t, &h, &b->z);
    if (rzr != NULL) {
        *rzr = t;
    }
    secp256k1_fe_mul(&r->z, &a->z, &t);

    secp256k1_fe_sqr(&h2, &h);
    secp256k1_fe_negate(&h2, &h2, 1);
    secp256k1_fe_mul(&h3, &h2, &h);
    secp256k1_fe_mul(&t, &u1, &h2);

    secp256k1_fe_sqr(&r->x, &i);
    secp256k1_fe_add(&r->x, &h3);
    secp256k1_fe_add(&r->x, &t);
    secp256k1_fe_add(&r->x, &t);

    secp256k1_fe_add(&t, &r->x);
    secp256k1_fe_mul(&r->y, &t, &i);
    secp256k1_fe_mul(&h3, &h3, &s1);
    secp256k1_fe_add(&r->y, &h3);
}

static void secp256k1_gej_add_ge(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b) {
    /* Operations: 7 mul, 5 sqr, 21 add/cmov/half/mul_int/negate/normalizes_to_zero */
    secp256k1_fe zz, u1, u2, s1, s2, t, tt, m, n, q, rr;
    secp256k1_fe m_alt, rr_alt;
    int degenerate;

    /*  In:
     *    Eric Brier and Marc Joye, Weierstrass Elliptic Curves and Side-Channel Attacks.
     *    In D. Naccache and P. Paillier, Eds., Public Key Cryptography, vol. 2274 of Lecture Notes in Computer Science, pages 335-345. Springer-Verlag, 2002.
     *  we find as solution for a unified addition/doubling formula:
     *    lambda = ((x1 + x2)^2 - x1 * x2 + a) / (y1 + y2), with a = 0 for secp256k1's curve equation.
     *    x3 = lambda^2 - (x1 + x2)
     *    2*y3 = lambda * (x1 + x2 - 2 * x3) - (y1 + y2).
     *
     *  Substituting x_i = Xi / Zi^2 and yi = Yi / Zi^3, for i=1,2,3, gives:
     *    U1 = X1*Z2^2, U2 = X2*Z1^2
     *    S1 = Y1*Z2^3, S2 = Y2*Z1^3
     *    Z = Z1*Z2
     *    T = U1+U2
     *    M = S1+S2
     *    Q = -T*M^2
     *    R = T^2-U1*U2
     *    X3 = R^2+Q
     *    Y3 = -(R*(2*X3+Q)+M^4)/2
     *    Z3 = M*Z
     *  (Note that the paper uses xi = Xi / Zi and yi = Yi / Zi instead.)
     *
     *  This formula has the benefit of being the same for both addition
     *  of distinct points and doubling. However, it breaks down in the
     *  case that either point is infinity, or that y1 = -y2. We handle
     *  these cases in the following ways:
     *
     *    - If b is infinity we simply bail by means of a VERIFY_CHECK.
     *
     *    - If a is infinity, we detect this, and at the end of the
     *      computation replace the result (which will be meaningless,
     *      but we compute to be constant-time) with b.x : b.y : 1.
     *
     *    - If a = -b, we have y1 = -y2, which is a degenerate case.
     *      But here the answer is infinity, so we simply set the
     *      infinity flag of the result, overriding the computed values
     *      without even needing to cmov.
     *
     *    - If y1 = -y2 but x1 != x2, which does occur thanks to certain
     *      properties of our curve (specifically, 1 has nontrivial cube
     *      roots in our field, and the curve equation has no x coefficient)
     *      then the answer is not infinity but also not given by the above
     *      equation. In this case, we cmov in place an alternate expression
     *      for lambda. Specifically (y1 - y2)/(x1 - x2). Where both these
     *      expressions for lambda are defined, they are equal, and can be
     *      obtained from each other by multiplication by (y1 + y2)/(y1 + y2)
     *      then substitution of x^3 + 7 for y^2 (using the curve equation).
     *      For all pairs of nonzero points (a, b) at least one is defined,
     *      so this covers everything.
     */

    secp256k1_fe_sqr(&zz, &a->z);                       /* z = Z1^2 */
    u1 = a->x;                                          /* u1 = U1 = X1*Z2^2 (GEJ_X_M) */
    secp256k1_fe_mul(&u2, &b->x, &zz);                  /* u2 = U2 = X2*Z1^2 (1) */
    s1 = a->y;                                          /* s1 = S1 = Y1*Z2^3 (GEJ_Y_M) */
    secp256k1_fe_mul(&s2, &b->y, &zz);                  /* s2 = Y2*Z1^2 (1) */
    secp256k1_fe_mul(&s2, &s2, &a->z);                  /* s2 = S2 = Y2*Z1^3 (1) */
    t = u1; secp256k1_fe_add(&t, &u2);                  /* t = T = U1+U2 (GEJ_X_M+1) */
    m = s1; secp256k1_fe_add(&m, &s2);                  /* m = M = S1+S2 (GEJ_Y_M+1) */
    secp256k1_fe_sqr(&rr, &t);                          /* rr = T^2 (1) */
    secp256k1_fe_negate(&m_alt, &u2, 1);                /* Malt = -X2*Z1^2 (2) */
    secp256k1_fe_mul(&tt, &u1, &m_alt);                 /* tt = -U1*U2 (1) */
    secp256k1_fe_add(&rr, &tt);                         /* rr = R = T^2-U1*U2 (2) */
    /* If lambda = R/M = R/0 we have a problem (except in the "trivial"
     * case that Z = z1z2 = 0, and this is special-cased later on). */
    degenerate = secp256k1_fe_normalizes_to_zero(&m);
    /* This only occurs when y1 == -y2 and x1^3 == x2^3, but x1 != x2.
     * This means either x1 == beta*x2 or beta*x1 == x2, where beta is
     * a nontrivial cube root of one. In either case, an alternate
     * non-indeterminate expression for lambda is (y1 - y2)/(x1 - x2),
     * so we set R/M equal to this. */
    rr_alt = s1;
    secp256k1_fe_mul_int(&rr_alt, 2);       /* rr_alt = Y1*Z2^3 - Y2*Z1^3 (GEJ_Y_M*2) */
    secp256k1_fe_add(&m_alt, &u1);          /* Malt = X1*Z2^2 - X2*Z1^2 (GEJ_X_M+2) */

    secp256k1_fe_cmov(&rr_alt, &rr, !degenerate);       /* rr_alt (GEJ_Y_M*2) */
    secp256k1_fe_cmov(&m_alt, &m, !degenerate);         /* m_alt (GEJ_X_M+2) */
    /* Now Ralt / Malt = lambda and is guaranteed not to be Ralt / 0.
     * From here on out Ralt and Malt represent the numerator
     * and denominator of lambda; R and M represent the explicit
     * expressions x1^2 + x2^2 + x1x2 and y1 + y2. */
    secp256k1_fe_sqr(&n, &m_alt);                       /* n = Malt^2 (1) */
    secp256k1_fe_negate(&q, &t,
        SECP256K1_GEJ_X_MAGNITUDE_MAX + 1);             /* q = -T (GEJ_X_M+2) */
    secp256k1_fe_mul(&q, &q, &n);                       /* q = Q = -T*Malt^2 (1) */
    /* These two lines use the observation that either M == Malt or M == 0,
     * so M^3 * Malt is either Malt^4 (which is computed by squaring), or
     * zero (which is "computed" by cmov). So the cost is one squaring
     * versus two multiplications. */
    secp256k1_fe_sqr(&n, &n);                           /* n = Malt^4 (1) */
    secp256k1_fe_cmov(&n, &m, degenerate);              /* n = M^3 * Malt (GEJ_Y_M+1) */
    secp256k1_fe_sqr(&t, &rr_alt);                      /* t = Ralt^2 (1) */
    secp256k1_fe_mul(&r->z, &a->z, &m_alt);             /* r->z = Z3 = Malt*Z (1) */
    secp256k1_fe_add(&t, &q);                           /* t = Ralt^2 + Q (2) */
    r->x = t;                                           /* r->x = X3 = Ralt^2 + Q (2) */
    secp256k1_fe_mul_int(&t, 2);                        /* t = 2*X3 (4) */
    secp256k1_fe_add(&t, &q);                           /* t = 2*X3 + Q (5) */
    secp256k1_fe_mul(&t, &t, &rr_alt);                  /* t = Ralt*(2*X3 + Q) (1) */
    secp256k1_fe_add(&t, &n);                           /* t = Ralt*(2*X3 + Q) + M^3*Malt (GEJ_Y_M+2) */
    secp256k1_fe_negate(&r->y, &t,
        SECP256K1_GEJ_Y_MAGNITUDE_MAX + 2);             /* r->y = -(Ralt*(2*X3 + Q) + M^3*Malt) (GEJ_Y_M+3) */
    secp256k1_fe_half(&r->y);                           /* r->y = Y3 = -(Ralt*(2*X3 + Q) + M^3*Malt)/2 ((GEJ_Y_M+3)/2 + 1) */

    /* In case a->infinity == 1, replace r with (b->x, b->y, 1). */
    secp256k1_fe_cmov(&r->x, &b->x, a->infinity);
    secp256k1_fe_cmov(&r->y, &b->y, a->infinity);
    secp256k1_fe_cmov(&r->z, &secp256k1_fe_one, a->infinity);

    /* Set r->infinity if r->z is 0.
     *
     * If a->infinity is set, then r->infinity = (r->z == 0) = (1 == 0) = false,
     * which is correct because the function assumes that b is not infinity.
     *
     * Now assume !a->infinity. This implies Z = Z1 != 0.
     *
     * Case y1 = -y2:
     * In this case we could have a = -b, namely if x1 = x2.
     * We have degenerate = true, r->z = (x1 - x2) * Z.
     * Then r->infinity = ((x1 - x2)Z == 0) = (x1 == x2) = (a == -b).
     *
     * Case y1 != -y2:
     * In this case, we can't have a = -b.
     * We have degenerate = false, r->z = (y1 + y2) * Z.
     * Then r->infinity = ((y1 + y2)Z == 0) = (y1 == -y2) = false. */
    r->infinity = secp256k1_fe_normalizes_to_zero(&r->z);
}

static void secp256k1_ge_from_storage(secp256k1_ge *r, const secp256k1_ge_storage *a) {
    secp256k1_fe_from_storage(&r->x, &a->x);
    secp256k1_fe_from_storage(&r->y, &a->y);
    r->infinity = 0;
}

static ossl_inline void secp256k1_ge_storage_cmov(secp256k1_ge_storage *r, const secp256k1_ge_storage *a, int flag) {
    secp256k1_fe_storage_cmov(&r->x, &a->x, flag);
    secp256k1_fe_storage_cmov(&r->y, &a->y, flag);
}

/** Fill a table 'prej' with precomputed odd multiples of a. Prej will contain
 *  the values [1*a,3*a,...,(2*n-1)*a], so it space for n values. zr[0] will
 *  contain prej[0].z / a.z. The other zr[i] values = prej[i].z / prej[i-1].z.
 *  Prej's Z values are undefined, except for the last value.
 */
static void secp256k1_ecmult_odd_multiples_table(int n, secp256k1_gej *prej, secp256k1_fe *zr, const secp256k1_gej *a) {
    secp256k1_gej d;
    secp256k1_ge a_ge, d_ge;
    int i;

    secp256k1_gej_double_var(&d, a, NULL);

    /*
     * Perform the additions on an isomorphism where 'd' is affine: drop the z coordinate
     * of 'd', and scale the 1P starting value's x/y coordinates without changing its z.
     */
    d_ge.x = d.x;
    d_ge.y = d.y;
    d_ge.infinity = 0;

    secp256k1_ge_set_gej_zinv(&a_ge, a, &d.z);
    prej[0].x = a_ge.x;
    prej[0].y = a_ge.y;
    prej[0].z = a->z;
    prej[0].infinity = 0;

    zr[0] = d.z;
    for (i = 1; i < n; i++) {
        secp256k1_gej_add_ge_var(&prej[i], &prej[i-1], &d_ge, &zr[i]);
    }

    /*
     * Each point in 'prej' has a z coordinate too small by a factor of 'd.z'. Only
     * the final point's z coordinate is actually used though, so just update that.
     */
    secp256k1_fe_mul(&prej[n-1].z, &prej[n-1].z, &d.z);
}

/** Fill a table 'pre' with precomputed odd multiples of a.
 *
 *  It brings its resulting point set to a single constant Z denominator,
 *  stores the X and Y coordinates as ge_storage points in pre, and stores the
 *  global Z in rz. It only operates on tables sized for WINDOW_A wnaf multiples.
 */
static void secp256k1_ecmult_odd_multiples_table_globalz_windowa(secp256k1_ge *pre, secp256k1_fe *globalz, const secp256k1_gej *a) {
    secp256k1_gej prej[ECMULT_TABLE_SIZE(WINDOW_A)];
    secp256k1_fe zr[ECMULT_TABLE_SIZE(WINDOW_A)];

    /* Compute the odd multiples in Jacobian form. */
    secp256k1_ecmult_odd_multiples_table(ECMULT_TABLE_SIZE(WINDOW_A), prej, zr, a);
    /* Bring them to the same Z denominator. */
    secp256k1_ge_globalz_set_table_gej(ECMULT_TABLE_SIZE(WINDOW_A), pre, globalz, prej, zr);
}

/** The following two macro retrieves a particular odd multiple from a table
 *  of precomputed multiples. */
#define ECMULT_TABLE_GET_GE(r,pre,n,w) do { \
    if ((n) > 0) { \
        *(r) = (pre)[((n)-1)/2]; \
    } else { \
        secp256k1_ge_neg((r), &(pre)[(-(n)-1)/2]); \
    } \
} while(0)

#define ECMULT_TABLE_GET_GE_STORAGE(r,pre,n,w) do { \
    if ((n) > 0) { \
        secp256k1_ge_from_storage((r), &(pre)[((n)-1)/2]); \
    } else { \
        secp256k1_ge_from_storage((r), &(pre)[(-(n)-1)/2]); \
        secp256k1_ge_neg((r), (r)); \
    } \
} while(0)

/** Convert a number to WNAF notation. The number becomes represented by sum(2^i * wnaf[i], i=0..bits),
 *  with the following guarantees:
 *  - each wnaf[i] is either 0, or an odd integer between -(1<<(w-1) - 1) and (1<<(w-1) - 1)
 *  - two non-zero entries in wnaf are separated by at least w-1 zeroes.
 *  - the number of set values in wnaf is returned. This number is at most 256, and at most one more
 *    than the number of bits in the (absolute value) of the input.
 */
static int secp256k1_ecmult_wnaf(int *wnaf, int len, const secp256k1_scalar *a, int w) {
    secp256k1_scalar s;
    int last_set_bit = -1;
    int bit = 0;
    int sign = 1;
    int carry = 0;

    for (bit = 0; bit < len; bit++) {
        wnaf[bit] = 0;
    }

    s = *a;
    if (secp256k1_scalar_get_bits(&s, 255, 1)) {
        secp256k1_scalar_negate(&s, &s);
        sign = -1;
    }

    bit = 0;
    while (bit < len) {
        int now;
        int word;
        if (secp256k1_scalar_get_bits(&s, bit, 1) == (unsigned int)carry) {
            bit++;
            continue;
        }

        now = w;
        if (now > len - bit) {
            now = len - bit;
        }

        word = secp256k1_scalar_get_bits_var(&s, bit, now) + carry;

        carry = (word >> (w-1)) & 1;
        word -= carry << w;

        wnaf[bit] = sign * word;
        last_set_bit = bit;

        bit += now;
    }

    return last_set_bit + 1;
}

static void secp256k1_ecmult(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_scalar *na) {
    secp256k1_ge pre_a[ECMULT_TABLE_SIZE(WINDOW_A)];
    secp256k1_ge tmpa;
    secp256k1_fe Z;

    int wnaf_na[256];
    int bits_na;

    int i;
    int bits;

    /* build wnaf representation for na. */
    bits_na = secp256k1_ecmult_wnaf(wnaf_na, 256, na, WINDOW_A);
    bits = bits_na;

    /* Calculate odd multiples of a.
     * All multiples are brought to the same Z 'denominator', which is stored
     * in Z. Due to secp256k1' isomorphism we can do all operations pretending
     * that the Z coordinate was 1, use affine addition formulae, and correct
     * the Z coordinate of the result once at the end.
     */
    secp256k1_ecmult_odd_multiples_table_globalz_windowa(pre_a, &Z, a);

    secp256k1_gej_set_infinity(r);

    for (i = bits - 1; i >= 0; i--) {
        int n;
        secp256k1_gej_double_var(r, r, NULL);
        if (i < bits_na && (n = wnaf_na[i])) {
            ECMULT_TABLE_GET_GE(&tmpa, pre_a, n, WINDOW_A);
            secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
        }
    }

    if (!r->infinity) {
        secp256k1_fe_mul(&r->z, &r->z, &Z);
    }
}

/*
 * Convert Jacobian coordinate point into affine coordinate (x,y)
 */
static int ecp_secp256k1_get_affine(const EC_GROUP *group,
                                    const EC_POINT *point,
                                    BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
{
    secp256k1_gej point_j;
    secp256k1_ge point_aff;

    if (EC_POINT_is_at_infinity(group, point)) {
        ECerr(ERR_LIB_EC, EC_R_POINT_AT_INFINITY);
        return 0;
    }

    if (x != NULL || y != NULL) {
        if (ecp_secp256k1_bignum_field_elem(&point_j.x, point->X) <= 0
            || ecp_secp256k1_bignum_field_elem(&point_j.y, point->Y) <= 0
            || ecp_secp256k1_bignum_field_elem(&point_j.z, point->Z) <= 0) {
            ECerr(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
            return 0;
        }
        point_j.infinity = secp256k1_fe_is_zero(&point_j.z);
        if (point_j.infinity) {
            ECerr(ERR_LIB_EC, EC_R_POINT_AT_INFINITY);
            return 0;
        }

        secp256k1_ge_set_gej(&point_aff, &point_j);

        if (x != NULL) {
            // TODO maybe not needeD.
            secp256k1_fe_normalize_var(&point_aff.x);
            if (!ecp_secp256k1_field_elem_bignum(x, &point_aff.x))
                return 0;
        }

        if (y != NULL) {
            // TODO maybe not needeD.
            secp256k1_fe_normalize_var(&point_aff.y);
            if (!ecp_secp256k1_field_elem_bignum(y, &point_aff.y))
                return 0;
        }
    }

    return 1;
}

static int ecp_secp256k1_export_point(EC_POINT *point, const secp256k1_gej *pt, const EC_GROUP *group) {
    if (secp256k1_gej_is_infinity(pt)) {
        EC_POINT_set_to_infinity(group, point);
        return 1;
    }

    if (ecp_secp256k1_field_elem_bignum(point->X, &pt->x) <= 0
        || ecp_secp256k1_field_elem_bignum(point->Y, &pt->y) <= 0
        || ecp_secp256k1_field_elem_bignum(point->Z, &pt->z) <= 0) {
        ECerr(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        return 0;
    }
    point->Z_is_one = 0; // TODO should probably test its actual value to optimize future computations...
    return 1;
}

static int ecp_secp256k1_import_point(secp256k1_gej *pt, const EC_GROUP *group, const EC_POINT *point) {
    if (EC_POINT_is_at_infinity(group, point)) {
        secp256k1_gej_set_infinity(pt);
        return 1;
    }

    if (ecp_secp256k1_bignum_field_elem(&pt->x, point->X) <= 0
        || ecp_secp256k1_bignum_field_elem(&pt->y, point->Y) <= 0
        || ecp_secp256k1_bignum_field_elem(&pt->z, point->Z) <= 0) {
        ECerr(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        return 0;
    }

    pt->infinity = secp256k1_fe_is_zero(&pt->z);
    return 1;
}

static int ecp_secp256k1_is_affine_G(const EC_GROUP *group, const EC_POINT *generator)
{
    secp256k1_gej pt;
    if (!ecp_secp256k1_import_point(&pt, group, generator)) {
        return 0;
    }
    return secp256k1_gej_equals_ge_var(&pt, &secp256k1_ge_const_g);
}

static void secp256k1_ecmult_gen(secp256k1_gej *r, const secp256k1_scalar *gn) {
    secp256k1_ge add;
    secp256k1_ge_storage adds;
    int bits;

    memset(&adds, 0, sizeof(secp256k1_ge_storage));
    secp256k1_gej_set_infinity(r);

    for (int j = 0; j < 64; j++) {
        bits = secp256k1_scalar_get_bits(gn, j * 4, 4);
        #if 1
        for (int i = 0; i < 16; i++) {
            /** This uses a conditional move to avoid any secret data in array indexes.
             *   _Any_ use of secret indexes has been demonstrated to result in timing
             *   sidechannels, even when the cache-line access patterns are uniform.
             *  See also:
             *   "A word of warning", CHES 2013 Rump Session, by Daniel J. Bernstein and Peter Schwabe
             *    (https://cryptojedi.org/peter/data/chesrump-20130822.pdf) and
             *   "Cache Attacks and Countermeasures: the Case of AES", RSA 2006,
             *    by Dag Arne Osvik, Adi Shamir, and Eran Tromer
             *    (http://www.tau.ac.il/~tromer/papers/cache.pdf)
             */
            secp256k1_ge_storage_cmov(&adds, &(secp256k1_ecmult_static_context[j][i]), i == bits);
        }
        secp256k1_ge_from_storage(&add, &adds);
        #else
            secp256k1_ge_from_storage(&add, &(secp256k1_ecmult_static_context[j][bits]));
        #endif
        secp256k1_gej_add_ge(r, r, &add);
    }
}

/* r = scalar*G + sum(scalars[i]*points[i]) */
static int ecp_secp256k1_points_mul(const EC_GROUP *group,
                                    EC_POINT *r,
                                    const BIGNUM *scalar,
                                    size_t num,
                                    const EC_POINT *points[],
                                    const BIGNUM *scalars[], BN_CTX *ctx)
{
    const EC_POINT *generator = NULL;
    int ret = 0;
    secp256k1_scalar current_scalar;
    secp256k1_gej r_j, current_point;

    BN_CTX_start(ctx);
    BIGNUM* tmp_scalar;
    if ((tmp_scalar = BN_CTX_get(ctx)) == NULL)
        goto err;
    secp256k1_gej_set_infinity(&r_j);

    if (scalar) {
        generator = EC_GROUP_get0_generator(group);
        if (generator == NULL) {
            ERR_raise(ERR_LIB_EC, EC_R_UNDEFINED_GENERATOR);
            goto err;
        }
        if ((BN_cmp(scalar, group->order) >= 0)
            || BN_is_negative(scalar)) {
            if (!BN_nnmod(tmp_scalar, scalar, group->order, ctx)) {
                ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
                goto err;
            }
            scalar = tmp_scalar;
        }
        if (!ecp_secp256k1_bignum_scalar(current_scalar, scalar)) {
            // should never happen because of the previous check.
            ECerr(ERR_LIB_EC, EC_R_BIGNUM_OUT_OF_RANGE);
            goto err;
        }
        if (ecp_secp256k1_is_affine_G(group, generator)) {
            secp256k1_ecmult_gen(&r_j, &current_scalar);
        } else {
            if (!ecp_secp256k1_import_point(&current_point, group, generator)) {
                goto err;
            }
            secp256k1_ecmult(&r_j, &current_point, &current_scalar);
        }
    }
    for (size_t i = 0; i < num; ++i) {
        if (EC_POINT_is_at_infinity(group, points[i]) || BN_is_zero(scalars[i]))
            continue;
        if (!ecp_secp256k1_import_point(&current_point, group, points[i])) {
            goto err;
        }
        if ((BN_cmp(scalars[i], group->order) >= 0)
            || BN_is_negative(scalars[i])) {
            if (!BN_nnmod(tmp_scalar, scalars[i], group->order, ctx)) {
                ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
                goto err;
            }
            scalars[i] = tmp_scalar;
        }
        if (!BN_is_one(scalars[i])) {
            if (!ecp_secp256k1_bignum_scalar(current_scalar, scalars[i])) {
                // should never happen because of the previous check.
                ECerr(ERR_LIB_EC, EC_R_BIGNUM_OUT_OF_RANGE);
                goto err;
            }
            secp256k1_ecmult(&current_point, &current_point, &current_scalar);
        }
        secp256k1_gej_add_var(&r_j, &r_j, &current_point, NULL);
    }
    if (!ecp_secp256k1_export_point(r, &r_j, group)) {
        goto err;
    }
    ret = 1;
err:
    BN_CTX_end(ctx);
    return ret;
}

static int ecp_secp256k1_field_mul(const EC_GROUP *group, BIGNUM *r,
                                   const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    secp256k1_fe a_fe, b_fe, r_fe;

    if (a == NULL || b == NULL || r == NULL)
        return 0;
    if (!ecp_secp256k1_bignum_field_elem(&a_fe, a)
        || !ecp_secp256k1_bignum_field_elem(&b_fe, b)) {
        ECerr(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        return 0;
    }
    secp256k1_fe_mul(&r_fe, &a_fe, &b_fe);
    if (!ecp_secp256k1_field_elem_bignum(r, &r_fe)) {
        ECerr(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        return 0;
    }
    return 1;
}

static int ecp_secp256k1_field_sqr(const EC_GROUP *group, BIGNUM *r,
                                   const BIGNUM *a, BN_CTX *ctx)
{
    secp256k1_fe a_fe, r_fe;

    if (a == NULL || r == NULL)
        return 0;
    if (!ecp_secp256k1_bignum_field_elem(&a_fe, a)) {
        ECerr(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        return 0;
    }
    secp256k1_fe_sqr(&r_fe, &a_fe);
    if (!ecp_secp256k1_field_elem_bignum(r, &r_fe)) {
        ECerr(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        return 0;
    }
    return 1;
}

static int ecp_secp256k1_field_inv(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, BN_CTX *ctx) {
    secp256k1_fe a_fe, r_fe;

    if (a == NULL || r == NULL)
        return 0;
    if ((BN_cmp(a, group->field) >= 0) || BN_is_negative(a)) {
        BIGNUM *tmp;

        if ((tmp = BN_CTX_get(ctx)) == NULL
            || !BN_nnmod(tmp, a, group->field, ctx)) {
            ECerr(ERR_LIB_EC, ERR_R_BN_LIB);
            return 0;
        }
        a = tmp;
    }
    if (BN_is_zero(a)) {
        ERR_raise(ERR_LIB_EC, EC_R_CANNOT_INVERT);
        return 0;
    }
    if (!ecp_secp256k1_bignum_field_elem(&a_fe, a)) {
        ECerr(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        return 0;
    }
    secp256k1_fe_inv(&r_fe, &a_fe);
    if (!ecp_secp256k1_field_elem_bignum(r, &r_fe)) {
        ECerr(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        return 0;
    }
    return 1;
}

static int ecp_secp256k1_inv_mod_ord(const EC_GROUP *group, BIGNUM *r,
                                     const BIGNUM *x, BN_CTX *ctx)
{
    secp256k1_scalar x_scalar, r_scalar;

    if (x == NULL || r == NULL)
        return 0;
    if ((BN_cmp(x, group->order) >= 0) || BN_is_negative(x)) {
        BIGNUM *tmp;

        if ((tmp = BN_CTX_get(ctx)) == NULL
            || !BN_nnmod(tmp, x, group->order, ctx)) {
            ECerr(ERR_LIB_EC, ERR_R_BN_LIB);
            return 0;
        }
        x = tmp;
    }
    if (BN_is_zero(x)) {
        ERR_raise(ERR_LIB_EC, EC_R_CANNOT_INVERT);
        return 0;
    }
    if (!ecp_secp256k1_bignum_scalar(x_scalar, x)) {
        ECerr(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        return 0;
    }
    secp256k1_scalar_inverse(&r_scalar, &x_scalar);
    if (!ecp_secp256k1_scalar_bignum(r, r_scalar)) {
        ECerr(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        return 0;
    }
    return 1;
}

static int ecp_secp256k1_group_set_curve(EC_GROUP *group, const BIGNUM *p,
                                         const BIGNUM *a, const BIGNUM *b,
                                         BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM *curve_p;
    BN_CTX *new_ctx = NULL;

    static const unsigned char prime[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F
    };

    if (ctx == NULL)
        ctx = new_ctx = BN_CTX_new();
    if (ctx == NULL)
        return 0;

    BN_CTX_start(ctx);
    curve_p = BN_CTX_get(ctx);
    if (curve_p == NULL)
        goto err;
    BN_bin2bn(prime, sizeof(prime), curve_p);
    if (BN_cmp(curve_p, p) != 0 || !BN_is_zero(a) || !BN_is_word(b, 7)) {
        ERR_raise(ERR_LIB_EC, EC_R_WRONG_CURVE_PARAMETERS);
        goto err;
    }
    ret = ossl_ec_GFp_simple_group_set_curve(group, p, a, b, ctx);
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

static int ecp_secp256k1_simple_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                           ossl_unused BN_CTX *ctx)
{
    secp256k1_gej a_j;
    int ret = 0;
    if (!group || !r || !a) {
        goto err;
    }
    if (EC_POINT_is_at_infinity(group, a)) {
        BN_zero(r->Z);
        r->Z_is_one = 0;
        return 1;
    }

    if (!ecp_secp256k1_import_point(&a_j, group, a)) {
        goto err;
    }

    secp256k1_gej_double_nonzero(&a_j, &a_j, NULL);
    if (!ecp_secp256k1_export_point(r, &a_j, group)) {
        goto err;
    }

    ret = 1;

 err:
    return ret;
}

static int ecp_secp256k1_is_on_curve(const EC_GROUP *group, const EC_POINT *a,
                           ossl_unused BN_CTX *ctx)
{
    secp256k1_gej a_j;
    int ret = 0;
    if (!group || !a) {
        goto err;
    }
    if (EC_POINT_is_at_infinity(group, a)) {
        return 1;
    }

    if (!ecp_secp256k1_import_point(&a_j, group, a)) {
        goto err;
    }

    ret = secp256k1_gej_is_valid_var(&a_j);

 err:
    return ret;
}

const EC_METHOD *EC_GFp_secp256k1_method(void)
{
    static const EC_METHOD ret = {
        EC_FLAGS_DEFAULT_OCT,
        NID_X9_62_prime_field,
        ossl_ec_GFp_simple_group_init,
        ossl_ec_GFp_simple_group_finish,
        ossl_ec_GFp_simple_group_clear_finish,
        ossl_ec_GFp_simple_group_copy,
        ecp_secp256k1_group_set_curve,
        ossl_ec_GFp_simple_group_get_curve,
        ossl_ec_GFp_simple_group_get_degree,
        ossl_ec_group_simple_order_bits,
        ossl_ec_GFp_simple_group_check_discriminant,
        ossl_ec_GFp_simple_point_init,
        ossl_ec_GFp_simple_point_finish,
        ossl_ec_GFp_simple_point_clear_finish,
        ossl_ec_GFp_simple_point_copy,
        ossl_ec_GFp_simple_point_set_to_infinity,
        ossl_ec_GFp_simple_point_set_affine_coordinates,
        ecp_secp256k1_get_affine,
        0, 0, 0,
        ossl_ec_GFp_simple_add,
        ecp_secp256k1_simple_dbl,
        ossl_ec_GFp_simple_invert,
        ossl_ec_GFp_simple_is_at_infinity,
        ecp_secp256k1_is_on_curve,
        ossl_ec_GFp_simple_cmp,
        ossl_ec_GFp_simple_make_affine,
        ossl_ec_GFp_simple_points_make_affine,
        ecp_secp256k1_points_mul,                    /* mul */
        0,   /* precompute_mult */
        0,   /* have_precompute_mult */
        ecp_secp256k1_field_mul,    /* field_mul */
        ecp_secp256k1_field_sqr,    /* field_sqr */
        0,                          /* field_div */
        ecp_secp256k1_field_inv,
        0 /* field_encode */,
        0 /* field_decode */,
        0 /* field_set_to_one */,
        ossl_ec_key_simple_priv2oct,
        ossl_ec_key_simple_oct2priv,
        0, /* set private */
        ossl_ec_key_simple_generate_key,
        ossl_ec_key_simple_check_key,
        ossl_ec_key_simple_generate_public_key,
        0, /* keycopy */
        0, /* keyfinish */
        ossl_ecdh_simple_compute_key,
        ossl_ecdsa_simple_sign_setup,
        ossl_ecdsa_simple_sign_sig,
        ossl_ecdsa_simple_verify_sig,
        ecp_secp256k1_inv_mod_ord,                  /* can be #define-d NULL */
        0,                                          /* blind_coordinates */
        0,                                          /* ladder_pre */
        0,                                          /* ladder_step */
        0,                                          /* ladder_post */
        0                                           /* group_full_init */
    };

    return &ret;
}
