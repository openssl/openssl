/***********************************************************************
 * Copyright (c) 2020 Peter Dettman                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODINV64_IMPL_H
#define SECP256K1_MODINV64_IMPL_H

#include <stdint.h>
#include "internal/numbers.h"

#ifndef INT128_MAX
# error "Your compiler doesn't appear to support 128-bit integer types"
#endif

/* This file implements modular inversion based on the paper "Fast constant-time gcd computation and
 * modular inversion" by Daniel J. Bernstein and Bo-Yin Yang.
 *
 * For an explanation of the algorithm, see doc/safegcd_implementation.md. This file contains an
 * implementation for N=62, using 62-bit signed limbs represented as int64_t.
 */


typedef uint128_t secp256k1_uint128;
typedef int128_t secp256k1_int128;

/* Data type for transition matrices (see section 3 of explanation).
 *
 * t = [ u  v ]
 *     [ q  r ]
 */
typedef struct {
    int64_t u, v, q, r;
} secp256k1_modinv64_trans2x2;

/* A signed 62-bit limb representation of integers.
 *
 * Its value is sum(v[i] * 2^(62*i), i=0..4). */
typedef struct {
    int64_t v[5];
} secp256k1_modinv64_signed62;

typedef struct {
    /* The modulus in signed62 notation, must be odd and in [3, 2^256]. */
    secp256k1_modinv64_signed62 modulus;

    /* modulus^{-1} mod 2^62 */
    uint64_t modulus_inv62;
} secp256k1_modinv64_modinfo;

static const secp256k1_modinv64_modinfo secp256k1_const_modinfo_fe = {
    {{-0x1000003D1LL, 0, 0, 0, 256}},
    0x27C7F6E22DDACACFLL
};

static const secp256k1_modinv64_modinfo secp256k1_const_modinfo_scalar = {
    {{0x3FD25E8CD0364141LL, 0x2ABB739ABD2280EELL, -0x15LL, 0, 256}},
    0x34F20099AA774EC1LL
};

static ossl_inline int secp256k1_ctz64_var(uint64_t x) {
    static const uint8_t debruijn[64] = {
        0, 1, 2, 53, 3, 7, 54, 27, 4, 38, 41, 8, 34, 55, 48, 28,
        62, 5, 39, 46, 44, 42, 22, 9, 24, 35, 59, 56, 49, 18, 29, 11,
        63, 52, 6, 26, 37, 40, 33, 47, 61, 45, 43, 21, 23, 58, 17, 10,
        51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12
    };
    return debruijn[(uint64_t)((x & -x) * 0x022FDD63CC95386DU) >> 58];
}

static ossl_inline void secp256k1_u128_load(secp256k1_uint128 *r, uint64_t hi, uint64_t lo) {
    *r = (((uint128_t)hi) << 64) + lo;
}

static ossl_inline void secp256k1_u128_mul(secp256k1_uint128 *r, uint64_t a, uint64_t b) {
   *r = (uint128_t)a * b;
}

static ossl_inline void secp256k1_u128_accum_mul(secp256k1_uint128 *r, uint64_t a, uint64_t b) {
   *r += (uint128_t)a * b;
}

static ossl_inline void secp256k1_u128_accum_u64(secp256k1_uint128 *r, uint64_t a) {
   *r += a;
}

static ossl_inline void secp256k1_u128_rshift(secp256k1_uint128 *r, unsigned int n) {
   *r >>= n;
}

static ossl_inline uint64_t secp256k1_u128_to_u64(const secp256k1_uint128 *a) {
   return (uint64_t)(*a);
}

static ossl_inline uint64_t secp256k1_u128_hi_u64(const secp256k1_uint128 *a) {
   return (uint64_t)(*a >> 64);
}

static ossl_inline void secp256k1_u128_from_u64(secp256k1_uint128 *r, uint64_t a) {
   *r = a;
}

static ossl_inline int secp256k1_u128_check_bits(const secp256k1_uint128 *r, unsigned int n) {
   return (*r >> n == 0);
}

static ossl_inline void secp256k1_i128_load(secp256k1_int128 *r, int64_t hi, uint64_t lo) {
    *r = (((uint128_t)(uint64_t)hi) << 64) + lo;
}

static ossl_inline void secp256k1_i128_mul(secp256k1_int128 *r, int64_t a, int64_t b) {
   *r = (int128_t)a * b;
}

static ossl_inline void secp256k1_i128_accum_mul(secp256k1_int128 *r, int64_t a, int64_t b) {
   int128_t ab = (int128_t)a * b;
   *r += ab;
}

static ossl_inline void secp256k1_i128_det(secp256k1_int128 *r, int64_t a, int64_t b, int64_t c, int64_t d) {
   int128_t ad = (int128_t)a * d;
   int128_t bc = (int128_t)b * c;
   *r = ad - bc;
}

static ossl_inline void secp256k1_i128_rshift(secp256k1_int128 *r, unsigned int n) {
   *r >>= n;
}

static ossl_inline uint64_t secp256k1_i128_to_u64(const secp256k1_int128 *a) {
   return (uint64_t)*a;
}

static ossl_inline int64_t secp256k1_i128_to_i64(const secp256k1_int128 *a) {
   return *a;
}

static ossl_inline void secp256k1_i128_from_i64(secp256k1_int128 *r, int64_t a) {
   *r = a;
}

static ossl_inline int secp256k1_i128_eq_var(const secp256k1_int128 *a, const secp256k1_int128 *b) {
   return *a == *b;
}

static ossl_inline int secp256k1_i128_check_pow2(const secp256k1_int128 *r, unsigned int n, int sign) {
   return (*r == (int128_t)((uint128_t)sign << n));
}

/* Take as input a signed62 number in range (-2*modulus,modulus), and add a multiple of the modulus
 * to it to bring it to range [0,modulus). If sign < 0, the input will also be negated in the
 * process. The input must have limbs in range (-2^62,2^62). The output will have limbs in range
 * [0,2^62). */
static void secp256k1_modinv64_normalize_62(secp256k1_modinv64_signed62 *r, int64_t sign, const secp256k1_modinv64_modinfo *modinfo) {
    const int64_t M62 = (int64_t)(UINT64_MAX >> 2);
    int64_t r0 = r->v[0], r1 = r->v[1], r2 = r->v[2], r3 = r->v[3], r4 = r->v[4];
    volatile int64_t cond_add, cond_negate;

    /* In a first step, add the modulus if the input is negative, and then negate if requested.
     * This brings r from range (-2*modulus,modulus) to range (-modulus,modulus). As all input
     * limbs are in range (-2^62,2^62), this cannot overflow an int64_t. Note that the right
     * shifts below are signed sign-extending shifts (see assumptions.h for tests that that is
     * indeed the behavior of the right shift operator). */
    cond_add = r4 >> 63;
    r0 += modinfo->modulus.v[0] & cond_add;
    r1 += modinfo->modulus.v[1] & cond_add;
    r2 += modinfo->modulus.v[2] & cond_add;
    r3 += modinfo->modulus.v[3] & cond_add;
    r4 += modinfo->modulus.v[4] & cond_add;
    cond_negate = sign >> 63;
    r0 = (r0 ^ cond_negate) - cond_negate;
    r1 = (r1 ^ cond_negate) - cond_negate;
    r2 = (r2 ^ cond_negate) - cond_negate;
    r3 = (r3 ^ cond_negate) - cond_negate;
    r4 = (r4 ^ cond_negate) - cond_negate;
    /* Propagate the top bits, to bring limbs back to range (-2^62,2^62). */
    r1 += r0 >> 62; r0 &= M62;
    r2 += r1 >> 62; r1 &= M62;
    r3 += r2 >> 62; r2 &= M62;
    r4 += r3 >> 62; r3 &= M62;

    /* In a second step add the modulus again if the result is still negative, bringing
     * r to range [0,modulus). */
    cond_add = r4 >> 63;
    r0 += modinfo->modulus.v[0] & cond_add;
    r1 += modinfo->modulus.v[1] & cond_add;
    r2 += modinfo->modulus.v[2] & cond_add;
    r3 += modinfo->modulus.v[3] & cond_add;
    r4 += modinfo->modulus.v[4] & cond_add;
    /* And propagate again. */
    r1 += r0 >> 62; r0 &= M62;
    r2 += r1 >> 62; r1 &= M62;
    r3 += r2 >> 62; r2 &= M62;
    r4 += r3 >> 62; r3 &= M62;

    r->v[0] = r0;
    r->v[1] = r1;
    r->v[2] = r2;
    r->v[3] = r3;
    r->v[4] = r4;
}

/* Compute (t/2^62) * [f, g], where t is a transition matrix scaled by 2^62.
 *
 * This implements the update_fg function from the explanation.
 */
static void secp256k1_modinv64_update_fg_62(secp256k1_modinv64_signed62 *f, secp256k1_modinv64_signed62 *g, const secp256k1_modinv64_trans2x2 *t) {
    const uint64_t M62 = UINT64_MAX >> 2;
    const int64_t f0 = f->v[0], f1 = f->v[1], f2 = f->v[2], f3 = f->v[3], f4 = f->v[4];
    const int64_t g0 = g->v[0], g1 = g->v[1], g2 = g->v[2], g3 = g->v[3], g4 = g->v[4];
    const int64_t u = t->u, v = t->v, q = t->q, r = t->r;
    secp256k1_int128 cf, cg;
    /* Start computing t*[f,g]. */
    secp256k1_i128_mul(&cf, u, f0);
    secp256k1_i128_accum_mul(&cf, v, g0);
    secp256k1_i128_mul(&cg, q, f0);
    secp256k1_i128_accum_mul(&cg, r, g0);
    /* Verify that the bottom 62 bits of the result are zero, and then throw them away. */
    secp256k1_i128_rshift(&cf, 62);
    secp256k1_i128_rshift(&cg, 62);
    /* Compute limb 1 of t*[f,g], and store it as output limb 0 (= down shift). */
    secp256k1_i128_accum_mul(&cf, u, f1);
    secp256k1_i128_accum_mul(&cf, v, g1);
    secp256k1_i128_accum_mul(&cg, q, f1);
    secp256k1_i128_accum_mul(&cg, r, g1);
    f->v[0] = secp256k1_i128_to_u64(&cf) & M62; secp256k1_i128_rshift(&cf, 62);
    g->v[0] = secp256k1_i128_to_u64(&cg) & M62; secp256k1_i128_rshift(&cg, 62);
    /* Compute limb 2 of t*[f,g], and store it as output limb 1. */
    secp256k1_i128_accum_mul(&cf, u, f2);
    secp256k1_i128_accum_mul(&cf, v, g2);
    secp256k1_i128_accum_mul(&cg, q, f2);
    secp256k1_i128_accum_mul(&cg, r, g2);
    f->v[1] = secp256k1_i128_to_u64(&cf) & M62; secp256k1_i128_rshift(&cf, 62);
    g->v[1] = secp256k1_i128_to_u64(&cg) & M62; secp256k1_i128_rshift(&cg, 62);
    /* Compute limb 3 of t*[f,g], and store it as output limb 2. */
    secp256k1_i128_accum_mul(&cf, u, f3);
    secp256k1_i128_accum_mul(&cf, v, g3);
    secp256k1_i128_accum_mul(&cg, q, f3);
    secp256k1_i128_accum_mul(&cg, r, g3);
    f->v[2] = secp256k1_i128_to_u64(&cf) & M62; secp256k1_i128_rshift(&cf, 62);
    g->v[2] = secp256k1_i128_to_u64(&cg) & M62; secp256k1_i128_rshift(&cg, 62);
    /* Compute limb 4 of t*[f,g], and store it as output limb 3. */
    secp256k1_i128_accum_mul(&cf, u, f4);
    secp256k1_i128_accum_mul(&cf, v, g4);
    secp256k1_i128_accum_mul(&cg, q, f4);
    secp256k1_i128_accum_mul(&cg, r, g4);
    f->v[3] = secp256k1_i128_to_u64(&cf) & M62; secp256k1_i128_rshift(&cf, 62);
    g->v[3] = secp256k1_i128_to_u64(&cg) & M62; secp256k1_i128_rshift(&cg, 62);
    /* What remains is limb 5 of t*[f,g]; store it as output limb 4. */
    f->v[4] = secp256k1_i128_to_i64(&cf);
    g->v[4] = secp256k1_i128_to_i64(&cg);
}

/* Compute (t/2^62) * [d, e] mod modulus, where t is a transition matrix scaled by 2^62.
 *
 * On input and output, d and e are in range (-2*modulus,modulus). All output limbs will be in range
 * (-2^62,2^62).
 *
 * This implements the update_de function from the explanation.
 */
static void secp256k1_modinv64_update_de_62(secp256k1_modinv64_signed62 *d, secp256k1_modinv64_signed62 *e, const secp256k1_modinv64_trans2x2 *t, const secp256k1_modinv64_modinfo* modinfo) {
    const uint64_t M62 = UINT64_MAX >> 2;
    const int64_t d0 = d->v[0], d1 = d->v[1], d2 = d->v[2], d3 = d->v[3], d4 = d->v[4];
    const int64_t e0 = e->v[0], e1 = e->v[1], e2 = e->v[2], e3 = e->v[3], e4 = e->v[4];
    const int64_t u = t->u, v = t->v, q = t->q, r = t->r;
    int64_t md, me, sd, se;
    secp256k1_int128 cd, ce;

    /* [md,me] start as zero; plus [u,q] if d is negative; plus [v,r] if e is negative. */
    sd = d4 >> 63;
    se = e4 >> 63;
    md = (u & sd) + (v & se);
    me = (q & sd) + (r & se);
    /* Begin computing t*[d,e]. */
    secp256k1_i128_mul(&cd, u, d0);
    secp256k1_i128_accum_mul(&cd, v, e0);
    secp256k1_i128_mul(&ce, q, d0);
    secp256k1_i128_accum_mul(&ce, r, e0);
    /* Correct md,me so that t*[d,e]+modulus*[md,me] has 62 zero bottom bits. */
    md -= (modinfo->modulus_inv62 * secp256k1_i128_to_u64(&cd) + md) & M62;
    me -= (modinfo->modulus_inv62 * secp256k1_i128_to_u64(&ce) + me) & M62;
    /* Update the beginning of computation for t*[d,e]+modulus*[md,me] now md,me are known. */
    secp256k1_i128_accum_mul(&cd, modinfo->modulus.v[0], md);
    secp256k1_i128_accum_mul(&ce, modinfo->modulus.v[0], me);
    /* Verify that the low 62 bits of the computation are indeed zero, and then throw them away. */
    secp256k1_i128_rshift(&cd, 62);
    secp256k1_i128_rshift(&ce, 62);
    /* Compute limb 1 of t*[d,e]+modulus*[md,me], and store it as output limb 0 (= down shift). */
    secp256k1_i128_accum_mul(&cd, u, d1);
    secp256k1_i128_accum_mul(&cd, v, e1);
    secp256k1_i128_accum_mul(&ce, q, d1);
    secp256k1_i128_accum_mul(&ce, r, e1);
    if (modinfo->modulus.v[1]) { /* Optimize for the case where limb of modulus is zero. */
        secp256k1_i128_accum_mul(&cd, modinfo->modulus.v[1], md);
        secp256k1_i128_accum_mul(&ce, modinfo->modulus.v[1], me);
    }
    d->v[0] = secp256k1_i128_to_u64(&cd) & M62; secp256k1_i128_rshift(&cd, 62);
    e->v[0] = secp256k1_i128_to_u64(&ce) & M62; secp256k1_i128_rshift(&ce, 62);
    /* Compute limb 2 of t*[d,e]+modulus*[md,me], and store it as output limb 1. */
    secp256k1_i128_accum_mul(&cd, u, d2);
    secp256k1_i128_accum_mul(&cd, v, e2);
    secp256k1_i128_accum_mul(&ce, q, d2);
    secp256k1_i128_accum_mul(&ce, r, e2);
    if (modinfo->modulus.v[2]) { /* Optimize for the case where limb of modulus is zero. */
        secp256k1_i128_accum_mul(&cd, modinfo->modulus.v[2], md);
        secp256k1_i128_accum_mul(&ce, modinfo->modulus.v[2], me);
    }
    d->v[1] = secp256k1_i128_to_u64(&cd) & M62; secp256k1_i128_rshift(&cd, 62);
    e->v[1] = secp256k1_i128_to_u64(&ce) & M62; secp256k1_i128_rshift(&ce, 62);
    /* Compute limb 3 of t*[d,e]+modulus*[md,me], and store it as output limb 2. */
    secp256k1_i128_accum_mul(&cd, u, d3);
    secp256k1_i128_accum_mul(&cd, v, e3);
    secp256k1_i128_accum_mul(&ce, q, d3);
    secp256k1_i128_accum_mul(&ce, r, e3);
    if (modinfo->modulus.v[3]) { /* Optimize for the case where limb of modulus is zero. */
        secp256k1_i128_accum_mul(&cd, modinfo->modulus.v[3], md);
        secp256k1_i128_accum_mul(&ce, modinfo->modulus.v[3], me);
    }
    d->v[2] = secp256k1_i128_to_u64(&cd) & M62; secp256k1_i128_rshift(&cd, 62);
    e->v[2] = secp256k1_i128_to_u64(&ce) & M62; secp256k1_i128_rshift(&ce, 62);
    /* Compute limb 4 of t*[d,e]+modulus*[md,me], and store it as output limb 3. */
    secp256k1_i128_accum_mul(&cd, u, d4);
    secp256k1_i128_accum_mul(&cd, v, e4);
    secp256k1_i128_accum_mul(&ce, q, d4);
    secp256k1_i128_accum_mul(&ce, r, e4);
    secp256k1_i128_accum_mul(&cd, modinfo->modulus.v[4], md);
    secp256k1_i128_accum_mul(&ce, modinfo->modulus.v[4], me);
    d->v[3] = secp256k1_i128_to_u64(&cd) & M62; secp256k1_i128_rshift(&cd, 62);
    e->v[3] = secp256k1_i128_to_u64(&ce) & M62; secp256k1_i128_rshift(&ce, 62);
    /* What remains is limb 5 of t*[d,e]+modulus*[md,me]; store it as output limb 4. */
    d->v[4] = secp256k1_i128_to_i64(&cd);
    e->v[4] = secp256k1_i128_to_i64(&ce);
}

/* Compute the transition matrix and eta for 59 divsteps (where zeta=-(delta+1/2)).
 * Note that the transformation matrix is scaled by 2^62 and not 2^59.
 *
 * Input:  zeta: initial zeta
 *         f0:   bottom limb of initial f
 *         g0:   bottom limb of initial g
 * Output: t: transition matrix
 * Return: final zeta
 *
 * Implements the divsteps_n_matrix function from the explanation.
 */
static int64_t secp256k1_modinv64_divsteps_59(int64_t zeta, uint64_t f0, uint64_t g0, secp256k1_modinv64_trans2x2 *t) {
    /* u,v,q,r are the elements of the transformation matrix being built up,
     * starting with the identity matrix times 8 (because the caller expects
     * a result scaled by 2^62). Semantically they are signed integers
     * in range [-2^62,2^62], but here represented as unsigned mod 2^64. This
     * permits left shifting (which is UB for negative numbers). The range
     * being inside [-2^63,2^63) means that casting to signed works correctly.
     */
    uint64_t u = 8, v = 0, q = 0, r = 8;
    volatile uint64_t c1, c2;
    uint64_t mask1, mask2, f = f0, g = g0, x, y, z;
    int i;

    for (i = 3; i < 62; ++i) {
        /* Compute conditional masks for (zeta < 0) and for (g & 1). */
        c1 = zeta >> 63;
        mask1 = c1;
        c2 = g & 1;
        mask2 = -c2;
        /* Compute x,y,z, conditionally negated versions of f,u,v. */
        x = (f ^ mask1) - mask1;
        y = (u ^ mask1) - mask1;
        z = (v ^ mask1) - mask1;
        /* Conditionally add x,y,z to g,q,r. */
        g += x & mask2;
        q += y & mask2;
        r += z & mask2;
        /* In what follows, c1 is a condition mask for (zeta < 0) and (g & 1). */
        mask1 &= mask2;
        /* Conditionally change zeta into -zeta-2 or zeta-1. */
        zeta = (zeta ^ mask1) - 1;
        /* Conditionally add g,q,r to f,u,v. */
        f += g & mask1;
        u += q & mask1;
        v += r & mask1;
        /* Shifts */
        g >>= 1;
        u <<= 1;
        v <<= 1;
    }
    /* Return data in t and return value. */
    t->u = (int64_t)u;
    t->v = (int64_t)v;
    t->q = (int64_t)q;
    t->r = (int64_t)r;

    return zeta;
}

/* Compute the inverse of x modulo modinfo->modulus, and replace x with it (constant time in x). */
static void secp256k1_modinv64(secp256k1_modinv64_signed62 *x, const secp256k1_modinv64_modinfo *modinfo) {
    /* Start with d=0, e=1, f=modulus, g=x, zeta=-1. */
    secp256k1_modinv64_signed62 d = {{0, 0, 0, 0, 0}};
    secp256k1_modinv64_signed62 e = {{1, 0, 0, 0, 0}};
    secp256k1_modinv64_signed62 f = modinfo->modulus;
    secp256k1_modinv64_signed62 g = *x;
    int i;
    int64_t zeta = -1; /* zeta = -(delta+1/2); delta starts at 1/2. */

    /* Do 10 iterations of 59 divsteps each = 590 divsteps. This suffices for 256-bit inputs. */
    for (i = 0; i < 10; ++i) {
        /* Compute transition matrix and new zeta after 59 divsteps. */
        secp256k1_modinv64_trans2x2 t;
        zeta = secp256k1_modinv64_divsteps_59(zeta, f.v[0], g.v[0], &t);
        /* Update d,e using that transition matrix. */
        secp256k1_modinv64_update_de_62(&d, &e, &t, modinfo);
        /* Update f,g using that transition matrix. */
        secp256k1_modinv64_update_fg_62(&f, &g, &t);
    }

    /* Optionally negate d, normalize to [0,modulus), and return it. */
    secp256k1_modinv64_normalize_62(&d, f.v[4], modinfo);
    *x = d;
}


#endif /* SECP256K1_MODINV64_IMPL_H */
