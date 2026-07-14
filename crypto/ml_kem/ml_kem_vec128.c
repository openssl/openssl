/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdint.h>

#if defined(OPENSSL_ML_KEM_S390X) && defined(__s390x__) && defined(__VX__)
#define VX_COMPILER_SUPPORT_VEC128
#include <vecintrin.h>
#endif

#include "ml_kem_local.h"

#if defined(VX_COMPILER_SUPPORT_VEC128)
#include <openssl/byteorder.h>
#include <openssl/rand.h>
#include <openssl/proverr.h>
#include "crypto/ml_kem.h"
#include "internal/common.h"
#include "internal/constant_time.h"
#include "internal/sha3.h"

/* Width of vector registers in bytes */
#define VECTOR_REG_WIDTH_BYTES 16

/*
 * __may_alias__ solves the undefined behavior problem in code like
 * vec_int16_t *out_vec_ptr = (vec_int16_t *)out->c;
 */
typedef int16_t vec_int16_t __attribute__((vector_size(VECTOR_REG_WIDTH_BYTES), __may_alias__));
typedef uint16_t vec_uint16_t __attribute__((vector_size(VECTOR_REG_WIDTH_BYTES), __may_alias__));

typedef int16_t vec_int16_noalias_t __attribute__((vector_size(VECTOR_REG_WIDTH_BYTES)));
typedef uint16_t vec_uint16_noalias_t __attribute__((vector_size(VECTOR_REG_WIDTH_BYTES)));

typedef unsigned char vec_uchar_t __attribute__((vector_size(VECTOR_REG_WIDTH_BYTES)));

/* Our implementation of the vectorized algorithms assumes NUM_INT16_IN_VECTOR == 8. */
#define NUM_INT16_IN_VECTOR (VECTOR_REG_WIDTH_BYTES / ((int)sizeof(int16_t)))

#define DEGREE ML_KEM_DEGREE
#define VECTOR_DEGREE (DEGREE / NUM_INT16_IN_VECTOR)

/*
 * Remainders modulo `kPrime`, for sufficiently small inputs, are computed in
 * constant time via Barrett reduction, and a final call to reduce_once(),
 * which reduces inputs that are at most 2*kPrime and is also constant-time.
 */
static const uint16_t kPrime = ML_KEM_PRIME;
/* q_inv = -3327, satisfying q * q_inv ≡ 1 (mod 2^16) */
static const int16_t kPrime_inverse = -3327;

#define REPEAT_EIGHT_TIMES(x) { x, x, x, x, x, x, x, x }

/* clang-format off */
/*
 * Constants organized by usage pattern for optimal cache performance.
 * Related constants accessed together are grouped to fit within cache lines.
 * s390x cache line size: 64 bytes
 */

/* ===== Group 1: Hot path vector constants (48 bytes, fits in 1 cache line) ===== */
static const vec_int16_t vec_q = REPEAT_EIGHT_TIMES(kPrime);
/* 1353 = R_M^2 mod q = 2285^2 mod q; the Montgomery factor needed to convert
 * an inv-Montgomery value back to standard form (see demontgomerize_vec128). */
static const vec_int16_t demontgomerize_const = REPEAT_EIGHT_TIMES(1353);
/* 20553 = 1353 * q_inv mod 2^16 = 1353 * (-3327) mod 65536; the precomputed
 * twist for demontgomerize_const, passed as a_twist to
 * multiply_montgomery_unreduced. */
static const vec_int16_t demontgomerize_const_twist = REPEAT_EIGHT_TIMES(20553);

/* ===== Group 2: Permutation vectors for even/odd extraction (32 bytes) ===== */
/* Used together in scalar_mult_vec128 and related functions */
static const vec_uchar_t perm_even __attribute__((aligned(16))) = {
    0, 1,    /* element 0 from first vector */
    4, 5,    /* element 2 from first vector */
    8, 9,    /* element 4 from first vector */
    12, 13,  /* element 6 from first vector */
    16, 17,  /* element 0 from second vector */
    20, 21,  /* element 2 from second vector */
    24, 25,  /* element 4 from second vector */
    28, 29   /* element 6 from second vector */
};

static const vec_uchar_t perm_odd __attribute__((aligned(16))) = {
    2, 3,    /* element 1 from first vector */
    6, 7,    /* element 3 from first vector */
    10, 11,  /* element 5 from first vector */
    14, 15,  /* element 7 from first vector */
    18, 19,  /* element 1 from second vector */
    22, 23,  /* element 3 from second vector */
    26, 27,  /* element 5 from second vector */
    30, 31   /* element 7 from second vector */
};

/* ===== Group 3: Permutation vectors for interleaving (32 bytes) ===== */
/* Used together in scalar_mult_vec128 and related functions */
static const vec_uchar_t perm_interleave_low __attribute__((aligned(16))) = {
    0, 1,    /* element 0 from first vector */
    16, 17,  /* element 0 from second vector */
    2, 3,    /* element 1 from first vector */
    18, 19,  /* element 1 from second vector */
    4, 5,    /* element 2 from first vector */
    20, 21,  /* element 2 from second vector */
    6, 7,    /* element 3 from first vector */
    22, 23   /* element 3 from second vector */
};

static const vec_uchar_t perm_interleave_high __attribute__((aligned(16))) = {
    8, 9,    /* element 4 from first vector */
    24, 25,  /* element 4 from second vector */
    10, 11,  /* element 5 from first vector */
    26, 27,  /* element 5 from second vector */
    12, 13,  /* element 6 from first vector */
    28, 29,  /* element 6 from second vector */
    14, 15,  /* element 7 from first vector */
    30, 31   /* element 7 from second vector */
};

/* ===== Group 4: Permutation vectors for half extraction (32 bytes) ===== */
/* Used together in NTT offset==4 stage */
static const vec_uchar_t perm_lower_half __attribute__((aligned(16))) = {
    0, 1, 2, 3, 4, 5, 6, 7,      /* elements 0-3 from first vector */
    16, 17, 18, 19, 20, 21, 22, 23  /* elements 0-3 from second vector */
};

static const vec_uchar_t perm_upper_half __attribute__((aligned(16))) = {
    8, 9, 10, 11, 12, 13, 14, 15,   /* elements 4-7 from first vector */
    24, 25, 26, 27, 28, 29, 30, 31  /* elements 4-7 from second vector */
};

/* Reuse perm_lower_half and perm_upper_half for interleaving halves */
#define perm_interleave_lower_halves perm_lower_half
#define perm_interleave_upper_halves perm_upper_half

/* ===== Group 5: Permutation vectors for element selection (32 bytes) ===== */
/* Used together in NTT offset==2 stage */
static const vec_uchar_t perm_0145 __attribute__((aligned(16))) = {
    0, 1, 2, 3,      /* elements 0,1 from first vector */
    8, 9, 10, 11,    /* elements 4,5 from first vector */
    16, 17, 18, 19,  /* elements 0,1 from second vector */
    24, 25, 26, 27   /* elements 4,5 from second vector */
};

static const vec_uchar_t perm_2367 __attribute__((aligned(16))) = {
    4, 5, 6, 7,      /* elements 2,3 from first vector */
    12, 13, 14, 15,  /* elements 6,7 from first vector */
    20, 21, 22, 23,  /* elements 2,3 from second vector */
    28, 29, 30, 31   /* elements 6,7 from second vector */
};

/* ===== Group 6: Permutation vectors for pair interleaving (32 bytes) ===== */
/* Used together in NTT offset==2 stage */
static const vec_uchar_t perm_interleave_pairs_low __attribute__((aligned(16))) = {
    0, 1, 2, 3,      /* elements 0,1 from first vector */
    16, 17, 18, 19,  /* elements 0,1 from second vector */
    4, 5, 6, 7,      /* elements 2,3 from first vector */
    20, 21, 22, 23   /* elements 2,3 from second vector */
};

static const vec_uchar_t perm_interleave_pairs_high __attribute__((aligned(16))) = {
    8, 9, 10, 11,    /* elements 4,5 from first vector */
    24, 25, 26, 27,  /* elements 4,5 from second vector */
    12, 13, 14, 15,  /* elements 6,7 from first vector */
    28, 29, 30, 31   /* elements 6,7 from second vector */
};

/* ===== Group 7: Large root arrays (each 256 bytes, separate cache lines) ===== */
/*
 * Twiddle factor tables.  All roots derive from 17, a primitive 256th root of
 * unity in Z_q (17^256 ≡ 1 (mod q), 17^128 ≡ -1 (mod q)).
 *
 * Let bitrev7(i) denote the 7-bit reversal of i (e.g. bitrev7(1) = 64).
 *
 * Standard-form twiddles (formula order, i in [0, 128)):
 *   nttRoots[i]    = 17^bitrev7(i)               mod q
 *   invNTTRoots[i] = 17^(-bitrev7(i))            mod q  (inverse roots)
 *   modRoots[i]    = 17^(2*bitrev7(i)+1)         mod q  (base-mult moduli)
 *
 * Montgomery-form twiddle: for any standard-form root z,
 *   z_mont = z * 2285 mod q
 * Key identity: MontMulRaw(a, z_mont) ≡ a * z (mod q), because
 *   MontMulRaw(a, z*2285) ≡ a * z * 2285 * R_M^{-1} ≡ a * z (mod q)
 * since 2285 = R_M mod q, so 2285 * R_M^{-1} ≡ 1 (mod q).
 * This lets each butterfly twiddle multiply be a single MontMulRaw call.
 *
 * kNTTRoots_montgomery:
 * Stored in formula order: kNTTRoots_montgomery[i] = nttRoots[i] * 2285 mod q.
 * Both loops use pre-increment (++roots_ptr before reading), so index 0 is
 * never consumed.  kNTTRoots_montgomery[0] = 2285 happens to equal the
 * trivial root nttRoots[0] * 2285 = 17^0 * 2285, but it is unused padding.
 * The NTT consumes indices 1..127 in natural order across its seven layers:
 *   layer 7 (offset 64): index 1           1 root   (17^bitrev7(1)  * 2285)
 *   layer 6 (offset 32): indices 2..3      2 roots
 *   layer 5 (offset 16): indices 4..7      4 roots
 *   layer 4 (offset  8): indices 8..15     8 roots
 *   layer 3 (offset  4): indices 16..31   16 roots
 *   layer 2 (offset  2): indices 32..63   32 roots
 *   layer 1 (offset  1): indices 64..127  64 roots
 *
 * kInverseNTTRoots_montgomery:
 * The INTT is the mirror of the NTT: it processes the deepest layer first.
 * Therefore the 127 twiddles are stored in reversed-layer order rather than
 * formula order.  Define:
 *   invNTTRoots_formula[i] = invNTTRoots[i] * 2285 mod q  (i in [0, 128))
 * Then kInverseNTTRoots_montgomery is laid out as follows:
 *   index 0           : 2285  (= invNTTRoots_formula[0]; unused padding)
 *   indices   1.. 64  : invNTTRoots_formula[64..127]   INTT layer 1 (offset  2)
 *   indices  65.. 96  : invNTTRoots_formula[32..63]    INTT layer 2 (offset  4)
 *   indices  97..112  : invNTTRoots_formula[16..31]    INTT layer 3 (offset  8)
 *   indices 113..120  : invNTTRoots_formula[8..15]     INTT layer 4 (offset 16)
 *   indices 121..124  : invNTTRoots_formula[4..7]      INTT layer 5 (offset 32)
 *   indices 125..126  : invNTTRoots_formula[2..3]      INTT layer 6 (offset 64)
 *   index  127        : invNTTRoots_formula[1]         INTT layer 7 (offset128)
 * Like the NTT, the INTT loop uses pre-increment, so index 0 is never read.
 * Index 0 is unused padding (demontgomerization uses the separate constants
 * demontgomerize_const and demontgomerize_const_twist, not these arrays).
 *
 * The following Python snippet generates and cross-checks all four arrays:
 *
 *   p, R = 3329, 2285           # prime and Montgomery constant R_M mod q
 *   q_inv = -3327               # q * q_inv ≡ 1 (mod 2^16)
 *
 *   def bitrev7(i):
 *       r = 0
 *       for _ in range(7):
 *           r = (r << 1) | (i & 1); i >>= 1
 *       return r
 *
 *   def to_int16(x): x &= 0xFFFF; return x - 0x10000 if x >= 0x8000 else x
 *
 *   ntt  = [(pow(17,  bitrev7(i), p) * R) % p for i in range(128)]
 *   intt_f = [(pow(17, -bitrev7(i), p) * R) % p for i in range(128)]
 *
 *   # kInverseNTTRoots_montgomery: reversed-layer layout
 *   intt = ([intt_f[0]]
 *           + intt_f[64:128] + intt_f[32:64] + intt_f[16:32]
 *           + intt_f[8:16]  + intt_f[4:8]   + intt_f[2:4]
 *           + [intt_f[1]])
 *
 *   ntt_tw  = [to_int16(v * q_inv) for v in ntt]   # kNTTRoots_twisted
 *   intt_tw = [to_int16(v * q_inv) for v in intt]  # kInverseNTTRoots_twisted
 *
 *   assert ntt   == list(kNTTRoots_montgomery)
 *   assert intt  == list(kInverseNTTRoots_montgomery)
 *   assert ntt_tw  == list(kNTTRoots_twisted)
 *   assert intt_tw == list(kInverseNTTRoots_twisted)
 *
 * Twisted-form arrays (kNTTRoots_twisted, kInverseNTTRoots_twisted):
 *   twisted[i] = montgomery[i] * q_inv mod 2^16  (signed 16-bit)
 * These are the precomputed a_twist values for multiply_montgomery_unreduced,
 * eliminating the low-word multiply from every butterfly call.
 */
static const int16_t kNTTRoots_montgomery[128] = {
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
    2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
    732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
    1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
    107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
    430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
    1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
    418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114,
    3193, 1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475,
    2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628
};

static const int16_t kNTTRoots_twisted[128] = {
    -19, 31499, 14746, 788, 13525, -12402, 28191, -16694, -20906, 27758, -3799,
    -15690, 10690, 1359, -11201, 31164, -5827, 17364, -26360, -29057, 5572,
    -1102, 21439, -26241, -28072, 24313, -10532, 8800, 18427, 8859, 26676,
    -16162, -5689, -6516, 1497, 30967, -23564, 20179, 20711, 25081, -12796,
    26617, 16065, -12441, 9135, -649, -25986, 27837, 19884, -28249, -15886,
    -8898, -28309, 9076, -30198, 18250, 13427, 14017, -29155, -12756, 16832,
    4312, -24155, -17914, -334, 11182, -11477, 13387, -32226, -14233, 20494,
    -21655, -27738, 13131, 945, -4586, -14882, 23093, 6182, 5493, 32011, -32502,
    10631, 30318, 29176, -18741, -28761, 12639, -18485, 20100, 17561, 18525,
    -14430, 19529, -5275, -12618, -31183, 20297, 25435, 2146, -7382, 15356,
    24392, -32384, -20926, -6279, 10946, -14902, 24215, -11044, 16990, 14470,
    10336, -21497, -7933, -20198, -22501, 23211, 10907, -17442, 31637, -23859,
    28644, -20257, 23998, 7757, -17422, 23132
};

static const int16_t kInverseNTTRoots_montgomery[128] = {
    2285, 1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510,
    2535, 1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945,
    1465, 1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872,
    2685, 1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460,
    291, 235, 3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103,
    1275, 2652, 1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499,
    271, 90, 853, 1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838,
    1293, 2314, 552, 2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681,
    130, 1602, 1871, 829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147,
    1752, 2707, 171, 3127, 3042, 1907, 1836, 1517, 359, 758
};

static const int16_t kInverseNTTRoots_twisted[128] = {
    -19, -23131, 17423, -7756, -23997, 20258, -28643, 23860, -31636, 17443,
    -10906, -23210, 22502, 20199, 7934, 21498, -10335, -14469, -16989, 11045,
    -24214, 14903, -10945, 6280, 20927, 32385, -24391, -15355, 7383, -2145,
    -25434, -20296, 31184, 12619, 5276, -19528, 14431, -18524, -17560, -20099,
    18486, -12638, 28762, 18742, -29175, -30317, -10630, 32503, -32010, -5492,
    -6181, -23092, 14883, 4587, -944, -13130, 27739, 21656, -20493, 14234,
    32227, -13386, 11478, -11181, 335, 17915, 24156, -4311, -16831, 12757,
    29156, -14016, -13426, -18249, 30199, -9075, 28310, 8899, 15887, 28250,
    -19883, -27836, 25987, 650, -9134, 12442, -16064, -26616, 12797, -25080,
    -20710, -20178, 23565, -30966, -1496, 6517, 5690, 16163, -26675, -8858,
    -18426, -8799, 10533, -24312, 28073, 26242, -21438, 1103, -5571, 29058,
    26361, -17363, 5828, -31163, 11202, -1358, -10689, 15691, 3800, -27757,
    20907, 16695, -28190, 12403, -13524, -787, -14745, -31498
};

/* ===== Group 8: Vectorized root arrays (each 256 bytes, separate cache lines) ===== */
/*
 * kModRoots_montgomery_vec[v][lane] = modRoots[v*8 + lane] * 2285 mod q,
 * where modRoots[i] = 17^(2*bitrev7(i)+1) mod q are the quadratic-residue
 * class moduli for the 128 NTT-domain factors (X^2 - modRoots[i]).
 * All modRoots[i] are nonzero mod q.  Each entry is in [0, q).
 *
 * kModRoots_twisted_vec[v][lane] = kModRoots_montgomery_vec[v][lane] * q_inv mod 2^16
 * (signed 16-bit), the precomputed a_twist for each modRoot entry.
 * Consecutive pairs in each row satisfy twisted[2i+1] = -twisted[2i],
 * reflecting modRoots_mont[2i+1] = q - modRoots_mont[2i].
 */
static const vec_int16_t kModRoots_montgomery_vec[16] = {
    { 2226, 1103, 430, 2899, 555, 2774, 843, 2486 },
    { 2078, 1251, 871, 2458, 1550, 1779, 105, 3224 },
    { 422, 2907, 587, 2742, 177, 3152, 3094, 235 },
    { 3038, 291, 2869, 460, 1574, 1755, 1653, 1676 },
    { 3083, 246, 778, 2551, 1159, 2170, 3182, 147 },
    { 2552, 777, 1483, 1846, 2727, 602, 1119, 2210 },
    { 1739, 1590, 644, 2685, 2457, 872, 349, 2980 },
    { 418, 2911, 329, 3000, 3173, 156, 3254, 75 },
    { 817, 2512, 1097, 2232, 603, 2726, 610, 2719 },
    { 1322, 2007, 2044, 1285, 1864, 1465, 384, 2945 },
    { 2114, 1215, 3193, 136, 1218, 2111, 1994, 1335 },
    { 2455, 874, 220, 3109, 2142, 1187, 1670, 1659 },
    { 2144, 1185, 1799, 1530, 2051, 1278, 794, 2535 },
    { 1819, 1510, 2475, 854, 2459, 870, 478, 2851 },
    { 3221, 108, 3021, 308, 996, 2333, 991, 2338 },
    { 958, 2371, 1869, 1460, 1522, 1807, 1628, 1701 }
};

static const vec_int16_t kModRoots_twisted_vec[16] = {
    { -334, 335, 11182, -11181, -11477, 11478, 13387, -13386 },
    { -32226, 32227, -14233, 14234, 20494, -20493, -21655, 21656 },
    { -27738, 27739, 13131, -13130, 945, -944, -4586, 4587 },
    { -14882, 14883, 23093, -23092, 6182, -6181, 5493, -5492 },
    { 32011, -32010, -32502, 32503, 10631, -10630, 30318, -30317 },
    { 29176, -29175, -18741, 18742, -28761, 28762, 12639, -12638 },
    { -18485, 18486, 20100, -20099, 17561, -17560, 18525, -18524 },
    { -14430, 14431, 19529, -19528, -5275, 5276, -12618, 12619 },
    { -31183, 31184, 20297, -20296, 25435, -25434, 2146, -2145 },
    { -7382, 7383, 15356, -15355, 24392, -24391, -32384, 32385 },
    { -20926, 20927, -6279, 6280, 10946, -10945, -14902, 14903 },
    { 24215, -24214, -11044, 11045, 16990, -16989, 14470, -14469 },
    { 10336, -10335, -21497, 21498, -7933, 7934, -20198, 20199 },
    { -22501, 22502, 23211, -23210, 10907, -10906, -17442, 17443 },
    { 31637, -31636, -23859, 23860, 28644, -28643, -20257, 20258 },
    { 23998, -23997, 7757, -7756, -17422, 17423, 23132, -23131 }
};

/* clang-format on */

/*
 * reduce_once_vec128: vectorized single-step conditional subtraction.
 *
 * Pre:  Every lane of a, interpreted as an unsigned 16-bit integer, is in [0, 2q).
 * Post: Every lane of the result is in [0, q) and congruent to the
 *       corresponding lane of a modulo q.
 */
static __owur ossl_inline vec_int16_t reduce_once_vec128(vec_int16_t a)
{
    vec_uint16_noalias_t b = (vec_uint16_t)a - (vec_uint16_t)vec_q;
    return (vec_int16_t)vec_min((vec_uint16_noalias_t)a, b);
}

/*
 * nonnegative_residue_class: add q to negative lanes to make all lanes non-negative.
 *
 * Pre:  Every lane of a is a signed 16-bit integer in (-q, 2q)
 *       (the range produced by the Barrett-approximation step inside reduce_fully).
 * Post: Every lane r of the result satisfies 0 <= r < 2q and r ≡ a (mod q).
 *       The result is suitable as input to reduce_once_vec128.
 */
static __owur ossl_inline vec_int16_t nonnegative_residue_class(vec_int16_t a)
{
    vec_uint16_noalias_t b = (vec_uint16_t)a + (vec_uint16_t)vec_q;
    return (vec_int16_t)vec_min((vec_uint16_noalias_t)a, b);
}

/* Barrett reduction constant: floor(2^(floor(log_2(q))-1) * 2^16 / q) = 20158 */
static const vec_int16_noalias_t v_reduce_fully = REPEAT_EIGHT_TIMES(20158);

/*
 * reduce_fully: vectorized Barrett reduction for signed values.
 *
 * Pre:  Every lane of a is a signed 16-bit integer with -2^16 < a[i] < 2^16.
 * Post: Every lane of the result is in [0, q) and congruent to a[i] mod q.
 *
 * Algorithm:
 *   v := 20158 = floor(2^(floor(log_2(q))-1) * 2^16 / q)
 *   t := mulh(a, v) >> 10    -- approximates floor(a[i] / q), t in [-64, 64]
 *   u := a - t * q           -- u in (-q, 2q)
 *   r := nonnegative_residue_class(u)  -- r in [0, 2q)
 *   result := reduce_once_vec128(r)    -- result in [0, q)
 */
static __owur ossl_inline vec_int16_t reduce_fully(vec_int16_t a)
{
    /* Shift by 10 to complete Barrett reduction: (a * v_reduce_fully) >> 26 */
    vec_int16_t t = vec_mulh((vec_int16_noalias_t)a, v_reduce_fully) >> 10;
    t *= vec_q;
    return reduce_once_vec128(nonnegative_residue_class(a - t));
}

/*
 * multiply_montgomery_unreduced: raw Montgomery multiplication (MontMulRaw)
 * using a caller-supplied precomputed twist.
 *
 * Algorithm (Seiler 2018, Algorithm 3):
 *
 *   k    = (a_twist * b) mod 2^16
 *   c    = mulh(k, q)
 *   z_hi = mulh(a, b)
 *   r    = z_hi - c
 *
 * where
 *
 *   a_twist = a * q_inv mod 2^16,
 *   q_inv   = -3327,
 *   q * q_inv ≡ 1 (mod 2^16).
 *
 * The twist is precomputed by the caller so that a single broadcasted value
 * can be reused across an entire scalar loop, eliminating the per-call
 * multiply by q_inv.
 *
 * Correctness
 * ===========
 * For every lane,
 *   r ≡ a[i] * b[i] * R_M^{-1} (mod q),
 * where R_M = 2^16.
 *
 * No canonical reduction to [0,q) is performed.
 *
 * Preconditions
 * =============
 *   0 <= a[i] < q
 *   a_twist[i] = a[i] * q_inv mod 2^16
 *   b[i] is interpreted as a signed 16-bit integer
 *
 * Range bounds
 * ============
 * Write
 *   z_hi = mulh(a,b),
 *   c    = mulh(k,q).
 * Since k is a signed 16-bit value and q = 3329,
 *   |c| <= floor((3329 * 2^15) / 2^16) = 1664.
 * The bound on z_hi depends on the ranges of both a and b.
 *
 * Case 1: a,b ∈ [0,q)
 *   max(a) = max(b) = q-1 = 3328
 *   |z_hi| <= floor(3328^2 / 2^16) = 169.
 *   Therefore |r| <= 169 + 1664 = 1833 < q.
 *
 * Case 2: a ∈ [0,q), b ∈ [-8q,8q]
 *   max(a) = 3328,
 *   max(|b|) = 8q = 26632
 *   |z_hi| <= floor((3328 * 26632) / 2^16) = 1352.
 *   Therefore |r| <= 1352 + 1664 = 3016 < q.
 *
 *   This is the range relevant to NTT twiddle multiplication.
 *
 * Case 3: a ∈ [0,q), arbitrary signed int16_t b
 *   max(a) = 3328,
 *   max(|b|) = 32768
 *   |z_hi| <= floor((3328 * 32768) / 2^16) = 1664.
 *   Therefore |r| <= 1664 + 1664 = 3328 < q.
 *
 * Case 4: a,b ∈ [0,2q-2]
 *   max(a) = max(b) = 2q-2 = 6656
 *   |z_hi| <= floor(6656^2 / 2^16) = 676.
 *   Therefore |r| <= 676 + 1664 = 2340 < q.
 */
static __owur ossl_inline vec_int16_t multiply_montgomery_unreduced(vec_int16_t b,
    vec_int16_t a,
    vec_int16_t a_twist)
{
    vec_int16_t k = a_twist * b;
    vec_int16_t c = vec_mulh((vec_int16_noalias_t)k, (vec_int16_noalias_t)vec_q);
    vec_int16_t z_high = vec_mulh((vec_int16_noalias_t)a, (vec_int16_noalias_t)b);
    vec_int16_t r = z_high - c;
    return r;
}

/*
 * demontgomerize_vec128: convert a vector from inverse-Montgomery form to
 * standard form.
 *
 * Computes MontMul(a, 1353) per lane, where 1353 = R_M^2 mod q = 2285^2 mod q.
 *
 * Correctness: if a[i] ≡ x[i] * R_M^{-1} (mod q) (inverse-Montgomery form)
 * and 0 <= a[i] < q, then:
 *   MontMul(a[i], 1353) ≡ a[i] * 1353 * R_M^{-1}
 *                       ≡ x[i] * R_M^{-1} * 1353 * R_M^{-1}
 *                       ≡ x[i] * ((R_M^{-1})^2 * 1353)   (mod q)
 *                       ≡ x[i]                           (mod q)
 * since (R_M^{-1})^2 * 1353 ≡ 1 (mod q)  (i.e. 1353 = (R_M^{-1})^{-2} mod q
 * = R_M^2 mod q = 2285^2 mod q).
 *
 * Pre:  Every lane of a satisfies |a[i]| <= 8 * q.
 * Post: Every lane of the result is in [0, q) and equals the logical
 *       coefficient x[i] such that a[i] ≡ x[i] * R_M^{-1} (mod q).
 */
static __owur ossl_inline vec_int16_t demontgomerize_vec128(vec_int16_t a)
{
    vec_int16_t unreduced_product = multiply_montgomery_unreduced(a, demontgomerize_const, demontgomerize_const_twist);
    return nonnegative_residue_class(unreduced_product);
}

/*
 * demontgomerize_scalar_vec128: in-place demontgomerization of a full scalar.
 *
 * Applies demontgomerize_vec128 to each 8-lane vector chunk of out->c.
 *
 * Pre:  Every coefficient out->c[i] satisfies |out->c[i]| < 8 * q.
 * Post: Every coefficient out->c[i] is replaced by the standard-form value
 *       x such that the old out->c[i] ≡ x * R_M^{-1} (mod q), with
 *       0 <= out->c[i] < q.
 */
static ossl_inline void demontgomerize_scalar_vec128(scalar *out)
{
    vec_int16_t *out_vec = (vec_int16_t *)out->c;
    for (int i = 0; i < VECTOR_DEGREE; ++i)
        out_vec[i] = demontgomerize_vec128(out_vec[i]);
}

/*
 * multiply_512_montgomery_unreduced: raw Montgomery multiplication
 * by the constant 512 = 2^9, using bit-shift specializations.
 *
 * Because a_twist = 512 * q_inv mod 2^16 and the product k = a_twist * b
 * mod 2^16 equals (b << 9) mod 2^16, the twist step is a left-shift by 9.
 * The high-word z_hi = mulh(512, b) simplifies to b >> 7 since
 * mulh(2^9, b) = floor(2^9 * b / 2^16) = b >> 7.
 *
 * Pre:  Every lane of b satisfies |b[i]| < q.
 * Post: Every lane of the result r satisfies -q < r < q and
 *       r ≡ b[i] * 512 * R_M^{-1} (mod q).
 *       No canonical reduction to [0, q) is performed.
 */
static __owur ossl_inline vec_int16_t multiply_512_montgomery_unreduced(vec_int16_t b)
{
    /* Multiply by 512 = 2^9 using shift, then compute high part >> 7 */
    vec_int16_t k = b << 9;
    vec_int16_t c = vec_mulh((vec_int16_noalias_t)k, (vec_int16_noalias_t)vec_q);
    vec_int16_t z_high = (vec_int16_noalias_t)b >> 7;
    vec_int16_t r = z_high - c;
    return r;
}

/*
 * multiply_512_montgomery: fully reduced Montgomery multiplication by 512.
 *
 * Pre:  Every lane of b satisfies |b[i]| < q.
 * Post: Every lane of the result is in [0, q) and equals
 *       b[i] * 512 * R_M^{-1} mod q.
 */
static __owur ossl_inline vec_int16_t multiply_512_montgomery(vec_int16_t b)
{
    vec_int16_t unreduced_product = multiply_512_montgomery_unreduced(b);
    return reduce_once_vec128(unreduced_product + vec_q);
}

/*
 * scalar_mult_const_512_vec128: in-place multiplication of every coefficient
 * of s by 512, used as the final normalization step of the inverse NTT.
 *
 * The reference INTT normalizes by multiplying by inverseDegree = 3303 =
 * 128^{-1} mod q = (n/2)^{-1} mod q.  The vectorized pipeline instead
 * multiplies by 512 and compensates by entering the INTT from inverse-
 * Montgomery form: since 512 * R_M^{-1} ≡ 3303 (mod q)  (verify: 512 * 169
 * = 86528 = 25 * 3329 + 3303), multiplying an inv-Montgomery value by 512
 * via MontMulRaw gives the same result as multiplying the standard-form value
 * by 3303.
 *
 * Pre:  Every coefficient s->c[i] satisfies |s->c[i]| < q
 *       (produced by a preceding multiply_montgomery_unreduced).
 * Post: Every coefficient s->c[i] is in [0, q) and equals the old value
 *       times 512 * R_M^{-1} mod q = 3303.
 */
static ossl_inline void scalar_mult_const_512_vec128(scalar *s)
{
    vec_int16_t *curr = (vec_int16_t *)s->c, *end = curr + VECTOR_DEGREE;

    do {
        *curr = multiply_512_montgomery(*curr);
        curr++;
    } while (curr < end);
}

/*-
 * scalar_ntt_vec128: FIPS 203, Section 4.3, Algorithm 9: "NTT".
 *
 * In-place number theoretic transform of a given scalar.  ML-KEM's prime 3329
 * does not have a 512th root of unity, so this transform omits the last
 * Cooley-Tukey layer.  The 128 relevant roots of unity are stored in
 * kNTTRoots_montgomery.  The output should be interpreted as 128 elements of
 * GF(3329^2), with consecutive pairs of entries in s->c forming each element.
 *
 * Root index schedule: kNTTRoots_montgomery[0] is unused here (it holds 2285
 * = R_M mod q, used in demontgomerization).  Root consumption starts at index
 * 1 and advances by 1 per block across all 7 layers in bit-reversal order.
 * The same schedule applies to the parallel twisted array kNTTRoots_twisted.
 *
 * Pre:  Every coefficient s->c[i] is in [0, q)  (Scalar / standard form).
 * Post: Every coefficient s->c[i] is in [0, q)  (NTTScalar / standard form),
 *       and s->c encodes NTT(s_in) in NTT-domain representation.
 *
 * Butterfly (lazy Cooley-Tukey, used in all 7 layers):
 *   Given even, odd in Z with twiddle zeta_mont = NTTRoots_montgomery[idx]:
 *     t        = MontMulRaw(odd, zeta_mont)  -- t in [-3016, 3016] subset [-q,q]
 *     new_even = even + t
 *     new_odd  = even - t
 *   Pre:  |even|, |odd| < B*q <= 8*q for the current layer bound B.
 *   Post: |new_even|, |new_odd| < (B+1)*q <= 9*q (bound grows by 1 per layer).
 *   Congruence: new_even ≡ even + odd * zeta_std (mod q)
 *               new_odd  ≡ even - odd * zeta_std (mod q)
 *   where zeta_std = nttRoots[idx] is the standard-form twiddle, and the
 *   Montgomery encoding ensures MontMulRaw(odd, zeta_mont) ≡ odd * zeta_std
 *   (mod q) via 2285 * R_M^{-1} ≡ 1 (mod q)  (2285 = R_M mod q).
 *
 * Overflow analysis:
 *   Starting bound B = 1 (input in [0, q)).  After each of the 7 lazy layers
 *   B increases by 1, giving B = 8 after layer 7.
 *   9 * q = 9 * 3329 = 29961 < 2^15, so no signed 16-bit overflow occurs
 *   across all 7 layers.
 *
 * The final layer (Stage 3, offset == 2) applies reduce_fully to each output,
 * which resets coefficients to [0, q) and satisfies the NTTScalar post-condition.
 * The intermediate layers (Stages 1 and 2) do not reduce, relying on the
 * overflow analysis above.
 */
void ossl_ml_kem_scalar_ntt_vec128(scalar *s)
{
    int offset = DEGREE / 2;

    vec_int16_t *curr_vec = (vec_int16_t *)s->c;
    const vec_int16_t *vec_end = curr_vec + VECTOR_DEGREE;

    const int16_t *roots_ptr = kNTTRoots_montgomery;
    const int16_t *roots_twisted_ptr = kNTTRoots_twisted;

    /* ===== Stage 1: Process offsets >= 8 (butterfly operations) ===== */
    do {
        vec_int16_t *curr = curr_vec, *peer;

        do {
            vec_int16_t *pause = curr + (offset / NUM_INT16_IN_VECTOR);
            int16_t zeta_orig = *++roots_ptr;
            int16_t zeta_orig_twisted = *++roots_twisted_ptr;
            vec_int16_t zeta_vec = vec_splats(zeta_orig);
            vec_int16_t zeta_vec_twisted = vec_splats(zeta_orig_twisted);

            peer = pause;
            do {
                vec_int16_t even_vec = *curr;
                vec_int16_t peer_vec = *peer;

                vec_int16_t t = multiply_montgomery_unreduced(peer_vec, zeta_vec, zeta_vec_twisted);
                vec_int16_t new_curr_vec = even_vec + t;
                vec_int16_t new_peer_vec = even_vec - t;

                *peer++ = new_peer_vec;
                *curr++ = new_curr_vec;
            } while (curr < pause);
        } while ((curr = peer) < vec_end);
    } while ((offset >>= 1) >= 8);

    /* ===== Stage 2: Process offset == 4 (half-vector operations) ===== */
    vec_int16_t *curr_out = (vec_int16_t *)s->c;
    vec_int16_t *end = curr_out + VECTOR_DEGREE;
    vec_int16_t *curr = curr_vec;

    do {
        int16_t zeta1 = *++roots_ptr;
        int16_t zeta2 = *++roots_ptr;
        vec_int16_t zeta_vec = vec_splats(zeta1);
        zeta_vec = vec_perm((vec_int16_noalias_t)zeta_vec, vec_splats(zeta2), perm_interleave_lower_halves);
        int16_t zeta1_twisted = *++roots_twisted_ptr;
        int16_t zeta2_twisted = *++roots_twisted_ptr;
        vec_int16_t zeta_vec_twisted = vec_splats(zeta1_twisted);
        zeta_vec_twisted = vec_perm((vec_int16_noalias_t)zeta_vec_twisted, vec_splats(zeta2_twisted), perm_interleave_lower_halves);

        vec_int16_noalias_t curr_vec1 = *curr++;
        vec_int16_noalias_t curr_vec2 = *curr++;
        vec_int16_t even_vec = vec_perm(curr_vec1, curr_vec2, perm_lower_half);
        vec_int16_t peer_vec = vec_perm(curr_vec1, curr_vec2, perm_upper_half);

        vec_int16_t t = multiply_montgomery_unreduced(peer_vec, zeta_vec, zeta_vec_twisted);
        vec_int16_noalias_t new_curr_vec = even_vec + t;
        vec_int16_noalias_t new_peer_vec = even_vec - t;

        *curr_out++ = vec_perm(new_curr_vec, new_peer_vec, perm_interleave_lower_halves);
        *curr_out++ = vec_perm(new_curr_vec, new_peer_vec, perm_interleave_upper_halves);
    } while (curr_out < end);

    /* ===== Stage 3: Process offset == 2 (pair operations with full reduction) ===== */
    curr_out = (vec_int16_t *)s->c;
    end = curr_out + VECTOR_DEGREE;
    curr = curr_vec;

    do {
        int16_t zeta1 = *++roots_ptr;
        int16_t zeta2 = *++roots_ptr;
        int16_t zeta3 = *++roots_ptr;
        int16_t zeta4 = *++roots_ptr;
        vec_int16_noalias_t zeta_pair1 = vec_perm(vec_splats(zeta1), vec_splats(zeta2), perm_interleave_pairs_low);
        vec_int16_noalias_t zeta_pair2 = vec_perm(vec_splats(zeta3), vec_splats(zeta4), perm_interleave_pairs_low);
        vec_int16_noalias_t zeta_vec = vec_perm(zeta_pair1, zeta_pair2, perm_interleave_lower_halves);
        int16_t zeta1_twisted = *++roots_twisted_ptr;
        int16_t zeta2_twisted = *++roots_twisted_ptr;
        int16_t zeta3_twisted = *++roots_twisted_ptr;
        int16_t zeta4_twisted = *++roots_twisted_ptr;
        vec_int16_noalias_t zeta_pair1_twisted = vec_perm(vec_splats(zeta1_twisted), vec_splats(zeta2_twisted), perm_interleave_pairs_low);
        vec_int16_noalias_t zeta_pair2_twisted = vec_perm(vec_splats(zeta3_twisted), vec_splats(zeta4_twisted), perm_interleave_pairs_low);
        vec_int16_t zeta_vec_twisted = vec_perm(zeta_pair1_twisted, zeta_pair2_twisted, perm_interleave_lower_halves);

        vec_int16_noalias_t curr_vec1 = *curr++;
        vec_int16_noalias_t curr_vec2 = *curr++;
        vec_int16_t even_vec = vec_perm(curr_vec1, curr_vec2, perm_0145);
        vec_int16_t peer_vec = vec_perm(curr_vec1, curr_vec2, perm_2367);

        vec_int16_t t = multiply_montgomery_unreduced(peer_vec, zeta_vec, zeta_vec_twisted);
        vec_int16_noalias_t new_curr_vec = reduce_fully(even_vec + t);
        vec_int16_noalias_t new_peer_vec = reduce_fully(even_vec - t);

        *curr_out++ = vec_perm(new_curr_vec, new_peer_vec, perm_interleave_pairs_low);
        *curr_out++ = vec_perm(new_curr_vec, new_peer_vec, perm_interleave_pairs_high);
    } while (curr_out < end);
}

/*-
 * scalar_inverse_ntt_vec128_raw: FIPS 203, Section 4.3, Algorithm 10: "NTT^(-1)"
 * (raw, without the final normalization multiply-by-512 step).
 *
 * In-place inverse number theoretic transform.  Pairs of consecutive entries in
 * s->c are interpreted as elements of GF(3329^2).  As with the forward NTT,
 * the first Gentleman-Sande layer is omitted because 3329 has no 512th root of
 * unity; the 128 relevant inverse roots are stored in kInverseNTTRoots_montgomery.
 *
 * Pre:  Every coefficient s->c[i] is in [0, q)  (NTTScalar / standard form).
 * Post: Every coefficient s->c[i] is in [0, q), encoding INTT(s_in) scaled by
 *       (n/2) = 128.  The caller must multiply by (n/2)^{-1} mod q = 3303,
 *       which scalar_mult_const_512_vec128 achieves as 512 * R_M^{-1} mod q.
 *
 * Butterfly (lazy Gentleman-Sande, used in all 7 layers):
 *   Given even, odd in Z with twiddle zeta_mont = InvNTTRoots_montgomery[idx]:
 *     new_even = even + odd
 *     t        = even - odd                      -- |t| < (2B+1)q <= 9q < 2^15
 *     new_odd  = MontMulRaw(zeta_mont, t)        -- |new_odd| in (-q, q)
 *   Pre:  |even|, |odd| < B*q for the current layer bound B.
 *   Post: |new_even| < 2*B*q  (sum — bound doubles each layer).
 *         |new_odd|  < q      (MontMulRaw resets the twiddle term to (-q, q)).
 *   Congruence: new_even ≡ even + odd              (mod q)
 *               new_odd  ≡ zeta_std * (even - odd) (mod q)
 *   where zeta_std = InvNTTRoots[idx].
 *
 * Overflow analysis and placement of reduce_fully:
 *   The MontMulRaw twiddle product new_odd is always reset to (-q, q), so only
 *   new_even accumulates growth.  Starting from B = 1 (input in [0, q)):
 *
 *     Layer  1 (offset  2): B_in = 1 -> |new_even| < 2q        (B = 2)
 *     Layer  2 (offset  4): B_in = 2 -> |new_even| < 4q        (B = 4)
 *     Layer  3 (offset  8): B_in = 4 -> |new_even| < 8q        (B = 8)
 *
 *   After layer 3: 8q = 8 * 3329 = 26632 < 2^15, still safe.  But one more
 *   doubling would give 16q = 53264 > 2^15, causing overflow.  Therefore
 *   reduce_fully is applied to new_even at the END of layer 3 (offset 8),
 *   resetting B back to 1.
 *
 *     Layer  4 (offset 16): B_in = 1 -> |new_even| < 2q        (B = 2)
 *     Layer  5 (offset 32): B_in = 2 -> |new_even| < 4q        (B = 4)
 *     Layer  6 (offset 64): B_in = 4 -> |new_even| < 8q        (B = 8)
 *
 *   Same argument: reduce_fully is applied to new_even at the END of layer 6
 *   (offset 64), resetting B to 1.
 *
 *     Layer  7 (offset 128): B_in = 1 -> |new_even| < 2q < 2^15, safe.
 *
 *   new_odd is always in (-q, q) after MontMulRaw, so it never overflows.
 *   The reduce_fully calls on new_odd are NOT present; only new_even is reduced.
 */
static void scalar_inverse_ntt_vec128_raw(scalar *s)
{
    int offset;
    const int16_t *roots_ptr = kInverseNTTRoots_montgomery;
    const int16_t *roots_twisted_ptr = kInverseNTTRoots_twisted;

    vec_int16_t *curr_vec = (vec_int16_t *)s->c;
    vec_int16_t *curr = curr_vec;
    vec_int16_t *curr_out = curr_vec;
    const vec_int16_t *vec_end = curr_vec + VECTOR_DEGREE;

    /* ===== Stage 1: Process offset == 2 (pair operations) ===== */
    do {
        int16_t zeta1 = *++roots_ptr;
        int16_t zeta2 = *++roots_ptr;
        int16_t zeta3 = *++roots_ptr;
        int16_t zeta4 = *++roots_ptr;
        vec_int16_noalias_t zeta_pair1 = vec_perm(vec_splats(zeta1), vec_splats(zeta2), perm_interleave_pairs_low);
        vec_int16_noalias_t zeta_pair2 = vec_perm(vec_splats(zeta3), vec_splats(zeta4), perm_interleave_pairs_low);
        vec_int16_t zeta_vec = vec_perm(zeta_pair1, zeta_pair2, perm_interleave_lower_halves);
        int16_t zeta1_twisted = *++roots_twisted_ptr;
        int16_t zeta2_twisted = *++roots_twisted_ptr;
        int16_t zeta3_twisted = *++roots_twisted_ptr;
        int16_t zeta4_twisted = *++roots_twisted_ptr;
        vec_int16_noalias_t zeta_pair1_twisted = vec_perm(vec_splats(zeta1_twisted), vec_splats(zeta2_twisted), perm_interleave_pairs_low);
        vec_int16_noalias_t zeta_pair2_twisted = vec_perm(vec_splats(zeta3_twisted), vec_splats(zeta4_twisted), perm_interleave_pairs_low);
        vec_int16_t zeta_vec_twisted = vec_perm(zeta_pair1_twisted, zeta_pair2_twisted, perm_interleave_lower_halves);

        vec_int16_noalias_t curr_vec1 = *curr++;
        vec_int16_noalias_t curr_vec2 = *curr++;
        vec_int16_t even_vec = vec_perm(curr_vec1, curr_vec2, perm_0145);
        vec_int16_t odd_vec = vec_perm(curr_vec1, curr_vec2, perm_2367);

        vec_int16_noalias_t new_curr_vec = (even_vec + odd_vec);
        vec_int16_t t = (even_vec - odd_vec);
        vec_int16_noalias_t new_peer_vec = multiply_montgomery_unreduced(t, zeta_vec, zeta_vec_twisted);

        *curr_out++ = vec_perm(new_curr_vec, new_peer_vec, perm_interleave_pairs_low);
        *curr_out++ = vec_perm(new_curr_vec, new_peer_vec, perm_interleave_pairs_high);
    } while (curr_out < vec_end);

    /* ===== Stage 2: Process offset == 4 (half-vector operations) ===== */
    curr_vec = (vec_int16_t *)s->c;
    curr = curr_vec;
    curr_out = curr_vec;
    do {
        int16_t zeta1 = *++roots_ptr;
        int16_t zeta2 = *++roots_ptr;
        vec_int16_noalias_t zeta_vec = vec_splats(zeta1);
        zeta_vec = vec_perm(zeta_vec, vec_splats(zeta2), perm_interleave_lower_halves);
        int16_t zeta1_twisted = *++roots_twisted_ptr;
        int16_t zeta2_twisted = *++roots_twisted_ptr;
        vec_int16_noalias_t zeta_vec_twisted = vec_splats(zeta1_twisted);
        zeta_vec_twisted = vec_perm(zeta_vec_twisted, vec_splats(zeta2_twisted), perm_interleave_lower_halves);

        vec_int16_noalias_t curr_vec1 = *curr++;
        vec_int16_noalias_t curr_vec2 = *curr++;
        vec_int16_t even_vec = vec_perm(curr_vec1, curr_vec2, perm_lower_half);
        vec_int16_t odd_vec = vec_perm(curr_vec1, curr_vec2, perm_upper_half);

        vec_int16_noalias_t new_curr_vec = (even_vec + odd_vec);
        vec_int16_t t = (even_vec - odd_vec);
        vec_int16_noalias_t new_peer_vec = multiply_montgomery_unreduced(t, zeta_vec, zeta_vec_twisted);

        *curr_out++ = vec_perm(new_curr_vec, new_peer_vec, perm_interleave_lower_halves);
        *curr_out++ = vec_perm(new_curr_vec, new_peer_vec, perm_interleave_upper_halves);
    } while (curr_out < vec_end);

    /* ===== Stage 3: Process offsets >= 8 (butterfly operations) ===== */
    offset = 8;
    curr_vec = (vec_int16_t *)s->c;
    curr = curr_vec;
    curr_out = curr_vec;
    do {
        vec_int16_t *inner_curr = curr_vec, *peer;

        do {
            vec_int16_t *pause = inner_curr + (offset / NUM_INT16_IN_VECTOR);
            int16_t zeta = *++roots_ptr;
            int16_t zeta_twisted = *++roots_twisted_ptr;
            vec_int16_t zeta_vec = vec_splats(zeta);
            vec_int16_t zeta_vec_twisted = vec_splats(zeta_twisted);

            peer = pause;
            do {
                vec_int16_t even_vec = *inner_curr;
                vec_int16_t odd_vec = *peer;

                vec_int16_t new_curr_vec = even_vec + odd_vec;
                vec_int16_t t = even_vec - odd_vec;
                vec_int16_t new_peer_vec = multiply_montgomery_unreduced(t, zeta_vec, zeta_vec_twisted);
                /*
                 * Reset the even output to [0, q) at the end of layers 3
                 * (offset 8) and 6 (offset 64) to prevent signed 16-bit
                 * overflow in the next group of three layers (see overflow
                 * analysis in the function comment above).
                 */
                if (offset == 8 || offset == 64) {
                    new_curr_vec = reduce_fully(new_curr_vec);
                }
                *peer++ = new_peer_vec;
                *inner_curr++ = new_curr_vec;
            } while (inner_curr < pause);
        } while ((inner_curr = peer) < vec_end);
    } while ((offset <<= 1) < DEGREE);
}

void ossl_ml_kem_scalar_inverse_ntt_vec128(scalar *s)
{
    scalar_inverse_ntt_vec128_raw(s);
    scalar_mult_const_512_vec128(s);
}

static ossl_inline void scalar_inverse_ntt_vec128_demontgomerize(scalar *s)
{
    demontgomerize_scalar_vec128(s);
    scalar_inverse_ntt_vec128_raw(s);
    scalar_mult_const_512_vec128(s);
}

/*
 * multiply_Fq2_montgomery_unreduced: one step of the NTT-domain base-multiplication loop.
 *
 * Multiplies two pairs of coefficient vectors in the ring
 * GF(q)[X]/(X^2 - modRoot[i]) using the twisted Karatsuba algorithm in
 * inverse-Montgomery form.  Operates on two 8-lane vector registers at a time
 * (16 coefficients = 8 coefficient pairs).
 *
 * Let (l0, l1) and (r0, r1) be the even- and odd-indexed coefficients
 * extracted from the two lhs/rhs vector pairs.  The algorithm computes:
 *
 *   P  = MontMulRaw(l0 + l1, r0 + r1)  -- l0 + l1, r0 + r1 in [0,2q-2] => |P| <= 2340
 *   P0 = MontMulRaw(l0, r0)            -- l0, r0 in [0,q) => |P0| <= 1833
 *   P1 = MontMulRaw(l1, r1)            -- l1, r1 in [0,q) => |P1| <= 1833
 *   result_odd  = P - (P0 + P1)        -- |result_odd| <= 2340 + 2*1833 = 6006
 *   result_even = P0 + MontMulRaw(P1, root)  -- |result_even| <= 2*1833 = 3666
 *
 * Correctness:
 *   result_even ≡ (l0*r0 + l1*r1 * root * 169) * 169  (mod q)
 *   result_odd  ≡ (l0*r1 + l1*r0) * 169               (mod q)
 * Both outputs are in inverse-Montgomery form; a subsequent
 * demontgomerize_vec128 call recovers the standard-form product.
 *
 * Pre:  lhs_coeffs[0..1] and rhs_coeffs[0..1] hold two consecutive 8-lane
 *       vector registers whose coefficients are in [0, q).
 *       roots[i] = modRoot[i/2] in standard form (kModRoots_montgomery_vec
 *       stores these as Montgomery-encoded twiddles with 0 <= roots[i] < q).
 *       roots_twisted[i] = roots[i] * q_inv mod 2^16 (kModRoots_twisted_vec).
 * Post: *result_even and *result_odd contain the even and odd output
 *       coefficients in inverse-Montgomery form.
 *       result_odd  in [-6006, 6006]
 *       result_even in [-3666, 3666].
 */
static ossl_inline void multiply_Fq2_montgomery_unreduced(const vec_int16_noalias_t *lhs_coeffs,
    const vec_int16_noalias_t *rhs_coeffs,
    vec_int16_t roots,
    vec_int16_t roots_twisted,
    vec_int16_noalias_t *result_even,
    vec_int16_noalias_t *result_odd)
{
    static const vec_uint16_noalias_t q_inv = REPEAT_EIGHT_TIMES((uint16_t)kPrime_inverse);
    vec_int16_t l0_vec = vec_perm(lhs_coeffs[0], lhs_coeffs[1], perm_even);
    vec_int16_t l1_vec = vec_perm(lhs_coeffs[0], lhs_coeffs[1], perm_odd);
    vec_int16_t r0_vec = vec_perm(rhs_coeffs[0], rhs_coeffs[1], perm_even);
    vec_int16_t r1_vec = vec_perm(rhs_coeffs[0], rhs_coeffs[1], perm_odd);

    /*
     * Twisted Karatsuba: 3 Montgomery multiplications.
     * Precompute the two lhs twists (l_twist = l * q_inv mod 2^16) once and
     * derive the twist for (l0 + l1) by addition, saving one vector multiply:
     *   (l0 + l1) * q_inv mod 2^16 = l0_twist + l1_twist  (mod 2^16 arithmetic)
     */
    vec_int16_t l0_twist = (vec_int16_t)((vec_uint16_t)l0_vec * q_inv);
    vec_int16_t l1_twist = (vec_int16_t)((vec_uint16_t)l1_vec * q_inv);
    vec_int16_t lsum_twist = l0_twist + l1_twist;

    vec_int16_t P = multiply_montgomery_unreduced(r0_vec + r1_vec, l0_vec + l1_vec, lsum_twist);
    vec_int16_t P0 = multiply_montgomery_unreduced(r0_vec, l0_vec, l0_twist);
    vec_int16_t P1 = multiply_montgomery_unreduced(r1_vec, l1_vec, l1_twist);
    *result_odd = P - (P0 + P1);
    *result_even = P0 + multiply_montgomery_unreduced(P1, roots, roots_twisted);
}

/*
 * scalar_mult_add_vec128: pointwise multiply-accumulate of two NTT-domain
 * scalars.
 *
 * Computes out[i] = reduce_once_vec128(out[i] + (lhs (*) rhs)[i]) for all i.
 * The product lhs (*) rhs is computed via twisted Karatsuba followed by
 * demontgomerization, then added to the existing out coefficients and reduced
 * back to [0, q).
 *
 * Pre:  Every coefficient of lhs and rhs is in [0, q)  (standard NTT-domain form).
 *       Every coefficient of out is in [0, q), so that after adding a product
 *       coefficient (also in [0, q)) the lane sum lies in [0, 2q) and
 *       reduce_once_vec128 is valid.
 * Post: Every coefficient of out is in [0, q) and equals
 *       reduce_once(old_out[i] + (lhs (*) rhs)[i]).
 */
void ossl_ml_kem_scalar_mult_add_vec128(scalar *out, const scalar *lhs, const scalar *rhs)
{
    vec_int16_t *curr = (vec_int16_t *)out->c, *end = curr + VECTOR_DEGREE;
    const vec_int16_noalias_t *lhs_coeffs = (vec_int16_noalias_t *)lhs->c;
    const vec_int16_noalias_t *rhs_coeffs = (vec_int16_noalias_t *)rhs->c;
    const vec_int16_t *roots_vec_ptr = kModRoots_montgomery_vec;
    const vec_int16_t *roots_twisted_vec_ptr = kModRoots_twisted_vec;

    do {
        vec_int16_t roots = *roots_vec_ptr++;
        vec_int16_t roots_twisted = *roots_twisted_vec_ptr++;
        vec_int16_noalias_t result_even, result_odd;

        multiply_Fq2_montgomery_unreduced(lhs_coeffs, rhs_coeffs, roots, roots_twisted,
            &result_even, &result_odd);
        lhs_coeffs += 2;
        rhs_coeffs += 2;

        result_even = demontgomerize_vec128(result_even);
        result_odd = demontgomerize_vec128(result_odd);

        curr[0] += vec_perm(result_even, result_odd, perm_interleave_low);
        curr[1] += vec_perm(result_even, result_odd, perm_interleave_high);

        curr[0] = reduce_once_vec128(curr[0]);
        curr[1] = reduce_once_vec128(curr[1]);

        curr += 2;
    } while (curr < end);
}

/*
 * scalar_mult_montgomery_vec128: pointwise multiplication leaving the result
 * in inverse-Montgomery form.
 *
 * Same computation as scalar_mult_vec128 but omits demontgomerize_vec128,
 * leaving the raw output of multiply_Fq2_montgomery_unreduced() in out.  Each coefficient is
 * in (-q, q) and represents the logical product scaled by R_M^{-1} = 169 mod q.
 *
 * Pre:  Every coefficient of lhs and rhs is in [0, q)  (standard NTT-domain form).
 *       out must not alias lhs or rhs.
 * Post: Every coefficient of out is in (-q, q) and represents
 *       (lhs (*) rhs)[i] * R_M^{-1} mod q  (inverse-Montgomery form).
 *       The caller is responsible for eventual demontgomerization.
 */
static ossl_inline void scalar_mult_montgomery_vec128(scalar *out,
    const scalar *lhs,
    const scalar *rhs)
{
    vec_int16_t *curr = (vec_int16_t *)out->c, *end = curr + VECTOR_DEGREE;
    const vec_int16_noalias_t *lhs_coeffs = (vec_int16_noalias_t *)lhs->c;
    const vec_int16_noalias_t *rhs_coeffs = (vec_int16_noalias_t *)rhs->c;
    const vec_int16_t *roots_vec_ptr = kModRoots_montgomery_vec;
    const vec_int16_t *roots_twisted_vec_ptr = kModRoots_twisted_vec;

    do {
        vec_int16_t roots = *roots_vec_ptr++;
        vec_int16_t roots_twisted = *roots_twisted_vec_ptr++;
        vec_int16_noalias_t result_even, result_odd;

        multiply_Fq2_montgomery_unreduced(lhs_coeffs, rhs_coeffs, roots, roots_twisted,
            &result_even, &result_odd);
        lhs_coeffs += 2;
        rhs_coeffs += 2;

        curr[0] = vec_perm(result_even, result_odd, perm_interleave_low);
        curr[1] = vec_perm(result_even, result_odd, perm_interleave_high);
        curr += 2;
    } while (curr < end);
}

/*
 * scalar_mult_add_montgomery_vec128: accumulate an NTT-domain product into out
 * while staying in inverse-Montgomery form.
 *
 * Adds the twisted-Karatsuba raw output (multiply_Fq2_montgomery_unreduced result) to out
 * without any reduction or demontgomerization.  Each individual twisted-Karatsuba
 * term satisfies |term[i]| <= 6006 (the result_odd worst case
 * from multiply_Fq2_montgomery_unreduced).  For ML-KEM's rank k <= 4, the
 * accumulated sum satisfies |out[i]| <= k * 6006 <= 4 * 6006 = 24024 < 2^15,
 * so no 16-bit signed overflow occurs.
 *
 * Pre:  Every coefficient of lhs and rhs is in [0, q)  (standard NTT-domain form).
 *       Every existing coefficient of out is a partial inverse-Montgomery sum
 *       with |out[i]| <= j * 6006, where j is the number of products
 *       accumulated so far and j + 1 <= k <= 4.
 * Post: out[i] += (lhs (*) rhs)[i] in inverse-Montgomery form; no reduction is
 *       applied.  The caller must call demontgomerize_scalar_vec128() once all
 *       terms have been accumulated.
 */
static ossl_inline void scalar_mult_add_montgomery_vec128(scalar *out,
    const scalar *lhs,
    const scalar *rhs)
{
    vec_int16_t *curr = (vec_int16_t *)out->c, *end = curr + VECTOR_DEGREE;
    const vec_int16_noalias_t *lhs_coeffs = (vec_int16_noalias_t *)lhs->c;
    const vec_int16_noalias_t *rhs_coeffs = (vec_int16_noalias_t *)rhs->c;
    const vec_int16_t *roots_vec_ptr = kModRoots_montgomery_vec;
    const vec_int16_t *roots_twisted_vec_ptr = kModRoots_twisted_vec;

    do {
        vec_int16_t roots = *roots_vec_ptr++;
        vec_int16_t roots_twisted = *roots_twisted_vec_ptr++;
        vec_int16_noalias_t result_even, result_odd;

        multiply_Fq2_montgomery_unreduced(lhs_coeffs, rhs_coeffs, roots, roots_twisted,
            &result_even, &result_odd);
        lhs_coeffs += 2;
        rhs_coeffs += 2;

        curr[0] += vec_perm(result_even, result_odd, perm_interleave_low);
        curr[1] += vec_perm(result_even, result_odd, perm_interleave_high);

        curr += 2;
    } while (curr < end);
}

/*
 * inner_product_montgomery_vec128: inner product leaving the result in
 * inverse-Montgomery form.
 *
 * Same accumulation as inner_product_vec128 but omits the final
 * demontgomerize_scalar_vec128() call.  Each output coefficient out[i]
 * satisfies out[i] ≡ IP(lhs, rhs)[i] * 169 (mod q), i.e. the inner-product
 * value in inverse-Montgomery form.
 *
 * Pre:  Same as inner_product_vec128.
 * Post: Every coefficient of out satisfies |out[i]| <= rank * 6006
 *       and represents the inner-product coefficient in
 *       inverse-Montgomery form.
 *       The caller must pass out to scalar_inverse_ntt_demontgomerize_vec128()
 *       rather than scalar_inverse_ntt_vec128().
 */
void ossl_ml_kem_inner_product_montgomery_vec128(scalar *out, const scalar *lhs,
    const scalar *rhs, int rank)
{
    scalar_mult_montgomery_vec128(out, lhs, rhs);
    while (--rank > 0)
        scalar_mult_add_montgomery_vec128(out, ++lhs, ++rhs);
}

/*
 * scalar_inverse_ntt_demontgomerize_vec128: inverse NTT on input in
 * inverse-Montgomery form.
 *
 * Variant of scalar_inverse_ntt_vec128 for use after
 * inner_product_montgomery_vec128.  It first converts the input from
 * inverse-Montgomery form to standard form via demontgomerize_scalar_vec128,
 * then runs the 7 Gentleman-Sande INTT layers
 * (scalar_inverse_ntt_vec128_raw), then multiplies by 512
 * (scalar_mult_const_512_vec128) for normalization.
 *
 * Pre:  Every coefficient s->c[i] satisfies |s->c[i]| <= 4*6006 < 8*q and represents a
 *       logical value in inverse-Montgomery form (value * R_M^{-1} mod q).
 * Post: Every coefficient s->c[i] is in [0, q) and equals INTT(s_std)[i],
 *       where s_std is the NTT-domain scalar encoded by the input.
 */
void ossl_ml_kem_scalar_inverse_ntt_demontgomerize_vec128(scalar *s)
{
    scalar_inverse_ntt_vec128_demontgomerize(s);
}

/*
 * matrix_mult_intt_vec128: matrix-vector multiplication followed by inverse
 * NTT.
 *
 * Computes out[i] = INTT(sum_{j=0}^{rank-1} m[i*rank+j] (*) a[j]) for each
 * row i.  Products are accumulated in inverse-Montgomery form without
 * per-step demontgomerization; the demontgomerizing INTT variant
 * (scalar_inverse_ntt_vec128_demontgomerize) handles conversion and INTT
 * for each row.
 *
 * Pre:  1 <= rank <= 4  (ML-KEM supports k in {2, 3, 4}).
 *       Every coefficient of m[i*rank+j] and a[j] is in [0, q)  (NTTScalar).
 *       out must not alias m or a.
 * Post: Every coefficient of out[i] is in [0, q) and equals
 *       INTT(sum_j m[i*rank+j] (*) a[j])[coeff] mod q.
 */
void ossl_ml_kem_matrix_mult_intt_vec128(scalar *out, const scalar *m, const scalar *a,
    int rank)
{
    const scalar *ar;
    int i, j;

    for (i = rank; i-- > 0; ++out) {
        ar = a;
        scalar_mult_montgomery_vec128(out, m++, ar);
        for (j = rank - 1; j > 0; --j)
            scalar_mult_add_montgomery_vec128(out, m++, ++ar);
        /* do the lazy reduction */
        demontgomerize_scalar_vec128(out);
        ossl_ml_kem_scalar_inverse_ntt_vec128(out);
    }
}

#endif /* VX_COMPILER_SUPPORT_VEC128 */
