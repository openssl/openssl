/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * AVX-512 implementation of the ML-KEM NTT and NTT-domain base multiplication.
 *
 * The transform is computed with signed Montgomery arithmetic on 16-bit lanes
 * (32 coefficients per 512-bit register, the whole polynomial in 8 registers).
 *
 * Polynomial coefficients stay in the plain domain.  Twiddle factors are
 * stored as zeta * 2^16 mod q, so a Montgomery multiply yields a
 * plain-domain product.  The inverse-degree scale and the base-multiplication
 * constants are Montgomery form as well.  Butterflies are not reduced every
 * level.
 * The forward transform canonicalises with one Barrett reduction on store.
 * The inverse transform Barrett-reduces after the third and sixth levels,
 * then multiplies by INVERSE_DEGREE = (n/2)^-1 mod q and canonicalises.
 * Base multiplication canonicalises on store the same way.  The fused
 * accumulator is a separate 32-bit dot product: it sums every rank product
 * and reduces once, and its transpose-add form adds the error polynomial
 * already stored at the output.  Matrix multiplication then runs the inverse
 * NTT on those registers and stores the row once, in standard form.
 * Every stored coefficient is in [0, q) and bit-identical to the generic
 * routines in ml_kem.c (ossl_ml_kem_scalar_ntt_generic(),
 * ossl_ml_kem_scalar_inverse_ntt_generic(),
 * ossl_ml_kem_scalar_mult_generic(), and
 * ossl_ml_kem_scalar_mult_add_generic(), including a chain of the last two
 * and the inverse NTT of that sum).
 *
 * The seven butterfly levels have stride (len) 128, 64, 32, 16, 8, 4, 2:
 *   - len >= 32: partners live in different registers.  len 128 broadcasts
 *     one zeta to every pair, len 64 broadcasts one zeta across two pairs,
 *     and len 32 broadcasts one zeta per pair.
 *   - len == 16: partners live inside a register.  vpermw aligns each pair
 *     and one broadcast zeta per register drives the butterfly.
 *   - len <= 8: same in-register permute, with a per-lane zeta vector.
 */

#include "ml_kem_local.h"
#include "internal/cryptlib.h"

#if ML_KEM_AVX512_ELIGIBLE
#define STRINGIFY_IMPLEMENTATION_(a) #a
#define STRINGIFY(a) STRINGIFY_IMPLEMENTATION_(a)

#ifdef __clang__
#define OPENSSL_TARGET_REGION(T)                                       \
    _Pragma(STRINGIFY(clang attribute push(__attribute__((target(T))), \
        apply_to = function)))
#define OPENSSL_UNTARGET_REGION _Pragma("clang attribute pop")
#elif defined(__GNUC__)
#define OPENSSL_TARGET_REGION(T) \
    _Pragma("GCC push_options") _Pragma(STRINGIFY(GCC target(T)))
#define OPENSSL_UNTARGET_REGION _Pragma("GCC pop_options")
#else
/* MSVC: AVX-512 intrinsics come from <immintrin.h>, with no target pragma. */
#define OPENSSL_TARGET_REGION(T)
#define OPENSSL_UNTARGET_REGION
#endif

#define OPENSSL_TARGET_AVX512 OPENSSL_TARGET_REGION("avx512f,avx512bw")
#define OPENSSL_UNTARGET_AVX512 OPENSSL_UNTARGET_REGION

#include <immintrin.h>

#if ML_KEM_DEGREE != 256
#error "ml_kem_avx512.c assumes ML_KEM_DEGREE == 256"
#endif

#define ML_KEM_MONT_R 2285 /* 2^16 mod q                          */
#define ML_KEM_QINV 62209 /* q^-1 mod 2^16 (as signed: -3327)    */
#define ML_KEM_BARRETT_V 20159 /* ((1 << 26) + q/2) / q               */
#define ML_KEM_INVERSE_DEGREE (ML_KEM_PRIME - 2 * 13)

int ossl_ml_kem_ntt_avx512_capable(void)
{
    return (OPENSSL_ia32cap_P[2] & (1U << 16)) != 0 /* AVX512F  */
        && (OPENSSL_ia32cap_P[2] & (1U << 30)) != 0; /* AVX512BW */
}

/*
 * Twiddle and permutation tables, derived once from the shared root tables in
 * ml_kem.c so they can never drift from the generic implementation.
 *
 *   zmont[k]  = ossl_ml_kem_ntt_roots[k]         * 2^16 mod q
 *   izmont[k] = ossl_ml_kem_inverse_ntt_roots[k] * 2^16 mod q
 *
 * For the in-register levels (len = 8,4,2) each register g needs a 32-lane
 * vector holding, per lane, the zeta of the butterfly group that lane belongs
 * to.  idxa/idxb are the vpermw indices that broadcast the lower/upper element
 * of every butterfly pair across both of its lanes (idxa[i]=i&~s, idxb[i]=i|s).
 */
static int16_t zmont[128], izmont[128];
static int16_t Z8f[8][32], Z4f[8][32], Z2f[8][32]; /* forward len 8,4,2  */
static int16_t IZ8[8][32], IZ4[8][32], IZ2[8][32]; /* inverse len 8,4,2  */
static int16_t idxa[4][32], idxb[4][32]; /* slots: s=16,8,4,2  */
static int16_t idxpair[32]; /* basemul: i ^ 1     */
static int16_t BZ[8][32]; /* basemul constants  */
static int16_t kinvdeg_mont; /* (n/2)^-1, Montgomery */
static int16_t r2_mont; /* 2^32 mod q         */
/* Fused accumulator: (1, zeta) and (0, Shoup(zeta)) for each 32-lane block. */
static int16_t mod_lo[8][32], mod_hi[8][32];
static int16_t r_shoup; /* floor(R * 2^16 / q), R = 2^16 mod q */
static CRYPTO_ONCE ml_kem_avx512_tables_once = CRYPTO_ONCE_STATIC_INIT;

static void ml_kem_avx512_init_tables(void)
{
    static const int svals[4] = { 16, 8, 4, 2 };
    int k, g, i;

    for (k = 0; k < 128; k++) {
        zmont[k] = (int16_t)(((uint32_t)ossl_ml_kem_ntt_roots[k]
                                 * ML_KEM_MONT_R)
            % ML_KEM_PRIME);
        izmont[k] = (int16_t)(((uint32_t)ossl_ml_kem_inverse_ntt_roots[k]
                                  * ML_KEM_MONT_R)
            % ML_KEM_PRIME);
    }
    kinvdeg_mont = (int16_t)(((uint32_t)ML_KEM_INVERSE_DEGREE
                                 * ML_KEM_MONT_R)
        % ML_KEM_PRIME);

    for (g = 0; g < 8; g++) {
        for (i = 0; i < 32; i++) {
            Z8f[g][i] = zmont[16 + 2 * g + (i >> 4)]; /* group = i / 16 */
            Z4f[g][i] = zmont[32 + 4 * g + (i >> 3)]; /* group = i / 8  */
            Z2f[g][i] = zmont[64 + 8 * g + (i >> 2)]; /* group = i / 4  */
            IZ2[g][i] = izmont[1 + 8 * g + (i >> 2)];
            IZ4[g][i] = izmont[65 + 4 * g + (i >> 3)];
            IZ8[g][i] = izmont[97 + 2 * g + (i >> 4)];
        }
    }

    for (k = 0; k < 4; k++) {
        for (i = 0; i < 32; i++) {
            idxa[k][i] = (int16_t)(i & ~svals[k]);
            idxb[k][i] = (int16_t)(i | svals[k]);
        }
    }

    /*
     * Base multiplication constants.  Pair i of the NTT-domain polynomial
     * lives in GF(q)[X]/(X^2 - r_i) with r_i = 17^(2*bitreverse(i)+1), which is
     * 17 * ossl_ml_kem_ntt_roots[i]^2 mod q (the roots table holds
     * 17^bitreverse(i)), so this stays tied to the shared table.
     *
     * A lane's constant both applies that root on the odd lane and converts
     * the Montgomery product back to the plain domain: 2^32 mod q on even
     * lanes, r_i * 2^32 mod q on odd lanes.
     */
    r2_mont = (int16_t)(((uint32_t)ML_KEM_MONT_R * ML_KEM_MONT_R)
        % ML_KEM_PRIME);
    for (i = 0; i < 32; i++)
        idxpair[i] = (int16_t)(i ^ 1);
    for (g = 0; g < 8; g++) {
        for (i = 0; i < 32; i++) {
            uint32_t root, nr;

            if ((i & 1) == 0) {
                BZ[g][i] = r2_mont;
                continue;
            }
            nr = ossl_ml_kem_ntt_roots[16 * g + i / 2];
            root = (17u * ((nr * nr) % ML_KEM_PRIME)) % ML_KEM_PRIME;
            BZ[g][i] = (int16_t)((root * (uint32_t)r2_mont) % ML_KEM_PRIME);
        }
    }

    /*
     * Same roots as kModRoots: r_i = 17 * ntt_roots[i]^2 mod q.  Even lanes
     * hold the multiplicative identity so the odd-lane Shoup product leaves
     * l0 unchanged.  Shoup factors above 32767 are stored as int16 bit
     * patterns and consumed by an unsigned high multiply.
     */
    r_shoup = (int16_t)(((uint32_t)ML_KEM_MONT_R << 16) / ML_KEM_PRIME);
    for (g = 0; g < 8; g++) {
        for (i = 0; i < 32; i++) {
            uint32_t nr, root;

            if ((i & 1) == 0) {
                mod_lo[g][i] = 1;
                mod_hi[g][i] = 0;
                continue;
            }
            nr = ossl_ml_kem_ntt_roots[16 * g + i / 2];
            root = (17u * ((nr * nr) % ML_KEM_PRIME)) % ML_KEM_PRIME;
            mod_lo[g][i] = (int16_t)root;
            mod_hi[g][i] = (int16_t)((root << 16) / ML_KEM_PRIME);
        }
    }
}

OPENSSL_TARGET_AVX512

/*
 * Signed Montgomery multiply on 16-bit lanes: returns a*b*2^-16 mod q in the
 * range (-q, q).  With b a Montgomery-form twiddle (zeta*2^16), this yields the
 * plain-domain product a*zeta mod q.
 *
 * Algorithm (Seiler 2018, Algorithm 3).
 */
static ossl_inline __m512i ml_kem_mont_mul(__m512i a, __m512i b)
{
    const __m512i q = _mm512_set1_epi16((short)ML_KEM_PRIME);
    const __m512i qinv = _mm512_set1_epi16((short)ML_KEM_QINV);
    __m512i lo = _mm512_mullo_epi16(a, b);
    __m512i hi = _mm512_mulhi_epi16(a, b);
    __m512i m = _mm512_mullo_epi16(lo, qinv);
    __m512i t = _mm512_mulhi_epi16(m, q);

    return _mm512_sub_epi16(hi, t);
}

/* Map a value in (-q, q) to the canonical range [0, q). */
static ossl_inline __m512i ml_kem_canon(__m512i r)
{
    const __m512i q = _mm512_set1_epi16((short)ML_KEM_PRIME);
    __m512i mask = _mm512_srai_epi16(r, 15); /* 0xFFFF where r < 0 */

    return _mm512_add_epi16(r, _mm512_and_si512(mask, q));
}

/* reduce_once: input in [0, 2q) -> [0, q). */
static ossl_inline __m512i ml_kem_reduce_once(__m512i x)
{
    const __m512i q = _mm512_set1_epi16((short)ML_KEM_PRIME);

    return _mm512_min_epu16(x, _mm512_sub_epi16(x, q));
}

/*
 * Barrett reduction for any signed |a| < 2^15, computing a mod q.
 *
 * t = floor(a * V / 2^26) equals floor(a / q) exactly over this range: the
 * relative error of V/2^26 against 1/q is under 2.1e-9, so |a| * error stays
 * below 6.6e-5, well inside the 1/q ~ 3.0e-4 gap between a/q and the nearest
 * integer.  The one exception is a negative exact multiple of q, where the
 * floor lands one lower and the result is q rather than 0; the output is
 * therefore in [0, q] and callers needing canonical form finish with
 * ml_kem_reduce_once().
 */
static ossl_inline __m512i ml_kem_barrett(__m512i a)
{
    const __m512i v = _mm512_set1_epi16((short)ML_KEM_BARRETT_V);
    const __m512i q = _mm512_set1_epi16((short)ML_KEM_PRIME);
    __m512i t = _mm512_mulhi_epi16(a, v);

    t = _mm512_srai_epi16(t, 10);
    t = _mm512_mullo_epi16(t, q);
    return _mm512_sub_epi16(a, t);
}

/* Signed value of any magnitude < 2^15 -> canonical [0, q). */
static ossl_inline __m512i ml_kem_canonical(__m512i a)
{
    return ml_kem_reduce_once(ml_kem_barrett(a));
}

/* Plain-domain twiddle multiply, result canonical [0, q). */
static ossl_inline __m512i ml_kem_fqmul(__m512i a, __m512i b)
{
    return ml_kem_canon(ml_kem_mont_mul(a, b));
}

/*
 * The butterflies below are "lazy": they leave results as signed
 * representatives rather than reducing to [0, q) every level.  See the range
 * analysis in the transform functions for why this cannot overflow int16.
 */

/* Cooley-Tukey butterfly across two registers (a = curr, b = peer). */
static ossl_inline void ml_kem_ct_cross(__m512i *a, __m512i *b, __m512i z)
{
    __m512i t = ml_kem_mont_mul(*b, z);
    __m512i av = *a;

    *a = _mm512_add_epi16(av, t);
    *b = _mm512_sub_epi16(av, t);
}

/* Cooley-Tukey butterfly within a register (stride < 32). */
static ossl_inline __m512i ml_kem_ct_inreg(__m512i x, __m512i ia, __m512i ib,
    __mmask32 peer, __m512i z)
{
    __m512i a = _mm512_permutexvar_epi16(ia, x);
    __m512i b = _mm512_permutexvar_epi16(ib, x);
    __m512i t = ml_kem_mont_mul(b, z);

    return _mm512_mask_blend_epi16(peer, _mm512_add_epi16(a, t),
        _mm512_sub_epi16(a, t));
}

/* Gentleman-Sande butterfly across two registers (a = curr, b = peer). */
static ossl_inline void ml_kem_gs_cross(__m512i *a, __m512i *b, __m512i z)
{
    __m512i av = *a, bv = *b;

    *a = _mm512_add_epi16(av, bv);
    *b = ml_kem_mont_mul(_mm512_sub_epi16(av, bv), z);
}

/* Gentleman-Sande butterfly within a register (stride < 32). */
static ossl_inline __m512i ml_kem_gs_inreg(__m512i x, __m512i ia, __m512i ib,
    __mmask32 peer, __m512i z)
{
    __m512i a = _mm512_permutexvar_epi16(ia, x);
    __m512i b = _mm512_permutexvar_epi16(ib, x);
    __m512i sum = _mm512_add_epi16(a, b);
    __m512i prod = ml_kem_mont_mul(_mm512_sub_epi16(a, b), z);

    return _mm512_mask_blend_epi16(peer, sum, prod);
}

/*
 * Forward NTT.  No intermediate reductions are needed: a Montgomery product is
 * always in (-q, q), so a Cooley-Tukey level grows the coefficient bound by at
 * most q.  Starting from the canonical input bound q, after all seven levels
 * the bound is 8q = 26632, which still fits a signed 16-bit lane (and every
 * multiplicand is at most 7q, inside the |x| < 2^15 requirement of the signed
 * Montgomery reduction).  A single Barrett pass canonicalises on store.
 */
void ossl_ml_kem_scalar_ntt_avx512(uint16_t *coeffs)
{
    __m512i r[8];
    int g;

    (void)CRYPTO_THREAD_run_once(&ml_kem_avx512_tables_once,
        ml_kem_avx512_init_tables);

    for (g = 0; g < 8; g++)
        r[g] = _mm512_loadu_si512((const void *)(coeffs + 32 * g));

    /* len = 128 */
    {
        __m512i z = _mm512_set1_epi16(zmont[1]);

        ml_kem_ct_cross(&r[0], &r[4], z);
        ml_kem_ct_cross(&r[1], &r[5], z);
        ml_kem_ct_cross(&r[2], &r[6], z);
        ml_kem_ct_cross(&r[3], &r[7], z);
    }
    /* len = 64 */
    {
        __m512i z2 = _mm512_set1_epi16(zmont[2]);
        __m512i z3 = _mm512_set1_epi16(zmont[3]);

        ml_kem_ct_cross(&r[0], &r[2], z2);
        ml_kem_ct_cross(&r[1], &r[3], z2);
        ml_kem_ct_cross(&r[4], &r[6], z3);
        ml_kem_ct_cross(&r[5], &r[7], z3);
    }
    /* len = 32 */
    ml_kem_ct_cross(&r[0], &r[1], _mm512_set1_epi16(zmont[4]));
    ml_kem_ct_cross(&r[2], &r[3], _mm512_set1_epi16(zmont[5]));
    ml_kem_ct_cross(&r[4], &r[5], _mm512_set1_epi16(zmont[6]));
    ml_kem_ct_cross(&r[6], &r[7], _mm512_set1_epi16(zmont[7]));

    /* len = 16 (in-register, one broadcast zeta per register) */
    {
        __m512i ia = _mm512_loadu_si512((const void *)idxa[0]);
        __m512i ib = _mm512_loadu_si512((const void *)idxb[0]);

        for (g = 0; g < 8; g++)
            r[g] = ml_kem_ct_inreg(r[g], ia, ib, 0xFFFF0000u,
                _mm512_set1_epi16(zmont[8 + g]));
    }
    /* len = 8 */
    {
        __m512i ia = _mm512_loadu_si512((const void *)idxa[1]);
        __m512i ib = _mm512_loadu_si512((const void *)idxb[1]);

        for (g = 0; g < 8; g++)
            r[g] = ml_kem_ct_inreg(r[g], ia, ib, 0xFF00FF00u,
                _mm512_loadu_si512((const void *)Z8f[g]));
    }
    /* len = 4 */
    {
        __m512i ia = _mm512_loadu_si512((const void *)idxa[2]);
        __m512i ib = _mm512_loadu_si512((const void *)idxb[2]);

        for (g = 0; g < 8; g++)
            r[g] = ml_kem_ct_inreg(r[g], ia, ib, 0xF0F0F0F0u,
                _mm512_loadu_si512((const void *)Z4f[g]));
    }
    /* len = 2 */
    {
        __m512i ia = _mm512_loadu_si512((const void *)idxa[3]);
        __m512i ib = _mm512_loadu_si512((const void *)idxb[3]);

        for (g = 0; g < 8; g++)
            r[g] = ml_kem_ct_inreg(r[g], ia, ib, 0xCCCCCCCCu,
                _mm512_loadu_si512((const void *)Z2f[g]));
    }

    for (g = 0; g < 8; g++)
        _mm512_storeu_si512((void *)(coeffs + 32 * g),
            ml_kem_canonical(r[g]));

    _mm256_zeroupper();
}

/*
 * Inverse NTT.  Unlike the forward transform, a Gentleman-Sande level doubles
 * the coefficient bound (the sum side is a + b), so starting from q the bound
 * runs q, 2q, 4q, 8q and the next level would need 16q = 53264, overflowing a
 * signed 16-bit lane.  Barrett reducing after the third and sixth levels keeps
 * every intermediate (and every multiplicand) inside |x| < 2^15.  The closing
 * multiply by INVERSE_DEGREE = (n/2)^-1 mod q then lands in (-q, q) and is
 * made canonical directly.  Callers may pass the eight registers straight
 * through from the fused accumulator, skipping the store and reload.
 */
#if defined(_MSC_VER)
#define ML_KEM_ALWAYS_INLINE __forceinline
#else
#define ML_KEM_ALWAYS_INLINE __attribute__((always_inline))
#endif

/* Kept inline so the fused accumulator can stay in zmm registers. */
static ossl_inline ML_KEM_ALWAYS_INLINE void ml_kem_inverse_ntt_regs(__m512i r[8])
{
    int g;

    /* len = 2 (in-register) */
    {
        __m512i ia = _mm512_loadu_si512((const void *)idxa[3]);
        __m512i ib = _mm512_loadu_si512((const void *)idxb[3]);

        for (g = 0; g < 8; g++)
            r[g] = ml_kem_gs_inreg(r[g], ia, ib, 0xCCCCCCCCu,
                _mm512_loadu_si512((const void *)IZ2[g]));
    }
    /* len = 4 */
    {
        __m512i ia = _mm512_loadu_si512((const void *)idxa[2]);
        __m512i ib = _mm512_loadu_si512((const void *)idxb[2]);

        for (g = 0; g < 8; g++)
            r[g] = ml_kem_gs_inreg(r[g], ia, ib, 0xF0F0F0F0u,
                _mm512_loadu_si512((const void *)IZ4[g]));
    }
    /* len = 8 */
    {
        __m512i ia = _mm512_loadu_si512((const void *)idxa[1]);
        __m512i ib = _mm512_loadu_si512((const void *)idxb[1]);

        for (g = 0; g < 8; g++)
            r[g] = ml_kem_gs_inreg(r[g], ia, ib, 0xFF00FF00u,
                _mm512_loadu_si512((const void *)IZ8[g]));
    }
    /* Bound is now 8q; reduce before it can double again. */
    for (g = 0; g < 8; g++)
        r[g] = ml_kem_barrett(r[g]);
    /* len = 16 (in-register, one broadcast zeta per register) */
    {
        __m512i ia = _mm512_loadu_si512((const void *)idxa[0]);
        __m512i ib = _mm512_loadu_si512((const void *)idxb[0]);

        for (g = 0; g < 8; g++)
            r[g] = ml_kem_gs_inreg(r[g], ia, ib, 0xFFFF0000u,
                _mm512_set1_epi16(izmont[113 + g]));
    }

    /* len = 32 */
    ml_kem_gs_cross(&r[0], &r[1], _mm512_set1_epi16(izmont[121]));
    ml_kem_gs_cross(&r[2], &r[3], _mm512_set1_epi16(izmont[122]));
    ml_kem_gs_cross(&r[4], &r[5], _mm512_set1_epi16(izmont[123]));
    ml_kem_gs_cross(&r[6], &r[7], _mm512_set1_epi16(izmont[124]));
    /* len = 64 */
    {
        __m512i z5 = _mm512_set1_epi16(izmont[125]);
        __m512i z6 = _mm512_set1_epi16(izmont[126]);

        ml_kem_gs_cross(&r[0], &r[2], z5);
        ml_kem_gs_cross(&r[1], &r[3], z5);
        ml_kem_gs_cross(&r[4], &r[6], z6);
        ml_kem_gs_cross(&r[5], &r[7], z6);
    }
    /* Bound is 8q again after the sixth level. */
    for (g = 0; g < 8; g++)
        r[g] = ml_kem_barrett(r[g]);
    /* len = 128 */
    {
        __m512i z7 = _mm512_set1_epi16(izmont[127]);

        ml_kem_gs_cross(&r[0], &r[4], z7);
        ml_kem_gs_cross(&r[1], &r[5], z7);
        ml_kem_gs_cross(&r[2], &r[6], z7);
        ml_kem_gs_cross(&r[3], &r[7], z7);
    }

    /* Final scaling by (n/2)^-1 (Montgomery), result canonical [0, q). */
    {
        __m512i f = _mm512_set1_epi16(kinvdeg_mont);

        for (g = 0; g < 8; g++)
            r[g] = ml_kem_fqmul(r[g], f);
    }
}

void ossl_ml_kem_scalar_inverse_ntt_avx512(uint16_t *coeffs)
{
    __m512i r[8];
    int g;

    (void)CRYPTO_THREAD_run_once(&ml_kem_avx512_tables_once,
        ml_kem_avx512_init_tables);

    for (g = 0; g < 8; g++)
        r[g] = _mm512_loadu_si512((const void *)(coeffs + 32 * g));
    ml_kem_inverse_ntt_regs(r);
    for (g = 0; g < 8; g++)
        _mm512_storeu_si512((void *)(coeffs + 32 * g), r[g]);

    _mm256_zeroupper();
}
/*
 * Base multiplication of one register's worth of coefficient pairs.  Pair
 * (l0, l1) times (r0, r1) in GF(q)[X]/(X^2 - r_i) is
 *
 *     out0 = l0*r0 + l1*r1*r_i,   out1 = l0*r1 + l1*r0
 *
 * All four products come from just two Montgomery multiplies at full lane
 * utilisation: multiplying the operands as loaded puts l0*r0 and l1*r1 in the
 * even and odd lanes, and multiplying against the pair-swapped rhs puts l0*r1
 * and l1*r0 there.  Scaling by the per-lane constants (see the table setup)
 * applies r_i on the odd lane and leaves the plain domain.  Adding each vector
 * to its own pair-swap then sums the two halves of each component, so the even
 * lanes of one result and the odd lanes of the other are what we keep.
 *
 * Output is a signed value with |x| < 2q; the caller canonicalises.
 */
static ossl_inline __m512i ml_kem_basemul_reg(__m512i lv, __m512i rv,
    __m512i sw, __m512i bz, __m512i r2)
{
    __m512i rs = _mm512_permutexvar_epi16(sw, rv);
    __m512i qq = ml_kem_mont_mul(lv, rv);
    __m512i pp = ml_kem_mont_mul(lv, rs);
    __m512i qz = ml_kem_mont_mul(qq, bz);
    __m512i pz = ml_kem_mont_mul(pp, r2);
    __m512i sq = _mm512_add_epi16(qz, _mm512_permutexvar_epi16(sw, qz));
    __m512i sp = _mm512_add_epi16(pz, _mm512_permutexvar_epi16(sw, pz));

    return _mm512_mask_blend_epi16(0xAAAAAAAAu, sq, sp);
}

void ossl_ml_kem_scalar_mult_avx512(uint16_t *out, const uint16_t *lhs,
    const uint16_t *rhs)
{
    __m512i sw, r2;
    int g;

    (void)CRYPTO_THREAD_run_once(&ml_kem_avx512_tables_once,
        ml_kem_avx512_init_tables);
    sw = _mm512_loadu_si512((const void *)idxpair);
    r2 = _mm512_set1_epi16(r2_mont);

    for (g = 0; g < 8; g++) {
        __m512i v = ml_kem_basemul_reg(
            _mm512_loadu_si512((const void *)(lhs + 32 * g)),
            _mm512_loadu_si512((const void *)(rhs + 32 * g)),
            sw, _mm512_loadu_si512((const void *)BZ[g]), r2);

        _mm512_storeu_si512((void *)(out + 32 * g), ml_kem_canonical(v));
    }

    _mm256_zeroupper();
}

void ossl_ml_kem_scalar_mult_add_avx512(uint16_t *out, const uint16_t *lhs,
    const uint16_t *rhs)
{
    __m512i sw, r2;
    int g;

    (void)CRYPTO_THREAD_run_once(&ml_kem_avx512_tables_once,
        ml_kem_avx512_init_tables);
    sw = _mm512_loadu_si512((const void *)idxpair);
    r2 = _mm512_set1_epi16(r2_mont);

    for (g = 0; g < 8; g++) {
        __m512i v = ml_kem_basemul_reg(
            _mm512_loadu_si512((const void *)(lhs + 32 * g)),
            _mm512_loadu_si512((const void *)(rhs + 32 * g)),
            sw, _mm512_loadu_si512((const void *)BZ[g]), r2);

        /* Accumulator is canonical, so the sum stays within |x| < 3q. */
        v = _mm512_add_epi16(v,
            _mm512_loadu_si512((const void *)(out + 32 * g)));
        _mm512_storeu_si512((void *)(out + 32 * g), ml_kem_canonical(v));
    }

    _mm256_zeroupper();
}

/*
 * Byte index that restores pair order after packus.  Each 128-bit lane of
 * packus_epi32 is (e0,e1,e2,e3,o0,o1,o2,o3); this shuffle makes
 * (e0,o0,e1,o1,...).  The shuffle does not cross 128-bit lanes.
 */
static const uint8_t ml_kem_interleave[64] = {
    0, 1, 8, 9, 2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15,
    0, 1, 8, 9, 2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15,
    0, 1, 8, 9, 2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15,
    0, 1, 8, 9, 2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15
};

/* Shoup multiply: 0 <= a * b < 2q for b in [0, q) and this b_shoup. */
static ossl_inline __m512i ml_kem_shoup_mul(__m512i a, __m512i b, __m512i b_shoup)
{
    const __m512i q = _mm512_set1_epi16((short)ML_KEM_PRIME);
    __m512i lo = _mm512_mullo_epi16(a, b);
    __m512i hi = _mm512_mulhi_epu16(a, b_shoup);

    return _mm512_sub_epi16(lo, _mm512_mullo_epi16(hi, q));
}

/* Montgomery reduction of 16 signed 32-bit lanes to canonical [0, q). */
static ossl_inline __m512i ml_kem_mont_reduce32(__m512i a)
{
    const __m512i q = _mm512_set1_epi32(ML_KEM_PRIME);
    const __m512i qinv = _mm512_set1_epi32(3327); /* -q^-1 mod 2^16 */
    const __m512i mask = _mm512_set1_epi32(65535);
    __m512i m = _mm512_and_si512(_mm512_mullo_epi32(a, qinv), mask);
    __m512i t = _mm512_add_epi32(a, _mm512_mullo_epi32(m, q));

    t = _mm512_srli_epi32(t, 16);
    return _mm512_min_epu32(t, _mm512_sub_epi32(t, q));
}

static ossl_inline __m512i ml_kem_pack_pairs(__m512i even, __m512i odd)
{
    __m512i packed = _mm512_packus_epi32(even, odd);

    return _mm512_shuffle_epi8(packed,
        _mm512_loadu_si512((const void *)ml_kem_interleave));
}

/*
 * Canonical NTT-domain dot product, one zmm per 32 coefficients.  The odd
 * left coefficients are Shoup-scaled by their base-multiplication roots,
 * then madd_epi16 produces the two 32-bit halves.  Four products fit in a
 * signed 32-bit lane.  One Montgomery reduction and a multiply by R mod q
 * return the canonical sum.
 *
 * add_from is the polynomial already sitting in the output (the error term
 * in key generation); NULL skips that add.  lhs_stride is 1 for a contiguous
 * vector and rank for one row of the transposed matrix.
 */
static ossl_inline void ml_kem_basemul_acc_regs(__m512i v[8],
    const uint16_t *add_from, const uint16_t *lhs, const uint16_t *rhs,
    int rank, int lhs_stride)
{
    __m512i sw = _mm512_loadu_si512((const void *)idxpair);
    __m512i mont_r = _mm512_set1_epi16(ML_KEM_MONT_R);
    __m512i rsh = _mm512_set1_epi16(r_shoup);
    int b;

    for (b = 0; b < 8; b++) {
        __m512i acc0 = _mm512_setzero_si512();
        __m512i acc1 = _mm512_setzero_si512();
        __m512i z = _mm512_loadu_si512((const void *)mod_lo[b]);
        __m512i zs = _mm512_loadu_si512((const void *)mod_hi[b]);
        int k;

        for (k = 0; k < rank; k++) {
            const uint16_t *lp = lhs + ((size_t)k * lhs_stride * ML_KEM_DEGREE + (size_t)b * 32);
            const uint16_t *rp = rhs + ((size_t)k * ML_KEM_DEGREE + (size_t)b * 32);
            __m512i lv = _mm512_loadu_si512((const void *)lp);
            __m512i rv = _mm512_loadu_si512((const void *)rp);
            __m512i scaled = ml_kem_shoup_mul(lv, z, zs);

            acc0 = _mm512_add_epi32(acc0, _mm512_madd_epi16(rv, scaled));
            acc1 = _mm512_add_epi32(acc1,
                _mm512_madd_epi16(_mm512_permutexvar_epi16(sw, rv), lv));
        }

        acc0 = ml_kem_mont_reduce32(acc0);
        acc1 = ml_kem_mont_reduce32(acc1);
        v[b] = ml_kem_reduce_once(ml_kem_shoup_mul(ml_kem_pack_pairs(acc0, acc1),
            mont_r, rsh));
        if (add_from != NULL) {
            v[b] = _mm512_add_epi16(v[b],
                _mm512_loadu_si512((const void *)(add_from + 32 * b)));
            v[b] = ml_kem_reduce_once(v[b]);
        }
    }
}

static void ml_kem_store_poly(uint16_t *out, const __m512i v[8])
{
    int b;

    for (b = 0; b < 8; b++)
        _mm512_storeu_si512((void *)(out + 32 * b), v[b]);
    _mm256_zeroupper();
}

void ossl_ml_kem_basemul_acc_avx512(uint16_t *out, const uint16_t *lhs,
    const uint16_t *rhs, int rank)
{
    __m512i v[8];

    (void)CRYPTO_THREAD_run_once(&ml_kem_avx512_tables_once,
        ml_kem_avx512_init_tables);
    ml_kem_basemul_acc_regs(v, NULL, lhs, rhs, rank, 1);
    ml_kem_store_poly(out, v);
}

void ossl_ml_kem_basemul_acc_transpose_add_avx512(uint16_t *out,
    const uint16_t *lhs, const uint16_t *rhs, int rank)
{
    __m512i v[8];

    (void)CRYPTO_THREAD_run_once(&ml_kem_avx512_tables_once,
        ml_kem_avx512_init_tables);
    ml_kem_basemul_acc_regs(v, out, lhs, rhs, rank, rank);
    ml_kem_store_poly(out, v);
}

/* Accumulated row, then inverse NTT, with one store of the standard-form row. */
void ossl_ml_kem_basemul_acc_intt_avx512(uint16_t *out, const uint16_t *lhs,
    const uint16_t *rhs, int rank)
{
    __m512i v[8];

    (void)CRYPTO_THREAD_run_once(&ml_kem_avx512_tables_once,
        ml_kem_avx512_init_tables);
    ml_kem_basemul_acc_regs(v, NULL, lhs, rhs, rank, 1);
    ml_kem_inverse_ntt_regs(v);
    ml_kem_store_poly(out, v);
}
OPENSSL_UNTARGET_AVX512
#endif /* ML_KEM_AVX512_ELIGIBLE */
