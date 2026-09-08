/*
 * Copyright 2018-2026 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018-2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/bn.h>
#include "crypto/bn.h"
#include "crypto/fn.h"
#include "crypto/fn_intern.h"
#include "crypto/fn_constants.h"
#include "rsa_local.h"

/*
 * Part of the RSA keypair test.
 * Check the Chinese Remainder Theorem components are valid.
 *
 * See SP800-5bBr1
 *   6.4.1.2.3: rsakpv1-crt Step 7
 *   6.4.1.3.3: rsakpv2-crt Step 7
 */
int ossl_rsa_check_crt_components(const RSA *rsa, BN_CTX *ctx)
{
    int ret = 0;
    const OSSL_FN *fn_p, *fn_q, *fn_e, *fn_dmp1, *fn_dmq1, *fn_iqmp;
    const OSSL_FN *fn_one = OSSL_FN_value_one();
    OSSL_FN *r = NULL, *p1 = NULL, *q1 = NULL;
    OSSL_FN_CTX *fn_ctx = NULL;
    size_t pl, ql, size;

    /* check if only some of the crt components are set */
    if (rsa->dmp1 == NULL || rsa->dmq1 == NULL || rsa->iqmp == NULL) {
        if (rsa->dmp1 != NULL || rsa->dmq1 != NULL || rsa->iqmp != NULL)
            return 0;
        return 1; /* return ok if all components are NULL */
    }

    fn_p = bn_get_ossl_fn(rsa->p);
    fn_q = bn_get_ossl_fn(rsa->q);
    fn_e = bn_get_ossl_fn(rsa->e);
    fn_dmp1 = bn_get_ossl_fn(rsa->dmp1);
    fn_dmq1 = bn_get_ossl_fn(rsa->dmq1);
    fn_iqmp = bn_get_ossl_fn(rsa->iqmp);
    if (fn_p == NULL || fn_q == NULL || fn_e == NULL || fn_dmp1 == NULL
        || fn_dmq1 == NULL || fn_iqmp == NULL)
        return 0;
    pl = ossl_fn_get_dsize((OSSL_FN *)fn_p);
    ql = ossl_fn_get_dsize((OSSL_FN *)fn_q);

    p1 = OSSL_FN_secure_new_limbs(pl);
    q1 = OSSL_FN_secure_new_limbs(ql);
    r = OSSL_FN_secure_new_limbs(pl > ql ? pl : ql);
    if (r == NULL || p1 == NULL || q1 == NULL)
        goto err;

    if (!OSSL_FN_copy(p1, fn_p) || !OSSL_FN_sub_word(p1, 1)
        || !OSSL_FN_copy(q1, fn_q) || !OSSL_FN_sub_word(q1, 1))
        goto err;

    /*
     * The three mod_mul checks run in one arena, sized for the largest:
     * each reduces a product of a CRT component (prime width) and e
     * modulo a prime(-minus-one).
     */
    size = OSSL_FN_mod_mul_ctx_size(r, fn_dmp1, fn_e, p1);
    size = ossl_fn_ctx_max_size(size,
        OSSL_FN_mod_mul_ctx_size(r, fn_dmq1, fn_e, q1));
    size = ossl_fn_ctx_max_size(size,
        OSSL_FN_mod_mul_ctx_size(r, fn_iqmp, fn_q, fn_p));
    if (size == 0
        || (fn_ctx = OSSL_FN_CTX_secure_new_size(rsa->libctx, size)) == NULL)
        goto err;

    ret = /* (a) 1 < dP < (p – 1). */
        (OSSL_FN_cmp(fn_dmp1, fn_one) > 0)
        && (OSSL_FN_cmp(fn_dmp1, p1) < 0)
        /* (b) 1 < dQ < (q - 1). */
        && (OSSL_FN_cmp(fn_dmq1, fn_one) > 0)
        && (OSSL_FN_cmp(fn_dmq1, q1) < 0)
        /* (c) 1 < qInv < p */
        && (OSSL_FN_cmp(fn_iqmp, fn_one) > 0)
        && (OSSL_FN_cmp(fn_iqmp, fn_p) < 0)
        /* (d) 1 = (dP . e) mod (p - 1) */
        && OSSL_FN_mod_mul(r, fn_dmp1, fn_e, p1, fn_ctx)
        && OSSL_FN_is_one(r)
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && OSSL_FN_mod_mul(r, fn_dmq1, fn_e, q1, fn_ctx)
        && OSSL_FN_is_one(r)
        /* (f) 1 = (qInv . q) mod p */
        && OSSL_FN_mod_mul(r, fn_iqmp, fn_q, fn_p, fn_ctx)
        && OSSL_FN_is_one(r);

err:
    OSSL_FN_CTX_free(fn_ctx);
    OSSL_FN_clear_free(r);
    OSSL_FN_clear_free(p1);
    OSSL_FN_clear_free(q1);
    return ret;
}

/*
 * Part of the RSA keypair test.
 * Check that (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2) - 1
 *
 * See SP800-5bBr1 6.4.1.2.1 Part 5 (c) & (g) - used for both p and q.
 *
 * (√2)(2^(nbits/2 - 1) = (√2/2)(2^(nbits/2))
 */
int ossl_rsa_check_prime_factor_range(const BIGNUM *p, int nbits, BN_CTX *ctx)
{
    int ret = 0;
    const OSSL_FN *fn_p = bn_get_ossl_fn(p);
    const OSSL_FN *fn_is2 = &ossl_fn_static_inv_sqrt_2_storage.fn;
    OSSL_FN *low = NULL;
    size_t pl, is2_bits, low_limbs;
    int shift;

    if (fn_p == NULL)
        return 0;

    nbits >>= 1;
    is2_bits = OSSL_FN_num_bits(fn_is2);
    shift = (int)(nbits - is2_bits);

    /* Upper bound check */
    if (OSSL_FN_num_bits(fn_p) != (size_t)nbits)
        return 0;

    /*
     * The shifted √2 bound needs the prime width when shifting left, the
     * constant's own width otherwise.
     */
    pl = ossl_fn_get_dsize((OSSL_FN *)fn_p);
    low_limbs = ossl_fn_get_dsize((OSSL_FN *)fn_is2);
    if (shift >= 0 && pl > low_limbs)
        low_limbs = pl;
    low = OSSL_FN_new_limbs(low_limbs);
    if (low == NULL)
        return 0;

    /* set low = (√2)(2^(nbits/2 - 1) */
    if (!OSSL_FN_copy(low, fn_is2))
        goto err;

    if (shift >= 0) {
        /*
         * We don't have all the bits. ossl_fn_inv_sqrt_2 contains a rounded
         * up value, so there is a very low probability that we'll reject a
         * valid value.
         */
        if (!OSSL_FN_lshift(low, low, shift))
            goto err;
    } else if (!OSSL_FN_rshift(low, low, -shift)) {
        goto err;
    }
    if (OSSL_FN_cmp(fn_p, low) <= 0)
        goto err;
    ret = 1;
err:
    OSSL_FN_free(low);
    return ret;
}

/*
 * Part of the RSA keypair test.
 * Check the prime factor (for either p or q)
 * i.e: p is prime AND GCD(p - 1, e) = 1
 *
 * See SP800-56Br1 6.4.1.2.3 Step 5 (a to d) & (e to h).
 */
int ossl_rsa_check_prime_factor(BIGNUM *p, BIGNUM *e, int nbits, BN_CTX *ctx)
{
    int ret = 0;
    const OSSL_FN *fn_p, *fn_e;
    OSSL_FN *p1 = NULL, *gcd = NULL;
    OSSL_FN_CTX *fn_ctx = NULL;
    size_t pl, size;

    fn_p = bn_get_ossl_fn(p);
    fn_e = bn_get_ossl_fn(e);
    if (fn_p == NULL || fn_e == NULL)
        return 0;
    pl = ossl_fn_get_dsize((OSSL_FN *)fn_p);

    /* (Steps 5 a-b) prime test */
    size = ossl_fn_check_prime_ctx_size(fn_p);
    if (size == 0
        || (fn_ctx = OSSL_FN_CTX_new_size(NULL, size)) == NULL)
        return 0;
    ret = ossl_fn_check_prime(fn_p, 0, fn_ctx, 1, NULL, NULL);
    OSSL_FN_CTX_free(fn_ctx);
    fn_ctx = NULL;
    if (ret != 1
        /* (Step 5c) (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2 - 1) */
        || ossl_rsa_check_prime_factor_range(p, nbits, ctx) != 1)
        return 0;

    p1 = OSSL_FN_secure_new_limbs(pl);
    gcd = OSSL_FN_secure_new_limbs(pl);
    if (p1 == NULL || gcd == NULL)
        goto err;

    /* (Step 5d) GCD(p-1, e) = 1 */
    if (!OSSL_FN_copy(p1, fn_p) || !OSSL_FN_sub_word(p1, 1))
        goto err;
    size = OSSL_FN_gcd_ctx_size(p1, fn_e);
    if (size == 0
        || (fn_ctx = OSSL_FN_CTX_secure_new_size(NULL, size)) == NULL)
        goto err;
    ret = OSSL_FN_gcd(gcd, p1, fn_e, fn_ctx)
        && OSSL_FN_is_one(gcd);

err:
    OSSL_FN_CTX_free(fn_ctx);
    OSSL_FN_clear_free(p1);
    OSSL_FN_clear_free(gcd);
    return ret;
}

/*
 * See SP800-56Br1 6.4.1.2.3 Part 6(a-b) Check the private exponent d
 * satisfies:
 *     (Step 6a) 2^(nBit/2) < d < LCM(p–1, q–1).
 *     (Step 6b) 1 = (d*e) mod LCM(p–1, q–1)
 */
int ossl_rsa_check_private_exponent(const RSA *rsa, int nbits, BN_CTX *ctx)
{
    int ret;
    const OSSL_FN *fn_d, *fn_e, *fn_lcm;
    OSSL_FN *r = NULL;
    OSSL_FN_CTX *fn_ctx = NULL;
    size_t size;

    /*
     * The LCM is computed by ossl_rsa_get_lcm() (already OSSL_FN inside,
     * BIGNUM at the boundary); only the closing mod_mul runs on OSSL_FN
     * here.
     */
    BIGNUM *lcm = NULL, *gcd = NULL, *p1 = NULL, *q1 = NULL, *p1q1 = NULL;

    fn_d = bn_get_ossl_fn(rsa->d);
    fn_e = bn_get_ossl_fn(rsa->e);
    if (fn_d == NULL || fn_e == NULL)
        return 0;

    /* (Step 6a) 2^(nbits/2) < d */
    if (OSSL_FN_num_bits(fn_d) <= (size_t)(nbits >> 1))
        return 0;

    BN_CTX_start(ctx);
    lcm = BN_CTX_get(ctx);
    gcd = BN_CTX_get(ctx);
    p1 = BN_CTX_get(ctx);
    q1 = BN_CTX_get(ctx);
    p1q1 = BN_CTX_get(ctx);
    if (p1q1 == NULL) {
        ret = 0;
        goto end;
    }

    ret = 0;
    /* LCM(p - 1, q - 1) */
    if (ossl_rsa_get_lcm(ctx, rsa->p, rsa->q, lcm, gcd, p1, q1, p1q1) != 1)
        goto end;
    fn_lcm = bn_get_ossl_fn(lcm);
    if (fn_lcm == NULL)
        goto end;

    /* (Step 6a) d < LCM(p - 1, q - 1) */
    if (OSSL_FN_cmp(fn_d, fn_lcm) >= 0)
        goto end;

    /* (Step 6b) 1 = (e . d) mod LCM(p - 1, q - 1) */
    r = OSSL_FN_secure_new_limbs(ossl_fn_get_dsize((OSSL_FN *)fn_lcm));
    if (r == NULL)
        goto end;
    size = OSSL_FN_mod_mul_ctx_size(r, fn_e, fn_d, fn_lcm);
    if (size == 0
        || (fn_ctx = OSSL_FN_CTX_secure_new_size(rsa->libctx, size)) == NULL)
        goto end;
    ret = OSSL_FN_mod_mul(r, fn_e, fn_d, fn_lcm, fn_ctx)
        && OSSL_FN_is_one(r);

end:
    OSSL_FN_CTX_free(fn_ctx);
    OSSL_FN_clear_free(r);
    BN_clear(lcm);
    BN_clear(gcd);
    BN_clear(p1);
    BN_clear(q1);
    BN_clear(p1q1);
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Check exponent is odd.
 * For FIPS also check the bit length is in the range [17..256]
 */
int ossl_rsa_check_public_exponent(const BIGNUM *e)
{
#ifdef FIPS_MODULE
    int bitlen;

    bitlen = BN_num_bits(e);
    return (BN_is_odd(e) && bitlen > 16 && bitlen < 257);
#else
    /* Allow small exponents larger than 1 for legacy purposes */
    return BN_is_odd(e) && BN_cmp(e, BN_value_one()) > 0;
#endif /* FIPS_MODULE */
}

/*
 * SP800-56Br1 6.4.1.2.1 (Step 5i): |p - q| > 2^(nbits/2 - 100)
 * i.e- numbits(p-q-1) > (nbits/2 -100)
 */
int ossl_rsa_check_pminusq_diff(BIGNUM *diff, const BIGNUM *p, const BIGNUM *q,
    int nbits)
{
    int bitlen = (nbits >> 1) - 100;

    if (!BN_sub(diff, p, q))
        return -1;
    BN_set_negative(diff, 0);

    if (BN_is_zero(diff))
        return 0;

    if (!BN_sub_word(diff, 1))
        return -1;
    return (BN_num_bits(diff) > bitlen);
}

/*
 * return LCM(p-1, q-1)
 *
 * Caller should ensure that lcm, gcd, p1, q1, p1q1 are flagged with
 * BN_FLG_CONSTTIME.
 */
int ossl_rsa_get_lcm(BN_CTX *ctx, const BIGNUM *p, const BIGNUM *q,
    BIGNUM *lcm, BIGNUM *gcd, BIGNUM *p1, BIGNUM *q1,
    BIGNUM *p1q1)
{
    /*
     * The LCM computation is a fixed-size candidate: p-1, q-1, their
     * product, gcd, and the quotient all fit in widths derived from p and
     * q.  The operands keep their BIGNUM signatures (this is an internal
     * helper with callers holding key-structure BIGNUMs); the arithmetic
     * is done on OSSL_FN views.
     */
    OSSL_FN_CTX *fn_ctx = NULL;
    OSSL_FN *fn_p1 = NULL, *fn_q1 = NULL, *fn_gcd = NULL, *fn_lcm = NULL;
    OSSL_FN *fn_p1q1 = NULL;
    const OSSL_FN *fn_p = NULL, *fn_q = NULL;
    size_t pl, ql, fn_size;
    int ret = 0;

    fn_p = bn_get_ossl_fn(p);
    fn_q = bn_get_ossl_fn(q);
    if (fn_p == NULL || fn_q == NULL)
        return 0;
    pl = ossl_fn_get_dsize((OSSL_FN *)fn_p);
    ql = ossl_fn_get_dsize((OSSL_FN *)fn_q);

    /*
     * Acquire the writable results before sizing.  p-1 and q-1 fit in the
     * prime widths; their product in pl+ql; gcd in min(pl,ql); lcm (the
     * quotient p1q1/gcd) in pl+ql.
     */
    fn_p1 = bn_acquire_ossl_fn(p1, (int)pl);
    fn_q1 = bn_acquire_ossl_fn(q1, (int)ql);
    fn_p1q1 = bn_acquire_ossl_fn(p1q1, (int)(pl + ql));
    fn_gcd = bn_acquire_ossl_fn(gcd, (int)(pl < ql ? pl : ql));
    fn_lcm = bn_acquire_ossl_fn(lcm, (int)(pl + ql));
    if (fn_p1 == NULL || fn_q1 == NULL || fn_p1q1 == NULL || fn_gcd == NULL
        || fn_lcm == NULL)
        goto err;

    /*
     * The operations run one after another in the same arena, each in its
     * own frame that is ended before the next begins, so the arena must be
     * large enough for the largest single operation, not the sum.  This
     * function itself does not draw from the arena (it only passes fn_ctx
     * down to the operations, which open their own frames), so it opens
     * no frame of its own; the sizing companions account for the
     * operations' frames.
     */
    fn_size = ossl_fn_ctx_max_size(
        ossl_fn_ctx_max_size(
            OSSL_FN_mul_ctx_size(fn_p1q1, fn_p1, fn_q1),
            OSSL_FN_gcd_ctx_size(fn_p1, fn_q1)),
        OSSL_FN_div_ctx_size(fn_lcm, NULL, fn_p1q1, fn_gcd));
    if (fn_size == 0)
        goto err;
    fn_ctx = OSSL_FN_CTX_secure_new_size(NULL, fn_size);
    if (fn_ctx == NULL)
        goto err;

    /* p-1 and q-1 */
    if (!OSSL_FN_copy_truncate(fn_p1, fn_p)
        || !OSSL_FN_sub_word(fn_p1, 1)
        || !OSSL_FN_copy_truncate(fn_q1, fn_q)
        || !OSSL_FN_sub_word(fn_q1, 1)
        /* (p-1)(q-1) */
        || !OSSL_FN_mul(fn_p1q1, fn_p1, fn_q1, fn_ctx)
        /* gcd(p-1, q-1) */
        || !OSSL_FN_gcd(fn_gcd, fn_p1, fn_q1, fn_ctx)
        /* LCM((p-1, q-1)) = (p-1)(q-1) / gcd */
        || !OSSL_FN_div(fn_lcm, NULL, fn_p1q1, fn_gcd, fn_ctx))
        goto err;

    bn_release(p1, (int)pl);
    bn_release(q1, (int)ql);
    bn_release(p1q1, (int)(pl + ql));
    bn_release(gcd, (int)(pl < ql ? pl : ql));
    bn_release(lcm, (int)(pl + ql));
    ret = 1;
err:
    OSSL_FN_CTX_free(fn_ctx);
    return ret;
}

/*
 * SP800-56Br1 6.4.2.2 Partial Public Key Validation for RSA refers to
 * SP800-89 5.3.3 (Explicit) Partial Public Key Validation for RSA
 * caveat is that the modulus must be as specified in SP800-56Br1
 */
int ossl_rsa_sp800_56b_check_public(const RSA *rsa)
{
    int ret = 0, status;
    int nbits;
    const OSSL_FN *fn_n, *fn_sf;
    OSSL_FN *gcd = NULL;
    OSSL_FN_CTX *fn_ctx = NULL;
    size_t size;

    if (rsa->n == NULL || rsa->e == NULL)
        return 0;

    fn_n = bn_get_ossl_fn(rsa->n);
    fn_sf = ossl_fn_get0_small_factors();
    if (fn_n == NULL || fn_sf == NULL)
        return 0;

    nbits = (int)OSSL_FN_num_bits(fn_n);
    if (nbits > OPENSSL_RSA_MAX_MODULUS_BITS) {
        ERR_raise(ERR_LIB_RSA, RSA_R_MODULUS_TOO_LARGE);
        return 0;
    }

#ifdef FIPS_MODULE
    /*
     * (Step a): modulus must be 2048 or 3072 (caveat from SP800-56Br1)
     * NOTE: changed to allow keys >= 2048
     */
    if (!ossl_rsa_sp800_56b_validate_strength(nbits, -1)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_KEY_LENGTH);
        return 0;
    }
#endif
    if (!OSSL_FN_is_odd(fn_n)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MODULUS);
        return 0;
    }
    /* (Steps b-c): 2^16 < e < 2^256, n and e must be odd */
    if (!ossl_rsa_check_public_exponent(rsa->e)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_PUB_EXPONENT_OUT_OF_RANGE);
        return 0;
    }

    /*
     * (Steps d-f):
     * The modulus is composite, but not a power of a prime.
     * The modulus has no factors smaller than 752.
     */
    gcd = OSSL_FN_new_limbs(ossl_fn_get_dsize((OSSL_FN *)fn_n));
    if (gcd == NULL)
        goto err;
    size = OSSL_FN_gcd_ctx_size(fn_n, fn_sf);
    if (size == 0
        || (fn_ctx = OSSL_FN_CTX_new_size(rsa->libctx, size)) == NULL)
        goto err;
    if (!OSSL_FN_gcd(gcd, fn_n, fn_sf, fn_ctx) || !OSSL_FN_is_one(gcd)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MODULUS);
        goto err;
    }
    OSSL_FN_CTX_free(fn_ctx);
    fn_ctx = NULL;

    /* Highest number of MR rounds from FIPS 186-5 Section B.3 Table B.1 */
    size = ossl_fn_miller_rabin_is_prime_ctx_size(fn_n);
    if (size == 0
        || (fn_ctx = OSSL_FN_CTX_new_size(rsa->libctx, size)) == NULL)
        goto err;
    ret = ossl_fn_miller_rabin_is_prime(fn_n, 5, fn_ctx, NULL, 1, &status,
        rsa->libctx);
#ifdef FIPS_MODULE
    if (ret != 1 || status != BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME) {
#else
    if (ret != 1 || (status != BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME && (nbits >= RSA_MIN_MODULUS_BITS || status != BN_PRIMETEST_COMPOSITE_WITH_FACTOR))) {
#endif
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MODULUS);
        ret = 0;
        goto err;
    }

    ret = 1;
err:
    OSSL_FN_CTX_free(fn_ctx);
    OSSL_FN_free(gcd);
    return ret;
}

/*
 * Perform validation of the RSA private key to check that 0 < D < N.
 */
int ossl_rsa_sp800_56b_check_private(const RSA *rsa)
{
    if (rsa->d == NULL || rsa->n == NULL)
        return 0;
    return BN_cmp(rsa->d, BN_value_one()) >= 0 && BN_cmp(rsa->d, rsa->n) < 0;
}

/*
 * RSA key pair validation.
 *
 * SP800-56Br1.
 *    6.4.1.2 "RSAKPV1 Family: RSA Key - Pair Validation with a Fixed Exponent"
 *    6.4.1.3 "RSAKPV2 Family: RSA Key - Pair Validation with a Random Exponent"
 *
 * It uses:
 *     6.4.1.2.3 "rsakpv1 - crt"
 *     6.4.1.3.3 "rsakpv2 - crt"
 */
int ossl_rsa_sp800_56b_check_keypair(const RSA *rsa, const BIGNUM *efixed,
    int strength, int nbits)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *r = NULL;
    const OSSL_FN *fn_n, *fn_p, *fn_q;
    OSSL_FN *prod = NULL;
    OSSL_FN_CTX *fn_ctx = NULL;
    size_t size;

    if (rsa->p == NULL
        || rsa->q == NULL
        || rsa->e == NULL
        || rsa->d == NULL
        || rsa->n == NULL) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_REQUEST);
        return 0;
    }
    /* (Step 1): Check Ranges */
    if (!ossl_rsa_sp800_56b_validate_strength(nbits, strength))
        return 0;

    /* If the exponent is known */
    if (efixed != NULL) {
        /* (2): Check fixed exponent matches public exponent. */
        if (BN_cmp(efixed, rsa->e) != 0) {
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_REQUEST);
            return 0;
        }
    }
    /* (Step 1.c): e is odd integer 65537 <= e < 2^256 */
    if (!ossl_rsa_check_public_exponent(rsa->e)) {
        /* exponent out of range */
        ERR_raise(ERR_LIB_RSA, RSA_R_PUB_EXPONENT_OUT_OF_RANGE);
        return 0;
    }

    fn_n = bn_get_ossl_fn(rsa->n);
    fn_p = bn_get_ossl_fn(rsa->p);
    fn_q = bn_get_ossl_fn(rsa->q);
    if (fn_n == NULL || fn_p == NULL || fn_q == NULL)
        return 0;

    /* (Step 3.b): check the modulus */
    if ((size_t)nbits != OSSL_FN_num_bits(fn_n)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_KEYPAIR);
        return 0;
    }
    /* (Step 3.c): check that the modulus length is a positive even integer */
    if (nbits <= 0 || (nbits & 0x1)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_KEYPAIR);
        return 0;
    }

    ctx = BN_CTX_new_ex(rsa->libctx);
    if (ctx == NULL)
        return 0;

    /* (Step 4.c): Check n = pq */
    prod = OSSL_FN_secure_new_limbs(ossl_fn_get_dsize((OSSL_FN *)fn_n)
        + 1);
    if (prod == NULL)
        goto err;
    size = OSSL_FN_mul_ctx_size(prod, fn_p, fn_q);
    if (size == 0
        || (fn_ctx = OSSL_FN_CTX_secure_new_size(rsa->libctx, size)) == NULL)
        goto err;
    if (!OSSL_FN_mul(prod, fn_p, fn_q, fn_ctx))
        goto err;
    if (OSSL_FN_cmp(fn_n, prod) != 0) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_REQUEST);
        goto err;
    }
    OSSL_FN_CTX_free(fn_ctx);
    fn_ctx = NULL;

    BN_CTX_start(ctx);
    r = BN_CTX_get(ctx);
    if (r == NULL)
        goto bn_err;

    /* (Step 5): check prime factors p & q */
    ret = ossl_rsa_check_prime_factor(rsa->p, rsa->e, nbits, ctx)
        && ossl_rsa_check_prime_factor(rsa->q, rsa->e, nbits, ctx)
        && (ossl_rsa_check_pminusq_diff(r, rsa->p, rsa->q, nbits) > 0)
        /* (Step 6): Check the private exponent d */
        && ossl_rsa_check_private_exponent(rsa, nbits, ctx)
        /* 6.4.1.2.3 (Step 7): Check the CRT components */
        && ossl_rsa_check_crt_components(rsa, ctx);
    if (ret != 1)
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_KEYPAIR);

bn_err:
    BN_clear(r);
    BN_CTX_end(ctx);
err:
    OSSL_FN_CTX_free(fn_ctx);
    OSSL_FN_clear_free(prod);
    BN_CTX_free(ctx);
    return ret;
}
