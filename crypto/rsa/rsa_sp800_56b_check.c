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
#include "crypto/fxn.h"
#include "crypto/fxn_intern.h"
#include "crypto/fxn_constants.h"
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
    const OSSL_FXN *fxn_p, *fxn_q, *fxn_e, *fxn_dmp1, *fxn_dmq1, *fxn_iqmp;
    const OSSL_FXN *fxn_one = OSSL_FXN_value_one();
    OSSL_FXN *r = NULL, *p1 = NULL, *q1 = NULL;
    OSSL_FXN_CTX *fxn_ctx = NULL;
    size_t pl, ql, size;

    /* check if only some of the crt components are set */
    if (rsa->dmp1 == NULL || rsa->dmq1 == NULL || rsa->iqmp == NULL) {
        if (rsa->dmp1 != NULL || rsa->dmq1 != NULL || rsa->iqmp != NULL)
            return 0;
        return 1; /* return ok if all components are NULL */
    }

    /*
     * The checks run on OSSL_FXN views, which are unsigned; reject
     * negative components rather than check their magnitudes.
     */
    if (BN_is_negative(rsa->p) || BN_is_negative(rsa->q)
        || BN_is_negative(rsa->e) || BN_is_negative(rsa->dmp1)
        || BN_is_negative(rsa->dmq1) || BN_is_negative(rsa->iqmp))
        return 0;

    fxn_p = bn_get_ossl_fxn(rsa->p);
    fxn_q = bn_get_ossl_fxn(rsa->q);
    fxn_e = bn_get_ossl_fxn(rsa->e);
    fxn_dmp1 = bn_get_ossl_fxn(rsa->dmp1);
    fxn_dmq1 = bn_get_ossl_fxn(rsa->dmq1);
    fxn_iqmp = bn_get_ossl_fxn(rsa->iqmp);
    if (fxn_p == NULL || fxn_q == NULL || fxn_e == NULL || fxn_dmp1 == NULL
        || fxn_dmq1 == NULL || fxn_iqmp == NULL)
        return 0;
    pl = ossl_fxn_get_dsize((OSSL_FXN *)fxn_p);
    ql = ossl_fxn_get_dsize((OSSL_FXN *)fxn_q);

    p1 = OSSL_FXN_secure_new_limbs(pl);
    q1 = OSSL_FXN_secure_new_limbs(ql);
    r = OSSL_FXN_secure_new_limbs(pl > ql ? pl : ql);
    if (r == NULL || p1 == NULL || q1 == NULL)
        goto err;

    if (!OSSL_FXN_copy(p1, fxn_p) || !OSSL_FXN_sub_word(p1, 1)
        || !OSSL_FXN_copy(q1, fxn_q) || !OSSL_FXN_sub_word(q1, 1))
        goto err;

    /*
     * The three mod_mul checks run in one arena, sized for the largest:
     * each reduces a product of a CRT component (prime width) and e
     * modulo a prime(-minus-one).
     */
    size = OSSL_FXN_mod_mul_ctx_size_from_nums(r, fxn_dmp1, fxn_e, p1);
    size = ossl_fxn_ctx_max_size(size,
        OSSL_FXN_mod_mul_ctx_size_from_nums(r, fxn_dmq1, fxn_e, q1));
    size = ossl_fxn_ctx_max_size(size,
        OSSL_FXN_mod_mul_ctx_size_from_nums(r, fxn_iqmp, fxn_q, fxn_p));
    /* TODO(FIXNUM): a secure arena is a possible future consideration */
    if (size == 0
        || (fxn_ctx = OSSL_FXN_CTX_new_size(rsa->libctx, size)) == NULL)
        goto err;

    ret = /* (a) 1 < dP < (p – 1). */
        (OSSL_FXN_cmp(fxn_dmp1, fxn_one) > 0)
        && (OSSL_FXN_cmp(fxn_dmp1, p1) < 0)
        /* (b) 1 < dQ < (q - 1). */
        && (OSSL_FXN_cmp(fxn_dmq1, fxn_one) > 0)
        && (OSSL_FXN_cmp(fxn_dmq1, q1) < 0)
        /* (c) 1 < qInv < p */
        && (OSSL_FXN_cmp(fxn_iqmp, fxn_one) > 0)
        && (OSSL_FXN_cmp(fxn_iqmp, fxn_p) < 0)
        /* (d) 1 = (dP . e) mod (p - 1) */
        && OSSL_FXN_mod_mul(r, fxn_dmp1, fxn_e, p1, fxn_ctx)
        && OSSL_FXN_is_one(r)
        /* (e) 1 = (dQ . e) mod (q - 1) */
        && OSSL_FXN_mod_mul(r, fxn_dmq1, fxn_e, q1, fxn_ctx)
        && OSSL_FXN_is_one(r)
        /* (f) 1 = (qInv . q) mod p */
        && OSSL_FXN_mod_mul(r, fxn_iqmp, fxn_q, fxn_p, fxn_ctx)
        && OSSL_FXN_is_one(r);

err:
    OSSL_FXN_CTX_free(fxn_ctx);
    OSSL_FXN_clear_free(r);
    OSSL_FXN_clear_free(p1);
    OSSL_FXN_clear_free(q1);
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
    const OSSL_FXN *fxn_p = NULL;
    const OSSL_FXN *fxn_is2 = &ossl_fxn_static_inv_sqrt_2_storage.fxn;
    OSSL_FXN *low = NULL;
    size_t pl, is2_bits, low_limbs;
    int shift;

    /* OSSL_FXN views are unsigned; a negative factor is invalid */
    if (BN_is_negative(p))
        return 0;
    fxn_p = bn_get_ossl_fxn(p);
    if (fxn_p == NULL)
        return 0;

    nbits >>= 1;
    is2_bits = OSSL_FXN_num_bits(fxn_is2);
    shift = (int)(nbits - is2_bits);

    /* Upper bound check */
    if (OSSL_FXN_num_bits(fxn_p) != (size_t)nbits)
        return 0;

    /*
     * The shifted √2 bound needs the prime width when shifting left, the
     * constant's own width otherwise.
     */
    pl = ossl_fxn_get_dsize((OSSL_FXN *)fxn_p);
    low_limbs = ossl_fxn_get_dsize((OSSL_FXN *)fxn_is2);
    if (shift >= 0 && pl > low_limbs)
        low_limbs = pl;
    low = OSSL_FXN_new_limbs(low_limbs);
    if (low == NULL)
        return 0;

    /* set low = (√2)(2^(nbits/2 - 1) */
    if (!OSSL_FXN_copy(low, fxn_is2))
        goto err;

    if (shift >= 0) {
        /*
         * We don't have all the bits. ossl_fxn_inv_sqrt_2 contains a rounded
         * up value, so there is a very low probability that we'll reject a
         * valid value.
         */
        if (!OSSL_FXN_lshift(low, low, shift))
            goto err;
    } else if (!OSSL_FXN_rshift(low, low, -shift)) {
        goto err;
    }
    if (OSSL_FXN_cmp(fxn_p, low) <= 0)
        goto err;
    ret = 1;
err:
    OSSL_FXN_free(low);
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
    const OSSL_FXN *fxn_p, *fxn_e;
    OSSL_FXN *p1 = NULL, *gcd = NULL;
    OSSL_FXN_CTX *fxn_ctx = NULL;
    OSSL_LIB_CTX *libctx = ossl_bn_get_libctx(ctx);
    size_t pl, size;

    /* OSSL_FXN views are unsigned; negative inputs are invalid */
    if (BN_is_negative(p) || BN_is_negative(e))
        return 0;
    fxn_p = bn_get_ossl_fxn(p);
    fxn_e = bn_get_ossl_fxn(e);
    if (fxn_p == NULL || fxn_e == NULL)
        return 0;
    pl = ossl_fxn_get_dsize((OSSL_FXN *)fxn_p);

    /* (Steps 5 a-b) prime test */
    size = ossl_fxn_check_prime_ctx_size_from_nums(fxn_p);
    if (size == 0
        || (fxn_ctx = OSSL_FXN_CTX_new_size(libctx, size)) == NULL)
        return 0;
    ret = ossl_fxn_check_prime(fxn_p, 0, fxn_ctx, 1, NULL, libctx);
    OSSL_FXN_CTX_free(fxn_ctx);
    fxn_ctx = NULL;
    if (ret != 1
        /* (Step 5c) (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2 - 1) */
        || ossl_rsa_check_prime_factor_range(p, nbits, ctx) != 1)
        return 0;

    p1 = OSSL_FXN_secure_new_limbs(pl);
    gcd = OSSL_FXN_secure_new_limbs(pl);
    if (p1 == NULL || gcd == NULL)
        goto err;

    /* (Step 5d) GCD(p-1, e) = 1 */
    if (!OSSL_FXN_copy(p1, fxn_p) || !OSSL_FXN_sub_word(p1, 1))
        goto err;
    size = OSSL_FXN_gcd_ctx_size_from_nums(p1, fxn_e);
    /* TODO(FIXNUM): a secure arena is a possible future consideration */
    if (size == 0
        || (fxn_ctx = OSSL_FXN_CTX_new_size(NULL, size)) == NULL)
        goto err;
    ret = OSSL_FXN_gcd(gcd, p1, fxn_e, fxn_ctx)
        && OSSL_FXN_is_one(gcd);

err:
    OSSL_FXN_CTX_free(fxn_ctx);
    OSSL_FXN_clear_free(p1);
    OSSL_FXN_clear_free(gcd);
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
    const OSSL_FXN *fxn_d, *fxn_e, *fxn_lcm;
    OSSL_FXN *r = NULL;
    OSSL_FXN_CTX *fxn_ctx = NULL;
    size_t size;

    /*
     * The LCM is computed by ossl_rsa_get_lcm() (already OSSL_FXN inside,
     * BIGNUM at the boundary); only the closing mod_mul runs on OSSL_FXN
     * here.
     */
    BIGNUM *lcm = NULL, *gcd = NULL, *p1 = NULL, *q1 = NULL, *p1q1 = NULL;

    fxn_d = bn_get_ossl_fxn(rsa->d);
    fxn_e = bn_get_ossl_fxn(rsa->e);
    if (fxn_d == NULL || fxn_e == NULL)
        return 0;
    /* OSSL_FXN views are unsigned; negative inputs are invalid */
    if (BN_is_negative(rsa->d) || BN_is_negative(rsa->e))
        return 0;

    /* (Step 6a) 2^(nbits/2) < d */
    if (OSSL_FXN_num_bits(fxn_d) <= (size_t)(nbits >> 1))
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
    fxn_lcm = bn_get_ossl_fxn(lcm);
    if (fxn_lcm == NULL)
        goto end;

    /* (Step 6a) d < LCM(p - 1, q - 1) */
    if (OSSL_FXN_cmp(fxn_d, fxn_lcm) >= 0)
        goto end;

    /* (Step 6b) 1 = (e . d) mod LCM(p - 1, q - 1) */
    r = OSSL_FXN_secure_new_limbs(ossl_fxn_get_dsize((OSSL_FXN *)fxn_lcm));
    if (r == NULL)
        goto end;
    size = OSSL_FXN_mod_mul_ctx_size_from_nums(r, fxn_e, fxn_d, fxn_lcm);
    /* TODO(FIXNUM): a secure arena is a possible future consideration */
    if (size == 0
        || (fxn_ctx = OSSL_FXN_CTX_new_size(rsa->libctx, size)) == NULL)
        goto end;
    ret = OSSL_FXN_mod_mul(r, fxn_e, fxn_d, fxn_lcm, fxn_ctx)
        && OSSL_FXN_is_one(r);

end:
    OSSL_FXN_CTX_free(fxn_ctx);
    OSSL_FXN_clear_free(r);
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
    const OSSL_FXN *fxn_p, *fxn_q;
    OSSL_FXN *fxn_diff;
    size_t pl, ql, dl;
    int diff_bits, ret = -1;

    /* OSSL_FXN views are unsigned; negative inputs are invalid */
    if (BN_is_negative(p) || BN_is_negative(q))
        return -1;
    fxn_p = bn_get_ossl_fxn(p);
    fxn_q = bn_get_ossl_fxn(q);
    if (fxn_p == NULL || fxn_q == NULL)
        return -1;
    pl = ossl_fxn_get_dsize((OSSL_FXN *)fxn_p);
    ql = ossl_fxn_get_dsize((OSSL_FXN *)fxn_q);
    dl = pl > ql ? pl : ql;

    if ((fxn_diff = bn_acquire_ossl_fxn(diff, (int)dl)) == NULL)
        return -1;

    /* |p - q|, i.e. the larger minus the smaller (OSSL_FXN is unsigned) */
    if (OSSL_FXN_cmp(fxn_p, fxn_q) >= 0) {
        if (!OSSL_FXN_sub(fxn_diff, fxn_p, fxn_q))
            goto err;
    } else {
        if (!OSSL_FXN_sub(fxn_diff, fxn_q, fxn_p))
            goto err;
    }

    diff_bits = (int)OSSL_FXN_num_bits(fxn_diff);
    if (diff_bits == 0) {
        ret = 0;
        goto err;
    }

    if (!OSSL_FXN_sub_word(fxn_diff, 1))
        goto err;
    diff_bits = (int)OSSL_FXN_num_bits(fxn_diff);
    ret = diff_bits > bitlen;

err:
    /* |p - q| is less than the wider of p and q, which fits in dl limbs */
    bn_release(diff, (int)dl);
    return ret;
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
     * is done on OSSL_FXN views.
     */
    OSSL_FXN_CTX *fxn_ctx = NULL;
    OSSL_FXN *fxn_p1 = NULL, *fxn_q1 = NULL, *fxn_gcd = NULL, *fxn_lcm = NULL;
    OSSL_FXN *fxn_p1q1 = NULL;
    const OSSL_FXN *fxn_p = NULL, *fxn_q = NULL;
    size_t pl, ql, fxn_size;
    int ret = 0;

    fxn_p = bn_get_ossl_fxn(p);
    fxn_q = bn_get_ossl_fxn(q);
    if (fxn_p == NULL || fxn_q == NULL)
        return 0;
    /* OSSL_FXN views are unsigned; negative inputs are invalid */
    if (BN_is_negative(p) || BN_is_negative(q))
        return 0;
    pl = ossl_fxn_get_dsize((OSSL_FXN *)fxn_p);
    ql = ossl_fxn_get_dsize((OSSL_FXN *)fxn_q);

    size_t p1_sz = pl, q1_sz = ql, p1q1_sz = pl + ql;
    size_t gcd_sz = pl < ql ? pl : ql, lcm_sz = pl + ql;

    /*
     * Acquire the writable results before sizing.  p-1 and q-1 fit in the
     * prime widths; their product in pl+ql; gcd in min(pl,ql); lcm (the
     * quotient p1q1/gcd) in pl+ql.
     */
    fxn_p1 = bn_acquire_ossl_fxn(p1, (int)pl);
    fxn_q1 = bn_acquire_ossl_fxn(q1, (int)ql);
    fxn_p1q1 = bn_acquire_ossl_fxn(p1q1, (int)(pl + ql));
    fxn_gcd = bn_acquire_ossl_fxn(gcd, (int)(pl < ql ? pl : ql));
    fxn_lcm = bn_acquire_ossl_fxn(lcm, (int)(pl + ql));
    if (fxn_p1 == NULL || fxn_q1 == NULL || fxn_p1q1 == NULL || fxn_gcd == NULL
        || fxn_lcm == NULL)
        goto err;

    /*
     * The operations run one after another in the same arena, each in its
     * own frame that is ended before the next begins, so the arena must be
     * large enough for the largest single operation, not the sum.  This
     * function itself does not draw from the arena (it only passes fxn_ctx
     * down to the operations, which open their own frames), so it opens
     * no frame of its own; the sizing companions account for the
     * operations' frames.
     */
    fxn_size = ossl_fxn_ctx_max_size(
        ossl_fxn_ctx_max_size(
            OSSL_FXN_mul_ctx_size_from_nums(fxn_p1q1, fxn_p1, fxn_q1),
            OSSL_FXN_gcd_ctx_size_from_nums(fxn_p1, fxn_q1)),
        OSSL_FXN_div_ctx_size_from_nums(fxn_lcm, NULL, fxn_p1q1, fxn_gcd));
    if (fxn_size == 0)
        goto err;
    /* TODO(FIXNUM): a secure arena is a possible future consideration */
    fxn_ctx = OSSL_FXN_CTX_new_size(NULL, fxn_size);
    if (fxn_ctx == NULL)
        goto err;

    /* p-1 and q-1 */
    if (!OSSL_FXN_copy_truncate(fxn_p1, fxn_p)
        || !OSSL_FXN_sub_word(fxn_p1, 1)
        || !OSSL_FXN_copy_truncate(fxn_q1, fxn_q)
        || !OSSL_FXN_sub_word(fxn_q1, 1)
        /* (p-1)(q-1) */
        || !OSSL_FXN_mul(fxn_p1q1, fxn_p1, fxn_q1, fxn_ctx)
        /* gcd(p-1, q-1) */
        || !OSSL_FXN_gcd(fxn_gcd, fxn_p1, fxn_q1, fxn_ctx)
        /* LCM((p-1, q-1)) = (p-1)(q-1) / gcd */
        || !OSSL_FXN_div(fxn_lcm, NULL, fxn_p1q1, fxn_gcd, fxn_ctx))
        goto err;

    ret = 1;
err:
    bn_release(p1, (int)p1_sz);
    bn_release(q1, (int)q1_sz);
    bn_release(p1q1, (int)p1q1_sz);
    bn_release(gcd, (int)gcd_sz);
    bn_release(lcm, (int)lcm_sz);
    OSSL_FXN_CTX_free(fxn_ctx);
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
    BN_CTX *ctx = NULL;
    BIGNUM *gcd = NULL;

    if (rsa->n == NULL || rsa->e == NULL)
        return 0;

    nbits = BN_num_bits(rsa->n);
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
    if (!BN_is_odd(rsa->n)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MODULUS);
        return 0;
    }
    /* (Steps b-c): 2^16 < e < 2^256, n and e must be odd */
    if (!ossl_rsa_check_public_exponent(rsa->e)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_PUB_EXPONENT_OUT_OF_RANGE);
        return 0;
    }

    ctx = BN_CTX_new_ex(rsa->libctx);
    gcd = BN_new();
    if (ctx == NULL || gcd == NULL)
        goto err;

    /* (Steps d-f):
     * The modulus is composite, but not a power of a prime.
     * The modulus has no factors smaller than 752.
     */
    if (!BN_gcd(gcd, rsa->n, ossl_bn_get0_small_factors(), ctx)
        || !BN_is_one(gcd)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MODULUS);
        goto err;
    }

    /* Highest number of MR rounds from FIPS 186-5 Section B.3 Table B.1 */
    ret = ossl_bn_miller_rabin_is_prime(rsa->n, 5, ctx, NULL, 1, &status);
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
    BN_free(gcd);
    BN_CTX_free(ctx);
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
    const OSSL_FXN *fxn_n, *fxn_p, *fxn_q;
    OSSL_FXN *prod = NULL;
    OSSL_FXN_CTX *fxn_ctx = NULL;
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

    /*
     * The checks run on OSSL_FXN views, which are unsigned; reject
     * negative components rather than check their magnitudes.
     */
    if (BN_is_negative(rsa->n) || BN_is_negative(rsa->p)
        || BN_is_negative(rsa->q) || BN_is_negative(rsa->e)
        || BN_is_negative(rsa->d)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_KEYPAIR);
        return 0;
    }

    fxn_n = bn_get_ossl_fxn(rsa->n);
    fxn_p = bn_get_ossl_fxn(rsa->p);
    fxn_q = bn_get_ossl_fxn(rsa->q);
    if (fxn_n == NULL || fxn_p == NULL || fxn_q == NULL)
        return 0;

    /* (Step 3.b): check the modulus */
    if ((size_t)nbits != OSSL_FXN_num_bits(fxn_n)) {
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
    prod = OSSL_FXN_secure_new_limbs(ossl_fxn_get_dsize((OSSL_FXN *)fxn_n)
        + 1);
    if (prod == NULL)
        goto err;
    size = OSSL_FXN_mul_ctx_size_from_nums(prod, fxn_p, fxn_q);
    /* TODO(FIXNUM): a secure arena is a possible future consideration */
    if (size == 0
        || (fxn_ctx = OSSL_FXN_CTX_new_size(rsa->libctx, size)) == NULL)
        goto err;
    if (!OSSL_FXN_mul(prod, fxn_p, fxn_q, fxn_ctx))
        goto err;
    if (OSSL_FXN_cmp(fxn_n, prod) != 0) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_REQUEST);
        goto err;
    }
    OSSL_FXN_CTX_free(fxn_ctx);
    fxn_ctx = NULL;

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
    OSSL_FXN_CTX_free(fxn_ctx);
    OSSL_FXN_clear_free(prod);
    BN_CTX_free(ctx);
    return ret;
}
