/*
 * Copyright 2018-2024 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018-2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/core.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "crypto/bn.h"
#include "crypto/fn.h"
#include "crypto/fn_intern.h"
#include "crypto/security_bits.h"
#include "rsa_local.h"

#define RSA_FIPS186_5_MIN_KEYGEN_KEYSIZE 2048
#define RSA_FIPS186_5_MIN_KEYGEN_STRENGTH 112

/*
 * Generate one probable prime (p or q) on OSSL_FN views, converting the
 * BIGNUM parameters at the boundary.  |p_bn| and |Xpo_bn| are the writable
 * results; |p1|, |p2| are optional writable results; |Xp|, |Xp1|, |Xp2|
 * are optional read-only inputs (all BIGNUM, for CAVS testing).  The
 * OSSL_FN generation runs in an explicitly sized OSSL_FN_CTX arena.
 */
static int rsa_fn_gen_prob_prime(BIGNUM *p_bn, BIGNUM *Xpo_bn,
    BIGNUM *p1, BIGNUM *p2,
    const BIGNUM *Xp, const BIGNUM *Xp1,
    const BIGNUM *Xp2, int nbits,
    const BIGNUM *e, BN_GENCB *cb, uint32_t c,
    OSSL_LIB_CTX *libctx)
{
    OSSL_FN_CTX *fn_ctx = NULL;
    OSSL_FN *fn_p = NULL, *fn_Xpo = NULL, *fn_p1 = NULL, *fn_p2 = NULL;
    const OSSL_FN *fn_Xp = NULL, *fn_Xp1 = NULL, *fn_Xp2 = NULL, *fn_e = NULL;
    size_t fn_size, pl;
    int ret = 0, p_bits;

    fn_e = bn_get_ossl_fn(e);
    if (fn_e == NULL)
        return 0;
    fn_Xp = Xp != NULL ? bn_get_ossl_fn(Xp) : NULL;
    fn_Xp1 = Xp1 != NULL ? bn_get_ossl_fn(Xp1) : NULL;
    fn_Xp2 = Xp2 != NULL ? bn_get_ossl_fn(Xp2) : NULL;

    /*
     * The prime and its random draw echo have room for nbits/2 bits; one
     * limb of headroom lets a carry past the width be detected rather
     * than truncated (per the OSSL_FN generation's width contract).
     */
    pl = (size_t)(nbits / 2 + BN_BITS2 - 1) / BN_BITS2 + 1;

    /* Acquire the writable results before OSSL_FN_CTX sizing. */
    fn_p = bn_acquire_ossl_fn(p_bn, (int)pl);
    fn_Xpo = bn_acquire_ossl_fn(Xpo_bn, (int)pl);
    if (fn_p == NULL || fn_Xpo == NULL)
        goto err;
    if (p1 != NULL && (fn_p1 = bn_acquire_ossl_fn(p1, (int)pl)) == NULL)
        goto err;
    if (p2 != NULL && (fn_p2 = bn_acquire_ossl_fn(p2, (int)pl)) == NULL)
        goto err;

    fn_size = ossl_fn_rsa_fips186_5_gen_prob_primes_ctx_size(fn_p, fn_Xpo,
        fn_p1, fn_p2, fn_Xp1, fn_Xp2,
        nbits, fn_e);
    if (fn_size == 0)
        goto err;
    fn_ctx = OSSL_FN_CTX_secure_new_size(libctx, fn_size);
    if (fn_ctx == NULL)
        goto err;

    if (!ossl_fn_rsa_fips186_5_gen_prob_primes(fn_p, fn_Xpo, fn_p1, fn_p2,
            fn_Xp, fn_Xp1, fn_Xp2, nbits,
            fn_e, fn_ctx, cb, c, libctx))
        goto err;

#ifdef BN_DEBUG
    {
        size_t pk_frames, pk_numbers, pk_limbs;

        OSSL_FN_CTX_peak_usage(fn_ctx, &pk_frames, &pk_numbers, &pk_limbs);
        fprintf(stderr,
            "DEBUG[%s]: estimate=%zu peak_frames=%zu peak_numbers=%zu "
            "peak_limbs=%zu (nbits=%d pl=%zu)\n",
            OPENSSL_FUNC, fn_size, pk_frames, pk_numbers, pk_limbs, nbits, pl);
    }
#endif

    p_bits = (int)OSSL_FN_num_bits(fn_p);
    bn_release(p_bn, p_bits > 0 ? (p_bits + BN_BITS2 - 1) / BN_BITS2 : 1);
    p_bits = (int)OSSL_FN_num_bits(fn_Xpo);
    bn_release(Xpo_bn, p_bits > 0 ? (p_bits + BN_BITS2 - 1) / BN_BITS2 : 1);
    if (p1 != NULL) {
        p_bits = (int)OSSL_FN_num_bits(fn_p1);
        bn_release(p1, p_bits > 0 ? (p_bits + BN_BITS2 - 1) / BN_BITS2 : 1);
    }
    if (p2 != NULL) {
        p_bits = (int)OSSL_FN_num_bits(fn_p2);
        bn_release(p2, p_bits > 0 ? (p_bits + BN_BITS2 - 1) / BN_BITS2 : 1);
    }
    ret = 1;
err:
    OSSL_FN_CTX_free(fn_ctx);
    return ret;
}

/*
 * Generate probable primes 'p' & 'q'. See FIPS 186-5 Section A.1.6
 * "Generation of Probable Primes with Conditions Based on Auxiliary Probable
 * Primes".
 *
 * Params:
 *     rsa  Object used to store primes p & q.
 *     test Object used for CAVS testing only.that contains..
 *       p1, p2 The returned auxiliary primes for p.
 *              If NULL they are not returned.
 *       Xp An optional passed in value (that is random number used during
 *          generation of p).
 *       Xp1, Xp2 Optionally passed in randomly generated numbers from which
 *                auxiliary primes p1 & p2 are calculated. If NULL these values
 *                are generated internally.
 *       q1, q2 The returned auxiliary primes for q.
 *              If NULL they are not returned.
 *       Xq An optional passed in value (that is random number used during
 *          generation of q).
 *       Xq1, Xq2 Optionally passed in randomly generated numbers from which
 *                auxiliary primes q1 & q2 are calculated. If NULL these values
 *                are generated internally.
 *     nbits The key size in bits (The size of the modulus n).
 *     e The public exponent.
 *     ctx A BN_CTX object.
 *     cb An optional BIGNUM callback.
 *     a An optional number with a value of 0, 1, 3, 5 or 7 that may be used
 *       to add the requirement p is congruent to a mod 8. The value is ignored
 *       if it is zero.
 *     b An optional number with a value of 0, 1, 3, 5 or 7 that may be used
 *       to add the requirement q is congruent to b mod 8. The value is ignored
 *       if it is zero.
 *
 * Returns: 1 if successful, or  0 otherwise.
 * Notes:
 *     p1, p2, q1, q2 are returned if they are not NULL.
 *     Xp, Xp1, Xp2, Xq, Xq1, Xq2 are optionally passed in.
 *     (Required for CAVS testing).
 */
int ossl_rsa_fips186_5_gen_prob_primes(RSA *rsa, RSA_ACVP_TEST *test,
    int nbits, const BIGNUM *e, BN_CTX *ctx,
    BN_GENCB *cb, uint32_t a, uint32_t b)
{
    int ret = 0, ok;
    /* Temp allocated BIGNUMS */
    BIGNUM *Xpo = NULL, *Xqo = NULL, *tmp = NULL;
    /* Intermediate BIGNUMS that can be returned for testing */
    BIGNUM *p1 = NULL, *p2 = NULL;
    BIGNUM *q1 = NULL, *q2 = NULL;
    /* Intermediate BIGNUMS that can be input for testing */
    BIGNUM *Xp = NULL, *Xp1 = NULL, *Xp2 = NULL;
    BIGNUM *Xq = NULL, *Xq1 = NULL, *Xq2 = NULL;

#if defined(FIPS_MODULE) && !defined(OPENSSL_NO_ACVP_TESTS)
    if (test != NULL) {
        Xp1 = test->Xp1;
        Xp2 = test->Xp2;
        Xq1 = test->Xq1;
        Xq2 = test->Xq2;
        Xp = test->Xp;
        Xq = test->Xq;
        p1 = test->p1;
        p2 = test->p2;
        q1 = test->q1;
        q2 = test->q2;
    }
#endif

    /*
     * (Step 1) Check key length
     * NOTE: SP800-131A Rev1 Disallows key lengths of < 2048 bits for RSA
     * Signature Generation and Key Agree/Transport.
     */
    if (nbits < RSA_FIPS186_5_MIN_KEYGEN_KEYSIZE) {
        ERR_raise(ERR_LIB_RSA, RSA_R_KEY_SIZE_TOO_SMALL);
        return 0;
    }

    /* (Step 2) Check exponent */
    if (!ossl_rsa_check_public_exponent(e)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_PUB_EXPONENT_OUT_OF_RANGE);
        return 0;
    }

    /*
     * (Step 3) Determine strength and check rand generator strength is ok -
     * this step is redundant because the generator always returns a higher
     * strength than is required.
     */

    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    Xpo = BN_CTX_get(ctx);
    Xqo = BN_CTX_get(ctx);
    if (tmp == NULL || Xpo == NULL || Xqo == NULL)
        goto err;
    BN_set_flags(Xpo, BN_FLG_CONSTTIME);
    BN_set_flags(Xqo, BN_FLG_CONSTTIME);

    if (rsa->p == NULL)
        rsa->p = BN_secure_new();
    if (rsa->q == NULL)
        rsa->q = BN_secure_new();
    if (rsa->p == NULL || rsa->q == NULL)
        goto err;
    BN_set_flags(rsa->p, BN_FLG_CONSTTIME);
    BN_set_flags(rsa->q, BN_FLG_CONSTTIME);

    /* (Step 4) Generate p, Xp */
    if (!rsa_fn_gen_prob_prime(rsa->p, Xpo, p1, p2, Xp, Xp1, Xp2,
            nbits, e, cb, a, rsa->libctx))
        goto err;
    for (;;) {
        /* (Step 5) Generate q, Xq*/
        if (!rsa_fn_gen_prob_prime(rsa->q, Xqo, q1, q2, Xq, Xq1, Xq2,
                nbits, e, cb, b, rsa->libctx))
            goto err;

        /* (Step 6) |Xp - Xq| > 2^(nbitlen/2 - 100) */
        ok = ossl_rsa_check_pminusq_diff(tmp, Xpo, Xqo, nbits);
        if (ok < 0)
            goto err;
        if (ok == 0)
            continue;

        /* (Step 6) |p - q| > 2^(nbitlen/2 - 100) */
        ok = ossl_rsa_check_pminusq_diff(tmp, rsa->p, rsa->q, nbits);
        if (ok < 0)
            goto err;
        if (ok == 0)
            continue;
        break; /* successfully finished */
    }
    rsa->dirty_cnt++;
    ret = 1;
err:
    /* (Step 7) Zeroize any internally generated values that are not returned */
    BN_clear(Xpo);
    BN_clear(Xqo);
    BN_clear(tmp);
    if (ret != 1) {
        BN_clear_free(rsa->p);
        rsa->p = NULL;
        BN_clear_free(rsa->q);
        rsa->q = NULL;
    }

    BN_CTX_end(ctx);
    return ret;
}

/*
 * Validates the RSA key size based on the target strength.
 * See SP800-56Br1 6.3.1.1 (Steps 1a-1b)
 *
 * Params:
 *     nbits The key size in bits.
 *     strength The target strength in bits. -1 means the target
 *              strength is unknown.
 * Returns: 1 if the key size matches the target strength, or 0 otherwise.
 */
int ossl_rsa_sp800_56b_validate_strength(int nbits, int strength)
{
    int s = (int)ossl_ifc_ffc_compute_security_bits(nbits);

#ifdef FIPS_MODULE
    if (s < RSA_FIPS186_5_MIN_KEYGEN_STRENGTH) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MODULUS);
        return 0;
    }
#endif
    if (strength != -1 && s != strength) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_STRENGTH);
        return 0;
    }
    return 1;
}

/*
 * Validate that the random bit generator is of sufficient strength to generate
 * a key of the specified length.
 */
static int rsa_validate_rng_strength(EVP_RAND_CTX *rng, int nbits)
{
    if (rng == NULL)
        return 0;
#ifdef FIPS_MODULE
    /*
     * This should become mainstream once similar tests are added to the other
     * key generations and once there is a way to disable these checks.
     */
    if (EVP_RAND_get_strength(rng) < ossl_ifc_ffc_compute_security_bits(nbits)) {
        ERR_raise(ERR_LIB_RSA,
            RSA_R_RANDOMNESS_SOURCE_STRENGTH_INSUFFICIENT);
        return 0;
    }
#endif
    return 1;
}

/*
 *
 * Using p & q, calculate other required parameters such as n, d.
 * as well as the CRT parameters dP, dQ, qInv.
 *
 * See SP800-56Br1
 *   6.3.1.1 rsakpg1 - basic (Steps 3-4)
 *   6.3.1.3 rsakpg1 - crt   (Step 5)
 *
 * Params:
 *     rsa An rsa object.
 *     nbits The key size.
 *     e The public exponent.
 *     ctx A BN_CTX object.
 * Notes:
 *   There is a small chance that the generated d will be too small.
 * Returns: -1 = error,
 *           0 = d is too small,
 *           1 = success.
 *
 * SP800-56b key generation always passes a non NULL value for e.
 * For other purposes, if e is NULL then it is assumed that e, n and d are
 * already set in the RSA key and do not need to be recalculated.
 */
int ossl_rsa_sp800_56b_derive_params_from_pq(RSA *rsa, int nbits,
    const BIGNUM *e, BN_CTX *ctx)
{
    int ret = -1;
    BIGNUM *p1, *q1, *lcm, *p1q1, *gcd;
    BN_CTX_start(ctx);
    p1 = BN_CTX_get(ctx);
    q1 = BN_CTX_get(ctx);
    lcm = BN_CTX_get(ctx);
    p1q1 = BN_CTX_get(ctx);
    gcd = BN_CTX_get(ctx);
    if (gcd == NULL)
        goto err;

    BN_set_flags(p1, BN_FLG_CONSTTIME);
    BN_set_flags(q1, BN_FLG_CONSTTIME);
    BN_set_flags(lcm, BN_FLG_CONSTTIME);
    BN_set_flags(p1q1, BN_FLG_CONSTTIME);
    BN_set_flags(gcd, BN_FLG_CONSTTIME);

    /* LCM((p-1, q-1)) */
    if (ossl_rsa_get_lcm(ctx, rsa->p, rsa->q, lcm, gcd, p1, q1, p1q1) != 1)
        goto err;

    /*
     * if e is provided as a parameter, don't recompute e, d or n
     */
    if (e != NULL) {
        OSSL_FN_CTX *fn_ctx = NULL;
        OSSL_FN *fn_d = NULL, *fn_n = NULL;
        const OSSL_FN *fn_e, *fn_lcm, *fn_p, *fn_q;
        size_t nl, fn_size;
        int d_bits;

        /* copy e */
        BN_free(rsa->e);
        rsa->e = BN_dup(e);
        if (rsa->e == NULL)
            goto err;

        BN_clear_free(rsa->d);
        /* (Step 3) d = (e^-1) mod (LCM(p-1, q-1)) */
        rsa->d = BN_secure_new();
        if (rsa->d == NULL)
            goto err;
        BN_set_flags(rsa->d, BN_FLG_CONSTTIME);

        fn_e = bn_get_ossl_fn(rsa->e);
        fn_lcm = bn_get_ossl_fn(lcm);
        fn_p = bn_get_ossl_fn(rsa->p);
        fn_q = bn_get_ossl_fn(rsa->q);
        if (fn_e == NULL || fn_lcm == NULL || fn_p == NULL || fn_q == NULL)
            goto err;
        nl = ossl_fn_get_dsize((OSSL_FN *)fn_lcm);

        /* (Step 3) d = (e^-1) mod lcm, on OSSL_FN views. */
        if ((fn_d = bn_acquire_ossl_fn(rsa->d, (int)nl)) == NULL)
            goto err;
        fn_size = OSSL_FN_mod_inverse_ctx_size(fn_d, fn_e, fn_lcm);
        if (fn_size == 0)
            goto err;
        fn_ctx = OSSL_FN_CTX_secure_new_size(rsa->libctx, fn_size);
        if (fn_ctx == NULL)
            goto err;
        if (!OSSL_FN_mod_inverse(fn_d, fn_e, fn_lcm, fn_ctx))
            goto fn_err;
        d_bits = (int)OSSL_FN_num_bits(fn_d);
        bn_release(rsa->d, d_bits > 0 ? (d_bits + BN_BITS2 - 1) / BN_BITS2 : 1);
        fn_d = NULL;
        OSSL_FN_CTX_free(fn_ctx);
        fn_ctx = NULL;

        /* (Step 3) return an error if d is too small */
        if (BN_num_bits(rsa->d) <= (nbits >> 1)) {
            ret = 0;
            goto err;
        }

        /* (Step 4) n = pq */
        if (rsa->n == NULL)
            rsa->n = BN_new();
        if (rsa->n == NULL)
            goto err;
        {
            size_t npl = ossl_fn_get_dsize((OSSL_FN *)fn_p);
            size_t nql = ossl_fn_get_dsize((OSSL_FN *)fn_q);

            if ((fn_n = bn_acquire_ossl_fn(rsa->n, (int)(npl + nql))) == NULL)
                goto err;
            fn_size = OSSL_FN_mul_ctx_size(fn_n, fn_p, fn_q);
            if (fn_size == 0)
                goto err;
            fn_ctx = OSSL_FN_CTX_new_size(rsa->libctx, fn_size);
            if (fn_ctx == NULL)
                goto err;
            if (!OSSL_FN_mul(fn_n, fn_p, fn_q, fn_ctx))
                goto fn_err;
            bn_release(rsa->n, (int)(npl + nql));
            fn_n = NULL;
            OSSL_FN_CTX_free(fn_ctx);
            fn_ctx = NULL;
        }
        goto derived;

    fn_err:
        OSSL_FN_CTX_free(fn_ctx);
        goto err;
    }

derived:;

    /* (Step 5a) dP = d mod (p-1) */
    if (rsa->dmp1 == NULL)
        rsa->dmp1 = BN_secure_new();
    if (rsa->dmp1 == NULL)
        goto err;
    BN_set_flags(rsa->dmp1, BN_FLG_CONSTTIME);
    /* (Step 5b) dQ = d mod (q-1) */
    if (rsa->dmq1 == NULL)
        rsa->dmq1 = BN_secure_new();
    if (rsa->dmq1 == NULL)
        goto err;
    BN_set_flags(rsa->dmq1, BN_FLG_CONSTTIME);
    /* (Step 5c) qInv = (inverse of q) mod p */
    BN_free(rsa->iqmp);
    rsa->iqmp = BN_secure_new();
    if (rsa->iqmp == NULL)
        goto err;
    BN_set_flags(rsa->iqmp, BN_FLG_CONSTTIME);

    /*
     * Steps 5a-5c on OSSL_FN views: dP = d mod (p-1), dQ = d mod (q-1),
     * qInv = q^-1 mod p.  p1 and q1 already hold p-1 and q-1.  The
     * operations run sequentially in one arena, each in its own frame, so
     * the arena is sized for the largest single operation; this block
     * opens no frame of its own (it only passes fn_ctx down).
     */
    {
        OSSL_FN_CTX *fn_ctx = NULL;
        OSSL_FN *fn_dmp1 = NULL, *fn_dmq1 = NULL, *fn_iqmp = NULL;
        const OSSL_FN *fn_d, *fn_p1, *fn_q1, *fn_q, *fn_p;
        size_t fn_size, sz, pl, ql, dl;

        fn_d = bn_get_ossl_fn(rsa->d);
        fn_p1 = bn_get_ossl_fn(p1);
        fn_q1 = bn_get_ossl_fn(q1);
        fn_q = bn_get_ossl_fn(rsa->q);
        fn_p = bn_get_ossl_fn(rsa->p);
        if (fn_d == NULL || fn_p1 == NULL || fn_q1 == NULL || fn_q == NULL
            || fn_p == NULL)
            goto err;
        pl = ossl_fn_get_dsize((OSSL_FN *)fn_p1);
        ql = ossl_fn_get_dsize((OSSL_FN *)fn_q1);
        dl = ossl_fn_get_dsize((OSSL_FN *)fn_p);

        fn_dmp1 = bn_acquire_ossl_fn(rsa->dmp1, (int)pl);
        fn_dmq1 = bn_acquire_ossl_fn(rsa->dmq1, (int)ql);
        fn_iqmp = bn_acquire_ossl_fn(rsa->iqmp, (int)dl);
        if (fn_dmp1 == NULL || fn_dmq1 == NULL || fn_iqmp == NULL)
            goto err;

        fn_size = 0;
        if ((sz = OSSL_FN_mod_ctx_size(fn_dmp1, fn_d, fn_p1)) > fn_size)
            fn_size = sz;
        if ((sz = OSSL_FN_mod_ctx_size(fn_dmq1, fn_d, fn_q1)) > fn_size)
            fn_size = sz;
        if ((sz = OSSL_FN_mod_inverse_ctx_size(fn_iqmp, fn_q, fn_p)) > fn_size)
            fn_size = sz;
        if (fn_size == 0)
            goto err;
        fn_ctx = OSSL_FN_CTX_secure_new_size(rsa->libctx, fn_size);
        if (fn_ctx == NULL)
            goto err;

        if (!OSSL_FN_mod(fn_dmp1, fn_d, fn_p1, fn_ctx)
            || !OSSL_FN_mod(fn_dmq1, fn_d, fn_q1, fn_ctx)
            || !OSSL_FN_mod_inverse(fn_iqmp, fn_q, fn_p, fn_ctx)) {
            OSSL_FN_CTX_free(fn_ctx);
            goto err;
        }

        bn_release(rsa->dmp1, (int)pl);
        bn_release(rsa->dmq1, (int)ql);
        bn_release(rsa->iqmp, (int)dl);
        OSSL_FN_CTX_free(fn_ctx);
    }

    rsa->dirty_cnt++;
    ret = 1;
err:
    if (ret != 1) {
        BN_free(rsa->e);
        rsa->e = NULL;
        BN_free(rsa->d);
        rsa->d = NULL;
        BN_free(rsa->n);
        rsa->n = NULL;
        BN_free(rsa->iqmp);
        rsa->iqmp = NULL;
        BN_free(rsa->dmq1);
        rsa->dmq1 = NULL;
        BN_free(rsa->dmp1);
        rsa->dmp1 = NULL;
    }
    BN_clear(p1);
    BN_clear(q1);
    BN_clear(lcm);
    BN_clear(p1q1);
    BN_clear(gcd);

    BN_CTX_end(ctx);
    return ret;
}

/*
 * Generate a SP800-56B RSA key.
 *
 * See SP800-56Br1 6.3.1 "RSA Key-Pair Generation with a Fixed Public Exponent"
 *    6.3.1.1 rsakpg1 - basic
 *    6.3.1.3 rsakpg1 - crt
 *
 * See also FIPS 186-5 Section A.1.6
 * "Generation of Probable Primes with Conditions Based on Auxiliary
 * Probable Primes."
 *
 * Params:
 *     rsa The rsa object.
 *     nbits The intended key size in bits.
 *     efixed The public exponent. If NULL a default of 65537 is used.
 *     cb An optional BIGNUM callback.
 *     a An optional number with a value of 0, 1, 3, 5 or 7 that may be used
 *       to add the requirement p is congruent to a mod 8. The value is ignored
 *       if it is zero.
 *     b An optional number with a value of 0, 1, 3, 5 or 7 that may be used
 *       to add the requirement q is congruent to b mod 8. The value is ignored
 *       if it is zero.
 * Returns: 1 if successfully generated otherwise it returns 0.
 */
int ossl_rsa_sp800_56b_generate_key(RSA *rsa, int nbits, const BIGNUM *efixed,
    BN_GENCB *cb, uint32_t a, uint32_t b)
{
    int ret = 0;
    int ok;
    BN_CTX *ctx = NULL;
    BIGNUM *e = NULL;
    RSA_ACVP_TEST *info = NULL;
    BIGNUM *tmp;

#if defined(FIPS_MODULE) && !defined(OPENSSL_NO_ACVP_TESTS)
    info = rsa->acvp_test;
#endif

    /* (Steps 1a-1b) : Currently ignores the strength check */
    if (!ossl_rsa_sp800_56b_validate_strength(nbits, -1))
        return 0;

    /* Check that the RNG is capable of generating a key this large */
    if (!rsa_validate_rng_strength(RAND_get0_private(rsa->libctx), nbits))
        return 0;

    ctx = BN_CTX_new_ex(rsa->libctx);
    if (ctx == NULL)
        return 0;

    /* Set default if e is not passed in */
    if (efixed == NULL) {
        e = BN_new();
        if (e == NULL || !BN_set_word(e, 65537))
            goto err;
    } else {
        e = (BIGNUM *)efixed;
    }
    /* (Step 1c) fixed exponent is checked later .*/

    for (;;) {
        /* (Step 2) Generate prime factors */
        if (!ossl_rsa_fips186_5_gen_prob_primes(rsa, info, nbits, e, ctx, cb, a, b))
            goto err;

        /* p>q check and skipping in case of acvp test */
        if (info == NULL && BN_cmp(rsa->p, rsa->q) < 0) {
            tmp = rsa->p;
            rsa->p = rsa->q;
            rsa->q = tmp;
        }

        /* (Steps 3-5) Compute params d, n, dP, dQ, qInv */
        ok = ossl_rsa_sp800_56b_derive_params_from_pq(rsa, nbits, e, ctx);
        if (ok < 0)
            goto err;
        if (ok > 0)
            break;
        /* Gets here if computed d is too small - so try again */
    }

    /* (Step 6) Do pairwise test - optional validity test has been omitted */
    ret = ossl_rsa_sp800_56b_pairwise_test(rsa, ctx);
err:
    if (efixed == NULL)
        BN_free(e);
    BN_CTX_free(ctx);
    return ret;
}

/*
 * See SP800-56Br1 6.3.1.3 (Step 6) Perform a pair-wise consistency test by
 * verifying that: k = (k^e)^d mod n for some integer k where 1 < k < n-1.
 *
 * Returns 1 if the RSA key passes the pairwise test or 0 if it fails.
 */
int ossl_rsa_sp800_56b_pairwise_test(RSA *rsa, BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM *k, *tmp;

    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    k = BN_CTX_get(ctx);
    if (k == NULL)
        goto err;
    BN_set_flags(k, BN_FLG_CONSTTIME);

    ret = (BN_set_word(k, 2)
        && BN_mod_exp(tmp, k, rsa->e, rsa->n, ctx)
        && BN_mod_exp(tmp, tmp, rsa->d, rsa->n, ctx)
        && BN_cmp(k, tmp) == 0);
    if (ret == 0)
        ERR_raise(ERR_LIB_RSA, RSA_R_PAIRWISE_TEST_FAILURE);
err:
    BN_CTX_end(ctx);
    return ret;
}
