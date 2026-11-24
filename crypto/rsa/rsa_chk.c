/*
 * Copyright 1999-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * RSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include "crypto/rsa.h"
#include "crypto/bn.h"
#include "crypto/fxn.h"
#include "crypto/fxn_intern.h"
#include "rsa_local.h"

#ifndef FIPS_MODULE
/*
 * Check that |w| is probably prime, on its OSSL_FXN view.  Returns 1 when
 * probably prime, 0 when composite, -1 on error.
 */
static int rsa_fxn_check_prime(const BIGNUM *w, BN_GENCB *cb,
    OSSL_LIB_CTX *libctx)
{
    OSSL_FXN_CTX *fxn_ctx = NULL;
    const OSSL_FXN *fxn_w = bn_get_ossl_fxn(w);
    size_t fxn_size;
    int ret = -1;

    if (fxn_w == NULL)
        return -1;
    fxn_size = ossl_fxn_check_prime_ctx_size_from_nums(fxn_w);
    if (fxn_size == 0)
        return -1;
    fxn_ctx = OSSL_FXN_CTX_new_size(libctx, fxn_size);
    if (fxn_ctx == NULL)
        return -1;
    ret = ossl_fxn_check_prime(fxn_w, 0, fxn_ctx, 1, cb, libctx);
    OSSL_FXN_CTX_free(fxn_ctx);
    return ret;
}

/* Create an arena of |size| bytes, reporting OOM on failure. */
static OSSL_FXN_CTX *rsa_fxn_ctx_new(size_t size, OSSL_LIB_CTX *libctx)
{
    OSSL_FXN_CTX *fxn_ctx;

    /* TODO(FIXNUM): a secure arena is a possible future consideration */
    if (size != 0 && (fxn_ctx = OSSL_FXN_CTX_new_size(libctx, size)) != NULL)
        return fxn_ctx;

    ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
    return NULL;
}

/**
 * Check an RSA key pair, including any extra primes of a multi-prime key:
 * e is odd and not 1, the primes are prime, n is their product, d*e is 1
 * modulo the lcm of the (prime - 1) values, and the CRT components, when
 * present, are consistent with d and the primes.
 *
 * @param[in]   key     The key to check.
 * @param[in]   cb      The callback for the primality tests, or NULL.
 * @returns             1 if the key is valid, 0 if it is not, -1 on error.
 */
static int rsa_validate_keypair_multiprime(const RSA *key, BN_GENCB *cb)
{
    OSSL_FXN_CTX *fxn_ctx = NULL;
    OSSL_FXN *i = NULL, *j = NULL, *k = NULL, *l = NULL, *m = NULL;
    const OSSL_FXN *fxn_p, *fxn_q, *fxn_d, *fxn_e, *fxn_n;
    size_t fxn_size, nl;
    int ret = 1, ex_primes = 0, idx;
    RSA_PRIME_INFO *pinfo;

    if (key->p == NULL || key->q == NULL || key->n == NULL
        || key->e == NULL || key->d == NULL) {
        ERR_raise(ERR_LIB_RSA, RSA_R_VALUE_MISSING);
        return 0;
    }

    /* multi-prime? */
    if (key->version == RSA_ASN1_VERSION_MULTI) {
        ex_primes = sk_RSA_PRIME_INFO_num(key->prime_infos);
        if (ex_primes <= 0
            || (ex_primes + 2) > ossl_rsa_multip_cap(BN_num_bits(key->n))) {
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MULTI_PRIME_KEY);
            return 0;
        }
    }

    if (BN_is_one(key->e)) {
        ret = 0;
        ERR_raise(ERR_LIB_RSA, RSA_R_BAD_E_VALUE);
    }
    if (!BN_is_odd(key->e)) {
        ret = 0;
        ERR_raise(ERR_LIB_RSA, RSA_R_BAD_E_VALUE);
    }

    /*
     * The checks run on OSSL_FXN views, which are unsigned; reject
     * negative components rather than validate their magnitudes.
     */
    if (BN_is_negative(key->p) || BN_is_negative(key->q)
        || BN_is_negative(key->n) || BN_is_negative(key->e)
        || BN_is_negative(key->d)
        || (key->dmp1 != NULL && BN_is_negative(key->dmp1))
        || (key->dmq1 != NULL && BN_is_negative(key->dmq1))
        || (key->iqmp != NULL && BN_is_negative(key->iqmp))) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_KEYPAIR);
        return 0;
    }
    for (idx = 0; idx < ex_primes; idx++) {
        pinfo = sk_RSA_PRIME_INFO_value(key->prime_infos, idx);
        if (BN_is_negative(pinfo->r) || BN_is_negative(pinfo->d)
            || BN_is_negative(pinfo->t) || BN_is_negative(pinfo->pp)) {
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MULTI_PRIME_KEY);
            return 0;
        }
    }

    /* p prime? */
    if (rsa_fxn_check_prime(key->p, cb, key->libctx) != 1) {
        ret = 0;
        ERR_raise(ERR_LIB_RSA, RSA_R_P_NOT_PRIME);
    }

    /* q prime? */
    if (rsa_fxn_check_prime(key->q, cb, key->libctx) != 1) {
        ret = 0;
        ERR_raise(ERR_LIB_RSA, RSA_R_Q_NOT_PRIME);
    }

    /* r_i prime? */
    for (idx = 0; idx < ex_primes; idx++) {
        pinfo = sk_RSA_PRIME_INFO_value(key->prime_infos, idx);
        if (rsa_fxn_check_prime(pinfo->r, cb, key->libctx) != 1) {
            ret = 0;
            ERR_raise(ERR_LIB_RSA, RSA_R_MP_R_NOT_PRIME);
        }
    }

    if (ret != 1)
        goto err;

    /*
     * All subsequent checks run on OSSL_FXN views of the key material.
     * The temporaries i .. m serve as both scratch and intermediate
     * containers; those that hold products or the LCM of prime-minus-one
     * values are sized at the modulus width, the rest at their natural
     * width.
     */
    fxn_n = bn_get_ossl_fxn(key->n);
    fxn_p = bn_get_ossl_fxn(key->p);
    fxn_q = bn_get_ossl_fxn(key->q);
    fxn_d = bn_get_ossl_fxn(key->d);
    fxn_e = bn_get_ossl_fxn(key->e);
    if (fxn_n == NULL || fxn_p == NULL || fxn_q == NULL || fxn_d == NULL
        || fxn_e == NULL) {
        ret = -1;
        ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
        goto err;
    }
    nl = (size_t)ossl_fxn_get_dsize((OSSL_FXN *)fxn_n);

    /*
     * Phase 1: n = p*q * r_3...r_i?
     *
     * i accumulates the product.  It is sized one limb past the
     * modulus width: the primes' containers may have a top-limb headroom
     * that lets a correct product of n-bit primes spill past n's
     * container, and the comparison against n must see the spill to
     * reject it.  An equal product stays within the modulus width.
     */
    i = OSSL_FXN_secure_new_limbs(nl + 1);
    if (i == NULL) {
        ret = -1;
        ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
        goto err;
    }
    fxn_size = OSSL_FXN_mul_ctx_size_from_nums(i, fxn_p, fxn_q);
    for (idx = 0; idx < ex_primes; idx++) {
        pinfo = sk_RSA_PRIME_INFO_value(key->prime_infos, idx);
        fxn_size = ossl_fxn_ctx_max_size(fxn_size,
            OSSL_FXN_mul_ctx_size_from_nums(i, i, bn_get_ossl_fxn(pinfo->r)));
    }
    if ((fxn_ctx = rsa_fxn_ctx_new(fxn_size, key->libctx)) == NULL) {
        ret = -1;
        goto err;
    }

    if (!OSSL_FXN_mul(i, fxn_p, fxn_q, fxn_ctx)) {
        ret = -1;
        goto err;
    }
    for (idx = 0; idx < ex_primes; idx++) {
        pinfo = sk_RSA_PRIME_INFO_value(key->prime_infos, idx);
        if (!OSSL_FXN_mul(i, i, bn_get_ossl_fxn(pinfo->r), fxn_ctx)) {
            ret = -1;
            goto err;
        }
    }
    if (OSSL_FXN_cmp(i, fxn_n) != 0) {
        ret = 0;
        if (ex_primes)
            ERR_raise(ERR_LIB_RSA, RSA_R_N_DOES_NOT_EQUAL_PRODUCT_OF_PRIMES);
        else
            ERR_raise(ERR_LIB_RSA, RSA_R_N_DOES_NOT_EQUAL_P_Q);
    }
    OSSL_FXN_CTX_free(fxn_ctx);
    fxn_ctx = NULL;

    /*
     * Phase 2: d*e = 1 mod \lambda(n)?, with \lambda(n) the LCM of all the
     * prime-minus-one values.  i, j, k hold p-1, q-1, r_i-1;
     * m is the running LCM and l the product term, both at the
     * modulus width.
     */
    j = OSSL_FXN_secure_new_limbs(nl);
    k = OSSL_FXN_secure_new_limbs(nl);
    l = OSSL_FXN_secure_new_limbs(nl);
    m = OSSL_FXN_secure_new_limbs(nl);
    if (j == NULL || k == NULL || l == NULL || m == NULL) {
        ret = -1;
        ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
        goto err;
    }
    if (!OSSL_FXN_copy(i, fxn_p) || !OSSL_FXN_sub_word(i, 1)
        || !OSSL_FXN_copy(j, fxn_q) || !OSSL_FXN_sub_word(j, 1)) {
        ret = -1;
        goto err;
    }

    /*
     * The arena must cover the largest single step: the div(m, l) has
     * both operands at the modulus width, which dominates the muls, the
     * gcds, and the closing mod_mul.
     */
    fxn_size = OSSL_FXN_div_ctx_size_from_nums(m, NULL, l, m);
    fxn_size = ossl_fxn_ctx_max_size(fxn_size,
        OSSL_FXN_mul_ctx_size_from_nums(l, i, j));
    fxn_size
        = ossl_fxn_ctx_max_size(fxn_size, OSSL_FXN_gcd_ctx_size_from_nums(i, j));
    fxn_size = ossl_fxn_ctx_max_size(fxn_size,
        OSSL_FXN_mod_mul_ctx_size_from_nums(i, fxn_d, fxn_e, m));
    if ((fxn_ctx = rsa_fxn_ctx_new(fxn_size, key->libctx)) == NULL) {
        ret = -1;
        goto err;
    }

    /* now compute m = \lambda(n) = LCM(i, j, r_3 - 1...) */
    if (!OSSL_FXN_mul(l, i, j, fxn_ctx)
        || !OSSL_FXN_gcd(m, i, j, fxn_ctx)
        || !OSSL_FXN_div(m, NULL, l, m, fxn_ctx)) { /* remainder 0 */
        ret = -1;
        goto err;
    }
    for (idx = 0; idx < ex_primes; idx++) {
        pinfo = sk_RSA_PRIME_INFO_value(key->prime_infos, idx);
        if (!OSSL_FXN_copy(k, bn_get_ossl_fxn(pinfo->r))
            || !OSSL_FXN_sub_word(k, 1)
            || !OSSL_FXN_mul(l, m, k, fxn_ctx)
            || !OSSL_FXN_gcd(m, m, k, fxn_ctx)
            || !OSSL_FXN_div(m, NULL, l, m, fxn_ctx)) { /* rem 0 */
            ret = -1;
            goto err;
        }
    }
    if (!OSSL_FXN_mod_mul(i, fxn_d, fxn_e, m, fxn_ctx)) {
        ret = -1;
        goto err;
    }

    if (!OSSL_FXN_is_one(i)) {
        ret = 0;
        ERR_raise(ERR_LIB_RSA, RSA_R_D_E_NOT_CONGRUENT_TO_1);
    }
    OSSL_FXN_CTX_free(fxn_ctx);
    fxn_ctx = NULL;

    /*
     * Phase 3: the CRT parameter checks.  The moduli here are the
     * prime(-minus-one) values, and OSSL_FXN_div sizes its arena divisor
     * copies from the divisor's width, so the p-1 / q-1 / r_i-1 values
     * are kept in prime-width temporaries (pm1, qm1, rm1).
     */
    {
        OSSL_FXN *pm1 = NULL, *qm1 = NULL, *rm1 = NULL;
        size_t pl = (size_t)ossl_fxn_get_dsize((OSSL_FXN *)fxn_p);
        size_t ql = (size_t)ossl_fxn_get_dsize((OSSL_FXN *)fxn_q);
        int phase3 = 1;

        pm1 = OSSL_FXN_secure_new_limbs(pl);
        qm1 = OSSL_FXN_secure_new_limbs(ql);
        if (pm1 == NULL || qm1 == NULL
            || !OSSL_FXN_copy(pm1, fxn_p) || !OSSL_FXN_sub_word(pm1, 1)
            || !OSSL_FXN_copy(qm1, fxn_q) || !OSSL_FXN_sub_word(qm1, 1)) {
            ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
            phase3 = -1;
        }

        /*
         * k serves as the result container for the mod and
         * mod_inverse checks; re-anchor it at the prime width, matching
         * the moduli, so the arena stays proportionate.
         */
        if (phase3 == 1) {
            OSSL_FXN_clear_free(k);
            k = OSSL_FXN_secure_new_limbs(pl > ql ? pl : ql);
            if (k == NULL) {
                ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
                phase3 = -1;
            }
        }

        if (phase3 == 1 && key->dmp1 != NULL && key->dmq1 != NULL
            && key->iqmp != NULL) {
            fxn_size = OSSL_FXN_mod_ctx_size_from_nums(k, fxn_d, pm1);
            fxn_size = ossl_fxn_ctx_max_size(fxn_size,
                OSSL_FXN_mod_ctx_size_from_nums(k, fxn_d, qm1));
            fxn_size = ossl_fxn_ctx_max_size(fxn_size,
                OSSL_FXN_mod_inverse_ctx_size_from_nums(k, fxn_q, fxn_p));
            if ((fxn_ctx = rsa_fxn_ctx_new(fxn_size, key->libctx)) == NULL) {
                phase3 = -1;
            }

            /* dmp1 = d mod (p-1)? */
            if (phase3 == 1 && !OSSL_FXN_mod(k, fxn_d, pm1, fxn_ctx))
                phase3 = -1;
            if (phase3 == 1
                && OSSL_FXN_cmp(k, bn_get_ossl_fxn(key->dmp1)) != 0) {
                ERR_raise(ERR_LIB_RSA, RSA_R_DMP1_NOT_CONGRUENT_TO_D);
                phase3 = 0;
            }

            /* dmq1 = d mod (q-1)? */
            if (phase3 == 1 && !OSSL_FXN_mod(k, fxn_d, qm1, fxn_ctx))
                phase3 = -1;
            if (phase3 == 1
                && OSSL_FXN_cmp(k, bn_get_ossl_fxn(key->dmq1)) != 0) {
                ERR_raise(ERR_LIB_RSA, RSA_R_DMQ1_NOT_CONGRUENT_TO_D);
                phase3 = 0;
            }

            /* iqmp = q^-1 mod p? */
            if (phase3 == 1
                && !OSSL_FXN_mod_inverse(k, fxn_q, fxn_p, fxn_ctx))
                phase3 = -1;
            if (phase3 == 1
                && OSSL_FXN_cmp(k, bn_get_ossl_fxn(key->iqmp)) != 0) {
                ERR_raise(ERR_LIB_RSA, RSA_R_IQMP_NOT_INVERSE_OF_Q);
                phase3 = 0;
            }
            OSSL_FXN_CTX_free(fxn_ctx);
            fxn_ctx = NULL;
        }

        for (idx = 0; phase3 == 1 && idx < ex_primes; idx++) {
            const OSSL_FXN *fxn_r, *fxn_rd, *fxn_pp, *fxn_t;
            OSSL_FXN *kr = NULL;
            size_t rl;

            pinfo = sk_RSA_PRIME_INFO_value(key->prime_infos, idx);
            fxn_r = bn_get_ossl_fxn(pinfo->r);
            fxn_rd = bn_get_ossl_fxn(pinfo->d);
            fxn_pp = bn_get_ossl_fxn(pinfo->pp);
            fxn_t = bn_get_ossl_fxn(pinfo->t);
            if (fxn_r == NULL || fxn_rd == NULL || fxn_pp == NULL
                || fxn_t == NULL) {
                ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
                phase3 = -1;
                break;
            }
            rl = (size_t)ossl_fxn_get_dsize((OSSL_FXN *)fxn_r);

            /*
             * d_i = d mod (r_i - 1)?  The results are r_i-width, so the
             * result container is anchored at r_i's width per prime;
             * k (anchored at p/q's width) can be narrower.
             */
            rm1 = OSSL_FXN_secure_new_limbs(rl);
            kr = OSSL_FXN_secure_new_limbs(rl);
            if (rm1 == NULL || kr == NULL
                || !OSSL_FXN_copy(rm1, fxn_r)
                || !OSSL_FXN_sub_word(rm1, 1)) {
                ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
                phase3 = -1;
                OSSL_FXN_clear_free(kr);
                OSSL_FXN_clear_free(rm1);
                break;
            }
            fxn_size = OSSL_FXN_mod_ctx_size_from_nums(kr, fxn_d, rm1);
            fxn_size = ossl_fxn_ctx_max_size(fxn_size,
                OSSL_FXN_mod_inverse_ctx_size_from_nums(kr, fxn_pp, fxn_r));
            if ((fxn_ctx = rsa_fxn_ctx_new(fxn_size, key->libctx)) == NULL) {
                phase3 = -1;
            } else {
                if (!OSSL_FXN_mod(kr, fxn_d, rm1, fxn_ctx))
                    phase3 = -1;
                if (phase3 == 1 && OSSL_FXN_cmp(kr, fxn_rd) != 0) {
                    ERR_raise(ERR_LIB_RSA,
                        RSA_R_MP_EXPONENT_NOT_CONGRUENT_TO_D);
                    phase3 = 0;
                }
                /* t_i = R_i ^ -1 mod r_i ? */
                if (phase3 == 1
                    && !OSSL_FXN_mod_inverse(kr, fxn_pp, fxn_r, fxn_ctx))
                    phase3 = -1;
                if (phase3 == 1 && OSSL_FXN_cmp(kr, fxn_t) != 0) {
                    ERR_raise(ERR_LIB_RSA,
                        RSA_R_MP_COEFFICIENT_NOT_INVERSE_OF_R);
                    phase3 = 0;
                }
                OSSL_FXN_CTX_free(fxn_ctx);
                fxn_ctx = NULL;
            }
            OSSL_FXN_clear_free(kr);
            OSSL_FXN_clear_free(rm1);
            rm1 = NULL;
        }
        OSSL_FXN_clear_free(pm1);
        OSSL_FXN_clear_free(qm1);
        if (phase3 != 1)
            ret = phase3;
    }

err:
    OSSL_FXN_CTX_free(fxn_ctx);
    OSSL_FXN_clear_free(i);
    OSSL_FXN_clear_free(j);
    OSSL_FXN_clear_free(k);
    OSSL_FXN_clear_free(l);
    OSSL_FXN_clear_free(m);
    return ret;
}
#endif /* FIPS_MODULE */

int ossl_rsa_validate_public(const RSA *key)
{
    return ossl_rsa_sp800_56b_check_public(key);
}

int ossl_rsa_validate_private(const RSA *key)
{
    return ossl_rsa_sp800_56b_check_private(key);
}

int ossl_rsa_validate_pairwise(const RSA *key)
{
#ifdef FIPS_MODULE
    return ossl_rsa_sp800_56b_check_keypair(key, NULL, -1, RSA_bits(key));
#else
    return rsa_validate_keypair_multiprime(key, NULL) > 0;
#endif
}

int RSA_check_key(const RSA *key)
{
    return RSA_check_key_ex(key, NULL);
}

int RSA_check_key_ex(const RSA *key, BN_GENCB *cb)
{
#ifdef FIPS_MODULE
    return ossl_rsa_validate_public(key)
        && ossl_rsa_validate_private(key)
        && ossl_rsa_validate_pairwise(key);
#else
    return rsa_validate_keypair_multiprime(key, cb);
#endif /* FIPS_MODULE */
}
