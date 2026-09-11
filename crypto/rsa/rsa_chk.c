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
#include "crypto/fn.h"
#include "crypto/fn_intern.h"
#include "rsa_local.h"

#ifndef FIPS_MODULE
/*
 * Check that |w| is probably prime, on its OSSL_FN view.  Returns 1 when
 * probably prime, 0 when composite, -1 on error.
 */
static int rsa_fn_check_prime(const BIGNUM *w, BN_GENCB *cb,
    OSSL_LIB_CTX *libctx)
{
    OSSL_FN_CTX *fn_ctx = NULL;
    const OSSL_FN *fn_w = bn_get_ossl_fn(w);
    size_t fn_size;
    int ret = -1;

    if (fn_w == NULL)
        return -1;
    fn_size = ossl_fn_check_prime_ctx_size(fn_w);
    if (fn_size == 0)
        return -1;
    fn_ctx = OSSL_FN_CTX_new_size(libctx, fn_size);
    if (fn_ctx == NULL)
        return -1;
    ret = ossl_fn_check_prime(fn_w, 0, fn_ctx, 1, cb, libctx);
    OSSL_FN_CTX_free(fn_ctx);
    return ret;
}

/* Create a secure arena of |size| bytes, reporting OOM on failure. */
static OSSL_FN_CTX *rsa_fn_ctx_new(size_t size, OSSL_LIB_CTX *libctx)
{
    OSSL_FN_CTX *fn_ctx;

    if (size == 0
        || (fn_ctx = OSSL_FN_CTX_secure_new_size(libctx, size)) == NULL)
        ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
    else
        return fn_ctx;
    return NULL;
}

static int rsa_validate_keypair_multiprime(const RSA *key, BN_GENCB *cb)
{
    OSSL_FN_CTX *fn_ctx = NULL;
    OSSL_FN *i = NULL, *j = NULL, *k = NULL, *l = NULL, *m = NULL;
    const OSSL_FN *fn_p, *fn_q, *fn_d, *fn_e, *fn_n;
    size_t fn_size, nl;
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

    /* p prime? */
    if (rsa_fn_check_prime(key->p, cb, key->libctx) != 1) {
        ret = 0;
        ERR_raise(ERR_LIB_RSA, RSA_R_P_NOT_PRIME);
    }

    /* q prime? */
    if (rsa_fn_check_prime(key->q, cb, key->libctx) != 1) {
        ret = 0;
        ERR_raise(ERR_LIB_RSA, RSA_R_Q_NOT_PRIME);
    }

    /* r_i prime? */
    for (idx = 0; idx < ex_primes; idx++) {
        pinfo = sk_RSA_PRIME_INFO_value(key->prime_infos, idx);
        if (rsa_fn_check_prime(pinfo->r, cb, key->libctx) != 1) {
            ret = 0;
            ERR_raise(ERR_LIB_RSA, RSA_R_MP_R_NOT_PRIME);
        }
    }

    if (ret != 1)
        goto err;

    /*
     * All subsequent checks run on OSSL_FN views of the key material.
     * The temporaries i .. m serve as both scratch and intermediate
     * containers; those that hold products or the LCM of prime-minus-one
     * values are sized at the modulus width, the rest at their natural
     * width.
     */
    fn_n = bn_get_ossl_fn(key->n);
    fn_p = bn_get_ossl_fn(key->p);
    fn_q = bn_get_ossl_fn(key->q);
    fn_d = bn_get_ossl_fn(key->d);
    fn_e = bn_get_ossl_fn(key->e);
    if (fn_n == NULL || fn_p == NULL || fn_q == NULL || fn_d == NULL
        || fn_e == NULL) {
        ret = -1;
        ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
        goto err;
    }
    nl = (size_t)ossl_fn_get_dsize((OSSL_FN *)fn_n);

    /*
     * Phase 1: n = p*q * r_3...r_i?
     *
     * i accumulates the product.  It is sized one limb past the
     * modulus width: the primes' containers may have a top-limb headroom
     * that lets a correct product of n-bit primes spill past n's
     * container, and the comparison against n must see the spill to
     * reject it.  An equal product stays within the modulus width.
     */
    i = OSSL_FN_secure_new_limbs(nl + 1);
    if (i == NULL) {
        ret = -1;
        ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
        goto err;
    }
    fn_size = OSSL_FN_mul_ctx_size(i, fn_p, fn_q);
    for (idx = 0; idx < ex_primes; idx++) {
        pinfo = sk_RSA_PRIME_INFO_value(key->prime_infos, idx);
        fn_size = ossl_fn_ctx_max_size(fn_size,
            OSSL_FN_mul_ctx_size(i, i, bn_get_ossl_fn(pinfo->r)));
    }
    if ((fn_ctx = rsa_fn_ctx_new(fn_size, key->libctx)) == NULL) {
        ret = -1;
        goto err;
    }

    if (!OSSL_FN_mul(i, fn_p, fn_q, fn_ctx)) {
        ret = -1;
        goto err;
    }
    for (idx = 0; idx < ex_primes; idx++) {
        pinfo = sk_RSA_PRIME_INFO_value(key->prime_infos, idx);
        if (!OSSL_FN_mul(i, i, bn_get_ossl_fn(pinfo->r), fn_ctx)) {
            ret = -1;
            goto err;
        }
    }
    if (OSSL_FN_cmp(i, fn_n) != 0) {
        ret = 0;
        if (ex_primes)
            ERR_raise(ERR_LIB_RSA, RSA_R_N_DOES_NOT_EQUAL_PRODUCT_OF_PRIMES);
        else
            ERR_raise(ERR_LIB_RSA, RSA_R_N_DOES_NOT_EQUAL_P_Q);
    }
    OSSL_FN_CTX_free(fn_ctx);
    fn_ctx = NULL;

    /*
     * Phase 2: d*e = 1 mod \lambda(n)?, with \lambda(n) the LCM of all the
     * prime-minus-one values.  i, j, k hold p-1, q-1, r_i-1;
     * m is the running LCM and l the product term, both at the
     * modulus width.
     */
    j = OSSL_FN_secure_new_limbs(nl);
    k = OSSL_FN_secure_new_limbs(nl);
    l = OSSL_FN_secure_new_limbs(nl);
    m = OSSL_FN_secure_new_limbs(nl);
    if (j == NULL || k == NULL || l == NULL || m == NULL) {
        ret = -1;
        ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
        goto err;
    }
    if (!OSSL_FN_copy(i, fn_p) || !OSSL_FN_sub_word(i, 1)
        || !OSSL_FN_copy(j, fn_q) || !OSSL_FN_sub_word(j, 1)) {
        ret = -1;
        goto err;
    }

    /*
     * The arena must cover the largest single step: the div(m, l) has
     * both operands at the modulus width, which dominates the muls, the
     * gcds, and the closing mod_mul.
     */
    fn_size = OSSL_FN_div_ctx_size(m, NULL, l, m);
    fn_size = ossl_fn_ctx_max_size(fn_size,
        OSSL_FN_mul_ctx_size(l, i, j));
    fn_size = ossl_fn_ctx_max_size(fn_size, OSSL_FN_gcd_ctx_size(i, j));
    fn_size = ossl_fn_ctx_max_size(fn_size,
        OSSL_FN_mod_mul_ctx_size(i, fn_d, fn_e, m));
    if ((fn_ctx = rsa_fn_ctx_new(fn_size, key->libctx)) == NULL) {
        ret = -1;
        goto err;
    }

    /* now compute m = \lambda(n) = LCM(i, j, r_3 - 1...) */
    if (!OSSL_FN_mul(l, i, j, fn_ctx)
        || !OSSL_FN_gcd(m, i, j, fn_ctx)
        || !OSSL_FN_div(m, NULL, l, m, fn_ctx)) { /* remainder 0 */
        ret = -1;
        goto err;
    }
    for (idx = 0; idx < ex_primes; idx++) {
        pinfo = sk_RSA_PRIME_INFO_value(key->prime_infos, idx);
        if (!OSSL_FN_copy(k, bn_get_ossl_fn(pinfo->r))
            || !OSSL_FN_sub_word(k, 1)
            || !OSSL_FN_mul(l, m, k, fn_ctx)
            || !OSSL_FN_gcd(m, m, k, fn_ctx)
            || !OSSL_FN_div(m, NULL, l, m, fn_ctx)) { /* rem 0 */
            ret = -1;
            goto err;
        }
    }
    if (!OSSL_FN_mod_mul(i, fn_d, fn_e, m, fn_ctx)) {
        ret = -1;
        goto err;
    }

    if (!OSSL_FN_is_one(i)) {
        ret = 0;
        ERR_raise(ERR_LIB_RSA, RSA_R_D_E_NOT_CONGRUENT_TO_1);
    }
    OSSL_FN_CTX_free(fn_ctx);
    fn_ctx = NULL;

    /*
     * Phase 3: the CRT parameter checks.  The moduli here are the
     * prime(-minus-one) values, and OSSL_FN_div sizes its arena divisor
     * copies from the divisor's width, so the p-1 / q-1 / r_i-1 values
     * are kept in prime-width temporaries (pm1, qm1, rm1).
     */
    {
        OSSL_FN *pm1 = NULL, *qm1 = NULL, *rm1 = NULL;
        size_t pl = (size_t)ossl_fn_get_dsize((OSSL_FN *)fn_p);
        size_t ql = (size_t)ossl_fn_get_dsize((OSSL_FN *)fn_q);
        int phase3 = 1;

        pm1 = OSSL_FN_secure_new_limbs(pl);
        qm1 = OSSL_FN_secure_new_limbs(ql);
        if (pm1 == NULL || qm1 == NULL
            || !OSSL_FN_copy(pm1, fn_p) || !OSSL_FN_sub_word(pm1, 1)
            || !OSSL_FN_copy(qm1, fn_q) || !OSSL_FN_sub_word(qm1, 1)) {
            ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
            phase3 = -1;
        }

        /*
         * k serves as the result container for the mod and
         * mod_inverse checks; re-anchor it at the prime width, matching
         * the moduli, so the arena stays proportionate.
         */
        if (phase3 == 1) {
            OSSL_FN_clear_free(k);
            k = OSSL_FN_secure_new_limbs(pl > ql ? pl : ql);
            if (k == NULL) {
                ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
                phase3 = -1;
            }
        }

        if (phase3 == 1 && key->dmp1 != NULL && key->dmq1 != NULL
            && key->iqmp != NULL) {
            fn_size = OSSL_FN_mod_ctx_size(k, fn_d, pm1);
            fn_size = ossl_fn_ctx_max_size(fn_size,
                OSSL_FN_mod_ctx_size(k, fn_d, qm1));
            fn_size = ossl_fn_ctx_max_size(fn_size,
                OSSL_FN_mod_inverse_ctx_size(k, fn_q, fn_p));
            if ((fn_ctx = rsa_fn_ctx_new(fn_size, key->libctx)) == NULL) {
                phase3 = -1;
            }

            /* dmp1 = d mod (p-1)? */
            if (phase3 == 1 && !OSSL_FN_mod(k, fn_d, pm1, fn_ctx))
                phase3 = -1;
            if (phase3 == 1
                && OSSL_FN_cmp(k, bn_get_ossl_fn(key->dmp1)) != 0) {
                ERR_raise(ERR_LIB_RSA, RSA_R_DMP1_NOT_CONGRUENT_TO_D);
                phase3 = 0;
            }

            /* dmq1 = d mod (q-1)? */
            if (phase3 == 1 && !OSSL_FN_mod(k, fn_d, qm1, fn_ctx))
                phase3 = -1;
            if (phase3 == 1
                && OSSL_FN_cmp(k, bn_get_ossl_fn(key->dmq1)) != 0) {
                ERR_raise(ERR_LIB_RSA, RSA_R_DMQ1_NOT_CONGRUENT_TO_D);
                phase3 = 0;
            }

            /* iqmp = q^-1 mod p? */
            if (phase3 == 1
                && !OSSL_FN_mod_inverse(k, fn_q, fn_p, fn_ctx))
                phase3 = -1;
            if (phase3 == 1
                && OSSL_FN_cmp(k, bn_get_ossl_fn(key->iqmp)) != 0) {
                ERR_raise(ERR_LIB_RSA, RSA_R_IQMP_NOT_INVERSE_OF_Q);
                phase3 = 0;
            }
            OSSL_FN_CTX_free(fn_ctx);
            fn_ctx = NULL;
        }

        for (idx = 0; phase3 == 1 && idx < ex_primes; idx++) {
            const OSSL_FN *fn_r, *fn_rd, *fn_pp, *fn_t;
            OSSL_FN *kr = NULL;
            size_t rl;

            pinfo = sk_RSA_PRIME_INFO_value(key->prime_infos, idx);
            fn_r = bn_get_ossl_fn(pinfo->r);
            fn_rd = bn_get_ossl_fn(pinfo->d);
            fn_pp = bn_get_ossl_fn(pinfo->pp);
            fn_t = bn_get_ossl_fn(pinfo->t);
            if (fn_r == NULL || fn_rd == NULL || fn_pp == NULL
                || fn_t == NULL) {
                ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
                phase3 = -1;
                break;
            }
            rl = (size_t)ossl_fn_get_dsize((OSSL_FN *)fn_r);

            /*
             * d_i = d mod (r_i - 1)?  The results are r_i-width, so the
             * result container is anchored at r_i's width per prime;
             * k (anchored at p/q's width) can be narrower.
             */
            rm1 = OSSL_FN_secure_new_limbs(rl);
            kr = OSSL_FN_secure_new_limbs(rl);
            if (rm1 == NULL || kr == NULL
                || !OSSL_FN_copy(rm1, fn_r)
                || !OSSL_FN_sub_word(rm1, 1)) {
                ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
                phase3 = -1;
                OSSL_FN_clear_free(kr);
                break;
            }
            fn_size = OSSL_FN_mod_ctx_size(kr, fn_d, rm1);
            fn_size = ossl_fn_ctx_max_size(fn_size,
                OSSL_FN_mod_inverse_ctx_size(kr, fn_pp, fn_r));
            if ((fn_ctx = rsa_fn_ctx_new(fn_size, key->libctx)) == NULL) {
                phase3 = -1;
            } else {
                if (!OSSL_FN_mod(kr, fn_d, rm1, fn_ctx))
                    phase3 = -1;
                if (phase3 == 1 && OSSL_FN_cmp(kr, fn_rd) != 0) {
                    ERR_raise(ERR_LIB_RSA,
                        RSA_R_MP_EXPONENT_NOT_CONGRUENT_TO_D);
                    phase3 = 0;
                }
                /* t_i = R_i ^ -1 mod r_i ? */
                if (phase3 == 1
                    && !OSSL_FN_mod_inverse(kr, fn_pp, fn_r, fn_ctx))
                    phase3 = -1;
                if (phase3 == 1 && OSSL_FN_cmp(kr, fn_t) != 0) {
                    ERR_raise(ERR_LIB_RSA,
                        RSA_R_MP_COEFFICIENT_NOT_INVERSE_OF_R);
                    phase3 = 0;
                }
                OSSL_FN_CTX_free(fn_ctx);
                fn_ctx = NULL;
            }
            OSSL_FN_clear_free(kr);
            OSSL_FN_clear_free(rm1);
            rm1 = NULL;
        }
        OSSL_FN_clear_free(pm1);
        OSSL_FN_clear_free(qm1);
        if (phase3 != 1)
            ret = phase3;
    }

err:
    OSSL_FN_CTX_free(fn_ctx);
    OSSL_FN_clear_free(i);
    OSSL_FN_clear_free(j);
    OSSL_FN_clear_free(k);
    OSSL_FN_clear_free(l);
    OSSL_FN_clear_free(m);
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
