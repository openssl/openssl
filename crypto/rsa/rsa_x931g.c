/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include "crypto/bn.h"
#include "crypto/fn.h"
#include "crypto/fn_intern.h"
#include "rsa_local.h"

/* X9.31 RSA key derivation and generation */

/*
 * Derive one X9.31 prime into |p| on an OSSL_FN view, converting at the
 * BIGNUM boundary.  |Xp|, |Xp1|, |Xp2| are read-only inputs, |p1|, |p2|
 * optional outputs.
 */
static int rsa_fn_x931_derive_prime(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
    const BIGNUM *Xp, const BIGNUM *Xp1,
    const BIGNUM *Xp2, const BIGNUM *e,
    BN_GENCB *cb, OSSL_LIB_CTX *libctx)
{
    OSSL_FN_CTX *fn_ctx = NULL;
    OSSL_FN *fn_p = NULL, *fn_p1 = NULL, *fn_p2 = NULL;
    const OSSL_FN *fn_Xp, *fn_Xp1, *fn_Xp2, *fn_e;
    size_t pl, fn_size;
    int ret = 0, p_bits;

    fn_Xp = bn_get_ossl_fn(Xp);
    fn_Xp1 = bn_get_ossl_fn(Xp1);
    fn_Xp2 = bn_get_ossl_fn(Xp2);
    fn_e = bn_get_ossl_fn(e);
    if (fn_Xp == NULL || fn_e == NULL)
        return 0;
    pl = ossl_fn_get_dsize((OSSL_FN *)fn_Xp);

    fn_p = bn_acquire_ossl_fn(p, (int)pl);
    if (fn_p == NULL)
        return 0;
    if (p1 != NULL)
        fn_p1 = bn_acquire_ossl_fn(p1, (int)pl);
    if (p2 != NULL)
        fn_p2 = bn_acquire_ossl_fn(p2, (int)pl);

    fn_size = OSSL_FN_X931_derive_prime_ctx_size(fn_p, fn_p1, fn_p2,
        fn_Xp, fn_Xp1, fn_Xp2, fn_e);
    if (fn_size == 0)
        goto err;
    fn_ctx = OSSL_FN_CTX_secure_new_size(libctx, fn_size);
    if (fn_ctx == NULL)
        goto err;

    if (!OSSL_FN_X931_derive_prime(fn_p, fn_p1, fn_p2, fn_Xp, fn_Xp1,
            fn_Xp2, fn_e, fn_ctx, cb, libctx))
        goto err;

    p_bits = (int)OSSL_FN_num_bits(fn_p);
    bn_release(p, p_bits > 0 ? (p_bits + BN_BITS2 - 1) / BN_BITS2 : 1);
    if (p1 != NULL && fn_p1 != NULL) {
        p_bits = (int)OSSL_FN_num_bits(fn_p1);
        bn_release(p1, p_bits > 0 ? (p_bits + BN_BITS2 - 1) / BN_BITS2 : 1);
    }
    if (p2 != NULL && fn_p2 != NULL) {
        p_bits = (int)OSSL_FN_num_bits(fn_p2);
        bn_release(p2, p_bits > 0 ? (p_bits + BN_BITS2 - 1) / BN_BITS2 : 1);
    }
    ret = 1;
err:
    OSSL_FN_CTX_free(fn_ctx);
    return ret;
}

int RSA_X931_derive_ex(RSA *rsa, BIGNUM *p1, BIGNUM *p2, BIGNUM *q1,
    BIGNUM *q2, const BIGNUM *Xp1, const BIGNUM *Xp2,
    const BIGNUM *Xp, const BIGNUM *Xq1, const BIGNUM *Xq2,
    const BIGNUM *Xq, const BIGNUM *e, BN_GENCB *cb)
{
    OSSL_FN_CTX *fn_ctx = NULL;
    OSSL_FN *r0 = NULL, *r1 = NULL, *r2 = NULL, *r3 = NULL;
    OSSL_FN *fn_d = NULL, *fn_n = NULL, *fn_dmp1 = NULL, *fn_dmq1 = NULL;
    OSSL_FN *fn_iqmp = NULL;
    const OSSL_FN *fn_p, *fn_q, *fn_e;
    size_t fn_size, nl, pl, ql;
    int ret = 0, bits;

    if (rsa == NULL)
        goto err;

    if (!rsa->e) {
        rsa->e = BN_dup(e);
        if (!rsa->e)
            goto err;
    } else {
        e = rsa->e;
    }

    /*
     * If not all parameters present only calculate what we can. This allows
     * test programs to output selective parameters.
     */

    if (Xp && rsa->p == NULL) {
        rsa->p = BN_new();
        if (rsa->p == NULL)
            goto err;

        if (!rsa_fn_x931_derive_prime(rsa->p, p1, p2,
                Xp, Xp1, Xp2, e, cb, rsa->libctx))
            goto err;
    }

    if (Xq && rsa->q == NULL) {
        rsa->q = BN_new();
        if (rsa->q == NULL)
            goto err;
        if (!rsa_fn_x931_derive_prime(rsa->q, q1, q2,
                Xq, Xq1, Xq2, e, cb, rsa->libctx))
            goto err;
    }

    if (rsa->p == NULL || rsa->q == NULL)
        return 2;

    /*
     * Since both primes are set we can now calculate all remaining
     * components on OSSL_FN views.
     */
    fn_p = bn_get_ossl_fn(rsa->p);
    fn_q = bn_get_ossl_fn(rsa->q);
    fn_e = bn_get_ossl_fn(rsa->e);
    if (fn_p == NULL || fn_q == NULL || fn_e == NULL)
        goto err;
    pl = ossl_fn_get_dsize((OSSL_FN *)fn_p);
    ql = ossl_fn_get_dsize((OSSL_FN *)fn_q);
    nl = pl + ql;

    /* n = p*q */
    rsa->n = BN_new();
    if (rsa->n == NULL)
        goto err;
    fn_n = bn_acquire_ossl_fn(rsa->n, (int)nl);
    if (fn_n == NULL)
        goto err;

    /* d = e^-1 mod LCM(p-1, q-1); dmp1, dmq1, iqmp */
    rsa->d = BN_secure_new();
    rsa->dmp1 = BN_secure_new();
    rsa->dmq1 = BN_secure_new();
    rsa->iqmp = BN_secure_new();
    if (rsa->d == NULL || rsa->dmp1 == NULL || rsa->dmq1 == NULL
        || rsa->iqmp == NULL)
        goto err;
    BN_set_flags(rsa->d, BN_FLG_CONSTTIME);
    BN_set_flags(rsa->dmp1, BN_FLG_CONSTTIME);
    BN_set_flags(rsa->dmq1, BN_FLG_CONSTTIME);
    BN_set_flags(rsa->iqmp, BN_FLG_CONSTTIME);

    fn_d = bn_acquire_ossl_fn(rsa->d, (int)nl);
    fn_dmp1 = bn_acquire_ossl_fn(rsa->dmp1, (int)pl);
    fn_dmq1 = bn_acquire_ossl_fn(rsa->dmq1, (int)ql);
    fn_iqmp = bn_acquire_ossl_fn(rsa->iqmp, (int)pl);
    if (fn_d == NULL || fn_dmp1 == NULL || fn_dmq1 == NULL || fn_iqmp == NULL)
        goto err;

    /* scratch: r0 (LCM, n-wide), r1 (p-1), r2 (q-1), r3 (gcd) */
    r0 = OSSL_FN_secure_new_limbs(nl);
    r1 = OSSL_FN_secure_new_limbs(pl);
    r2 = OSSL_FN_secure_new_limbs(ql);
    r3 = OSSL_FN_secure_new_limbs(pl < ql ? pl : ql);
    if (r0 == NULL || r1 == NULL || r2 == NULL || r3 == NULL)
        goto err;

    /* p-1, q-1 */
    if (!OSSL_FN_copy(r1, fn_p) || !OSSL_FN_sub_word(r1, 1)
        || !OSSL_FN_copy(r2, fn_q) || !OSSL_FN_sub_word(r2, 1))
        goto err;

    /*
     * The operations run sequentially in one arena, each in its own frame,
     * so the arena is sized for the largest single operation.
     */
    fn_size = OSSL_FN_mul_ctx_size(fn_n, fn_p, fn_q);
    fn_size = ossl_fn_ctx_max_size(fn_size,
        OSSL_FN_mul_ctx_size(r0, r1, r2));
    fn_size = ossl_fn_ctx_max_size(fn_size,
        OSSL_FN_gcd_ctx_size(r1, r2));
    fn_size = ossl_fn_ctx_max_size(fn_size,
        OSSL_FN_div_ctx_size(r0, NULL, r0, r3));
    fn_size = ossl_fn_ctx_max_size(fn_size,
        OSSL_FN_mod_inverse_ctx_size(fn_d, fn_e, r0));
    fn_size = ossl_fn_ctx_max_size(fn_size,
        OSSL_FN_mod_ctx_size(fn_dmp1, fn_d, r1));
    fn_size = ossl_fn_ctx_max_size(fn_size,
        OSSL_FN_mod_ctx_size(fn_dmq1, fn_d, r2));
    fn_size = ossl_fn_ctx_max_size(fn_size,
        OSSL_FN_mod_inverse_ctx_size(fn_iqmp, fn_q, fn_p));
    if (fn_size == 0)
        goto err;
    fn_ctx = OSSL_FN_CTX_secure_new_size(rsa->libctx, fn_size);
    if (fn_ctx == NULL)
        goto err;

    if (!OSSL_FN_mul(fn_n, fn_p, fn_q, fn_ctx))
        goto err;

    /* LCM((p-1)(q-1)) into r0 */
    if (!OSSL_FN_mul(r0, r1, r2, fn_ctx)
        || !OSSL_FN_gcd(r3, r1, r2, fn_ctx)
        || !OSSL_FN_div(r0, NULL, r0, r3, fn_ctx))
        goto err;

    /* d = e^-1 mod LCM */
    if (!OSSL_FN_mod_inverse(fn_d, fn_e, r0, fn_ctx))
        goto err;

    /* dmp1 = d mod (p-1), dmq1 = d mod (q-1), iqmp = q^-1 mod p */
    if (!OSSL_FN_mod(fn_dmp1, fn_d, r1, fn_ctx)
        || !OSSL_FN_mod(fn_dmq1, fn_d, r2, fn_ctx)
        || !OSSL_FN_mod_inverse(fn_iqmp, fn_q, fn_p, fn_ctx))
        goto err;

    bn_release(rsa->n, (int)nl);
    bits = (int)OSSL_FN_num_bits(fn_d);
    bn_release(rsa->d, bits > 0 ? (bits + BN_BITS2 - 1) / BN_BITS2 : 1);
    bn_release(rsa->dmp1, (int)pl);
    bn_release(rsa->dmq1, (int)ql);
    bn_release(rsa->iqmp, (int)pl);

    rsa->dirty_cnt++;
    ret = 1;
err:
    OSSL_FN_CTX_free(fn_ctx);
    OSSL_FN_clear_free(r0);
    OSSL_FN_clear_free(r1);
    OSSL_FN_clear_free(r2);
    OSSL_FN_clear_free(r3);

    return ret;
}

int RSA_X931_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e,
    BN_GENCB *cb)
{
    int ok = 0;
    OSSL_FN_CTX *fn_ctx = NULL;
    OSSL_FN *Xp = NULL, *Xq = NULL;
    size_t xpl, fn_size;

    /*
     * Xp and Xq carry bits/2 bits, rounded up to a limb, plus the headroom
     * the X931 generator expects.
     */
    xpl = (size_t)((bits / 2 + BN_BITS2 - 1) / BN_BITS2) + 1;
    Xp = OSSL_FN_secure_new_limbs(xpl);
    Xq = OSSL_FN_secure_new_limbs(xpl);
    if (Xp == NULL || Xq == NULL)
        goto error;

    fn_size = OSSL_FN_X931_generate_Xpq_ctx_size(Xp);
    if (fn_size == 0)
        goto error;
    fn_ctx = OSSL_FN_CTX_secure_new_size(rsa->libctx, fn_size);
    if (fn_ctx == NULL)
        goto error;
    if (!OSSL_FN_X931_generate_Xpq(Xp, Xq, bits, fn_ctx, rsa->libctx))
        goto error;
    OSSL_FN_CTX_free(fn_ctx);
    fn_ctx = NULL;

    rsa->p = BN_new();
    rsa->q = BN_new();
    if (rsa->p == NULL || rsa->q == NULL)
        goto error;

    /* Generate two primes from Xp, Xq */
    {
        const OSSL_FN *fn_e = bn_get_ossl_fn(e);
        OSSL_FN *fn_p, *fn_q;

        if (fn_e == NULL)
            goto error;
        fn_p = bn_acquire_ossl_fn(rsa->p, (int)xpl);
        fn_q = bn_acquire_ossl_fn(rsa->q, (int)xpl);
        if (fn_p == NULL || fn_q == NULL)
            goto error;

        fn_size = OSSL_FN_X931_generate_prime_ctx_size(fn_p, NULL, NULL,
            Xp, fn_e);
        if (fn_size == 0)
            goto error;
        fn_ctx = OSSL_FN_CTX_secure_new_size(rsa->libctx, fn_size);
        if (fn_ctx == NULL)
            goto error;
        if (!OSSL_FN_X931_generate_prime(fn_p, NULL, NULL, NULL, NULL,
                Xp, fn_e, fn_ctx, cb, rsa->libctx))
            goto x931_err;
        OSSL_FN_CTX_free(fn_ctx);
        fn_ctx = NULL;

        fn_size = OSSL_FN_X931_generate_prime_ctx_size(fn_q, NULL, NULL,
            Xq, fn_e);
        if (fn_size == 0)
            goto error;
        fn_ctx = OSSL_FN_CTX_secure_new_size(rsa->libctx, fn_size);
        if (fn_ctx == NULL)
            goto error;
        if (!OSSL_FN_X931_generate_prime(fn_q, NULL, NULL, NULL, NULL,
                Xq, fn_e, fn_ctx, cb, rsa->libctx))
            goto x931_err;
        OSSL_FN_CTX_free(fn_ctx);
        fn_ctx = NULL;

        {
            int p_bits = (int)OSSL_FN_num_bits(fn_p);
            int q_bits = (int)OSSL_FN_num_bits(fn_q);

            bn_release(rsa->p,
                p_bits > 0 ? (p_bits + BN_BITS2 - 1) / BN_BITS2 : 1);
            bn_release(rsa->q,
                q_bits > 0 ? (q_bits + BN_BITS2 - 1) / BN_BITS2 : 1);
        }
        goto generated;

    x931_err:
        OSSL_FN_CTX_free(fn_ctx);
        fn_ctx = NULL;
        goto error;
    }

generated:

    /*
     * Since rsa->p and rsa->q are valid this call will just derive remaining
     * RSA components.
     */
    if (!RSA_X931_derive_ex(rsa, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL, e, cb))
        goto error;

    rsa->dirty_cnt++;
    ok = 1;

error:
    OSSL_FN_CTX_free(fn_ctx);
    OSSL_FN_clear_free(Xp);
    OSSL_FN_clear_free(Xq);

    return ok;
}
