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
#include "crypto/fxn.h"
#include "crypto/fxn_intern.h"
#include "rsa_local.h"

/* X9.31 RSA key derivation and generation */

/*
 * Derive one X9.31 prime into |p| on an OSSL_FXN view, converting at the
 * BIGNUM boundary.  |Xp|, |Xp1|, |Xp2| are read-only inputs, |p1|, |p2|
 * optional outputs.
 */
static int rsa_fxn_x931_derive_prime(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
    const BIGNUM *Xp, const BIGNUM *Xp1,
    const BIGNUM *Xp2, const BIGNUM *e,
    BN_GENCB *cb, OSSL_LIB_CTX *libctx)
{
    OSSL_FXN_CTX *fxn_ctx = NULL;
    OSSL_FXN *fxn_p = NULL, *fxn_p1 = NULL, *fxn_p2 = NULL;
    const OSSL_FXN *fxn_Xp, *fxn_Xp1, *fxn_Xp2, *fxn_e;
    size_t pl, fxn_size;
    int ret = 0;

    fxn_Xp = bn_get_ossl_fxn(Xp);
    fxn_Xp1 = bn_get_ossl_fxn(Xp1);
    fxn_Xp2 = bn_get_ossl_fxn(Xp2);
    fxn_e = bn_get_ossl_fxn(e);
    if (fxn_Xp == NULL || fxn_e == NULL)
        return 0;
    pl = ossl_fxn_get_dsize((OSSL_FXN *)fxn_Xp);

    fxn_p = bn_acquire_ossl_fxn(p, (int)pl);
    if (fxn_p == NULL)
        return 0;
    if (p1 != NULL
        && (fxn_p1 = bn_acquire_ossl_fxn(p1, (int)pl)) == NULL)
        goto err;
    if (p2 != NULL
        && (fxn_p2 = bn_acquire_ossl_fxn(p2, (int)pl)) == NULL)
        goto err;

    fxn_size = OSSL_FXN_X931_derive_prime_ctx_size_from_nums(fxn_p, fxn_p1, fxn_p2,
        fxn_Xp, fxn_Xp1, fxn_Xp2, fxn_e);
    if (fxn_size == 0)
        goto err;
    /* TODO(FIXNUM): a secure arena is a possible future consideration */
    fxn_ctx = OSSL_FXN_CTX_new_size(libctx, fxn_size);
    if (fxn_ctx == NULL)
        goto err;

    if (!OSSL_FXN_X931_derive_prime(fxn_p, fxn_p1, fxn_p2, fxn_Xp, fxn_Xp1,
            fxn_Xp2, fxn_e, fxn_ctx, cb, libctx))
        goto err;

    ret = 1;
err:
    /*
     * The derived prime and the auxiliary primes fit in Xp's width,
     * which is pl limbs.
     */
    bn_release(p, (int)pl);
    bn_release(p1, (int)pl);
    bn_release(p2, (int)pl);
    OSSL_FXN_CTX_free(fxn_ctx);
    return ret;
}

int RSA_X931_derive_ex(RSA *rsa, BIGNUM *p1, BIGNUM *p2, BIGNUM *q1,
    BIGNUM *q2, const BIGNUM *Xp1, const BIGNUM *Xp2,
    const BIGNUM *Xp, const BIGNUM *Xq1, const BIGNUM *Xq2,
    const BIGNUM *Xq, const BIGNUM *e, BN_GENCB *cb)
{
    OSSL_FXN_CTX *fxn_ctx = NULL;
    OSSL_FXN *r0 = NULL, *r1 = NULL, *r2 = NULL, *r3 = NULL;
    OSSL_FXN *fxn_d = NULL, *fxn_n = NULL, *fxn_dmp1 = NULL, *fxn_dmq1 = NULL;
    OSSL_FXN *fxn_iqmp = NULL;
    const OSSL_FXN *fxn_p, *fxn_q, *fxn_e;
    size_t fxn_size, nl = 0, pl = 0, ql = 0;
    int ret = 0;

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

        if (!rsa_fxn_x931_derive_prime(rsa->p, p1, p2,
                Xp, Xp1, Xp2, e, cb, rsa->libctx))
            goto err;
    }

    if (Xq && rsa->q == NULL) {
        rsa->q = BN_new();
        if (rsa->q == NULL)
            goto err;
        if (!rsa_fxn_x931_derive_prime(rsa->q, q1, q2,
                Xq, Xq1, Xq2, e, cb, rsa->libctx))
            goto err;
    }

    if (rsa->p == NULL || rsa->q == NULL)
        return 2;

    /*
     * Since both primes are set we can now calculate all remaining
     * components on OSSL_FXN views.
     */
    fxn_p = bn_get_ossl_fxn(rsa->p);
    fxn_q = bn_get_ossl_fxn(rsa->q);
    fxn_e = bn_get_ossl_fxn(rsa->e);
    if (fxn_p == NULL || fxn_q == NULL || fxn_e == NULL)
        goto err;
    pl = ossl_fxn_get_dsize((OSSL_FXN *)fxn_p);
    ql = ossl_fxn_get_dsize((OSSL_FXN *)fxn_q);
    nl = pl + ql;

    /* n = p*q */
    rsa->n = BN_new();
    if (rsa->n == NULL)
        goto err;
    fxn_n = bn_acquire_ossl_fxn(rsa->n, (int)nl);
    if (fxn_n == NULL)
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

    fxn_d = bn_acquire_ossl_fxn(rsa->d, (int)nl);
    fxn_dmp1 = bn_acquire_ossl_fxn(rsa->dmp1, (int)pl);
    fxn_dmq1 = bn_acquire_ossl_fxn(rsa->dmq1, (int)ql);
    fxn_iqmp = bn_acquire_ossl_fxn(rsa->iqmp, (int)pl);
    if (fxn_d == NULL || fxn_dmp1 == NULL || fxn_dmq1 == NULL || fxn_iqmp == NULL)
        goto err;

    /* scratch: r0 (LCM, n-wide), r1 (p-1), r2 (q-1), r3 (gcd) */
    r0 = OSSL_FXN_secure_new_limbs(nl);
    r1 = OSSL_FXN_secure_new_limbs(pl);
    r2 = OSSL_FXN_secure_new_limbs(ql);
    r3 = OSSL_FXN_secure_new_limbs(pl < ql ? pl : ql);
    if (r0 == NULL || r1 == NULL || r2 == NULL || r3 == NULL)
        goto err;

    /* p-1, q-1 */
    if (!OSSL_FXN_copy(r1, fxn_p) || !OSSL_FXN_sub_word(r1, 1)
        || !OSSL_FXN_copy(r2, fxn_q) || !OSSL_FXN_sub_word(r2, 1))
        goto err;

    /*
     * The operations run sequentially in one arena, each in its own frame,
     * so the arena is sized for the largest single operation.
     */
    fxn_size = OSSL_FXN_mul_ctx_size_from_nums(fxn_n, fxn_p, fxn_q);
    fxn_size = ossl_fxn_ctx_max_size(fxn_size,
        OSSL_FXN_mul_ctx_size_from_nums(r0, r1, r2));
    fxn_size = ossl_fxn_ctx_max_size(fxn_size,
        OSSL_FXN_gcd_ctx_size_from_nums(r1, r2));
    fxn_size = ossl_fxn_ctx_max_size(fxn_size,
        OSSL_FXN_div_ctx_size_from_nums(r0, NULL, r0, r3));
    fxn_size = ossl_fxn_ctx_max_size(fxn_size,
        OSSL_FXN_mod_inverse_ctx_size_from_nums(fxn_d, fxn_e, r0));
    fxn_size = ossl_fxn_ctx_max_size(fxn_size,
        OSSL_FXN_mod_ctx_size_from_nums(fxn_dmp1, fxn_d, r1));
    fxn_size = ossl_fxn_ctx_max_size(fxn_size,
        OSSL_FXN_mod_ctx_size_from_nums(fxn_dmq1, fxn_d, r2));
    fxn_size = ossl_fxn_ctx_max_size(fxn_size,
        OSSL_FXN_mod_inverse_ctx_size_from_nums(fxn_iqmp, fxn_q, fxn_p));
    if (fxn_size == 0)
        goto err;
    /* TODO(FIXNUM): a secure arena is a possible future consideration */
    fxn_ctx = OSSL_FXN_CTX_new_size(rsa->libctx, fxn_size);
    if (fxn_ctx == NULL)
        goto err;

    if (!OSSL_FXN_mul(fxn_n, fxn_p, fxn_q, fxn_ctx))
        goto err;

    /* LCM((p-1)(q-1)) into r0 */
    if (!OSSL_FXN_mul(r0, r1, r2, fxn_ctx)
        || !OSSL_FXN_gcd(r3, r1, r2, fxn_ctx)
        || !OSSL_FXN_div(r0, NULL, r0, r3, fxn_ctx))
        goto err;

    /* d = e^-1 mod LCM */
    if (!OSSL_FXN_mod_inverse(fxn_d, fxn_e, r0, fxn_ctx))
        goto err;

    /* dmp1 = d mod (p-1), dmq1 = d mod (q-1), iqmp = q^-1 mod p */
    if (!OSSL_FXN_mod(fxn_dmp1, fxn_d, r1, fxn_ctx)
        || !OSSL_FXN_mod(fxn_dmq1, fxn_d, r2, fxn_ctx)
        || !OSSL_FXN_mod_inverse(fxn_iqmp, fxn_q, fxn_p, fxn_ctx))
        goto err;

    rsa->dirty_cnt++;
    ret = 1;
err:
    /*
     * n = p*q fits in pl + ql limbs; d = e^-1 mod LCM(p-1, q-1) is less
     * than (p-1)(q-1), which fits in the same width; dmp1, dmq1 and
     * iqmp are less than their moduli p-1, q-1 and p.
     */
    bn_release(rsa->n, (int)nl);
    bn_release(rsa->d, (int)nl);
    bn_release(rsa->dmp1, (int)pl);
    bn_release(rsa->dmq1, (int)ql);
    bn_release(rsa->iqmp, (int)pl);
    OSSL_FXN_CTX_free(fxn_ctx);
    OSSL_FXN_clear_free(r0);
    OSSL_FXN_clear_free(r1);
    OSSL_FXN_clear_free(r2);
    OSSL_FXN_clear_free(r3);

    return ret;
}

int RSA_X931_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e,
    BN_GENCB *cb)
{
    int ok = 0;
    OSSL_FXN_CTX *fxn_ctx = NULL;
    OSSL_FXN *Xp = NULL, *Xq = NULL;
    size_t xpl, fxn_size;

    /*
     * Xp and Xq carry bits/2 bits, rounded up to a limb, plus the headroom
     * the X931 generator expects.
     */
    xpl = (size_t)((bits / 2 + BN_BITS2 - 1) / BN_BITS2) + 1;
    Xp = OSSL_FXN_secure_new_limbs(xpl);
    Xq = OSSL_FXN_secure_new_limbs(xpl);
    if (Xp == NULL || Xq == NULL)
        goto error;

    fxn_size = OSSL_FXN_X931_generate_Xpq_ctx_size_from_nums(Xp);
    if (fxn_size == 0)
        goto error;
    /* TODO(FIXNUM): a secure arena is a possible future consideration */
    fxn_ctx = OSSL_FXN_CTX_new_size(rsa->libctx, fxn_size);
    if (fxn_ctx == NULL)
        goto error;
    if (!OSSL_FXN_X931_generate_Xpq(Xp, Xq, bits, fxn_ctx, rsa->libctx))
        goto error;
    OSSL_FXN_CTX_free(fxn_ctx);
    fxn_ctx = NULL;

    rsa->p = BN_new();
    rsa->q = BN_new();
    if (rsa->p == NULL || rsa->q == NULL)
        goto error;

    /* Generate two primes from Xp, Xq */
    {
        const OSSL_FXN *fxn_e = bn_get_ossl_fxn(e);
        OSSL_FXN *fxn_p, *fxn_q;

        if (fxn_e == NULL)
            goto error;
        fxn_p = bn_acquire_ossl_fxn(rsa->p, (int)xpl);
        fxn_q = bn_acquire_ossl_fxn(rsa->q, (int)xpl);
        if (fxn_p == NULL || fxn_q == NULL)
            goto x931_err;

        fxn_size = OSSL_FXN_X931_generate_prime_ctx_size_from_nums(
            fxn_p, NULL, NULL, Xp, fxn_e);
        if (fxn_size == 0)
            goto x931_err;
        /* TODO(FIXNUM): a secure arena is a possible future consideration */
        fxn_ctx = OSSL_FXN_CTX_new_size(rsa->libctx, fxn_size);
        if (fxn_ctx == NULL)
            goto x931_err;
        if (!OSSL_FXN_X931_generate_prime(fxn_p, NULL, NULL, NULL, NULL,
                Xp, fxn_e, fxn_ctx, cb, rsa->libctx))
            goto x931_err;
        OSSL_FXN_CTX_free(fxn_ctx);
        fxn_ctx = NULL;

        fxn_size = OSSL_FXN_X931_generate_prime_ctx_size_from_nums(
            fxn_q, NULL, NULL, Xq, fxn_e);
        if (fxn_size == 0)
            goto x931_err;
        /* TODO(FIXNUM): a secure arena is a possible future consideration */
        fxn_ctx = OSSL_FXN_CTX_new_size(rsa->libctx, fxn_size);
        if (fxn_ctx == NULL)
            goto x931_err;
        if (!OSSL_FXN_X931_generate_prime(fxn_q, NULL, NULL, NULL, NULL,
                Xq, fxn_e, fxn_ctx, cb, rsa->libctx))
            goto x931_err;
        OSSL_FXN_CTX_free(fxn_ctx);
        fxn_ctx = NULL;

        /* The generated primes have bits/2 bits, which fits in xpl limbs */
        bn_release(rsa->p, (int)xpl);
        bn_release(rsa->q, (int)xpl);
        goto generated;

    x931_err:
        bn_release(rsa->p, (int)xpl);
        bn_release(rsa->q, (int)xpl);
        OSSL_FXN_CTX_free(fxn_ctx);
        fxn_ctx = NULL;
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
    OSSL_FXN_CTX_free(fxn_ctx);
    OSSL_FXN_clear_free(Xp);
    OSSL_FXN_clear_free(Xq);

    return ok;
}
