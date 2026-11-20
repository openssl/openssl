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
#include "crypto/fsn.h"
#include "crypto/fsn_intern.h"
#include "rsa_local.h"

/* X9.31 RSA key derivation and generation */

/*
 * Derive one X9.31 prime into |p| on an OSSL_FSN view, converting at the
 * BIGNUM boundary.  |Xp|, |Xp1|, |Xp2| are read-only inputs, |p1|, |p2|
 * optional outputs.
 */
static int rsa_fsn_x931_derive_prime(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
    const BIGNUM *Xp, const BIGNUM *Xp1,
    const BIGNUM *Xp2, const BIGNUM *e,
    BN_GENCB *cb, OSSL_LIB_CTX *libctx)
{
    OSSL_FSN_CTX *fsn_ctx = NULL;
    OSSL_FSN *fsn_p = NULL, *fsn_p1 = NULL, *fsn_p2 = NULL;
    const OSSL_FSN *fsn_Xp, *fsn_Xp1, *fsn_Xp2, *fsn_e;
    size_t pl, fsn_size;
    int ret = 0;

    fsn_Xp = bn_get_ossl_fsn(Xp);
    fsn_Xp1 = bn_get_ossl_fsn(Xp1);
    fsn_Xp2 = bn_get_ossl_fsn(Xp2);
    fsn_e = bn_get_ossl_fsn(e);
    if (fsn_Xp == NULL || fsn_e == NULL)
        return 0;
    pl = ossl_fsn_get_dsize((OSSL_FSN *)fsn_Xp);

    fsn_p = bn_acquire_ossl_fsn(p, (int)pl);
    if (fsn_p == NULL)
        return 0;
    if (p1 != NULL
        && (fsn_p1 = bn_acquire_ossl_fsn(p1, (int)pl)) == NULL)
        goto err;
    if (p2 != NULL
        && (fsn_p2 = bn_acquire_ossl_fsn(p2, (int)pl)) == NULL)
        goto err;

    fsn_size = OSSL_FSN_X931_derive_prime_ctx_size_from_nums(fsn_p, fsn_p1, fsn_p2,
        fsn_Xp, fsn_Xp1, fsn_Xp2, fsn_e);
    if (fsn_size == 0)
        goto err;
    /* TODO(FIXNUM): a secure arena is a possible future consideration */
    fsn_ctx = OSSL_FSN_CTX_new_size(libctx, fsn_size);
    if (fsn_ctx == NULL)
        goto err;

    if (!OSSL_FSN_X931_derive_prime(fsn_p, fsn_p1, fsn_p2, fsn_Xp, fsn_Xp1,
            fsn_Xp2, fsn_e, fsn_ctx, cb, libctx))
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
    OSSL_FSN_CTX_free(fsn_ctx);
    return ret;
}

int RSA_X931_derive_ex(RSA *rsa, BIGNUM *p1, BIGNUM *p2, BIGNUM *q1,
    BIGNUM *q2, const BIGNUM *Xp1, const BIGNUM *Xp2,
    const BIGNUM *Xp, const BIGNUM *Xq1, const BIGNUM *Xq2,
    const BIGNUM *Xq, const BIGNUM *e, BN_GENCB *cb)
{
    OSSL_FSN_CTX *fsn_ctx = NULL;
    OSSL_FSN *r0 = NULL, *r1 = NULL, *r2 = NULL, *r3 = NULL;
    OSSL_FSN *fsn_d = NULL, *fsn_n = NULL, *fsn_dmp1 = NULL, *fsn_dmq1 = NULL;
    OSSL_FSN *fsn_iqmp = NULL;
    const OSSL_FSN *fsn_p, *fsn_q, *fsn_e;
    size_t fsn_size, nl = 0, pl = 0, ql = 0;
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

        if (!rsa_fsn_x931_derive_prime(rsa->p, p1, p2,
                Xp, Xp1, Xp2, e, cb, rsa->libctx))
            goto err;
    }

    if (Xq && rsa->q == NULL) {
        rsa->q = BN_new();
        if (rsa->q == NULL)
            goto err;
        if (!rsa_fsn_x931_derive_prime(rsa->q, q1, q2,
                Xq, Xq1, Xq2, e, cb, rsa->libctx))
            goto err;
    }

    if (rsa->p == NULL || rsa->q == NULL)
        return 2;

    /*
     * Since both primes are set we can now calculate all remaining
     * components on OSSL_FSN views.
     */
    fsn_p = bn_get_ossl_fsn(rsa->p);
    fsn_q = bn_get_ossl_fsn(rsa->q);
    fsn_e = bn_get_ossl_fsn(rsa->e);
    if (fsn_p == NULL || fsn_q == NULL || fsn_e == NULL)
        goto err;
    pl = ossl_fsn_get_dsize((OSSL_FSN *)fsn_p);
    ql = ossl_fsn_get_dsize((OSSL_FSN *)fsn_q);
    nl = pl + ql;

    /* n = p*q */
    rsa->n = BN_new();
    if (rsa->n == NULL)
        goto err;
    fsn_n = bn_acquire_ossl_fsn(rsa->n, (int)nl);
    if (fsn_n == NULL)
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

    fsn_d = bn_acquire_ossl_fsn(rsa->d, (int)nl);
    fsn_dmp1 = bn_acquire_ossl_fsn(rsa->dmp1, (int)pl);
    fsn_dmq1 = bn_acquire_ossl_fsn(rsa->dmq1, (int)ql);
    fsn_iqmp = bn_acquire_ossl_fsn(rsa->iqmp, (int)pl);
    if (fsn_d == NULL || fsn_dmp1 == NULL || fsn_dmq1 == NULL || fsn_iqmp == NULL)
        goto err;

    /* scratch: r0 (LCM, n-wide), r1 (p-1), r2 (q-1), r3 (gcd) */
    r0 = OSSL_FSN_secure_new_limbs(nl);
    r1 = OSSL_FSN_secure_new_limbs(pl);
    r2 = OSSL_FSN_secure_new_limbs(ql);
    r3 = OSSL_FSN_secure_new_limbs(pl < ql ? pl : ql);
    if (r0 == NULL || r1 == NULL || r2 == NULL || r3 == NULL)
        goto err;

    /* p-1, q-1 */
    if (!OSSL_FSN_copy(r1, fsn_p) || !OSSL_FSN_sub_word(r1, 1)
        || !OSSL_FSN_copy(r2, fsn_q) || !OSSL_FSN_sub_word(r2, 1))
        goto err;

    /*
     * The operations run sequentially in one arena, each in its own frame,
     * so the arena is sized for the largest single operation.
     */
    fsn_size = OSSL_FSN_mul_ctx_size_from_nums(fsn_n, fsn_p, fsn_q);
    fsn_size = ossl_fsn_ctx_max_size(fsn_size,
        OSSL_FSN_mul_ctx_size_from_nums(r0, r1, r2));
    fsn_size = ossl_fsn_ctx_max_size(fsn_size,
        OSSL_FSN_gcd_ctx_size_from_nums(r1, r2));
    fsn_size = ossl_fsn_ctx_max_size(fsn_size,
        OSSL_FSN_div_ctx_size_from_nums(r0, NULL, r0, r3));
    fsn_size = ossl_fsn_ctx_max_size(fsn_size,
        OSSL_FSN_mod_inverse_ctx_size_from_nums(fsn_d, fsn_e, r0));
    fsn_size = ossl_fsn_ctx_max_size(fsn_size,
        OSSL_FSN_mod_ctx_size_from_nums(fsn_dmp1, fsn_d, r1));
    fsn_size = ossl_fsn_ctx_max_size(fsn_size,
        OSSL_FSN_mod_ctx_size_from_nums(fsn_dmq1, fsn_d, r2));
    fsn_size = ossl_fsn_ctx_max_size(fsn_size,
        OSSL_FSN_mod_inverse_ctx_size_from_nums(fsn_iqmp, fsn_q, fsn_p));
    if (fsn_size == 0)
        goto err;
    /* TODO(FIXNUM): a secure arena is a possible future consideration */
    fsn_ctx = OSSL_FSN_CTX_new_size(rsa->libctx, fsn_size);
    if (fsn_ctx == NULL)
        goto err;

    if (!OSSL_FSN_mul(fsn_n, fsn_p, fsn_q, fsn_ctx))
        goto err;

    /* LCM((p-1)(q-1)) into r0 */
    if (!OSSL_FSN_mul(r0, r1, r2, fsn_ctx)
        || !OSSL_FSN_gcd(r3, r1, r2, fsn_ctx)
        || !OSSL_FSN_div(r0, NULL, r0, r3, fsn_ctx))
        goto err;

    /* d = e^-1 mod LCM */
    if (!OSSL_FSN_mod_inverse(fsn_d, fsn_e, r0, fsn_ctx))
        goto err;

    /* dmp1 = d mod (p-1), dmq1 = d mod (q-1), iqmp = q^-1 mod p */
    if (!OSSL_FSN_mod(fsn_dmp1, fsn_d, r1, fsn_ctx)
        || !OSSL_FSN_mod(fsn_dmq1, fsn_d, r2, fsn_ctx)
        || !OSSL_FSN_mod_inverse(fsn_iqmp, fsn_q, fsn_p, fsn_ctx))
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
    OSSL_FSN_CTX_free(fsn_ctx);
    OSSL_FSN_clear_free(r0);
    OSSL_FSN_clear_free(r1);
    OSSL_FSN_clear_free(r2);
    OSSL_FSN_clear_free(r3);

    return ret;
}

int RSA_X931_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e,
    BN_GENCB *cb)
{
    int ok = 0;
    OSSL_FSN_CTX *fsn_ctx = NULL;
    OSSL_FSN *Xp = NULL, *Xq = NULL;
    size_t xpl, fsn_size;

    /*
     * Xp and Xq carry bits/2 bits, rounded up to a limb, plus the headroom
     * the X931 generator expects.
     */
    xpl = (size_t)((bits / 2 + BN_BITS2 - 1) / BN_BITS2) + 1;
    Xp = OSSL_FSN_secure_new_limbs(xpl);
    Xq = OSSL_FSN_secure_new_limbs(xpl);
    if (Xp == NULL || Xq == NULL)
        goto error;

    fsn_size = OSSL_FSN_X931_generate_Xpq_ctx_size_from_nums(Xp);
    if (fsn_size == 0)
        goto error;
    /* TODO(FIXNUM): a secure arena is a possible future consideration */
    fsn_ctx = OSSL_FSN_CTX_new_size(rsa->libctx, fsn_size);
    if (fsn_ctx == NULL)
        goto error;
    if (!OSSL_FSN_X931_generate_Xpq(Xp, Xq, bits, fsn_ctx, rsa->libctx))
        goto error;
    OSSL_FSN_CTX_free(fsn_ctx);
    fsn_ctx = NULL;

    rsa->p = BN_new();
    rsa->q = BN_new();
    if (rsa->p == NULL || rsa->q == NULL)
        goto error;

    /* Generate two primes from Xp, Xq */
    {
        const OSSL_FSN *fsn_e = bn_get_ossl_fsn(e);
        OSSL_FSN *fsn_p, *fsn_q;

        if (fsn_e == NULL)
            goto error;
        fsn_p = bn_acquire_ossl_fsn(rsa->p, (int)xpl);
        fsn_q = bn_acquire_ossl_fsn(rsa->q, (int)xpl);
        if (fsn_p == NULL || fsn_q == NULL)
            goto x931_err;

        fsn_size = OSSL_FSN_X931_generate_prime_ctx_size_from_nums(
            fsn_p, NULL, NULL, Xp, fsn_e);
        if (fsn_size == 0)
            goto x931_err;
        /* TODO(FIXNUM): a secure arena is a possible future consideration */
        fsn_ctx = OSSL_FSN_CTX_new_size(rsa->libctx, fsn_size);
        if (fsn_ctx == NULL)
            goto x931_err;
        if (!OSSL_FSN_X931_generate_prime(fsn_p, NULL, NULL, NULL, NULL,
                Xp, fsn_e, fsn_ctx, cb, rsa->libctx))
            goto x931_err;
        OSSL_FSN_CTX_free(fsn_ctx);
        fsn_ctx = NULL;

        fsn_size = OSSL_FSN_X931_generate_prime_ctx_size_from_nums(
            fsn_q, NULL, NULL, Xq, fsn_e);
        if (fsn_size == 0)
            goto x931_err;
        /* TODO(FIXNUM): a secure arena is a possible future consideration */
        fsn_ctx = OSSL_FSN_CTX_new_size(rsa->libctx, fsn_size);
        if (fsn_ctx == NULL)
            goto x931_err;
        if (!OSSL_FSN_X931_generate_prime(fsn_q, NULL, NULL, NULL, NULL,
                Xq, fsn_e, fsn_ctx, cb, rsa->libctx))
            goto x931_err;
        OSSL_FSN_CTX_free(fsn_ctx);
        fsn_ctx = NULL;

        /* The generated primes have bits/2 bits, which fits in xpl limbs */
        bn_release(rsa->p, (int)xpl);
        bn_release(rsa->q, (int)xpl);
        goto generated;

    x931_err:
        bn_release(rsa->p, (int)xpl);
        bn_release(rsa->q, (int)xpl);
        OSSL_FSN_CTX_free(fsn_ctx);
        fsn_ctx = NULL;
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
    OSSL_FSN_CTX_free(fsn_ctx);
    OSSL_FSN_clear_free(Xp);
    OSSL_FSN_clear_free(Xq);

    return ok;
}
