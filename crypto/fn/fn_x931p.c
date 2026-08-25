/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include "internal/mem_alloc_utils.h"
#include "crypto/fnerr.h"
#include "fn_local.h"

/*
 * Generate the initial values of Xp and Xq, to be used for further
 * derivation of primes p and q.  The |Xp - Xq| > 2^(nbits - 100)
 * requirement ensures the pair is not accidentally close.
 */
static int ossl_fn_x931_generate_Xpq_int(OSSL_FN *dst, OSSL_FN *oth,
    int nbits, OSSL_FN_CTX *ctx, OSSL_LIB_CTX *libctx)
{
    OSSL_FN *bigger, *smaller, *t;
    const void *token;
    int i, ret = 0;

    if ((token = OSSL_FN_CTX_start(ctx)) == NULL)
        return 0;
    t = OSSL_FN_CTX_get_limbs(ctx, (size_t)dst->dsize);
    if (t == NULL)
        goto err;

    if (!OSSL_FN_priv_rand(dst, nbits, OSSL_FN_RAND_TOP_TWO,
            OSSL_FN_RAND_BOTTOM_ANY, 0, libctx))
        goto err;

    for (i = 0; i < 1000; i++) {
        if (!OSSL_FN_priv_rand(oth, nbits, OSSL_FN_RAND_TOP_TWO,
                OSSL_FN_RAND_BOTTOM_ANY, 0, libctx))
            goto err;

        bigger = dst;
        smaller = oth;
        if (OSSL_FN_cmp(dst, oth) < 0) {
            bigger = oth;
            smaller = dst;
        }

        if (!OSSL_FN_sub(t, bigger, smaller))
            goto err;
        if (OSSL_FN_num_bits(t) > (size_t)(nbits - 100)) {
            ret = 1;
            goto err;
        }
    }

err:
    if (!OSSL_FN_CTX_end(ctx, token))
        ret = 0;
    return ret;
}

int OSSL_FN_X931_generate_Xpq(OSSL_FN *Xp, OSSL_FN *Xq, int nbits,
    OSSL_FN_CTX *ctx, OSSL_LIB_CTX *libctx)
{
    /* 512+128s shape check, sized as the sum of both Xp and Xq */
    if ((nbits < 1024) || (nbits & 0xff)) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_INVALID_RANGE);
        return 0;
    }
    nbits >>= 1;

    return ossl_fn_x931_generate_Xpq_int(Xp, Xq, nbits, ctx, libctx);
}

/* The usual static helpers from the other fn_*.c operation files. */
static size_t ctx_add_size(size_t a, size_t b)
{
    int err = 0;
    size_t r = safe_add_size_t(a, b, &err);

    return err == 0 ? r : 0;
}

static size_t ctx_max_size(size_t a, size_t b)
{
    return a > b ? a : b;
}

/*
 * Estimate the arena payload for OSSL_FN_X931_generate_Xpq().  The
 * operation holds one scratch number of the destination's width for
 * the pair gap check.
 */
size_t OSSL_FN_X931_generate_Xpq_ctx_size(const OSSL_FN *Xp)
{
    if (Xp == NULL || Xp->dsize == 0)
        return 0;

    return OSSL_FN_CTX_size(1, 1, (size_t)Xp->dsize);
}

/*
 * Estimate the arena payload for one embedded primality test on a
 * candidate of width |n| limbs.
 */
static size_t ossl_fn_x931_check_prime_ctx_size(size_t n)
{
    OSSL_FN w;

    if (n == 0)
        return 0;
    w.dsize = n;

    return ossl_fn_miller_rabin_is_prime_ctx_size(&w);
}

/*
 * Estimate the arena payload for OSSL_FN_X931_derive_prime().  The outer
 * frame holds five numbers (p1, p2 of n limbs; p1p2 of 2n limbs; t and pm1
 * of n limbs), so the scratch budget is 5n limbs over 5 numbers.  The
 * operation's phases run sequentially within that frame; each sized
 * operation is added as its own term, with same-width alternatives
 * taking the maximum.
 */
size_t OSSL_FN_X931_derive_prime_ctx_size(const OSSL_FN *p,
    const OSSL_FN *p1, const OSSL_FN *p2, const OSSL_FN *Xp,
    const OSSL_FN *Xp1, const OSSL_FN *Xp2, const OSSL_FN *e)
{
    OSSL_FN p1w, p2w, p1p2w, tw, pm1w;
    size_t scratch, pi, mul, inv, mm, ms, loop, own;

    if (p == NULL || Xp == NULL || e == NULL || Xp->dsize == 0
        || ossl_fn_totalsize(2 * (size_t)Xp->dsize) == 0)
        return 0;

    p1w.dsize = p2w.dsize = Xp->dsize;
    p1p2w.dsize = 2 * Xp->dsize;
    tw.dsize = Xp->dsize;
    pm1w.dsize = Xp->dsize;

    scratch = OSSL_FN_CTX_size(1, 5, 5 * (size_t)Xp->dsize);
    pi = ctx_max_size(ossl_fn_x931_check_prime_ctx_size(
                          Xp1 != NULL ? (size_t)Xp1->dsize : (size_t)Xp->dsize),
        ossl_fn_x931_check_prime_ctx_size(
            Xp2 != NULL ? (size_t)Xp2->dsize : (size_t)Xp->dsize));
    mul = OSSL_FN_mul_ctx_size(&p1p2w, &p1w, &p2w);
    inv = ctx_max_size(
        OSSL_FN_mod_inverse_ctx_size(p, &p2w, &p1w),
        OSSL_FN_mod_inverse_ctx_size(&tw, &p1w, &p2w));
    mm = ctx_max_size(
        OSSL_FN_mod_mul_ctx_size(p, p, &p2w, &p1p2w),
        OSSL_FN_mod_mul_ctx_size(&tw, &tw, &p1w, &p1p2w));
    ms = OSSL_FN_mod_sub_ctx_size(p, p, &tw, &p1p2w);
    loop = ctx_max_size(
        OSSL_FN_gcd_ctx_size(&pm1w, e),
        ossl_fn_x931_check_prime_ctx_size(p->dsize));

    own = ctx_add_size(ctx_add_size(scratch, pi),
        ctx_add_size(ctx_add_size(mul, inv),
            ctx_add_size(mm, ms)));
    return ctx_add_size(own, loop);
}

static int ossl_fn_x931_derive_pi(OSSL_FN *pi, const OSSL_FN *Xpi,
    OSSL_FN_CTX *ctx, BN_GENCB *cb, OSSL_LIB_CTX *libctx)
{
    int i = 0, is_prime;

    if (OSSL_FN_copy_truncate(pi, Xpi) == NULL)
        return 0;
    if (!OSSL_FN_is_odd(pi) && !OSSL_FN_add_word(pi, 1))
        return 0;
    for (;;) {
        i++;
        BN_GENCB_call(cb, 0, i);
        is_prime = ossl_fn_check_prime(pi, 0, ctx, 1, cb, libctx);
        if (is_prime < 0)
            return 0;
        if (is_prime)
            break;
        if (!OSSL_FN_add_word(pi, 2))
            return 0;
    }
    BN_GENCB_call(cb, 2, i);
    return 1;
}

int OSSL_FN_X931_derive_prime(OSSL_FN *p, OSSL_FN *p1, OSSL_FN *p2,
    const OSSL_FN *Xp, const OSSL_FN *Xp1, const OSSL_FN *Xp2,
    const OSSL_FN *e, OSSL_FN_CTX *ctx, BN_GENCB *cb,
    OSSL_LIB_CTX *libctx)
{
    const void *token;
    OSSL_FN *p1p2, *t, *pm1;
    int ret = 0;

    /* Only odd e supported */
    if (!OSSL_FN_is_odd(e))
        return 0;

    if ((token = OSSL_FN_CTX_start(ctx)) == NULL)
        return 0;

    if (p1 == NULL && (p1 = OSSL_FN_CTX_get_limbs(ctx, (size_t)Xp->dsize)) == NULL)
        goto err;
    if (p2 == NULL && (p2 = OSSL_FN_CTX_get_limbs(ctx, (size_t)Xp->dsize)) == NULL)
        goto err;

    p1p2 = OSSL_FN_CTX_get_limbs(ctx, 2 * (size_t)Xp->dsize);
    t = OSSL_FN_CTX_get_limbs(ctx, (size_t)Xp->dsize);
    pm1 = OSSL_FN_CTX_get_limbs(ctx, (size_t)Xp->dsize);
    if (pm1 == NULL)
        goto err;

    if (!ossl_fn_x931_derive_pi(p1, Xp1, ctx, cb, libctx))
        goto err;
    if (!ossl_fn_x931_derive_pi(p2, Xp2, ctx, cb, libctx))
        goto err;
    if (!OSSL_FN_mul(p1p2, p1, p2, ctx))
        goto err;

    /* Compute Rp = (p2^-1 mod p1) * p2 - (p1^-1 mod p2) * p1 (mod p1p2),
     * then Yp0 = Xp + Rp - Xp modulo p1p2.  The products are reduced
     * against p1p2 rather than p1 or p2, so the CRT difference survives.
     * The sign fix-up of the BN counterpart collapses into the modular
     * reduction.
     */
    if (!OSSL_FN_mod_inverse(p, p2, p1, ctx))
        goto err;
    if (!OSSL_FN_mod_mul(p, p, p2, p1p2, ctx))
        goto err;
    if (!OSSL_FN_mod_inverse(t, p1, p2, ctx))
        goto err;
    if (!OSSL_FN_mod_mul(t, t, p1, p1p2, ctx))
        goto err;
    if (!OSSL_FN_mod_sub(p, p, t, p1p2, ctx))
        goto err;

    /* p now equals Yp0 */
    for (;;) {
        BN_GENCB_call(cb, 0, 1);
        if (OSSL_FN_copy(pm1, p) == NULL || !OSSL_FN_sub_word(pm1, 1))
            goto err;
        if (!OSSL_FN_gcd(t, pm1, e, ctx))
            goto err;
        if (OSSL_FN_is_one(t)) {
            /*
             * gcd(p - 1, e) == 1 is the X9.31 condition, so only then is a
             * primality test warranted.
             */
            int r = ossl_fn_check_prime(p, 0, ctx, 1, cb, libctx);

            if (r < 0)
                goto err;
            if (r)
                break;
        }
        if (!OSSL_FN_add(p, p, p1p2))
            goto err;
    }

    BN_GENCB_call(cb, 3, 0);

    ret = 1;

err:
    if (!OSSL_FN_CTX_end(ctx, token))
        ret = 0;
    return ret;
}
