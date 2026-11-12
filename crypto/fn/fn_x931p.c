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
    t = OSSL_FN_CTX_get_limbs(ctx, token, (size_t)dst->dsize);
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
    if (ossl_unlikely(Xp == NULL || Xq == NULL)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* 512+128s shape check, sized as the sum of both Xp and Xq */
    if ((nbits < 1024) || (nbits & 0xff)) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_INVALID_RANGE);
        return 0;
    }
    nbits >>= 1;

    return ossl_fn_x931_generate_Xpq_int(Xp, Xq, nbits, ctx, libctx);
}

/*
 * Estimate the arena payload for OSSL_FN_X931_generate_Xpq().  The
 * operation holds one scratch number of the destination's width for
 * the pair gap check.
 */
size_t OSSL_FN_X931_generate_Xpq_ctx_size_from_sizes(size_t Xp_dsize)
{
    if (Xp_dsize == 0)
        return 0;

    return OSSL_FN_CTX_size(1, 1, Xp_dsize);
}

size_t OSSL_FN_X931_generate_Xpq_ctx_size_from_data(const OSSL_FN *Xp)
{
    if (Xp == NULL)
        return 0;

    return OSSL_FN_X931_generate_Xpq_ctx_size_from_sizes(Xp->dsize);
}

/*
 * Estimate the arena payload for OSSL_FN_X931_derive_prime().  The outer
 * frame holds five numbers: p1 and p2 of the main width (n limbs), and
 * p1p2, t and pm1 of double width (2n limbs).  The scratch budget below
 * sums to 8n limbs over the 5 numbers.  The
 * operation's phases run sequentially within that frame; each sized
 * operation is added as its own term, with same-width alternatives
 * taking the maximum.
 */
size_t OSSL_FN_X931_derive_prime_ctx_size_from_sizes(size_t p_dsize,
    size_t p1_dsize, size_t p2_dsize, size_t Xp_dsize, size_t Xp1_dsize,
    size_t Xp2_dsize, size_t e_dsize)
{
    size_t n = Xp_dsize, n2;
    size_t scratch, pi, mul, inv, mm, ms, loop, own;

    if (n == 0 || n > SIZE_MAX / 2 || ossl_fn_totalsize(2 * n) == 0)
        return 0;

    /* p1 and p2 are n limbs wide, p1p2, t and pm1 2n limbs. */
    n2 = 2 * n;

    scratch = OSSL_FN_CTX_size(1, 5, n + n + n2 + n2 + n2);
    /* An absent |Xp1| or |Xp2| (passed as 0) is drawn at |Xp|'s width. */
    pi = ossl_fn_ctx_max_size(
        ossl_fn_check_prime_ctx_size_from_sizes(Xp1_dsize != 0 ? Xp1_dsize : n),
        ossl_fn_check_prime_ctx_size_from_sizes(Xp2_dsize != 0 ? Xp2_dsize : n));
    mul = OSSL_FN_mul_ctx_size_from_sizes(n2, n, n);
    inv = ossl_fn_ctx_max_size(
        OSSL_FN_mod_inverse_ctx_size_from_sizes(p_dsize, n, n),
        OSSL_FN_mod_inverse_ctx_size_from_sizes(n2, n, n));
    mm = ossl_fn_ctx_max_size(
        OSSL_FN_mod_mul_ctx_size_from_sizes(p_dsize, p_dsize, n, n2),
        OSSL_FN_mod_mul_ctx_size_from_sizes(n2, n2, n, n2));
    ms = OSSL_FN_mod_sub_ctx_size_from_sizes(p_dsize, p_dsize, n2, n2);
    loop = ossl_fn_ctx_max_size(
        OSSL_FN_gcd_ctx_size_from_sizes(n2, e_dsize),
        ossl_fn_check_prime_ctx_size_from_sizes(p_dsize));

    own = ossl_fn_ctx_add_size(ossl_fn_ctx_add_size(scratch, pi),
        ossl_fn_ctx_add_size(ossl_fn_ctx_add_size(mul, inv),
            ossl_fn_ctx_add_size(mm, ms)));
    return ossl_fn_ctx_add_size(own, loop);
}

size_t OSSL_FN_X931_derive_prime_ctx_size_from_data(const OSSL_FN *p,
    const OSSL_FN *p1, const OSSL_FN *p2, const OSSL_FN *Xp,
    const OSSL_FN *Xp1, const OSSL_FN *Xp2, const OSSL_FN *e)
{
    if (p == NULL || Xp == NULL || e == NULL)
        return 0;

    return OSSL_FN_X931_derive_prime_ctx_size_from_sizes(p->dsize,
        OSSL_FN_size_limbs(p1), OSSL_FN_size_limbs(p2), Xp->dsize,
        OSSL_FN_size_limbs(Xp1), OSSL_FN_size_limbs(Xp2), e->dsize);
}

/*
 * Estimate the arena payload for OSSL_FN_X931_generate_prime().  The
 * operation's own frame holds the four main-width numbers it may draw
 * into (p1, p2, Xp1 and Xp2 when passed as NULL), so 4n limbs over 4
 * numbers come on top of the OSSL_FN_X931_derive_prime() estimate.
 */
size_t OSSL_FN_X931_generate_prime_ctx_size_from_sizes(size_t p_dsize,
    size_t p1_dsize, size_t p2_dsize, size_t Xp_dsize, size_t e_dsize)
{
    size_t own, derive;

    if (Xp_dsize == 0 || Xp_dsize > SIZE_MAX / 4
        || ossl_fn_totalsize(4 * Xp_dsize) == 0)
        return 0;

    own = OSSL_FN_CTX_size(1, 4, 4 * Xp_dsize);
    derive = OSSL_FN_X931_derive_prime_ctx_size_from_sizes(p_dsize, p1_dsize,
        p2_dsize, Xp_dsize, 0, 0, e_dsize);
    return ossl_fn_ctx_add_size(own, derive);
}

size_t OSSL_FN_X931_generate_prime_ctx_size_from_data(const OSSL_FN *p,
    const OSSL_FN *p1, const OSSL_FN *p2, const OSSL_FN *Xp,
    const OSSL_FN *e)
{
    if (p == NULL || Xp == NULL || e == NULL)
        return 0;

    return OSSL_FN_X931_generate_prime_ctx_size_from_sizes(p->dsize,
        OSSL_FN_size_limbs(p1), OSSL_FN_size_limbs(p2), Xp->dsize, e->dsize);
}

/*
 * Derive one X9.31 prime pi from the parameter Xpi by checking successive
 * odd integers upward from Xpi.
 */
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

    if (ossl_unlikely(p == NULL || Xp == NULL || Xp1 == NULL || Xp2 == NULL
            || e == NULL)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* Only odd e supported */
    if (!OSSL_FN_is_odd(e))
        return 0;

    if ((token = OSSL_FN_CTX_start(ctx)) == NULL)
        return 0;

    if (p1 == NULL && (p1 = OSSL_FN_CTX_get_limbs(ctx, token, (size_t)Xp->dsize)) == NULL)
        goto err;
    if (p2 == NULL && (p2 = OSSL_FN_CTX_get_limbs(ctx, token, (size_t)Xp->dsize)) == NULL)
        goto err;

    p1p2 = OSSL_FN_CTX_get_limbs(ctx, token, 2 * (size_t)Xp->dsize);
    t = OSSL_FN_CTX_get_limbs(ctx, token, 2 * (size_t)Xp->dsize);
    pm1 = OSSL_FN_CTX_get_limbs(ctx, token, 2 * (size_t)Xp->dsize);
    /* t and pm1 are double width: t is reduced modulo p1p2, and pm1
     * carries p's full width in the gcd filter. */
    if (pm1 == NULL)
        goto err;

    if (!ossl_fn_x931_derive_pi(p1, Xp1, ctx, cb, libctx))
        goto err;
    if (!ossl_fn_x931_derive_pi(p2, Xp2, ctx, cb, libctx))
        goto err;
    if (!OSSL_FN_mul(p1p2, p1, p2, ctx))
        goto err;

    /*
     * Compute Rp = (p2^-1 mod p1) * p2 - (p1^-1 mod p2) * p1 (mod p1p2).
     * The products are reduced against p1p2 rather than p1 or p2, so the
     * CRT difference survives.  The sign fix-up of the BN counterpart
     * collapses into the unsigned modular reduction.
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

    /* p now equals Rp; normalize to Yp0 = Xp + ((Rp - Xp) mod p1p2). */
    if (!OSSL_FN_mod_sub(p, p, Xp, p1p2, ctx))
        goto err;
    if (!OSSL_FN_add(p, p, Xp))
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

int OSSL_FN_X931_generate_prime(OSSL_FN *p, OSSL_FN *p1, OSSL_FN *p2,
    OSSL_FN *Xp1, OSSL_FN *Xp2, const OSSL_FN *Xp, const OSSL_FN *e,
    OSSL_FN_CTX *ctx, BN_GENCB *cb, OSSL_LIB_CTX *libctx)
{
    const void *token;
    int ret = 0;

    if (ossl_unlikely(p == NULL || Xp == NULL || e == NULL)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((token = OSSL_FN_CTX_start(ctx)) == NULL)
        return 0;

    if (p1 == NULL && (p1 = OSSL_FN_CTX_get_limbs(ctx, token, (size_t)Xp->dsize)) == NULL)
        goto err;
    if (p2 == NULL && (p2 = OSSL_FN_CTX_get_limbs(ctx, token, (size_t)Xp->dsize)) == NULL)
        goto err;
    if (Xp1 == NULL && (Xp1 = OSSL_FN_CTX_get_limbs(ctx, token, (size_t)Xp->dsize)) == NULL)
        goto err;
    if (Xp2 == NULL && (Xp2 = OSSL_FN_CTX_get_limbs(ctx, token, (size_t)Xp->dsize)) == NULL)
        goto err;

    if (!OSSL_FN_priv_rand(Xp1, 101, OSSL_FN_RAND_TOP_ONE,
            OSSL_FN_RAND_BOTTOM_ANY, 0, libctx)
        || !OSSL_FN_priv_rand(Xp2, 101, OSSL_FN_RAND_TOP_ONE,
            OSSL_FN_RAND_BOTTOM_ANY, 0, libctx))
        goto err;

    ret = OSSL_FN_X931_derive_prime(p, p1, p2, Xp, Xp1, Xp2, e,
        ctx, cb, libctx);

err:
    if (!OSSL_FN_CTX_end(ctx, token))
        ret = 0;
    return ret;
}
