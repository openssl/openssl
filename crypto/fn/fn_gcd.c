/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You may obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <openssl/err.h>
#include "crypto/cryptlib.h"
#include "crypto/fnerr.h"
#include "internal/constant_time.h"
#include "fn_local.h"

/*
 * Constant-time helpers.
 *
 * OSSL_FN values are fixed-width: there is no |top|, so any zero/nonzero
 * classification must scan the full |dsize|.  These helpers perform such scans
 * without branching on the scanned value.  They branch only on the (public)
 * limb count.
 */

/* Returns all-ones if |a| is zero, zero otherwise. */
static OSSL_FN_ULONG ossl_fn_ct_is_zero_mask(const OSSL_FN *a, int nwords)
{
    OSSL_FN_ULONG acc = 0;

    for (int i = 0; i < nwords; i++)
        acc |= a->d[i];

    return constant_time_is_zero_bn(acc);
}

/* Returns all-ones if |a| is non-zero and odd, zero otherwise. */
static OSSL_FN_ULONG ossl_fn_ct_odd_nonzero_mask(const OSSL_FN *a, int nwords)
{
    OSSL_FN_ULONG nonzero = ~constant_time_is_zero_bn(a->d[0]);

    for (int i = 1; i < nwords; i++)
        nonzero |= ~constant_time_is_zero_bn(a->d[i]);

    return nonzero & (0 - (a->d[0] & 1));
}

/*
 * Conditionally swap the limb contents of |a| and |b|, and the accompanying
 * sign flags, without branching on |mask|.  |mask| is all-ones to swap or
 * zero to leave both untouched.  |a| and |b| must have the same |dsize|, which
 * is given explicitly as |nwords|.  This mirrors BN_consttime_swap()'s data
 * loop; the sign-flag swap mirrors BN_consttime_swap()'s |neg| swap.
 */
static void ossl_fn_ct_swap(OSSL_FN_ULONG mask, OSSL_FN *a, OSSL_FN *b,
    int nwords, int *aneg, int *bneg)
{
    for (int i = 0; i < nwords; i++) {
        OSSL_FN_ULONG t = (a->d[i] ^ b->d[i]) & mask;

        a->d[i] ^= t;
        b->d[i] ^= t;
    }

    int bit = (int)(mask & (OSSL_FN_ULONG)1);
    int t = (*aneg ^ *bneg) & bit;

    *aneg ^= t;
    *bneg ^= t;
}

/*
 * Compute r = a + b as a signed sum, where |aneg|/|bneg| carry the signs of
 * |a|/|b| (0 = non-negative, 1 = negative).  |rneg| receives the sign of the
 * result.  OSSL_FN storage is unsigned, so the magnitude operation is chosen
 * with ordinary branches on the sign flags, exactly as BN_add() chooses
 * between bn_uadd() and bn_usub() on |a->neg == b->neg| and |BN_ucmp()|.  The
 * only value-dependent branch here therefore matches BN_add()'s profile; the
 * trailing zero-sign normalisation is performed in constant time.
 */
static int ossl_fn_signed_add(OSSL_FN *r, int *rneg,
    const OSSL_FN *a, int aneg, const OSSL_FN *b, int bneg)
{
    int cmp;
    OSSL_FN_ULONG z;

    if (aneg == bneg) {
        if (!OSSL_FN_add(r, a, b))
            return 0;
        *rneg = aneg;
    } else if ((cmp = OSSL_FN_cmp(a, b)) >= 0) {
        if (!OSSL_FN_sub(r, a, b))
            return 0;
        *rneg = aneg;
    } else {
        if (!OSSL_FN_sub(r, b, a))
            return 0;
        *rneg = bneg;
    }

    /* A zero result is non-negative; clear the sign without branching. */
    z = ossl_fn_ct_is_zero_mask(r, r->dsize);
    *rneg = constant_time_select_int((unsigned int)z, 0, *rneg);

    return 1;
}

int OSSL_FN_gcd(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    OSSL_FN_CTX *ctx)
{
    const void *token = OSSL_FN_CTX_start(ctx);
    if (token == NULL)
        return 0;

    int ret = 0;
    size_t al = (size_t)a->dsize;
    size_t bl = (size_t)b->dsize;
    size_t max = al > bl ? al : bl;
    size_t scratch = max + 1;
    OSSL_FN *u = NULL, *v = NULL, *t = NULL, *rr = NULL;
    int uneg = 0, vneg = 0, tneg = 0, delta = 1;
    int nwords = (int)scratch;
    int shift;
    size_t ubits, vbits, m;

    if ((u = OSSL_FN_CTX_get_limbs(ctx, scratch)) == NULL
        || (v = OSSL_FN_CTX_get_limbs(ctx, scratch)) == NULL
        || (t = OSSL_FN_CTX_get_limbs(ctx, scratch)) == NULL
        || (rr = OSSL_FN_CTX_get_limbs(ctx, scratch)) == NULL)
        goto err;

    /*
     * This is a faithful, constant-time translation of BN_gcd()'s
     * Bernstein-Yang-inspired binary GCD.  The structure is preserved so that
     * the constant-time profile matches BN_gcd():
     *
     *   - The shared power of two is removed via a constant-time scan over
     *     u | v (the |pow2_*| block below), replacing a value-branching
     *     trailing-zero count.
     *   - The loop condition, conditional swaps, conditional delta negation,
     *     and sign flips are all computed as masks and applied with
     *     ossl_fn_ct_swap(), never with "if (cond) swap".
     *   - Zero inputs are not short-circuited; BN_gcd() does not do so either,
     *     and the algorithm reduces gcd(0, x) = x and gcd(0, 0) = 0 naturally.
     *
     * What still leaks, exactly as in BN_gcd(): the iteration count |m|
     * (derived from OSSL_FN_num_bits(), which reveals input magnitudes), and
     * the add/subtract selection inside ossl_fn_signed_add() (which mirrors
     * BN_add()'s sign-agreement branch).  Limb values themselves do not drive
     * any branch.
     *
     * The loop treats |u|, |v|, and |t| as signed intermediate values via the
     * separate |uneg|, |vneg|, and |tneg| flags.  This mirrors BN_gcd()'s use
     * of BIGNUM->neg during the elimination step: when BN_gcd() computes
     * temp = g + r, the operation may be addition or subtraction depending on
     * r's sign.  OSSL_FN remains unsigned throughout; the flags only choose the
     * correct unsigned add/sub for these intermediates, and travel with the
     * values through ossl_fn_ct_swap().
     */
    if (!OSSL_FN_lshift1(u, a)
        || !OSSL_FN_lshift1(v, b))
        goto err;

    /*
     * Find the shared power of two as v2(u | v).  Since u = 2*a and v = 2*b,
     * this equals 1 + min(v2(a), v2(b)), which is exactly the |shift| to
     * remove (the artificial lshift1 bit plus the shared trailing zeros).
     * This scan is a direct port of BN_gcd()'s |pow2_*| block: it counts
     * trailing zero limbs and captures the first non-zero OR limb without
     * branching on limb values.
     */
    {
        OSSL_FN_ULONG pow2_flag = (OSSL_FN_ULONG)1;
        OSSL_FN_ULONG pow2_numbits = 0;
        int pow2_shifts = 0;

        for (int i = 0; i < nwords; i++) {
            OSSL_FN_ULONG temp = u->d[i] | v->d[i];
            OSSL_FN_ULONG cond = constant_time_is_zero_bn(pow2_flag);

            pow2_flag &= constant_time_is_zero_bn(temp);
            pow2_shifts += (int)pow2_flag;
            pow2_numbits = constant_time_select_bn(cond, pow2_numbits, temp);
        }

        pow2_numbits = ~pow2_numbits;
        pow2_shifts *= OSSL_FN_BITS;
        pow2_flag = (OSSL_FN_ULONG)1;
        for (int j = 0; j < OSSL_FN_BITS; j++) {
            pow2_flag &= pow2_numbits;
            pow2_shifts += (int)pow2_flag;
            pow2_numbits >>= 1;
        }

        shift = pow2_shifts;
    }

    if (!OSSL_FN_rshift(u, u, shift)
        || !OSSL_FN_rshift(v, v, shift))
        goto err;

    /* Rearrange so that u is odd, without branching on u's value. */
    ossl_fn_ct_swap(0 - (OSSL_FN_ULONG)(~u->d[0] & 1), u, v, nwords,
        &uneg, &vneg);

    ubits = OSSL_FN_num_bits(u);
    vbits = OSSL_FN_num_bits(v);
    m = ubits > vbits ? ubits : vbits;
    if (m > ((size_t)INT_MAX - 4) / 3)
        goto err;
    m = 4 + 3 * m;

    for (size_t i = 0; i < m; i++) {
        /*
         * Conditionally flip signs if delta is positive and v is odd and
         * non-zero.  |cond| is a full-width all-ones/zero mask used for the
         * constant-time swap; |condb| is the 0/1 bit used for the delta and
         * sign arithmetic, exactly as in BN_gcd()'s loop where cond is a bit.
         */
        OSSL_FN_ULONG v_odd = ossl_fn_ct_odd_nonzero_mask(v, nwords);
        OSSL_FN_ULONG delta_pos = 0
            - (OSSL_FN_ULONG)(((unsigned int)-delta
                                  >> (8 * sizeof(delta) - 1))
                & 1u);
        OSSL_FN_ULONG cond = delta_pos & v_odd;
        unsigned int condb = (unsigned int)(cond & (OSSL_FN_ULONG)1);

        delta = (-condb & (unsigned int)-delta)
            | ((condb - 1) & (unsigned int)delta);
        uneg ^= (int)condb;
        ossl_fn_ct_swap(cond, u, v, nwords, &uneg, &vneg);

        /* Elimination step: t = v + u (signed). */
        delta++;
        if (!ossl_fn_signed_add(t, &tneg, v, vneg, u, uneg))
            goto err;

        /* If v is odd and non-zero, v = t.  Recompute after the swap above. */
        v_odd = ossl_fn_ct_odd_nonzero_mask(v, nwords);
        ossl_fn_ct_swap(v_odd, v, t, nwords, &vneg, &tneg);

        if (!OSSL_FN_rshift1(v, v))
            goto err;

        /* A zero v is non-negative; clear the sign without branching. */
        {
            OSSL_FN_ULONG z = ossl_fn_ct_is_zero_mask(v, nwords);

            vneg = constant_time_select_int((unsigned int)z, 0, vneg);
        }
    }

    if (!OSSL_FN_lshift(rr, u, shift)
        || !OSSL_FN_rshift1(rr, rr))
        goto err;

    OSSL_FN_copy_truncate(r, rr);
    ret = 1;
err:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}
