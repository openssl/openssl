/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "crypto/fnerr.h"
#include "fn_local.h"

/*-
 * mod_exp2_mont_nested() -- nested arena size for OSSL_FN_mod_exp2_mont().
 * |own_size| is added by the callers.  Nested frames are sequential, so the
 * size is their max.
 *
 * |in_mont| mirrors OSSL_FN_mod_exp2_mont(): NULL models the function-owned
 * context, a real value sizes for a reused one; both give the same size.
 * The loop and from_mont operate on reduced ml-wide Montgomery-domain
 * values; their sizing helpers read only mont->N->dsize (== ml), so those
 * operands are not modelled here.
 */
static size_t mod_exp2_mont_nested(const OSSL_FN *a1, const OSSL_FN *a2,
    const OSSL_FN *m, OSSL_FN_MONT_CTX *in_mont)
{
    OSSL_FN_MONT_CTX mont_model = { .N = m };
    size_t to_mont_1_size, to_mont_2_size;
    size_t mont_size;

    if (in_mont == NULL)
        in_mont = &mont_model;

    to_mont_1_size = OSSL_FN_to_mont_ctx_size(NULL, a1, in_mont);
    to_mont_2_size = OSSL_FN_to_mont_ctx_size(NULL, a2, in_mont);
    mont_size = ossl_fn_ctx_max_size(ossl_fn_ctx_max_size(to_mont_1_size, to_mont_2_size),
        ossl_fn_ctx_max_size(OSSL_FN_mul_mont_quick_ctx_size(NULL, NULL, NULL, in_mont),
            OSSL_FN_from_mont_ctx_size(NULL, NULL, in_mont)));

    return mont_size;
}

/*-
 * OSSL_FN_mod_exp2_mont_ctx_size() -- arena sizing for
 * OSSL_FN_mod_exp2_mont().  Sizes two independent val[] table trees of
 * TABLE_SIZE entries each, plus rr, d, and tmp; the |in_mont| modelling
 * matches mod_exp2_mont_nested() (NULL/reused equivalent).
 */
size_t OSSL_FN_mod_exp2_mont_ctx_size(const OSSL_FN *r, const OSSL_FN *a1,
    const OSSL_FN *p1, const OSSL_FN *a2, const OSSL_FN *p2, const OSSL_FN *m,
    OSSL_FN_MONT_CTX *in_mont)
{
    if (a1 == NULL || p1 == NULL || a2 == NULL || p2 == NULL || m == NULL)
        return 0;

    size_t ml = (size_t)m->dsize;
    /* A zero-limb modulus is invalid; OSSL_FN_mod_exp2_mont() rejects it. */
    if (ml == 0 || ossl_fn_totalsize(ml) == 0)
        return 0;

    /* rr, d, tmp, plus both val-arrays fully allocated. */
    size_t n_numbers = 3 + TABLE_SIZE + TABLE_SIZE;
    size_t own_size = OSSL_FN_CTX_size(1, n_numbers, n_numbers * ml);

    size_t nested_size = mod_exp2_mont_nested(a1, a2, m, in_mont);
    if (own_size == 0 || nested_size == 0)
        return 0;

    return ossl_fn_ctx_add_size(own_size, nested_size);
}

/*
 * OSSL_FN_mod_exp2_mont() -- double-base Montgomery sliding-window
 * exponentiation  r = a1^p1 * a2^p2 mod m  (Shamir's trick).  One mont
 * context, two independent pending windows in a single bit sweep; the
 * accumulator is squared once per bit, and each pending odd window consumes
 * its own precomputed odd-powers table at its completing bit.  The result
 * is computed for roughly the price of one modular exponentiation.
 *
 * |in_mont| may be a reusable Montgomery context for |m| (borrowed; never
 * freed here), or NULL to build and free a temporary one.  When non-NULL,
 * its modulus must be |m|.
 *
 * Not constant-time: branches on both exponents' bits; do not use for
 * secret exponents (see the leak note in OSSL_FN_mod_exp()).  The mont(1)
 * accumulator init also branches on m's top bit, which is public.  The
 * m == 1 early exit likewise branches only on the public modulus.
 *
 * Fixed-width: OSSL_FN_mul_mont / OSSL_FN_from_mont need ml-limb <N
 * operands, so the algorithm runs in an ml-limb accumulator |rr|, and the
 * final from_mont runs into ml-limb |tmp| before a copy-truncate into |r|.
 * Aliasing |r| with any operand except |m| is safe; |r == m| is rejected.
 * Both |a1| and |a2| are reduced internally by to_mont(), which removes any
 * separate OSSL_FN_mod() stage.
 */
int OSSL_FN_mod_exp2_mont(OSSL_FN *r, const OSSL_FN *a1, const OSSL_FN *p1,
    const OSSL_FN *a2, const OSSL_FN *p2, const OSSL_FN *m, OSSL_FN_CTX *ctx,
    OSSL_FN_MONT_CTX *in_mont)
{
    const void *token = OSSL_FN_CTX_start(ctx);
    OSSL_FN_MONT_CTX *mont = NULL;
    int i, j, b;
    int ret = 0;
    int r_is_one = 1;
    int wvalue1 = 0, wvalue2 = 0;
    int wpos1 = 0, wpos2 = 0;

    if (token == NULL)
        return 0;

    if (r == m) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    /* Defensive: modulus must be odd, as with OSSL_FN_mod_exp_mont(). */
    if (m->dsize <= 0 || (m->d[0] & OSSL_FN_ULONG_C(1)) == 0) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    if (OSSL_FN_is_one(m)) {
        OSSL_FN_clear(r);
        ret = 1;
        goto err;
    }

    int bits1 = (int)OSSL_FN_num_bits(p1);
    int bits2 = (int)OSSL_FN_num_bits(p2);

    if (bits1 == 0 && bits2 == 0) {
        /*
         * TODO(FIXNUM): BN parity returns 1 for 0**0; mathematically
         * undefined, so consider erroring out instead.  Kept as-is until
         * existing call sites are analysed.
         */
        OSSL_FN_clear(r);
        if (r->dsize > 0)
            r->d[0] = OSSL_FN_ULONG_C(1);
        ret = 1;
        goto err;
    }

    size_t ml = (size_t)m->dsize;

    OSSL_FN *rr = OSSL_FN_CTX_get_limbs(ctx, ml);
    OSSL_FN *d = OSSL_FN_CTX_get_limbs(ctx, ml);
    OSSL_FN *tmp = OSSL_FN_CTX_get_limbs(ctx, ml);
    if (rr == NULL || d == NULL || tmp == NULL)
        goto err;

    OSSL_FN *val1[TABLE_SIZE], *val2[TABLE_SIZE];

    /* Clear both val tables so OSSL_FN_CTX_end() never sees stale pointers. */
    for (i = 0; i < TABLE_SIZE; i++)
        val1[i] = val2[i] = NULL;

    if (in_mont != NULL) {
        if (m->dsize != in_mont->N->dsize || OSSL_FN_cmp(m, in_mont->N) != 0) {
            ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_INVALID_ARGUMENT);
            goto err;
        }
        mont = in_mont;
    } else {
        mont = OSSL_FN_MONT_CTX_new(m);
        if (mont == NULL)
            goto err;
    }

    if ((val1[0] = OSSL_FN_CTX_get_limbs(ctx, ml)) == NULL)
        goto err;
    if (!OSSL_FN_to_mont(val1[0], a1, mont, ctx))
        goto err;

    int window1 = OSSL_FN_WINDOW_BITS_FOR_EXPONENT_SIZE(bits1);
    if (window1 > 1) {
        if (!OSSL_FN_mul_mont_quick(d, val1[0], val1[0], mont, ctx))
            goto err;
        j = 1 << (window1 - 1);
        for (i = 1; i < j; i++) {
            if ((val1[i] = OSSL_FN_CTX_get_limbs(ctx, ml)) == NULL)
                goto err;
            if (!OSSL_FN_mul_mont_quick(val1[i], val1[i - 1], d, mont, ctx))
                goto err;
        }
    }

    if ((val2[0] = OSSL_FN_CTX_get_limbs(ctx, ml)) == NULL)
        goto err;
    if (!OSSL_FN_to_mont(val2[0], a2, mont, ctx))
        goto err;

    int window2 = OSSL_FN_WINDOW_BITS_FOR_EXPONENT_SIZE(bits2);
    if (window2 > 1) {
        if (!OSSL_FN_mul_mont_quick(d, val2[0], val2[0], mont, ctx))
            goto err;
        j = 1 << (window2 - 1);
        for (i = 1; i < j; i++) {
            if ((val2[i] = OSSL_FN_CTX_get_limbs(ctx, ml)) == NULL)
                goto err;
            if (!OSSL_FN_mul_mont_quick(val2[i], val2[i - 1], d, mont, ctx))
                goto err;
        }
    }

    /*
     * The mont(1) accumulator init branches on the modulus top bit, which
     * is public.  When set, R mod N == R - N (the modulus's two's
     * complement); otherwise convert 1 to Montgomery form.
     */
    if (m->d[ml - 1] & OSSL_FN_HIGH_BIT_MASK) {
        rr->d[0] = OSSL_FN_ULONG_C(0) - m->d[0];
        for (i = 1; i < (int)ml; i++)
            rr->d[i] = ~m->d[i];
    } else {
        if (!ossl_assert(OSSL_FN_one(tmp)))
            goto err;
        if (!OSSL_FN_to_mont(rr, tmp, mont, ctx))
            goto err;
    }

    int bits_total = bits1 > bits2 ? bits1 : bits2;

    /*
     * Pending-window sweep: |wvalue1| / |wvalue2| accumulate while their
     * |wpos1| / |wpos2| record the completing bit.  The low-scan stops at
     * the first set bit, so the window value is always odd; table entry
     * |val[<w>>1]| then matches the odd powers (2i + 1) indexing used by
     * the precomputed table.  OSSL_FN_is_bit_set() reads a negative index
     * as 0, so the scan may dip below zero.
     */
    for (b = bits_total - 1; b >= 0; b--) {
        if (!r_is_one)
            if (!OSSL_FN_mul_mont_quick(rr, rr, rr, mont, ctx))
                goto err;

        if (!wvalue1)
            if (OSSL_FN_is_bit_set(p1, b)) {
                /* Consider bits b-window1+1 .. b for this window. */
                i = b - window1 + 1;
                while (!OSSL_FN_is_bit_set(p1, i))
                    i++;
                wpos1 = i;
                wvalue1 = 1;
                for (i = b - 1; i >= wpos1; i--) {
                    wvalue1 <<= 1;
                    if (OSSL_FN_is_bit_set(p1, i))
                        wvalue1++;
                }
            }

        if (!wvalue2)
            if (OSSL_FN_is_bit_set(p2, b)) {
                /* Consider bits b-window2+1 .. b for this window. */
                i = b - window2 + 1;
                while (!OSSL_FN_is_bit_set(p2, i))
                    i++;
                wpos2 = i;
                wvalue2 = 1;
                for (i = b - 1; i >= wpos2; i--) {
                    wvalue2 <<= 1;
                    if (OSSL_FN_is_bit_set(p2, i))
                        wvalue2++;
                }
            }

        /* wvalue1 and wvalue2 are odd and < 2^window, so >> 1 indexes val. */
        if (wvalue1 && b == wpos1) {
            if (!OSSL_FN_mul_mont_quick(rr, rr, val1[wvalue1 >> 1], mont, ctx))
                goto err;
            wvalue1 = 0;
            r_is_one = 0;
        }

        if (wvalue2 && b == wpos2) {
            if (!OSSL_FN_mul_mont_quick(rr, rr, val2[wvalue2 >> 1], mont, ctx))
                goto err;
            wvalue2 = 0;
            r_is_one = 0;
        }
    }

    /* from_mont needs an ml-limb destination; then copy-truncate into |r|. */
    if (!OSSL_FN_from_mont(tmp, rr, mont, ctx))
        goto err;
    if (OSSL_FN_copy_truncate(r, tmp) == NULL)
        goto err;
    ret = 1;

err:
    if (in_mont == NULL)
        OSSL_FN_MONT_CTX_free(mont);
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}
