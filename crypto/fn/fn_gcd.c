/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <openssl/err.h>
#include "crypto/cryptlib.h"
#include "crypto/fnerr.h"
#include "fn_local.h"

/*
 * GCD needs zero detection for zero-input handling and loop termination.
 * This scans the full fixed-width value rather than deriving a significant
 * size from |dsize|.
 */
static int ossl_fn_is_zero(const OSSL_FN *a)
{
    OSSL_FN_ULONG acc = 0;

    for (int i = 0; i < a->dsize; i++)
        acc |= a->d[i];

    return acc == 0;
}

static int ossl_fn_is_odd_nonzero(const OSSL_FN *a)
{
    return !ossl_fn_is_zero(a) && (a->d[0] & 1) != 0;
}

/*
 * GCD needs the 2-adic valuation of its inputs to remove common powers of two.
 * This scan is value-dependent by nature, but does not treat |dsize| as a
 * significant-size indicator; leading zero limbs remain part of the fixed
 * width.
 */
static int ossl_fn_count_trailing_zeros(const OSSL_FN *a)
{
    int ret = 0;

    for (int i = 0; i < a->dsize; i++) {
        OSSL_FN_ULONG limb = a->d[i];

        if (limb != 0) {
            for (int j = 0; j < OSSL_FN_BITS; j++) {
                if (((limb >> j) & 1) != 0)
                    return ret + j;
            }
        }

        if (ret > INT_MAX - OSSL_FN_BITS)
            return INT_MAX;
        ret += OSSL_FN_BITS;
    }

    return ret;
}

static void ossl_fn_swap(OSSL_FN **a, int *aneg, OSSL_FN **b, int *bneg)
{
    OSSL_FN *tmp = *a;
    int tmpneg = *aneg;

    *a = *b;
    *aneg = *bneg;
    *b = tmp;
    *bneg = tmpneg;
}

static int ossl_fn_signed_add(OSSL_FN *r, int *rneg,
    const OSSL_FN *a, int aneg, const OSSL_FN *b, int bneg)
{
    int cmp;

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

    if (ossl_fn_is_zero(r))
        *rneg = 0;

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
    int shift, vshift;
    size_t ubits, vbits, m;

    if (ossl_fn_is_zero(a)) {
        OSSL_FN_copy_truncate(r, b);
        ret = 1;
        goto err;
    }
    if (ossl_fn_is_zero(b)) {
        OSSL_FN_copy_truncate(r, a);
        ret = 1;
        goto err;
    }

    if ((u = OSSL_FN_CTX_get_limbs(ctx, scratch)) == NULL
        || (v = OSSL_FN_CTX_get_limbs(ctx, scratch)) == NULL
        || (t = OSSL_FN_CTX_get_limbs(ctx, scratch)) == NULL
        || (rr = OSSL_FN_CTX_get_limbs(ctx, scratch)) == NULL)
        goto err;

    /*
     * Strongly follows BN_gcd(): make both inputs artificially even, remove
     * shared powers of two including the artificial shift, run the fixed
     * Bernstein-Yang-inspired loop, then restore the removed power of two and
     * undo the artificial shift.
     *
     * The loop treats |u|, |v|, and |t| as signed intermediate values,
     * represented by the separate |uneg|, |vneg|, and |tneg| flags.  This
     * mirrors BN_gcd()'s use of BIGNUM->neg during the elimination step:
     * when BN_gcd() computes temp = g + r, the mathematical operation may be
     * either addition or subtraction depending on r's sign.  OSSL_FN remains
     * unsigned throughout; the local flags only choose the correct unsigned
     * add/sub operation for these algorithmic intermediates.
     */
    if (!OSSL_FN_lshift1(u, a)
        || !OSSL_FN_lshift1(v, b))
        goto err;

    shift = ossl_fn_count_trailing_zeros(a);
    vshift = ossl_fn_count_trailing_zeros(b);
    if (vshift < shift)
        shift = vshift;
    if (shift == INT_MAX)
        goto err;
    shift++;

    if (!OSSL_FN_rshift(u, u, shift)
        || !OSSL_FN_rshift(v, v, shift))
        goto err;

    if (!ossl_fn_is_odd_nonzero(u))
        ossl_fn_swap(&u, &uneg, &v, &vneg);

    ubits = OSSL_FN_num_bits(u);
    vbits = OSSL_FN_num_bits(v);
    m = ubits > vbits ? ubits : vbits;
    if (m > ((size_t)INT_MAX - 4) / 3)
        goto err;
    m = 4 + 3 * m;

    for (size_t i = 0; i < m; i++) {
        int cond = delta > 0 && ossl_fn_is_odd_nonzero(v);

        if (cond) {
            delta = -delta;
            uneg ^= 1;
            ossl_fn_swap(&u, &uneg, &v, &vneg);
        }

        delta++;
        if (!ossl_fn_signed_add(t, &tneg, v, vneg, u, uneg))
            goto err;

        if (ossl_fn_is_odd_nonzero(v))
            ossl_fn_swap(&v, &vneg, &t, &tneg);

        if (!OSSL_FN_rshift1(v, v))
            goto err;
        if (ossl_fn_is_zero(v))
            vneg = 0;
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
