/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "internal/safe_math.h"
#include "crypto/fnerr.h"
#include "fn_local.h"

OSSL_SAFE_MATH_ADDU(size_t, size_t, OSSL_SAFE_MATH_MAXU(size_t))

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

/*-
 * OSSL_FN_mod_inverse() computes the modular multiplicative inverse of |a|
 * modulo |n|, i.e. a value |r| such that  r * a == 1  (mod n), with
 * 0 <= r < n.  It uses the extended-Euclidean algorithm with the
 * A/B/X/Y/D/M/T working-set rotation and no value-branching shortcuts.
 * The invariant comments inside the loop are load-bearing.
 *
 * Constant-time profile:
 *   - No masked conditional swap/select is used, and none is needed: the
 *     loop rotates working values by pointer reassignment, not by
 *     value-dependent swaps.
 *   - What leaks: the iteration count (the while !is_zero(B) loop runs until
 *     B is reduced to zero, so the count reveals the operands' magnitudes),
 *     the final is_one(A) test, the OSSL_FN_cmp(Y, n) test, and the
 *     if (sign < 0) test.
 *   - The OSSL_FN primitives used here (OSSL_FN_mod, OSSL_FN_mul, OSSL_FN_add,
 *     OSSL_FN_sub, OSSL_FN_copy_truncate, OSSL_FN_one, OSSL_FN_zero,
 *     OSSL_FN_is_zero, OSSL_FN_is_one) branch only on public widths, not on
 *     limb values, except that OSSL_FN_div / OSSL_FN_mod scan the
 *     denominator's significant limbs (see OSSL_FN_div) and OSSL_FN_cmp
 *     performs a value comparison.
 *
 * OSSL_FN is unsigned, so the |sign| bookkeeping (an int flipped with -sign)
 * is kept entirely internal to this function; no sign is returned or passed
 * across the public(ish) boundary.
 *
 * TODO(FIXNUM): a value-branching variant with an odd-n <= 2048-bit fast
 * path and small-D (is_one / is_word(2) / is_word(4) / single-word) D*X+Y
 * optimizations is not included here.  It may be added later if a use case
 * needs the speed and can tolerate its value-branching leak profile.
 */

/*-
 * The *_ctx_size helper below uses a local OSSL_FN header with only |dsize|
 * set to represent a temporary that the operation allocates with
 * OSSL_FN_CTX_get_limbs().  This is enough for nested ctx-size helpers,
 * which only inspect operand sizes.
 *
 * Working set (A, B, X, Y, D, M, T):
 *   A, B, X, Y, D, M, T  -- seven temporaries, each L limbs, where
 *   L = max(a->dsize, n->dsize).
 *
 *   - L covers the initial B = a (before reduction) and A = n copies.
 *   - The extended-Euclid coefficients X, Y stay strictly less than |n|
 *     throughout (standard bound; X and Y are never reduced inside the
 *     loop), so D*X < n and the OSSL_FN_mul(tmp, D, X) call is exact --
 *     the high limbs it may truncate are genuinely zero.
 *
 * Nested calls (sequential, so only one nested frame live at a time):
 *   - initial reduction: OSSL_FN_mod(B, a, n)        [== OSSL_FN_div]
 *   - loop body:         OSSL_FN_div(D, M, A, B)     [the (D, M) := (A/B, A%B) step]
 *                        OSSL_FN_mul(T, D, X)        [exact, see above]
 *                        OSSL_FN_add(T, T, Y)
 *   - final fixup:       OSSL_FN_sub(Y, n, Y)        [if sign < 0]
 *                        OSSL_FN_mod(r, Y, n)        [if reduction needed]
 *
 * The dominant nested requirement is OSSL_FN_div(D, M, A, B), whose ctx-size
 * is OSSL_FN_div_ctx_size(D, M, A, B).  OSSL_FN_mul's own ctx requirement is
 * zero when r != a and r != b (T != D and T != X here), so it contributes no
 * nested frame.  OSSL_FN_add and OSSL_FN_sub take no ctx.  The two OSSL_FN_mod
 * calls' requirements are bounded by OSSL_FN_div's, so the max over the nested
 * calls is OSSL_FN_div_ctx_size(D, M, A, B) (with D possibly NULL for the
 * final mod).  We compute the max of the div and mod sizes to be safe across
 * the reduction and the loop-body division.
 */
size_t OSSL_FN_mod_inverse_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *n)
{
    size_t al, nl, L, own_size, div_size, mod_size, nested_size;

    if (r == NULL || a == NULL || n == NULL)
        return 0;

    al = (size_t)a->dsize;
    nl = (size_t)n->dsize;
    L = al > nl ? al : nl;
    if (ossl_fn_totalsize(L) == 0)
        return 0;

    /* Seven temporaries of L limbs each, in our own frame. */
    own_size = OSSL_FN_CTX_size(1, 7, 7 * L);

    /*
     * Nested: the loop-body division OSSL_FN_div(D, M, A, B) with all four at
     * L limbs, and the final reduction OSSL_FN_mod(r, Y, n).  Model the
     * temporaries the nested calls see with a local header at L limbs.
     */
    OSSL_FN t_L = { .dsize = (int)L };

    /* OSSL_FN_div(D, M, A, B): D and M are results, A and B are operands. */
    div_size = OSSL_FN_div_ctx_size(&t_L, &t_L, &t_L, &t_L);
    /* OSSL_FN_mod(r, Y, n): the final reduction, r is the caller's. */
    mod_size = OSSL_FN_mod_ctx_size(r, &t_L, n);

    nested_size = ctx_max_size(div_size, mod_size);
    if (own_size == 0 || nested_size == 0)
        return 0;

    return ctx_add_size(own_size, nested_size);
}

/*
 * Modular multiplicative inverse.
 *
 * This is an internal function, we assume all callers pass valid arguments:
 * r, a, n are non-NULL; ctx is non-NULL and sized per
 * OSSL_FN_mod_inverse_ctx_size().
 */
int OSSL_FN_mod_inverse(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *n,
    OSSL_FN_CTX *ctx)
{
    const void *token = OSSL_FN_CTX_start(ctx);
    OSSL_FN *A, *B, *X, *Y, *D, *M, *T;
    OSSL_FN *tmp;
    int sign;
    int ret = 0;

    if (token == NULL)
        return 0;

    /*
     * The degenerate moduli have no inverse for any a: for n == 0 the
     * relation r*a == 1 (mod 0) is never satisfiable, and for n == 1 the
     * only residue in [0, n) is 0, so the identity 1 is not representable
     * and no element can act as a multiplicative inverse.  Short-circuit
     * both to NO_INVERSE rather than surfacing the DIV_BY_ZERO the reduction
     * below would raise for n == 0, and rather than reporting a spurious
     * r == 0 inverse for n == 1.  This is the only input pre-check; every
     * other edge case (a == 0, non-coprime) falls out of the algorithm
     * below.
     */
    if (OSSL_FN_is_zero(n) || OSSL_FN_is_one(n)) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_NO_INVERSE);
        goto err;
    }

    size_t al = (size_t)a->dsize;
    size_t nl = (size_t)n->dsize;
    size_t L = al > nl ? al : nl;

    A = OSSL_FN_CTX_get_limbs(ctx, L);
    B = OSSL_FN_CTX_get_limbs(ctx, L);
    X = OSSL_FN_CTX_get_limbs(ctx, L);
    Y = OSSL_FN_CTX_get_limbs(ctx, L);
    D = OSSL_FN_CTX_get_limbs(ctx, L);
    M = OSSL_FN_CTX_get_limbs(ctx, L);
    T = OSSL_FN_CTX_get_limbs(ctx, L);
    if (A == NULL || B == NULL || X == NULL || Y == NULL
        || D == NULL || M == NULL || T == NULL)
        goto err;

    /* X = 1, Y = 0 */
    if (!OSSL_FN_one(X) || !OSSL_FN_zero(Y))
        goto err;
    /* B = a, A = |n| (n is already unsigned, so A = n) */
    if (OSSL_FN_copy_truncate(B, a) == NULL
        || OSSL_FN_copy_truncate(A, n) == NULL)
        goto err;

    if (OSSL_FN_cmp(B, A) >= 0) {
        if (!OSSL_FN_mod(B, B, A, ctx))
            goto err;
    }
    sign = -1;
    /*-
     * From  B = a mod |n|,  A = |n|  it follows that
     *
     *      0 <= B < A,
     *     -sign*X*a  ==  B   (mod |n|),
     *      sign*Y*a  ==  A   (mod |n|).
     */

    while (!OSSL_FN_is_zero(B)) {
        /*-
         *      0 < B < A,
         * (*) -sign*X*a  ==  B   (mod |n|),
         *      sign*Y*a  ==  A   (mod |n|)
         */

        /* (D, M) := (A/B, A%B) ... */
        if (!OSSL_FN_div(D, M, A, B, ctx))
            goto err;

        /*-
         * Now
         *      A = D*B + M;
         * thus we have
         * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
         */

        tmp = A; /* keep the OSSL_FN object, the value does not
                  * matter */

        /* (A, B) := (B, A mod B) ... */
        A = B;
        B = M;
        /* ... so we have  0 <= B < A  again */

        /*-
         * Since the former  M  is now  B  and the former  B  is now  A,
         * (**) translates into
         *       sign*Y*a  ==  D*A + B    (mod |n|),
         * i.e.
         *       sign*Y*a - D*A  ==  B    (mod |n|).
         * Similarly, (*) translates into
         *      -sign*X*a  ==  A          (mod |n|).
         *
         * Thus,
         *   sign*Y*a + D*sign*X*a  ==  B  (mod |n|),
         * i.e.
         *        sign*(Y + D*X)*a  ==  B  (mod |n|).
         *
         * So if we set  (X, Y, sign) := (Y + D*X, X, -sign), we arrive back at
         *      -sign*X*a  ==  B   (mod |n|),
         *       sign*Y*a  ==  A   (mod |n|).
         * Note that  X  and  Y  stay non-negative all the time.
         */

        if (!OSSL_FN_mul(tmp, D, X, ctx))
            goto err;
        if (!OSSL_FN_add(tmp, tmp, Y))
            goto err;

        M = Y; /* keep the OSSL_FN object, the value does not
                * matter */
        Y = X;
        X = tmp;
        sign = -sign;
    }

    /*-
     * The while loop (Euclid's algorithm) ends when
     *      A == gcd(a,n);
     * we have
     *       sign*Y*a  ==  A  (mod |n|),
     * where  Y  is non-negative.
     */

    if (sign < 0) {
        if (!OSSL_FN_sub(Y, n, Y))
            goto err;
    }
    /* Now  Y*a  ==  A  (mod |n|).  */

    if (OSSL_FN_is_one(A)) {
        /* Y*a == 1  (mod |n|); A is exactly one. */
        if (OSSL_FN_cmp(Y, n) < 0) {
            if (OSSL_FN_copy_truncate(r, Y) == NULL)
                goto err;
        } else {
            if (!OSSL_FN_mod(r, Y, n, ctx))
                goto err;
        }
    } else {
        /* a and n are not coprime. */
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_NO_INVERSE);
        goto err;
    }

    ret = 1;

err:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}
