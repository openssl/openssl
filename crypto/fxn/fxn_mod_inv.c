/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "crypto/fxnerr.h"
#include "crypto/fxn_constants.h"
#include "fxn_local.h"

/*-
 * OSSL_FXN_mod_inverse_ctx_size_from_sizes() calculates a plausible upper bound
 * for the OSSL_FXN_CTX size.
 *
 * Working set (A, B, X, Y, D, M):
 *   A, B, X, Y, D, M  -- six temporaries, each L limbs, where
 *   L = max(a->dsize, n->dsize).
 *
 *   - L covers the initial B = a (before reduction) and A = n copies.
 *   - The extended-Euclid coefficients X, Y stay at most |n|
 *     throughout (standard bound; X and Y are never reduced inside the
 *     loop), so Y + D*X stays at most |n| and the OSSL_FXN_mul(tmp, D, X)
 *     call is exact -- the high limbs it may truncate are genuinely zero.
 *
 * Nested calls (sequential, so only one nested frame live at a time):
 *   - initial reduction: OSSL_FXN_mod(B, B, A)        [== OSSL_FXN_div]
 *   - loop body:         OSSL_FXN_div(D, M, A, B)     [the (D, M) := (A/B, A%B) step]
 *                        OSSL_FXN_mul(tmp, D, X)      [exact, see above]
 *                        OSSL_FXN_add(tmp, tmp, Y)
 *   - final fixup:       OSSL_FXN_sub(Y, n, Y)        [if sign < 0]
 *                        OSSL_FXN_mod(r, Y, n)        [if reduction needed]
 *
 * The dominant nested requirement is that of the two OSSL_FXN_mod() calls
 * (OSSL_FXN_div() with q == NULL, which makes
 * OSSL_FXN_div_ctx_size_from_sizes() reserve an extra quotient temporary).
 * OSSL_FXN_mul's own ctx requirement is zero when r != a and r != b
 * (tmp != D and tmp != X here), so it contributes no nested frame.
 * OSSL_FXN_add and OSSL_FXN_sub take no ctx.
 * The loop-body OSSL_FXN_div(D, M, A, B)'s requirement is bounded by the
 * OSSL_FXN_mod calls'.  We compute the max of the div and mod sizes to be
 * safe across the reductions and the loop-body division.
 */
size_t OSSL_FXN_mod_inverse_ctx_size_from_sizes(size_t r_dsize, size_t a_dsize,
    size_t n_dsize)
{
    size_t L = a_dsize > n_dsize ? a_dsize : n_dsize;
    if (ossl_fxn_totalsize(L) == 0)
        return 0;

    size_t own_size = OSSL_FXN_CTX_size(1, 6, 6 * L);

    /*
     * Nested: the loop-body division OSSL_FXN_div(D, M, A, B) with all four at
     * L limbs, and the final reduction OSSL_FXN_mod(r, Y, n).
     */

    /* OSSL_FXN_div(D, M, A, B): D and M are results, A and B are operands. */
    size_t div_size = OSSL_FXN_div_ctx_size_from_sizes(L, L, L, L);
    /* OSSL_FXN_mod(r, Y, n): the final reduction, r is the caller's. */
    size_t mod_size = OSSL_FXN_mod_ctx_size_from_sizes(r_dsize, L, n_dsize);

    size_t nested_size = ossl_fxn_ctx_max_size(div_size, mod_size);
    return ossl_fxn_ctx_add_size(own_size, nested_size);
}

size_t OSSL_FXN_mod_inverse_ctx_size_from_nums(
    const OSSL_FXN *r, const OSSL_FXN *a, const OSSL_FXN *n)
{
    if (a == NULL || n == NULL)
        return 0;

    return OSSL_FXN_mod_inverse_ctx_size_from_sizes(OSSL_FXN_size_limbs(r),
        a->dsize, n->dsize);
}

/*-
 * OSSL_FXN_mod_inverse() computes the modular multiplicative inverse of |a|
 * modulo |n|, i.e. a value |r| such that  r * a == 1  (mod n), with
 * 0 <= r < n.  It uses the extended-Euclidean algorithm with the
 * A/B/X/Y/D/M working-set rotation and no value-branching shortcuts.
 * The invariant comments inside the loop are load-bearing.
 *
 * Constant-time profile:
 *   - No masked conditional swap/select is used, and none is needed: the
 *     loop rotates working values by pointer reassignment, not by
 *     value-dependent swaps.
 *   - What leaks: the iteration count (the while !is_zero(B) loop runs until
 *     B is reduced to zero, so the count reveals the operands' magnitudes),
 *     the final is_one(A) test, the OSSL_FXN_cmp(Y, n) test, and the
 *     if (sign < 0) test.
 *   - The OSSL_FXN primitives used here (OSSL_FXN_mod, OSSL_FXN_mul,
 *     OSSL_FXN_add, OSSL_FXN_sub, OSSL_FXN_copy_truncate, OSSL_FXN_one,
 *     OSSL_FXN_zero, OSSL_FXN_is_zero, OSSL_FXN_is_one) branch only on public
 *     widths, not on limb values, except that OSSL_FXN_div / OSSL_FXN_mod scan
 *     the denominator's significant limbs (see OSSL_FXN_div) and OSSL_FXN_cmp
 *     performs a value comparison.
 *
 * OSSL_FXN is unsigned, so the |sign| bookkeeping (an int flipped with -sign)
 * is kept entirely internal to this function; no sign is returned or passed
 * across the public(ish) boundary.
 *
 * TODO(FIXNUM): a value-branching variant with an odd-n <= 2048-bit fast
 * path and small-D (is_one / is_word(2) / is_word(4) / single-word) D*X+Y
 * optimizations is not included here.  It may be added later if a use case
 * needs the speed and can tolerate its value-branching leak profile.
 */
int OSSL_FXN_mod_inverse(OSSL_FXN *r, const OSSL_FXN *a, const OSSL_FXN *n,
    OSSL_FXN_CTX *ctx)
{
    if (ossl_unlikely(r == NULL || a == NULL || n == NULL)) {
        ERR_raise(ERR_LIB_OSSL_FXN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    const void *token = OSSL_FXN_CTX_start(ctx);
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
    if (OSSL_FXN_is_zero(n) || OSSL_FXN_is_one(n)) {
        ERR_raise(ERR_LIB_OSSL_FXN, OSSL_FXN_R_NO_INVERSE);
        goto err;
    }

    size_t al = (size_t)a->dsize;
    size_t nl = (size_t)n->dsize;
    size_t L = al > nl ? al : nl;

    OSSL_FXN *A = OSSL_FXN_CTX_get_limbs(ctx, token, L);
    OSSL_FXN *B = OSSL_FXN_CTX_get_limbs(ctx, token, L);
    OSSL_FXN *X = OSSL_FXN_CTX_get_limbs(ctx, token, L);
    OSSL_FXN *Y = OSSL_FXN_CTX_get_limbs(ctx, token, L);
    OSSL_FXN *D = OSSL_FXN_CTX_get_limbs(ctx, token, L);
    OSSL_FXN *M = OSSL_FXN_CTX_get_limbs(ctx, token, L);
    if (A == NULL || B == NULL || X == NULL || Y == NULL
        || D == NULL || M == NULL)
        goto err;

    if (!OSSL_FXN_one(X) || !OSSL_FXN_zero(Y))
        goto err;
    if (OSSL_FXN_copy_truncate(B, a) == NULL
        || OSSL_FXN_copy_truncate(A, n) == NULL)
        goto err;

    if (OSSL_FXN_cmp(B, A) >= 0) {
        if (!OSSL_FXN_mod(B, B, A, ctx))
            goto err;
    }

    /*-
     * From  B = a mod |n|,  A = |n|  it follows that
     *
     *      0 <= B < A,
     *     -sign*X*a  ==  B   (mod |n|),
     *      sign*Y*a  ==  A   (mod |n|).
     */

    int sign = -1;
    while (!OSSL_FXN_is_zero(B)) {
        /*-
         *      0 < B < A,
         * (*) -sign*X*a  ==  B   (mod |n|),
         *      sign*Y*a  ==  A   (mod |n|)
         */

        /* (D, M) := (A/B, A%B) ... */
        if (!OSSL_FXN_div(D, M, A, B, ctx))
            goto err;

        /*-
         * Now
         *      A = D*B + M;
         * thus we have
         * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
         */

        /* hold on to the original A */
        OSSL_FXN *tmp = A;

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

        if (!OSSL_FXN_mul(tmp, D, X, ctx))
            goto err;
        if (!OSSL_FXN_add(tmp, tmp, Y))
            goto err;

        M = Y; /* keep the OSSL_FXN object, the value does not
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
        if (!OSSL_FXN_sub(Y, n, Y))
            goto err;
    }

    if (OSSL_FXN_is_one(A)) {
        /* Y*a == 1  (mod |n|); A is exactly one. */
        if (OSSL_FXN_cmp(Y, n) < 0) {
            if (OSSL_FXN_copy_truncate(r, Y) == NULL)
                goto err;
        } else {
            if (!OSSL_FXN_mod(r, Y, n, ctx))
                goto err;
        }
    } else {
        /* a and n are not coprime. */
        ERR_raise(ERR_LIB_OSSL_FXN, OSSL_FXN_R_NO_INVERSE);
        goto err;
    }

    ret = 1;

err:
    OSSL_FXN_CTX_end(ctx, token);
    return ret;
}

/*-
 * OSSL_FXN_mod_inverse_prime_ctx_size_from_sizes() -- arena sizing for
 * OSSL_FXN_mod_inverse_prime().
 *
 * The exponent e = m - 2 the operator computes internally is exactly
 * m-wide, so |m|'s width stands in for it in the nested
 * OSSL_FXN_mod_exp_mont_ctx_size_from_sizes() call.  Sizing goes directly to
 * the Montgomery companion, since that is the path the operator takes.
 */
size_t OSSL_FXN_mod_inverse_prime_ctx_size_from_sizes(size_t r_dsize,
    size_t a_dsize, size_t m_dsize, size_t in_mont_dsize)
{
    size_t ml = m_dsize;
    /* A zero-limb modulus is invalid; OSSL_FXN_mod_inverse_prime() rejects it. */
    if (ml == 0 || ossl_fxn_totalsize(ml) == 0)
        return 0;

    /* One frame holding the m-wide exponent scratch e = m - 2. */
    size_t own_size = OSSL_FXN_CTX_size(1, 1, ml);

    /*
     * The nested OSSL_FXN_mod_exp_mont() call: base |a|, an m-wide
     * exponent, modulus |m|, and the caller's Montgomery context, if any,
     * passed on as is.
     */
    size_t nested_size = OSSL_FXN_mod_exp_mont_ctx_size_from_sizes(r_dsize,
        a_dsize, ml, ml, in_mont_dsize);
    return ossl_fxn_ctx_add_size(own_size, nested_size);
}

size_t OSSL_FXN_mod_inverse_prime_ctx_size_from_nums(const OSSL_FXN *r,
    const OSSL_FXN *a, const OSSL_FXN *m, OSSL_FXN_MONT_CTX *in_mont)
{
    if (a == NULL || m == NULL)
        return 0;

    return OSSL_FXN_mod_inverse_prime_ctx_size_from_sizes(OSSL_FXN_size_limbs(r),
        a->dsize, m->dsize,
        in_mont == NULL ? 0 : OSSL_FXN_size_limbs(in_mont->N));
}

/*-
 * OSSL_FXN_mod_inverse_prime() computes the modular multiplicative inverse
 * of |a| modulo the prime |m| as  a^(m-2) mod m,  a Montgomery fixed-window
 * exponentiation via OSSL_FXN_mod_exp_mont().
 *
 * Constant-time profile:
 *   - The exponent e = m - 2 derives from the modulus alone, so it is
 *     public in all intended uses; the fixed-window loop iterates over the
 *     exponent's full allocated width, so the base may be secret: nothing
 *     branches on its value.  What may leak is limited to the operand
 *     widths and the modulus.
 *   - |m| is public: OSSL_FXN_mod_exp_mont() branches on it (the oddness
 *     check, the m == 1 early exit, the R mod N special case).
 *
 * Preconditions (unchecked beyond what OSSL_FXN_mod_exp_mont() enforces):
 *   - |m| must be prime.  A composite modulus makes the result garbage,
 *     not an error: the Fermat relation simply does not hold.
 *   - |m| must be odd; OSSL_FXN_mod_exp_mont() rejects even moduli, so the
 *     prime 2 and zero are diagnosed, while m == 1 (odd, not prime) yields
 *     0 through that function's early exit.
 * a == 0 (mod m) yields 0, which is not an inverse; callers are expected
 * to handle that case, typically with a retry / reject loop.  The
 * constant-time profile above requires |a| reduced mod m and m-wide; an
 * unreduced |a| is still handled correctly, but not in constant time.
 */
int OSSL_FXN_mod_inverse_prime(OSSL_FXN *r, const OSSL_FXN *a, const OSSL_FXN *m,
    OSSL_FXN_CTX *ctx, OSSL_FXN_MONT_CTX *in_mont)
{
    const void *token = OSSL_FXN_CTX_start(ctx);
    OSSL_FXN *e = NULL;
    int ret = 0;

    if (token == NULL)
        return 0;
    if (ossl_unlikely(r == NULL || a == NULL || m == NULL)) {
        ERR_raise(ERR_LIB_OSSL_FXN, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }
    /* OSSL_FXN_mod_exp_mont() validates the modulus further (odd, m != 1). */
    if (m->dsize <= 0) {
        ERR_raise(ERR_LIB_OSSL_FXN, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }

    /* e = m - 2, exactly m-wide; 2 is the shared static constant. */
    if ((e = OSSL_FXN_CTX_get_limbs(ctx, token, (size_t)m->dsize)) == NULL)
        goto err;
    if (!OSSL_FXN_sub(e, m, &ossl_fxn_static_const_2_storage.fxn))
        goto err;

    ret = OSSL_FXN_mod_exp_mont(r, a, e, m, ctx, in_mont);

err:
    OSSL_FXN_CTX_end(ctx, token);
    return ret;
}
