/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
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
 * OSSL_FN_mod_sqrt() computes ret such that ret^2 == a (mod p), using the
 * Tonelli/Shanks algorithm (cf. Henri Cohen, "A Course in Algebraic
 * Computational Number Theory", algorithm 1.5.1).
 *
 * OSSL_FN is unsigned, so |p| is just p and sign handling belongs at the
 * BIGNUM boundary.  The e > 2 random fallback reduces y into [0, p) with
 * OSSL_FN_mod(y, y, p), and falls back to a small candidate when y is zero.
 *
 * The result is computed and verified in p-wide temporaries, then truncated
 * or zero-padded into the caller-sized |ret|.  OSSL_FN requires |ret| to be a
 * non-NULL writable destination.
 *
 * This function is not constant-time: it branches on values throughout --
 * the e-dispatch, the e==2 Atkin path, the e > 2 non-residue search with
 * OSSL_FN_kronecker(), and the "smallest i with b^(2^i)==1" scan.
 *
 * 'p' must be prime, otherwise an error or an incorrect result is returned.
 */
int OSSL_FN_mod_sqrt(OSSL_FN *ret, const OSSL_FN *a, const OSSL_FN *p,
    OSSL_FN_CTX *ctx)
{
    const void *token;
    OSSL_FN *A, *b, *q, *t, *x, *y, *z;
    int e, i, j;
    int err = 1;
    int r;
    size_t pl, L;

    token = OSSL_FN_CTX_start(ctx);
    if (token == NULL)
        return 0;

    pl = (size_t)p->dsize;
    L = pl; /* all temporaries are p-wide */

    if (!OSSL_FN_is_odd(p) || OSSL_FN_is_word(p, 1)) {
        if (OSSL_FN_is_word(p, 2)) {
            /* result is bit 0 of a */
            if (!OSSL_FN_set_word(ret, OSSL_FN_is_bit_set(a, 0))) {
                err = 1;
                goto end;
            }
            err = 0;
            goto end;
        }

        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_P_IS_NOT_PRIME);
        goto end;
    }

    if (OSSL_FN_is_zero(a) || OSSL_FN_is_one(a)) {
        if (!OSSL_FN_set_word(ret, OSSL_FN_is_one(a))) {
            err = 1;
            goto end;
        }
        err = 0;
        goto end;
    }

    A = OSSL_FN_CTX_get_limbs(ctx, L);
    b = OSSL_FN_CTX_get_limbs(ctx, L);
    q = OSSL_FN_CTX_get_limbs(ctx, L);
    t = OSSL_FN_CTX_get_limbs(ctx, L);
    x = OSSL_FN_CTX_get_limbs(ctx, L);
    y = OSSL_FN_CTX_get_limbs(ctx, L);
    z = OSSL_FN_CTX_get_limbs(ctx, L);
    if (z == NULL)
        goto end;

    /* A = a mod p */
    if (!OSSL_FN_mod(A, a, p, ctx))
        goto end;

    /* now write  |p| - 1  as  2^e*q  where  q  is odd */
    e = 1;
    while (!OSSL_FN_is_bit_set(p, e))
        e++;
    /* we'll set  q  later (if needed) */

    if (e == 1) {
        /*-
         * The easy case:  (|p|-1)/2  is odd, so 2 has an inverse
         * modulo  (|p|-1)/2,  and square roots can be computed
         * directly by modular exponentiation.
         * We have
         *     2 * (|p|+1)/4 == 1   (mod (|p|-1)/2),
         * so we can use exponent  (|p|+1)/4,  i.e.  (|p|-3)/4 + 1.
         */
        if (!OSSL_FN_rshift(q, p, 2))
            goto end;
        if (!OSSL_FN_add_word(q, 1))
            goto end;
        if (!OSSL_FN_mod_exp(z, A, q, p, ctx))
            goto end;
        err = 0;
        goto vrfy;
    }

    if (e == 2) {
        /*-
         * |p| == 5  (mod 8)  (Atkin's trick; see BN_mod_sqrt for the
         * full derivation, due to A.O.L. Atkin, NMBRTHRY, Nov 1992).
         */

        /* t := 2*a */
        if (!OSSL_FN_mod_lshift1_quick(t, A, p))
            goto end;

        /* b := (2*a)^((|p|-5)/8) */
        if (!OSSL_FN_rshift(q, p, 3))
            goto end;
        if (!OSSL_FN_mod_exp(b, t, q, p, ctx))
            goto end;

        /* y := b^2 */
        if (!OSSL_FN_mod_sqr(y, b, p, ctx))
            goto end;

        /* t := (2*a)*b^2 - 1 */
        if (!OSSL_FN_mod_mul(t, t, y, p, ctx))
            goto end;
        if (!OSSL_FN_sub_word(t, 1))
            goto end;

        /* x = a*b*t */
        if (!OSSL_FN_mod_mul(x, A, b, p, ctx))
            goto end;
        if (!OSSL_FN_mod_mul(x, x, t, p, ctx))
            goto end;

        if (OSSL_FN_copy(z, x) == NULL)
            goto end;
        err = 0;
        goto vrfy;
    }

    /*
     * e > 2, so we really have to use the Tonelli/Shanks algorithm. First,
     * find some y that is not a square.
     */
    if (OSSL_FN_copy(q, p) == NULL)
        goto end; /* use 'q' as temp */
    i = 2;
    do {
        /*
         * For efficiency, try small numbers first; if this fails, try random
         * numbers.
         */
        if (i < 22) {
            if (!OSSL_FN_set_word(y, i))
                goto end;
        } else {
            if (!OSSL_FN_priv_rand(y, (int)OSSL_FN_num_bits(p),
                    OSSL_FN_RAND_TOP_ANY, OSSL_FN_RAND_BOTTOM_ANY,
                    0, NULL))
                goto end;
            /*
             * OSSL_FN is unsigned, so |p| is just p and an out-of-range
             * random value is reduced into [0, p).
             */
            if (OSSL_FN_cmp(y, p) >= 0) {
                if (!OSSL_FN_mod(y, y, p, ctx))
                    goto end;
            }
            /* now 0 <= y < p */
            if (OSSL_FN_is_zero(y))
                if (!OSSL_FN_set_word(y, i))
                    goto end;
        }

        r = OSSL_FN_kronecker(y, q, ctx); /* here 'q' is |p| */
        if (r < -1)
            goto end;
        if (r == 0) {
            /* m divides p */
            ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_P_IS_NOT_PRIME);
            goto end;
        }
    } while (r == 1 && ++i < 82);

    if (r != -1) {
        /*
         * Many rounds and still no non-square -- this is more likely a bug
         * than just bad luck. Even if p is not prime, we should have found
         * some y such that r == -1.
         */
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_TOO_MANY_ITERATIONS);
        goto end;
    }

    /* Here's our actual 'q': */
    if (!OSSL_FN_rshift(q, q, e))
        goto end;

    /*
     * Now that we have some non-square, we can find an element of order 2^e
     * by computing its q'th power.
     */
    if (!OSSL_FN_mod_exp(y, y, q, p, ctx))
        goto end;
    if (OSSL_FN_is_one(y)) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_P_IS_NOT_PRIME);
        goto end;
    }

    /*-
     * Now we know that (if  p  is indeed prime) there is an integer
     * k,  0 <= k < 2^e,  such that
     *
     *      a^q * y^k == 1   (mod p).
     *
     * As  a^q  is a square and  y  is not,  k  must be even.
     * q+1  is even, too, so there is an element
     *
     *     X := a^((q+1)/2) * y^(k/2),
     *
     * and it satisfies
     *
     *     X^2 = a^q * a     * y^k
     *         = a,
     *
     * so it is the square root that we are looking for.
     */

    /* t := (q-1)/2  (note that  q  is odd) */
    if (!OSSL_FN_rshift1(t, q))
        goto end;

    /* x := a^((q-1)/2) */
    if (OSSL_FN_is_zero(t)) { /* special case: p = 2^e + 1 */
        if (!OSSL_FN_mod(t, A, p, ctx))
            goto end;
        if (OSSL_FN_is_zero(t)) {
            /* special case: a == 0  (mod p) */
            if (!OSSL_FN_zero(z))
                goto end;
            err = 0;
            goto vrfy;
        } else if (!OSSL_FN_one(x)) {
            goto end;
        }
    } else {
        if (!OSSL_FN_mod_exp(x, A, t, p, ctx))
            goto end;
        if (OSSL_FN_is_zero(x)) {
            /* special case: a == 0  (mod p) */
            if (!OSSL_FN_zero(z))
                goto end;
            err = 0;
            goto vrfy;
        }
    }

    /* b := a*x^2  (= a^q) */
    if (!OSSL_FN_mod_sqr(b, x, p, ctx))
        goto end;
    if (!OSSL_FN_mod_mul(b, b, A, p, ctx))
        goto end;

    /* x := a*x    (= a^((q+1)/2)) */
    if (!OSSL_FN_mod_mul(x, x, A, p, ctx))
        goto end;

    while (1) {
        /*-
         * Now  b  is  a^q * y^k  for some even  k  (0 <= k < 2^E
         * where  E  refers to the original value of  e,  which we
         * don't keep in a variable),  and  x  is  a^((q+1)/2) * y^(k/2).
         *
         * We have  a*b = x^2,
         *    y^2^(e-1) = -1,
         *    b^2^(e-1) = 1.
         */

        if (OSSL_FN_is_one(b)) {
            if (OSSL_FN_copy(z, x) == NULL)
                goto end;
            err = 0;
            goto vrfy;
        }

        /* Find the smallest i, 0 < i < e, such that b^(2^i) = 1. */
        for (i = 1; i < e; i++) {
            if (i == 1) {
                if (!OSSL_FN_mod_sqr(t, b, p, ctx))
                    goto end;
            } else {
                if (!OSSL_FN_mod_mul(t, t, t, p, ctx))
                    goto end;
            }
            if (OSSL_FN_is_one(t))
                break;
        }
        /* If not found, a is not a square or p is not prime. */
        if (i >= e) {
            ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_NOT_A_SQUARE);
            goto end;
        }

        /* t := y^2^(e - i - 1) */
        if (OSSL_FN_copy(t, y) == NULL)
            goto end;
        for (j = e - i - 1; j > 0; j--) {
            if (!OSSL_FN_mod_sqr(t, t, p, ctx))
                goto end;
        }
        if (!OSSL_FN_mod_mul(y, t, t, p, ctx))
            goto end;
        if (!OSSL_FN_mod_mul(x, x, t, p, ctx))
            goto end;
        if (!OSSL_FN_mod_mul(b, b, y, p, ctx))
            goto end;
        e = i;
    }

vrfy:
    if (!err) {
        /*
         * verify the result -- the input might have been not a square (test
         * added in 0.9.8)
         */
        if (!OSSL_FN_mod_sqr(x, z, p, ctx))
            err = 1;

        if (!err && OSSL_FN_cmp(x, A) != 0) {
            ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_NOT_A_SQUARE);
            err = 1;
        }

        if (!err && OSSL_FN_copy_truncate(ret, z) == NULL)
            err = 1;
    }

end:
    if (!OSSL_FN_CTX_end(ctx, token))
        return 0;
    if (err)
        return 0;
    return 1;
}

/*-
 * Calculate the arena payload size that OSSL_FN_mod_sqrt() needs.
 *
 * @param[in]           ret     The OSSL_FN for the result
 * @param[in]           a       The operand
 * @param[in]           p       The prime modulus
 * @returns             The arena payload size, in bytes.
 * @retval              0       on arithmetic overflow or invalid input.
 *
 * The returned size includes any frame budget needed by OSSL_FN_mod_sqrt().
 * Seven temporaries of p->dsize limbs are needed (A, b, q, t, x, y, z), plus
 * the nested calls: OSSL_FN_mod_exp, OSSL_FN_mod_sqr, OSSL_FN_mod_mul,
 * OSSL_FN_mod_lshift1_quick, OSSL_FN_mod, and OSSL_FN_kronecker.  The
 * largest nested requirement dominates; mod_exp is typically the heaviest.
 */
size_t OSSL_FN_mod_sqrt_ctx_size(const OSSL_FN *ret, const OSSL_FN *a,
    const OSSL_FN *p)
{
    size_t L, own_size, nested_size;

    if (ret == NULL || a == NULL || p == NULL)
        return 0;

    L = (size_t)p->dsize;
    if (ossl_fn_totalsize(L) == 0)
        return 0;

    /* Seven temporaries of L limbs each, in our own frame. */
    own_size = OSSL_FN_CTX_size(1, 7, 7 * L);

    /*
     * Nested calls, all with operands/results at L limbs.  Take the max:
     *   - OSSL_FN_mod_exp(ret, A, q, p)  (e==1, e==2, and e>2 paths)
     *   - OSSL_FN_mod_sqr(y, b, p)
     *   - OSSL_FN_mod_mul(t, t, y, p)
     *   - OSSL_FN_mod_lshift1_quick(t, A, p)
     *   - OSSL_FN_mod(y, y, p)           (random reduction)
     *   - OSSL_FN_kronecker(y, q, p)
     *   - OSSL_FN_mod(ret, a, p)         (initial A = a mod p, via OSSL_FN_mod)
     *
     * |p| stands in for the L-wide temporaries (sizing reads only dsize).
     */
    {
        size_t mod_exp_size = OSSL_FN_mod_exp_ctx_size(p, p, p, p);
        size_t mod_sqr_size = OSSL_FN_mod_sqr_ctx_size(p, p, p);
        size_t mod_mul_size = OSSL_FN_mod_mul_ctx_size(p, p, p, p);
        size_t mod_lshift1_size = OSSL_FN_mod_lshift1_ctx_size(p, p, p);
        size_t mod_size = OSSL_FN_mod_ctx_size(p, p, p);
        size_t kronecker_size = OSSL_FN_kronecker_ctx_size(p, p);

        nested_size = ctx_max_size(mod_exp_size,
            ctx_max_size(mod_sqr_size,
                ctx_max_size(mod_mul_size,
                    ctx_max_size(mod_lshift1_size,
                        ctx_max_size(mod_size, kronecker_size)))));
    }

    if (own_size == 0 || nested_size == 0)
        return 0;

    return ctx_add_size(own_size, nested_size);
}
