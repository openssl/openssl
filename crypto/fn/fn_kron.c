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

/* least significant word; 0 if the operand has no limbs (i.e. is zero) */
#define lsw(n) \
    (((n)->dsize == 0) ? (OSSL_FN_ULONG)0 : (n)->d[0])

static size_t ctx_add_size(size_t a, size_t b)
{
    int err = 0;
    size_t r = safe_add_size_t(a, b, &err);

    return err == 0 ? r : 0;
}

/*-
 * OSSL_FN_kronecker() computes the Kronecker symbol (a/b), returning -1, 0,
 * or 1, using Cohen's algorithm 1.4.10 ("A Course in Algebraic Computational
 * Number Theory").
 *
 * OSSL_FN is unsigned, so sign handling belongs at the BIGNUM boundary.  The
 * mod-sqrt call site passes |p| (non-negative) and a non-negative candidate,
 * so the unsigned Jacobi symbol is exactly what is needed.
 *
 * lsw(n) tests dsize == 0 for a zero-limb number, i.e. zero.  Otherwise,
 * OSSL_FN has no significance top: dsize is the allocated width, not a
 * significance count.
 *
 * This function is not constant-time: it branches on values throughout (the
 * trailing-zero scans, the parity checks, and the lsw tabulation).  It is
 * used by mod-sqrt's non-residue search, which is itself non-CT.
 *
 * Returns -2 for errors (because -1, 0, and 1 are all valid results).
 */
int OSSL_FN_kronecker(const OSSL_FN *a, const OSSL_FN *b, OSSL_FN_CTX *ctx)
{
    int i;
    int ret = -2; /* avoid 'uninitialized' warning */
    int err = 0;
    OSSL_FN *A, *B, *tmp;
    size_t al, bl, L;
    const void *token;
    /*
     * In 'tab', only odd-indexed entries are relevant:
     * For any odd number n,
     *     tab[n & 7]
     * is $(-1)^{(n^2-1)/8}$ (using TeX notation).
     * (The sign of n does not matter, but OSSL_FN is unsigned anyway.)
     */
    static const int tab[8] = { 0, 1, 0, -1, 0, -1, 0, 1 };

    token = OSSL_FN_CTX_start(ctx);
    if (token == NULL)
        return -2;

    al = (size_t)a->dsize;
    bl = (size_t)b->dsize;
    L = al > bl ? al : bl;

    A = OSSL_FN_CTX_get_limbs(ctx, L);
    B = OSSL_FN_CTX_get_limbs(ctx, L);
    if (B == NULL)
        goto end;

    err = (OSSL_FN_copy(A, a) == NULL);
    if (err)
        goto end;
    err = (OSSL_FN_copy(B, b) == NULL);
    if (err)
        goto end;

    /*
     * Kronecker symbol, implemented according to Henri Cohen,
     * "A Course in Computational Algebraic Number Theory"
     * (algorithm 1.4.10).
     */

    /* Cohen's step 1: */

    if (OSSL_FN_is_zero(B)) {
        ret = OSSL_FN_is_word(A, 1);
        goto end;
    }

    /* Cohen's step 2: */

    if (!OSSL_FN_is_odd(A) && !OSSL_FN_is_odd(B)) {
        ret = 0;
        goto end;
    }

    /* now  B  is non-zero */
    i = 0;
    while (!OSSL_FN_is_bit_set(B, i))
        i++;
    err = !OSSL_FN_rshift(B, B, i);
    if (err)
        goto end;
    if (i & 1) {
        /* i is odd */
        /* (thus  B  was even, thus  A  must be odd!)  */

        /* set 'ret' to $(-1)^{(A^2-1)/8}$ */
        ret = tab[lsw(A) & 7];
    } else {
        /* i is even */
        ret = 1;
    }

    /*
     * now B is positive and odd, so what remains to be done is to compute
     * the Jacobi symbol (A/B) and multiply it by 'ret'
     */

    while (1) {
        /* Cohen's step 3: */

        /*  B  is positive and odd */

        if (OSSL_FN_is_zero(A)) {
            ret = OSSL_FN_is_one(B) ? ret : 0;
            goto end;
        }

        /* now  A  is non-zero */
        i = 0;
        while (!OSSL_FN_is_bit_set(A, i))
            i++;
        err = !OSSL_FN_rshift(A, A, i);
        if (err)
            goto end;
        if (i & 1) {
            /* i is odd */
            /* multiply 'ret' by  $(-1)^{(B^2-1)/8}$ */
            ret = ret * tab[lsw(B) & 7];
        }

        /* Cohen's step 4: */
        /* multiply 'ret' by  $(-1)^{(A-1)(B-1)/4}$ */
        if (lsw(A) & lsw(B) & 2)
            ret = -ret;

        /* (A, B) := (B mod |A|, |A|) */
        err = !OSSL_FN_mod(B, B, A, ctx);
        if (err)
            goto end;
        tmp = A;
        A = B;
        B = tmp;
    }
end:
    if (!OSSL_FN_CTX_end(ctx, token))
        return -2;
    if (err)
        return -2;
    else
        return ret;
}

/*-
 * Calculate the arena payload size that OSSL_FN_kronecker() needs.
 *
 * @param[in]           a       The first operand
 * @param[in]           b       The second operand
 * @returns             The arena payload size, in bytes.
 * @retval              0       on arithmetic overflow or invalid input.
 *
 * The returned size includes any frame budget needed by OSSL_FN_kronecker().
 * Two temporaries of max(a, b) limbs are needed (the working copies A and B
 * that the algorithm swaps), plus the nested OSSL_FN_mod() (= OSSL_FN_div())
 * call in the loop body.
 */
size_t OSSL_FN_kronecker_ctx_size(const OSSL_FN *a, const OSSL_FN *b)
{
    size_t al, bl, L, own_size, nested_size;

    if (a == NULL || b == NULL)
        return 0;

    al = (size_t)a->dsize;
    bl = (size_t)b->dsize;
    L = al > bl ? al : bl;
    if (ossl_fn_totalsize(L) == 0)
        return 0;

    /* Two temporaries of L limbs each, in our own frame. */
    own_size = OSSL_FN_CTX_size(1, 2, 2 * L);

    /*
     * Nested: the loop-body reduction OSSL_FN_mod(B, B, A) with all three at
     * L limbs.  Model the temporaries the nested call sees with a local
     * header at L limbs.
     */
    {
        OSSL_FN t_L = { .dsize = (int)L };

        nested_size = OSSL_FN_mod_ctx_size(&t_L, &t_L, &t_L);
    }

    if (own_size == 0 || nested_size == 0)
        return 0;

    return ctx_add_size(own_size, nested_size);
}
