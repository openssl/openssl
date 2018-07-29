/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include "internal/cryptlib.h"
#include "bn_lcl.h"

/*
 * The quick sieve algorithm approach to weeding out primes is Philip
 * Zimmermann's, as implemented in PGP.  I have had a read of his comments
 * and implemented my own version.
 */
#include "bn_prime.h"

static int witness(BIGNUM *w, const BIGNUM *a, const BIGNUM *a1,
                   const BIGNUM *a1_odd, int k, BN_CTX *ctx,
                   BN_MONT_CTX *mont);
static int probable_prime(BIGNUM *rnd, int bits, prime_t *mods);
static int probable_prime_dh_safe(BIGNUM *rnd, int bits,
                                  const BIGNUM *add, const BIGNUM *rem,
                                  BN_CTX *ctx);

int BN_GENCB_call(BN_GENCB *cb, int a, int b)
{
    /* No callback means continue */
    if (!cb)
        return 1;
    switch (cb->ver) {
    case 1:
        /* Deprecated-style callbacks */
        if (!cb->cb.cb_1)
            return 1;
        cb->cb.cb_1(a, b, cb->arg);
        return 1;
    case 2:
        /* New-style callbacks */
        return cb->cb.cb_2(a, b, cb);
    default:
        break;
    }
    /* Unrecognised callback type */
    return 0;
}

int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe,
                         const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb)
{
    BIGNUM *t;
    int found = 0;
    int i, j, c1 = 0;
    BN_CTX *ctx = NULL;
    prime_t *mods = NULL;
    int checks = BN_prime_checks_for_size(bits);

    if (bits < 2) {
        /* There are no prime numbers this small. */
        BNerr(BN_F_BN_GENERATE_PRIME_EX, BN_R_BITS_TOO_SMALL);
        return 0;
    } else if (bits == 2 && safe) {
        /* The smallest safe prime (7) is three bits. */
        BNerr(BN_F_BN_GENERATE_PRIME_EX, BN_R_BITS_TOO_SMALL);
        return 0;
    }

    mods = OPENSSL_zalloc(sizeof(*mods) * NUMPRIMES);
    if (mods == NULL)
        goto err;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    t = BN_CTX_get(ctx);
    if (t == NULL)
        goto err;
 loop:
    /* make a random number and set the top and bottom bits */
    if (add == NULL) {
        if (!probable_prime(ret, bits, mods))
            goto err;
    } else {
        if (safe) {
            if (!probable_prime_dh_safe(ret, bits, add, rem, ctx))
                goto err;
        } else {
            if (!bn_probable_prime_dh(ret, bits, add, rem, ctx))
                goto err;
        }
    }

    if (!BN_GENCB_call(cb, 0, c1++))
        /* aborted */
        goto err;

    if (!safe) {
        i = BN_is_prime_fasttest_ex(ret, checks, ctx, 0, cb);
        if (i == -1)
            goto err;
        if (i == 0)
            goto loop;
    } else {
        /*
         * for "safe prime" generation, check that (p-1)/2 is prime. Since a
         * prime is odd, We just need to divide by 2
         */
        if (!BN_rshift1(t, ret))
            goto err;

        for (i = 0; i < checks; i++) {
            j = BN_is_prime_fasttest_ex(ret, 1, ctx, 0, cb);
            if (j == -1)
                goto err;
            if (j == 0)
                goto loop;

            j = BN_is_prime_fasttest_ex(t, 1, ctx, 0, cb);
            if (j == -1)
                goto err;
            if (j == 0)
                goto loop;

            if (!BN_GENCB_call(cb, 2, c1 - 1))
                goto err;
            /* We have a safe prime test pass */
        }
    }
    /* we have a prime :-) */
    found = 1;
 err:
    OPENSSL_free(mods);
    if (ctx != NULL)
        BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    bn_check_top(ret);
    return found;
}

int BN_is_prime_ex(const BIGNUM *a, int checks, BN_CTX *ctx_passed,
                   BN_GENCB *cb)
{
    return BN_is_prime_fasttest_ex(a, checks, ctx_passed, 0, cb);
}

int BN_is_prime_fasttest_ex(const BIGNUM *a, int checks, BN_CTX *ctx_passed,
                            int do_trial_division, BN_GENCB *cb)
{
    int i, j, ret = -1;
    int k;
    BN_CTX *ctx = NULL;
    BIGNUM *A1, *A1_odd, *A3, *check; /* taken from ctx */
    BN_MONT_CTX *mont = NULL;

    /* Take care of the really small primes 2 & 3 */
    if (BN_is_word(a, 2) || BN_is_word(a, 3))
        return 1;

    /* Check odd and bigger than 1 */
    if (!BN_is_odd(a) || BN_cmp(a, BN_value_one()) <= 0)
        return 0;

    if (checks == BN_prime_checks)
        checks = BN_prime_checks_for_size(BN_num_bits(a));

    /* first look for small factors */
    if (do_trial_division) {
        for (i = 1; i < NUMPRIMES; i++) {
            BN_ULONG mod = BN_mod_word(a, primes[i]);
            if (mod == (BN_ULONG)-1)
                goto err;
            if (mod == 0)
                return BN_is_word(a, primes[i]);
        }
        if (!BN_GENCB_call(cb, 1, -1))
            goto err;
    }

    if (ctx_passed != NULL)
        ctx = ctx_passed;
    else if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);

    A1 = BN_CTX_get(ctx);
    A3 = BN_CTX_get(ctx);
    A1_odd = BN_CTX_get(ctx);
    check = BN_CTX_get(ctx);
    if (check == NULL)
        goto err;

    /* compute A1 := a - 1 */
    if (!BN_copy(A1, a) || !BN_sub_word(A1, 1))
        goto err;
    /* compute A3 := a - 3 */
    if (!BN_copy(A3, a) || !BN_sub_word(A3, 3))
        goto err;

    /* write  A1  as  A1_odd * 2^k */
    k = 1;
    while (!BN_is_bit_set(A1, k))
        k++;
    if (!BN_rshift(A1_odd, A1, k))
        goto err;

    /* Montgomery setup for computations mod a */
    mont = BN_MONT_CTX_new();
    if (mont == NULL)
        goto err;
    if (!BN_MONT_CTX_set(mont, a, ctx))
        goto err;

    for (i = 0; i < checks; i++) {
        /* 1 < check < a-1 */
        if (!BN_priv_rand_range(check, A3) || !BN_add_word(check, 2))
            goto err;

        j = witness(check, a, A1, A1_odd, k, ctx, mont);
        if (j == -1)
            goto err;
        if (j) {
            ret = 0;
            goto err;
        }
        if (!BN_GENCB_call(cb, 1, i))
            goto err;
    }
    ret = 1;
 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        if (ctx_passed == NULL)
            BN_CTX_free(ctx);
    }
    BN_MONT_CTX_free(mont);

    return ret;
}

static int witness(BIGNUM *w, const BIGNUM *a, const BIGNUM *a1,
                   const BIGNUM *a1_odd, int k, BN_CTX *ctx,
                   BN_MONT_CTX *mont)
{
    if (!BN_mod_exp_mont(w, w, a1_odd, a, ctx, mont)) /* w := w^a1_odd mod a */
        return -1;
    if (BN_is_one(w))
        return 0;               /* probably prime */
    if (BN_cmp(w, a1) == 0)
        return 0;               /* w == -1 (mod a), 'a' is probably prime */
    while (--k) {
        if (!BN_mod_mul(w, w, w, a, ctx)) /* w := w^2 mod a */
            return -1;
        if (BN_is_one(w))
            return 1;           /* 'a' is composite, otherwise a previous 'w'
                                 * would have been == -1 (mod 'a') */
        if (BN_cmp(w, a1) == 0)
            return 0;           /* w == -1 (mod a), 'a' is probably prime */
    }
    /*
     * If we get here, 'w' is the (a-1)/2-th power of the original 'w', and
     * it is neither -1 nor +1 -- so 'a' cannot be prime
     */
    bn_check_top(w);
    return 1;
}

static int probable_prime(BIGNUM *rnd, int bits, prime_t *mods)
{
    int i;
    BN_ULONG delta;
    BN_ULONG maxdelta = BN_MASK2 - primes[NUMPRIMES - 1];
    char is_single_word = bits <= BN_BITS2;

 again:
    /* TODO: Not all primes are private */
    if (!BN_priv_rand(rnd, bits, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD))
        return 0;
    /* we now have a random number 'rnd' to test. */
    for (i = 1; i < NUMPRIMES; i++) {
        BN_ULONG mod = BN_mod_word(rnd, (BN_ULONG)primes[i]);
        if (mod == (BN_ULONG)-1)
            return 0;
        mods[i] = (prime_t) mod;
    }
    /*
     * If bits is so small that it fits into a single word then we
     * additionally don't want to exceed that many bits.
     */
    if (is_single_word) {
        BN_ULONG size_limit;

        if (bits == BN_BITS2) {
            /*
             * Shifting by this much has undefined behaviour so we do it a
             * different way
             */
            size_limit = ~((BN_ULONG)0) - BN_get_word(rnd);
        } else {
            size_limit = (((BN_ULONG)1) << bits) - BN_get_word(rnd) - 1;
        }
        if (size_limit < maxdelta)
            maxdelta = size_limit;
    }
    delta = 0;
 loop:
    if (is_single_word) {
        BN_ULONG rnd_word = BN_get_word(rnd);

        /*-
         * In the case that the candidate prime is a single word then
         * we check that:
         *   1) It's greater than primes[i] because we shouldn't reject
         *      3 as being a prime number because it's a multiple of
         *      three.
         *   2) That it's not a multiple of a known prime. We don't
         *      check that rnd-1 is also coprime to all the known
         *      primes because there aren't many small primes where
         *      that's true.
         */
        for (i = 1; i < NUMPRIMES && primes[i] < rnd_word; i++) {
            if ((mods[i] + delta) % primes[i] == 0) {
                delta += 2;
                if (delta > maxdelta)
                    goto again;
                goto loop;
            }
        }
    } else {
        for (i = 1; i < NUMPRIMES; i++) {
            /*
             * check that rnd is not a prime and also that gcd(rnd-1,primes)
             * == 1 (except for 2)
             */
            if (((mods[i] + delta) % primes[i]) <= 1) {
                delta += 2;
                if (delta > maxdelta)
                    goto again;
                goto loop;
            }
        }
    }
    if (!BN_add_word(rnd, delta))
        return 0;
    if (BN_num_bits(rnd) != bits)
        goto again;
    bn_check_top(rnd);
    return 1;
}

int bn_probable_prime_dh(BIGNUM *rnd, int bits,
                         const BIGNUM *add, const BIGNUM *rem, BN_CTX *ctx)
{
    int i, ret = 0;
    BIGNUM *t1;

    BN_CTX_start(ctx);
    if ((t1 = BN_CTX_get(ctx)) == NULL)
        goto err;

    if (!BN_rand(rnd, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD))
        goto err;

    /* we need ((rnd-rem) % add) == 0 */

    if (!BN_mod(t1, rnd, add, ctx))
        goto err;
    if (!BN_sub(rnd, rnd, t1))
        goto err;
    if (rem == NULL) {
        if (!BN_add_word(rnd, 1))
            goto err;
    } else {
        if (!BN_add(rnd, rnd, rem))
            goto err;
    }

    /* we now have a random number 'rand' to test. */

 loop:
    for (i = 1; i < NUMPRIMES; i++) {
        /* check that rnd is a prime */
        BN_ULONG mod = BN_mod_word(rnd, (BN_ULONG)primes[i]);
        if (mod == (BN_ULONG)-1)
            goto err;
        if (mod <= 1) {
            if (!BN_add(rnd, rnd, add))
                goto err;
            goto loop;
        }
    }
    ret = 1;

 err:
    BN_CTX_end(ctx);
    bn_check_top(rnd);
    return ret;
}

static int probable_prime_dh_safe(BIGNUM *p, int bits, const BIGNUM *padd,
                                  const BIGNUM *rem, BN_CTX *ctx)
{
    int i, ret = 0;
    BIGNUM *t1, *qadd, *q;

    bits--;
    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    qadd = BN_CTX_get(ctx);
    if (qadd == NULL)
        goto err;

    if (!BN_rshift1(qadd, padd))
        goto err;

    if (!BN_rand(q, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD))
        goto err;

    /* we need ((rnd-rem) % add) == 0 */
    if (!BN_mod(t1, q, qadd, ctx))
        goto err;
    if (!BN_sub(q, q, t1))
        goto err;
    if (rem == NULL) {
        if (!BN_add_word(q, 1))
            goto err;
    } else {
        if (!BN_rshift1(t1, rem))
            goto err;
        if (!BN_add(q, q, t1))
            goto err;
    }

    /* we now have a random number 'rand' to test. */
    if (!BN_lshift1(p, q))
        goto err;
    if (!BN_add_word(p, 1))
        goto err;

 loop:
    for (i = 1; i < NUMPRIMES; i++) {
        /* check that p and q are prime */
        /*
         * check that for p and q gcd(p-1,primes) == 1 (except for 2)
         */
        BN_ULONG pmod = BN_mod_word(p, (BN_ULONG)primes[i]);
        BN_ULONG qmod = BN_mod_word(q, (BN_ULONG)primes[i]);
        if (pmod == (BN_ULONG)-1 || qmod == (BN_ULONG)-1)
            goto err;
        if (pmod == 0 || qmod == 0) {
            if (!BN_add(p, p, padd))
                goto err;
            if (!BN_add(q, q, qadd))
                goto err;
            goto loop;
        }
    }
    ret = 1;

 err:
    BN_CTX_end(ctx);
    bn_check_top(p);
    return ret;
}

/*
 * This impelements the "ordinary" algorithm (based on Euclid’s GCD algorithm)
 *
 * This is very similar to the algorithm in FIPS 186-4, appendix C.5,
 * except that this version doesn't work recursivly, and supports negative
 * vaues in |a|.
 * doi: https://dx.doi.org/10.6028/NIST.FIPS.186-4
 *
 */
int BN_jacobi_symbol(const BIGNUM *a, const BIGNUM *b, BN_CTX *in_ctx)
{
    BIGNUM *A, *B;
    BIGNUM *temp;
    BN_CTX *ctx;
    int ret = 1;

    if (BN_is_zero(b) || BN_is_negative(b) || !BN_is_odd(b))
        return -2;

    if (in_ctx == NULL) {
        ctx = BN_CTX_new();
        if (ctx == NULL)
            return -2;
    } else {
        ctx = in_ctx;
    }

    BN_CTX_start(ctx);

    A = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    if (B == NULL) {
        ret = -2;
        goto done;
    }

    if ((BN_copy(A, a) == NULL) || (BN_copy(B, b) == NULL)) {
        ret = -2;
        goto done;
    }

    if (BN_is_negative(A)) {
        BN_set_negative(A, 0);
        if ((B->d[0] & 3) == 3)
            ret = 0-ret;
    }

    while (!BN_is_zero(A)) {
        while (!BN_is_odd(A)) {
            if (!BN_rshift1(A, A)) {
                ret = -2;
                goto done;
            }
            if ((B->d[0] & 7) == 3 || (B->d[0] & 7) == 5)
                ret = 0-ret;
        }
        temp = A;
        A = B;
        B = temp;
        /* A and B are both positive odd numbers. Check that both mod 4 == 3 */
        if ((A->d[0] & B->d[0] & 2) != 0)
            ret = 0-ret;
        if (!BN_mod(A, A, B, ctx)) {
            ret = -2;
            goto done;
        }
    }
    if (!BN_is_one(B))
        ret = 0;

done:
    BN_CTX_end(ctx);
    if (in_ctx == NULL)
        BN_CTX_free(ctx);
    return ret;
}

/*
 * returns 1 when it's a perfect square, 0 when it's not, -1 on error.
 *
 * It uses the algorithm of FIPS 186-4, appendinx C.4
 * doi: https://dx.doi.org/10.6028/NIST.FIPS.186-4
 */
int BN_is_perfect_square(const BIGNUM *C, BN_CTX *in_ctx)
{
    BIGNUM *x0, *x1, *x0_2, *stop;
    int ret = -1;
    int n, m;
    BN_CTX *ctx;

    if (BN_is_zero(C) || BN_is_negative(C))
        return -1;

    if (in_ctx == NULL) {
        ctx = BN_CTX_new();
        if (ctx == NULL)
            return -1;
    } else {
        ctx = in_ctx;
    }

    BN_CTX_start(ctx);
    x0 = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    stop = BN_CTX_get(ctx);
    x0_2 = BN_CTX_get(ctx);
    if (x0_2 == NULL)
        goto err;

    n = BN_num_bits(C);
    m = (n+1)/2;
    if (BN_copy(x0, C) == NULL ||
        !BN_rshift(x0, x0, n-m))
        goto err;

    if (!BN_set_word(stop, 1)
        || !BN_lshift(stop, stop, m)
        || !BN_add(stop, stop, C))
        goto err;

    if (!BN_sqr(x0_2, x0, ctx))
        goto err;

    do {
        if (!BN_add(x1, x0_2, C)
            || !BN_div(x1, NULL, x1, x0, ctx)
            || !BN_rshift1(x1, x1)
            || BN_copy(x0, x1) == NULL
            || !BN_sqr(x0_2, x1, ctx))
            goto err;
    }
    while (BN_cmp(x0_2, stop) >= 0);

    ret = BN_cmp(x0_2, C) == 0;

err:
    BN_CTX_end(ctx);
    if (in_ctx == NULL)
        BN_CTX_free(ctx);
    return ret;
}

/*
 * This calculates a lucas sequence mod |n|, and with P == 1. P and |Q| are the
 * variables of the lucas squence. |D| = |P|^2-4*|Q|. |i| is the index of the current
 * values in |U| and |V|, |inext| the index of the |U| and |V| that are
 * wanted.
 *
 * return 1 on success, 0 on failure.
 *
 * On the first call |U|, |V| and |i| are 1, and |inext| can be any number >=
 * |i|. On other calls |inext| is the double of |i|.
 *
 * The algorithm works by binary writing |i|, doubling |i|, then finding what
 * the value of the next bit should be.
 *
 * This is step 4 and 6 from FIPS 186-5, appendix C.3.3
 * doi: https://dx.doi.org/10.6028/NIST.FIPS.186-4
 */
static int bn_lucas_sequence(const BIGNUM *Q, const BIGNUM *D, const BIGNUM *n,
                             BIGNUM *U, BIGNUM *V, BIGNUM *i,
                             const BIGNUM *inext, BN_CTX *ctx)
{
    BIGNUM *t, *n1;
    int ret = 0;

    if (BN_cmp(i, inext) == 0)
        return 1;

    BN_CTX_start(ctx);

    n1 = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx);
    if (t == NULL)
        goto err;

    if (!BN_set_word(n1, 1))
        goto err;

    while (BN_cmp(i, inext) != 0) {
        if (!BN_mod_mul(U, U, V, n, ctx) ||
            !BN_mod_exp(t, Q, i, n, ctx) ||
            !BN_lshift1(t, t) ||
            !BN_mod_sqr(V, V, n, ctx) ||
            !BN_mod_sub(V, V, t, n, ctx) ||
            !BN_lshift1(i, i))
            goto err;

        BN_copy(t, inext);
        BN_rshift(t, t, BN_num_bits(inext) - BN_num_bits(i));

        if (BN_is_odd(t)) {
            if (BN_copy(t, U) == NULL)
                goto err;

            if (!BN_add(U, U, V))
                goto err;
            if (BN_is_odd(U))
                if (!BN_add(U, U, n))
                    goto err;
            if (!BN_rshift1(U, U) ||
                !BN_mod(U, U, n, ctx))
                goto err;

            if (!BN_mul(t, D, t, ctx) ||
                !BN_add(V, V, t))
                goto err;
            if (BN_is_odd(V))
                if (!BN_add(V, V, n))
                    goto err;
            if (!BN_rshift1(V, V) ||
                !BN_mod(V, V, n, ctx))
                goto err;

            if (!BN_add(i, i, n1))
                goto err;
        }
    }
    ret = 1;

err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * Based on Robert Baillie and Samuel S Wagstaff. "Lucas pseudoprimes"
 * Mathematics of Computation, Volume 35, number 152, october 1980,
 * pages 1391–1417
 * DOI: https://doi.org/10.1090/S0025-5718-1980-0583518-6
 *
 * Using Method A (Selfridge parameters)
 *
 * FIPS 186-4 documents a non-strong version in appendinx C.3.3.
 * doi: https://dx.doi.org/10.6028/NIST.FIPS.186-4
 * This version just has the "strong" checks in it, reducing the number
 * of pseudoprimes. All pseudoprimes generated by the strong version
 * are also pseudoprimes of the non-strong version.
 *
 * Returns 1 when probably prime, 0 when it's composite, and -1 on error.
 */
int BN_strong_lucas_prime(const BIGNUM *p, BN_CTX *in_ctx)
{
    BIGNUM *Q, *D;
    BIGNUM *U, *V;
    BIGNUM *p1;
    BIGNUM *d;
    BIGNUM *i;
    BIGNUM *n1, *n2;
    int neg = 0;
    int ret = -1;
    int strong = 0;
    BN_CTX *ctx;

    if (in_ctx == NULL) {
        ctx = BN_CTX_new();
        if (ctx == NULL)
            return -1;
    } else {
        ctx = in_ctx;
    }

    BN_CTX_start(ctx);

    Q = BN_CTX_get(ctx);
    D = BN_CTX_get(ctx);
    U = BN_CTX_get(ctx);
    V = BN_CTX_get(ctx);
    p1 = BN_CTX_get(ctx);
    i = BN_CTX_get(ctx);
    d = BN_CTX_get(ctx);
    n1 = BN_CTX_get(ctx);
    n2 = BN_CTX_get(ctx);
    if (n2 == NULL)
        goto done;

    if (!BN_set_word(D, 5) || !BN_one(n1) || !BN_set_word(n2, 2))
        goto done;

    if (BN_cmp(p, n2) == 0) {
        /*
         * 2 is a lucas prime, but Jacobi does not work for odd numbers so
         * would return an error.
         */
        ret = 1;
        goto done;
    }

    if (BN_cmp(p, n2) > 0 && !BN_is_odd(p)) {
        ret = 0;
        goto done;
    }

    while (1) {
        int jacobi = BN_jacobi_symbol(D, p, ctx);
        if (jacobi == -2)
            goto done;
        if (jacobi == -1)
            break;
        BN_set_negative(D, 0);
        /*
         * 5 and 11 end up with testing themself, and Jacobi then returns 0.
         * Just continue searching for D instead of saying, it should still find
         * either a -1 or 0.
         */
        if (jacobi == 0 && BN_cmp(D, p) != 0) {
            ret = 0;
            goto done;
        }

        /* On average after 1.78 tries we should have found D, but we won't find
         * it in case p is a perfect square. So check that it's a perfect square
         * after the 7th D we tried. */
        if (BN_is_word(D, 17)) {
            int ps = BN_is_perfect_square(p, ctx);
            if (ps == -1)
                goto done;
            if (ps == 1) {
                ret = 0;
                goto done;
            }
        }

        /* D should have the Selfright sequence 5, -7, 9, -11, 13, -15, ... */
        if (!BN_add(D, D, n2))
            goto done;
        neg = !neg;
        BN_set_negative(D, neg);
    }

    /* Q = (1-D)/4, so -1, 2, -2, 3, -3, ... */
    if (BN_copy(Q, D) == NULL)
        goto done;
    if (!BN_sub(Q, n1, D))
        goto done;
    if (!BN_rshift(Q, Q, 2))
        goto done;

    if (!BN_add(p1, p, n1))
            goto done;

    if (BN_copy(d, p1) == NULL)
        goto done;
    while(!BN_is_odd(d))
        if (!BN_rshift1(d, d))
            goto done;

    if (!BN_one(U) || !BN_one(V) || !BN_one(i))
        goto done;

    if (!bn_lucas_sequence(Q, D, p, U, V, i, d, ctx) ||
        !BN_mod(U, U, p, ctx))
        goto done;
    if (BN_is_zero(U))
        strong = 1;
    if (!BN_mod(V, V, p, ctx))
        goto done;
    if (BN_is_zero(V))
        strong = 1;

    while (BN_ucmp(i, p1) != 0) {
        if (!BN_lshift1(d, i) ||
            !bn_lucas_sequence(Q, D, p, U, V, i, d, ctx) ||
            !BN_mod(V, V, p, ctx))
            goto done;
        if (BN_is_zero(V))
            strong = 1;
    }

    if (!strong) {
        ret = 0;
        goto done;
    }

    if (!BN_is_zero(U)) {
        ret = 0;
        goto done;
    }

#if 0
    /*
     * This is one of the very cheap tests that eliminates other non-primes,
     * but then they are not strong lucas primes anymore.
     */
    if (!BN_lshift1(t, Q))
        goto done;
    if (BN_is_negative(t) && !BN_mod_add(t, t, p, p, ctx))
        goto done;
    if (BN_cmp(V, t) != 0) {
        ret = 0;
        goto done;
    }
#endif

    ret = 1;

done:
    BN_CTX_end(ctx);
    if (in_ctx == NULL)
        BN_CTX_free(ctx);
    return ret;
}
