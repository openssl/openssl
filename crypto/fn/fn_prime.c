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
#include "crypto/bn.h" /* For BN_GENCB / BN_GENCB_call and the prime-test status codes */
#include "../bn/bn_prime.h" /* For the sieve primes[] table and prime_t */
#include "fn_local.h"

#define square(x) ((OSSL_FN_ULONG)(x) * (OSSL_FN_ULONG)(x))

/*
 * Calculate the number of trial divisions that gives the best speed in
 * combination with the Miller-Rabin prime test, based on the size of the
 * candidate prime.  The size is the candidate's public width in bits.
 */
static int ossl_fn_calc_trial_divisions(size_t bits)
{
    if (bits <= 512)
        return 64;
    else if (bits <= 1024)
        return 128;
    else if (bits <= 2048)
        return 384;
    else if (bits <= 4096)
        return 1024;
    return NUMPRIMES;
}

/*
 * Use a minimum of 64 rounds of Miller-Rabin, which should give a false
 * positive rate of 2^-128.  If the size of the prime is larger than 2048
 * the caller probably wants a higher security level than 128, so switch
 * to 128 rounds giving a false positive rate of 2^-256.
 * Returns the number of rounds.  The size is the candidate's public width
 * in bits.
 */
static int ossl_fn_mr_min_checks(size_t bits)
{
    if (bits > 2048)
        return 128;
    return 64;
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
 * Estimate the arena payload for ossl_fn_miller_rabin_is_prime() on a
 * candidate of width |w|->dsize.  The operation holds seven |w|-limb
 * numbers for the whole round set; the gcd, modular exponentiation and
 * modular multiplication it calls run sequentially within that frame, so
 * their nested needs combine by maximum.  The enhanced variant's gcd calls
 * are accounted for whether the caller uses them or not.
 */
size_t ossl_fn_miller_rabin_is_prime_ctx_size(const OSSL_FN *w)
{
    OSSL_FN n;
    size_t scratch, exp, mul, gcd, inner;

    if (w == NULL || w->dsize == 0)
        return 0;

    n.dsize = w->dsize;

    /* Seven |w|-limb numbers held for the whole round set. */
    scratch = OSSL_FN_CTX_size(1, 7, 7 * (size_t)w->dsize);

    exp = OSSL_FN_mod_exp_mont_ctx_size(&n, &n, &n, &n, NULL);
    mul = OSSL_FN_mod_mul_ctx_size(&n, &n, &n, &n);
    gcd = OSSL_FN_gcd_ctx_size(&n, &n);
    inner = ctx_max_size(exp, ctx_max_size(mul, gcd));

    return ctx_add_size(scratch, inner);
}

/*
 * Refer to FIPS 186-4 C.3.2 Enhanced Miller-Rabin Probabilistic Primality
 * Test, or C.3.1 Miller-Rabin Probabilistic Primality Test (if |enhanced| is
 * zero).  The Step numbers listed in the code refer to the enhanced case.
 *
 * The number of rounds and the random-base draws branch on |w|'s public
 * width and on the public iteration count, not on limb values; the modular
 * arithmetic (gcd, modexp, modmul) is constant-time with respect to the
 * operand values.  What leaks, as OSSL_FN's own properties: the magnitude of
 * |w| (via its width), the iteration count, and the composite/prime verdict
 * that is the whole point of the test.
 *
 * If |enhanced| is set, then |status| returns one of the following:
 *     BN_PRIMETEST_PROBABLY_PRIME
 *     BN_PRIMETEST_COMPOSITE_WITH_FACTOR
 *     BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME
 * if |enhanced| is zero, then |status| returns either
 *     BN_PRIMETEST_PROBABLY_PRIME or BN_PRIMETEST_COMPOSITE
 *
 * Returns 1 on success (|status| is set), 0 on error.
 */
int ossl_fn_miller_rabin_is_prime(const OSSL_FN *w, int iterations,
    OSSL_FN_CTX *ctx, BN_GENCB *cb, int enhanced, int *status,
    OSSL_LIB_CTX *libctx)
{
    int i, j, a, ret = 0;
    OSSL_FN *g, *w1, *w3, *x, *m, *z, *b;
    OSSL_FN_MONT_CTX *mont = NULL;
    const void *token = NULL;
    size_t wbits = (size_t)w->dsize * OSSL_FN_BITS;

    /* w must be odd */
    if (!OSSL_FN_is_odd(w))
        return 0;

    if ((token = OSSL_FN_CTX_start(ctx)) == NULL)
        goto err;
    g = OSSL_FN_CTX_get_limbs(ctx, w->dsize);
    w1 = OSSL_FN_CTX_get_limbs(ctx, w->dsize);
    w3 = OSSL_FN_CTX_get_limbs(ctx, w->dsize);
    x = OSSL_FN_CTX_get_limbs(ctx, w->dsize);
    m = OSSL_FN_CTX_get_limbs(ctx, w->dsize);
    z = OSSL_FN_CTX_get_limbs(ctx, w->dsize);
    b = OSSL_FN_CTX_get_limbs(ctx, w->dsize);

    if (!(b != NULL
            /* w1 := w - 1 */
            && OSSL_FN_copy(w1, w) != NULL
            && OSSL_FN_sub_word(w1, 1)
            /* w3 := w - 3 */
            && OSSL_FN_copy(w3, w) != NULL
            && OSSL_FN_sub_word(w3, 3)))
        goto err;

    /* check w is larger than 3, otherwise the random b will be too small */
    if (OSSL_FN_is_zero(w3))
        goto err;

    /* (Step 1) Calculate largest integer 'a' such that 2^a divides w-1 */
    a = 1;
    while (!OSSL_FN_is_bit_set(w1, a))
        a++;
    /* (Step 2) m = (w-1) / 2^a */
    if (!OSSL_FN_rshift(m, w1, a))
        goto err;

    /* Montgomery setup for computations mod w */
    mont = OSSL_FN_MONT_CTX_new(w);
    if (mont == NULL)
        goto err;

    if (iterations == 0)
        iterations = ossl_fn_mr_min_checks(wbits);

    /* (Step 4) */
    for (i = 0; i < iterations; ++i) {
        /* (Step 4.1) obtain a random b where 1 < b < w-1 */
        if (!OSSL_FN_priv_rand_range(b, w3, 0, libctx)
            || !OSSL_FN_add_word(b, 2)) /* 1 < b < w-1 */
            goto err;

        if (enhanced) {
            /* (Step 4.3) */
            if (!OSSL_FN_gcd(g, b, w, ctx))
                goto err;
            /* (Step 4.4) */
            if (!OSSL_FN_is_one(g)) {
                *status = BN_PRIMETEST_COMPOSITE_WITH_FACTOR;
                ret = 1;
                goto err;
            }
        }
        /* (Step 4.5) z = b^m mod w */
        if (!OSSL_FN_mod_exp_mont(z, b, m, w, ctx, mont))
            goto err;
        /* (Step 4.6) if (z = 1 or z = w-1) */
        if (OSSL_FN_is_one(z) || OSSL_FN_cmp(z, w1) == 0)
            goto outer_loop;
        /* (Step 4.7) for j = 1 to a-1 */
        for (j = 1; j < a; ++j) {
            /* (Step 4.7.1 - 4.7.2) x = z. z = x^2 mod w */
            if (OSSL_FN_copy(x, z) == NULL
                || !OSSL_FN_mod_mul(z, x, x, w, ctx))
                goto err;
            /* (Step 4.7.3) */
            if (OSSL_FN_cmp(z, w1) == 0)
                goto outer_loop;
            /* (Step 4.7.4) */
            if (OSSL_FN_is_one(z))
                goto composite;
        }
        /* At this point z = b^((w-1)/2) mod w */
        /* (Steps 4.8 - 4.9) x = z, z = x^2 mod w */
        if (OSSL_FN_copy(x, z) == NULL || !OSSL_FN_mod_mul(z, x, x, w, ctx))
            goto err;
        /* (Step 4.10) */
        if (OSSL_FN_is_one(z))
            goto composite;
        /* (Step 4.11) x = b^(w-1) mod w */
        if (OSSL_FN_copy(x, z) == NULL)
            goto err;
    composite:
        if (enhanced) {
            /* (Step 4.1.2) g = GCD(x-1, w) */
            if (!OSSL_FN_sub_word(x, 1) || !OSSL_FN_gcd(g, x, w, ctx))
                goto err;
            /* (Steps 4.1.3 - 4.1.4) */
            if (OSSL_FN_is_one(g))
                *status = BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME;
            else
                *status = BN_PRIMETEST_COMPOSITE_WITH_FACTOR;
        } else {
            *status = BN_PRIMETEST_COMPOSITE;
        }
        ret = 1;
        goto err;
    outer_loop:;
        /* (Step 4.1.5) */
        if (!BN_GENCB_call(cb, 1, i))
            goto err;
    }
    /* (Step 5) */
    *status = BN_PRIMETEST_PROBABLY_PRIME;
    ret = 1;
err:
    if (b != NULL) {
        OSSL_FN_clear(g);
        OSSL_FN_clear(w1);
        OSSL_FN_clear(w3);
        OSSL_FN_clear(x);
        OSSL_FN_clear(m);
        OSSL_FN_clear(z);
        OSSL_FN_clear(b);
    }
    if (token != NULL)
        OSSL_FN_CTX_end(ctx, token);
    OSSL_FN_MONT_CTX_free(mont);
    return ret;
}

/*
 * Tests that |w| is probably prime.
 * See FIPS 186-4 C.3.1 Miller Rabin Probabilistic Primality Test.
 *
 * Returns 0 when composite, 1 when probable prime, -1 on error.
 */
static int ossl_fn_is_prime_int(const OSSL_FN *w, int checks, OSSL_FN_CTX *ctx,
    int do_trial_division, BN_GENCB *cb, OSSL_LIB_CTX *libctx)
{
    int i, status, ret = -1;
    size_t wbits = (size_t)w->dsize * OSSL_FN_BITS;

    /* w must be bigger than 1 */
    if (OSSL_FN_is_zero(w) || OSSL_FN_is_one(w))
        return 0;

    /* w must be odd */
    if (OSSL_FN_is_odd(w)) {
        /* Take care of the really small prime 3 */
        if (OSSL_FN_is_word(w, 3))
            return 1;
    } else {
        /* 2 is the only even prime */
        return OSSL_FN_is_word(w, 2);
    }

    /* first look for small factors */
    if (do_trial_division) {
        int trial_divisions = ossl_fn_calc_trial_divisions(wbits);

        for (i = 1; i < trial_divisions; i++) {
            OSSL_FN_ULONG mod = OSSL_FN_mod_word(w, primes[i]);

            if (mod == (OSSL_FN_ULONG)-1)
                return -1;
            if (mod == 0)
                return OSSL_FN_is_word(w, primes[i]);
        }
        if (!BN_GENCB_call(cb, 1, -1))
            return -1;
    }

    if (!ossl_fn_miller_rabin_is_prime(w, checks, ctx, cb, 0, &status,
            libctx)) {
        ret = -1;
        goto err;
    }
    ret = (status == BN_PRIMETEST_PROBABLY_PRIME);
err:
    return ret;
}

/* Wrapper around ossl_fn_is_prime_int that sets the minimum number of checks */
int ossl_fn_check_prime(const OSSL_FN *w, int checks, OSSL_FN_CTX *ctx,
    int do_trial_division, BN_GENCB *cb, OSSL_LIB_CTX *libctx)
{
    int min_checks = ossl_fn_mr_min_checks((size_t)w->dsize * OSSL_FN_BITS);

    if (checks < min_checks)
        checks = min_checks;

    return ossl_fn_is_prime_int(w, checks, ctx, do_trial_division, cb, libctx);
}

/*
 * Use this only for key generation.
 * It always uses trial division.  The number of checks (MR rounds) passed in
 * is used without being clamped to a minimum value.
 */
int ossl_fn_check_generated_prime(const OSSL_FN *w, int checks,
    OSSL_FN_CTX *ctx, BN_GENCB *cb, OSSL_LIB_CTX *libctx)
{
    return ossl_fn_is_prime_int(w, checks, ctx, 1, cb, libctx);
}

/*
 * Both primality test variants need what the Miller-Rabin test needs;
 * trial division uses no context space.
 */
size_t ossl_fn_check_prime_ctx_size(const OSSL_FN *w)
{
    return ossl_fn_miller_rabin_is_prime_ctx_size(w);
}

size_t ossl_fn_check_generated_prime_ctx_size(const OSSL_FN *w)
{
    return ossl_fn_miller_rabin_is_prime_ctx_size(w);
}

/*
 * Generate a random number of |bits| bits that is probably prime by sieving.
 * If |safe| != 0, it generates a safe prime.
 * |mods| is a preallocated array that gets reused when called again.
 *
 * |rnd| must have room for |bits| bits plus one limb of headroom: the sieve
 * adds a word-sized delta, and a carry past |bits| is detected by the
 * significance check below rather than silently truncated.
 *
 * The probably prime is saved in |rnd|.
 *
 * Returns 1 on success and 0 on error.
 */
static int ossl_fn_probable_prime(OSSL_FN *rnd, size_t bits, int safe,
    prime_t *mods, OSSL_LIB_CTX *libctx)
{
    int i;
    OSSL_FN_ULONG delta;
    int trial_divisions = ossl_fn_calc_trial_divisions(bits);
    OSSL_FN_ULONG maxdelta = OSSL_FN_MASK - primes[trial_divisions - 1];

again:
    if (!OSSL_FN_priv_rand(rnd, bits, OSSL_FN_RAND_TOP_TWO,
            OSSL_FN_RAND_BOTTOM_ODD, 0, libctx))
        return 0;
    if (safe && !OSSL_FN_set_bit(rnd, 1))
        return 0;
    /* we now have a random number 'rnd' to test. */
    for (i = 1; i < trial_divisions; i++) {
        OSSL_FN_ULONG mod = OSSL_FN_mod_word(rnd, (OSSL_FN_ULONG)primes[i]);

        if (mod == (OSSL_FN_ULONG)-1)
            return 0;
        mods[i] = (prime_t)mod;
    }
    delta = 0;
loop:
    for (i = 1; i < trial_divisions; i++) {
        /*
         * check that rnd is a prime and also that
         * gcd(rnd-1,primes) == 1 (except for 2)
         * do the second check only if we are interested in safe primes
         * in the case that the candidate prime is a single word then
         * we check only the primes up to sqrt(rnd)
         */
        if (bits <= 31 && delta <= 0x7fffffff
            && square(primes[i]) > OSSL_FN_get_word(rnd) + delta)
            break;
        if (safe ? (mods[i] + delta) % primes[i] <= 1
                 : (mods[i] + delta) % primes[i] == 0) {
            delta += safe ? 4 : 2;
            if (delta > maxdelta)
                goto again;
            goto loop;
        }
    }
    if (!OSSL_FN_add_word(rnd, delta))
        return 0;
    /*
     * A carry past |bits| lands in the headroom limb and is caught here;
     * the candidate is redrawn in that case.
     */
    if (OSSL_FN_num_bits(rnd) != bits)
        goto again;
    return 1;
}

/*
 * Generate a random number |rnd| of |bits| bits that is probably prime
 * and satisfies |rnd| % |add| == |rem| by sieving.
 * If |safe| != 0, it generates a safe prime.
 * |mods| is a preallocated array that gets reused when called again.
 *
 * |rnd| must have room for |bits| bits plus one limb of headroom: the
 * residue adjustment and the sieve delta can push the candidate slightly
 * past |bits| bits, and the headroom keeps that visible rather than
 * truncated.
 *
 * The probably prime is saved in |rnd|.
 *
 * Returns 1 on success and 0 on error.
 */
static int ossl_fn_probable_prime_dh(OSSL_FN *rnd, size_t bits, int safe,
    prime_t *mods, const OSSL_FN *add, const OSSL_FN *rem,
    OSSL_FN_CTX *ctx, OSSL_LIB_CTX *libctx)
{
    int i, ret = 0;
    OSSL_FN *t1;
    OSSL_FN_ULONG delta;
    int trial_divisions = ossl_fn_calc_trial_divisions(bits);
    OSSL_FN_ULONG maxdelta = OSSL_FN_MASK - primes[trial_divisions - 1];
    const void *token = NULL;

    if (maxdelta > OSSL_FN_MASK - OSSL_FN_get_word(add))
        maxdelta = OSSL_FN_MASK - OSSL_FN_get_word(add);

    if ((token = OSSL_FN_CTX_start(ctx)) == NULL)
        return 0;
    if ((t1 = OSSL_FN_CTX_get_limbs(ctx, rnd->dsize)) == NULL)
        goto err;

again:
    if (!OSSL_FN_rand(rnd, bits, OSSL_FN_RAND_TOP_ONE,
            OSSL_FN_RAND_BOTTOM_ODD, 0, libctx))
        goto err;

    /* we need ((rnd-rem) % add) == 0 */

    if (!OSSL_FN_div(NULL, t1, rnd, add, ctx))
        goto err;
    if (!OSSL_FN_sub(rnd, rnd, t1))
        goto err;
    if (rem == NULL) {
        if (!OSSL_FN_add_word(rnd, safe ? 3u : 1u))
            goto err;
    } else {
        if (!OSSL_FN_add(rnd, rnd, rem))
            goto err;
    }

    if (OSSL_FN_num_bits(rnd) < bits
        || OSSL_FN_get_word(rnd) < (safe ? 5u : 3u)) {
        if (!OSSL_FN_add(rnd, rnd, add))
            goto err;
    }

    /* we now have a random number 'rnd' to test. */
    for (i = 1; i < trial_divisions; i++) {
        OSSL_FN_ULONG mod = OSSL_FN_mod_word(rnd, (OSSL_FN_ULONG)primes[i]);

        if (mod == (OSSL_FN_ULONG)-1)
            goto err;
        mods[i] = (prime_t)mod;
    }
    delta = 0;
loop:
    for (i = 1; i < trial_divisions; i++) {
        /* check that rnd is a prime */
        if (bits <= 31 && delta <= 0x7fffffff
            && square(primes[i]) > OSSL_FN_get_word(rnd) + delta)
            break;
        /* rnd mod p == 1 implies q = (rnd-1)/2 is divisible by p */
        if (safe ? (mods[i] + delta) % primes[i] <= 1
                 : (mods[i] + delta) % primes[i] == 0) {
            delta += OSSL_FN_get_word(add);
            if (delta > maxdelta)
                goto again;
            goto loop;
        }
    }
    if (!OSSL_FN_add_word(rnd, delta))
        goto err;
    ret = 1;

err:
    if (token != NULL)
        OSSL_FN_CTX_end(ctx, token);
    return ret;
}

/*
 * Generate a random number of |bits| bits that is probably prime.
 * If |safe| != 0, it generates a safe prime.  If |add| is not NULL, the
 * prime satisfies ret % |add| == |rem| (or ret % |add| == (safe ? 3 : 1)
 * when |rem| is NULL).
 *
 * The result is generated in an arena temporary with one limb of headroom
 * over |bits|, so that a sieve carry past |bits| is detected and redrawn
 * rather than truncated, and is copied to |ret| on success.  |ret| must
 * have room for |bits| bits; with |add| not NULL the result can
 * occasionally exceed |bits| bits by a small amount, so one limb of
 * headroom in |ret| is advisable in that case.
 *
 * Returns 1 on success and 0 on error.
 */
int OSSL_FN_generate_prime(OSSL_FN *ret, size_t bits, int safe,
    const OSSL_FN *add, const OSSL_FN *rem, BN_GENCB *cb,
    OSSL_FN_CTX *ctx, OSSL_LIB_CTX *libctx)
{
    OSSL_FN *t, *rntmp;
    int found = 0;
    int i, j, c1 = 0;
    prime_t *mods = NULL;
    int checks = ossl_fn_mr_min_checks(bits);
    size_t limbs = bits / OSSL_FN_BITS + (bits % OSSL_FN_BITS != 0);
    const void *token = NULL;

    if (bits < 2) {
        /* There are no prime numbers this small. */
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_BITS_TOO_SMALL);
        return 0;
    } else if (add == NULL && safe && bits < 6 && bits != 3) {
        /*
         * The smallest safe prime (7) is three bits.
         * But the following two safe primes with less than 6 bits (11, 23)
         * are unreachable for OSSL_FN_rand with OSSL_FN_RAND_TOP_TWO.
         */
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_BITS_TOO_SMALL);
        return 0;
    }

    /* The destination must have room for |bits| bits. */
    if ((size_t)ret->dsize < limbs) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_RESULT_ARG_TOO_SMALL);
        return 0;
    }

    mods = OPENSSL_calloc(NUMPRIMES, sizeof(*mods));
    if (mods == NULL)
        return 0;

    if ((token = OSSL_FN_CTX_start(ctx)) == NULL)
        goto err;
    /* One limb of headroom over |bits|, for carry detection. */
    rntmp = OSSL_FN_CTX_get_limbs(ctx, limbs + 1);
    t = OSSL_FN_CTX_get_limbs(ctx, limbs + 1);
    if (t == NULL || rntmp == NULL)
        goto err;
loop:
    /* make a random number and set the top and bottom bits */
    if (add == NULL) {
        if (!ossl_fn_probable_prime(rntmp, bits, safe, mods, libctx))
            goto err;
    } else {
        if (!ossl_fn_probable_prime_dh(rntmp, bits, safe, mods, add, rem,
                ctx, libctx))
            goto err;
    }

    if (!BN_GENCB_call(cb, 0, c1++))
        /* aborted */
        goto err;

    if (!safe) {
        i = ossl_fn_is_prime_int(rntmp, checks, ctx, 0, cb, libctx);
        if (i == -1)
            goto err;
        if (i == 0)
            goto loop;
    } else {
        /*
         * for "safe prime" generation, check that (p-1)/2 is prime.  Since a
         * prime is odd, we just need to divide by 2.
         */
        if (!OSSL_FN_rshift1(t, rntmp))
            goto err;

        for (i = 0; i < checks; i++) {
            j = ossl_fn_is_prime_int(rntmp, 1, ctx, 0, cb, libctx);
            if (j == -1)
                goto err;
            if (j == 0)
                goto loop;

            j = ossl_fn_is_prime_int(t, 1, ctx, 0, cb, libctx);
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
    if (found)
        /*
         * The candidate has exactly |bits| bits (add == NULL) or slightly
         * more (add != NULL); the copy is exact when |ret| is sized per the
         * contract above.
         */
        OSSL_FN_copy_truncate(ret, rntmp);
    OPENSSL_free(mods);
    if (token != NULL)
        OSSL_FN_CTX_end(ctx, token);
    return found;
}

/*
 * Estimate the arena payload for OSSL_FN_generate_prime().  The frame
 * holds two numbers of one limb more than |bits| needs; each generation
 * attempt adds the residue adjustment when |add| is not NULL, and one or
 * two primality tests, all run sequentially.
 */
size_t OSSL_FN_generate_prime_ctx_size(const OSSL_FN *ret, size_t bits,
    int safe, const OSSL_FN *add, const OSSL_FN *rem)
{
    OSSL_FN cand;
    size_t limbs = bits / OSSL_FN_BITS + (bits % OSSL_FN_BITS != 0);
    size_t scratch, mr, div, tests;

    if (bits < 2 || limbs == 0 || (add == NULL && rem != NULL)
        || (add != NULL && (size_t)add->dsize < limbs)
        || (ret != NULL && (size_t)ret->dsize < limbs))
        return 0;

    /* Candidates carry one limb of headroom over |bits|. */
    cand.dsize = limbs + 1;

    scratch = OSSL_FN_CTX_size(1, 2, 2 * (limbs + 1));
    mr = ossl_fn_miller_rabin_is_prime_ctx_size(&cand);
    div = add != NULL ? OSSL_FN_div_ctx_size(NULL, &cand, &cand, add) : 0;
    tests = ctx_add_size(mr, mr);

    return ctx_add_size(scratch, ctx_max_size(div, tests));
}
