/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
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
