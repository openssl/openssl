/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/bn.h>
#include "bn_lcl.h"
#include "internal/bn_int.h"

/*
 * FIPS 186-4 Table B.1. "Min length of auxilary primes p1, p2, q1, q2".
 */
static int bn_rsa_fips186_4_aux_prime_min_size(int nbits)
{
    int min_bits;
    switch (nbits) {
#if 0
    case 1024:
        min_bits = 101;
        break;
#endif
    case 2048:
        min_bits = 141;
        break;
    case 3072:
        min_bits = 171;
        break;
    default:
        return 0;
    }
    return min_bits;
}

/*
 * FIPS 186-4 Table B.1 "Maximum length of len(p1)+len(p2) and len(q1)+len(q2)
 * for p,q Probable Primes".
 */
static int bn_rsa_fips186_4_aux_prime_max_sum_size_for_prob_primes(int nbits)
{
    int max_bits;
    switch (nbits) {
#if 0
    case 1024:
        max_bits = 496;
        break;
#endif
    case 2048:
        max_bits = 1007;
        break;
    case 3072:
        max_bits = 1518;
        break;
    default:
        return 0;
    }
    return max_bits;
}

/* FIPS 186-4 Table C.3 for error probability of 2^-100
 * Minimum number of Miller Rabin Rounds for p1, p2, q1 & q2.
 */
static int bn_rsa_fips186_4_aux_prime_MR_min_checks(int aux_prime_bits)
{
    if (aux_prime_bits > 170)
        return 27;
    else if (aux_prime_bits > 140)
        return 32;
#if 0
    else if (aux_prime_bits > 100)
        return 38;
#endif
    else
        return 0; /* Error case */
}

/*
 * Find the first odd integer that is a probable prime.
 *
 * See section FIPS 186-4 B.3.6 (Steps 4.2/5.2)
 */
static int bn_rsa_fips186_4_find_aux_prob_prime(int nlen, const BIGNUM *Xp1,
                                                BIGNUM *p1, BN_CTX *ctx,
                                                BN_GENCB *cb)
{
    int ret = 0;
    int i = 0;
    int checks = bn_rsa_fips186_4_aux_prime_MR_min_checks(BN_num_bits(Xp1));

    if (!BN_copy(p1, Xp1))
        goto err;

    /* Find the first odd number >= Xp1 that is probably prime */
    for(;;) {
        i++;
        BN_GENCB_call(cb, 0, i);
        /* MR test with trial division */
        if (BN_is_prime_fasttest_ex(p1, checks, ctx, 1, cb))
            break;
        /* Get next odd number */
        if (!BN_add_word(p1, 2))
            goto err;
    }
    BN_GENCB_call(cb, 2, i);
    ret = 1;
err:
    return ret;
}

/*
 * FIPS 186-4 Table C.3 for error probability of 2^-100
 * Minimum number of Miller Rabin Rounds for p, q.
 */
int bn_rsa_fips186_4_prime_MR_min_checks(int nbits)
{
    if (nbits == 3072)      /* > 170 */
        return 3;
    else if (nbits == 2048) /* > 140 */
        return 4;
#if 0
    else if (nbits == 1024) /* > 100 */
        return 7;
#endif
    else
        return 0; /* Error case */
}

/*
 * FIPS 186-4 B.3.6  (Steps 4 & 5)
 *
 * This method is called for both p and q.
 *
 * Notes:
 * If p1, p2 are non NULL then they are returned.
 * Xp, Xp1 & Xp2 can be optionally passed in instead of being randomly
 * generated.
 */
int bn_rsa_fips186_4_gen_prob_primes(BIGNUM *p, BIGNUM *Xpout,
                                     BIGNUM *p1, BIGNUM *p2,
                                     const BIGNUM *Xp, const BIGNUM *Xp1,
                                     const BIGNUM *Xp2, int nlen,
                                     const BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb)
{
    int ret = 0;
    BIGNUM *p1i = NULL, *p2i = NULL, *Xp1i = NULL, *Xp2i = NULL;
    int bitlen;

    if (p == NULL || Xpout == NULL)
        return 0;

    BN_CTX_start(ctx);

    p1i = (p1 != NULL) ? p1 : BN_CTX_get(ctx);
    p2i = (p2 != NULL) ? p2 : BN_CTX_get(ctx);
    Xp1i = (Xp1 != NULL) ? (BIGNUM *)Xp1 : BN_CTX_get(ctx);
    Xp2i = (Xp2 != NULL) ? (BIGNUM *)Xp2 : BN_CTX_get(ctx);
    if (p1i == NULL || p2i == NULL || Xp1i == NULL || Xp2i == NULL)
        goto err;

    bitlen = bn_rsa_fips186_4_aux_prime_min_size(nlen);

    /* (Steps 4.1/5.1): Randomly generate Xp1 if it is not passed in */
    if (Xp1 == NULL) {
        /* Set the top and bottom bits to make it odd and the correct size */
        if (!BN_priv_rand(Xp1i, bitlen, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD))
            goto err;
    }
    /* (Steps 4.1/5.1): Randomly generate Xp2 if it is not passed in */
    if (Xp2 == NULL) {
        /* Set the top and bottom bits to make it odd and the correct size */
        if (!BN_priv_rand(Xp2i, bitlen, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD))
            goto err;
    }

    /* (Steps 4.2/5.2) - find first auxiliary probable primes */
    if (!bn_rsa_fips186_4_find_aux_prob_prime(nlen, Xp1i, p1i, ctx, cb)
            || !bn_rsa_fips186_4_find_aux_prob_prime(nlen, Xp2i, p2i, ctx, cb))
        goto err;
    /* (Table B.1) auxiliary prime Max length check */
    if ((BN_num_bits(p1i) + BN_num_bits(p2i)) >=
            bn_rsa_fips186_4_aux_prime_max_sum_size_for_prob_primes(nlen))
        goto err;
    /* (Steps 4.3/5.3) - generate prime */
    if (!bn_rsa_fips186_4_derive_prime(p, Xpout, Xp, p1i, p2i, nlen, e, ctx, cb))
        goto err;
    ret = 1;
err:
    /* Zeroize any internally generated values that are not returned */
    if (p1 == NULL)
        BN_clear(p1i);
    if (p2 == NULL)
        BN_clear(p2i);
    if (Xp1 == NULL)
        BN_clear(Xp1i);
    if (Xp2 == NULL)
        BN_clear(Xp2i);
    BN_CTX_end(ctx);
    return ret;
}

/*
 * See FIPS 186-4 C.9
 * "Compute a Probable Prime Factor Based on Auxiliary Primes.
 * Used by FIPS 186-4 B.3.6 Section 4.3 for p and Section 5.3 for q.
 *
 * Assumptions: Y, X, r1, r2, e are not NULL.
 */
int bn_rsa_fips186_4_derive_prime(BIGNUM *Y, BIGNUM *X, const BIGNUM *Xin,
                                  const BIGNUM *r1, const BIGNUM *r2, int nlen,
                                  const BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb)
{
    int ret = 0;
    int i, imax;
    int bits = nlen >> 1;
    int checks = bn_rsa_fips186_4_prime_MR_min_checks(nlen);
    BIGNUM *tmp, *R, *r1r2x2, *y1, *r1x2;

    BN_CTX_start(ctx);

    R = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    r1r2x2 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    r1x2 = BN_CTX_get(ctx);

    if (Xin != NULL && !BN_copy(X, Xin))
        goto err;

    if (!(r1x2 != NULL
            && BN_lshift1(r1x2, r1)
            /* (Step 1) GCD(2r1, r2) = 1 */
            && BN_gcd(tmp, r1x2, r2, ctx)
            && BN_is_one(tmp)
            /* (Step 2) R = ((r2^-1 mod 2r1) * r2) - ((2r1^-1 mod r2)*2r1) */
            && BN_mul(r1r2x2, r1x2, r2, ctx)
            && BN_mod_inverse(R, r2, r1x2, ctx)
            && BN_mul(R, R, r2, ctx) /* R = (r2^-1 mod 2r1) * r2 */
            && BN_mod_inverse(tmp, r1x2, r2, ctx)
            && BN_mul(tmp, tmp, r1x2, ctx) /* tmp = (2r1^-1 mod r2)*2r1 */
            && BN_sub(R, R, tmp)))
        goto err;
    /* Make positive by adding the modulus */
    if (BN_is_negative(R) && !BN_add(R, R, r1r2x2))
        goto err;

    imax = 5 * bits; /* max = 5/2 * nbits */
    for (;;) {
        if (Xin == NULL) {
            /*
             * (Step 3) Choose Random X such that
             *    sqrt(2) * 2^(nlen/2-1) < Random X < (2^(nlen/2)) - 1.
             *
             * For the lower bound:
             *   sqrt(2) * 2^(nlen/2 - 1) == sqrt(2)/2 * 2^(nlen/2)
             *   where sqrt(2)/2 = 0.70710678.. = 0.B504FC33F9DE...
             *   so largest number will have B5... as the top byte
             *   Setting the top 2 bits gives 0xC0.
             */
            if (!BN_priv_rand(X, bits, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY))
                goto end;
        }
        /* (Step 4) Y = X + ((R - X) mod 2r1r2) */
        if (!BN_mod_sub(Y, R, X, r1r2x2, ctx) || !BN_add(Y, Y, X))
            goto err;
        /* (Step 5) */
        i = 0;
        for (;;) {
            /* (Step 6) */
            if (BN_num_bits(Y) > bits) {
                if (Xin == NULL)
                    break; /* Randomly Generated X so Go back to Step 3 */
                else
                    goto err; /* X is not random so it will always fail */
            }
            BN_GENCB_call(cb, 0, 2);

            /* (Step 7) If GCD(Y-1) == 1 & Y is probably prime then return Y */
            if (!BN_copy(y1, Y)
                    || !BN_sub_word(y1, 1)
                    || !BN_gcd(tmp, y1, e, ctx))
                goto err;
            if (BN_is_one(tmp)
                    && BN_is_prime_fasttest_ex(Y, checks, ctx, 1, cb))
                goto end;
            /* (Step 8-10) */
            if (++i >= imax || !BN_add(Y, Y, r1r2x2))
                goto err;
        }
    }
end:
    ret = 1;
    BN_GENCB_call(cb, 3, 0);
err:
    BN_clear(y1);
    BN_CTX_end(ctx);
    return ret;
}

