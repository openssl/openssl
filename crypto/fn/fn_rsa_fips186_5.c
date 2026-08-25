/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * FIPS 186-5 RSA probable-prime helpers, as used by RSA SP 800-56B key
 * generation.  FIPS 186-4 Table B.1 specifies RSA modulus lengths of 2048
 * and 3072 bits with the min/max total length of the auxiliary primes;
 * FIPS 186-5 Table A.1 adds an entry for 4096, included here.
 *
 * The primality verdicts (ossl_fn_check_generated_prime()) intentionally
 * branch on the candidates' values; that is the whole point of the test.
 * Everything else branches on public widths and round counts only.
 */
#include <openssl/err.h>
#include "internal/mem_alloc_utils.h"
#include "crypto/fnerr.h"
#include "crypto/bn.h" /* For BN_GENCB / BN_GENCB_call and BN_R_* retryable errors */
#include "crypto/fn_constants.h" /* For the inverse-square-root constant */
#include "fn_local.h"

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
 * Refer to FIPS 186-5 Table B.1 for minimum rounds of Miller Rabin
 * required for generation of RSA aux primes (p1, p2, q1 and q2).
 */
static int ossl_fn_rsa_fips186_5_aux_prime_MR_rounds(int nbits)
{
    if (nbits >= 4096)
        return 44;
    if (nbits >= 3072)
        return 41;
    if (nbits >= 2048)
        return 38;
    return 0; /* Error */
}

/*
 * Refer to FIPS 186-5 Table B.1 for minimum rounds of Miller Rabin
 * required for generation of RSA primes (p and q)
 */
static int ossl_fn_rsa_fips186_5_prime_MR_rounds(int nbits)
{
    if (nbits >= 3072)
        return 4;
    if (nbits >= 2048)
        return 5;
    return 0; /* Error */
}

/*
 * FIPS 186-5 Table A.1. "Min length of auxiliary primes p1, p2, q1, q2".
 * (FIPS 186-5 has an entry for >= 4096 bits).
 *
 * Params:
 *     nbits The key size in bits.
 * Returns:
 *     The minimum size of the auxiliary primes or 0 if nbits is invalid.
 */
static int ossl_fn_rsa_fips186_5_aux_prime_min_size(int nbits)
{
    if (nbits >= 4096)
        return 201;
    if (nbits >= 3072)
        return 171;
    if (nbits >= 2048)
        return 141;
    return 0;
}

/*
 * FIPS 186-5 Table A.1 "Max of len(p1) + len(p2) and
 * len(q1) + len(q2) for p,q Probable Primes".
 * (FIPS 186-5 has an entry for >= 4096 bits).
 * Params:
 *     nbits The key size in bits.
 *     c If this is non zero then the probable prime is congruent to c mod 8
 *       and is 3 bits smaller
 * Returns:
 *     The maximum length or 0 if nbits is invalid.
 */
static int ossl_fn_rsa_fips186_5_aux_prime_max_sum_size_for_prob_primes(int nbits,
    uint32_t c)
{
    int reduce_bits = (c == 0) ? 0 : 3;

    if (nbits >= 4096)
        return 2030 - reduce_bits;
    if (nbits >= 3072)
        return 1518 - reduce_bits;
    if (nbits >= 2048)
        return 1007 - reduce_bits;
    return 0;
}

/*
 * Find the first odd integer that is a probable prime.
 *
 * See section FIPS 186-5 A.1.6 (Steps 4.2/5.2).
 *
 * Params:
 *     Xp1 The passed in starting point to find a probably prime.
 *     p1 The returned probable prime (first odd integer >= Xp1)
 *     ctx An OSSL_FN_CTX object.
 *     rounds The number of Miller Rabin rounds
 *     cb An optional callback.
 *     libctx The library context for the primality test's random draws.
 * Returns: 1 on success otherwise it returns 0.
 */
static int ossl_fn_rsa_fips186_5_find_aux_prob_prime(const OSSL_FN *Xp1,
    OSSL_FN *p1, OSSL_FN_CTX *ctx, int rounds, BN_GENCB *cb,
    OSSL_LIB_CTX *libctx)
{
    int ret = 0;
    int i = 0;
    int tmp = 0;

    if (OSSL_FN_copy(p1, Xp1) == NULL)
        return 0;

    /* Find the first odd number >= Xp1 that is probably prime */
    for (;;) {
        i++;
        if (!BN_GENCB_call(cb, 0, i))
            goto err;
        /* MR test with trial division */
        tmp = ossl_fn_check_generated_prime(p1, rounds, ctx, cb, libctx);
        if (tmp > 0)
            break;
        if (tmp < 0)
            goto err;
        /* Get next odd number */
        if (!OSSL_FN_add_word(p1, 2))
            goto err;
    }
    if (!BN_GENCB_call(cb, 2, i))
        goto err;
    ret = 1;
err:
    return ret;
}

static ossl_inline int get_multiple_of_y_congruent_to_cmod8(OSSL_FN *y,
    const OSSL_FN *r1r2x2, int c)
{
    int i = 0;

    for (i = 0; i < 3; ++i) {
        /* Check for Y = c mod 8 */
        if ((OSSL_FN_get_word(y) & 7) == (OSSL_FN_ULONG)c)
            return 1;
        /* Y = Y + 2r1r2 */
        if (!OSSL_FN_add(y, y, r1r2x2))
            return 0;
    }
    /* Fall through for y = y + 6 * r1r2 */
    return 1;
}

/*
 * Estimate the arena payload for ossl_fn_rsa_fips186_5_derive_prime().
 * The frame holds nine numbers: |base| of nlen/2 bits and |range| with one
 * limb of headroom over that, the CRT modulus |r1r2x2|, the interim
 * products |R| and |tmp|, and the congruence step |r1r2x2_step| of
 * |r1| + |r2| + 1 limbs each, the doubled auxiliary prime |r1x2|, and
 * |y1| and |g| of |Y|'s width.  The modular inverses, products and
 * subtractions, the gcd and the primality checks it calls run
 * sequentially within that frame, so their nested needs combine by
 * maximum.
 */
size_t ossl_fn_rsa_fips186_5_derive_prime_ctx_size(const OSSL_FN *Y,
    const OSSL_FN *X, const OSSL_FN *r1, const OSSL_FN *r2, int nlen,
    const OSSL_FN *e)
{
    int bits = nlen >> 1;
    size_t bits_limbs, r1x2_limbs, r1r2x2_limbs, limbs;
    size_t own, nested, inv1, inv2, mul1, mul2, mul3, msub1, msub2;
    size_t gcd, prime;
    OSSL_FN m_R, m_tmp, m_mod, m_y1, m_r1x2;

    if (Y == NULL || X == NULL || r1 == NULL || r2 == NULL || e == NULL
        || nlen <= 0 || bits <= 0)
        return 0;

    bits_limbs = (size_t)bits / OSSL_FN_BITS
        + ((size_t)bits % OSSL_FN_BITS != 0);
    r1x2_limbs = (size_t)r1->dsize + 1;
    r1r2x2_limbs = r1x2_limbs + (size_t)r2->dsize;
    m_R.dsize = (int)r1r2x2_limbs;
    m_tmp.dsize = (int)r1r2x2_limbs;
    m_mod.dsize = (int)r1r2x2_limbs;
    m_y1.dsize = Y->dsize;
    m_r1x2.dsize = (int)r1x2_limbs;

    limbs = bits_limbs + (bits_limbs + 1) + 4 * r1r2x2_limbs + 1
        + r1x2_limbs + 2 * (size_t)Y->dsize;
    own = OSSL_FN_CTX_size(1, 9, limbs);

    inv1 = OSSL_FN_mod_inverse_ctx_size(&m_tmp, &m_r1x2, r2);
    inv2 = OSSL_FN_mod_inverse_ctx_size(&m_R, r2, &m_r1x2);
    mul1 = OSSL_FN_mul_ctx_size(&m_R, &m_R, r2);
    mul2 = OSSL_FN_mul_ctx_size(&m_tmp, &m_tmp, &m_r1x2);
    mul3 = OSSL_FN_mul_ctx_size(&m_mod, &m_r1x2, r2);
    msub1 = OSSL_FN_mod_sub_ctx_size(&m_R, &m_R, &m_tmp, &m_mod);
    msub2 = OSSL_FN_mod_sub_ctx_size(Y, &m_R, X, &m_mod);
    gcd = OSSL_FN_gcd_ctx_size(&m_y1, e);
    prime = ossl_fn_check_generated_prime_ctx_size(Y);

    nested = ctx_max_size(inv1,
        ctx_max_size(inv2,
            ctx_max_size(mul1,
                ctx_max_size(mul2,
                    ctx_max_size(mul3,
                        ctx_max_size(msub1,
                            ctx_max_size(msub2,
                                ctx_max_size(gcd, prime))))))));
    if (own == 0 || nested == 0)
        return 0;
    return ctx_add_size(own, nested);
}

/*
 * Constructs a probable prime (a candidate for p or q) using 2 auxiliary
 * prime numbers and the Chinese Remainder Theorem.
 *
 * See FIPS 186-5 B.9 "Compute a Probable Prime Factor Based on Auxiliary
 * Primes". Used by FIPS 186-5 A.1.6 Section (4.3) for p and Section (5.3)
 * for q.
 *
 * |Y|, |X|, |r1|, |r2|, |e| are not NULL.  |Y| must have room for nlen/2
 * bits; one limb of headroom over that width lets the width check at
 * (Step 6) see a carry past the width rather than have it truncated.
 *
 * The inverse of r1x2 modulo r2 and the inverse of r2 modulo r1x2 imply
 * the FIPS 186-5 B.9 (Step 1) condition GCD(2r1, r2) == 1.
 * |R| = ((r2^-1 mod 2r1) * r2) - ((2r1^-1 mod r2) * 2r1) modulo 2r1r2,
 * computed by modular reduction only, with no sign adjustment.
 *
 * Returns: 1 on success otherwise it returns 0.
 */
int ossl_fn_rsa_fips186_5_derive_prime(OSSL_FN *Y, OSSL_FN *X,
    const OSSL_FN *Xin, const OSSL_FN *r1, const OSSL_FN *r2,
    int nlen, const OSSL_FN *e, OSSL_FN_CTX *ctx, BN_GENCB *cb,
    uint32_t c, OSSL_LIB_CTX *libctx)
{
    int ret = 0;
    int i, imax, rounds;
    int bits = nlen >> 1;
    size_t bits_limbs = (size_t)bits / OSSL_FN_BITS
        + ((size_t)bits % OSSL_FN_BITS != 0);
    size_t r1x2_limbs = (size_t)r1->dsize + 1;
    size_t r1r2x2_limbs = r1x2_limbs + (size_t)r2->dsize;
    OSSL_FN *tmp, *R, *r1r2x2, *r1r2x2_step, *y1, *r1x2;
    OSSL_FN *base, *range, *g;
    const OSSL_FN *step;
    const void *token = NULL;

    if ((token = OSSL_FN_CTX_start(ctx)) == NULL)
        return 0;

    base = OSSL_FN_CTX_get_limbs(ctx, bits_limbs);
    range = OSSL_FN_CTX_get_limbs(ctx, bits_limbs + 1);
    R = OSSL_FN_CTX_get_limbs(ctx, r1r2x2_limbs);
    tmp = OSSL_FN_CTX_get_limbs(ctx, r1r2x2_limbs);
    r1r2x2 = OSSL_FN_CTX_get_limbs(ctx, r1r2x2_limbs);
    y1 = OSSL_FN_CTX_get_limbs(ctx, (size_t)Y->dsize);
    r1x2 = OSSL_FN_CTX_get_limbs(ctx, r1x2_limbs);
    g = OSSL_FN_CTX_get_limbs(ctx, (size_t)Y->dsize);
    r1r2x2_step = OSSL_FN_CTX_get_limbs(ctx, r1r2x2_limbs + 1);
    if (r1r2x2_step == NULL)
        goto err;

    if (Xin != NULL && OSSL_FN_copy(X, Xin) == NULL)
        goto err;

    /*
     * We need to generate a random number X in the range
     * 1/sqrt(2) * 2^(nlen/2) <= X < 2^(nlen/2).
     * We can rewrite that as:
     * base = 1/sqrt(2) * 2^(nlen/2)
     * range = ((2^(nlen/2))) - (1/sqrt(2) * 2^(nlen/2))
     * X = base + random(range)
     * We only have the first 256 bits of 1/sqrt(2)
     */
    if (Xin == NULL) {
        size_t isqrt_bits = OSSL_FN_num_bits(&ossl_fn_static_inv_sqrt_2_storage.fn);

        if ((size_t)bits < isqrt_bits)
            goto err;
        if (!OSSL_FN_lshift(base, &ossl_fn_static_inv_sqrt_2_storage.fn,
                bits - (int)isqrt_bits)
            || !OSSL_FN_one(range)
            || !OSSL_FN_lshift(range, range, bits)
            || !OSSL_FN_sub(range, range, base))
            goto err;
    }

    /*
     * (Step 1) GCD(2r1, r2) = 1, and (Step 2)
     * R = ((r2^-1 mod 2r1) * r2) - ((2r1^-1 mod r2)*2r1).
     * The GCD test is carried by the inverse computations.
     */
    if (!(OSSL_FN_lshift1(r1x2, r1)
            && OSSL_FN_mod_inverse(tmp, r1x2, r2, ctx)
            && OSSL_FN_mod_inverse(R, r2, r1x2, ctx)
            && OSSL_FN_mul(R, R, r2, ctx)
            && OSSL_FN_mul(tmp, tmp, r1x2, ctx)
            && OSSL_FN_mul(r1r2x2, r1x2, r2, ctx)
            /* R = (R * r2 - tmp * r1x2) mod 2r1r2 */
            && OSSL_FN_mod_sub(R, R, tmp, r1r2x2, ctx)))
        goto err;

    /*
     * With the c mod 8 requirement, the candidate must advance in steps
     * that preserve the congruence; 8r1r2 is the smallest such multiple
     * of 2r1r2.
     */
    step = r1r2x2;
    if (c != 0) {
        if (!OSSL_FN_lshift(r1r2x2_step, r1r2x2, 2))
            goto err;
        step = r1r2x2_step;
    }

    /*
     * In FIPS 186-4 imax was set to 5 * nlen/2.
     * Analysis by Allen Roginsky
     * (See https://csrc.nist.gov/CSRC/media/Publications/fips/186/4/final/documents/comments-received-fips186-4-december-2015.pdf
     * page 68) indicates this has a 1 in 2 million chance of failure.
     * The number has been updated to 20 * nlen/2 as used in
     * FIPS186-5 Appendix B.9 Step 9.
     */
    rounds = ossl_fn_rsa_fips186_5_prime_MR_rounds(nlen);
    imax = 20 * bits; /* max = 20/2 * nbits */
    for (;;) {
        if (Xin == NULL) {
            /*
             * (Step 3) Choose Random X such that
             *    1/sqrt(2) * 2^(nlen/2) <= Random X <= (2^(nlen/2)) - 1.
             */
            if (!OSSL_FN_priv_rand_range(X, range, 0, libctx)
                || !OSSL_FN_add(X, X, base))
                goto err;
        }
        /* (Step 4) Y = X + ((R - X) mod 2r1r2) */
        if (!OSSL_FN_mod_sub(Y, R, X, r1r2x2, ctx) || !OSSL_FN_add(Y, Y, X))
            goto err;
        /*
         * (Step 4.1) If there is an optional requirement that the
         * computed prime is equal to c mod 8, then choose the value
         * Y, Y + 2r1r2, Y + 4r1r2 OR Y + 6r1r2 that satisfies the
         * requirement.
         */
        if (c != 0) {
            if (!get_multiple_of_y_congruent_to_cmod8(Y, r1r2x2, c))
                goto err;
        }
        /* (Step 5) */
        i = 0;
        for (;;) {
            /* (Step 6) */
            if (OSSL_FN_num_bits(Y) > (size_t)bits) {
                if (Xin == NULL)
                    break; /* Randomly Generated X so Go back to Step 3 */
                else
                    goto err; /* X is not random so it will always fail */
            }
            if (!BN_GENCB_call(cb, 0, 2))
                goto err;

            /* (Step 7) If GCD(Y-1) == 1 & Y is probably prime then return Y */
            if (OSSL_FN_copy(y1, Y) == NULL || !OSSL_FN_sub_word(y1, 1))
                goto err;

            if (!OSSL_FN_gcd(g, y1, e, ctx))
                goto err;
            if (OSSL_FN_is_one(g)) {
                int rv = ossl_fn_check_generated_prime(Y, rounds, ctx, cb,
                    libctx);

                if (rv > 0)
                    goto end;
                if (rv < 0)
                    goto err;
            }
            /* (Step 8-10) */
            if (++i >= imax) {
                ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_TOO_MANY_ITERATIONS);
                goto err;
            }
            if (!OSSL_FN_add(Y, Y, step))
                goto err;
        }
    }
end:
    ret = 1;
    if (!BN_GENCB_call(cb, 3, 0))
        ret = 0;
err:
    if (r1r2x2_step != NULL) {
        /* r1r2x2_step is allocated last; clear the sensitive temporaries */
        OSSL_FN_clear(R);
        OSSL_FN_clear(tmp);
        OSSL_FN_clear(r1x2);
        OSSL_FN_clear(r1r2x2);
        OSSL_FN_clear(r1r2x2_step);
        OSSL_FN_clear(y1);
        OSSL_FN_clear(g);
    }
    if (!OSSL_FN_CTX_end(ctx, token))
        ret = 0;
    return ret;
}

/*
 * Estimate the arena payload for
 * ossl_fn_rsa_fips186_5_gen_prob_primes().  The frame holds one
 * auxiliary-prime-width temporary for each of |p1|, |p2|, |Xp1| and
 * |Xp2| that the caller leaves NULL; caller-provided numbers keep
 * their own width for the nested auxiliary prime hunts.  The hunts
 * and the prime derivation run sequentially within that frame, so
 * their nested needs combine by maximum.  Returns 0 for an invalid
 * |nlen|, like the operation itself.
 */
size_t ossl_fn_rsa_fips186_5_gen_prob_primes_ctx_size(const OSSL_FN *p,
    const OSSL_FN *Xpout, const OSSL_FN *p1, const OSSL_FN *p2,
    const OSSL_FN *Xp1, const OSSL_FN *Xp2, int nlen, const OSSL_FN *e)
{
    int bitlen;
    size_t bitlimbs, n_temps, own, nested, hunt1, hunt2, derive;
    OSSL_FN m_p1, m_p2;

    if (p == NULL || Xpout == NULL || e == NULL)
        return 0;
    bitlen = ossl_fn_rsa_fips186_5_aux_prime_min_size(nlen);
    if (bitlen == 0)
        return 0;
    bitlimbs = (size_t)bitlen / OSSL_FN_BITS
        + ((size_t)bitlen % OSSL_FN_BITS != 0);

    m_p1.dsize = p1 != NULL ? p1->dsize : (int)bitlimbs;
    m_p2.dsize = p2 != NULL ? p2->dsize : (int)bitlimbs;
    n_temps = (size_t)(p1 == NULL) + (p2 == NULL) + (Xp1 == NULL)
        + (Xp2 == NULL);
    own = OSSL_FN_CTX_size(1, n_temps, n_temps * bitlimbs);

    hunt1 = ossl_fn_check_generated_prime_ctx_size(&m_p1);
    hunt2 = ossl_fn_check_generated_prime_ctx_size(&m_p2);
    derive = ossl_fn_rsa_fips186_5_derive_prime_ctx_size(p, Xpout, &m_p1,
        &m_p2, nlen, e);
    nested = ctx_max_size(hunt1, ctx_max_size(hunt2, derive));
    if (own == 0 || nested == 0)
        return 0;
    return ctx_add_size(own, nested);
}

/*
 * Generate a probable prime (p or q).
 *
 * See FIPS 186-5 A.1.6 (Steps 4 & 5)
 *
 * |p|, |Xpout| are not NULL.  Same width-contract as
 * ossl_fn_rsa_fips186_5_derive_prime().
 *
 * Returns: 1 on success otherwise it returns 0.
 */
int ossl_fn_rsa_fips186_5_gen_prob_primes(OSSL_FN *p, OSSL_FN *Xpout,
    OSSL_FN *p1, OSSL_FN *p2,
    const OSSL_FN *Xp, const OSSL_FN *Xp1,
    const OSSL_FN *Xp2, int nlen,
    const OSSL_FN *e, OSSL_FN_CTX *ctx,
    BN_GENCB *cb, uint32_t c, OSSL_LIB_CTX *libctx)
{
    int ret = 0;
    OSSL_FN *p1i = NULL, *p2i = NULL, *Xp1i = NULL, *Xp2i = NULL;
    int bitlen, rounds;
    size_t bitlimbs;
    const void *token = NULL;
    /* 1 when the values are ours to clear, 0 when returned */
    int clear_mask = 0;

    if (p == NULL || Xpout == NULL)
        return 0;

    if ((token = OSSL_FN_CTX_start(ctx)) == NULL)
        return 0;

    bitlen = ossl_fn_rsa_fips186_5_aux_prime_min_size(nlen);
    if (bitlen == 0)
        goto err;
    bitlimbs = (size_t)bitlen / OSSL_FN_BITS
        + ((size_t)bitlen % OSSL_FN_BITS != 0);

    p1i = (p1 != NULL) ? p1 : OSSL_FN_CTX_get_limbs(ctx, bitlimbs);
    p2i = (p2 != NULL) ? p2 : OSSL_FN_CTX_get_limbs(ctx, bitlimbs);
    Xp1i = (Xp1 != NULL) ? (OSSL_FN *)Xp1 : OSSL_FN_CTX_get_limbs(ctx, bitlimbs);
    Xp2i = (Xp2 != NULL) ? (OSSL_FN *)Xp2 : OSSL_FN_CTX_get_limbs(ctx, bitlimbs);
    if (p1i == NULL || p2i == NULL || Xp1i == NULL || Xp2i == NULL)
        goto err;
    clear_mask = (p1 == NULL ? 1 : 0) | (p2 == NULL ? 2 : 0)
        | (Xp1 == NULL ? 4 : 0) | (Xp2 == NULL ? 8 : 0);

    rounds = ossl_fn_rsa_fips186_5_aux_prime_MR_rounds(nlen);

    /* (Steps 4.1/5.1): Randomly generate Xp1 if it is not passed in */
    if (Xp1 == NULL) {
        /* Set the top and bottom bits to make it odd and the correct size */
        if (!OSSL_FN_priv_rand(Xp1i, bitlen, OSSL_FN_RAND_TOP_ONE,
                OSSL_FN_RAND_BOTTOM_ODD, 0, libctx))
            goto err;
    }
    /* (Steps 4.1/5.1): Randomly generate Xp2 if it is not passed in */
    if (Xp2 == NULL) {
        /* Set the top and bottom bits to make it odd and the correct size */
        if (!OSSL_FN_priv_rand(Xp2i, bitlen, OSSL_FN_RAND_TOP_ONE,
                OSSL_FN_RAND_BOTTOM_ODD, 0, libctx))
            goto err;
    }

    /* (Steps 4.2/5.2) - find first auxiliary probable primes */
    if (!ossl_fn_rsa_fips186_5_find_aux_prob_prime(Xp1i, p1i, ctx, rounds, cb,
            libctx)
        || !ossl_fn_rsa_fips186_5_find_aux_prob_prime(Xp2i, p2i, ctx, rounds,
            cb, libctx))
        goto err;
    /* (FIPS 186-5 Table A.1) auxiliary prime Max length check */
    if (OSSL_FN_num_bits(p1i) + OSSL_FN_num_bits(p2i)
        >= (size_t)ossl_fn_rsa_fips186_5_aux_prime_max_sum_size_for_prob_primes(nlen,
            c))
        goto err;
    /* (Steps 4.3/5.3) - generate prime */
    if (!ossl_fn_rsa_fips186_5_derive_prime(p, Xpout, Xp, p1i, p2i, nlen, e,
            ctx, cb, c, libctx))
        goto err;
    ret = 1;
err:
    /* Clear any internally generated values that are not returned */
    if ((clear_mask & 1) != 0)
        OSSL_FN_clear(p1i);
    if ((clear_mask & 2) != 0)
        OSSL_FN_clear(p2i);
    if ((clear_mask & 4) != 0)
        OSSL_FN_clear(Xp1i);
    if ((clear_mask & 8) != 0)
        OSSL_FN_clear(Xp2i);
    if (!OSSL_FN_CTX_end(ctx, token))
        ret = 0;
    return ret;
}
