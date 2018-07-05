/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_BN_INT_H
# define HEADER_BN_INT_H

# include <openssl/bn.h>
# include <limits.h>

BIGNUM *bn_wexpand(BIGNUM *a, int words);
BIGNUM *bn_expand2(BIGNUM *a, int words);

void bn_correct_top(BIGNUM *a);

/*
 * Determine the modified width-(w+1) Non-Adjacent Form (wNAF) of 'scalar'.
 * This is an array r[] of values that are either zero or odd with an
 * absolute value less than 2^w satisfying scalar = \sum_j r[j]*2^j where at
 * most one of any w+1 consecutive digits is non-zero with the exception that
 * the most significant digit may be only w-1 zeros away from that next
 * non-zero digit.
 */
signed char *bn_compute_wNAF(const BIGNUM *scalar, int w, size_t *ret_len);

int bn_get_top(const BIGNUM *a);

int bn_get_dmax(const BIGNUM *a);

/* Set all words to zero */
void bn_set_all_zero(BIGNUM *a);

/*
 * Copy the internal BIGNUM words into out which holds size elements (and size
 * must be bigger than top)
 */
int bn_copy_words(BN_ULONG *out, const BIGNUM *in, int size);

BN_ULONG *bn_get_words(const BIGNUM *a);

/*
 * Set the internal data words in a to point to words which contains size
 * elements. The BN_FLG_STATIC_DATA flag is set
 */
void bn_set_static_words(BIGNUM *a, BN_ULONG *words, int size);

/*
 * Copy words into the BIGNUM |a|, reallocating space as necessary.
 * The negative flag of |a| is not modified.
 * Returns 1 on success and 0 on failure.
 */
/*
 * |num_words| is int because bn_expand2 takes an int. This is an internal
 * function so we simply trust callers not to pass negative values.
 */
int bn_set_words(BIGNUM *a, BN_ULONG *words, int num_words);

#define BN_PRIMETEST_COMPOSITE                    0
#define BN_PRIMETEST_COMPOSITE_WITH_FACTOR        1
#define BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME 2
#define BN_PRIMETEST_PROBABLY_PRIME               3

int bn_miller_rabin_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx,
                             BN_GENCB *cb, int enhanced, int *status);

const BIGNUM *bn_get0_small_factors(void);

int bn_rsa_fips186_4_prime_MR_min_checks(int nbits);

int bn_rsa_fips186_4_gen_prob_primes(BIGNUM *p, BIGNUM *Xpout,
                                     BIGNUM *p1, BIGNUM *p2,
                                     const BIGNUM *Xp, const BIGNUM *Xp1,
                                     const BIGNUM *Xp2, int nlen,
                                     const BIGNUM *e, BN_CTX *ctx,
                                     BN_GENCB *cb);

int bn_rsa_fips186_4_derive_prime(BIGNUM *Y, BIGNUM *X, const BIGNUM *Xin,
                                  const BIGNUM *r1, const BIGNUM *r2, int nlen,
                                  const BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb);

#ifdef  __cplusplus
}
#endif

#endif
