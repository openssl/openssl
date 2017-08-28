/******************************************************************************
 * NTRU Cryptography Reference Source Code
 *
 * Copyright (C) 2009-2016  Security Innovation (SI)
 *
 * SI has dedicated the work to the public domain by waiving all of its rights
 * to the work worldwide under copyright law, including all related and
 * neighboring rights, to the extent allowed by law.
 *
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * You can copy, modify, distribute and perform the work, even for commercial
 * purposes, all without asking permission. You should have received a copy of
 * the creative commons license (CC0 1.0 universal) along with this program.
 * See the license file for more information. 
 *
 *
 *********************************************************************************/

/******************************************************************************
 *
 * File:  ntru_crypto_ntru_poly.h
 *
 * Contents: Public header file for generating and operating on polynomials
 *           in the NTRU algorithm.
 *
 *****************************************************************************/

#ifndef NTRU_CRYPTO_NTRU_POLY_H
#define NTRU_CRYPTO_NTRU_POLY_H

#include "ntru_crypto.h"
#include "ntru_crypto_hash_basics.h"

/* function declarations */

/* ntru_gen_poly
 *
 * Generates polynomials by creating for each polynomial, a list of the
 * indices of the +1 coefficients followed by a list of the indices of
 * the -1 coefficients.
 *
 * If a single polynomial is generated (non-product form), indices_counts
 * contains a single value of the total number of indices (for +1 and -1
 * comefficients combined).
 *
 * If multiple polynomials are generated (for product form), their lists of
 * indices are sequentially stored in the indices buffer.  Each byte of
 * indices_counts contains the total number of indices (for +1 and -1
 * coefficients combined) for a single polynomial, beginning with the
 * low-order byte for the first polynomial.  The high-order byte is unused.
 *
 * Returns NTRU_OK if successful.
 * Returns HASH_BAD_ALG if the algorithm is not supported.
 *
 */

extern uint32_t
ntru_gen_poly(
    NTRU_CRYPTO_HASH_ALGID hash_algid, /*  in - hash algorithm ID for
                                                      IGF-2 */
    uint8_t md_len,                    /*  in - no. of octets in digest */
    uint8_t min_calls,                 /*  in - minimum no. of hash
                                                      calls */
    uint16_t seed_len,                 /*  in - no. of octets in seed */
    uint8_t *seed,                     /*  in - pointer to seed */
    uint8_t *buf,                      /*  in - pointer to working
                                                      buffer */
    uint16_t N,                        /*  in - max index + 1 */
    uint8_t c_bits,                    /*  in - no. bits for candidate */
    uint16_t limit,                    /*  in - conversion to index
                                                      limit */
    bool is_product_form,              /*  in - if generating multiple
                                                      polys */
    uint32_t indices_counts,           /*  in - nos. of indices needed */
    uint16_t *indices);                /* out - address for indices */

/* ntru_poly_check_min_weight
 *
 * Checks that the number of 0, +1, and -1 trinary ring elements meet or exceed
 * a minimum weight.
 */

extern bool
ntru_poly_check_min_weight(
    uint16_t num_els, /*  in - degree of polynomial */
    uint8_t *ringels, /*  in - pointer to trinary ring elements */
    uint16_t min_wt); /*  in - minimum weight */

/* ntru_ring_mult_indices
 *
 * Multiplies ring element (polynomial) "a" by ring element (polynomial) "b"
 * to produce ring element (polynomial) "c" in (Z/qZ)[X]/(X^N - 1).
 * This is a convolution operation.
 *
 * Ring element "b" is a sparse trinary polynomial with coefficients -1, 0,
 * and 1.  It is specified by a list, bi, of its nonzero indices containing
 * indices for the bi_P1_len +1 coefficients followed by the indices for the
 * bi_M1_len -1 coefficients.
 * The indices are in the range [0,N).
 *
 * The result array "c" may share the same memory space as input array "a",
 * or input array "b".
 *
 * This assumes q is 2^r where 8 < r < 16, so that overflow of the sum
 * beyond 16 bits does not matter.
 */

/* wrapper */
extern void
ntru_ring_mult_indices(
    uint16_t const *a,        /*  in - pointer to ring element a */
    uint16_t const bi_P1_len, /*  in - no. of +1 coefficients in b */
    uint16_t const bi_M1_len, /*  in - no. of -1 coefficients in b */
    uint16_t const *bi,       /*  in - pointer to the list of nonzero
                                         indices of ring element b,
                                         containing indices for the +1
                                         coefficients followed by the
                                         indices for -1 coefficients */
    uint16_t const N,         /*  in - no. of coefficients in a, b, c */
    uint16_t const q,         /*  in - large modulus */
    uint16_t *t,              /*  in - temp buffer. Size is impl dependent.
                                         see ntru_ring_mult_indices_memreq */
    uint16_t *c);             /* out - address for polynomial c */

/* ntru_ring_mult_product_indices
 *
 * Multiplies ring element (polynomial) "a" by ring element (polynomial) "b"
 * to produce ring element (polynomial) "c" in (Z/qZ)[X]/(X^N - 1).
 * This is a convolution operation.
 *
 * Ring element "b" is represented by the product form b1 * b2 + b3, where
 * b1, b2, and b3 are each a sparse trinary polynomial with coefficients -1,
 * 0, and 1.  It is specified by a list, bi, of the nonzero indices of b1, b2,
 * and b3, containing the indices for the +1 coefficients followed by the
 * indices for the -1 coefficients for each polynomial in that order.
 * The indices are in the range [0,N).
 *
 * The result array "c" may share the same memory space as input array "a",
 * or input array "b".
 *
 * This assumes q is 2^r where 8 < r < 16, so that overflow of the sum
 * beyond 16 bits does not matter.
 */

extern void
ntru_ring_mult_product_indices(
    uint16_t const *a,      /*  in - pointer to ring element a */
    uint16_t const b1i_len, /*  in - no. of +1 or -1 coefficients in b1 */
    uint16_t const b2i_len, /*  in - no. of +1 or -1 coefficients in b2 */
    uint16_t const b3i_len, /*  in - no. of +1 or -1 coefficients in b3 */
    uint16_t const *bi,     /*  in - pointer to the list of nonzero
                                         indices of polynomials b1, b2, b3,
                                         containing indices for the +1
                                         coefficients followed by the
                                         indices for -1 coefficients for
                                         each polynomial */
    uint16_t const N,       /*  in - no. of coefficients in a, b, c */
    uint16_t const q,       /*  in - large modulus */
    uint16_t *t,            /*  in - temp buffer. Size is impl dependent.
                                         see ntru_ring_mult_indices_memreq */
    uint16_t *c);           /* out - address for polynomial c */

/* ntru_ring_mult_coefficients
 *
 * Multiplies ring element (polynomial) "a" by ring element (polynomial) "b"
 * to produce ring element (polynomial) "c" in (Z/qZ)[X]/(X^N - 1).
 * This is a convolution operation.
 *
 * This assumes q is 2^r where 8 < r < 16, so that overflow of the sum
 * beyond 16 bits does not matter.
 */

extern void
ntru_ring_mult_coefficients(
    uint16_t const *a, /*  in - pointer to polynomial a */
    uint16_t const *b, /*  in - pointer to polynomial b */
    uint16_t N,        /*  in - degree of (x^N - 1) */
    uint16_t q,        /*  in - large modulus */
    uint16_t *tmp,     /*  in - temp buffer. Size is impl dependent.
                                       see ntru_ring_mult_coefficients_memreq */
    uint16_t *c);      /* out - address for polynomial c */

/* ntru_ring_inv
 *
 * Finds the inverse of a polynomial, a, in (Z/2^rZ)[X]/(X^N - 1).
 *
 * This assumes q is 2^r where 8 < r < 16, so that operations mod q can
 * wait until the end, and only 16-bit arrays need to be used.
 */

extern bool
ntru_ring_inv(
    uint16_t *a,      /*  in - pointer to polynomial a */
    uint16_t N,       /*  in - no. of coefficients in a */
    uint16_t *t,      /*  in - temp buffer of 2N elements */
    uint16_t *a_inv); /* out - address for polynomial a^-1 */

/* ntru_ring_lift_inv_pow2_standard
 *
 * Lifts an element of (Z/2)[x]/(x^N - 1) to (Z/q)[x]/(x^N - 1)
 * where q is a power of 2 such that 256 < q <= 65536.
 *
 * inv must be padded with zeros to the degree used by
 * ntru_ring_mult_coefficients.
 *
 * inv is assumed to be the inverse mod 2 of the trinary element f.
 * The lift is performed in place -- inv will be overwritten with the result.
 *
 * Requires scratch space for ntru_ring_mult_coefficients + one extra
 * polynomial with the same padding.
 */
uint32_t
ntru_ring_lift_inv_pow2_standard(
    uint16_t *inv,
    uint16_t const *f,
    uint16_t const N,
    uint16_t const q,
    uint16_t *t);

/* ntru_ring_lift_inv_pow2_product
 *
 * Lifts an element of (Z/2)[x]/(x^N - 1) to (Z/q)[x]/(x^N - 1)
 * where q is a power of 2 such that 256 < q <= 65536.
 *
 * inv must be padded with zeros to the degree used by
 * ntru_ring_mult_coefficients.
 *
 * inv is assumed to be the inverse mod 2 of the product form element
 * given by (1 + 3*(F1*F2 + F3)). The lift is performed in place --
 * inv will be overwritten with the result.
 *
 * Requires scratch space for ntru_ring_mult_coefficients + one extra
 * polynomial with the same padding.
 */
uint32_t
ntru_ring_lift_inv_pow2_product(
    uint16_t *inv,
    uint16_t const dF1,
    uint16_t const dF2,
    uint16_t const dF3,
    uint16_t const *F_buf,
    uint16_t const N,
    uint16_t const q,
    uint16_t *t);

/* ntru_ring_mult_coefficients_memreq
 *
 * Different implementations of ntru_ring_mult_coefficients may
 * have different memory requirements.
 *
 * This gets the memory requirements of ntru_ring_mult_coefficients as
 * a number of scratch polynomials and the number of coefficients needed
 * per polynomial.
 */
void ntru_ring_mult_coefficients_memreq(
    uint16_t N,
    uint16_t *num_scratch_polys,
    uint16_t *pad_deg);

/* ntru_ring_mult_indices_memreq
 *
 * Different implementations of ntru_ring_mult_indices may
 * have different memory requirements.
 *
 * This gets the memory requirements of ntru_ring_mult_indices as
 * a number of scratch polynomials (num_scratch_polys) and the number
 * of coefficients needed per polynomial (pad_deg).
 *
 * Note that ntru_ring_mult_prod_indices requires one additional polynomial
 * of degree pad_deg for holding a temporary result.
 */
void ntru_ring_mult_indices_memreq(
    uint16_t N,
    uint16_t *num_scratch_polys,
    uint16_t *pad_deg);

#endif /* NTRU_CRYPTO_NTRU_POLY_H */
