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
 * File: ntru_crypto_ntru_poly.c
 *
 * Contents: Routines for generating and operating on polynomials in the
 *           NTRU algorithm.
 *
 *****************************************************************************/

#include "ntru_crypto.h"
#include "ntru_crypto_ntru_poly.h"
#include "ntru_crypto_ntru_mgf1.h"

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

uint32_t
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
    uint16_t *indices)                 /* out - address for indices */
{
	uint8_t *mgf_out;
	uint8_t *octets;
	uint8_t *used;
	uint8_t num_polys;
	uint16_t num_indices;
	uint16_t octets_available;
	uint16_t index_cnt = 0;
	uint8_t left = 0;
	uint8_t num_left = 0;
	uint32_t retcode;

	/* generate minimum MGF1 output */

	mgf_out = buf + md_len + 4;
	if ((retcode = ntru_mgf1(buf, hash_algid, md_len, min_calls,
	                         seed_len, seed, mgf_out)) != NTRU_OK) {
		return retcode;
	}

	octets = mgf_out;
	octets_available = min_calls * md_len;

	/* init indices counts for number of polynomials being generated */

	if (is_product_form) {
		/* number of indices for poly1 is in low byte of indices_counts,
         * number of indices for poly2 and poly3 are in next higher bytes
         */

		num_polys = 3;
		num_indices = (uint16_t)(indices_counts & 0xff);
		indices_counts >>= 8;

	} else {
		/* number of bytes for poly is in low 16 bits of indices_counts */

		num_polys = 1;
		num_indices = (uint16_t) indices_counts;
	}

	/* init used-index array */

	used = mgf_out + octets_available;
	memset(used, 0, N);

	/* generate indices (IGF-2) for all polynomials */

	while (num_polys > 0) {

		/* generate indices for a single polynomial */

		while (index_cnt < num_indices) {
			uint16_t index;
			uint8_t num_needed;

			/* form next index to convert to an index */

			do {
				/* use any leftover bits first */

				if (num_left != 0) {
					index = left << (c_bits - num_left);
				} else {
					index = 0;
				}

				/* get the rest of the bits needed from new octets */

				num_needed = c_bits - num_left;
				while (num_needed != 0) {
					/* get another octet */

					if (octets_available == 0) {
						if ((retcode = ntru_mgf1(buf, hash_algid, md_len, 1,
						                         0, NULL, mgf_out)) != NTRU_OK) {
							return retcode;
						}

						octets = mgf_out;
						octets_available = md_len;
					}
					left = *octets++;
					--octets_available;

					if (num_needed <= 8) {
						/* all bits needed to fill the index are in this octet */

						index |= ((uint16_t)(left)) >> (8 - num_needed);
						num_left = 8 - num_needed;
						num_needed = 0;
						left &= 0xff >> (8 - num_left);

					} else {
						/* another octet will be needed after using this
                         * whole octet
                         */

						index |= ((uint16_t) left) << (num_needed - 8);
						num_needed -= 8;
					}
				}
			} while (index >= limit);

			/* form index and check if unique */

			index %= N;

			if (!used[index]) {
				used[index] = 1;
				indices[index_cnt] = index;
				++index_cnt;
			}
		}
		--num_polys;

		/* init for next polynomial if another polynomial to be generated */

		if (num_polys > 0) {
			memset(used, 0, N);
			num_indices = num_indices +
			              (uint16_t)(indices_counts & 0xff);
			indices_counts >>= 8;
		}
	}

	NTRU_RET(NTRU_OK);
}

/* ntru_poly_check_min_weight
 *
 * Checks that the number of 0, +1, and -1 trinary ring elements meet or exceed
 * a minimum weight.
 */

bool ntru_poly_check_min_weight(
    uint16_t num_els, /*  in - degree of polynomial */
    uint8_t *ringels, /*  in - pointer to trinary ring elements */
    uint16_t min_wt)  /*  in - minimum weight */
{
	uint16_t wt[3];
	uint16_t i;

	wt[0] = wt[1] = wt[2] = 0;

	for (i = 0; i < num_els; i++) {
		++wt[ringels[i]];
	}

	if ((wt[0] < min_wt) || (wt[1] < min_wt) || (wt[2] < min_wt)) {
		return FALSE;
	}

	return TRUE;
}

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

void ntru_ring_mult_product_indices(
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
    uint16_t *t,            /*  in - temp buffer of 2N elements */
    uint16_t *c)            /* out - address for polynomial c */
{
	uint16_t scratch_polys;
	uint16_t poly_coeffs;
	uint16_t *t2;
	uint16_t mod_q_mask;
	uint16_t i;

	ntru_ring_mult_indices_memreq(N, &scratch_polys, &poly_coeffs);
	t2 = t + scratch_polys * poly_coeffs;
	mod_q_mask = q - 1;

	/* t2 = a * b1 */

	ntru_ring_mult_indices(a, b1i_len, b1i_len, bi, N, q, t, t2);

	/* t2 = (a * b1) * b2 */

	ntru_ring_mult_indices(t2, b2i_len, b2i_len, bi + (b1i_len << 1), N, q,
	                       t, t2);

	/* t = a * b3 */

	ntru_ring_mult_indices(a, b3i_len, b3i_len,
	                       bi + ((b1i_len + b2i_len) << 1), N, q, t, t);

	/* c = (a * b1 * b2) + (a * b3) */

	for (i = 0; i < N; i++) {
		c[i] = (t2[i] + t[i]) & mod_q_mask;
	}
	for (; i < poly_coeffs; i++) {
		c[i] = 0;
	}

	return;
}

/* ntru_ring_inv
 *
 * Finds the inverse of a polynomial, a, in (Z/2Z)[X]/(X^N - 1).
  */

bool ntru_ring_inv(
    uint16_t *a,     /*  in - pointer to polynomial a */
    uint16_t N,      /*  in - no. of coefficients in a */
    uint16_t *t,     /*  in - temp buffer of 2N elements */
    uint16_t *a_inv) /* out - address for polynomial a^-1 */
{
	uint8_t *b = (uint8_t *) t; /* b cannot be in a_inv since it must be
                                       rotated and copied there as a^-1 mod 2 */
	uint8_t *c = b + N;         /* c cannot be in a_inv since it exchanges
                                       with b, and b cannot be in a_inv */
	uint8_t *f = c + N;
	uint8_t *g = (uint8_t *) a_inv; /* g needs N + 1 bytes */
	uint16_t deg_b;
	uint16_t deg_c;
	uint16_t deg_f;
	uint16_t deg_g;
	uint16_t k = 0;
	uint16_t i, j;

	if (a == NULL || t == NULL || a_inv == NULL) {
		return FALSE;
	}

	/* form a^-1 in (Z/2Z)[X]/(X^N - 1) */

	memset(b, 0, (N << 1)); /* clear to init b, c */

	/* b(X) = 1 */

	b[0] = 1;
	deg_b = 0;

	/* c(X) = 0 (cleared above) */

	deg_c = 0;

	/* f(X) = a(X) mod 2 */

	deg_f = 0;
	j = 0;
	for (i = 0; i < N; i++) {
		f[i] = (uint8_t)(a[i] & 1);
		j ^= f[i];
		if (f[i])
			deg_f = i;
	}

	/* Parity is zero, not invertible */
	if (j == 0) {
		return FALSE;
	}

	/* g(X) = X^N - 1 */

	g[0] = 1;
	memset(g + 1, 0, N - 1);
	g[N] = 1;
	deg_g = N;

	/* until f(X) = 1 */

	while (1) {
		/* while f[0] = 0, f(X) /= X, c(X) *= X, k++ */

		for (i = 0; (i <= deg_f) && (f[i] == 0); ++i)
			;
		if (i > deg_f)
			return FALSE;
		if (i) {
			k = k + i;

			f = f + i;
			deg_f = deg_f - i;

			memmove(c + i, c, deg_c + 1);
			memset(c, 0, i);
			deg_c = deg_c + i;
		}

		/* if f(X) = 1, done */

		if (deg_f == 0) {
			break;
		}

		/* if deg_f < deg_g, f <-> g, b <-> c */

		if (deg_f < deg_g) {
			uint8_t *x;

			x = f;
			f = g;
			g = x;
			deg_f ^= deg_g;
			deg_g ^= deg_f;
			deg_f ^= deg_g;
			x = b;
			b = c;
			c = x;
			deg_b ^= deg_c;
			deg_c ^= deg_b;
			deg_b ^= deg_c;
		}

		/* f(X) += g(X)
         * might change degree of f if deg_g >= deg_f
         */
		for (i = 0; i <= deg_g; i++) {
			f[i] ^= g[i];
		}

		if (deg_g == deg_f) {
			while (deg_f > 0 && f[deg_f] == 0) {
				--deg_f;
			}
		}

		/* b(X) += c(X) */
		for (i = 0; i <= deg_c; i++) {
			b[i] ^= c[i];
		}

		if (deg_c >= deg_b) {
			deg_b = deg_c;
			while (deg_b > 0 && b[deg_b] == 0) {
				--deg_b;
			}
		}
	}

	/* a^-1 in (Z/2Z)[X]/(X^N - 1) = b(X) shifted left k coefficients */

	j = 0;

	if (k >= N) {
		k = k - N;
	}

	for (i = k; i < N; i++) {
		a_inv[j++] = (uint16_t)(b[i]);
	}

	for (i = 0; i < k; i++) {
		a_inv[j++] = (uint16_t)(b[i]);
	}

	return TRUE;
}

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
    uint16_t *t) {
	uint16_t i;
	uint16_t j;
	uint16_t mod_q_mask = q - 1;
	uint16_t padN;
	ntru_ring_mult_coefficients_memreq(N, NULL, &padN);

	for (j = 0; j < 4; ++j) /* assumes 256 < q <= 65536 */
	{
		/* f^-1 = f^-1 * (2 - f * f^-1) mod q */
		ntru_ring_mult_product_indices(inv, (uint16_t) dF1,
		                               (uint16_t) dF2, (uint16_t) dF3,
		                               F_buf, N, q,
		                               t, t);
		for (i = 0; i < N; ++i) {
			t[i] = -((inv[i] + 3 * t[i]) & mod_q_mask);
		}
		t[0] = t[0] + 2;
		/* mult_indices works with degree N, mult_coefficients with padN */
		memset(t + N, 0, (padN - N) * sizeof(uint16_t));

		ntru_ring_mult_coefficients(inv, t, N, q, t + padN, inv);
	}

	NTRU_RET(NTRU_OK);
}

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
    uint16_t *t) {
	uint16_t i;
	uint16_t j;
	uint16_t padN;
	ntru_ring_mult_coefficients_memreq(N, NULL, &padN);

	for (j = 0; j < 4; ++j) /* assumes 256 < q <= 65536 */
	{
		/* f^-1 = f^-1 * (2 - f * f^-1) mod q */
		ntru_ring_mult_coefficients(f, inv, N, q, t, t);
		for (i = 0; i < N; ++i) {
			t[i] = -t[i];
		}
		t[0] = t[0] + 2;

		ntru_ring_mult_coefficients(inv, t, N, q, t + padN, inv);
	}

	NTRU_RET(NTRU_OK);
}
