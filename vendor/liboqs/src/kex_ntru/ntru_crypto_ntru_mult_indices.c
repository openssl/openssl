#include "ntru_crypto.h"
#include "ntru_crypto_ntru_poly.h"

void ntru_ring_mult_indices_memreq(
    uint16_t N,
    uint16_t *tmp_polys,
    uint16_t *poly_coeffs) {
	if (tmp_polys) {
		*tmp_polys = 1;
	}

	if (poly_coeffs) {
		*poly_coeffs = N;
	}
}

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
 * input array "b", or temp array "t".
 *
 * This assumes q is 2^r where 8 < r < 16, so that overflow of the sum
 * beyond 16 bits does not matter.
 */

void ntru_ring_mult_indices(
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
    uint16_t *t,              /*  in - temp buffer of N elements */
    uint16_t *c)              /* out - address for polynomial c */
{
	uint16_t mod_q_mask = q - 1;
	uint16_t i, j, k;

	/* t[(i+k)%N] = sum i=0 through N-1 of a[i], for b[k] = -1 */

	for (k = 0; k < N; k++) {
		t[k] = 0;
	}

	for (j = bi_P1_len; j < bi_P1_len + bi_M1_len; j++) {
		k = bi[j];

		for (i = 0; k < N; ++i, ++k) {
			t[k] = t[k] + a[i];
		}

		for (k = 0; i < N; ++i, ++k) {
			t[k] = t[k] + a[i];
		}
	}

	/* t[(i+k)%N] = -(sum i=0 through N-1 of a[i] for b[k] = -1) */

	for (k = 0; k < N; k++) {
		t[k] = -t[k];
	}

	/* t[(i+k)%N] += sum i=0 through N-1 of a[i] for b[k] = +1 */

	for (j = 0; j < bi_P1_len; j++) {
		k = bi[j];

		for (i = 0; k < N; ++i, ++k) {
			t[k] = t[k] + a[i];
		}

		for (k = 0; i < N; ++i, ++k) {
			t[k] = t[k] + a[i];
		}
	}

	/* c = (a * b) mod q */

	for (k = 0; k < N; k++) {
		c[k] = t[k] & mod_q_mask;
	}

	return;
}
