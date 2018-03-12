#include "ntru_crypto.h"
#include "ntru_crypto_ntru_poly.h"

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
	uint16_t mod_q_mask;
	uint32_t mask_interval;
	uint16_t iA, iT, iB; /* Loop variables for the relevant arrays */
	uint16_t mask_time;
	uint16_t end;

	uint32_t tmp1;
	uint32_t tmp2;

	end = N & 0xfffe; /* 4 * floor((N-i)/4) */

	mod_q_mask = q - 1;
	mask_interval = ((1 << 16) / q);
	mask_time = 0;

	/* t[(i+k)%N] = sum i=0 through N-1 of a[i], for b[k] = -1 */
	memset(t, 0, N * sizeof(uint16_t));
	for (iB = bi_P1_len; iB < bi_P1_len + bi_M1_len; iB++) {
		/* first half -- iT from bi[iB] to N
                         iA from 0 to N - bi[iB] */
		iT = bi[iB];

		for (iA = 0; iT < end; iA += 2, iT += 2) {
			memcpy(&tmp1, t + iT, sizeof tmp1);
			memcpy(&tmp2, a + iA, sizeof tmp2);
			tmp1 += tmp2;
			memcpy(t + iT, &tmp1, sizeof tmp1);
		}

		if (iT < N) {
			t[iT] += a[iA];
			iT++;
			iA++;
		}

		/* second half -- iT from 0 to bi[iB]
                          iA from bi[iB] to N  */

		for (iT = 0; iA < end; iA += 2, iT += 2) {
			memcpy(&tmp1, t + iT, sizeof tmp1);
			memcpy(&tmp2, a + iA, sizeof tmp2);
			tmp1 += tmp2;
			memcpy(t + iT, &tmp1, sizeof tmp1);
		}

		if (iA < N) {
			t[iT] += a[iA];
			iT++;
			iA++;
		}

		mask_time++;
		if (mask_time == mask_interval) {
			for (iT = 0; iT < N; iT++) {
				t[iT] &= mod_q_mask;
			}
			mask_time = 0;
		}
	} /* for (iB = 0; iB < bi_M1_len; iB++) -- minus-index loop */

	/* Minus everything */
	for (iT = 0; iT < N; iT++) {
		t[iT] = -t[iT];
		t[iT] &= mod_q_mask;
	}
	mask_time = 0;

	for (iB = 0; iB < bi_P1_len; iB++) {
		/* first half -- iT from bi[iB] to N
                         iA from 0 to N - bi[iB] */
		iT = bi[iB];

		for (iA = 0; iT < end; iA += 2, iT += 2) {
			memcpy(&tmp1, t + iT, sizeof tmp1);
			memcpy(&tmp2, a + iA, sizeof tmp2);
			tmp1 += tmp2;
			memcpy(t + iT, &tmp1, sizeof tmp1);
		}

		if (iT < N) {
			t[iT] += a[iA];
			iT++;
			iA++;
		}

		/* second half -- iT from 0 to bi[iB]
                          iA from bi[iB] to N  */
		for (iT = 0; iA < end; iA += 2, iT += 2) {
			memcpy(&tmp1, t + iT, sizeof tmp1);
			memcpy(&tmp2, a + iA, sizeof tmp2);
			tmp1 += tmp2;
			memcpy(t + iT, &tmp1, sizeof tmp1);
		}

		if (iA < N) {
			t[iT] += a[iA];
			iT++;
			iA++;
		}

		mask_time++;
		if (mask_time == mask_interval) {
			for (iT = 0; iT < N; iT++) {
				t[iT] &= mod_q_mask;
			}
			mask_time = 0;
		}

	} /* for (iB = 0; iB < bi_P1_len; iB++) -- plus-index loop */

	/* c = (a * b) mod q */
	for (iT = 0; iT < N; iT++) {
		c[iT] = t[iT] & mod_q_mask;
	}

	return;
}
