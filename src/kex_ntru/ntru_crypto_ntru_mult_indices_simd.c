#include "ntru_crypto.h"
#include "ntru_crypto_ntru_poly.h"
#include <immintrin.h>

#define PAD(N) ((N + 0x0007) & 0xfff8)

void ntru_ring_mult_indices_memreq(
    uint16_t N,
    uint16_t *tmp_polys,
    uint16_t *poly_coeffs) {
	if (tmp_polys) {
		*tmp_polys = 2;
	}

	if (poly_coeffs) {
		*poly_coeffs = PAD(N);
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
	__m128i *T;
	__m128i *Tp;
	__m128i *Ti;

	uint16_t i;
	uint16_t j;
	uint16_t k;
	uint16_t m;
	uint16_t const mod_q_mask = q - 1;

	__m128i a0s[8];
	__m128i aNs[8];

	__m128i neg;
	__m128i x0;
	__m128i x1;
	__m128i x2;
	__m128i x3;
	__m128i x4;

	T = (__m128i *) t;
	memset(T, 0, 2 * PAD(N) * sizeof(uint16_t));

	a0s[0] = _mm_lddqu_si128((__m128i *) a);
	aNs[0] = _mm_lddqu_si128((__m128i *) (a + N - 8));
	for (i = 1; i < 8; i++) {
		a0s[i] = _mm_slli_si128(a0s[i - 1], 2);
		aNs[i] = _mm_srli_si128(aNs[i - 1], 2);
	}

	for (i = bi_P1_len; i < bi_P1_len + bi_M1_len; i++) {
		k = bi[i];
		m = k & 7;
		k /= 8;
		Tp = T + k;
		x2 = _mm_add_epi16(*Tp, a0s[m]);
		_mm_store_si128(Tp, x2);
		Tp++;
		for (j = 8 - m; j <= (N - 8); j += 8) {
			x3 = _mm_lddqu_si128((__m128i *) &a[j]);
			x2 = _mm_add_epi16(*Tp, x3);
			_mm_store_si128(Tp, x2);
			Tp++;
		}
		if (j == N)
			continue;
		x2 = _mm_add_epi16(*Tp, aNs[j - (N - 8)]);
		_mm_store_si128(Tp, x2);
	}

	neg = _mm_setzero_si128();
	neg = _mm_cmpeq_epi8(neg, neg);
	Tp = T;
	for (i = 0; i < (2 * PAD(N)) / 8; i++) {
		x1 = _mm_sign_epi16(*Tp, neg);
		_mm_store_si128(Tp, x1);
		Tp++;
	}

	for (i = 0; i < bi_P1_len; i++) {
		k = bi[i];
		m = k & 7;
		k /= 8;
		Tp = T + k;
		x2 = _mm_add_epi16(*Tp, a0s[m]);
		_mm_store_si128(Tp, x2);
		Tp++;
		for (j = 8 - m; j <= (N - 8); j += 8) {
			x3 = _mm_lddqu_si128((__m128i *) &a[j]);
			x2 = _mm_add_epi16(*Tp, x3);
			_mm_store_si128(Tp, x2);
			Tp++;
		}
		if (j == N)
			continue;
		x2 = _mm_add_epi16(*Tp, aNs[j - (N - 8)]);
		_mm_store_si128(Tp, x2);
	}

	Ti = T;
	Tp = (__m128i *) (((uint16_t *) T) + N);
	x0 = _mm_set1_epi16(mod_q_mask);
	for (j = 0; j < N; j += 8) {
		x1 = _mm_load_si128(Ti);
		x2 = _mm_lddqu_si128(Tp);
		x3 = _mm_add_epi16(x1, x2);
		x4 = _mm_and_si128(x3, x0);
		_mm_store_si128(Ti, x4);
		Ti++;
		Tp++;
	}
	memmove(c, T, N * sizeof(uint16_t));
	for (j = N; j < PAD(N); j++) {
		c[j] = 0;
	}

	return;
}
