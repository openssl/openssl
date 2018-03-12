#include "ntru_crypto.h"
#include "ntru_crypto_ntru_poly.h"

#define PAD(N) ((N + 0x000f) & 0xfff0)

static void
grade_school_mul(
    uint16_t *res1,    /* out - a * b in Z[x], must be length 2N */
    uint16_t const *a, /*  in - polynomial */
    uint16_t const *b, /*  in - polynomial */
    uint16_t const N)  /*  in - number of coefficients in a and b */
{
	uint16_t i;
	uint16_t j;

	for (j = 0; j < N; j++) {
		res1[j] = a[0] * b[j];
	}
	for (i = 1; i < N; i++) {
		res1[i + N - 1] = 0;
		for (j = 0; j < N; j++) {
			res1[i + j] += a[i] * b[j];
		}
	}
	res1[2 * N - 1] = 0;

	return;
}

static void
karatsuba(
    uint16_t *res1,    /* out - a * b in Z[x], must be length 2k */
    uint16_t *tmp1,    /*  in - k coefficients of scratch space */
    uint16_t const *a, /*  in - polynomial */
    uint16_t const *b, /*  in - polynomial */
    uint16_t const k)  /*  in - number of coefficients in a and b */
{
	uint16_t i;

	uint16_t const p = k >> 1;

	uint16_t *res2;
	uint16_t *res3;
	uint16_t *res4;
	uint16_t *tmp2;
	uint16_t const *a2;
	uint16_t const *b2;

	/* Grade school multiplication for small / odd inputs */
	if (k <= 38 || (k & 1) != 0) {
		grade_school_mul(res1, a, b, k);
		return;
	}

	res2 = res1 + p;
	res3 = res1 + k;
	res4 = res1 + k + p;
	tmp2 = tmp1 + p;
	a2 = a + p;
	b2 = b + p;

	for (i = 0; i < p; i++) {
		res1[i] = a[i] - a2[i];
		res2[i] = b2[i] - b[i];
	}

	karatsuba(tmp1, res3, res1, res2, p);

	karatsuba(res3, res1, a2, b2, p);

	for (i = 0; i < p; i++) {
		tmp1[i] += res3[i];
	}

	for (i = 0; i < p; i++) {
		res2[i] = tmp1[i];
		tmp2[i] += res4[i];
		res3[i] += tmp2[i];
	}

	karatsuba(tmp1, res1, a, b, p);

	for (i = 0; i < p; i++) {
		res1[i] = tmp1[i];
		res2[i] += tmp1[i] + tmp2[i];
		res3[i] += tmp2[i];
	}

	return;
}

void ntru_ring_mult_coefficients_memreq(
    uint16_t N,
    uint16_t *tmp_polys,
    uint16_t *poly_coeffs) {
	if (tmp_polys) {
		*tmp_polys = 3;
	}

	if (poly_coeffs) {
		*poly_coeffs = PAD(N);
	}
}

/* ntru_ring_mult_coefficients
 *
 * Multiplies ring element (polynomial) "a" by ring element (polynomial) "b"
 * to produce ring element (polynomial) "c" in (Z/qZ)[X]/(X^N - 1).
 * This is a convolution operation.
 *
 * This assumes q is 2^r where 8 < r < 16, so that overflow of the sum
 * beyond 16 bits does not matter.
 */

void ntru_ring_mult_coefficients(
    uint16_t const *a, /*  in - pointer to polynomial a */
    uint16_t const *b, /*  in - pointer to polynomial b */
    uint16_t N,        /*  in - degree of (x^N - 1) */
    uint16_t q,        /*  in - large modulus */
    uint16_t *tmp,     /*  in - temp buffer of 3*padN elements */
    uint16_t *c)       /* out - address for polynomial c */
{
	uint16_t i;
	uint16_t q_mask = q - 1;

	memset(tmp, 0, 3 * PAD(N) * sizeof(uint16_t));
	karatsuba(tmp, tmp + 2 * PAD(N), a, b, PAD(N));

	for (i = 0; i < N; i++) {
		c[i] = (tmp[i] + tmp[i + N]) & q_mask;
	}
	for (; i < PAD(N); i++) {
		c[i] = 0;
	}

	return;
}
