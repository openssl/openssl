#include "params.h"
#include <oqs/sha3.h>

typedef struct {
	uint16_t coeffs[KYBER_N];
#if defined(WINDOWS)
} poly;
#else
} poly __attribute__((aligned(32)));
#endif

/* include cbd.c */
static uint32_t load_littleendian(const unsigned char *x) {
	return x[0] | (((uint32_t) x[1]) << 8) | (((uint32_t) x[2]) << 16) | (((uint32_t) x[3]) << 24);
}

static void cbd(poly *r, const unsigned char *buf) {
#if KYBER_K != 4
#error "poly_getnoise in poly.c only supports k=4"
#endif

	uint32_t t, d, a[4], b[4];
	int i, j;

	for (i = 0; i < KYBER_N / 4; i++) {
		t = load_littleendian(buf + 4 * i);
		d = 0;
		for (j = 0; j < 4; j++)
			d += (t >> j) & 0x11111111;

		a[0] = d & 0xf;
		b[0] = (d >> 4) & 0xf;
		a[1] = (d >> 8) & 0xf;
		b[1] = (d >> 12) & 0xf;
		a[2] = (d >> 16) & 0xf;
		b[2] = (d >> 20) & 0xf;
		a[3] = (d >> 24) & 0xf;
		b[3] = (d >> 28);

		r->coeffs[4 * i + 0] = a[0] + KYBER_Q - b[0];
		r->coeffs[4 * i + 1] = a[1] + KYBER_Q - b[1];
		r->coeffs[4 * i + 2] = a[2] + KYBER_Q - b[2];
		r->coeffs[4 * i + 3] = a[3] + KYBER_Q - b[3];
	}
}
/* end cbd.c */

static void poly_compress(unsigned char *r, const poly *a) {
	uint32_t t[8];
	unsigned int i, j, k = 0;

	for (i = 0; i < KYBER_N; i += 8) {
		for (j = 0; j < 8; j++)
			t[j] = (((freeze(a->coeffs[i + j]) << 3) + KYBER_Q / 2) / KYBER_Q) & 7;

		r[k] = t[0] | (t[1] << 3) | (t[2] << 6);
		r[k + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
		r[k + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
		k += 3;
	}
}

static void poly_decompress(poly *r, const unsigned char *a) {
	unsigned int i;
	for (i = 0; i < KYBER_N; i += 8) {
		r->coeffs[i + 0] = (((a[0] & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 1] = ((((a[0] >> 3) & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 2] = ((((a[0] >> 6) | ((a[1] << 2) & 4)) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 3] = ((((a[1] >> 1) & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 4] = ((((a[1] >> 4) & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 5] = ((((a[1] >> 7) | ((a[2] << 1) & 6)) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 6] = ((((a[2] >> 2) & 7) * KYBER_Q) + 4) >> 3;
		r->coeffs[i + 7] = ((((a[2] >> 5)) * KYBER_Q) + 4) >> 3;
		a += 3;
	}
}

static void poly_tobytes(unsigned char *r, const poly *a) {
	int i, j;
	uint16_t t[8];

	for (i = 0; i < KYBER_N / 8; i++) {
		for (j = 0; j < 8; j++)
			t[j] = freeze(a->coeffs[8 * i + j]);

		r[13 * i + 0] = t[0] & 0xff;
		r[13 * i + 1] = (t[0] >> 8) | ((t[1] & 0x07) << 5);
		r[13 * i + 2] = (t[1] >> 3) & 0xff;
		r[13 * i + 3] = (t[1] >> 11) | ((t[2] & 0x3f) << 2);
		r[13 * i + 4] = (t[2] >> 6) | ((t[3] & 0x01) << 7);
		r[13 * i + 5] = (t[3] >> 1) & 0xff;
		r[13 * i + 6] = (t[3] >> 9) | ((t[4] & 0x0f) << 4);
		r[13 * i + 7] = (t[4] >> 4) & 0xff;
		r[13 * i + 8] = (t[4] >> 12) | ((t[5] & 0x7f) << 1);
		r[13 * i + 9] = (t[5] >> 7) | ((t[6] & 0x03) << 6);
		r[13 * i + 10] = (t[6] >> 2) & 0xff;
		r[13 * i + 11] = (t[6] >> 10) | ((t[7] & 0x1f) << 3);
		r[13 * i + 12] = (t[7] >> 5);
	}
}

static void poly_frombytes(poly *r, const unsigned char *a) {
	int i;
	for (i = 0; i < KYBER_N / 8; i++) {
		r->coeffs[8 * i + 0] = a[13 * i + 0] | (((uint16_t) a[13 * i + 1] & 0x1f) << 8);
		r->coeffs[8 * i + 1] = (a[13 * i + 1] >> 5) | (((uint16_t) a[13 * i + 2]) << 3) | (((uint16_t) a[13 * i + 3] & 0x03) << 11);
		r->coeffs[8 * i + 2] = (a[13 * i + 3] >> 2) | (((uint16_t) a[13 * i + 4] & 0x7f) << 6);
		r->coeffs[8 * i + 3] = (a[13 * i + 4] >> 7) | (((uint16_t) a[13 * i + 5]) << 1) | (((uint16_t) a[13 * i + 6] & 0x0f) << 9);
		r->coeffs[8 * i + 4] = (a[13 * i + 6] >> 4) | (((uint16_t) a[13 * i + 7]) << 4) | (((uint16_t) a[13 * i + 8] & 0x01) << 12);
		r->coeffs[8 * i + 5] = (a[13 * i + 8] >> 1) | (((uint16_t) a[13 * i + 9] & 0x3f) << 7);
		r->coeffs[8 * i + 6] = (a[13 * i + 9] >> 6) | (((uint16_t) a[13 * i + 10]) << 2) | (((uint16_t) a[13 * i + 11] & 0x07) << 10);
		r->coeffs[8 * i + 7] = (a[13 * i + 11] >> 3) | (((uint16_t) a[13 * i + 12]) << 5);
	}
}

static void poly_getnoise(poly *r, const unsigned char *seed, unsigned char nonce) {
	unsigned char buf[KYBER_N];

	OQS_SHA3_cshake128_simple(buf, KYBER_N, nonce, seed, KYBER_NOISESEEDBYTES);

	cbd(r, buf);
}

static void poly_ntt(poly *r) {
	mul_coefficients(r->coeffs, oqs_kex_mlwe_kyber_psis_bitrev_montgomery);
	ntt(r->coeffs, oqs_kex_mlwe_kyber_omegas_montgomery);
}

static void poly_invntt(poly *r) {
	bitrev_vector(r->coeffs);
	ntt(r->coeffs, oqs_kex_mlwe_kyber_omegas_inv_bitrev_montgomery);
	mul_coefficients(r->coeffs, oqs_kex_mlwe_kyber_psis_inv_montgomery);
}

static void poly_add(poly *r, const poly *a, const poly *b) {
	int i;
	for (i = 0; i < KYBER_N; i++)
		r->coeffs[i] = barrett_reduce(a->coeffs[i] + b->coeffs[i]);
}

static void poly_sub(poly *r, const poly *a, const poly *b) {
	int i;
	for (i = 0; i < KYBER_N; i++)
		r->coeffs[i] = barrett_reduce(a->coeffs[i] + 3 * KYBER_Q - b->coeffs[i]);
}

static void poly_frommsg(poly *r, const unsigned char msg[KYBER_SHAREDKEYBYTES]) {
	uint16_t i, j, mask;

	for (i = 0; i < KYBER_SHAREDKEYBYTES; i++) {
		for (j = 0; j < 8; j++) {
			mask = -((msg[i] >> j) & 1);
			r->coeffs[8 * i + j] = mask & ((KYBER_Q + 1) / 2);
		}
	}
}

static void poly_tomsg(unsigned char msg[KYBER_SHAREDKEYBYTES], const poly *a) {
	uint16_t t;
	int i, j;

	for (i = 0; i < KYBER_SHAREDKEYBYTES; i++) {
		msg[i] = 0;
		for (j = 0; j < 8; j++) {
			t = (((freeze(a->coeffs[8 * i + j]) << 1) + KYBER_Q / 2) / KYBER_Q) & 1;
			msg[i] |= t << j;
		}
	}
}
