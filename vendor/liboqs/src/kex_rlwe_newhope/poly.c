#include "params.h"
#include <oqs/rand.h>

typedef struct {
	uint16_t coeffs[PARAM_N];
#if defined(WINDOWS)
} poly;
#else
} poly __attribute__((aligned(32)));
#endif


static const uint32_t qinv = 12287; // -inverse_mod(p,2^18)
static const uint32_t rlog = 18;

static uint16_t montgomery_reduce(uint32_t a) {
	uint32_t u;

	u = (a * qinv);
	u &= ((1 << rlog) - 1);
	u *= PARAM_Q;
	a = a + u;
	return a >> 18;
}

static uint16_t barrett_reduce(uint16_t a) {
	uint32_t u;

	u = ((uint32_t) a * 5) >> 16;
	u *= PARAM_Q;
	a -= u;
	return a;
}

static void bitrev_vector(uint16_t *poly) {
	unsigned int i, r;
	uint16_t tmp;

	for (i = 0; i < PARAM_N; i++) {
		r = bitrev_table[i];
		if (i < r) {
			tmp = poly[i];
			poly[i] = poly[r];
			poly[r] = tmp;
		}
	}
}

static void mul_coefficients(uint16_t *poly, const uint16_t *factors) {
	unsigned int i;

	for (i = 0; i < PARAM_N; i++) {
		poly[i] = montgomery_reduce((poly[i] * factors[i]));
	}
}



/* GS_bo_to_no; omegas need to be in Montgomery domain */
static void ntt(uint16_t *a, const uint16_t *omega) {
	int i, start, j, jTwiddle, distance;
	uint16_t temp, W;


	for (i = 0; i < 10; i += 2) {
		// Even level
		distance = (1 << i);
		for (start = 0; start < distance; start++) {
			jTwiddle = 0;
			for (j = start; j < PARAM_N - 1; j += 2 * distance) {
				W = omega[jTwiddle++];
				temp = a[j];
				a[j] = (temp + a[j + distance]); // Omit reduction (be lazy)
				a[j + distance] = montgomery_reduce((W * ((uint32_t)temp + 3 * PARAM_Q - a[j + distance])));
			}
		}

		// Odd level
		distance <<= 1;
		for (start = 0; start < distance; start++) {
			jTwiddle = 0;
			for (j = start; j < PARAM_N - 1; j += 2 * distance) {
				W = omega[jTwiddle++];
				temp = a[j];
				a[j] = barrett_reduce((temp + a[j + distance]));
				a[j + distance] = montgomery_reduce((W * ((uint32_t)temp + 3 * PARAM_Q - a[j + distance])));
			}
		}
	}
}

static void poly_frombytes(poly *r, const unsigned char *a) {
	int i;
	for (i = 0; i < PARAM_N / 4; i++) {
		r->coeffs[4 * i + 0] =                               a[7 * i + 0]        | (((uint16_t)a[7 * i + 1] & 0x3f) << 8);
		r->coeffs[4 * i + 1] = (a[7 * i + 1] >> 6) | (((uint16_t)a[7 * i + 2]) << 2) | (((uint16_t)a[7 * i + 3] & 0x0f) << 10);
		r->coeffs[4 * i + 2] = (a[7 * i + 3] >> 4) | (((uint16_t)a[7 * i + 4]) << 4) | (((uint16_t)a[7 * i + 5] & 0x03) << 12);
		r->coeffs[4 * i + 3] = (a[7 * i + 5] >> 2) | (((uint16_t)a[7 * i + 6]) << 6);
	}
}

static void poly_tobytes(unsigned char *r, const poly *p) {
	int i;
	uint16_t t0, t1, t2, t3, m;
	int16_t c;
	for (i = 0; i < PARAM_N / 4; i++) {
		t0 = barrett_reduce(p->coeffs[4 * i + 0]); //Make sure that coefficients have only 14 bits
		t1 = barrett_reduce(p->coeffs[4 * i + 1]);
		t2 = barrett_reduce(p->coeffs[4 * i + 2]);
		t3 = barrett_reduce(p->coeffs[4 * i + 3]);

		m = t0 - PARAM_Q;
		c = m;
		c >>= 15;
		t0 = m ^ ((t0 ^ m)&c); // <Make sure that coefficients are in [0,q]

		m = t1 - PARAM_Q;
		c = m;
		c >>= 15;
		t1 = m ^ ((t1 ^ m)&c); // <Make sure that coefficients are in [0,q]

		m = t2 - PARAM_Q;
		c = m;
		c >>= 15;
		t2 = m ^ ((t2 ^ m)&c); // <Make sure that coefficients are in [0,q]

		m = t3 - PARAM_Q;
		c = m;
		c >>= 15;
		t3 = m ^ ((t3 ^ m)&c); // <Make sure that coefficients are in [0,q]

		r[7 * i + 0] =  t0 & 0xff;
		r[7 * i + 1] = (t0 >> 8) | (t1 << 6);
		r[7 * i + 2] = (t1 >> 2);
		r[7 * i + 3] = (t1 >> 10) | (t2 << 4);
		r[7 * i + 4] = (t2 >> 4);
		r[7 * i + 5] = (t2 >> 12) | (t3 << 2);
		r[7 * i + 6] = (t3 >> 6);
	}
}

static void poly_uniform(poly *a, const unsigned char *seed) {
	unsigned int pos = 0, ctr = 0;
	uint16_t val;
	uint64_t state[OQS_SHA3_STATESIZE];
	unsigned int nblocks = 16;
	uint8_t buf[OQS_SHA3_SHAKE128_RATE * 16];

	OQS_SHA3_shake128_absorb(state, seed, NEWHOPE_SEEDBYTES);

	OQS_SHA3_shake128_squeezeblocks((unsigned char *) buf, nblocks, state);

	while (ctr < PARAM_N) {
		val = (buf[pos] | ((uint16_t) buf[pos + 1] << 8)) & 0x3fff; // Specialized for q = 12889
		if (val < PARAM_Q) {
			a->coeffs[ctr++] = val;
		}
		pos += 2;
		if (pos > OQS_SHA3_SHAKE128_RATE * nblocks - 2) {
			nblocks = 1;
			OQS_SHA3_shake128_squeezeblocks((unsigned char *) buf, nblocks, state);
			pos = 0;
		}
	}
}


static void poly_getnoise(poly *r, OQS_RAND *rand) {
#if PARAM_K != 16
#error "poly_getnoise in poly.c only supports k=16"
#endif

	unsigned char buf[4 * PARAM_N];
	uint32_t *tp, t, d, a, b;
	int i, j;

	tp = (uint32_t *) buf;

	rand->rand_n(rand, buf, 4 * PARAM_N);

	for (i = 0; i < PARAM_N; i++) {
		t = tp[i];
		d = 0;
		for (j = 0; j < 8; j++) {
			d += (t >> j) & 0x01010101;
		}
		a = ((d >> 8) & 0xff) + (d & 0xff);
		b = (d >> 24) + ((d >> 16) & 0xff);
		r->coeffs[i] = a + PARAM_Q - b;
	}
}

static void poly_pointwise(poly *r, const poly *a, const poly *b) {
	int i;
	uint16_t t;
	for (i = 0; i < PARAM_N; i++) {
		t       = montgomery_reduce(3186 * b->coeffs[i]); /* t is now in Montgomery domain */
		r->coeffs[i] = montgomery_reduce(a->coeffs[i] * t); /* r->coeffs[i] is back in normal domain */
	}
}

static void poly_add(poly *r, const poly *a, const poly *b) {
	int i;
	for (i = 0; i < PARAM_N; i++) {
		r->coeffs[i] = barrett_reduce(a->coeffs[i] + b->coeffs[i]);
	}
}

static void poly_ntt(poly *r) {
	mul_coefficients(r->coeffs, psis_bitrev_montgomery);
	ntt((uint16_t *)r->coeffs, omegas_montgomery);
}

static void poly_invntt(poly *r) {
	bitrev_vector(r->coeffs);
	ntt((uint16_t *)r->coeffs, omegas_inv_montgomery);
	mul_coefficients(r->coeffs, psis_inv_montgomery);
}


//Error Correction:

static int32_t nh_abs(int32_t v) {
	int32_t mask = v >> 31;
	return (v ^ mask) - mask;
}


static int32_t f(int32_t *v0, int32_t *v1, int32_t x) {
	int32_t xit, t, r, b;

	// Next 6 lines compute t = x/PARAM_Q;
	b = x * 2730;
	t = b >> 25;
	b = x - t * 12289;
	b = 12288 - b;
	b >>= 31;
	t -= b;

	r = t & 1;
	xit = (t >> 1);
	*v0 = xit + r; // v0 = round(x/(2*PARAM_Q))

	t -= 1;
	r = t & 1;
	*v1 = (t >> 1) + r;

	return nh_abs(x - ((*v0) * 2 * PARAM_Q));
}

static int32_t g(int32_t x) {
	int32_t t, c, b;

	// Next 6 lines compute t = x/(4*PARAM_Q);
	b = x * 2730;
	t = b >> 27;
	b = x - t * 49156;
	b = 49155 - b;
	b >>= 31;
	t -= b;

	c = t & 1;
	t = (t >> 1) + c; // t = round(x/(8*PARAM_Q))

	t *= 8 * PARAM_Q;

	return nh_abs(t - x);
}


static int16_t LDDecode(int32_t xi0, int32_t xi1, int32_t xi2, int32_t xi3) {
	int32_t t;

	t  = g(xi0);
	t += g(xi1);
	t += g(xi2);
	t += g(xi3);

	t -= 8 * PARAM_Q;
	t >>= 31;
	return t & 1;
}


static void helprec(poly *c, const poly *v, OQS_RAND *oqs_rand) {
	int32_t v0[4], v1[4], v_tmp[4], k;
	unsigned char rbit;
	unsigned char rand[32];
	int i;

	oqs_rand->rand_n(oqs_rand, rand, 32);

	for (i = 0; i < 256; i++) {
		rbit = (rand[i >> 3] >> (i & 7)) & 1;

		k  = f(v0 + 0, v1 + 0, 8 * v->coeffs[  0 + i] + 4 * rbit);
		k += f(v0 + 1, v1 + 1, 8 * v->coeffs[256 + i] + 4 * rbit);
		k += f(v0 + 2, v1 + 2, 8 * v->coeffs[512 + i] + 4 * rbit);
		k += f(v0 + 3, v1 + 3, 8 * v->coeffs[768 + i] + 4 * rbit);

		k = (2 * PARAM_Q - 1 - k) >> 31;

		v_tmp[0] = ((~k) & v0[0]) ^ (k & v1[0]);
		v_tmp[1] = ((~k) & v0[1]) ^ (k & v1[1]);
		v_tmp[2] = ((~k) & v0[2]) ^ (k & v1[2]);
		v_tmp[3] = ((~k) & v0[3]) ^ (k & v1[3]);

		c->coeffs[  0 + i] = (v_tmp[0] -   v_tmp[3]) & 3;
		c->coeffs[256 + i] = (v_tmp[1] -   v_tmp[3]) & 3;
		c->coeffs[512 + i] = (v_tmp[2] -   v_tmp[3]) & 3;
		c->coeffs[768 + i] = (   -k    + 2 * v_tmp[3]) & 3;
	}
}


static void rec(unsigned char *key, const poly *v, const poly *c) {
	int i;
	int32_t tmp[4];

	for (i = 0; i < 32; i++) {
		key[i] = 0;
	}

	for (i = 0; i < 256; i++) {
		tmp[0] = 16 * PARAM_Q + 8 * (int32_t)v->coeffs[  0 + i] - PARAM_Q * (2 * c->coeffs[  0 + i] + c->coeffs[768 + i]);
		tmp[1] = 16 * PARAM_Q + 8 * (int32_t)v->coeffs[256 + i] - PARAM_Q * (2 * c->coeffs[256 + i] + c->coeffs[768 + i]);
		tmp[2] = 16 * PARAM_Q + 8 * (int32_t)v->coeffs[512 + i] - PARAM_Q * (2 * c->coeffs[512 + i] + c->coeffs[768 + i]);
		tmp[3] = 16 * PARAM_Q + 8 * (int32_t)v->coeffs[768 + i] - PARAM_Q * (              c->coeffs[768 + i]);

		key[i >> 3] |= LDDecode(tmp[0], tmp[1], tmp[2], tmp[3]) << (i & 7);
	}
}
