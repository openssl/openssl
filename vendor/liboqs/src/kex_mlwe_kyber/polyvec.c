#include "params.h"

typedef struct {
	poly vec[KYBER_D];
#if defined(WINDOWS)
} polyvec;
#else
} polyvec __attribute__((aligned(32)));
#endif

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_D * 352))
static void polyvec_compress(unsigned char *r, const polyvec *a) {
	int i, j, k;
	uint16_t t[8];
	for (i = 0; i < KYBER_D; i++) {
		for (j = 0; j < KYBER_N / 8; j++) {
			for (k = 0; k < 8; k++)
				t[k] = ((((uint32_t) freeze(a->vec[i].coeffs[8 * j + k]) << 11) + KYBER_Q / 2) / KYBER_Q) & 0x7ff;

			r[11 * j + 0] = t[0] & 0xff;
			r[11 * j + 1] = (t[0] >> 8) | ((t[1] & 0x1f) << 3);
			r[11 * j + 2] = (t[1] >> 5) | ((t[2] & 0x03) << 6);
			r[11 * j + 3] = (t[2] >> 2) & 0xff;
			r[11 * j + 4] = (t[2] >> 10) | ((t[3] & 0x7f) << 1);
			r[11 * j + 5] = (t[3] >> 7) | ((t[4] & 0x0f) << 4);
			r[11 * j + 6] = (t[4] >> 4) | ((t[5] & 0x01) << 7);
			r[11 * j + 7] = (t[5] >> 1) & 0xff;
			r[11 * j + 8] = (t[5] >> 9) | ((t[6] & 0x3f) << 2);
			r[11 * j + 9] = (t[6] >> 6) | ((t[7] & 0x07) << 5);
			r[11 * j + 10] = (t[7] >> 3);
		}
		r += 352;
	}
}

static void polyvec_decompress(polyvec *r, const unsigned char *a) {
	int i, j;
	for (i = 0; i < KYBER_D; i++) {
		for (j = 0; j < KYBER_N / 8; j++) {
			r->vec[i].coeffs[8 * j + 0] = (((a[11 * j + 0] | (((uint32_t) a[11 * j + 1] & 0x07) << 8)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 1] = ((((a[11 * j + 1] >> 3) | (((uint32_t) a[11 * j + 2] & 0x3f) << 5)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 2] = ((((a[11 * j + 2] >> 6) | (((uint32_t) a[11 * j + 3] & 0xff) << 2) | (((uint32_t) a[11 * j + 4] & 0x01) << 10)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 3] = ((((a[11 * j + 4] >> 1) | (((uint32_t) a[11 * j + 5] & 0x0f) << 7)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 4] = ((((a[11 * j + 5] >> 4) | (((uint32_t) a[11 * j + 6] & 0x7f) << 4)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 5] = ((((a[11 * j + 6] >> 7) | (((uint32_t) a[11 * j + 7] & 0xff) << 1) | (((uint32_t) a[11 * j + 8] & 0x03) << 9)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 6] = ((((a[11 * j + 8] >> 2) | (((uint32_t) a[11 * j + 9] & 0x1f) << 6)) * KYBER_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 7] = ((((a[11 * j + 9] >> 5) | (((uint32_t) a[11 * j + 10] & 0xff) << 3)) * KYBER_Q) + 1024) >> 11;
		}
		a += 352;
	}
}

#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_D * 320))

static void polyvec_compress(unsigned char *r, const polyvec *a) {
	int i, j, k;
	uint16_t t[4];
	for (i = 0; i < KYBER_D; i++) {
		for (j = 0; j < KYBER_N / 4; j++) {
			for (k = 0; k < 4; k++)
				t[k] = ((((uint32_t) freeze(a->vec[i].coeffs[4 * j + k]) << 10) + KYBER_Q / 2) / KYBER_Q) & 0x3ff;

			r[5 * j + 0] = t[0] & 0xff;
			r[5 * j + 1] = (t[0] >> 8) | ((t[1] & 0x3f) << 2);
			r[5 * j + 2] = (t[1] >> 6) | ((t[2] & 0x0f) << 4);
			r[5 * j + 3] = (t[2] >> 4) | ((t[3] & 0x03) << 6);
			r[5 * j + 4] = (t[3] >> 2);
		}
		r += 320;
	}
}

static void polyvec_decompress(polyvec *r, const unsigned char *a) {
	int i, j;
	for (i = 0; i < KYBER_D; i++) {
		for (j = 0; j < KYBER_N / 4; j++) {
			r->vec[i].coeffs[4 * j + 0] = (((a[5 * j + 0] | (((uint32_t) a[5 * j + 1] & 0x03) << 8)) * KYBER_Q) + 512) >> 10;
			r->vec[i].coeffs[4 * j + 1] = ((((a[5 * j + 1] >> 2) | (((uint32_t) a[5 * j + 2] & 0x0f) << 6)) * KYBER_Q) + 512) >> 10;
			r->vec[i].coeffs[4 * j + 2] = ((((a[5 * j + 2] >> 4) | (((uint32_t) a[5 * j + 3] & 0x3f) << 4)) * KYBER_Q) + 512) >> 10;
			r->vec[i].coeffs[4 * j + 3] = ((((a[5 * j + 3] >> 6) | (((uint32_t) a[5 * j + 4] & 0xff) << 2)) * KYBER_Q) + 512) >> 10;
		}
		a += 320;
	}
}

#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_D * 288))

static void polyvec_compress(unsigned char *r, const polyvec *a) {
	int i, j, k;
	uint16_t t[8];
	for (i = 0; i < KYBER_D; i++) {
		for (j = 0; j < KYBER_N / 8; j++) {
			for (k = 0; k < 8; k++)
				t[k] = ((((uint32_t) freeze(a->vec[i].coeffs[8 * j + k]) << 9) + KYBER_Q / 2) / KYBER_Q) & 0x1ff;

			r[9 * j + 0] = t[0] & 0xff;
			r[9 * j + 1] = (t[0] >> 8) | ((t[1] & 0x7f) << 1);
			r[9 * j + 2] = (t[1] >> 7) | ((t[2] & 0x3f) << 2);
			r[9 * j + 3] = (t[2] >> 6) | ((t[3] & 0x1f) << 3);
			r[9 * j + 4] = (t[3] >> 5) | ((t[4] & 0x0f) << 4);
			r[9 * j + 5] = (t[4] >> 4) | ((t[5] & 0x07) << 5);
			r[9 * j + 6] = (t[5] >> 3) | ((t[6] & 0x03) << 6);
			r[9 * j + 7] = (t[6] >> 2) | ((t[7] & 0x01) << 7);
			r[9 * j + 8] = (t[7] >> 1);
		}
		r += 288;
	}
}

static void polyvec_decompress(polyvec *r, const unsigned char *a) {
	int i, j;
	for (i = 0; i < KYBER_D; i++) {
		for (j = 0; j < KYBER_N / 8; j++) {
			r->vec[i].coeffs[8 * j + 0] = (((a[9 * j + 0] | (((uint32_t) a[9 * j + 1] & 0x01) << 8)) * KYBER_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 1] = ((((a[9 * j + 1] >> 1) | (((uint32_t) a[9 * j + 2] & 0x03) << 7)) * KYBER_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 2] = ((((a[9 * j + 2] >> 2) | (((uint32_t) a[9 * j + 3] & 0x07) << 6)) * KYBER_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 3] = ((((a[9 * j + 3] >> 3) | (((uint32_t) a[9 * j + 4] & 0x0f) << 5)) * KYBER_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 4] = ((((a[9 * j + 4] >> 4) | (((uint32_t) a[9 * j + 5] & 0x1f) << 4)) * KYBER_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 5] = ((((a[9 * j + 5] >> 5) | (((uint32_t) a[9 * j + 6] & 0x3f) << 3)) * KYBER_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 6] = ((((a[9 * j + 6] >> 6) | (((uint32_t) a[9 * j + 7] & 0x7f) << 2)) * KYBER_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 7] = ((((a[9 * j + 7] >> 7) | (((uint32_t) a[9 * j + 8] & 0xff) << 1)) * KYBER_Q) + 256) >> 9;
		}
		a += 288;
	}
}

#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_D * 256))

static void polyvec_compress(unsigned char *r, const polyvec *a) {
	int i, j, k;
	uint16_t t;
	for (i = 0; i < KYBER_D; i++) {
		for (j = 0; j < KYBER_N; j++) {
			r[j] = ((((uint32_t) freeze(a->vec[i].coeffs[j]) << 8) + KYBER_Q / 2) / KYBER_Q) & 0xff;
		}
		r += 256;
	}
}

static void polyvec_decompress(polyvec *r, const unsigned char *a) {
	int i, j;
	for (i = 0; i < KYBER_D; i++) {
		for (j = 0; j < KYBER_N; j++) {
			r->vec[i].coeffs[j] = ((a[j] * KYBER_Q) + 128) >> 8;
		}
		a += 256;
	}
}

#else
#error "Unsupported compression of polyvec"
#endif

static void polyvec_tobytes(unsigned char *r, const polyvec *a) {
	int i;
	for (i = 0; i < KYBER_D; i++)
		poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
}

static void polyvec_frombytes(polyvec *r, const unsigned char *a) {
	int i;
	for (i = 0; i < KYBER_D; i++)
		poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
}

static void polyvec_ntt(polyvec *r) {
	int i;
	for (i = 0; i < KYBER_D; i++)
		poly_ntt(&r->vec[i]);
}

static void polyvec_invntt(polyvec *r) {
	int i;
	for (i = 0; i < KYBER_D; i++)
		poly_invntt(&r->vec[i]);
}

static void polyvec_pointwise_acc(poly *r, const polyvec *a, const polyvec *b) {
	int i, j;
	uint16_t t;
	for (j = 0; j < KYBER_N; j++) {
		t = montgomery_reduce(4613 * (uint32_t) b->vec[0].coeffs[j]); // 4613 = 2^{2*18} % q
		r->coeffs[j] = montgomery_reduce(a->vec[0].coeffs[j] * t);
		for (i = 1; i < KYBER_D; i++) {
			t = montgomery_reduce(4613 * (uint32_t) b->vec[i].coeffs[j]);
			r->coeffs[j] += montgomery_reduce(a->vec[i].coeffs[j] * t);
		}
		r->coeffs[j] = barrett_reduce(r->coeffs[j]);
	}
}

static void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b) {
	int i;
	for (i = 0; i < KYBER_D; i++)
		poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}
