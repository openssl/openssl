/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#include <stdlib.h>
#include <string.h>

#include "fft.h"

/* Reduction modulo p = 2^32 - 1.
 * This is not a prime since 2^32-1 = (2^1+1)*(2^2+1)*(2^4+1)*(2^8+1)*(2^16+1).
 * But since 2 is a unit in Z/pZ we can use it for computing FFTs in
 * Z/pZ[X]/(X^(2^7)+1)
 */

/* Caution:
 * We use a redundant representation where the integer 0 is represented both
 * by 0 and 2^32-1.
 * This approach follows the describtion from the paper:
 * Joppe W. Bos, Craig Costello, Huseyin Hisil, and Kristin Lauter: Fast Cryptography in Genus 2
 * EUROCRYPT 2013, Lecture Notes in Computer Science 7881, pp. 194-210, Springer, 2013.
 * More specifically see: Section 3 related to Modular Addition/Subtraction.
 */

/* Compute: c = (a+b) mod (2^32-1)
 * Let, t = a+b = t_1*2^32 + t0, where 0 <= t_1 <= 1, 0 <= t_0 < 2^32.
 * Then t mod (2^32-1) = t0 + t1 */

/* NOTE:
 * Implementing this arithmetic in asm might significantly
 * increase performance.
 */

#define modadd(c,a,b) \
do { \
  uint32_t _t = a+b; \
  c = _t + (_t < a); \
} while (0)

#define modsub(c,a,b) c = (a-b) - (b > a)

#define modmul(c,a,b) \
do { \
  uint64_t _T = (uint64_t) a * (uint64_t) b; \
  modadd (c, ((uint32_t) _T), ((uint32_t) ((uint64_t) _T >> (uint64_t) 32))); \
} while (0)


#define modmuladd(c,a,b) \
do { \
  uint64_t _T = (uint64_t) a * (uint64_t) b + c; \
  modadd (c, ((uint32_t) _T), ((uint32_t) ((uint64_t) _T >> (uint64_t) 32))); \
} while (0)

#define div2(c,a) c= (uint32_t) (((uint64_t) (a) + (uint64_t) ((uint32_t)(0-((a)&1))&0xFFFFFFFF))>>1)
#define normalize(c,a) c = (a) + ((a) == 0xFFFFFFFF)

/* Define the basic building blocks for the FFT. */
#define DATATYPE uint32_t

#define SET_ZERO(x) (x)=0
#define add(c,a,b) modadd(c,a,b)
#define sub(c,a,b) modsub(c,a,b)
#define mul(c,a,b) modmul(c,a,b)
#define moddiv2(c,a)  normalize(c,a); div2(c,c)
#define neg(c,a)   (c)=0xFFFFFFFF-(a); normalize(c,c)
#define squ(c,a)   mul(c,a,a)
#define set(c,a)   (c)=(a)

/* Reverse the bits, approach from "Bit Twiddling Hacks"
 * See: https://graphics.stanford.edu/~seander/bithacks.html
 */
static uint32_t reverse(uint32_t x) {
	x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
	x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
	x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
	x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));
	return ((x >> 16) | (x << 16));
}

/* Nussbaumer approach, see:
 * H. J. Nussbaumer. Fast polynomial transform algorithms for digital convolution. Acoustics, Speech and
 * Signal Processing, IEEE Transactions on, 28(2):205{215, 1980
 * We followed the describtion from Knuth:
 * D. E. Knuth. Seminumerical Algorithms. The Art of Computer Programming. Addison-Wesley, Reading,
 * Massachusetts, USA, 3rd edition, 1997
 * Exercise Exercise 4.6.4.59.
 */

static void naive(DATATYPE *z, const DATATYPE *x, const DATATYPE *y, unsigned int n) {
	unsigned int i, j, k;
	DATATYPE A, B;

	for (i = 0; i < n; i++) {
		SET_ZERO(B);

		mul(A, x[0], y[i]);

		for (j = 1; j <= i; j++) {
			modmuladd(A, x[j], y[i - j]);
		}

		for (k = 1; j < n; j++, k++) {
			modmuladd(B, x[j], y[n - k]);
		}
		sub(z[i], A, B);
	}
}

static void nussbaumer_fft(DATATYPE *z, const DATATYPE *x, const DATATYPE *y, FFT_CTX *ctx) {
	DATATYPE **X1;
	DATATYPE **Y1;
	DATATYPE **Z1;
	DATATYPE *T1;
	unsigned int i;
	int j;

	X1 = (DATATYPE **) ctx->x1;
	Y1 = (DATATYPE **) ctx->y1;

	for (i = 0; i < 32; i++) {
		for (j = 0; j < 32; j++) {
			set(X1[i][j], x[32 * j + i]);
			set(X1[i + 32][j], x[32 * j + i]);

			set(Y1[i][j], y[32 * j + i]);
			set(Y1[i + 32][j], y[32 * j + i]);
		}
	}

	Z1 = (DATATYPE **) ctx->z1;
	T1 = (DATATYPE *) ctx->t1;

	for (j = 4; j >= 0; j--) {
		for (i = 0; i < (1U << (5 - j)); i++) {
			unsigned int t, ssr = reverse(i);
			for (t = 0; t < (1U << j); t++) {
				unsigned int s, sr, I, L, a;
				s = i;
				sr = (ssr >> (32 - 5 + j));
				sr <<= j;
				s <<= (j + 1);

				// X_i(w) = X_i(w) + w^kX_l(w) can be computed as
				// X_ij = X_ij - X_l(j-k+r)  for  0 <= j < k
				// X_ij = X_ij + X_l(j-k)    for  k <= j < r
				I = s + t, L = s + t + (1 << j);

				for (a = sr; a < 32; a++) {
					set(T1[a], X1[L][a - sr]);
				}
				for (a = 0; a < sr; a++) {
					neg(T1[a], X1[L][32 + a - sr]);
				}

				for (a = 0; a < 32; a++) {
					sub(X1[L][a], X1[I][a], T1[a]);
					add(X1[I][a], X1[I][a], T1[a]);
				}

				for (a = sr; a < 32; a++) {
					set(T1[a], Y1[L][a - sr]);
				}
				for (a = 0; a < sr; a++) {
					neg(T1[a], Y1[L][32 + a - sr]);
				}

				for (a = 0; a < 32; a++) {
					sub(Y1[L][a], Y1[I][a], T1[a]);
					add(Y1[I][a], Y1[I][a], T1[a]);
				}
			}
		}
	}

	for (i = 0; i < 2 * 32; i++) {
		naive(Z1[i], X1[i], Y1[i], 32);
	}

	for (j = 0; j <= (int) 5; j++) {
		for (i = 0; i < (1U << (5 - j)); i++) {
			unsigned int t, ssr = reverse(i);
			for (t = 0; t < (1U << j); t++) {
				unsigned int s, sr, A, B, a;
				s = i;
				sr = (ssr >> (32 - 5 + j));
				sr <<= j;
				s <<= (j + 1);

				A = s + t;
				B = s + t + (1 << j);
				for (a = 0; a < 32; a++) {
					sub(T1[a], Z1[A][a], Z1[B][a]);
					moddiv2(T1[a], T1[a]);
					add(Z1[A][a], Z1[A][a], Z1[B][a]);
					moddiv2(Z1[A][a], Z1[A][a]);
				}

				// w^{-(r/m)s'} (Z_{s+t}(w)-Z_{s+t+2^j}(w))
				for (a = 0; a < 32 - sr; a++) {
					set(Z1[B][a], T1[a + sr]);
				}
				for (a = 32 - sr; a < 32; a++) {
					neg(Z1[B][a], T1[a - (32 - sr)]);
				}
			}
		}
	}

	for (i = 0; i < 32; i++) {
		sub(z[i], Z1[i][0], Z1[32 + i][32 - 1]);
		for (j = 1; j < 32; j++) {
			add(z[32 * j + i], Z1[i][j], Z1[32 + i][j - 1]);
		}
	}
}

void FFT_mul(uint32_t *z, const uint32_t *x, const uint32_t *y, FFT_CTX *ctx) {
	nussbaumer_fft(z, x, y, ctx);
}

void FFT_add(uint32_t *z, const uint32_t *x, const uint32_t *y) {
	int i;
	for (i = 0; i < 1024; i++) {
		add(z[i], x[i], y[i]);
	}
}

int FFT_CTX_init(FFT_CTX *ctx) {
	ctx->x1 = (uint32_t **) malloc(64 * sizeof(uint32_t *));
	ctx->y1 = (uint32_t **) malloc(64 * sizeof(uint32_t *));
	ctx->z1 = (uint32_t **) malloc(64 * sizeof(uint32_t *));
	ctx->t1 = (uint32_t *) malloc(64 * sizeof(uint32_t));
	if (ctx->x1 == NULL || ctx->y1 == NULL || ctx->z1 == NULL || ctx->t1 == NULL) {
		return 0;
	}
	for (int i = 0; i < 64; i++) {
		ctx->x1[i] = (uint32_t *) malloc(64 * sizeof(uint32_t));
		ctx->y1[i] = (uint32_t *) malloc(64 * sizeof(uint32_t));
		ctx->z1[i] = (uint32_t *) malloc(64 * sizeof(uint32_t));
		if (ctx->x1[i] == NULL || ctx->y1[i] == NULL || ctx->z1[i] == NULL) {
			return 0;
		}
	}
	return 1;
}

void FFT_CTX_clear(FFT_CTX *ctx) {
	if (ctx == NULL) {
		return;
	}
	for (int i = 0; i < 64; i++) {
		memset((void *) ctx->x1[i], 0, 64 * sizeof(uint32_t));
		memset((void *) ctx->y1[i], 0, 64 * sizeof(uint32_t));
		memset((void *) ctx->z1[i], 0, 64 * sizeof(uint32_t));
	}
	memset((void *) ctx->t1, 0, 64 * sizeof(uint32_t));
}

void FFT_CTX_free(FFT_CTX *ctx) {
	if (ctx == NULL) {
		return;
	}
	for (int i = 0; i < 64; i++) {
		free(ctx->x1[i]);
		free(ctx->y1[i]);
		free(ctx->z1[i]);
	}
	free(ctx->x1);
	free(ctx->y1);
	free(ctx->z1);
	free(ctx->t1);
}

