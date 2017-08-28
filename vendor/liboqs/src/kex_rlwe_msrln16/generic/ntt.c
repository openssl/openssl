/****************************************************************************************
* LatticeCrypto: an efficient post-quantum Ring-Learning With Errors cryptography library
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: NTT functions and other polynomial operations
*
*****************************************************************************************/

#include "../LatticeCrypto_priv.h"

const uint32_t mask12 = ((uint64_t) 1 << 12) - 1;

int32_t oqs_rlwe_msrln16_reduce12289(int64_t a) { // Reduction modulo q
	int32_t c0, c1;

	c0 = (int32_t)(a & mask12);
	c1 = (int32_t)(a >> 12);

	return (3 * c0 - c1);
}

int32_t oqs_rlwe_msrln16_reduce12289_2x(int64_t a) { // Two merged reductions modulo q
	int32_t c0, c1, c2;

	c0 = (int32_t)(a & mask12);
	c1 = (int32_t)((a >> 12) & mask12);
	c2 = (int32_t)(a >> 24);

	return (9 * c0 - 3 * c1 + c2);
}

void oqs_rlwe_msrln16_NTT_CT_std2rev_12289(int32_t *a, const int32_t *psi_rev, unsigned int N) { // Forward NTT
	unsigned int m, i, j, j1, j2, k = N;
	int32_t S, U, V;

	for (m = 1; m < 128; m = 2 * m) {
		k = k >> 1;
		for (i = 0; i < m; i++) {
			j1 = 2 * i * k;
			j2 = j1 + k - 1;
			S = psi_rev[m + i];
			for (j = j1; j <= j2; j++) {
				U = a[j];
				V = oqs_rlwe_msrln16_reduce12289((int64_t) a[j + k] * S);
				a[j] = U + V;
				a[j + k] = U - V;
			}
		}
	}

	k = 4;
	for (i = 0; i < 128; i++) {
		j1 = 8 * i;
		j2 = j1 + 3;
		S = psi_rev[i + 128];
		for (j = j1; j <= j2; j++) {
			U = oqs_rlwe_msrln16_reduce12289((int64_t) a[j]);
			V = oqs_rlwe_msrln16_reduce12289_2x((int64_t) a[j + 4] * S);
			a[j] = U + V;
			a[j + 4] = U - V;
		}
	}

	for (m = 256; m < N; m = 2 * m) {
		k = k >> 1;
		for (i = 0; i < m; i++) {
			j1 = 2 * i * k;
			j2 = j1 + k - 1;
			S = psi_rev[m + i];
			for (j = j1; j <= j2; j++) {
				U = a[j];
				V = oqs_rlwe_msrln16_reduce12289((int64_t) a[j + k] * S);
				a[j] = U + V;
				a[j + k] = U - V;
			}
		}
	}
	return;
}

void oqs_rlwe_msrln16_INTT_GS_rev2std_12289(int32_t *a, const int32_t *omegainv_rev, const int32_t omegainv1N_rev, const int32_t Ninv, unsigned int N) { // Inverse NTT
	unsigned int m, h, i, j, j1, j2, k = 1;
	int32_t S, U, V;
	int64_t temp;

	for (m = N; m > 2; m >>= 1) {
		j1 = 0;
		h = m >> 1;
		for (i = 0; i < h; i++) {
			j2 = j1 + k - 1;
			S = omegainv_rev[h + i];
			for (j = j1; j <= j2; j++) {
				U = a[j];
				V = a[j + k];
				a[j] = U + V;
				temp = (int64_t)(U - V) * S;
				if (m == 32) {
					a[j] = oqs_rlwe_msrln16_reduce12289((int64_t) a[j]);
					a[j + k] = oqs_rlwe_msrln16_reduce12289_2x(temp);
				} else {
					a[j + k] = oqs_rlwe_msrln16_reduce12289(temp);
				}
			}
			j1 = j1 + 2 * k;
		}
		k = 2 * k;
	}
	for (j = 0; j < k; j++) {
		U = a[j];
		V = a[j + k];
		a[j] = oqs_rlwe_msrln16_reduce12289((int64_t)(U + V) * Ninv);
		a[j + k] = oqs_rlwe_msrln16_reduce12289((int64_t)(U - V) * omegainv1N_rev);
	}
	return;
}

void oqs_rlwe_msrln16_two_reduce12289(int32_t *a, unsigned int N) { // Two consecutive reductions modulo q
	unsigned int i;

	for (i = 0; i < N; i++) {
		a[i] = oqs_rlwe_msrln16_reduce12289((int64_t) a[i]);
		a[i] = oqs_rlwe_msrln16_reduce12289((int64_t) a[i]);
	}
}

void oqs_rlwe_msrln16_pmul(int32_t *a, int32_t *b, int32_t *c, unsigned int N) { // Component-wise multiplication
	unsigned int i;

	for (i = 0; i < N; i++) {
		c[i] = oqs_rlwe_msrln16_reduce12289((int64_t) a[i] * b[i]);
		c[i] = oqs_rlwe_msrln16_reduce12289((int64_t) c[i]);
	}
}

void oqs_rlwe_msrln16_pmuladd(int32_t *a, int32_t *b, int32_t *c, int32_t *d, unsigned int N) { // Component-wise multiplication and addition
	unsigned int i;

	for (i = 0; i < N; i++) {
		d[i] = oqs_rlwe_msrln16_reduce12289((int64_t) a[i] * b[i] + c[i]);
		d[i] = oqs_rlwe_msrln16_reduce12289((int64_t) d[i]);
	}
}

void oqs_rlwe_msrln16_smul(int32_t *a, int32_t scalar, unsigned int N) { // Component-wise multiplication with scalar
	unsigned int i;

	for (i = 0; i < N; i++) {
		a[i] = a[i] * scalar;
	}
}

void oqs_rlwe_msrln16_correction(int32_t *a, int32_t p, unsigned int N) { // Correction modulo q
	unsigned int i;
	int32_t mask;

	for (i = 0; i < N; i++) {
		mask = a[i] >> (4 * sizeof(int32_t) - 1);
		a[i] += (p & mask) - p;
		mask = a[i] >> (4 * sizeof(int32_t) - 1);
		a[i] += (p & mask);
	}
}
